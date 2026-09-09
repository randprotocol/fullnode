//! Genesis configuration and derivation of the genesis block + ledger.

use crate::crypto::{Address, Hash, PublicKey, Signature};
use crate::ledger::{Account, Ledger};
use crate::types::{Block, BlockHeader, QuorumCertificate, Validator, ValidatorSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Hex-encoded Dilithium2 public key.
    pub public_key: PublicKey,
    pub stake: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: u64,
    pub timestamp_ms: u64,
    pub validators: Vec<GenesisValidator>,
    /// Address (base58) -> balance in smallest units.
    #[serde(default)]
    pub alloc: BTreeMap<String, u128>,
    /// Testnet only: allow `Mint` transactions (up to 100 SHRUGG each). Part of the genesis hash.
    #[serde(default)]
    pub faucet: bool,
    /// Allow Deploy/Call transactions (zkVM verification). Part of the genesis hash.
    #[serde(default = "default_true")]
    pub confidential: bool,
    /// zkVM FRI profile every node must use: "production" or "test" (tests only). Part of the genesis hash.
    #[serde(default = "default_profile")]
    pub fri_profile: String,
}

fn default_true() -> bool {
    true
}

fn default_profile() -> String {
    "production".into()
}

pub const FRI_PROFILES: [&str; 2] = ["production", "test"];

#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("no validators")]
    NoValidators,
    #[error("invalid alloc address {0}")]
    BadAddress(String),
    #[error("alloc overflow")]
    Overflow,
    #[error("validator {0} has zero stake")]
    ZeroStake(Address),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown fri_profile {0} (production|test)")]
    BadFriProfile(String),
}

/// Everything a node derives from the genesis file.
#[derive(Clone, Debug)]
pub struct GenesisState {
    pub chain_id: u64,
    pub faucet: bool,
    pub confidential: bool,
    pub fri_profile: String,
    pub validators: ValidatorSet,
    pub ledger: Ledger,
    pub block: Block,
}

impl GenesisState {
    pub fn hash(&self) -> Hash {
        self.block.hash()
    }
}

impl Genesis {
    pub fn from_json(s: &str) -> Result<Genesis, GenesisError> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("genesis serializes")
    }

    pub fn build(&self) -> Result<GenesisState, GenesisError> {
        if self.validators.is_empty() {
            return Err(GenesisError::NoValidators);
        }
        if !FRI_PROFILES.contains(&self.fri_profile.as_str()) {
            return Err(GenesisError::BadFriProfile(self.fri_profile.clone()));
        }
        let mut vals = Vec::new();
        for v in &self.validators {
            if v.stake == 0 {
                return Err(GenesisError::ZeroStake(v.public_key.address()));
            }
            vals.push(Validator { public_key: v.public_key.clone(), stake: v.stake });
        }
        let validators = ValidatorSet::new(vals);

        let mut accounts = BTreeMap::new();
        for (addr_s, bal) in &self.alloc {
            let addr = Address::from_base58(addr_s).map_err(|_| GenesisError::BadAddress(addr_s.clone()))?;
            let acct: &mut Account = accounts.entry(addr).or_default();
            acct.balance = acct.balance.checked_add(*bal).ok_or(GenesisError::Overflow)?;
        }
        let mut ledger = Ledger::from_accounts(self.chain_id, accounts);
        ledger.set_faucet(self.faucet);

        // The genesis block is unsigned and has a self-referential placeholder
        // justify; its hash commits to chain id, validators, and the initial state.
        let proposer = validators.iter().next().expect("non-empty").public_key.clone();
        let mut commit = Vec::new();
        commit.extend_from_slice(&self.chain_id.to_be_bytes());
        commit.extend_from_slice(&bincode::serialize(&validators).expect("serializes"));
        commit.push(self.faucet as u8);
        commit.push(self.confidential as u8);
        commit.extend_from_slice(self.fri_profile.as_bytes());
        let genesis_binding = Hash::digest_domain(b"shrugg-genesis", &commit);
        let header = BlockHeader {
            height: 0,
            view: 0,
            parent: genesis_binding,
            proposer,
            timestamp_ms: self.timestamp_ms,
            tx_root: Hash::ZERO,
            state_root: ledger.state_root(),
            justify: QuorumCertificate { view: 0, block_hash: Hash::ZERO, votes: Vec::new() },
        };
        let block = Block { header, transactions: Vec::new(), signature: Signature::empty() };
        Ok(GenesisState { chain_id: self.chain_id, faucet: self.faucet, confidential: self.confidential, fri_profile: self.fri_profile.clone(), validators, ledger, block })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn genesis(n: u8) -> Genesis {
        let keys: Vec<Keypair> = (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
        Genesis {
            chain_id: 42,
            timestamp_ms: 1_700_000_000_000,
            validators: keys.iter().map(|k| GenesisValidator { public_key: k.public_key().clone(), stake: 100 }).collect(),
            alloc: keys.iter().map(|k| (k.address().to_base58(), 1_000_000)).collect(),
            faucet: false,
            confidential: true,
            fri_profile: "production".into(),
        }
    }

    #[test]
    fn confidential_flags_are_in_the_genesis_hash() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.confidential = false;
        let mut c = genesis(1);
        c.fri_profile = "test".into();
        let ha = a.build().unwrap().hash();
        assert_ne!(ha, b.build().unwrap().hash());
        assert_ne!(ha, c.build().unwrap().hash());
        let mut d = genesis(1);
        d.fri_profile = "bogus".into();
        assert!(matches!(d.build(), Err(GenesisError::BadFriProfile(_))));
        let js = a.to_json();
        assert!(js.contains("\"confidential\": true"));
    }

    #[test]
    fn faucet_flag_changes_genesis_hash_and_ledger() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.faucet = true;
        let sa = a.build().unwrap();
        let sb = b.build().unwrap();
        assert_ne!(sa.hash(), sb.hash());
        assert!(!sa.ledger.faucet_enabled());
        assert!(sb.ledger.faucet_enabled());
        assert_eq!(sa.ledger.state_root(), sb.ledger.state_root(), "faucet flag is not state");
    }

    #[test]
    fn json_roundtrip_and_deterministic_hash() {
        let g = genesis(2);
        let js = g.to_json();
        let g2 = Genesis::from_json(&js).unwrap();
        assert_eq!(g, g2);
        let s1 = g.build().unwrap();
        let s2 = g2.build().unwrap();
        assert_eq!(s1.hash(), s2.hash());
        assert_eq!(s1.validators.len(), 2);
        assert_eq!(s1.ledger.balance(&s1.validators.iter().next().unwrap().address()), 1_000_000);
        assert_eq!(s1.block.header.state_root, s1.ledger.state_root());
    }

    #[test]
    fn different_chain_id_changes_genesis_hash() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.chain_id = 43;
        assert_ne!(a.build().unwrap().hash(), b.build().unwrap().hash());
    }

    #[test]
    fn rejects_bad_input() {
        let mut g = genesis(1);
        g.alloc.insert("!!!".into(), 1);
        assert!(matches!(g.build(), Err(GenesisError::BadAddress(_))));
        let mut g = genesis(1);
        g.validators.clear();
        assert!(matches!(g.build(), Err(GenesisError::NoValidators)));
        let mut g = genesis(1);
        g.validators[0].stake = 0;
        assert!(matches!(g.build(), Err(GenesisError::ZeroStake(_))));
    }
}
