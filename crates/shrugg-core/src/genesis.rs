//! Genesis configuration and derivation of the genesis block + ledger.

use crate::bridge::{BridgeCommit, BridgeConfig, BridgeState, GuardianKey, CHAIN_RAND, GOVERNANCE_EMITTER};
use crate::crypto::{Address, Hash, PublicKey, Signature};
use crate::ledger::{Account, Ledger};
use crate::types::{Block, BlockHeader, QuorumCertificate, Validator, ValidatorSet};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    /// Cross-chain bridge: the outbound emitter, the initial guardian set, and
    /// the registered emitter of each source chain. Part of the genesis hash
    /// when present; omitted entirely when absent, so a bridge-less chain's
    /// genesis file, hash, and state root are byte-for-byte what a pre-bridge
    /// node produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgeConfig>,
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
    #[error("duplicate validator {0}")]
    DuplicateValidator(Address),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown fri_profile {0} (production|test)")]
    BadFriProfile(String),
    #[error("bad bridge config: {0}")]
    BadBridgeConfig(String),
}

/// Everything a node derives from the genesis file.
#[derive(Clone, Debug)]
pub struct GenesisState {
    pub chain_id: u64,
    pub faucet: bool,
    pub confidential: bool,
    pub fri_profile: String,
    /// The genesis `bridge` section, or `None` on a chain without a bridge.
    /// `ledger.bridge()` is the state derived from it.
    pub bridge: Option<BridgeConfig>,
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
        if let Some(bridge) = &self.bridge {
            check_bridge(bridge)?;
        }
        let mut vals = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut total_stake = 0u128;
        for v in &self.validators {
            if v.stake == 0 {
                return Err(GenesisError::ZeroStake(v.public_key.address()));
            }
            // ValidatorSet::new would silently collapse duplicates (and the
            // genesis hash would commit to the collapsed set): reject instead.
            if !seen.insert(v.public_key.address()) {
                return Err(GenesisError::DuplicateValidator(v.public_key.address()));
            }
            total_stake = total_stake.checked_add(v.stake).ok_or(GenesisError::Overflow)?;
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
        ledger.set_bridge(self.bridge.as_ref().map(BridgeState::from_config));
        // The genesis ledger is positioned at the genesis block, so it carries
        // that block's time structurally rather than relying on every caller
        // (`HotStuff::resume`, `verify_chain`) to patch it in. The timestamp is
        // transient state, not part of the state root or the genesis hash.
        ledger.set_timestamp_ms(self.timestamp_ms);

        // The genesis block is unsigned and has a self-referential placeholder
        // justify; its hash commits to chain id, validators, and the initial state.
        let proposer = validators.iter().next().expect("non-empty").public_key.clone();
        let mut commit = Vec::new();
        commit.extend_from_slice(&self.chain_id.to_be_bytes());
        commit.extend_from_slice(&bincode::serialize(&validators).expect("serializes"));
        commit.push(self.faucet as u8);
        commit.push(self.confidential as u8);
        commit.extend_from_slice(self.fri_profile.as_bytes());
        // Appended only when a bridge is configured, so a bridge-less chain's
        // genesis hash is unchanged. `BridgeCommit` is the plain-bytes twin of
        // `BridgeConfig`, whose own serde is hex text.
        if let Some(bridge) = &self.bridge {
            commit.extend_from_slice(&bincode::serialize(&BridgeCommit::from(bridge)).expect("serializes"));
        }
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
        Ok(GenesisState {
            chain_id: self.chain_id,
            faucet: self.faucet,
            confidential: self.confidential,
            fri_profile: self.fri_profile.clone(),
            bridge: self.bridge.clone(),
            validators,
            ledger,
            block,
        })
    }
}

/// Rejects a `bridge` section a chain could not run: an empty, duplicated or
/// zero guardian set, Rand itself registered as a source emitter, or a source
/// emitter that collides with the governance emitter (which would let a
/// source chain forge guardian-set upgrades).
fn check_bridge(cfg: &BridgeConfig) -> Result<(), GenesisError> {
    let bad = |m: String| Err(GenesisError::BadBridgeConfig(m));
    if cfg.guardians.is_empty() {
        return bad("no guardians".into());
    }
    if cfg.guardians.iter().collect::<BTreeSet<&GuardianKey>>().len() != cfg.guardians.len() {
        return bad("duplicate guardian key".into());
    }
    if cfg.guardians.contains(&[0u8; 20]) {
        return bad("zero guardian key".into());
    }
    if cfg.emitter == [0u8; 32] {
        return bad("zero emitter address".into());
    }
    if cfg.emitter == GOVERNANCE_EMITTER {
        return bad("emitter is the governance emitter".into());
    }
    if cfg.emitters.contains_key(&CHAIN_RAND) {
        return bad(format!("chain {CHAIN_RAND} is Rand itself and cannot be a source emitter"));
    }
    if let Some((chain, _)) = cfg.emitters.iter().find(|(_, addr)| **addr == GOVERNANCE_EMITTER) {
        return bad(format!("emitter for chain {chain} is the governance emitter"));
    }
    // A zero source emitter is never a real contract, and registering one
    // would mean any attestation naming that chain with an all-zero
    // `emitter_address` passes the emitter binding of spec 3.8.
    if let Some((chain, _)) = cfg.emitters.iter().find(|(_, addr)| **addr == [0u8; 32]) {
        return bad(format!("zero emitter address for chain {chain}"));
    }
    Ok(())
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
            bridge: None,
        }
    }

    fn bridge_cfg() -> BridgeConfig {
        BridgeConfig { emitter: [1; 32], guardians: vec![[2; 20]], emitters: BTreeMap::new() }
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
        // The genesis ledger is positioned at the genesis block's time.
        assert_eq!(sa.ledger.timestamp_ms(), sa.block.header.timestamp_ms);
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

    /// The live testnet genesis must keep hashing to the value `deploy/README.md`
    /// documents: a chain without a `bridge` section is byte-for-byte what a
    /// pre-bridge node produced. A failure here is a hard fork, not a stale
    /// expectation.
    #[test]
    fn genesis_hash_unchanged_without_bridge_and_changes_with() {
        let g = Genesis::from_json(include_str!("../../../deploy/genesis.json")).unwrap();
        assert!(g.bridge.is_none());
        assert_eq!(
            g.build().unwrap().hash().to_hex(),
            "3a82b0c7b6c4eb1eb1e1ba8a54b4306a883a57d46ccebce1e7adb7b5fd9ffa86"
        );
        assert!(g.build().unwrap().ledger.bridge().is_none());
        // ... and a bridge section moves both the genesis hash and the state root
        let mut with = g.clone();
        with.bridge = Some(bridge_cfg());
        assert_ne!(with.build().unwrap().hash(), g.build().unwrap().hash());
        assert!(with.build().unwrap().ledger.bridge().is_some());
        assert_ne!(with.build().unwrap().ledger.state_root(), g.build().unwrap().ledger.state_root());
        // the section survives a JSON round trip and is omitted when absent
        assert!(!g.to_json().contains("bridge"));
        assert_eq!(Genesis::from_json(&with.to_json()).unwrap(), with);
    }

    #[test]
    fn bridge_section_is_validated() {
        let bad = |cfg: BridgeConfig| {
            let mut g = genesis(1);
            g.bridge = Some(cfg);
            match g.build() {
                Err(GenesisError::BadBridgeConfig(m)) => m,
                other => panic!("expected BadBridgeConfig, got {other:?}"),
            }
        };
        assert!(bad(BridgeConfig { guardians: vec![], ..bridge_cfg() }).contains("guardian"));
        assert!(bad(BridgeConfig { guardians: vec![[2; 20], [2; 20]], ..bridge_cfg() }).contains("duplicate"));
        assert!(bad(BridgeConfig { guardians: vec![[0; 20]], ..bridge_cfg() }).contains("zero"));
        assert!(bad(BridgeConfig { emitter: [0; 32], ..bridge_cfg() }).contains("zero emitter"));
        assert!(bad(BridgeConfig { emitter: GOVERNANCE_EMITTER, ..bridge_cfg() }).contains("governance"));
        assert!(bad(BridgeConfig { emitters: BTreeMap::from([(1u16, [7u8; 32])]), ..bridge_cfg() }).contains("Rand"));
        assert!(
            bad(BridgeConfig { emitters: BTreeMap::from([(2u16, GOVERNANCE_EMITTER)]), ..bridge_cfg() })
                .contains("governance")
        );
        assert!(
            bad(BridgeConfig { emitters: BTreeMap::from([(2u16, [0u8; 32])]), ..bridge_cfg() })
                .contains("zero emitter address for chain 2")
        );
        let mut ok = genesis(1);
        ok.bridge = Some(BridgeConfig { emitters: BTreeMap::from([(2u16, [7u8; 32])]), ..bridge_cfg() });
        let state = ok.build().unwrap();
        assert_eq!(state.bridge.as_ref().unwrap().guardians, vec![[2u8; 20]]);
        let bridge = state.ledger.bridge().unwrap();
        assert_eq!(bridge.guardian_sets[&0].keys, vec![[2u8; 20]]);
        assert_eq!(bridge.emitters, BTreeMap::from([(2u16, [7u8; 32])]));
        assert_eq!(bridge.emitter, [1u8; 32]);
    }

    #[test]
    fn rejects_duplicate_validators_and_stake_overflow() {
        let mut g = genesis(2);
        g.validators.push(g.validators[0].clone());
        assert!(matches!(g.build(), Err(GenesisError::DuplicateValidator(_))));
        let mut g = genesis(2);
        g.validators[0].stake = u128::MAX;
        assert!(matches!(g.build(), Err(GenesisError::Overflow)));
    }
}
