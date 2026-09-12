//! Genesis configuration and derivation of the genesis block + ledger.

use crate::bridge::{BridgeCommit, BridgeConfig, BridgeState, GuardianKey, CHAIN_RAND, GOVERNANCE_EMITTER};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{Address, Hash, PublicKey, Signature};
use crate::ledger::Ledger;
use crate::notes::{word8_from_hex, word8_to_bytes, Envelope, Word8};
use crate::types::{Block, BlockHeader, QuorumCertificate, Validator, ValidatorSet};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Hex-encoded Dilithium2 public key.
    pub public_key: PublicKey,
    pub stake: u128,
    /// Phase S2: the shielded address this validator's rewards and unbonded stake are paid to
    /// (`shrugg1…`). Optional and *not* part of the genesis binding yet — S2 seeds the register
    /// from it, makes it required, and binds it then. Until then a genesis carrying one builds
    /// to exactly the same chain as one without.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout: Option<String>,
}

/// The four envelope parts as hex text, so a genesis file stays readable JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeHex {
    pub kem_ct: String,
    pub to_receiver: String,
    pub to_sender: String,
    pub body: String,
}

impl EnvelopeHex {
    pub fn from_envelope(e: &Envelope) -> EnvelopeHex {
        EnvelopeHex {
            kem_ct: hex::encode(&e.kem_ct),
            to_receiver: hex::encode(&e.to_receiver),
            to_sender: hex::encode(&e.to_sender),
            body: hex::encode(&e.body),
        }
    }

    pub fn to_envelope(&self) -> Result<Envelope, GenesisError> {
        let part = |s: &String| hex::decode(s).map_err(|_| GenesisError::BadNote(s.clone()));
        Ok(Envelope {
            kem_ct: part(&self.kem_ct)?,
            to_receiver: part(&self.to_receiver)?,
            to_sender: part(&self.to_sender)?,
            body: part(&self.body)?,
        })
    }
}

/// A deposit note the chain starts with (spec §8): its commitment, the envelope that opens it,
/// and the amount it carries. The amount is not chain state — the note's value lives inside the
/// commitment — but it is part of the genesis binding so every node agrees on the initial supply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisNote {
    /// 64 hex characters.
    pub cm: String,
    pub envelope: EnvelopeHex,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: u64,
    pub timestamp_ms: u64,
    pub validators: Vec<GenesisValidator>,
    /// The deposit notes the chain starts with.
    #[serde(default)]
    pub alloc: Vec<GenesisNote>,
    /// Testnet only: allow `Mint` transactions (up to 100 SHRUGG each). Part of the genesis hash.
    #[serde(default)]
    pub faucet: bool,
    /// Allow Deploy/Call transactions (zkVM verification). Part of the genesis hash.
    #[serde(default = "default_true")]
    pub confidential: bool,
    /// zkVM FRI profile every node must use: "production" or "test" (tests only). Part of the genesis hash.
    #[serde(default = "default_profile")]
    pub fri_profile: String,
    /// The `bundle` guest's program commitment, 64 hex characters: the only proof-system
    /// parameter a bundle proof is checked against. Part of the genesis hash.
    pub hc_bundle: String,
    /// Cross-chain bridge (spec §10): the outbound emitter, the initial guardian set and the
    /// source-chain emitters. Part of the genesis hash and of the state root when present;
    /// omitted entirely when absent, so a bridge-less chain's genesis file, hash and state root
    /// are byte-for-byte what phase S1 produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgeConfig>,
    /// Phase S2: blocks per epoch — the validator set for epoch `e` is derived from the
    /// register as of the last block of epoch `e - 1`. Configurable so a cluster test does not
    /// have to run 1000 blocks to cross a boundary. Part of the genesis hash: two chains that
    /// disagree about it derive different sets from the same register.
    #[serde(default = "default_epoch_blocks")]
    pub epoch_blocks: u64,
}

fn default_true() -> bool {
    true
}

/// Spec §8 / S2's `EPOCH_BLOCKS_DEFAULT`.
pub const EPOCH_BLOCKS_DEFAULT: u64 = 1000;

fn default_epoch_blocks() -> u64 {
    EPOCH_BLOCKS_DEFAULT
}

/// Largest `epoch_blocks` a genesis file may ask for. `epoch(h) = h / epoch_blocks`, so zero is
/// a division by zero and anything past a chain's reachable height is an epoch that never ends —
/// one set, forever, which is not what a genesis author means by a large number. `1 << 32` blocks
/// is ~136 years at 1 s blocks: far beyond any real chain and still far from `u64::MAX`.
pub const MAX_EPOCH_BLOCKS: u64 = 1 << 32;

fn default_profile() -> String {
    "production".into()
}

pub const FRI_PROFILES: [&str; 2] = ["production", "test"];

#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("no validators")]
    NoValidators,
    #[error("stake overflow")]
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
    #[error("bad hc_bundle {0} (64 hex characters)")]
    BadHcBundle(String),
    #[error("bad alloc note {0}")]
    BadNote(String),
    #[error("duplicate alloc note {0}")]
    DuplicateNote(String),
    #[error("bad epoch_blocks {0} (1..={MAX_EPOCH_BLOCKS})")]
    BadEpochBlocks(u64),
}

/// Everything a node derives from the genesis file.
#[derive(Clone, Debug)]
pub struct GenesisState {
    pub chain_id: u64,
    pub faucet: bool,
    pub confidential: bool,
    pub fri_profile: String,
    pub hc_bundle: Word8,
    pub validators: ValidatorSet,
    /// Phase S2: blocks per epoch, as the genesis file set it.
    pub epoch_blocks: u64,
    pub ledger: Ledger,
    pub block: Block,
    /// The alloc notes in file order: commitment, envelope, amount.
    pub notes: Vec<(Word8, Envelope, u64)>,
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

    pub fn build(&self, executor: &dyn ConfidentialExecutor) -> Result<GenesisState, GenesisError> {
        if self.validators.is_empty() {
            return Err(GenesisError::NoValidators);
        }
        if !FRI_PROFILES.contains(&self.fri_profile.as_str()) {
            return Err(GenesisError::BadFriProfile(self.fri_profile.clone()));
        }
        if let Some(bridge) = &self.bridge {
            check_bridge(bridge)?;
        }
        // S2 divides by `epoch_blocks` to get the epoch of a height; a genesis file that says
        // zero would panic every node on the first block rather than at the one place that
        // reads the file. The upper bound costs nothing and rejects an epoch that never ends.
        if self.epoch_blocks == 0 || self.epoch_blocks > MAX_EPOCH_BLOCKS {
            return Err(GenesisError::BadEpochBlocks(self.epoch_blocks));
        }
        let mut vals = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut total_stake = 0u128;
        for v in &self.validators {
            if v.stake == 0 {
                return Err(GenesisError::ZeroStake(v.public_key.address()));
            }
            // ValidatorSet::new would silently collapse duplicates (and the genesis hash would
            // commit to the collapsed set): reject instead.
            if !seen.insert(v.public_key.address()) {
                return Err(GenesisError::DuplicateValidator(v.public_key.address()));
            }
            total_stake = total_stake.checked_add(v.stake).ok_or(GenesisError::Overflow)?;
            vals.push(Validator { public_key: v.public_key.clone(), stake: v.stake });
        }
        let validators = ValidatorSet::new(vals);

        let hc_bundle = word8_from_hex(&self.hc_bundle).ok_or_else(|| GenesisError::BadHcBundle(self.hc_bundle.clone()))?;
        let mut ledger = Ledger::new(self.chain_id, hc_bundle, &validators, executor);
        ledger.set_faucet(self.faucet);
        ledger.set_confidential(self.confidential);
        ledger.set_bridge(self.bridge.as_ref().map(BridgeState::from_config));
        // The genesis ledger is positioned at the genesis block, so it carries that block's
        // time structurally rather than relying on every caller to patch it in. The timestamp
        // is transient state, not part of the state root or the genesis hash.
        ledger.set_timestamp_ms(self.timestamp_ms);
        let mut notes = Vec::new();
        for n in &self.alloc {
            let cm = word8_from_hex(&n.cm).ok_or_else(|| GenesisError::BadNote(n.cm.clone()))?;
            let envelope = n.envelope.to_envelope()?;
            ledger.deposit(cm, executor).map_err(|_| GenesisError::DuplicateNote(n.cm.clone()))?;
            notes.push((cm, envelope, n.amount));
        }
        // Replaces the empty-tree root `Ledger::new` recorded, so the only anchor a chain
        // starts with is the root the deposit notes leave behind.
        ledger.record_anchor(0);

        // The genesis block is unsigned and has a self-referential placeholder justify; its hash
        // commits to chain id, validators, the chain switches, the bundle guest and every note.
        let proposer = validators.iter().next().expect("non-empty").public_key.clone();
        let mut commit = Vec::new();
        commit.extend_from_slice(&self.chain_id.to_be_bytes());
        commit.extend_from_slice(&bincode::serialize(&validators).expect("serializes"));
        commit.push(self.faucet as u8);
        commit.push(self.confidential as u8);
        commit.extend_from_slice(self.fri_profile.as_bytes());
        commit.extend_from_slice(&word8_to_bytes(&hc_bundle));
        for (cm, _, amount) in &notes {
            commit.extend_from_slice(&word8_to_bytes(cm));
            commit.extend_from_slice(&amount.to_be_bytes());
        }
        // S2 scaffold: `epoch_blocks` is bound unconditionally, after the notes. Appending it
        // only when it is non-default would make the binding depend on a default this file can
        // change later; paying one hash change now (`the_genesis_hash_is_pinned`, re-pinned in
        // the same commit) buys a binding that stays stable through S2. `GenesisValidator.payout`
        // is deliberately *not* here yet — it is optional until S2 makes it required, and
        // binding an optional field would split chains on a field nobody has filled in.
        commit.extend_from_slice(&self.epoch_blocks.to_be_bytes());
        // S3: appended only when a bridge is configured, so a bridge-less chain's genesis hash
        // is unchanged. `BridgeCommit` is the plain-bytes twin of `BridgeConfig`, whose own
        // serde is hex text — bincode of that would commit to hex *strings*.
        if let Some(bridge) = &self.bridge {
            commit.extend_from_slice(&bincode::serialize(&BridgeCommit::from(bridge)).expect("serializes"));
        }
        let genesis_binding = Hash::digest_domain(b"shrugg-genesis-2", &commit);
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
            hc_bundle,
            validators,
            epoch_blocks: self.epoch_blocks,
            ledger,
            block,
            notes,
        })
    }
}

/// Rejects a `bridge` section a chain could not run: an empty, duplicated or zero guardian set,
/// Rand itself registered as a source emitter, or a source emitter that collides with the
/// governance emitter (which would let a source chain forge guardian-set upgrades).
fn check_bridge(cfg: &BridgeConfig) -> Result<(), GenesisError> {
    let bad = |m: String| Err(GenesisError::BadBridgeConfig(m));
    if cfg.guardians.is_empty() {
        return bad("no guardians".into());
    }
    if cfg.guardians.iter().collect::<std::collections::BTreeSet<&GuardianKey>>().len() != cfg.guardians.len() {
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
    // A zero source emitter is never a real contract, and registering one would mean any
    // attestation naming that chain with an all-zero `emitter_address` passes the emitter
    // binding of spec 3.8.
    if let Some((chain, _)) = cfg.emitters.iter().find(|(_, addr)| **addr == [0u8; 32]) {
        return bad(format!("zero emitter address for chain {chain}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::notes::word8_to_hex;
    use std::collections::BTreeMap;

    fn note(seed: u32, amount: u64) -> GenesisNote {
        GenesisNote {
            cm: word8_to_hex(&[seed; 8]),
            envelope: EnvelopeHex::from_envelope(&Envelope {
                kem_ct: vec![1; 8],
                to_receiver: vec![],
                to_sender: vec![],
                body: vec![2; 8],
            }),
            amount,
        }
    }

    fn genesis(n: u8) -> Genesis {
        let keys: Vec<Keypair> = (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
        Genesis {
            chain_id: 42,
            timestamp_ms: 1_700_000_000_000,
            validators: keys
                .iter()
                .map(|k| GenesisValidator { public_key: k.public_key().clone(), stake: 100, payout: None })
                .collect(),
            alloc: vec![note(7, 1_000_000), note(8, 2_000_000)],
            faucet: false,
            confidential: true,
            fri_profile: "production".into(),
            hc_bundle: word8_to_hex(&[3; 8]),
            bridge: None,
            epoch_blocks: EPOCH_BLOCKS_DEFAULT,
        }
    }

    fn build(g: &Genesis) -> GenesisState {
        g.build(&StubExecutor).unwrap()
    }

    #[test]
    fn alloc_notes_are_in_the_tree_and_the_binding() {
        let g = genesis(1);
        let s = build(&g);
        assert_eq!(s.ledger.next_index(), 2);
        assert!(s.ledger.has_commitment(&[7; 8]) && s.ledger.has_commitment(&[8; 8]));
        assert_eq!(s.notes.iter().map(|(cm, _, a)| (*cm, *a)).collect::<Vec<_>>(), vec![([7; 8], 1_000_000), ([8; 8], 2_000_000)]);
        assert_eq!(s.notes[0].1.body, vec![2; 8]);
        // The genesis ledger starts with exactly one anchor: the root the notes leave behind.
        assert_eq!(s.ledger.anchors().len(), 1);
        assert_eq!(s.ledger.anchors()[0], (0, s.ledger.root()));
        // An amount is part of the binding even though it is not chain state.
        let mut other = g.clone();
        other.alloc[1].amount += 1;
        assert_ne!(build(&other).hash(), s.hash());
        assert_eq!(build(&other).ledger.state_root(), s.ledger.state_root());
        // ... and so is the commitment, which is.
        let mut moved = g.clone();
        moved.alloc[1] = note(9, 2_000_000);
        assert_ne!(build(&moved).hash(), s.hash());
        assert_ne!(build(&moved).ledger.state_root(), s.ledger.state_root());
        // The same note twice is rejected rather than silently collapsed.
        let mut dup = g.clone();
        dup.alloc.push(note(7, 5));
        assert!(matches!(dup.build(&StubExecutor), Err(GenesisError::DuplicateNote(_))));
        let mut bad = g.clone();
        bad.alloc[0].cm = "zz".into();
        assert!(matches!(bad.build(&StubExecutor), Err(GenesisError::BadNote(_))));
        let mut bad_env = g.clone();
        bad_env.alloc[0].envelope.body = "nothex".into();
        assert!(matches!(bad_env.build(&StubExecutor), Err(GenesisError::BadNote(_))));
    }

    #[test]
    fn hc_bundle_is_required_and_bound() {
        let g = genesis(1);
        let mut without = serde_json::to_value(&g).unwrap();
        without.as_object_mut().unwrap().remove("hc_bundle");
        assert!(Genesis::from_json(&without.to_string()).is_err(), "hc_bundle has no default");
        let s = build(&g);
        assert_eq!(s.hc_bundle, [3; 8]);
        assert_eq!(s.ledger.hc_bundle(), [3; 8]);
        let mut other = g.clone();
        other.hc_bundle = word8_to_hex(&[4; 8]);
        assert_ne!(build(&other).hash(), s.hash());
        let mut bad = g.clone();
        bad.hc_bundle = "not hex".into();
        assert!(matches!(bad.build(&StubExecutor), Err(GenesisError::BadHcBundle(_))));
    }

    #[test]
    fn faucet_and_confidential_flags_change_the_hash_not_the_state_root() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.faucet = true;
        let mut c = genesis(1);
        c.confidential = false;
        let mut d = genesis(1);
        d.fri_profile = "test".into();
        let (sa, sb, sc, sd) = (build(&a), build(&b), build(&c), build(&d));
        assert_ne!(sa.hash(), sb.hash());
        assert_ne!(sa.hash(), sc.hash());
        assert_ne!(sa.hash(), sd.hash());
        assert!(!sa.ledger.faucet_enabled() && sb.ledger.faucet_enabled());
        assert!(sa.ledger.confidential_enabled() && !sc.ledger.confidential_enabled());
        for s in [&sb, &sc, &sd] {
            assert_eq!(s.ledger.state_root(), sa.ledger.state_root(), "chain switches are not state");
        }
        // The genesis ledger is positioned at the genesis block's time.
        assert_eq!(sa.ledger.timestamp_ms(), sa.block.header.timestamp_ms);
        let mut bogus = genesis(1);
        bogus.fri_profile = "bogus".into();
        assert!(matches!(bogus.build(&StubExecutor), Err(GenesisError::BadFriProfile(_))));
        assert!(a.to_json().contains("\"confidential\": true"));
    }

    fn bridge_cfg() -> BridgeConfig {
        BridgeConfig { emitter: [1; 32], guardians: vec![[2; 20]], emitters: BTreeMap::from([(2u16, [9u8; 32])]) }
    }

    /// The hard fork phase S3 ships is opt-in per chain. A genesis without a `bridge` section
    /// builds the chain phase S1 built, down to the bytes of the state root; one with a section
    /// gets a fifth state-root component and a different genesis hash.
    ///
    /// The pinned root below is phase S1's. It must not move when the bridge is merely
    /// *available* — only when a chain actually turns it on. (`shrugg-node`'s
    /// `the_genesis_hash_is_pinned` guards the whole genesis binding the same way.)
    #[test]
    fn a_bridge_section_is_accepted_and_only_a_bridged_chain_changes() {
        let plain = genesis(1);
        let s = build(&plain);
        assert!(s.ledger.bridge().is_none());
        assert_eq!(
            s.ledger.state_root().to_hex(),
            "a90970f86e480a5777f402bf73f7eb65a811fe84df32a0bbc853b34d8f18c9a1",
            "a chain without a bridge commits exactly what phase S1 committed"
        );
        assert!(!plain.to_json().contains("bridge"), "and its genesis file does not mention one");

        let mut bridged = plain.clone();
        bridged.bridge = Some(bridge_cfg());
        let sb = build(&bridged);
        assert!(sb.ledger.bridge().is_some());
        assert_ne!(sb.ledger.state_root(), s.ledger.state_root(), "the bridge root is the fifth component");
        assert_ne!(sb.hash(), s.hash(), "and the section is part of the genesis binding");
        assert!(bridged.to_json().contains("bridge"));
        // The initial guardian set is set 0 and is the one the file named.
        let bridge = sb.ledger.bridge().unwrap();
        assert_eq!(bridge.current_set, 0);
        assert_eq!(bridge.guardian_sets[&0].keys, vec![[2u8; 20]]);
        assert_eq!(bridge.emitters, BTreeMap::from([(2u16, [9u8; 32])]));
        // Two chains that differ only in their guardians are different chains.
        let mut other_guardians = bridged.clone();
        other_guardians.bridge.as_mut().unwrap().guardians = vec![[3; 20]];
        assert_ne!(build(&other_guardians).hash(), sb.hash());
    }

    /// A `bridge` section a chain could not safely run is refused at build time rather than at
    /// the first attestation.
    #[test]
    fn an_unrunnable_bridge_section_is_refused() {
        let bad = |f: fn(&mut BridgeConfig)| {
            let mut g = genesis(1);
            let mut cfg = bridge_cfg();
            f(&mut cfg);
            g.bridge = Some(cfg);
            match g.build(&StubExecutor) {
                Err(GenesisError::BadBridgeConfig(m)) => m,
                other => panic!("expected BadBridgeConfig, got {other:?}"),
            }
        };
        assert_eq!(bad(|c| c.guardians.clear()), "no guardians");
        assert_eq!(bad(|c| c.guardians = vec![[2; 20], [2; 20]]), "duplicate guardian key");
        assert_eq!(bad(|c| c.guardians = vec![[0; 20]]), "zero guardian key");
        assert_eq!(bad(|c| c.emitter = [0; 32]), "zero emitter address");
        assert_eq!(bad(|c| c.emitter = GOVERNANCE_EMITTER), "emitter is the governance emitter");
        // Rand cannot be its own source chain: that is how governance payloads are told apart.
        assert!(bad(|c| {
            c.emitters.insert(CHAIN_RAND, [9; 32]);
        })
        .contains("is Rand itself"));
        assert!(bad(|c| {
            c.emitters.insert(2, GOVERNANCE_EMITTER);
        })
        .contains("is the governance emitter"));
        assert!(bad(|c| {
            c.emitters.insert(2, [0; 32]);
        })
        .contains("zero emitter address for chain 2"));
    }

    /// S2 scaffold. `epoch_blocks` defaults, is bound, and reaches the built state;
    /// `payout` defaults, is *not* bound, and an old genesis file still parses.
    #[test]
    fn the_s2_fields_default_and_only_epoch_blocks_is_bound() {
        let g = genesis(1);
        let s = build(&g);
        assert_eq!(s.epoch_blocks, EPOCH_BLOCKS_DEFAULT);

        let mut faster = g.clone();
        faster.epoch_blocks = 4;
        let sf = build(&faster);
        assert_eq!(sf.epoch_blocks, 4);
        assert_ne!(sf.hash(), s.hash(), "epoch_blocks is part of the genesis binding");
        assert_eq!(sf.ledger.state_root(), s.ledger.state_root(), "and is not state");

        let mut paid = g.clone();
        paid.validators[0].payout = Some("shrugg1abc".into());
        assert_eq!(build(&paid).hash(), s.hash(), "payout is not bound until S2 makes it required");

        // A genesis file written before either field existed still parses, with the defaults.
        let mut old = serde_json::to_value(&g).unwrap();
        old.as_object_mut().unwrap().remove("epoch_blocks");
        let parsed = Genesis::from_json(&old.to_string()).unwrap();
        assert_eq!(parsed.epoch_blocks, EPOCH_BLOCKS_DEFAULT);
        assert!(parsed.validators.iter().all(|v| v.payout.is_none()));
        assert_eq!(build(&parsed).hash(), s.hash());
        // An unset payout stays out of the file entirely.
        assert!(!g.to_json().contains("payout"));
        assert!(g.to_json().contains("\"epoch_blocks\""));
    }

    /// S2 scaffold: `epoch(h) = h / epoch_blocks`, so a genesis file has to name a divisor the
    /// chain can actually use. Rejected at the one place that reads the file, not at the first
    /// division.
    #[test]
    fn epoch_blocks_must_be_a_usable_divisor() {
        let g = genesis(1);
        for bad in [0, MAX_EPOCH_BLOCKS + 1, u64::MAX] {
            let mut broken = g.clone();
            broken.epoch_blocks = bad;
            match broken.build(&StubExecutor) {
                Err(GenesisError::BadEpochBlocks(n)) => assert_eq!(n, bad),
                other => panic!("expected BadEpochBlocks for {bad}, got {other:?}"),
            }
        }
        // The edges that are fine: one block per epoch, and the cap itself.
        for ok in [1, EPOCH_BLOCKS_DEFAULT, MAX_EPOCH_BLOCKS] {
            let mut fine = g.clone();
            fine.epoch_blocks = ok;
            assert_eq!(build(&fine).epoch_blocks, ok);
        }
    }

    #[test]
    fn json_roundtrip_and_deterministic_hash() {
        let g = genesis(2);
        let js = g.to_json();
        let g2 = Genesis::from_json(&js).unwrap();
        assert_eq!(g, g2);
        let s1 = build(&g);
        let s2 = build(&g2);
        assert_eq!(s1.hash(), s2.hash());
        assert_eq!(s1.validators.len(), 2);
        assert_eq!(s1.ledger.validators().len(), 2);
        assert_eq!(s1.block.header.state_root, s1.ledger.state_root());
    }

    #[test]
    fn different_chain_id_changes_genesis_hash() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.chain_id = 43;
        assert_ne!(build(&a).hash(), build(&b).hash());
    }

    #[test]
    fn rejects_bad_validators() {
        let mut g = genesis(1);
        g.validators.clear();
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::NoValidators)));
        let mut g = genesis(1);
        g.validators[0].stake = 0;
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::ZeroStake(_))));
        let mut g = genesis(2);
        g.validators.push(g.validators[0].clone());
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::DuplicateValidator(_))));
        let mut g = genesis(2);
        g.validators[0].stake = u128::MAX;
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::Overflow)));
    }
}
