//! The Rand-side bridge ledger: guardian sets, bridged asset balances, the
//! consumed-digest set, and the outbound burn message log.
//!
//! Everything here is pure state transition logic; the ledger (Task C2)
//! owns persistence, fee accounting, and the block timestamp that feeds
//! `now` (unix seconds) and burn message timestamps.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bridge::{
    asset_id, digest, verify, Attestation, Body, GuardianKey, GuardianSet, Payload, Transfer,
    VerifyError, AssetId, CHAIN_RAND, GOVERNANCE_EMITTER, GUARDIAN_GRACE_SECS,
};
use crate::crypto::{merkle_root, Address, Hash};

/// The genesis-facing `bridge` section: the Rand emitter address published
/// in outbound burn messages, the initial guardian set, and the registered
/// emitter address for each source chain.
///
/// Serialized as human JSON — `emitter` and each `emitters` value as 64 hex
/// characters, each guardian as 40 hex characters, `emitters` keyed by the
/// decimal chain id as a string:
///
/// ```json
/// { "emitter": "<64 hex>", "guardians": ["<40 hex>"], "emitters": { "2": "<64 hex>" } }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    #[serde(with = "hex_bytes32")]
    pub emitter: [u8; 32],
    #[serde(with = "hex_guardians")]
    pub guardians: Vec<GuardianKey>,
    #[serde(default, with = "hex_emitters")]
    pub emitters: BTreeMap<u16, [u8; 32]>,
}

/// The plain-bytes twin of [`BridgeConfig`], used for the genesis
/// commitment.
///
/// `BridgeConfig` serializes as human-readable hex so the genesis file is
/// editable; `bincode` of that would commit to hex *strings*. The genesis
/// hash commits to this struct instead, so the bytes it covers are the
/// bytes the chain runs on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCommit {
    pub emitter: [u8; 32],
    pub guardians: Vec<GuardianKey>,
    pub emitters: BTreeMap<u16, [u8; 32]>,
}

impl From<&BridgeConfig> for BridgeCommit {
    /// Destructured on purpose: a new `BridgeConfig` field must not silently
    /// fall out of the genesis commitment — it has to break this conversion.
    fn from(cfg: &BridgeConfig) -> BridgeCommit {
        let BridgeConfig { emitter, guardians, emitters } = cfg;
        BridgeCommit {
            emitter: *emitter,
            guardians: guardians.clone(),
            emitters: emitters.clone(),
        }
    }
}

/// One outbound (Rand -> source chain) bridge message, produced by a
/// `BridgeBurn` transaction. Guardians read these over RPC and sign
/// [`BridgeBurnRecord::digest`]; a source-chain contract releases against
/// the resulting attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeBurnRecord {
    pub sequence: u64,
    /// The encoded Section 3.2 [`Body`].
    pub body: Vec<u8>,
    /// `mu = keccak256(keccak256(body))`.
    pub digest: [u8; 32],
    /// The transaction that produced this message.
    pub tx: Hash,
    pub height: u64,
}

/// The bridge ledger.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BridgeState {
    pub emitter: [u8; 32],
    pub emitters: BTreeMap<u16, [u8; 32]>,
    pub guardian_sets: BTreeMap<u32, GuardianSet>,
    pub current_set: u32,
    pub balances: BTreeMap<(AssetId, Address), u128>,
    pub assets: BTreeMap<AssetId, (u16, [u8; 32])>,
    pub spent: BTreeSet<Hash>,
    pub burn_sequence: u64,
    pub burns: BTreeMap<u64, BridgeBurnRecord>,
}

/// The small, whole-state half of a [`BridgeState`]: everything except the
/// three collections a node stores one row at a time (`balances`, `spent`,
/// `burns`).
///
/// Storage keeps this as a single `bincode` blob under one `meta` key and the
/// three collections in column families, so a commit rewrites only the rows a
/// block touched. Owning the split here — rather than in the node crate —
/// keeps it in one place: a new [`BridgeState`] field has to be classified in
/// [`BridgeState::meta`] and [`BridgeState::from_parts`] or those stop
/// compiling.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BridgeMeta {
    pub emitter: [u8; 32],
    pub emitters: BTreeMap<u16, [u8; 32]>,
    pub guardian_sets: BTreeMap<u32, GuardianSet>,
    pub current_set: u32,
    pub assets: BTreeMap<AssetId, (u16, [u8; 32])>,
    pub burn_sequence: u64,
}

/// Why a bridge transaction was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum BridgeError {
    #[error("bridge is not enabled on this chain")]
    Disabled,
    #[error("attestation verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("unregistered emitter")]
    WrongEmitter,
    #[error("transfer is not addressed to this chain")]
    WrongToChain,
    #[error("asset is not native to that chain")]
    WrongTokenChain,
    #[error("fee exceeds amount")]
    FeeExceedsAmount,
    #[error("amount does not fit in u128")]
    AmountOverflow,
    #[error("amount is zero")]
    ZeroAmount,
    #[error("undecodable payload")]
    BadPayload,
    #[error("attestation already consumed")]
    Replay,
    #[error("guardian set upgrade index: expected {expected}, got {got}")]
    BadUpgradeIndex { expected: u32, got: u32 },
    #[error("duplicate or zero guardian key")]
    DuplicateGuardian,
    #[error("unknown asset")]
    UnknownAsset,
    #[error("insufficient asset balance: have {have}, need {need}")]
    InsufficientAsset { have: u128, need: u128 },
    #[error("balance overflow")]
    Overflow,
}

/// What a successfully applied `BridgeAttest` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestOutcome {
    /// `amount` is the net credited to `to`; `fee` went to the submitter.
    Minted {
        asset: AssetId,
        to: Address,
        amount: u128,
        fee: u128,
    },
    GuardianSetUpgraded(u32),
}

impl BridgeState {
    /// Builds the genesis bridge state: guardian set 0 is the config's
    /// guardians and is current (`expires_at: 0`).
    pub fn from_config(cfg: &BridgeConfig) -> BridgeState {
        let mut guardian_sets = BTreeMap::new();
        guardian_sets.insert(
            0,
            GuardianSet {
                keys: cfg.guardians.clone(),
                expires_at: 0,
            },
        );
        BridgeState {
            emitter: cfg.emitter,
            emitters: cfg.emitters.clone(),
            guardian_sets,
            current_set: 0,
            ..Default::default()
        }
    }

    /// The whole-state half of this bridge, for storage's single `meta` blob.
    ///
    /// Destructured on purpose: a new [`BridgeState`] field must be classified
    /// as blob or column family rather than silently dropped from persistence.
    pub fn meta(&self) -> BridgeMeta {
        let BridgeState {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            balances: _,
            assets,
            spent: _,
            burn_sequence,
            burns: _,
        } = self;
        BridgeMeta {
            emitter: *emitter,
            emitters: emitters.clone(),
            guardian_sets: guardian_sets.clone(),
            current_set: *current_set,
            assets: assets.clone(),
            burn_sequence: *burn_sequence,
        }
    }

    /// Rebuilds a bridge from the two halves storage keeps apart. The inverse
    /// of [`BridgeState::meta`] plus the three row-wise collections.
    pub fn from_parts(
        meta: BridgeMeta,
        balances: BTreeMap<(AssetId, Address), u128>,
        spent: BTreeSet<Hash>,
        burns: BTreeMap<u64, BridgeBurnRecord>,
    ) -> BridgeState {
        let BridgeMeta {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            assets,
            burn_sequence,
        } = meta;
        BridgeState {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            balances,
            assets,
            spent,
            burn_sequence,
            burns,
        }
    }

    /// `addr`'s balance of bridged asset `asset`; absent means zero.
    pub fn balance(&self, asset: &AssetId, addr: &Address) -> u128 {
        self.balances.get(&(*asset, *addr)).copied().unwrap_or(0)
    }

    /// The balances a minted transfer would produce: `amount - fee` to the
    /// recipient and `fee` to `submitter`, accumulated when they are the same
    /// address. Computed before any mutation, so an overflow leaves the state
    /// untouched — and screened by `check_attest`, so `apply_attest` cannot
    /// fail on a transfer that validated.
    fn transfer_credits(
        &self,
        asset: &AssetId,
        to: Address,
        net: u128,
        submitter: Address,
        fee: u128,
    ) -> Result<BTreeMap<Address, u128>, BridgeError> {
        let mut credited: BTreeMap<Address, u128> = BTreeMap::new();
        for (addr, delta) in [(to, net), (submitter, fee)] {
            if delta == 0 {
                continue;
            }
            let current = match credited.get(&addr) {
                Some(v) => *v,
                None => self.balance(asset, &addr),
            };
            let next = current.checked_add(delta).ok_or(BridgeError::Overflow)?;
            credited.insert(addr, next);
        }
        Ok(credited)
    }

    /// Validates an encoded attestation without mutating anything: resolve
    /// the guardian set named by the envelope, verify the quorum, decode
    /// and check the payload, screen the mint credits for overflow, and
    /// reject an already-consumed digest.
    ///
    /// `submitter` is the account that would keep the transfer's bridge fee;
    /// `now` is unix seconds (the ledger passes `timestamp_ms / 1000`).
    pub fn check_attest(
        &self,
        bytes: &[u8],
        submitter: Address,
        now: u64,
    ) -> Result<(Attestation, [u8; 32], Payload), BridgeError> {
        let index = Attestation::decode(bytes)
            .map_err(VerifyError::Codec)?
            .guardian_set_index;
        let set = self
            .guardian_sets
            .get(&index)
            .ok_or(VerifyError::UnknownGuardianSet(index))?;
        let (att, mu) = verify(bytes, set, now)?;
        let payload = Payload::decode(&att.body.payload).map_err(|_| BridgeError::BadPayload)?;
        match &payload {
            Payload::Transfer(t) => {
                if self.emitters.get(&att.body.emitter_chain) != Some(&att.body.emitter_address) {
                    return Err(BridgeError::WrongEmitter);
                }
                if t.token_chain != att.body.emitter_chain {
                    return Err(BridgeError::WrongTokenChain);
                }
                if t.to_chain != CHAIN_RAND {
                    return Err(BridgeError::WrongToChain);
                }
                let amount = t.amount_u128().ok_or(BridgeError::AmountOverflow)?;
                let fee = t.fee_u128().ok_or(BridgeError::AmountOverflow)?;
                if fee > amount {
                    return Err(BridgeError::FeeExceedsAmount);
                }
                self.transfer_credits(
                    &asset_id(t.token_chain, &t.token_address),
                    Address(t.to),
                    amount - fee,
                    submitter,
                    fee,
                )?;
            }
            Payload::GuardianSetUpgrade(g) => {
                if (att.body.emitter_chain, att.body.emitter_address)
                    != (CHAIN_RAND, GOVERNANCE_EMITTER)
                {
                    return Err(BridgeError::WrongEmitter);
                }
                let expected = self.current_set.saturating_add(1);
                if g.new_index != expected {
                    return Err(BridgeError::BadUpgradeIndex {
                        expected,
                        got: g.new_index,
                    });
                }
                let unique: BTreeSet<&GuardianKey> = g.keys.iter().collect();
                if unique.len() != g.keys.len() || g.keys.iter().any(|k| k == &[0u8; 20]) {
                    return Err(BridgeError::DuplicateGuardian);
                }
            }
        }
        if self.spent.contains(&Hash(mu)) {
            return Err(BridgeError::Replay);
        }
        Ok((att, mu, payload))
    }

    /// Consumes an attestation: mints a transfer (crediting `amount - fee`
    /// to the recipient and `fee` to `submitter`) or rotates the guardian
    /// set, marking the digest spent either way. Leaves `self` untouched on
    /// error.
    pub fn apply_attest(
        &mut self,
        bytes: &[u8],
        submitter: Address,
        now: u64,
    ) -> Result<AttestOutcome, BridgeError> {
        let (_, mu, payload) = self.check_attest(bytes, submitter, now)?;
        match payload {
            Payload::Transfer(t) => {
                let asset = asset_id(t.token_chain, &t.token_address);
                let amount = t.amount_u128().expect("checked by check_attest");
                let fee = t.fee_u128().expect("checked by check_attest");
                let to = Address(t.to);
                let net = amount - fee;
                let credited = self
                    .transfer_credits(&asset, to, net, submitter, fee)
                    .expect("checked by check_attest");
                self.spent.insert(Hash(mu));
                self.assets
                    .entry(asset)
                    .or_insert((t.token_chain, t.token_address));
                for (addr, balance) in credited {
                    self.balances.insert((asset, addr), balance);
                }
                Ok(AttestOutcome::Minted {
                    asset,
                    to,
                    amount: net,
                    fee,
                })
            }
            Payload::GuardianSetUpgrade(g) => {
                self.spent.insert(Hash(mu));
                if let Some(old) = self.guardian_sets.get_mut(&self.current_set) {
                    old.expires_at = now.saturating_add(GUARDIAN_GRACE_SECS);
                }
                self.guardian_sets.insert(
                    g.new_index,
                    GuardianSet {
                        keys: g.keys,
                        expires_at: 0,
                    },
                );
                self.current_set = g.new_index;
                Ok(AttestOutcome::GuardianSetUpgraded(g.new_index))
            }
        }
    }

    /// Validates an outbound burn: the asset must be registered, `to_chain`
    /// must be the asset's home chain, `fee <= amount`, and `from` must
    /// hold at least `amount`.
    pub fn check_burn(
        &self,
        from: &Address,
        asset: &AssetId,
        amount: u128,
        to_chain: u16,
        fee: u128,
    ) -> Result<(), BridgeError> {
        let (token_chain, _) = self.assets.get(asset).ok_or(BridgeError::UnknownAsset)?;
        if to_chain != *token_chain {
            return Err(BridgeError::WrongTokenChain);
        }
        if fee > amount {
            return Err(BridgeError::FeeExceedsAmount);
        }
        if amount == 0 {
            return Err(BridgeError::ZeroAmount);
        }
        let have = self.balance(asset, from);
        if have < amount {
            return Err(BridgeError::InsufficientAsset {
                have,
                need: amount,
            });
        }
        Ok(())
    }

    /// Burns `amount` of `asset` from `from` and records the outbound
    /// message guardians will sign. `timestamp` is the block time in unix
    /// seconds. Leaves `self` untouched on error.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_burn(
        &mut self,
        from: Address,
        asset: AssetId,
        amount: u128,
        to_chain: u16,
        to: [u8; 32],
        fee: u128,
        tx: Hash,
        height: u64,
        timestamp: u32,
    ) -> Result<BridgeBurnRecord, BridgeError> {
        self.check_burn(&from, &asset, amount, to_chain, fee)?;
        let (token_chain, token_address) = self.assets[&asset];
        let remaining = self.balance(&asset, &from) - amount;
        if remaining == 0 {
            self.balances.remove(&(asset, from));
        } else {
            self.balances.insert((asset, from), remaining);
        }
        let sequence = self.burn_sequence;
        let body = Body {
            timestamp,
            nonce: 0,
            emitter_chain: CHAIN_RAND,
            emitter_address: self.emitter,
            sequence,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address,
                token_chain,
                to,
                to_chain,
                fee: Transfer::u256_from_u128(fee),
            })
            .encode(),
        }
        .encode();
        let record = BridgeBurnRecord {
            sequence,
            digest: digest(&body),
            body,
            tx,
            height,
        };
        self.burn_sequence = self.burn_sequence.saturating_add(1);
        self.burns.insert(sequence, record.clone());
        Ok(record)
    }

    /// Deterministic bridge commitment (spec 6.3):
    ///
    /// ```text
    /// blake3("shrugg-bridge-state"
    ///     || bincode(emitter, emitters, current_set, guardian_sets)
    ///     || merkle(blake3("shrugg-asset-balance" || asset || addr || balance BE))
    ///     || merkle(blake3("shrugg-asset-registry" || asset || chain BE || token))
    ///     || merkle(sorted spent digests)
    ///     || burn_sequence BE)
    /// ```
    ///
    /// The outbound emitter and the source-chain emitter table are part of
    /// the commitment: they are consensus-relevant genesis configuration.
    /// `burns` is derivable from the transaction history and is deliberately
    /// excluded. Zero balances are pruned so a never-credited holder and a
    /// drained one commit identically.
    pub fn root(&self) -> Hash {
        let balance_leaves: Vec<Hash> = self
            .balances
            .iter()
            .filter(|(_, balance)| **balance != 0)
            .map(|((asset, addr), balance)| {
                let mut buf = Vec::with_capacity(32 + 32 + 16);
                buf.extend_from_slice(asset.as_bytes());
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&balance.to_be_bytes());
                Hash::digest_domain(b"shrugg-asset-balance", &buf)
            })
            .collect();
        let registry_leaves: Vec<Hash> = self
            .assets
            .iter()
            .map(|(asset, (chain, token))| {
                let mut buf = Vec::with_capacity(32 + 2 + 32);
                buf.extend_from_slice(asset.as_bytes());
                buf.extend_from_slice(&chain.to_be_bytes());
                buf.extend_from_slice(token);
                Hash::digest_domain(b"shrugg-asset-registry", &buf)
            })
            .collect();
        let spent_leaves: Vec<Hash> = self.spent.iter().copied().collect();
        let mut buf = bincode::serialize(&(
            self.emitter,
            &self.emitters,
            self.current_set,
            &self.guardian_sets,
        ))
        .expect("bridge configuration and guardian sets serialize");
        buf.extend_from_slice(merkle_root(&balance_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&registry_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&spent_leaves).as_bytes());
        buf.extend_from_slice(&self.burn_sequence.to_be_bytes());
        Hash::digest_domain(b"shrugg-bridge-state", &buf)
    }
}

// ---------------------------------------------------------------------------
// Hex serde helpers for the genesis-facing config
// ---------------------------------------------------------------------------

fn from_hex<const N: usize, E: serde::de::Error>(s: &str) -> Result<[u8; N], E> {
    let bytes = hex::decode(s).map_err(|_| E::custom(format!("invalid hex string {s:?}")))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| E::custom(format!("expected {N} bytes, got {}", v.len())))
}

mod hex_bytes32 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        from_hex::<32, D::Error>(&s)
    }
}

mod hex_guardians {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[GuardianKey], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(hex::encode))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<GuardianKey>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| from_hex::<20, D::Error>(s))
            .collect()
    }
}

mod hex_emitters {
    use super::*;

    pub fn serialize<S: Serializer>(
        v: &BTreeMap<u16, [u8; 32]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_map(v.iter().map(|(k, a)| (k.to_string(), hex::encode(a))))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<u16, [u8; 32]>, D::Error> {
        use serde::de::Error as _;
        BTreeMap::<String, String>::deserialize(d)?
            .into_iter()
            .map(|(k, v)| {
                let chain: u16 = k
                    .parse()
                    .map_err(|_| D::Error::custom(format!("invalid chain id {k:?}")))?;
                Ok((chain, from_hex::<32, D::Error>(&v)?))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{guardian_address, sign_digest, GuardianSetUpgrade, TRANSFER_PAYLOAD_LEN};
    use crate::crypto::Keypair;

    fn key(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    /// Six guardian secrets plus a config with emitter `[1; 32]` and the
    /// four source chains registered as `{2: [2; 32], .., 5: [5; 32]}`.
    fn cfg() -> (BridgeConfig, Vec<[u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (1u8..=6).map(|i| [i; 32]).collect();
        let config = BridgeConfig {
            emitter: [1; 32],
            guardians: secrets.iter().map(guardian_address).collect(),
            emitters: (2u16..=5).map(|c| (c, [c as u8; 32])).collect(),
        };
        (config, secrets)
    }

    /// Signs `body` with the first five secrets (quorum for a set of six)
    /// and returns the encoded attestation.
    fn attest(secrets: &[[u8; 32]], set_index: u32, body: Body) -> Vec<u8> {
        let d = digest(&body.encode());
        let signatures = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
        Attestation {
            guardian_set_index: set_index,
            signatures,
            body,
        }
        .encode()
    }

    /// A governance guardian-set upgrade to `new_index` carrying `keys`.
    fn upgrade_body(new_index: u32, keys: Vec<GuardianKey>) -> Body {
        Body {
            timestamp: 100,
            nonce: 0,
            emitter_chain: CHAIN_RAND,
            emitter_address: GOVERNANCE_EMITTER,
            sequence: new_index as u64,
            consistency_level: 0,
            payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade { new_index, keys }).encode(),
        }
    }

    /// A transfer of `amount` (fee `fee`) of token `[0xaa; 32]` native to
    /// `emitter_chain`, emitted by that chain's registered emitter, to
    /// `key(1)` on `to_chain`.
    fn transfer_body(emitter_chain: u16, amount: u128, fee: u128, to_chain: u16) -> Body {
        Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain,
            emitter_address: [emitter_chain as u8; 32],
            sequence: 0,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: [0xaa; 32],
                token_chain: emitter_chain,
                to: key(1).address().0,
                to_chain,
                fee: Transfer::u256_from_u128(fee),
            })
            .encode(),
        }
    }

    #[test]
    fn mint_credits_recipient_and_fee_to_submitter() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let out = st
            .apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 10, 1)), key(9).address(), 1)
            .unwrap();
        let asset = asset_id(2, &[0xaa; 32]);
        assert_eq!(
            out,
            AttestOutcome::Minted {
                asset,
                to: key(1).address(),
                amount: 990,
                fee: 10
            }
        );
        assert_eq!(st.balance(&asset, &key(1).address()), 990);
        assert_eq!(st.balance(&asset, &key(9).address()), 10);
        assert_eq!(st.assets[&asset], (2, [0xaa; 32]));
        assert_eq!(st.spent.len(), 1);
    }

    #[test]
    fn replay_wrong_emitter_wrong_chain_fee_overflow() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let a = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        st.apply_attest(&a, key(9).address(), 1).unwrap();
        assert_eq!(
            st.apply_attest(&a, key(9).address(), 1).unwrap_err(),
            BridgeError::Replay
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_address = [9; 32];
        assert_eq!(
            st.check_attest(&attest(&s, 0, b), key(9).address(), 1).unwrap_err(),
            BridgeError::WrongEmitter
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_chain = 3; // chain-2 address presented as chain 3
        assert_eq!(
            st.check_attest(&attest(&s, 0, b), key(9).address(), 1).unwrap_err(),
            BridgeError::WrongEmitter
        );
        assert_eq!(
            st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 2)), key(9).address(), 1)
                .unwrap_err(),
            BridgeError::WrongToChain
        );
        assert_eq!(
            st.check_attest(&attest(&s, 0, transfer_body(2, 1, 2, 1)), key(9).address(), 1)
                .unwrap_err(),
            BridgeError::FeeExceedsAmount
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.payload[1] = 1; // amount top byte
        assert_eq!(
            st.check_attest(&attest(&s, 0, b), key(9).address(), 1).unwrap_err(),
            BridgeError::AmountOverflow
        );
    }

    #[test]
    fn burn_debits_and_records_message() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), key(9).address(), 1)
            .unwrap();
        let asset = asset_id(2, &[0xaa; 32]);
        let rec = st
            .apply_burn(key(1).address(), asset, 400, 2, [0x22; 32], 5, Hash::ZERO, 12, 1_700)
            .unwrap();
        assert_eq!(rec.sequence, 0);
        assert_eq!(st.burn_sequence, 1);
        assert_eq!(st.balance(&asset, &key(1).address()), 600);
        let body = Body::decode(&rec.body).unwrap();
        assert_eq!(
            (
                body.emitter_chain,
                body.emitter_address,
                body.sequence,
                body.timestamp,
                body.nonce,
                body.consistency_level
            ),
            (1, [1; 32], 0, 1_700, 0, 0)
        );
        match Payload::decode(&body.payload).unwrap() {
            Payload::Transfer(t) => {
                assert_eq!(t.amount_u128(), Some(400));
                assert_eq!(t.fee_u128(), Some(5));
                assert_eq!(
                    (t.token_chain, t.token_address, t.to_chain, t.to),
                    (2, [0xaa; 32], 2, [0x22; 32])
                );
            }
            _ => panic!(),
        }
        assert_eq!(rec.digest, digest(&rec.body));
        assert_eq!(
            st.check_burn(&key(1).address(), &asset, 601, 2, 0).unwrap_err(),
            BridgeError::InsufficientAsset {
                have: 600,
                need: 601
            }
        );
        assert_eq!(
            st.check_burn(&key(1).address(), &asset, 1, 3, 0).unwrap_err(),
            BridgeError::WrongTokenChain
        );
        assert_eq!(
            st.check_burn(&key(1).address(), &Hash::ZERO, 1, 2, 0).unwrap_err(),
            BridgeError::UnknownAsset
        );
    }

    /// `meta` + the three row-wise collections must reassemble the exact same
    /// bridge — the invariant storage's column-family layout depends on.
    #[test]
    fn meta_and_parts_round_trip() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 7, 1)), key(9).address(), 1)
            .unwrap();
        st.apply_burn(key(1).address(), asset_id(2, &[0xaa; 32]), 400, 2, [0x22; 32], 5, Hash::ZERO, 12, 1_700)
            .unwrap();
        st.apply_attest(&attest(&s, 0, upgrade_body(1, vec![[7u8; 20], [8u8; 20]])), key(9).address(), 1)
            .unwrap();
        assert!(!st.balances.is_empty() && !st.spent.is_empty() && !st.burns.is_empty());
        // The blob itself must survive bincode, which is how storage keeps it.
        let blob = bincode::serialize(&st.meta()).unwrap();
        let meta: BridgeMeta = bincode::deserialize(&blob).unwrap();
        assert_eq!(meta, st.meta());
        let rebuilt = BridgeState::from_parts(meta, st.balances.clone(), st.spent.clone(), st.burns.clone());
        assert_eq!(rebuilt, st);
        assert_eq!(rebuilt.root(), st.root());
    }

    #[test]
    fn guardian_upgrade_rotates_with_grace_and_rejects_skips() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let new_keys: Vec<GuardianKey> = s[1..]
            .iter()
            .map(guardian_address)
            .chain([guardian_address(&[7; 32])])
            .collect();
        let up = |idx: u32| Body {
            timestamp: 100,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: GOVERNANCE_EMITTER,
            sequence: idx as u64,
            consistency_level: 0,
            payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade {
                new_index: idx,
                keys: new_keys.clone(),
            })
            .encode(),
        };
        assert_eq!(
            st.check_attest(&attest(&s, 0, up(2)), key(9).address(), 100).unwrap_err(),
            BridgeError::BadUpgradeIndex {
                expected: 1,
                got: 2
            }
        );
        assert_eq!(
            st.apply_attest(&attest(&s, 0, up(1)), key(9).address(), 100)
                .unwrap(),
            AttestOutcome::GuardianSetUpgraded(1)
        );
        assert_eq!(st.current_set, 1);
        assert_eq!(st.guardian_sets[&0].expires_at, 100 + GUARDIAN_GRACE_SECS);
        assert_eq!(st.guardian_sets[&1].keys, new_keys);
        // old set still mints inside grace, not after
        assert!(st
            .check_attest(
                &attest(&s, 0, transfer_body(2, 1, 0, 1)),
                key(9).address(),
                100 + GUARDIAN_GRACE_SECS
            )
            .is_ok());
        assert_eq!(
            st.check_attest(
                &attest(&s, 0, transfer_body(2, 1, 0, 1)),
                key(9).address(),
                101 + GUARDIAN_GRACE_SECS
            )
            .unwrap_err(),
            BridgeError::Verify(VerifyError::SetExpired)
        );
    }

    #[test]
    fn root_changes_with_balances_spent_and_sequence_but_not_burn_records() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let empty_root = st.root();
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), key(9).address(), 1)
            .unwrap();
        let minted_root = st.root();
        assert_ne!(minted_root, empty_root);
        let asset = asset_id(2, &[0xaa; 32]);
        st.apply_burn(key(1).address(), asset, 400, 2, [0x22; 32], 0, Hash::ZERO, 12, 1_700)
            .unwrap();
        let burned_root = st.root();
        assert_ne!(burned_root, minted_root);
        // burn records are derivable and deliberately excluded from the root
        let mut without_burns = st.clone();
        without_burns.burns.clear();
        assert!(!st.burns.is_empty());
        assert_eq!(without_burns.root(), burned_root);
        assert_eq!(st.root(), burned_root);
    }

    #[test]
    fn config_round_trips_through_human_json() {
        let (c, _) = cfg();
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["emitter"].as_str().unwrap(), hex::encode([1u8; 32]));
        assert_eq!(json["guardians"][0].as_str().unwrap().len(), 40);
        assert_eq!(json["emitters"]["2"].as_str().unwrap(), hex::encode([2u8; 32]));
        assert_eq!(
            serde_json::from_str::<BridgeConfig>(&serde_json::to_string(&c).unwrap()).unwrap(),
            c
        );
        assert!(serde_json::from_str::<BridgeConfig>(
            r#"{"emitter":"00","guardians":[],"emitters":{}}"#
        )
        .is_err());
    }

    #[test]
    fn upgrade_rejects_duplicate_and_zero_guardian_keys() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let keys: Vec<GuardianKey> = s.iter().map(guardian_address).collect();
        let mut duplicated = keys.clone();
        duplicated[2] = duplicated[1];
        assert_eq!(
            st.check_attest(&attest(&s, 0, upgrade_body(1, duplicated)), key(9).address(), 100)
                .unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        let mut zeroed = keys.clone();
        zeroed[3] = [0u8; 20];
        assert_eq!(
            st.check_attest(&attest(&s, 0, upgrade_body(1, zeroed)), key(9).address(), 100)
                .unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        // the same upgrade with distinct, non-zero keys clears every rung
        assert!(st
            .check_attest(&attest(&s, 0, upgrade_body(1, keys)), key(9).address(), 100)
            .is_ok());
    }

    #[test]
    fn unknown_guardian_set_index_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        assert_eq!(
            st.check_attest(&attest(&s, 5, transfer_body(2, 1, 0, 1)), key(9).address(), 1)
                .unwrap_err(),
            BridgeError::Verify(VerifyError::UnknownGuardianSet(5))
        );
    }

    #[test]
    fn undecodable_payloads_are_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let mut unknown_id = transfer_body(2, 1, 0, 1);
        unknown_id.payload = vec![9u8; TRANSFER_PAYLOAD_LEN]; // payload id 9
        assert_eq!(
            st.check_attest(&attest(&s, 0, unknown_id), key(9).address(), 1).unwrap_err(),
            BridgeError::BadPayload
        );
        let mut short = transfer_body(2, 1, 0, 1);
        short.payload.truncate(TRANSFER_PAYLOAD_LEN - 1); // a 132-byte transfer
        assert_eq!(short.payload.len(), 132);
        assert_eq!(
            st.check_attest(&attest(&s, 0, short), key(9).address(), 1).unwrap_err(),
            BridgeError::BadPayload
        );
    }

    #[test]
    fn transfer_token_chain_must_match_the_emitting_chain() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let mut b = transfer_body(2, 1, 0, 1);
        // token_chain lives at payload[65..67]: id (1) + amount (32) + token_address (32)
        b.payload[65..67].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            st.check_attest(&attest(&s, 0, b), key(9).address(), 1).unwrap_err(),
            BridgeError::WrongTokenChain
        );
    }

    #[test]
    fn zero_amount_burn_is_rejected() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), key(9).address(), 1)
            .unwrap();
        let asset = asset_id(2, &[0xaa; 32]);
        assert_eq!(
            st.check_burn(&key(1).address(), &asset, 0, 2, 0).unwrap_err(),
            BridgeError::ZeroAmount
        );
        assert_eq!(
            st.apply_burn(key(1).address(), asset, 0, 2, [0x22; 32], 0, Hash::ZERO, 1, 1_700)
                .unwrap_err(),
            BridgeError::ZeroAmount
        );
        assert_eq!(st.burn_sequence, 0);
        assert!(st.burns.is_empty());
        assert_eq!(st.balance(&asset, &key(1).address()), 1_000);
    }

    /// Golden vector for the spec 6.3 commitment. Changing this hash changes
    /// consensus: every node's state root moves with it, so treat a failure
    /// here as a hard fork, never as a test to re-baseline.
    #[test]
    fn root_is_pinned_for_a_fixed_state() {
        let mut st = BridgeState::from_config(&BridgeConfig {
            emitter: [1; 32],
            guardians: vec![[0x11; 20], [0x22; 20]],
            emitters: BTreeMap::from([(2u16, [2u8; 32])]),
        });
        let asset = asset_id(2, &[0xaa; 32]);
        st.assets.insert(asset, (2, [0xaa; 32]));
        st.balances.insert((asset, Address([0x33; 32])), 1_000);
        st.spent.insert(Hash([0x44; 32]));
        st.burn_sequence = 7;
        assert_eq!(st.root().to_hex(), "c757e13d25a59234ca3c642f38fd53970051055a73a1db9bc63f2c0b3058b043");
        // the emitter and the source-chain emitter table are committed too
        let mut other_emitter = st.clone();
        other_emitter.emitter = [9; 32];
        assert_ne!(other_emitter.root(), st.root());
        let mut other_emitters = st.clone();
        other_emitters.emitters.insert(3, [3; 32]);
        assert_ne!(other_emitters.root(), st.root());
    }

    /// A mint that would overflow a `u128` balance must be caught while
    /// checking, so the ledger can never apply an attestation it validated
    /// and then fail half way through.
    #[test]
    fn mint_overflow_is_rejected_at_check_time() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let asset = asset_id(2, &[0xaa; 32]);
        let (recipient, submitter) = (key(1).address(), key(9).address());
        st.assets.insert(asset, (2, [0xaa; 32]));
        st.balances.insert((asset, recipient), u128::MAX - 1);
        let a = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        assert_eq!(st.check_attest(&a, submitter, 1).unwrap_err(), BridgeError::Overflow);
        assert_eq!(st.apply_attest(&a, submitter, 1).unwrap_err(), BridgeError::Overflow);
        // the fee credit is screened too: here the *submitter* is the one at the ceiling
        st.balances.insert((asset, recipient), 0);
        st.balances.insert((asset, submitter), u128::MAX);
        assert_eq!(st.check_attest(&a, submitter, 1).unwrap_err(), BridgeError::Overflow);
        // nothing was consumed or credited by either rejection
        assert!(st.spent.is_empty());
        assert_eq!(st.balance(&asset, &recipient), 0);
        // and the same attestation is fine once the balance has room
        st.balances.insert((asset, submitter), 0);
        assert!(st.check_attest(&a, submitter, 1).is_ok());
    }

    #[test]
    fn config_rejects_unknown_fields() {
        let json = format!(
            r#"{{"emitter":"{}","guardians":["{}"],"emiters":{{}}}}"#,
            hex::encode([1u8; 32]),
            hex::encode([0x11u8; 20])
        );
        let err = serde_json::from_str::<BridgeConfig>(&json).unwrap_err().to_string();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn config_without_emitters_parses_to_an_empty_map() {
        let json = format!(
            r#"{{"emitter":"{}","guardians":["{}"]}}"#,
            hex::encode([1u8; 32]),
            hex::encode([0x11u8; 20])
        );
        let c: BridgeConfig = serde_json::from_str(&json).unwrap();
        assert!(c.emitters.is_empty());
        assert_eq!(c.emitter, [1u8; 32]);
        assert_eq!(c.guardians, vec![[0x11u8; 20]]);
        // and such a chain can mint nothing: no emitter is registered
        assert!(BridgeState::from_config(&c).emitters.is_empty());
    }
}
