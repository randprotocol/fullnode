//! The Rand-side bridge ledger: guardian sets, the bridged asset registry,
//! the consumed-digest set, and the outbound burn message log.
//!
//! Everything here is pure state transition logic; the ledger
//! ([`crate::ledger::bridge_notes`]) owns persistence, the deposit notes an
//! attestation creates, and the block timestamp that feeds `now` (unix
//! seconds) and burn message timestamps.
//!
//! Phase S3 removed per-account balances: on the shielded chain a bridged
//! holding is a *note* whose `asset` word is the registry index below, not a
//! number next to an address. What is left here is the public half of the
//! bridge — who may attest, which assets exist and under which index, which
//! digests are consumed, and what has been burned outbound.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bridge::{
    asset_id, digest, verify_decoded, Attestation, Body, GuardianKey, GuardianSet, GuardianSetUpgrade,
    Payload, Transfer, VerifyError, AssetId, CHAIN_RAND, GOVERNANCE_EMITTER, GUARDIAN_GRACE_SECS,
};
use crate::crypto::{merkle_root, Hash};

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

/// A registered bridged asset: the wire identity guardians sign about (its
/// home chain and token address) and the dense `u32` **index** a note of that
/// asset carries in its `asset` word (spec §10).
///
/// The 32-byte [`AssetId`] does not fit a note's one-word asset field, so the
/// registry hands out indices `1, 2, …` in registration order and the pool
/// speaks in indices. Index 0 is SHRUGG and is never in this registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetInfo {
    pub chain: u16,
    pub token: [u8; 32],
    pub index: u32,
}

/// The first index the registry hands out. 0 is reserved for SHRUGG, which is
/// not a bridged asset and is never registered.
pub const FIRST_ASSET_INDEX: u32 = 1;

/// The bridge ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeState {
    pub emitter: [u8; 32],
    pub emitters: BTreeMap<u16, [u8; 32]>,
    pub guardian_sets: BTreeMap<u32, GuardianSet>,
    pub current_set: u32,
    /// Every asset an accepted attestation has ever named, with the note index
    /// assigned to it at that first registration.
    pub assets: BTreeMap<AssetId, AssetInfo>,
    /// The index the next newly registered asset gets. Consensus state, not a
    /// cache: two nodes that disagree about it would mint notes with different
    /// `asset` words from the same attestation.
    pub next_index: u32,
    pub spent: BTreeSet<Hash>,
    pub burn_sequence: u64,
    /// Every outbound burn message ever emitted, held whole in memory and
    /// cloned on every speculative block execution: known linear growth,
    /// to be drained into storage per block before ~100k burns (spec 6.3).
    pub burns: BTreeMap<u64, BridgeBurnRecord>,
}

/// `next_index` starts at [`FIRST_ASSET_INDEX`], not at zero, so a defaulted
/// bridge cannot hand a bridged asset the index SHRUGG owns. Written out
/// rather than derived for exactly that one field.
impl Default for BridgeState {
    fn default() -> BridgeState {
        BridgeState {
            emitter: [0; 32],
            emitters: BTreeMap::new(),
            guardian_sets: BTreeMap::new(),
            current_set: 0,
            assets: BTreeMap::new(),
            next_index: FIRST_ASSET_INDEX,
            spent: BTreeSet::new(),
            burn_sequence: 0,
            burns: BTreeMap::new(),
        }
    }
}

/// The small, whole-state half of a [`BridgeState`]: everything except the
/// two collections a node stores one row at a time (`spent`, `burns`).
///
/// Storage keeps this as a single `bincode` blob under one `meta` key and the
/// two collections in column families, so a commit rewrites only the rows a
/// block touched. Owning the split here — rather than in the node crate —
/// keeps it in one place: a new [`BridgeState`] field has to be classified in
/// [`BridgeState::meta`] and [`BridgeState::from_parts`] or those stop
/// compiling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMeta {
    pub emitter: [u8; 32],
    pub emitters: BTreeMap<u16, [u8; 32]>,
    pub guardian_sets: BTreeMap<u32, GuardianSet>,
    pub current_set: u32,
    pub assets: BTreeMap<AssetId, AssetInfo>,
    pub next_index: u32,
    pub burn_sequence: u64,
}

/// Mirrors [`BridgeState`]'s own default, for the same reason.
impl Default for BridgeMeta {
    fn default() -> BridgeMeta {
        BridgeState::default().meta()
    }
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
    /// A note's amount is a `u64`; the wire format's is a u256. A transfer
    /// the bridge could carry but the pool could not hold is refused rather
    /// than truncated into a note.
    #[error("amount does not fit in u64")]
    AmountTooLarge,
    #[error("amount is zero")]
    ZeroAmount,
    #[error("recipient is unusable on the destination chain")]
    BadRecipient,
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
    /// Every `u32` index has been handed out. Unreachable in practice (it
    /// takes four billion distinct registered assets) but checked so
    /// `apply_attest` cannot fail on an attestation `check_attest` accepted.
    #[error("the asset registry is full")]
    AssetRegistryFull,
}

/// A transfer attestation as the pool needs it: which asset, under which note
/// index, how much, to whom, and how much of that is the relayer's.
///
/// `amount` is the gross figure the guardians signed; the recipient's note
/// carries `amount - relayer_fee` and the relayer's carries `relayer_fee`.
/// `to_hash` is the wire `to` field, which on the shielded chain is
/// `blake3("shrugg-shielded-recipient", pk || kem_ek)` of the recipient's
/// address — the bridge never sees the address itself, only its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeTransfer {
    pub asset: AssetId,
    /// The registry entry for `asset`. When the asset is not registered yet,
    /// `info.index` is the index registration *will* assign, so the ledger can
    /// compute the deposit note's commitment while checking and get the same
    /// answer applying.
    pub info: AssetInfo,
    pub amount: u64,
    pub to_hash: [u8; 32],
    pub relayer_fee: u64,
}

/// What an attestation would do, decoded and validated but not yet applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestPlan {
    Transfer(BridgeTransfer),
    GuardianSetUpgrade(GuardianSetUpgrade),
}

/// What a successfully applied `BridgeAttest` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestOutcome {
    /// The transfer the ledger turns into deposit notes.
    Minted(BridgeTransfer),
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
            assets,
            next_index,
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
            next_index: *next_index,
            burn_sequence: *burn_sequence,
        }
    }

    /// Rebuilds a bridge from the two halves storage keeps apart. The inverse
    /// of [`BridgeState::meta`] plus the two row-wise collections.
    pub fn from_parts(
        meta: BridgeMeta,
        spent: BTreeSet<Hash>,
        burns: BTreeMap<u64, BridgeBurnRecord>,
    ) -> BridgeState {
        let BridgeMeta {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            assets,
            next_index,
            burn_sequence,
        } = meta;
        BridgeState {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            assets,
            next_index,
            spent,
            burn_sequence,
            burns,
        }
    }

    /// The note index of a registered asset, or `None` if it has never been
    /// named by an accepted attestation.
    pub fn asset_index(&self, asset: &AssetId) -> Option<u32> {
        self.assets.get(asset).map(|info| info.index)
    }

    /// The asset a note index names. `0` (SHRUGG) is never registered, so it
    /// answers `None`, as does any index beyond what has been handed out.
    pub fn asset_by_index(&self, index: u32) -> Option<AssetId> {
        self.assets.iter().find(|(_, info)| info.index == index).map(|(asset, _)| *asset)
    }

    /// The registry entry `asset` has, or the one it would get on
    /// registration. Deterministic from state, which is what lets
    /// `check_attest` hand the ledger an index before `apply_attest` writes
    /// it: both compute the same number from the same `next_index`.
    fn asset_entry(&self, asset: &AssetId, chain: u16, token: [u8; 32]) -> Result<AssetInfo, BridgeError> {
        match self.assets.get(asset) {
            Some(info) => Ok(*info),
            None if self.next_index == u32::MAX => Err(BridgeError::AssetRegistryFull),
            None => Ok(AssetInfo { chain, token, index: self.next_index }),
        }
    }

    /// Validates an encoded attestation without mutating anything: resolve
    /// the guardian set named by the envelope, reject an already-consumed
    /// digest, decode and check the payload, and only then verify the quorum.
    ///
    /// Cheap before expensive: `BridgeAttest` has a zero minimum fee, so
    /// every check that needs no signature recovery runs first. Otherwise a
    /// replayed (public, already-consumed) or mis-addressed attestation
    /// would buy a full quorum of secp256k1 recoveries on every node that
    /// validates it. The accepted set is identical either way; only which
    /// refusal is reported first changes.
    ///
    /// `now` is unix seconds (the ledger passes `timestamp_ms / 1000`). On a
    /// transfer the returned [`AttestPlan`] carries everything the pool needs
    /// to build the deposit notes; nothing about the *recipient's* shielded
    /// address is checked here, because the bridge only ever sees its hash —
    /// that comparison belongs to [`crate::ledger::bridge_notes`].
    pub fn check_attest(
        &self,
        bytes: &[u8],
        now: u64,
    ) -> Result<(Attestation, [u8; 32], AttestPlan), BridgeError> {
        // One decode for the whole check: the envelope is parsed here and
        // the already-decoded value handed to `verify_decoded`, which
        // hashes the wire body bytes rather than a re-encoding.
        let att = Attestation::decode(bytes).map_err(VerifyError::Codec)?;
        let body_bytes = Attestation::body_bytes(bytes).map_err(VerifyError::Codec)?;
        let index = att.guardian_set_index;
        let set = self
            .guardian_sets
            .get(&index)
            .ok_or(VerifyError::UnknownGuardianSet(index))?;
        let mu = digest(body_bytes);
        if self.spent.contains(&Hash(mu)) {
            return Err(BridgeError::Replay);
        }
        let payload = Payload::decode(&att.body.payload).map_err(|_| BridgeError::BadPayload)?;
        let plan = match payload {
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
                // Symmetry with `check_burn`: a zero-value mint consumes a
                // digest and moves nothing, so refuse it outright.
                if amount == 0 {
                    return Err(BridgeError::ZeroAmount);
                }
                // A note holds a `u64`. Checked after the amount relations
                // above so a malformed transfer is still reported as malformed.
                let amount = u64::try_from(amount).map_err(|_| BridgeError::AmountTooLarge)?;
                let relayer_fee = fee as u64; // fee <= amount, which fits
                let asset = asset_id(t.token_chain, &t.token_address);
                let info = self.asset_entry(&asset, t.token_chain, t.token_address)?;
                AttestPlan::Transfer(BridgeTransfer { asset, info, amount, to_hash: t.to, relayer_fee })
            }
            Payload::GuardianSetUpgrade(g) => {
                if (att.body.emitter_chain, att.body.emitter_address)
                    != (CHAIN_RAND, GOVERNANCE_EMITTER)
                {
                    return Err(BridgeError::WrongEmitter);
                }
                // A rotation must be signed by the set it replaces. The
                // grace window (spec 3.4) exists so in-flight *transfers*
                // signed by a just-superseded set are not stranded; letting
                // it also cover payload 2 would let a superseded set —
                // exactly the set a rotation may be running away from —
                // rotate the bridge again for a whole day. Parity with the
                // Solana program and the EVM contracts.
                if att.guardian_set_index != self.current_set {
                    return Err(BridgeError::Verify(VerifyError::SetExpired));
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
                AttestPlan::GuardianSetUpgrade(g)
            }
        };
        // The expensive part last: set expiry, index and quorum rule, low-s,
        // and one recovery per signature.
        let verified = verify_decoded(&att, body_bytes, set, now)?;
        debug_assert_eq!(verified, mu);
        Ok((att, mu, plan))
    }

    /// Consumes an attestation: registers the asset a transfer names (if new)
    /// and hands the transfer back for the pool to turn into notes, or rotates
    /// the guardian set — marking the digest spent either way. Leaves `self`
    /// untouched on error.
    pub fn apply_attest(&mut self, bytes: &[u8], now: u64) -> Result<AttestOutcome, BridgeError> {
        let (_, mu, plan) = self.check_attest(bytes, now)?;
        match plan {
            AttestPlan::Transfer(t) => {
                self.spent.insert(Hash(mu));
                // First sighting registers the asset under the index
                // `check_attest` already told the caller about.
                if self.assets.insert(t.asset, t.info).is_none() {
                    debug_assert_eq!(t.info.index, self.next_index);
                    self.next_index += 1;
                }
                Ok(AttestOutcome::Minted(t))
            }
            AttestPlan::GuardianSetUpgrade(g) => {
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

    /// Validates an outbound burn: `asset_index` must name a registered
    /// asset, `to_chain` must be that asset's home chain, `to` must be a
    /// usable recipient on that chain, and `relayer_fee <= amount != 0`.
    /// Returns the asset id the index names.
    ///
    /// There is no balance to check any more: what bounds a burn on the
    /// shielded chain is the asset bundle's proof, which the ledger verifies
    /// (`burn == amount + relayer_fee` in that bundle, spec §10).
    pub fn check_burn(
        &self,
        asset_index: u32,
        amount: u64,
        to_chain: u16,
        to: &[u8; 32],
        relayer_fee: u64,
    ) -> Result<AssetId, BridgeError> {
        let asset = self.asset_by_index(asset_index).ok_or(BridgeError::UnknownAsset)?;
        let info = self.assets[&asset];
        if to_chain != info.chain {
            return Err(BridgeError::WrongTokenChain);
        }
        // The burn is one-way and irreversible once the message is signed,
        // so screen the recipient here rather than leaving the source
        // contract to reject the release: a zero recipient is unspendable
        // everywhere, and on an EVM/TVM chain (2, 3, 4) `to` is a 20-byte
        // address left-padded to 32 (spec 3.5) — a non-zero upper 12 bytes
        // means the address was built for a different address space and
        // `RandBridgeBase._recipient` would revert `BadRecipient`.
        if to == &[0u8; 32] {
            return Err(BridgeError::BadRecipient);
        }
        if matches!(to_chain, 2 | 3 | 4) && to[..12] != [0u8; 12] {
            return Err(BridgeError::BadRecipient);
        }
        if relayer_fee > amount {
            return Err(BridgeError::FeeExceedsAmount);
        }
        if amount == 0 {
            return Err(BridgeError::ZeroAmount);
        }
        Ok(asset)
    }

    /// Records the outbound message guardians will sign for a burn of
    /// `amount` of the asset at `asset_index`. `tx` is the transaction hash,
    /// which stands in for the sender slot: a burn is funded by notes, so
    /// there is no sender identity to record. `timestamp` is the block time
    /// in unix seconds. Leaves `self` untouched on error.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_burn(
        &mut self,
        tx: Hash,
        asset_index: u32,
        amount: u64,
        to_chain: u16,
        to: [u8; 32],
        relayer_fee: u64,
        height: u64,
        timestamp: u32,
    ) -> Result<BridgeBurnRecord, BridgeError> {
        let asset = self.check_burn(asset_index, amount, to_chain, &to, relayer_fee)?;
        let AssetInfo { chain: token_chain, token: token_address, .. } = self.assets[&asset];
        let (amount, fee) = (amount as u128, relayer_fee as u128);
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

    /// Deterministic bridge commitment (spec 6.3, as phase S3 left it):
    ///
    /// ```text
    /// blake3("shrugg-bridge-state"
    ///     || bincode(emitter, emitters, current_set, guardian_sets)
    ///     || merkle(blake3("shrugg-asset-registry" || asset || chain BE || token || index BE))
    ///     || merkle(sorted spent digests)
    ///     || burn_sequence BE || next_index BE)
    /// ```
    ///
    /// The outbound emitter and the source-chain emitter table are part of
    /// the commitment: they are consensus-relevant genesis configuration. So
    /// are the note indices and the counter that assigns the next one — two
    /// nodes that disagreed about them would mint notes with different
    /// `asset` words from the same attestation. `burns` is derivable from the
    /// transaction history and is deliberately excluded.
    ///
    /// Per-account balances are gone (phase S3): a bridged holding is a note,
    /// and notes are committed to by the ledger's own tree.
    pub fn root(&self) -> Hash {
        let registry_leaves: Vec<Hash> = self
            .assets
            .iter()
            .map(|(asset, info)| {
                let mut buf = Vec::with_capacity(32 + 2 + 32 + 4);
                buf.extend_from_slice(asset.as_bytes());
                buf.extend_from_slice(&info.chain.to_be_bytes());
                buf.extend_from_slice(&info.token);
                buf.extend_from_slice(&info.index.to_be_bytes());
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
        buf.extend_from_slice(merkle_root(&registry_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&spent_leaves).as_bytes());
        buf.extend_from_slice(&self.burn_sequence.to_be_bytes());
        buf.extend_from_slice(&self.next_index.to_be_bytes());
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

    /// A well-formed EVM recipient: 12 zero bytes then 20 address bytes
    /// (spec 3.5), the shape `check_burn` requires for chains 2, 3 and 4.
    const EVM_TO: [u8; 32] = {
        let mut t = [0u8; 32];
        let mut i = 12;
        while i < 32 {
            t[i] = 0x22;
            i += 1;
        }
        t
    };

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

    /// A transfer of `amount` (fee `fee`) of `token`, native to
    /// `emitter_chain` and emitted by that chain's registered emitter, to the
    /// 32-byte recipient field `to_hash` on `to_chain`.
    fn token_body(emitter_chain: u16, token: [u8; 32], amount: u128, fee: u128, to_chain: u16) -> Body {
        Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain,
            emitter_address: [emitter_chain as u8; 32],
            sequence: 0,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: token,
                token_chain: emitter_chain,
                to: key(1).address().0,
                to_chain,
                fee: Transfer::u256_from_u128(fee),
            })
            .encode(),
        }
    }

    /// [`token_body`] for the canonical test token `[0xaa; 32]`.
    fn transfer_body(emitter_chain: u16, amount: u128, fee: u128, to_chain: u16) -> Body {
        token_body(emitter_chain, [0xaa; 32], amount, fee, to_chain)
    }

    /// The recipient field of the transfer bodies above, which is what the
    /// ledger compares against `blake3("shrugg-shielded-recipient", ..)`.
    fn to_hash() -> [u8; 32] {
        key(1).address().0
    }

    #[test]
    fn a_transfer_decodes_to_an_index_an_amount_and_a_recipient_hash() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let asset = asset_id(2, &[0xaa; 32]);
        // The plan is available before anything is applied, and names the index the asset is
        // about to get — the ledger needs it to compute the deposit note's commitment.
        let (_, _, plan) = st.check_attest(&attest(&s, 0, transfer_body(2, 1_000, 10, 1)), 1).unwrap();
        let want = BridgeTransfer {
            asset,
            info: AssetInfo { chain: 2, token: [0xaa; 32], index: 1 },
            amount: 1_000,
            to_hash: to_hash(),
            relayer_fee: 10,
        };
        assert_eq!(plan, AttestPlan::Transfer(want.clone()));
        let out = st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 10, 1)), 1).unwrap();
        assert_eq!(out, AttestOutcome::Minted(want));
        assert_eq!(st.assets[&asset], AssetInfo { chain: 2, token: [0xaa; 32], index: 1 });
        assert_eq!(st.asset_index(&asset), Some(1));
        assert_eq!(st.asset_by_index(1), Some(asset));
        assert_eq!(st.spent.len(), 1);
        // 0 is SHRUGG and is never handed out.
        assert_eq!(st.asset_by_index(0), None);
    }

    /// Indices are dense and assigned in registration order, and a second
    /// transfer of an already-registered asset reuses its index rather than
    /// minting a new one — the property a note's `asset` word depends on.
    #[test]
    fn asset_indices_are_assigned_once_in_registration_order() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        assert_eq!(st.next_index, FIRST_ASSET_INDEX);
        st.apply_attest(&attest(&s, 0, token_body(2, [0xaa; 32], 10, 0, 1)), 1).unwrap();
        st.apply_attest(&attest(&s, 0, token_body(3, [0xbb; 32], 10, 0, 1)), 1).unwrap();
        st.apply_attest(&attest(&s, 0, token_body(2, [0xaa; 32], 11, 0, 1)), 1).unwrap();
        assert_eq!(st.asset_index(&asset_id(2, &[0xaa; 32])), Some(1));
        assert_eq!(st.asset_index(&asset_id(3, &[0xbb; 32])), Some(2));
        assert_eq!(st.next_index, 3, "three attestations, two assets");
        assert_eq!(st.asset_by_index(2), Some(asset_id(3, &[0xbb; 32])));
        assert_eq!(st.asset_index(&Hash::ZERO), None);
    }

    #[test]
    fn replay_wrong_emitter_wrong_chain_fee_overflow() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let a = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        st.apply_attest(&a, 1).unwrap();
        assert_eq!(st.apply_attest(&a, 1).unwrap_err(), BridgeError::Replay);
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_address = [9; 32];
        assert_eq!(st.check_attest(&attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_chain = 3; // chain-2 address presented as chain 3
        assert_eq!(st.check_attest(&attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        assert_eq!(
            st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 2)), 1).unwrap_err(),
            BridgeError::WrongToChain
        );
        assert_eq!(
            st.check_attest(&attest(&s, 0, transfer_body(2, 1, 2, 1)), 1).unwrap_err(),
            BridgeError::FeeExceedsAmount
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.payload[1] = 1; // amount top byte
        assert_eq!(st.check_attest(&attest(&s, 0, b), 1).unwrap_err(), BridgeError::AmountOverflow);
    }

    /// A note's `amount` is a `u64`, so a transfer the wire format can carry
    /// but the pool cannot hold is refused at attestation time rather than
    /// truncated into a note (spec §10, `docs/bridge.md` §12).
    #[test]
    fn an_amount_above_u64_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let over = u64::MAX as u128 + 1;
        assert_eq!(
            st.check_attest(&attest(&s, 0, transfer_body(2, over, 0, 1)), 1).unwrap_err(),
            BridgeError::AmountTooLarge
        );
        // The largest amount that does fit still validates, fee and all.
        let plan = st.check_attest(&attest(&s, 0, transfer_body(2, u64::MAX as u128, 7, 1)), 1).unwrap().2;
        assert_eq!(
            plan,
            AttestPlan::Transfer(BridgeTransfer {
                asset: asset_id(2, &[0xaa; 32]),
                info: AssetInfo { chain: 2, token: [0xaa; 32], index: 1 },
                amount: u64::MAX,
                to_hash: to_hash(),
                relayer_fee: 7,
            })
        );
    }

    /// `next_index` is a `u32` and the registry never forgets an asset, so
    /// the one state in which a registration could collide with an existing
    /// index is refused while checking — `apply_attest` must not be able to
    /// fail on an attestation that validated.
    #[test]
    fn a_full_asset_registry_refuses_a_new_asset_but_not_a_known_one() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, token_body(2, [0xaa; 32], 10, 0, 1)), 1).unwrap();
        st.next_index = u32::MAX;
        assert_eq!(
            st.check_attest(&attest(&s, 0, token_body(3, [0xbb; 32], 10, 0, 1)), 1).unwrap_err(),
            BridgeError::AssetRegistryFull
        );
        // The already-registered asset needs no new index and is unaffected.
        assert!(st.check_attest(&attest(&s, 0, token_body(2, [0xaa; 32], 11, 0, 1)), 1).is_ok());
    }

    #[test]
    fn burn_records_the_message_against_an_index() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        let tx = Hash::digest(b"burn-tx");
        let rec = st.apply_burn(tx, 1, 400, 2, EVM_TO, 5, 12, 1_700).unwrap();
        assert_eq!(rec.sequence, 0);
        assert_eq!(st.burn_sequence, 1);
        assert_eq!(rec.tx, tx, "the transaction hash stands in for the absent sender");
        let body = Body::decode(&rec.body).unwrap();
        assert_eq!(
            (body.emitter_chain, body.emitter_address, body.sequence, body.timestamp, body.nonce, body.consistency_level),
            (1, [1; 32], 0, 1_700, 0, 0)
        );
        match Payload::decode(&body.payload).unwrap() {
            Payload::Transfer(t) => {
                assert_eq!(t.amount_u128(), Some(400));
                assert_eq!(t.fee_u128(), Some(5));
                assert_eq!((t.token_chain, t.token_address, t.to_chain, t.to), (2, [0xaa; 32], 2, EVM_TO));
            }
            _ => panic!(),
        }
        assert_eq!(rec.digest, digest(&rec.body));
        // There is no balance to run out of any more: the asset bundle's proof is what bounds
        // a burn. What is left here is the registry and the destination.
        assert_eq!(st.check_burn(1, u64::MAX, 2, &EVM_TO, 0), Ok(asset_id(2, &[0xaa; 32])));
        assert_eq!(st.check_burn(1, 1, 3, &EVM_TO, 0).unwrap_err(), BridgeError::WrongTokenChain);
        assert_eq!(st.check_burn(2, 1, 2, &EVM_TO, 0).unwrap_err(), BridgeError::UnknownAsset);
        assert_eq!(st.check_burn(0, 1, 2, &EVM_TO, 0).unwrap_err(), BridgeError::UnknownAsset, "0 is SHRUGG");
        assert_eq!(st.check_burn(1, 10, 2, &EVM_TO, 11).unwrap_err(), BridgeError::FeeExceedsAmount);
    }

    /// `meta` + the two row-wise collections must reassemble the exact same
    /// bridge — the invariant storage's column-family layout depends on.
    #[test]
    fn meta_and_parts_round_trip() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 7, 1)), 1).unwrap();
        st.apply_burn(Hash::ZERO, 1, 400, 2, EVM_TO, 5, 12, 1_700).unwrap();
        st.apply_attest(&attest(&s, 0, upgrade_body(1, vec![[7u8; 20], [8u8; 20]])), 1).unwrap();
        assert!(!st.assets.is_empty() && !st.spent.is_empty() && !st.burns.is_empty());
        // The blob itself must survive bincode, which is how storage keeps it.
        let blob = bincode::serialize(&st.meta()).unwrap();
        let meta: BridgeMeta = bincode::deserialize(&blob).unwrap();
        assert_eq!(meta, st.meta());
        assert_eq!(meta.next_index, 2, "the index counter is part of the blob, not derived");
        let rebuilt = BridgeState::from_parts(meta, st.spent.clone(), st.burns.clone());
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
            st.check_attest(&attest(&s, 0, up(2)), 100).unwrap_err(),
            BridgeError::BadUpgradeIndex { expected: 1, got: 2 }
        );
        assert_eq!(st.apply_attest(&attest(&s, 0, up(1)), 100).unwrap(), AttestOutcome::GuardianSetUpgraded(1));
        assert_eq!(st.current_set, 1);
        assert_eq!(st.guardian_sets[&0].expires_at, 100 + GUARDIAN_GRACE_SECS);
        assert_eq!(st.guardian_sets[&1].keys, new_keys);
        // old set still mints inside grace, not after
        assert!(st
            .check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 1)), 100 + GUARDIAN_GRACE_SECS)
            .is_ok());
        assert_eq!(
            st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 1)), 101 + GUARDIAN_GRACE_SECS)
                .unwrap_err(),
            BridgeError::Verify(VerifyError::SetExpired)
        );
    }

    #[test]
    fn root_changes_with_the_registry_spent_and_sequence_but_not_burn_records() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let empty_root = st.root();
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        let minted_root = st.root();
        assert_ne!(minted_root, empty_root, "a registered asset and a consumed digest");
        st.apply_burn(Hash::ZERO, 1, 400, 2, EVM_TO, 0, 12, 1_700).unwrap();
        let burned_root = st.root();
        assert_ne!(burned_root, minted_root, "the burn sequence moved");
        // burn records are derivable and deliberately excluded from the root
        let mut without_burns = st.clone();
        without_burns.burns.clear();
        assert!(!st.burns.is_empty());
        assert_eq!(without_burns.root(), burned_root);
        assert_eq!(st.root(), burned_root);
        // ... but an asset's index is not: two registries that differ only in which index an
        // asset holds would mint notes with different `asset` words.
        let mut renumbered = st.clone();
        let asset = asset_id(2, &[0xaa; 32]);
        renumbered.assets.get_mut(&asset).unwrap().index = 9;
        assert_ne!(renumbered.root(), burned_root);
        let mut recounted = st.clone();
        recounted.next_index = 9;
        assert_ne!(recounted.root(), burned_root, "the next index is what a future note will carry");
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
            st.check_attest(&attest(&s, 0, upgrade_body(1, duplicated)), 100).unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        let mut zeroed = keys.clone();
        zeroed[3] = [0u8; 20];
        assert_eq!(
            st.check_attest(&attest(&s, 0, upgrade_body(1, zeroed)), 100).unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        // the same upgrade with distinct, non-zero keys clears every rung
        assert!(st.check_attest(&attest(&s, 0, upgrade_body(1, keys)), 100).is_ok());
    }

    #[test]
    fn unknown_guardian_set_index_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        assert_eq!(
            st.check_attest(&attest(&s, 5, transfer_body(2, 1, 0, 1)), 1).unwrap_err(),
            BridgeError::Verify(VerifyError::UnknownGuardianSet(5))
        );
    }

    #[test]
    fn undecodable_payloads_are_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let mut unknown_id = transfer_body(2, 1, 0, 1);
        unknown_id.payload = vec![9u8; TRANSFER_PAYLOAD_LEN]; // payload id 9
        assert_eq!(st.check_attest(&attest(&s, 0, unknown_id), 1).unwrap_err(), BridgeError::BadPayload);
        let mut short = transfer_body(2, 1, 0, 1);
        short.payload.truncate(TRANSFER_PAYLOAD_LEN - 1); // a 132-byte transfer
        assert_eq!(short.payload.len(), 132);
        assert_eq!(st.check_attest(&attest(&s, 0, short), 1).unwrap_err(), BridgeError::BadPayload);
    }

    #[test]
    fn transfer_token_chain_must_match_the_emitting_chain() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let mut b = transfer_body(2, 1, 0, 1);
        // token_chain lives at payload[65..67]: id (1) + amount (32) + token_address (32)
        b.payload[65..67].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(st.check_attest(&attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongTokenChain);
    }

    #[test]
    fn zero_amount_burn_is_rejected() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        assert_eq!(st.check_burn(1, 0, 2, &EVM_TO, 0).unwrap_err(), BridgeError::ZeroAmount);
        assert_eq!(
            st.apply_burn(Hash::ZERO, 1, 0, 2, EVM_TO, 0, 1, 1_700).unwrap_err(),
            BridgeError::ZeroAmount
        );
        assert_eq!(st.burn_sequence, 0);
        assert!(st.burns.is_empty());
    }

    /// Spec 3.4/3.6: the grace window covers transfer payloads only. A
    /// payload-2 rotation must additionally carry
    /// `guardian_set_index == current_set`, so a set that has already been
    /// superseded cannot rotate the bridge again while its grace period
    /// runs. Parity with the Solana program and the EVM contracts.
    #[test]
    fn guardian_upgrade_must_be_signed_by_the_current_set() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        // Set 1 = guardians 2..=6 plus a 7th key, so `&s[1..]` signs for it
        // with indices 0..=4 exactly as `attest` lays them out.
        let set1_keys: Vec<GuardianKey> = s[1..]
            .iter()
            .map(guardian_address)
            .chain([guardian_address(&[7; 32])])
            .collect();
        st.apply_attest(&attest(&s, 0, upgrade_body(1, set1_keys.clone())), 100).unwrap();
        assert_eq!(st.current_set, 1);
        // Set 0 is superseded but still inside its grace window ...
        assert!(st.guardian_sets[&0].expires_at > 100);
        let set2_keys: Vec<GuardianKey> = (10u8..=15).map(|i| [i; 20]).collect();
        // ... which buys it nothing on a rotation.
        assert_eq!(
            st.check_attest(&attest(&s, 0, upgrade_body(2, set2_keys.clone())), 100).unwrap_err(),
            BridgeError::Verify(VerifyError::SetExpired)
        );
        // The very same upgrade signed by the current set is accepted.
        assert_eq!(
            st.apply_attest(&attest(&s[1..], 1, upgrade_body(2, set2_keys.clone())), 100).unwrap(),
            AttestOutcome::GuardianSetUpgraded(2)
        );
        assert_eq!(st.current_set, 2);
        assert_eq!(st.guardian_sets[&2].keys, set2_keys);
        // Transfers, by contrast, still ride the grace window (spec 3.4).
        assert!(st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 1)), 100).is_ok());
    }

    /// Symmetry with `check_burn`: a zero-value mint would consume a digest
    /// and move nothing.
    #[test]
    fn zero_amount_transfer_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        assert_eq!(
            st.check_attest(&attest(&s, 0, transfer_body(2, 0, 0, 1)), 1).unwrap_err(),
            BridgeError::ZeroAmount
        );
        // ... and a non-zero amount over the same path still validates.
        assert!(st.check_attest(&attest(&s, 0, transfer_body(2, 1, 0, 1)), 1).is_ok());
    }

    /// A burn is irreversible once guardians sign it, so an unspendable
    /// recipient is refused before the message exists rather than left for
    /// the source contract to reject.
    #[test]
    fn burn_rejects_zero_and_wrongly_shaped_recipients() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        // A chain-5 (Solana) asset, to prove the upper-12-bytes rule is
        // scoped to the EVM-family chains.
        st.apply_attest(&attest(&s, 0, token_body(5, [0xbb; 32], 1_000, 0, 1)), 1).unwrap();
        let (evm, sol) = (1u32, 2u32);
        assert_eq!(st.asset_by_index(sol), Some(asset_id(5, &[0xbb; 32])));

        // Zero recipient: unspendable on every chain.
        assert_eq!(st.check_burn(evm, 1, 2, &[0u8; 32], 0).unwrap_err(), BridgeError::BadRecipient);
        assert_eq!(st.check_burn(sol, 1, 5, &[0u8; 32], 0).unwrap_err(), BridgeError::BadRecipient);
        // Dirty upper 12 bytes on an EVM-family chain (2, 3, 4).
        let mut dirty = EVM_TO;
        dirty[11] = 1;
        assert_eq!(st.check_burn(evm, 1, 2, &dirty, 0).unwrap_err(), BridgeError::BadRecipient);
        // A full 32-byte Solana pubkey is fine on chain 5.
        assert!(st.check_burn(sol, 1, 5, &[0x22u8; 32], 0).is_ok());
        // ... and a left-padded address is fine on chain 2.
        assert!(st.check_burn(evm, 1, 2, &EVM_TO, 0).is_ok());
        // `apply_burn` refuses it too and records nothing.
        assert_eq!(
            st.apply_burn(Hash::ZERO, evm, 1, 2, dirty, 0, 1, 1_700).unwrap_err(),
            BridgeError::BadRecipient
        );
        assert_eq!(st.burn_sequence, 0);
        assert!(st.burns.is_empty());
    }

    /// Golden vector for the spec 6.3 commitment. Changing this hash changes
    /// consensus: every node's state root moves with it, so treat a failure
    /// here as a hard fork, never as a test to re-baseline.
    ///
    /// Re-pinned exactly once, in phase S3 (`docs/superpowers/plans/2026-09-12-shielded-pool-s3.md`):
    /// per-account `balances` left `BridgeState` altogether and the asset
    /// registry gained the dense note index (and its `next_index` counter),
    /// so the commitment's second component is a registry leaf with an index
    /// in it and the balance leaves are gone. That *is* the hard fork this
    /// phase ships; the previous value was c757e13d25a59234ca3c642f38fd53970051055a73a1db9bc63f2c0b3058b043.
    #[test]
    fn root_is_pinned_for_a_fixed_state() {
        let mut st = BridgeState::from_config(&BridgeConfig {
            emitter: [1; 32],
            guardians: vec![[0x11; 20], [0x22; 20]],
            emitters: BTreeMap::from([(2u16, [2u8; 32])]),
        });
        let asset = asset_id(2, &[0xaa; 32]);
        st.assets.insert(asset, AssetInfo { chain: 2, token: [0xaa; 32], index: 1 });
        st.next_index = 2;
        st.spent.insert(Hash([0x44; 32]));
        st.burn_sequence = 7;
        assert_eq!(st.root().to_hex(), "ee50b48c82eacf7aca2a1bdb33b32b7c98b1a255e645c9ba12dde9d060c43dc8");
        // the emitter and the source-chain emitter table are committed too
        let mut other_emitter = st.clone();
        other_emitter.emitter = [9; 32];
        assert_ne!(other_emitter.root(), st.root());
        let mut other_emitters = st.clone();
        other_emitters.emitters.insert(3, [3; 32]);
        assert_ne!(other_emitters.root(), st.root());
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

    /// `attest`, but signed by six keys outside the set, so the quorum
    /// check can only fail: a submission rejected with any *other* error
    /// was rejected before signature recovery ran.
    fn misattest(set_index: u32, body: Body) -> Vec<u8> {
        let strangers: Vec<[u8; 32]> = (11u8..=16).map(|i| [i; 32]).collect();
        attest(&strangers, set_index, body)
    }

    /// Cheap-before-expensive (fullnode d5143a6, applied to the bridge):
    /// everything that needs no signature recovery — replay, emitter
    /// binding, payload shape and amounts, the rotation index — is decided
    /// first, so a replayed or mis-addressed attestation cannot buy the
    /// quorum's secp256k1 recoveries at the zero minimum fee. The set of
    /// accepted attestations is unchanged; only the order of refusals is.
    #[test]
    fn cheap_checks_run_before_signature_recovery() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        st.apply_attest(&attest(&s, 0, transfer_body(2, 1_000, 10, 1)), 1).unwrap();
        // A consumed digest is public knowledge and free to resubmit.
        assert_eq!(
            st.check_attest(&misattest(0, transfer_body(2, 1_000, 10, 1)), 1).unwrap_err(),
            BridgeError::Replay
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_address = [9; 32];
        assert_eq!(st.check_attest(&misattest(0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        assert_eq!(
            st.check_attest(&misattest(0, transfer_body(2, 1, 0, 2)), 1).unwrap_err(),
            BridgeError::WrongToChain
        );
        assert_eq!(
            st.check_attest(&misattest(0, transfer_body(2, 1, 2, 1)), 1).unwrap_err(),
            BridgeError::FeeExceedsAmount
        );
        assert_eq!(
            st.check_attest(&misattest(0, transfer_body(2, 0, 0, 1)), 1).unwrap_err(),
            BridgeError::ZeroAmount
        );
        assert_eq!(
            st.check_attest(&misattest(0, transfer_body(2, u64::MAX as u128 + 1, 0, 1)), 1).unwrap_err(),
            BridgeError::AmountTooLarge
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.payload[0] = 9; // unknown payload id
        assert_eq!(st.check_attest(&misattest(0, b), 1).unwrap_err(), BridgeError::BadPayload);
        let keys = vec![guardian_address(&[21; 32])];
        assert_eq!(
            st.check_attest(&misattest(0, upgrade_body(5, keys)), 1).unwrap_err(),
            BridgeError::BadUpgradeIndex { expected: 1, got: 5 }
        );
        // Well-formed and fresh: now the quorum is what fails.
        assert!(matches!(
            st.check_attest(&misattest(0, transfer_body(2, 1, 0, 1)), 1).unwrap_err(),
            BridgeError::Verify(VerifyError::WrongGuardian(_))
        ));
    }
}
