//! The Rand-side bridge ledger: guardian sets, the consumed-digest set, and
//! the outbound burn message log.
//!
//! Everything here is pure state transition logic; the ledger
//! ([`crate::ledger::bridge_notes`]) owns persistence, the deposit notes an
//! attestation creates, and the block timestamp that feeds `now` (unix
//! seconds) and burn message timestamps.
//!
//! Phase S3 removed per-account balances: on the shielded chain a bridged
//! holding is a *note* whose `asset` word is a dense registry index, not a
//! number next to an address. The RPL token standard then removed the
//! bridge's *own* registry: the indices live in
//! [`crate::ledger::tokens::TokenRegistry`], one registry for bridged and
//! native assets alike, and the bridge is a reader of it. A bridged token is
//! **listed** — in genesis, or by a later governance message — and never
//! registered by first sighting, so an attestation naming a token nobody
//! listed is [`BridgeError::UnlistedToken`] rather than a new index.
//!
//! What is left here is the public half of the bridge — who may attest, which
//! digests are consumed, and what has been burned outbound.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bridge::{
    digest, verify_decoded, Attestation, Body, GuardianKey, GuardianSet, GuardianSetUpgrade,
    Payload, Transfer, VerifyError, AssetId, CHAIN_RAND, GOVERNANCE_EMITTER, GUARDIAN_GRACE_SECS,
};
use crate::crypto::{merkle_root, Hash};
use crate::ledger::tokens::{MintAuthority, TokenError, TokenRegistry};

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeState {
    pub emitter: [u8; 32],
    pub emitters: BTreeMap<u16, [u8; 32]>,
    pub guardian_sets: BTreeMap<u32, GuardianSet>,
    pub current_set: u32,
    pub spent: BTreeSet<Hash>,
    pub burn_sequence: u64,
    /// Every outbound burn message ever emitted, held whole in memory and
    /// cloned on every speculative block execution: known linear growth,
    /// to be drained into storage per block before ~100k burns (spec 6.3).
    pub burns: BTreeMap<u64, BridgeBurnRecord>,
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMeta {
    pub emitter: [u8; 32],
    pub emitters: BTreeMap<u16, [u8; 32]>,
    pub guardian_sets: BTreeMap<u32, GuardianSet>,
    pub current_set: u32,
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
    /// A burn's `asset_index` names no token in the registry, or names one
    /// that is not bridged (its mint authority is not
    /// [`MintAuthority::Bridge`], so there is no home chain to release on and
    /// no wire identity to put in the outbound message).
    #[error("unknown asset")]
    UnknownAsset,
    /// The attestation names a `(chain, token)` pair nobody listed on this
    /// chain. Bridged tokens are listed — at genesis, or by a governance
    /// message — and never registered by first sighting, so this is the
    /// refusal that used to be a fresh index. It replaces `AssetRegistryFull`,
    /// which only existed because first sighting could run out of indices.
    #[error("token {} of chain {chain} is not listed on this chain", hex::encode(token))]
    UnlistedToken { chain: u16, token: [u8; 32] },
    /// What the token registry refused about a deposit or a redemption: the named
    /// `(chain, token)` is not a backing of the asset
    /// ([`crate::ledger::tokens::TokenError::NotABacking`]), the backing holds less than the
    /// burn asks for ([`crate::ledger::tokens::TokenError::InsufficientBacking`]), or a lock
    /// would overflow it. One bridged token has many backings (spec §12), so these are the
    /// registry's verdicts to give and the bridge carries them rather than restating them.
    #[error("{0}")]
    Token(#[from] TokenError),
}

/// A transfer attestation as the pool needs it: which asset, under which note
/// index, how much, and to whom.
///
/// `amount` is the gross figure the guardians signed, and the gross figure is
/// what the deposit note carries — see `deposit_commitment` in
/// [`crate::ledger::bridge_notes`]. The relayer fee is *not* deducted: on a
/// shielded chain the submitter has no identity to pay, so netting it would
/// burn the difference and the pool would stop holding what the source chain
/// locked.
///
/// `to_hash` is the wire `to` field, which on the shielded chain is
/// `blake3("rand-shielded-recipient", pk || kem_ek)` of the recipient's
/// address — the bridge never sees the address itself, only its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeTransfer {
    /// The registry id of the token this deposit mints — the *token's* id (its registration
    /// fields, `tokens::bridged_asset_id`), not the per-backing wire id: one bridged token has
    /// many backings and they all mint the same asset.
    pub asset: AssetId,
    /// The token registry's dense index for `asset` — the note's `asset` word.
    /// A fact, not a prediction: the token was listed before this attestation
    /// arrived and its index never moves, so check and apply cannot disagree
    /// about it and no submitter can lose a race for it.
    pub index: u32,
    /// The backing this deposit locks against: the source chain and token address the
    /// attestation named, which is the pair whose `locked` moves (spec §12). Carried on the plan
    /// so apply locks exactly the backing check resolved.
    pub chain: u16,
    pub token: [u8; 32],
    pub amount: u64,
    pub to_hash: [u8; 32],
    /// Carried for the record — the figure the source chain meant for whoever
    /// relayed this attestation. The pool pays no relayer.
    pub relayer_fee: u64,
}

/// What an attestation would do, decoded and validated but not yet applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestPlan {
    Transfer(BridgeTransfer),
    GuardianSetUpgrade(GuardianSetUpgrade),
}

/// An attestation that has passed [`BridgeState::check_attest`] in full: decoded, screened
/// against this state, and its guardian quorum verified.
///
/// Only `check_attest` can build one — the fields are private — and
/// [`BridgeState::apply_attest`] takes one instead of raw bytes. That is what makes the quorum
/// verification happen exactly *once* per attestation: the ledger checks in its validate step
/// and hands the token to its apply step, rather than paying for a second round of secp256k1
/// recoveries there.
///
/// It carries the `now` it was judged at, so the grace window a rotation opens cannot drift
/// from the time the quorum was checked against. It is valid only against the state that
/// produced it, so check and apply against the same [`BridgeState`], which is what the ledger
/// does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedAttestation {
    /// `mu`, the consumed-digest key.
    digest: [u8; 32],
    now: u64,
    plan: AttestPlan,
}

impl CheckedAttestation {
    /// What applying this attestation would do. The ledger reads it to compute a deposit note's
    /// commitment before committing to anything.
    pub fn plan(&self) -> &AttestPlan {
        &self.plan
    }

    /// `mu`, the digest that goes into the consumed set.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
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
            spent: _,
            burn_sequence,
            burns: _,
        } = self;
        BridgeMeta {
            emitter: *emitter,
            emitters: emitters.clone(),
            guardian_sets: guardian_sets.clone(),
            current_set: *current_set,
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
            burn_sequence,
        } = meta;
        BridgeState {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            spent,
            burn_sequence,
            burns,
        }
    }

    /// Validates an encoded attestation without mutating anything: resolve
    /// the guardian set named by the envelope, reject an already-consumed
    /// digest, decode and check the payload, and only then verify the quorum.
    ///
    /// Cheap before expensive: `BridgeAttest`'s attestation-specific fee is
    /// zero (its floor is the bundle base like any transaction), so every
    /// check that needs no signature recovery runs first. Otherwise a
    /// replayed (public, already-consumed) or mis-addressed attestation
    /// would buy a full quorum of secp256k1 recoveries on every node that
    /// validates it. The accepted set is identical either way; only which
    /// refusal is reported first changes.
    ///
    /// `now` is unix seconds (the ledger passes `timestamp_ms / 1000`). On a
    /// transfer the returned plan carries everything the pool needs to build
    /// the deposit notes; nothing about the *recipient's* shielded address is
    /// checked here, because the bridge only ever sees its hash — that
    /// comparison belongs to [`crate::ledger::bridge_notes`].
    ///
    /// The result is the only thing [`BridgeState::apply_attest`] accepts, so
    /// an attestation is verified here and nowhere else.
    ///
    /// `tokens` is the chain's one asset registry (the RPL token standard):
    /// a transfer's note index is read from it, and a `(chain, token)` pair
    /// nobody listed is [`BridgeError::UnlistedToken`]. A lookup, so it runs
    /// with the other cheap checks, before the quorum.
    pub fn check_attest(
        &self,
        tokens: &TokenRegistry,
        bytes: &[u8],
        now: u64,
    ) -> Result<CheckedAttestation, BridgeError> {
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
                // The one registry: a bridged token is listed there before it
                // can be deposited, and its index is what a note carries. An
                // unlisted pair is refused rather than given a fresh index —
                // no first sighting, so no race for the index an envelope was
                // sealed against.
                //
                // `bridged` resolves through the backing map, into which only a
                // `MintAuthority::Bridge` registration ever writes, so an
                // attestation cannot reach a token of any other authority: the
                // asymmetry `check_burn` has always had (it demands a `Bridge`
                // token) is closed here rather than assumed.
                let info = tokens
                    .bridged(t.token_chain, &t.token_address)
                    .ok_or(BridgeError::UnlistedToken { chain: t.token_chain, token: t.token_address })?;
                let (asset, index) = (info.id, info.index);
                // Everything the ledger's `lock` would refuse, decided here, while this is still
                // a comparison: this backing's `locked` overflowing, then the token's supply.
                // The ledger applies the deposit note *before* it locks, so a refusal there
                // would be a half-applied transaction.
                tokens.check_lock(index, t.token_chain, &t.token_address, amount)?;
                AttestPlan::Transfer(BridgeTransfer {
                    asset,
                    index,
                    chain: t.token_chain,
                    token: t.token_address,
                    amount,
                    to_hash: t.to,
                    relayer_fee,
                })
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
        Ok(CheckedAttestation { digest: mu, now, plan })
    }

    /// Consumes a [`CheckedAttestation`]: hands a transfer back for the pool
    /// to turn into notes, or rotates the guardian set — marking the digest
    /// spent either way.
    ///
    /// It registers nothing: a bridged token is listed before it can be
    /// deposited, so the only writes here are the consumed digest and, for a
    /// rotation, the guardian sets. The token's supply is the ledger's to
    /// credit ([`crate::ledger::bridge_notes`]), beside the deposit note.
    ///
    /// Infallible, and deliberately so: everything that could refuse an
    /// attestation was decided by [`BridgeState::check_attest`], so there is
    /// no half-applied state to unwind and no reason to verify the quorum a
    /// second time.
    pub fn apply_attest(&mut self, checked: CheckedAttestation) -> AttestOutcome {
        let CheckedAttestation { digest: mu, now, plan } = checked;
        self.spent.insert(Hash(mu));
        match plan {
            AttestPlan::Transfer(t) => AttestOutcome::Minted(t),
            AttestPlan::GuardianSetUpgrade(g) => {
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
                AttestOutcome::GuardianSetUpgraded(g.new_index)
            }
        }
    }

    /// Validates an outbound burn: `asset_index` must name a **bridged** token
    /// in `tokens` — one whose mint authority is [`MintAuthority::Bridge`],
    /// which is the only kind with source-chain coins to release — the pair
    /// `(to_chain, token)` must be one of that token's backings, `amount` and
    /// `relayer_fee` must each be a whole number of that backing's release
    /// unit, that backing must hold at least `amount`, `to` must be a usable
    /// recipient on `to_chain`, and `relayer_fee <= amount != 0`.
    ///
    /// A registered but non-bridged token (a native RPL token, whose supply
    /// moves by its own mint authority and never crossed this bridge) is
    /// [`BridgeError::UnknownAsset`], exactly as an index nothing was ever
    /// registered under: from the bridge's side there is no such asset. The
    /// registry cannot name a source chain and token address for it, which is
    /// what an outbound message is made of.
    ///
    /// One bridged token has many backings (spec §12), so a burn names the coin
    /// it redeems: a pair that backs nothing, or that backs a *different* token,
    /// is [`crate::ledger::tokens::TokenError::NotABacking`], and asking for
    /// more than that coin's contract is holding is
    /// [`crate::ledger::tokens::TokenError::InsufficientBacking`] — even when
    /// the token's whole supply would cover it. That is the check that keeps a
    /// burn from succeeding here and failing to release on the source chain.
    ///
    /// The release unit is the second half of that (bridge-06/audit O-5): the
    /// attestation wire carries amounts at eight decimals, so a coin declaring
    /// fewer releases in units of `10^(8-decimals)` and anything else would
    /// either strand a remainder in custody or, below one unit, release
    /// nothing — [`crate::ledger::tokens::TokenError::NotReleasable`], for the
    /// amount and for the relayer fee alike, since the far side carves the fee
    /// out of the amount in native units too.
    ///
    /// The pool-side bound is elsewhere: what a burner may destroy is what the
    /// asset bundle's proof says they hold (`burn == amount` in that bundle,
    /// spec §10). The registry's own move is the ledger's to make, in the same
    /// step that appends the asset bundle's notes — and everything it could
    /// refuse is decided here ([`TokenRegistry::check_release`]), so that step
    /// cannot fail.
    #[allow(clippy::too_many_arguments)]
    pub fn check_burn(
        &self,
        tokens: &TokenRegistry,
        asset_index: u32,
        amount: u64,
        to_chain: u16,
        token: &[u8; 32],
        to: &[u8; 32],
        relayer_fee: u64,
    ) -> Result<(), BridgeError> {
        // A bridged token at all, before anything about the coin: an index that names no token,
        // or one of another authority, is the bridge's `UnknownAsset` rather than a backing
        // refusal about a token this bridge has nothing to do with.
        if !is_bridged(tokens, asset_index) {
            return Err(BridgeError::UnknownAsset);
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
        // The coin: it must back *this* token, hold what is being redeemed, and release a whole
        // number of native units of `amount` and of `relayer_fee` (bridge-06/audit O-5) — exactly
        // what `TokenRegistry::release` would refuse, so the ledger's apply step cannot.
        tokens.check_release(asset_index, to_chain, token, amount, relayer_fee)?;
        Ok(())
    }

    /// Records the outbound message guardians will sign for a burn of
    /// `amount` of the asset at `asset_index`, releasing the backing
    /// `(to_chain, token)`. `tx` is the transaction hash, which stands in for
    /// the sender slot: a burn is funded by notes, so there is no sender
    /// identity to record. `timestamp` is the block time in unix seconds.
    /// Leaves `self` untouched on error.
    ///
    /// The message names the *backing's* chain and token address, which is the
    /// pair the burner chose and the pair whose `locked` the ledger releases —
    /// so the coin this chain stops counting is the coin the source contract
    /// pays out (spec §12).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_burn(
        &mut self,
        tokens: &TokenRegistry,
        tx: Hash,
        asset_index: u32,
        amount: u64,
        to_chain: u16,
        token: [u8; 32],
        to: [u8; 32],
        relayer_fee: u64,
        height: u64,
        timestamp: u32,
    ) -> Result<BridgeBurnRecord, BridgeError> {
        self.check_burn(tokens, asset_index, amount, to_chain, &token, &to, relayer_fee)?;
        // The check above resolved exactly this backing, so the message is built from what the
        // burn named rather than from a second lookup that could disagree with it.
        let (token_chain, token_address) = (to_chain, token);
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

    /// Deterministic bridge commitment (spec 6.3, as the RPL token standard
    /// left it):
    ///
    /// ```text
    /// blake3("rand-bridge-state-2"
    ///     || bincode(emitter, emitters, current_set, guardian_sets)
    ///     || merkle(sorted spent digests)
    ///     || burn_sequence BE)
    /// ```
    ///
    /// The outbound emitter and the source-chain emitter table are part of
    /// the commitment: they are consensus-relevant genesis configuration.
    /// `burns` is derivable from the transaction history and is deliberately
    /// excluded.
    ///
    /// The asset registry is *not* here any more, and neither is the counter
    /// that used to assign the next index: both moved to
    /// [`crate::ledger::tokens::TokenRegistry`], which the state root commits
    /// to with its own `tokens_root` component. Committing them twice would
    /// only give two places for the same fact to disagree. That move is the
    /// domain bump — `rand-bridge-state-2` — and it is a hard fork for a
    /// bridged chain (chain 14's cut), byte-for-byte nothing for a chain
    /// without a `bridge` section, which has no bridge root at all.
    ///
    /// Per-account balances are gone (phase S3): a bridged holding is a note,
    /// and notes are committed to by the ledger's own tree.
    pub fn root(&self) -> Hash {
        let spent_leaves: Vec<Hash> = self.spent.iter().copied().collect();
        let mut buf = bincode::serialize(&(
            self.emitter,
            &self.emitters,
            self.current_set,
            &self.guardian_sets,
        ))
        .expect("bridge configuration and guardian sets serialize");
        buf.extend_from_slice(merkle_root(&spent_leaves).as_bytes());
        buf.extend_from_slice(&self.burn_sequence.to_be_bytes());
        Hash::digest_domain(b"rand-bridge-state-2", &buf)
    }
}

/// Whether a note's `asset` word names a token this bridge can release at all: one registered
/// with a [`MintAuthority::Bridge`], which is the only kind that has source-chain coins behind
/// it.
///
/// An index nothing is registered under and an index whose token is native are the same thing
/// from the bridge's side — [`BridgeError::UnknownAsset`], an index it can name no source-chain
/// identity for. *Which* coin is released is the burn's own `(to_chain, token)`, checked against
/// the token's backings by [`TokenRegistry::check_release`].
fn is_bridged(tokens: &TokenRegistry, asset_index: u32) -> bool {
    matches!(tokens.get(asset_index).map(|info| &info.authority), Some(MintAuthority::Bridge { .. }))
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

pub(crate) mod hex_bytes32 {
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

    /// The canonical test token, native to chain 2.
    const TOKEN: [u8; 32] = [0xaa; 32];
    /// A second test token, listed for chain 3 in the index test and for chain 5 (Solana) in the
    /// recipient-shape one — a token address is only unique together with its chain.
    const OTHER_TOKEN: [u8; 32] = [0xbb; 32];

    /// An empty token registry, charging the genesis minimum.
    fn tokens() -> TokenRegistry {
        TokenRegistry::new(1_000_000_000)
    }

    /// Lists a bridged token backed by `pairs` — what genesis (or a governance
    /// message) does before any attestation of one of those coins can be
    /// accepted. Returns the index it was given. `salt` keeps two listings in
    /// one test distinct, since a bridged id is over the registration fields
    /// and no longer over a `(chain, token)` pair.
    fn list_backed_by(tokens: &mut TokenRegistry, salt: u8, pairs: &[(u16, [u8; 32])]) -> u32 {
        tokens
            .register(
                crate::ledger::tokens::bridged_asset_id("Rand USD", "zUSD", &[salt; 32]),
                "Rand USD".into(),
                "zUSD".into(),
                8,
                MintAuthority::Bridge {
                    backings: pairs
                        .iter()
                        .map(|&(chain, token)| crate::ledger::tokens::Backing { chain, token, decimals: 8, locked: 0 })
                        .collect(),
                },
                0,
            )
            .expect("a fresh listing")
    }

    /// One coin as its own token, the shape the tests that predate many-backings assume.
    fn list(tokens: &mut TokenRegistry, chain: u16, token: [u8; 32]) -> u32 {
        list_backed_by(tokens, chain as u8 ^ token[0], &[(chain, token)])
    }

    /// A registry with [`TOKEN`] listed at index 1, the shape most tests want, with enough
    /// locked against its one backing that a burn in these tests is never the thing refused.
    fn tokens_with_the_test_token() -> TokenRegistry {
        let mut t = tokens();
        assert_eq!(list(&mut t, 2, TOKEN), 1);
        t.lock(1, 2, &TOKEN, 1_000_000).expect("the fixture's locked backing");
        t
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

    /// Check then apply, which is what a test wants when the plan in between
    /// is not the point. The ledger keeps the two halves apart on purpose: it
    /// checks in its validate step and applies the token in its apply step, so
    /// the quorum is verified once.
    fn apply(
        st: &mut BridgeState,
        tokens: &TokenRegistry,
        bytes: &[u8],
        now: u64,
    ) -> Result<AttestOutcome, BridgeError> {
        let checked = st.check_attest(tokens, bytes, now)?;
        Ok(st.apply_attest(checked))
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

    /// [`token_body`] for the canonical test token.
    fn transfer_body(emitter_chain: u16, amount: u128, fee: u128, to_chain: u16) -> Body {
        token_body(emitter_chain, TOKEN, amount, fee, to_chain)
    }

    /// The recipient field of the transfer bodies above, which is what the
    /// ledger compares against `blake3("rand-shielded-recipient", ..)`.
    fn to_hash() -> [u8; 32] {
        key(1).address().0
    }

    /// The guardian quorum is verified in `check_attest` and nowhere else. `apply_attest` takes
    /// the token that check produced — whose fields are private, so only `check_attest` can make
    /// one — and returns an outcome rather than a `Result`, because there is nothing left for it
    /// to refuse. That signature is the guarantee; this test pins it.
    #[test]
    fn an_attestation_is_verified_once_and_then_applied_from_its_token() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let body = transfer_body(2, 1_000, 10, 1);
        let mu = digest(&body.encode());
        let bytes = attest(&s, 0, body);

        let checked = st.check_attest(&tk, &bytes, 1).unwrap();
        assert_eq!(checked.digest(), mu);
        assert!(matches!(checked.plan(), AttestPlan::Transfer(_)));
        // No `unwrap`: applying a checked attestation cannot fail.
        let out: AttestOutcome = st.apply_attest(checked);
        assert!(matches!(out, AttestOutcome::Minted(_)));
        assert!(st.spent.contains(&Hash(mu)));
        // And the token cannot be made again: the digest is consumed, so a second attempt is a
        // replay — which is refused before any signature is recovered.
        assert_eq!(st.check_attest(&tk, &bytes, 1).unwrap_err(), BridgeError::Replay);
    }

    #[test]
    fn a_transfer_decodes_to_an_index_an_amount_and_a_recipient_hash() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        // The token's own registry id, not the per-backing wire id: one token, many coins.
        let asset = tk.get(1).unwrap().id;
        // The plan is available before anything is applied, and names the index the listing gave
        // the token, plus the coin the attestation deposits against — the ledger needs the first
        // to compute the deposit note's commitment and the second to lock the right backing.
        let plan = st.check_attest(&tk, &attest(&s, 0, transfer_body(2, 1_000, 10, 1)), 1).unwrap().plan().clone();
        let want = BridgeTransfer { asset, index: 1, chain: 2, token: TOKEN, amount: 1_000, to_hash: to_hash(), relayer_fee: 10 };
        assert_eq!(plan, AttestPlan::Transfer(want.clone()));
        let out = apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 10, 1)), 1).unwrap();
        assert_eq!(out, AttestOutcome::Minted(want));
        assert_eq!(st.spent.len(), 1);
    }

    /// The rule this task installs: a bridged token is **listed**, never registered by first
    /// sighting, so an attestation naming a pair nobody listed is refused — and once listed, the
    /// index its deposits carry is the registry's, decided before the attestation existed.
    #[test]
    fn an_unlisted_token_is_refused_and_a_listed_one_deposits_under_its_index() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let mut tk = tokens();
        let att = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        assert!(matches!(
            st.check_attest(&tk, &att, 1),
            Err(BridgeError::UnlistedToken { chain: 2, token }) if token == TOKEN
        ));
        assert_eq!(list(&mut tk, 2, TOKEN), 1);
        let checked = st.check_attest(&tk, &att, 1).unwrap();
        assert!(matches!(checked.plan(), AttestPlan::Transfer(BridgeTransfer { index: 1, .. })));
    }

    /// Indices belong to the token registry and to the listing order there, not to the order
    /// attestations happen to arrive in: a token listed second deposits under index 2 however
    /// many times the first one has been attested.
    #[test]
    fn a_deposit_carries_the_index_its_listing_was_given() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let mut tk = tokens();
        assert_eq!(list(&mut tk, 2, TOKEN), 1);
        assert_eq!(list(&mut tk, 3, OTHER_TOKEN), 2);
        let index = |out: AttestOutcome| match out {
            AttestOutcome::Minted(t) => t.index,
            _ => panic!("a transfer"),
        };
        assert_eq!(index(apply(&mut st, &tk, &attest(&s, 0, token_body(3, OTHER_TOKEN, 10, 0, 1)), 1).unwrap()), 2);
        assert_eq!(index(apply(&mut st, &tk, &attest(&s, 0, token_body(2, TOKEN, 10, 0, 1)), 1).unwrap()), 1);
        assert_eq!(index(apply(&mut st, &tk, &attest(&s, 0, token_body(2, TOKEN, 11, 0, 1)), 1).unwrap()), 1);
        // And applying registers nothing: the registry is exactly what the listings left.
        assert_eq!(tk.len(), 2);
        assert_eq!(tk.bridged(2, &TOKEN).unwrap().index, 1);
        assert_eq!(tk.bridged(3, &OTHER_TOKEN).unwrap().index, 2);
    }

    #[test]
    fn replay_wrong_emitter_wrong_chain_fee_overflow() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let a = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        apply(&mut st, &tk, &a, 1).unwrap();
        assert_eq!(apply(&mut st, &tk, &a, 1).unwrap_err(), BridgeError::Replay);
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_address = [9; 32];
        assert_eq!(st.check_attest(&tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_chain = 3; // chain-2 address presented as chain 3
        assert_eq!(st.check_attest(&tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, transfer_body(2, 1, 0, 2)), 1).unwrap_err(),
            BridgeError::WrongToChain
        );
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, transfer_body(2, 1, 2, 1)), 1).unwrap_err(),
            BridgeError::FeeExceedsAmount
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.payload[1] = 1; // amount top byte
        assert_eq!(st.check_attest(&tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::AmountOverflow);
    }

    /// A note's `amount` is a `u64`, so a transfer the wire format can carry
    /// but the pool cannot hold is refused at attestation time rather than
    /// truncated into a note (spec §10, `docs/bridge.md` §12).
    #[test]
    fn an_amount_above_u64_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        // Nothing locked yet, so the largest amount a note can hold is still lockable: with the
        // fixture's million already against this coin it would be the backing that overflowed.
        let mut tk = tokens();
        assert_eq!(list(&mut tk, 2, TOKEN), 1);
        let over = u64::MAX as u128 + 1;
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, transfer_body(2, over, 0, 1)), 1).unwrap_err(),
            BridgeError::AmountTooLarge
        );
        // The largest amount that does fit still validates, fee and all.
        let plan = st.check_attest(&tk, &attest(&s, 0, transfer_body(2, u64::MAX as u128, 7, 1)), 1).unwrap().plan().clone();
        assert_eq!(
            plan,
            AttestPlan::Transfer(BridgeTransfer {
                asset: tk.get(1).unwrap().id,
                index: 1,
                chain: 2,
                token: TOKEN,
                amount: u64::MAX,
                to_hash: to_hash(),
                relayer_fee: 7,
            })
        );
        // And once that coin is holding anything at all, the same transfer is refused before a
        // single signature is recovered: `check_attest` decides what `lock` would refuse, so the
        // ledger's apply step cannot be the thing that discovers it.
        tk.lock(1, 2, &TOKEN, 1).unwrap();
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, transfer_body(2, u64::MAX as u128, 7, 1)), 1).unwrap_err(),
            BridgeError::Token(TokenError::SupplyOverflow)
        );
    }

    /// A token listed under a mint authority that is not [`MintAuthority::Bridge`] is no asset
    /// of this bridge's: an attestation cannot reach it (it is keyed by a different asset id)
    /// and a burn naming its index is refused, because the registry can name no home chain or
    /// token address to put in the outbound message.
    #[test]
    fn a_token_that_is_not_bridged_is_no_asset_of_the_bridges() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let mut tk = tokens_with_the_test_token();
        let pk = crate::crypto::Keypair::from_seed([9; 32]).unwrap().public_key().clone();
        let native = crate::ledger::tokens::native_asset_id("Native", "NTV", 9, &MintAuthority::Key(pk.clone()), &None, &[7; 32]);
        assert_eq!(tk.register(native, "Native".into(), "NTV".into(), 9, MintAuthority::Key(pk), 0).unwrap(), 2);
        assert_eq!(st.check_burn(&tk, 2, 1, 2, &TOKEN, &EVM_TO, 0).unwrap_err(), BridgeError::UnknownAsset);
        assert_eq!(
            st.apply_burn(&tk, Hash::ZERO, 2, 1, 2, TOKEN, EVM_TO, 0, 1, 1_700).unwrap_err(),
            BridgeError::UnknownAsset
        );
        // The bridged one beside it is unaffected.
        assert_eq!(st.check_burn(&tk, 1, 1, 2, &TOKEN, &EVM_TO, 0), Ok(()));
        // And an attestation of the *unlisted* pair is still refused, listing or no listing.
        assert!(matches!(
            st.check_attest(&tk, &attest(&s, 0, token_body(3, OTHER_TOKEN, 10, 0, 1)), 1),
            Err(BridgeError::UnlistedToken { chain: 3, .. })
        ));
    }

    #[test]
    fn burn_records_the_message_against_an_index() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        let tx = Hash::digest(b"burn-tx");
        let rec = st.apply_burn(&tk, tx, 1, 400, 2, TOKEN, EVM_TO, 5, 12, 1_700).unwrap();
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
                assert_eq!((t.token_chain, t.token_address, t.to_chain, t.to), (2, TOKEN, 2, EVM_TO));
            }
            _ => panic!(),
        }
        assert_eq!(rec.digest, digest(&rec.body));
        // The pool-side bound is the asset bundle's proof; what is left here is the registry,
        // the coin and the destination. The coin is bounded by its *own* locked amount — this
        // fixture locked a million against chain 2's TOKEN — not by the whole supply.
        assert_eq!(
            st.check_burn(&tk, 1, u64::MAX, 2, &TOKEN, &EVM_TO, 0).unwrap_err(),
            BridgeError::Token(TokenError::InsufficientBacking { locked: 1_000_000, amount: u64::MAX })
        );
        assert_eq!(st.check_burn(&tk, 1, 1_000_000, 2, &TOKEN, &EVM_TO, 0), Ok(()), "exactly what is locked");
        // A chain this token has no coin on is not a backing of it — the verdict that replaced
        // `WrongTokenChain`, which could only ever mean one home chain.
        assert_eq!(
            st.check_burn(&tk, 1, 1, 3, &TOKEN, &EVM_TO, 0).unwrap_err(),
            BridgeError::Token(TokenError::NotABacking { index: 1, chain: 3 })
        );
        // And the right chain with the wrong coin on it is the same refusal.
        assert_eq!(
            st.check_burn(&tk, 1, 1, 2, &OTHER_TOKEN, &EVM_TO, 0).unwrap_err(),
            BridgeError::Token(TokenError::NotABacking { index: 1, chain: 2 })
        );
        assert_eq!(st.check_burn(&tk, 2, 1, 2, &TOKEN, &EVM_TO, 0).unwrap_err(), BridgeError::UnknownAsset);
        assert_eq!(st.check_burn(&tk, 0, 1, 2, &TOKEN, &EVM_TO, 0).unwrap_err(), BridgeError::UnknownAsset, "0 is RAND");
        assert_eq!(st.check_burn(&tk, 1, 10, 2, &TOKEN, &EVM_TO, 11).unwrap_err(), BridgeError::FeeExceedsAmount);
    }

    /// `meta` + the two row-wise collections must reassemble the exact same
    /// bridge — the invariant storage's column-family layout depends on.
    #[test]
    fn meta_and_parts_round_trip() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 7, 1)), 1).unwrap();
        st.apply_burn(&tk, Hash::ZERO, 1, 400, 2, TOKEN, EVM_TO, 5, 12, 1_700).unwrap();
        apply(&mut st, &tk, &attest(&s, 0, upgrade_body(1, vec![[7u8; 20], [8u8; 20]])), 1).unwrap();
        assert!(!st.spent.is_empty() && !st.burns.is_empty());
        // The blob itself must survive bincode, which is how storage keeps it.
        let blob = bincode::serialize(&st.meta()).unwrap();
        let meta: BridgeMeta = bincode::deserialize(&blob).unwrap();
        assert_eq!(meta, st.meta());
        assert_eq!(meta.current_set, 1, "the rotation is part of the blob, not derived");
        let rebuilt = BridgeState::from_parts(meta, st.spent.clone(), st.burns.clone());
        assert_eq!(rebuilt, st);
        assert_eq!(rebuilt.root(), st.root());
    }

    #[test]
    fn guardian_upgrade_rotates_with_grace_and_rejects_skips() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
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
            st.check_attest(&tk, &attest(&s, 0, up(2)), 100).unwrap_err(),
            BridgeError::BadUpgradeIndex { expected: 1, got: 2 }
        );
        assert_eq!(apply(&mut st, &tk, &attest(&s, 0, up(1)), 100).unwrap(), AttestOutcome::GuardianSetUpgraded(1));
        assert_eq!(st.current_set, 1);
        assert_eq!(st.guardian_sets[&0].expires_at, 100 + GUARDIAN_GRACE_SECS);
        assert_eq!(st.guardian_sets[&1].keys, new_keys);
        // old set still mints inside grace, not after
        assert!(st
            .check_attest(&tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 100 + GUARDIAN_GRACE_SECS)
            .is_ok());
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 101 + GUARDIAN_GRACE_SECS)
                .unwrap_err(),
            BridgeError::Verify(VerifyError::SetExpired)
        );
    }

    #[test]
    fn root_changes_with_the_spent_set_and_the_sequence_but_not_burn_records() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let empty_root = st.root();
        apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        let minted_root = st.root();
        assert_ne!(minted_root, empty_root, "a consumed digest");
        st.apply_burn(&tk, Hash::ZERO, 1, 400, 2, TOKEN, EVM_TO, 0, 12, 1_700).unwrap();
        let burned_root = st.root();
        assert_ne!(burned_root, minted_root, "the burn sequence moved");
        // burn records are derivable and deliberately excluded from the root
        let mut without_burns = st.clone();
        without_burns.burns.clear();
        assert!(!st.burns.is_empty());
        assert_eq!(without_burns.root(), burned_root);
        assert_eq!(st.root(), burned_root);
        // A rotation is committed to, as the one other thing an attestation can write.
        let mut rotated = st.clone();
        apply(&mut rotated, &tk, &attest(&s, 0, upgrade_body(1, vec![[7u8; 20], [8u8; 20]])), 1).unwrap();
        assert_ne!(rotated.root(), burned_root);
    }

    /// The registry left this commitment: a token's index, its metadata and its supply are the
    /// token registry's to commit to (`TokenRegistry::root`, its own component of the state
    /// root), and the bridge root does not move when a token is listed or its supply changes.
    /// Committing the same fact twice only creates two places for it to disagree.
    #[test]
    fn the_bridge_root_no_longer_moves_with_the_token_registry() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let mut tk = tokens_with_the_test_token();
        apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        let before = st.root();
        let tokens_before = tk.root();
        list(&mut tk, 3, OTHER_TOKEN);
        tk.lock(1, 2, &TOKEN, 1_000).unwrap();
        assert_eq!(st.root(), before, "the bridge root is blind to the registry");
        assert_ne!(tk.root(), tokens_before, "which is exactly what the tokens root is for");
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
        let tk = tokens_with_the_test_token();
        let keys: Vec<GuardianKey> = s.iter().map(guardian_address).collect();
        let mut duplicated = keys.clone();
        duplicated[2] = duplicated[1];
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, upgrade_body(1, duplicated)), 100).unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        let mut zeroed = keys.clone();
        zeroed[3] = [0u8; 20];
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, upgrade_body(1, zeroed)), 100).unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        // the same upgrade with distinct, non-zero keys clears every rung
        assert!(st.check_attest(&tk, &attest(&s, 0, upgrade_body(1, keys)), 100).is_ok());
    }

    #[test]
    fn unknown_guardian_set_index_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 5, transfer_body(2, 1, 0, 1)), 1).unwrap_err(),
            BridgeError::Verify(VerifyError::UnknownGuardianSet(5))
        );
    }

    #[test]
    fn undecodable_payloads_are_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let mut unknown_id = transfer_body(2, 1, 0, 1);
        unknown_id.payload = vec![9u8; TRANSFER_PAYLOAD_LEN]; // payload id 9
        assert_eq!(st.check_attest(&tk, &attest(&s, 0, unknown_id), 1).unwrap_err(), BridgeError::BadPayload);
        let mut short = transfer_body(2, 1, 0, 1);
        short.payload.truncate(TRANSFER_PAYLOAD_LEN - 1); // a 132-byte transfer
        assert_eq!(short.payload.len(), 132);
        assert_eq!(st.check_attest(&tk, &attest(&s, 0, short), 1).unwrap_err(), BridgeError::BadPayload);
    }

    #[test]
    fn transfer_token_chain_must_match_the_emitting_chain() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let mut b = transfer_body(2, 1, 0, 1);
        // token_chain lives at payload[65..67]: id (1) + amount (32) + token_address (32)
        b.payload[65..67].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(st.check_attest(&tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongTokenChain);
    }

    #[test]
    fn zero_amount_burn_is_rejected() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        assert_eq!(st.check_burn(&tk, 1, 0, 2, &TOKEN, &EVM_TO, 0).unwrap_err(), BridgeError::ZeroAmount);
        assert_eq!(
            st.apply_burn(&tk, Hash::ZERO, 1, 0, 2, TOKEN, EVM_TO, 0, 1, 1_700).unwrap_err(),
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
        let tk = tokens_with_the_test_token();
        // Set 1 = guardians 2..=6 plus a 7th key, so `&s[1..]` signs for it
        // with indices 0..=4 exactly as `attest` lays them out.
        let set1_keys: Vec<GuardianKey> = s[1..]
            .iter()
            .map(guardian_address)
            .chain([guardian_address(&[7; 32])])
            .collect();
        apply(&mut st, &tk, &attest(&s, 0, upgrade_body(1, set1_keys.clone())), 100).unwrap();
        assert_eq!(st.current_set, 1);
        // Set 0 is superseded but still inside its grace window ...
        assert!(st.guardian_sets[&0].expires_at > 100);
        let set2_keys: Vec<GuardianKey> = (10u8..=15).map(|i| [i; 20]).collect();
        // ... which buys it nothing on a rotation.
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, upgrade_body(2, set2_keys.clone())), 100).unwrap_err(),
            BridgeError::Verify(VerifyError::SetExpired)
        );
        // The very same upgrade signed by the current set is accepted.
        assert_eq!(
            apply(&mut st, &tk, &attest(&s[1..], 1, upgrade_body(2, set2_keys.clone())), 100).unwrap(),
            AttestOutcome::GuardianSetUpgraded(2)
        );
        assert_eq!(st.current_set, 2);
        assert_eq!(st.guardian_sets[&2].keys, set2_keys);
        // Transfers, by contrast, still ride the grace window (spec 3.4).
        assert!(st.check_attest(&tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 100).is_ok());
    }

    /// Symmetry with `check_burn`: a zero-value mint would consume a digest
    /// and move nothing.
    #[test]
    fn zero_amount_transfer_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        assert_eq!(
            st.check_attest(&tk, &attest(&s, 0, transfer_body(2, 0, 0, 1)), 1).unwrap_err(),
            BridgeError::ZeroAmount
        );
        // ... and a non-zero amount over the same path still validates.
        assert!(st.check_attest(&tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 1).is_ok());
    }

    /// A burn is irreversible once guardians sign it, so an unspendable
    /// recipient is refused before the message exists rather than left for
    /// the source contract to reject.
    #[test]
    fn burn_rejects_zero_and_wrongly_shaped_recipients() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let mut tk = tokens_with_the_test_token();
        // A chain-5 (Solana) asset beside it, to prove the upper-12-bytes rule is
        // scoped to the EVM-family chains.
        let (evm, sol) = (1u32, list(&mut tk, 5, OTHER_TOKEN));
        assert_eq!(sol, 2);
        // Both coins have to be holding something for a burn of them to get past the backing
        // check at all — that is the registry's business, not this state's.
        tk.lock(sol, 5, &OTHER_TOKEN, 1_000).unwrap();
        apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 0, 1)), 1).unwrap();
        apply(&mut st, &tk, &attest(&s, 0, token_body(5, OTHER_TOKEN, 1_000, 0, 1)), 1).unwrap();

        // Zero recipient: unspendable on every chain.
        assert_eq!(st.check_burn(&tk, evm, 1, 2, &TOKEN, &[0u8; 32], 0).unwrap_err(), BridgeError::BadRecipient);
        assert_eq!(st.check_burn(&tk, sol, 1, 5, &OTHER_TOKEN, &[0u8; 32], 0).unwrap_err(), BridgeError::BadRecipient);
        // Dirty upper 12 bytes on an EVM-family chain (2, 3, 4).
        let mut dirty = EVM_TO;
        dirty[11] = 1;
        assert_eq!(st.check_burn(&tk, evm, 1, 2, &TOKEN, &dirty, 0).unwrap_err(), BridgeError::BadRecipient);
        // A full 32-byte Solana pubkey is fine on chain 5.
        assert!(st.check_burn(&tk, sol, 1, 5, &OTHER_TOKEN, &[0x22u8; 32], 0).is_ok());
        // ... and a left-padded address is fine on chain 2.
        assert!(st.check_burn(&tk, evm, 1, 2, &TOKEN, &EVM_TO, 0).is_ok());
        // `apply_burn` refuses it too and records nothing.
        assert_eq!(
            st.apply_burn(&tk, Hash::ZERO, evm, 1, 2, TOKEN, dirty, 0, 1, 1_700).unwrap_err(),
            BridgeError::BadRecipient
        );
        assert_eq!(st.burn_sequence, 0);
        assert!(st.burns.is_empty());
    }

    /// The three things bridge-06's guardian signer checks before it will sign an outbound
    /// transfer — asserted on the body this chain actually emits, because a body that fails any
    /// of them is a burn whose value nobody can ever release:
    ///
    /// 1. `token_chain == to_chain`. The signer refuses to release a coin on a chain that is not
    ///    the coin's own. A RandProtocol burn is always a redemption of one of the token's
    ///    backings, so [`BridgeState::apply_burn`] builds both fields from the one backing the
    ///    burner chose and the two are equal by construction rather than by a later check.
    /// 2. `emitter_address` is the genesis `bridge.emitter`, the single address the guardians
    ///    watch — a body from anywhere else is not this chain's.
    /// 3. On the EVM-family chains (2, 3, 4), the upper 12 bytes of **both** `to` and
    ///    `token_address` are zero: each is a 20-byte address left-padded to 32, and
    ///    `RandBridgeBase` reverts on either. `to` is this chain's own rule, refused in validate
    ///    (`check_burn`, asserted below as well as in
    ///    `burn_rejects_zero_and_wrongly_shaped_recipients`); `token_address` comes from the
    ///    genesis listing, which is why this fixture uses chain 14's real Ethereum USDT address
    ///    rather than a synthetic one — a listing that got it wrong is a genesis mistake, not a
    ///    per-burn one.
    #[test]
    fn the_outbound_burn_body_satisfies_the_guardians_signing_policy() {
        // Ethereum USDT and Solana USDT, verbatim from `chain14-zusd-backings.md`, behind one
        // zUSD — the real shape the policy is checked against.
        let eth_usdt: [u8; 32] = hex::decode("000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7")
            .unwrap()
            .try_into()
            .unwrap();
        let sol_usdt: [u8; 32] = hex::decode("ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264")
            .unwrap()
            .try_into()
            .unwrap();
        let (c, _) = cfg();
        let mut st = BridgeState::from_config(&c);
        let mut tk = tokens();
        let zusd = list_backed_by(&mut tk, 0x5a, &[(2, eth_usdt), (5, sol_usdt)]);
        tk.lock(zusd, 2, &eth_usdt, 1_000_000).unwrap();
        tk.lock(zusd, 5, &sol_usdt, 1_000_000).unwrap();

        // Each backing in turn: the chain-2 coin to an EVM recipient, the chain-5 coin to a full
        // 32-byte Solana pubkey.
        for (to_chain, token, to) in [(2u16, eth_usdt, EVM_TO), (5, sol_usdt, [0x22u8; 32])] {
            let rec = st.apply_burn(&tk, Hash::ZERO, zusd, 100, to_chain, token, to, 0, 1, 1_700).unwrap();
            let body = Body::decode(&rec.body).unwrap();
            assert_eq!(body.emitter_address, c.emitter, "the one emitter the guardians watch");
            assert_eq!(body.emitter_chain, CHAIN_RAND);
            let Payload::Transfer(t) = Payload::decode(&body.payload).unwrap() else { panic!("a transfer") };
            assert_eq!(t.token_chain, t.to_chain, "the coin is released on the chain it is sent to");
            assert_eq!(t.to_chain, to_chain);
            assert_eq!(t.token_address, token, "the backing the burner chose, not a second lookup");
            if matches!(to_chain, 2 | 3 | 4) {
                assert_eq!(t.to[..12], [0u8; 12], "a left-padded 20-byte recipient");
                assert_eq!(t.token_address[..12], [0u8; 12], "and a left-padded 20-byte token");
            }
        }

        // And the `to` half of rule 3 is a refusal, not only a property of well-formed burns: an
        // address with a dirty upper half never reaches a body at all.
        let mut dirty = EVM_TO;
        dirty[0] = 1;
        assert_eq!(st.check_burn(&tk, zusd, 100, 2, &eth_usdt, &dirty, 0).unwrap_err(), BridgeError::BadRecipient);
        assert_eq!(st.burn_sequence, 2, "and the two well-formed burns are all that were recorded");
    }

    /// Golden vector for the spec 6.3 commitment. Changing this hash changes
    /// consensus: every node's state root moves with it, so treat a failure
    /// here as a hard fork, never as a test to re-baseline.
    ///
    /// Re-pinned twice. Phase S3 (`docs/superpowers/plans/2026-09-12-shielded-pool-s3.md`):
    /// per-account `balances` left `BridgeState` altogether and the asset
    /// registry gained the dense note index (and its `next_index` counter), so
    /// the commitment's second component became a registry leaf with an index
    /// in it and the balance leaves were gone — the value before that was
    /// c757e13d25a59234ca3c642f38fd53970051055a73a1db9bc63f2c0b3058b043.
    /// The RPL token standard: the asset registry and `next_index` moved to
    /// [`crate::ledger::tokens::TokenRegistry`], whose own root is a component
    /// of the state root, so the registry leaves and the counter left this
    /// commitment and the domain became `rand-bridge-state-2` — the value
    /// before that was
    /// 89555202bad2a2c36210636e3f33a9c559cb6145c7b1be7548352f9ba642cf5b.
    #[test]
    fn root_is_pinned_for_a_fixed_state() {
        let mut st = BridgeState::from_config(&BridgeConfig {
            emitter: [1; 32],
            guardians: vec![[0x11; 20], [0x22; 20]],
            emitters: BTreeMap::from([(2u16, [2u8; 32])]),
        });
        st.spent.insert(Hash([0x44; 32]));
        st.burn_sequence = 7;
        assert_eq!(st.root().to_hex(), "2504a9da5f62f2ef092493e4c38a8a47560340d0394b1d3721b5aceb6366e141");
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
    /// quorum's secp256k1 recoveries at the bridge's zero attestation
    /// surcharge. The set of
    /// accepted attestations is unchanged; only the order of refusals is.
    #[test]
    fn cheap_checks_run_before_signature_recovery() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        apply(&mut st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 10, 1)), 1).unwrap();
        // A consumed digest is public knowledge and free to resubmit.
        assert_eq!(
            st.check_attest(&tk, &misattest(0, transfer_body(2, 1_000, 10, 1)), 1).unwrap_err(),
            BridgeError::Replay
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_address = [9; 32];
        assert_eq!(st.check_attest(&tk, &misattest(0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        assert_eq!(
            st.check_attest(&tk, &misattest(0, transfer_body(2, 1, 0, 2)), 1).unwrap_err(),
            BridgeError::WrongToChain
        );
        assert_eq!(
            st.check_attest(&tk, &misattest(0, transfer_body(2, 1, 2, 1)), 1).unwrap_err(),
            BridgeError::FeeExceedsAmount
        );
        assert_eq!(
            st.check_attest(&tk, &misattest(0, transfer_body(2, 0, 0, 1)), 1).unwrap_err(),
            BridgeError::ZeroAmount
        );
        assert_eq!(
            st.check_attest(&tk, &misattest(0, transfer_body(2, u64::MAX as u128 + 1, 0, 1)), 1).unwrap_err(),
            BridgeError::AmountTooLarge
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.payload[0] = 9; // unknown payload id
        assert_eq!(st.check_attest(&tk, &misattest(0, b), 1).unwrap_err(), BridgeError::BadPayload);
        let keys = vec![guardian_address(&[21; 32])];
        assert_eq!(
            st.check_attest(&tk, &misattest(0, upgrade_body(5, keys)), 1).unwrap_err(),
            BridgeError::BadUpgradeIndex { expected: 1, got: 5 }
        );
        // Well-formed and fresh: now the quorum is what fails.
        assert!(matches!(
            st.check_attest(&tk, &misattest(0, transfer_body(2, 1, 0, 1)), 1).unwrap_err(),
            BridgeError::Verify(VerifyError::WrongGuardian(_))
        ));
    }
}
