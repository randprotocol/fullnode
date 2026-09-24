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
use crate::bridge::pq::{check_pq_structure, verify_pq_signatures, PqSignature};
use crate::crypto::{merkle_root, Hash, PublicKey};
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
/// { "emitter": "<64 hex>", "guardians": ["<40 hex>"], "emitters": { "2": "<64 hex>" },
///   "pq_guardians": ["<2624 hex>"] }
/// ```
///
/// `pq_guardians` (bridge hardening spec §4, B3) are the guardians' Dilithium2 public keys,
/// **index-aligned with `guardians`**: `pq_guardians[i]` belongs to the operator of
/// `guardians[i]`. Genesis validation holds the two lists to the same length and each key to a
/// Dilithium2 key's exact length, unique. Parsing defaults it to empty only so that validation,
/// not the JSON decoder, reports the mismatch.
///
/// `pause_key` (bridge hardening spec §2, B1) is the one Dilithium2 key that may **pause** minting
/// (`Action::PauseMints`, over [`crate::bridge::gov::pause_message`]); lifting a pause needs a PQ
/// guardian quorum. Genesis validation requires it on every bridged chain, as a Dilithium2 key
/// that is none of the `pq_guardians` (it must be held away from the guardian keys); parsing
/// defaults it to absent for the same reason `pq_guardians` defaults to empty.
///
/// `rules_v2` (audit v4, bridge rules v2 — `docs/bridge.md` §21) switches on, for the chain's
/// life, the PQ and pause-key rotations, the rolling-window mint caps and the no-listing-while-
/// paused rule. Absent on chain 14, and then **absent from the genesis commitment, the bridge
/// root and the storage blob alike** — it is committed by `genesis.rs` under its own tag, folded
/// into `rand-bridge-state-5` and stored under its own key only when present, so a chain-14
/// file, root and database are byte-for-byte what they were.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    #[serde(with = "hex_bytes32")]
    pub emitter: [u8; 32],
    #[serde(with = "hex_guardians")]
    pub guardians: Vec<GuardianKey>,
    #[serde(default, with = "hex_emitters")]
    pub emitters: BTreeMap<u16, [u8; 32]>,
    #[serde(default)]
    pub pq_guardians: Vec<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_key: Option<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_v2: Option<BridgeRulesV2>,
}

/// Bridge rules v2 (audit v4 BRG-14 / BR-4): the parameters the second rule set adds. Genesis
/// holds `cap_window_secs` to `3600..=7 × 86 400` and `global_mint_cap_per_window` above zero.
///
/// - `global_mint_cap_per_window`: the most **every backing of every token together** may mint
///   inside one window, in eight-decimal token units (a plain number in the genesis file, like
///   `tokens.mint_cap_per_day`).
/// - `cap_window_secs`: the rolling window, of the block timestamp, that both this cap and the
///   per-backing `mint_cap_per_day` are measured over instead of the calendar day.
///
/// Part of the genesis hash (`b"bridge_rules_v2"` ‖ cap ‖ window, tagged, only when present), of
/// the bridge root (`rand-bridge-state-5`) and of the token root (the windows themselves, under
/// `rand-token-registry-3`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeRulesV2 {
    pub global_mint_cap_per_window: u64,
    pub cap_window_secs: u32,
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
    pub pq_guardians: Vec<PublicKey>,
    pub pause_key: Option<PublicKey>,
}

impl From<&BridgeConfig> for BridgeCommit {
    /// Destructured on purpose: a new `BridgeConfig` field must not silently
    /// fall out of the genesis commitment — it has to break this conversion.
    ///
    /// `rules_v2` is destructured and deliberately *not* here: `BridgeCommit` is bincode, and an
    /// `Option` field would put a byte into every chain's commitment, chain 14's included. The
    /// genesis builder commits it under its own tag, only when present (`Genesis::build`), the
    /// way the call limits are committed.
    fn from(cfg: &BridgeConfig) -> BridgeCommit {
        let BridgeConfig { emitter, guardians, emitters, pq_guardians, pause_key, rules_v2: _ } = cfg;
        BridgeCommit {
            emitter: *emitter,
            guardians: guardians.clone(),
            emitters: emitters.clone(),
            pq_guardians: pq_guardians.clone(),
            pause_key: pause_key.clone(),
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
    /// The PQ guardian set (B3): the genesis `bridge.pq_guardians`, index-aligned with guardian
    /// set 0. Every `BridgeAttest` needs a quorum of Dilithium2 co-signatures by it. Fixed for
    /// the chain's life: a payload-2 rotation moves the ECDSA set only (a PQ rotation is the
    /// deferred payload 3).
    pub pq_guardians: Vec<PublicKey>,
    /// B1: the genesis `bridge.pause_key`, the one key whose signature over
    /// [`crate::bridge::gov::pause_message`] pauses minting. `None` only on a state not built
    /// from a validated genesis; a `PauseMints` then has no key to verify against.
    pub pause_key: Option<PublicKey>,
    /// B1: while `true`, every `BridgeAttest` carrying a transfer is refused
    /// [`BridgeError::MintsPaused`]. Burns and guardian-set rotations stay open — a pause must
    /// never trap redemption.
    pub mint_paused: bool,
    /// B1: the nonce `M_pause` and `M_unpause` must carry; each accepted `PauseMints` or
    /// `UnpauseMints` bumps it, so neither message can be replayed.
    pub pause_nonce: u64,
    /// B4: the nonce `M_list` and `M_register` must carry; each accepted `ListBacking` or
    /// `RegisterBridgedToken` bumps it.
    pub list_nonce: u64,
    /// Bridge rules v2: the nonce `M_rotate_pq` and `M_rotate_pause` must carry; each accepted
    /// `RotatePqGuardians` or `RotatePauseKey` bumps it. Always zero without `rules_v2`, and
    /// then in no root and no blob.
    pub rotation_nonce: u64,
    /// Bridge rules v2: the genesis `bridge.rules_v2`, `None` on chain 14. The gate every v2
    /// rule reads first (`BridgeError::RulesV2Disabled`).
    pub rules_v2: Option<BridgeRulesV2>,
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
    pub pq_guardians: Vec<PublicKey>,
    pub pause_key: Option<PublicKey>,
    pub mint_paused: bool,
    pub pause_nonce: u64,
    pub list_nonce: u64,
}

/// The v2 half of the storage blob (bridge rules v2): what [`BridgeMeta`] cannot carry without
/// changing its layout. Stored under its own key, and only on a chain whose genesis has
/// `rules_v2` — so a chain-14 database keeps decoding its v1 blob strictly, and a v0.5.4 node
/// on chain 14 never writes a key an older build would trip over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMetaV2 {
    pub rotation_nonce: u64,
    pub rules: BridgeRulesV2,
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
    /// The Dilithium2 co-signature (bridge hardening spec §4, [`crate::bridge::pq`]), rule 1:
    /// fewer than `need = quorum(n)` co-signatures, or more than the `n` PQ guardians.
    #[error("{have} PQ co-signatures, need {need} of {n}")]
    PqNoQuorum { have: usize, need: usize, n: usize },
    /// Rule 2: the co-signers' indices are not strictly increasing (so one would count twice).
    #[error("PQ co-signature indices are not strictly increasing")]
    PqIndexOrder,
    /// Rule 2: a co-signer's index names no PQ guardian.
    #[error("PQ co-signature index {index} is out of range for {n} PQ guardians")]
    PqIndexOutOfRange { index: u8, n: usize },
    /// Rule 3: a co-signature that is not exactly a Dilithium2 signature's 2 420 bytes.
    #[error("PQ co-signature {index} is {len} bytes, not 2420")]
    PqBadSignatureLength { index: u8, len: usize },
    /// Rule 4: a co-signature that does not verify under its PQ guardian's key over
    /// `b"rand-bridge-pq-cosign-1" ‖ chain_id ‖ mu`.
    #[error("PQ co-signature {index} does not verify")]
    PqBadSignature { index: u8 },
    /// B1: minting is paused (`PauseMints`), and this attestation carries a transfer. Not a
    /// verdict on the transaction — it becomes admissible once a PQ quorum unpauses.
    #[error("bridge minting is paused")]
    MintsPaused,
    /// B1: a `PauseMints` on a chain whose bridge has no pause key.
    #[error("this bridge has no pause key")]
    NoPauseKey,
    /// B1: a `PauseMints` while minting is already paused. Refused rather than accepted as a
    /// no-op, so a pause spends no nonce it does not need.
    #[error("bridge minting is already paused")]
    AlreadyPaused,
    /// B1: an `UnpauseMints` while minting is not paused. Refused, so an unpause can never be
    /// used to move `pause_nonce` past a pause the key has already signed.
    #[error("bridge minting is not paused")]
    NotPaused,
    /// B1: `M_pause`/`M_unpause` must carry the bridge's current `pause_nonce`.
    #[error("wrong pause nonce: expected {expected}, got {got}")]
    BadPauseNonce { expected: u64, got: u64 },
    /// B1: the pause key's signature over `M_pause` does not verify.
    #[error("the pause signature does not verify")]
    BadPauseSignature,
    /// F1 (chain 14): a `BridgeAttest` whose blinding `r` is not the one the attestation's digest
    /// fixes, `ledger::bridge_notes::derive_deposit_r(mu)`. The deposit note's commitment is then
    /// a function of the guardians' `mu`, the recipient, the amount, the registry's index and the
    /// action's `time` — nothing a front-runner of a relayer's transaction can choose but `time`.
    /// A statement about the transaction's own bytes (the `r` field against a hash of its
    /// `attestation` field), so it is a permanent admission verdict.
    #[error("the deposit blinding is not the one the attestation's digest derives")]
    WrongDepositBlinding,
    /// B4: `M_list`/`M_register` must carry the bridge's current `list_nonce`.
    #[error("wrong list nonce: expected {expected}, got {got}")]
    BadListNonce { expected: u64, got: u64 },
    /// B4: a backing on a chain this bridge registers no emitter for — no attestation of it could
    /// ever be admitted, so the listing is refused rather than left unusable.
    #[error("chain {chain} has no registered emitter on this bridge")]
    NoEmitter { chain: u16 },
    /// Bridge rules v2: a `RotatePqGuardians` or `RotatePauseKey` on a chain whose genesis has no
    /// `bridge.rules_v2` — chain 14. A genesis constant, so a permanent verdict.
    #[error("bridge rules v2 are not enabled on this chain")]
    RulesV2Disabled,
    /// Bridge rules v2: `M_rotate_pq`/`M_rotate_pause` must carry the bridge's `rotation_nonce`.
    #[error("wrong rotation nonce: expected {expected}, got {got}")]
    BadRotationNonce { expected: u64, got: u64 },
    /// Bridge rules v2: the new PQ set must be index-aligned with the current ECDSA set — one PQ
    /// key per guardian, the genesis rule.
    #[error("the new PQ set has {got} keys, the current guardian set {expected}: the two are index-aligned")]
    PqSetLengthMismatch { expected: usize, got: usize },
    /// Bridge rules v2: a new PQ guardian key that is not exactly a Dilithium2 public key's 1 312
    /// bytes. A byte length, so a permanent verdict.
    #[error("new PQ guardian {index} is {len} bytes, not a Dilithium2 public key's 1312")]
    BadPqGuardianKey { index: usize, len: usize },
    /// Bridge rules v2: the same key twice in the new PQ set (one operator would count twice).
    #[error("duplicate key in the new PQ guardian set")]
    DuplicatePqGuardian,
    /// Bridge rules v2: the new PQ set contains the pause key, which must be held apart from the
    /// guardian keys (the genesis rule).
    #[error("the new PQ guardian set contains the pause key")]
    GuardianIsPauseKey,
    /// Bridge rules v2: a new pause key that is not exactly a Dilithium2 public key's 1 312 bytes.
    #[error("the new pause key is {len} bytes, not a Dilithium2 public key's 1312")]
    BadPauseKeyLength { len: usize },
    /// Bridge rules v2: the new pause key is one of the PQ guardians'.
    #[error("the new pause key is a PQ guardian's key")]
    PauseKeyIsGuardian,
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
    /// The block time, unix seconds, `check_attest` judged this deposit at — carried so apply
    /// moves the very counters check compared: B1's day counter ([`mint_day`] of it) and, under
    /// bridge rules v2, the rolling windows.
    pub now: u64,
}

/// B1: seconds in a mint-cap day. A day is a UTC calendar day of the block timestamp
/// (bridge hardening spec §2), which B2 bounds.
pub const MINT_DAY_SECS: u64 = 86_400;

/// B1: the mint-cap day of `now` (unix seconds, `timestamp_ms / 1000`) — `timestamp_ms /
/// 86_400_000`, since flooring twice is flooring once. Saturates rather than wraps past `u32`
/// (eleven million years out).
pub fn mint_day(now: u64) -> u32 {
    u32::try_from(now / MINT_DAY_SECS).unwrap_or(u32::MAX)
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
            pq_guardians: cfg.pq_guardians.clone(),
            pause_key: cfg.pause_key.clone(),
            rules_v2: cfg.rules_v2.clone(),
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
            pq_guardians,
            pause_key,
            mint_paused,
            pause_nonce,
            list_nonce,
            // The v2 half: `meta_v2`'s, never this blob's (its layout is chain 14's).
            rotation_nonce: _,
            rules_v2: _,
        } = self;
        BridgeMeta {
            emitter: *emitter,
            emitters: emitters.clone(),
            guardian_sets: guardian_sets.clone(),
            current_set: *current_set,
            burn_sequence: *burn_sequence,
            pq_guardians: pq_guardians.clone(),
            pause_key: pause_key.clone(),
            mint_paused: *mint_paused,
            pause_nonce: *pause_nonce,
            list_nonce: *list_nonce,
        }
    }

    /// The v2 half of the storage blob (bridge rules v2): `Some` exactly when the genesis carries
    /// `rules_v2`, `None` on chain 14 — where there is nothing to store and no key to write.
    pub fn meta_v2(&self) -> Option<BridgeMetaV2> {
        self.rules_v2.clone().map(|rules| BridgeMetaV2 { rotation_nonce: self.rotation_nonce, rules })
    }

    /// Rebuilds a bridge from the halves storage keeps apart: the v1 blob, the v2 blob when the
    /// chain has one, and the two row-wise collections. The inverse of [`BridgeState::meta`] and
    /// [`BridgeState::meta_v2`].
    pub fn from_parts(
        meta: BridgeMeta,
        v2: Option<BridgeMetaV2>,
        spent: BTreeSet<Hash>,
        burns: BTreeMap<u64, BridgeBurnRecord>,
    ) -> BridgeState {
        let BridgeMeta {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            burn_sequence,
            pq_guardians,
            pause_key,
            mint_paused,
            pause_nonce,
            list_nonce,
        } = meta;
        let (rotation_nonce, rules_v2) = match v2 {
            Some(BridgeMetaV2 { rotation_nonce, rules }) => (rotation_nonce, Some(rules)),
            None => (0, None),
        };
        BridgeState {
            emitter,
            emitters,
            guardian_sets,
            current_set,
            spent,
            burn_sequence,
            burns,
            pq_guardians,
            pause_key,
            mint_paused,
            pause_nonce,
            list_nonce,
            rotation_nonce,
            rules_v2,
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
    ///
    /// `pq_signatures` is the attestation's Dilithium2 co-signature quorum (B3,
    /// [`crate::bridge::pq`]), required on every attestation — rotations
    /// included — over `M = b"rand-bridge-pq-cosign-1" ‖ chain_id ‖ mu`, where
    /// `chain_id` is this Rand chain's. The cost order: the PQ list's
    /// structural rules (count, index order, index range, lengths) first,
    /// before anything else here; then every existing check, the ECDSA
    /// quorum's own structural rules and recoveries last among them; then the
    /// Dilithium verifications, last of all. The PQ signers are counted on
    /// their own, independent of which guardians signed the ECDSA quorum.
    pub fn check_attest(
        &self,
        tokens: &TokenRegistry,
        bytes: &[u8],
        pq_signatures: &[PqSignature],
        chain_id: u64,
        now: u64,
    ) -> Result<CheckedAttestation, BridgeError> {
        // The PQ quorum's structure, which needs neither the attestation nor
        // any key: rules 1-3 of the co-signature, in the vectors' order.
        check_pq_structure(pq_signatures, self.pq_guardians.len())?;
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
                // B1: a paused bridge mints nothing. A flag read, before any other transfer
                // check and long before a signature is looked at; rotations (below) and burns
                // (`check_burn`) never read it, so a pause cannot trap redemption.
                if self.mint_paused {
                    return Err(BridgeError::MintsPaused);
                }
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
                // a comparison: B1's per-backing daily mint cap for today's block day, then this
                // backing's `locked` overflowing, then the token's supply. The ledger applies the
                // deposit note *before* it locks, so a refusal there would be a half-applied
                // transaction.
                // (Under bridge rules v2 the registry judges the rolling windows here too, the
                // global one included.)
                tokens.check_lock(index, t.token_chain, &t.token_address, amount, now)?;
                AttestPlan::Transfer(BridgeTransfer {
                    asset,
                    index,
                    chain: t.token_chain,
                    token: t.token_address,
                    amount,
                    to_hash: t.to,
                    relayer_fee,
                    now,
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
        // Last of all: one Dilithium2 verification per co-signature, over the
        // same `mu` the ECDSA quorum signed, bound to this chain's id.
        verify_pq_signatures(pq_signatures, &self.pq_guardians, chain_id, &mu)?;
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
    /// and then the bridge hardening's B3 left it):
    ///
    /// ```text
    /// blake3("rand-bridge-state-4"
    ///     || bincode(emitter, emitters, current_set, guardian_sets)
    ///     || merkle(sorted spent digests)
    ///     || burn_sequence BE
    ///     || bincode(pq_guardians)
    ///     || bincode(pause_key, mint_paused, pause_nonce, list_nonce))
    /// ```
    ///
    /// Under bridge rules v2 (audit v4) — and only then — the same bytes continue with
    /// `|| bincode(rotation_nonce, rules_v2)` and the domain is `rand-bridge-state-5`: the
    /// rotation nonce decides which rotation is admissible next and the two cap parameters decide
    /// which mints are, so two nodes disagreeing about either must disagree at the state root. A
    /// chain without the section — chain 14 — hashes byte-for-byte as above, whatever
    /// `rotation_nonce` reads (nothing can move it there).
    ///
    /// B1/B4 appended the pause key, the pause flag and the two governance
    /// nonces and bumped the domain to `rand-bridge-state-4`: each decides
    /// what the next governance message or attestation may do, so two nodes
    /// that disagree about one must disagree at the state root.
    ///
    /// B3 appended the PQ guardian set and bumped the domain to
    /// `rand-bridge-state-3`: the set decides which attestations are
    /// admissible exactly as the ECDSA sets do, so two nodes that disagree
    /// about it must disagree at the state root, not only at the genesis hash.
    /// Still byte-for-byte nothing for a chain without a `bridge` section.
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
        buf.extend_from_slice(&bincode::serialize(&self.pq_guardians).expect("PQ guardian keys serialize"));
        buf.extend_from_slice(
            &bincode::serialize(&(&self.pause_key, self.mint_paused, self.pause_nonce, self.list_nonce))
                .expect("the pause and listing state serializes"),
        );
        if let Some(rules) = &self.rules_v2 {
            buf.extend_from_slice(
                &bincode::serialize(&(self.rotation_nonce, rules)).expect("the rotation nonce and the rules serialize"),
            );
            return Hash::digest_domain(b"rand-bridge-state-5", &buf);
        }
        Hash::digest_domain(b"rand-bridge-state-4", &buf)
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
    use crate::bridge::pq::{pq_cosign, PqSignature, PQ_SIGNATURE_LEN};
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
                        .map(|&(chain, token)| crate::ledger::tokens::Backing { chain, token, decimals: 8, locked: 0, minted_today: 0, mint_day: 0 })
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
        t.lock(1, 2, &TOKEN, 1_000_000, 0).expect("the fixture's locked backing");
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
            pq_guardians: pq_keys().iter().map(|k| k.public_key().clone()).collect(),
            pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
            rules_v2: None,
        };
        (config, secrets)
    }

    /// The chain id every test here checks against.
    const CHAIN: u64 = 7;

    /// The six PQ guardians' Dilithium2 keys, index-aligned with [`cfg`]'s guardians.
    fn pq_keys() -> Vec<Keypair> {
        (0..6u8).map(|i| Keypair::from_seed([0x70 + i; 32]).unwrap()).collect()
    }

    /// `mu` of an encoded attestation, or zeros for bytes that do not decode (whose check is
    /// refused before any co-signature is read).
    fn mu_of(bytes: &[u8]) -> [u8; 32] {
        Attestation::body_bytes(bytes).map(digest).unwrap_or([0; 32])
    }

    /// A PQ quorum by the PQ guardians at `indices`, over `bytes`' `mu` for `chain_id`.
    fn cosign_by(indices: &[u8], bytes: &[u8], chain_id: u64) -> Vec<PqSignature> {
        let keys = pq_keys();
        indices.iter().map(|&i| pq_cosign(&keys[i as usize], i, chain_id, &mu_of(bytes))).collect()
    }

    /// The lowest-five PQ quorum a relayer submits for `bytes` on [`CHAIN`].
    fn cosign(bytes: &[u8]) -> Vec<PqSignature> {
        cosign_by(&[0, 1, 2, 3, 4], bytes, CHAIN)
    }

    /// `check_attest` with an honest PQ quorum, for the tests whose subject is the attestation.
    fn check(st: &BridgeState, tokens: &TokenRegistry, bytes: &[u8], now: u64) -> Result<CheckedAttestation, BridgeError> {
        st.check_attest(tokens, bytes, &cosign(bytes), CHAIN, now)
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
        let checked = check(st, tokens, bytes, now)?;
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

        let checked = check(&st, &tk, &bytes, 1).unwrap();
        assert_eq!(checked.digest(), mu);
        assert!(matches!(checked.plan(), AttestPlan::Transfer(_)));
        // No `unwrap`: applying a checked attestation cannot fail.
        let out: AttestOutcome = st.apply_attest(checked);
        assert!(matches!(out, AttestOutcome::Minted(_)));
        assert!(st.spent.contains(&Hash(mu)));
        // And the token cannot be made again: the digest is consumed, so a second attempt is a
        // replay — which is refused before any signature is recovered.
        assert_eq!(check(&st, &tk, &bytes, 1).unwrap_err(), BridgeError::Replay);
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
        let plan = check(&st, &tk, &attest(&s, 0, transfer_body(2, 1_000, 10, 1)), 1).unwrap().plan().clone();
        let want = BridgeTransfer { asset, index: 1, chain: 2, token: TOKEN, amount: 1_000, to_hash: to_hash(), relayer_fee: 10, now: 1 };
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
            check(&st, &tk, &att, 1),
            Err(BridgeError::UnlistedToken { chain: 2, token }) if token == TOKEN
        ));
        assert_eq!(list(&mut tk, 2, TOKEN), 1);
        let checked = check(&st, &tk, &att, 1).unwrap();
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
        assert_eq!(check(&st, &tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_chain = 3; // chain-2 address presented as chain 3
        assert_eq!(check(&st, &tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        assert_eq!(
            check(&st, &tk, &attest(&s, 0, transfer_body(2, 1, 0, 2)), 1).unwrap_err(),
            BridgeError::WrongToChain
        );
        assert_eq!(
            check(&st, &tk, &attest(&s, 0, transfer_body(2, 1, 2, 1)), 1).unwrap_err(),
            BridgeError::FeeExceedsAmount
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.payload[1] = 1; // amount top byte
        assert_eq!(check(&st, &tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::AmountOverflow);
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
            check(&st, &tk, &attest(&s, 0, transfer_body(2, over, 0, 1)), 1).unwrap_err(),
            BridgeError::AmountTooLarge
        );
        // The largest amount that does fit still validates, fee and all.
        let plan = check(&st, &tk, &attest(&s, 0, transfer_body(2, u64::MAX as u128, 7, 1)), 1).unwrap().plan().clone();
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
                now: 1,
            })
        );
        // And once that coin is holding anything at all, the same transfer is refused before a
        // single signature is recovered: `check_attest` decides what `lock` would refuse, so the
        // ledger's apply step cannot be the thing that discovers it.
        tk.lock(1, 2, &TOKEN, 1, 0).unwrap();
        assert_eq!(
            check(&st, &tk, &attest(&s, 0, transfer_body(2, u64::MAX as u128, 7, 1)), 1).unwrap_err(),
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
            check(&st, &tk, &attest(&s, 0, token_body(3, OTHER_TOKEN, 10, 0, 1)), 1),
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
        let rebuilt = BridgeState::from_parts(meta, None, st.spent.clone(), st.burns.clone());
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
            check(&st, &tk, &attest(&s, 0, up(2)), 100).unwrap_err(),
            BridgeError::BadUpgradeIndex { expected: 1, got: 2 }
        );
        assert_eq!(apply(&mut st, &tk, &attest(&s, 0, up(1)), 100).unwrap(), AttestOutcome::GuardianSetUpgraded(1));
        assert_eq!(st.current_set, 1);
        assert_eq!(st.guardian_sets[&0].expires_at, 100 + GUARDIAN_GRACE_SECS);
        assert_eq!(st.guardian_sets[&1].keys, new_keys);
        // old set still mints inside grace, not after
        assert!(check(&st, &tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 100 + GUARDIAN_GRACE_SECS)
            .is_ok());
        assert_eq!(
            check(&st, &tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 101 + GUARDIAN_GRACE_SECS)
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
        tk.lock(1, 2, &TOKEN, 1_000, 0).unwrap();
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
            check(&st, &tk, &attest(&s, 0, upgrade_body(1, duplicated)), 100).unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        let mut zeroed = keys.clone();
        zeroed[3] = [0u8; 20];
        assert_eq!(
            check(&st, &tk, &attest(&s, 0, upgrade_body(1, zeroed)), 100).unwrap_err(),
            BridgeError::DuplicateGuardian
        );
        // the same upgrade with distinct, non-zero keys clears every rung
        assert!(check(&st, &tk, &attest(&s, 0, upgrade_body(1, keys)), 100).is_ok());
    }

    #[test]
    fn unknown_guardian_set_index_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        assert_eq!(
            check(&st, &tk, &attest(&s, 5, transfer_body(2, 1, 0, 1)), 1).unwrap_err(),
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
        assert_eq!(check(&st, &tk, &attest(&s, 0, unknown_id), 1).unwrap_err(), BridgeError::BadPayload);
        let mut short = transfer_body(2, 1, 0, 1);
        short.payload.truncate(TRANSFER_PAYLOAD_LEN - 1); // a 132-byte transfer
        assert_eq!(short.payload.len(), 132);
        assert_eq!(check(&st, &tk, &attest(&s, 0, short), 1).unwrap_err(), BridgeError::BadPayload);
    }

    #[test]
    fn transfer_token_chain_must_match_the_emitting_chain() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let mut b = transfer_body(2, 1, 0, 1);
        // token_chain lives at payload[65..67]: id (1) + amount (32) + token_address (32)
        b.payload[65..67].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(check(&st, &tk, &attest(&s, 0, b), 1).unwrap_err(), BridgeError::WrongTokenChain);
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
            check(&st, &tk, &attest(&s, 0, upgrade_body(2, set2_keys.clone())), 100).unwrap_err(),
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
        assert!(check(&st, &tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 100).is_ok());
    }

    /// Symmetry with `check_burn`: a zero-value mint would consume a digest
    /// and move nothing.
    #[test]
    fn zero_amount_transfer_is_rejected() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        assert_eq!(
            check(&st, &tk, &attest(&s, 0, transfer_body(2, 0, 0, 1)), 1).unwrap_err(),
            BridgeError::ZeroAmount
        );
        // ... and a non-zero amount over the same path still validates.
        assert!(check(&st, &tk, &attest(&s, 0, transfer_body(2, 1, 0, 1)), 1).is_ok());
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
        tk.lock(sol, 5, &OTHER_TOKEN, 1_000, 0).unwrap();
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
        tk.lock(zusd, 2, &eth_usdt, 1_000_000, 0).unwrap();
        tk.lock(zusd, 5, &sol_usdt, 1_000_000, 0).unwrap();

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
    /// The bridge hardening's B3 appended the PQ guardian set and bumped the
    /// domain to `rand-bridge-state-3` — the value before that was
    /// 2504a9da5f62f2ef092493e4c38a8a47560340d0394b1d3721b5aceb6366e141.
    /// B1/B4 appended the pause key, the pause flag and the two governance
    /// nonces and bumped the domain to `rand-bridge-state-4` — the value
    /// before that was
    /// 2f1798b1aa25286958e333718b3d606590b97f0fa20ce3690499dd6550e63c46.
    #[test]
    fn root_is_pinned_for_a_fixed_state() {
        let mut st = BridgeState::from_config(&BridgeConfig {
            emitter: [1; 32],
            guardians: vec![[0x11; 20], [0x22; 20]],
            emitters: BTreeMap::from([(2u16, [2u8; 32])]),
            pq_guardians: vec![
                PublicKey::from_bytes(&[0x33; crate::crypto::PUBLIC_KEY_LEN]).unwrap(),
                PublicKey::from_bytes(&[0x44; crate::crypto::PUBLIC_KEY_LEN]).unwrap(),
            ],
            pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
            rules_v2: None,
        });
        st.spent.insert(Hash([0x44; 32]));
        st.burn_sequence = 7;
        assert_eq!(st.root().to_hex(), "4f2ea1290d513a855ddaaa7aa2ce68a3bd5a54ef3f84819b238a6e9c1da0f712");
        // B1/B4: the pause key, the pause flag and both governance nonces are committed.
        for change in [
            (|b: &mut BridgeState| b.pause_key = None) as fn(&mut BridgeState),
            |b| b.mint_paused = true,
            |b| b.pause_nonce = 1,
            |b| b.list_nonce = 1,
        ] {
            let mut other = st.clone();
            change(&mut other);
            assert_ne!(other.root(), st.root());
        }
        // and so is the PQ guardian set (B3)
        let mut other_pq = st.clone();
        other_pq.pq_guardians.reverse();
        assert_ne!(other_pq.root(), st.root());
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
            check(&st, &tk, &misattest(0, transfer_body(2, 1_000, 10, 1)), 1).unwrap_err(),
            BridgeError::Replay
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.emitter_address = [9; 32];
        assert_eq!(check(&st, &tk, &misattest(0, b), 1).unwrap_err(), BridgeError::WrongEmitter);
        assert_eq!(
            check(&st, &tk, &misattest(0, transfer_body(2, 1, 0, 2)), 1).unwrap_err(),
            BridgeError::WrongToChain
        );
        assert_eq!(
            check(&st, &tk, &misattest(0, transfer_body(2, 1, 2, 1)), 1).unwrap_err(),
            BridgeError::FeeExceedsAmount
        );
        assert_eq!(
            check(&st, &tk, &misattest(0, transfer_body(2, 0, 0, 1)), 1).unwrap_err(),
            BridgeError::ZeroAmount
        );
        assert_eq!(
            check(&st, &tk, &misattest(0, transfer_body(2, u64::MAX as u128 + 1, 0, 1)), 1).unwrap_err(),
            BridgeError::AmountTooLarge
        );
        let mut b = transfer_body(2, 1, 0, 1);
        b.payload[0] = 9; // unknown payload id
        assert_eq!(check(&st, &tk, &misattest(0, b), 1).unwrap_err(), BridgeError::BadPayload);
        let keys = vec![guardian_address(&[21; 32])];
        assert_eq!(
            check(&st, &tk, &misattest(0, upgrade_body(5, keys)), 1).unwrap_err(),
            BridgeError::BadUpgradeIndex { expected: 1, got: 5 }
        );
        // Well-formed and fresh: now the quorum is what fails.
        assert!(matches!(
            check(&st, &tk, &misattest(0, transfer_body(2, 1, 0, 1)), 1).unwrap_err(),
            BridgeError::Verify(VerifyError::WrongGuardian(_))
        ));
    }

    // ---- B3: the Dilithium2 co-signature on every attestation --------------------------------

    /// A mint with a valid ECDSA quorum and no PQ co-signatures is refused — and so is a rotation:
    /// the PQ quorum is required on every `BridgeAttest`. Nothing is consumed by a refusal.
    #[test]
    fn a_valid_ecdsa_quorum_without_pq_signatures_is_refused() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let mint = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        assert_eq!(
            st.check_attest(&tk, &mint, &[], CHAIN, 1).unwrap_err(),
            BridgeError::PqNoQuorum { have: 0, need: 5, n: 6 }
        );
        let rotation = attest(&s, 0, upgrade_body(1, vec![[7u8; 20], [8u8; 20]]));
        assert_eq!(
            st.check_attest(&tk, &rotation, &[], CHAIN, 100).unwrap_err(),
            BridgeError::PqNoQuorum { have: 0, need: 5, n: 6 }
        );
        // Four of six is short too; five is the quorum.
        assert!(matches!(
            st.check_attest(&tk, &mint, &cosign_by(&[0, 1, 2, 3], &mint, CHAIN), CHAIN, 1),
            Err(BridgeError::PqNoQuorum { have: 4, .. })
        ));
        assert!(st.check_attest(&tk, &mint, &cosign(&mint), CHAIN, 1).is_ok());
    }

    /// The co-signature names the Rand chain: a quorum made for another chain id never verifies
    /// here, whatever keys were reused, and one made over another attestation's `mu` does not
    /// either.
    #[test]
    fn a_pq_quorum_for_another_chain_or_another_body_is_refused() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let mint = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        assert_eq!(
            st.check_attest(&tk, &mint, &cosign_by(&[0, 1, 2, 3, 4], &mint, CHAIN + 1), CHAIN, 1).unwrap_err(),
            BridgeError::PqBadSignature { index: 0 }
        );
        let other = attest(&s, 0, transfer_body(2, 2_000, 10, 1));
        assert_eq!(
            st.check_attest(&tk, &mint, &cosign(&other), CHAIN, 1).unwrap_err(),
            BridgeError::PqBadSignature { index: 0 }
        );
    }

    /// Rule 5: each quorum is counted on its own. The ECDSA quorum here is guardians 0-4 and the
    /// PQ quorum guardians 1-5 — accepted; and a PQ signature filed under another guardian's
    /// index fails even though that guardian is an ECDSA signer.
    #[test]
    fn the_pq_signers_are_independent_of_the_ecdsa_signers() {
        let (c, s) = cfg();
        let st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let mint = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        assert!(st.check_attest(&tk, &mint, &cosign_by(&[1, 2, 3, 4, 5], &mint, CHAIN), CHAIN, 1).is_ok());
        let mut misfiled = cosign(&mint);
        misfiled[4].signature = cosign_by(&[5], &mint, CHAIN)[0].signature.clone();
        assert_eq!(
            st.check_attest(&tk, &mint, &misfiled, CHAIN, 1).unwrap_err(),
            BridgeError::PqBadSignature { index: 4 }
        );
    }

    /// The cost order (spec §4 and §10): the PQ list's structure before *anything* else —
    /// even a replayed digest or a mis-addressed body is refused for its co-signature shape first
    /// — and the Dilithium verifications after every other check, the ECDSA recoveries included:
    /// a structurally sound but forged PQ list on an attestation whose ECDSA quorum is wrong is
    /// refused for the ECDSA quorum.
    #[test]
    fn pq_structure_runs_first_and_dilithium_verification_last() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let mint = attest(&s, 0, transfer_body(2, 1_000, 10, 1));
        apply(&mut st, &tk, &mint, 1).unwrap();
        let replayed = mint;
        assert_eq!(st.check_attest(&tk, &replayed, &[], CHAIN, 1).unwrap_err(), BridgeError::PqNoQuorum { have: 0, need: 5, n: 6 });
        let mut long = cosign(&replayed);
        long[2].signature.push(0);
        assert_eq!(
            st.check_attest(&tk, &replayed, &long, CHAIN, 1).unwrap_err(),
            BridgeError::PqBadSignatureLength { index: 2, len: PQ_SIGNATURE_LEN + 1 }
        );
        assert_eq!(st.check_attest(&tk, &replayed, &cosign(&replayed), CHAIN, 1).unwrap_err(), BridgeError::Replay);
        // Well-formed zeros: they pass the structure and would fail verification — but the ECDSA
        // quorum is by strangers, and that is what is reported.
        let zeros: Vec<PqSignature> =
            (0..5).map(|i| PqSignature { index: i, signature: vec![0; PQ_SIGNATURE_LEN] }).collect();
        let forged = misattest(0, transfer_body(2, 5, 0, 1));
        assert!(matches!(
            st.check_attest(&tk, &forged, &zeros, CHAIN, 1).unwrap_err(),
            BridgeError::Verify(VerifyError::WrongGuardian(_))
        ));
        // With the ECDSA quorum honest, the zeros are what is left to refuse.
        let honest = attest(&s, 0, transfer_body(2, 5, 0, 1));
        assert_eq!(st.check_attest(&tk, &honest, &zeros, CHAIN, 1).unwrap_err(), BridgeError::PqBadSignature { index: 0 });
    }

    /// A payload-2 rotation must itself carry a PQ quorum by the *current* PQ set, and it moves
    /// the ECDSA set only: the PQ guardians are the genesis set before and after, and the next
    /// mint — ECDSA-signed by the new set — is co-signed by the same PQ keys.
    #[test]
    fn a_rotation_needs_a_pq_quorum_and_does_not_change_the_pq_set() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        let pq_before = st.pq_guardians.clone();
        let new_secrets: Vec<[u8; 32]> = (21u8..=26).map(|i| [i; 32]).collect();
        let rotation = attest(&s, 0, upgrade_body(1, new_secrets.iter().map(guardian_address).collect()));
        let checked = st.check_attest(&tk, &rotation, &cosign(&rotation), CHAIN, 100).unwrap();
        assert_eq!(st.apply_attest(checked), AttestOutcome::GuardianSetUpgraded(1));
        assert_eq!(st.pq_guardians, pq_before, "a payload-2 rotation leaves the PQ set alone");
        assert_eq!(st.meta().pq_guardians, pq_before);
        let mint = attest(&new_secrets, 1, transfer_body(2, 1_000, 10, 1));
        assert!(st.check_attest(&tk, &mint, &cosign(&mint), CHAIN, 101).is_ok());
    }

    /// The PQ guardian set is committed by the bridge root (`rand-bridge-state-3`) and carried in
    /// storage's meta blob.
    #[test]
    fn the_pq_set_is_in_the_root_and_the_meta_blob() {
        let (c, _) = cfg();
        let st = BridgeState::from_config(&c);
        assert_eq!(st.pq_guardians, c.pq_guardians);
        let mut other = st.clone();
        other.pq_guardians.swap(0, 1);
        assert_ne!(other.root(), st.root());
        let meta: BridgeMeta = bincode::deserialize(&bincode::serialize(&st.meta()).unwrap()).unwrap();
        assert_eq!(BridgeState::from_parts(meta, None, BTreeSet::new(), BTreeMap::new()), st);
    }

    /// Every case of the bridge repo's `pq-cosignatures.json`, end to end through `check_attest`:
    /// the attestation vector the cases were made over (`transfer_eth_usdt_6dp_ok`, with its real
    /// ECDSA quorum from `vectors.json`), on a bridge whose ECDSA set, emitters and PQ set are the
    /// vectors' own, at the case's `rand_chain_id`. Each gets its expected verdict — and the
    /// rotation body in the file, `upgrade_set1_ok`, is admitted with its lowest five co-signers.
    #[test]
    fn every_pq_vector_case_through_check_attest() {
        use crate::bridge::pq::tests::{hex32, vector_keys, vector_sigs, vectors, verdict};
        let pq = vectors();
        let att: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
        let guardians: Vec<GuardianKey> = att["guardians"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| hex::decode(g["address"].as_str().unwrap()).unwrap().try_into().unwrap())
            .collect();
        let emitters: BTreeMap<u16, [u8; 32]> = att["emitters"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(chain, a)| (chain.parse().unwrap(), hex32(a)))
            .collect();
        let st = BridgeState::from_config(&BridgeConfig {
            emitter: hex32(&att["rand_emitter"]),
            guardians,
            emitters,
            pq_guardians: vector_keys(&pq),
            pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
            rules_v2: None,
        });
        let now = att["now"].as_u64().unwrap();
        let by_name = |name: &str| {
            let v = att["vectors"].as_array().unwrap().iter().find(|v| v["name"] == name).unwrap().clone();
            hex::decode(v["attestation"].as_str().unwrap()).unwrap()
        };
        // The cases' body: a transfer of an Ethereum token, listed here as a bridged coin.
        let transfer = by_name("transfer_eth_usdt_6dp_ok");
        let Payload::Transfer(t) =
            Payload::decode(&Attestation::decode(&transfer).unwrap().body.payload).unwrap()
        else {
            panic!("a transfer")
        };
        let mut tk = tokens();
        list(&mut tk, t.token_chain, t.token_address);
        let mut checked = 0;
        for case in pq["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            assert_eq!(hex32(&case["mu"]), mu_of(&transfer), "{name}: the cases are over this body");
            let got = st
                .check_attest(&tk, &transfer, &vector_sigs(&case["pq_signatures"]), case["rand_chain_id"].as_u64().unwrap(), now)
                .map(|_| ());
            assert_eq!(verdict(&got), case["expect"].as_str().unwrap(), "{name}: {got:?}");
            checked += 1;
        }
        assert_eq!(checked, 12);
        // The rotation body, with the lowest-five co-signers out of its six.
        let chain_id = pq["rand_chain_id"].as_u64().unwrap();
        let rotation = by_name("upgrade_set1_ok");
        let body = pq["bodies"].as_array().unwrap().iter().find(|b| b["attestation_vector"] == "upgrade_set1_ok").unwrap();
        let five: Vec<PqSignature> = vector_sigs(&body["pq_signatures"]).into_iter().take(5).collect();
        assert!(st.check_attest(&tk, &rotation, &five, chain_id, now).is_ok());
        assert!(matches!(st.check_attest(&tk, &rotation, &[], chain_id, now), Err(BridgeError::PqNoQuorum { .. })));
    }

    // ---- bridge hardening B1: the mint pause and the per-backing daily cap ----------------------

    /// A secret set that is no guardian set: its quorum passes every structural check and fails
    /// at recovery — the expensive half — so a refusal it gets first was decided before any
    /// signature work.
    fn strangers() -> Vec<[u8; 32]> {
        (0x90u8..0x96).map(|i| [i; 32]).collect()
    }

    /// While paused, every transfer is refused `MintsPaused` — before a single signature is
    /// recovered — and nothing else is: a rotation is admitted and a burn's check passes, so a
    /// pause never traps redemption. Unpaused, the same transfer is admitted.
    #[test]
    fn a_paused_bridge_refuses_transfers_only() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let tk = tokens_with_the_test_token();
        st.mint_paused = true;
        let transfer = attest(&s, 0, transfer_body(2, 1_000, 0, CHAIN_RAND));
        assert_eq!(check(&st, &tk, &transfer, 1).unwrap_err(), BridgeError::MintsPaused);
        // Decided before recovery: a quorum of strangers gets the same answer.
        let forged = attest(&strangers(), 0, transfer_body(2, 1_000, 0, CHAIN_RAND));
        assert_eq!(check(&st, &tk, &forged, 1).unwrap_err(), BridgeError::MintsPaused);
        // Burns stay open, and so do rotations (payload 2).
        assert_eq!(st.check_burn(&tk, 1, 1_000, 2, &TOKEN, &EVM_TO, 0), Ok(()));
        let rotation = attest(&s, 0, upgrade_body(1, vec![[7u8; 20], [8u8; 20]]));
        assert_eq!(apply(&mut st, &tk, &rotation, 1).unwrap(), AttestOutcome::GuardianSetUpgraded(1));
        st.mint_paused = false;
        assert!(check(&st, &tk, &transfer, 1).is_ok(), "the signing set is superseded but inside its grace window");
    }

    /// The cap, per backing and per UTC day of the block time: exactly the cap is admitted, one
    /// unit over is `MintCapExceeded` with the figures, the next day counts from zero, and one
    /// coin's deposits leave another coin of the same token untouched. Decided before recovery.
    #[test]
    fn the_daily_mint_cap_is_per_backing_and_resets_at_the_next_utc_day() {
        let (c, s) = cfg();
        let mut st = BridgeState::from_config(&c);
        let mut tk = tokens().with_mint_cap(1_000);
        let zusd = list_backed_by(&mut tk, 1, &[(2, TOKEN), (2, OTHER_TOKEN)]);
        let day0 = 5 * MINT_DAY_SECS + 17; // any second of day 5
        let deposit = |st: &mut BridgeState, tk: &mut TokenRegistry, token: [u8; 32], amount: u128, fee: u128, now: u64| {
            let bytes = attest(&s, 0, token_body(2, token, amount, fee, CHAIN_RAND));
            let checked = check(st, tk, &bytes, now)?;
            let AttestPlan::Transfer(t) = checked.plan().clone() else { panic!("a transfer") };
            assert_eq!(t.now, now);
            st.apply_attest(checked);
            tk.lock(t.index, t.chain, &t.token, t.amount, t.now).map_err(BridgeError::Token)?;
            Ok::<_, BridgeError>(())
        };
        deposit(&mut st, &mut tk, TOKEN, 600, 0, day0).unwrap();
        // 400 more is exactly the cap: admitted.
        deposit(&mut st, &mut tk, TOKEN, 400, 0, day0 + 60).unwrap();
        let b = tk.backing(zusd, 2, &TOKEN).unwrap();
        assert_eq!((b.minted_today, b.mint_day, b.locked), (1_000, 5, 1_000));
        // One unit more is refused, with the figures, and before any signature is recovered.
        let want = BridgeError::Token(TokenError::MintCapExceeded { cap: 1_000, minted_today: 1_000, amount: 1 });
        assert_eq!(deposit(&mut st, &mut tk, TOKEN, 1, 0, day0 + 120).unwrap_err(), want);
        let forged = attest(&strangers(), 0, token_body(2, TOKEN, 1, 0, CHAIN_RAND));
        assert_eq!(check(&st, &tk, &forged, day0 + 120).unwrap_err(), want);
        // The other coin of the same token has its own counter.
        deposit(&mut st, &mut tk, OTHER_TOKEN, 1_000, 0, day0 + 180).unwrap();
        assert_eq!(tk.get(zusd).unwrap().total_supply, 2_000);
        // The last second of day 5 is still day 5; the first of day 6 starts from zero.
        assert_eq!(deposit(&mut st, &mut tk, TOKEN, 1, 1, 6 * MINT_DAY_SECS - 1).unwrap_err(), BridgeError::Token(TokenError::MintCapExceeded { cap: 1_000, minted_today: 1_000, amount: 1 }));
        deposit(&mut st, &mut tk, TOKEN, 1_000, 2, 6 * MINT_DAY_SECS).unwrap();
        let b = tk.backing(zusd, 2, &TOKEN).unwrap();
        assert_eq!((b.minted_today, b.mint_day, b.locked), (1_000, 6, 2_000));
        assert!(tk.backing_invariant_holds());
        // A burn releases custody and never touches the day's counter: minting is what is capped.
        tk.release(zusd, 2, &TOKEN, 500, 0).unwrap();
        assert_eq!(tk.backing(zusd, 2, &TOKEN).unwrap().minted_today, 1_000);
    }

    /// The day is the block timestamp's UTC day: `timestamp_ms / 86_400_000`, which is what the
    /// ledger's `now_secs / 86_400` computes.
    #[test]
    fn the_mint_day_is_the_utc_day_of_the_block_time() {
        for ms in [0u64, 86_399_999, 86_400_000, 1_758_240_000_000, 1_758_326_399_999] {
            assert_eq!(mint_day(ms / 1000) as u64, ms / 86_400_000, "{ms}");
        }
        assert_eq!(mint_day(u64::MAX), u32::MAX, "saturates, never wraps");
    }

    /// Audit v4 (bridge rules v2), the gating guard: a bridge built from a chain-14-shaped config
    /// — no `rules_v2` — commits under `rand-bridge-state-4` to exactly the bytes it did before
    /// v0.5.4, whatever the rotation counter reads, and its storage blob is the v1 `BridgeMeta`
    /// with no v2 half. The pin is the root this fixture had at v0.5.3.
    #[test]
    fn a_bridge_without_rules_v2_has_the_pinned_v4_root_and_no_v2_meta() {
        let (c, _) = cfg();
        let mut st = BridgeState::from_config(&c);
        (st.mint_paused, st.pause_nonce, st.list_nonce, st.burn_sequence) = (true, 3, 9, 2);
        assert_eq!(st.root().to_hex(), "5df59d6ada206d29301125c469d8e61beee05d4ee6568a09f0bf63083eb18014");
        assert_eq!(st.rules_v2, None);
        assert_eq!(st.meta_v2(), None, "no v2 half to store");
        // The rotation counter is not in the v4 root: without `rules_v2` nothing can move it,
        // and a chain-14 node must not fork on a field it never had.
        st.rotation_nonce = 7;
        assert_eq!(st.root().to_hex(), "5df59d6ada206d29301125c469d8e61beee05d4ee6568a09f0bf63083eb18014");
        let meta = st.meta();
        assert_eq!(BridgeState::from_parts(meta, None, BTreeSet::new(), BTreeMap::new()).rotation_nonce, 0);
    }

    /// Bridge rules v2: a `rules_v2` section moves the bridge root to `rand-bridge-state-5`
    /// (the rotation nonce and the two cap parameters are in it), the v2 half of the meta is
    /// `Some` and round-trips beside the unchanged v1 blob, and `from_config` carries the rules.
    #[test]
    fn rules_v2_move_the_root_to_the_v5_domain_and_ride_a_second_meta_blob() {
        let (mut c, _) = cfg();
        let v1 = BridgeState::from_config(&c);
        c.rules_v2 = Some(BridgeRulesV2 { global_mint_cap_per_window: 5_000, cap_window_secs: 86_400 });
        let mut st = BridgeState::from_config(&c);
        assert_eq!(st.rules_v2, c.rules_v2);
        assert_eq!(st.meta(), v1.meta(), "the v1 blob is byte-for-byte the v1 bridge's");
        assert_ne!(st.root(), v1.root(), "the rules are in the root");
        let r0 = st.root();
        st.rotation_nonce = 1;
        assert_ne!(st.root(), r0, "and so is the rotation nonce");
        let v2: BridgeMetaV2 = bincode::deserialize(&bincode::serialize(&st.meta_v2().unwrap()).unwrap()).unwrap();
        assert_eq!(v2, BridgeMetaV2 { rotation_nonce: 1, rules: c.rules_v2.clone().unwrap() });
        assert_eq!(BridgeState::from_parts(st.meta(), Some(v2), BTreeSet::new(), BTreeMap::new()), st);
    }

    /// The pause state, both nonces and the pause key ride the storage blob.
    #[test]
    fn the_pause_state_is_in_the_meta_blob() {
        let (c, _) = cfg();
        let mut st = BridgeState::from_config(&c);
        assert_eq!(st.pause_key, c.pause_key);
        assert!(!st.mint_paused);
        (st.mint_paused, st.pause_nonce, st.list_nonce) = (true, 3, 9);
        let meta: BridgeMeta = bincode::deserialize(&bincode::serialize(&st.meta()).unwrap()).unwrap();
        assert_eq!(BridgeState::from_parts(meta, None, BTreeSet::new(), BTreeMap::new()), st);
    }
}
