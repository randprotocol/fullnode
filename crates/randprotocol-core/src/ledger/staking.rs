//! The validator register and the staking rules for `Bond`, `Unbond` and `Withdraw`
//! (spec §8, phase S2).
//!
//! The register is the one public table on the chain: a validator's key, its bonded stake, the
//! amounts it has moved into unbonding, the fees it has earned as proposer, the shielded address
//! it is paid at, and the nonce that keeps its signed actions from being replayed. It is hashed
//! into the state root (`super::Ledger::state_root`), and [`derive_set`] is the only place the
//! rule turning it into an epoch's [`ValidatorSet`] is written.
//!
//! Everything here is deterministic and cheap: no proof is verified, and the only hash is the
//! note commitment the chain computes for a withdraw's deposit — which the chain computes
//! itself, from the register's payout address and the action's published blinding, precisely so
//! a validator cannot declare one amount and mint a note for another.
//!
//! One thing here is not about the register at all: [`Ledger::derived_commitment`], which answers
//! that same question — "what note would this action make the ledger create?" — for every action
//! that makes one, a `BridgeAttest` included. It lives beside the withdraw note because the
//! withdraw is where the problem first appeared, and it is one function because the mempool needs
//! one answer (`randprotocol_node::mempool`).

use super::{bridge_notes, Ledger, TxError};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{Address, PublicKey, Signature};
use crate::gas;
use crate::notes::{ShieldedAddress, Word8, KEM_EK_BYTES};
use crate::types::actions::{
    admit_validator_message, registration_message_v2, Registration,
    SignedHeader,
};
use crate::types::{Action, Transaction, ValidatorSet, UNITS_PER_RAND};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Blocks per epoch unless genesis says otherwise (spec §8).
pub const EPOCH_BLOCKS_DEFAULT: u64 = 1000;
/// Epochs an unbonded amount waits before it can be withdrawn.
pub const UNBONDING_EPOCHS: u64 = 2;
/// Stake an entry needs to be in an epoch's validator set (1000 RAND).
pub const MIN_STAKE: u64 = 1000 * UNITS_PER_RAND;
/// Largest validator set an epoch can have.
pub const MAX_VALIDATORS: usize = 100;
/// The most admissions the ledger holds at once under `staking.admission_by_vote` (audit v6,
/// STAKE-2): keys the set has voted in that have not registered yet. The set is consensus state
/// — hashed, persisted, cloned with the ledger — so it is bounded; past it an `AdmitValidator`
/// is refused `AdmissionSetFull` until a registration consumes a row. 256 is two and a half
/// full validator sets' worth of candidates waiting at once.
pub const MAX_ADMITTED: usize = 256;
/// How far back equivocation evidence is admitted (audit v6, STAKE-1), in epochs: a
/// `SlashEquivocation` is valid only while `epoch(header height) + EVIDENCE_EPOCHS >= epoch()`
/// for both headers — the epoch the headers claim, or the one after it. The one inequality the
/// rule rests on: **`EVIDENCE_EPOCHS < UNBONDING_EPOCHS`**. A leader of epoch `E` held at least
/// `MIN_STAKE` at the end of `E − 1` (the set of `E` is derived from that register), so the
/// earliest `Unbond` of that stake is in epoch `E` and its release epoch at least `E +
/// UNBONDING_EPOCHS`; evidence for a header of epoch `E` is admissible through `E +
/// EVIDENCE_EPOCHS`, strictly before that, so the stake is still bonded or still unbonding
/// (`pending`) — slashable either way — whenever the evidence can land.
/// `evidence_cannot_outlive_the_stake` pins the inequality.
pub const EVIDENCE_EPOCHS: u64 = 1;
const _: () = assert!(EVIDENCE_EPOCHS < UNBONDING_EPOCHS, "evidence must land before the offender's stake can leave");
/// The most a `SlashEquivocation` transaction may encode to (audit v6, STAKE-1): 1 MiB. Each
/// header carries its `justify` certificate, up to `MAX_VALIDATORS` Dilithium2 votes of ~3.8 KB
/// (~380 KB a header); two of them and the rest fit with room. A header whose justify is bigger
/// than that verifies as no block — a certificate holds at most one vote per validator of its
/// set — so the pair a harmful equivocation consists of (two blocks some replica could accept)
/// always fits; only a junk second header nobody could vote for can be too big to carry, and it
/// harmed nobody.
pub const MAX_EVIDENCE_BYTES: usize = 1 << 20;

/// One row of the register (spec §8). `stake`, `pending` and `rewards` are token units like
/// every other amount on this chain; they are the only amounts stored in the clear.
///
/// v2 (phase S2) over the S1 shape: `stake` narrowed from `u128` to `u64` (it is widened again
/// at the [`ValidatorSet`] boundary, where consensus arithmetic wants the headroom), and
/// `pending`, `payout` and `nonce` are new.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub public_key: PublicKey,
    /// Bonded stake: the weight [`derive_set`] gives this validator in an epoch's set.
    pub stake: u64,
    /// Unbonding amounts as `(release_epoch, amount)`, oldest first. Withdrawable once
    /// `release_epoch <= ledger.epoch()`.
    pub pending: Vec<(u64, u64)>,
    /// Fees credited to this validator as a block proposer (spec §8): a bundle's fee, and the
    /// base a `Withdraw` pays out of the amount it withdraws. Paid out by `Withdraw`.
    pub rewards: u64,
    /// Where `Withdraw` pays: the shielded address the deposit note is created for.
    pub payout: ShieldedAddress,
    /// Incremented on every accepted `Unbond` and `Withdraw`. There are no accounts on this
    /// chain, so this is the whole of the replay protection for validator-signed actions.
    pub nonce: u64,
    /// The first epoch this entry may be in the set of (audit v4, STAKE-2 rule 3). Genesis
    /// validators and every bond on a chain without a [`StakingConfig`] carry 0 — weight at the
    /// very next boundary, as always — and under the section a registering bond in epoch `e`
    /// carries `e + 1 + bond_activation_epochs`. Last, so a row stored before the field
    /// existed decodes with a fallback (`Storage::register`); hashed into the leaf only under
    /// the section (`rand-validator-leaf-4`), so a chain without one commits the v2 leaf.
    pub activation_epoch: u64,
}

/// The `staking` genesis section (audit v4, STAKE-2): a per-epoch budget for the testnet faucet
/// and an activation delay for bonds. Present only on a chain whose genesis carries it — the
/// three rules it switches on are gated on `Ledger::staking()` being `Some`, so chain 14, which
/// has no section, behaves and hashes byte-for-byte as before.
///
/// `faucet_budget_per_epoch` is in RAND's base unit, and rides in the genesis file as a decimal
/// string like every amount an RPC serves; `bond_activation_epochs` is the number of whole
/// epochs a new bond waits *beyond* the boundary it would have joined at.
///
/// Three later fields close the gaps the v4 re-review listed (admission, weight cap, proof of
/// possession). Each is optional inside the optional section, omitted from the file when
/// absent and committed to the genesis hash only when present, so a v0.5.4-shaped section
/// hashes byte-for-byte as it did:
///
/// - `max_weight_bps`: no validator's voting weight exceeds this fraction of its set's total,
///   in basis points (3333 = one third) — [`cap_weights`];
/// - `max_stake_entry_per_epoch`: the most stake, new entries and top-ups together, that may
///   become voting weight at one epoch boundary; the rest waits its turn in the bond queue
///   ([`QueuedStake`], `Ledger::admit_queued_stake`);
/// - `registration_v2`: a `Bond`'s registration is signed over [`registration_message_v2`] —
///   the genesis hash and the validator's address beside the chain id and the payout — instead
///   of the v1 message. Only `true` switches it on.
///
/// And one for a testnet that keeps a bridge *and* a faucet (chain 15):
///
/// - `faucet_recipients`: a `Mint` may create a note only for one of these spend keys
///   (`TxError::FaucetRecipientNotAllowed`), so the faucet feeds the named testers and cannot buy
///   the register for anyone else. It is what lets `faucet: true` sit beside a `bridge` section
///   (`GenesisError::FaucetWithBridge` otherwise); an empty list is refused. The budget above
///   still applies on top.
///
/// And its twin on the signing side, which closes the rescan's RESCAN-LEDGER-1 as a validity rule
/// (the next cut):
///
/// - `faucet_minters`: a `Mint` may be signed only by one of these validator keys
///   (`TxError::MinterNotAllowed`). The ledger's own rule is a row in the register, which a
///   permissionless `Bond` writes at once, and the bonded key is in the active set
///   `bond_activation_epochs + 1` epochs later — so neither bounds who drains the budget. An empty
///   or duplicated list is refused; absent, the register row is the rule and every node's
///   admission policy admits the genesis validators only.
///
/// And audit v6's (STAKE-2), each absent from every genesis through chain 18, omitted from the file
/// when absent and committed to the genesis hash under its own tag, after every tag that existed
/// before it, only when set:
///
/// - `admission_by_vote`: a `Bond` that would *register* a new validator key is refused
///   ([`StakingError::NotAdmitted`]) unless the set has voted the key in with an
///   `Action::AdmitValidator`. Until slashing exists an open register turns the price of two
///   thirds of the stake into a purchase; this turns it into a vote. Only `true` switches it on.
/// - `max_stake_entry_bps_per_epoch`: the entry budget as a fraction — the most weight, in basis
///   points of the active bonded weight at the boundary, that may become weight at one epoch
///   boundary ([`Ledger::admit_queued_stake`]). `max_stake_entry_per_epoch` is a fixed RAND
///   figure: 10 000 RAND an epoch bounds a 26 000-RAND genesis for two epochs and a 26 000 000-RAND
///   one for two thousand, so the time an entrant needs to reach a third of the weight scales with
///   the genesis stake; as a fraction that time is the same at every scale. `1..=10 000`; refused
///   beside `max_stake_entry_per_epoch` (one budget, not two).
/// - `slashing` (audit v6, STAKE-1): leader equivocation is punished — `equivocation_bps` of the
///   offender's bonded and unbonding stake is destroyed and the key is jailed for `jail_epochs`
///   epochs (`0` = for good) from the next boundary. Absent, an equivocation is refused and
///   logged as before and nothing is at stake. Needs `consensus_domain: 1` (the evidence is two
///   signatures under the chain's own domain) and is refused beside a `vesting` section (stake
///   bonded from a lock is not slashable yet — see [`SlashingConfig`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StakingConfig {
    #[serde(with = "amount_string")]
    pub faucet_budget_per_epoch: u64,
    pub bond_activation_epochs: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_weight_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_amount_string")]
    pub max_stake_entry_per_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_v2: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet_recipients: Option<Vec<FaucetRecipient>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet_minters: Option<Vec<FaucetMinter>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_by_vote: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stake_entry_bps_per_epoch: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slashing: Option<SlashingConfig>,
}

/// The `staking.slashing` section (audit v6, STAKE-1): what a leader equivocation costs.
///
/// - `equivocation_bps` (`1..=10 000`): the fraction of the offender's stake — bonded, and every
///   unbonding row not yet withdrawn — destroyed at the slash, floor-rounded per amount, counted
///   in the supply's `slashed` (`total_supply == issued − slashed` holds through it).
/// - `jail_epochs`: how many whole epochs the key is out of the active set, from the boundary
///   after the slash; `0` is for good, and otherwise more than [`EVIDENCE_EPOCHS`] (genesis
///   refuses `1..=EVIDENCE_EPOCHS`: a shorter jail could end while the same evidence is still in
///   its window, and the one offence would be slashed twice). A jailed key is refused a `Bond` top-up
///   (`StakingError::Jailed`) and cannot re-register (a registered key never leaves the
///   register). While jailed a second piece of evidence is refused (`Jailed`), and every piece
///   that existed at the slash is outside [`EVIDENCE_EPOCHS`] by the time any jail ends — a jail
///   is at least one boundary plus one epoch — so one offence is slashed once and a key that
///   equivocated ten times in an epoch loses `equivocation_bps` once, and its seat.
///
/// What is **not** evidence: vote equivocation (two votes by one key for one view — refused and
/// logged by `HotStuff::on_vote`, never slashed), a proposal for a wrong view or by a non-leader,
/// and anything that is not two signatures by one key over two different headers of one view.
///
/// Refused beside a `vesting` section at genesis: stake a lock bonded (`BondVested`) sits in the
/// validator's `stake` and returns to the lock's own unbonding rows — which carry no validator —
/// so it could leave a slashed validator untouched. Slashing locked stake needs the vesting
/// register to attribute its unbonding rows; until it does, a chain has one section or the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlashingConfig {
    pub equivocation_bps: u32,
    pub jail_epochs: u64,
}

impl SlashingConfig {
    /// The first epoch a key slashed in `epoch` may be in a set again: the boundary after the
    /// slash opens `epoch + 1`, and the jail holds through `jail_epochs` whole epochs from there
    /// — `u64::MAX` for good, which no epoch reaches.
    pub fn jailed_until(&self, epoch: u64) -> u64 {
        match self.jail_epochs {
            0 => u64::MAX,
            n => epoch.saturating_add(1).saturating_add(n),
        }
    }
}

impl StakingConfig {
    /// Whether registrations need the set's vote (audit v6, STAKE-2): only `Some(true)`.
    pub fn admission_by_vote(&self) -> bool {
        self.admission_by_vote == Some(true)
    }
}

/// One entry of `staking.faucet_recipients`: the spend public key `pk` a faucet `Mint` may pay.
/// Since POOL-1 a mint publishes its note's opening, `pk` included, and the ledger recomputes the
/// commitment from it — so the recipient is on the wire and a list of keys can be enforced.
///
/// The genesis file may name one either way: 64 hex characters (the `pk` of a `GenesisOpening`,
/// `word8_to_hex`), or a whole `rand1…` shielded address (what `rand address` prints), whose `pk`
/// is taken and whose ML-KEM key is dropped — a faucet note is sealed to whatever envelope the
/// minter builds, and only `pk` is bound. It is always written back as hex, and only the 32 `pk`
/// bytes are committed to the genesis hash, so both spellings of one key are one chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaucetRecipient(pub Word8);

impl Serialize for FaucetRecipient {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::notes::word8_to_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for FaucetRecipient {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let t = String::deserialize(d)?;
        if t.starts_with(crate::notes::ADDRESS_PREFIX) {
            return ShieldedAddress::parse(&t)
                .map(|a| FaucetRecipient(a.pk))
                .map_err(|e| serde::de::Error::custom(format!("faucet recipient {t:?}: {e}")));
        }
        crate::notes::word8_from_hex(&t).map(FaucetRecipient).ok_or_else(|| {
            serde::de::Error::custom(format!("faucet recipient {t:?} is neither 64 hex characters nor a rand1 address"))
        })
    }
}

/// One entry of `staking.faucet_minters`: the address of a validator key that may sign a faucet
/// `Mint`. The genesis file may name one three ways — the address as `rand-node` prints it
/// (base58), those 32 bytes as 64 hex characters, or the validator's whole Dilithium2 public key
/// in hex, as `validators[].public_key` carries it — and it is always written back as the base58
/// address. Only the 32 address bytes are committed to the genesis hash, so every spelling of one
/// key is one chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FaucetMinter(pub Address);

impl Serialize for FaucetMinter {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for FaucetMinter {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let t = String::deserialize(d)?;
        if t.len() == 64 {
            if let Ok(bytes) = hex::decode(&t) {
                return Ok(FaucetMinter(Address(bytes.try_into().expect("64 hex characters are 32 bytes"))));
            }
        }
        if let Ok(pk) = PublicKey::from_hex(&t) {
            return Ok(FaucetMinter(pk.address()));
        }
        Address::from_base58(&t).map(FaucetMinter).map_err(|_| {
            serde::de::Error::custom(format!(
                "faucet minter {t:?} is neither an address (base58 or 64 hex characters) nor a validator public key in hex"
            ))
        })
    }
}

/// The largest `max_weight_bps` means anything: 10 000 is the whole set, i.e. no cap.
pub const MAX_WEIGHT_BPS: u32 = 10_000;

/// Stake bonded under a `staking` section that is not voting weight yet (the v4 re-review's
/// "admission" and "delay" gaps). Every `Bond` under the section — a registration and a top-up
/// alike — adds its amount to the entry's `stake` at once (so the supply audit, the register's
/// RPC rows and the overflow bound see bonded value where it is) *and* queues it here, and
/// [`derive_set_with`] subtracts what is still queued from the entry's weight.
///
/// `epoch` is the first epoch the amount may be weight in: `e + 1 + bond_activation_epochs` for a
/// bond in epoch `e`, the registration's `activation_epoch` and a top-up's alike. The queue is in
/// the order the bonds were applied, and that order is the admission order: at each epoch
/// boundary `Ledger::admit_queued_stake` walks it front to back, admits what is due up to
/// `max_stake_entry_per_epoch` and moves the rest of what was due to the next epoch, in place.
/// Consensus state under the section: hashed into the state root and persisted beside
/// `META_SUPPLY`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedStake {
    pub validator: Address,
    pub amount: u64,
    pub epoch: u64,
}

/// A `u64` amount as a decimal string in the genesis file (the RPC's amount convention). A
/// plain JSON number is accepted on the way in, so a hand-edited file is not refused for it.
pub(crate) mod amount_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Text(String),
            Number(u64),
        }
        match Repr::deserialize(d)? {
            Repr::Number(n) => Ok(n),
            Repr::Text(t) => t.parse().map_err(|_| serde::de::Error::custom(format!("not a decimal amount: {t:?}"))),
        }
    }
}

/// `Option<u64>` as [`amount_string`] writes a `u64`: a decimal string when present.
mod opt_amount_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(n) => super::amount_string::serialize(n, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        struct Wrap(#[serde(with = "super::amount_string")] u64);
        Ok(Option::<Wrap>::deserialize(d)?.map(|w| w.0))
    }
}

/// Why a staking action was refused. Carried inside [`TxError::Staking`] so admission reports
/// one reason per rule rather than a single "invalid transaction".
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum StakingError {
    #[error("validator {0} is not in the register")]
    UnknownValidator(Address),
    #[error("validator {0} is already registered")]
    AlreadyRegistered(Address),
    #[error("stake {amount} is below the minimum {min}")]
    BelowMinStake { amount: u64, min: u64 },
    #[error("a bond to an unregistered validator must carry its registration")]
    RegistrationRequired,
    #[error("the registration is for another validator")]
    BadRegistration,
    #[error("wrong nonce: expected {expected}, got {actual}")]
    BadNonce { expected: u64, actual: u64 },
    #[error("bad validator signature")]
    BadSignature,
    #[error("stake {have} is less than the {want} being unbonded")]
    InsufficientStake { have: u64, want: u64 },
    #[error("amount must not be zero")]
    ZeroAmount,
    #[error("only {available} is released, cannot withdraw {want}")]
    NothingReleased { available: u64, want: u64 },
    #[error("withdraw of {amount} does not cover the bundle base {base}")]
    BelowBundleBase { amount: u64, base: u64 },
    #[error("a bond's bundle must burn exactly the bonded amount: burn {burn}, amount {amount}")]
    BurnMismatch { burn: u64, amount: u64 },
    #[error("arithmetic overflow")]
    Overflow,
    /// Audit v6, STAKE-2: under `staking.admission_by_vote`, a `Bond` that would register a key
    /// the validator set has not voted in. State — an `AdmitValidator` one block later makes the
    /// same bond valid — so never a permanent admission verdict.
    #[error("validator {0} has not been admitted by the validator set's vote (staking.admission_by_vote); ask the validators for an AdmitValidator first")]
    NotAdmitted(Address),
    /// An `AdmitValidator` for a key that is already admitted and waiting to register.
    #[error("validator {0} is already admitted")]
    AlreadyAdmitted(Address),
    /// The admitted set holds [`MAX_ADMITTED`] keys that have not registered yet.
    #[error("the admitted set is full ({max} keys admitted and not yet registered)")]
    AdmissionSetFull { max: usize },
    /// An `AdmitValidator` whose candidate key is not a Dilithium2 public key's length: no such
    /// key could ever sign a registration. About the bytes alone.
    #[error("the candidate key is {len} bytes, not a validator key")]
    BadCandidateKey { len: usize },
    /// An `AdmitValidator` carrying no vote, or more votes than the voting set has members.
    #[error("an admission carries {got} votes; the voting set has {max} members")]
    AdmissionVoteCount { got: usize, max: usize },
    /// The votes are not in strictly ascending order of their voters' addresses — which is also
    /// what a voter listed twice is. About the bytes alone.
    #[error("the admission's votes are not in strictly ascending voter order (a voter may appear once)")]
    AdmissionVoteOrder,
    /// A vote by a key that is not in the voting set: not registered, not yet active, or below
    /// the minimum stake.
    #[error("{0} is not in the voting validator set")]
    AdmissionVoterNotInSet(Address),
    /// The voters' combined weight is not strictly more than two thirds of the voting set's.
    #[error("the admission's voters hold {weight} of {total}: not more than two thirds")]
    AdmissionNoQuorum { weight: u128, total: u128 },
    /// A vote whose signature does not verify under its own key over this chain's admission
    /// message for this candidate — a vote for another chain's genesis, or for another key.
    /// About the bytes against the genesis hash.
    #[error("the vote by {0} is not a signature over this chain's admission of this candidate")]
    BadAdmissionVote(Address),
    /// Audit v6, STAKE-1: a `Bond` top-up of a jailed key, or evidence against a key already
    /// jailed (one slash per jail). `until` is the first epoch it may be in a set again
    /// (`u64::MAX`: for good). State: the jail ends.
    #[error("validator {validator} is jailed until epoch {until}")]
    Jailed { validator: Address, until: u64 },
    /// A `SlashEquivocation` whose two headers are not an equivocation: the same header twice,
    /// two views, two keys, or the pair out of canonical order. About the bytes alone.
    #[error("the two headers are not an equivocation: {0}")]
    NotEquivocation(&'static str),
    /// A `SlashEquivocation` over [`MAX_EVIDENCE_BYTES`]. About the bytes alone.
    #[error("the evidence encodes to {size} bytes, over the {max} byte cap")]
    EvidenceTooLarge { size: usize, max: usize },
    /// A header from the future (past the ledger's height) or older than [`EVIDENCE_EPOCHS`]
    /// epochs. State: the window moves.
    #[error("evidence at height {height} (epoch {epoch}) is outside the window at epoch {current}: a header must be at most one block above the head and at most {} epoch(s) old", EVIDENCE_EPOCHS)]
    EvidenceOutOfWindow { height: u64, epoch: u64, current: u64 },
    /// The offender has neither bonded nor unbonding stake: nothing to slash. State.
    #[error("validator {0} has nothing at stake")]
    NothingAtStake(Address),
    /// One of the two signatures does not verify under the header's own proposer key over this
    /// chain's consensus signing domain (`SigningDomain::block_message`). About the bytes against
    /// the genesis: a header signed for another chain never verifies here.
    #[error("the {0} header's signature does not verify under its proposer key on this chain")]
    BadEvidenceSignature(&'static str),
}

/// The validator set for an epoch, from the register as of the last block of the epoch before
/// (spec §8, and the plan's Global Constraints): every entry with `stake >= MIN_STAKE`, the top
/// [`MAX_VALIDATORS`] by `(stake desc, address asc)`, in address order.
///
/// This is a pure function of the register, which is what lets every replica derive the same set
/// from the same parent ledger without agreeing on anything else first.
///
/// **The result can be empty**, and a caller must not use an empty set: `ValidatorSet::leader`
/// takes `view % len()`. Genesis refuses a validator below [`MIN_STAKE`], so a chain cannot
/// start empty, but every validator unbonding below it during one epoch would empty the next
/// one. Consensus answers that in `HotStuff::shared_set_for_height`: an empty derivation carries
/// the previous epoch's set forward, so there is still a block in which to bond back in. Deriving
/// the set is not the place to decide that — this function says what the register contains, not
/// what consensus does about it.
///
/// `epoch` is the epoch the set is derived *for*: an entry whose `activation_epoch` is past it
/// is not in the set, whatever its stake (audit v4, STAKE-2 rule 3). On a chain without a
/// `staking` section every entry's activation epoch is 0 and the argument changes nothing.
pub fn derive_set(register: &BTreeMap<Address, ValidatorEntry>, epoch: u64) -> ValidatorSet {
    derive_set_with(register, &[], epoch, None)
}

/// [`derive_set`] under a `staking` section's later fields: an entry's weight is its stake less
/// what of it is still queued for an epoch past `epoch` (the bond queue, [`QueuedStake`]), the
/// minimum, the activation epoch and the [`MAX_VALIDATORS`] cut are applied to that weight, and
/// the survivors' weights are then capped by [`cap_weights`] when `max_weight_bps` is set.
///
/// This is the only place a `ValidatorSet`'s weights come from after genesis, so every reader
/// of them — the quorum and third checks, QC verification, the leader schedule's set — reads
/// the capped weights and nothing else. With an empty queue and no cap it is [`derive_set`].
pub fn derive_set_with(
    register: &BTreeMap<Address, ValidatorEntry>,
    queue: &[QueuedStake],
    epoch: u64,
    max_weight_bps: Option<u32>,
) -> ValidatorSet {
    derive_set_jailed(register, queue, epoch, max_weight_bps, &BTreeMap::new())
}

/// [`derive_set_with`] under `staking.slashing` (audit v6, STAKE-1): an entry jailed for `epoch`
/// — `jailed[addr] > epoch` — is in no set, whatever its stake. `Ledger::derive_next_set` passes
/// the ledger's jail; without the section the map is empty and this is [`derive_set_with`].
pub fn derive_set_jailed(
    register: &BTreeMap<Address, ValidatorEntry>,
    queue: &[QueuedStake],
    epoch: u64,
    max_weight_bps: Option<u32>,
    jailed: &BTreeMap<Address, u64>,
) -> ValidatorSet {
    let mut waiting: BTreeMap<&Address, u64> = BTreeMap::new();
    for q in queue.iter().filter(|q| q.epoch > epoch) {
        let w = waiting.entry(&q.validator).or_default();
        *w = w.saturating_add(q.amount);
    }
    let mut eligible: Vec<(&Address, &ValidatorEntry, u64)> = register
        .iter()
        .map(|(a, e)| (a, e, e.stake.saturating_sub(waiting.get(a).copied().unwrap_or(0))))
        .filter(|(a, e, weight)| *weight >= MIN_STAKE && e.activation_epoch <= epoch && !jailed.get(*a).is_some_and(|until| *until > epoch))
        .collect();
    // Descending weight, then ascending address: the cut must not depend on map order.
    eligible.sort_by(|(a_addr, _, a), (b_addr, _, b)| b.cmp(a).then_with(|| a_addr.cmp(b_addr)));
    eligible.truncate(MAX_VALIDATORS);
    // `ValidatorSet::new` puts the survivors back in address order.
    let set = ValidatorSet::from_entries(eligible.into_iter().map(|(_, e, weight)| (&e.public_key, weight)));
    match max_weight_bps {
        Some(bps) => cap_weights(set, bps),
        None => set,
    }
}

/// Clamp every weight in `set` so that no validator holds more than `max_weight_bps` / 10 000 of
/// the set's (clamped) total — the v4 re-review's weight cap. One level `C` is found and every
/// weight above it is lowered to it; weights below it are untouched, and the result is a pure
/// function of the multiset of weights (ties cannot matter: equal weights clamp equally).
///
/// Clamping lowers the total, so a cap computed once from the unclamped total is not enough.
/// With the weights sorted descending `w_0 ≥ w_1 ≥ … ≥ w_{n-1}`, `b = max_weight_bps` and
/// `R_k = w_k + … + w_{n-1}`, clamping exactly the top `k` to `C` needs `C ≤ b·(k·C + R_k)/10⁴`,
/// whose largest integer solution is `C_k = ⌊b·R_k / (10⁴ − b·k)⌋`. The smallest `k` with
/// `C_k ≥ w_k` is taken: then every clamped weight exceeds `C_k` (the `k − 1` case failed, which is
/// `C_k < w_{k−1}` exactly), no unclamped one does, and `C_k ≤ b·total/10⁴` by construction.
/// `k = 0` is a set already under the cap, returned unchanged.
///
/// A set with fewer than ⌈10⁴ / b⌉ members cannot meet the cap at all (three equal validators
/// hold a third each, above 3 333 basis points); no `k` qualifies, and every weight is levelled
/// to the smallest — the closest to the cap such a set can come. `b ≥ 10 000` changes nothing;
/// genesis refuses 0 (`Genesis::validate`).
pub fn cap_weights(set: ValidatorSet, max_weight_bps: u32) -> ValidatorSet {
    const DENOM: u128 = MAX_WEIGHT_BPS as u128;
    let b = u128::from(max_weight_bps);
    if b >= DENOM || set.is_empty() {
        return set;
    }
    let mut w: Vec<u128> = set.iter().map(|v| v.stake).collect();
    w.sort_unstable_by(|x, y| y.cmp(x));
    let mut suffix = vec![0u128; w.len() + 1];
    for k in (0..w.len()).rev() {
        suffix[k] = suffix[k + 1].saturating_add(w[k]);
    }
    let mut level = w[w.len() - 1];
    for k in 0..w.len() {
        let Some(den) = DENOM.checked_sub(b * k as u128).filter(|d| *d > 0) else { break };
        let c = b.saturating_mul(suffix[k]) / den;
        if c >= w[k] {
            level = c;
            break;
        }
    }
    ValidatorSet::new(
        set.iter().map(|v| crate::types::Validator { public_key: v.public_key.clone(), stake: v.stake.min(level) }).collect(),
    )
}

impl Ledger {
    /// Released value: unbonded amounts whose epoch has arrived, plus the proposer rewards.
    /// Unknown validators have nothing released rather than being an error, so a caller can ask
    /// about any address.
    pub fn released(&self, validator: &Address) -> u64 {
        let epoch = self.epoch();
        self.validators().get(validator).map_or(0, |e| {
            e.pending
                .iter()
                .filter(|(release_epoch, _)| *release_epoch <= epoch)
                .map(|(_, amount)| *amount)
                .fold(e.rewards, |acc, a| acc.saturating_add(a))
        })
    }

    /// The note this ledger would create for `action` itself — the one commitment that is not on
    /// the wire — for a caller that has to reason about it before admission does: the mempool's
    /// conflict index, which must hold such a note just as it holds a bundle's outputs, or it
    /// pools two transactions of which at most one could ever be included.
    ///
    /// Both actions that mint a note out of public words and a blinding are here, and this is the
    /// only place either is derived from outside the ledger:
    ///
    /// - a `Withdraw` (S2), whose owner is known only to the register — the validator's payout
    ///   address — and whose amount is the withdrawal less the bundle base;
    /// - a `BridgeAttest` (S3), whose amount is the one the guardians signed and whose `asset` is
    ///   the index the token registry holds for it, neither of which the submitter chooses. Read
    ///   off the wire bytes and the registry alone (`bridge_notes::attested_transfer`,
    ///   `TokenRegistry::get_by_id`): no
    ///   guardian signature is recovered, because a caller screening a pool must not be able to
    ///   buy that work. The action's own `asset` word is deliberately not consulted: it is the
    ///   submitter's claim, and admission holds it to this very index
    ///   (`TxError::AttestAssetMismatch`).
    ///
    /// The aggregator register's two are alongside, one role over: the `WithdrawAggregator`'s,
    /// the bond less the base at the entry's payout, and the `Aggregate`'s payout note (spec §4
    /// step 5), the subsidy the block would pay — both claimed in the mempool before either is
    /// validated, exactly as the two above.
    ///
    /// `None` when the action creates no such note, and when this state cannot derive one — an
    /// unknown validator, an amount that does not cover the bundle base, a chain with no bridge, an
    /// attestation over [`gas::MAX_ATTESTATION_BYTES`] (checked before the decode, so a caller
    /// screening unvalidated transactions cannot be made to parse a blob), one that decodes to no
    /// transfer (a rotation deposits nothing), or one naming an asset the registry has no index for.
    /// Every one of those is something [`validate`] refuses on its own, which is what makes a
    /// missing claim safe here: the pool would admit a second transaction only for the ledger to
    /// refuse it.
    pub fn derived_commitment(&self, action: &Action, executor: &dyn ConfidentialExecutor) -> Option<Word8> {
        match action {
            Action::Withdraw { validator, amount, time, r, .. } => {
                withdraw_note(self, validator, *amount, *time, r, executor).ok()
            }
            // Genesis vesting: a claim's or a revoke's note, derived from the action alone.
            a @ (Action::ClaimVested { .. } | Action::RevokeVesting { .. }) => super::vesting::derived_note(a, executor),
            Action::WithdrawAggregator { aggregator, time, r, .. } => {
                // The aggregator's withdraw note derives the same way, one register over: the
                // bond less the base, at the entry's payout (spec §2.2).
                super::aggregation::withdraw_note(self, aggregator, *time, r, executor).ok()
            }
            Action::Aggregate { aggregator, covers, time, r, .. } => {
                // The payout note (spec §4 step 5): the subsidy plus the covered bundles'
                // bucketed excesses the block would pay, at the entry's payout, stamped with
                // the action's `time` and blinding — claimed in the mempool exactly as a
                // `BridgeAttest`'s derived deposit is.
                super::aggregation::payout_note(self, aggregator, covers, *time, r, executor).ok()
            }
            Action::BridgeAttest { attestation, recipient, r, time, .. } => {
                // The size cap, before the decode. `validate` applies it at step 1
                // (`TxError::AttestationTooLarge`), but this runs *before* validation — the
                // mempool claims what a transaction would create in order to decide whether to
                // validate it at all — so an oversized blob would otherwise buy a decode here at
                // no fee. Nothing admissible is lost: a transaction over the cap is refused.
                if attestation.len() > gas::MAX_ATTESTATION_BYTES {
                    return None;
                }
                let (chain, token, amount) = bridge_notes::attested_transfer(attestation)?;
                // A bridged holding's index is the token registry's, and an attestation naming a
                // coin nobody listed as a backing deposits nothing — `validate` refuses it
                // outright (`BridgeError::UnlistedToken`), which is what makes a missing claim
                // safe.
                let index = self.bridge().and(self.tokens())?.bridged(chain, &token)?.index;
                Some(bridge_notes::deposit_commitment(recipient, amount, index, *time, r, executor))
            }
            // RPL's two minting actions (spec §4), which derive their note the same way and from
            // the action alone: the recipient, the amount, the index and the blinding are all on
            // the wire, and the chain computes the leaf from them. A registration's index is the
            // one it claims — admission holds it to the registry's next index, so a pooled
            // registration claims exactly the note it would create.
            Action::TokenMint { asset, amount, recipient, r, time, .. } => {
                Some(super::tokens::mint_commitment(recipient, *amount, *asset, *time, r, executor))
            }
            Action::RegisterToken { initial: Some(m), index, .. } => {
                Some(super::tokens::mint_commitment(&m.recipient, m.amount, *index, m.time, &m.r, executor))
            }
            _ => None,
        }
    }

    /// Every note `tx` would make the ledger create beyond the ones it carries on the wire, in
    /// the order the ledger appends them: [`Self::derived_commitment`]'s one for the actions it
    /// answers, and for an RPL-2 `Invoke` one per payout of its transition, pays then mints
    /// ([`super::program_state::payout_commitment`]). An invoke's notes are stamped with its
    /// bundle's `time`, which is why this takes the transaction and the singular form, which
    /// sees only the action, cannot answer for it.
    ///
    /// Like the singular form this runs before validation — the mempool claims what a
    /// transaction would create in order to decide whether to validate it at all — so the payout
    /// count is capped before anything is hashed: a transition over
    /// [`super::program_state::MAX_PAYOUTS`] derives nothing here, and `validate` refuses it
    /// (`ProgramStateError::TooManyPayouts`), as it does an invoke without a bundle.
    pub fn derived_commitments(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Vec<Word8> {
        match (&tx.action, &tx.bundle) {
            (Action::Invoke { transition, .. }, Some(b)) => {
                if transition.pays.len() + transition.mints.len() > super::program_state::MAX_PAYOUTS {
                    return Vec::new();
                }
                transition.payouts().map(|p| super::program_state::payout_commitment(p, b.time, executor)).collect()
            }
            (Action::Invoke { .. }, None) => Vec::new(),
            (action, _) => self.derived_commitment(action, executor).into_iter().collect(),
        }
    }

    /// Add `amount` to `validator`'s stake, inserting the entry when `registration` is present.
    /// The bundle's `burn` is checked by admission (spec §7 step 3), not here — which is why
    /// this is crate-internal: a bond only ever arrives as an `Action::Bond` whose bundle burned
    /// the amount, or as a genesis-vesting `BondVested` (`vesting::apply`), which moves the same
    /// amount out of the vesting register in the same step. Any other direct call would mint
    /// stake out of nothing. (`unbond` and
    /// `withdraw` are public: they take nothing in, and the node's CLI signs them.)
    pub(crate) fn bond(
        &mut self,
        validator: Address,
        amount: u64,
        registration: Option<&Registration>,
        chain_id: u64,
    ) -> Result<(), StakingError> {
        check_bond(self, &validator, amount, registration, chain_id)?;
        match registration {
            Some(r) => {
                // STAKE-2 (audit v6): the registration consumes the admission that permitted it
                // (`check_bond` just required it under the flag). Without the flag the set is
                // empty and this removes nothing.
                self.admitted.remove(&validator);
                // STAKE-2 rule 3: under the section a new entry waits `bond_activation_epochs`
                // whole epochs past the boundary it would otherwise have joined at (`epoch() +
                // 1`). Without the section the field stays 0 — today's rule, and today's leaf.
                let activation_epoch = match self.staking() {
                    Some(_) => self.bond_activation_epoch(),
                    None => 0,
                };
                self.validators.insert(
                    validator,
                    ValidatorEntry {
                        public_key: r.public_key.clone(),
                        stake: amount,
                        pending: Vec::new(),
                        rewards: 0,
                        payout: r.payout.clone(),
                        nonce: 0,
                        activation_epoch,
                    },
                );
            }
            None => {
                let e = self.validators.get_mut(&validator).expect("checked above");
                e.stake = e.stake.checked_add(amount).ok_or(StakingError::Overflow)?;
            }
        }
        // Under the section every bonded amount, a top-up of an active entry included, waits
        // in the bond queue for its activation epoch and its turn (the v4 re-review's "delay"
        // and "admission" gaps). Before this a top-up was weight at the very next boundary
        // whatever `bond_activation_epochs` said, so an active validator could skip the delay
        // a fresh key served.
        if self.staking().is_some() {
            let epoch = self.bond_activation_epoch();
            self.queue_stake(validator, amount, epoch);
        }
        Ok(())
    }

    /// The first epoch a bond applied now may be weight in, under a `staking` section:
    /// `epoch() + 1 + bond_activation_epochs` (STAKE-2 rule 3).
    fn bond_activation_epoch(&self) -> u64 {
        let delay = self.staking().map_or(0, |cfg| u64::from(cfg.bond_activation_epochs));
        self.epoch().saturating_add(1).saturating_add(delay)
    }

    /// Append to the bond queue, merged into the last row when it is the same validator's for
    /// the same epoch — the queue is hashed into the state root, so a hundred top-ups in a row
    /// are one row, as `unbond` keeps one `pending` row per release epoch. A zero amount queues
    /// nothing.
    fn queue_stake(&mut self, validator: Address, amount: u64, epoch: u64) {
        if amount == 0 {
            return;
        }
        match self.bond_queue.last_mut() {
            // `stake` already holds this amount and did not overflow, so neither can a row of it.
            Some(q) if q.validator == validator && q.epoch == epoch => q.amount = q.amount.saturating_add(amount),
            _ => self.bond_queue.push(QueuedStake { validator, amount, epoch }),
        }
    }

    /// What of `validator`'s stake is still in the bond queue, whatever its epoch: bonded, but
    /// not yet weight, and not yet unbondable either.
    pub fn queued_stake(&self, validator: &Address) -> u64 {
        self.bond_queue
            .iter()
            .filter(|q| q.validator == *validator)
            .fold(0u64, |acc, q| acc.saturating_add(q.amount))
    }

    /// The epoch boundary's half of the bond queue, run by `close_block` on the last block of
    /// every epoch under a `staking` section, for `next_epoch`, the epoch the next block opens.
    /// Front to back, in the order the bonds were applied: a row due by `next_epoch` is admitted
    /// in full while the epoch's `max_stake_entry_per_epoch` lasts, in part when it runs out mid
    /// row, and whatever of it is left keeps its place with its epoch moved to `next_epoch + 1`,
    /// so [`derive_set_with`] — which reads this very ledger for `next_epoch`'s set — counts it
    /// as waiting. Rows not yet due are passed over untouched. Without a budget every due row is
    /// admitted, which is the delay rule alone.
    pub(crate) fn admit_queued_stake(&mut self, next_epoch: u64) {
        let Some(cfg) = self.staking() else { return };
        // Audit v6, STAKE-2: the budget as a fraction of the weight already active — the register
        // as `derive_set_with` reads it for `next_epoch` with *every* queued row still waiting
        // (nothing this boundary is about to admit counts towards its own budget), the top
        // `MAX_VALIDATORS`, uncapped (the cap is a vote-weight rule; the budget bounds what
        // enters the stake). `⌊active · bps / 10 000⌋`, so a budget that comes to less than a
        // registration admits it over several boundaries, as the fixed figure does.
        let fraction = cfg.max_stake_entry_bps_per_epoch.map(|bps| {
            let waiting: Vec<QueuedStake> =
                self.bond_queue.iter().map(|q| QueuedStake { validator: q.validator, amount: q.amount, epoch: u64::MAX }).collect();
            let active = derive_set_jailed(&self.validators, &waiting, next_epoch, None, &self.jailed).total_stake();
            u64::try_from(active.saturating_mul(u128::from(bps)) / u128::from(MAX_WEIGHT_BPS)).unwrap_or(u64::MAX)
        });
        let mut budget = fraction.or(cfg.max_stake_entry_per_epoch).unwrap_or(u64::MAX);
        let mut kept = Vec::with_capacity(self.bond_queue.len());
        for mut q in std::mem::take(&mut self.bond_queue) {
            if q.epoch > next_epoch {
                kept.push(q);
                continue;
            }
            let admitted = q.amount.min(budget);
            budget -= admitted;
            if admitted < q.amount {
                q.amount -= admitted;
                q.epoch = next_epoch.saturating_add(1);
                kept.push(q);
            }
        }
        self.bond_queue = kept;
    }

    /// Move `amount` of `validator`'s stake into unbonding, released two epochs from now.
    pub fn unbond(
        &mut self,
        validator: &Address,
        amount: u64,
        nonce: u64,
        signature: &Signature,
        chain_id: u64,
    ) -> Result<(), StakingError> {
        check_unbond(self, validator, amount, nonce, signature, chain_id)?;
        let release_epoch = self.epoch().checked_add(UNBONDING_EPOCHS).ok_or(StakingError::Overflow)?;
        let e = self.validators.get_mut(validator).expect("checked above");
        // One entry per release epoch, not one per transaction: `pending` is hashed into the
        // state root, and a validator that unbonds a hundred times in a block would otherwise
        // make every node carry and hash a hundred rows for it. Epochs only move forward, so
        // the entry to merge into can only ever be the last one.
        let merged = e.pending.last_mut().filter(|(last, _)| *last == release_epoch);
        match merged {
            Some((_, pending)) => *pending = pending.checked_add(amount).ok_or(StakingError::Overflow)?,
            None => e.pending.push((release_epoch, amount)),
        }
        e.stake -= amount;
        e.nonce += 1;
        Ok(())
    }

    /// Take `amount` out of `validator`'s released pending entries and then its rewards,
    /// returning what is left released afterwards. The note itself is created by [`apply`],
    /// which owns the executor; this is only the register's half. The whole `amount` leaves the
    /// register: the note is worth `amount - gas::BUNDLE_BASE`, and the base goes to the block's
    /// proposer (also in [`apply`], which is the only place that knows who that is).
    ///
    /// `time`, `r` and `envelope` are here because the validator's signature is over them too
    /// (spec §6): the note the chain computes has to be the note the validator asked for, so the
    /// message binds them, and this method cannot check the signature without them.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &mut self,
        validator: &Address,
        amount: u64,
        nonce: u64,
        time: u32,
        r: &Word8,
        envelope: &crate::notes::Envelope,
        signature: &Signature,
        chain_id: u64,
    ) -> Result<u64, StakingError> {
        let available = check_withdraw(self, validator, amount, nonce, time, r, envelope, signature, chain_id)?;
        let epoch = self.epoch();
        let e = self.validators.get_mut(validator).expect("checked above");
        // Released pending entries first, oldest first, then the rewards — worked out in full
        // before the entry is touched, so a sum that does not add up changes nothing.
        let mut want = amount;
        let mut kept = Vec::with_capacity(e.pending.len());
        for &(release_epoch, pending) in e.pending.iter() {
            if release_epoch <= epoch && want > 0 {
                let taken = want.min(pending);
                want -= taken;
                if pending > taken {
                    kept.push((release_epoch, pending - taken));
                }
            } else {
                kept.push((release_epoch, pending));
            }
        }
        // `check_withdraw` proved the rewards cover whatever the queue did not, unless
        // `released` had to saturate — in which case this is the rule that says no.
        let rewards = e.rewards.checked_sub(want).ok_or(StakingError::Overflow)?;
        e.pending = kept;
        e.rewards = rewards;
        e.nonce += 1;
        Ok(available.saturating_sub(amount))
    }
}

/// Bond's rules, in spec order: registration present exactly when the validator is unknown, the
/// registration is for this validator and signed by it, and a registration bonds at least
/// [`MIN_STAKE`].
pub(crate) fn check_bond(
    ledger: &Ledger,
    validator: &Address,
    amount: u64,
    registration: Option<&Registration>,
    chain_id: u64,
) -> Result<(), StakingError> {
    match (ledger.validators().get(validator), registration) {
        (Some(_), Some(_)) => return Err(StakingError::AlreadyRegistered(*validator)),
        (None, None) => return Err(StakingError::RegistrationRequired),
        (Some(e), None) => {
            // Audit v6, STAKE-1: a jailed key takes no top-up — nothing is bought back into a
            // seat a slash took. A lookup, before the arithmetic. Empty without the section.
            if let Some(until) = ledger.jailed_until(validator) {
                return Err(StakingError::Jailed { validator: *validator, until });
            }
            e.stake.checked_add(amount).ok_or(StakingError::Overflow)?;
        }
        (None, Some(r)) => {
            if r.public_key.address() != *validator {
                return Err(StakingError::BadRegistration);
            }
            // A payout nobody can seal a note to is not an address: the withdraw note this
            // register entry exists to pay would be unopenable. It also keeps every entry's
            // `payout` a fixed width, which is what makes the v2 validator leaf unambiguous.
            if r.payout.kem_ek.len() != KEM_EK_BYTES {
                return Err(StakingError::BadRegistration);
            }
            // Audit v6, STAKE-2, under `staking.admission_by_vote`: a new key registers only once
            // the validator set has voted it in (`Action::AdmitValidator`). A set lookup, so it
            // comes before the signature. A top-up of an existing entry (the arm above) is not a
            // registration and needs no vote; a `BondVested` that registers comes through here
            // too. Without the flag — every chain through 18 — nothing is asked.
            if ledger.staking().is_some_and(|s| s.admission_by_vote()) && !ledger.admitted().contains(validator) {
                return Err(StakingError::NotAdmitted(*validator));
            }
            // Under `staking.registration_v2` the registration is bound to this chain's genesis
            // and to the validator's address as well (the v4 re-review's "proof of
            // possession"): a v1 registration signed for another chain that shares the chain id
            // bonds nothing here.
            let v2 = ledger.staking().and_then(|s| s.registration_v2) == Some(true);
            let message = match v2 {
                true => registration_message_v2(&ledger.signing_domain().genesis, chain_id, validator, &r.payout),
                // BIND-1: under genesis `binding_domain: 1` the chain-id-only v1 message is gone —
                // the domain answers the v2 message here too.
                false => ledger.binding_domain().registration_message(chain_id, validator, &r.payout),
            };
            if !r.public_key.verify(message.as_bytes(), &r.signature) {
                return Err(StakingError::BadSignature);
            }
            if amount < MIN_STAKE {
                return Err(StakingError::BelowMinStake { amount, min: MIN_STAKE });
            }
        }
    }
    Ok(())
}

/// The two validator-signed actions share three checks, in this order: the validator is in the
/// register, the nonce is the one the register expects, and the signature is that validator's
/// over `message`.
fn signed_by<'a>(
    ledger: &'a Ledger,
    validator: &Address,
    nonce: u64,
    signature: &Signature,
    message: impl FnOnce() -> crate::crypto::Hash,
) -> Result<&'a ValidatorEntry, StakingError> {
    let e = ledger.validators().get(validator).ok_or(StakingError::UnknownValidator(*validator))?;
    if nonce != e.nonce {
        return Err(StakingError::BadNonce { expected: e.nonce, actual: nonce });
    }
    if !e.public_key.verify(message().as_bytes(), signature) {
        return Err(StakingError::BadSignature);
    }
    Ok(e)
}

fn check_unbond(
    ledger: &Ledger,
    validator: &Address,
    amount: u64,
    nonce: u64,
    signature: &Signature,
    chain_id: u64,
) -> Result<(), StakingError> {
    let e = signed_by(ledger, validator, nonce, signature, || ledger.binding_domain().unbond_message(chain_id, validator, amount, nonce))?;
    // A zero unbond would spend a nonce and a `pending` row to move nothing.
    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }
    // Only active stake unbonds: what is still in the bond queue is not weight yet, and letting
    // it leave would let a bond skip the queue's order on its way back out. Without a section
    // the queue is empty and this is the whole stake.
    //
    // Genesis vesting: nor does stake a vesting entry bonded here (`BondVested`) — only its
    // beneficiary may take that back, and only into the lock. Conservative while such a bond is
    // itself still queued (it is then subtracted twice), never generous. 0 without the section.
    let vested = ledger.vesting().map_or(0, |v| v.bonded_to(validator));
    let have = e.stake.saturating_sub(ledger.queued_stake(validator)).saturating_sub(vested);
    if amount > have {
        return Err(StakingError::InsufficientStake { have, want: amount });
    }
    Ok(())
}

/// What an `AdmitValidator` gets on a chain whose genesis does not set
/// `staking.admission_by_vote`: the gate, before a byte of the action is read, so an old node's
/// refusal of the unknown wire variant and this node's refusal of the action agree.
const NO_ADMISSION: TxError = TxError::UnsupportedAction("admission by vote is not enabled on this chain (genesis staking.admission_by_vote)");

/// The set whose vote admits a validator (audit v6, STAKE-2): the register's validators whose
/// activation epoch has come, weighted by their stake less what is still queued, the top
/// [`MAX_VALIDATORS`], capped by `max_weight_bps` — [`derive_set_with`] over this ledger for its
/// own epoch, the very function the epoch's consensus set was derived by.
///
/// It is **not** byte-for-byte the set consensus is running the epoch with: that one was derived
/// from the register as of the last block of the epoch before, and the ledger does not keep it.
/// The two differ only by what happened since that boundary, and only downwards — under a
/// `staking` section every bond (registration or top-up) is queued for a later epoch and is not
/// weight here either, while an `Unbond` leaves this set at once and the consensus set at the
/// next boundary. So a validator on its way out stops voting on admissions a little before it
/// stops voting on blocks, and nothing that is not weight in consensus is weight here.
pub fn voting_set(ledger: &Ledger) -> ValidatorSet {
    ledger.derive_next_set(ledger.epoch())
}

/// The state half of an admission, with no signature work: the gate, then a candidate that is
/// neither registered nor already admitted, then room in the set. What the mempool asks at every
/// tip (`Mempool::applies`), and the first thing [`check_admit`] asks.
pub fn check_admission_open(ledger: &Ledger, candidate: &Address) -> Result<(), TxError> {
    if !ledger.staking().is_some_and(|s| s.admission_by_vote()) {
        return Err(NO_ADMISSION);
    }
    if ledger.validators().contains_key(candidate) {
        return Err(StakingError::AlreadyRegistered(*candidate).into());
    }
    if ledger.admitted().contains(candidate) {
        return Err(StakingError::AlreadyAdmitted(*candidate).into());
    }
    if ledger.admitted().len() >= MAX_ADMITTED {
        return Err(StakingError::AdmissionSetFull { max: MAX_ADMITTED }.into());
    }
    Ok(())
}

/// `AdmitValidator`'s rules (audit v6, STAKE-2), cheap before expensive: the gate, the candidate
/// key's length, the state lookups ([`check_admission_open`]), the vote list's shape against the
/// voting set (count, strict voter order, membership, quorum weight), and only then one
/// Dilithium2 verification per vote. Every vote listed must count: a vote by a key outside the
/// set, a repeated voter or a signature that does not verify refuses the whole action rather than
/// being skipped, so one voter set has exactly one admissible encoding.
fn check_admit(
    ledger: &Ledger,
    candidate: &crate::crypto::PublicKey,
    signatures: &[(crate::crypto::PublicKey, Signature)],
) -> Result<(), TxError> {
    if !ledger.staking().is_some_and(|s| s.admission_by_vote()) {
        return Err(NO_ADMISSION);
    }
    let len = candidate.as_bytes().len();
    if len != crate::crypto::PUBLIC_KEY_LEN {
        return Err(StakingError::BadCandidateKey { len }.into());
    }
    let address = candidate.address();
    check_admission_open(ledger, &address)?;
    let set = voting_set(ledger);
    if signatures.is_empty() || signatures.len() > set.len() {
        return Err(StakingError::AdmissionVoteCount { got: signatures.len(), max: set.len() }.into());
    }
    let voters: Vec<Address> = signatures.iter().map(|(key, _)| key.address()).collect();
    if voters.windows(2).any(|w| w[0] >= w[1]) {
        return Err(StakingError::AdmissionVoteOrder.into());
    }
    let mut weight = 0u128;
    for voter in &voters {
        let v = set.get(voter).ok_or(StakingError::AdmissionVoterNotInSet(*voter))?;
        weight = weight.saturating_add(v.stake);
    }
    // Strictly more than two thirds, by the arithmetic a quorum certificate is judged with.
    if !set.has_quorum(weight) {
        return Err(StakingError::AdmissionNoQuorum { weight, total: set.total_stake() }.into());
    }
    let message = admit_validator_message(&ledger.signing_domain().genesis, &address);
    for ((key, signature), voter) in signatures.iter().zip(&voters) {
        if !key.verify(message.as_bytes(), signature) {
            return Err(StakingError::BadAdmissionVote(*voter).into());
        }
    }
    Ok(())
}

/// What a `SlashEquivocation` gets on a chain whose genesis has no `staking.slashing`: the gate,
/// before a byte of it is read — every chain through 18 refuses it by name, as an old node
/// refuses the unknown wire variant.
const NO_SLASHING: TxError = TxError::UnsupportedAction("slashing is not enabled on this chain (genesis staking.slashing)");

/// The state half of a slash, with no signature work (audit v6, STAKE-1): the gate, both headers
/// inside the evidence window, the offender registered, not jailed, with something at stake.
/// What the mempool asks at every tip (`Mempool::applies`) and what [`check_slash`] asks before
/// it verifies a signature.
pub fn check_slash_open(ledger: &Ledger, offender: &Address, heights: [u64; 2]) -> Result<(), TxError> {
    if ledger.staking().and_then(|s| s.slashing).is_none() {
        return Err(NO_SLASHING);
    }
    // The window: a header at most one above the ledger's height — the block being applied when
    // the slash is applied, and the block after the tip when a node pools the evidence against
    // its tip ledger (the equivocating proposals extend the tip, so they are one above it) — and
    // at most `EVIDENCE_EPOCHS` epochs old, which is what keeps the slash ahead of the offender's
    // `UNBONDING_EPOCHS` (see the constant). The upper bound is what keeps one offence from
    // being replayed after its jail: a header admitted at most one block past the slash is out
    // of the window by the time any jail of more than `EVIDENCE_EPOCHS` epochs ends
    // (`Genesis::validate` refuses a shorter one).
    let (current, blocks) = (ledger.epoch(), ledger.epoch_blocks().max(1));
    for height in heights {
        let epoch = height / blocks;
        if height > ledger.height().saturating_add(1) || epoch.saturating_add(EVIDENCE_EPOCHS) < current {
            return Err(StakingError::EvidenceOutOfWindow { height, epoch, current }.into());
        }
    }
    let e = ledger.validators().get(offender).ok_or(StakingError::UnknownValidator(*offender))?;
    if let Some(until) = ledger.jailed_until(offender) {
        return Err(StakingError::Jailed { validator: *offender, until }.into());
    }
    if slashable(e) == 0 {
        return Err(StakingError::NothingAtStake(*offender).into());
    }
    Ok(())
}

/// What a slash can reach: the bonded stake and every unbonding row not yet withdrawn. Rewards
/// are fees earned, not stake, and are left alone.
fn slashable(e: &ValidatorEntry) -> u64 {
    e.pending.iter().fold(e.stake, |acc, (_, amount)| acc.saturating_add(*amount))
}

/// `SlashEquivocation`'s rules (audit v6, STAKE-1), cheap before expensive: the gate; the pair's
/// shape — one key, one view, two different headers, the lower hash first — which is what makes
/// two headers an equivocation at all; the window and the offender's state
/// ([`check_slash_open`]); and last, one Dilithium2 verification per header under this chain's
/// consensus signing domain, the very check every replica made when it took the block. An
/// honest leader's key never signs two headers for one view (`HotStuff::propose` persists the
/// view before the proposal leaves and refuses a second), so the only thing between an honest
/// validator and a slash is that nobody can produce its second signature: a tampered header
/// fails here (`a_tampered_second_header_is_not_evidence`).
fn check_slash(ledger: &Ledger, first: &SignedHeader, second: &SignedHeader) -> Result<(), TxError> {
    if ledger.staking().and_then(|s| s.slashing).is_none() {
        return Err(NO_SLASHING);
    }
    if first.header.proposer != second.header.proposer {
        return Err(StakingError::NotEquivocation("the headers are signed by two different keys").into());
    }
    if first.header.view != second.header.view {
        return Err(StakingError::NotEquivocation("the headers are for two different views").into());
    }
    let (a, b) = (first.hash(), second.hash());
    if a == b {
        return Err(StakingError::NotEquivocation("the same header twice").into());
    }
    if a > b {
        return Err(StakingError::NotEquivocation("the pair is not in canonical order (the lower hash first)").into());
    }
    let offender = first.header.proposer.address();
    check_slash_open(ledger, &offender, [first.header.height, second.header.height])?;
    let domain = ledger.signing_domain();
    if !first.verify(domain) {
        return Err(StakingError::BadEvidenceSignature("first").into());
    }
    if !second.verify(domain) {
        return Err(StakingError::BadEvidenceSignature("second").into());
    }
    Ok(())
}

/// What an action reaching this module that it does not own gets. Only a routing mistake in
/// [`super::Ledger::validate_inner`] can produce one, and refusing it is the safe answer: `Ok`
/// would let a mis-routed action skip the rules of the module that does own it.
const NOT_STAKING: TxError = TxError::UnsupportedAction("staking");

/// The action step of admission (spec §7 step 7) for the three staking actions.
pub(super) fn validate(
    ledger: &Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    match action {
        Action::Bond { validator, amount, registration } => {
            check_bond(ledger, validator, *amount, registration.as_ref(), tx.chain_id)?;
        }
        Action::Unbond { validator, amount, nonce, signature } => {
            check_unbond(ledger, validator, *amount, *nonce, signature, tx.chain_id)?;
        }
        Action::Withdraw { validator, amount, nonce, time, r, envelope, signature } => {
            check_withdraw(ledger, validator, *amount, *nonce, *time, r, envelope, signature, tx.chain_id)?;
            // The deposit the chain is about to create must be a note nobody has created yet.
            // Checking it here keeps admission's answer and application's answer the same one:
            // a withdraw carries no bundle, so there is nothing else in this transaction that
            // could append the same commitment first.
            let cm = withdraw_note(ledger, validator, *amount, *time, r, executor)?;
            if ledger.has_commitment(&cm) {
                return Err(TxError::CommitmentExists(cm));
            }
        }
        Action::AdmitValidator { candidate, signatures } => check_admit(ledger, candidate, signatures)?,
        Action::SlashEquivocation { first, second } => check_slash(ledger, first, second)?,
        _ => return Err(NOT_STAKING),
    }
    Ok(())
}

/// The apply step, in lockstep with [`validate`]: each arm re-runs its checks through the
/// `Ledger` method that owns the mutation, so the two halves cannot drift apart.
pub(super) fn apply(
    ledger: &mut Ledger,
    tx: &Transaction,
    action: &Action,
    proposer: &Address,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    match action {
        Action::Bond { validator, amount, registration } => {
            ledger.bond(*validator, *amount, registration.as_ref(), tx.chain_id)?;
        }
        Action::Unbond { validator, amount, nonce, signature } => {
            ledger.unbond(validator, *amount, *nonce, signature, tx.chain_id)?;
        }
        Action::Withdraw { validator, amount, nonce, time, r, envelope, signature } => {
            // Everything that can fail happens before the first mutation: the register's half
            // is checked by `withdraw`, and the note and the proposer's credit are worked out
            // here, so a refused withdraw leaves the ledger byte-identical.
            let cm = withdraw_note(ledger, validator, *amount, *time, r, executor)?;
            if ledger.has_commitment(&cm) {
                return Err(TxError::CommitmentExists(cm));
            }
            // A withdraw carries no bundle, so this is where its fee is charged: the base is
            // taken out of the amount and credited to the proposer, exactly as a bundle fee is
            // (`Ledger::apply_tx`). In practice the proposer is always in the register —
            // `apply_block` rejects a block whose proposer is not.
            let rewards = ledger.validators().get(proposer).ok_or(TxError::UnknownProposer(*proposer))?.rewards;
            let _ = rewards.checked_add(gas::BUNDLE_BASE).ok_or(TxError::Overflow)?;
            let paid = note_amount(*amount)?;

            ledger.withdraw(validator, *amount, *nonce, *time, r, envelope, signature, tx.chain_id)?;
            ledger.append_deposit(cm, envelope.clone(), executor)?;
            // Re-read rather than reuse the value above: when the proposer *is* the withdrawing
            // validator, `withdraw` has just taken value out of this very field. It can only
            // have shrunk, so the `checked_add` proved above still holds.
            let e = ledger.validators.get_mut(proposer).expect("looked up above");
            e.rewards = e.rewards.checked_add(gas::BUNDLE_BASE).ok_or(TxError::Overflow)?;
            // What actually reached the pool is the note, not the amount: the base stayed in the
            // register (see `ledger::supply`). S3's `BridgeAttest` of asset 0 would be counted
            // the same way.
            ledger.supply.withdraw_deposited =
                ledger.supply.withdraw_deposited.checked_add(paid).ok_or(TxError::Overflow)?;
        }
        Action::AdmitValidator { candidate, signatures } => {
            // Re-checked against this very state, like every arm here, then the one write: the
            // candidate's address joins the admitted set, where its registration will find it.
            check_admit(ledger, candidate, signatures)?;
            ledger.admitted.insert(candidate.address());
        }
        Action::SlashEquivocation { first, second } => {
            check_slash(ledger, first, second)?;
            ledger.slash(&first.header.proposer.address())?;
        }
        _ => return Err(NOT_STAKING),
    }
    Ok(())
}

impl Ledger {
    /// Audit v6, STAKE-1: destroy `equivocation_bps` of `offender`'s bonded stake and of each
    /// unbonding row (floor-rounded per amount, so the sum never exceeds the fraction of the
    /// whole), count it in the supply's `slashed`, and jail the key from the next boundary.
    /// `check_slash` has verified the evidence against this very state; this is the write.
    pub(crate) fn slash(&mut self, offender: &Address) -> Result<(), TxError> {
        let cfg = self.staking().and_then(|s| s.slashing).ok_or(NO_SLASHING)?;
        let bps = u128::from(cfg.equivocation_bps);
        let cut = |amount: u64| u64::try_from(u128::from(amount) * bps / u128::from(MAX_WEIGHT_BPS)).unwrap_or(amount);
        let until = cfg.jailed_until(self.epoch());
        let e = self.validators.get_mut(offender).ok_or(StakingError::UnknownValidator(*offender))?;
        let mut destroyed = cut(e.stake);
        e.stake -= destroyed;
        for (_, amount) in e.pending.iter_mut() {
            let c = cut(*amount);
            *amount -= c;
            destroyed = destroyed.checked_add(c).ok_or(TxError::Overflow)?;
        }
        // Rows cut to nothing are dropped: a zero row would be hashed into the leaf for nothing.
        e.pending.retain(|(_, amount)| *amount > 0);
        self.supply.slashed = self.supply.slashed.checked_add(destroyed).ok_or(TxError::Overflow)?;
        self.jailed.insert(*offender, until);
        Ok(())
    }
}

/// The deposit note a withdraw creates: the register's payout address, no sender, the amount less
/// the bundle base, the native asset, the action's own `time`, and the blinding it published
/// (plan: "Withdraw creates a deposit note the ledger can check").
///
/// The `time` is the action's and not the applying block's height: the node seals the envelope
/// against this note before it knows which block will carry the transaction, so a note bound to
/// the apply height would be one the payout wallet cannot open by scanning.
fn withdraw_note(
    ledger: &Ledger,
    validator: &Address,
    amount: u64,
    time: u32,
    r: &Word8,
    executor: &dyn ConfidentialExecutor,
) -> Result<Word8, TxError> {
    let e = ledger
        .validators()
        .get(validator)
        .ok_or(TxError::Staking(StakingError::UnknownValidator(*validator)))?;
    Ok(executor.note_commitment(&e.payout.pk, &[0; 8], note_amount(amount)?, 0, time, r))
}

/// What a withdraw's note is worth: the amount, less the bundle base it pays the proposer.
fn note_amount(amount: u64) -> Result<u64, StakingError> {
    amount.checked_sub(gas::BUNDLE_BASE).ok_or(StakingError::BelowBundleBase { amount, base: gas::BUNDLE_BASE })
}

#[allow(clippy::too_many_arguments)]
fn check_withdraw(
    ledger: &Ledger,
    validator: &Address,
    amount: u64,
    nonce: u64,
    time: u32,
    r: &Word8,
    envelope: &crate::notes::Envelope,
    signature: &Signature,
    chain_id: u64,
) -> Result<u64, StakingError> {
    signed_by(ledger, validator, nonce, signature, || {
        ledger.binding_domain().withdraw_message(chain_id, validator, amount, nonce, time, r, envelope)
    })?;
    // The base fee comes out of the amount, so an amount that cannot cover it buys a note worth
    // nothing — or nothing at all. This subsumes a zero withdraw, which is why there is no
    // separate `ZeroAmount` arm here (`Unbond` still has one: it pays no fee).
    if amount <= gas::BUNDLE_BASE {
        return Err(StakingError::BelowBundleBase { amount, base: gas::BUNDLE_BASE });
    }
    let available = ledger.released(validator);
    if amount > available {
        return Err(StakingError::NothingReleased { available, want: amount });
    }
    Ok(available)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::{Address, Keypair, Signature};
    use crate::ledger::TIME_WINDOW;
    use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};
    use crate::types::actions::{
        registration_message, registration_message_v2, unbond_message, withdraw_message, Registration,
    };
    use crate::types::Transaction;
    use std::collections::BTreeMap;

    const HC: Word8 = [11; 8];
    const CHAIN: u64 = 7;
    /// The bundle base a withdraw pays out of the amount it withdraws. Every staked amount here
    /// is a multiple of it, so a note's worth (`amount − BASE`) is readable at a glance.
    const BASE: u64 = gas::BUNDLE_BASE;

    fn key(i: u8) -> Keypair {
        Keypair::from_seed([i; 32]).unwrap()
    }

    fn payout(i: u8) -> ShieldedAddress {
        ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i; KEM_EK_BYTES] }
    }

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn entry(k: &Keypair, stake: u64, payout: ShieldedAddress) -> ValidatorEntry {
        ValidatorEntry {
            public_key: k.public_key().clone(),
            stake,
            pending: Vec::new(),
            rewards: 0,
            payout,
            nonce: 0,
            activation_epoch: 0,
        }
    }

    fn register(entries: Vec<ValidatorEntry>) -> BTreeMap<Address, ValidatorEntry> {
        entries.into_iter().map(|e| (e.public_key.address(), e)).collect()
    }

    /// A ledger whose register holds `entries`, positioned at height 5 with four-block epochs
    /// (so `epoch()` is 1 and a two-epoch unbonding release lands at 3).
    fn ledger(entries: Vec<ValidatorEntry>) -> Ledger {
        let mut l = Ledger::new(CHAIN, HC, register(entries), &StubExecutor);
        l.set_epoch_blocks(4);
        l.set_height(5);
        l
    }

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes. `burn` is
    /// its RAND burn, `burn_r` — the only field a bond may burn through (spec §3.7).
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], burn: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.root(),
            nullifiers: crate::notes::pad4(nfs),
            commitments: crate::notes::pad4(cms),
            fee: gas::BUNDLE_BASE,
            burn_a: 0,
            burn_r: burn,
            burn_asset: 0,
            time: l.height() as u32,
            envelopes: [env(), env(), env(), env()],
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        b
    }

    /// A transaction carrying `action`, with fresh nullifiers and commitments keyed off `n`.
    fn tx(l: &Ledger, n: u32, burn: u64, action: Action) -> Transaction {
        StubExecutor::bound(Transaction::shielded(CHAIN, bundle(l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], burn), action))
    }

    fn registration(k: &Keypair, payout: ShieldedAddress) -> Registration {
        let signature = k.sign(registration_message(CHAIN, &payout).as_bytes());
        Registration { public_key: k.public_key().clone(), payout, signature }
    }

    fn bond_tx(l: &Ledger, n: u32, validator: &Keypair, amount: u64, registration: Option<Registration>) -> Transaction {
        tx(l, n, amount, Action::Bond { validator: validator.address(), amount, registration })
    }

    /// A validator-signed action rides alone, with no bundle to pay a fee from — a validator key
    /// owns no notes (ruling B).
    fn signed_tx(action: Action) -> Transaction {
        Transaction { chain_id: CHAIN, bundle: None, action }
    }

    fn unbond_tx(v: &Keypair, amount: u64, nonce: u64) -> Transaction {
        let signature = v.sign(unbond_message(CHAIN, &v.address(), amount, nonce).as_bytes());
        signed_tx(Action::Unbond { validator: v.address(), amount, nonce, signature })
    }

    fn withdraw_tx(v: &Keypair, amount: u64, nonce: u64, time: u32, r: Word8) -> Transaction {
        let signature = v.sign(withdraw_message(CHAIN, &v.address(), amount, nonce, time, &r, &env()).as_bytes());
        signed_tx(Action::Withdraw { validator: v.address(), amount, nonce, time, r, envelope: env(), signature })
    }

    /// The note a withdraw of `amount` at `time` pays to validator `i`'s payout address.
    fn withdrawn_note(i: u8, amount: u64, time: u32, r: Word8) -> Word8 {
        StubExecutor.note_commitment(&payout(i).pk, &[0; 8], amount - BASE, 0, time, &r)
    }

    fn staking_err(e: TxError) -> StakingError {
        match e {
            TxError::Staking(s) => s,
            other => panic!("expected a staking error, got {other:?}"),
        }
    }

    /// The one place the epoch's set is decided: below-minimum entries drop out, the rest are
    /// capped by stake and the set itself is in address order whatever the stakes were.
    #[test]
    fn derive_set_filters_sorts_and_caps() {
        let entries: Vec<ValidatorEntry> = (1..=11u8)
            .map(|i| {
                // Two entries sit below the minimum and must not reach the set.
                let stake = if i <= 2 { MIN_STAKE - 1 } else { MIN_STAKE + i as u64 };
                entry(&key(i), stake, payout(i))
            })
            .collect();
        let set = derive_set(&register(entries), 1);
        assert_eq!(set.len(), 9, "the two below-minimum entries are filtered out");
        for i in 1..=2u8 {
            assert!(!set.contains(&key(i).address()), "validator {i} is below the minimum stake");
        }
        let addrs: Vec<Address> = set.iter().map(|v| v.address()).collect();
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(addrs, sorted, "the set is in address order");
        // The register's u64 stake is the consensus weight, widened at this one boundary.
        assert_eq!(set.get(&key(3).address()).unwrap().stake, (MIN_STAKE + 3) as u128);

        // 101 eligible entries: the cap keeps the top 100 by stake, so the smallest drops.
        let many: Vec<ValidatorEntry> =
            (1..=101u8).map(|i| entry(&key(i), MIN_STAKE + i as u64, payout(i))).collect();
        let capped = derive_set(&register(many), 1);
        assert_eq!(capped.len(), MAX_VALIDATORS);
        assert!(!capped.contains(&key(1).address()), "the lowest stake is the one dropped");
        assert!(capped.contains(&key(2).address()));

        // 101 entries of equal stake: the tie is broken by address, ascending, so the largest
        // address is the one left out.
        let tied: Vec<ValidatorEntry> = (1..=101u8).map(|i| entry(&key(i), MIN_STAKE, payout(i))).collect();
        let by_addr = derive_set(&register(tied), 1);
        assert_eq!(by_addr.len(), MAX_VALIDATORS);
        let last = (1..=101u8).map(|i| key(i).address()).max().unwrap();
        assert!(!by_addr.contains(&last), "the highest address loses the tie");
    }

    #[test]
    fn bond_registers_and_tops_up() {
        let genesis = key(1);
        let newcomer = key(2);
        let mut l = ledger(vec![entry(&genesis, MIN_STAKE, payout(1))]);
        let proposer = genesis.address();

        // A validator nobody has registered needs its registration.
        let plain = bond_tx(&l, 10, &newcomer, MIN_STAKE, None);
        assert_eq!(staking_err(l.validate(&plain, &StubExecutor).unwrap_err()), StakingError::RegistrationRequired);

        // A registration under the minimum stake is refused.
        let small = bond_tx(&l, 20, &newcomer, MIN_STAKE - 1, Some(registration(&newcomer, payout(2))));
        assert_eq!(
            staking_err(l.validate(&small, &StubExecutor).unwrap_err()),
            StakingError::BelowMinStake { amount: MIN_STAKE - 1, min: MIN_STAKE }
        );

        // A registration for another key than the action's validator.
        let wrong_key = bond_tx(&l, 30, &newcomer, MIN_STAKE, Some(registration(&key(3), payout(2))));
        assert_eq!(staking_err(l.validate(&wrong_key, &StubExecutor).unwrap_err()), StakingError::BadRegistration);

        // A registration whose payout could never be sealed to.
        let short = ShieldedAddress { pk: [2; 8], kem_ek: vec![2; 32] };
        let stub = bond_tx(&l, 35, &newcomer, MIN_STAKE, Some(registration(&newcomer, short)));
        assert_eq!(staking_err(l.validate(&stub, &StubExecutor).unwrap_err()), StakingError::BadRegistration);

        // A registration whose signature is for another payout address.
        let mut forged = registration(&newcomer, payout(2));
        forged.payout = payout(9);
        let bad_sig = bond_tx(&l, 40, &newcomer, MIN_STAKE, Some(forged));
        assert_eq!(staking_err(l.validate(&bad_sig, &StubExecutor).unwrap_err()), StakingError::BadSignature);

        // The good one registers the entry with a zero nonce and the payout it signed.
        let good = bond_tx(&l, 50, &newcomer, MIN_STAKE, Some(registration(&newcomer, payout(2))));
        l.apply_tx(&good, &proposer, &StubExecutor).unwrap();
        l.record_anchor(l.height()); // the block ends; its root is what the next bundle anchors to
        let e = &l.validators()[&newcomer.address()];
        assert_eq!((e.stake, e.nonce, e.rewards, e.pending.len()), (MIN_STAKE, 0, 0, 0));
        assert_eq!(e.payout, payout(2));

        // A second registration for a validator already in the register is refused...
        let again = bond_tx(&l, 60, &newcomer, MIN_STAKE, Some(registration(&newcomer, payout(3))));
        assert_eq!(
            staking_err(l.validate(&again, &StubExecutor).unwrap_err()),
            StakingError::AlreadyRegistered(newcomer.address())
        );
        // ... while a plain top-up adds to the stake and changes nothing else.
        let top_up = bond_tx(&l, 70, &newcomer, 500, None);
        l.apply_tx(&top_up, &proposer, &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let e = &l.validators()[&newcomer.address()];
        assert_eq!((e.stake, e.nonce), (MIN_STAKE + 500, 0));
        assert_eq!(e.payout, payout(2), "a top-up cannot move the payout address");
    }

    /// Bond is the one action whose bundle may burn: value leaves the pool exactly as stake.
    #[test]
    fn bond_requires_burn_equal_to_amount() {
        let genesis = key(1);
        let l = ledger(vec![entry(&genesis, MIN_STAKE, payout(1))]);
        let amount = MIN_STAKE;
        let reg = Some(registration(&key(2), payout(2)));
        let action = Action::Bond { validator: key(2).address(), amount, registration: reg };
        for (n, burn, want) in [(10u32, 0u64, Some(0u64)), (20, amount - 1, Some(amount - 1)), (30, amount, None)] {
            let t = tx(&l, n, burn, action.clone());
            match (l.validate(&t, &StubExecutor), want) {
                (Ok(()), None) => {}
                (Err(e), Some(burn)) => {
                    assert_eq!(staking_err(e), StakingError::BurnMismatch { burn, amount });
                }
                (got, _) => panic!("burn {burn}: unexpected {got:?}"),
            }
        }
        // Every other action still has to burn nothing at all.
        let t = tx(&l, 40, 5, Action::None);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedBurn(5)));
    }

    #[test]
    fn unbond_moves_to_pending_and_needs_nonce_and_signature() {
        let v = key(1);
        let mut l = ledger(vec![entry(&v, MIN_STAKE + 1000, payout(1))]);
        let proposer = v.address();
        assert_eq!(l.epoch(), 1, "height 5 with four-block epochs");

        let stranger = key(9);
        let unknown = unbond_tx(&stranger, 10, 0);
        assert_eq!(
            staking_err(l.validate(&unknown, &StubExecutor).unwrap_err()),
            StakingError::UnknownValidator(stranger.address())
        );
        let stale = unbond_tx(&v, 10, 7);
        assert_eq!(
            staking_err(l.validate(&stale, &StubExecutor).unwrap_err()),
            StakingError::BadNonce { expected: 0, actual: 7 }
        );
        // A signature over another amount than the action carries.
        let mut forged = unbond_tx(&v, 10, 0);
        if let Action::Unbond { amount, .. } = &mut forged.action {
            *amount = 11;
        }
        assert_eq!(staking_err(l.validate(&forged, &StubExecutor).unwrap_err()), StakingError::BadSignature);
        let greedy = unbond_tx(&v, MIN_STAKE + 1001, 0);
        assert_eq!(
            staking_err(l.validate(&greedy, &StubExecutor).unwrap_err()),
            StakingError::InsufficientStake { have: MIN_STAKE + 1000, want: MIN_STAKE + 1001 }
        );

        let good = unbond_tx(&v, 1000, 0);
        l.apply_tx(&good, &proposer, &StubExecutor).unwrap();
        let e = &l.validators()[&v.address()];
        assert_eq!(e.stake, MIN_STAKE);
        assert_eq!(e.pending, vec![(1 + UNBONDING_EPOCHS, 1000)], "released two epochs from now");
        assert_eq!(e.nonce, 1, "the nonce is the replay protection");
        // Which is exactly what makes the same signed action unusable a second time.
        let replay = unbond_tx(&v, 1000, 0);
        assert_eq!(
            staking_err(l.validate(&replay, &StubExecutor).unwrap_err()),
            StakingError::BadNonce { expected: 1, actual: 0 }
        );
        // Nothing is released: an unbond is free (ruling B), so no fee was earned, and the
        // amount just queued waits for its epoch.
        assert_eq!(l.released(&v.address()), 0, "an unbond pays no fee to anyone");

        // A second unbond in the same epoch joins the entry already there: `pending` is hashed
        // into the state root, so it holds one row per release epoch, not one per transaction.
        let again = unbond_tx(&v, 500, 1);
        l.apply_tx(&again, &proposer, &StubExecutor).unwrap();
        let e = &l.validators()[&v.address()];
        assert_eq!(e.pending, vec![(1 + UNBONDING_EPOCHS, 1500)], "one row, two unbonds");
        assert_eq!((e.stake, e.nonce), (MIN_STAKE - 500, 2));

        // A zero unbond moves nothing and is refused rather than spending a nonce and a row.
        let nothing = unbond_tx(&v, 0, 2);
        assert_eq!(staking_err(l.validate(&nothing, &StubExecutor).unwrap_err()), StakingError::ZeroAmount);

        // The next epoch opens a new row, and what is still unreleased never exceeds the
        // unbonding window: an entry released later than `epoch` was made at `epoch` or before,
        // so its release epoch is one of the next `UNBONDING_EPOCHS`.
        l.set_height(9);
        assert_eq!(l.epoch(), 2);
        let next_epoch = unbond_tx(&v, 200, 2);
        l.apply_tx(&next_epoch, &proposer, &StubExecutor).unwrap();
        let e = &l.validators()[&v.address()];
        assert_eq!(e.pending, vec![(3, 1500), (4, 200)]);
        let unreleased = e.pending.iter().filter(|(release, _)| *release > l.epoch()).count();
        assert!(unreleased as u64 <= UNBONDING_EPOCHS, "{:?} at epoch {}", e.pending, l.epoch());
    }

    #[test]
    fn withdraw_pays_released_and_rewards_into_a_checkable_note() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.pending = vec![(0, 100 * BASE), (5, 200 * BASE)];
        e.rewards = 50 * BASE;
        let mut l = ledger(vec![e, entry(&key(2), MIN_STAKE, payout(2))]);
        // The block's proposer is another validator, so the base fee this withdraw pays lands in
        // *its* rewards and leaves the withdrawing validator's arithmetic alone.
        let proposer = key(2).address();
        assert_eq!(l.released(&v.address()), 150 * BASE, "the epoch-0 pending entry plus the rewards");

        let notes_before = l.next_index();
        let t = withdraw_tx(&v, 120 * BASE, 0, 5, [3; 8]);
        // The note this will create, before it is created: what the mempool's conflict index
        // claims for a withdraw, since the transaction itself does not carry the commitment.
        let claimed = l.derived_commitment(&t.action, &StubExecutor);
        l.apply_tx(&t, &proposer, &StubExecutor).unwrap();

        // The note the chain created is the note its own executor computes from the register's
        // payout address, the amount less the base fee, the action's `time` and the published
        // blinding.
        let cm = withdrawn_note(1, 120 * BASE, 5, [3; 8]);
        assert!(l.has_commitment(&cm), "the withdraw note is in the tree");
        assert_eq!(claimed, Some(cm), "and it is the note the ledger named in advance");
        assert_eq!(
            l.derived_commitment(&Action::None, &StubExecutor),
            None,
            "an action that makes the ledger create no note derives none"
        );
        assert_eq!(l.next_index(), notes_before + 1, "one note, and no bundle to carry two more");
        let deposits = l.deposits();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].cm, cm);
        assert_eq!(deposits[0].envelope, env(), "the envelope storage writes beside the note");
        assert_eq!(deposits[0].index, notes_before);
        // A validator that published a different `r` would have got a different note.
        assert_ne!(cm, withdrawn_note(1, 120 * BASE, 5, [4; 8]));

        // Released pending first, then rewards; the unreleased entry is untouched.
        let e = &l.validators()[&v.address()];
        assert_eq!(e.pending, vec![(5, 200 * BASE)]);
        assert_eq!(e.rewards, 30 * BASE);
        assert_eq!(e.nonce, 1);
        assert_eq!(l.released(&v.address()), 30 * BASE);
        assert_eq!(e.stake, MIN_STAKE, "a withdraw never touches the bonded stake");

        // Admission answers exactly what application would: a withdraw whose note is already in
        // the tree is refused when it is admitted, not after the register has been drained.
        let collide = withdrawn_note(1, 30 * BASE, 5, [9; 8]);
        l.record_anchor(l.height()); // the block ends; its root is what the next bundle anchors to
        let mut transfer = tx(&l, 40, 0, Action::None);
        {
            let b = transfer.bundle.as_mut().unwrap();
            b.commitments = crate::notes::pad4([collide, [43; 8]]);
            b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
        }
        StubExecutor::bind(&mut transfer);
        l.apply_tx(&transfer, &proposer, &StubExecutor).unwrap();
        let t = withdraw_tx(&v, 30 * BASE, 1, 5, [9; 8]);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentExists(collide)));
        let mut scratch = l.clone();
        assert_eq!(scratch.apply_tx(&t, &proposer, &StubExecutor), Err(TxError::CommitmentExists(collide)));
        assert_eq!(scratch, l, "and nothing of it is applied");
    }

    /// Ruling A: the note is bound to the action's own `time`, not to the height the block
    /// happens to apply at. The node seals the envelope before it knows that height, so an
    /// apply-height note would be one the payout wallet cannot open by scanning.
    #[test]
    fn withdraw_note_uses_the_action_time_not_the_apply_height() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.rewards = 10 * BASE;
        let mut l = ledger(vec![e, entry(&key(2), MIN_STAKE, payout(2))]);
        // Behind the apply height, inside the window: what a node that sealed its envelope three
        // blocks ago submits.
        let time = l.height() as u32 - 3;
        l.apply_tx(&withdraw_tx(&v, 5 * BASE, 0, time, [3; 8]), &key(2).address(), &StubExecutor).unwrap();

        assert!(l.has_commitment(&withdrawn_note(1, 5 * BASE, time, [3; 8])), "the note the action's time names");
        assert!(
            !l.has_commitment(&withdrawn_note(1, 5 * BASE, l.height() as u32, [3; 8])),
            "and not the one the apply height would have named"
        );
        assert_eq!(l.deposits()[0].cm, withdrawn_note(1, 5 * BASE, time, [3; 8]));
    }

    /// The bundle window rule of spec §7 item 5, applied to a bundle-less withdraw's own `time`.
    #[test]
    fn withdraw_time_outside_the_window_is_refused() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.rewards = 10 * BASE;
        let mut l = ledger(vec![e]);
        // Past the window, so both of its edges exist.
        let h = TIME_WINDOW + 100;
        l.set_height(h);
        let oldest = (h - TIME_WINDOW) as u32;
        for time in [h as u32 + 1, oldest - 1] {
            let t = withdraw_tx(&v, 5 * BASE, 0, time, [3; 8]);
            assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time, height: h, window: TIME_WINDOW }));
        }
        // Exactly `height - TIME_WINDOW` is still inside it.
        assert_eq!(l.validate(&withdraw_tx(&v, 5 * BASE, 0, oldest, [3; 8]), &StubExecutor), Ok(()));

        // And the window is checked where a bundle's is — before any signature work, so a
        // stale time costs a Dilithium verification of nothing.
        let mut forged = withdraw_tx(&v, 5 * BASE, 0, h as u32 + 1, [3; 8]);
        if let Action::Withdraw { signature, .. } = &mut forged.action {
            *signature = Signature::empty();
        }
        assert_eq!(
            l.validate(&forged, &StubExecutor),
            Err(TxError::TimeOutOfWindow { time: h as u32 + 1, height: h, window: TIME_WINDOW })
        );
    }

    /// Ruling B: both validator-signed actions ride bundle-less, exactly as a mint does, and a
    /// bundle on either is refused by shape — with the action named, so a wallet that attached
    /// one is told which of its transactions was wrong.
    #[test]
    fn unbond_or_withdraw_with_a_bundle_is_refused() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE + 1000, payout(1));
        e.rewards = 10 * BASE;
        let l = ledger(vec![e]);
        for (t, name) in [(unbond_tx(&v, 1000, 0), "unbond"), (withdraw_tx(&v, 5 * BASE, 0, 5, [3; 8]), "withdraw")] {
            assert_eq!(l.validate(&t, &StubExecutor), Ok(()), "{name}: bundle-less is the shape it rides in");
            let with_bundle = Transaction { bundle: Some(bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], 0)), ..t };
            assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::ActionCarriesBundle(name)));
        }
    }

    /// A withdraw pays the bundle base out of the amount it withdraws (ruling B), so an amount
    /// that cannot cover it is refused rather than creating a note worth nothing.
    #[test]
    fn withdraw_below_the_bundle_base_is_refused() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.rewards = 10 * BASE;
        let mut l = ledger(vec![e]);
        for amount in [0, 1, BASE] {
            let t = withdraw_tx(&v, amount, 0, 5, [3; 8]);
            assert_eq!(
                staking_err(l.validate(&t, &StubExecutor).unwrap_err()),
                StakingError::BelowBundleBase { amount, base: BASE }
            );
        }
        // One unit over the base is the smallest withdraw there is: a note worth one unit.
        l.apply_tx(&withdraw_tx(&v, BASE + 1, 0, 5, [3; 8]), &v.address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&withdrawn_note(1, BASE + 1, 5, [3; 8])));
    }

    /// Ruling B's split: the register loses the whole amount, the note is worth all but the
    /// bundle base, and the base lands in the block proposer's `rewards` — the same place a
    /// bundle fee goes. The supply invariant is what ties the three together.
    #[test]
    fn withdraw_pays_the_bundle_base_to_the_proposer_and_the_rest_to_the_note() {
        let v = key(1);
        let p = key(2);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.pending = vec![(0, 100 * BASE)];
        e.rewards = 50 * BASE;
        let mut l = ledger(vec![e, entry(&p, MIN_STAKE, payout(2))]);
        // Nothing was ever deposited into the pool here: the whole supply is in the register, so
        // every unit the withdraw moves has to show up on the other side of the audit.
        let issued = 2 * MIN_STAKE + 150 * BASE;
        l.set_genesis_supply(0, issued);
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());

        let amount = 120 * BASE;
        l.apply_tx(&withdraw_tx(&v, amount, 0, 5, [3; 8]), &p.address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&withdrawn_note(1, amount, 5, [3; 8])), "the note is worth the amount less the base");
        assert_eq!(l.validators()[&p.address()].rewards, BASE, "the base is the proposer's, like a bundle fee");
        let w = &l.validators()[&v.address()];
        assert_eq!((w.pending.as_slice(), w.rewards), (&[][..], 30 * BASE), "the register lost the whole amount");
        let a = l.audit();
        assert_eq!(a.supply.withdraw_deposited, amount - BASE, "only what reached the pool is counted");
        assert_eq!(a.supply.fees_paid, 0, "the base never left the pool, so it is not a fee paid out of it");
        assert_eq!(a.total_supply(), issued);
        assert!(a.invariant_holds(), "{a:?}");

        // And when the proposer *is* the withdrawing validator, the two touches compose: the
        // register's half is taken out first, then the base is credited back in.
        l.apply_tx(&withdraw_tx(&v, 2 * BASE, 1, 5, [4; 8]), &v.address(), &StubExecutor).unwrap();
        assert_eq!(l.validators()[&v.address()].rewards, 30 * BASE - 2 * BASE + BASE);
        let a = l.audit();
        assert_eq!(a.supply.withdraw_deposited, amount - BASE + BASE);
        assert!(a.invariant_holds(), "{a:?}");
        assert_eq!(a.total_supply(), issued);
    }

    #[test]
    fn withdraw_rejects_unreleased_pending() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.pending = vec![(5, 200 * BASE)];
        let mut l = ledger(vec![e]);
        assert_eq!(l.released(&v.address()), 0);

        let early = withdraw_tx(&v, 10 * BASE, 0, 5, [3; 8]);
        assert_eq!(
            staking_err(l.validate(&early, &StubExecutor).unwrap_err()),
            StakingError::NothingReleased { available: 0, want: 10 * BASE }
        );
        // And a refused withdraw leaves the register, the tree and the deposits untouched.
        let before = l.clone();
        assert!(l.apply_tx(&early, &v.address(), &StubExecutor).is_err());
        assert_eq!(l, before);
        assert!(l.deposits().is_empty());

        // Once its epoch arrives the same pending entry is spendable, up to its amount.
        l.set_height(5 * 4);
        assert_eq!(l.epoch(), 5);
        assert_eq!(l.released(&v.address()), 200 * BASE);
        let greedy = withdraw_tx(&v, 200 * BASE + 1, 0, 20, [3; 8]);
        assert_eq!(
            staking_err(l.validate(&greedy, &StubExecutor).unwrap_err()),
            StakingError::NothingReleased { available: 200 * BASE, want: 200 * BASE + 1 }
        );
        let ok = withdraw_tx(&v, 200 * BASE, 0, 20, [3; 8]);
        l.apply_tx(&ok, &v.address(), &StubExecutor).unwrap();
        assert!(l.validators()[&v.address()].pending.is_empty());
    }

    /// Fail closed: an action this module does not own is refused rather than waved through,
    /// and `validate` and `apply` answer alike. Only a dispatch bug can get here, which is
    /// exactly the case where `Ok(())` would silently skip the action's real rules.
    #[test]
    fn a_non_staking_action_routed_here_is_refused() {
        let mut l = ledger(vec![entry(&key(1), MIN_STAKE, payout(1))]);
        let t = Transaction { chain_id: CHAIN, bundle: None, action: Action::None };
        for a in [Action::None, Action::Deploy { base_pc: 0, words: vec![0x13; 2], public: vec![] }] {
            assert_eq!(validate(&l, &t, &a, &StubExecutor), Err(NOT_STAKING), "{a:?}");
            assert_eq!(apply(&mut l, &t, &a, &key(1).address(), &StubExecutor), Err(NOT_STAKING), "{a:?}");
        }
    }

    /// The nonce is per validator, not per chain: a signature never carries across keys.
    #[test]
    fn a_signature_by_another_validator_is_refused() {
        let v = key(1);
        let other = key(2);
        let l = ledger(vec![entry(&v, MIN_STAKE, payout(1)), entry(&other, MIN_STAKE, payout(2))]);
        let signature = other.sign(unbond_message(CHAIN, &v.address(), 10, 0).as_bytes());
        let t = signed_tx(Action::Unbond { validator: v.address(), amount: 10, nonce: 0, signature });
        assert_eq!(staking_err(l.validate(&t, &StubExecutor).unwrap_err()), StakingError::BadSignature);
    }

    /// The supply audit (`ledger::supply`) through the whole staking cycle. Every public
    /// movement of RAND is one of these five counters, so after each step the pool plus the
    /// register must still add up to exactly what the chain issued — and the point of checking
    /// it after *every* step is that a counter credited in the wrong arm would balance again by
    /// the end of the sequence.
    #[test]
    fn the_supply_counters_balance_through_bond_unbond_withdraw_and_transfer() {
        let genesis = key(1);
        let newcomer = key(2);
        let mut l = ledger(vec![entry(&genesis, MIN_STAKE, payout(1))]);
        // Genesis deposits nine times the minimum into the pool and stakes one; nothing else is
        // ever minted here, so `issued()` never moves again.
        let issued = 10 * MIN_STAKE;
        l.set_genesis_supply(issued - MIN_STAKE, MIN_STAKE);
        let proposer = genesis.address();
        let check = |l: &Ledger, what: &str| {
            let a = l.audit();
            assert!(a.invariant_holds(), "{what}: {a:?}");
            assert_eq!(a.total_supply(), issued, "{what}");
            a
        };
        let start = check(&l, "genesis");
        assert_eq!(start.register_total, MIN_STAKE, "the genesis validator's stake");
        assert_eq!(start.pool_value, issued - MIN_STAKE);

        // A bond burns out of the pool into public stake, and its bundle pays a fee that moves
        // into the proposer's rewards — two separate exits, both of them into the register.
        let fee = gas::BUNDLE_BASE;
        l.apply_tx(&bond_tx(&l, 10, &newcomer, MIN_STAKE, Some(registration(&newcomer, payout(2)))), &proposer, &StubExecutor)
            .unwrap();
        let after_bond = check(&l, "bond");
        assert_eq!(after_bond.supply.burned, MIN_STAKE);
        assert_eq!(after_bond.supply.fees_paid, fee);
        assert_eq!(after_bond.register_total, 2 * MIN_STAKE + fee);

        // An unbond moves stake to `pending` inside the register and is free (ruling B): not one
        // of the counters moves.
        l.apply_tx(&unbond_tx(&newcomer, MIN_STAKE, 0), &proposer, &StubExecutor).unwrap();
        let after_unbond = check(&l, "unbond");
        assert_eq!(after_unbond.supply, after_bond.supply, "a free, bundle-less action moves no counter");
        assert_eq!(after_unbond.register_total, after_bond.register_total);

        // A withdraw is the return leg: released value leaves the register and re-enters the
        // pool as a note the chain computed itself — all but the base fee, which stays in the
        // register as the proposer's reward.
        l.set_height(l.epoch_blocks() * (l.epoch() + UNBONDING_EPOCHS));
        let time = l.height() as u32;
        l.apply_tx(&withdraw_tx(&newcomer, MIN_STAKE, 1, time, [3; 8]), &proposer, &StubExecutor).unwrap();
        let after_withdraw = check(&l, "withdraw");
        assert_eq!(after_withdraw.supply.withdraw_deposited, MIN_STAKE - fee, "the note is worth all but the base");
        assert_eq!(after_withdraw.supply.fees_paid, fee, "the base was never in the pool to be paid out of it");
        assert_eq!(after_withdraw.register_total, after_unbond.register_total - MIN_STAKE + fee);

        // A plain transfer moves nothing across the boundary but its fee.
        l.record_anchor(l.height());
        l.apply_tx(&tx(&l, 40, 0, Action::None), &proposer, &StubExecutor).unwrap();
        let after_transfer = check(&l, "transfer");
        assert_eq!(after_transfer.supply.fees_paid, 2 * fee);
        assert_eq!(after_transfer.supply.burned, MIN_STAKE, "only a bond burns");
        assert_eq!(after_transfer.register_total, after_withdraw.register_total + fee);
    }

    /// A `Bond` burns its stake through the bundle's RAND burn, `burn_r` (the hidden-asset
    /// bundle, spec §3.7): exactly the bonded amount, and nothing through `burn_a` or
    /// `burn_asset` — the audit's `burned` counter moves by `burn_r`.
    #[test]
    fn a_bond_burns_through_burn_r_and_nothing_else() {
        let l = ledger(vec![entry(&key(1), MIN_STAKE, payout(1)), entry(&key(2), MIN_STAKE, payout(2))]);
        let ok = bond_tx(&l, 10, &key(2), 500, None);
        assert_eq!(ok.bundle.as_ref().unwrap().burn_r, 500);
        assert_eq!(l.validate(&ok, &StubExecutor), Ok(()));
        let altered = |f: fn(&mut Bundle)| {
            let mut t = bond_tx(&l, 10, &key(2), 500, None);
            let b = t.bundle.as_mut().unwrap();
            f(b);
            b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
            StubExecutor::bind(&mut t);
            t
        };
        assert_eq!(
            l.validate(&altered(|b| b.burn_r = 499), &StubExecutor),
            Err(StakingError::BurnMismatch { burn: 499, amount: 500 }.into())
        );
        // The stake burned through the token slots instead: refused, however it is labelled.
        assert_eq!(
            l.validate(&altered(|b| { b.burn_r = 0; b.burn_a = 500 }), &StubExecutor),
            Err(TxError::NonCanonicalRandBurn(500))
        );
        assert_eq!(
            l.validate(&altered(|b| { b.burn_a = 500; b.burn_asset = 1 }), &StubExecutor),
            Err(TxError::UnsupportedAsset(1))
        );
        let mut applied = l.clone();
        applied.apply_tx(&ok, &key(1).address(), &StubExecutor).unwrap();
        assert_eq!(applied.supply().burned, 500, "the audit counts burn_r");
    }

    /// Task 5b: a `Bond`'s bundle burns the stake, and before the binding a copier could keep the
    /// bundle and its proof and name *another* registered validator — the burned stake credited
    /// to someone the sender never chose. Refused now; the original still validates.
    #[test]
    fn a_bonds_proof_cannot_ride_a_changed_validator() {
        let l = ledger(vec![entry(&key(1), MIN_STAKE, payout(1)), entry(&key(2), MIN_STAKE, payout(2))]);
        let original = bond_tx(&l, 10, &key(2), 500, None);
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        let mut copy = original.clone();
        let Action::Bond { validator, .. } = &mut copy.action else { panic!("a bond") };
        *validator = key(1).address();
        assert!(
            matches!(l.validate(&copy, &StubExecutor), Err(TxError::InvalidBundleProof(_))),
            "{:?}",
            l.validate(&copy, &StubExecutor)
        );
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

    /// Audit v4, STAKE-2 rule 3: under the `staking` section a bond in epoch `e` is in no set
    /// for epochs `e + 1 ..= e + N` and is in the set derived for `e + N + 1`; genesis
    /// validators activate at 0. Without the section a bond is weight at the very next
    /// boundary, as it always was.
    #[test]
    fn a_bond_waits_its_activation_epochs_before_it_is_in_the_set() {
        let genesis = key(1);
        let newcomer = key(9);
        let bond_new = |l: &mut Ledger| {
            let t = bond_tx(l, 40, &newcomer, MIN_STAKE, Some(registration(&newcomer, payout(9))));
            l.apply_tx(&t, &genesis.address(), &StubExecutor).unwrap();
        };
        // Bonded at epoch 0 (height 1 of ten-block epochs), two epochs of delay.
        let mut l = Ledger::new(CHAIN, HC, register(vec![entry(&genesis, MIN_STAKE, payout(1))]), &StubExecutor);
        l.set_epoch_blocks(10);
        l.set_height(1);
        l.set_staking(Some(StakingConfig { faucet_budget_per_epoch: 0, bond_activation_epochs: 2, ..Default::default() }));
        assert_eq!(l.epoch(), 0);
        bond_new(&mut l);
        assert_eq!(l.validators()[&newcomer.address()].activation_epoch, 3, "epoch 0 + 1 + 2");
        assert_eq!(l.validators()[&genesis.address()].activation_epoch, 0, "genesis validators activate at 0");
        assert!(!l.derive_next_set(1).contains(&newcomer.address()));
        assert!(!l.derive_next_set(2).contains(&newcomer.address()));
        assert!(l.derive_next_set(3).contains(&newcomer.address()));
        assert!(l.derive_next_set(1).contains(&genesis.address()), "genesis validators activate at 0");
        // A top-up of an activated-later entry does not move its activation epoch. (The first
        // bond's notes moved the tree: record the block-end anchor the next bundle spends at.)
        l.record_anchor(1);
        let top_up = bond_tx(&l, 50, &newcomer, MIN_STAKE, None);
        l.apply_tx(&top_up, &genesis.address(), &StubExecutor).unwrap();
        assert_eq!(l.validators()[&newcomer.address()].activation_epoch, 3);
        assert_eq!(l.validators()[&newcomer.address()].stake, 2 * MIN_STAKE);
        // The same bond bonded in epoch 4 activates at 7.
        l.set_height(41);
        l.record_anchor(41);
        let later = key(10);
        let t = bond_tx(&l, 60, &later, MIN_STAKE, Some(registration(&later, payout(10))));
        l.apply_tx(&t, &genesis.address(), &StubExecutor).unwrap();
        assert_eq!(l.validators()[&later.address()].activation_epoch, 7);
        assert!(!l.derive_next_set(6).contains(&later.address()));
        assert!(l.derive_next_set(7).contains(&later.address()));
        // Without the section: weight at the next boundary, the activation epoch left at 0.
        let mut l = Ledger::new(CHAIN, HC, register(vec![entry(&genesis, MIN_STAKE, payout(1))]), &StubExecutor);
        l.set_epoch_blocks(10);
        l.set_height(1);
        bond_new(&mut l);
        assert_eq!(l.validators()[&newcomer.address()].activation_epoch, 0);
        assert!(l.derive_next_set(1).contains(&newcomer.address()));
        // `derive_set` itself: an entry whose activation epoch is ahead of the epoch derived for
        // is skipped, whatever its stake.
        let mut ahead = entry(&key(2), 10 * MIN_STAKE, payout(2));
        ahead.activation_epoch = 5;
        let reg = register(vec![entry(&genesis, MIN_STAKE, payout(1)), ahead]);
        assert!(!derive_set(&reg, 4).contains(&key(2).address()));
        assert!(derive_set(&reg, 5).contains(&key(2).address()));
        assert_eq!(derive_set(&reg, 4).len(), 1);
    }

    /// RESCAN-LEDGER-1: a permissionless `Bond` writes the register row at once, and two epochs
    /// later the key is in the active set — the `Mint` arm asked only for the row, so the bonder
    /// was a faucet minter, and set membership would not have stopped it either. Under
    /// `staking.faucet_minters` only a listed key mints, at admission and at apply, however long
    /// it has been bonded; the register check still comes first. Without the list (chain 15) the
    /// rule is unchanged, and the node's admission policy is what keeps such a mint out.
    #[test]
    fn under_faucet_minters_only_a_listed_key_mints_even_once_a_bonder_is_in_the_active_set() {
        use crate::ledger::FAUCET_MAX_UNITS;
        let genesis = key(1);
        let bonder = key(9);
        let cfg = |minters: Option<Vec<FaucetMinter>>| StakingConfig {
            faucet_budget_per_epoch: 10_000 * UNITS_PER_RAND,
            bond_activation_epochs: 2,
            faucet_minters: minters,
            ..Default::default()
        };
        let mint = |l: &Ledger, k: &Keypair, seed: u32| {
            Transaction::mint(CHAIN, [seed; 8], l.height() as u32, [seed + 1; 8], env(), FAUCET_MAX_UNITS, k, &StubExecutor)
        };
        // Bonded in epoch 0 of ten-block epochs, and in the active set from epoch 3.
        let bonded = |minters: Option<Vec<FaucetMinter>>| {
            let mut l = sectioned(vec![entry(&genesis, MIN_STAKE, payout(1))], cfg(minters));
            l.set_faucet(true);
            let t = bond_tx(&l, 40, &bonder, MIN_STAKE, Some(registration(&bonder, payout(9))));
            l.apply_tx(&t, &genesis.address(), &StubExecutor).unwrap();
            l.set_height(30);
            assert!(l.derive_next_set(l.epoch()).contains(&bonder.address()), "the bonder is an active validator");
            l
        };

        // Chain 15's rule, unchanged: the row is enough.
        let mut off = bonded(None);
        let attack = mint(&off, &bonder, 70);
        assert_eq!(off.validate(&attack, &StubExecutor), Ok(()));
        off.apply_tx(&attack, &genesis.address(), &StubExecutor).unwrap();

        // Under the list: refused at admission and at apply, the ledger untouched.
        let mut on = bonded(Some(vec![FaucetMinter(genesis.address())]));
        let refusal = TxError::MinterNotAllowed(bonder.address());
        assert_eq!(on.validate(&attack, &StubExecutor), Err(refusal.clone()));
        let before = on.clone();
        assert_eq!(on.apply_tx(&attack, &genesis.address(), &StubExecutor), Err(refusal));
        assert_eq!(on, before, "a refused mint leaves the ledger untouched");
        // A listed key mints; a key with no row is `MinterNotValidator` first, listed or not.
        on.apply_tx(&mint(&on, &genesis, 80), &genesis.address(), &StubExecutor).unwrap();
        let stranger = key(10);
        let mut listed_stranger = bonded(Some(vec![FaucetMinter(stranger.address())]));
        assert_eq!(
            listed_stranger.validate(&mint(&listed_stranger, &stranger, 90), &StubExecutor),
            Err(TxError::MinterNotValidator(stranger.address()))
        );
        // And a bonder the list names mints like any other listed key.
        listed_stranger.set_staking(Some(cfg(Some(vec![FaucetMinter(genesis.address()), FaucetMinter(bonder.address())]))));
        assert_eq!(listed_stranger.validate(&attack, &StubExecutor), Ok(()));
    }

    /// A ledger at height 1 of ten-block epochs under a `staking` section, holding `entries`.
    fn sectioned(entries: Vec<ValidatorEntry>, cfg: StakingConfig) -> Ledger {
        let mut l = Ledger::new(CHAIN, HC, register(entries), &StubExecutor);
        l.set_epoch_blocks(10);
        l.set_height(1);
        l.set_staking(Some(cfg));
        l
    }

    /// Close the last block of the epoch `height` ends: what a replica does before the next
    /// epoch's set is derived from this very ledger.
    fn close_epoch(l: &mut Ledger, height: u64, proposer: &Address) {
        l.set_height(height);
        l.close_block(height, proposer, 0, 0);
    }

    fn weight(set: &ValidatorSet, k: &Keypair) -> Option<u128> {
        set.get(&k.address()).map(|v| v.stake)
    }

    /// The v4 re-review's weight cap: under `max_weight_bps` no validator's weight exceeds that
    /// fraction of its set's total — the total *after* clamping, which a one-pass cap at a third
    /// of the unclamped total would miss. A faucet-bought whale holding 96% of the stake ends
    /// with a third of the weight: no quorum alone, not even a blocking third.
    #[test]
    fn max_weight_bps_caps_every_weight_at_its_fraction_of_the_capped_total() {
        let whale = key(1);
        let small: Vec<Keypair> = (2..=5u8).map(key).collect();
        let mut entries = vec![entry(&whale, 100 * MIN_STAKE, payout(1))];
        entries.extend(small.iter().enumerate().map(|(i, k)| entry(k, MIN_STAKE, payout(i as u8 + 2))));
        let cfg = StakingConfig { max_weight_bps: Some(3333), ..Default::default() };
        let l = sectioned(entries.clone(), cfg);
        let set = l.derive_next_set(1);
        let w = weight(&set, &whale).unwrap();
        let total = set.total_stake();
        assert!(w * 10_000 <= 3333 * total, "the whale holds {w} of {total}: over 3333 bps");
        assert!(!set.has_quorum(w) && !set.has_third(w), "one key can neither decide nor block");
        for k in &small {
            assert_eq!(weight(&set, k), Some(MIN_STAKE as u128), "a weight under the cap is untouched");
        }
        // Exactly the level the closed form names: k = 1 clamped, C = ⌊3333·4·MIN / (10⁴ − 3333)⌋.
        assert_eq!(w, 3333 * 4 * MIN_STAKE as u128 / (10_000 - 3333));
        // Without the field the set is the register, as it always was.
        let uncapped = sectioned(entries, StakingConfig::default()).derive_next_set(1);
        assert_eq!(weight(&uncapped, &whale), Some(100 * MIN_STAKE as u128));
        assert!(uncapped.has_quorum(100 * MIN_STAKE as u128));
    }

    /// `cap_weights` over many sets: whenever the set is big enough to meet the cap
    /// (`n · bps ≥ 10⁴`) the largest weight is within it, nothing below the level moves, and a
    /// set too small to meet it is levelled to its smallest weight.
    #[test]
    fn cap_weights_meets_the_cap_whenever_the_set_can() {
        let mut seed: u64 = 0x5eed;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            seed >> 33
        };
        for round in 0..300 {
            let n = 1 + (next() % 20) as usize;
            let bps = [1000u32, 2500, 3333, 5000, 6667, 9999][(next() % 6) as usize];
            let validators: Vec<crate::types::Validator> = (0..n)
                .map(|i| crate::types::Validator {
                    public_key: key(i as u8 + 1).public_key().clone(),
                    stake: MIN_STAKE as u128 * (1 + (next() % 1000) as u128),
                })
                .collect();
            let before = ValidatorSet::new(validators);
            let after = cap_weights(before.clone(), bps);
            let max = after.iter().map(|v| v.stake).max().unwrap();
            let min_before = before.iter().map(|v| v.stake).min().unwrap();
            if n as u128 * bps as u128 >= 10_000 {
                assert!(max * 10_000 <= bps as u128 * after.total_stake(), "round {round}: n {n} bps {bps}");
            } else {
                assert!(after.iter().all(|v| v.stake == min_before), "round {round}: a small set is levelled");
            }
            for (b, a) in before.iter().zip(after.iter()) {
                assert_eq!(b.address(), a.address());
                assert!(a.stake <= b.stake);
                assert!(a.stake == b.stake || a.stake == max, "round {round}: one level, nothing else moves");
            }
        }
        // 10 000 basis points is no cap.
        let set = ValidatorSet::from_entries([(key(1).public_key(), 50 * MIN_STAKE), (key(2).public_key(), MIN_STAKE)]);
        assert_eq!(cap_weights(set.clone(), 10_000), set);
    }

    /// The v4 re-review's "delay" gap: before the bond queue a top-up of an *active* entry was
    /// weight at the very next boundary, whatever `bond_activation_epochs` said — only a fresh
    /// registration waited. Under the section a top-up now waits exactly as long, stays in the
    /// entry's `stake` (the supply audit and the register rows see it) and cannot be unbonded
    /// before it is weight.
    #[test]
    fn a_top_up_waits_its_activation_epochs_like_a_registration() {
        let (a, b) = (key(1), key(2));
        let cfg = StakingConfig { bond_activation_epochs: 2, ..Default::default() };
        let mut l = sectioned(vec![entry(&a, MIN_STAKE, payout(1)), entry(&b, MIN_STAKE, payout(2))], cfg);
        l.apply_tx(&bond_tx(&l, 10, &a, 5 * MIN_STAKE, None), &b.address(), &StubExecutor).unwrap();
        assert_eq!(l.validators()[&a.address()].stake, 6 * MIN_STAKE, "bonded at once");
        assert_eq!(l.queued_stake(&a.address()), 5 * MIN_STAKE, "but queued");
        assert_eq!(l.bond_queue(), &[QueuedStake { validator: a.address(), amount: 5 * MIN_STAKE, epoch: 3 }]);
        close_epoch(&mut l, 9, &b.address());
        assert_eq!(weight(&l.derive_next_set(1), &a), Some(MIN_STAKE as u128), "not weight at e + 1");
        close_epoch(&mut l, 19, &b.address());
        assert_eq!(weight(&l.derive_next_set(2), &a), Some(MIN_STAKE as u128), "nor at e + N");
        // Queued stake is not unbondable: only the active MIN_STAKE is.
        let greedy = unbond_tx(&a, 2 * MIN_STAKE, 0);
        assert_eq!(
            staking_err(l.validate(&greedy, &StubExecutor).unwrap_err()),
            StakingError::InsufficientStake { have: MIN_STAKE, want: 2 * MIN_STAKE }
        );
        close_epoch(&mut l, 29, &b.address());
        assert_eq!(weight(&l.derive_next_set(3), &a), Some(6 * MIN_STAKE as u128), "weight at e + N + 1");
        assert!(l.bond_queue().is_empty(), "admitted rows leave the queue");
        assert_eq!(l.validate(&unbond_tx(&a, 2 * MIN_STAKE, 0), &StubExecutor), Ok(()));
        // Without the section nothing queues: a top-up is weight at the next boundary.
        let mut plain = ledger(vec![entry(&a, MIN_STAKE, payout(1)), entry(&b, MIN_STAKE, payout(2))]);
        plain.apply_tx(&bond_tx(&plain, 10, &a, 5 * MIN_STAKE, None), &b.address(), &StubExecutor).unwrap();
        assert!(plain.bond_queue().is_empty());
        assert_eq!(weight(&plain.derive_next_set(2), &a), Some(6 * MIN_STAKE as u128));
    }

    /// The v4 re-review's "admission" gap: `max_stake_entry_per_epoch` bounds the stake that
    /// becomes weight at one boundary, registrations and top-ups together. What is due beyond it
    /// waits for the next boundary in the order it was bonded, split mid-row if the budget runs
    /// out there.
    #[test]
    fn stake_entering_one_epoch_is_capped_and_the_rest_waits_in_bond_order() {
        let (g, x, y) = (key(1), key(2), key(3));
        let cfg = StakingConfig { max_stake_entry_per_epoch: Some(2 * MIN_STAKE), ..Default::default() };
        let mut l = sectioned(vec![entry(&g, 10 * MIN_STAKE, payout(1))], cfg);
        let proposer = g.address();
        l.apply_tx(&bond_tx(&l, 10, &x, 3 * MIN_STAKE, Some(registration(&x, payout(2)))), &proposer, &StubExecutor)
            .unwrap();
        l.record_anchor(1);
        l.apply_tx(&bond_tx(&l, 20, &y, MIN_STAKE, Some(registration(&y, payout(3)))), &proposer, &StubExecutor)
            .unwrap();
        // Epoch 1's boundary admits 2·MIN of the 4·MIN due: two thirds of x's row, none of y's.
        close_epoch(&mut l, 9, &proposer);
        let set = l.derive_next_set(1);
        assert_eq!(weight(&set, &x), Some(2 * MIN_STAKE as u128));
        assert_eq!(weight(&set, &y), None, "y waits behind x");
        assert_eq!(
            l.bond_queue(),
            &[
                QueuedStake { validator: x.address(), amount: MIN_STAKE, epoch: 2 },
                QueuedStake { validator: y.address(), amount: MIN_STAKE, epoch: 2 },
            ]
        );
        // Epoch 2's admits the rest.
        close_epoch(&mut l, 19, &proposer);
        let set = l.derive_next_set(2);
        assert_eq!((weight(&set, &x), weight(&set, &y)), (Some(3 * MIN_STAKE as u128), Some(MIN_STAKE as u128)));
        assert!(l.bond_queue().is_empty());
        // A block that is not an epoch's last admits nothing.
        let mut mid = sectioned(vec![entry(&g, 10 * MIN_STAKE, payout(1))], StakingConfig::default());
        mid.apply_tx(&bond_tx(&mid, 10, &x, MIN_STAKE, Some(registration(&x, payout(2)))), &proposer, &StubExecutor)
            .unwrap();
        close_epoch(&mut mid, 5, &proposer);
        assert_eq!(mid.bond_queue().len(), 1);
    }

    /// The v4 re-review's "proof of possession" gap: the v1 registration binds the chain id and
    /// the payout, not the chain's genesis nor the address it registers. Under
    /// `registration_v2` only a `rand-register-2` signature over this genesis, this chain id,
    /// this validator and this payout registers.
    #[test]
    fn registration_v2_binds_the_genesis_and_the_validator() {
        let (g, x) = (key(1), key(2));
        let genesis = crate::crypto::Hash::digest(b"this chain");
        let cfg = StakingConfig { registration_v2: Some(true), ..Default::default() };
        let mut l = sectioned(vec![entry(&g, MIN_STAKE, payout(1))], cfg);
        l.set_signing_domain(crate::types::SigningDomain::v0(genesis));
        let v2 = |over: &crate::crypto::Hash, validator: &Address| {
            let msg = registration_message_v2(over, CHAIN, validator, &payout(2));
            Registration { public_key: x.public_key().clone(), payout: payout(2), signature: x.sign(msg.as_bytes()) }
        };
        let bond = |r: Registration| bond_tx(&l, 10, &x, MIN_STAKE, Some(r));
        assert_eq!(
            staking_err(l.validate(&bond(registration(&x, payout(2))), &StubExecutor).unwrap_err()),
            StakingError::BadSignature,
            "a v1 registration"
        );
        let elsewhere = crate::crypto::Hash::digest(b"another chain, same id");
        assert_eq!(
            staking_err(l.validate(&bond(v2(&elsewhere, &x.address())), &StubExecutor).unwrap_err()),
            StakingError::BadSignature,
            "a v2 registration for another genesis"
        );
        assert_eq!(
            staking_err(l.validate(&bond(v2(&genesis, &g.address())), &StubExecutor).unwrap_err()),
            StakingError::BadSignature,
            "a v2 registration naming another address"
        );
        assert_eq!(l.validate(&bond(v2(&genesis, &x.address())), &StubExecutor), Ok(()));
        // Without the flag the v1 message is the rule, and a v2 signature is not it.
        let mut plain = sectioned(vec![entry(&g, MIN_STAKE, payout(1))], StakingConfig::default());
        plain.set_signing_domain(crate::types::SigningDomain::v0(genesis));
        assert_eq!(plain.validate(&bond_tx(&plain, 10, &x, MIN_STAKE, Some(registration(&x, payout(2)))), &StubExecutor), Ok(()));
        assert_eq!(
            staking_err(plain.validate(&bond_tx(&plain, 10, &x, MIN_STAKE, Some(v2(&genesis, &x.address()))), &StubExecutor).unwrap_err()),
            StakingError::BadSignature
        );
    }

    // ---- audit v6, STAKE-1: slashing leader equivocation -----------------------------------------

    fn slashing_cfg(jail_epochs: u64) -> StakingConfig {
        StakingConfig { slashing: Some(SlashingConfig { equivocation_bps: 1_000, jail_epochs }), ..Default::default() }
    }

    /// Four validators of `4·MIN_STAKE` at height 15 of ten-block epochs (epoch 1), signing under
    /// `this_chain()` v1, with the supply seeded so the audit balances, under `cfg`.
    fn slashing_ledger(cfg: StakingConfig) -> (Vec<Keypair>, Ledger) {
        let vals: Vec<Keypair> = (1..=4u8).map(key).collect();
        let mut l = sectioned(vals.iter().enumerate().map(|(i, k)| entry(k, 4 * MIN_STAKE, payout(i as u8 + 1))).collect(), cfg);
        l.set_signing_domain(crate::types::SigningDomain::v1(this_chain()));
        l.set_genesis_supply(0, 16 * MIN_STAKE);
        l.set_height(15);
        (vals, l)
    }

    /// A header `k` signs for `view` at `height`, its contents varied by `salt`, under `domain`.
    fn signed_header_under(domain: &crate::types::SigningDomain, k: &Keypair, view: u64, height: u64, salt: u8) -> SignedHeader {
        let header = crate::types::BlockHeader {
            height,
            view,
            parent: crate::crypto::Hash([salt; 32]),
            proposer: k.public_key().clone(),
            timestamp_ms: u64::from(salt),
            tx_root: crate::crypto::Hash::ZERO,
            state_root: crate::crypto::Hash::ZERO,
            justify: crate::types::QuorumCertificate::genesis(crate::crypto::Hash::ZERO),
        };
        let signature = k.sign(domain.block_message(&header).as_bytes());
        SignedHeader { header, signature }
    }

    fn signed_header(k: &Keypair, view: u64, height: u64, salt: u8) -> SignedHeader {
        signed_header_under(&crate::types::SigningDomain::v1(this_chain()), k, view, height, salt)
    }

    fn slash_tx(a: SignedHeader, b: SignedHeader) -> Transaction {
        let (first, second) = SignedHeader::ordered(a, b);
        signed_tx(Action::SlashEquivocation { first, second })
    }

    /// Audit v6, STAKE-1: a leader that signs two different headers for one view loses
    /// `equivocation_bps` of its bonded *and* unbonding stake — destroyed, counted in `slashed`, the
    /// supply identity intact — and is jailed: in no set from the next boundary, no top-up taken,
    /// and a second piece of evidence refused, so one offence is slashed once.
    #[test]
    fn a_two_header_equivocation_slashes_and_jails_the_leader() {
        let (vals, mut l) = slashing_ledger(slashing_cfg(3));
        let offender = &vals[1];
        // Some of the stake is already unbonding: the slash reaches it too.
        l.apply_tx(&unbond_tx(offender, MIN_STAKE, 0), &vals[0].address(), &StubExecutor).unwrap();
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
        let evidence = slash_tx(signed_header(offender, 12, 12, 1), signed_header(offender, 12, 12, 2));
        assert_eq!(l.validate(&evidence, &StubExecutor), Ok(()));
        let root_before = l.state_root();
        l.apply_tx(&evidence, &vals[0].address(), &StubExecutor).unwrap();
        let e = &l.validators()[&offender.address()];
        assert_eq!(e.stake, 3 * MIN_STAKE - 3 * MIN_STAKE / 10, "10% of the bonded 3·MIN");
        assert_eq!(e.pending, vec![(1 + UNBONDING_EPOCHS, MIN_STAKE - MIN_STAKE / 10)], "10% of the unbonding MIN");
        assert_eq!(l.supply().slashed, 4 * MIN_STAKE / 10, "destroyed, and counted");
        let a = l.audit();
        assert!(a.invariant_holds(), "total_supply == issued − slashed: {a:?}");
        assert_eq!(a.total_supply(), 16 * MIN_STAKE - 4 * MIN_STAKE / 10);
        assert_eq!(l.jailed_until(&offender.address()), Some(1 + 1 + 3), "from the next boundary, three whole epochs");
        assert_ne!(l.state_root(), root_before);
        // Out of the next epoch's set, whatever its stake.
        assert!(!l.derive_next_set(2).contains(&offender.address()));
        assert!(!l.derive_next_set(4).contains(&offender.address()));
        assert!(l.derive_next_set(2).contains(&vals[0].address()));
        // A top-up is refused while jailed.
        l.record_anchor(l.height());
        let top_up = bond_tx(&l, 50, offender, MIN_STAKE, None);
        assert_eq!(
            staking_err(l.validate(&top_up, &StubExecutor).unwrap_err()),
            StakingError::Jailed { validator: offender.address(), until: 5 }
        );
        // The same evidence again, or another offence in another view, does not slash twice.
        assert_eq!(staking_err(l.validate(&evidence, &StubExecutor).unwrap_err()), StakingError::Jailed { validator: offender.address(), until: 5 });
        let other = slash_tx(signed_header(offender, 13, 13, 3), signed_header(offender, 13, 13, 4));
        assert!(matches!(staking_err(l.validate(&other, &StubExecutor).unwrap_err()), StakingError::Jailed { .. }));
        // The jail ends at its epoch: the boundary into epoch 5 drops the row and seats the key.
        for h in [19u64, 29, 39, 49] {
            close_epoch(&mut l, h, &vals[0].address());
        }
        assert_eq!(l.jailed_until(&offender.address()), None);
        assert!(l.jailed().is_empty(), "the boundary dropped the expired row");
        assert!(l.derive_next_set(5).contains(&offender.address()));
        // And the old evidence cannot be replayed now that the jail is over: it is out of window.
        l.set_height(50);
        assert!(matches!(staking_err(l.validate(&evidence, &StubExecutor).unwrap_err()), StakingError::EvidenceOutOfWindow { .. }));
    }

    /// The pairs that are not evidence (audit v6, STAKE-1: "a slashing bug can itself remove honest
    /// validators"): the same header twice, two views, two keys, the pair out of canonical order, a
    /// pair signed under another chain's domain, and a tampered second header. In every case the
    /// honest validator's stake is untouched; what stands in the way of slashing an honest leader
    /// is that nobody can produce its second signature.
    #[test]
    fn only_two_signed_headers_of_one_key_for_one_view_are_evidence() {
        let (vals, l) = slashing_ledger(slashing_cfg(3));
        let v = &vals[1];
        let refusal = |t: &Transaction| staking_err(l.validate(t, &StubExecutor).unwrap_err());
        let h = signed_header(v, 12, 12, 1);
        let same = signed_tx(Action::SlashEquivocation { first: Box::new(h.clone()), second: Box::new(h.clone()) });
        assert_eq!(refusal(&same), StakingError::NotEquivocation("the same header twice"));
        assert_eq!(refusal(&slash_tx(signed_header(v, 12, 12, 1), signed_header(v, 13, 13, 2))), StakingError::NotEquivocation("the headers are for two different views"));
        assert_eq!(refusal(&slash_tx(signed_header(v, 12, 12, 1), signed_header(&vals[2], 12, 12, 2))), StakingError::NotEquivocation("the headers are signed by two different keys"));
        let (a, b) = SignedHeader::ordered(signed_header(v, 12, 12, 1), signed_header(v, 12, 12, 2));
        let reversed = signed_tx(Action::SlashEquivocation { first: b, second: a });
        assert!(matches!(refusal(&reversed), StakingError::NotEquivocation(_)), "one canonical encoding per offence");
        // Another chain's domain (same keys, another genesis): neither signature verifies here.
        let elsewhere = crate::types::SigningDomain::v1(crate::crypto::Hash::digest(b"another chain"));
        let foreign = slash_tx(signed_header_under(&elsewhere, v, 12, 12, 1), signed_header_under(&elsewhere, v, 12, 12, 2));
        assert!(matches!(refusal(&foreign), StakingError::BadEvidenceSignature(_)));
        // An honest leader's one real header, and a second one made by changing it: the
        // tampered header carries a signature over something else.
        let honest = signed_header(v, 12, 12, 1);
        let mut forged = honest.clone();
        forged.header.timestamp_ms += 1;
        let t = slash_tx(honest, forged);
        assert!(matches!(refusal(&t), StakingError::BadEvidenceSignature(_)), "the verification is what stands in the way");
        let mut scratch = l.clone();
        assert!(scratch.apply_tx(&t, &vals[0].address(), &StubExecutor).is_err());
        assert_eq!(scratch.validators()[&v.address()].stake, 4 * MIN_STAKE, "nothing slashed");
        assert!(scratch.jailed().is_empty());
        // A key that is not in the register has nothing to slash.
        let stranger = key(9);
        assert_eq!(
            refusal(&slash_tx(signed_header(&stranger, 12, 12, 1), signed_header(&stranger, 12, 12, 2))),
            StakingError::UnknownValidator(stranger.address())
        );
    }

    /// The evidence window and the one inequality it rests on: **`EVIDENCE_EPOCHS <
    /// UNBONDING_EPOCHS`**. A leader of epoch `E` that unbonds everything in `E` has it in `pending`
    /// until `E + UNBONDING_EPOCHS`, so evidence for its header — admissible through `E +
    /// EVIDENCE_EPOCHS` — always finds the stake, and it cannot withdraw first. Older evidence, or a
    /// header above the head, is refused.
    #[test]
    fn evidence_cannot_outlive_the_stake() {
        const { assert!(EVIDENCE_EPOCHS < UNBONDING_EPOCHS) };
        let (vals, mut l) = slashing_ledger(slashing_cfg(3));
        let v = &vals[1];
        // Height 15, epoch 1: v led view 12 at height 12 and unbonds all it has, at once.
        l.apply_tx(&unbond_tx(v, 4 * MIN_STAKE, 0), &vals[0].address(), &StubExecutor).unwrap();
        let evidence = slash_tx(signed_header(v, 12, 12, 1), signed_header(v, 12, 12, 2));
        // The last epoch the evidence is admissible in: E + EVIDENCE_EPOCHS = 2.
        l.set_height(29);
        assert_eq!(l.epoch(), 1 + EVIDENCE_EPOCHS);
        assert_eq!(l.released(&v.address()), 0, "the stake has not come back yet");
        assert!(
            matches!(staking_err(l.validate(&withdraw_tx(v, 4 * MIN_STAKE, 1, 29, [3; 8]), &StubExecutor).unwrap_err()), StakingError::NothingReleased { .. }),
            "and cannot be withdrawn before the evidence window closes"
        );
        assert_eq!(l.validate(&evidence, &StubExecutor), Ok(()), "the evidence lands while the stake is still unbonding");
        let mut slashed = l.clone();
        slashed.apply_tx(&evidence, &vals[0].address(), &StubExecutor).unwrap();
        assert_eq!(slashed.supply().slashed, 4 * MIN_STAKE / 10, "it reached the unbonding stake");
        // One epoch later the evidence is out of the window.
        l.set_height(30);
        assert!(matches!(staking_err(l.validate(&evidence, &StubExecutor).unwrap_err()), StakingError::EvidenceOutOfWindow { height: 12, epoch: 1, current: 3 }));
        // A header more than one block above the head is refused (it could replay after a jail);
        // one above is the proposal that extends the tip, which a node pools at once.
        let (_, l2) = slashing_ledger(slashing_cfg(3));
        let future = slash_tx(signed_header(v, 40, 17, 1), signed_header(v, 40, 17, 2));
        assert!(matches!(staking_err(l2.validate(&future, &StubExecutor).unwrap_err()), StakingError::EvidenceOutOfWindow { height: 17, .. }));
        let next = slash_tx(signed_header(v, 16, 16, 1), signed_header(v, 16, 16, 2));
        assert_eq!(l2.validate(&next, &StubExecutor), Ok(()));
    }

    /// Without `staking.slashing` — every chain through 18 — the evidence is refused by name and
    /// the ledger is untouched; `jail_epochs: 0` jails for good.
    #[test]
    fn without_the_section_nothing_is_slashed_and_a_zero_jail_is_for_good() {
        let (vals, l) = slashing_ledger(StakingConfig::default());
        let evidence = slash_tx(signed_header(&vals[1], 12, 12, 1), signed_header(&vals[1], 12, 12, 2));
        assert!(matches!(l.validate(&evidence, &StubExecutor), Err(TxError::UnsupportedAction(_))));
        let mut scratch = l.clone();
        assert!(matches!(scratch.apply_tx(&evidence, &vals[0].address(), &StubExecutor), Err(TxError::UnsupportedAction(_))));
        assert_eq!(scratch, l);
        let (vals, mut forever) = slashing_ledger(slashing_cfg(0));
        let evidence = slash_tx(signed_header(&vals[1], 12, 12, 1), signed_header(&vals[1], 12, 12, 2));
        forever.apply_tx(&evidence, &vals[0].address(), &StubExecutor).unwrap();
        assert_eq!(forever.jailed_until(&vals[1].address()), Some(u64::MAX));
        assert!(!forever.derive_next_set(1_000_000).contains(&vals[1].address()));
        // The jail is in the root only under the section.
        let mut jailed = forever.clone();
        jailed.set_jailed(Default::default());
        assert_ne!(jailed.state_root(), forever.state_root());
    }

    // ---- audit v6, STAKE-2: the entry budget as a fraction ------------------------------------

    /// Audit v6, STAKE-2 (§8.5 option 3): `max_stake_entry_per_epoch` is a fixed RAND figure, so
    /// the epochs an entrant needs to reach a blocking third scale with the genesis stake — two
    /// on chain 18's 26 × 1 000 RAND, over a thousand on 26 × 1 000 000. As basis points of the
    /// active weight (`max_stake_entry_bps_per_epoch`) the count is the same at every scale: the
    /// budget is a fraction of what is already there, so the entrant's share after `k` boundaries
    /// is `1 − (1 + b)^−k` whatever the unit.
    #[test]
    fn a_fractional_entry_budget_holds_the_time_to_a_third_constant_across_scales() {
        let epochs_to_a_third = |stake: u64, cfg: StakingConfig| -> u64 {
            let vals: Vec<Keypair> = (1..=26u8).map(key).collect();
            let entrant = key(30);
            let mut l = sectioned(vals.iter().enumerate().map(|(i, k)| entry(k, stake, payout(i as u8 + 1))).collect(), cfg);
            let proposer = vals[0].address();
            // Bonds as much as the whole set holds: the budget, not the bond, is what paces it.
            let amount = 26 * stake;
            let t = bond_tx(&l, 40, &entrant, amount, Some(registration(&entrant, payout(30))));
            l.apply_tx(&t, &proposer, &StubExecutor).unwrap();
            for epoch in 1..=10_000u64 {
                close_epoch(&mut l, epoch * 10 - 1, &proposer);
                let set = l.derive_next_set(epoch);
                if let Some(v) = set.get(&entrant.address()) {
                    if set.has_third(v.stake) {
                        return epoch;
                    }
                }
            }
            panic!("never a third");
        };
        let (small, large) = (1_000 * UNITS_PER_RAND, 1_000_000 * UNITS_PER_RAND);
        let fixed = StakingConfig { max_stake_entry_per_epoch: Some(10_000 * UNITS_PER_RAND), ..Default::default() };
        let (small_fixed, large_fixed) = (epochs_to_a_third(small, fixed.clone()), epochs_to_a_third(large, fixed));
        assert_eq!(small_fixed, 2, "chain 18's figures: 10 000 RAND an epoch against 26 000");
        assert_eq!(large_fixed, 1301, "the same figure against 26 000 000: a thousand times longer");
        let fraction = StakingConfig { max_stake_entry_bps_per_epoch: Some(2_500), ..Default::default() };
        let (small_bps, large_bps) = (epochs_to_a_third(small, fraction.clone()), epochs_to_a_third(large, fraction));
        assert_eq!((small_bps, large_bps), (2, 2), "a quarter of the active weight an epoch: 1 − 1.25⁻² > 1/3 at every scale");
        // Without either budget every due row is admitted at once: a third at the first boundary.
        assert_eq!(epochs_to_a_third(small, StakingConfig::default()), 1);
    }

    /// The fraction is of the weight *already active* at the boundary — the register with every
    /// queued row still waiting, `derive_set_with`'s own view — so what a boundary admits never
    /// counts towards its own budget, the leftover keeps its place for the next one, and a budget
    /// under a registration admits it in parts, as the fixed figure does.
    #[test]
    fn the_fractional_budget_is_of_the_weight_active_before_the_boundary() {
        let (g, x, y) = (key(1), key(2), key(3));
        let cfg = StakingConfig { max_stake_entry_bps_per_epoch: Some(2_000), ..Default::default() };
        let mut l = sectioned(vec![entry(&g, 10 * MIN_STAKE, payout(1))], cfg);
        let proposer = g.address();
        l.apply_tx(&bond_tx(&l, 10, &x, 3 * MIN_STAKE, Some(registration(&x, payout(2)))), &proposer, &StubExecutor).unwrap();
        l.record_anchor(1);
        l.apply_tx(&bond_tx(&l, 20, &y, MIN_STAKE, Some(registration(&y, payout(3)))), &proposer, &StubExecutor).unwrap();
        // 20% of the 10·MIN active: 2·MIN of the 4·MIN due — two thirds of x's row, none of y's.
        close_epoch(&mut l, 9, &proposer);
        let set = l.derive_next_set(1);
        assert_eq!((weight(&set, &x), weight(&set, &y)), (Some(2 * MIN_STAKE as u128), None));
        assert_eq!(
            l.bond_queue(),
            &[
                QueuedStake { validator: x.address(), amount: MIN_STAKE, epoch: 2 },
                QueuedStake { validator: y.address(), amount: MIN_STAKE, epoch: 2 },
            ]
        );
        // 20% of the 12·MIN now active: 2.4·MIN — the rest of x's row and y's whole row.
        close_epoch(&mut l, 19, &proposer);
        let set = l.derive_next_set(2);
        assert_eq!((weight(&set, &x), weight(&set, &y)), (Some(3 * MIN_STAKE as u128), Some(MIN_STAKE as u128)));
        assert!(l.bond_queue().is_empty());
    }

    // ---- audit v6, STAKE-2: admission by vote ---------------------------------------------------

    fn this_chain() -> crate::crypto::Hash {
        crate::crypto::Hash::digest(b"this chain")
    }

    /// Four genesis validators of `MIN_STAKE` each at height 1 of ten-block epochs, under a
    /// `staking` section with `admission_by_vote` on or off, signing under `this_chain()`.
    fn four_validators(admission: bool) -> (Vec<Keypair>, Ledger) {
        let vals: Vec<Keypair> = (1..=4u8).map(key).collect();
        let cfg = StakingConfig { admission_by_vote: admission.then_some(true), ..Default::default() };
        let mut l = sectioned(vals.iter().enumerate().map(|(i, k)| entry(k, MIN_STAKE, payout(i as u8 + 1))).collect(), cfg);
        l.set_signing_domain(crate::types::SigningDomain::v1(this_chain()));
        (vals, l)
    }

    /// An `AdmitValidator` of `candidate` voted by `voters`, each over `genesis`'s admission
    /// message for `candidate`, in the canonical (ascending voter address) order.
    fn admit_tx(genesis: &crate::crypto::Hash, candidate: &Keypair, voters: &[&Keypair]) -> Transaction {
        let message = admit_validator_message(genesis, &candidate.address());
        let mut signatures: Vec<(crate::crypto::PublicKey, Signature)> =
            voters.iter().map(|k| (k.public_key().clone(), k.sign(message.as_bytes()))).collect();
        signatures.sort_by_key(|(key, _)| key.address());
        signed_tx(Action::AdmitValidator { candidate: candidate.public_key().clone(), signatures })
    }

    /// Audit v6, STAKE-2: `Bond` was permissionless — anyone holding `MIN_STAKE` registered a
    /// validator, so the price of two thirds of the stake was a purchase. Under
    /// `staking.admission_by_vote` a registration is refused until validators holding strictly
    /// more than two thirds of the voting set's weight have signed the key in, and the
    /// registration consumes that admission. Without the flag nothing changes, and the action
    /// itself is refused by name.
    #[test]
    fn under_admission_by_vote_a_registration_needs_the_validator_sets_vote() {
        let newcomer = key(9);
        let register = |l: &Ledger, n: u32| bond_tx(l, n, &newcomer, MIN_STAKE, Some(registration(&newcomer, payout(9))));

        // Without the flag: a registration needs no vote, and an admission is not an action here.
        let (vals, open) = four_validators(false);
        assert_eq!(open.validate(&register(&open, 10), &StubExecutor), Ok(()));
        let vote = admit_tx(&this_chain(), &newcomer, &[&vals[0], &vals[1], &vals[2]]);
        assert!(matches!(open.validate(&vote, &StubExecutor), Err(TxError::UnsupportedAction(_))), "{:?}", open.validate(&vote, &StubExecutor));
        let mut scratch = open.clone();
        assert!(matches!(scratch.apply_tx(&vote, &vals[0].address(), &StubExecutor), Err(TxError::UnsupportedAction(_))));
        assert_eq!(scratch, open, "and nothing of it is applied");
        assert!(open.admitted().is_empty());

        // Under the flag: the same registration is refused until the set has voted.
        let (vals, mut l) = four_validators(true);
        let proposer = vals[0].address();
        assert_eq!(staking_err(l.validate(&register(&l, 10), &StubExecutor).unwrap_err()), StakingError::NotAdmitted(newcomer.address()));
        let mut scratch = l.clone();
        assert!(scratch.apply_tx(&register(&l, 10), &proposer, &StubExecutor).is_err());
        assert!(!scratch.validators().contains_key(&newcomer.address()), "a refused registration writes no row");
        // A top-up of an entry already in the register is not a registration: no vote asked.
        assert_eq!(l.validate(&bond_tx(&l, 20, &vals[1], MIN_STAKE, None), &StubExecutor), Ok(()));

        // A lone validator of four cannot admit — one of four is not a quorum — and neither can
        // the candidate vote itself in: it is not in the set its admission is judged by.
        let lone = admit_tx(&this_chain(), &newcomer, &[&vals[0]]);
        assert_eq!(
            staking_err(l.validate(&lone, &StubExecutor).unwrap_err()),
            StakingError::AdmissionNoQuorum { weight: MIN_STAKE as u128, total: 4 * MIN_STAKE as u128 }
        );
        let two = admit_tx(&this_chain(), &newcomer, &[&vals[0], &vals[1]]);
        assert!(matches!(staking_err(l.validate(&two, &StubExecutor).unwrap_err()), StakingError::AdmissionNoQuorum { .. }), "two of four is not more than two thirds");
        let itself = admit_tx(&this_chain(), &newcomer, &[&newcomer]);
        assert_eq!(staking_err(l.validate(&itself, &StubExecutor).unwrap_err()), StakingError::AdmissionVoterNotInSet(newcomer.address()));

        // Three of four can. The admission is state: in the set, in the root.
        let three = admit_tx(&this_chain(), &newcomer, &[&vals[0], &vals[1], &vals[2]]);
        assert_eq!(l.validate(&three, &StubExecutor), Ok(()));
        let root_before = l.state_root();
        l.apply_tx(&three, &proposer, &StubExecutor).unwrap();
        assert!(l.admitted().contains(&newcomer.address()));
        assert_ne!(l.state_root(), root_before, "the admitted set is in the state root");
        // A second admission of an admitted key is refused, whoever votes it.
        let again = admit_tx(&this_chain(), &newcomer, &[&vals[1], &vals[2], &vals[3]]);
        assert_eq!(staking_err(l.validate(&again, &StubExecutor).unwrap_err()), StakingError::AlreadyAdmitted(newcomer.address()));

        // The registration now applies, and consumes the admission it was permitted by.
        l.apply_tx(&register(&l, 10), &proposer, &StubExecutor).unwrap();
        l.record_anchor(l.height());
        assert!(l.validators().contains_key(&newcomer.address()));
        assert!(l.admitted().is_empty(), "the admission is consumed by the registration");
        // A registered key can never be admitted again.
        assert_eq!(staking_err(l.validate(&again, &StubExecutor).unwrap_err()), StakingError::AlreadyRegistered(newcomer.address()));
        // And the newcomer does not vote yet: its weight waits in the bond queue.
        let other = key(10);
        let with_newcomer = admit_tx(&this_chain(), &other, &[&vals[0], &vals[1], &newcomer]);
        assert_eq!(
            staking_err(l.validate(&with_newcomer, &StubExecutor).unwrap_err()),
            StakingError::AdmissionVoterNotInSet(newcomer.address()),
            "a key whose stake is not weight yet is not in the voting set"
        );
    }

    /// The votes that do not count (audit v6, STAKE-2): one signed for another chain's genesis or
    /// for another candidate, a voter listed twice, a voter outside the set, a list out of order,
    /// an empty or over-long list, and a candidate that is not a key. Each refuses the whole
    /// action — and in every case the same three honest votes alone would have admitted.
    #[test]
    fn a_vote_for_another_chain_a_repeated_voter_and_an_outsider_do_not_admit() {
        let (vals, l) = four_validators(true);
        let newcomer = key(9);
        let message = admit_validator_message(&this_chain(), &newcomer.address());
        let vote = |k: &Keypair| (k.public_key().clone(), k.sign(message.as_bytes()));
        let sorted = |mut v: Vec<(crate::crypto::PublicKey, Signature)>| {
            v.sort_by_key(|(key, _)| key.address());
            v
        };
        let admit = |signatures: Vec<(crate::crypto::PublicKey, Signature)>| {
            signed_tx(Action::AdmitValidator { candidate: newcomer.public_key().clone(), signatures })
        };
        let refusal = |t: &Transaction| staking_err(l.validate(t, &StubExecutor).unwrap_err());
        assert_eq!(l.validate(&admit(sorted(vec![vote(&vals[0]), vote(&vals[1]), vote(&vals[2])])), &StubExecutor), Ok(()));

        // A vote signed for another genesis (another chain sharing the validators' keys).
        let elsewhere = admit_validator_message(&crate::crypto::Hash::digest(b"another chain"), &newcomer.address());
        let foreign = (vals[2].public_key().clone(), vals[2].sign(elsewhere.as_bytes()));
        assert_eq!(
            refusal(&admit(sorted(vec![vote(&vals[0]), vote(&vals[1]), foreign]))),
            StakingError::BadAdmissionVote(vals[2].address())
        );
        // A vote for another candidate, moved under this one.
        let other = admit_validator_message(&this_chain(), &key(10).address());
        let moved = (vals[2].public_key().clone(), vals[2].sign(other.as_bytes()));
        assert_eq!(
            refusal(&admit(sorted(vec![vote(&vals[0]), vote(&vals[1]), moved]))),
            StakingError::BadAdmissionVote(vals[2].address())
        );
        // A voter listed twice: two distinct voters and a repeat are not three.
        assert_eq!(refusal(&admit(sorted(vec![vote(&vals[0]), vote(&vals[0]), vote(&vals[1])]))), StakingError::AdmissionVoteOrder);
        // The same three honest votes out of canonical order.
        let mut reversed = sorted(vec![vote(&vals[0]), vote(&vals[1]), vote(&vals[2])]);
        reversed.reverse();
        assert_eq!(refusal(&admit(reversed)), StakingError::AdmissionVoteOrder);
        // A voter that is not in the set: its signature is good and counts for nothing.
        let outsider = key(11);
        assert_eq!(
            refusal(&admit(sorted(vec![vote(&vals[0]), vote(&vals[1]), vote(&outsider)]))),
            StakingError::AdmissionVoterNotInSet(outsider.address())
        );
        // No votes, and more votes than the set has members.
        assert_eq!(refusal(&admit(vec![])), StakingError::AdmissionVoteCount { got: 0, max: 4 });
        let five = sorted(vec![vote(&vals[0]), vote(&vals[1]), vote(&vals[2]), vote(&vals[3]), vote(&outsider)]);
        assert_eq!(refusal(&admit(five)), StakingError::AdmissionVoteCount { got: 5, max: 4 });
        // A candidate that is not a validator key.
        // (`PublicKey::from_bytes` refuses the length; the wire does not, so it arrives by decode.)
        let short_key: crate::crypto::PublicKey = serde_json::from_str(&format!("\"{}\"", hex::encode([7u8; 16]))).unwrap();
        let short = signed_tx(Action::AdmitValidator { candidate: short_key, signatures: vec![vote(&vals[0])] });
        assert_eq!(refusal(&short), StakingError::BadCandidateKey { len: 16 });
        // A bundle on it is refused by shape, like every bundle-less action.
        let with_bundle = Transaction {
            bundle: Some(bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], 0)),
            ..admit(sorted(vec![vote(&vals[0]), vote(&vals[1]), vote(&vals[2])]))
        };
        assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::ActionCarriesBundle("admit_validator")));
    }

    /// The quorum is by weight, not by head count, and the voting set is the register's own
    /// derivation: a validator whose activation epoch has not come, or whose stake has left,
    /// does not vote; and the admitted set is bounded.
    #[test]
    fn an_admission_is_judged_by_weight_in_the_derived_voting_set() {
        let newcomer = key(9);
        let (big, a, b, c) = (key(1), key(2), key(3), key(4));
        let cfg = StakingConfig { admission_by_vote: Some(true), ..Default::default() };
        let mut pending = entry(&c, 10 * MIN_STAKE, payout(4));
        pending.activation_epoch = 5;
        let mut l = sectioned(
            vec![entry(&big, 10 * MIN_STAKE, payout(1)), entry(&a, MIN_STAKE, payout(2)), entry(&b, MIN_STAKE, payout(3)), pending],
            cfg,
        );
        l.set_signing_domain(crate::types::SigningDomain::v1(this_chain()));
        let set = voting_set(&l);
        assert_eq!((set.len(), set.total_stake()), (3, 12 * MIN_STAKE as u128), "the not-yet-active entry is not in it");
        // Two of three by count, a sixth by weight.
        assert_eq!(
            staking_err(l.validate(&admit_tx(&this_chain(), &newcomer, &[&a, &b]), &StubExecutor).unwrap_err()),
            StakingError::AdmissionNoQuorum { weight: 2 * MIN_STAKE as u128, total: 12 * MIN_STAKE as u128 }
        );
        // One of three by count, ten twelfths by weight.
        assert_eq!(l.validate(&admit_tx(&this_chain(), &newcomer, &[&big]), &StubExecutor), Ok(()));
        // The entry whose activation epoch is ahead does not vote, whatever its stake.
        assert_eq!(
            staking_err(l.validate(&admit_tx(&this_chain(), &newcomer, &[&big, &c]), &StubExecutor).unwrap_err()),
            StakingError::AdmissionVoterNotInSet(c.address())
        );
        // The admitted set is bounded: at `MAX_ADMITTED` the next admission is refused.
        let full: std::collections::BTreeSet<Address> = (0..MAX_ADMITTED as u32).map(|i| {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_be_bytes());
            Address(a)
        }).collect();
        l.set_admitted(full);
        assert_eq!(
            staking_err(l.validate(&admit_tx(&this_chain(), &newcomer, &[&big]), &StubExecutor).unwrap_err()),
            StakingError::AdmissionSetFull { max: MAX_ADMITTED }
        );
    }

    /// The admitted set reaches the state root only under the flag, and the root moves with it:
    /// without `admission_by_vote` — every chain through 18 — the root is the one the section
    /// alone commits, whatever the (always empty) set holds.
    #[test]
    fn the_admitted_set_is_in_the_state_root_only_under_the_flag() {
        let (_, off) = four_validators(false);
        let (_, on) = four_validators(true);
        assert_ne!(on.state_root(), off.state_root(), "the flag re-domains the root");
        let mut with_one = on.clone();
        with_one.set_admitted([Address([7; 32])].into_iter().collect());
        assert_ne!(with_one.state_root(), on.state_root());
        assert_ne!(with_one, on, "and the set is inside the ledger's equality");
        let mut other = on.clone();
        other.set_admitted([Address([8; 32])].into_iter().collect());
        assert_ne!(other.state_root(), with_one.state_root());
        // The wrapped root is exactly `H("rand-state-admitted-1", inner ‖ admitted_root)` over
        // the root the same ledger commits without the flag.
        let mut expect = off.state_root().as_bytes().to_vec();
        expect.extend_from_slice(on.admitted_root().as_bytes());
        assert_eq!(on.state_root(), crate::crypto::Hash::digest_domain(b"rand-state-admitted-1", &expect));
    }
}
