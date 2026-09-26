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
    registration_message, registration_message_v2, unbond_message, withdraw_message, Registration,
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
mod amount_string {
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
    let mut waiting: BTreeMap<&Address, u64> = BTreeMap::new();
    for q in queue.iter().filter(|q| q.epoch > epoch) {
        let w = waiting.entry(&q.validator).or_default();
        *w = w.saturating_add(q.amount);
    }
    let mut eligible: Vec<(&Address, &ValidatorEntry, u64)> = register
        .iter()
        .map(|(a, e)| (a, e, e.stake.saturating_sub(waiting.get(a).copied().unwrap_or(0))))
        .filter(|(_, e, weight)| *weight >= MIN_STAKE && e.activation_epoch <= epoch)
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

    /// Add `amount` to `validator`'s stake, inserting the entry when `registration` is present.
    /// The bundle's `burn` is checked by admission (spec §7 step 3), not here — which is why
    /// this is crate-internal: a bond only ever arrives as an `Action::Bond` whose bundle burned
    /// the amount, and calling it directly would mint stake out of nothing. (`unbond` and
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
        let mut budget = cfg.max_stake_entry_per_epoch.unwrap_or(u64::MAX);
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
fn check_bond(
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
            // Under `staking.registration_v2` the registration is bound to this chain's genesis
            // and to the validator's address as well (the v4 re-review's "proof of
            // possession"): a v1 registration signed for another chain that shares the chain id
            // bonds nothing here.
            let v2 = ledger.staking().and_then(|s| s.registration_v2) == Some(true);
            let message = match v2 {
                true => registration_message_v2(&ledger.signing_domain().genesis, chain_id, validator, &r.payout),
                false => registration_message(chain_id, &r.payout),
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
    let e = signed_by(ledger, validator, nonce, signature, || unbond_message(chain_id, validator, amount, nonce))?;
    // A zero unbond would spend a nonce and a `pending` row to move nothing.
    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }
    // Only active stake unbonds: what is still in the bond queue is not weight yet, and letting
    // it leave would let a bond skip the queue's order on its way back out. Without a section
    // the queue is empty and this is the whole stake.
    let have = e.stake.saturating_sub(ledger.queued_stake(validator));
    if amount > have {
        return Err(StakingError::InsufficientStake { have, want: amount });
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
        _ => return Err(NOT_STAKING),
    }
    Ok(())
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
        withdraw_message(chain_id, validator, amount, nonce, time, r, envelope)
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
            assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time, height: h }));
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
            Err(TxError::TimeOutOfWindow { time: h as u32 + 1, height: h })
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
        l.close_block(height, proposer);
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
}
