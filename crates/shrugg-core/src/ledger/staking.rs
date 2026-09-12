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

use super::{Ledger, TxError};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{Address, PublicKey, Signature};
use crate::gas;
use crate::notes::{ShieldedAddress, Word8, KEM_EK_BYTES};
use crate::types::actions::{registration_message, unbond_message, withdraw_message, Registration};
use crate::types::{Action, Transaction, ValidatorSet, UNITS_PER_SHRUGG};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Blocks per epoch unless genesis says otherwise (spec §8).
pub const EPOCH_BLOCKS_DEFAULT: u64 = 1000;
/// Epochs an unbonded amount waits before it can be withdrawn.
pub const UNBONDING_EPOCHS: u64 = 2;
/// Stake an entry needs to be in an epoch's validator set (1000 SHRUGG).
pub const MIN_STAKE: u64 = 1000 * UNITS_PER_SHRUGG;
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
pub fn derive_set(register: &BTreeMap<Address, ValidatorEntry>) -> ValidatorSet {
    let mut eligible: Vec<(&Address, &ValidatorEntry)> =
        register.iter().filter(|(_, e)| e.stake >= MIN_STAKE).collect();
    // Descending stake, then ascending address: the cap must not depend on map order.
    eligible.sort_by(|(a_addr, a), (b_addr, b)| b.stake.cmp(&a.stake).then_with(|| a_addr.cmp(b_addr)));
    eligible.truncate(MAX_VALIDATORS);
    // `ValidatorSet::new` puts the survivors back in address order.
    ValidatorSet::from_entries(eligible.into_iter().map(|(_, e)| (&e.public_key, e.stake)))
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
                self.validators.insert(
                    validator,
                    ValidatorEntry {
                        public_key: r.public_key.clone(),
                        stake: amount,
                        pending: Vec::new(),
                        rewards: 0,
                        payout: r.payout.clone(),
                        nonce: 0,
                    },
                );
            }
            None => {
                let e = self.validators.get_mut(&validator).expect("checked above");
                e.stake = e.stake.checked_add(amount).ok_or(StakingError::Overflow)?;
            }
        }
        Ok(())
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
            if !r.public_key.verify(registration_message(chain_id, &r.payout).as_bytes(), &r.signature) {
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
    if amount > e.stake {
        return Err(StakingError::InsufficientStake { have: e.stake, want: amount });
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
    use crate::types::actions::{registration_message, unbond_message, withdraw_message, Registration};
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
        ValidatorEntry { public_key: k.public_key().clone(), stake, pending: Vec::new(), rewards: 0, payout, nonce: 0 }
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

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes.
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], burn: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.root(),
            nullifiers: nfs,
            commitments: cms,
            fee: gas::BUNDLE_BASE,
            burn,
            asset: 0,
            time: l.height() as u32,
            envelopes: [env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        b
    }

    /// A transaction carrying `action`, with fresh nullifiers and commitments keyed off `n`.
    fn tx(l: &Ledger, n: u32, burn: u64, action: Action) -> Transaction {
        Transaction::shielded(CHAIN, bundle(l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], burn), action)
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
        let set = derive_set(&register(entries));
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
        let capped = derive_set(&register(many));
        assert_eq!(capped.len(), MAX_VALIDATORS);
        assert!(!capped.contains(&key(1).address()), "the lowest stake is the one dropped");
        assert!(capped.contains(&key(2).address()));

        // 101 entries of equal stake: the tie is broken by address, ascending, so the largest
        // address is the one left out.
        let tied: Vec<ValidatorEntry> = (1..=101u8).map(|i| entry(&key(i), MIN_STAKE, payout(i))).collect();
        let by_addr = derive_set(&register(tied));
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
        l.apply_tx(&t, &proposer, &StubExecutor).unwrap();

        // The note the chain created is the note its own executor computes from the register's
        // payout address, the amount less the base fee, the action's `time` and the published
        // blinding.
        let cm = withdrawn_note(1, 120 * BASE, 5, [3; 8]);
        assert!(l.has_commitment(&cm), "the withdraw note is in the tree");
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
            b.commitments = [collide, [43; 8]];
            b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()));
        }
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
        for a in [Action::None, Action::Deploy { base_pc: 0, words: vec![0x13; 2] }] {
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
    /// movement of SHRUGG is one of these five counters, so after each step the pool plus the
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
}
