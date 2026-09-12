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
use crate::notes::{ShieldedAddress, Word8};
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
    /// Bundle fees credited to this proposer (spec §8); paid out by `Withdraw`.
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
    #[error("only {available} is released, cannot withdraw {want}")]
    NothingReleased { available: u64, want: u64 },
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
    /// The bundle's `burn` is checked by admission (spec §7 step 3), not here.
    pub fn bond(
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
        e.stake -= amount;
        e.pending.push((release_epoch, amount));
        e.nonce += 1;
        Ok(())
    }

    /// Take `amount` out of `validator`'s released pending entries and then its rewards,
    /// returning what is left released afterwards. The note itself is created by [`apply`],
    /// which owns the executor; this is only the register's half.
    ///
    /// `r` and `envelope` are here because the validator's signature is over them too (spec §6):
    /// the note the chain computes has to be the note the validator asked for, so the message
    /// binds the blinding and the envelope, and this method cannot check the signature without
    /// them.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &mut self,
        validator: &Address,
        amount: u64,
        nonce: u64,
        r: &Word8,
        envelope: &crate::notes::Envelope,
        signature: &Signature,
        chain_id: u64,
    ) -> Result<u64, StakingError> {
        let available = check_withdraw(self, validator, amount, nonce, r, envelope, signature, chain_id)?;
        let epoch = self.epoch();
        let e = self.validators.get_mut(validator).expect("checked above");
        // Released pending entries first, oldest first, then the rewards.
        let mut want = amount;
        let mut kept = Vec::with_capacity(e.pending.len());
        for (release_epoch, pending) in std::mem::take(&mut e.pending) {
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
        e.pending = kept;
        e.rewards -= want; // `check_withdraw` proved rewards cover whatever the queue did not
        e.nonce += 1;
        Ok(available - amount)
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
    if amount > e.stake {
        return Err(StakingError::InsufficientStake { have: e.stake, want: amount });
    }
    Ok(())
}

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
        Action::Withdraw { validator, amount, nonce, r, envelope, signature } => {
            check_withdraw(ledger, validator, *amount, *nonce, r, envelope, signature, tx.chain_id)?;
            // The deposit the chain is about to create must be a note nobody has created yet.
            let cm = withdraw_note(ledger, validator, *amount, r, executor)?;
            if ledger.has_commitment(&cm) {
                return Err(TxError::CommitmentExists(cm));
            }
        }
        _ => {}
    }
    Ok(())
}

/// The apply step, in lockstep with [`validate`]: each arm re-runs its checks through the
/// `Ledger` method that owns the mutation, so the two halves cannot drift apart.
pub(super) fn apply(
    ledger: &mut Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    match action {
        Action::Bond { validator, amount, registration } => {
            ledger.bond(*validator, *amount, registration.as_ref(), tx.chain_id)?;
        }
        Action::Unbond { validator, amount, nonce, signature } => {
            ledger.unbond(validator, *amount, *nonce, signature, tx.chain_id)?;
        }
        Action::Withdraw { validator, amount, nonce, r, envelope, signature } => {
            // Everything that can fail happens before the first mutation: the register's half
            // is checked by `withdraw`, and the note is computed and checked here, so a refused
            // withdraw leaves the ledger byte-identical.
            let cm = withdraw_note(ledger, validator, *amount, r, executor)?;
            if ledger.has_commitment(&cm) {
                return Err(TxError::CommitmentExists(cm));
            }
            ledger.withdraw(validator, *amount, *nonce, r, envelope, signature, tx.chain_id)?;
            ledger.append_deposit(cm, envelope.clone(), executor)?;
        }
        _ => {}
    }
    Ok(())
}

/// The deposit note a withdraw creates: the register's payout address, no sender, the public
/// amount, the native asset, this block's height, and the blinding the action published
/// (plan: "Withdraw creates a deposit note the ledger can check").
fn withdraw_note(
    ledger: &Ledger,
    validator: &Address,
    amount: u64,
    r: &Word8,
    executor: &dyn ConfidentialExecutor,
) -> Result<Word8, TxError> {
    let e = ledger
        .validators()
        .get(validator)
        .ok_or(TxError::Staking(StakingError::UnknownValidator(*validator)))?;
    Ok(executor.note_commitment(&e.payout.pk, &[0; 8], amount, 0, ledger.height() as u32, r))
}

#[allow(clippy::too_many_arguments)]
fn check_withdraw(
    ledger: &Ledger,
    validator: &Address,
    amount: u64,
    nonce: u64,
    r: &Word8,
    envelope: &crate::notes::Envelope,
    signature: &Signature,
    chain_id: u64,
) -> Result<u64, StakingError> {
    signed_by(ledger, validator, nonce, signature, || {
        withdraw_message(chain_id, validator, amount, nonce, r, envelope)
    })?;
    let available = ledger.released(validator);
    if amount > available {
        return Err(StakingError::NothingReleased { available, want: amount });
    }
    Ok(available)
}

#[cfg(test)]

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::{Address, Keypair, Signature};
    use crate::gas;
    use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};
    use crate::types::actions::{registration_message, unbond_message, withdraw_message, Registration};
    use crate::types::Transaction;
    use std::collections::BTreeMap;

    const HC: Word8 = [11; 8];
    const CHAIN: u64 = 7;

    fn key(i: u8) -> Keypair {
        Keypair::from_seed([i; 32]).unwrap()
    }

    fn payout(i: u8) -> ShieldedAddress {
        ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i; 32] }
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

    fn unbond_tx(l: &Ledger, n: u32, v: &Keypair, amount: u64, nonce: u64) -> Transaction {
        let signature = v.sign(unbond_message(CHAIN, &v.address(), amount, nonce).as_bytes());
        tx(l, n, 0, Action::Unbond { validator: v.address(), amount, nonce, signature })
    }

    fn withdraw_tx(l: &Ledger, n: u32, v: &Keypair, amount: u64, nonce: u64, r: Word8) -> Transaction {
        let signature = v.sign(withdraw_message(CHAIN, &v.address(), amount, nonce, &r, &env()).as_bytes());
        tx(l, n, 0, Action::Withdraw { validator: v.address(), amount, nonce, r, envelope: env(), signature })
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
        let unknown = unbond_tx(&l, 10, &stranger, 10, 0);
        assert_eq!(
            staking_err(l.validate(&unknown, &StubExecutor).unwrap_err()),
            StakingError::UnknownValidator(stranger.address())
        );
        let stale = unbond_tx(&l, 20, &v, 10, 7);
        assert_eq!(
            staking_err(l.validate(&stale, &StubExecutor).unwrap_err()),
            StakingError::BadNonce { expected: 0, actual: 7 }
        );
        // A signature over another amount than the action carries.
        let mut forged = unbond_tx(&l, 30, &v, 10, 0);
        if let Action::Unbond { amount, .. } = &mut forged.action {
            *amount = 11;
        }
        assert_eq!(staking_err(l.validate(&forged, &StubExecutor).unwrap_err()), StakingError::BadSignature);
        let greedy = unbond_tx(&l, 40, &v, MIN_STAKE + 1001, 0);
        assert_eq!(
            staking_err(l.validate(&greedy, &StubExecutor).unwrap_err()),
            StakingError::InsufficientStake { have: MIN_STAKE + 1000, want: MIN_STAKE + 1001 }
        );

        let good = unbond_tx(&l, 50, &v, 1000, 0);
        l.apply_tx(&good, &proposer, &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let e = &l.validators()[&v.address()];
        assert_eq!(e.stake, MIN_STAKE);
        assert_eq!(e.pending, vec![(1 + UNBONDING_EPOCHS, 1000)], "released two epochs from now");
        assert_eq!(e.nonce, 1, "the nonce is the replay protection");
        // Which is exactly what makes the same signed action unusable a second time, even in a
        // fresh bundle that has nothing spent yet.
        let replay = unbond_tx(&l, 60, &v, 1000, 0);
        assert_eq!(
            staking_err(l.validate(&replay, &StubExecutor).unwrap_err()),
            StakingError::BadNonce { expected: 1, actual: 0 }
        );
        // Released value is the fees it has earned as proposer of these blocks and nothing from
        // the unbonding queue: that amount waits for its epoch.
        assert_eq!(l.released(&v.address()), gas::BUNDLE_BASE, "one applied bundle, one fee");
    }

    #[test]
    fn withdraw_pays_released_and_rewards_into_a_checkable_note() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.pending = vec![(0, 100), (5, 200)];
        e.rewards = 50;
        let mut l = ledger(vec![e, entry(&key(2), MIN_STAKE, payout(2))]);
        // The block's proposer is another validator, so the bundle fee this transaction pays
        // lands in *its* rewards and leaves the withdrawing validator's arithmetic alone.
        let proposer = key(2).address();
        assert_eq!(l.released(&v.address()), 150, "the epoch-0 pending entry plus the rewards");

        let notes_before = l.next_index();
        let t = withdraw_tx(&l, 10, &v, 120, 0, [3; 8]);
        l.apply_tx(&t, &proposer, &StubExecutor).unwrap();

        // The note the chain created is the note its own executor computes from the register's
        // payout address, the public amount, the block height and the published blinding.
        let cm = StubExecutor.note_commitment(&payout(1).pk, &[0; 8], 120, 0, 5, &[3; 8]);
        assert!(l.has_commitment(&cm), "the withdraw note is in the tree");
        assert_eq!(l.next_index(), notes_before + 3, "the bundle's two notes and the deposit");
        let deposits = l.deposits();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].cm, cm);
        assert_eq!(deposits[0].envelope, env(), "the envelope storage writes beside the note");
        assert_eq!(deposits[0].index, notes_before + 2, "appended after the bundle's own notes");
        // A validator that published a different `r` would have got a different note.
        assert_ne!(cm, StubExecutor.note_commitment(&payout(1).pk, &[0; 8], 120, 0, 5, &[4; 8]));

        // Released pending first, then rewards; the unreleased entry is untouched.
        let e = &l.validators()[&v.address()];
        assert_eq!(e.pending, vec![(5, 200)]);
        assert_eq!(e.rewards, 30);
        assert_eq!(e.nonce, 1);
        assert_eq!(l.released(&v.address()), 30);
        assert_eq!(e.stake, MIN_STAKE, "a withdraw never touches the bonded stake");
    }

    #[test]
    fn withdraw_rejects_unreleased_pending() {
        let v = key(1);
        let mut e = entry(&v, MIN_STAKE, payout(1));
        e.pending = vec![(5, 200)];
        let mut l = ledger(vec![e]);
        assert_eq!(l.released(&v.address()), 0);

        let early = withdraw_tx(&l, 10, &v, 10, 0, [3; 8]);
        assert_eq!(
            staking_err(l.validate(&early, &StubExecutor).unwrap_err()),
            StakingError::NothingReleased { available: 0, want: 10 }
        );
        // And a refused withdraw leaves the register, the tree and the deposits untouched.
        let before = l.clone();
        assert!(l.apply_tx(&early, &v.address(), &StubExecutor).is_err());
        assert_eq!(l, before);
        assert!(l.deposits().is_empty());

        // Once its epoch arrives the same pending entry is spendable, up to its amount.
        l.set_height(5 * 4);
        assert_eq!(l.epoch(), 5);
        assert_eq!(l.released(&v.address()), 200);
        let greedy = withdraw_tx(&l, 20, &v, 201, 0, [3; 8]);
        assert_eq!(
            staking_err(l.validate(&greedy, &StubExecutor).unwrap_err()),
            StakingError::NothingReleased { available: 200, want: 201 }
        );
        let ok = withdraw_tx(&l, 30, &v, 200, 0, [3; 8]);
        l.apply_tx(&ok, &v.address(), &StubExecutor).unwrap();
        assert!(l.validators()[&v.address()].pending.is_empty());
    }

    /// The nonce is per validator, not per chain: a signature never carries across keys.
    #[test]
    fn a_signature_by_another_validator_is_refused() {
        let v = key(1);
        let other = key(2);
        let l = ledger(vec![entry(&v, MIN_STAKE, payout(1)), entry(&other, MIN_STAKE, payout(2))]);
        let signature = other.sign(unbond_message(CHAIN, &v.address(), 10, 0).as_bytes());
        let t = tx(&l, 10, 0, Action::Unbond { validator: v.address(), amount: 10, nonce: 0, signature });
        assert_eq!(staking_err(l.validate(&t, &StubExecutor).unwrap_err()), StakingError::BadSignature);
        let _ = Signature::empty();
    }
}
