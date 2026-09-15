//! The aggregator register and the `Aggregate` action's home in the ledger (block aggregation,
//! spec §2–§4).
//!
//! Modelled on S2's validator register ([`super::staking`]): one public row per registered
//! aggregator, hashed into the state root as a component present exactly when
//! `genesis.aggregation` is `Some`. A chain without the section behaves byte-for-byte as
//! before — the register is empty, the component is absent, and the five actions are refused
//! with a named error rather than applied.

use crate::crypto::{merkle_root, Address, Hash, PublicKey};
use crate::notes::{word8_to_bytes, ShieldedAddress, Word8};
use crate::types::DeclaredShape;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The aggregation section of a genesis file (spec §2.3): present exactly on chains that
/// aggregate. Every field is part of the genesis hash, like the bridge section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// The bond an aggregator burns at registration (`RegisterAggregator`'s bundle burns
    /// exactly this).
    pub bond: u64,
    /// The most bundles one aggregate may cover.
    pub max_covers: u32,
    /// The subsidy at `n = 0` (`subsidy_base >> (n / halving_blocks)` thereafter, spec §5.1).
    pub subsidy_base: u64,
    /// The halving interval, in sealed blocks.
    pub halving_blocks: u64,
    /// How many finalised blocks an aggregate may lag (spec §3.3), and the pruning gate.
    pub window: u64,
    /// The registered inner shapes: at activation exactly one (the constraint-set-6 bundle
    /// guest at its production shape).
    pub admitted_shapes: Vec<AdmittedShape>,
}

/// One registered inner shape and its aggregate program digest (spec §2.3). The inner
/// verifier key's preprocessed cap is derived at startup, never stored here.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AdmittedShape {
    pub shape: DeclaredShape,
    /// The bundle guest's digest — what `pv::HC0..7` of every covered bundle must equal, so an
    /// aggregate cannot cover a proof of some other guest.
    pub hc: Hash,
    /// `aggregate_program_digest(shape, key)` for the shape, measured at activation.
    pub aggregate_program_digest: [u64; 4],
}

/// One row of the aggregator register (spec §2.1): the Dilithium2 key, the burned bond, the
/// shielded payout, the action nonce, and the unbonding release height when set. The validator
/// entry's twin, one role over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorEntry {
    pub public_key: PublicKey,
    pub bond: u64,
    pub payout: ShieldedAddress,
    pub nonce: u64,
    pub unbonding: Option<u64>,
}

/// The register's leaf (spec §2.1): `blake3("shrugg-aggregator-leaf-1", addr ‖ bond ‖ nonce ‖
/// presence+release ‖ payout pk ‖ payout kem_ek)`. The unbonding option is a presence byte plus
/// the height, so `None` and `Some(0)` can never collide.
pub fn aggregator_leaf(addr: &Address, entry: &AggregatorEntry) -> Hash {
    let mut buf = Vec::with_capacity(32 + 8 + 8 + 1 + 8 + 8 + entry.payout.kem_ek.len());
    buf.extend_from_slice(addr.as_bytes());
    buf.extend_from_slice(&entry.bond.to_be_bytes());
    buf.extend_from_slice(&entry.nonce.to_be_bytes());
    buf.push(entry.unbonding.is_some() as u8);
    buf.extend_from_slice(&entry.unbonding.unwrap_or(0).to_be_bytes());
    buf.extend_from_slice(&word8_to_bytes(&entry.payout.pk));
    buf.extend_from_slice(&entry.payout.kem_ek);
    Hash::digest_domain(b"shrugg-aggregator-leaf-1", &buf)
}

/// The register's component of the state root: the merkle root of every entry's leaf, empty at
/// chain-9 block 0. Joined into the root (under the `shrugg-state-3` domain) exactly when
/// `genesis.aggregation` is `Some`; a chain without the section keeps the state-2 root
/// byte-for-byte.
pub fn aggregators_root(register: &BTreeMap<Address, AggregatorEntry>) -> Hash {
    let leaves: Vec<Hash> = register.iter().map(|(addr, e)| aggregator_leaf(addr, e)).collect();
    merkle_root(&leaves)
}

// ── the register's four actions (spec §2.2) ─────────────────────────────────────────────────

use crate::crypto::Signature;
use crate::gas;
use crate::ledger::{Ledger, TxError};
use crate::types::actions::{
    aggregate_signing_hash, aggregator_register_message, aggregator_unbond_message,
    aggregator_withdraw_message, AggregatorRegistration,
};
use crate::types::{Action, SignedAggregateHeader, Transaction};

/// Why an aggregation action was refused. Carried inside [`TxError::Aggregation`] so admission
/// reports the module's own name for it — [`super::staking::StakingError`]'s role, one role over.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AggregationError {
    #[error("aggregator {0} is not in the register")]
    UnknownAggregator(Address),
    #[error("aggregator {0} is already registered")]
    AlreadyRegistered(Address),
    #[error("the registration is for another aggregator or its payout is not an address")]
    BadRegistration,
    #[error("bad aggregator signature")]
    BadSignature,
    #[error("wrong nonce: expected {expected}, got {actual}")]
    BadNonce { expected: u64, actual: u64 },
    #[error("a register bundle must burn exactly the genesis bond: burn {burn}, bond {bond}")]
    BondMismatch { burn: u64, bond: u64 },
    #[error("aggregator {0} is unbonding and cannot submit")]
    Unbonding(Address),
    #[error("nothing is released before height {release}; withdraw at {height} refused")]
    NothingReleased { release: u64, height: u64 },
    #[error("withdraw of {amount} does not cover the bundle base {base}")]
    BelowBundleBase { amount: u64, base: u64 },
    #[error("a slash's headers must share one aggregator at one nonce with different content")]
    NotEquivocation,
    #[error("arithmetic overflow")]
    Overflow,
}

/// What an action reaching this module that it does not own gets. Only a routing mistake in
/// [`super::Ledger::validate_inner`] can produce one, and refusing it is the safe answer
/// (`super::staking`'s `NOT_STAKING`, mirrored).
pub(super) const NOT_AGGREGATION: TxError = TxError::UnsupportedAction("aggregation");

/// The bundle-burn check (spec §2.2): a `RegisterAggregator`'s bundle must burn exactly the
/// genesis bond. `None` on a chain without the section — where the action itself is refused at
/// the action step and the burn number does not matter.
pub(super) fn check_burn(ledger: &Ledger, burn: u64) -> Result<(), TxError> {
    let Some(cfg) = ledger.aggregation() else { return Ok(()) };
    if burn != cfg.bond {
        return Err(AggregationError::BondMismatch { burn, bond: cfg.bond }.into());
    }
    Ok(())
}

/// The action step of admission for the four register actions (spec §2.2), the staking
/// module's `validate` mirrored: the Aggregate itself is not this module's yet (Task 4).
pub(super) fn validate(
    ledger: &Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn crate::confidential::ConfidentialExecutor,
) -> Result<(), TxError> {
    // The absolute gate (spec §9): a chain without the section refuses every aggregation action
    // by name, before any register check — and `apply` never sees one.
    if ledger.aggregation().is_none() {
        return Err(NOT_AGGREGATION);
    }
    match action {
        Action::RegisterAggregator { registration } => {
            check_register(ledger, registration, tx.chain_id)?;
        }
        Action::UnbondAggregator { aggregator, nonce, signature } => {
            check_unbond(ledger, aggregator, *nonce, signature, tx.chain_id)?;
        }
        Action::WithdrawAggregator { aggregator, nonce, time, r, envelope, signature } => {
            check_withdraw(ledger, aggregator, *nonce, *time, r, envelope, signature, tx.chain_id)?;
            // The deposit the chain is about to create must be a note nobody has created yet
            // (the staking `Withdraw` rule, verbatim).
            let cm = withdraw_note(ledger, aggregator, *time, r, executor)?;
            if ledger.has_commitment(&cm) {
                return Err(TxError::CommitmentExists(cm));
            }
        }
        Action::SlashAggregator { a, b } => {
            check_slash(ledger, a, b, tx.chain_id)?;
        }
        _ => return Err(NOT_AGGREGATION),
    }
    Ok(())
}

/// The apply step, in lockstep with [`validate`]: each arm re-runs its checks through the
/// `Ledger` method that owns the mutation, so the two halves cannot drift apart (`staking`'s
/// `apply`, mirrored).
pub(super) fn apply(
    ledger: &mut Ledger,
    tx: &Transaction,
    action: &Action,
    proposer: &Address,
    executor: &dyn crate::confidential::ConfidentialExecutor,
) -> Result<(), TxError> {
    match action {
        Action::RegisterAggregator { registration } => {
            let bond = ledger.aggregation().expect("gated by validate").bond;
            ledger.register_aggregator(registration, bond, tx.chain_id)?;
        }
        Action::UnbondAggregator { aggregator, nonce, signature } => {
            ledger.unbond_aggregator(aggregator, *nonce, signature, tx.chain_id)?;
        }
        Action::WithdrawAggregator { aggregator, nonce, time, r, envelope, signature } => {
            // Everything that can fail happens before the first mutation (the staking
            // `Withdraw` rule, verbatim): the register's half is checked by `withdraw`, and the
            // note and the proposer's credit are worked out here.
            let cm = withdraw_note(ledger, aggregator, *time, r, executor)?;
            if ledger.has_commitment(&cm) {
                return Err(TxError::CommitmentExists(cm));
            }
            let rewards = ledger.validators().get(proposer).ok_or(TxError::UnknownProposer(*proposer))?.rewards;
            let _ = rewards.checked_add(gas::BUNDLE_BASE).ok_or(TxError::Overflow)?;
            let bond = ledger
                .aggregators()
                .get(aggregator)
                .ok_or(TxError::Aggregation(AggregationError::UnknownAggregator(*aggregator)))?
                .bond;
            let paid = note_amount(bond)?;

            ledger.withdraw_aggregator(aggregator, *nonce, *time, r, envelope, signature, tx.chain_id)?;
            ledger.append_deposit(cm, envelope.clone(), executor)?;
            // The base goes to the proposer, exactly as a `Withdraw`'s; and what actually
            // reached the pool is the note, not the bond (see `ledger::supply`).
            let e = ledger.validators.get_mut(proposer).expect("looked up above");
            e.rewards = e.rewards.checked_add(gas::BUNDLE_BASE).ok_or(TxError::Overflow)?;
            ledger.supply.withdraw_deposited =
                ledger.supply.withdraw_deposited.checked_add(paid).ok_or(TxError::Overflow)?;
            ledger.supply.aggregator_bonds =
                ledger.supply.aggregator_bonds.checked_sub(bond).ok_or(TxError::Overflow)?;
        }
        Action::SlashAggregator { a, b } => {
            ledger.slash_aggregator(a, b, tx.chain_id)?;
        }
        _ => return Err(NOT_AGGREGATION),
    }
    Ok(())
}

impl Ledger {
    /// Register the address as an aggregator (spec §2.2), inserting the entry at nonce 0. The
    /// bundle's burn is checked by admission, not here — a register only ever arrives as an
    /// `Action::RegisterAggregator` whose bundle burned the genesis bond (crate-internal, like
    /// the validator register's `bond`).
    pub(crate) fn register_aggregator(
        &mut self,
        registration: &AggregatorRegistration,
        bond: u64,
        chain_id: u64,
    ) -> Result<(), AggregationError> {
        check_register(self, registration, chain_id)?;
        let aggregator = registration.public_key.address();
        self.aggregators.insert(
            aggregator,
            AggregatorEntry {
                public_key: registration.public_key.clone(),
                bond,
                payout: registration.payout.clone(),
                nonce: 0,
                unbonding: None,
            },
        );
        self.supply.aggregator_bonds =
            self.supply.aggregator_bonds.checked_add(bond).ok_or(AggregationError::Overflow)?;
        Ok(())
    }

    /// Stop the aggregator submitting and set its unbonding release height (spec §2.2).
    pub fn unbond_aggregator(
        &mut self,
        aggregator: &Address,
        nonce: u64,
        signature: &Signature,
        chain_id: u64,
    ) -> Result<(), AggregationError> {
        check_unbond(self, aggregator, nonce, signature, chain_id)?;
        let release = self
            .height
            .checked_add(self.aggregation().expect("gated").window)
            .ok_or(AggregationError::Overflow)?;
        let e = self.aggregators.get_mut(aggregator).expect("checked above");
        e.unbonding = Some(release);
        e.nonce += 1;
        Ok(())
    }

    /// Pay the released bond as a derived deposit note and delete the entry (spec §2.2). The
    /// note itself is created by [`apply`], which owns the executor; this is the register's
    /// half. The base goes to the block's proposer (also in [`apply`]).
    pub fn withdraw_aggregator(
        &mut self,
        aggregator: &Address,
        nonce: u64,
        time: u32,
        r: &Word8,
        envelope: &crate::notes::Envelope,
        signature: &Signature,
        chain_id: u64,
    ) -> Result<(), AggregationError> {
        check_withdraw(self, aggregator, nonce, time, r, envelope, signature, chain_id)?;
        self.aggregators.remove(aggregator).expect("checked above");
        Ok(())
    }

    /// Burn the bond and delete the entry on an equivocation proof (spec §2.2). The checks are
    /// in [`check_slash`]; this is the mutation it gates.
    pub(crate) fn slash_aggregator(
        &mut self,
        a: &SignedAggregateHeader,
        b: &SignedAggregateHeader,
        chain_id: u64,
    ) -> Result<(), AggregationError> {
        check_slash(self, a, b, chain_id)?;
        let bond = self
            .aggregators
            .remove(&a.aggregator)
            .expect("checked above")
            .bond;
        self.supply.aggregator_bonds =
            self.supply.aggregator_bonds.checked_sub(bond).ok_or(AggregationError::Overflow)?;
        self.supply.slashed = self.supply.slashed.checked_add(bond).ok_or(AggregationError::Overflow)?;
        Ok(())
    }
}

/// Registration's rules (spec §2.2): the address is unknown, the registration's key claims
/// that very address, its payout is sealable (a fixed-width `kem_ek`, the validator
/// registration's rule), and the signature is over the register message — `check_bond`'s
/// registration arm, one register over.
fn check_register(
    ledger: &Ledger,
    registration: &AggregatorRegistration,
    chain_id: u64,
) -> Result<(), AggregationError> {
    let aggregator = registration.public_key.address();
    if ledger.aggregators().contains_key(&aggregator) {
        return Err(AggregationError::AlreadyRegistered(aggregator));
    }
    if registration.payout.kem_ek.len() != crate::notes::KEM_EK_BYTES {
        return Err(AggregationError::BadRegistration);
    }
    if !registration
        .public_key
        .verify(aggregator_register_message(chain_id, &registration.payout).as_bytes(), &registration.signature)
    {
        return Err(AggregationError::BadSignature);
    }
    Ok(())
}

/// The three signed actions share three checks, in this order (`staking`'s `signed_by`): the
/// aggregator is in the register, the nonce is the one the register expects, and the signature
/// is that aggregator's over `message`.
fn signed_by<'a>(
    ledger: &'a Ledger,
    aggregator: &Address,
    nonce: u64,
    signature: &Signature,
    message: impl FnOnce() -> crate::crypto::Hash,
) -> Result<&'a AggregatorEntry, AggregationError> {
    let e = ledger.aggregators().get(aggregator).ok_or(AggregationError::UnknownAggregator(*aggregator))?;
    if nonce != e.nonce {
        return Err(AggregationError::BadNonce { expected: e.nonce, actual: nonce });
    }
    if !e.public_key.verify(message().as_bytes(), signature) {
        return Err(AggregationError::BadSignature);
    }
    Ok(e)
}

fn check_unbond(
    ledger: &Ledger,
    aggregator: &Address,
    nonce: u64,
    signature: &Signature,
    chain_id: u64,
) -> Result<(), AggregationError> {
    let e = signed_by(ledger, aggregator, nonce, signature, || aggregator_unbond_message(chain_id, aggregator, nonce))?;
    if e.unbonding.is_some() {
        return Err(AggregationError::Unbonding(*aggregator));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_withdraw(
    ledger: &Ledger,
    aggregator: &Address,
    nonce: u64,
    time: u32,
    r: &Word8,
    envelope: &crate::notes::Envelope,
    signature: &Signature,
    chain_id: u64,
) -> Result<(), AggregationError> {
    let e = signed_by(ledger, aggregator, nonce, signature, || {
        aggregator_withdraw_message(chain_id, aggregator, nonce, time, r, envelope)
    })?;
    if e.bond <= gas::BUNDLE_BASE {
        return Err(AggregationError::BelowBundleBase { amount: e.bond, base: gas::BUNDLE_BASE });
    }
    match e.unbonding {
        Some(release) if release <= ledger.height => Ok(()),
        _ => Err(AggregationError::NothingReleased {
            release: e.unbonding.unwrap_or(0),
            height: ledger.height,
        }),
    }
}

/// The equivocation check (spec §2.2): both headers are signed by the same aggregator at the
/// same nonce with different content — the only fault provable on chain.
fn check_slash(
    ledger: &Ledger,
    a: &SignedAggregateHeader,
    b: &SignedAggregateHeader,
    chain_id: u64,
) -> Result<(), AggregationError> {
    if a.aggregator != b.aggregator || a.nonce != b.nonce || a == b {
        return Err(AggregationError::NotEquivocation);
    }
    let e = ledger
        .aggregators()
        .get(&a.aggregator)
        .ok_or(AggregationError::UnknownAggregator(a.aggregator))?;
    for h in [a, b] {
        let msg = aggregate_signing_hash(chain_id, h.nonce, h.time, &h.r, &h.covers, &h.proof_hash);
        if !e.public_key.verify(msg.as_bytes(), &h.signature) {
            return Err(AggregationError::BadSignature);
        }
    }
    Ok(())
}

/// The deposit note an aggregator withdraw creates: the register's payout address, no sender,
/// the bond less the bundle base, the native asset, the action's own `time`, and the blinding
/// it published — the validator withdraw note's exact construction, one register over.
pub(crate) fn withdraw_note(
    ledger: &Ledger,
    aggregator: &Address,
    time: u32,
    r: &Word8,
    executor: &dyn crate::confidential::ConfidentialExecutor,
) -> Result<Word8, TxError> {
    let e = ledger
        .aggregators()
        .get(aggregator)
        .ok_or(TxError::Aggregation(AggregationError::UnknownAggregator(*aggregator)))?;
    Ok(executor.note_commitment(&e.payout.pk, &[0; 8], note_amount(e.bond)?, 0, time, r))
}

/// What an aggregator withdraw's note is worth: the bond, less the bundle base it pays the
/// proposer (`staking`'s `note_amount`, one register over).
fn note_amount(bond: u64) -> Result<u64, AggregationError> {
    bond.checked_sub(gas::BUNDLE_BASE)
        .ok_or(AggregationError::BelowBundleBase { amount: bond, base: gas::BUNDLE_BASE })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::{Keypair, Hash};
    use crate::gas;
    use crate::ledger::staking::ValidatorEntry;
    use crate::ledger::Ledger;
    use crate::types::{Action, AggregatorRegistration, SignedAggregateHeader, UNITS_PER_SHRUGG};
    use std::collections::BTreeMap;

    fn keys() -> (Keypair, Keypair) {
        (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap())
    }

    fn entry(k: &Keypair, stake: u64) -> (Address, ValidatorEntry) {
        (
            k.public_key().address(),
            ValidatorEntry {
                public_key: k.public_key().clone(),
                stake,
                pending: Vec::new(),
                rewards: 0,
                payout: crate::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
                nonce: 0,
            },
        )
    }

    fn ledger() -> Ledger {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, [11; 8], register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l
    }

    fn cfg() -> AggregationConfig {
        AggregationConfig {
            bond: 100 * UNITS_PER_SHRUGG,
            max_covers: 3,
            subsidy_base: 100 * UNITS_PER_SHRUGG,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        }
    }

    /// The manual state-root computation, written out per the documented construction: the
    /// state-2 root of `tree ‖ nullifiers ‖ validators ‖ programs [‖ bridge]`, the state-3 root
    /// with the aggregator component appended, each hashed with its own domain. Any drift in the
    /// implementation's construction fails against this, not against a hash pasted from it.
    fn manual_state_root(l: &Ledger, domain: &'static [u8], with_aggregators: bool) -> Hash {
        use crate::crypto::merkle_root;
        use crate::notes::word8_to_bytes;
        let nf_leaves: Vec<Hash> = l
            .nullifiers()
            .iter()
            .map(|nf| Hash::digest_domain(b"shrugg-nullifier-leaf", &word8_to_bytes(nf)))
            .collect();
        let val_leaves: Vec<Hash> = l
            .validators()
            .iter()
            .map(|(addr, v)| {
                let mut buf = Vec::new();
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&v.stake.to_be_bytes());
                buf.extend_from_slice(&v.rewards.to_be_bytes());
                buf.extend_from_slice(&v.nonce.to_be_bytes());
                buf.extend_from_slice(&(v.pending.len() as u64).to_be_bytes());
                for (release_epoch, amount) in &v.pending {
                    buf.extend_from_slice(&release_epoch.to_be_bytes());
                    buf.extend_from_slice(&amount.to_be_bytes());
                }
                buf.extend_from_slice(&word8_to_bytes(&v.payout.pk));
                buf.extend_from_slice(&v.payout.kem_ek);
                Hash::digest_domain(b"shrugg-validator-leaf-2", &buf)
            })
            .collect();
        let prog_leaves: Vec<Hash> = l
            .programs()
            .keys()
            .map(|id| Hash::digest_domain(b"shrugg-program-leaf", id.as_bytes()))
            .collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&word8_to_bytes(&l.root()));
        buf.extend_from_slice(merkle_root(&nf_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&val_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&prog_leaves).as_bytes());
        if let Some(bridge) = l.bridge() {
            buf.extend_from_slice(bridge.root().as_bytes());
        }
        if with_aggregators {
            buf.extend_from_slice(aggregators_root(l.aggregators()).as_bytes());
        }
        Hash::digest_domain(domain, &buf)
    }

    /// The absolute gate: an aggregation-less chain's root is today's, computed exactly the way
    /// it is computed now — and a gated chain's is a different domain's, with the component in.
    #[test]
    fn a_chain_without_the_section_keeps_todays_state_root_byte_for_byte() {
        let l = ledger();
        assert_eq!(l.state_root(), manual_state_root(&l, b"shrugg-state-2", false));
        // The same ledger, gated, gets a different root — and the component is the empty
        // register's (so an empty register at chain-9 block 0 is well-defined).
        let mut gated = l.clone();
        gated.set_aggregation(Some(cfg()));
        assert_eq!(gated.state_root(), manual_state_root(&gated, b"shrugg-state-3", true));
        assert_ne!(gated.state_root(), l.state_root());
        // And taking the section back off is the identity, not a third value.
        let mut ungated = gated.clone();
        ungated.set_aggregation(None);
        assert_eq!(ungated.state_root(), l.state_root());
    }

    /// The register's leaf: every field of the entry is in the hash, in the documented order —
    /// addr ‖ bond ‖ nonce ‖ presence+release ‖ payout pk ‖ payout kem_ek.
    #[test]
    fn the_aggregator_leaf_hashes_every_field() {
        let payout = crate::notes::ShieldedAddress { pk: [7; 8], kem_ek: vec![8; 32] };
        let entry = AggregatorEntry {
            public_key: Keypair::from_seed([1; 32]).unwrap().public_key().clone(),
            bond: 42,
            payout: payout.clone(),
            nonce: 3,
            unbonding: Some(999),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(entry.public_key.address().as_bytes());
        buf.extend_from_slice(&42u64.to_be_bytes());
        buf.extend_from_slice(&3u64.to_be_bytes());
        buf.push(1u8);
        buf.extend_from_slice(&999u64.to_be_bytes());
        buf.extend_from_slice(&crate::notes::word8_to_bytes(&payout.pk));
        buf.extend_from_slice(&payout.kem_ek);
        assert_eq!(aggregator_leaf(&entry.public_key.address(), &entry), Hash::digest_domain(b"shrugg-aggregator-leaf-1", &buf));
        // A second entry with `unbonding: None` must not collide with `Some(0)`.
        let none_entry = AggregatorEntry { unbonding: None, ..entry.clone() };
        let zero_entry = AggregatorEntry { unbonding: Some(0), ..entry.clone() };
        assert_ne!(
            aggregator_leaf(&entry.public_key.address(), &none_entry),
            aggregator_leaf(&entry.public_key.address(), &zero_entry)
        );
    }

    /// The five actions on the wire: bincode round-trips, and `bundle_less` names the four
    /// bundle-less ones — `RegisterAggregator` is the one that rides a bundle (it burns the bond).
    #[test]
    fn the_five_actions_roundtrip_and_their_bundle_shape() {
        let kp = Keypair::from_seed([2; 32]).unwrap();
        let sig = kp.sign(b"test");
        let payout = crate::notes::ShieldedAddress { pk: [5; 8], kem_ek: vec![6; 32] };
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout,
            signature: sig.clone(),
        };
        let actions = vec![
            Action::RegisterAggregator { registration },
            Action::UnbondAggregator { aggregator: kp.public_key().address(), nonce: 1, signature: sig.clone() },
            Action::WithdrawAggregator {
                aggregator: kp.public_key().address(),
                nonce: 2,
                time: 9,
                r: [3; 8],
                envelope: env(),
                signature: sig.clone(),
            },
            Action::SlashAggregator {
                a: Box::new(signed_header(&kp, 1, &sig)),
                b: Box::new(signed_header(&kp, 1, &sig)),
            },
            Action::Aggregate {
                covers: vec![Hash::digest(b"one"), Hash::digest(b"two")],
                proof: vec![9; 64],
                aggregator: kp.public_key().address(),
                nonce: 3,
                time: 9,
                r: [4; 8],
                envelope: env(),
                signature: sig,
            },
        ];
        for a in &actions {
            let back: Action = bincode::deserialize(&bincode::serialize(a).unwrap()).unwrap();
            assert_eq!(*a, back);
        }
        assert_eq!(actions[0].bundle_less(), None, "RegisterAggregator burns the bond through its bundle");
        assert_eq!(actions[1].bundle_less(), Some("unbond_aggregator"));
        assert_eq!(actions[2].bundle_less(), Some("withdraw_aggregator"));
        assert_eq!(actions[3].bundle_less(), Some("slash_aggregator"));
        assert_eq!(actions[4].bundle_less(), Some("aggregate"));
    }

    fn signed_header(kp: &Keypair, nonce: u64, sig: &crate::crypto::Signature) -> SignedAggregateHeader {
        SignedAggregateHeader {
            aggregator: kp.public_key().address(),
            nonce,
            time: 9,
            r: [1; 8],
            covers: vec![Hash::digest(b"x")],
            proof_hash: Hash::digest(b"p"),
            signature: sig.clone(),
        }
    }

    fn env() -> crate::notes::Envelope {
        crate::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] }
    }

    /// The wire cap: the proof cap plus the covers and the interface-list bound and the fixed
    /// overhead — pinned as a derivation, not a magic number (spec §3.1).
    #[test]
    fn max_aggregate_bytes_is_the_proof_cap_plus_the_cover_and_list_bounds() {
        assert_eq!(
            gas::MAX_AGGREGATE_BYTES,
            gas::MAX_PROOF_BYTES + 3 * 32 + (4 + 1 + 34 * 3) * 8 + 4_400
        );
        // And it admits a 2 MiB proof with the three covers and the envelope.
        assert!(gas::MAX_AGGREGATE_BYTES > gas::MAX_PROOF_BYTES + 3 * 32 + 2_000);
    }

    /// The genesis section gates the ledger (spec §9): a genesis without it builds a ledger
    /// whose `aggregation` is `None`; with it, the section is installed, the register starts
    /// empty, and the state root is the gated one. And the activation placeholder — an admitted
    /// shape with an all-zero program digest — is refused at validation, so it can never reach
    /// a fleet.
    fn genesis() -> crate::genesis::Genesis {
        let k = Keypair::from_seed([9; 32]).unwrap();
        crate::genesis::Genesis {
            chain_id: 42,
            timestamp_ms: 1_700_000_000_000,
            validators: vec![crate::genesis::GenesisValidator {
                public_key: k.public_key().clone(),
                stake: crate::ledger::staking::MIN_STAKE as u128,
                payout: crate::notes::ShieldedAddress { pk: [4; 8], kem_ek: vec![5; crate::notes::KEM_EK_BYTES] }.to_string(),
            }],
            alloc: vec![],
            faucet: false,
            confidential: true,
            fri_profile: "production".into(),
            hc_bundle: crate::notes::word8_to_hex(&[3; 8]),
            bridge: None,
            aggregation: None,
            epoch_blocks: crate::genesis::EPOCH_BLOCKS_DEFAULT,
        }
    }

    #[test]
    fn the_genesis_section_gates_the_ledger_and_the_placeholder_is_refused() {
        let mut g = genesis();
        assert!(g.aggregation.is_none());
        let built = g.build(&StubExecutor).unwrap();
        assert!(built.ledger.aggregation().is_none());

        g.aggregation = Some(cfg());
        let built = g.build(&StubExecutor).unwrap();
        assert!(built.ledger.aggregation().is_some());
        assert!(built.ledger.aggregators().is_empty());
        assert_eq!(
            built.ledger.state_root(),
            manual_state_root(&built.ledger, b"shrugg-state-3", true)
        );

        let mut bad = genesis();
        let mut c = cfg();
        c.admitted_shapes = vec![AdmittedShape {
            shape: crate::types::DeclaredShape {
                profile: crate::types::FriProfile::Production,
                tier: 14,
                program_log_height: 13,
                input_log_height: 12,
                keccak_log_height: 0,
                sha256_log_height: 0,
                public_log_height: 2,
                mem_log_height: 18,
            },
            hc: crate::crypto::Hash::digest(b"bundle guest"),
            aggregate_program_digest: [0; 4],
        }];
        bad.aggregation = Some(c);
        assert!(matches!(
            bad.build(&StubExecutor),
            Err(crate::genesis::GenesisError::BadAggregationConfig(_))
        ));
    }

    /// The subsidy schedule: 100 SHRUGG per sealed block, halving every 210 000, zero from the
    /// 64th halving (spec §5.1).
    #[test]
    fn the_subsidy_halves_on_schedule_and_ends_at_the_64th() {
        let c = cfg();
        assert_eq!(gas::subsidy(0, &c), 100 * UNITS_PER_SHRUGG);
        assert_eq!(gas::subsidy(209_999, &c), 100 * UNITS_PER_SHRUGG);
        assert_eq!(gas::subsidy(210_000, &c), 50 * UNITS_PER_SHRUGG);
        assert_eq!(gas::subsidy(210_000 * 63, &c), c.subsidy_base >> 63);
        assert_eq!(gas::subsidy(210_000 * 64, &c), 0);
        assert_eq!(gas::subsidy(u64::MAX, &c), 0);
        // Monotone non-increasing across the whole schedule.
        let mut prev = u64::MAX;
        for k in 0..70u64 {
            let s = gas::subsidy(k * 210_000, &c);
            assert!(s <= prev, "subsidy increased at halving {k}");
            prev = s;
        }
    }
}

// ── the register's four actions (Task 2) ─────────────────────────────────────────────────────
#[cfg(test)]
mod register_tests {
    use super::*;
    use crate::confidential::{ConfidentialExecutor, StubExecutor};
    use crate::crypto::{Keypair, Hash, Signature};
    use crate::gas;
    use crate::ledger::staking::ValidatorEntry;
    use crate::ledger::Ledger;
    use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};
    use crate::types::actions::{
        aggregator_register_message, aggregator_unbond_message, aggregator_withdraw_message,
        aggregate_signing_hash, AggregatorRegistration,
    };
    use crate::types::{Action, SignedAggregateHeader, Transaction};
    use std::collections::BTreeMap;

    const HC: Word8 = [11; 8];

    fn keys() -> (Keypair, Keypair) {
        (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap())
    }

    fn entry(k: &Keypair, stake: u64) -> (Address, ValidatorEntry) {
        (
            k.public_key().address(),
            ValidatorEntry {
                public_key: k.public_key().clone(),
                stake,
                pending: Vec::new(),
                rewards: 0,
                payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
                nonce: 0,
            },
        )
    }

    fn gated() -> Ledger {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l.set_aggregation(Some(cfg()));
        l
    }

    fn cfg() -> AggregationConfig {
        AggregationConfig {
            bond: 100 * crate::types::UNITS_PER_SHRUGG,
            max_covers: 3,
            subsidy_base: 100 * crate::types::UNITS_PER_SHRUGG,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        }
    }

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] }
    }

    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64, burn: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.root(),
            nullifiers: nfs,
            commitments: cms,
            fee,
            burn,
            asset: 0,
            time: l.height as u32,
            envelopes: [env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        b
    }

    fn registration(kp: &Keypair, payout: &ShieldedAddress) -> AggregatorRegistration {
        AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(7, payout).as_bytes()),
        }
    }

    fn register_tx(l: &Ledger, kp: &Keypair, payout: &ShieldedAddress, burn: u64) -> Transaction {
        Transaction::shielded(
            7,
            bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE, burn),
            Action::RegisterAggregator { registration: registration(kp, payout) },
        )
    }

    fn unbond_tx(kp: &Keypair, nonce: u64) -> Transaction {
        let aggregator = kp.public_key().address();
        Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::UnbondAggregator {
                aggregator,
                nonce,
                signature: kp.sign(aggregator_unbond_message(7, &aggregator, nonce).as_bytes()),
            },
        }
    }

    fn withdraw_tx(kp: &Keypair, nonce: u64, time: u32, r: Word8) -> Transaction {
        let aggregator = kp.public_key().address();
        let envelope = env();
        Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::WithdrawAggregator {
                aggregator,
                nonce,
                time,
                r,
                envelope: envelope.clone(),
                signature: kp.sign(aggregator_withdraw_message(7, &aggregator, nonce, time, &r, &envelope).as_bytes()),
            },
        }
    }

    fn signed_header(kp: &Keypair, nonce: u64, covers: Vec<Hash>, proof_hash: Hash) -> Box<SignedAggregateHeader> {
        let aggregator = kp.public_key().address();
        let signature = kp.sign(aggregate_signing_hash(7, nonce, 9, &[1; 8], &covers, &proof_hash).as_bytes());
        Box::new(SignedAggregateHeader { aggregator, nonce, time: 9, r: [1; 8], covers, proof_hash, signature })
    }

    fn payout_addr() -> ShieldedAddress {
        ShieldedAddress { pk: [7; 8], kem_ek: vec![8; crate::notes::KEM_EK_BYTES] }
    }

    fn proposer(l: &Ledger) -> Address {
        *l.validators().keys().next().unwrap()
    }

    /// Registering: the bundle burns exactly the genesis bond, the entry appears at nonce 0,
    /// and the register's root moves.
    #[test]
    fn registering_creates_the_entry_and_moves_the_root() {
        let mut l = gated();
        let (kp, _) = keys();
        let payout = payout_addr();
        let before = crate::ledger::aggregation::aggregators_root(l.aggregators());
        let tx = register_tx(&l, &kp, &payout, cfg().bond);
        l.apply_tx(&tx, &proposer(&l), &StubExecutor).unwrap();
        let e = &l.aggregators()[&kp.public_key().address()];
        assert_eq!(e.bond, cfg().bond);
        assert_eq!(e.payout, payout);
        assert_eq!(e.nonce, 0);
        assert_eq!(e.unbonding, None);
        assert_ne!(crate::ledger::aggregation::aggregators_root(l.aggregators()), before);
    }

    /// The burn must be exactly the genesis bond — no more, no less (spec §2.2).
    #[test]
    fn registering_with_the_wrong_burn_is_refused() {
        let mut l = gated();
        let (kp, _) = keys();
        let payout = payout_addr();
        for burn in [cfg().bond - 1, cfg().bond + 1, 0] {
            let tx = register_tx(&l, &kp, &payout, burn);
            match l.apply_tx(&tx, &proposer(&l), &StubExecutor) {
                Err(crate::ledger::TxError::Aggregation(AggregationError::BondMismatch { burn: b, bond })) => {
                    assert_eq!(b, burn);
                    assert_eq!(bond, cfg().bond);
                }
                other => panic!("burn {burn} must fail the bond check, got {other:?}"),
            }
        }
        assert!(l.aggregators().is_empty());
    }

    /// A second registration under the same address is refused.
    #[test]
    fn registering_twice_is_refused() {
        let mut l = gated();
        let (kp, _) = keys();
        let payout = payout_addr();
        let tx = register_tx(&l, &kp, &payout, cfg().bond);
        l.apply_tx(&tx, &proposer(&l), &StubExecutor).unwrap();
        let tx2 = register_tx(&l, &kp, &payout, cfg().bond);
        // The second bundle spends the same nullifiers, so use fresh ones.
        let mut tx2 = tx2;
        tx2.bundle.as_mut().unwrap().nullifiers = [[5; 8], [6; 8]];
        tx2.bundle.as_mut().unwrap().commitments = [[7; 8], [8; 8]];
        let d = StubExecutor.bundle_digest(&tx2.bundle.as_ref().unwrap().digest_input());
        tx2.bundle.as_mut().unwrap().proof = StubExecutor::make_bundle_proof(&HC, &d);
        assert!(l.apply_tx(&tx2, &proposer(&l), &StubExecutor).is_err());
    }

    /// A chain without the section refuses every aggregation action by name.
    #[test]
    fn the_actions_are_refused_on_an_ungated_chain() {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        let (kp, _) = keys();
        let tx = register_tx(&l, &kp, &payout_addr(), cfg().bond);
        match l.apply_tx(&tx, &proposer(&l), &StubExecutor) {
            Err(crate::ledger::TxError::UnsupportedAction("aggregation")) => {}
            other => panic!("expected the named refusal, got {other:?}"),
        }
        match l.apply_tx(&unbond_tx(&kp, 0), &proposer(&l), &StubExecutor) {
            Err(crate::ledger::TxError::UnsupportedAction("aggregation")) => {}
            other => panic!("expected the named refusal, got {other:?}"),
        }
    }

    /// A registration signed over the wrong message is refused.
    #[test]
    fn a_bad_registration_signature_is_refused() {
        let mut l = gated();
        let (kp, _) = keys();
        let payout = payout_addr();
        let mut registration = registration(&kp, &payout);
        registration.signature = kp.sign(b"not the registration message");
        let tx = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE, cfg().bond),
            Action::RegisterAggregator { registration },
        );
        assert!(l.apply_tx(&tx, &proposer(&l), &StubExecutor).is_err());
    }

    /// Unbonding sets the release height and bars further submissions; the nonce is monotonic.
    #[test]
    fn unbonding_sets_the_release_and_the_nonce_is_monotonic() {
        let mut l = gated();
        let (kp, _) = keys();
        l.apply_tx(&register_tx(&l, &kp, &payout_addr(), cfg().bond), &proposer(&l), &StubExecutor).unwrap();
        l.apply_tx(&unbond_tx(&kp, 0), &proposer(&l), &StubExecutor).unwrap();
        let e = &l.aggregators()[&kp.public_key().address()];
        assert_eq!(e.nonce, 1);
        assert_eq!(e.unbonding, Some(l.height + cfg().window));
        // The replay: nonce 0 again is refused.
        assert!(l.apply_tx(&unbond_tx(&kp, 0), &proposer(&l), &StubExecutor).is_err());
        // And a second unbond with unbonding already set is refused.
        assert!(l.apply_tx(&unbond_tx(&kp, 1), &proposer(&l), &StubExecutor).is_err());
    }

    /// The withdraw: before the release height it is refused; at it, the bond less the base is
    /// paid as a note the ledger derives, the base goes to the proposer, and the entry is gone.
    #[test]
    fn the_withdraw_pays_the_bond_less_the_base_at_release() {
        let mut l = gated();
        let (kp, _) = keys();
        let payout = payout_addr();
        l.apply_tx(&register_tx(&l, &kp, &payout, cfg().bond), &proposer(&l), &StubExecutor).unwrap();
        l.apply_tx(&unbond_tx(&kp, 0), &proposer(&l), &StubExecutor).unwrap();
        let release = l.height + cfg().window;
        // Before the release: refused.
        assert!(l.apply_tx(&withdraw_tx(&kp, 1, l.height as u32, [9; 8]), &proposer(&l), &StubExecutor).is_err());
        // At the release height: pays bond − BUNDLE_BASE as a derived note.
        l.set_height(release);
        let before_rewards = l.validators()[&proposer(&l)].rewards;
        let tx = withdraw_tx(&kp, 1, release as u32, [9; 8]);
        let expected_cm = l.derived_commitment(&tx.action, &StubExecutor).expect("the note is derivable at admission");
        l.apply_tx(&tx, &proposer(&l), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm), "the derived note is in the tree");
        assert_eq!(
            l.validators()[&proposer(&l)].rewards,
            before_rewards + gas::BUNDLE_BASE,
            "the base goes to the proposer"
        );
        assert!(l.aggregators().get(&kp.public_key().address()).is_none(), "the entry is deleted");
    }

    /// Slashing: two headers by the same aggregator at the same nonce with different content
    /// burn the bond and delete the entry — and anyone may submit the proof.
    #[test]
    fn a_slash_burns_the_bond_and_deletes_the_entry() {
        let mut l = gated();
        let (kp, other) = keys();
        l.apply_tx(&register_tx(&l, &kp, &payout_addr(), cfg().bond), &proposer(&l), &StubExecutor).unwrap();
        let h1 = Hash::digest(b"covers one");
        let h2 = Hash::digest(b"covers two");
        let slash = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::SlashAggregator {
                a: signed_header(&kp, 1, vec![h1], Hash::digest(b"proof one")),
                b: signed_header(&kp, 1, vec![h2], Hash::digest(b"proof two")),
            },
        };
        l.apply_tx(&slash, &proposer(&l), &StubExecutor).unwrap();
        assert!(l.aggregators().get(&kp.public_key().address()).is_none(), "the entry is slashed away");
        let _ = other;
    }

    /// Not equivocation: identical content, or the same aggregator at different nonces.
    #[test]
    fn a_slash_without_equivocation_is_refused() {
        let mut l = gated();
        let (kp, _) = keys();
        l.apply_tx(&register_tx(&l, &kp, &payout_addr(), cfg().bond), &proposer(&l), &StubExecutor).unwrap();
        let h = Hash::digest(b"covers");
        let p = Hash::digest(b"proof");
        // Identical headers.
        let same = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::SlashAggregator { a: signed_header(&kp, 1, vec![h], p), b: signed_header(&kp, 1, vec![h], p) },
        };
        assert!(l.apply_tx(&same, &proposer(&l), &StubExecutor).is_err());
        // Different nonces.
        let different = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::SlashAggregator {
                a: signed_header(&kp, 1, vec![h], p),
                b: signed_header(&kp, 2, vec![Hash::digest(b"other")], Hash::digest(b"other proof")),
            },
        };
        assert!(l.apply_tx(&different, &proposer(&l), &StubExecutor).is_err());
        assert_eq!(l.aggregators().len(), 1, "the entry survives both refusals");
    }
}
