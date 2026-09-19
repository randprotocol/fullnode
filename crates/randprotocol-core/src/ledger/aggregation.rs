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

/// The register's leaf (spec §2.1): `blake3("rand-aggregator-leaf-1", addr ‖ bond ‖ nonce ‖
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
    Hash::digest_domain(b"rand-aggregator-leaf-1", &buf)
}

/// The register's component of the state root: the merkle root of every entry's leaf, empty at
/// chain-9 block 0. Joined into the root (under the `rand-state-3` domain) exactly when
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
    #[error("an aggregate covers at least one bundle")]
    EmptyCoverSet,
    #[error("an aggregate covers {got} bundles, over the cap {max}")]
    TooManyCovers { got: usize, max: u32 },
    #[error("the cover set names {0} twice")]
    DuplicateCover(Hash),
    #[error("the covered records ({covered}) do not match the cover set ({covers})")]
    CoverAssemblyMismatch { covers: usize, covered: usize },
    #[error("covered bundle {0}'s declared shape is not a registered shape")]
    UnregisteredShape(Hash),
    #[error("covered bundle {cover} declares {field} {actual}; the set's first bundle declares {expected}")]
    CoveredShapeMismatch { cover: Hash, field: &'static str, expected: u8, actual: u8 },
    #[error("covered bundle {0} is a proof of another guest")]
    CoveredGuestMismatch(Hash),
    /// The cover set's node-side half (spec §3.2): the hash names no committed transaction.
    #[error("cover {0} names no committed transaction")]
    UnknownCover(Hash),
    /// It names one, but not a bundle-carrying one — there is no bundle proof to aggregate.
    #[error("cover {0} names a transaction with no bundle")]
    CoverNotABundle(Hash),
    /// Its block has scrolled out of the aggregation window (spec §3.3).
    #[error("cover {cover}'s block {block} is outside the window at head {head}")]
    CoverOutsideWindow { cover: Hash, block: u64, head: u64 },
    /// It is already covered: `sealed_by` is present (spec §3.2.3). A statement about committed
    /// history — a seal, once committed, never un-happens — so a permanent verdict.
    #[error("cover {0} is already sealed by another aggregate")]
    CoverSealed(Hash),
    /// The stored record a cover names cannot be read back — this node's store, not the
    /// transaction, is at fault; never a permanent verdict.
    #[error("the stored record for cover {0} is corrupt")]
    CoverStoreCorrupt(Hash),
    /// The ledger's half of coverability, a block-validity rule (the pre-v0.1 review's H1): the
    /// cover is not in the ledger's coverable set — never a bundle this chain applied, already
    /// covered, or past its window and swept. The node's three verdicts above name the case at
    /// admission; at apply the ledger only knows the set. Permanent: none of the three un-happens.
    #[error("cover {0} is not coverable: unknown, already covered, or past its window")]
    CoverNotCoverable(Hash),
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

// ── the `Aggregate` itself: admission (spec §4) and apply (spec §5) ──────────────────────────

use crate::confidential::ConfidentialExecutor;
use crate::types::{pv, CoveredBundle};

/// What a valid aggregate carries past admission (spec §4): the covered-bundle records the
/// node assembled, the payout note's derived commitment (step 5), and each covered bundle's
/// `OUT0..7` as the proof returned them, in cover order (step 8) — apply's inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedAggregate {
    pub covered: Vec<CoveredBundle>,
    pub payout_cm: Word8,
    pub outs: Vec<[u32; 8]>,
}

/// The aggregate's payment (spec §5.4): the subsidy at the ledger's sealed-block counter, the
/// covered bundles' proving shares, their sum, and the one deposit note they are paid as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payment {
    pub subsidy: u64,
    pub proving_shares: u64,
    pub total: u64,
    pub note: Word8,
}

impl Ledger {
    /// At bundle inclusion: the proposer keeps `gas::BUNDLE_BASE`; the excess is bucketed
    /// against the bundle transaction's hash (spec §5.2) with its coverable-until height —
    /// the two resolutions of which are the aggregate's payment and the commit sweep.
    pub(crate) fn bucket_excess(&mut self, bundle_hash: Hash, excess: u64, proposer: Address, expires_at: u64) {
        self.unsealed_fees.insert(bundle_hash, (excess, proposer, expires_at));
    }

    /// At block commit: every bucket entry whose window passed is credited to its recorded
    /// proposer (spec §5.2) — the moment the excess actually leaves the pool's accounting, so
    /// `fees_paid` moves here and not at inclusion. Bounded by construction (the bucket holds
    /// at most `window × max_covers` entries) and a no-op on a chain without the section.
    pub(crate) fn sweep_expired_excesses(&mut self, head_height: u64, committing: &Address) {
        if self.aggregation().is_none() {
            return;
        }
        let expired: Vec<Hash> = self
            .unsealed_fees
            .iter()
            .filter(|(_, (_, _, until))| *until <= head_height)
            .map(|(h, _)| *h)
            .collect();
        for h in expired {
            let (excess, recorded, _) = self.unsealed_fees.remove(&h).expect("iterated from the map");
            // The recorded proposer's entry may be gone — it withdrew since including the
            // bundle; the committing block's proposer takes the excess then, so it always
            // lands register-side. Either way it leaves the pool now: `fees_paid` moves.
            // Saturating, per `Supply::pool_value`'s own rule: the arithmetic cannot wrap on a
            // chain whose blocks all applied, and a damaged counter shows up as the audit's
            // invariant failing, not as a panic inside block application.
            let credit = if self.validators.contains_key(&recorded) { recorded } else { *committing };
            let e = self.validators.get_mut(&credit).expect("the committing proposer is in the register");
            e.rewards = e.rewards.saturating_add(excess);
            self.supply.fees_paid = self.supply.fees_paid.saturating_add(excess);
        }
    }

    /// The aggregate's one deposit note (spec §5.4): `subsidy(sealed_blocks)` plus the covered
    /// bundles' bucketed excesses, derived exactly as a validator's `Withdraw` note — the
    /// amount admission's step 5 derives, the mempool claims, and apply appends.
    fn aggregate_payment(
        &self,
        covers: &[Hash],
        cfg: &AggregationConfig,
        time: u32,
        r: &Word8,
        payout: &ShieldedAddress,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Payment, TxError> {
        let subsidy = gas::subsidy(self.supply.sealed_blocks, cfg);
        let proving_shares = covers.iter().try_fold(0u64, |acc, c| {
            // Validation already required the entry; a missing one here is the same refusal,
            // never a silent zero share.
            let e = self.unsealed_fees.get(c).map(|(excess, _, _)| *excess).ok_or(AggregationError::CoverNotCoverable(*c))?;
            acc.checked_add(e).ok_or(TxError::Overflow)
        })?;
        let total = subsidy.checked_add(proving_shares).ok_or(TxError::Overflow)?;
        let note = executor.note_commitment(&payout.pk, &[0; 8], total, 0, time, r);
        Ok(Payment { subsidy, proving_shares, total, note })
    }
}

/// The aggregate's payout note (spec §5.4), derived for admission and the mempool's claim:
/// the entry's payout address looked up, then [`Ledger::aggregate_payment`]'s note.
pub(crate) fn payout_note(
    ledger: &Ledger,
    aggregator: &Address,
    covers: &[Hash],
    time: u32,
    r: &Word8,
    executor: &dyn ConfidentialExecutor,
) -> Result<Word8, TxError> {
    let cfg = ledger.aggregation().expect("gated by the caller");
    let e = ledger
        .aggregators()
        .get(aggregator)
        .ok_or(TxError::Aggregation(AggregationError::UnknownAggregator(*aggregator)))?;
    Ok(ledger.aggregate_payment(covers, cfg, time, r, &e.payout, executor)?.note)
}

/// Spec §4's nine steps, in order, cheap before expensive (`validate_inner`'s discipline,
/// extended). Steps 1–4's ledger half refuse before any hashing; step 8 is the one expensive
/// step, last. The cover set's other half — every hash naming a *coverable* bundle (finalised,
/// in-window, unsealed) — is the node's, which assembled `covered` from its store (spec §3.2);
/// this function checks everything the ledger can check against `covered` as given.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_aggregate(
    ledger: &Ledger,
    tx: &Transaction,
    covers: &[Hash],
    aggregator: &Address,
    nonce: u64,
    time: u32,
    r: &Word8,
    envelope: &crate::notes::Envelope,
    signature: &Signature,
    proof: &[u8],
    covered: &[CoveredBundle],
    executor: &dyn ConfidentialExecutor,
) -> Result<ValidatedAggregate, TxError> {
    // The absolute gate (spec §9), first here as it is in `validate`.
    let Some(cfg) = ledger.aggregation() else { return Err(NOT_AGGREGATION) };
    // 1. The wire caps (`validate_inner`'s step 1 has them too — this entry must stand alone)
    //    and the chain id, before any register work.
    if proof.len() > ledger.max_proof_bytes() {
        return Err(TxError::ProofTooLarge);
    }
    if envelope.len() > crate::notes::MAX_ENVELOPE_BYTES {
        return Err(TxError::EnvelopeTooLarge);
    }
    if tx.encoded_len() > ledger.max_aggregate_bytes() {
        return Err(TxError::AggregateTooLarge { size: tx.encoded_len(), max: ledger.max_aggregate_bytes() });
    }
    if tx.chain_id != ledger.chain_id() {
        return Err(TxError::WrongChain { expected: ledger.chain_id(), actual: tx.chain_id });
    }
    // 2. The aggregator: registered, not unbonding, the nonce the register expects, and the
    //    signature over the action's signing hash — `signed_by`'s three, plus the bar.
    let entry = signed_by(ledger, aggregator, nonce, signature, || {
        aggregate_signing_hash(tx.chain_id, nonce, time, r, covers, &Hash::digest(proof))
    })?;
    if entry.unbonding.is_some() {
        return Err(AggregationError::Unbonding(*aggregator).into());
    }
    // 3. The payout note's `time`, the ledger's ordinary window (a bundle-less `Withdraw`'s
    //    rule, one action over).
    ledger.check_time(time)?;
    // 4. The cover set's ledger half: `1 ≤ covers ≤ max_covers`, no duplicates, and the node's
    //    covered records matching the set one for one. (Coverability itself — finalised,
    //    in-window, unsealed — is the node's half, spec §3.2.)
    if covers.is_empty() {
        return Err(AggregationError::EmptyCoverSet.into());
    }
    if covers.len() > cfg.max_covers as usize {
        return Err(AggregationError::TooManyCovers { got: covers.len(), max: cfg.max_covers }.into());
    }
    for (i, cover) in covers.iter().enumerate() {
        if covers[..i].contains(cover) {
            return Err(AggregationError::DuplicateCover(*cover).into());
        }
    }
    if covered.len() != covers.len() {
        return Err(AggregationError::CoverAssemblyMismatch { covers: covers.len(), covered: covered.len() }.into());
    }
    //    And the ledger's own half of coverability (the pre-v0.1 review's H1): every cover
    //    must stand in the coverable set — a bundle this chain applied, not yet covered, and
    //    inside its window. The node's admission names the case; here the set is the rule, so
    //    a block that re-covers a sealed bundle, or covers one whose window passed, is invalid
    //    on every replica and not only refused by an honest pool.
    for cover in covers {
        if !ledger.unsealed_fees.contains_key(cover) {
            return Err(AggregationError::CoverNotCoverable(*cover).into());
        }
    }
    // 5. The payout note's commitment is new — derived as a `BridgeAttest`'s is, claimed in
    //    the mempool by the same `derived_commitment` arm.
    let payout_cm = payout_note(ledger, aggregator, covers, time, r, executor)?;
    if ledger.has_commitment(&payout_cm) {
        return Err(TxError::CommitmentExists(payout_cm));
    }
    // 6. Per covered bundle, the declared-shape check (pure integer compares): the first
    //    bundle's shape must be a registered shape, and every other bundle's must equal it —
    //    the aggregate program's interface digest binds one inner verifier key, so a mixed set
    //    could never digest-match, and refusing here names it before any rVM work.
    let first = &covered[0];
    let admitted = cfg
        .admitted_shapes
        .iter()
        .find(|a| a.shape == first.shape)
        .ok_or(AggregationError::UnregisteredShape(covers[0]))?;
    for (c, cover) in covered[1..].iter().zip(&covers[1..]) {
        if let Some((field, expected, actual)) = shape_mismatch(&first.shape, &c.shape) {
            return Err(AggregationError::CoveredShapeMismatch { cover: *cover, field, expected, actual }.into());
        }
    }
    // 7. The chain-side half of the digest step: every covered bundle must be a proof of the
    //    registered guest — `HC0..7` equals its `hc`. The digest compare itself cannot catch a
    //    wrong-guest cover (a prover commits those very words), so the ledger pins it; the
    //    compare against the proof's batch public values is the executor's, inside step 8.
    let hc_words = crate::notes::word8_from_bytes(admitted.hc.as_bytes()).expect("a Hash is 32 bytes");
    for (c, cover) in covered.iter().zip(covers) {
        if (0..8).any(|k| c.public_values[pv::HC0 + k] != hc_words[k] as u64) {
            return Err(AggregationError::CoveredGuestMismatch(*cover).into());
        }
    }
    // 8. The proof: the interface-list recompute and digest compare, then the rVM
    //    `Machine::verify` — the executor's pair, the one expensive step, last.
    let outs = executor
        .verify_aggregate(&first.shape, covered, proof)
        .map_err(TxError::InvalidAggregateProof)?;
    Ok(ValidatedAggregate { covered: covered.to_vec(), payout_cm, outs })
}

/// The first field on which two declared shapes differ, as `(field, expected, actual)` — the
/// profile compared as its discriminant. `None` when they are equal.
fn shape_mismatch(a: &DeclaredShape, b: &DeclaredShape) -> Option<(&'static str, u8, u8)> {
    let profile = |p: &crate::types::FriProfile| match p {
        crate::types::FriProfile::Test => 0,
        crate::types::FriProfile::Production => 1,
    };
    let fields: [(&'static str, u8, u8); 8] = [
        ("profile", profile(&a.profile), profile(&b.profile)),
        ("tier", a.tier, b.tier),
        ("program_log_height", a.program_log_height, b.program_log_height),
        ("input_log_height", a.input_log_height, b.input_log_height),
        ("keccak_log_height", a.keccak_log_height, b.keccak_log_height),
        ("sha256_log_height", a.sha256_log_height, b.sha256_log_height),
        ("public_log_height", a.public_log_height, b.public_log_height),
        ("mem_log_height", a.mem_log_height, b.mem_log_height),
    ];
    fields.into_iter().find(|(_, x, y)| x != y)
}

impl Ledger {
    /// The byte-level half of aggregate admission (spec §4 step 1): everything checkable
    /// without the covered records or the register, run by the node before it assembles them,
    /// so a garbage aggregate is refused before any storage read. `validate_aggregate` re-runs
    /// these as its own first step — this is a pre-screen, like the mempool's.
    pub fn preflight_aggregate(&self, tx: &Transaction) -> Result<(), TxError> {
        let Action::Aggregate { proof, envelope, .. } = &tx.action else { return Err(NOT_AGGREGATION) };
        if self.aggregation().is_none() {
            return Err(NOT_AGGREGATION);
        }
        if proof.len() > self.max_proof_bytes() {
            return Err(TxError::ProofTooLarge);
        }
        if envelope.len() > crate::notes::MAX_ENVELOPE_BYTES {
            return Err(TxError::EnvelopeTooLarge);
        }
        if tx.encoded_len() > self.max_aggregate_bytes() {
            return Err(TxError::AggregateTooLarge { size: tx.encoded_len(), max: self.max_aggregate_bytes() });
        }
        if tx.chain_id != self.chain_id {
            return Err(TxError::WrongChain { expected: self.chain_id, actual: tx.chain_id });
        }
        Ok(())
    }

    /// The covered-carrying admission of an `Aggregate` (spec §4): `validate_inner`'s action
    /// arm names its refusal because the covered bundles' records live in node storage, so the
    /// node's workers assemble them (spec §3.2's coverability) and come here.
    pub fn validate_aggregate(
        &self,
        tx: &Transaction,
        covered: &[CoveredBundle],
        executor: &dyn ConfidentialExecutor,
    ) -> Result<ValidatedAggregate, TxError> {
        let Action::Aggregate { covers, proof, aggregator, nonce, time, r, envelope, signature } = &tx.action else {
            return Err(NOT_AGGREGATION);
        };
        validate_aggregate(
            self, tx, covers, aggregator, *nonce, *time, r, envelope, signature, proof, covered, executor,
        )
    }

    /// The apply half, in lockstep with [`Ledger::validate_aggregate`] (spec §4 validated, then
    /// spec §5 paid): the one deposit note of subsidy plus covered proving shares is appended,
    /// the covered excesses leave the bucket, the subsidy counters and the register nonce move.
    /// Everything fallible is in the validation and the payment's derivation, before the first
    /// mutation (`apply_tx`'s rule for its own arms, one action over). Sealing (spec §6) is
    /// Task 6's, and until its covered pre-pass lands no proposer includes an aggregate
    /// (`apply_tx`'s arm refuses the action by name, so a block carrying one cannot be built or
    /// applied yet).
    pub fn apply_aggregate(
        &mut self,
        tx: &Transaction,
        covered: &[CoveredBundle],
        executor: &dyn ConfidentialExecutor,
    ) -> Result<(), TxError> {
        let Action::Aggregate { covers, aggregator, time, r, envelope, .. } = &tx.action else {
            return Err(NOT_AGGREGATION);
        };
        let (covers, aggregator, time, r, envelope) = (covers.clone(), *aggregator, *time, *r, envelope.clone());
        let validated = self.validate_aggregate(tx, covered, executor)?;
        let cfg = self.aggregation().expect("validated above").clone();
        let payout = self.aggregators().get(&aggregator).expect("validated above").payout.clone();
        let payment = self.aggregate_payment(&covers, &cfg, time, &r, &payout, executor)?;
        debug_assert_eq!(
            payment.note, validated.payout_cm,
            "admission and apply derive one note from one state"
        );
        self.append_deposit(payment.note, envelope, executor)?;
        for c in &covers {
            self.unsealed_fees.remove(c);
        }
        self.supply.subsidised = self.supply.subsidised.checked_add(payment.subsidy).ok_or(TxError::Overflow)?;
        self.supply.sealed_blocks = self.supply.sealed_blocks.checked_add(1).ok_or(TxError::Overflow)?;
        let e = self.aggregators.get_mut(&aggregator).expect("validated above");
        e.nonce += 1;
        Ok(())
    }
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
    use crate::types::{Action, AggregatorRegistration, SignedAggregateHeader, UNITS_PER_RAND};
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
            bond: 100 * UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * UNITS_PER_RAND,
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
            .map(|nf| Hash::digest_domain(b"rand-nullifier-leaf", &word8_to_bytes(nf)))
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
                Hash::digest_domain(b"rand-validator-leaf-2", &buf)
            })
            .collect();
        let prog_leaves: Vec<Hash> = l
            .programs()
            .keys()
            .map(|id| Hash::digest_domain(b"rand-program-leaf", id.as_bytes()))
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
        assert_eq!(l.state_root(), manual_state_root(&l, b"rand-state-2", false));
        // The same ledger, gated, gets a different root — and the component is the empty
        // register's (so an empty register at chain-9 block 0 is well-defined).
        let mut gated = l.clone();
        gated.set_aggregation(Some(cfg()));
        assert_eq!(gated.state_root(), manual_state_root(&gated, b"rand-state-3", true));
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
        assert_eq!(aggregator_leaf(&entry.public_key.address(), &entry), Hash::digest_domain(b"rand-aggregator-leaf-1", &buf));
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
            max_program_words: None,
            max_proof_bytes: None,
            max_block_bytes: None,
            max_call_envelope_bytes: None,
            max_program_public_words: None,
            receivers: None,
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
            manual_state_root(&built.ledger, b"rand-state-3", true)
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

    /// The subsidy schedule: 100 RAND per sealed block, halving every 210 000, zero from the
    /// 64th halving (spec §5.1).
    #[test]
    fn the_subsidy_halves_on_schedule_and_ends_at_the_64th() {
        let c = cfg();
        assert_eq!(gas::subsidy(0, &c), 100 * UNITS_PER_RAND);
        assert_eq!(gas::subsidy(209_999, &c), 100 * UNITS_PER_RAND);
        assert_eq!(gas::subsidy(210_000, &c), 50 * UNITS_PER_RAND);
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
    use crate::crypto::{Hash, Keypair};
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
            bond: 100 * crate::types::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * crate::types::UNITS_PER_RAND,
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

// ── Task 4: aggregate admission (spec §4) ────────────────────────────────────────────────────
#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
    use crate::crypto::{Hash, Keypair};
    use crate::gas;
    use crate::ledger::staking::ValidatorEntry;
    use crate::ledger::{Ledger, TxError};
    use crate::notes::{word8_from_bytes, Bundle, Envelope, ShieldedAddress, Word8};
    use crate::types::actions::{aggregator_register_message, aggregate_signing_hash, AggregatorRegistration};
    use crate::types::{pv, Action, CoveredBundle, DeclaredShape, FriProfile, Transaction};
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

    /// The one registered shape these tests admit, and its bundle-guest `hc`.
    fn shape() -> DeclaredShape {
        DeclaredShape {
            profile: FriProfile::Test,
            tier: 14,
            program_log_height: 13,
            input_log_height: 12,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 2,
            mem_log_height: 18,
        }
    }

    fn guest_hc() -> Hash {
        Hash::digest(b"the bundle guest")
    }

    fn cfg() -> AggregationConfig {
        AggregationConfig {
            bond: 100 * crate::types::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * crate::types::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape { shape: shape(), hc: guest_hc(), aggregate_program_digest: [1; 4] }],
        }
    }

    fn gated() -> Ledger {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(100);
        l.set_aggregation(Some(cfg()));
        l
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
            time: l.height() as u32,
            envelopes: [env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        b
    }

    fn payout_addr() -> ShieldedAddress {
        ShieldedAddress { pk: [7; 8], kem_ek: vec![8; crate::notes::KEM_EK_BYTES] }
    }

    fn proposer(l: &Ledger) -> Address {
        *l.validators().keys().next().unwrap()
    }

    /// Register `kp` as an aggregator (nonce 0), through the ordinary apply path.
    fn register(l: &mut Ledger, kp: &Keypair) {
        let payout = payout_addr();
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(7, &payout).as_bytes()),
        };
        let tx = Transaction::shielded(
            7,
            bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE, cfg().bond),
            Action::RegisterAggregator { registration },
        );
        l.apply_tx(&tx, &proposer(l), &StubExecutor).unwrap();
    }

    /// A well-formed aggregate transaction over `covers`; the stub executor accepts any proof
    /// but `b"reject"`.
    fn aggregate_tx(kp: &Keypair, nonce: u64, time: u32, covers: Vec<Hash>, proof: Vec<u8>) -> Transaction {
        let aggregator = kp.public_key().address();
        let r = [9; 8];
        let signature = kp.sign(aggregate_signing_hash(7, nonce, time, &r, &covers, &Hash::digest(&proof)).as_bytes());
        Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::Aggregate {
                covers,
                proof,
                aggregator,
                nonce,
                time,
                r,
                envelope: env(),
                signature,
            },
        }
    }

    /// The covered-bundle records the node would assemble for an honest aggregate: the
    /// registered shape, the registered guest's `hc` at `HC0..7`, and a distinct `OUT0..7` run
    /// per bundle (so the stub's return is checkable).
    fn covered_records(shape: &DeclaredShape, tags: &[u8]) -> Vec<CoveredBundle> {
        let hc_words = word8_from_bytes(guest_hc().as_bytes()).unwrap();
        tags.iter()
            .map(|&t| {
                let mut public_values = [0u64; 34];
                public_values[pv::TIER] = shape.tier as u64;
                for k in 0..8 {
                    public_values[pv::OUT0 + k] = t as u64 * 100 + k as u64;
                    public_values[pv::HC0 + k] = hc_words[k] as u64;
                }
                CoveredBundle { public_values, shape: *shape }
            })
            .collect()
    }

    fn covers(n: usize) -> Vec<Hash> {
        (0..n).map(|i| Hash::digest(&[i as u8 + 40])).collect()
    }

    fn setup() -> (Ledger, Keypair) {
        let mut l = gated();
        let (kp, _) = keys();
        register(&mut l, &kp);
        // The synthetic covers in the ledger's coverable set (H1's block rule), excess-free.
        let p = proposer(&l);
        for c in covers(4) {
            l.bucket_excess(c, 0, p, u64::MAX);
        }
        (l, kp)
    }

    /// The happy path, end to end through the covered-carrying entry: steps 1–8 pass, the
    /// validated record carries the payout commitment and the covered bundles' `OUT0..7`, and
    /// apply moves the register nonce and nothing else (payment is Task 5's).
    #[test]
    fn a_valid_aggregate_validates_and_applies() {
        let (mut l, kp) = setup();
        let tx = aggregate_tx(&kp, 0, 100, covers(2), b"ok".to_vec());
        let covered = covered_records(&shape(), &[1, 2]);
        let v = l.validate_aggregate(&tx, &covered, &StubExecutor).expect("a well-formed aggregate validates");
        // The payout note: subsidy(0) = subsidy_base at a chain that has sealed nothing, to the
        // entry's payout address, stamped with the action's own time and blinding (spec §5.4).
        let want_cm = StubExecutor.note_commitment(&payout_addr().pk, &[0; 8], cfg().subsidy_base, 0, 100, &[9; 8]);
        assert_eq!(v.payout_cm, want_cm);
        assert_eq!(
            l.derived_commitment(&tx.action, &StubExecutor),
            Some(want_cm),
            "the mempool claims exactly the note admission derives"
        );
        assert_eq!(v.covered, covered);
        let want_outs: Vec<[u32; 8]> = (1..=2u8)
            .map(|t| std::array::from_fn(|k| (t as u32) * 100 + k as u32))
            .collect();
        assert_eq!(v.outs, want_outs);
        l.apply_aggregate(&tx, &covered, &StubExecutor).unwrap();
        assert_eq!(l.aggregators()[&kp.public_key().address()].nonce, 1);
        // And the same transaction can never apply again.
        match l.apply_aggregate(&tx, &covered, &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::BadNonce { expected: 1, actual: 0 })) => {}
            other => panic!("a replayed aggregate must fail the nonce check, got {other:?}"),
        }
    }

    /// The absolute gate (spec §9): a chain without the section refuses the covered-carrying
    /// path by name too.
    #[test]
    fn an_ungated_chain_refuses_the_covered_carrying_path_by_name() {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(100);
        let (kp, _) = keys();
        let tx = aggregate_tx(&kp, 0, 100, covers(1), b"ok".to_vec());
        assert_eq!(
            l.validate_aggregate(&tx, &covered_records(&shape(), &[1]), &StubExecutor),
            Err(NOT_AGGREGATION)
        );
        assert_eq!(l.preflight_aggregate(&tx), Err(NOT_AGGREGATION));
    }

    /// Step 1, the wire caps: the proof cap, the envelope cap, and the composite
    /// `MAX_AGGREGATE_BYTES` — each refused before any register work, and the first two exactly
    /// where `validate_inner` puts every action's caps.
    #[test]
    fn step_1_refuses_the_oversized_before_any_state_work() {
        let (l, kp) = setup();
        let big_proof = aggregate_tx(&kp, 0, 100, covers(1), vec![0; gas::MAX_PROOF_BYTES + 1]);
        assert_eq!(l.preflight_aggregate(&big_proof), Err(TxError::ProofTooLarge));
        assert_eq!(l.validate(&big_proof, &StubExecutor), Err(TxError::ProofTooLarge), "validate_inner's step 1 shares the cap");
        let mut big_env = aggregate_tx(&kp, 0, 100, covers(1), b"ok".to_vec());
        if let Action::Aggregate { envelope, .. } = &mut big_env.action {
            envelope.body = vec![0; crate::notes::MAX_ENVELOPE_BYTES + 1];
        }
        assert_eq!(l.preflight_aggregate(&big_env), Err(TxError::EnvelopeTooLarge));
        // The composite cap is over the whole transaction's encoding — a giant cover list is
        // the cheapest way over it without tripping a per-field cap.
        let giant = aggregate_tx(&kp, 0, 100, vec![Hash::ZERO; gas::MAX_AGGREGATE_BYTES / 32], b"ok".to_vec());
        match l.preflight_aggregate(&giant) {
            Err(TxError::AggregateTooLarge { .. }) => {}
            other => panic!("expected the composite cap, got {other:?}"),
        }
        // And the wrong chain id is step 1's other half, refused before the aggregator is consulted.
        let mut wrong_chain = aggregate_tx(&kp, 0, 100, covers(1), b"ok".to_vec());
        wrong_chain.chain_id = 99;
        match l.preflight_aggregate(&wrong_chain) {
            Err(TxError::WrongChain { expected: 7, actual: 99 }) => {}
            other => panic!("expected WrongChain, got {other:?}"),
        }
    }

    /// The call limits (spec §4): an aggregate's proof cap is the ledger's `max_proof_bytes`, in
    /// all three places it is checked, and the composite wire cap grows with it — so a proof the
    /// raised cap admits is not refused by the composite one instead.
    #[test]
    fn the_aggregate_proof_cap_is_the_ledgers_max_proof_bytes() {
        let (l, kp) = setup();
        let (mut raised, _) = setup();
        raised.set_max_proof_bytes(8 << 20);
        raised.set_max_block_bytes(17 << 20);
        assert_eq!(l.max_aggregate_bytes(), gas::MAX_AGGREGATE_BYTES, "the default is today's cap");
        assert_eq!(raised.max_aggregate_bytes(), gas::MAX_AGGREGATE_BYTES + (6 << 20));
        let over = aggregate_tx(&kp, 0, 100, covers(1), vec![0; gas::MAX_PROOF_BYTES + 1]);
        let covered = covered_records(&shape(), &[1]);
        assert_eq!(l.preflight_aggregate(&over), Err(TxError::ProofTooLarge));
        assert_eq!(l.validate(&over, &StubExecutor), Err(TxError::ProofTooLarge));
        assert!(matches!(l.validate_aggregate(&over, &covered, &StubExecutor), Err(TxError::ProofTooLarge)));
        let not_size = |r: Result<(), TxError>| {
            !matches!(r, Err(TxError::ProofTooLarge | TxError::AggregateTooLarge { .. } | TxError::TransactionTooLarge { .. }))
        };
        assert_eq!(raised.preflight_aggregate(&over), Ok(()), "the byte-level pre-screen passes");
        assert!(not_size(raised.validate(&over, &StubExecutor)));
        assert!(not_size(raised.validate_aggregate(&over, &covered, &StubExecutor).map(|_| ())));
        let at = aggregate_tx(&kp, 0, 100, covers(1), vec![0; 8 << 20]);
        assert_eq!(raised.preflight_aggregate(&at), Ok(()));
        let past = aggregate_tx(&kp, 0, 100, covers(1), vec![0; (8 << 20) + 1]);
        assert_eq!(raised.preflight_aggregate(&past), Err(TxError::ProofTooLarge));
    }

    /// Step 2: the aggregator must be registered, not unbonding, at the action's nonce, and the
    /// signature must be over the action's signing hash — in that order.
    #[test]
    fn step_2_refuses_the_unknown_unbonding_stale_and_forged() {
        let (mut l, kp) = setup();
        let covered = covered_records(&shape(), &[1]);
        // Unknown: never registered.
        let (_, stranger) = keys();
        let tx = aggregate_tx(&stranger, 0, 100, covers(1), b"ok".to_vec());
        match l.validate_aggregate(&tx, &covered, &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::UnknownAggregator(a))) => {
                assert_eq!(a, stranger.public_key().address())
            }
            other => panic!("expected UnknownAggregator, got {other:?}"),
        }
        // Bad nonce.
        let tx = aggregate_tx(&kp, 7, 100, covers(1), b"ok".to_vec());
        match l.validate_aggregate(&tx, &covered, &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::BadNonce { expected: 0, actual: 7 })) => {}
            other => panic!("expected BadNonce, got {other:?}"),
        }
        // A signature over something else.
        let mut tx = aggregate_tx(&kp, 0, 100, covers(1), b"ok".to_vec());
        if let Action::Aggregate { signature, .. } = &mut tx.action {
            *signature = kp.sign(b"not the signing hash");
        }
        assert_eq!(
            l.validate_aggregate(&tx, &covered, &StubExecutor),
            Err(TxError::Aggregation(AggregationError::BadSignature))
        );
        // Unbonding: the register entry is mid-exit and cannot submit.
        let aggregator = kp.public_key().address();
        let unbond = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::UnbondAggregator {
                aggregator,
                nonce: 0,
                signature: kp.sign(
                    crate::types::actions::aggregator_unbond_message(7, &aggregator, 0).as_bytes()
                ),
            },
        };
        l.apply_tx(&unbond, &proposer(&l), &StubExecutor).unwrap();
        let tx = aggregate_tx(&kp, 1, 100, covers(1), b"ok".to_vec());
        match l.validate_aggregate(&tx, &covered, &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::Unbonding(a))) => assert_eq!(a, aggregator),
            other => panic!("expected Unbonding, got {other:?}"),
        }
    }

    /// Step 3: the payout note's `time` is held to the ledger's ordinary window.
    #[test]
    fn step_3_refuses_a_time_outside_the_window() {
        let (l, kp) = setup();
        // A future time: at height 100 every past time is inside the 256-block window.
        let tx = aggregate_tx(&kp, 0, 101, covers(1), b"ok".to_vec());
        match l.validate_aggregate(&tx, &covered_records(&shape(), &[1]), &StubExecutor) {
            Err(TxError::TimeOutOfWindow { time: 101, height: 100 }) => {}
            other => panic!("expected TimeOutOfWindow, got {other:?}"),
        }
    }

    /// Step 4's ledger half: `1 ≤ covers ≤ max_covers`, no duplicates, and the node's covered
    /// records must match the cover set one for one.
    #[test]
    fn step_4_refuses_the_empty_the_too_many_the_duplicated_and_the_mismatched() {
        let (l, kp) = setup();
        let tx = aggregate_tx(&kp, 0, 100, vec![], b"ok".to_vec());
        assert_eq!(
            l.validate_aggregate(&tx, &[], &StubExecutor),
            Err(TxError::Aggregation(AggregationError::EmptyCoverSet))
        );
        let tx = aggregate_tx(&kp, 0, 100, covers(4), b"ok".to_vec());
        match l.validate_aggregate(&tx, &covered_records(&shape(), &[1, 2, 3, 4]), &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::TooManyCovers { got: 4, max: 3 })) => {}
            other => panic!("expected TooManyCovers, got {other:?}"),
        }
        let dup = Hash::digest(b"one cover twice");
        let tx = aggregate_tx(&kp, 0, 100, vec![dup, Hash::digest(b"other"), dup], b"ok".to_vec());
        assert_eq!(
            l.validate_aggregate(&tx, &covered_records(&shape(), &[1, 2, 3]), &StubExecutor),
            Err(TxError::Aggregation(AggregationError::DuplicateCover(dup)))
        );
        let tx = aggregate_tx(&kp, 0, 100, covers(2), b"ok".to_vec());
        match l.validate_aggregate(&tx, &covered_records(&shape(), &[1]), &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::CoverAssemblyMismatch { covers: 2, covered: 1 })) => {}
            other => panic!("expected CoverAssemblyMismatch, got {other:?}"),
        }
    }

    /// Step 5: the payout note's commitment must be new — derived exactly as a `Withdraw`'s and
    /// refused when the tree already holds it.
    #[test]
    fn step_5_refuses_a_payout_commitment_the_tree_already_holds() {
        let (mut l, kp) = setup();
        let tx = aggregate_tx(&kp, 0, 100, covers(1), b"ok".to_vec());
        let cm = l.derived_commitment(&tx.action, &StubExecutor).expect("a registered aggregator's note derives");
        l.append_deposit(cm, env(), &StubExecutor).unwrap();
        assert_eq!(
            l.validate_aggregate(&tx, &covered_records(&shape(), &[1]), &StubExecutor),
            Err(TxError::CommitmentExists(cm))
        );
    }

    /// Step 6: every covered bundle's declared shape must equal a registered shape — the first
    /// bundle's sets the set's, and a later bundle differing from it names the field.
    #[test]
    fn step_6_refuses_the_unregistered_and_the_mixed_shape() {
        let (l, kp) = setup();
        let tx = aggregate_tx(&kp, 0, 100, covers(2), b"ok".to_vec());
        // covered[0] is not a registered shape at all.
        let mut foreign = shape();
        foreign.mem_log_height += 1;
        let mut bad = covered_records(&shape(), &[1, 2]);
        for c in &mut bad {
            c.shape = foreign;
        }
        match l.validate_aggregate(&tx, &bad, &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::UnregisteredShape(cover))) => {
                assert_eq!(cover, tx_covers(&tx)[0])
            }
            other => panic!("expected UnregisteredShape, got {other:?}"),
        }
        // covered[1] differs from covered[0] in one field — named in the error.
        let mut mixed = covered_records(&shape(), &[1, 2]);
        mixed[1].shape.input_log_height += 1;
        match l.validate_aggregate(&tx, &mixed, &StubExecutor) {
            Err(TxError::Aggregation(AggregationError::CoveredShapeMismatch {
                cover,
                field: "input_log_height",
                expected,
                actual,
            })) => {
                assert_eq!(cover, tx_covers(&tx)[1]);
                assert_eq!((expected, actual), (shape().input_log_height, shape().input_log_height + 1));
            }
            other => panic!("expected CoveredShapeMismatch, got {other:?}"),
        }
    }

    fn tx_covers(tx: &Transaction) -> Vec<Hash> {
        match &tx.action {
            Action::Aggregate { covers, .. } => covers.clone(),
            _ => panic!("not an aggregate"),
        }
    }

    /// Step 7's chain-side half: a covered bundle whose `HC0..7` is not the registered guest's
    /// `hc` is a proof of something else — the digest compare cannot catch it (a prover would
    /// commit those very words), so the ledger pins it itself.
    #[test]
    fn step_7_refuses_a_proof_of_another_guest() {
        let (l, kp) = setup();
        let tx = aggregate_tx(&kp, 0, 100, covers(2), b"ok".to_vec());
        let mut bad = covered_records(&shape(), &[1, 2]);
        bad[1].public_values[pv::HC0] += 1;
        assert_eq!(
            l.validate_aggregate(&tx, &bad, &StubExecutor),
            Err(TxError::Aggregation(AggregationError::CoveredGuestMismatch(tx_covers(&tx)[1])))
        );
    }

    /// Step 8: the proof itself — the one expensive step, last, through the executor.
    #[test]
    fn step_8_refuses_the_proof_the_executor_refuses() {
        let (l, kp) = setup();
        let tx = aggregate_tx(&kp, 0, 100, covers(1), b"reject".to_vec());
        match l.validate_aggregate(&tx, &covered_records(&shape(), &[1]), &StubExecutor) {
            Err(TxError::InvalidAggregateProof(ConfidentialError::InvalidAggregateProof(_))) => {}
            other => panic!("expected InvalidAggregateProof, got {other:?}"),
        }
    }

    /// The ordinary `Ledger::validate` cannot take an aggregate anywhere: its covered bundles
    /// live in node storage, so the action arm names the covered-carrying path instead.
    #[test]
    fn validate_inner_names_the_covered_carrying_path() {
        let (l, kp) = setup();
        let tx = aggregate_tx(&kp, 0, 100, covers(1), b"ok".to_vec());
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::AggregateNeedsCovered));
    }
}

// ── Task 5: the subsidy, the proving share, and the supply audit ─────────────────────────────
#[cfg(test)]
mod payment_tests {
    use super::*;
    use crate::confidential::{ConfidentialExecutor, StubExecutor};
    use crate::crypto::{Hash, Keypair};
    use crate::gas;
    use crate::ledger::staking::ValidatorEntry;
    use crate::ledger::{Ledger, TxError};
    use crate::types::{Block, BlockHeader, QuorumCertificate};
    use crate::notes::{word8_from_bytes, Bundle, Envelope, ShieldedAddress, Word8};
    use crate::types::actions::{aggregate_signing_hash, aggregator_register_message, AggregatorRegistration};
    use crate::types::{pv, Action, CoveredBundle, DeclaredShape, FriProfile, Transaction};
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

    fn shape() -> DeclaredShape {
        DeclaredShape {
            profile: FriProfile::Test,
            tier: 14,
            program_log_height: 13,
            input_log_height: 12,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 2,
            mem_log_height: 18,
        }
    }

    fn cfg_with_window(window: u64) -> AggregationConfig {
        AggregationConfig {
            bond: 100 * crate::types::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * crate::types::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window,
            admitted_shapes: vec![AdmittedShape { shape: shape(), hc: Hash::digest(b"the bundle guest"), aggregate_program_digest: [1; 4] }],
        }
    }

    fn gated(window: u64) -> Ledger {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l.set_aggregation(Some(cfg_with_window(window)));
        l.set_genesis_supply(300 * crate::types::UNITS_PER_RAND - 20, 20);
        l
    }

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] }
    }

    fn payout_addr() -> ShieldedAddress {
        ShieldedAddress { pk: [7; 8], kem_ek: vec![8; crate::notes::KEM_EK_BYTES] }
    }

    fn proposer(l: &Ledger) -> Address {
        *l.validators().keys().next().unwrap()
    }

    /// A fee-paying bundle whose stub proof publishes the recomputed digest.
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64, burn: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.root(),
            nullifiers: nfs,
            commitments: cms,
            fee,
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

    fn register(l: &mut Ledger, kp: &Keypair, tag: u32) {
        let payout = payout_addr();
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(7, &payout).as_bytes()),
        };
        let tx = Transaction::shielded(
            7,
            bundle(l, [[tag; 8], [tag + 1; 8]], [[tag + 2; 8], [tag + 3; 8]], gas::BUNDLE_BASE, cfg_with_window(256).bond),
            Action::RegisterAggregator { registration },
        );
        l.apply_tx(&tx, &proposer(l), &StubExecutor).unwrap();
        l.record_anchor(l.height());
    }

    fn aggregate_tx(kp: &Keypair, nonce: u64, time: u32, covers: Vec<Hash>, proof: Vec<u8>) -> Transaction {
        let aggregator = kp.public_key().address();
        let r = [9; 8];
        let signature = kp.sign(aggregate_signing_hash(7, nonce, time, &r, &covers, &Hash::digest(&proof)).as_bytes());
        Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::Aggregate { covers, proof, aggregator, nonce, time, r, envelope: env(), signature },
        }
    }

    fn covered_records(tags: &[u8]) -> Vec<CoveredBundle> {
        let hc_words = word8_from_bytes(Hash::digest(b"the bundle guest").as_bytes()).unwrap();
        tags.iter()
            .map(|&t| {
                let mut public_values = [0u64; 34];
                public_values[pv::TIER] = shape().tier as u64;
                for k in 0..8 {
                    public_values[pv::OUT0 + k] = t as u64 * 100 + k as u64;
                    public_values[pv::HC0 + k] = hc_words[k] as u64;
                }
                CoveredBundle { public_values, shape: shape() }
            })
            .collect()
    }

    /// A block signed by `key` over the ledger's real post-apply root — `mod.rs`'s own fixture.
    fn signed_block(l: &Ledger, txs: Vec<Transaction>, key: &Keypair, height: u64) -> Block {
        signed_block_with_covered(l, txs, key, height, &BTreeMap::new())
    }

    /// `signed_block` whose transactions may include an `Aggregate`: the root is computed
    /// through the covered-carrying apply, exactly as `apply_block` now runs it.
    fn signed_block_with_covered(
        l: &Ledger,
        txs: Vec<Transaction>,
        key: &Keypair,
        height: u64,
        covered: &BTreeMap<usize, Vec<CoveredBundle>>,
    ) -> Block {
        let mut after = l.clone();
        after.set_height(height);
        after.set_timestamp_ms(height);
        after.apply_transactions_with_covered(&txs, &key.address(), covered, &StubExecutor).unwrap();
        after.sweep_expired_excesses(height, &key.address());
        after.record_anchor(height);
        let header = BlockHeader {
            height,
            view: height,
            parent: Hash::ZERO,
            proposer: key.public_key().clone(),
            timestamp_ms: height,
            tx_root: Block::tx_root(&txs),
            state_root: after.state_root(),
            justify: QuorumCertificate::genesis(Hash::ZERO),
        };
        Block::sign(header, txs, key)
    }

    /// The fee split at bundle inclusion (spec §5.2): the proposer keeps exactly the floor, the
    /// excess is bucketed against the bundle's hash with its coverable-until height — and an
    /// ungated chain keeps the full fee to the proposer, byte-for-byte.
    #[test]
    fn the_proposer_keeps_the_floor_and_the_excess_is_bucketed() {
        let mut l = gated(256);
        let p = proposer(&l);
        let fee = gas::BUNDLE_BASE + 60;
        let tx = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee, 0), Action::None);
        l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        assert_eq!(l.validators()[&p].rewards, gas::BUNDLE_BASE, "the proposer keeps the floor");
        assert_eq!(l.supply().fees_paid, gas::BUNDLE_BASE, "only the floor has left the pool so far");
        assert_eq!(
            l.unsealed_fees().get(&tx.hash()),
            Some(&(60, p, 1 + 256)),
            "the excess is bucketed with the coverable-until height"
        );
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());

        // Ungated: the split is off, exactly today's accounting.
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut u = Ledger::new(7, HC, register, &StubExecutor);
        u.set_faucet(true);
        u.set_confidential(true);
        u.set_height(1);
        let tx = Transaction::shielded(7, bundle(&u, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee, 0), Action::None);
        u.apply_tx(&tx, &p, &StubExecutor).unwrap();
        assert_eq!(u.validators()[&p].rewards, fee);
        assert_eq!(u.supply().fees_paid, fee);
        assert!(u.unsealed_fees().is_empty(), "no bucket exists without the section");
    }

    /// The covered exit (spec §5.2/§5.4): the aggregate's one deposit note pays subsidy(n) plus
    /// the covered bundles' excesses to the entry's payout address; the bucket empties of them;
    /// the counters move exactly the subsidy's worth.
    #[test]
    fn a_covering_aggregate_pays_subsidy_plus_the_covered_excesses() {
        let mut l = gated(256);
        let (kp, _) = keys();
        register(&mut l, &kp, 10);
        l.record_anchor(1);
        let p = proposer(&l);
        let fee = gas::BUNDLE_BASE + 60;
        let covered_tx = Transaction::shielded(7, bundle(&l, [[21; 8], [22; 8]], [[23; 8], [24; 8]], fee, 0), Action::None);
        l.apply_tx(&covered_tx, &p, &StubExecutor).unwrap();
        let before = l.supply();

        let tx = aggregate_tx(&kp, 0, 1, vec![covered_tx.hash()], b"ok".to_vec());
        let covered = covered_records(&[1]);
        let v = l.validate_aggregate(&tx, &covered, &StubExecutor).unwrap();
        let subsidy = gas::subsidy(0, &cfg_with_window(256));
        let want_cm = StubExecutor.note_commitment(&payout_addr().pk, &[0; 8], subsidy + 60, 0, 1, &[9; 8]);
        assert_eq!(v.payout_cm, want_cm, "the T4 derivation, now with the real amount (spec §5.4)");
        l.apply_aggregate(&tx, &covered, &StubExecutor).unwrap();
        assert!(l.has_commitment(&want_cm), "the payout note is in the tree");
        assert!(!l.unsealed_fees().contains_key(&covered_tx.hash()), "the covered excess left the bucket");
        assert_eq!(l.supply().subsidised, subsidy);
        assert_eq!(l.supply().sealed_blocks, 1);
        assert_eq!(l.supply().fees_paid, before.fees_paid, "the payout is not a fee movement");
        assert_eq!(l.supply().withdraw_deposited, before.withdraw_deposited, "nor a withdraw's");
        assert_eq!(l.aggregators()[&kp.public_key().address()].nonce, 1);
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
    }

    /// The expiry exit: a bundle whose window passes uncovered has its excess credited to the
    /// recorded proposer at block commit — the moment it actually leaves the pool's accounting.
    #[test]
    fn an_expired_excess_is_swept_to_the_recorded_proposer_at_commit() {
        let mut l = gated(2);
        let (a, _) = keys();
        let p = proposer(&l);
        let fee = gas::BUNDLE_BASE + 60;
        let tx = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee, 0), Action::None);
        l.apply_block(&signed_block(&l, vec![tx.clone()], &a, 1), &StubExecutor).unwrap();
        assert_eq!(l.unsealed_fees().get(&tx.hash()), Some(&(60, p, 3)), "bucketed, coverable until 1 + 2");
        assert!(l.audit().invariant_holds());

        // Block 2 commits with the bundle still coverable: the bucket holds, nothing moves.
        l.apply_block(&signed_block(&l, vec![], &a, 2), &StubExecutor).unwrap();
        assert_eq!(l.unsealed_fees().len(), 1, "still bucketed inside the window");
        assert_eq!(l.validators()[&p].rewards, gas::BUNDLE_BASE);

        // Block 3 is the first head at which the bundle is uncoverable: the sweep lands.
        l.apply_block(&signed_block(&l, vec![], &a, 3), &StubExecutor).unwrap();
        assert!(l.unsealed_fees().is_empty(), "the window passed: the entry resolved");
        assert_eq!(l.validators()[&p].rewards, gas::BUNDLE_BASE + 60, "the recorded proposer takes the excess");
        assert_eq!(l.supply().fees_paid, fee, "and only now has the whole fee left the pool");
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
    }

    /// `sealed_blocks` is the subsidy schedule's index: it counts included aggregates, never
    /// blocks — an idle chain consumes nothing of the schedule (spec §5.1).
    #[test]
    fn sealed_blocks_counts_aggregates_not_blocks() {
        let mut l = gated(256);
        let (a, _) = keys();
        let (kp, _) = keys();
        register(&mut l, &kp, 10);
        l.apply_block(&signed_block(&l, vec![], &a, 1), &StubExecutor).unwrap();
        l.apply_block(&signed_block(&l, vec![], &a, 2), &StubExecutor).unwrap();
        assert_eq!(l.supply().sealed_blocks, 0, "empty blocks do not consume the schedule");
        for (i, tag) in [30u8, 40].iter().enumerate() {
            let p = proposer(&l);
            l.bucket_excess(Hash::digest(&[*tag]), 0, p, u64::MAX);
            let tx = aggregate_tx(&kp, i as u64, (i + 1) as u32, vec![Hash::digest(&[*tag])], b"ok".to_vec());
            l.apply_aggregate(&tx, &covered_records(&[1]), &StubExecutor).unwrap();
        }
        assert_eq!(l.supply().sealed_blocks, 2);
        assert_eq!(l.supply().subsidised, 2 * gas::subsidy(0, &cfg_with_window(256)));
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
    }

    /// The audit across the whole lifecycle (spec §5.3): a register, a fee-paying bundle, an
    /// aggregate covering it, an aggregator withdraw, and a slash — after each, the pool plus
    /// the register adds up to exactly what the chain issued less what was slashed.
    #[test]
    fn the_supply_invariant_holds_across_register_aggregate_withdraw_and_slash() {
        let (a, b) = keys();
        let validators: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, validators, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l.set_aggregation(Some(cfg_with_window(2)));
        let issued = 300 * crate::types::UNITS_PER_RAND;
        l.set_genesis_supply(issued - 20, 20);
        let check = |l: &Ledger, what: &str| {
            let audit = l.audit();
            assert!(audit.invariant_holds(), "{what}: {audit:?}");
        };
        check(&l, "genesis");

        // Register two aggregators: bonds leave the pool for the register, counted both sides.
        register(&mut l, &a, 10);
        register(&mut l, &b, 20);
        l.record_anchor(1);
        check(&l, "two registers");
        assert_eq!(l.supply().aggregator_bonds, 2 * cfg_with_window(2).bond);

        // A fee-paying bundle, then the aggregate covering it: subsidy minted, excess paid.
        let p = proposer(&l);
        let covered_tx = Transaction::shielded(
            7,
            bundle(&l, [[31; 8], [32; 8]], [[33; 8], [34; 8]], gas::BUNDLE_BASE + 60, 0),
            Action::None,
        );
        l.apply_tx(&covered_tx, &p, &StubExecutor).unwrap();
        check(&l, "a fee-paying bundle");
        let agg_tx = aggregate_tx(&a, 0, 1, vec![covered_tx.hash()], b"ok".to_vec());
        l.apply_aggregate(&agg_tx, &covered_records(&[1]), &StubExecutor).unwrap();
        check(&l, "the covering aggregate");

        // Unbond then withdraw `a`'s bond once the (window-2) release passes: the bond comes
        // back into the pool as a note, less the base the proposer takes.
        let unbond = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::UnbondAggregator {
                aggregator: a.public_key().address(),
                nonce: 1,
                signature: a.sign(
                    crate::types::actions::aggregator_unbond_message(7, &a.public_key().address(), 1).as_bytes()
                ),
            },
        };
        l.apply_tx(&unbond, &p, &StubExecutor).unwrap();
        check(&l, "unbond");
        l.set_height(1 + 2);
        let withdraw = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::WithdrawAggregator {
                aggregator: a.public_key().address(),
                nonce: 2,
                time: 3,
                r: [5; 8],
                envelope: env(),
                signature: a.sign(
                    crate::types::actions::aggregator_withdraw_message(
                        7,
                        &a.public_key().address(),
                        2,
                        3,
                        &[5; 8],
                        &env(),
                    )
                    .as_bytes(),
                ),
            },
        };
        l.apply_tx(&withdraw, &p, &StubExecutor).unwrap();
        check(&l, "withdraw");

        // Slash `b` for equivocation: the bond is destroyed, and `issued − slashed` tracks it.
        let slash = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::SlashAggregator {
                a: Box::new(signed_header(&b, 0, vec![Hash::digest(b"x")])),
                b: Box::new(signed_header(&b, 0, vec![Hash::digest(b"y")])),
            },
        };
        l.apply_tx(&slash, &p, &StubExecutor).unwrap();
        check(&l, "slash");
        assert_eq!(l.supply().slashed, cfg_with_window(2).bond);
        assert_eq!(l.supply().aggregator_bonds, 0, "both bonds resolved");
    }

    /// The T4 interim closes (spec §4's admission, run at apply): a block carrying an
    /// `Aggregate` applies through the covered-carrying path — the payment lands, the counters
    /// move — and the same block without the records is refused at the aggregate's index with
    /// the signpost error.
    #[test]
    fn a_block_carrying_an_aggregate_applies_through_the_covered_carrying_path() {
        let (a, _) = keys();
        let mut l = gated(256);
        let (kp, _) = keys();
        register(&mut l, &kp, 10);
        let fee = gas::BUNDLE_BASE + 60;
        let covered_tx = Transaction::shielded(7, bundle(&l, [[21; 8], [22; 8]], [[23; 8], [24; 8]], fee, 0), Action::None);
        l.apply_block(&signed_block(&l, vec![covered_tx.clone()], &a, 1), &StubExecutor).unwrap();

        let tx = aggregate_tx(&kp, 0, 1, vec![covered_tx.hash()], b"ok".to_vec());
        let mut sidecar: BTreeMap<usize, Vec<CoveredBundle>> = BTreeMap::new();
        sidecar.insert(0, covered_records(&[1]));
        let block = signed_block_with_covered(&l, vec![tx.clone()], &a, 2, &sidecar);
        // Without the records: the signpost, at the aggregate's index.
        match l.apply_block(&block, &StubExecutor) {
            Err(crate::ledger::BlockError::InvalidTx { index: 0, error: TxError::AggregateNeedsCovered }) => {}
            other => panic!("expected the signpost at index 0, got {other:?}"),
        }
        l.apply_block_with_covered(&block, &sidecar, &StubExecutor).unwrap();
        assert_eq!(l.supply().sealed_blocks, 1);
        assert!(!l.unsealed_fees().contains_key(&covered_tx.hash()), "the covered excess was paid out");
        let subsidy = gas::subsidy(0, &cfg_with_window(256));
        let want_cm = StubExecutor.note_commitment(&payout_addr().pk, &[0; 8], subsidy + 60, 0, 1, &[9; 8]);
        assert!(l.has_commitment(&want_cm), "the payout note is in the tree");
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
    }

    /// A block whose validity is decided before its root is compared: the header carries the
    /// pre-apply root, so a refusal must come from the transactions, never from the root check.
    fn unchecked_block(l: &Ledger, txs: Vec<Transaction>, key: &Keypair, height: u64) -> Block {
        let header = BlockHeader {
            height,
            view: height,
            parent: Hash::ZERO,
            proposer: key.public_key().clone(),
            timestamp_ms: height,
            tx_root: Block::tx_root(&txs),
            state_root: l.state_root(),
            justify: QuorumCertificate::genesis(Hash::ZERO),
        };
        Block::sign(header, txs, key)
    }

    /// Two covered bundles in block 1, on a chain of `window`; the aggregator registered.
    fn two_covered(window: u64) -> (Ledger, Keypair, Keypair, Transaction, Transaction) {
        let (a, _) = keys();
        let mut l = gated(window);
        let (kp, _) = keys();
        register(&mut l, &kp, 10);
        let fee = gas::BUNDLE_BASE + 60;
        let c1 = Transaction::shielded(7, bundle(&l, [[21; 8], [22; 8]], [[23; 8], [24; 8]], fee, 0), Action::None);
        let c2 = Transaction::shielded(7, bundle(&l, [[31; 8], [32; 8]], [[33; 8], [34; 8]], fee, 0), Action::None);
        l.apply_block(&signed_block(&l, vec![c1.clone(), c2.clone()], &a, 1), &StubExecutor).unwrap();
        (l, a, kp, c1, c2)
    }

    /// "At most one `Aggregate` per block" is a block-validity rule, not proposer selection
    /// (the pre-v0.1 review's H1): a replica refuses the second, by index, before any root work.
    #[test]
    fn a_block_carrying_two_aggregates_is_refused_at_the_second() {
        let (mut l, a, kp, c1, c2) = two_covered(256);
        let t1 = aggregate_tx(&kp, 0, 1, vec![c1.hash()], b"ok".to_vec());
        let t2 = aggregate_tx(&kp, 1, 2, vec![c2.hash()], b"ok2".to_vec());
        let mut sidecar: BTreeMap<usize, Vec<CoveredBundle>> = BTreeMap::new();
        sidecar.insert(0, covered_records(&[1]));
        sidecar.insert(1, covered_records(&[2]));
        let block = unchecked_block(&l, vec![t1, t2], &a, 2);
        match l.apply_block_with_covered(&block, &sidecar, &StubExecutor) {
            Err(crate::ledger::BlockError::SecondAggregate { index: 1 }) => {}
            other => panic!("expected the second aggregate refused at index 1, got {other:?}"),
        }
        assert_eq!(l.supply().sealed_blocks, 0, "nothing applied");
    }

    /// A covered bundle is never coverable again, at apply (H1): the same proof bytes re-signed
    /// under the register's next nonce name a cover the ledger no longer holds, and the block
    /// is refused — no second subsidy, no second `sealed_blocks`.
    #[test]
    fn an_aggregate_over_an_already_covered_bundle_is_refused_under_a_fresh_nonce() {
        let (mut l, a, kp, c1, _) = two_covered(256);
        let mut sidecar: BTreeMap<usize, Vec<CoveredBundle>> = BTreeMap::new();
        sidecar.insert(0, covered_records(&[1]));
        let first = aggregate_tx(&kp, 0, 1, vec![c1.hash()], b"ok".to_vec());
        l.apply_block_with_covered(&signed_block_with_covered(&l, vec![first], &a, 2, &sidecar), &sidecar, &StubExecutor)
            .unwrap();
        assert_eq!(l.supply().sealed_blocks, 1);
        let subsidised = l.supply().subsidised;
        let replay = aggregate_tx(&kp, 1, 1, vec![c1.hash()], b"ok".to_vec());
        let block = unchecked_block(&l, vec![replay], &a, 3);
        match l.apply_block_with_covered(&block, &sidecar, &StubExecutor) {
            Err(crate::ledger::BlockError::InvalidTx {
                index: 0,
                error: TxError::Aggregation(AggregationError::CoverNotCoverable(h)),
            }) if h == c1.hash() => {}
            other => panic!("expected the sealed cover refused by name, got {other:?}"),
        }
        assert_eq!(l.supply().sealed_blocks, 1, "no second seal");
        assert_eq!(l.supply().subsidised, subsidised, "no second subsidy");
    }

    /// The window is a block-validity rule too (H1): once the bundle's window passed and the
    /// sweep resolved it, an aggregate naming it is refused at apply.
    #[test]
    fn an_aggregate_over_an_expired_cover_is_refused_at_apply() {
        let (mut l, a, kp, c1, _) = two_covered(2);
        // Block 1 carried the bundles, coverable until 3: the empty blocks 2 and 3 pass the window.
        l.apply_block(&signed_block(&l, vec![], &a, 2), &StubExecutor).unwrap();
        l.apply_block(&signed_block(&l, vec![], &a, 3), &StubExecutor).unwrap();
        assert!(l.unsealed_fees().is_empty(), "the window passed: both entries resolved");
        let mut sidecar: BTreeMap<usize, Vec<CoveredBundle>> = BTreeMap::new();
        sidecar.insert(0, covered_records(&[1]));
        let late = aggregate_tx(&kp, 0, 4, vec![c1.hash()], b"ok".to_vec());
        let block = unchecked_block(&l, vec![late], &a, 4);
        match l.apply_block_with_covered(&block, &sidecar, &StubExecutor) {
            Err(crate::ledger::BlockError::InvalidTx {
                index: 0,
                error: TxError::Aggregation(AggregationError::CoverNotCoverable(h)),
            }) if h == c1.hash() => {}
            other => panic!("expected the expired cover refused by name, got {other:?}"),
        }
    }

    /// A bundle at exactly the floor has no excess but is a bundle all the same: it is recorded
    /// as coverable (excess 0) so an aggregate over it applies and pays the subsidy alone.
    #[test]
    fn a_bundle_at_the_base_fee_is_coverable_and_pays_the_subsidy_alone() {
        let (a, _) = keys();
        let mut l = gated(256);
        let (kp, _) = keys();
        register(&mut l, &kp, 10);
        let floor = Transaction::shielded(7, bundle(&l, [[21; 8], [22; 8]], [[23; 8], [24; 8]], gas::BUNDLE_BASE, 0), Action::None);
        l.apply_block(&signed_block(&l, vec![floor.clone()], &a, 1), &StubExecutor).unwrap();
        assert_eq!(l.unsealed_fees().get(&floor.hash()).map(|e| e.0), Some(0), "coverable, with no excess");
        let tx = aggregate_tx(&kp, 0, 1, vec![floor.hash()], b"ok".to_vec());
        let mut sidecar: BTreeMap<usize, Vec<CoveredBundle>> = BTreeMap::new();
        sidecar.insert(0, covered_records(&[1]));
        l.apply_block_with_covered(&signed_block_with_covered(&l, vec![tx], &a, 2, &sidecar), &sidecar, &StubExecutor)
            .unwrap();
        let subsidy = gas::subsidy(0, &cfg_with_window(256));
        let want_cm = StubExecutor.note_commitment(&payout_addr().pk, &[0; 8], subsidy, 0, 1, &[9; 8]);
        assert!(l.has_commitment(&want_cm), "the payout note is the subsidy alone");
        assert!(!l.unsealed_fees().contains_key(&floor.hash()), "covered: never coverable again");
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
    }

    /// The sealed form binds the whole pruned transaction, not only its digest fields (the
    /// pre-v0.1 review's M1): a transaction hashes its bundle proof by digest, so the marker
    /// form hashes to the raw hash the certified tx root commits to, and a sync peer that
    /// substitutes an envelope (or anything else outside the proof) fails that root.
    #[test]
    fn a_sealed_block_binds_its_pruned_transactions_beyond_the_digest_fields() {
        use crate::consensus::PrunedBundle;
        let (a, _) = keys();
        let l = gated(256);
        let tx = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE, 0), Action::None);
        let digest = StubExecutor.bundle_digest(&tx.bundle.as_ref().unwrap().digest_input());
        let mut pv = [0u64; 34];
        for k in 0..8 {
            pv[pv::OUT0 + k] = digest[k] as u64;
        }
        let proof_hash = Hash::digest(&tx.bundle.as_ref().unwrap().proof);
        let mut marker = crate::notes::PRUNED_PROOF_MARKER.to_vec();
        marker.extend_from_slice(proof_hash.as_bytes());
        let mut pruned_tx = tx.clone();
        pruned_tx.bundle.as_mut().unwrap().proof = marker;
        let side = PrunedBundle { tx_hash: tx.hash(), proof_hash, public_values: pv.to_vec(), shape: shape() };
        assert_eq!(pruned_tx.hash(), tx.hash(), "the marker form hashes to the raw hash");
        let mut forged = pruned_tx.clone();
        forged.bundle.as_mut().unwrap().envelopes[0].body = vec![0xEE; 16];
        assert_ne!(forged.hash(), tx.hash(), "a substituted envelope changes the hash");
        let block = Block::sign(
            BlockHeader {
                height: 1,
                view: 1,
                parent: Hash::ZERO,
                proposer: a.public_key().clone(),
                timestamp_ms: 1,
                tx_root: crate::crypto::merkle_root(&[tx.hash()]),
                state_root: Hash::ZERO,
                justify: QuorumCertificate::genesis(Hash::ZERO),
            },
            vec![forged],
            &a,
        );
        let mut after = l.clone();
        match after.apply_block_for_sync(&block, &BTreeMap::new(), std::slice::from_ref(&side), &StubExecutor) {
            Err(crate::ledger::BlockError::TxRootMismatch) => {}
            other => panic!("expected the substituted envelope refused by the tx root, got {other:?}"),
        }
    }

    /// The sealed form's ledger half (spec §7): a pruned bundle applies on the marker's
    /// membership and the digest binding — the public fields hash to the digest the covering
    /// aggregate's verified pv commits to — and every malformed variation is refused by name.
    #[test]
    fn a_pruned_bundle_applies_on_membership_and_the_digest_binding() {
        use crate::consensus::PrunedBundle;
        let (a, _) = keys();
        let l = gated(256);
        let p = proposer(&l);
        // A bundle whose "proof" is the marker form: the side table's pv carries the digest
        // its own public fields hash to.
        let tx = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE, 0), Action::None);
        let digest = StubExecutor.bundle_digest(&tx.bundle.as_ref().unwrap().digest_input());
        let mut pv = [0u64; 34];
        for k in 0..8 {
            pv[pv::OUT0 + k] = digest[k] as u64;
        }
        // The marker carries the raw proof's digest — what the raw hash commits the proof by.
        let proof_hash = Hash::digest(&tx.bundle.as_ref().unwrap().proof);
        let mut marker = crate::notes::PRUNED_PROOF_MARKER.to_vec();
        marker.extend_from_slice(proof_hash.as_bytes());
        let mut pruned_tx = tx.clone();
        pruned_tx.bundle.as_mut().unwrap().proof = marker;
        let side = PrunedBundle {
            tx_hash: tx.hash(),
            proof_hash,
            public_values: pv.to_vec(),
            shape: shape(),
        };
        // The block carries the marker form; its root is over the *raw* hashes, as the table
        // attests.
        let root = crate::crypto::merkle_root(&[tx.hash()]);
        let block = Block::sign(
            BlockHeader {
                height: 1,
                view: 1,
                parent: Hash::ZERO,
                proposer: a.public_key().clone(),
                timestamp_ms: 1,
                tx_root: root,
                state_root: Hash::ZERO,
                justify: QuorumCertificate::genesis(Hash::ZERO),
            },
            vec![pruned_tx.clone()],
            &a,
        );
        // The ledger root must be computed by the same path: apply the pruned tx with the side
        // table, over a fresh clone.
        let root_after = {
            let mut after = l.clone();
            after.set_height(1);
            after.set_timestamp_ms(1);
            after.apply_transactions_for_sync(&[pruned_tx.clone()], &p, &BTreeMap::new(), std::slice::from_ref(&side), &StubExecutor).unwrap();
            after.sweep_expired_excesses(1, &p);
            after.record_anchor(1);
            after.state_root()
        };
        let mut header = block.header.clone();
        header.state_root = root_after;
        let block = Block::sign(header, vec![pruned_tx.clone()], &a);

        let mut m = l.clone();
        m.apply_block_for_sync(&block, &BTreeMap::new(), std::slice::from_ref(&side), &StubExecutor)
            .expect("the pruned bundle applies on the table's attestation");
        assert!(m.is_spent(&[1; 8]) && m.has_commitment(&[3; 8]), "the public-field effects land");
        // And the fee split treats it like any bundle.
        assert_eq!(m.validators()[&p].rewards, gas::BUNDLE_BASE);
        // The pruned bundle's excess is bucketed under the *raw* hash — the hash an aggregate's
        // covers name — not the marker form's (spec §6.2's byte-identical replay).
        let mut rich_tx = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], gas::BUNDLE_BASE + 60, 0), Action::None);
        let rich_digest = StubExecutor.bundle_digest(&rich_tx.bundle.as_ref().unwrap().digest_input());
        let mut rich_pv = [0u64; 34];
        for k in 0..8 {
            rich_pv[pv::OUT0 + k] = rich_digest[k] as u64;
        }
        let rich_marker = {
            let mut m2 = crate::notes::PRUNED_PROOF_MARKER.to_vec();
            m2.extend_from_slice(Hash::digest(b"the rich raw proof").as_bytes());
            m2
        };
        rich_tx.bundle.as_mut().unwrap().proof = rich_marker;
        let rich_side = PrunedBundle {
            tx_hash: {
                // The raw hash: recompute the tx with a placeholder raw proof (any bytes —
                // the hash covers them, which is the point of the side table attesting it).
                let mut raw = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], gas::BUNDLE_BASE + 60, 0), Action::None);
                raw.bundle.as_mut().unwrap().proof = b"the rich raw proof".to_vec();
                raw.hash()
            },
            proof_hash: Hash::digest(b"the rich raw proof"),
            public_values: rich_pv.to_vec(),
            shape: shape(),
        };
        let mut m2 = l.clone();
        m2.set_height(1);
        m2.set_timestamp_ms(1);
        m2.apply_transactions_for_sync(&[rich_tx], &p, &BTreeMap::new(), std::slice::from_ref(&rich_side), &StubExecutor)
            .unwrap();
        assert!(
            m2.unsealed_fees().contains_key(&rich_side.tx_hash),
            "the excess is bucketed under the raw hash"
        );
        assert_eq!(m2.unsealed_fees().len(), 1, "and under no second key");

        // Without any side table the root still holds (the marker form hashes to the raw
        // hash), but the marker has no entry: the malformed-marker refusal, at its index.
        match l.clone().apply_block_for_sync(&block, &BTreeMap::new(), &[], &StubExecutor) {
            Err(crate::ledger::BlockError::InvalidTx { index: 0, error: TxError::InvalidBundleProof(_) }) => {}
            other => panic!("expected the unattested-marker refusal, got {other:?}"),
        }
        // And a table that simply does not attest this proof: the malformed-marker refusal,
        // at its index.
        let other_side = PrunedBundle {
            tx_hash: Hash::digest(b"some other tx"),
            proof_hash: Hash::digest(b"some other proof"),
            public_values: pv.to_vec(),
            shape: shape(),
        };
        match l.clone().apply_block_for_sync(&block, &BTreeMap::new(), std::slice::from_ref(&other_side), &StubExecutor) {
            Err(crate::ledger::BlockError::InvalidTx { index: 0, error: TxError::InvalidBundleProof(_) }) => {}
            other => panic!("expected the unattested-marker refusal, got {other:?}"),
        }
        // A table whose pv does not match the bundle's own fields: the binding refuses it.
        let mut forged = side.clone();
        forged.public_values[pv::OUT0] += 1;
        match l.clone().apply_block_for_sync(&block, &BTreeMap::new(), std::slice::from_ref(&forged), &StubExecutor) {
            Err(crate::ledger::BlockError::InvalidTx { index: 0, error: TxError::BadDigest }) => {}
            other => panic!("expected the binding's BadDigest, got {other:?}"),
        }
        // (A side-table raw hash that lies is not the ledger's check: the *coverage* rule is
        // the caller's, and the digest binding above is what anchors the content.)
    }

    /// The proposer–validator invariant for an aggregate-carrying block: the root a proposer
    /// computes by trial-applying the aggregate onto the parent's ledger is the root every
    /// validator recomputes through `apply_block_with_covered` — the same txs, the same order,
    /// the same covered records.
    #[test]
    fn the_proposers_trial_apply_and_the_validators_block_apply_compute_one_root() {
        let (a, _) = keys();
        let mut l = gated(256);
        let (kp, _) = keys();
        register(&mut l, &kp, 10);
        let covered_tx = Transaction::shielded(7, bundle(&l, [[21; 8], [22; 8]], [[23; 8], [24; 8]], gas::BUNDLE_BASE + 60, 0), Action::None);
        l.apply_block(&signed_block(&l, vec![covered_tx.clone()], &a, 1), &StubExecutor).unwrap();

        let tx = aggregate_tx(&kp, 0, 2, vec![covered_tx.hash()], b"ok".to_vec());
        let covered = covered_records(&[1]);
        let mut sidecar: BTreeMap<usize, Vec<CoveredBundle>> = BTreeMap::new();
        sidecar.insert(0, covered.clone());

        // The proposer's computation (HotStuff::propose's shape): clone the parent ledger, set
        // height and timestamp, trial-apply the aggregate onto it, read the root.
        let parent = l.clone();
        let mut trial = parent.clone();
        trial.set_height(2);
        trial.set_timestamp_ms(2);
        trial.apply_aggregate(&tx, &covered, &StubExecutor).unwrap();
        let header_root = trial.state_root();

        // The validators' computation: apply_block_with_covered of a block built over that root.
        let block = signed_block_with_covered(&parent, vec![tx.clone()], &a, 2, &sidecar);
        let mut v = parent.clone();
        v.apply_block_with_covered(&block, &sidecar, &StubExecutor).unwrap();
        assert_eq!(v.state_root(), header_root, "the proposer's root is the validators' root");
        assert_eq!(block.header.state_root, header_root, "and the block carries it");
    }

    fn signed_header(kp: &Keypair, nonce: u64, covers: Vec<Hash>) -> crate::types::SignedAggregateHeader {
        let aggregator = kp.public_key().address();
        let proof_hash = Hash::digest(b"p");
        let signature = kp.sign(aggregate_signing_hash(7, nonce, 9, &[1; 8], &covers, &proof_hash).as_bytes());
        crate::types::SignedAggregateHeader { aggregator, nonce, time: 9, r: [1; 8], covers, proof_hash, signature }
    }
}
