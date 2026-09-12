//! The shielded notes ledger and block application rules (design spec §7, §9).
//!
//! Everything common to every transaction — the size caps, the chain id, the fee floor, the
//! anchor and time windows, the bundle's nullifier/commitment uniqueness, the bundle proof —
//! lives here. The rules that belong to one feature live in a module beside this one and are
//! reached from the action step (spec §7 step 7): [`staking`] for `Bond`/`Unbond`/`Withdraw`
//! (phase S2), [`call_envelope`] and [`bridge_notes`] for `Call`'s input transcript and
//! `BridgeAttest`/`BridgeBurn` (phase S3). That split is what lets S2 and S3 be implemented in
//! parallel: each phase owns its own file.

pub mod bridge_notes;
pub mod call_envelope;
pub mod staking;
pub mod supply;

use crate::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
use crate::crypto::{merkle_root, Address, Hash};
use crate::gas;
use crate::notes::{word8_to_bytes, Bundle, CommitmentTree, Envelope, Word8, MAX_ENVELOPE_BYTES};
use crate::program::{program_id, CallOutcome, CallReceipt, ProgramId, ProgramRecord};
use crate::types::{Action, Block, Transaction, ValidatorSet, FAUCET_MAX_UNITS};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// How many block-end roots a bundle may anchor to (spec §7 item 4).
///
/// The spec proposed 64, sized for "about a minute at 1 s blocks". A tier-14 bundle proof measures
/// ~100 s on a laptop and the fleet makes a block every ~2 s, so 64 blocks expired an anchor
/// roughly halfway through proving one honest transfer. 256 blocks is ~8.5 minutes at the fleet's
/// pace and ~2 minutes even at 500 ms blocks — comfortably longer than the proof it has to outlive.
pub const ANCHOR_WINDOW: usize = 256;
/// How far behind the current height a bundle's `time` may be (spec §7 item 5). Kept equal to
/// [`ANCHOR_WINDOW`]: the two windows exist for the same reason (a prover needs the chain to still
/// accept what it started proving), and a shorter `time` window would reject bundles whose anchor
/// is still live.
pub const TIME_WINDOW: u64 = 256;

pub use staking::{StakingError, ValidatorEntry};
pub use supply::{register_total, Audit, Supply};

/// A deposit note the ledger created itself while applying a transaction, rather than accepting
/// on the wire: S2's `Withdraw` (and S3's `BridgeAttest`) publish only a blinding and a public
/// amount, so the commitment is computed here and is not in [`Transaction::commitments`].
///
/// This is transient output, like a call receipt — not consensus state, not in the state root,
/// not compared by [`Ledger`]'s equality. `apply_transactions` clears the list when a block
/// starts, so after `apply_block` the ledger's [`Ledger::deposits`] are exactly that block's,
/// in the order they were appended to the tree. Storage (S2 Task 3) writes one `NoteRow` per
/// entry at `index`, beside the notes `created_notes(tx)` already yields for the bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    /// Leaf index the note was appended at.
    pub index: u64,
    pub cm: Word8,
    /// The envelope the action carried, stored with the note so its owner can open it.
    pub envelope: Envelope,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum TxError {
    #[error("wrong chain id: expected {expected}, got {actual}")]
    WrongChain { expected: u64, actual: u64 },
    #[error("transaction carries no bundle")]
    MissingBundle,
    #[error("a mint must not carry a bundle")]
    MintCarriesBundle,
    #[error("envelope exceeds {MAX_ENVELOPE_BYTES} bytes")]
    EnvelopeTooLarge,
    #[error("proof too large")]
    ProofTooLarge,
    #[error("attestation exceeds {} bytes", gas::MAX_ATTESTATION_BYTES)]
    AttestationTooLarge,
    #[error("program too large")]
    ProgramTooLarge,
    #[error("asset {0} is not supported in this release")]
    UnsupportedAsset(u32),
    #[error("burn of {0} is not supported in this release")]
    UnsupportedBurn(u64),
    #[error("fee {fee} below minimum {min}")]
    FeeTooLow { min: u64, fee: u64 },
    #[error("anchor is not one of the last {ANCHOR_WINDOW} roots")]
    UnknownAnchor,
    #[error("bundle time {time} is outside [{}, {height}]", height.saturating_sub(TIME_WINDOW))]
    TimeOutOfWindow { time: u32, height: u64 },
    #[error("the bundle spends the same nullifier twice")]
    DuplicateNullifierInBundle,
    #[error("nullifier already spent")]
    Spent(Word8),
    #[error("the bundle creates the same commitment twice")]
    DuplicateCommitmentInBundle,
    #[error("commitment already in the tree")]
    CommitmentExists(Word8),
    #[error("faucet is disabled on this chain")]
    FaucetDisabled,
    #[error("mint of {amount} exceeds faucet cap {cap}")]
    MintTooLarge { amount: u64, cap: u64 },
    #[error("minter {0} is not a validator")]
    MinterNotValidator(Address),
    #[error("bad mint signature")]
    BadMintSignature,
    #[error("confidential computation is disabled on this chain")]
    ConfidentialDisabled,
    #[error("bad program: {0}")]
    BadProgram(ConfidentialError),
    #[error("unknown program {0}")]
    UnknownProgram(ProgramId),
    /// An action whose variant exists on the wire but whose rules have not shipped yet. The
    /// message names the phase that turns it on, so a wallet built against a newer node tells
    /// its user which upgrade it is waiting for rather than "invalid transaction".
    #[error("{0}")]
    UnsupportedAction(&'static str),
    #[error("invalid proof: {0}")]
    InvalidProof(ConfidentialError),
    #[error("the bundle's digest is not what its proof published")]
    BadDigest,
    #[error("invalid bundle proof: {0}")]
    InvalidBundleProof(ConfidentialError),
    #[error("proposer {0} is not in the validator register")]
    UnknownProposer(Address),
    /// Phase S2: a `Bond`, `Unbond` or `Withdraw` the register refused (see [`StakingError`]).
    #[error("staking: {0}")]
    Staking(#[from] StakingError),
    #[error("arithmetic overflow")]
    Overflow,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum BlockError {
    #[error("tx {index} invalid: {error}")]
    InvalidTx { index: usize, error: TxError },
    #[error("tx root mismatch")]
    TxRootMismatch,
    #[error("state root mismatch: computed {computed}, header {header}")]
    StateRootMismatch { computed: Hash, header: Hash },
    #[error("bad proposer signature")]
    BadProposerSignature,
    #[error("proposer {0} is not a validator")]
    UnknownProposer(Address),
    #[error("too many transactions in block")]
    TooManyTransactions,
    #[error("block transaction bytes exceed the per-block limit")]
    TooLarge,
}

/// Receipt data for a call, before it is placed in a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallReceiptData {
    pub program: ProgramId,
    pub tier: u8,
    pub outputs: [u32; 8],
}

/// In-memory chain state: the note commitment tree, the nullifier set, the validator register
/// and the deployed programs. Cheap to clone (used for speculative execution).
#[derive(Clone, Debug)]
pub struct Ledger {
    chain_id: u64,
    /// The pinned commitment of the `bundle` guest every bundle proof must be for.
    hc_bundle: Word8,
    faucet: bool,
    confidential: bool,
    tree: CommitmentTree,
    /// Every leaf ever appended — spec §7 item 6 needs membership the frontier cannot answer.
    commitments: BTreeSet<Word8>,
    nullifiers: BTreeSet<Word8>,
    /// Block-end roots, oldest first, at most ANCHOR_WINDOW.
    anchors: VecDeque<(u64, Word8)>,
    validators: BTreeMap<Address, ValidatorEntry>,
    programs: BTreeMap<ProgramId, ProgramRecord>,
    /// Blocks per epoch (spec §8), from genesis. Not state: like `faucet` and `confidential`,
    /// a reloading node sets it from its genesis file.
    epoch_blocks: u64,
    /// Height of the block being applied (the `time` window and `ProgramRecord::deployed_at`).
    height: u64,
    /// Timestamp of the block being applied, in unix milliseconds.
    timestamp_ms: u64,
    /// Deposit notes this block's transactions made the ledger create (see [`Deposit`]).
    deposits: Vec<Deposit>,
    /// The public supply counters (see [`supply`]). Derived from the chain, not hashed into
    /// the state root.
    supply: Supply,
}

/// Equality is over consensus state only. `height` and `timestamp_ms` are the position of the
/// block being applied, and `faucet`/`confidential` are genesis switches a reloading node sets
/// from its genesis file rather than from storage, so two ledgers holding the same notes,
/// nullifiers, anchors, validators and programs are the same ledger.
///
/// The [`supply`] counters are deliberately **out**: nothing in the state root covers them, and
/// `Ledger::from_parts` cannot know them, so a rebuilt ledger would never compare equal to the
/// one it was rebuilt from. A node audits its stored copy of them separately, by replay
/// (`Storage::verify_chain`).
impl PartialEq for Ledger {
    fn eq(&self, o: &Ledger) -> bool {
        self.chain_id == o.chain_id
            && self.hc_bundle == o.hc_bundle
            && self.tree == o.tree
            && self.commitments == o.commitments
            && self.nullifiers == o.nullifiers
            && self.anchors == o.anchors
            && self.validators == o.validators
            && self.programs == o.programs
    }
}
impl Eq for Ledger {}

impl Ledger {
    /// An empty ledger whose only anchor is the empty tree's root at height 0, with `validators`
    /// as its register. Genesis is the one caller that seeds a register (spec §8); every later
    /// entry arrives through a `Bond`.
    pub fn new(
        chain_id: u64,
        hc_bundle: Word8,
        validators: BTreeMap<Address, ValidatorEntry>,
        executor: &dyn ConfidentialExecutor,
    ) -> Ledger {
        let tree = CommitmentTree::new(executor);
        let mut anchors = VecDeque::new();
        anchors.push_back((0, tree.root()));
        Ledger {
            chain_id,
            hc_bundle,
            faucet: false,
            confidential: true,
            tree,
            commitments: BTreeSet::new(),
            nullifiers: BTreeSet::new(),
            anchors,
            validators,
            programs: BTreeMap::new(),
            epoch_blocks: staking::EPOCH_BLOCKS_DEFAULT,
            height: 0,
            timestamp_ms: 0,
            deposits: Vec::new(),
            supply: Supply::default(),
        }
    }

    /// Rebuild a ledger from stored state. The faucet and confidential switches come from
    /// genesis, not from storage, so the caller sets them afterwards.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        chain_id: u64,
        hc_bundle: Word8,
        tree: CommitmentTree,
        commitments: BTreeSet<Word8>,
        nullifiers: BTreeSet<Word8>,
        anchors: Vec<(u64, Word8)>,
        validators: BTreeMap<Address, ValidatorEntry>,
        programs: BTreeMap<ProgramId, ProgramRecord>,
    ) -> Ledger {
        Ledger {
            chain_id,
            hc_bundle,
            faucet: false,
            confidential: true,
            tree,
            commitments,
            nullifiers,
            anchors: anchors.into_iter().collect(),
            validators,
            programs,
            epoch_blocks: staking::EPOCH_BLOCKS_DEFAULT,
            height: 0,
            timestamp_ms: 0,
            deposits: Vec::new(),
            supply: Supply::default(),
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn hc_bundle(&self) -> Word8 {
        self.hc_bundle
    }

    pub fn faucet_enabled(&self) -> bool {
        self.faucet
    }

    pub fn set_faucet(&mut self, on: bool) {
        self.faucet = on;
    }

    pub fn confidential_enabled(&self) -> bool {
        self.confidential
    }

    pub fn set_confidential(&mut self, on: bool) {
        self.confidential = on;
    }

    /// Blocks per epoch (spec §8), as genesis set it.
    pub fn epoch_blocks(&self) -> u64 {
        self.epoch_blocks
    }

    /// Set by the node from its genesis file, like the faucet and confidential switches. Zero is
    /// refused into 1 so `epoch` can never divide by zero on a malformed genesis.
    pub fn set_epoch_blocks(&mut self, n: u64) {
        self.epoch_blocks = n.max(1);
    }

    /// The epoch of the block being applied: `height / epoch_blocks`, so genesis is epoch 0.
    pub fn epoch(&self) -> u64 {
        self.height / self.epoch_blocks.max(1)
    }

    /// The validator set the next epoch would use if this ledger were the last block of one
    /// (spec §8). The rule itself lives in [`staking::derive_set`].
    pub fn derive_next_set(&self) -> ValidatorSet {
        staking::derive_set(&self.validators)
    }

    /// The public supply counters as of this ledger (see [`supply`]).
    pub fn supply(&self) -> Supply {
        self.supply
    }

    /// Restore the counters a node persisted beside the state. Like the faucet and confidential
    /// switches, they do not come out of the note, nullifier and validator families, so the
    /// loader sets them; `Ledger::from_parts` leaves them at zero.
    pub fn set_supply(&mut self, s: Supply) {
        self.supply = s;
    }

    /// What genesis itself created, set once by [`crate::genesis::Genesis::build`]: the deposit
    /// notes in the pool and the stakes in the register. Neither was minted by a transaction,
    /// and together they are the whole of a chain's supply before its first block.
    pub fn set_genesis_supply(&mut self, deposited: u64, staked: u64) {
        self.supply.genesis_deposited = deposited;
        self.supply.genesis_staked = staked;
    }

    /// The supply audit against this ledger's own register.
    pub fn audit(&self) -> Audit {
        Audit::new(self.supply, register_total(&self.validators))
    }

    /// Deposit notes this ledger created while applying the current block (see [`Deposit`]).
    pub fn deposits(&self) -> &[Deposit] {
        &self.deposits
    }

    /// Take the deposits, leaving the list empty.
    pub fn take_deposits(&mut self) -> Vec<Deposit> {
        std::mem::take(&mut self.deposits)
    }

    /// Append a note the ledger computed itself and record it for storage. Fails — before any
    /// mutation — if the commitment is already in the tree.
    pub(crate) fn append_deposit(
        &mut self,
        cm: Word8,
        envelope: Envelope,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<u64, TxError> {
        if !self.commitments.insert(cm) {
            return Err(TxError::CommitmentExists(cm));
        }
        let index = self.tree.append(cm, executor);
        self.deposits.push(Deposit { index, cm, envelope });
        Ok(index)
    }

    /// Height of the block whose transactions are being applied.
    pub fn set_height(&mut self, h: u64) {
        self.height = h;
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    /// Timestamp of the block whose transactions are being applied, in unix milliseconds.
    pub fn set_timestamp_ms(&mut self, t: u64) {
        self.timestamp_ms = t;
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub fn tree(&self) -> &CommitmentTree {
        &self.tree
    }

    pub fn root(&self) -> Word8 {
        self.tree.root()
    }

    /// The index the next appended note gets, i.e. the number of notes so far.
    pub fn next_index(&self) -> u64 {
        self.tree.next_index()
    }

    pub fn anchors(&self) -> &VecDeque<(u64, Word8)> {
        &self.anchors
    }

    /// Spec §7 item 4: only a recorded block-end root is an anchor. A root the tree passes
    /// through mid-block is never one, so what a prover may anchor to is exactly what a synced
    /// node can enumerate.
    pub fn is_anchor(&self, root: &Word8) -> bool {
        self.anchors.iter().any(|(_, r)| r == root)
    }

    pub fn nullifiers(&self) -> &BTreeSet<Word8> {
        &self.nullifiers
    }

    pub fn is_spent(&self, nf: &Word8) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Every commitment ever appended, which the frontier tree cannot answer on its own.
    pub fn commitments_set(&self) -> &BTreeSet<Word8> {
        &self.commitments
    }

    pub fn has_commitment(&self, cm: &Word8) -> bool {
        self.commitments.contains(cm)
    }

    pub fn validators(&self) -> &BTreeMap<Address, ValidatorEntry> {
        &self.validators
    }

    pub fn programs(&self) -> &BTreeMap<ProgramId, ProgramRecord> {
        &self.programs
    }

    pub fn program(&self, id: &ProgramId) -> Option<&ProgramRecord> {
        self.programs.get(id)
    }

    /// Record the root at the end of block `height`. Idempotent per height: re-recording the
    /// same height replaces that entry rather than filling the window with one block's roots.
    pub fn record_anchor(&mut self, height: u64) {
        let root = self.tree.root();
        if let Some(entry) = self.anchors.iter_mut().find(|(h, _)| *h == height) {
            entry.1 = root;
            return;
        }
        self.anchors.push_back((height, root));
        while self.anchors.len() > ANCHOR_WINDOW {
            self.anchors.pop_front();
        }
    }

    /// Genesis only: append a deposit note without a transaction.
    pub fn deposit(&mut self, cm: Word8, executor: &dyn ConfidentialExecutor) -> Result<u64, TxError> {
        if !self.commitments.insert(cm) {
            return Err(TxError::CommitmentExists(cm));
        }
        Ok(self.tree.append(cm, executor))
    }

    /// Check a transaction against the current state without applying it.
    pub fn validate(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        self.validate_inner(tx, executor).map(|_| ())
    }

    /// Spec §7, in order: cheap before expensive. Returns the verified call outcome so
    /// `apply_tx` verifies a proof once.
    fn validate_inner(
        &self,
        tx: &Transaction,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Option<CallOutcome>, TxError> {
        // 1. size caps
        if let Some(b) = &tx.bundle {
            if b.envelopes.iter().any(|e| e.len() > MAX_ENVELOPE_BYTES) {
                return Err(TxError::EnvelopeTooLarge);
            }
            if b.proof.len() > gas::MAX_PROOF_BYTES {
                return Err(TxError::ProofTooLarge);
            }
        }
        match &tx.action {
            Action::Mint { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::Deploy { words, .. } if words.len() > gas::MAX_PROGRAM_WORDS => {
                return Err(TxError::ProgramTooLarge)
            }
            Action::Call { proof, .. } if proof.len() > gas::MAX_PROOF_BYTES => return Err(TxError::ProofTooLarge),
            Action::Withdraw { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::BridgeAttest { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::BridgeAttest { attestation, .. } if attestation.len() > gas::MAX_ATTESTATION_BYTES => {
                return Err(TxError::AttestationTooLarge)
            }
            // A burn's second bundle is a bundle: the caps above it are the caps every bundle
            // gets, applied here because `tx.bundle` is only the fee bundle.
            Action::BridgeBurn { asset_bundle, .. }
                if asset_bundle.envelopes.iter().any(|e| e.len() > MAX_ENVELOPE_BYTES) =>
            {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::BridgeBurn { asset_bundle, .. } if asset_bundle.proof.len() > gas::MAX_PROOF_BYTES => {
                return Err(TxError::ProofTooLarge)
            }
            _ => {}
        }
        // Every variable-length field that reaches a node before any signature or proof work is
        // capped above, with one exception: a `Call`'s `input_envelope` has its own cap
        // (`MAX_CALL_ENVELOPE_BYTES`, larger than a note envelope's) and is checked in
        // `call_envelope::validate` at step 7. Nothing between here and there reads it.
        // 2. chain id
        if tx.chain_id != self.chain_id {
            return Err(TxError::WrongChain { expected: self.chain_id, actual: tx.chain_id });
        }
        // 3. shape and fee floor
        let is_mint = matches!(tx.action, Action::Mint { .. });
        let bundle: Option<&Bundle> = match (&tx.bundle, is_mint) {
            (None, true) => None,
            (None, false) => return Err(TxError::MissingBundle),
            (Some(_), true) => return Err(TxError::MintCarriesBundle),
            (Some(b), false) => Some(b),
        };
        if let Some(b) = bundle {
            if b.asset != 0 {
                return Err(TxError::UnsupportedAsset(b.asset));
            }
            // Phase S2: `Bond` is the one action whose bundle may burn, and it must burn exactly
            // what it bonds — that is how value leaves the pool and becomes public stake.
            match &tx.action {
                Action::Bond { amount, .. } if b.burn != *amount => {
                    return Err(StakingError::BurnMismatch { burn: b.burn, amount: *amount }.into())
                }
                Action::Bond { .. } => {}
                _ if b.burn != 0 => return Err(TxError::UnsupportedBurn(b.burn)),
                _ => {}
            }
            let min = gas::fee_floor(&tx.action);
            if b.fee < min {
                return Err(TxError::FeeTooLow { min, fee: b.fee });
            }
            // 4. anchor
            if !self.is_anchor(&b.anchor) {
                return Err(TxError::UnknownAnchor);
            }
            // 5. time
            let t = b.time as u64;
            if t > self.height || self.height - t > TIME_WINDOW {
                return Err(TxError::TimeOutOfWindow { time: b.time, height: self.height });
            }
            // 6. nullifiers and commitments
            if b.nullifiers[0] == b.nullifiers[1] {
                return Err(TxError::DuplicateNullifierInBundle);
            }
            for nf in &b.nullifiers {
                if self.nullifiers.contains(nf) {
                    return Err(TxError::Spent(*nf));
                }
            }
            if b.commitments[0] == b.commitments[1] {
                return Err(TxError::DuplicateCommitmentInBundle);
            }
            for cm in &b.commitments {
                if self.commitments.contains(cm) {
                    return Err(TxError::CommitmentExists(*cm));
                }
            }
        }
        // 7. action-specific cheap checks
        let mut call_record = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, envelope, amount, minter, signature } => {
                if !self.faucet {
                    return Err(TxError::FaucetDisabled);
                }
                if *amount > FAUCET_MAX_UNITS {
                    return Err(TxError::MintTooLarge { amount: *amount, cap: FAUCET_MAX_UNITS });
                }
                let addr = minter.address();
                if !self.validators.contains_key(&addr) {
                    return Err(TxError::MinterNotValidator(addr));
                }
                let signing_hash = Transaction::mint_signing_hash(tx.chain_id, cm, envelope, *amount);
                if !minter.verify(signing_hash.as_bytes(), signature) {
                    return Err(TxError::BadMintSignature);
                }
                if self.commitments.contains(cm) {
                    return Err(TxError::CommitmentExists(*cm));
                }
            }
            Action::Deploy { base_pc, words } => {
                if !self.confidential {
                    return Err(TxError::ConfidentialDisabled);
                }
                executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
            }
            Action::Call { program, input_envelope, .. } => {
                if !self.confidential {
                    return Err(TxError::ConfidentialDisabled);
                }
                call_envelope::validate(input_envelope)?;
                call_record = Some(self.programs.get(program).ok_or(TxError::UnknownProgram(*program))?);
            }
            a @ (Action::Bond { .. } | Action::Unbond { .. } | Action::Withdraw { .. }) => {
                staking::validate(self, tx, a, executor)?;
            }
            a @ (Action::BridgeAttest { .. } | Action::BridgeBurn { .. }) => {
                bridge_notes::validate(self, tx, a, executor)?;
            }
        }
        // 8-9. the bundle's digest, then its proof
        if let Some(b) = bundle {
            let published = executor.bundle_proof_digest(&b.proof).map_err(TxError::InvalidBundleProof)?;
            if published != executor.bundle_digest(&b.digest_input()) {
                return Err(TxError::BadDigest);
            }
            executor.verify_bundle(&self.hc_bundle, &b.proof).map_err(TxError::InvalidBundleProof)?;
        }
        // 10. the call's own proof, then its tier-dependent fee
        if let (Some(record), Action::Call { proof, .. }) = (call_record, &tx.action) {
            let outcome = executor.verify_call(record, proof).map_err(TxError::InvalidProof)?;
            let min = gas::BUNDLE_BASE + gas::call_fee(outcome.tier);
            let fee = tx.fee();
            if fee < min {
                return Err(TxError::FeeTooLow { min, fee });
            }
            return Ok(Some(outcome));
        }
        Ok(None)
    }

    /// Validate and apply one transaction; for calls, return the receipt data. The bundle fee
    /// is credited to `proposer`'s validator entry.
    pub fn apply_tx(
        &mut self,
        tx: &Transaction,
        proposer: &Address,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Option<CallReceiptData>, TxError> {
        let outcome = self.validate_inner(tx, executor)?;
        if let Some(b) = &tx.bundle {
            // This method is not atomic on its own: the action step below runs after these
            // writes and can still fail (S2's `staking::apply`, S3's `bridge_notes::apply`),
            // which would leave a half-applied bundle behind. What makes a rejected
            // transaction leave the ledger byte-identical is the caller: `apply_transactions`
            // applies every transaction to a scratch clone and only assigns it back once the
            // whole block succeeded. Call `apply_tx` on a ledger you are willing to discard.
            // In practice the proposer is always in the register — `apply_block` rejects a
            // block whose proposer is not, and `HotStuff::propose` runs only when this node
            // is the leader.
            let entry = self.validators.get(proposer).ok_or(TxError::UnknownProposer(*proposer))?;
            let rewards = entry.rewards.checked_add(b.fee).ok_or(TxError::Overflow)?;
            // Both halves of what this bundle takes out of the pool (see [`supply`]): the fee
            // becomes the proposer's `rewards` below, and the burn becomes `stake` in the
            // `Bond` arm — which is why they are counted here, where every bundle passes,
            // rather than in the arms that receive them.
            self.supply.fees_paid = self.supply.fees_paid.checked_add(b.fee).ok_or(TxError::Overflow)?;
            self.supply.burned = self.supply.burned.checked_add(b.burn).ok_or(TxError::Overflow)?;
            for nf in &b.nullifiers {
                self.nullifiers.insert(*nf);
            }
            for cm in &b.commitments {
                self.commitments.insert(*cm);
                self.tree.append(*cm, executor);
            }
            self.validators.get_mut(proposer).expect("looked up above").rewards = rewards;
        }
        let mut receipt = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, amount, .. } => {
                self.supply.faucet_minted =
                    self.supply.faucet_minted.checked_add(*amount).ok_or(TxError::Overflow)?;
                self.commitments.insert(*cm);
                self.tree.append(*cm, executor);
            }
            Action::Deploy { base_pc, words } => {
                let id = program_id(*base_pc, words);
                if !self.programs.contains_key(&id) {
                    let code_hash = executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
                    self.programs.insert(
                        id,
                        ProgramRecord { id, base_pc: *base_pc, words: words.clone(), code_hash, deployed_at: self.height },
                    );
                }
            }
            Action::Call { program, .. } => {
                let o = outcome.expect("validate_inner returns the outcome for calls");
                receipt = Some(CallReceiptData { program: *program, tier: o.tier, outputs: o.outputs });
            }
            a @ (Action::Bond { .. } | Action::Unbond { .. } | Action::Withdraw { .. }) => {
                staking::apply(self, tx, a, executor)?;
            }
            a @ (Action::BridgeAttest { .. } | Action::BridgeBurn { .. }) => {
                bridge_notes::apply(self, tx, a, executor)?;
            }
        }
        Ok(receipt)
    }

    /// Apply every tx of a block in order, returning `(index, receipt)` for each call.
    /// On any error the ledger is left unchanged. Does not check the header's state root;
    /// see `apply_block`.
    pub fn apply_transactions(
        &mut self,
        txs: &[Transaction],
        proposer: &Address,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Vec<(usize, CallReceiptData)>, BlockError> {
        let mut scratch = self.clone();
        // The deposits reported after a block are exactly that block's (see `Deposit`).
        scratch.deposits.clear();
        let mut receipts = Vec::new();
        for (index, tx) in txs.iter().enumerate() {
            if let Some(r) =
                scratch.apply_tx(tx, proposer, executor).map_err(|error| BlockError::InvalidTx { index, error })?
            {
                receipts.push((index, r));
            }
        }
        *self = scratch;
        Ok(receipts)
    }

    /// Full block application: proposer signature, tx root, every tx, the block-end anchor, and
    /// the resulting state root must match the header. Ledger unchanged on error. Returns the
    /// receipts of the block's calls.
    pub fn apply_block(&mut self, block: &Block, executor: &dyn ConfidentialExecutor) -> Result<Vec<CallReceipt>, BlockError> {
        // Size limits are a consensus rule, not only proposer policy: without them a Byzantine
        // leader can stuff a block up to the gossip transport cap and force every replica to
        // execute it.
        if block.transactions.len() > gas::MAX_BLOCK_TXS {
            return Err(BlockError::TooManyTransactions);
        }
        let mut bytes = 0usize;
        for tx in &block.transactions {
            bytes += tx.encoded_len();
            if bytes > gas::MAX_BLOCK_BYTES {
                return Err(BlockError::TooLarge);
            }
        }
        if !block.verify_signature() {
            return Err(BlockError::BadProposerSignature);
        }
        if !block.verify_tx_root() {
            return Err(BlockError::TxRootMismatch);
        }
        let proposer = block.proposer();
        if !self.validators.contains_key(&proposer) {
            return Err(BlockError::UnknownProposer(proposer));
        }
        let mut scratch = self.clone();
        scratch.set_height(block.height());
        scratch.set_timestamp_ms(block.header.timestamp_ms);
        let data = scratch.apply_transactions(&block.transactions, &proposer, executor)?;
        scratch.record_anchor(block.height());
        let computed = scratch.state_root();
        if computed != block.header.state_root {
            return Err(BlockError::StateRootMismatch { computed, header: block.header.state_root });
        }
        *self = scratch;
        Ok(data
            .into_iter()
            .map(|(index, r)| CallReceipt {
                tx: block.transactions[index].hash(),
                program: r.program,
                tier: r.tier,
                outputs: r.outputs,
                height: block.height(),
                index: index as u32,
            })
            .collect())
    }

    /// Deterministic state commitment (spec §9):
    /// `blake3("shrugg-state-2" || tree_root || nullifier_root || validators_root || programs_root)`.
    /// The nullifier and validator roots are BLAKE3 Merkle roots over the sorted sets; programs
    /// are content addressed, so their ids commit to the code.
    pub fn state_root(&self) -> Hash {
        let nf_leaves: Vec<Hash> = self
            .nullifiers
            .iter()
            .map(|nf| Hash::digest_domain(b"shrugg-nullifier-leaf", &word8_to_bytes(nf)))
            .collect();
        let val_leaves: Vec<Hash> = self
            .validators
            .iter()
            .map(|(addr, v)| {
                let mut buf = Vec::with_capacity(96 + 16 * v.pending.len() + v.payout.kem_ek.len());
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&v.stake.to_be_bytes());
                buf.extend_from_slice(&v.rewards.to_be_bytes());
                buf.extend_from_slice(&v.nonce.to_be_bytes());
                // The queue's length before the queue itself: `pending` is the one
                // variable-length run in the leaf, and without a count a short payout key with
                // one pending entry could serialise to the same bytes as a longer key with
                // none. Every field is fixed-width again from here on.
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
        let prog_leaves: Vec<Hash> =
            self.programs.keys().map(|id| Hash::digest_domain(b"shrugg-program-leaf", id.as_bytes())).collect();
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&word8_to_bytes(&self.tree.root()));
        buf.extend_from_slice(merkle_root(&nf_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&val_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&prog_leaves).as_bytes());
        Hash::digest_domain(b"shrugg-state-2", &buf)
    }
}

/// Default executor for nodes until a real verifier exists.
pub fn default_executor() -> StubExecutor {
    StubExecutor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::notes::{Envelope, ShieldedAddress};
    use crate::types::{BlockHeader, QuorumCertificate};

    const HC: Word8 = [11; 8];

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn keys() -> (Keypair, Keypair) {
        (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap())
    }

    /// A register entry for `k`: the S1 fixture's stake, with the S2 fields at their defaults.
    fn entry(k: &Keypair, stake: u64) -> (Address, ValidatorEntry) {
        (
            k.address(),
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

    fn ledger() -> Ledger {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l
    }

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes.
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.root(),
            nullifiers: nfs,
            commitments: cms,
            fee,
            burn: 0,
            asset: 0,
            time: l.height as u32,
            envelopes: [env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        b
    }

    fn tx(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2]) -> Transaction {
        Transaction::shielded(7, bundle(l, nfs, cms, gas::BUNDLE_BASE), Action::None)
    }

    /// A block signed by `key`, carrying `state_root` verbatim so a test can commit to a wrong one.
    fn signed_block(txs: Vec<Transaction>, key: &Keypair, height: u64, state_root: Hash) -> Block {
        let header = BlockHeader {
            height,
            view: height,
            parent: Hash::ZERO,
            proposer: key.public_key().clone(),
            timestamp_ms: 0,
            tx_root: Block::tx_root(&txs),
            state_root,
            justify: QuorumCertificate::genesis(Hash::ZERO),
        };
        Block::sign(header, txs, key)
    }

    /// The state root `txs` leave behind when `proposer` applies them as block `height`.
    fn root_after(l: &Ledger, txs: &[Transaction], proposer: &Address, height: u64) -> Hash {
        let mut scratch = l.clone();
        scratch.set_height(height);
        scratch.apply_transactions(txs, proposer, &StubExecutor).unwrap();
        scratch.record_anchor(height);
        scratch.state_root()
    }

    #[test]
    fn a_valid_bundle_spends_appends_and_pays_the_proposer() {
        let mut l = ledger();
        let (a, _) = keys();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert!(l.is_spent(&[1; 8]) && l.is_spent(&[2; 8]));
        assert!(l.has_commitment(&[3; 8]) && l.has_commitment(&[4; 8]));
        assert_eq!(l.next_index(), 2);
        assert_eq!(l.validators()[&a.address()].rewards, gas::BUNDLE_BASE);
        // replay: both nullifiers now spent
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Spent([1; 8])));
    }

    #[test]
    fn admission_checks_run_in_spec_order() {
        let mut l = ledger();
        let (a, _) = keys();
        // wrong chain
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.chain_id = 8;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::WrongChain { expected: 7, actual: 8 }));
        // envelope cap
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().envelopes[0].body = vec![0; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::EnvelopeTooLarge));
        // fee floor
        let t = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE - 1),
            Action::None,
        );
        assert_eq!(
            l.validate(&t, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE - 1 })
        );
        // asset / burn unsupported in S1
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().asset = 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedAsset(1)));
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().burn = 5;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedBurn(5)));
        // unknown anchor
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().anchor = [9; 8];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnknownAnchor));
        // time window: future and too old. The height is chosen past the window so both edges
        // exist; the edges themselves are expressed in TIME_WINDOW, never in its current value.
        const H: u64 = TIME_WINDOW + 100;
        let oldest = (H - TIME_WINDOW) as u32;
        l.set_height(H);
        l.record_anchor(H);
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().time = H as u32 + 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: H as u32 + 1, height: H }));
        t.bundle.as_mut().unwrap().time = oldest - 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: oldest - 1, height: H }));
        t.bundle.as_mut().unwrap().time = oldest; // exactly height - TIME_WINDOW is allowed
        let mut b = t.bundle.clone().unwrap();
        b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()));
        t.bundle = Some(b);
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        // duplicate nullifier inside the bundle, duplicate commitment inside the bundle
        assert_eq!(
            l.validate(&tx(&l, [[1; 8], [1; 8]], [[3; 8], [4; 8]]), &StubExecutor),
            Err(TxError::DuplicateNullifierInBundle)
        );
        assert_eq!(
            l.validate(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [3; 8]]), &StubExecutor),
            Err(TxError::DuplicateCommitmentInBundle)
        );
        // existing commitment
        l.apply_tx(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height()); // the block ends; its root becomes the anchor the next tx uses
        assert_eq!(
            l.validate(&tx(&l, [[5; 8], [6; 8]], [[3; 8], [7; 8]]), &StubExecutor),
            Err(TxError::CommitmentExists([3; 8]))
        );
        // digest mismatch: plaintext fee differs from what the proof committed to
        let mut t = tx(&l, [[5; 8], [6; 8]], [[8; 8], [9; 8]]);
        t.bundle.as_mut().unwrap().fee += 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BadDigest));
        // proof for another guest
        let mut t = tx(&l, [[5; 8], [6; 8]], [[8; 8], [9; 8]]);
        let d = StubExecutor.bundle_digest(&t.bundle.as_ref().unwrap().digest_input());
        t.bundle.as_mut().unwrap().proof = StubExecutor::make_bundle_proof(&[12; 8], &d);
        assert!(matches!(l.validate(&t, &StubExecutor), Err(TxError::InvalidBundleProof(_))));
    }

    #[test]
    fn anchors_are_a_sliding_window_of_block_end_roots() {
        let mut l = ledger();
        let (a, _) = keys();
        let genesis_root = l.root();
        for h in 1..=(ANCHOR_WINDOW as u64) {
            l.set_height(h);
            l.apply_tx(
                &tx(
                    &l,
                    [[h as u32; 8], [h as u32 + 1000; 8]],
                    [[h as u32 + 2000; 8], [h as u32 + 3000; 8]],
                ),
                &a.address(),
                &StubExecutor,
            )
            .unwrap();
            l.record_anchor(h);
        }
        assert_eq!(l.anchors().len(), ANCHOR_WINDOW);
        assert!(!l.is_anchor(&genesis_root), "the genesis root scrolled out after ANCHOR_WINDOW blocks");
        assert_eq!(l.anchors().back(), Some(&(ANCHOR_WINDOW as u64, l.root())), "the last block's end root");
        // A root the tree only passes through is not an anchor: apply one more block's worth of
        // notes without closing the block, and a bundle anchored at the live root is rejected.
        // Values above every one the loop generated (it used h, h+1000, h+2000 and h+3000 for
        // h up to ANCHOR_WINDOW), so these notes are fresh whatever the window's size is.
        l.set_height(ANCHOR_WINDOW as u64 + 1);
        l.apply_tx(&tx(&l, [[10_000; 8], [10_001; 8]], [[10_002; 8], [10_003; 8]]), &a.address(), &StubExecutor).unwrap();
        assert!(!l.is_anchor(&l.root()), "a mid-block root is not an anchor");
        assert_eq!(
            l.validate(&tx(&l, [[10_004; 8], [10_005; 8]], [[10_006; 8], [10_007; 8]]), &StubExecutor),
            Err(TxError::UnknownAnchor)
        );
    }

    #[test]
    fn apply_block_records_the_block_end_anchor_and_rejects_an_unknown_proposer() {
        let mut l = ledger();
        let (a, _) = keys();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let good = signed_block(vec![t], &a, 1, root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1));
        assert_eq!(l.apply_block(&good, &StubExecutor).unwrap(), Vec::new());
        assert!(l.is_spent(&[1; 8]) && l.has_commitment(&[3; 8]));
        assert_eq!(l.anchors().back(), Some(&(1, l.root())), "the block-end root is recorded");
        // ... and the bundle fee reached the proposer's register entry.
        assert_eq!(l.validators()[&a.address()].rewards, gas::BUNDLE_BASE);
        // A block signed by a key outside the register is rejected before any execution.
        let stranger = Keypair::from_seed([9; 32]).unwrap();
        let bad = signed_block(Vec::new(), &stranger, 2, Hash::ZERO);
        assert_eq!(
            l.apply_block(&bad, &StubExecutor),
            Err(BlockError::UnknownProposer(stranger.address()))
        );
        // A header committing to the wrong state leaves the ledger untouched.
        let before = l.clone();
        let wrong = signed_block(Vec::new(), &a, 2, Hash::ZERO);
        assert!(matches!(l.apply_block(&wrong, &StubExecutor), Err(BlockError::StateRootMismatch { .. })));
        assert_eq!(l, before, "unchanged on error");
        // An empty block still closes with its own anchor.
        let empty = signed_block(Vec::new(), &a, 2, root_after(&l, &[], &a.address(), 2));
        l.apply_block(&empty, &StubExecutor).unwrap();
        assert_eq!(l.anchors().back(), Some(&(2, l.root())));
        // The same rule one level down: a fee has nowhere to go if the proposer is not in the
        // register, and the rejected transaction leaves nothing behind.
        let before = l.clone();
        let orphan = tx(&l, [[70; 8], [71; 8]], [[72; 8], [73; 8]]);
        assert_eq!(
            l.apply_tx(&orphan, &stranger.address(), &StubExecutor),
            Err(TxError::UnknownProposer(stranger.address()))
        );
        assert_eq!(l, before, "unchanged on error");
    }

    #[test]
    fn mint_needs_the_faucet_a_validator_signature_and_no_bundle() {
        let mut l = ledger();
        let (a, _) = keys();
        let stranger = Keypair::from_seed([9; 32]).unwrap();
        let t = Transaction::mint(7, [5; 8], env(), FAUCET_MAX_UNITS, &a);
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        assert_eq!(
            l.validate(&Transaction::mint(7, [5; 8], env(), FAUCET_MAX_UNITS + 1, &a), &StubExecutor),
            Err(TxError::MintTooLarge { amount: FAUCET_MAX_UNITS + 1, cap: FAUCET_MAX_UNITS })
        );
        assert_eq!(
            l.validate(&Transaction::mint(7, [5; 8], env(), 1, &stranger), &StubExecutor),
            Err(TxError::MinterNotValidator(stranger.address()))
        );
        let mut forged = Transaction::mint(7, [5; 8], env(), 1, &a);
        if let Action::Mint { amount, .. } = &mut forged.action {
            *amount = 2;
        }
        assert_eq!(l.validate(&forged, &StubExecutor), Err(TxError::BadMintSignature));
        let with_bundle =
            Transaction { bundle: Some(bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE)), ..t.clone() };
        assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::MintCarriesBundle));
        let no_bundle = Transaction { chain_id: 7, bundle: None, action: Action::None };
        assert_eq!(l.validate(&no_bundle, &StubExecutor), Err(TxError::MissingBundle));
        l.set_faucet(false);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::FaucetDisabled));
        l.set_faucet(true);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&[5; 8]));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentExists([5; 8])));
    }

    #[test]
    fn deploy_and_call_ride_on_bundles_and_pay_their_floors() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone() };
        let under =
            Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), deploy.clone());
        assert_eq!(
            l.validate(&under, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::fee_floor(&deploy), fee: gas::BUNDLE_BASE })
        );
        let ok = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy.clone(),
        );
        l.apply_tx(&ok, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = program_id(0, &words);
        assert!(l.program(&id).is_some());
        let proof = StubExecutor::make_proof(&id, 12, [1, 2, 3, 4, 5, 6, 7, 8]);
        let call = Action::Call { program: id, proof, input_envelope: None };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12);
        let t = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], fee), call.clone());
        let r = l.apply_tx(&t, &a.address(), &StubExecutor).unwrap().unwrap();
        l.record_anchor(l.height());
        assert_eq!(r.outputs, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.tier, 12);
        let cheap = Transaction::shielded(7, bundle(&l, [[9; 8], [10; 8]], [[11; 8], [12; 8]], fee - 1), call.clone());
        assert_eq!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: fee, fee: fee - 1 }));
        l.set_confidential(false);
        // A fresh transaction: `t`'s nullifiers are spent by now, and `Spent` would fire first.
        let disabled = Transaction::shielded(7, bundle(&l, [[13; 8], [14; 8]], [[15; 8], [16; 8]], fee), call);
        assert_eq!(l.validate(&disabled, &StubExecutor), Err(TxError::ConfidentialDisabled));
    }

    /// Each scaffolded action reaches its module, is refused there naming the phase that turns
    /// it on, and leaves the ledger untouched. S2 has landed, so only the bridge half is left;
    /// S3's Task 2 takes this helper with it.
    fn refused_until_its_phase(l: &Ledger, phase: &str, first_nullifier: u32, action: Action) {
        let n = first_nullifier;
        let b = bundle(l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], gas::fee_floor(&action));
        let t = Transaction::shielded(7, b, action);
        match l.validate(&t, &StubExecutor) {
            Err(TxError::UnsupportedAction(m)) => {
                assert!(m.contains(phase), "{m} should name phase {phase}");
                assert!(m.contains("not available until"), "{m}");
            }
            other => panic!("expected UnsupportedAction, got {other:?}"),
        }
        // And nothing is applied: the refusal comes from the action step, before any write.
        let mut scratch = l.clone();
        assert!(scratch.apply_tx(&t, &keys().0.address(), &StubExecutor).is_err());
        assert_eq!(&scratch, l, "a refused action leaves the ledger untouched");
    }

    /// S3 scaffold: the two bridge variants reach [`bridge_notes`] and are refused there. S3's
    /// Task 2 deletes this test. (The staking half is gone: S2 Task 1 gave the three staking
    /// variants rules, and their tests live in `staking.rs`.)
    #[test]
    fn the_bridge_actions_are_refused_until_phase_s3() {
        let l = ledger();
        let recipient = ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] };
        refused_until_its_phase(
            &l,
            "S3",
            112,
            Action::BridgeAttest { attestation: vec![1; 32], recipient, r: [7; 8], envelope: env() },
        );
        let asset_bundle = bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], 0);
        refused_until_its_phase(
            &l,
            "S3",
            116,
            Action::BridgeBurn { asset_bundle, asset: 1, amount: 400, relayer_fee: 100, to_chain: 2, to: [9; 32] },
        );
    }

    /// Step 1 caps every variable-length field the new actions carry, before any signature or
    /// proof work — and before the action step, which is what makes the cap the error a fat
    /// transaction gets. A transaction that clears the cap is still refused further down (an
    /// unregistered validator, or the phase that has not landed); what it is never refused for
    /// is its size.
    #[test]
    fn the_new_actions_are_size_capped_at_step_one() {
        let l = ledger();
        let v = Address([1; 32]);
        let sig = crate::crypto::Signature::empty();
        let recipient = ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] };
        // An envelope of exactly `body` bytes of payload, so the cap edge is exact.
        let fat = |body: usize| Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![3; body] };
        let check = |n: u32, action: Action, expect: Result<(), TxError>| {
            let b = bundle(&l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], gas::fee_floor(&action));
            let got = l.validate(&Transaction::shielded(7, b, action), &StubExecutor);
            match expect {
                Err(e) => assert_eq!(got, Err(e), "n={n}"),
                // "the cap passed": whatever refuses this transaction next, it is not a size
                // error. (A `Withdraw` now reaches the staking rules and is refused there for
                // naming a validator no register holds.)
                Ok(()) => assert!(
                    !matches!(
                        got,
                        Err(TxError::EnvelopeTooLarge | TxError::AttestationTooLarge | TxError::ProofTooLarge)
                    ),
                    "n={n}: {got:?}"
                ),
            }
        };
        let withdraw = |envelope: Envelope| Action::Withdraw {
            validator: v,
            amount: 5,
            nonce: 0,
            r: [7; 8],
            envelope,
            signature: sig.clone(),
        };
        check(200, withdraw(fat(MAX_ENVELOPE_BYTES)), Ok(()));
        check(204, withdraw(fat(MAX_ENVELOPE_BYTES + 1)), Err(TxError::EnvelopeTooLarge));

        let attest = |attestation: Vec<u8>, envelope: Envelope| Action::BridgeAttest {
            attestation,
            recipient: recipient.clone(),
            r: [7; 8],
            envelope,
        };
        check(208, attest(vec![1; 32], fat(MAX_ENVELOPE_BYTES)), Ok(()));
        check(212, attest(vec![1; 32], fat(MAX_ENVELOPE_BYTES + 1)), Err(TxError::EnvelopeTooLarge));
        check(216, attest(vec![1; gas::MAX_ATTESTATION_BYTES], env()), Ok(()));
        check(220, attest(vec![1; gas::MAX_ATTESTATION_BYTES + 1], env()), Err(TxError::AttestationTooLarge));

        // A burn's asset bundle gets the caps every bundle gets: `tx.bundle` is only the fee one.
        let burn = |envelopes: [Envelope; 2], proof: Vec<u8>| {
            let mut asset_bundle = bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], 0);
            asset_bundle.envelopes = envelopes;
            asset_bundle.proof = proof;
            Action::BridgeBurn { asset_bundle, asset: 1, amount: 400, relayer_fee: 100, to_chain: 2, to: [9; 32] }
        };
        check(224, burn([fat(MAX_ENVELOPE_BYTES), env()], vec![]), Ok(()));
        check(228, burn([env(), fat(MAX_ENVELOPE_BYTES + 1)], vec![]), Err(TxError::EnvelopeTooLarge));
        check(232, burn([env(), env()], vec![0; gas::MAX_PROOF_BYTES]), Ok(()));
        check(236, burn([env(), env()], vec![0; gas::MAX_PROOF_BYTES + 1]), Err(TxError::ProofTooLarge));
    }

    /// The one rule of the call-input envelope the chain does enforce, through a real ledger.
    #[test]
    fn a_call_envelope_passes_when_absent_or_small_and_is_capped() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone() };
        let d = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy,
        );
        l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = program_id(0, &words);
        let fee = gas::BUNDLE_BASE + gas::call_fee(12);
        let envelope = |body: usize| crate::types::CallEnvelope {
            kem_ct: vec![1; 1088],
            to_sender: vec![2; 48],
            to_auditor: vec![3; 48],
            body: vec![4; body],
        };
        let fits = crate::types::MAX_CALL_ENVELOPE_BYTES - (1088 + 48 + 48);
        for (n, input_envelope, expect) in [
            (10u32, None, Ok(())),
            (20, Some(envelope(16)), Ok(())),
            (30, Some(envelope(fits)), Ok(())),
            (40, Some(envelope(fits + 1)), Err(TxError::EnvelopeTooLarge)),
        ] {
            let proof = StubExecutor::make_proof(&id, 12, [0; 8]);
            let action = Action::Call { program: id, proof, input_envelope };
            let b = bundle(&l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], fee);
            assert_eq!(l.validate(&Transaction::shielded(7, b, action), &StubExecutor), expect, "n={n}");
        }
    }

    #[test]
    fn deploy_and_call_rejections_and_redeploy_idempotence() {
        let mut l = ledger();
        let (a, _) = keys();
        // An oversized program is refused by the size cap, before any fee or code check.
        let big = Action::Deploy { base_pc: 0, words: vec![0x13; gas::MAX_PROGRAM_WORDS + 1] };
        let t = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), big);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::ProgramTooLarge));
        // A call naming a program nobody deployed.
        let ghost = Hash::digest(b"never deployed");
        let unknown = Action::Call { program: ghost, proof: Vec::new(), input_envelope: None };
        let t = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&unknown)),
            unknown,
        );
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnknownProgram(ghost)));
        // Deploy two programs, then call one with the other's proof.
        let words = vec![0x13u32; 4];
        let other = vec![0x73u32; 4];
        for (n, code) in [(0u32, &words), (1, &other)] {
            let deploy = Action::Deploy { base_pc: 0, words: code.clone() };
            let d = Transaction::shielded(
                7,
                bundle(&l, [[10 + n; 8], [20 + n; 8]], [[30 + n; 8], [40 + n; 8]], gas::fee_floor(&deploy)),
                deploy,
            );
            l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
            l.record_anchor(l.height());
        }
        let (id, other_id) = (program_id(0, &words), program_id(0, &other));
        let wrong_proof = StubExecutor::make_proof(&other_id, 12, [0; 8]);
        let call = Action::Call { program: id, proof: wrong_proof, input_envelope: None };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12);
        let t = Transaction::shielded(7, bundle(&l, [[50; 8], [51; 8]], [[52; 8], [53; 8]], fee), call);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::InvalidProof(ConfidentialError::WrongProgram)));
        // Redeploying the same code is a no-op: the record keeps its original height.
        assert_eq!(l.program(&id).unwrap().deployed_at, 1);
        l.set_height(9);
        let deploy = Action::Deploy { base_pc: 0, words: words.clone() };
        let again = Transaction::shielded(
            7,
            bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], gas::fee_floor(&deploy)),
            deploy,
        );
        l.apply_tx(&again, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.programs().len(), 2);
        assert_eq!(l.program(&id).unwrap().deployed_at, 1, "a redeploy does not move deployed_at");
    }

    #[test]
    fn state_root_covers_tree_nullifiers_validators_and_programs() {
        let mut l = ledger();
        let (a, _) = keys();
        let r0 = l.state_root();
        l.apply_tx(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        let r1 = l.state_root();
        assert_ne!(r0, r1);
        let mut l2 = ledger();
        l2.apply_tx(&tx(&l2, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        assert_eq!(l2.state_root(), r1, "deterministic");
        let rebuilt = Ledger::from_parts(
            7,
            HC,
            l.tree().clone(),
            l.commitments_set().clone(),
            l.nullifiers().clone(),
            l.anchors().iter().copied().collect(),
            l.validators().clone(),
            l.programs().clone(),
        );
        assert_eq!(rebuilt.state_root(), r1);
        assert_eq!(rebuilt, l);
    }

    /// The register is state: every field of the v2 validator leaf — including the two S2
    /// additions, `pending` and `payout` — moves the state root, so two chains that disagree
    /// about a validator's unbonding queue or where its rewards go cannot both be valid.
    #[test]
    fn validator_leaf_v2_changes_the_root_when_pending_or_payout_change() {
        let k = Keypair::from_seed([1; 32]).unwrap();
        let base = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 1_000,
            pending: Vec::new(),
            rewards: 0,
            payout: crate::notes::ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
            nonce: 0,
        };
        let root_of = |e: &ValidatorEntry| {
            let register: BTreeMap<Address, ValidatorEntry> = [(k.address(), e.clone())].into_iter().collect();
            Ledger::new(7, HC, register, &StubExecutor).state_root()
        };
        let r0 = root_of(&base);
        assert_eq!(r0, root_of(&base.clone()), "deterministic");
        let mut roots = vec![r0];
        for changed in [
            ValidatorEntry { stake: 1_001, ..base.clone() },
            ValidatorEntry { rewards: 1, ..base.clone() },
            ValidatorEntry { nonce: 1, ..base.clone() },
            ValidatorEntry { pending: vec![(3, 10)], ..base.clone() },
            ValidatorEntry { pending: vec![(4, 10)], ..base.clone() },
            ValidatorEntry { pending: vec![(3, 11)], ..base.clone() },
            ValidatorEntry { pending: vec![(3, 10), (4, 10)], ..base.clone() },
            ValidatorEntry {
                payout: crate::notes::ShieldedAddress { pk: [5; 8], kem_ek: vec![6; 32] },
                ..base.clone()
            },
            ValidatorEntry {
                payout: crate::notes::ShieldedAddress { pk: [4; 8], kem_ek: vec![7; 32] },
                ..base.clone()
            },
        ] {
            let r = root_of(&changed);
            assert!(!roots.contains(&r), "a v2 leaf field does not reach the state root: {changed:?}");
            roots.push(r);
        }
    }

    #[test]
    fn a_block_with_two_bundles_sharing_a_nullifier_is_invalid() {
        let l = ledger();
        let t1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let t2 = tx(&l, [[2; 8], [5; 8]], [[6; 8], [7; 8]]);
        let (a, _) = keys();
        let mut scratch = l.clone();
        let err = scratch.apply_transactions(&[t1, t2], &a.address(), &StubExecutor).unwrap_err();
        assert_eq!(err, BlockError::InvalidTx { index: 1, error: TxError::Spent([2; 8]) });
        assert_eq!(scratch, l, "unchanged on error");
    }

    /// The positive counterpart: two bundles that share nothing both land in one block, even
    /// though both are anchored at the root as it stood when the block started — the first
    /// bundle's two new leaves move the tree, but an anchor is checked against the recorded
    /// block-end roots, not against the mid-block root, so the second bundle is still valid.
    #[test]
    fn two_independent_bundles_anchored_at_the_block_start_root_both_apply() {
        let l = ledger();
        let (a, _) = keys();
        let start_root = l.root();
        let t1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let t2 = tx(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]]);
        assert_eq!(t1.bundle.as_ref().unwrap().anchor, start_root);
        assert_eq!(t2.bundle.as_ref().unwrap().anchor, start_root);

        let mut scratch = l.clone();
        let receipts = scratch.apply_transactions(&[t1, t2], &a.address(), &StubExecutor).unwrap();
        assert!(receipts.is_empty(), "neither bundle carries a call");
        for nf in [[1; 8], [2; 8], [5; 8], [6; 8]] {
            assert!(scratch.is_spent(&nf), "nullifier {nf:?} not spent");
        }
        for cm in [[3; 8], [4; 8], [7; 8], [8; 8]] {
            assert!(scratch.has_commitment(&cm), "commitment {cm:?} not appended");
        }
        assert_eq!(scratch.next_index(), 4, "four new leaves in tree order");
        assert_eq!(scratch.validators()[&a.address()].rewards, 2 * gas::BUNDLE_BASE);
    }
}
