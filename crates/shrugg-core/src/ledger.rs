//! The shielded notes ledger and block application rules (design spec §7, §9).

use crate::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
use crate::crypto::{merkle_root, Address, Hash, PublicKey};
use crate::gas;
use crate::notes::{word8_to_bytes, Bundle, CommitmentTree, Word8, MAX_ENVELOPE_BYTES};
use crate::program::{program_id, CallOutcome, CallReceipt, ProgramId, ProgramRecord};
use crate::types::{Action, Block, Transaction, ValidatorSet, FAUCET_MAX_UNITS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// How many block-end roots a bundle may anchor to (spec §7 item 4).
pub const ANCHOR_WINDOW: usize = 64;
/// How far behind the current height a bundle's `time` may be (spec §7 item 5).
pub const TIME_WINDOW: u64 = 64;

/// The one public register on the chain (spec §8): a validator's key, its stake, and the
/// bundle fees credited to it as proposer. `stake` stays `u128` so the existing weighting and
/// quorum arithmetic is unchanged; `rewards` are token units like every other amount.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub public_key: PublicKey,
    pub stake: u128,
    /// Bundle fees credited to this proposer (spec §8); paid out by S2's Withdraw.
    pub rewards: u64,
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
    #[error("invalid proof: {0}")]
    InvalidProof(ConfidentialError),
    #[error("the bundle's digest is not what its proof published")]
    BadDigest,
    #[error("invalid bundle proof: {0}")]
    InvalidBundleProof(ConfidentialError),
    #[error("proposer {0} is not in the validator register")]
    UnknownProposer(Address),
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
    /// Height of the block being applied (the `time` window and `ProgramRecord::deployed_at`).
    height: u64,
    /// Timestamp of the block being applied, in unix milliseconds.
    timestamp_ms: u64,
}

/// Equality is over consensus state only. `height` and `timestamp_ms` are the position of the
/// block being applied, and `faucet`/`confidential` are genesis switches a reloading node sets
/// from its genesis file rather than from storage, so two ledgers holding the same notes,
/// nullifiers, anchors, validators and programs are the same ledger.
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
    /// An empty ledger whose only anchor is the empty tree's root at height 0.
    pub fn new(chain_id: u64, hc_bundle: Word8, validators: &ValidatorSet, executor: &dyn ConfidentialExecutor) -> Ledger {
        let tree = CommitmentTree::new(executor);
        let mut anchors = VecDeque::new();
        anchors.push_back((0, tree.root()));
        let validators = validators
            .iter()
            .map(|v| {
                (
                    v.public_key.address(),
                    ValidatorEntry { public_key: v.public_key.clone(), stake: v.stake, rewards: 0 },
                )
            })
            .collect();
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
            height: 0,
            timestamp_ms: 0,
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
            height: 0,
            timestamp_ms: 0,
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
            _ => {}
        }
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
            if b.burn != 0 {
                return Err(TxError::UnsupportedBurn(b.burn));
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
            Action::Call { program, .. } => {
                if !self.confidential {
                    return Err(TxError::ConfidentialDisabled);
                }
                call_record = Some(self.programs.get(program).ok_or(TxError::UnknownProgram(*program))?);
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
            // Everything that can still fail is resolved before the first mutation, so a
            // rejected transaction leaves the ledger byte-identical. In practice the proposer
            // is always in the register — `apply_block` rejects a block whose proposer is not,
            // and `HotStuff::propose` runs only when this node is the leader.
            let entry = self.validators.get(proposer).ok_or(TxError::UnknownProposer(*proposer))?;
            let rewards = entry.rewards.checked_add(b.fee).ok_or(TxError::Overflow)?;
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
            Action::Mint { cm, .. } => {
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
                let mut buf = Vec::with_capacity(32 + 16 + 8);
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&v.stake.to_be_bytes());
                buf.extend_from_slice(&v.rewards.to_be_bytes());
                Hash::digest_domain(b"shrugg-validator-leaf", &buf)
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
    use crate::notes::Envelope;
    use crate::types::{BlockHeader, QuorumCertificate, Validator, ValidatorSet};

    const HC: Word8 = [11; 8];

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn keys() -> (Keypair, Keypair) {
        (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap())
    }

    fn ledger() -> Ledger {
        let (a, b) = keys();
        let set = ValidatorSet::new(vec![
            Validator { public_key: a.public_key().clone(), stake: 10 },
            Validator { public_key: b.public_key().clone(), stake: 10 },
        ]);
        let mut l = Ledger::new(7, HC, &set, &StubExecutor);
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
        // time window: future and too old
        l.set_height(100);
        l.record_anchor(100);
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().time = 101;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: 101, height: 100 }));
        t.bundle.as_mut().unwrap().time = 35;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: 35, height: 100 }));
        t.bundle.as_mut().unwrap().time = 36; // height - 64 is allowed
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
        assert!(!l.is_anchor(&genesis_root), "the genesis root scrolled out after 64 blocks");
        assert_eq!(l.anchors().back(), Some(&(ANCHOR_WINDOW as u64, l.root())), "the last block's end root");
        // A root the tree only passes through is not an anchor: apply one more block's worth of
        // notes without closing the block, and a bundle anchored at the live root is rejected.
        l.set_height(ANCHOR_WINDOW as u64 + 1);
        l.apply_tx(&tx(&l, [[90; 8], [91; 8]], [[92; 8], [93; 8]]), &a.address(), &StubExecutor).unwrap();
        assert!(!l.is_anchor(&l.root()), "a mid-block root is not an anchor");
        assert_eq!(
            l.validate(&tx(&l, [[94; 8], [95; 8]], [[96; 8], [97; 8]]), &StubExecutor),
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
        let call = Action::Call { program: id, proof };
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
        let unknown = Action::Call { program: ghost, proof: Vec::new() };
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
        let call = Action::Call { program: id, proof: wrong_proof };
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
}
