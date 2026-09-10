//! Account-based SHRUGG ledger and block application rules.

use crate::bridge::{AssetId, BridgeError, BridgeState};
use crate::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
use crate::crypto::{merkle_root, Address, Hash};
use crate::effect::{self, Effect, EffectError};
use crate::gas;
use crate::program::{program_id, CallOutcome, CallReceipt, ProgramId, ProgramRecord};
use crate::types::{Block, Transaction, TxKind, FAUCET_MAX_UNITS};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Account {
    pub nonce: u64,
    pub balance: u128,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum TxError {
    #[error("wrong chain id: expected {expected}, got {actual}")]
    WrongChain { expected: u64, actual: u64 },
    #[error("bad signature")]
    BadSignature,
    #[error("bad nonce: expected {expected}, got {actual}")]
    BadNonce { expected: u64, actual: u64 },
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },
    #[error("arithmetic overflow")]
    Overflow,
    #[error("faucet is disabled on this chain")]
    FaucetDisabled,
    #[error("program too large")]
    ProgramTooLarge,
    #[error("bad program: {0}")]
    BadProgram(ConfidentialError),
    #[error("unknown program {0}")]
    UnknownProgram(ProgramId),
    #[error("proof too large")]
    ProofTooLarge,
    #[error("too many recipients")]
    TooManyRecipients,
    #[error("invalid proof: {0}")]
    InvalidProof(ConfidentialError),
    #[error("fee {fee} below minimum {min}")]
    FeeTooLow { min: u128, fee: u128 },
    #[error("bad effect: {0}")]
    BadEffect(#[from] EffectError),
    #[error("insufficient balance for emitted transfer: have {have}, need {need}")]
    InsufficientForEffect { have: u128, need: u128 },
    #[error("mint of {amount} exceeds faucet cap {cap}")]
    MintTooLarge { amount: u128, cap: u128 },
    #[error("bridge: {0}")]
    Bridge(#[from] BridgeError),
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
    /// Only on chains with a bridge, where the block timestamp is consensus
    /// input (guardian-set expiry, burn message times): a leader must not be
    /// able to rewind time and revive an expired guardian set. Equal
    /// timestamps are allowed.
    #[error("block timestamp {block} is before its parent's {parent}")]
    TimestampRewind { parent: u64, block: u64 },
}

/// Receipt data for a call, before it is placed in a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallReceiptData {
    pub program: ProgramId,
    pub tier: u8,
    pub outputs: [u32; 8],
    pub effect: Option<(Address, u128)>,
}

/// In-memory chain state: accounts and deployed programs. Cheap to clone (used for
/// speculative execution).
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    chain_id: u64,
    /// Testnet faucet enabled (from genesis). Not part of the state root.
    faucet: bool,
    accounts: BTreeMap<Address, Account>,
    programs: BTreeMap<ProgramId, ProgramRecord>,
    /// Height of the block being applied (recorded in `ProgramRecord::deployed_at`).
    height: u64,
    /// Bridged-asset state, present only on chains whose genesis has a
    /// `bridge` section. Part of the state root when present; both bridge
    /// transaction kinds are rejected when absent.
    bridge: Option<BridgeState>,
    /// Timestamp of the block being applied, in unix milliseconds. Transient
    /// like `height` (set by `apply_block`), so it is not part of the state
    /// root or of equality; bridge validation reads it as `now` in seconds.
    timestamp_ms: u64,
}

impl PartialEq for Ledger {
    fn eq(&self, other: &Ledger) -> bool {
        self.chain_id == other.chain_id
            && self.faucet == other.faucet
            && self.accounts == other.accounts
            && self.programs == other.programs
            && self.bridge == other.bridge
    }
}
impl Eq for Ledger {}

impl Ledger {
    pub fn new(chain_id: u64) -> Ledger {
        Ledger { chain_id, ..Default::default() }
    }

    pub fn from_accounts(chain_id: u64, accounts: BTreeMap<Address, Account>) -> Ledger {
        Ledger { chain_id, accounts, ..Default::default() }
    }

    pub fn from_parts(chain_id: u64, accounts: BTreeMap<Address, Account>, programs: BTreeMap<ProgramId, ProgramRecord>) -> Ledger {
        Ledger { chain_id, accounts, programs, ..Default::default() }
    }

    pub fn programs(&self) -> &BTreeMap<ProgramId, ProgramRecord> {
        &self.programs
    }

    pub fn program(&self, id: &ProgramId) -> Option<&ProgramRecord> {
        self.programs.get(id)
    }

    /// Height of the block whose transactions are being applied.
    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    /// Timestamp of the block whose transactions are being applied, in unix
    /// milliseconds. Bridge validation and outbound burn messages use it, so
    /// every ledger built from a head block must carry that block's time.
    pub fn set_timestamp_ms(&mut self, timestamp_ms: u64) {
        self.timestamp_ms = timestamp_ms;
    }

    /// The block time this ledger is positioned at, in unix milliseconds.
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// The block time in unix seconds — `now` for guardian-set expiry and the
    /// timestamp of outbound burn messages.
    fn now_secs(&self) -> u64 {
        self.timestamp_ms / 1000
    }

    /// Install (or clear) the bridge state. Genesis calls this once; storage
    /// calls it when reloading a bridged chain.
    pub fn set_bridge(&mut self, bridge: Option<BridgeState>) {
        self.bridge = bridge;
    }

    /// The bridge state, or `None` on a chain without a bridge.
    pub fn bridge(&self) -> Option<&BridgeState> {
        self.bridge.as_ref()
    }

    pub fn bridge_mut(&mut self) -> Option<&mut BridgeState> {
        self.bridge.as_mut()
    }

    /// `addr`'s balance of bridged asset `asset`; zero without a bridge.
    pub fn asset_balance(&self, asset: &AssetId, addr: &Address) -> u128 {
        self.bridge.as_ref().map_or(0, |b| b.balance(asset, addr))
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn faucet_enabled(&self) -> bool {
        self.faucet
    }

    pub fn set_faucet(&mut self, enabled: bool) {
        self.faucet = enabled;
    }

    pub fn account(&self, addr: &Address) -> Account {
        self.accounts.get(addr).copied().unwrap_or_default()
    }

    pub fn balance(&self, addr: &Address) -> u128 {
        self.account(addr).balance
    }

    pub fn nonce(&self, addr: &Address) -> u64 {
        self.account(addr).nonce
    }

    pub fn accounts(&self) -> &BTreeMap<Address, Account> {
        &self.accounts
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Overwrite one account (mempool nonce probing; never used by block application).
    pub fn set_account(&mut self, addr: Address, acct: Account) {
        self.accounts.insert(addr, acct);
    }

    /// Credit without any checks (genesis allocation, fee payout).
    pub fn credit(&mut self, addr: Address, amount: u128) -> Result<(), TxError> {
        let acct = self.accounts.entry(addr).or_default();
        acct.balance = acct.balance.checked_add(amount).ok_or(TxError::Overflow)?;
        Ok(())
    }

    /// Check a transaction against the current state without applying it.
    pub fn validate(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        self.validate_inner(tx, executor).map(|_| ())
    }

    /// Validation that also returns the verified call outcome, so `apply` verifies a proof once.
    fn validate_inner(
        &self,
        tx: &Transaction,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Option<(CallOutcome, Effect)>, TxError> {
        if tx.body.chain_id != self.chain_id {
            return Err(TxError::WrongChain { expected: self.chain_id, actual: tx.body.chain_id });
        }
        if !tx.verify_signature() {
            return Err(TxError::BadSignature);
        }
        let sender = tx.sender();
        let acct = self.account(&sender);
        if tx.body.nonce != acct.nonce {
            return Err(TxError::BadNonce { expected: acct.nonce, actual: tx.body.nonce });
        }
        let need = tx.total_cost().ok_or(TxError::Overflow)?;
        if acct.balance < need {
            return Err(TxError::InsufficientBalance { have: acct.balance, need });
        }
        match &tx.body.kind {
            TxKind::Transfer { .. } => Ok(None),
            TxKind::Mint { amount, .. } => {
                if !self.faucet {
                    return Err(TxError::FaucetDisabled);
                }
                if *amount > FAUCET_MAX_UNITS {
                    return Err(TxError::MintTooLarge { amount: *amount, cap: FAUCET_MAX_UNITS });
                }
                Ok(None)
            }
            TxKind::Deploy { base_pc, words } => {
                if words.len() > gas::MAX_PROGRAM_WORDS {
                    return Err(TxError::ProgramTooLarge);
                }
                let min = gas::deploy_fee(words.len());
                if tx.body.fee < min {
                    return Err(TxError::FeeTooLow { min, fee: tx.body.fee });
                }
                executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
                Ok(None)
            }
            TxKind::Call { program, proof, recipients } => {
                Ok(Some(self.check_call(tx, program, proof, recipients, executor)?))
            }
            TxKind::BridgeAttest { attestation } => {
                let bridge = self.bridge.as_ref().ok_or(BridgeError::Disabled)?;
                bridge.check_attest(attestation, sender, self.now_secs())?;
                Ok(None)
            }
            TxKind::BridgeBurn { asset, amount, to_chain, fee, .. } => {
                let bridge = self.bridge.as_ref().ok_or(BridgeError::Disabled)?;
                bridge.check_burn(&sender, asset, *amount, *to_chain, *fee)?;
                Ok(None)
            }
        }
    }

    fn check_call(
        &self,
        tx: &Transaction,
        program: &ProgramId,
        proof: &[u8],
        recipients: &[Address],
        executor: &dyn ConfidentialExecutor,
    ) -> Result<(CallOutcome, Effect), TxError> {
        if proof.len() > gas::MAX_PROOF_BYTES {
            return Err(TxError::ProofTooLarge);
        }
        if recipients.len() > gas::MAX_RECIPIENTS {
            return Err(TxError::TooManyRecipients);
        }
        let record = self.programs.get(program).ok_or(TxError::UnknownProgram(*program))?;
        let outcome = executor.verify_call(record, proof).map_err(TxError::InvalidProof)?;
        let min = gas::call_fee(outcome.tier);
        if tx.body.fee < min {
            return Err(TxError::FeeTooLow { min, fee: tx.body.fee });
        }
        let effect = effect::decode(&outcome.outputs, recipients)?;
        if let Effect::Transfer { amount, .. } = effect {
            let have = self.balance(&tx.sender());
            let need = amount.checked_add(tx.body.fee).ok_or(TxError::Overflow)?;
            if have < need {
                return Err(TxError::InsufficientForEffect { have, need });
            }
        }
        Ok((outcome, effect))
    }

    /// Validate and apply one transaction. Fee goes to `fee_recipient`.
    pub fn apply_tx(
        &mut self,
        tx: &Transaction,
        fee_recipient: &Address,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<(), TxError> {
        self.apply_tx_with_receipt(tx, fee_recipient, executor).map(|_| ())
    }

    /// Validate and apply one transaction; for calls, return the receipt data.
    pub fn apply_tx_with_receipt(
        &mut self,
        tx: &Transaction,
        fee_recipient: &Address,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Option<CallReceiptData>, TxError> {
        let call = self.validate_inner(tx, executor)?;
        let sender = tx.sender();
        let cost = tx.total_cost().ok_or(TxError::Overflow)?;
        {
            let acct = self.accounts.entry(sender).or_default();
            acct.balance -= cost;
            acct.nonce += 1;
        }
        let mut receipt = None;
        match &tx.body.kind {
            TxKind::Transfer { to, amount } | TxKind::Mint { to, amount } => self.credit(*to, *amount)?,
            TxKind::Deploy { base_pc, words } => {
                let id = program_id(*base_pc, words);
                if !self.programs.contains_key(&id) {
                    let code_hash = executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
                    self.programs.insert(
                        id,
                        ProgramRecord { id, base_pc: *base_pc, words: words.clone(), code_hash, deployer: sender, deployed_at: self.height },
                    );
                }
            }
            TxKind::Call { program, .. } => {
                let (outcome, effect) = call.expect("validate_inner returns the outcome for calls");
                let applied = match effect {
                    Effect::Transfer { to, amount } => {
                        let acct = self.accounts.entry(sender).or_default();
                        acct.balance -= amount; // covered: check_call verified amount + fee
                        self.credit(to, amount)?;
                        Some((to, amount))
                    }
                    Effect::None => None,
                };
                receipt = Some(CallReceiptData { program: *program, tier: outcome.tier, outputs: outcome.outputs, effect: applied });
            }
            // Bridge kinds move bridged assets, never SHRUGG: the debit above
            // took only the fee. `validate_inner` has already rejected them
            // when no bridge is configured, so the state is present here.
            TxKind::BridgeAttest { attestation } => {
                let now = self.now_secs();
                self.bridge
                    .as_mut()
                    .expect("validate_inner rejects bridge txs on a chain without a bridge")
                    .apply_attest(attestation, sender, now)?;
            }
            TxKind::BridgeBurn { asset, amount, to_chain, to, fee } => {
                // The wire format's timestamp is a 4-byte field (spec 3.2), so
                // the cast is the encoding's own range, not a narrowing choice:
                // every chain verifying these messages wraps at 2106 alike.
                let (timestamp, height) = (self.now_secs() as u32, self.height);
                self.bridge
                    .as_mut()
                    .expect("validate_inner rejects bridge txs on a chain without a bridge")
                    .apply_burn(sender, *asset, *amount, *to_chain, *to, *fee, tx.hash(), height, timestamp)?;
            }
        }
        self.credit(*fee_recipient, tx.body.fee)?;
        Ok(receipt)
    }

    /// Apply every tx of a block in order, returning `(index, receipt)` for each call.
    /// On any error the ledger is left unchanged. Does not check the header's
    /// state root; see `apply_block`.
    pub fn apply_transactions(
        &mut self,
        txs: &[Transaction],
        fee_recipient: &Address,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Vec<(usize, CallReceiptData)>, BlockError> {
        let mut scratch = self.clone();
        let mut receipts = Vec::new();
        for (index, tx) in txs.iter().enumerate() {
            if let Some(r) = scratch
                .apply_tx_with_receipt(tx, fee_recipient, executor)
                .map_err(|error| BlockError::InvalidTx { index, error })?
            {
                receipts.push((index, r));
            }
        }
        *self = scratch;
        Ok(receipts)
    }

    /// Full block application: proposer signature, tx root, every tx, and the
    /// resulting state root must match the header. Ledger unchanged on error.
    /// Returns the receipts of the block's calls.
    pub fn apply_block(&mut self, block: &Block, executor: &dyn ConfidentialExecutor) -> Result<Vec<CallReceipt>, BlockError> {
        if !block.verify_signature() {
            return Err(BlockError::BadProposerSignature);
        }
        if !block.verify_tx_root() {
            return Err(BlockError::TxRootMismatch);
        }
        // Time only constrains validity where it is consensus input, so a
        // chain without a bridge keeps byte-identical validity rules.
        if self.bridge.is_some() && block.header.timestamp_ms < self.timestamp_ms {
            return Err(BlockError::TimestampRewind { parent: self.timestamp_ms, block: block.header.timestamp_ms });
        }
        let mut scratch = self.clone();
        scratch.set_height(block.height());
        scratch.set_timestamp_ms(block.header.timestamp_ms);
        let data = scratch.apply_transactions(&block.transactions, &block.proposer(), executor)?;
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
                effect: r.effect,
                height: block.height(),
                index: index as u32,
            })
            .collect())
    }

    /// Deterministic state commitment: `blake3(accounts_root || programs_root)`,
    /// or `blake3(accounts_root || programs_root || bridge_root)` on a chain
    /// with a `bridge` section. A chain without one commits exactly the 64
    /// bytes a pre-bridge node committed.
    ///
    /// Accounts with zero balance and zero nonce are pruned so a never-touched
    /// account and an absent one hash identically. Programs are content addressed,
    /// so their ids commit to the code.
    pub fn state_root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .accounts
            .iter()
            .filter(|(_, a)| a.balance != 0 || a.nonce != 0)
            .map(|(addr, acct)| {
                let mut buf = Vec::with_capacity(32 + 8 + 16);
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&acct.nonce.to_be_bytes());
                buf.extend_from_slice(&acct.balance.to_be_bytes());
                Hash::digest_domain(b"shrugg-account", &buf)
            })
            .collect();
        let accounts_root = merkle_root(&leaves);
        let program_leaves: Vec<Hash> =
            self.programs.keys().map(|id| Hash::digest_domain(b"shrugg-program-leaf", id.as_bytes())).collect();
        let programs_root = merkle_root(&program_leaves);
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(accounts_root.as_bytes());
        buf.extend_from_slice(programs_root.as_bytes());
        if let Some(bridge) = &self.bridge {
            buf.extend_from_slice(bridge.root().as_bytes());
        }
        Hash::digest_domain(b"shrugg-state", &buf)
    }
}

/// Default executor for nodes until a real verifier exists.
pub fn default_executor() -> StubExecutor {
    StubExecutor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{
        asset_id, digest, guardian_address, sign_digest, Attestation, Body, BridgeConfig, BridgeState, GuardianKey,
        GuardianSet, Payload, Transfer, VerifyError, CHAIN_RAND,
    };
    use crate::crypto::Keypair;

    fn key(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    fn funded() -> (Ledger, Keypair, Keypair, Address) {
        let alice = key(1);
        let bob = key(2);
        let proposer = key(3).address();
        let mut l = Ledger::new(1);
        l.credit(alice.address(), 1_000).unwrap();
        (l, alice, bob, proposer)
    }

    #[test]
    fn transfer_moves_funds_and_pays_fee() {
        let (mut l, alice, bob, proposer) = funded();
        let tx = Transaction::transfer(&alice, 1, 0, bob.address(), 300, 10);
        l.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.balance(&alice.address()), 690);
        assert_eq!(l.balance(&bob.address()), 300);
        assert_eq!(l.balance(&proposer), 10);
        assert_eq!(l.nonce(&alice.address()), 1);
    }

    /// A chain whose genesis has no `bridge` section rejects both bridge
    /// kinds at validation, and they never mutate the ledger.
    #[test]
    fn bridge_txs_rejected_without_bridge_section() {
        let (mut l, alice, _, proposer) = funded();
        let attest = Transaction::bridge_attest(&alice, 1, 0, vec![1, 2, 3], 10);
        assert_eq!(
            l.validate(&attest, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Disabled))
        );
        assert_eq!(
            l.apply_tx(&attest, &proposer, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Disabled))
        );
        let burn = Transaction::bridge_burn(&alice, 1, 0, Hash::digest(b"asset"), 5, 2, [7; 32], 1, 10);
        assert_eq!(
            l.validate(&burn, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Disabled))
        );
        assert_eq!(
            l.apply_tx(&burn, &proposer, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Disabled))
        );
        assert_eq!(l.balance(&alice.address()), 1_000);
        assert_eq!(l.nonce(&alice.address()), 0);
        assert_eq!(l.balance(&proposer), 0);
    }

    #[test]
    fn validation_matrix() {
        let (l, alice, bob, _) = funded();
        let ok = Transaction::transfer(&alice, 1, 0, bob.address(), 1, 0);
        assert_eq!(l.validate(&ok, &StubExecutor), Ok(()));
        let wrong_chain = Transaction::transfer(&alice, 2, 0, bob.address(), 1, 0);
        assert!(matches!(l.validate(&wrong_chain, &StubExecutor), Err(TxError::WrongChain { .. })));
        let bad_nonce = Transaction::transfer(&alice, 1, 1, bob.address(), 1, 0);
        assert!(matches!(l.validate(&bad_nonce, &StubExecutor), Err(TxError::BadNonce { expected: 0, actual: 1 })));
        let too_much = Transaction::transfer(&alice, 1, 0, bob.address(), 1_000, 1);
        assert!(matches!(l.validate(&too_much, &StubExecutor), Err(TxError::InsufficientBalance { .. })));
        let broke = Transaction::transfer(&bob, 1, 0, alice.address(), 1, 0);
        assert!(matches!(l.validate(&broke, &StubExecutor), Err(TxError::InsufficientBalance { .. })));
        let mut forged = ok.clone();
        forged.body.fee = 5;
        assert_eq!(l.validate(&forged, &StubExecutor), Err(TxError::BadSignature));
        let overflow = Transaction::transfer(&alice, 1, 0, bob.address(), u128::MAX, 1);
        assert_eq!(l.validate(&overflow, &StubExecutor), Err(TxError::Overflow));
    }

    #[test]
    fn self_transfer_only_costs_fee() {
        let (mut l, alice, _, proposer) = funded();
        let tx = Transaction::transfer(&alice, 1, 0, alice.address(), 500, 7);
        l.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.balance(&alice.address()), 993);
    }

    fn funded_with(units: u128) -> (Ledger, Keypair, Keypair, Address) {
        let alice = key(1);
        let bob = key(2);
        let proposer = key(3).address();
        let mut l = Ledger::new(1);
        l.credit(alice.address(), units).unwrap();
        l.credit(bob.address(), units).unwrap();
        (l, alice, bob, proposer)
    }

    fn deployed(l: &mut Ledger, deployer: &Keypair) -> ProgramId {
        let words = vec![0x00000013u32; 4]; // four nops
        let tx = Transaction::deploy(deployer, 1, l.nonce(&deployer.address()), 0, words.clone(), gas::deploy_fee(4));
        l.apply_tx(&tx, &key(3).address(), &StubExecutor).unwrap();
        program_id(0, &words)
    }

    #[test]
    fn deploy_stores_program_and_charges_gas() {
        let (mut l, alice, _, proposer) = funded_with(1_000_000_000);
        let words = vec![0x13u32; 4];
        let cheap = Transaction::deploy(&alice, 1, 0, 0, words.clone(), 1);
        assert!(matches!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: 400_000, fee: 1 })));
        let ok = Transaction::deploy(&alice, 1, 0, 0, words.clone(), 400_000);
        l.set_height(7);
        l.apply_tx(&ok, &proposer, &StubExecutor).unwrap();
        let id = program_id(0, &words);
        let rec = l.program(&id).unwrap();
        assert_eq!(rec.words, words);
        assert_eq!(rec.deployer, alice.address());
        assert_eq!(rec.deployed_at, 7);
        assert_eq!(l.balance(&proposer), 400_000);
        let again = Transaction::deploy(&alice, 1, 1, 0, words.clone(), 400_000);
        l.apply_tx(&again, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.programs().len(), 1);
        let big = Transaction::deploy(&alice, 1, 2, 0, vec![0x13; gas::MAX_PROGRAM_WORDS + 1], 0);
        assert!(matches!(l.validate(&big, &StubExecutor), Err(TxError::ProgramTooLarge)));
    }

    #[test]
    fn call_verifies_proof_charges_gas_and_applies_transfer_effect() {
        let (mut l, alice, bob, proposer) = funded_with(1_000_000_000);
        let id = deployed(&mut l, &alice);
        let fee = gas::call_fee(10);
        let proof = StubExecutor::make_proof(&id, 10, [1, 0, 250, 0, 0, 0, 0, 0]);
        let tx = Transaction::call(&alice, 1, 1, id, proof, vec![bob.address()], fee);
        let before = l.balance(&alice.address());
        let r = l.apply_tx_with_receipt(&tx, &proposer, &StubExecutor).unwrap().expect("call receipt");
        assert_eq!(r.tier, 10);
        assert_eq!(r.effect, Some((bob.address(), 250)));
        assert_eq!(l.balance(&bob.address()), 1_000_000_000 + 250);
        assert_eq!(l.balance(&alice.address()), before - fee - 250);
        assert_eq!(l.nonce(&alice.address()), 2);
    }

    #[test]
    fn call_rejections() {
        let (mut l, alice, bob, _) = funded_with(1_000_000_000);
        let id = deployed(&mut l, &alice);
        let fee = gas::call_fee(10);
        let np = Hash::digest(b"nope");
        let unknown = Transaction::call(&alice, 1, 1, np, StubExecutor::make_proof(&np, 10, [0; 8]), vec![], fee);
        assert!(matches!(l.validate(&unknown, &StubExecutor), Err(TxError::UnknownProgram(_))));
        let bad_proof = Transaction::call(&alice, 1, 1, id, b"garbage".to_vec(), vec![], fee);
        assert!(matches!(l.validate(&bad_proof, &StubExecutor), Err(TxError::InvalidProof(_))));
        let low_fee = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 12, [0; 8]), vec![], fee);
        assert!(matches!(l.validate(&low_fee, &StubExecutor), Err(TxError::FeeTooLow { .. })));
        let bad_index = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [1, 3, 1, 0, 0, 0, 0, 0]), vec![bob.address()], fee);
        assert!(matches!(l.validate(&bad_index, &StubExecutor), Err(TxError::BadEffect(_))));
        let too_much = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [1, 0, 0xffff_ffff, 0xffff_ffff, 0, 0, 0, 0]), vec![bob.address()], fee);
        assert!(matches!(l.validate(&too_much, &StubExecutor), Err(TxError::InsufficientForEffect { .. })));
        let many: Vec<Address> = (0..9).map(|i| key(20 + i).address()).collect();
        let too_many = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [0; 8]), many, fee);
        assert!(matches!(l.validate(&too_many, &StubExecutor), Err(TxError::TooManyRecipients)));
        let none = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [0, 0, 0, 0, 0, 0, 0, 42]), vec![], fee);
        let r = l.apply_tx_with_receipt(&none, &key(3).address(), &StubExecutor).unwrap().unwrap();
        assert_eq!(r.effect, None);
        assert_eq!(r.outputs[7], 42);
    }

    #[test]
    fn state_root_covers_programs() {
        let (mut a, alice, _, _) = funded_with(1_000_000_000);
        let b = a.clone();
        let root_before = a.state_root();
        let _ = deployed(&mut a, &alice);
        assert_ne!(a.state_root(), root_before);
        let mut c = b.clone();
        let _ = deployed(&mut c, &alice);
        assert_eq!(a.state_root(), c.state_root());
    }

    #[test]
    fn apply_transactions_is_atomic() {
        let (mut l, alice, bob, proposer) = funded();
        let before = l.clone();
        let t1 = Transaction::transfer(&alice, 1, 0, bob.address(), 100, 0);
        let t2 = Transaction::transfer(&alice, 1, 5, bob.address(), 100, 0); // bad nonce
        let err = l.apply_transactions(&[t1, t2], &proposer, &StubExecutor).unwrap_err();
        assert!(matches!(err, BlockError::InvalidTx { index: 1, .. }));
        assert_eq!(l, before);
    }

    #[test]
    fn sequential_nonces_within_a_block() {
        let (mut l, alice, bob, proposer) = funded();
        let txs: Vec<_> = (0..3).map(|n| Transaction::transfer(&alice, 1, n, bob.address(), 10, 1)).collect();
        l.apply_transactions(&txs, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.nonce(&alice.address()), 3);
        assert_eq!(l.balance(&bob.address()), 30);
        assert_eq!(l.balance(&proposer), 3);
    }

    #[test]
    fn state_root_is_deterministic_and_prunes_empty_accounts() {
        let (mut a, alice, bob, proposer) = funded();
        let mut b = a.clone();
        assert_eq!(a.state_root(), b.state_root());
        let tx = Transaction::transfer(&alice, 1, 0, bob.address(), 1, 0);
        a.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
        assert_ne!(a.state_root(), b.state_root());
        b.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
        assert_eq!(a.state_root(), b.state_root());
        // proposer received 0 fee -> pruned; identical to a ledger without that entry
        let mut c = Ledger::new(1);
        c.credit(alice.address(), 1_000).unwrap();
        c.apply_tx(&tx, &key(9).address(), &StubExecutor).unwrap();
        assert_eq!(a.state_root(), c.state_root());
        assert_eq!(Ledger::new(1).state_root(), Ledger::new(1).state_root());
        assert_ne!(Ledger::new(1).state_root(), a.state_root());
    }

    // ---- bridge -----------------------------------------------------------

    /// Six guardian secrets, emitter `[1; 32]`, and chains 2..5 registered as
    /// `{2: [2; 32], .., 5: [5; 32]}` — the same shape as the `bridge::state`
    /// tests, so `transfer_body` bodies verify.
    fn bridge_cfg() -> (BridgeConfig, Vec<[u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (1u8..=6).map(|i| [i; 32]).collect();
        let config = BridgeConfig {
            emitter: [1; 32],
            guardians: secrets.iter().map(guardian_address).collect(),
            emitters: (2u16..=5).map(|c| (c, [c as u8; 32])).collect(),
        };
        (config, secrets)
    }

    /// `funded()` plus a bridge section: `alice` (`key(1)`) is the recipient
    /// of every `transfer_body`, and the returned secrets sign attestations.
    fn bridged() -> (Ledger, Vec<[u8; 32]>, Keypair, Address) {
        let (config, secrets) = bridge_cfg();
        let alice = key(1);
        let proposer = key(3).address();
        let mut l = Ledger::new(1);
        l.credit(alice.address(), 1_000).unwrap();
        l.set_bridge(Some(BridgeState::from_config(&config)));
        (l, secrets, alice, proposer)
    }

    /// Signs `body` with the first five secrets (quorum for a set of six).
    fn attest(secrets: &[[u8; 32]], set_index: u32, body: Body) -> Vec<u8> {
        let d = digest(&body.encode());
        let signatures = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
        Attestation { guardian_set_index: set_index, signatures, body }.encode()
    }

    /// A transfer of `amount` (bridge fee `fee`) of token `[0xaa; 32]` native
    /// to `emitter_chain`, emitted by that chain's registered emitter, to
    /// `key(1)` on `to_chain`.
    fn transfer_body(emitter_chain: u16, amount: u128, fee: u128, to_chain: u16) -> Body {
        Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain,
            emitter_address: [emitter_chain as u8; 32],
            sequence: 0,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: [0xaa; 32],
                token_chain: emitter_chain,
                to: key(1).address().0,
                to_chain,
                fee: Transfer::u256_from_u128(fee),
            })
            .encode(),
        }
    }

    #[test]
    fn bridge_attest_mints_and_burn_emits() {
        let (mut l, s, alice, proposer) = bridged();
        let att = attest(&s, 0, transfer_body(2, 1_000, 10, CHAIN_RAND)); // to = alice
        let tx = Transaction::bridge_attest(&alice, 1, 0, att, 1);
        l.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
        let asset = asset_id(2, &[0xaa; 32]);
        // 990 net to the recipient + the 10 bridge fee to the submitter (both alice)
        assert_eq!(l.asset_balance(&asset, &alice.address()), 1_000);
        assert_eq!(l.balance(&alice.address()), 999);
        assert_eq!(l.balance(&proposer), 1);
        assert_eq!(l.nonce(&alice.address()), 1);

        let burn = Transaction::bridge_burn(&alice, 1, 1, asset, 400, 2, [0x22; 32], 5, 1);
        l.set_timestamp_ms(1_700_000);
        l.apply_tx(&burn, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.asset_balance(&asset, &alice.address()), 600);
        assert_eq!(l.balance(&alice.address()), 998);
        let rec = &l.bridge().unwrap().burns[&0];
        assert_eq!(rec.tx, burn.hash());
        assert_eq!(rec.height, 0);
        // the burn message carries the block time in unix seconds
        assert_eq!(Body::decode(&rec.body).unwrap().timestamp, 1_700);
    }

    #[test]
    fn bridge_burn_rejections_leave_the_bridge_untouched() {
        let (mut l, s, alice, proposer) = bridged();
        l.apply_tx(
            &Transaction::bridge_attest(&alice, 1, 0, attest(&s, 0, transfer_body(2, 1_000, 0, CHAIN_RAND)), 0),
            &proposer,
            &StubExecutor,
        )
        .unwrap();
        let asset = asset_id(2, &[0xaa; 32]);
        let before = l.bridge().unwrap().clone();
        let unknown = Transaction::bridge_burn(&alice, 1, 1, Hash::digest(b"nope"), 1, 2, [0x22; 32], 0, 0);
        assert_eq!(l.validate(&unknown, &StubExecutor), Err(TxError::Bridge(BridgeError::UnknownAsset)));
        let too_much = Transaction::bridge_burn(&alice, 1, 1, asset, 1_001, 2, [0x22; 32], 0, 0);
        assert_eq!(
            l.apply_tx(&too_much, &proposer, &StubExecutor),
            Err(TxError::Bridge(BridgeError::InsufficientAsset { have: 1_000, need: 1_001 }))
        );
        let wrong_chain = Transaction::bridge_burn(&alice, 1, 1, asset, 1, 3, [0x22; 32], 0, 0);
        assert_eq!(
            l.apply_tx(&wrong_chain, &proposer, &StubExecutor),
            Err(TxError::Bridge(BridgeError::WrongTokenChain))
        );
        assert_eq!(l.bridge().unwrap(), &before);
        assert_eq!(l.nonce(&alice.address()), 1);
    }

    #[test]
    fn state_root_unchanged_without_bridge_and_covers_bridge_with() {
        let (a, ..) = funded();
        let mut b = a.clone();
        b.set_bridge(None);
        assert_eq!(a.state_root(), b.state_root());
        let (mut l, s, alice, proposer) = bridged();
        let before = l.state_root();
        l.apply_tx(
            &Transaction::bridge_attest(&alice, 1, 0, attest(&s, 0, transfer_body(2, 1, 0, CHAIN_RAND)), 0),
            &proposer,
            &StubExecutor,
        )
        .unwrap();
        assert_ne!(l.state_root(), before);
        // and a bridge section is state: the same accounts with and without it differ
        let (c, ..) = funded();
        let mut d = c.clone();
        d.set_bridge(Some(BridgeState::from_config(&bridge_cfg().0)));
        assert_ne!(c.state_root(), d.state_root());
    }

    /// An empty block on top of `ledger` at `height`, carrying `timestamp_ms`.
    fn empty_block(ledger: &Ledger, key: &Keypair, height: u64, timestamp_ms: u64) -> Block {
        use crate::types::{BlockHeader, QuorumCertificate};
        let header = BlockHeader {
            height,
            view: height,
            parent: Hash::ZERO,
            proposer: key.public_key().clone(),
            timestamp_ms,
            tx_root: Block::tx_root(&[]),
            state_root: ledger.state_root(),
            justify: QuorumCertificate::genesis(Hash::ZERO),
        };
        Block::sign(header, Vec::new(), key)
    }

    /// A bridged chain's block time is consensus input, so it may not move
    /// backwards; a chain without a bridge keeps the older, weaker rule.
    #[test]
    fn block_timestamp_may_not_rewind_on_a_bridged_chain() {
        let proposer = key(3);
        let (mut l, ..) = bridged();
        l.set_timestamp_ms(1_000_000);
        assert_eq!(
            l.apply_block(&empty_block(&l, &proposer, 1, 999_999), &StubExecutor),
            Err(BlockError::TimestampRewind { parent: 1_000_000, block: 999_999 })
        );
        // equal is allowed (the rule is non-strict), and so is moving forward
        l.apply_block(&empty_block(&l, &proposer, 1, 1_000_000), &StubExecutor).unwrap();
        l.apply_block(&empty_block(&l, &proposer, 2, 1_000_001), &StubExecutor).unwrap();
        assert_eq!(
            l.apply_block(&empty_block(&l, &proposer, 3, 1_000_000), &StubExecutor),
            Err(BlockError::TimestampRewind { parent: 1_000_001, block: 1_000_000 })
        );
        // ... and a chain without a bridge accepts the very same rewind
        let (mut plain, ..) = funded();
        plain.set_timestamp_ms(1_000_000);
        plain.apply_block(&empty_block(&plain, &proposer, 1, 999_999), &StubExecutor).unwrap();
    }

    fn hex_array<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).expect("hex").try_into().expect("width")
    }

    /// Cross-checks the ledger-level `expect` values of the shared
    /// `tools/vectors` fixture (Task B1) through a real `BridgeAttest`
    /// transaction. The signature-level ones are covered in `bridge::tests`.
    #[test]
    fn vectors_ledger_level() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("bridge/vectors.json")).expect("vectors.json parses");
        let now = file["now"].as_u64().expect("now");
        let config = BridgeConfig {
            emitter: hex_array(file["rand_emitter"].as_str().expect("rand_emitter")),
            guardians: file["guardians"]
                .as_array()
                .expect("guardians")
                .iter()
                .map(|g| hex_array::<20>(g["address"].as_str().expect("address")))
                .collect(),
            emitters: file["emitters"]
                .as_object()
                .expect("emitters")
                .iter()
                .map(|(chain, addr)| (chain.parse().expect("chain id"), hex_array(addr.as_str().expect("hex"))))
                .collect(),
        };
        const LEDGER_LEVEL: &[&str] = &[
            "ok",
            "wrong_emitter",
            "wrong_to_chain",
            "wrong_token_chain",
            "fee_exceeds_amount",
            "amount_overflow",
            "bad_payload",
            "replay",
            "unknown_set",
            "set_expired",
        ];
        let vectors = file["vectors"].as_array().expect("vectors array");
        let attestation_of = |v: &serde_json::Value| hex::decode(v["attestation"].as_str().expect("attestation")).expect("hex");
        let alice = key(1);
        let proposer = key(3).address();
        let mut checked = 0usize;
        for v in vectors {
            let name = v["name"].as_str().expect("name");
            let expect = v["expect"].as_str().expect("expect");
            if !LEDGER_LEVEL.contains(&expect) || v["verifier_chain"].as_u64().expect("verifier_chain") != 1 {
                continue;
            }
            checked += 1;

            // A fresh ledger per vector, carrying that vector's guardian sets
            // (the upgrade/grace series needs sets other than 0 installed).
            let mut bridge = BridgeState::from_config(&config);
            for set in v["sets"].as_array().expect("sets") {
                let keys: Vec<GuardianKey> = set["keys"]
                    .as_array()
                    .expect("keys")
                    .iter()
                    .map(|k| hex_array::<20>(k.as_str().expect("key hex")))
                    .collect();
                bridge.guardian_sets.insert(
                    set["index"].as_u64().expect("index") as u32,
                    GuardianSet { keys, expires_at: set["expires_at"].as_u64().expect("expires_at") },
                );
            }
            bridge.current_set = v["current_set"].as_u64().expect("current_set") as u32;
            let mut l = Ledger::new(1);
            l.credit(alice.address(), 1_000).unwrap();
            l.set_bridge(Some(bridge));
            l.set_timestamp_ms(now * 1_000);

            // A `replay` vector is the second submission of another vector.
            let mut nonce = 0;
            if let Some(prior) = v["replay_of"].as_str() {
                let first = vectors
                    .iter()
                    .find(|o| o["name"].as_str() == Some(prior))
                    .unwrap_or_else(|| panic!("{name}: replay_of {prior} is not in the file"));
                let tx = Transaction::bridge_attest(&alice, 1, nonce, attestation_of(first), 0);
                l.apply_tx(&tx, &proposer, &StubExecutor)
                    .unwrap_or_else(|e| panic!("{name}: replay_of {prior} did not apply: {e}"));
                nonce += 1;
            }

            let tx = Transaction::bridge_attest(&alice, 1, nonce, attestation_of(v), 0);
            let got = l.apply_tx(&tx, &proposer, &StubExecutor);
            let want = match expect {
                "ok" => {
                    got.unwrap_or_else(|e| panic!("{name}: expected ok, got {e:?}"));
                    assert_eq!(l.nonce(&alice.address()), nonce + 1, "{name}");
                    continue;
                }
                "wrong_emitter" => BridgeError::WrongEmitter,
                "wrong_to_chain" => BridgeError::WrongToChain,
                "wrong_token_chain" => BridgeError::WrongTokenChain,
                "fee_exceeds_amount" => BridgeError::FeeExceedsAmount,
                "amount_overflow" => BridgeError::AmountOverflow,
                "bad_payload" => BridgeError::BadPayload,
                "replay" => BridgeError::Replay,
                "set_expired" => BridgeError::Verify(VerifyError::SetExpired),
                "unknown_set" => BridgeError::Verify(VerifyError::UnknownGuardianSet(
                    v["guardian_set_index"].as_u64().expect("guardian_set_index") as u32,
                )),
                other => panic!("{name}: unhandled expect {other}"),
            };
            assert_eq!(got, Err(TxError::Bridge(want)), "{name}");
            // a rejected attestation costs the sender nothing
            assert_eq!(l.nonce(&alice.address()), nonce, "{name}");
        }
        // Exact: a vector that stops matching (a renamed `expect`, a changed
        // `verifier_chain`) must fail here rather than quietly go unchecked.
        assert_eq!(checked, 19, "expected 19 ledger-level vectors on chain 1");
    }
}
