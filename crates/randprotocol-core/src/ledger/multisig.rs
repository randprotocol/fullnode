//! Multisig accounts (`docs/superpowers/specs/2026-10-08-multisig-design.md`): a public,
//! threshold-controlled RAND (and token) account that pays into the shielded pool.
//!
//! An account is a set of 1..=[`MAX_SIGNERS`] Dilithium2 keys and a threshold. Its id is derived
//! from the chain, a salt, the threshold and the signer list ([`account_id`]), so the same
//! signers can hold several accounts and an id can be computed before the account exists. The
//! account holds a public per-asset vault; a payment (signed by `threshold` signers) moves vault
//! value into shielded notes, a deposit burns shielded value into the vault.
//!
//! Genesis-gated: a chain whose genesis has no `multisig` section has no register, and the
//! multisig actions are refused. An empty section switches the module on with no accounts.
//!
//! This file holds the config, the id, the register and its root, then the rules of the four
//! actions (create, deposit, pay, rotate) and `still_applies`, the pool's selection-time re-check.

use crate::crypto::{merkle_root, Hash, PublicKey, PUBLIC_KEY_LEN};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Most signers an account lists.
pub const MAX_SIGNERS: usize = 10;
/// Largest `create_fee` a genesis may set (1 000 RAND).
pub const MAX_CREATE_FEE: u64 = 1_000 * crate::types::UNITS_PER_RAND;
/// Most payouts one `MultisigPay` carries: the program-state cap.
pub const MAX_PAYOUTS: usize = super::program_state::MAX_PAYOUTS;

/// One account as the genesis file lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultisigAccountConfig {
    /// 32 bytes, 64 hex characters; makes the id unique per account over the same signers.
    #[serde(with = "crate::bridge::state::hex_bytes32")]
    pub salt: [u8; 32],
    pub signers: Vec<PublicKey>,
    pub threshold: u8,
    /// Opening RAND balance of the vault, in base units (a decimal string in the file).
    #[serde(with = "crate::ledger::staking::amount_string")]
    pub balance: u64,
}

/// The genesis `multisig` section.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultisigConfig {
    /// Extra fee a `CreateMultisig` pays on top of the bundle base, burned.
    #[serde(default, with = "crate::ledger::staking::amount_string")]
    pub create_fee: u64,
    #[serde(default)]
    pub accounts: Vec<MultisigAccountConfig>,
}

impl MultisigConfig {
    /// Every rule a genesis section must meet; returns the sum of the opening balances (the RAND
    /// the register is issued with, which the genesis supply check must account for).
    pub fn check(&self, chain_id: u64) -> Result<u64, String> {
        if self.create_fee > MAX_CREATE_FEE {
            return Err(format!("multisig create_fee {} exceeds the maximum {MAX_CREATE_FEE}", self.create_fee));
        }
        let mut total = 0u64;
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(self.accounts.len());
        for (i, a) in self.accounts.iter().enumerate() {
            check_signers(&a.signers, a.threshold).map_err(|e| format!("account {i}: {e}"))?;
            let id = a.id(chain_id);
            if seen.contains(&id) {
                return Err(format!("account {i}: already listed (same id)"));
            }
            seen.push(id);
            total = total.checked_add(a.balance).ok_or_else(|| "multisig balances overflow".to_string())?;
        }
        Ok(total)
    }
}

impl MultisigAccountConfig {
    pub fn id(&self, chain_id: u64) -> [u8; 32] {
        account_id(chain_id, &self.salt, self.threshold, &self.signers)
    }
}

/// The rules on a signer set and threshold, shared by genesis, creation and rotation.
pub fn check_signers(signers: &[PublicKey], threshold: u8) -> Result<(), String> {
    if signers.is_empty() || signers.len() > MAX_SIGNERS {
        return Err(format!("{} signers, an account has 1..=10 signers", signers.len()));
    }
    for (i, k) in signers.iter().enumerate() {
        if k.as_bytes().len() != PUBLIC_KEY_LEN {
            return Err(format!("signer {i} is not a Dilithium2 public key"));
        }
        if signers[..i].contains(k) {
            return Err(format!("signer {i} is listed twice"));
        }
    }
    if threshold == 0 || threshold as usize > signers.len() {
        return Err(format!("threshold {threshold} is outside 1..={}", signers.len()));
    }
    Ok(())
}

/// `blake3("rand-multisig-id-1", chain_id ‖ salt ‖ threshold ‖ n ‖ keys)`. Order of the signers
/// matters: a signature names its signer by position.
pub fn account_id(chain_id: u64, salt: &[u8; 32], threshold: u8, signers: &[PublicKey]) -> [u8; 32] {
    let mut b = Vec::with_capacity(42 + signers.len() * PUBLIC_KEY_LEN);
    b.extend_from_slice(&chain_id.to_be_bytes());
    b.extend_from_slice(salt);
    b.push(threshold);
    b.push(signers.len() as u8);
    for k in signers {
        b.extend_from_slice(k.as_bytes());
    }
    Hash::digest_domain(b"rand-multisig-id-1", &b).0
}

/// One live account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub signers: Vec<PublicKey>,
    pub threshold: u8,
    /// Replay counter shared by pay and rotate.
    pub nonce: u64,
    /// Asset id to amount; a zero row is never stored, so absent has one encoding.
    pub vault: BTreeMap<u32, u64>,
}

impl Account {
    pub fn balance(&self, asset: u32) -> u64 {
        self.vault.get(&asset).copied().unwrap_or(0)
    }

    /// `id ‖ threshold ‖ n ‖ keys ‖ nonce ‖ rows ‖ (asset, amount)*` under `rand-multisig-leaf-1`,
    /// every field fixed-width.
    pub fn leaf(&self, id: &[u8; 32]) -> Hash {
        let mut b = Vec::with_capacity(32 + 2 + self.signers.len() * PUBLIC_KEY_LEN + 12 + self.vault.len() * 12);
        b.extend_from_slice(id);
        b.push(self.threshold);
        b.push(self.signers.len() as u8);
        for k in &self.signers {
            b.extend_from_slice(k.as_bytes());
        }
        b.extend_from_slice(&self.nonce.to_be_bytes());
        b.extend_from_slice(&(self.vault.len() as u32).to_be_bytes());
        for (asset, amount) in &self.vault {
            b.extend_from_slice(&asset.to_be_bytes());
            b.extend_from_slice(&amount.to_be_bytes());
        }
        Hash::digest_domain(b"rand-multisig-leaf-1", &b)
    }

    pub(super) fn set_balance(&mut self, asset: u32, amount: u64) {
        if amount == 0 {
            self.vault.remove(&asset);
        } else {
            self.vault.insert(asset, amount);
        }
    }
}

/// Every account, plus the running totals that let the supply identity be checked without
/// walking the accounts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigRegister {
    accounts: BTreeMap<[u8; 32], Account>,
    pub create_fee: u64,
    /// RAND the genesis opened the vaults with.
    pub issued: u64,
    /// RAND deposited into vaults / paid out of them / burned as base fees since genesis.
    pub rand_in: u64,
    pub rand_out: u64,
    pub base_out: u64,
}

impl MultisigRegister {
    pub fn from_config(c: &MultisigConfig, chain_id: u64) -> MultisigRegister {
        let mut r = MultisigRegister { create_fee: c.create_fee, ..Default::default() };
        for a in &c.accounts {
            let mut acct = Account { signers: a.signers.clone(), threshold: a.threshold, nonce: 0, vault: BTreeMap::new() };
            acct.set_balance(0, a.balance);
            r.issued = r.issued.saturating_add(a.balance);
            r.accounts.insert(a.id(chain_id), acct);
        }
        r
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&Account> {
        self.accounts.get(id)
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Every account with its id, in id order (the order the root and the genesis commit use;
    /// `rand-node genesis` prints the seeded accounts this way).
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &Account)> {
        self.accounts.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// RAND the vaults should hold: issued + deposited − paid out − base fees, saturating.
    pub fn rand_held(&self) -> u64 {
        self.issued.saturating_add(self.rand_in).saturating_sub(self.rand_out).saturating_sub(self.base_out)
    }

    /// `blake3("rand-multisig-root-1", merkle_root(leaves in id order) ‖ count ‖ create_fee ‖
    /// issued ‖ rand_in ‖ rand_out ‖ base_out)`, the integers 8-byte big-endian.
    pub fn root(&self) -> Hash {
        let leaves: Vec<Hash> = self.accounts.iter().map(|(id, a)| a.leaf(id)).collect();
        let mut b = merkle_root(&leaves).as_bytes().to_vec();
        b.extend_from_slice(&(self.accounts.len() as u64).to_be_bytes());
        for v in [self.create_fee, self.issued, self.rand_in, self.rand_out, self.base_out] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        Hash::digest_domain(b"rand-multisig-root-1", &b)
    }

    pub(super) fn get_mut(&mut self, id: &[u8; 32]) -> Option<&mut Account> {
        self.accounts.get_mut(id)
    }

    pub(super) fn insert(&mut self, id: [u8; 32], a: Account) {
        self.accounts.insert(id, a);
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum MultisigError {
    #[error("unknown multisig account {0}")]
    UnknownAccount(String),
    #[error("multisig account {0} already exists")]
    AccountExists(String),
    #[error("bad signer set: {0}")]
    BadSigners(String),
    #[error("nonce {actual}, the account is at {expected}")]
    BadNonce { expected: u64, actual: u64 },
    #[error("{have} signatures, the account needs {need}")]
    BelowThreshold { have: usize, need: usize },
    #[error("signer index {0} is outside the account's list")]
    BadSignerIndex(u8),
    #[error("signer {0} signed twice")]
    DuplicateSigner(u8),
    #[error("signature {0} does not verify")]
    BadSignature(u8),
    #[error("the account holds {have} of asset {asset}, the action needs {want}")]
    VaultShort { asset: u32, have: u64, want: u64 },
    #[error("a payment pays nobody")]
    NoPayouts,
    #[error("{0} payouts, at most {MAX_PAYOUTS}")]
    TooManyPayouts(usize),
    #[error("a payout of zero")]
    ZeroPayout,
    #[error("a deposit that burns nothing")]
    EmptyDeposit,
    #[error("overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::notes::{Envelope, ShieldedAddress};
    use crate::types::actions::{multisig_pay_message, multisig_rotate_message};

    fn key(seed: u8) -> PublicKey { Keypair::from_seed([seed; 32]).unwrap().public_key().clone() }
    fn cfg(n: usize, threshold: u8, balance: u64) -> MultisigAccountConfig {
        MultisigAccountConfig { salt: [7; 32], signers: (1..=n as u8).map(key).collect(), threshold, balance }
    }

    #[test]
    fn the_config_rules_are_each_refused() {
        let ok = MultisigConfig { create_fee: 0, accounts: vec![cfg(3, 2, 100)] };
        assert_eq!(ok.check(20), Ok(100));
        let bad = |f: &dyn Fn(&mut MultisigConfig), why: &str| {
            let mut c = ok.clone(); f(&mut c);
            let e = c.check(20).unwrap_err(); assert!(e.contains(why), "{e:?} should mention {why}");
        };
        bad(&|c| c.accounts[0].signers.clear(), "1..=10 signers");
        bad(&|c| c.accounts[0].signers = (1..=11).map(key).collect(), "1..=10 signers");
        bad(&|c| c.accounts[0].signers[1] = key(1), "listed twice");
        bad(&|c| c.accounts[0].threshold = 0, "threshold");
        bad(&|c| c.accounts[0].threshold = 4, "threshold");
        bad(&|c| c.accounts.push(cfg(3, 2, 1)), "already"); // same salt+signers+threshold = same id
        bad(&|c| c.create_fee = MAX_CREATE_FEE + 1, "create_fee");
        bad(&|c| { c.accounts.push(cfg(3, 2, u64::MAX)); c.accounts[1].salt = [8; 32]; }, "overflow");
        assert_eq!(MultisigConfig::default().check(20), Ok(0), "an empty section switches the module on");
    }

    #[test]
    fn the_id_binds_every_input() {
        let a = cfg(3, 2, 0);
        let base = a.id(20);
        assert_ne!(base, a.id(21), "chain id");
        assert_ne!(base, MultisigAccountConfig { salt: [8; 32], ..a.clone() }.id(20), "salt");
        assert_ne!(base, MultisigAccountConfig { threshold: 3, ..a.clone() }.id(20), "threshold");
        let mut swapped = a.clone(); swapped.signers.swap(0, 1);
        assert_ne!(base, swapped.id(20), "signer order");
        assert_eq!(base, account_id(20, &a.salt, a.threshold, &a.signers));
        // Known-answer vector. A consensus encoding: the CLI's `multisig id` and every node must
        // reproduce these bytes exactly.
        assert_eq!(hex::encode(account_id(20, &[7; 32], 2, &[key(1), key(2), key(3)])), "fedc03921236f89e18ffe73a692892e18fb1d7198db3d19e2d9ce31828f4da7c");
    }

    #[test]
    fn the_register_root_moves_with_every_field_and_a_zero_row_disappears() {
        let c = MultisigConfig { create_fee: 5, accounts: vec![cfg(3, 2, 100)] };
        let reg = MultisigRegister::from_config(&c, 20);
        let id = c.accounts[0].id(20);
        assert_eq!(reg.get(&id).unwrap().balance(0), 100);
        assert_eq!((reg.issued, reg.rand_held()), (100, 100));
        let r0 = reg.root();
        let m = |f: &dyn Fn(&mut MultisigRegister)| { let mut r = reg.clone(); f(&mut r); assert_ne!(r.root(), r0); };
        m(&|r| r.get_mut(&id).unwrap().nonce += 1);
        m(&|r| r.get_mut(&id).unwrap().threshold = 3);
        m(&|r| r.get_mut(&id).unwrap().signers.swap(0, 1));
        m(&|r| r.get_mut(&id).unwrap().set_balance(2, 1));
        m(&|r| r.create_fee = 6);
        m(&|r| r.rand_in = 1);
        m(&|r| r.base_out = 1);
        let mut r = reg.clone();
        r.get_mut(&id).unwrap().set_balance(0, 0);
        assert!(r.get(&id).unwrap().vault.is_empty(), "a zero row is removed, so absent has one encoding");
        // Known-answer vector for the register root: a consensus encoding every node must reproduce.
        assert_eq!(hex::encode(reg.root().as_bytes()), "d143907c34caa45ea340472dc5a51ef9c45422b2a80e2837743eb6005dff4fb9");
        let mut full = reg.clone();
        full.issued = 100; full.rand_in = 50; full.rand_out = 30; full.base_out = 5;
        assert_eq!(full.rand_held(), 100 + 50 - 30 - 5);
        m(&|r| r.rand_out = 1);
        assert_eq!(MultisigRegister::default().root(), MultisigRegister::from_config(&MultisigConfig::default(), 20).root());
    }

    #[test]
    fn the_messages_bind_every_field_under_distinct_domains() {
        let g = Hash::digest_domain(b"t", b"g");
        let pays = vec![crate::ledger::program_state::Payout { asset: 0, amount: 5, recipient: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; crate::notes::KEM_EK_BYTES] }, r: [3; 8], envelope: Envelope { kem_ct: vec![1], to_receiver: vec![2], to_sender: vec![3], body: vec![4] } }];
        let p = multisig_pay_message(&g, 20, &[9; 32], 0, 7, &pays);
        assert_ne!(p, multisig_pay_message(&g, 21, &[9; 32], 0, 7, &pays));
        assert_ne!(p, multisig_pay_message(&g, 20, &[8; 32], 0, 7, &pays));
        assert_ne!(p, multisig_pay_message(&g, 20, &[9; 32], 1, 7, &pays));
        assert_ne!(p, multisig_pay_message(&g, 20, &[9; 32], 0, 8, &pays));
        let g2 = Hash::digest_domain(b"t", b"g2");
        assert_ne!(p, multisig_pay_message(&g2, 20, &[9; 32], 0, 7, &pays), "genesis");
        let mut other = pays.clone(); other[0].amount = 6;
        assert_ne!(p, multisig_pay_message(&g, 20, &[9; 32], 0, 7, &other));
        let r = multisig_rotate_message(&g, 20, &[9; 32], 0, &[key(1)], 1);
        assert_ne!(r, multisig_rotate_message(&g, 20, &[9; 32], 0, &[key(2)], 1));
        assert_ne!(r, multisig_rotate_message(&g, 20, &[9; 32], 0, &[key(1), key(2)], 1));
        assert_ne!(r, multisig_rotate_message(&g, 20, &[9; 32], 0, &[key(1)], 2));
        assert_ne!(r, multisig_rotate_message(&g2, 20, &[9; 32], 0, &[key(1)], 1), "genesis");
    }
}

// ------------------------------------------------------------------ the four actions

use super::program_state::{payout_commitment, Payout, ProgramStateError};
use super::tokens::{self, TokenError};
use super::{Ledger, TxError};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::Address;
use crate::gas;
use crate::notes::{Bundle, Word8, MAX_NOTE_VALUE};
use crate::types::actions::{multisig_pay_message, multisig_rotate_message, SignerSignature};
use crate::types::{Action, Transaction};

/// What every multisig action gets on a chain without the section: the gate is absolute
/// (vesting's `NOT_VESTING`, one register over).
const NOT_MULTISIG: TxError = TxError::UnsupportedAction("multisig");

/// The extra fee a `CreateMultisig` owes on top of the bundle base: 0 without the section.
pub(super) fn create_fee_of(ledger: &Ledger) -> u64 {
    ledger.multisig().map_or(0, |r| r.create_fee)
}

fn account<'a>(ledger: &'a Ledger, id: &[u8; 32]) -> Result<&'a Account, TxError> {
    let reg = ledger.multisig().ok_or(NOT_MULTISIG)?;
    reg.get(id).ok_or_else(|| MultisigError::UnknownAccount(hex::encode(id)).into())
}

fn check_nonce(a: &Account, nonce: u64) -> Result<(), MultisigError> {
    if nonce != a.nonce {
        return Err(MultisigError::BadNonce { expected: a.nonce, actual: nonce });
    }
    Ok(())
}

/// The shape of a signature list against the account's current signers, before any signature
/// is verified: every index in the list, no signer twice, at least `threshold` of them. All of it
/// is the transaction's bytes against the account's set.
fn check_signer_set(a: &Account, signatures: &[SignerSignature]) -> Result<(), MultisigError> {
    // `MAX_SIGNERS` is 10, so an index that passed the bound fits a u16 mask; a list longer than
    // the signers necessarily trips the bound or the mask.
    let mut seen = 0u16;
    for s in signatures {
        if s.index as usize >= a.signers.len() {
            return Err(MultisigError::BadSignerIndex(s.index));
        }
        if seen & (1 << s.index) != 0 {
            return Err(MultisigError::DuplicateSigner(s.index));
        }
        seen |= 1 << s.index;
    }
    if signatures.len() < a.threshold as usize {
        return Err(MultisigError::BelowThreshold { have: signatures.len(), need: a.threshold as usize });
    }
    Ok(())
}

/// Every listed signature must verify: `check_signer_set` counted the list, so one bad signature
/// among enough good ones is a refusal, not a smaller quorum.
fn check_signatures(a: &Account, msg: &crate::crypto::Hash, signatures: &[SignerSignature]) -> Result<(), MultisigError> {
    for s in signatures {
        if !a.signers[s.index as usize].verify(msg.as_bytes(), &s.signature) {
            return Err(MultisigError::BadSignature(s.index));
        }
    }
    Ok(())
}

/// The rows a create's or a deposit's bundle credits: `burn_r` into row 0, `burn_a` into the
/// `burn_asset` row, which must be a registered token (any authority, as a program vault
/// accepts a bridged token). RAND never arrives through `burn_a` — `check_burn_shape` refuses
/// it (`NonCanonicalRandBurn`). Returns the rows after the credit.
fn credit(ledger: &Ledger, current: Option<&Account>, b: &Bundle) -> Result<Vec<(u32, u64)>, TxError> {
    let have = |asset: u32| current.map_or(0, |a| a.balance(asset));
    let mut rows = Vec::with_capacity(2);
    if b.burn_r != 0 {
        rows.push((0, have(0).checked_add(b.burn_r).ok_or(MultisigError::Overflow)?));
    }
    if b.burn_a != 0 {
        ledger.tokens().and_then(|t| t.get(b.burn_asset)).ok_or(TokenError::UnknownToken(b.burn_asset))?;
        rows.push((b.burn_asset, have(b.burn_asset).checked_add(b.burn_a).ok_or(MultisigError::Overflow)?));
    }
    Ok(rows)
}

/// A pay's byte rules on each payout (the count was capped by `validate_inner`): non-zero, under
/// the note bound — the program-state payout rule, so a note at or above 2^63 is refused as there
/// — and a recipient a note can be sealed to.
fn check_payouts(ledger: &Ledger, pays: &[Payout]) -> Result<(), TxError> {
    for p in pays {
        if p.amount == 0 {
            return Err(MultisigError::ZeroPayout.into());
        }
        if p.amount >= MAX_NOTE_VALUE {
            return Err(ProgramStateError::PayoutTooLarge(p.amount).into());
        }
        tokens::check_recipient(&p.recipient)?;
        if p.asset != 0 {
            ledger.tokens().and_then(|t| t.get(p.asset)).ok_or(TokenError::UnknownToken(p.asset))?;
        }
    }
    Ok(())
}

/// The rows a pay leaves and the RAND it pays out as notes. Row 0 covers the base and every RAND
/// payout — so an account needs the base in RAND to pay anything, tokens included — and every
/// other row covers the sum of its payouts.
fn pay_moves(a: &Account, pays: &[Payout]) -> Result<(Vec<(u32, u64)>, u64), MultisigError> {
    let mut want: BTreeMap<u32, u64> = BTreeMap::new();
    want.insert(0, gas::BUNDLE_BASE);
    for p in pays {
        let w = want.entry(p.asset).or_insert(0);
        *w = w.checked_add(p.amount).ok_or(MultisigError::Overflow)?;
    }
    let mut rows = Vec::with_capacity(want.len());
    for (asset, want) in want {
        let have = a.balance(asset);
        rows.push((asset, have.checked_sub(want).ok_or(MultisigError::VaultShort { asset, have, want })?));
    }
    let rand_out = pays.iter().filter(|p| p.asset == 0).map(|p| p.amount).sum();
    Ok((rows, rand_out))
}

/// The state half of a pay's rules (account, nonce, rows), shared with [`still_applies`].
fn check_pay_state<'a>(ledger: &'a Ledger, id: &[u8; 32], nonce: u64, pays: &[Payout]) -> Result<&'a Account, TxError> {
    let a = account(ledger, id)?;
    check_nonce(a, nonce)?;
    pay_moves(a, pays)?;
    Ok(a)
}

/// A pay's rules, cheap before expensive: the payouts' bytes, the signature list's shape, the
/// nonce and the rows, then the signatures, then the payout notes (hashes) last.
#[allow(clippy::too_many_arguments)]
fn check_pay(
    ledger: &Ledger,
    chain_id: u64,
    id: &[u8; 32],
    nonce: u64,
    time: u32,
    pays: &[Payout],
    signatures: &[SignerSignature],
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    check_payouts(ledger, pays)?;
    let a = account(ledger, id)?;
    check_signer_set(a, signatures)?;
    check_pay_state(ledger, id, nonce, pays)?;
    let msg = multisig_pay_message(&ledger.signing_domain().genesis, chain_id, id, nonce, time, pays);
    check_signatures(a, &msg, signatures)?;
    let mut seen: Vec<Word8> = Vec::with_capacity(pays.len());
    for p in pays {
        let cm = payout_commitment(p, time, executor);
        if ledger.has_commitment(&cm) || seen.contains(&cm) {
            return Err(TxError::CommitmentExists(cm));
        }
        seen.push(cm);
    }
    Ok(())
}

/// Admission for the four multisig actions: the gate, then each action's rules — cheap bytes
/// first, state next, signatures last. Nothing is written.
pub(super) fn validate(
    ledger: &Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    let reg = ledger.multisig().ok_or(NOT_MULTISIG)?;
    match action {
        Action::CreateMultisig { salt, signers, threshold } => {
            check_signers(signers, *threshold).map_err(MultisigError::BadSigners)?;
            let id = account_id(tx.chain_id, salt, *threshold, signers);
            if reg.get(&id).is_some() {
                return Err(MultisigError::AccountExists(hex::encode(id)).into());
            }
            let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
            credit(ledger, None, b)?;
            // The floor beyond the common path's `BUNDLE_BASE` (R2): the create fee is paid to
            // the proposer with the rest of the fee, so the supply identity does not move.
            let min = gas::BUNDLE_BASE.saturating_add(create_fee_of(ledger));
            if tx.fee() < min {
                return Err(TxError::FeeTooLow { min, fee: tx.fee() });
            }
        }
        Action::MultisigDeposit { account: id } => {
            let a = account(ledger, id)?;
            let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
            if b.burn_r == 0 && b.burn_a == 0 {
                return Err(MultisigError::EmptyDeposit.into());
            }
            credit(ledger, Some(a), b)?;
        }
        Action::MultisigPay { account: id, nonce, time, pays, signatures } => {
            check_pay(ledger, tx.chain_id, id, *nonce, *time, pays, signatures, executor)?;
        }
        Action::MultisigRotate { account: id, nonce, signers, threshold, signatures } => {
            let a = account(ledger, id)?;
            check_signers(signers, *threshold).map_err(MultisigError::BadSigners)?;
            // The current set signs its own replacement.
            check_signer_set(a, signatures)?;
            check_nonce(a, *nonce)?;
            let msg = multisig_rotate_message(&ledger.signing_domain().genesis, tx.chain_id, id, *nonce, signers, *threshold);
            check_signatures(a, &msg, signatures)?;
        }
        _ => return Err(NOT_MULTISIG),
    }
    Ok(())
}

/// The apply step, in lockstep with [`validate`]: every rule re-run, everything that can fail
/// worked out before the first write (the gate included, so a ledger without the section is
/// refused untouched).
pub(super) fn apply(
    ledger: &mut Ledger,
    tx: &Transaction,
    action: &Action,
    proposer: &Address,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    validate(ledger, tx, action, executor)?;
    match action {
        Action::CreateMultisig { salt, signers, threshold } => {
            let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
            let rows = credit(ledger, None, b)?;
            let reg = ledger.multisig_mut().ok_or(NOT_MULTISIG)?;
            let rand_in = reg.rand_in.checked_add(b.burn_r).ok_or(MultisigError::Overflow)?;
            let mut a = Account { signers: signers.clone(), threshold: *threshold, nonce: 0, vault: BTreeMap::new() };
            for (asset, amount) in rows {
                a.set_balance(asset, amount);
            }
            reg.insert(account_id(tx.chain_id, salt, *threshold, signers), a);
            reg.rand_in = rand_in;
        }
        Action::MultisigDeposit { account: id } => {
            let b = tx.bundle.as_ref().ok_or(TxError::MissingBundle)?;
            let rows = credit(ledger, ledger.multisig().and_then(|r| r.get(id)), b)?;
            let reg = ledger.multisig_mut().ok_or(NOT_MULTISIG)?;
            let rand_in = reg.rand_in.checked_add(b.burn_r).ok_or(MultisigError::Overflow)?;
            let a = reg.get_mut(id).expect("validated above");
            for (asset, amount) in rows {
                a.set_balance(asset, amount);
            }
            reg.rand_in = rand_in;
        }
        Action::MultisigPay { account: id, time, pays, .. } => {
            let (rows, paid) = pay_moves(account(ledger, id)?, pays)?;
            let cms: Vec<Word8> = pays.iter().map(|p| payout_commitment(p, *time, executor)).collect();
            // The proposer takes the base: looked up and its sum checked before the first write.
            let rewards = ledger.validators.get(proposer).ok_or(TxError::UnknownProposer(*proposer))?.rewards;
            rewards.checked_add(gas::BUNDLE_BASE).ok_or(TxError::Overflow)?;
            let reg = ledger.multisig_mut().ok_or(NOT_MULTISIG)?;
            let rand_out = reg.rand_out.checked_add(paid).ok_or(MultisigError::Overflow)?;
            let base_out = reg.base_out.checked_add(gas::BUNDLE_BASE).ok_or(MultisigError::Overflow)?;
            let a = reg.get_mut(id).expect("validated above");
            for (asset, amount) in rows {
                a.set_balance(asset, amount);
            }
            a.nonce += 1;
            reg.rand_out = rand_out;
            reg.base_out = base_out;
            for cm in cms {
                ledger.deposit(cm, executor)?;
            }
            let p = ledger.validators.get_mut(proposer).expect("looked up above");
            p.rewards = p.rewards.checked_add(gas::BUNDLE_BASE).ok_or(TxError::Overflow)?;
        }
        Action::MultisigRotate { account: id, signers, threshold, .. } => {
            let reg = ledger.multisig_mut().ok_or(NOT_MULTISIG)?;
            let a = reg.get_mut(id).expect("validated above");
            a.signers = signers.clone();
            a.threshold = *threshold;
            a.nonce += 1;
        }
        _ => return Err(NOT_MULTISIG),
    }
    Ok(())
}

/// Whether `tx`, a `MultisigPay` that [`validate`] accepted on an earlier state, can still apply
/// on `ledger`: the state half of its rules — the account, its nonce, the rows covering the base
/// and the payouts — with the verdict [`validate`] would give (`program_state::still_applies`'s
/// twin). For a node's pool, which asks at selection: another pay draining the row this one pays
/// from makes it inapplicable, and it must leave the pool rather than be offered to every block.
/// No hash, no signature. `Ok` for every other action.
pub fn still_applies(ledger: &Ledger, tx: &Transaction) -> Result<(), TxError> {
    let Action::MultisigPay { account: id, nonce, pays, .. } = &tx.action else {
        return Ok(());
    };
    ledger.multisig().ok_or(NOT_MULTISIG)?;
    // The count first, as admission has it: this may run as a pre-screen, and an oversized list
    // must not buy a lookup per entry.
    if pays.len() > MAX_PAYOUTS {
        return Err(MultisigError::TooManyPayouts(pays.len()).into());
    }
    check_pay_state(ledger, id, *nonce, pays).map(|_| ())
}

#[cfg(test)]
mod rule_tests {
    use super::*;
    use crate::confidential::{ConfidentialExecutor, StubExecutor};
    use crate::crypto::{Address, Keypair};
    use crate::gas;
    use crate::ledger::program_state::{payout_commitment, Payout, ProgramStateError};
    use crate::ledger::tokens::{MintAuthority, TokenError, TokenRegistry};
    use crate::ledger::{Ledger, TxError, ValidatorEntry};
    use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8, KEM_EK_BYTES, MAX_NOTE_VALUE};
    use crate::types::actions::{multisig_pay_message, multisig_rotate_message, SignerSignature};
    use crate::types::{Action, Transaction};

    const CHAIN: u64 = 7;
    const HC: Word8 = [11; 8];
    const BASE: u64 = gas::BUNDLE_BASE;
    const U: u64 = crate::types::UNITS_PER_RAND;
    const CREATE_FEE: u64 = 5 * BASE;
    const PROPOSER: u8 = 90;
    /// The account's three signers, by key seed, in list order; two of them sign.
    const SIGNERS: [u8; 3] = [1, 2, 3];
    /// The registered token's index (the fixture registers exactly one).
    const TOKEN: u32 = 1;

    fn kp(seed: u8) -> Keypair {
        Keypair::from_seed([seed; 32]).unwrap()
    }

    fn keys(seeds: &[u8]) -> Vec<PublicKey> {
        seeds.iter().map(|s| kp(*s).public_key().clone()).collect()
    }

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn genesis_account(salt: u8, balance: u64) -> MultisigAccountConfig {
        MultisigAccountConfig { salt: [salt; 32], signers: keys(&SIGNERS), threshold: 2, balance }
    }

    /// A ledger with the `multisig` section (`accounts` seeded at genesis, `CREATE_FEE`), a
    /// `tokens` registry holding token 1, and one validator — the proposer.
    fn ledger(accounts: Vec<MultisigAccountConfig>) -> Ledger {
        let p = kp(PROPOSER);
        let entry = ValidatorEntry {
            public_key: p.public_key().clone(),
            stake: 10,
            pending: Vec::new(),
            rewards: 0,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
            activation_epoch: 0,
        };
        let mut l = Ledger::new(CHAIN, HC, [(p.address(), entry)].into_iter().collect(), &StubExecutor);
        let mut tokens = TokenRegistry::new(U);
        let index = tokens
            .register(crate::crypto::Hash([5; 32]), "Test Coin".into(), "TST".into(), 6, MintAuthority::Key(kp(21).public_key().clone()), 0)
            .unwrap();
        assert_eq!(index, TOKEN);
        l.set_tokens(Some(tokens));
        let cfg = MultisigConfig { create_fee: CREATE_FEE, accounts };
        cfg.check(CHAIN).unwrap();
        l.set_multisig(Some(MultisigRegister::from_config(&cfg, CHAIN)));
        l.set_genesis_supply(1_000_000 * U, 10);
        l.set_height(1);
        l.set_timestamp_ms(1_000_000);
        l
    }

    /// One genesis account (salt 1) holding `rand`, plus `token_rows` written straight into its
    /// vault (tokens sit outside the RAND identity).
    fn account_with(rand: u64, token_rows: &[(u32, u64)]) -> (Ledger, [u8; 32]) {
        let a = genesis_account(1, rand);
        let id = a.id(CHAIN);
        let mut l = ledger(vec![a]);
        let acct = l.multisig_mut().unwrap().get_mut(&id).unwrap();
        for (asset, amount) in token_rows {
            acct.set_balance(*asset, *amount);
        }
        (l, id)
    }

    fn proposer() -> Address {
        kp(PROPOSER).address()
    }

    fn rewards(l: &Ledger) -> u64 {
        l.validators().get(&proposer()).unwrap().rewards
    }

    fn acct(l: &Ledger, id: &[u8; 32]) -> Account {
        l.multisig().unwrap().get(id).unwrap().clone()
    }

    fn pay(asset: u32, amount: u64, n: u32) -> Payout {
        Payout { asset, amount, recipient: ShieldedAddress { pk: [n; 8], kem_ek: vec![6; KEM_EK_BYTES] }, r: [n + 100; 8], envelope: env() }
    }

    /// A pay of `pays` at `nonce`, signed by `signers`: each `(index, key seed)` — the position
    /// the signature claims and the key that actually signs.
    fn signed_pay(l: &Ledger, id: &[u8; 32], nonce: u64, pays: Vec<Payout>, signers: &[(u8, u8)]) -> Transaction {
        let time = l.height() as u32;
        let m = multisig_pay_message(&l.signing_domain().genesis, CHAIN, id, nonce, time, &pays);
        let signatures = signers.iter().map(|(index, seed)| SignerSignature { index: *index, signature: kp(*seed).sign(m.as_bytes()) }).collect();
        Transaction { chain_id: CHAIN, bundle: None, action: Action::MultisigPay { account: *id, nonce, time, pays, signatures } }
    }

    fn signed_rotate(l: &Ledger, id: &[u8; 32], nonce: u64, new: &[u8], threshold: u8, signers: &[(u8, u8)]) -> Transaction {
        let new = keys(new);
        let m = multisig_rotate_message(&l.signing_domain().genesis, CHAIN, id, nonce, &new, threshold);
        let signatures = signers.iter().map(|(index, seed)| SignerSignature { index: *index, signature: kp(*seed).sign(m.as_bytes()) }).collect();
        Transaction { chain_id: CHAIN, bundle: None, action: Action::MultisigRotate { account: *id, nonce, signers: new, threshold, signatures } }
    }

    /// The two rightful signers of the fixture account.
    const TWO: [(u8, u8); 2] = [(0, 1), (1, 2)];

    fn bundle(l: &Ledger, seed: u32, fee: u64, burn_r: u64, burn_asset: u32, burn_a: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: crate::notes::pad4([[seed; 8], [seed + 1; 8]]),
            commitments: crate::notes::pad4([[seed + 2; 8], [seed + 3; 8]]),
            fee,
            burn_a,
            burn_r,
            burn_asset,
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

    fn create(l: &Ledger, seed: u32, fee: u64, salt: u8, signers: &[u8], threshold: u8, burns: (u64, u32, u64)) -> Transaction {
        let action = Action::CreateMultisig { salt: [salt; 32], signers: keys(signers), threshold };
        StubExecutor::bound(Transaction::shielded(CHAIN, bundle(l, seed, fee, burns.0, burns.1, burns.2), action))
    }

    fn deposit(l: &Ledger, seed: u32, id: &[u8; 32], burns: (u64, u32, u64)) -> Transaction {
        StubExecutor::bound(Transaction::shielded(CHAIN, bundle(l, seed, BASE, burns.0, burns.1, burns.2), Action::MultisigDeposit { account: *id }))
    }

    fn apply(l: &mut Ledger, tx: &Transaction) -> Result<(), TxError> {
        l.apply_tx(tx, &proposer(), &StubExecutor).map(|_| ())
    }

    /// Build the transaction against the ledger first, then apply it.
    macro_rules! ap {
        ($l:ident, $t:expr) => {{
            let t = $t;
            apply(&mut $l, &t)
        }};
    }

    fn refusal(l: &Ledger, tx: &Transaction) -> TxError {
        l.validate(tx, &StubExecutor).expect_err("refused")
    }

    fn ms(e: MultisigError) -> TxError {
        TxError::Multisig(e)
    }

    #[test]
    fn a_create_derives_its_id_funds_the_vault_from_the_burn_and_pays_the_create_fee() {
        let mut l = ledger(vec![]);
        assert_eq!(create_fee_of(&l), CREATE_FEE);
        let id = account_id(CHAIN, &[4; 32], 2, &keys(&SIGNERS));
        let fee = BASE + CREATE_FEE;
        let before = rewards(&l);
        ap!(l, create(&l, 10, fee, 4, &SIGNERS, 2, (3 * U, TOKEN, 70))).unwrap();
        let a = acct(&l, &id);
        assert_eq!((a.signers, a.threshold, a.nonce), (keys(&SIGNERS), 2, 0));
        assert_eq!(a.vault, [(0, 3 * U), (TOKEN, 70)].into_iter().collect(), "burn_r into row 0, burn_a into the token's row");
        assert_eq!(l.multisig().unwrap().rand_in, 3 * U);
        assert_eq!(rewards(&l), before + fee, "the create fee goes to the proposer with the rest of the fee");
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
        // An unfunded account: no rows at all.
        ap!(l, create(&l, 20, fee, 5, &SIGNERS, 2, (0, 0, 0))).unwrap();
        assert!(acct(&l, &account_id(CHAIN, &[5; 32], 2, &keys(&SIGNERS))).vault.is_empty());
        assert_eq!(l.multisig().unwrap().len(), 2);
    }

    #[test]
    fn a_create_below_the_fee_floor_or_of_an_existing_id_or_a_bad_signer_set_is_refused() {
        let a = genesis_account(1, 0);
        let l = ledger(vec![a.clone()]);
        let fee = BASE + CREATE_FEE;
        assert_eq!(refusal(&l, &create(&l, 10, fee - 1, 4, &SIGNERS, 2, (0, 0, 0))), TxError::FeeTooLow { min: fee, fee: fee - 1 });
        assert_eq!(refusal(&l, &create(&l, 10, fee, 1, &SIGNERS, 2, (0, 0, 0))), ms(MultisigError::AccountExists(hex::encode(a.id(CHAIN)))));
        for (signers, threshold) in [(&[][..], 1), (&[1, 1][..], 1), (&SIGNERS[..], 0), (&SIGNERS[..], 4), (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11][..], 1)] {
            assert!(matches!(refusal(&l, &create(&l, 10, fee, 4, signers, threshold, (0, 0, 0))), TxError::Multisig(MultisigError::BadSigners(_))), "{signers:?} {threshold}");
        }
        assert_eq!(refusal(&l, &create(&l, 10, fee, 4, &SIGNERS, 2, (0, 9, 5))), TxError::Token(TokenError::UnknownToken(9)));
        assert_eq!(l.validate(&create(&l, 10, fee, 4, &SIGNERS, 2, (0, 0, 0)), &StubExecutor), Ok(()));
    }

    #[test]
    fn a_deposit_credits_rand_and_a_registered_token_and_refuses_an_empty_or_unknown_one() {
        let (mut l, id) = account_with(U, &[]);
        ap!(l, deposit(&l, 10, &id, (2 * U, TOKEN, 40))).unwrap();
        assert_eq!(acct(&l, &id).vault, [(0, 3 * U), (TOKEN, 40)].into_iter().collect());
        ap!(l, deposit(&l, 20, &id, (0, TOKEN, 2))).unwrap();
        assert_eq!(acct(&l, &id).balance(TOKEN), 42);
        assert_eq!(l.multisig().unwrap().rand_in, 2 * U);
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
        assert_eq!(refusal(&l, &deposit(&l, 30, &id, (0, 0, 0))), ms(MultisigError::EmptyDeposit));
        assert_eq!(refusal(&l, &deposit(&l, 30, &id, (0, 9, 1))), TxError::Token(TokenError::UnknownToken(9)));
        assert_eq!(refusal(&l, &deposit(&l, 30, &[8; 32], (U, 0, 0))), ms(MultisigError::UnknownAccount(hex::encode([8; 32]))));
        // A row at the top of u64 cannot take more.
        l.multisig_mut().unwrap().get_mut(&id).unwrap().set_balance(TOKEN, u64::MAX);
        assert_eq!(refusal(&l, &deposit(&l, 30, &id, (0, TOKEN, 1))), ms(MultisigError::Overflow));
    }

    #[test]
    fn a_pay_debits_each_row_appends_each_note_and_pays_the_base_to_the_proposer() {
        let (mut l, id) = account_with(10 * U, &[(TOKEN, 500)]);
        let pays = vec![pay(0, 2 * U, 1), pay(TOKEN, 300, 2), pay(0, U, 3)];
        let tx = signed_pay(&l, &id, 0, pays.clone(), &TWO);
        let time = l.height() as u32;
        let want: Vec<Word8> = pays.iter().map(|p| payout_commitment(p, time, &StubExecutor)).collect();
        // The derived commitments are exactly what apply appends, in order, stamped with `time`.
        assert_eq!(l.derived_commitments(&tx, &StubExecutor), want);
        let mut expected = l.clone();
        for cm in &want {
            expected.deposit(*cm, &StubExecutor).unwrap();
        }
        let first = l.next_index();
        apply(&mut l, &tx).unwrap();
        assert_eq!(l.next_index(), first + 3);
        assert_eq!(l.root(), expected.root(), "the payout notes, in order");
        assert!(want.iter().all(|cm| l.has_commitment(cm)));
        let a = acct(&l, &id);
        assert_eq!(a.vault, [(0, 10 * U - 3 * U - BASE), (TOKEN, 200)].into_iter().collect());
        assert_eq!(a.nonce, 1);
        assert_eq!(rewards(&l), BASE);
        let r = l.multisig().unwrap();
        assert_eq!((r.rand_out, r.base_out), (3 * U, BASE));
    }

    #[test]
    fn a_pay_needs_the_base_in_rand_even_for_a_token_payout() {
        let (l, id) = account_with(0, &[(TOKEN, 500)]);
        let tx = signed_pay(&l, &id, 0, vec![pay(TOKEN, 100, 1)], &TWO);
        assert_eq!(refusal(&l, &tx), ms(MultisigError::VaultShort { asset: 0, have: 0, want: BASE }));
        let (l, id) = account_with(BASE, &[(TOKEN, 500)]);
        let tx = signed_pay(&l, &id, 0, vec![pay(TOKEN, 100, 1)], &TWO);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        // RAND payouts and the base come out of the same row.
        let (l, id) = account_with(U, &[]);
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, vec![pay(0, U, 1)], &TWO)), ms(MultisigError::VaultShort { asset: 0, have: U, want: U + BASE }));
    }

    #[test]
    fn a_pay_short_on_a_row_is_refused_before_any_signature_is_checked() {
        let (l, id) = account_with(U, &[(TOKEN, 5)]);
        // Signed by the wrong keys: the vault is what the refusal names.
        let bad = [(0, 8), (1, 9)];
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, vec![pay(TOKEN, 6, 1)], &bad)), ms(MultisigError::VaultShort { asset: TOKEN, have: 5, want: 6 }));
        assert_eq!(
            refusal(&l, &signed_pay(&l, &id, 0, vec![pay(TOKEN, 3, 1), pay(TOKEN, 3, 2)], &bad)),
            ms(MultisigError::VaultShort { asset: TOKEN, have: 5, want: 6 }),
            "a row covers the sum of its payouts"
        );
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, vec![pay(TOKEN, 3, 1)], &bad)), ms(MultisigError::BadSignature(0)));
    }

    #[test]
    fn fewer_than_threshold_a_duplicate_or_an_out_of_range_signer_is_refused_on_the_bytes() {
        let (l, id) = account_with(10 * U, &[]);
        let p = || vec![pay(0, U, 1)];
        // The shape is refused on the bytes: wrong keys sign every one of these, and the shape
        // error is still what is heard.
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, p(), &[(0, 8)])), ms(MultisigError::BelowThreshold { have: 1, need: 2 }));
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, p(), &[])), ms(MultisigError::BelowThreshold { have: 0, need: 2 }));
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, p(), &[(1, 8), (1, 9)])), ms(MultisigError::DuplicateSigner(1)));
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, p(), &[(0, 8), (3, 9)])), ms(MultisigError::BadSignerIndex(3)));
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, p(), &[(0, 8), (255, 9)])), ms(MultisigError::BadSignerIndex(255)));
        // The same signer under two indices is two signatures from one key: the second index's
        // key did not sign.
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 0, p(), &[(0, 1), (1, 1)])), ms(MultisigError::BadSignature(1)));
        // Any two of the three, in any order.
        assert_eq!(l.validate(&signed_pay(&l, &id, 0, p(), &[(2, 3), (0, 1)]), &StubExecutor), Ok(()));
        // And the nonce is the account's.
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 1, p(), &TWO)), ms(MultisigError::BadNonce { expected: 0, actual: 1 }));
        assert_eq!(refusal(&l, &signed_pay(&l, &[8; 32], 0, p(), &TWO)), ms(MultisigError::UnknownAccount(hex::encode([8; 32]))));
    }

    #[test]
    fn one_bad_signature_among_enough_good_ones_refuses_the_pay() {
        let (l, id) = account_with(10 * U, &[]);
        let tx = signed_pay(&l, &id, 0, vec![pay(0, U, 1)], &[(0, 1), (1, 2), (2, 9)]);
        assert_eq!(refusal(&l, &tx), ms(MultisigError::BadSignature(2)));
        // A signature over another payment does not count either.
        let mut tx = signed_pay(&l, &id, 0, vec![pay(0, U, 1)], &TWO);
        let Action::MultisigPay { pays, .. } = &mut tx.action else { unreachable!() };
        pays[0].amount = 2 * U;
        assert_eq!(refusal(&l, &tx), ms(MultisigError::BadSignature(0)));
    }

    #[test]
    fn a_pay_and_a_rotate_share_the_nonce_and_the_old_signers_die_with_the_rotation() {
        let (mut l, id) = account_with(10 * U, &[]);
        let stale_pay = signed_pay(&l, &id, 0, vec![pay(0, U, 1)], &TWO);
        let rotate = signed_rotate(&l, &id, 0, &[4, 5], 1, &TWO);
        apply(&mut l, &rotate).unwrap();
        assert_eq!(acct(&l, &id).nonce, 1);
        assert_eq!(refusal(&l, &stale_pay), ms(MultisigError::BadNonce { expected: 1, actual: 0 }));
        // Re-signed at the new nonce by the old signers: their keys are gone.
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 1, vec![pay(0, U, 1)], &[(0, 1)])), ms(MultisigError::BadSignature(0)));
        // The new set pays, and its pay moves the nonce a rotate signed at 1 needed.
        let stale_rotate = signed_rotate(&l, &id, 1, &[6], 1, &[(0, 4)]);
        ap!(l, signed_pay(&l, &id, 1, vec![pay(0, U, 1)], &[(1, 5)])).unwrap();
        assert_eq!(refusal(&l, &stale_rotate), ms(MultisigError::BadNonce { expected: 2, actual: 1 }));
    }

    #[test]
    fn a_rotate_replaces_the_set_under_the_creation_rules_and_leaves_the_vault_alone() {
        let (mut l, id) = account_with(10 * U, &[(TOKEN, 7)]);
        for (new, threshold) in [(&[][..], 1), (&[4, 4][..], 1), (&[4, 5][..], 0), (&[4, 5][..], 3)] {
            assert!(matches!(refusal(&l, &signed_rotate(&l, &id, 0, new, threshold, &TWO)), TxError::Multisig(MultisigError::BadSigners(_))), "{new:?} {threshold}");
        }
        // Signed by the current set: the threshold that counts is the current one.
        assert_eq!(refusal(&l, &signed_rotate(&l, &id, 0, &[4], 1, &[(0, 1)])), ms(MultisigError::BelowThreshold { have: 1, need: 2 }));
        assert_eq!(refusal(&l, &signed_rotate(&l, &id, 0, &[4], 1, &[(0, 4), (1, 2)])), ms(MultisigError::BadSignature(0)));
        let before = acct(&l, &id);
        let rewards_before = rewards(&l);
        ap!(l, signed_rotate(&l, &id, 0, &[4, 5, 6], 3, &TWO)).unwrap();
        let after = acct(&l, &id);
        assert_eq!((after.signers, after.threshold, after.nonce), (keys(&[4, 5, 6]), 3, 1));
        assert_eq!(after.vault, before.vault, "the vault is untouched");
        assert_eq!(rewards(&l), rewards_before, "fee-less");
        assert_eq!(l.multisig().unwrap().len(), 1, "the id does not move");
    }

    #[test]
    fn a_repeated_payout_commitment_is_refused() {
        let (mut l, id) = account_with(10 * U, &[]);
        let twice = signed_pay(&l, &id, 0, vec![pay(0, U, 1), pay(0, U, 1)], &TWO);
        let cm = payout_commitment(&pay(0, U, 1), l.height() as u32, &StubExecutor);
        assert_eq!(refusal(&l, &twice), TxError::CommitmentExists(cm));
        ap!(l, signed_pay(&l, &id, 0, vec![pay(0, U, 1)], &TWO)).unwrap();
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 1, vec![pay(0, U, 1)], &TWO)), TxError::CommitmentExists(cm), "already in the tree");
        // The payout shape: zero, above the note bound, a recipient nobody can seal to.
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 1, vec![pay(0, 0, 2)], &TWO)), ms(MultisigError::ZeroPayout));
        assert_eq!(
            refusal(&l, &signed_pay(&l, &id, 1, vec![pay(0, MAX_NOTE_VALUE, 2)], &TWO)),
            TxError::ProgramState(ProgramStateError::PayoutTooLarge(MAX_NOTE_VALUE))
        );
        let mut short = pay(0, U, 2);
        short.recipient.kem_ek = vec![6; 32];
        assert!(matches!(refusal(&l, &signed_pay(&l, &id, 1, vec![short], &TWO)), TxError::Token(TokenError::BadRecipientKey { .. })));
        assert_eq!(refusal(&l, &signed_pay(&l, &id, 1, vec![pay(9, 1, 2)], &TWO)), TxError::Token(TokenError::UnknownToken(9)));
    }

    #[test]
    fn still_applies_prunes_a_pay_whose_row_another_pay_drained() {
        let (mut l, id) = account_with(10 * U, &[]);
        let a = signed_pay(&l, &id, 0, vec![pay(0, 8 * U, 1)], &TWO);
        let b = signed_pay(&l, &id, 1, vec![pay(0, U, 2)], &TWO);
        let c = signed_pay(&l, &id, 1, vec![pay(0, 2 * U, 3)], &TWO);
        assert_eq!(still_applies(&l, &a), Ok(()));
        assert_eq!(still_applies(&l, &b), Err(ms(MultisigError::BadNonce { expected: 0, actual: 1 })));
        apply(&mut l, &a).unwrap();
        assert_eq!(still_applies(&l, &a), Err(ms(MultisigError::BadNonce { expected: 1, actual: 0 })));
        assert_eq!(still_applies(&l, &b), Ok(()));
        assert_eq!(still_applies(&l, &c), Err(ms(MultisigError::VaultShort { asset: 0, have: 2 * U - BASE, want: 2 * U + BASE })));
        // Every other action is not this function's question.
        assert_eq!(still_applies(&l, &signed_rotate(&l, &id, 9, &[4], 1, &[])), Ok(()));
        assert_eq!(still_applies(&l, &deposit(&l, 10, &id, (0, 0, 0))), Ok(()));
    }

    #[test]
    fn the_supply_identity_holds_through_create_deposit_pay_and_rotate() {
        let g = genesis_account(1, 10 * U);
        let id = g.id(CHAIN);
        let mut l = ledger(vec![g]);
        let check = |l: &Ledger, step: &str| assert!(l.audit().invariant_holds(), "{step}: {:?}", l.audit());
        check(&l, "genesis");
        assert_eq!(l.audit().multisig_issued, 10 * U);
        ap!(l, create(&l, 10, BASE + CREATE_FEE, 4, &SIGNERS, 2, (2 * U, 0, 0))).unwrap();
        check(&l, "create");
        ap!(l, deposit(&l, 20, &id, (3 * U, TOKEN, 9))).unwrap();
        check(&l, "deposit");
        let held = l.multisig().unwrap().rand_held();
        assert_eq!(held, 15 * U);
        let (pool, rewards_before) = (l.audit().pool_value, rewards(&l));
        let paid_rand = 4 * U + 7;
        ap!(l, signed_pay(&l, &id, 0, vec![pay(0, 4 * U, 1), pay(TOKEN, 9, 2), pay(0, 7, 3)], &TWO)).unwrap();
        check(&l, "pay");
        let audit = l.audit();
        assert_eq!(audit.multisig_rand_out, paid_rand);
        assert_eq!(audit.pool_value, pool + paid_rand);
        assert_eq!(rewards(&l), rewards_before + BASE);
        assert_eq!(l.multisig().unwrap().rand_held(), held - paid_rand - BASE);
        assert_eq!(audit.multisig_rand_held, held - paid_rand - BASE);
        ap!(l, signed_rotate(&l, &id, 1, &[4], 1, &TWO)).unwrap();
        check(&l, "rotate");
        assert_eq!(l.multisig().unwrap().rand_held(), held - paid_rand - BASE);
    }

    #[test]
    fn the_root_changes_on_every_apply_and_the_gate_is_rechecked_at_apply() {
        let (mut l, id) = account_with(10 * U, &[]);
        let mut roots = vec![l.state_root()];
        let mut step = |l: &mut Ledger, tx: Transaction| {
            apply(l, &tx).unwrap();
            let r = l.state_root();
            assert!(!roots.contains(&r), "{:?}", tx.action);
            roots.push(r);
        };
        let tx = create(&l, 10, BASE + CREATE_FEE, 4, &SIGNERS, 2, (0, 0, 0));
        step(&mut l, tx);
        let tx = deposit(&l, 20, &id, (U, 0, 0));
        step(&mut l, tx);
        let tx = signed_pay(&l, &id, 0, vec![pay(0, U, 1)], &TWO);
        step(&mut l, tx);
        let tx = signed_rotate(&l, &id, 1, &[4], 1, &TWO);
        step(&mut l, tx);
        // The gate at apply: a ledger whose section is gone refuses before any write.
        let tx = signed_pay(&l, &id, 2, vec![pay(0, U, 2)], &[(0, 4)]);
        assert_eq!(l.validate(&tx, &StubExecutor), Ok(()));
        l.set_multisig(None);
        let before = l.clone();
        assert_eq!(super::apply(&mut l, &tx, &tx.action, &proposer(), &StubExecutor), Err(TxError::UnsupportedAction("multisig")));
        assert_eq!(super::validate(&l, &tx, &tx.action, &StubExecutor), Err(TxError::UnsupportedAction("multisig")));
        assert!(l == before, "nothing written");
        // Apply re-runs the rules: a pay whose vault was drained between admission and apply
        // is refused there too, before any write.
        let (mut l, id) = account_with(10 * U, &[]);
        let tx = signed_pay(&l, &id, 0, vec![pay(0, U, 2)], &TWO);
        l.multisig_mut().unwrap().get_mut(&id).unwrap().set_balance(0, U);
        let before = l.clone();
        assert_eq!(super::apply(&mut l, &tx, &tx.action, &proposer(), &StubExecutor), Err(ms(MultisigError::VaultShort { asset: 0, have: U, want: U + BASE })));
        assert!(l == before, "nothing written");
    }
}
