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
//! This file holds the data only: the config, the id, the register and its root. The actions that
//! move value live beside it as they land.

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

    #[allow(dead_code)] // used from Task 3/4
    pub(super) fn get_mut(&mut self, id: &[u8; 32]) -> Option<&mut Account> {
        self.accounts.get_mut(id)
    }

    #[allow(dead_code)] // used from Task 3/4
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

/// What every multisig action gets on a chain without the section: the gate is absolute
/// (vesting's `NOT_VESTING`, one register over).
const NOT_MULTISIG: crate::ledger::TxError = crate::ledger::TxError::UnsupportedAction("multisig");

/// Admission for the four multisig actions. Stub: the gate only; the rules land with Task 4, and
/// until then a chain that has the section refuses them too.
pub(super) fn validate(
    ledger: &super::Ledger,
    _tx: &crate::types::Transaction,
    _action: &crate::types::Action,
    _executor: &dyn crate::confidential::ConfidentialExecutor,
) -> Result<(), crate::ledger::TxError> {
    let _ = ledger.multisig().ok_or(NOT_MULTISIG)?;
    Err(NOT_MULTISIG)
}

/// Apply for the four multisig actions. Stub, as [`validate`].
pub(super) fn apply(
    ledger: &mut super::Ledger,
    _tx: &crate::types::Transaction,
    _action: &crate::types::Action,
    _proposer: &crate::crypto::Address,
    _executor: &dyn crate::confidential::ConfidentialExecutor,
) -> Result<(), crate::ledger::TxError> {
    let _ = ledger.multisig().ok_or(NOT_MULTISIG)?;
    Err(NOT_MULTISIG)
}
