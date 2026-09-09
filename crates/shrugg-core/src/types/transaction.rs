//! Transactions: signed, nonce-ordered operations on the SHRUGG ledger.

use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::program::ProgramId;
use serde::{Deserialize, Serialize};

/// Native token symbol. The whitepaper (Draft 3) calls this SHRUGG; rename here if needed.
pub const TOKEN_SYMBOL: &str = "SHRUGG";
/// Smallest-unit decimals: 1 SHRUGG = 10^9 units.
pub const TOKEN_DECIMALS: u32 = 9;
pub const UNITS_PER_SHRUGG: u128 = 1_000_000_000;
/// Largest amount a single testnet faucet mint may create.
pub const FAUCET_MAX_UNITS: u128 = 100 * UNITS_PER_SHRUGG;

/// Format smallest units as a decimal SHRUGG string ("1.5").
pub fn format_amount(units: u128) -> String {
    let scale = 10u128.pow(TOKEN_DECIMALS);
    let whole = units / scale;
    let frac = units % scale;
    if frac == 0 {
        format!("{whole}")
    } else {
        let s = format!("{frac:0width$}", width = TOKEN_DECIMALS as usize);
        format!("{whole}.{}", s.trim_end_matches('0'))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AmountError {
    #[error("too many decimal places (max {TOKEN_DECIMALS})")]
    TooManyDecimals,
    #[error("not a number")]
    NotANumber,
    #[error("amount overflow")]
    Overflow,
}

/// Parse a decimal SHRUGG string ("1.5", ".25") into smallest units.
pub fn parse_amount(s: &str) -> Result<u128, AmountError> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > TOKEN_DECIMALS as usize {
        return Err(AmountError::TooManyDecimals);
    }
    if whole.is_empty() && frac.is_empty() {
        return Err(AmountError::NotANumber);
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| AmountError::NotANumber)? };
    let frac_units: u128 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<width$}", width = TOKEN_DECIMALS as usize).parse().map_err(|_| AmountError::NotANumber)?
    };
    whole
        .checked_mul(10u128.pow(TOKEN_DECIMALS))
        .and_then(|w| w.checked_add(frac_units))
        .ok_or(AmountError::Overflow)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxKind {
    /// Move `amount` units from the sender to `to`.
    Transfer { to: Address, amount: u128 },
    /// Testnet faucet: create `amount` units for `to`. Only valid on chains whose
    /// genesis enables the faucet, and capped at `FAUCET_MAX_UNITS` per transaction.
    Mint { to: Address, amount: u128 },
    /// Put a zkVM program on chain. Content addressed; see `program::program_id`.
    Deploy { base_pc: u32, words: Vec<u32> },
    /// A confidential call: a STARK proof that `program` ran on private inputs and produced the
    /// eight public outputs carried in the proof. `recipients` is the public list the outputs may
    /// pick a transfer target from (see `effect`).
    Call { program: ProgramId, proof: Vec<u8>, recipients: Vec<Address> },
}

/// The signed part of a transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxBody {
    pub chain_id: u64,
    pub from: PublicKey,
    pub nonce: u64,
    pub fee: u128,
    pub kind: TxKind,
}

impl TxBody {
    pub fn signing_hash(&self) -> Hash {
        let bytes = bincode::serialize(self).expect("TxBody serializes");
        Hash::digest_domain(b"shrugg-tx", &bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub body: TxBody,
    pub signature: Signature,
}

impl Transaction {
    pub fn sign(body: TxBody, key: &Keypair) -> Transaction {
        debug_assert_eq!(key.public_key(), &body.from);
        let signature = key.sign(body.signing_hash().as_bytes());
        Transaction { body, signature }
    }

    pub fn transfer(key: &Keypair, chain_id: u64, nonce: u64, to: Address, amount: u128, fee: u128) -> Transaction {
        Transaction::sign(
            TxBody {
                chain_id,
                from: key.public_key().clone(),
                nonce,
                fee,
                kind: TxKind::Transfer { to, amount },
            },
            key,
        )
    }

    pub fn mint(key: &Keypair, chain_id: u64, nonce: u64, to: Address, amount: u128, fee: u128) -> Transaction {
        Transaction::sign(
            TxBody { chain_id, from: key.public_key().clone(), nonce, fee, kind: TxKind::Mint { to, amount } },
            key,
        )
    }

    pub fn deploy(key: &Keypair, chain_id: u64, nonce: u64, base_pc: u32, words: Vec<u32>, fee: u128) -> Transaction {
        Transaction::sign(TxBody { chain_id, from: key.public_key().clone(), nonce, fee, kind: TxKind::Deploy { base_pc, words } }, key)
    }

    pub fn call(key: &Keypair, chain_id: u64, nonce: u64, program: ProgramId, proof: Vec<u8>, recipients: Vec<Address>, fee: u128) -> Transaction {
        Transaction::sign(TxBody { chain_id, from: key.public_key().clone(), nonce, fee, kind: TxKind::Call { program, proof, recipients } }, key)
    }

    /// Wire size, used for block byte accounting.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    pub fn sender(&self) -> Address {
        self.body.from.address()
    }

    /// Transaction id = hash of the full signed encoding.
    pub fn hash(&self) -> Hash {
        Hash::digest_domain(b"shrugg-txid", &self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Transaction serializes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Transaction, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn verify_signature(&self) -> bool {
        self.body.from.verify(self.body.signing_hash().as_bytes(), &self.signature)
    }

    /// Total units debited from the sender if this tx succeeds.
    pub fn total_cost(&self) -> Option<u128> {
        match &self.body.kind {
            TxKind::Transfer { amount, .. } => amount.checked_add(self.body.fee),
            TxKind::Mint { .. } | TxKind::Deploy { .. } | TxKind::Call { .. } => Some(self.body.fee),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    #[test]
    fn transfer_signature_verifies_and_tamper_fails() {
        let alice = key(1);
        let bob = key(2);
        let tx = Transaction::transfer(&alice, 1, 0, bob.address(), 100, 1);
        assert!(tx.verify_signature());
        let mut bad = tx.clone();
        bad.body.fee = 2;
        assert!(!bad.verify_signature());
        let mut wrong_signer = tx.clone();
        wrong_signer.body.from = bob.public_key().clone();
        assert!(!wrong_signer.verify_signature());
    }

    #[test]
    fn encode_decode_roundtrip_keeps_hash() {
        let tx = Transaction::transfer(&key(1), 7, 3, key(2).address(), 5, 1);
        let bytes = tx.encode();
        let back = Transaction::decode(&bytes).unwrap();
        assert_eq!(back, tx);
        assert_eq!(back.hash(), tx.hash());
    }

    #[test]
    fn amount_roundtrip() {
        assert_eq!(parse_amount("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_amount("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_amount("0.000000001").unwrap(), 1);
        assert_eq!(parse_amount(".25").unwrap(), 250_000_000);
        assert_eq!(parse_amount("0.0000000001"), Err(AmountError::TooManyDecimals));
        assert_eq!(parse_amount("abc"), Err(AmountError::NotANumber));
        assert_eq!(format_amount(1_500_000_000), "1.5");
        assert_eq!(format_amount(1), "0.000000001");
        assert_eq!(format_amount(42_000_000_000), "42");
    }

    #[test]
    fn deploy_and_call_roundtrip() {
        let k = key(1);
        let d = Transaction::deploy(&k, 1, 0, 0, vec![0x13, 0x73], 5);
        assert!(d.verify_signature());
        assert_eq!(Transaction::decode(&d.encode()).unwrap(), d);
        let c = Transaction::call(&k, 1, 1, Hash::digest(b"p"), vec![1, 2, 3], vec![key(2).address()], 7);
        assert_eq!(Transaction::decode(&c.encode()).unwrap(), c);
        assert_eq!(c.total_cost(), Some(7));
        assert!(c.encoded_len() > 2420 + 1312);
    }

    #[test]
    fn total_cost_overflow_is_none() {
        let tx = Transaction::transfer(&key(1), 1, 0, key(2).address(), u128::MAX, 1);
        assert_eq!(tx.total_cost(), None);
    }
}
