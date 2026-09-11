//! Transactions: signed, nonce-ordered operations on the SHRUGG ledger.

use crate::bridge::AssetId;
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
    /// Redeem a guardian-signed bridge attestation: mint the attested transfer or
    /// rotate the guardian set. Anyone may submit one; the submitter keeps the
    /// attestation's bridge fee. Only valid on chains whose genesis enables the bridge.
    ///
    /// Appended after `Call` (tag 4): existing tags 0..3 keep their encoding.
    BridgeAttest { attestation: Vec<u8> },
    /// Burn `amount` of a bridged asset and post an outbound message for the
    /// guardians to sign, releasing on `to_chain` to `to`. Tag 5.
    BridgeBurn { asset: AssetId, amount: u128, to_chain: u16, to: [u8; 32], fee: u128 },
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

    pub fn bridge_attest(key: &Keypair, chain_id: u64, nonce: u64, attestation: Vec<u8>, fee: u128) -> Transaction {
        Transaction::sign(
            TxBody { chain_id, from: key.public_key().clone(), nonce, fee, kind: TxKind::BridgeAttest { attestation } },
            key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bridge_burn(
        key: &Keypair,
        chain_id: u64,
        nonce: u64,
        asset: AssetId,
        amount: u128,
        to_chain: u16,
        to: [u8; 32],
        bridge_fee: u128,
        fee: u128,
    ) -> Transaction {
        Transaction::sign(
            TxBody {
                chain_id,
                from: key.public_key().clone(),
                nonce,
                fee,
                kind: TxKind::BridgeBurn { asset, amount, to_chain, to, fee: bridge_fee },
            },
            key,
        )
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
            // Bridge kinds move bridged assets, not SHRUGG: only the fee is debited.
            TxKind::Mint { .. }
            | TxKind::Deploy { .. }
            | TxKind::Call { .. }
            | TxKind::BridgeAttest { .. }
            | TxKind::BridgeBurn { .. } => Some(self.body.fee),
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
    fn bridge_kinds_are_tags_four_and_five_and_cost_only_the_fee() {
        let k = key(1);
        let attest = Transaction::bridge_attest(&k, 1, 0, vec![1, 2, 3], 9);
        assert!(attest.verify_signature());
        assert_eq!(Transaction::decode(&attest.encode()).unwrap(), attest);
        assert_eq!(attest.total_cost(), Some(9));
        let burn = Transaction::bridge_burn(&k, 1, 1, Hash::digest(b"asset"), 500, 2, [7; 32], 5, 11);
        assert!(burn.verify_signature());
        assert_eq!(Transaction::decode(&burn.encode()).unwrap(), burn);
        assert_eq!(burn.total_cost(), Some(11));
        // Tags are appended after Call, so tags 0..3 keep their bincode encoding.
        let tag = |kind: &TxKind| bincode::serialize(kind).unwrap()[..4].to_vec();
        assert_eq!(tag(&TxKind::Transfer { to: key(2).address(), amount: 1 }), vec![0, 0, 0, 0]);
        assert_eq!(tag(&TxKind::Mint { to: key(2).address(), amount: 1 }), vec![1, 0, 0, 0]);
        assert_eq!(tag(&TxKind::Deploy { base_pc: 0, words: vec![] }), vec![2, 0, 0, 0]);
        assert_eq!(
            tag(&TxKind::Call { program: Hash::ZERO, proof: vec![], recipients: vec![] }),
            vec![3, 0, 0, 0]
        );
        assert_eq!(tag(&TxKind::BridgeAttest { attestation: vec![] }), vec![4, 0, 0, 0]);
        assert_eq!(
            tag(&TxKind::BridgeBurn { asset: Hash::ZERO, amount: 1, to_chain: 2, to: [0; 32], fee: 0 }),
            vec![5, 0, 0, 0]
        );
        // AssetId, u16 and [u8; 32] carry their plain bytes in the burn encoding.
        let burn_kind = TxKind::BridgeBurn { asset: Hash([0xab; 32]), amount: 1, to_chain: 2, to: [0xcd; 32], fee: 3 };
        let bytes = bincode::serialize(&burn_kind).unwrap();
        assert_eq!(bytes.len(), 4 + 32 + 16 + 2 + 32 + 16);
        assert_eq!(&bytes[4..36], &[0xab; 32]);
    }

    #[test]
    fn total_cost_overflow_is_none() {
        let tx = Transaction::transfer(&key(1), 1, 0, key(2).address(), u128::MAX, 1);
        assert_eq!(tx.total_cost(), None);
    }
}
