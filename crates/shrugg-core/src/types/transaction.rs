//! Transactions: a shielded bundle plus an optional action (design spec §3, §6).

use crate::crypto::{Hash, Keypair, PublicKey, Signature};
use crate::notes::{Bundle, Envelope, Word8};
use crate::program::ProgramId;
use serde::{Deserialize, Serialize};

/// Native token symbol. The whitepaper (Draft 3) calls this SHRUGG; rename here if needed.
pub const TOKEN_SYMBOL: &str = "SHRUGG";
/// Smallest-unit decimals: 1 SHRUGG = 10^9 units.
pub const TOKEN_DECIMALS: u32 = 9;
pub const UNITS_PER_SHRUGG: u64 = 1_000_000_000;
/// Largest amount a single testnet faucet mint may create.
pub const FAUCET_MAX_UNITS: u64 = 100 * UNITS_PER_SHRUGG;

/// Format smallest units as a decimal SHRUGG string ("1.5").
pub fn format_amount(units: u64) -> String {
    let scale = 10u64.pow(TOKEN_DECIMALS);
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
pub fn parse_amount(s: &str) -> Result<u64, AmountError> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > TOKEN_DECIMALS as usize {
        return Err(AmountError::TooManyDecimals);
    }
    if whole.is_empty() && frac.is_empty() {
        return Err(AmountError::NotANumber);
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| AmountError::NotANumber)? };
    let frac_units: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<width$}", width = TOKEN_DECIMALS as usize).parse().map_err(|_| AmountError::NotANumber)?
    };
    whole
        .checked_mul(10u64.pow(TOKEN_DECIMALS))
        .and_then(|w| w.checked_add(frac_units))
        .ok_or(AmountError::Overflow)
}

/// What a transaction does besides moving shielded value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// A plain shielded transfer: the bundle is the whole transaction.
    None,
    /// Testnet faucet deposit (spec §6): a note of public `amount` created by a validator.
    /// Carried by a bundle-less transaction; `signature` is `minter`'s Dilithium2 signature over
    /// [`Transaction::mint_signing_hash`].
    Mint { cm: Word8, envelope: Envelope, amount: u64, minter: PublicKey, signature: Signature },
    /// Put a zkVM program on chain. Content addressed; see `program::program_id`.
    Deploy { base_pc: u32, words: Vec<u32> },
    /// A confidential call: a STARK proof that `program` ran on private inputs and published
    /// the eight public outputs carried in the proof.
    Call { program: ProgramId, proof: Vec<u8> },
}

/// A transaction: a shielded bundle, an action, or (for a faucet mint) an action alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: u64,
    /// `None` only for [`Action::Mint`].
    pub bundle: Option<Bundle>,
    pub action: Action,
}

impl Transaction {
    /// A bundle-carrying transaction; `Action::None` for a plain transfer.
    pub fn shielded(chain_id: u64, bundle: Bundle, action: Action) -> Transaction {
        Transaction { chain_id, bundle: Some(bundle), action }
    }

    /// What a faucet minter signs: the chain, the new note's commitment, its envelope and the
    /// public amount. Binding the chain keeps a testnet mint off another chain.
    pub fn mint_signing_hash(chain_id: u64, cm: &Word8, envelope: &Envelope, amount: u64) -> Hash {
        let bytes = bincode::serialize(&(chain_id, cm, envelope, amount)).expect("serializes");
        Hash::digest_domain(b"shrugg-mint", &bytes)
    }

    pub fn mint(chain_id: u64, cm: Word8, envelope: Envelope, amount: u64, minter: &Keypair) -> Transaction {
        let signature = minter.sign(Self::mint_signing_hash(chain_id, &cm, &envelope, amount).as_bytes());
        Transaction {
            chain_id,
            bundle: None,
            action: Action::Mint { cm, envelope, amount, minter: minter.public_key().clone(), signature },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Transaction serializes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Transaction, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Transaction id = hash of the full encoding.
    pub fn hash(&self) -> Hash {
        Hash::digest_domain(b"shrugg-txid", &self.encode())
    }

    /// Wire size, used for block byte accounting.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    /// The bundle's fee, or zero for a bundle-less transaction.
    pub fn fee(&self) -> u64 {
        self.bundle.as_ref().map_or(0, |b| b.fee)
    }

    /// The nullifiers this transaction spends.
    pub fn nullifiers(&self) -> Vec<Word8> {
        self.bundle.as_ref().map_or(Vec::new(), |b| b.nullifiers.to_vec())
    }

    /// Every note commitment this transaction creates: the bundle's two output slots in order,
    /// then a mint's note.
    pub fn commitments(&self) -> Vec<Word8> {
        let mut v: Vec<Word8> = self.bundle.as_ref().map_or(Vec::new(), |b| b.commitments.to_vec());
        if let Action::Mint { cm, .. } = &self.action {
            v.push(*cm);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] }
    }

    fn bundle() -> Bundle {
        Bundle {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8]],
            commitments: [[4; 8], [5; 8]],
            fee: 1_000_000,
            burn: 0,
            asset: 0,
            time: 9,
            envelopes: [env(), env()],
            proof: vec![9; 40],
        }
    }

    #[test]
    fn transactions_roundtrip_and_hash_their_full_encoding() {
        let tx = Transaction::shielded(7, bundle(), Action::None);
        let back = Transaction::decode(&tx.encode()).unwrap();
        assert_eq!(back, tx);
        assert_eq!(tx.fee(), 1_000_000);
        assert_eq!(tx.nullifiers(), vec![[2; 8], [3; 8]]);
        assert_eq!(tx.commitments(), vec![[4; 8], [5; 8]]);
        let mut other = tx.clone();
        other.bundle.as_mut().unwrap().fee += 1;
        assert_ne!(other.hash(), tx.hash());
    }

    #[test]
    fn a_mint_is_signed_by_its_minter_and_has_no_bundle() {
        let k = Keypair::from_seed([5; 32]).unwrap();
        let tx = Transaction::mint(7, [8; 8], env(), 100, &k);
        assert!(tx.bundle.is_none());
        assert_eq!(tx.fee(), 0);
        assert_eq!(tx.commitments(), vec![[8; 8]]);
        let Action::Mint { cm, envelope, amount, minter, signature } = &tx.action else { panic!() };
        assert!(minter.verify(Transaction::mint_signing_hash(7, cm, envelope, *amount).as_bytes(), signature));
        assert!(!minter.verify(Transaction::mint_signing_hash(8, cm, envelope, *amount).as_bytes(), signature));
    }

    #[test]
    fn amounts_format_and_parse_in_shrugg() {
        assert_eq!(format_amount(1_500_000_000), "1.5");
        assert_eq!(parse_amount("0.000001").unwrap(), 1_000);
        assert!(parse_amount("1.0000000001").is_err());
        assert_eq!(parse_amount("1").unwrap(), UNITS_PER_SHRUGG);
        assert_eq!(parse_amount(".25").unwrap(), 250_000_000);
        assert_eq!(parse_amount("abc"), Err(AmountError::NotANumber));
        assert_eq!(format_amount(42_000_000_000), "42");
        assert_eq!(format_amount(1), "0.000000001");
    }
}
