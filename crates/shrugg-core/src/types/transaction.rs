//! Transactions: a shielded bundle plus an optional action (design spec §3, §6).

use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};
use crate::program::ProgramId;
use crate::types::actions::{CallEnvelope, Registration};
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
    /// the eight public outputs carried in the proof. `input_envelope` is the optional
    /// encrypted transcript of those private inputs (spec §6.1); the chain checks only its size.
    Call { program: ProgramId, proof: Vec<u8>, input_envelope: Option<CallEnvelope> },
    /// Phase S2: add `amount` (burned by the bundle) to `validator`'s stake. `registration` is
    /// present exactly when the validator is not yet in the register.
    Bond { validator: Address, amount: u64, registration: Option<Registration> },
    /// Phase S2: move `amount` of `validator`'s stake into unbonding. Signed over
    /// [`crate::types::actions::unbond_message`].
    Unbond { validator: Address, amount: u64, nonce: u64, signature: Signature },
    /// Phase S2: pay released stake and rewards into a deposit note the ledger computes itself
    /// from `r` and the register's payout address. Signed over [`crate::types::actions::withdraw_message`].
    Withdraw { validator: Address, amount: u64, nonce: u64, r: Word8, envelope: Envelope, signature: Signature },
    /// Phase S3: a guardian-signed bridge attestation, deposited as a note of the bridged
    /// asset to `recipient` with blinding `r`.
    BridgeAttest { attestation: Vec<u8>, recipient: ShieldedAddress, r: Word8, envelope: Envelope },
    /// Phase S3: burn `amount` of asset `asset` to a destination chain. `asset_bundle` is the
    /// second bundle of the transaction — the one spending the asset notes; the transaction's
    /// own `bundle` pays the SHRUGG fee.
    BridgeBurn { asset_bundle: Bundle, asset: u32, amount: u64, relayer_fee: u64, to_chain: u16, to: [u8; 32] },
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

    /// The nullifiers this transaction spends: the fee bundle's, then — for a `BridgeBurn` —
    /// the asset bundle's, which are spent by the same transaction and must be just as unique.
    pub fn nullifiers(&self) -> Vec<Word8> {
        let mut v: Vec<Word8> = self.bundle.as_ref().map_or(Vec::new(), |b| b.nullifiers.to_vec());
        if let Action::BridgeBurn { asset_bundle, .. } = &self.action {
            v.extend_from_slice(&asset_bundle.nullifiers);
        }
        v
    }

    /// Every note commitment this transaction creates: the bundle's two output slots in order,
    /// then a mint's note, then — for a `BridgeBurn` — the asset bundle's two slots.
    ///
    /// A `Withdraw`'s and a `BridgeAttest`'s deposit notes are deliberately absent: their
    /// commitment is not carried on the wire at all, it is computed by the ledger from the
    /// action's `r` and the amount it is paying out (spec §7).
    pub fn commitments(&self) -> Vec<Word8> {
        let mut v: Vec<Word8> = self.bundle.as_ref().map_or(Vec::new(), |b| b.commitments.to_vec());
        match &self.action {
            Action::Mint { cm, .. } => v.push(*cm),
            Action::BridgeBurn { asset_bundle, .. } => v.extend_from_slice(&asset_bundle.commitments),
            _ => {}
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

    /// A burn spends and creates through two bundles, so both must be visible to the mempool's
    /// and the ledger's uniqueness checks. A withdraw's deposit is not on the wire at all.
    #[test]
    fn a_bridge_burn_reports_both_bundles_and_a_withdraw_reports_no_deposit() {
        let mut asset_bundle = bundle();
        asset_bundle.nullifiers = [[6; 8], [7; 8]];
        asset_bundle.commitments = [[8; 8], [9; 8]];
        asset_bundle.asset = 3;
        asset_bundle.burn = 500;
        let burn = Transaction::shielded(
            7,
            bundle(),
            Action::BridgeBurn { asset_bundle, asset: 3, amount: 400, relayer_fee: 100, to_chain: 2, to: [1; 32] },
        );
        assert_eq!(burn.nullifiers(), vec![[2; 8], [3; 8], [6; 8], [7; 8]]);
        assert_eq!(burn.commitments(), vec![[4; 8], [5; 8], [8; 8], [9; 8]]);
        assert_eq!(Transaction::decode(&burn.encode()).unwrap(), burn);

        let w = Transaction::shielded(
            7,
            bundle(),
            Action::Withdraw {
                validator: Address([1; 32]),
                amount: 9,
                nonce: 0,
                r: [5; 8],
                envelope: env(),
                signature: Signature::empty(),
            },
        );
        assert_eq!(w.commitments(), vec![[4; 8], [5; 8]], "the ledger computes the deposit, the wire does not carry it");
        let a = Transaction::shielded(
            7,
            bundle(),
            Action::BridgeAttest {
                attestation: vec![1, 2, 3],
                recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                r: [5; 8],
                envelope: env(),
            },
        );
        assert_eq!(a.commitments(), vec![[4; 8], [5; 8]]);
        assert_eq!(a.nullifiers(), vec![[2; 8], [3; 8]]);
    }

    /// Every new variant is on the wire, and a `Call`'s envelope is part of the transaction id.
    #[test]
    fn the_new_variants_roundtrip_and_a_call_envelope_is_bound_to_the_tx_hash() {
        let call = Action::Call { program: Hash::ZERO, proof: vec![1; 4], input_envelope: None };
        let plain = Transaction::shielded(7, bundle(), call);
        let sealed = Transaction::shielded(
            7,
            bundle(),
            Action::Call {
                program: Hash::ZERO,
                proof: vec![1; 4],
                input_envelope: Some(CallEnvelope {
                    kem_ct: vec![],
                    to_sender: vec![2; 48],
                    to_auditor: vec![],
                    body: vec![3; 64],
                }),
            },
        );
        assert_ne!(plain.hash(), sealed.hash());
        for t in [&plain, &sealed] {
            assert_eq!(&Transaction::decode(&t.encode()).unwrap(), t);
        }
        for action in [
            Action::Bond { validator: Address([1; 32]), amount: 5, registration: None },
            Action::Unbond { validator: Address([1; 32]), amount: 5, nonce: 3, signature: Signature::empty() },
        ] {
            let t = Transaction::shielded(7, bundle(), action);
            assert_eq!(Transaction::decode(&t.encode()).unwrap(), t);
        }
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
