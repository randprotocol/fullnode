//! The receiver id (the short shielded address) and the receiver record (spec
//! docs/superpowers/specs/2026-09-17-short-shielded-address.md §1–§3).
use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::notes::{word8_to_bytes, Word8, KEM_EK_BYTES};
use serde::{Deserialize, Serialize};

pub const ADDRESS_PREFIX: &str = "rand1";
pub const MAX_RECORD_BYTES: usize = 8192;
const CHECKSUM_LEN: usize = 4;

/// blake3 of the receiver's Dilithium2 signing key: the shielded address, 32 bytes, the same
/// bytes as the transparent `Address` of that key (spec §1). Its text form is 53–55
/// characters (base58 is variable length; 54 typical).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReceiverId(pub [u8; 32]);

impl ReceiverId {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    fn checksum(&self) -> [u8; CHECKSUM_LEN] {
        let h = Hash::digest_domain(b"rand-receiver-addr-1", &self.0);
        h.0[..CHECKSUM_LEN].try_into().unwrap()
    }
    pub fn parse(s: &str) -> Result<ReceiverId, RecordError> {
        let rest = s.strip_prefix(ADDRESS_PREFIX).ok_or(RecordError::Prefix)?;
        let raw = bs58::decode(rest).into_vec().map_err(|_| RecordError::Base58)?;
        if raw.len() == 32 + KEM_EK_BYTES { return Err(RecordError::LongForm); }
        if raw.len() != 32 + CHECKSUM_LEN { return Err(RecordError::Length(raw.len())); }
        let id = ReceiverId(raw[..32].try_into().unwrap());
        if raw[32..] != id.checksum() { return Err(RecordError::Checksum); }
        Ok(id)
    }
}
impl From<&PublicKey> for ReceiverId { fn from(pk: &PublicKey) -> Self { ReceiverId(pk.address().0) } }
impl From<Address> for ReceiverId { fn from(a: Address) -> Self { ReceiverId(a.0) } }
impl std::fmt::Display for ReceiverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut raw = self.0.to_vec();
        raw.extend_from_slice(&self.checksum());
        write!(f, "{ADDRESS_PREFIX}{}", bs58::encode(raw).into_string())
    }
}
impl std::fmt::Debug for ReceiverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self}") }
}
impl std::str::FromStr for ReceiverId {
    type Err = RecordError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { ReceiverId::parse(s) }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum RecordError {
    #[error("shielded address must start with {ADDRESS_PREFIX}")] Prefix,
    #[error("shielded address is not base58")] Base58,
    #[error("this is the pre-chain-11 long address form (pk + KEM key); chain 11 addresses are 54 characters — ask the receiver for their current address")] LongForm,
    #[error("shielded address decodes to {0} bytes, expected 36")] Length(usize),
    #[error("shielded address checksum mismatch")] Checksum,
    #[error("the record's signing key is not the address's")] WrongId,
    #[error("the record's signature does not verify")] BadSignature,
    #[error("the record's KEM key is {0} bytes, expected {KEM_EK_BYTES}")] KemLength(usize),
    #[error("the record is {0} bytes, over the {MAX_RECORD_BYTES}-byte cap")] TooLarge(usize),
}

/// The signed, versioned record a receiver id resolves to (spec §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverRecord {
    pub version: u32,
    pub pk: Word8,
    pub kem_ek: Vec<u8>,
    pub signing_key: PublicKey,
    pub signature: Signature,
}

impl ReceiverRecord {
    pub fn signing_hash(chain_id: u64, version: u32, pk: &Word8, kem_ek: &[u8]) -> Hash {
        let mut buf = Vec::with_capacity(8 + 4 + 32 + kem_ek.len());
        buf.extend_from_slice(&chain_id.to_be_bytes());
        buf.extend_from_slice(&version.to_be_bytes());
        buf.extend_from_slice(&word8_to_bytes(pk));
        buf.extend_from_slice(kem_ek);
        Hash::digest_domain(b"rand-receiver-record-1", &buf)
    }
    pub fn sign(kp: &Keypair, chain_id: u64, version: u32, pk: Word8, kem_ek: Vec<u8>) -> ReceiverRecord {
        let signature = kp.sign(Self::signing_hash(chain_id, version, &pk, &kem_ek).as_bytes());
        ReceiverRecord { version, pk, kem_ek, signing_key: kp.public_key().clone(), signature }
    }
    pub fn id(&self) -> ReceiverId { ReceiverId::from(&self.signing_key) }
    pub fn encoded_len(&self) -> usize { bincode::serialize(self).expect("serializes").len() }
    /// The one verifier (spec §3): the id, then the signature. Cheap checks first.
    pub fn verify(&self, id: &ReceiverId, chain_id: u64) -> Result<(), RecordError> {
        if self.kem_ek.len() != KEM_EK_BYTES { return Err(RecordError::KemLength(self.kem_ek.len())); }
        let len = self.encoded_len();
        if len > MAX_RECORD_BYTES { return Err(RecordError::TooLarge(len)); }
        if self.id() != *id { return Err(RecordError::WrongId); }
        let h = Self::signing_hash(chain_id, self.version, &self.pk, &self.kem_ek);
        if !self.signing_key.verify(h.as_bytes(), &self.signature) { return Err(RecordError::BadSignature); }
        Ok(())
    }
}

/// The receiver signing key, derived from the wallet's spend key (spec §1): nothing new to
/// back up, and the key that makes the id equal the wallet's transparent address.
pub fn receiver_signing_keypair(spend_key: &[u8; 32]) -> Keypair {
    let seed = Hash::digest_domain(b"rand-receiver-sign-1", spend_key);
    Keypair::from_seed(seed.0).expect("a 32-byte seed is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::notes::KEM_EK_BYTES;

    fn kp() -> Keypair { receiver_signing_keypair(&[7u8; 32]) }

    #[test]
    fn the_signing_key_derives_from_the_spend_key_and_the_id_is_its_address() {
        let a = receiver_signing_keypair(&[7u8; 32]);
        let b = receiver_signing_keypair(&[7u8; 32]);
        assert_eq!(a.public_key(), b.public_key(), "deterministic");
        assert_ne!(receiver_signing_keypair(&[8u8; 32]).public_key(), a.public_key());
        let id = ReceiverId::from(a.public_key());
        assert_eq!(id.0, a.address().0, "the receiver id is the transparent address of the signing key");
    }

    #[test]
    fn the_address_is_about_54_chars_and_round_trips() {
        let id = ReceiverId::from(kp().public_key());
        let s = id.to_string();
        assert!(s.starts_with("rand1"));
        assert!((53..=55).contains(&s.len()), "{s} is {} chars", s.len());
        assert_eq!(s.parse::<ReceiverId>().unwrap(), id);
    }

    #[test]
    fn the_address_refuses_a_bad_checksum_a_bad_prefix_and_the_long_form() {
        let id = ReceiverId::from(kp().public_key());
        let mut s = id.to_string();
        let last = s.pop().unwrap();
        s.push(if last == '1' { '2' } else { '1' });
        assert!(matches!(s.parse::<ReceiverId>(), Err(RecordError::Checksum)));
        assert!(matches!("xand1abc".parse::<ReceiverId>(), Err(RecordError::Prefix)));
        let long = format!("rand1{}", bs58::encode(vec![1u8; 32 + KEM_EK_BYTES]).into_string());
        assert!(matches!(long.parse::<ReceiverId>(), Err(RecordError::LongForm)));
    }

    #[test]
    fn a_record_verifies_and_every_tampering_is_refused() {
        let k = kp();
        let id = ReceiverId::from(k.public_key());
        let rec = ReceiverRecord::sign(&k, 11, 1, [3; 8], vec![9; KEM_EK_BYTES]);
        assert_eq!(rec.id(), id);
        rec.verify(&id, 11).unwrap();
        assert!(matches!(rec.verify(&ReceiverId([0; 32]), 11), Err(RecordError::WrongId)));
        assert!(matches!(rec.verify(&id, 12), Err(RecordError::BadSignature)), "chain id is in the hash");
        let mut t = rec.clone(); t.version = 2;
        assert!(matches!(t.verify(&id, 11), Err(RecordError::BadSignature)));
        let mut t = rec.clone(); t.pk[0] ^= 1;
        assert!(matches!(t.verify(&id, 11), Err(RecordError::BadSignature)));
        let mut t = rec.clone(); t.kem_ek[5] ^= 1;
        assert!(matches!(t.verify(&id, 11), Err(RecordError::BadSignature)));
        let mut t = rec.clone(); t.kem_ek.truncate(100);
        assert!(matches!(t.verify(&id, 11), Err(RecordError::KemLength(100))));
        let other = receiver_signing_keypair(&[8u8; 32]);
        let mut t = rec.clone(); t.signing_key = other.public_key().clone();
        assert!(matches!(t.verify(&id, 11), Err(RecordError::WrongId)));
        assert!(rec.encoded_len() < MAX_RECORD_BYTES, "{}", rec.encoded_len());
    }
}
