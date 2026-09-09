//! Cryptographic primitives: BLAKE3 hashes, Dilithium2 keys and signatures,
//! and 32-byte addresses derived from public keys.

use crystals_dilithium::dilithium2;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

pub const HASH_LEN: usize = 32;
pub const SEED_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = dilithium2::PUBLICKEYBYTES;
pub const SIGNATURE_LEN: usize = dilithium2::SIGNBYTES;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid length for {kind}: expected {expected}, got {actual}")]
    InvalidLength {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid base58 encoding")]
    InvalidBase58,
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("key generation failed: {0}")]
    KeyGen(String),
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/// 32-byte BLAKE3 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; HASH_LEN]);

    pub fn digest(data: &[u8]) -> Hash {
        Hash(*blake3::hash(data).as_bytes())
    }

    /// Domain-separated hash: `blake3(domain || data)`.
    pub fn digest_domain(domain: &[u8], data: &[u8]) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(domain);
        h.update(data);
        Hash(*h.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Hash, CryptoError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidHex)?;
        let arr: [u8; HASH_LEN] = bytes.try_into().map_err(|v: Vec<u8>| CryptoError::InvalidLength {
            kind: "hash",
            expected: HASH_LEN,
            actual: v.len(),
        })?;
        Ok(Hash(arr))
    }

    pub fn is_zero(&self) -> bool {
        *self == Hash::ZERO
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Merkle root over a list of hashes (BLAKE3, duplicate-last for odd levels).
/// Empty list hashes to `Hash::ZERO`.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::ZERO;
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0].0);
                buf[32..].copy_from_slice(&pair[1].0);
                Hash::digest_domain(b"shrugg-merkle-node", &buf)
            })
            .collect();
    }
    level[0]
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// 32-byte account address = blake3(public key). Rendered as base58.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Address(pub [u8; HASH_LEN]);

impl Address {
    pub const ZERO: Address = Address([0u8; HASH_LEN]);

    pub fn from_public_key(pk: &PublicKey) -> Address {
        Address(Hash::digest_domain(b"shrugg-address", pk.as_bytes()).0)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    pub fn from_base58(s: &str) -> Result<Address, CryptoError> {
        let bytes = bs58::decode(s).into_vec().map_err(|_| CryptoError::InvalidBase58)?;
        let arr: [u8; HASH_LEN] = bytes.try_into().map_err(|v: Vec<u8>| CryptoError::InvalidLength {
            kind: "address",
            expected: HASH_LEN,
            actual: v.len(),
        })?;
        Ok(Address(arr))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_base58();
        write!(f, "{}..{}", &s[..6], &s[s.len() - 4..])
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl std::str::FromStr for Address {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_base58(s)
    }
}

// ---------------------------------------------------------------------------
// Public key
// ---------------------------------------------------------------------------

/// Dilithium2 public key (1312 bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "serde_bytes_vec")] Vec<u8>);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                kind: "public key",
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(PublicKey(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn address(&self) -> Address {
        Address::from_public_key(self)
    }

    /// Verify `sig` over `msg`. Returns false on any malformed input.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        if self.0.len() != PUBLIC_KEY_LEN {
            return false;
        }
        match dilithium2::PublicKey::from_bytes(&self.0) {
            Ok(pk) => pk.verify(msg, sig.as_bytes()),
            Err(_) => false,
        }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<PublicKey, CryptoError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidHex)?;
        PublicKey::from_bytes(&bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({:?})", self.address())
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// Dilithium2 signature (2420 bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_bytes_vec")] Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, CryptoError> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength {
                kind: "signature",
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Signature(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// A placeholder of the correct length, used before a message is signed.
    pub fn empty() -> Signature {
        Signature(vec![0u8; SIGNATURE_LEN])
    }

    pub fn is_well_formed(&self) -> bool {
        self.0.len() == SIGNATURE_LEN
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}..)", hex::encode(&self.0[..4.min(self.0.len())]))
    }
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

/// Dilithium2 keypair, deterministically derived from a 32-byte seed.
pub struct Keypair {
    seed: [u8; SEED_LEN],
    inner: dilithium2::Keypair,
    public: PublicKey,
}

impl Keypair {
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Result<Keypair, CryptoError> {
        let inner = dilithium2::Keypair::generate(Some(&seed))
            .map_err(|e| CryptoError::KeyGen(e.to_string()))?;
        let public = PublicKey(inner.public.to_bytes().to_vec());
        Ok(Keypair { seed, inner, public })
    }

    pub fn generate() -> Keypair {
        use rand::RngCore;
        let mut seed = [0u8; SEED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Keypair::from_seed(seed).expect("random seed is valid")
    }

    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn address(&self) -> Address {
        self.public.address()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.inner.sign(msg).to_vec())
    }

    /// Derive a 32-byte secret for a sub-purpose (e.g. the libp2p identity key).
    pub fn derive_subkey(&self, purpose: &[u8]) -> [u8; 32] {
        Hash::digest_domain(purpose, &self.seed).0
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keypair({:?})", self.address())
    }
}

/// Serialize Vec<u8> as bytes for bincode and as hex for JSON.
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(v))
        } else {
            s.serialize_bytes(v)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)
        } else {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                    Ok(v.to_vec())
                }
                fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                    Ok(v)
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                    let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(out)
                }
            }
            d.deserialize_bytes(V)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_deterministic_from_seed() {
        let a = Keypair::from_seed([7u8; 32]).unwrap();
        let b = Keypair::from_seed([7u8; 32]).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.address(), b.address());
        let c = Keypair::from_seed([8u8; 32]).unwrap();
        assert_ne!(a.address(), c.address());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::from_seed([1u8; 32]).unwrap();
        let sig = kp.sign(b"hello");
        assert_eq!(sig.as_bytes().len(), SIGNATURE_LEN);
        assert!(kp.public_key().verify(b"hello", &sig));
        assert!(!kp.public_key().verify(b"hellp", &sig));
        let other = Keypair::from_seed([2u8; 32]).unwrap();
        assert!(!other.public_key().verify(b"hello", &sig));
        assert!(!kp.public_key().verify(b"hello", &Signature::empty()));
    }

    #[test]
    fn address_base58_roundtrip() {
        let kp = Keypair::from_seed([3u8; 32]).unwrap();
        let s = kp.address().to_base58();
        assert_eq!(Address::from_base58(&s).unwrap(), kp.address());
        assert!(Address::from_base58("not-base58-!!").is_err());
        assert!(Address::from_base58("1111").is_err());
    }

    #[test]
    fn public_key_length_enforced() {
        assert!(PublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(Signature::from_bytes(&[0u8; 10]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; PUBLIC_KEY_LEN]).is_ok());
    }

    #[test]
    fn bincode_and_json_roundtrip() {
        let kp = Keypair::from_seed([4u8; 32]).unwrap();
        let sig = kp.sign(b"x");
        let pk = kp.public_key().clone();
        let bin = bincode::serialize(&(pk.clone(), sig.clone())).unwrap();
        assert_eq!(bin.len(), 8 + PUBLIC_KEY_LEN + 8 + SIGNATURE_LEN);
        let (pk2, sig2): (PublicKey, Signature) = bincode::deserialize(&bin).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sig, sig2);
        let js = serde_json::to_string(&pk).unwrap();
        assert!(js.starts_with("\""));
        let pk3: PublicKey = serde_json::from_str(&js).unwrap();
        assert_eq!(pk, pk3);
    }

    #[test]
    fn merkle_root_properties() {
        assert_eq!(merkle_root(&[]), Hash::ZERO);
        let a = Hash::digest(b"a");
        let b = Hash::digest(b"b");
        let c = Hash::digest(b"c");
        assert_eq!(merkle_root(&[a]), a);
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
        assert_eq!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c]));
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b]));
    }

    #[test]
    fn hash_hex_roundtrip() {
        let h = Hash::digest(b"z");
        assert_eq!(Hash::from_hex(&h.to_hex()).unwrap(), h);
        assert_eq!(Hash::from_hex(&format!("0x{}", h.to_hex())).unwrap(), h);
        assert!(Hash::from_hex("zz").is_err());
    }
}
