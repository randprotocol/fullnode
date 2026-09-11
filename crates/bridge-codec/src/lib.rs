//! Rand bridge attestation wire format.
//!
//! `no_std` + `alloc`, zero dependencies: this crate is the single source of
//! truth for the Wormhole-shaped attestation byte layout shared by the
//! Solidity contracts, the Solana program, and the Rand fullnode. Hashing
//! and ECDSA are deliberately NOT performed here; callers inject a keccak256
//! and a secp256k1 verifier.
#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod envelope;
mod payload;

pub use envelope::{Attestation, Body, Signature};
pub use payload::{GuardianSetUpgrade, Payload, Transfer};

/// Rand's own chain id in the bridge's chain-id space.
pub const CHAIN_RAND: u16 = 1;
/// Ethereum's chain id in the bridge's chain-id space.
pub const CHAIN_ETHEREUM: u16 = 2;
/// BSC's chain id in the bridge's chain-id space.
pub const CHAIN_BSC: u16 = 3;
/// Tron's chain id in the bridge's chain-id space.
pub const CHAIN_TRON: u16 = 4;
/// Solana's chain id in the bridge's chain-id space.
pub const CHAIN_SOLANA: u16 = 5;

/// Wire format version encoded in byte 0 of an [`Attestation`].
pub const VERSION: u8 = 1;
/// Exact encoded length, in bytes, of a [`Payload::Transfer`].
pub const TRANSFER_PAYLOAD_LEN: usize = 133;
/// Guardian grace period after a guardian-set upgrade, in seconds.
pub const GUARDIAN_GRACE_SECS: u64 = 86_400;

/// `keccak256("rand-bridge-governance")`, pinned via
/// `cast keccak "rand-bridge-governance"`.
///
/// This crate has no keccak256 of its own, so the value is pinned here as a
/// literal; `shrugg-core` (Task A2) carries a test that hashes the string
/// `"rand-bridge-governance"` and asserts it matches this constant.
pub const GOVERNANCE_EMITTER: [u8; 32] = [
    0xb8, 0x6d, 0xc2, 0x9d, 0x18, 0x21, 0x46, 0x83, 0x1b, 0xe3, 0x19, 0xf8, 0xcd, 0xd0, 0xbe, 0x86,
    0xac, 0xe8, 0x23, 0x41, 0x3a, 0x47, 0x74, 0x58, 0xbf, 0x67, 0xff, 0xb1, 0x51, 0xb2, 0xb5, 0x5f,
];

/// A guardian's public identity: the last 20 bytes of
/// `keccak256(uncompressed_pubkey[1..])`.
pub type GuardianKey = [u8; 20];

/// secp256k1 curve order `n`, divided by two, big-endian. Used by
/// [`is_low_s`] to enforce the low-s signature malleability rule.
pub const SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Errors that can occur while decoding an [`Attestation`] or [`Payload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The leading version byte was not [`VERSION`].
    BadVersion,
    /// The input ended before a required field could be read.
    Truncated,
    /// The payload id byte did not match a known [`Payload`] variant.
    BadPayloadId,
    /// A fixed-length payload (currently only [`Payload::Transfer`]) had the
    /// wrong total length.
    BadPayloadLength,
    /// A guardian-set upgrade listed more guardian keys than fit in the
    /// wire format's single-byte count.
    TooManyGuardians,
    /// A guardian-set upgrade listed zero guardian keys.
    ZeroGuardians,
    /// There were extra bytes after a variable-length payload was fully
    /// decoded.
    TrailingBytes,
}

/// Byte cursor shared by [`envelope`] and [`payload`] decoders.
pub(crate) struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.p + n > self.b.len() {
            return Err(CodecError::Truncated);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, CodecError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes(s.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes(s.try_into().unwrap()))
    }

    pub(crate) fn arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub(crate) fn pos(&self) -> usize {
        self.p
    }
}

/// Guardian quorum size for a guardian set of `n` keys: `n * 2 / 3 + 1`.
pub fn quorum(n: usize) -> usize {
    n * 2 / 3 + 1
}

/// Errors from [`check_indices`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexError {
    /// Fewer than `need` signatures were present.
    NoQuorum { have: usize, need: usize },
    /// Signature indices were not strictly increasing.
    IndexOrder,
    /// A signature index was `>= n`.
    IndexOutOfRange,
}

/// Validates a set of guardian signatures against a guardian set of size
/// `n`: indices must be strictly increasing, every index must be `< n`, and
/// there must be at least `quorum(n)` of them.
pub fn check_indices(sigs: &[Signature], n: usize) -> Result<(), IndexError> {
    let mut prev: Option<u8> = None;
    for sig in sigs {
        if sig.index as usize >= n {
            return Err(IndexError::IndexOutOfRange);
        }
        if let Some(p) = prev {
            if sig.index <= p {
                return Err(IndexError::IndexOrder);
            }
        }
        prev = Some(sig.index);
    }
    let need = quorum(n);
    if sigs.len() < need {
        return Err(IndexError::NoQuorum {
            have: sigs.len(),
            need,
        });
    }
    Ok(())
}

/// Returns true if `s <= n/2` for the secp256k1 curve order `n`, i.e. `s` is
/// the "low-s" canonical form required of guardian signatures.
pub fn is_low_s(s: &[u8; 32]) -> bool {
    *s <= SECP256K1_HALF_N
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Decodes a 64-char hex string into a 32-byte array. Test-only, no
    /// dependencies: a tiny nibble parser.
    fn hex(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "hex helper expects a 64-char hex string");
        fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("invalid hex digit"),
            }
        }
        let bytes = s.as_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = nibble(bytes[2 * i]);
            let lo = nibble(bytes[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    #[test]
    fn transfer_payload_is_133_bytes_and_round_trips() {
        let t = Transfer {
            amount: Transfer::u256_from_u128(123_456_789),
            token_address: [7; 32],
            token_chain: CHAIN_ETHEREUM,
            to: [9; 32],
            to_chain: CHAIN_RAND,
            fee: Transfer::u256_from_u128(5),
        };
        let bytes = Payload::Transfer(t.clone()).encode();
        assert_eq!(bytes.len(), TRANSFER_PAYLOAD_LEN);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..33], &t.amount);
        assert_eq!(&bytes[65..67], &CHAIN_ETHEREUM.to_be_bytes());
        assert_eq!(Payload::decode(&bytes), Ok(Payload::Transfer(t)));
    }

    #[test]
    fn envelope_round_trips_and_body_bytes_are_the_tail() {
        let body = Body {
            timestamp: 1,
            nonce: 2,
            emitter_chain: 3,
            emitter_address: [4; 32],
            sequence: 5,
            consistency_level: 6,
            payload: vec![1, 2, 3],
        };
        let att = Attestation {
            guardian_set_index: 9,
            signatures: vec![Signature {
                index: 0,
                r: [1; 32],
                s: [2; 32],
                v: 1,
            }],
            body: body.clone(),
        };
        let bytes = att.encode();
        assert_eq!(bytes[0], VERSION);
        assert_eq!(&bytes[1..5], &9u32.to_be_bytes());
        assert_eq!(bytes[5], 1);
        assert_eq!(bytes.len(), 6 + 66 + 51 + 3);
        assert_eq!(Attestation::body_bytes(&bytes).unwrap(), &body.encode()[..]);
        assert_eq!(Attestation::decode(&bytes), Ok(att));
    }

    #[test]
    fn rejects_bad_version_truncation_and_bad_payloads() {
        assert_eq!(
            Attestation::decode(&[2, 0, 0, 0, 0, 0]),
            Err(CodecError::BadVersion)
        );
        assert_eq!(
            Attestation::decode(&[1, 0, 0, 0, 0, 1, 0]),
            Err(CodecError::Truncated)
        );
        assert_eq!(Payload::decode(&[3]), Err(CodecError::BadPayloadId));
        assert_eq!(
            Payload::decode(&[1; 132]),
            Err(CodecError::BadPayloadLength)
        );
        assert_eq!(
            Payload::decode(&[2, 0, 0, 0, 1, 0]),
            Err(CodecError::ZeroGuardians)
        );
        let mut up = vec![2, 0, 0, 0, 1, 1];
        up.extend([0u8; 20]);
        up.push(0xff);
        assert_eq!(Payload::decode(&up), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn quorum_and_index_rules() {
        assert_eq!(quorum(6), 5);
        assert_eq!(quorum(4), 3);
        assert_eq!(quorum(1), 1);
        let sig = |i| Signature {
            index: i,
            r: [0; 32],
            s: [0; 32],
            v: 0,
        };
        assert_eq!(
            check_indices(&[sig(0), sig(1), sig(2), sig(3), sig(4)], 6),
            Ok(())
        );
        assert_eq!(
            check_indices(&[sig(0), sig(1), sig(2), sig(3)], 6),
            Err(IndexError::NoQuorum { have: 4, need: 5 })
        );
        assert_eq!(
            check_indices(&[sig(0), sig(0), sig(0), sig(0), sig(0)], 6),
            Err(IndexError::IndexOrder)
        );
        assert_eq!(
            check_indices(&[sig(0), sig(1), sig(2), sig(3), sig(6)], 6),
            Err(IndexError::IndexOutOfRange)
        );
        assert!(is_low_s(&[0; 32]));
        let mut half_n =
            hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");
        assert!(is_low_s(&half_n));
        half_n[31] += 1;
        assert!(!is_low_s(&half_n));
    }
}
