//! The address fingerprint (spec 2026-09-26 §2.1): 80 bits of a domain-tagged blake3 over the
//! address's raw bytes, as 16 Crockford base32 digits a person can read out and compare.
//! Display only — nothing on chain or on the wire carries one.

use crate::crypto::Hash;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DOMAIN: &[u8] = b"rand-address-fingerprint-1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 10]);

impl Fingerprint {
    /// Over the address's raw bytes (`pk` ‖ `kem_ek`, the 1 216 bytes its text form encodes).
    pub fn of_raw(raw: &[u8]) -> Fingerprint {
        let h = Hash::digest_domain(DOMAIN, raw).0;
        Fingerprint(h[..10].try_into().unwrap())
    }

    fn digits(&self) -> [u8; 16] {
        let n = u128::from_be_bytes([[0u8; 6].as_slice(), &self.0].concat().try_into().unwrap());
        std::array::from_fn(|i| ALPHABET[((n >> (5 * (15 - i))) & 31) as usize])
    }

    /// Case- and hyphen-insensitive; `O` reads as `0`, `I`/`L` as `1`.
    pub fn parse(s: &str) -> Option<Fingerprint> {
        let mut n: u128 = 0;
        let mut count = 0;
        for c in s.chars().filter(|&c| c != '-') {
            let c = match c.to_ascii_uppercase() { 'O' => '0', 'I' | 'L' => '1', c => c };
            let d = ALPHABET.iter().position(|&a| a as char == c)? as u128;
            n = (n << 5) | d;
            count += 1;
        }
        if count != 16 { return None; }
        Some(Fingerprint(n.to_be_bytes()[6..].try_into().unwrap()))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = self.digits();
        let s = std::str::from_utf8(&d).unwrap();
        write!(f, "{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
    }
}
