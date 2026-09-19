//! A token's checksummed text form, `rpl1…` (bridge hardening spec §8): **bech32m** (BIP-350)
//! with the human-readable part `rpl` over the 32-byte [`AssetId`] — 52 data characters and a
//! six-character checksum, 62 characters in all.
//!
//! Shown beside the 64-hex id wherever a token is named (`rand_getTokens` rows, `rand_getToken`),
//! and accepted wherever one is looked up; hex stays accepted too. Parsing is strict: a bad
//! checksum, another HRP, a payload that is not exactly 32 bytes (or carries non-zero padding
//! bits) and a string mixing upper and lower case are each refused, so a mistyped id is an error
//! rather than some other token.
//!
//! Implemented here rather than through a crate: bech32m is a polymod and a base-32 regrouping,
//! and pinning it against BIP-350's own vectors (the tests below) costs less than a dependency.

use crate::bridge::AssetId;
use crate::crypto::Hash;

/// The human-readable part of a token id's text form.
pub const HRP: &str = "rpl";
/// Length of every `rpl1…` string: HRP, separator, 52 data characters, 6 checksum characters.
pub const TEXT_LEN: usize = HRP.len() + 1 + 52 + 6;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// BIP-350's checksum constant — what makes this bech32**m** rather than BIP-173's bech32 (1).
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Why a string is not a token id's text form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenIdError {
    #[error("a token id mixes upper and lower case")]
    MixedCase,
    #[error("a token id has no '1' separator")]
    NoSeparator,
    #[error("a token id starts with {0:?}, not \"rpl1\"")]
    WrongHrp(String),
    #[error("a token id holds a character outside the bech32 alphabet")]
    BadCharacter,
    #[error("a token id's checksum does not match (a typo, or not a bech32m string)")]
    BadChecksum,
    #[error("a token id must be {TEXT_LEN} characters, got {0}")]
    WrongLength(usize),
    #[error("a token id's payload is not a clean 32 bytes")]
    BadPadding,
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes().map(|c| c >> 5).chain(std::iter::once(0)).chain(hrp.bytes().map(|c| c & 31))
}

/// The 32 bytes regrouped into 52 five-bit groups, the last one zero-padded.
fn to_base32(bytes: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// `id` as `rpl1…`, always lower case.
pub fn encode(id: &AssetId) -> String {
    let data = to_base32(id.as_bytes());
    let pm = polymod(hrp_expand(HRP).chain(data.iter().copied()).chain([0u8; 6])) ^ BECH32M_CONST;
    let mut s = String::with_capacity(TEXT_LEN);
    s.push_str(HRP);
    s.push('1');
    for d in data.iter().copied().chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8)) {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

/// Parse an `rpl1…` string (all lower or all upper case) back to its [`AssetId`].
pub fn decode(text: &str) -> Result<AssetId, TokenIdError> {
    let has_lower = text.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = text.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(TokenIdError::MixedCase);
    }
    let text = text.to_ascii_lowercase();
    let sep = text.rfind('1').ok_or(TokenIdError::NoSeparator)?;
    let (hrp, rest) = (&text[..sep], &text[sep + 1..]);
    if hrp != HRP {
        return Err(TokenIdError::WrongHrp(hrp.chars().take(16).collect()));
    }
    if text.len() != TEXT_LEN {
        return Err(TokenIdError::WrongLength(text.len()));
    }
    let data = rest
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or(TokenIdError::BadCharacter)?;
    if polymod(hrp_expand(HRP).chain(data.iter().copied())) != BECH32M_CONST {
        return Err(TokenIdError::BadChecksum);
    }
    let payload = &data[..data.len() - 6];
    let mut bytes = Vec::with_capacity(32);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &d in payload {
        acc = (acc << 5) | u32::from(d);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // 52 groups are 260 bits: 32 bytes and four padding bits, which must be zero — otherwise two
    // strings would name one id.
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return Err(TokenIdError::BadPadding);
    }
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| TokenIdError::BadPadding)?;
    Ok(Hash(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(bytes: [u8; 32]) -> AssetId {
        Hash(bytes)
    }

    fn counting() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    /// Fixed vectors, cross-checked against BIP-350's reference implementation.
    const COUNTING: &str = "rpl1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0sa8xk4p";
    const ZERO: &str = "rpl1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5nd54c";
    const ONES: &str = "rpl1lllllllllllllllllllllllllllllllllllllllllllllllllllskdw9u0";

    #[test]
    fn a_fixed_id_encodes_to_its_vector_and_back() {
        for (bytes, text) in [(counting(), COUNTING), ([0u8; 32], ZERO), ([0xff; 32], ONES)] {
            assert_eq!(encode(&id(bytes)), text);
            assert_eq!(text.len(), TEXT_LEN);
            assert_eq!(decode(text), Ok(id(bytes)));
            // All upper case is the same string, as BIP-173 allows.
            assert_eq!(decode(&text.to_ascii_uppercase()), Ok(id(bytes)));
        }
    }

    /// The polymod is BIP-350's: its own two valid bech32m vectors check.
    #[test]
    fn the_checksum_is_bip350s() {
        for s in ["a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"] {
            let sep = s.rfind('1').unwrap();
            let data: Vec<u8> =
                s[sep + 1..].bytes().map(|c| CHARSET.iter().position(|&x| x == c).unwrap() as u8).collect();
            assert_eq!(polymod(hrp_expand(&s[..sep]).chain(data)), BECH32M_CONST, "{s}");
        }
    }

    #[test]
    fn a_bad_checksum_is_refused() {
        let mut s = COUNTING.to_string();
        // Swap one data character for another alphabet character.
        let i = 10;
        let c = if &s[i..i + 1] == "q" { "p" } else { "q" };
        s.replace_range(i..i + 1, c);
        assert_eq!(decode(&s), Err(TokenIdError::BadChecksum));
        let mut last = COUNTING.to_string();
        last.pop();
        last.push('q');
        assert_eq!(decode(&last), Err(TokenIdError::BadChecksum));
    }

    #[test]
    fn a_wrong_hrp_is_refused() {
        // A bech32m string under another HRP with a valid checksum of its own.
        let data = to_base32(&counting());
        let pm = polymod(hrp_expand("rpx").chain(data.iter().copied()).chain([0u8; 6])) ^ BECH32M_CONST;
        let mut s = String::from("rpx1");
        for d in data.iter().copied().chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8)) {
            s.push(CHARSET[d as usize] as char);
        }
        assert_eq!(decode(&s), Err(TokenIdError::WrongHrp("rpx".into())));
        // A shielded address is not a token id.
        assert!(matches!(decode("rand1qqqq"), Err(TokenIdError::WrongHrp(_))));
        assert_eq!(decode("qqqq"), Err(TokenIdError::NoSeparator));
    }

    #[test]
    fn a_wrong_length_is_refused() {
        // A checksum-valid bech32m string over 31 bytes: its length, not its checksum, refuses it.
        let short = {
            let mut data = to_base32(&counting());
            data.truncate(50); // 250 bits: 31 bytes and 2 padding bits
            let pm = polymod(hrp_expand(HRP).chain(data.iter().copied()).chain([0u8; 6])) ^ BECH32M_CONST;
            let mut s = String::from("rpl1");
            for d in data.iter().copied().chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8)) {
                s.push(CHARSET[d as usize] as char);
            }
            s
        };
        assert_eq!(decode(&short), Err(TokenIdError::WrongLength(short.len())));
        assert_eq!(decode(&format!("{COUNTING}q")), Err(TokenIdError::WrongLength(TEXT_LEN + 1)));
        assert_eq!(decode("rpl1"), Err(TokenIdError::WrongLength(4)));
    }

    #[test]
    fn non_zero_padding_bits_are_refused() {
        // The last data group carries four padding bits; set one and re-checksum.
        let mut data = to_base32(&counting());
        data[51] |= 1;
        let pm = polymod(hrp_expand(HRP).chain(data.iter().copied()).chain([0u8; 6])) ^ BECH32M_CONST;
        let mut s = String::from("rpl1");
        for d in data.iter().copied().chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8)) {
            s.push(CHARSET[d as usize] as char);
        }
        assert_eq!(decode(&s), Err(TokenIdError::BadPadding));
    }

    #[test]
    fn mixed_case_and_foreign_characters_are_refused() {
        let mut mixed = COUNTING.to_string();
        mixed.replace_range(5..6, &COUNTING[5..6].to_ascii_uppercase());
        assert_eq!(decode(&mixed), Err(TokenIdError::MixedCase));
        let mut bad = COUNTING.to_string();
        bad.replace_range(10..11, "b"); // 'b' is not in the bech32 alphabet
        assert_eq!(decode(&bad), Err(TokenIdError::BadCharacter));
    }
}
