//! Address text formats (short-address spec §4): Bech32m strings with the 90-character limit
//! removed, in two types — the **direct** form (`q`) carrying `pk || kem_ek || check4`, payable
//! with no lookup, and the **short** form (`s`) carrying the 32-byte receiver id, payable once
//! the id is in the receiver registry. The legacy `rand1` + base58 form still parses (F-8).
//!
//! The checksum is written here rather than taken from a crate: a stock Bech32m decoder stops
//! at the code's 1,023-character length, and the direct form is 1,963 (F-4a).

use crate::crypto::Hash;
use crate::notes::{word8_from_bytes, word8_to_bytes, ShieldedAddress, Word8, KEM_EK_BYTES};

/// The legacy text prefix: `rand1` + base58(`pk || kem_ek`). Parsed, never emitted (F-9).
pub const LEGACY_PREFIX: &str = "rand1";
/// F-4: nothing longer is decoded (matches the node RPC's `MAX_ADDRESS_CHARS`).
pub const MAX_ADDRESS_CHARS: usize = 2000;
/// The receiver id's hash domain: the bridge's `recipient_hash`, unchanged (spec §5).
pub const ID_DOMAIN: &[u8] = b"rand-shielded-recipient";
const CHECK_DOMAIN: &[u8] = b"rand-addr-check-1";
const TYPE_DIRECT: u8 = 0; // 'q'
const TYPE_SHORT: u8 = 16; // 's'
const DIRECT_PAYLOAD: usize = 32 + KEM_EK_BYTES + 4;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// The network class an address is for (spec §4.1): the hrp names a class, not a chain id, so
/// a re-cut test chain keeps its addresses while a test string can never pay the main network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
    Dev,
}

impl Network {
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Main => "rnd",
            Network::Test => "trnd",
            Network::Dev => "drnd",
        }
    }

    fn from_hrp(hrp: &str) -> Option<Network> {
        [Network::Main, Network::Test, Network::Dev]
            .into_iter()
            .find(|n| n.hrp() == hrp)
    }

    /// This process's network. Every chain so far is a test network, so `Test` unless
    /// `RAND_NETWORK` says `main` or `dev`; read once.
    pub fn current() -> Network {
        static NET: std::sync::OnceLock<Network> = std::sync::OnceLock::new();
        *NET.get_or_init(|| match std::env::var("RAND_NETWORK").as_deref() {
            Ok("main") => Network::Main,
            Ok("dev") => Network::Dev,
            _ => Network::Test,
        })
    }
}

/// A receiver id: `BLAKE3("rand-shielded-recipient" || pk || kem_ek)`, the 32 bytes a short
/// address carries and the receiver registry is keyed by. Byte-identical to
/// [`ShieldedAddress::recipient_hash`].
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ReceiverId(pub [u8; 32]);

impl ReceiverId {
    pub fn of(pk: &Word8, kem_ek: &[u8]) -> ReceiverId {
        let mut raw = word8_to_bytes(pk).to_vec();
        raw.extend_from_slice(kem_ek);
        ReceiverId(Hash::digest_domain(ID_DOMAIN, &raw).0)
    }

    pub fn of_address(a: &ShieldedAddress) -> ReceiverId {
        ReceiverId::of(&a.pk, &a.kem_ek)
    }

    /// The short address for this id on `net`.
    pub fn to_short(&self, net: Network) -> String {
        encode(net.hrp(), TYPE_SHORT, &self.0)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ReceiverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_short(Network::current()))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AddressError {
    #[error("address is {0} characters, at most {MAX_ADDRESS_CHARS} allowed")]
    TooLong(usize),
    #[error("address mixes upper and lower case")]
    MixedCase,
    #[error("address has no separator")]
    NoSeparator,
    #[error("unknown address prefix {0:?}")]
    UnknownPrefix(String),
    #[error("this is a {found} address; this node is on {expected}")]
    WrongNetwork {
        expected: &'static str,
        found: &'static str,
    },
    #[error("address contains a character outside the Bech32 alphabet")]
    BadCharacter,
    #[error("address checksum does not match (a mistyped character?)")]
    BadChecksum,
    #[error("reserved address type {0}")]
    ReservedType(u8),
    #[error("address has non-zero padding bits")]
    BadPadding,
    #[error("address payload is {got} bytes, expected {expected}")]
    Length { got: usize, expected: usize },
    #[error("address inner check does not match")]
    BadInnerCheck,
    #[error("address key is not canonical (a limb at or above the Goldilocks modulus)")]
    NonCanonicalPk,
    #[error("legacy address is not base58")]
    Base58,
    #[error(
        "this is a short address; it names a receiver id and needs resolving before it can be paid"
    )]
    ShortNotDirect,
}

/// What a decoded string was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// `rnd1q…`: the keys themselves.
    Direct(ShieldedAddress),
    /// `rnd1s…`: a receiver id, to resolve through the registry.
    Short(ReceiverId),
    /// `rand1…`: today's base58 form.
    Legacy(ShieldedAddress),
}

/// F-6: each of the four 64-bit limbs of `pk` (low word, high word) is below the Goldilocks
/// modulus `2^64 − 2^32 + 1`.
pub fn pk_is_canonical(pk: &Word8) -> bool {
    const P: u64 = 0xffff_ffff_0000_0001;
    (0..4).all(|i| ((pk[2 * i + 1] as u64) << 32 | pk[2 * i] as u64) < P)
}

/// The direct form of `a` on `net`: `hrp 1 q base32(pk || kem_ek || check4) checksum`.
pub fn encode_direct(a: &ShieldedAddress, net: Network) -> String {
    let mut payload = word8_to_bytes(&a.pk).to_vec();
    payload.extend_from_slice(&a.kem_ek);
    payload.extend_from_slice(&check4(net.hrp(), &a.pk, &a.kem_ek));
    encode(net.hrp(), TYPE_DIRECT, &payload)
}

/// Decode any address form for this process's network ([`Network::current`]).
pub fn decode(s: &str) -> Result<Decoded, AddressError> {
    decode_for(s, Network::current())
}

/// Decode any address form, requiring a Bech32m string's hrp to be `net`'s (F-2). A legacy
/// string carries no network and is accepted on every network, as it always has been.
pub fn decode_for(s: &str, net: Network) -> Result<Decoded, AddressError> {
    // F-4 before any decoding work.
    if s.len() > MAX_ADDRESS_CHARS {
        return Err(AddressError::TooLong(s.len()));
    }
    if let Some(rest) = s.strip_prefix(LEGACY_PREFIX) {
        let raw = bs58::decode(rest)
            .into_vec()
            .map_err(|_| AddressError::Base58)?;
        return Ok(Decoded::Legacy(split_record(&raw, 32 + KEM_EK_BYTES)?));
    }
    // F-1: all-lower or all-upper.
    let has_lower = s.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = s.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(AddressError::MixedCase);
    }
    let s = s.to_ascii_lowercase();
    let sep = s.rfind('1').ok_or(AddressError::NoSeparator)?;
    let (hrp, data) = (&s[..sep], &s[sep + 1..]);
    let found =
        Network::from_hrp(hrp).ok_or_else(|| AddressError::UnknownPrefix(hrp.to_string()))?;
    if found != net {
        return Err(AddressError::WrongNetwork {
            expected: net.hrp(),
            found: found.hrp(),
        });
    }
    let values: Vec<u8> = data
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<_>>()
        .ok_or(AddressError::BadCharacter)?;
    if values.len() < 7 {
        return Err(AddressError::BadChecksum);
    }
    if polymod(&[hrp_expand(hrp), values.clone()].concat()) != BECH32M_CONST {
        return Err(AddressError::BadChecksum);
    }
    let body = &values[..values.len() - 6];
    let (ty, groups) = (body[0], &body[1..]);
    let payload = from_5bit(groups)?;
    match ty {
        TYPE_SHORT => {
            if payload.len() != 32 {
                return Err(AddressError::Length {
                    got: payload.len(),
                    expected: 32,
                });
            }
            Ok(Decoded::Short(ReceiverId(
                payload.try_into().expect("length checked"),
            )))
        }
        TYPE_DIRECT => {
            let a = split_record(&payload, DIRECT_PAYLOAD)?;
            // F-5: the inner check binds hrp and type independently of the BCH code.
            if payload[32 + KEM_EK_BYTES..] != check4(hrp, &a.pk, &a.kem_ek) {
                return Err(AddressError::BadInnerCheck);
            }
            Ok(Decoded::Direct(a))
        }
        other => Err(AddressError::ReservedType(other)),
    }
}

/// The keys an address string pays, when it carries them (direct or legacy); a short address
/// is [`AddressError::ShortNotDirect`] — it has to be resolved first.
pub fn parse_keys(s: &str) -> Result<ShieldedAddress, AddressError> {
    match decode(s)? {
        Decoded::Direct(a) | Decoded::Legacy(a) => Ok(a),
        Decoded::Short(_) => Err(AddressError::ShortNotDirect),
    }
}

/// `pk || kem_ek` (and, for the direct form, the four check bytes after them) out of `raw`,
/// with the length and F-6 canonicity checked.
fn split_record(raw: &[u8], expected: usize) -> Result<ShieldedAddress, AddressError> {
    if raw.len() != expected {
        return Err(AddressError::Length {
            got: raw.len(),
            expected,
        });
    }
    let pk = word8_from_bytes(&raw[..32]).expect("32 bytes");
    if !pk_is_canonical(&pk) {
        return Err(AddressError::NonCanonicalPk);
    }
    Ok(ShieldedAddress {
        pk,
        kem_ek: raw[32..32 + KEM_EK_BYTES].to_vec(),
    })
}

fn check4(hrp: &str, pk: &Word8, kem_ek: &[u8]) -> [u8; 4] {
    let mut data = hrp.as_bytes().to_vec();
    data.push(0);
    data.extend_from_slice(&word8_to_bytes(pk));
    data.extend_from_slice(kem_ek);
    Hash::digest_domain(CHECK_DOMAIN, &data).0[..4]
        .try_into()
        .expect("4 bytes")
}

fn encode(hrp: &str, ty: u8, payload: &[u8]) -> String {
    let mut values = vec![ty];
    values.extend(to_5bit(payload));
    let chk = polymod(&[hrp_expand(hrp), values.clone(), vec![0; 6]].concat()) ^ BECH32M_CONST;
    values.extend((0..6).map(|i| ((chk >> (5 * (5 - i))) & 31) as u8));
    let mut s = String::with_capacity(hrp.len() + 1 + values.len());
    s.push_str(hrp);
    s.push('1');
    s.extend(values.iter().map(|&v| CHARSET[v as usize] as char));
    s
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    b.iter()
        .map(|c| c >> 5)
        .chain([0])
        .chain(b.iter().map(|c| c & 31))
        .collect()
}

fn to_5bit(data: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity(data.len() * 8 / 5 + 1));
    for &b in data {
        acc = (acc << 8) | b as u32;
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

/// F-3: the inverse of [`to_5bit`], refusing a padding group of five or more bits or any
/// non-zero padding bit.
fn from_5bit(groups: &[u8]) -> Result<Vec<u8>, AddressError> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity(groups.len() * 5 / 8));
    for &g in groups {
        acc = (acc << 5) | g as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return Err(AddressError::BadPadding);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §4.5's vector: `pk` = words 1..8, `kem_ek` = `i mod 251` (not a valid ML-KEM key).
    fn vector() -> ShieldedAddress {
        ShieldedAddress {
            pk: [1, 2, 3, 4, 5, 6, 7, 8],
            kem_ek: (0..KEM_EK_BYTES).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn the_spec_vector_reproduces() {
        let a = vector();
        let id = ReceiverId::of_address(&a);
        assert_eq!(
            id.to_hex(),
            "2c3bb9f942d0d66b095dd7491db1153de6d8f08dc411c89def38717863ecf0d4"
        );
        assert_eq!(
            id.0,
            a.recipient_hash(),
            "the id is the bridge's recipient hash"
        );
        assert_eq!(
            id.to_short(Network::Main),
            "rnd1s9samn72z6rtxkz2a6ay3mvg48hnd3uydcsgu38008pchsclv7r2qhkzy0z"
        );
        assert_eq!(
            id.to_short(Network::Test),
            "trnd1s9samn72z6rtxkz2a6ay3mvg48hnd3uydcsgu38008pchsclv7r2quex6sh"
        );
        assert_eq!(hex::encode(check4("rnd", &a.pk, &a.kem_ek)), "a153ea56");
        assert_eq!(hex::encode(check4("trnd", &a.pk, &a.kem_ek)), "0e07e80e");
        let direct = encode_direct(&a, Network::Main);
        assert_eq!(direct.len(), 1963);
        assert!(
            direct.starts_with("rnd1qqyqqqqqzqqqqqqcqqqqqgqqqqqzsqqqqqcq"),
            "{}",
            &direct[..40]
        );
        assert!(
            direct.ends_with("9d46hmpvdjkws486jkspq06c"),
            "{}",
            &direct[direct.len() - 30..]
        );
        assert_eq!(encode_direct(&a, Network::Test).len(), 1964);
    }

    #[test]
    fn both_forms_round_trip_on_every_network() {
        let a = vector();
        let id = ReceiverId::of_address(&a);
        for net in [Network::Main, Network::Test, Network::Dev] {
            assert_eq!(
                decode_for(&encode_direct(&a, net), net),
                Ok(Decoded::Direct(a.clone()))
            );
            assert_eq!(decode_for(&id.to_short(net), net), Ok(Decoded::Short(id)));
            // F-1: upper case decodes too (QR alphanumeric mode).
            assert_eq!(
                decode_for(&id.to_short(net).to_ascii_uppercase(), net),
                Ok(Decoded::Short(id))
            );
        }
    }

    #[test]
    fn every_single_character_substitution_of_a_short_address_is_refused() {
        let s = ReceiverId::of_address(&vector()).to_short(Network::Main);
        for i in 4..s.len() {
            for &c in CHARSET {
                if s.as_bytes()[i] == c {
                    continue;
                }
                let mut b = s.clone().into_bytes();
                b[i] = c;
                let t = String::from_utf8(b).unwrap();
                assert!(
                    decode_for(&t, Network::Main).is_err(),
                    "substitution at {i} accepted: {t}"
                );
            }
        }
    }

    #[test]
    fn wrong_network_mixed_case_and_reserved_types_are_refused() {
        let a = vector();
        let short = ReceiverId::of_address(&a).to_short(Network::Test);
        assert_eq!(
            decode_for(&short, Network::Main),
            Err(AddressError::WrongNetwork {
                expected: "rnd",
                found: "trnd"
            })
        );
        let mut mixed = short.clone();
        mixed.replace_range(7..8, &mixed[7..8].to_ascii_uppercase());
        assert_eq!(
            decode_for(&mixed, Network::Test),
            Err(AddressError::MixedCase)
        );
        // A well-checksummed string of a reserved type.
        let reserved = encode("rnd", 1, &[0u8; 32]);
        assert_eq!(
            decode_for(&reserved, Network::Main),
            Err(AddressError::ReservedType(1))
        );
        // Wrong payload length for the short type.
        let short31 = encode("rnd", TYPE_SHORT, &[0u8; 31]);
        assert!(matches!(
            decode_for(&short31, Network::Main),
            Err(AddressError::Length { .. }) | Err(AddressError::BadPadding)
        ));
        assert_eq!(
            decode_for(&"q".repeat(3000), Network::Main),
            Err(AddressError::TooLong(3000))
        );
    }

    #[test]
    fn a_bad_inner_check_under_a_recomputed_outer_checksum_is_refused() {
        let a = vector();
        let mut payload = word8_to_bytes(&a.pk).to_vec();
        payload.extend_from_slice(&a.kem_ek);
        payload.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            decode_for(&encode("rnd", TYPE_DIRECT, &payload), Network::Main),
            Err(AddressError::BadInnerCheck)
        );
        // A direct string re-encoded under another network's hrp fails the inner check too.
        let mut main_payload = word8_to_bytes(&a.pk).to_vec();
        main_payload.extend_from_slice(&a.kem_ek);
        main_payload.extend_from_slice(&check4("rnd", &a.pk, &a.kem_ek));
        assert_eq!(
            decode_for(&encode("trnd", TYPE_DIRECT, &main_payload), Network::Test),
            Err(AddressError::BadInnerCheck)
        );
    }

    #[test]
    fn a_non_canonical_pk_is_refused() {
        let mut a = vector();
        a.pk[0] = 1;
        a.pk[1] = 0xffff_ffff; // limb 0 = 0xffffffff_00000001 = p
        assert_eq!(
            decode_for(&encode_direct(&a, Network::Main), Network::Main),
            Err(AddressError::NonCanonicalPk)
        );
    }

    #[test]
    fn legacy_strings_still_parse() {
        let a = vector();
        let mut raw = word8_to_bytes(&a.pk).to_vec();
        raw.extend_from_slice(&a.kem_ek);
        let legacy = format!("{LEGACY_PREFIX}{}", bs58::encode(raw).into_string());
        assert_eq!(
            decode_for(&legacy, Network::Main),
            Ok(Decoded::Legacy(a.clone()))
        );
        assert_eq!(decode_for(&legacy, Network::Test), Ok(Decoded::Legacy(a)));
    }
}
