//! Bridge digest, secp256k1 signing/recovery, and guardian quorum
//! verification, layered on top of the dependency-free `bridge-codec` wire
//! format.
//!
//! Digest `mu = keccak256(keccak256(body))`; guardian address = the last 20
//! bytes of `keccak256(uncompressed_pubkey[1..])`; low-s is required for
//! every guardian signature, and recovery id must be 0 or 1.

use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};

pub mod state;

pub use bridge_codec::*;
pub use state::*;

use crate::crypto::Hash;

/// A bridge-side asset identifier: `blake3("shrugg-bridge-asset" ||
/// token_chain BE u16 || token_address)`.
pub type AssetId = Hash;

/// keccak256 of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The attestation digest `mu = keccak256(keccak256(body_bytes))`.
pub fn digest(body_bytes: &[u8]) -> [u8; 32] {
    keccak256(&keccak256(body_bytes))
}

/// Domain-separated, chain-shaped asset id: `blake3("shrugg-bridge-asset" ||
/// token_chain BE u16 || token_address)`.
pub fn asset_id(token_chain: u16, token_address: &[u8; 32]) -> AssetId {
    let mut data = Vec::with_capacity(2 + 32);
    data.extend_from_slice(&token_chain.to_be_bytes());
    data.extend_from_slice(token_address);
    Hash::digest_domain(b"shrugg-bridge-asset", &data)
}

/// A guardian set: its member keys (indexed 0..n) and the time at which it
/// expires. `expires_at == 0` means "current, never expires".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSet {
    pub keys: Vec<GuardianKey>,
    pub expires_at: u64,
}

/// Errors from [`verify`].
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum VerifyError {
    #[error("codec error: {0:?}")]
    Codec(CodecError),
    #[error("index error: {0:?}")]
    Index(IndexError),
    #[error("unknown guardian set {0}")]
    UnknownGuardianSet(u32),
    #[error("guardian set expired")]
    SetExpired,
    #[error("high-s signature at index {0}")]
    HighS(u8),
    #[error("unrecoverable signature at index {0}")]
    BadSignature(u8),
    #[error("wrong guardian at index {0}")]
    WrongGuardian(u8),
}

/// Recovers the guardian address (last 20 bytes of
/// `keccak256(uncompressed_pubkey[1..])`) that produced `sig` over
/// `digest`, or `None` if the signature is malformed or unrecoverable.
pub fn recover_address(digest: &[u8; 32], sig: &Signature) -> Option<GuardianKey> {
    if sig.v > 1 {
        return None;
    }
    let ecdsa_sig = EcdsaSignature::from_scalars(sig.r, sig.s).ok()?;
    let recid = RecoveryId::from_byte(sig.v)?;
    let verifying_key = VerifyingKey::recover_from_prehash(digest, &ecdsa_sig, recid).ok()?;
    Some(address_from_verifying_key(&verifying_key))
}

/// Signs `digest` with the secp256k1 secret key `secret`, returning a
/// low-s [`Signature`] tagged with guardian `index` and recovery id 0 or 1.
pub fn sign_digest(secret: &[u8; 32], index: u8, digest: &[u8; 32]) -> Signature {
    let signing_key = SigningKey::from_bytes(secret.into()).expect("valid secp256k1 secret key");
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest)
        .expect("prehash signing cannot fail for a valid key and 32-byte digest");
    let (sig, recid) = match sig.normalize_s() {
        Some(normalized) => {
            let flipped = RecoveryId::from_byte(recid.to_byte() ^ 1)
                .expect("flipping bit 0 of a valid recovery id stays valid");
            (normalized, flipped)
        }
        None => (sig, recid),
    };
    let (r, s) = sig.split_bytes();
    Signature {
        index,
        r: r.into(),
        s: s.into(),
        v: recid.to_byte(),
    }
}

/// The guardian address corresponding to secp256k1 secret key `secret`.
pub fn guardian_address(secret: &[u8; 32]) -> GuardianKey {
    let signing_key = SigningKey::from_bytes(secret.into()).expect("valid secp256k1 secret key");
    let verifying_key = VerifyingKey::from(&signing_key);
    address_from_verifying_key(&verifying_key)
}

/// The last 20 bytes of `keccak256(uncompressed_pubkey[1..])`, i.e. the
/// guardian address for `key`.
fn address_from_verifying_key(key: &VerifyingKey) -> GuardianKey {
    let encoded = key.to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// Full envelope check: decode, quorum/index rule, low-s, recover each
/// signer, compare to the set. Returns `(attestation, digest)`.
pub fn verify(
    bytes: &[u8],
    set: &GuardianSet,
    now: u64,
) -> Result<(Attestation, [u8; 32]), VerifyError> {
    let att = Attestation::decode(bytes).map_err(VerifyError::Codec)?;
    if set.expires_at != 0 && now > set.expires_at {
        return Err(VerifyError::SetExpired);
    }
    check_indices(&att.signatures, set.keys.len()).map_err(VerifyError::Index)?;
    let d = digest(&att.body.encode());
    for sig in &att.signatures {
        if !is_low_s(&sig.s) {
            return Err(VerifyError::HighS(sig.index));
        }
        let recovered = recover_address(&d, sig).ok_or(VerifyError::BadSignature(sig.index))?;
        if recovered != set.keys[sig.index as usize] {
            return Err(VerifyError::WrongGuardian(sig.index));
        }
    }
    Ok((att, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_emitter_matches_string() {
        assert_eq!(keccak256(b"rand-bridge-governance"), GOVERNANCE_EMITTER);
    }

    #[test]
    fn keccak_known_answer() {
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn sign_recover_round_trip_and_quorum() {
        let secrets: Vec<[u8; 32]> = (1u8..=6)
            .map(|i| {
                let mut s = [0u8; 32];
                s[31] = i;
                s
            })
            .collect();
        let set = GuardianSet {
            keys: secrets.iter().map(guardian_address).collect(),
            expires_at: 0,
        };
        let body = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: 2,
            emitter_address: [1; 32],
            sequence: 0,
            consistency_level: 1,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(100),
                token_address: [2; 32],
                token_chain: 2,
                to: [3; 32],
                to_chain: 1,
                fee: [0; 32],
            })
            .encode(),
        };
        let d = digest(&body.encode());
        let sigs: Vec<Signature> = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
        for s in &sigs {
            assert_eq!(recover_address(&d, s), Some(set.keys[s.index as usize]));
            assert!(is_low_s(&s.s));
        }
        let att = Attestation {
            guardian_set_index: 0,
            signatures: sigs.clone(),
            body: body.clone(),
        };
        let (parsed, got) = verify(&att.encode(), &set, 1_000).unwrap();
        assert_eq!(got, d);
        assert_eq!(parsed, att);
        let four = Attestation {
            signatures: sigs[..4].to_vec(),
            ..att.clone()
        };
        assert_eq!(
            verify(&four.encode(), &set, 1_000).unwrap_err(),
            VerifyError::Index(IndexError::NoQuorum { have: 4, need: 5 })
        );
        let mut forged = att.clone();
        forged.signatures[2] = sign_digest(&[9; 32], 2, &d);
        assert_eq!(
            verify(&forged.encode(), &set, 1_000).unwrap_err(),
            VerifyError::WrongGuardian(2)
        );
        let mut high = att.clone();
        high.signatures[0].s = [0xff; 32];
        assert_eq!(
            verify(&high.encode(), &set, 1_000).unwrap_err(),
            VerifyError::HighS(0)
        );
        let expired = GuardianSet {
            expires_at: 999,
            ..set.clone()
        };
        assert_eq!(
            verify(&att.encode(), &expired, 1_000).unwrap_err(),
            VerifyError::SetExpired
        );
    }

    #[test]
    fn asset_id_is_domain_separated_blake3() {
        let mut buf = b"shrugg-bridge-asset".to_vec();
        buf.extend(2u16.to_be_bytes());
        buf.extend([5u8; 32]);
        assert_eq!(asset_id(2, &[5; 32]), Hash(*blake3::hash(&buf).as_bytes()));
    }

    #[test]
    fn recover_address_rejects_v_greater_than_one() {
        let mut sig = sign_digest(&[7; 32], 0, &[1; 32]);
        sig.v = 2;
        assert_eq!(recover_address(&[1; 32], &sig), None);
    }

    /// Cross-checks every signature-level vector from the shared
    /// `tools/vectors` generator (Task B1) against `verify`. The remaining
    /// `expect` values (`wrong_emitter`, `fee_exceeds_amount`, `replay`,
    /// etc.) are ledger-level and are asserted in Task C2. `unknown_set` is
    /// also ledger-level: `verify` takes an already-resolved `GuardianSet`,
    /// not an index, so "no set at this index" is a set-*resolution*
    /// concern that belongs to `BridgeState::check_attest` (Task C2),
    /// which maps it to `VerifyError::UnknownGuardianSet`. Asserting it
    /// here against the vector's own `sets` would be tautological (true by
    /// construction of the generator), so it is intentionally not checked
    /// in this test.
    #[test]
    fn shared_vectors_match_verify() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("vectors.json")).expect("vectors.json parses");
        let now = file["now"].as_u64().expect("now");
        const SIGNATURE_LEVEL: &[&str] = &[
            "ok",
            "no_quorum",
            "index_order",
            "index_out_of_range",
            "bad_signature",
            "high_s",
            "wrong_guardian",
            "set_expired",
            "bad_version",
        ];
        let mut checked = 0usize;
        for v in file["vectors"].as_array().expect("vectors array") {
            let name = v["name"].as_str().expect("name");
            let expect = v["expect"].as_str().expect("expect");
            if !SIGNATURE_LEVEL.contains(&expect) {
                continue;
            }
            checked += 1;
            let bytes = hex::decode(v["attestation"].as_str().expect("attestation")).expect("hex");
            let guardian_set_index = v["guardian_set_index"].as_u64().expect("guardian_set_index") as u32;
            let sets = v["sets"].as_array().expect("sets");
            let set_json = sets
                .iter()
                .find(|s| s["index"].as_u64().expect("index") as u32 == guardian_set_index);

            let set_json = set_json.unwrap_or_else(|| panic!("{name}: missing set {guardian_set_index}"));
            let keys: Vec<GuardianKey> = set_json["keys"]
                .as_array()
                .expect("keys")
                .iter()
                .map(|k| {
                    let b = hex::decode(k.as_str().expect("key hex")).expect("hex");
                    let arr: GuardianKey = b.try_into().expect("20-byte key");
                    arr
                })
                .collect();
            let expires_at = set_json["expires_at"].as_u64().expect("expires_at");
            let set = GuardianSet { keys, expires_at };

            let result = verify(&bytes, &set, now);
            match expect {
                "ok" => {
                    let (_, d) = result.unwrap_or_else(|e| panic!("{name}: expected ok, got {e:?}"));
                    let expected_digest = v["digest"].as_str().expect("digest");
                    assert_eq!(hex::encode(d), expected_digest, "{name}: digest mismatch");
                }
                "no_quorum" => assert!(
                    matches!(result, Err(VerifyError::Index(IndexError::NoQuorum { .. }))),
                    "{name}: {result:?}"
                ),
                "index_order" => assert!(
                    matches!(result, Err(VerifyError::Index(IndexError::IndexOrder))),
                    "{name}: {result:?}"
                ),
                "index_out_of_range" => assert!(
                    matches!(result, Err(VerifyError::Index(IndexError::IndexOutOfRange))),
                    "{name}: {result:?}"
                ),
                "bad_signature" => assert!(
                    matches!(result, Err(VerifyError::BadSignature(_))),
                    "{name}: {result:?}"
                ),
                "high_s" => assert!(matches!(result, Err(VerifyError::HighS(_))), "{name}: {result:?}"),
                "wrong_guardian" => assert!(
                    matches!(result, Err(VerifyError::WrongGuardian(_))),
                    "{name}: {result:?}"
                ),
                "set_expired" => assert!(matches!(result, Err(VerifyError::SetExpired)), "{name}: {result:?}"),
                "bad_version" => assert!(
                    matches!(result, Err(VerifyError::Codec(CodecError::BadVersion))),
                    "{name}: {result:?}"
                ),
                other => panic!("{name}: unhandled expect {other}"),
            }
        }
        assert!(
            checked >= 10,
            "expected at least 10 signature-level vectors, checked {checked}"
        );
    }
}
