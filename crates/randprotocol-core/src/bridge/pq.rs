//! The Dilithium2 co-signature on every `BridgeAttest` (bridge hardening spec §4 and §10;
//! the format is `docs/superpowers/specs/2026-09-19-pq-cosignature-bridge.md`, a verbatim copy of
//! the bridge repo's `spec/PQ-COSIGNATURE.md` — binding byte for byte).
//!
//! Every attestation Rand accepts from the guardians — a deposit and a guardian-set rotation
//! alike — carries, beside its ECDSA quorum, a quorum of Dilithium2 signatures by the genesis
//! `bridge.pq_guardians` over
//!
//! ```text
//! M = b"rand-bridge-pq-cosign-1" ‖ rand_chain_id (u64 BE) ‖ mu        (63 bytes)
//! ```
//!
//! where `mu` is the digest the ECDSA quorum signs. The scheme is `crystals_dilithium::
//! dilithium2` (round 3), the one [`crate::crypto`] already links for validator keys, and
//! verification is [`crate::crypto::PublicKey::verify`].
//!
//! The five rules, and the refusal order the shared vectors pin (count → index order → index
//! range → every length → every verification):
//!
//! 1. `quorum(n) <= len <= n`, `n = pq_guardians.len()` — [`BridgeError::PqNoQuorum`];
//! 2. indices strictly increasing — [`BridgeError::PqIndexOrder`] — and each `< n` —
//!    [`BridgeError::PqIndexOutOfRange`];
//! 3. every signature exactly [`PQ_SIGNATURE_LEN`] bytes — [`BridgeError::PqBadSignatureLength`];
//! 4. every signature verifies `M` under `pq_guardians[index]` — [`BridgeError::PqBadSignature`];
//! 5. the PQ signer indices are counted on their own, independent of the ECDSA signers'.
//!
//! Rules 1–3 are [`check_pq_structure`] (no signature work); rule 4 is [`verify_pq_signatures`].
//! `BridgeState::check_attest` runs the first before anything else it checks and the second
//! after every other check, the ECDSA recoveries included — Dilithium verification is last.

use serde::{Deserialize, Serialize};

use crate::bridge::{quorum, BridgeError};
use crate::crypto::{Keypair, PublicKey, Signature};

/// The co-signature's domain tag: the first 23 bytes of `M`, ASCII, no terminator.
pub const PQ_COSIGN_DOMAIN: &[u8] = b"rand-bridge-pq-cosign-1";

/// A Dilithium2 signature's exact length (rule 3).
pub const PQ_SIGNATURE_LEN: usize = crate::crypto::SIGNATURE_LEN;

/// A Dilithium2 public key's exact length, which genesis holds every `pq_guardians` entry to.
pub const PQ_PUBLIC_KEY_LEN: usize = crate::crypto::PUBLIC_KEY_LEN;

/// One co-signature: the guardian's position in `bridge.pq_guardians`, and its Dilithium2
/// signature over [`pq_cosign_message`]. The last field of `Action::BridgeAttest`, inside the
/// transaction binding — it is not a proof, so a copier cannot strip or swap it.
///
/// `signature` is a `Vec`, not a [`Signature`], on purpose: a wrong length must survive decoding
/// so that admission can refuse it as [`BridgeError::PqBadSignatureLength`], in its place in the
/// refusal order, rather than failing the transaction's decode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignature {
    pub index: u8,
    #[serde(with = "crate::crypto::wire_bytes")]
    pub signature: Vec<u8>,
}

/// `M = b"rand-bridge-pq-cosign-1" ‖ chain_id (u64 BE) ‖ mu`, 63 bytes. The guardian-set index
/// is deliberately not in it (as it is not in `mu`): a co-signature stays valid across an ECDSA
/// rotation. The chain id is: a testnet co-signature never verifies on a mainnet chain.
pub fn pq_cosign_message(chain_id: u64, mu: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PQ_COSIGN_DOMAIN.len() + 8 + 32);
    m.extend_from_slice(PQ_COSIGN_DOMAIN);
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(mu);
    m
}

/// A guardian's co-signature: deterministic Dilithium2 over [`pq_cosign_message`]. What the
/// guardian daemon produces, and what tests and tools build quorums with.
pub fn pq_cosign(key: &Keypair, index: u8, chain_id: u64, mu: &[u8; 32]) -> PqSignature {
    PqSignature { index, signature: key.sign(&pq_cosign_message(chain_id, mu)).as_bytes().to_vec() }
}

/// Rules 1–3, in the vectors' order, with no signature work: the count against the quorum and
/// `n`, then index order over the whole list, then index range, then every length. Each pass
/// completes before the next begins, so a list that breaks two rules reports the earlier one.
pub fn check_pq_structure(sigs: &[PqSignature], n: usize) -> Result<(), BridgeError> {
    let need = quorum(n);
    if sigs.len() < need || sigs.len() > n {
        return Err(BridgeError::PqNoQuorum { have: sigs.len(), need, n });
    }
    if sigs.windows(2).any(|w| w[1].index <= w[0].index) {
        return Err(BridgeError::PqIndexOrder);
    }
    if let Some(s) = sigs.iter().find(|s| s.index as usize >= n) {
        return Err(BridgeError::PqIndexOutOfRange { index: s.index, n });
    }
    if let Some(s) = sigs.iter().find(|s| s.signature.len() != PQ_SIGNATURE_LEN) {
        return Err(BridgeError::PqBadSignatureLength { index: s.index, len: s.signature.len() });
    }
    Ok(())
}

/// Rule 4: every listed signature verifies `M(chain_id, mu)` under `keys[index]`. One failure
/// refuses the whole list. Must run after [`check_pq_structure`] accepted the same list (every
/// index is then in range and every length exact); an index out of range here is still a
/// refusal, never a panic.
pub fn verify_pq_signatures(
    sigs: &[PqSignature],
    keys: &[PublicKey],
    chain_id: u64,
    mu: &[u8; 32],
) -> Result<(), BridgeError> {
    verify_pq_message(sigs, keys, &pq_cosign_message(chain_id, mu))
}

/// Rule 4 over any message: every listed signature verifies `message` under `keys[index]`. The
/// one verification loop behind both the mint co-signature ([`verify_pq_signatures`], over
/// [`pq_cosign_message`]) and the Rand-only governance messages of bridge hardening B1/B4
/// ([`crate::bridge::gov`]: unpause, list, register) — so a governance quorum is judged by
/// exactly the function a mint's is, rule for rule.
pub fn verify_pq_message(sigs: &[PqSignature], keys: &[PublicKey], message: &[u8]) -> Result<(), BridgeError> {
    for s in sigs {
        let ok = match (keys.get(s.index as usize), Signature::from_bytes(&s.signature)) {
            (Some(key), Ok(sig)) => key.verify(message, &sig),
            _ => false,
        };
        if !ok {
            return Err(BridgeError::PqBadSignature { index: s.index });
        }
    }
    Ok(())
}

/// All five rules over any message — [`check_pq_structure`] then [`verify_pq_message`]: the
/// governance twin of [`check_pq_quorum`], and what a wallet runs before it submits one.
pub fn check_pq_quorum_message(sigs: &[PqSignature], keys: &[PublicKey], message: &[u8]) -> Result<(), BridgeError> {
    check_pq_structure(sigs, keys.len())?;
    verify_pq_message(sigs, keys, message)
}

/// All five rules at once — [`check_pq_structure`] then [`verify_pq_signatures`]. The ledger
/// splits the two around its other checks (`BridgeState::check_attest`); this is the whole
/// verdict on a list alone, as the shared vectors state it.
pub fn check_pq_quorum(
    sigs: &[PqSignature],
    keys: &[PublicKey],
    chain_id: u64,
    mu: &[u8; 32],
) -> Result<(), BridgeError> {
    check_pq_structure(sigs, keys.len())?;
    verify_pq_signatures(sigs, keys, chain_id, mu)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bridge::keccak256;

    /// The bridge repo's `vectors/pq-cosignatures.json` at ba01afb (its `_source` key says so),
    /// copied as a fixture.
    pub(crate) fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../tests/fixtures/pq-cosignatures.json")).expect("the PQ vectors parse")
    }

    pub(crate) fn hex32(v: &serde_json::Value) -> [u8; 32] {
        hex::decode(v.as_str().expect("hex string")).expect("hex").try_into().expect("32 bytes")
    }

    pub(crate) fn vector_keys(file: &serde_json::Value) -> Vec<PublicKey> {
        file["pq_guardians"]
            .as_array()
            .expect("pq_guardians")
            .iter()
            .map(|g| PublicKey::from_hex(g["public_key"].as_str().expect("public_key")).expect("a Dilithium2 key"))
            .collect()
    }

    pub(crate) fn vector_sigs(list: &serde_json::Value) -> Vec<PqSignature> {
        list.as_array()
            .expect("pq_signatures")
            .iter()
            .map(|s| PqSignature {
                index: s["index"].as_u64().expect("index") as u8,
                signature: hex::decode(s["signature"].as_str().expect("signature")).expect("hex"),
            })
            .collect()
    }

    /// The name the vectors give each refusal.
    pub(crate) fn verdict(r: &Result<(), BridgeError>) -> &'static str {
        match r {
            Ok(()) => "ok",
            Err(BridgeError::PqNoQuorum { .. }) => "PqNoQuorum",
            Err(BridgeError::PqIndexOrder) => "PqIndexOrder",
            Err(BridgeError::PqIndexOutOfRange { .. }) => "PqIndexOutOfRange",
            Err(BridgeError::PqBadSignatureLength { .. }) => "PqBadSignatureLength",
            Err(BridgeError::PqBadSignature { .. }) => "PqBadSignature",
            Err(_) => "other",
        }
    }

    #[test]
    fn the_message_is_the_domain_the_chain_id_and_mu() {
        let m = pq_cosign_message(0x0102_0304_0506_0708, &[0xab; 32]);
        assert_eq!(m.len(), 63);
        assert_eq!(&m[..23], b"rand-bridge-pq-cosign-1");
        assert_eq!(&m[23..31], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&m[31..], &[0xab; 32]);
        assert_eq!(PQ_SIGNATURE_LEN, 2420);
        assert_eq!(PQ_PUBLIC_KEY_LEN, 1312);
    }

    /// The six test guardians: `seed_i = keccak256("rand-bridge-pq-test-guardian" ‖ u8(i))`, and
    /// the public key each derives through `Keypair::from_seed` — the node's own derivation.
    #[test]
    fn the_vector_guardians_derive_from_their_seeds() {
        let file = vectors();
        assert_eq!(file["domain"], "rand-bridge-pq-cosign-1");
        let guardians = file["pq_guardians"].as_array().unwrap();
        assert_eq!(guardians.len(), 6);
        assert_eq!(file["quorum"].as_u64().unwrap() as usize, quorum(guardians.len()));
        for (i, g) in guardians.iter().enumerate() {
            assert_eq!(g["index"].as_u64().unwrap() as usize, i);
            let mut pre = b"rand-bridge-pq-test-guardian".to_vec();
            pre.push(i as u8);
            let seed = hex32(&g["seed"]);
            assert_eq!(seed, keccak256(&pre), "guardian {i}'s seed");
            let key = Keypair::from_seed(seed).unwrap();
            assert_eq!(key.public_key().to_hex(), g["public_key"].as_str().unwrap(), "guardian {i}'s key");
        }
    }

    /// Every body: its `mu` is the attestation vector's digest, its `message` is exactly
    /// [`pq_cosign_message`], each of its six co-signatures verifies under its guardian's key, and
    /// re-signing reproduces each one byte for byte (signing is deterministic).
    #[test]
    fn every_vector_body_verifies_and_reproduces_byte_for_byte() {
        let file = vectors();
        let chain_id = file["rand_chain_id"].as_u64().unwrap();
        assert_eq!(chain_id, 99);
        let keys = vector_keys(&file);
        let seeds: Vec<[u8; 32]> = file["pq_guardians"].as_array().unwrap().iter().map(|g| hex32(&g["seed"])).collect();
        let attestations: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
        let bodies = file["bodies"].as_array().unwrap();
        assert_eq!(bodies.len(), 9);
        let mut signatures = 0;
        for body in bodies {
            let name = body["attestation_vector"].as_str().unwrap();
            let mu = hex32(&body["mu"]);
            let att = attestations["vectors"].as_array().unwrap().iter().find(|v| v["name"] == name).expect(name);
            assert_eq!(att["expect"], "ok", "{name}");
            assert_eq!(hex::encode(mu), att["digest"].as_str().unwrap(), "{name}: mu is the attestation's digest");
            let bytes = hex::decode(att["attestation"].as_str().unwrap()).unwrap();
            let wire_mu = crate::bridge::digest(crate::bridge::Attestation::body_bytes(&bytes).unwrap());
            assert_eq!(wire_mu, mu, "{name}: mu recomputed from the wire body");
            let message = hex::decode(body["message"].as_str().unwrap()).unwrap();
            assert_eq!(message, pq_cosign_message(chain_id, &mu), "{name}: message bytes");
            let sigs = vector_sigs(&body["pq_signatures"]);
            assert_eq!(sigs.len(), 6, "{name}");
            for s in &sigs {
                let i = s.index as usize;
                assert_eq!(verify_pq_signatures(std::slice::from_ref(s), &keys, chain_id, &mu), Ok(()), "{name}/{i}");
                let mine = pq_cosign(&Keypair::from_seed(seeds[i]).unwrap(), s.index, chain_id, &mu);
                assert_eq!(&mine, s, "{name}/{i}: deterministic signing reproduces the vector");
                signatures += 1;
            }
            assert_eq!(check_pq_quorum(&sigs, &keys, chain_id, &mu), Ok(()), "{name}: all six");
        }
        assert_eq!(signatures, 54);
    }

    /// Every case, with its expected verdict: the list alone against the vectors' keys, the
    /// case's own `rand_chain_id` and `mu`. The exact count guards against a case silently
    /// dropping out of the file.
    #[test]
    fn every_vector_case_gets_its_verdict() {
        let file = vectors();
        let keys = vector_keys(&file);
        let cases = file["cases"].as_array().unwrap();
        let mut checked = 0;
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let got = check_pq_quorum(
                &vector_sigs(&case["pq_signatures"]),
                &keys,
                case["rand_chain_id"].as_u64().unwrap(),
                &hex32(&case["mu"]),
            );
            assert_eq!(verdict(&got), case["expect"].as_str().unwrap(), "{name}: {got:?}");
            checked += 1;
        }
        assert_eq!(checked, 12);
    }

    /// Structural refusals are reached without a key: they are statements about the list and `n`
    /// alone, and each pass completes before the next — a list that is both descending and out of
    /// range is `PqIndexOrder`, one in order with an index out of range and a short signature is
    /// `PqIndexOutOfRange`, and more signatures than guardians is `PqNoQuorum`.
    #[test]
    fn the_structural_rules_run_in_order_before_any_key_is_read() {
        let s = |index: u8, len: usize| PqSignature { index, signature: vec![0; len] };
        let full = PQ_SIGNATURE_LEN;
        assert!(matches!(check_pq_structure(&(0..4).map(|i| s(i, full)).collect::<Vec<_>>(), 6), Err(BridgeError::PqNoQuorum { have: 4, need: 5, n: 6 })));
        let seven: Vec<_> = (0..7).map(|i| s(i, full)).collect();
        assert!(matches!(check_pq_structure(&seven, 6), Err(BridgeError::PqNoQuorum { have: 7, .. })));
        let desc_and_out: Vec<_> = [9u8, 3, 2, 1, 0].into_iter().map(|i| s(i, 1)).collect();
        assert_eq!(check_pq_structure(&desc_and_out, 6), Err(BridgeError::PqIndexOrder));
        let out_and_short = vec![s(0, 1), s(1, full), s(2, full), s(3, full), s(6, full)];
        assert_eq!(check_pq_structure(&out_and_short, 6), Err(BridgeError::PqIndexOutOfRange { index: 6, n: 6 }));
        let long = vec![s(0, full), s(1, full), s(2, full), s(3, full), s(4, full + 1)];
        assert_eq!(check_pq_structure(&long, 6), Err(BridgeError::PqBadSignatureLength { index: 4, len: full + 1 }));
        // A well-formed list of zero bytes passes structure and fails verification.
        let zeros: Vec<_> = (0..5).map(|i| s(i, full)).collect();
        assert_eq!(check_pq_structure(&zeros, 6), Ok(()));
        let keys: Vec<PublicKey> = (0..6u8).map(|i| Keypair::from_seed([i; 32]).unwrap().public_key().clone()).collect();
        assert_eq!(verify_pq_signatures(&zeros, &keys, 1, &[0; 32]), Err(BridgeError::PqBadSignature { index: 0 }));
    }
}
