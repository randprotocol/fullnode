//! The Rand-only bridge governance messages (bridge hardening spec §9; the bridge repo's
//! `spec/PQ-COSIGNATURE.md` §8 and `daemons/src/pq_gov.rs`, whose vectors pin them): **fixed
//! big-endian layouts, never bincode**, so an auditor or a hardware signer can rebuild each one by
//! hand. None of them ever reaches a source-chain endpoint.
//!
//! ```text
//! M_pause   = b"rand-bridge-pause-1"      ‖ chain_id u64 ‖ nonce u64    (the one genesis pause key)
//! M_unpause = b"rand-bridge-pq-unpause-1" ‖ chain_id u64 ‖ nonce u64    (a PQ guardian quorum)
//! ```
//!
//! Both carry the bridge's `pause_nonce` ([`crate::bridge::BridgeState::pause_nonce`]). The pause
//! key signs `M_pause` directly (Dilithium2 over the raw bytes, like a co-signature); the unpause
//! quorum is judged by the co-signature's own five rules
//! ([`crate::bridge::pq::check_pq_structure`], [`crate::bridge::pq::verify_pq_message`]). The two
//! domains differ, so a pause signature is never an unpause signature, whoever holds the key.

/// `M_pause`'s domain tag: 19 ASCII bytes, no terminator.
pub const PAUSE_DOMAIN: &[u8] = b"rand-bridge-pause-1";
/// `M_unpause`'s domain tag: 24 ASCII bytes, no terminator.
pub const UNPAUSE_DOMAIN: &[u8] = b"rand-bridge-pq-unpause-1";

/// `domain ‖ chain_id (u64 BE) ‖ nonce (u64 BE)` — the head every governance message starts with.
fn head(domain: &[u8], chain_id: u64, nonce: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 16);
    m.extend_from_slice(domain);
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(&nonce.to_be_bytes());
    m
}

/// `M_pause`: what the genesis `bridge.pause_key` signs to pause minting at `pause_nonce`. It can
/// only pause — there is no message this key signs that unpauses.
pub fn pause_message(chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    head(PAUSE_DOMAIN, chain_id, pause_nonce)
}

/// `M_unpause`: what a PQ guardian quorum signs to lift a pause at `pause_nonce`.
pub fn unpause_message(chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    head(UNPAUSE_DOMAIN, chain_id, pause_nonce)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bridge::pq::tests::{hex32, vector_keys, vector_sigs, vectors, verdict};
    use crate::bridge::pq::{check_pq_quorum_message, PqSignature};
    use crate::bridge::BridgeError;
    use crate::crypto::{Keypair, PublicKey, Signature};

    /// The vectors' `governance` section.
    pub(crate) fn governance() -> serde_json::Value {
        vectors()["governance"].clone()
    }

    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().expect("hex")).expect("hex")
    }

    /// Re-signing with the vectors' own seeds reproduces every co-signature byte for byte
    /// (Dilithium2 signing is deterministic), so the node's `Keypair` is the bridge daemons' key.
    fn reproduces(sigs: &[PqSignature], message: &[u8]) {
        let file = vectors();
        let seeds: Vec<[u8; 32]> = file["pq_guardians"].as_array().unwrap().iter().map(|g| hex32(&g["seed"])).collect();
        for s in sigs {
            let key = Keypair::from_seed(seeds[s.index as usize]).unwrap();
            assert_eq!(key.sign(message).as_bytes(), &s.signature[..], "index {}", s.index);
        }
    }

    #[test]
    fn the_pause_messages_are_the_domain_the_chain_id_and_the_nonce() {
        let p = pause_message(0x0102_0304_0506_0708, 9);
        assert_eq!(&p[..19], b"rand-bridge-pause-1");
        assert_eq!(&p[19..27], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&p[27..], &9u64.to_be_bytes());
        let u = unpause_message(0x0102_0304_0506_0708, 9);
        assert_eq!(&u[..24], b"rand-bridge-pq-unpause-1");
        assert_eq!(&u[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&u[32..], &9u64.to_be_bytes());
        assert_eq!((p.len(), u.len()), (35, 40));
    }

    /// The `pause` vector: its message is exactly [`pause_message`] at the vector's nonce, the
    /// pause key derives from its seed, and the signature verifies — and reproduces byte for byte.
    #[test]
    fn the_pause_vector_reproduces_and_verifies() {
        let file = vectors();
        let chain_id = file["rand_chain_id"].as_u64().unwrap();
        let g = governance();
        let v = &g["pause"];
        let nonce = v["pause_nonce"].as_u64().unwrap();
        let message = pause_message(chain_id, nonce);
        assert_eq!(message, bytes(&v["message"]), "M_pause byte for byte");
        let key = Keypair::from_seed(hex32(&v["pause_key_seed"])).unwrap();
        assert_eq!(key.public_key().to_hex(), v["pause_key"].as_str().unwrap(), "the pause key derives from its seed");
        let sig = Signature::from_bytes(&bytes(&v["signature"])).unwrap();
        assert!(key.public_key().verify(&message, &sig));
        assert_eq!(key.sign(&message), sig, "deterministic signing reproduces the vector");
        // The pause key's signature is over the pause domain only: it verifies for no other nonce,
        // no other chain, and never as an unpause.
        assert!(!key.public_key().verify(&pause_message(chain_id, nonce + 1), &sig));
        assert!(!key.public_key().verify(&pause_message(chain_id + 1, nonce), &sig));
        assert!(!key.public_key().verify(&unpause_message(chain_id, nonce), &sig));
    }

    /// The `unpause` vector: [`unpause_message`] byte for byte, its quorum `ok` under the five rules
    /// (the co-signature's own check, over this message), and every signature reproduced. A quorum
    /// for this message authorises no other nonce and no other chain.
    #[test]
    fn the_unpause_vector_reproduces_and_its_quorum_verifies() {
        let file = vectors();
        let chain_id = file["rand_chain_id"].as_u64().unwrap();
        let keys = vector_keys(&file);
        let g = governance();
        let v = &g["unpause"];
        let nonce = v["pause_nonce"].as_u64().unwrap();
        let message = unpause_message(chain_id, nonce);
        assert_eq!(message, bytes(&v["message"]), "M_unpause byte for byte");
        let sigs = vector_sigs(&v["pq_signatures"]);
        assert_eq!(sigs.len(), 5, "exactly a quorum, lowest indices");
        assert_eq!(verdict(&check_pq_quorum_message(&sigs, &keys, &message)), "ok");
        reproduces(&sigs, &message);
        for other in [unpause_message(chain_id, nonce + 1), unpause_message(chain_id + 1, nonce), pause_message(chain_id, nonce)] {
            assert_eq!(verdict(&check_pq_quorum_message(&sigs, &keys, &other)), "PqBadSignature");
        }
        // The pause key is not a PQ guardian: its signature filed under any index is refused.
        let pause_key = Keypair::from_seed(hex32(&g["pause"]["pause_key_seed"])).unwrap();
        let mut forged = sigs.clone();
        forged[0].signature = pause_key.sign(&message).as_bytes().to_vec();
        assert_eq!(check_pq_quorum_message(&forged, &keys, &message), Err(BridgeError::PqBadSignature { index: 0 }));
        assert!(!keys.iter().any(|k: &PublicKey| k == pause_key.public_key()));
    }
}
