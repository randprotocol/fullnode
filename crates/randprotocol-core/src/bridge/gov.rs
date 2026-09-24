//! The Rand-only bridge governance messages (bridge hardening spec §9; the bridge repo's
//! `spec/PQ-COSIGNATURE.md` §8 and `daemons/src/pq_gov.rs`, whose vectors pin them): **fixed
//! big-endian layouts, never bincode**, so an auditor or a hardware signer can rebuild each one by
//! hand. None of them ever reaches a source-chain endpoint.
//!
//! ```text
//! M_pause   = b"rand-bridge-pause-1"      ‖ chain_id u64 ‖ nonce u64    (the one genesis pause key)
//! M_unpause = b"rand-bridge-pq-unpause-1" ‖ chain_id u64 ‖ nonce u64    (a PQ guardian quorum)
//! M_list     = b"rand-bridge-pq-list-1"     ‖ chain_id u64 ‖ nonce u64 ‖ token_index u32 ‖ chain u16
//!              ‖ token [32] ‖ decimals u8
//! M_register = b"rand-bridge-pq-register-1" ‖ chain_id u64 ‖ nonce u64 ‖ u8 len ‖ name ‖ u8 len
//!              ‖ symbol ‖ salt [32] ‖ chain u16 ‖ token [32] ‖ decimals u8
//! M_rotate_pq    = b"rand-bridge-pq-rotate-pq-1"    ‖ chain_id u64 ‖ nonce u64 ‖ u32 count ‖ key [1312] …
//! M_rotate_pause = b"rand-bridge-pq-rotate-pause-1" ‖ chain_id u64 ‖ nonce u64 ‖ key [1312]
//! ```
//!
//! `M_rotate_pq` and `M_rotate_pause` (audit v4, bridge rules v2 — `docs/bridge.md` §21) carry the
//! bridge's `rotation_nonce` and are signed by a PQ guardian quorum of the *current* set; the keys
//! are Dilithium2 public keys, exactly 1 312 raw bytes each, in index order (the count is the
//! number of keys, not a byte length — admission holds every key to that length before the
//! message is built).
//!
//! `M_list` and `M_register` (B4) carry the bridge's `list_nonce` and are signed by a PQ guardian
//! quorum; `decimals` is always the **backing's source** decimals (the bridged token itself is
//! eight on Rand and is not in either message).
//!
//! `M_pause` and `M_unpause` carry the bridge's `pause_nonce` ([`crate::bridge::BridgeState::pause_nonce`]). The pause
//! key signs `M_pause` directly (Dilithium2 over the raw bytes, like a co-signature); the unpause
//! quorum is judged by the co-signature's own five rules
//! ([`crate::bridge::pq::check_pq_structure`], [`crate::bridge::pq::verify_pq_message`]). The two
//! domains differ, so a pause signature is never an unpause signature, whoever holds the key.

/// `M_pause`'s domain tag: 19 ASCII bytes, no terminator.
pub const PAUSE_DOMAIN: &[u8] = b"rand-bridge-pause-1";
/// `M_unpause`'s domain tag: 24 ASCII bytes, no terminator.
pub const UNPAUSE_DOMAIN: &[u8] = b"rand-bridge-pq-unpause-1";
/// `M_list`'s domain tag: 21 ASCII bytes, no terminator.
pub const LIST_DOMAIN: &[u8] = b"rand-bridge-pq-list-1";
/// `M_register`'s domain tag: 25 ASCII bytes, no terminator.
pub const REGISTER_DOMAIN: &[u8] = b"rand-bridge-pq-register-1";
/// `M_rotate_pq`'s domain tag: 26 ASCII bytes, no terminator.
pub const ROTATE_PQ_DOMAIN: &[u8] = b"rand-bridge-pq-rotate-pq-1";
/// `M_rotate_pause`'s domain tag: 29 ASCII bytes, no terminator.
pub const ROTATE_PAUSE_DOMAIN: &[u8] = b"rand-bridge-pq-rotate-pause-1";

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

/// `chain u16 ‖ token [32] ‖ decimals u8` — one backing, as both listing messages end.
fn backing_tail(m: &mut Vec<u8>, chain: u16, token: &[u8; 32], decimals: u8) {
    m.extend_from_slice(&chain.to_be_bytes());
    m.extend_from_slice(token);
    m.push(decimals);
}

/// `M_list`: what a PQ guardian quorum signs to add the backing `(chain, token)` — a coin of
/// `decimals` source decimals — to the bridged token at `token_index`, at `list_nonce`.
pub fn list_message(chain_id: u64, list_nonce: u64, token_index: u32, chain: u16, token: &[u8; 32], decimals: u8) -> Vec<u8> {
    let mut m = head(LIST_DOMAIN, chain_id, list_nonce);
    m.extend_from_slice(&token_index.to_be_bytes());
    backing_tail(&mut m, chain, token, decimals);
    m
}

/// `M_register`: what a PQ guardian quorum signs to register a new bridged token `name`/`symbol`
/// (its asset id salted by `salt`) with its first backing `(chain, token)` of `decimals` source
/// decimals, at `list_nonce`. `name` and `symbol` each ride behind a one-byte length, so `None`
/// for either empty or over 255 bytes — neither can be a registrable token anyway
/// (`tokens::check_metadata` holds them to 32 and 12).
#[allow(clippy::too_many_arguments)]
pub fn register_message(
    chain_id: u64,
    list_nonce: u64,
    name: &str,
    symbol: &str,
    salt: &[u8; 32],
    chain: u16,
    token: &[u8; 32],
    decimals: u8,
) -> Option<Vec<u8>> {
    let len = |s: &str| u8::try_from(s.len()).ok().filter(|n| *n > 0);
    let (name_len, symbol_len) = (len(name)?, len(symbol)?);
    let mut m = head(REGISTER_DOMAIN, chain_id, list_nonce);
    m.push(name_len);
    m.extend_from_slice(name.as_bytes());
    m.push(symbol_len);
    m.extend_from_slice(symbol.as_bytes());
    m.extend_from_slice(salt);
    backing_tail(&mut m, chain, token, decimals);
    Some(m)
}

/// `M_rotate_pq`: what a PQ guardian quorum of the current set signs to replace the whole PQ set
/// with `new_pq_guardians` at `rotation_nonce` (bridge rules v2). A `u32` count of keys, then each
/// key's raw bytes in index order — `PublicKey::as_bytes`, which admission has held to exactly
/// [`crate::bridge::PQ_PUBLIC_KEY_LEN`] (1 312) each before this is built.
pub fn rotate_pq_message(chain_id: u64, rotation_nonce: u64, new_pq_guardians: &[crate::crypto::PublicKey]) -> Vec<u8> {
    let mut m = head(ROTATE_PQ_DOMAIN, chain_id, rotation_nonce);
    m.extend_from_slice(&(new_pq_guardians.len() as u32).to_be_bytes());
    for k in new_pq_guardians {
        m.extend_from_slice(k.as_bytes());
    }
    m
}

/// `M_rotate_pause`: what a PQ guardian quorum signs to replace the pause key with
/// `new_pause_key` at `rotation_nonce` (bridge rules v2). The key's raw bytes, held to 1 312 by
/// admission before this is built.
pub fn rotate_pause_message(chain_id: u64, rotation_nonce: u64, new_pause_key: &crate::crypto::PublicKey) -> Vec<u8> {
    let mut m = head(ROTATE_PAUSE_DOMAIN, chain_id, rotation_nonce);
    m.extend_from_slice(new_pause_key.as_bytes());
    m
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

    #[test]
    fn the_listing_messages_are_laid_out_byte_for_byte() {
        let l = list_message(0x0102_0304_0506_0708, 9, 0x0a0b_0c0d, 0x0e0f, &[0x11; 32], 6);
        assert_eq!(&l[..21], b"rand-bridge-pq-list-1");
        assert_eq!(&l[21..29], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&l[29..37], &9u64.to_be_bytes());
        assert_eq!(&l[37..41], &[0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(&l[41..43], &[0x0e, 0x0f]);
        assert_eq!(&l[43..75], &[0x11; 32]);
        assert_eq!((l[75], l.len()), (6, 76));
        let r = register_message(7, 1, "Shielded USD", "zUSD", &[0x5a; 32], 2, &[0x22; 32], 18).unwrap();
        assert_eq!(&r[..25], b"rand-bridge-pq-register-1");
        assert_eq!(&r[25..33], &7u64.to_be_bytes());
        assert_eq!(&r[33..41], &1u64.to_be_bytes());
        assert_eq!(r[41], 12);
        assert_eq!(&r[42..54], b"Shielded USD");
        assert_eq!(r[54], 4);
        assert_eq!(&r[55..59], b"zUSD");
        assert_eq!(&r[59..91], &[0x5a; 32]);
        assert_eq!(&r[91..93], &2u16.to_be_bytes());
        assert_eq!(&r[93..125], &[0x22; 32]);
        assert_eq!((r[125], r.len()), (18, 126));
        // A one-byte length cannot carry an empty or a 256-byte field.
        assert_eq!(register_message(7, 1, "", "zUSD", &[0; 32], 2, &[0; 32], 6), None);
        assert_eq!(register_message(7, 1, "x", &"y".repeat(256), &[0; 32], 2, &[0; 32], 6), None);
        assert!(register_message(7, 1, &"n".repeat(255), "y", &[0; 32], 2, &[0; 32], 6).is_some());
    }

    /// The `register` and `list` vectors: each message byte for byte from the vector's own fields,
    /// each quorum `ok` under the five rules and reproduced signature by signature — and a quorum
    /// for one message authorises no other: not the other kind, not another nonce, not another
    /// field of the same kind.
    #[test]
    fn the_listing_vectors_reproduce_and_their_quorums_verify() {
        let file = vectors();
        let chain_id = file["rand_chain_id"].as_u64().unwrap();
        let keys = vector_keys(&file);
        let g = governance();

        let v = &g["register"];
        let (nonce, chain, decimals) =
            (v["list_nonce"].as_u64().unwrap(), v["chain"].as_u64().unwrap() as u16, v["decimals"].as_u64().unwrap() as u8);
        let (name, symbol) = (v["name"].as_str().unwrap(), v["symbol"].as_str().unwrap());
        let (salt, token) = (hex32(&v["salt"]), hex32(&v["token"]));
        let register = register_message(chain_id, nonce, name, symbol, &salt, chain, &token, decimals).unwrap();
        assert_eq!(register, bytes(&v["message"]), "M_register byte for byte");
        let register_sigs = vector_sigs(&v["pq_signatures"]);
        assert_eq!(register_sigs.len(), 5);
        assert_eq!(verdict(&check_pq_quorum_message(&register_sigs, &keys, &register)), "ok");
        reproduces(&register_sigs, &register);

        let v = &g["list"];
        let (nonce_l, index, chain_l, decimals_l) = (
            v["list_nonce"].as_u64().unwrap(),
            v["token_index"].as_u64().unwrap() as u32,
            v["chain"].as_u64().unwrap() as u16,
            v["decimals"].as_u64().unwrap() as u8,
        );
        let token_l = hex32(&v["token"]);
        let list = list_message(chain_id, nonce_l, index, chain_l, &token_l, decimals_l);
        assert_eq!(list, bytes(&v["message"]), "M_list byte for byte");
        let list_sigs = vector_sigs(&v["pq_signatures"]);
        assert_eq!(list_sigs.len(), 5);
        assert_eq!(verdict(&check_pq_quorum_message(&list_sigs, &keys, &list)), "ok");
        reproduces(&list_sigs, &list);

        // One message's quorum is no other message's.
        let bad = |sigs: &[PqSignature], m: Vec<u8>| verdict(&check_pq_quorum_message(sigs, &keys, &m));
        assert_eq!(bad(&register_sigs, list.clone()), "PqBadSignature");
        assert_eq!(bad(&list_sigs, register.clone()), "PqBadSignature");
        assert_eq!(bad(&list_sigs, list_message(chain_id, nonce_l + 1, index, chain_l, &token_l, decimals_l)), "PqBadSignature");
        assert_eq!(bad(&list_sigs, list_message(chain_id + 1, nonce_l, index, chain_l, &token_l, decimals_l)), "PqBadSignature");
        assert_eq!(bad(&list_sigs, list_message(chain_id, nonce_l, index + 1, chain_l, &token_l, decimals_l)), "PqBadSignature");
        assert_eq!(bad(&list_sigs, list_message(chain_id, nonce_l, index, chain_l, &token_l, decimals_l + 1)), "PqBadSignature");
        assert_eq!(
            bad(&register_sigs, register_message(chain_id, nonce, name, "zUSDC", &salt, chain, &token, decimals).unwrap()),
            "PqBadSignature"
        );
        assert_eq!(
            bad(&register_sigs, register_message(chain_id, nonce, name, symbol, &[0; 32], chain, &token, decimals).unwrap()),
            "PqBadSignature"
        );
        assert_eq!(bad(&register_sigs, unpause_message(chain_id, nonce)), "PqBadSignature");
    }

    /// Audit v4 (bridge rules v2): the two rotation messages, byte for byte. `M_rotate_pq` is the
    /// domain, the chain id, the bridge's `rotation_nonce`, a `u32` count and every new PQ key's
    /// 1 312 raw bytes in index order; `M_rotate_pause` is the domain, the chain id, the nonce and
    /// the new pause key's 1 312 bytes. What `rand-bridge-gov pq-rotate-pq`/`pq-rotate-pause` must
    /// reproduce (`docs/bridge.md` §21).
    #[test]
    fn the_rotation_messages_are_fixed_bytes_over_the_nonce_and_the_raw_keys() {
        let keys: Vec<PublicKey> = (0..2u8).map(|i| Keypair::from_seed([0x40 + i; 32]).unwrap().public_key().clone()).collect();
        let m = rotate_pq_message(0x0102_0304_0506_0708, 5, &keys);
        assert_eq!(&m[..26], b"rand-bridge-pq-rotate-pq-1");
        assert_eq!(&m[26..34], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&m[34..42], &5u64.to_be_bytes());
        assert_eq!(&m[42..46], &2u32.to_be_bytes());
        assert_eq!(&m[46..46 + 1312], keys[0].as_bytes());
        assert_eq!(&m[46 + 1312..46 + 2 * 1312], keys[1].as_bytes());
        assert_eq!(m.len(), 46 + 2 * 1312);
        assert_eq!(ROTATE_PQ_DOMAIN.len(), 26);
        // An empty set is still a well-formed message (validate refuses it on the length rule).
        assert_eq!(rotate_pq_message(7, 0, &[]).len(), 46);

        let p = rotate_pause_message(0x0102_0304_0506_0708, 5, &keys[1]);
        assert_eq!(&p[..29], b"rand-bridge-pq-rotate-pause-1");
        assert_eq!(&p[29..37], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&p[37..45], &5u64.to_be_bytes());
        assert_eq!(&p[45..], keys[1].as_bytes());
        assert_eq!(p.len(), 45 + 1312);
        assert_eq!(ROTATE_PAUSE_DOMAIN.len(), 29);
        // Neither is the other, nor a message of another kind at the same nonce.
        assert_ne!(rotate_pq_message(7, 1, &keys[1..]), rotate_pause_message(7, 1, &keys[1]));
        assert_ne!(&rotate_pq_message(7, 1, &keys)[..24], &unpause_message(7, 1)[..24]);
    }

    /// Every vector of the `governance` section, counted: the four kinds the bridge repo ships
    /// (register, list, unpause, pause), so a kind silently dropped from the file fails here.
    #[test]
    fn the_governance_section_has_exactly_the_four_kinds() {
        let g = governance();
        let mut kinds: Vec<&str> = g.as_object().unwrap().keys().map(String::as_str).collect();
        kinds.sort();
        assert_eq!(kinds, ["list", "pause", "register", "unpause"]);
    }
}
