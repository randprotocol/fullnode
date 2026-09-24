//! Test bridge guardians: the six ECDSA guardian secrets, the six Dilithium2 PQ guardian keys, the
//! pause key, and the signed material they produce — transfer attestations from any registered
//! source chain, the PQ co-signature over an attestation, and a PQ quorum over any Rand-only
//! governance message (`M_register`, `M_list`, `M_unpause`).
//!
//! Built out of the public API (`guardian_address`, `sign_digest`, `pq_cosign`, the `gov`
//! message builders) exactly as the core bridge tests and the bridge repo's vectors build them —
//! those tests are `#[cfg(test)]` inside `randprotocol-core` and unreachable from here. Shared by
//! `cluster.rs` and `zusd_e2e.rs`.

use randprotocol_core::bridge::{
    digest, guardian_address, pq_cosign, sign_digest, Attestation, Body, BridgeConfig, Payload, PqSignature, Transfer,
    CHAIN_RAND,
};
use randprotocol_core::Keypair;
use std::collections::BTreeMap;

/// The six guardian secrets of a bridged test chain. Five signatures is a quorum for six keys.
pub fn guardian_secrets() -> Vec<[u8; 32]> {
    (1u8..=6).map(|i| [i; 32]).collect()
}

/// The six PQ guardians' Dilithium2 keys (bridge hardening B3), index-aligned with
/// [`guardian_secrets`].
pub fn pq_guardian_keys() -> Vec<Keypair> {
    (0..6u8).map(|i| Keypair::from_seed([0x70 + i; 32]).unwrap()).collect()
}

/// The genesis `bridge.pause_key`'s keypair (B1): it signs `M_pause` and nothing else.
pub fn pause_keypair() -> Keypair {
    Keypair::from_seed([0x7f; 32]).unwrap()
}

/// A source chain's registered emitter address on a test chain: 32 bytes of the chain id.
pub fn emitter_of(chain: u16) -> [u8; 32] {
    [chain as u8; 32]
}

/// A `bridge` section naming those guardians, the PQ set and the pause key, with `emitter` as
/// Rand's own outbound emitter and every chain in `source_chains` registered at [`emitter_of`].
pub fn bridge_config_for(emitter: [u8; 32], source_chains: &[u16]) -> BridgeConfig {
    BridgeConfig {
        emitter,
        guardians: guardian_secrets().iter().map(guardian_address).collect(),
        emitters: source_chains.iter().map(|c| (*c, emitter_of(*c))).collect::<BTreeMap<_, _>>(),
        pq_guardians: pq_guardian_keys().iter().map(|k| k.public_key().clone()).collect(),
        pause_key: Some(pause_keypair().public_key().clone()),
        rules_v2: None,
    }
}

/// One inbound transfer attestation, guardian set 0, signed by the lowest five guardians:
/// `amount` (eight-decimal wire units) of `token` native to `chain`, emitted by that chain's
/// registered emitter with `sequence`, addressed to the recipient hash `to`.
pub fn transfer_attestation(chain: u16, token: [u8; 32], to: [u8; 32], amount: u128, sequence: u64) -> Vec<u8> {
    let secrets = guardian_secrets();
    let body = Body {
        timestamp: 1,
        nonce: 0,
        emitter_chain: chain,
        emitter_address: emitter_of(chain),
        sequence,
        consistency_level: 0,
        payload: Payload::Transfer(Transfer {
            amount: Transfer::u256_from_u128(amount),
            token_address: token,
            token_chain: chain,
            to,
            to_chain: CHAIN_RAND,
            fee: Transfer::u256_from_u128(0),
        })
        .encode(),
    };
    let d = digest(&body.encode());
    let signatures = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
    Attestation { guardian_set_index: 0, signatures, body }.encode()
}

/// The lowest-five PQ co-signature quorum over `attestation`'s `mu` on chain `chain_id`.
pub fn pq_quorum(chain_id: u64, attestation: &[u8]) -> Vec<PqSignature> {
    let mu = Attestation::body_bytes(attestation).map(digest).expect("a decodable attestation");
    pq_guardian_keys().iter().take(5).enumerate().map(|(i, k)| pq_cosign(k, i as u8, chain_id, &mu)).collect()
}

/// The lowest-five PQ quorum over a Rand-only governance message (`bridge::gov`'s `M_register`,
/// `M_list`, `M_unpause`): each guardian signs the fixed-layout bytes directly, as
/// `rand-bridge-gov` does.
pub fn pq_quorum_message(message: &[u8]) -> Vec<PqSignature> {
    pq_guardian_keys()
        .iter()
        .take(5)
        .enumerate()
        .map(|(i, k)| PqSignature { index: i as u8, signature: k.sign(message).as_bytes().to_vec() })
        .collect()
}
