//! Limits and the v0 fee schedule for the shielded pool and confidential computation.

use crate::types::Action;

/// Largest program, in 32-bit words (16 KiB of code).
pub const MAX_PROGRAM_WORDS: usize = 4096;
/// Largest proof accepted in a transaction.
pub const MAX_PROOF_BYTES: usize = 1 << 20;
/// Largest bridge attestation accepted in a `BridgeAttest` transaction.
///
/// A real attestation is tiny: 6 envelope bytes, 66 per signature, a
/// 51-byte body header and a payload of 133 bytes (transfer) or
/// 5 + 20 * n (upgrade) — 520 bytes at the launch parameters (n = 6,
/// quorum 5). 16 KiB still admits a quorum of well over 200 guardians,
/// so it constrains nothing reachable while keeping an oversized blob
/// from buying decode and signature-recovery work at a zero fee.
pub const MAX_ATTESTATION_BYTES: usize = 16_384;
/// Transaction bytes per block (proofs are ~0.9 MB each).
pub const MAX_BLOCK_BYTES: usize = 4 << 20;
/// Transactions per block.
pub const MAX_BLOCK_TXS: usize = 2_000;
/// zkVM tiers (log2 of the CPU table height).
pub const MIN_TIER: u8 = 10;
pub const MAX_TIER: u8 = 20;

/// What every bundle pays before its action's own floor (0.001 SHRUGG, spec §7 item 3).
pub const BUNDLE_BASE: u64 = 1_000_000;
pub const DEPLOY_PER_WORD: u64 = 100_000;
pub const CALL_BASE: u64 = 1_000_000;
pub const CALL_PER_TIER_STEP: u64 = 100_000;

/// Minimum fee to deploy a program of `words` words.
pub fn deploy_fee(words: usize) -> u64 {
    DEPLOY_PER_WORD * words as u64
}

/// Minimum fee for a call proven at `tier` (10, 12, ..., 20).
pub fn call_fee(tier: u8) -> u64 {
    let steps = (tier.saturating_sub(MIN_TIER) / 2) as u64;
    CALL_BASE + CALL_PER_TIER_STEP * steps
}

/// The floor a bundle must pay before the action's proof is verified. A call's tier-dependent
/// part is only known once its proof has been decoded, so it is charged afterwards
/// (`Ledger::validate`); this floor is what keeps that work from being bought for nothing.
/// A mint carries no bundle and pays nothing.
pub fn fee_floor(action: &Action) -> u64 {
    match action {
        Action::Mint { .. } => 0,
        Action::None => BUNDLE_BASE,
        Action::Deploy { words, .. } => BUNDLE_BASE + deploy_fee(words.len()),
        Action::Call { .. } => BUNDLE_BASE + CALL_BASE,
        // S2 scaffold: staking has no proving work of its own, so the plain bundle base is
        // likely its final floor; S2 owns this arm and confirms or refines it.
        Action::Bond { .. } | Action::Unbond { .. } | Action::Withdraw { .. } => BUNDLE_BASE,
        // S3 scaffold: the bundle base until S3 prices the work these buy — an attestation's
        // decode and guardian signature recovery, and a burn's second bundle proof. S3 owns
        // this arm, so the two phases never touch the same line.
        Action::BridgeAttest { .. } | Action::BridgeBurn { .. } => BUNDLE_BASE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_fee_is_linear_in_words() {
        assert_eq!(deploy_fee(0), 0);
        assert_eq!(deploy_fee(1), 100_000);
        assert_eq!(deploy_fee(256), 25_600_000);
    }

    #[test]
    fn fee_floor_adds_the_bundle_base() {
        assert_eq!(fee_floor(&Action::None), 1_000_000);
        assert_eq!(fee_floor(&Action::Deploy { base_pc: 0, words: vec![0x13; 10] }), 1_000_000 + 1_000_000);
        assert_eq!(
            fee_floor(&Action::Call { program: crate::crypto::Hash::ZERO, proof: vec![], input_envelope: None }),
            2_000_000
        );
        assert_eq!(
            fee_floor(&Action::Mint {
                cm: [0; 8],
                envelope: crate::notes::Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] },
                amount: 5,
                minter: crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone(),
                signature: crate::crypto::Signature::empty(),
            }),
            0
        );
    }

    fn env() -> crate::notes::Envelope {
        crate::notes::Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] }
    }

    /// S2 scaffold: each staking action pays exactly the bundle base, no more and no less.
    /// S2 owns this test and its arm of [`fee_floor`].
    #[test]
    fn the_staking_actions_pay_the_bundle_base() {
        use crate::crypto::{Address, Signature};
        for a in [
            Action::Bond { validator: Address([1; 32]), amount: 1, registration: None },
            Action::Unbond { validator: Address([1; 32]), amount: 1, nonce: 0, signature: Signature::empty() },
            Action::Withdraw {
                validator: Address([1; 32]),
                amount: 1,
                nonce: 0,
                r: [0; 8],
                envelope: env(),
                signature: Signature::empty(),
            },
        ] {
            assert_eq!(fee_floor(&a), BUNDLE_BASE, "{a:?}");
        }
    }

    /// S3 scaffold: each bridge action pays exactly the bundle base, no more and no less.
    /// S3 owns this test and its arm of [`fee_floor`].
    #[test]
    fn the_bridge_actions_pay_the_bundle_base() {
        let b = crate::notes::Bundle {
            anchor: [0; 8],
            nullifiers: [[0; 8], [1; 8]],
            commitments: [[2; 8], [3; 8]],
            fee: 0,
            burn: 0,
            asset: 0,
            time: 0,
            envelopes: [env(), env()],
            proof: vec![],
        };
        for a in [
            Action::BridgeAttest {
                attestation: vec![],
                recipient: crate::notes::ShieldedAddress { pk: [0; 8], kem_ek: vec![] },
                r: [0; 8],
                envelope: env(),
            },
            Action::BridgeBurn { asset_bundle: b, asset: 1, amount: 1, relayer_fee: 0, to_chain: 2, to: [0; 32] },
        ] {
            assert_eq!(fee_floor(&a), BUNDLE_BASE, "{a:?}");
        }
    }

    #[test]
    fn call_fee_steps_every_two_tiers() {
        assert_eq!(call_fee(10), 1_000_000);
        assert_eq!(call_fee(12), 1_100_000);
        assert_eq!(call_fee(20), 1_500_000);
        assert_eq!(call_fee(0), 1_000_000, "below MIN_TIER saturates");
    }
}
