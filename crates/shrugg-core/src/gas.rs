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
///
/// An action that rides without a bundle ([`Action::bundle_less`]) has nothing to pay a fee
/// *from*, so its floor is zero: a mint and an `Unbond` are free, and a `Withdraw` pays the base
/// out of the amount it withdraws instead (`ledger::staking`).
pub fn fee_floor(action: &Action) -> u64 {
    match action {
        Action::Mint { .. } | Action::Unbond { .. } | Action::Withdraw { .. } => 0,
        Action::None => BUNDLE_BASE,
        Action::Deploy { words, .. } => BUNDLE_BASE + deploy_fee(words.len()),
        Action::Call { .. } => BUNDLE_BASE + CALL_BASE,
        // A bond is the one staking action that rides on a bundle — the bundle is what burns the
        // stake out of the pool — so it pays the plain base like a transfer.
        Action::Bond { .. } => BUNDLE_BASE,
        // An attestation's decode and guardian signature recovery are cheap next to a STARK
        // verify, and the bundle base already covers the one bundle it carries.
        Action::BridgeAttest { .. } => BUNDLE_BASE,
        // Spec §7 item 3 charges the bundle base "for every bundle", and a `BridgeBurn` is the
        // one transaction that carries two: the SHRUGG fee bundle and the asset bundle inside
        // the action. Both are verified, so both are paid for — and by this bundle, because the
        // asset bundle's `fee` must be zero (the guest's "`asset != 0` => `fee = 0`" rule).
        Action::BridgeBurn { .. } => 2 * BUNDLE_BASE,
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

    /// A bond rides on the bundle that burns its stake, so it pays the base like a transfer; the
    /// two validator-signed actions ride bundle-less and have nothing to pay a fee from at all.
    #[test]
    fn only_bond_of_the_staking_actions_pays_the_bundle_base() {
        use crate::crypto::{Address, Signature};
        let v = Address([1; 32]);
        assert_eq!(fee_floor(&Action::Bond { validator: v, amount: 1, registration: None }), BUNDLE_BASE);
        for a in [
            Action::Unbond { validator: v, amount: 1, nonce: 0, signature: Signature::empty() },
            Action::Withdraw {
                validator: v,
                amount: 1,
                nonce: 0,
                time: 0,
                r: [0; 8],
                envelope: env(),
                signature: Signature::empty(),
            },
        ] {
            assert_eq!(fee_floor(&a), 0, "{a:?}");
            assert!(a.bundle_less().is_some(), "a zero floor is only for an action with no bundle: {a:?}");
        }
    }

    /// Spec §7 item 3 charges the bundle base per *bundle*, so a `BridgeAttest` — one bundle —
    /// pays it once and a `BridgeBurn` — the chain's only two-bundle transaction — pays it
    /// twice, out of the one bundle that is allowed a non-zero fee.
    #[test]
    fn a_burn_pays_the_bundle_base_for_both_of_its_bundles() {
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
        let attest = Action::BridgeAttest {
            attestation: vec![],
            recipient: crate::notes::ShieldedAddress { pk: [0; 8], kem_ek: vec![] },
            r: [0; 8],
            time: 0,
            asset: 1,
            envelope: env(),
        };
        assert_eq!(fee_floor(&attest), BUNDLE_BASE);
        let burn = Action::BridgeBurn { asset_bundle: b, asset: 1, amount: 1, relayer_fee: 0, to_chain: 2, to: [0; 32] };
        assert_eq!(fee_floor(&burn), 2 * BUNDLE_BASE);
    }

    #[test]
    fn call_fee_steps_every_two_tiers() {
        assert_eq!(call_fee(10), 1_000_000);
        assert_eq!(call_fee(12), 1_100_000);
        assert_eq!(call_fee(20), 1_500_000);
        assert_eq!(call_fee(0), 1_000_000, "below MIN_TIER saturates");
    }
}
