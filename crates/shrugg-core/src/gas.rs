//! Limits and the v0 fee schedule for confidential computation.

/// Largest program, in 32-bit words (16 KiB of code).
pub const MAX_PROGRAM_WORDS: usize = 4096;
/// Largest proof accepted in a transaction.
pub const MAX_PROOF_BYTES: usize = 1 << 20;
/// Largest public recipient list on a call.
pub const MAX_RECIPIENTS: usize = 8;
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
/// zkVM tiers (log2 of the CPU table height).
pub const MIN_TIER: u8 = 10;
pub const MAX_TIER: u8 = 20;

pub const DEPLOY_PER_WORD: u128 = 100_000;
pub const CALL_BASE: u128 = 1_000_000;
pub const CALL_PER_TIER_STEP: u128 = 100_000;

/// Minimum fee to deploy a program of `words` words.
pub fn deploy_fee(words: usize) -> u128 {
    DEPLOY_PER_WORD * words as u128
}

/// Minimum fee for a call proven at `tier` (10, 12, ..., 20).
pub fn call_fee(tier: u8) -> u128 {
    let steps = (tier.saturating_sub(MIN_TIER) / 2) as u128;
    CALL_BASE + CALL_PER_TIER_STEP * steps
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
    fn call_fee_steps_every_two_tiers() {
        assert_eq!(call_fee(10), 1_000_000);
        assert_eq!(call_fee(12), 1_100_000);
        assert_eq!(call_fee(20), 1_500_000);
        assert_eq!(call_fee(0), 1_000_000, "below MIN_TIER saturates");
    }
}
