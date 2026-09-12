//! Limits and the v0 fee schedule for the shielded pool and confidential computation.

use crate::types::Action;

/// Largest program, in 32-bit words (16 KiB of code).
pub const MAX_PROGRAM_WORDS: usize = 4096;
/// Largest proof accepted in a transaction.
///
/// Constraint set 5 (upstream `ffd9e1e`, milestone 4.2) restored the whitepaper's production FRI
/// profile — 80 queries, blowup 8, 20 proof-of-work bits — and with it the proof sizes the
/// whitepaper's parameter table implies: a keccak-free tier-10 proof measures ~1 202 416 bytes
/// and a tier-12 one ~1 252 338 bytes (upstream `research/docs/03-privacy.md`, measured on
/// `guests::fib`). The old 1 MiB cap rejected *every* production proof, so it is 2 MiB now.
///
/// 2 MiB is the smallest power-of-two cap above the measured sizes with room for the ~1%
/// run-to-run variation the hiding PCS's fresh per-proof entropy causes, and it is deliberately
/// *below* the ~3.11 MB a tier-10 proof that carries the optional keccak table costs: no guest
/// this chain deploys calls `SYS_KECCAK`, and admitting one at 4 MiB would put a single
/// transaction in reach of the whole block (see `MAX_BLOCK_BYTES`).
pub const MAX_PROOF_BYTES: usize = 2 << 20;
/// Largest bridge attestation accepted in a `BridgeAttest` transaction.
///
/// A real attestation is tiny: 6 envelope bytes, 66 per signature, a
/// 51-byte body header and a payload of 133 bytes (transfer) or
/// 5 + 20 * n (upgrade) — 520 bytes at the launch parameters (n = 6,
/// quorum 5). 16 KiB still admits a quorum of well over 200 guardians,
/// so it constrains nothing reachable while keeping an oversized blob
/// from buying decode and signature-recovery work at a zero fee.
pub const MAX_ATTESTATION_BYTES: usize = 16_384;
/// Transaction bytes per block. Under constraint set 5 a proof is ~1.2–1.3 MB (see
/// `MAX_PROOF_BYTES`), so 4 MiB admits **three** shielded transfers per block rather than the
/// nine the 27-query profile allowed.
///
/// Deliberately unchanged at 4 MiB: `docs/block-space.md` §5 records the decision. Raising the
/// cap buys throughput linearly and nothing else, while every validator pays the bandwidth and
/// the disk for it — a full 4 MiB block every ~2 s is already ~170 GB/day — and block-level
/// aggregation, not a bigger block, is the queued remedy (§6).
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
        assert_eq!(fee_floor(&Action::Call { program: crate::crypto::Hash::ZERO, proof: vec![] }), 2_000_000);
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

    #[test]
    fn call_fee_steps_every_two_tiers() {
        assert_eq!(call_fee(10), 1_000_000);
        assert_eq!(call_fee(12), 1_100_000);
        assert_eq!(call_fee(20), 1_500_000);
        assert_eq!(call_fee(0), 1_000_000, "below MIN_TIER saturates");
    }
}
