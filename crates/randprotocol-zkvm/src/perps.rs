//! RPL-3 perps: the Poseidon2 domains of the perp words, as a guest (durian.market's
//! `perp-guest`) hashes them.
//!
//! **Node-local, not vendored.** These sat in `notes::domain` beside the other tags, but `notes.rs`
//! is vendored from the research crate by `deploy/sync-zkvm.sh`, and a resync would erase them;
//! this module is on that script's rsync exclude list instead, as `hidden.rs` is.
//! `randprotocol_core::ledger::perps::domain::{BLOCK, STATE, PAYOUTS}` mirrors them (core cannot
//! name this crate); the test below pins the two.

/// A block's input digest `D_h`, the engine's state root `R`, and a state proof's payouts digest —
/// each `perps::perp_digest` over a length-prefixed, chunked word string. Upstream's
/// `notes::domain` hands out tags sequentially from 1 (16 is `KEM_SEED_VERSION`); 17–20 are left
/// free.
pub const PERP_BLOCK: u32 = 21;
/// The engine's state root `R`.
pub const PERP_STATE: u32 = 22;
/// A state proof's payouts digest.
pub const PERP_PAYOUTS: u32 = 23;

#[cfg(test)]
mod tests {
    use super::{PERP_BLOCK, PERP_PAYOUTS, PERP_STATE};
    use randprotocol_core::ledger::perps;

    /// The ledger computes `D_h`, `R` and the payouts digest through the executor under its own
    /// copies of the three domains; a guest uses these. They must be the same words. Likewise the
    /// tier list `PerpsConfig::check` holds `max_tier` to.
    #[test]
    fn perp_domains_match_core() {
        assert_eq!(PERP_BLOCK, perps::domain::BLOCK);
        assert_eq!(PERP_STATE, perps::domain::STATE);
        assert_eq!(PERP_PAYOUTS, perps::domain::PAYOUTS);
        let tiers: Vec<usize> = perps::TIERS.iter().map(|&t| t as usize).collect();
        assert_eq!(tiers, crate::machine::TIERS, "PerpsConfig::check's tier list is the machine's");
    }
}
