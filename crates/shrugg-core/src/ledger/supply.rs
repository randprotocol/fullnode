//! The public supply audit (phase S2).
//!
//! A note's value is hidden, so the pool's contents cannot be summed. Every *entry to* and
//! *exit from* the pool is public, though, and that is enough: the chain keeps five running
//! counters of the value that crossed the boundary, and the register holds the rest of the
//! supply in the clear (spec §8). Together they say what the chain has issued and where it is,
//! without saying anything about who holds which note.
//!
//! These counters are **not** consensus state in the state-root sense — [`super::Ledger::state_root`]
//! does not hash them, and no rule reads them. They are derived from the chain like the note
//! tree is: a node persists them beside the state and `--verify-chain` recomputes them by
//! replaying every block, which is what makes them auditable rather than merely reported.

use super::ValidatorEntry;
use crate::crypto::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Every public movement of SHRUGG across the pool's boundary, in token units.
///
/// The pool is everything the commitment tree holds; the register is everything the staking
/// table holds. Value enters the pool as a genesis deposit, a faucet mint or a validator's
/// withdraw, and leaves it as a bundle fee (into the proposer's `rewards`) or a burn (today
/// only a `Bond`, into `stake`). Nothing else moves value between the two, which is why
/// [`total_supply`](Audit::total_supply) can be checked against what was ever issued.
///
/// A withdraw pays the bundle base to the block's proposer out of the amount it withdraws, and
/// that half never leaves the register: only the note is counted here, and the base simply moves
/// from one register entry to another.
///
/// Phase S3's bridge adds no counter, and deliberately: asset index 0 is reserved for SHRUGG and
/// the asset registry never hands it out ([`crate::bridge::FIRST_ASSET_INDEX`]), so a
/// `BridgeAttest` always deposits a note of some *other* asset and a `BridgeBurn`'s asset bundle
/// always destroys one. Neither crosses the SHRUGG boundary, which is why `apply_tx` counts
/// `fees_paid`/`burned` on the fee bundle's path only and not inside
/// [`super::Ledger::apply_bundle_notes`], which both bundles share. Each bridged asset's own
/// audit is the bridge state's business (`shrugg_getAssets`), not this one's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Supply {
    /// Σ of the genesis deposit notes (asset 0).
    pub genesis_deposited: u64,
    /// Σ of the stakes genesis seeded the register with.
    ///
    /// Not in the addendum's first sketch of this audit, and not optional: a genesis validator's
    /// stake is real SHRUGG — it can be unbonded and withdrawn into a note like any other — but
    /// it was never deposited into the pool, so without it every chain with validators would
    /// report `total_supply` exceeding what it issued from its very first block.
    pub genesis_staked: u64,
    /// Σ of every accepted `Mint` (the testnet faucet).
    pub faucet_minted: u64,
    /// Σ of the notes accepted `Withdraw`s created: stake and rewards paid back into the pool.
    ///
    /// The note is worth `amount - gas::BUNDLE_BASE`, not the whole amount — the base is the fee
    /// the withdraw pays its block's proposer, and it stays in the register — so this is what
    /// actually crossed into the pool, which is what the invariant needs it to be.
    pub withdraw_deposited: u64,
    /// Σ of every bundle fee: value that left the pool into a proposer's `rewards`.
    pub fees_paid: u64,
    /// Σ of every bundle `burn`. Today only a `Bond` may burn, and it burns into `stake`.
    pub burned: u64,
}

impl Supply {
    /// Value the pool holds: what entered minus what left.
    ///
    /// Saturating rather than wrapping: the arithmetic cannot go negative on a chain whose
    /// blocks all applied (a fee or a burn is paid out of a note the pool already held), so a
    /// saturation would mean the counters are wrong — and it shows up as
    /// [`Audit::invariant_holds`] being false rather than as a panic in an RPC handler.
    pub fn pool_value(&self) -> u64 {
        self.genesis_deposited
            .saturating_add(self.faucet_minted)
            .saturating_add(self.withdraw_deposited)
            .saturating_sub(self.fees_paid)
            .saturating_sub(self.burned)
    }

    /// Everything this chain has ever issued: what genesis created, plus the faucet. A withdraw
    /// is not issuance — it moves value the register already held back into the pool — and
    /// neither is a fee or a burn, which move value the other way.
    pub fn issued(&self) -> u64 {
        self.genesis_deposited.saturating_add(self.genesis_staked).saturating_add(self.faucet_minted)
    }
}

/// What the register holds in the clear: bonded stake, unbonding amounts and unpaid rewards.
pub fn register_total(register: &BTreeMap<Address, ValidatorEntry>) -> u64 {
    register.values().fold(0u64, |acc, e| {
        let pending: u64 = e.pending.iter().fold(0u64, |a, (_, amount)| a.saturating_add(*amount));
        acc.saturating_add(e.stake).saturating_add(pending).saturating_add(e.rewards)
    })
}

/// The answer `shrugg_getSupply` gives: the counters, the two halves they add up to, and
/// whether the two halves still account for everything the chain issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Audit {
    pub supply: Supply,
    pub pool_value: u64,
    pub register_total: u64,
}

impl Audit {
    pub fn new(supply: Supply, register_total: u64) -> Audit {
        Audit { supply, pool_value: supply.pool_value(), register_total }
    }

    pub fn total_supply(&self) -> u64 {
        self.pool_value.saturating_add(self.register_total)
    }

    /// Everything the chain issued is either in the pool or in the register. A false here is a
    /// consensus bug or a damaged counter, never a legitimate chain state.
    pub fn invariant_holds(&self) -> bool {
        self.total_supply() == self.supply.issued()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::notes::ShieldedAddress;

    fn entry(stake: u64, pending: Vec<(u64, u64)>, rewards: u64) -> ValidatorEntry {
        ValidatorEntry {
            public_key: Keypair::from_seed([1; 32]).unwrap().public_key().clone(),
            stake,
            pending,
            rewards,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
        }
    }

    #[test]
    fn the_pool_is_what_entered_minus_what_left() {
        let s = Supply {
            genesis_deposited: 1_000,
            faucet_minted: 500,
            withdraw_deposited: 70,
            fees_paid: 20,
            burned: 300,
            ..Default::default()
        };
        assert_eq!(s.pool_value(), 1_000 + 500 + 70 - 20 - 300);
        assert_eq!(s.issued(), 1_500, "a withdraw returns value, it does not issue it");
        assert_eq!(
            Supply { genesis_staked: 7, ..s }.issued(),
            1_507,
            "a genesis stake is issued too, it is simply issued into the register"
        );
        // The register holds the fees (as rewards) and the burn (as stake), less what was
        // withdrawn back out of it.
        let register: BTreeMap<Address, ValidatorEntry> =
            [(Address([1; 32]), entry(230, vec![(3, 50)], 20))].into_iter().collect();
        assert_eq!(register_total(&register), 300);
        let audit = Audit::new(s, register_total(&register));
        assert_eq!(audit.total_supply(), 1_550);
        assert!(!audit.invariant_holds(), "230 + 50 + 20 does not account for the 70 withdrawn");
        let audit = Audit::new(s, 250);
        assert!(audit.invariant_holds());
    }

    #[test]
    fn a_counter_that_cannot_be_right_saturates_instead_of_wrapping() {
        // Fees only ever leave a pool something was deposited into, so this cannot arise on a
        // chain whose blocks all applied. If a damaged counter ever produced it, the pool reads
        // as empty rather than as `u64::MAX`.
        let s = Supply { fees_paid: 5, ..Default::default() };
        assert_eq!(s.pool_value(), 0);
        assert_eq!(Audit::new(s, 0).total_supply(), 0);
    }
}
