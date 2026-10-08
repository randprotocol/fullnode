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

/// Every public movement of RAND across the pool's boundary, in token units.
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
/// Phase S3's bridge and the RPL token standard add no counter, and deliberately: asset index 0
/// is reserved for RAND and the token registry never hands it out
/// ([`crate::ledger::tokens::FIRST_TOKEN_INDEX`]), so a `BridgeAttest` always deposits a note of
/// some *other* asset, and a bundle's `burn_a` — a `BridgeBurn`'s or a `TokenBurn`'s — always
/// destroys one (a RAND `burn_a` is refused, `TxError::NonCanonicalRandBurn`). None of them
/// crosses the RAND boundary (a token's own supply is the registry's count, audited there), so
/// `apply_tx` counts `fees_paid` and `burned` from a bundle's `fee` and `burn_r` alone. A
/// transfer of a token inside the pool moves no counter at all: its asset is not even public.
/// Each bridged asset's own audit is the bridge state's business (`rand_getAssets`), not this
/// one's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Supply {
    /// Σ of the genesis deposit notes (asset 0).
    pub genesis_deposited: u64,
    /// Σ of the stakes genesis seeded the register with.
    ///
    /// Not in the addendum's first sketch of this audit, and not optional: a genesis validator's
    /// stake is real RAND — it can be unbonded and withdrawn into a note like any other — but
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
    ///
    /// On an aggregating chain the fee splits at inclusion (spec §5.2): the proposer keeps the
    /// floor (`gas::BUNDLE_BASE`), counted here at once, and the excess is bucketed in
    /// `unsealed_fees` — still pool-side in this accounting until it resolves. It resolves one
    /// of two ways, each counted here at that moment and not before: an expired excess is swept
    /// to the recorded proposer, and a covered one returns to the pool inside the aggregate's
    /// payout note (spec §5.4), where it needs no counter — it never left.
    ///
    /// Under `tokens.burn_registration_fee` (audit v5 TOK-2) a `RegisterToken`'s or
    /// `RegisterBridgedToken`'s fee is split first: the `registration_fee` part is destroyed
    /// (`burned`, below) and only the remainder is the fee this counter and the proposer see.
    pub fees_paid: u64,
    /// Σ of every bundle's `burn_r`, its RAND burn. Only a `Bond` may set one, and it burns into
    /// `stake` — and a `RegisterAggregator`'s bundle, which burns into `aggregator_bonds` (spec
    /// §5.3). Under `tokens.burn_registration_fee` (audit v5 TOK-2) every registration's
    /// `registration_fee` is added here too: it goes nowhere — not to the proposer, not to any
    /// register entry — so it sits on the right of the audit's identity like a slashed bond.
    pub burned: u64,
    /// Σ of aggregator bonds burned in, minus bonds paid out or slashed (block aggregation,
    /// spec §5.3): the register-side twin of the aggregator register's outstanding bonds.
    pub aggregator_bonds: u64,
    /// Σ of what slashing destroyed: aggregator bonds by `SlashAggregator` (retired), and — under
    /// `staking.slashing` (audit v6, STAKE-1) — `equivocation_bps` of an equivocating leader's
    /// bonded and unbonding stake by `SlashEquivocation`. Slashing destroys issuance: nothing is
    /// paid out, so it appears on the right of the audit's identity (`total_supply == issued −
    /// slashed`).
    pub slashed: u64,
    /// The count of sealed blocks — blocks carrying an included `Aggregate` (spec §5.1's `n`).
    /// The subsidy schedule reads it; it increments at the aggregate's apply, so on a chain
    /// that has sealed nothing it is 0 and the subsidy is `subsidy_base`.
    pub sealed_blocks: u64,
    /// Σ of every `subsidy(n)` minted at an `Aggregate`'s apply (spec §5.1) — under the genesis
    /// `fees.subsidy_net_of_fees` only its shortfall over the covered proving shares
    /// (`aggregation::minted_subsidy`, `docs/fees.md` §1.3). This is new issuance, and it is
    /// the *whole* of what the payout note adds to these counters: the note's other part, the
    /// covered bundles' proving shares, is value that never left the pool in this accounting
    /// (see `fees_paid`), so it touches no counter when it lands.
    pub subsidised: u64,
}

impl Supply {
    /// Value the pool holds: what entered minus what left.
    ///
    /// Saturating rather than wrapping: the arithmetic cannot go negative on a chain whose
    /// blocks all applied (a fee or a burn is paid out of a note the pool already held), so a
    /// saturation would mean the counters are wrong — and it shows up as
    /// [`Audit::invariant_holds`] being false rather than as a panic in an RPC handler.
    ///
    /// On an aggregating chain this reads a little high while proving shares are unresolved:
    /// the bucketed excess of a not-yet-covered, not-yet-expired bundle is pool-side in this
    /// accounting until it seals or sweeps (see `fees_paid`), so the number includes it. The
    /// audit's *total* is exact at every height either way.
    pub fn pool_value(&self) -> u64 {
        self.genesis_deposited
            .saturating_add(self.faucet_minted)
            .saturating_add(self.withdraw_deposited)
            .saturating_add(self.subsidised)
            .saturating_sub(self.fees_paid)
            .saturating_sub(self.burned)
    }

    /// Everything this chain has ever issued: what genesis created, plus the faucet and the
    /// aggregation subsidy. A withdraw is not issuance — it moves value the register already
    /// held back into the pool — and neither is a fee or a burn, which move value the other way.
    pub fn issued(&self) -> u64 {
        self.genesis_deposited
            .saturating_add(self.genesis_staked)
            .saturating_add(self.faucet_minted)
            .saturating_add(self.subsidised)
    }
}

/// What the register holds in the clear: bonded stake, unbonding amounts and unpaid rewards.
pub fn register_total(register: &BTreeMap<Address, ValidatorEntry>) -> u64 {
    register.values().fold(0u64, |acc, e| {
        let pending: u64 = e.pending.iter().fold(0u64, |a, (_, amount)| a.saturating_add(*amount));
        acc.saturating_add(e.stake).saturating_add(pending).saturating_add(e.rewards)
    })
}

/// The aggregator register's half of the register total (block aggregation, spec §5.3): the
/// outstanding bonds. Deliberately a separate function from [`register_total`] — the validator
/// register's shape is unchanged by the new register, and callers that predate it keep their
/// answer.
pub fn aggregators_total(aggregators: &BTreeMap<Address, super::aggregation::AggregatorEntry>) -> u64 {
    aggregators.values().fold(0u64, |acc, e| acc.saturating_add(e.bond))
}

/// The answer `rand_getSupply` gives: the counters, the two halves they add up to, and
/// whether the two halves still account for everything the chain issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Audit {
    pub supply: Supply,
    pub pool_value: u64,
    pub register_total: u64,
    /// Σ of the registration fees burned under `tokens.burn_registration_fee` (audit v5,
    /// TOK-2; `Ledger::registration_fees_burned`). Inside `burned` on the pool side and in no
    /// register entry: destroyed issuance, on the right of the identity beside `slashed`. Kept
    /// off [`Supply`] so chain 14's stored blob keeps its layout; 0 without the gate.
    pub registration_fees_burned: u64,
    /// Σ of the `BUNDLE_BASE`s burned under `fees.burn_base` — each bundle's whole floor under
    /// `fees.burn_floor` (`docs/fees.md` §1.3;
    /// `Ledger::base_fees_burned`). `registration_fees_burned`'s sibling: inside `burned` on the
    /// pool side, in no register entry, on the right of the identity, kept off [`Supply`] for the
    /// same layout reason; 0 without the flag.
    pub base_fees_burned: u64,
    /// Genesis vesting (spec §7), all 0 without a `vesting` section and kept off [`Supply`] for
    /// the same layout reason: what genesis issued into the vesting register (issuance, like
    /// `genesis_staked`) …
    pub vesting_issued: u64,
    /// … what claims and revokes have put into the pool as notes, net of their bases (value
    /// entering the pool, like `withdraw_deposited`) …
    pub vesting_released: u64,
    /// … and what the vesting register itself still holds (RAND bonded from it is in the
    /// validator register's `stake`, so inside `register_total`).
    pub vesting_in_register: u64,
    /// RPL-2, both 0 without a `program_state` section and kept off [`Supply`] for the same
    /// layout reason: RAND that `Invoke`s have paid out of program vaults as notes (value
    /// entering the pool, like `withdraw_deposited`) …
    pub program_rand_out: u64,
    /// … and what the vaults still hold. It got there through a bundle's `burn_r`, so it is
    /// already inside [`Supply::burned`] on the pool side; this is its register-side twin.
    pub program_rand_held: u64,
    /// RPL-3, both 0 without a `perps` section and kept off [`Supply`] for the same layout
    /// reason — [`Self::program_rand_out`]'s and [`Self::program_rand_held`]'s twins for the
    /// exchange: RAND that state proofs have paid out of it as withdrawal notes (value entering
    /// the pool) …
    pub perps_rand_out: u64,
    /// … and what the exchange still holds: every RAND `PerpDeposit`'s `burn_r` (inside
    /// [`Supply::burned`] on the pool side) less what was paid out.
    pub perps_rand_held: u64,
}

impl Audit {
    pub fn new(supply: Supply, register_total: u64, registration_fees_burned: u64) -> Audit {
        Audit {
            supply,
            pool_value: supply.pool_value(),
            register_total,
            registration_fees_burned,
            base_fees_burned: 0,
            vesting_issued: 0,
            vesting_released: 0,
            vesting_in_register: 0,
            program_rand_out: 0,
            program_rand_held: 0,
            perps_rand_out: 0,
            perps_rand_held: 0,
        }
    }

    /// The same audit with the bases burned under `fees.burn_base` on the right of its identity.
    /// A builder rather than a fourth `new` argument, so every caller from before the flag keeps
    /// its call as it was.
    pub fn with_base_fees_burned(self, base_fees_burned: u64) -> Audit {
        Audit { base_fees_burned, ..self }
    }

    /// The same audit with the program vaults' RAND in it: `rand_in` is every `burn_r` an
    /// `Invoke` deposited, `rand_out` every RAND note a vault paid.
    pub fn with_program_vaults(self, rand_in: u64, rand_out: u64) -> Audit {
        Audit {
            pool_value: self.pool_value.saturating_add(rand_out),
            program_rand_out: rand_out,
            program_rand_held: rand_in.saturating_sub(rand_out),
            ..self
        }
    }

    /// The same audit with the perps exchange's RAND in it (RPL-3): `rand_in` is every RAND
    /// `PerpDeposit`'s `burn_r`, `rand_out` every RAND withdrawal a state proof paid. Composes
    /// with [`Self::with_program_vaults`] (each adds its own `rand_out` to the pool); like it,
    /// it must come after [`Self::with_vesting`], which recomputes the pool from the counters.
    pub fn with_perps(self, rand_in: u64, rand_out: u64) -> Audit {
        Audit {
            pool_value: self.pool_value.saturating_add(rand_out),
            perps_rand_out: rand_out,
            perps_rand_held: rand_in.saturating_sub(rand_out),
            ..self
        }
    }

    /// The same audit with the vesting register's three numbers in it.
    pub fn with_vesting(self, issued: u64, released: u64, in_register: u64) -> Audit {
        Audit {
            pool_value: self.supply.pool_value().saturating_add(released),
            vesting_issued: issued,
            vesting_released: released,
            vesting_in_register: in_register,
            ..self
        }
    }

    /// What was issued: [`Supply::issued`] plus the vesting register's genesis issuance.
    pub fn issued(&self) -> u64 {
        self.supply.issued().saturating_add(self.vesting_issued)
    }

    pub fn total_supply(&self) -> u64 {
        self.pool_value
            .saturating_add(self.register_total)
            .saturating_add(self.vesting_in_register)
            .saturating_add(self.program_rand_held)
            .saturating_add(self.perps_rand_held)
    }

    /// Everything the chain issued is either in the pool or in the register, less what was
    /// destroyed: a slashed bond, a registration fee burned under the TOK-2 gate, or a bundle base
    /// burned under `fees.burn_base`. A false here is a consensus bug or a damaged counter, never
    /// a legitimate chain state.
    pub fn invariant_holds(&self) -> bool {
        self.total_supply()
            == self
                .issued()
                .saturating_sub(self.supply.slashed)
                .saturating_sub(self.registration_fees_burned)
                .saturating_sub(self.base_fees_burned)
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
            activation_epoch: 0,
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
        let audit = Audit::new(s, register_total(&register), 0);
        assert_eq!(audit.total_supply(), 1_550);
        assert!(!audit.invariant_holds(), "230 + 50 + 20 does not account for the 70 withdrawn");
        let audit = Audit::new(s, 250, 0);
        assert!(audit.invariant_holds());
        // A registration fee burned under the gate (audit v5, TOK-2) is inside `burned` and in
        // no register entry: it balances only on the right, beside a slashed bond.
        let destroyed = Supply { burned: 300 + 40, ..s };
        assert!(!Audit::new(destroyed, 250, 0).invariant_holds(), "40 left the pool and went nowhere");
        assert!(Audit::new(destroyed, 250, 40).invariant_holds());
    }

    #[test]
    fn a_counter_that_cannot_be_right_saturates_instead_of_wrapping() {
        // Fees only ever leave a pool something was deposited into, so this cannot arise on a
        // chain whose blocks all applied. If a damaged counter ever produced it, the pool reads
        // as empty rather than as `u64::MAX`.
        let s = Supply { fees_paid: 5, ..Default::default() };
        assert_eq!(s.pool_value(), 0);
        assert_eq!(Audit::new(s, 0, 0).total_supply(), 0);
    }

    /// Genesis vesting (spec §7): a claim moves value from the vesting register into the pool
    /// (and its base into a proposer's rewards), a bond from the lock moves it into a validator's
    /// stake — neither creates nor destroys any, and the identity holds through both.
    #[test]
    fn the_vesting_register_is_the_third_half_of_the_identity() {
        let s = Supply { genesis_deposited: 1_000, genesis_staked: 4_000, ..Supply::default() };
        // Genesis: 600 vesting, nothing released.
        let a = Audit::new(s, 4_000, 0).with_vesting(600, 0, 600);
        assert_eq!((a.issued(), a.total_supply()), (5_600, 5_600));
        assert!(a.invariant_holds());
        // A claim of 100 gross: a 99 note, 1 base to a proposer's rewards.
        let a = Audit::new(s, 4_001, 0).with_vesting(600, 99, 500);
        assert!(a.invariant_holds());
        assert_eq!(a.pool_value, 1_099);
        // 200 bonded from the lock: out of the vesting register, into a validator's stake.
        let a = Audit::new(s, 4_201, 0).with_vesting(600, 99, 300);
        assert!(a.invariant_holds());
        // Counting the claim twice — or not at all — breaks it.
        assert!(!Audit::new(s, 4_001, 0).with_vesting(600, 99, 600).invariant_holds());
        assert!(!Audit::new(s, 4_001, 0).with_vesting(600, 0, 500).invariant_holds());
    }
}
