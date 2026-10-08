//! The genesis `fees` section: the fee-feedback rules (`docs/fees.md` §1.3, plan
//! `docs/superpowers/plans/2026-10-05-fee-feedback.md`).
//!
//! Three genesis-gated consensus rules, each off by default and each following the pattern of
//! `tokens.burn_registration_fee` (audit v5, TOK-2) exactly: absent — or present and `false` —
//! the chain is byte for byte what it was (genesis hash, state root, stored values, RPC values);
//! `true`, the rule applies from block 1.
//!
//! - `burn_base`: every bundle's [`crate::gas::BUNDLE_BASE`] is destroyed instead of paid to the
//!   proposer (`Ledger::apply_tx_with`'s fee split). The proposer keeps the rest of the fee — the
//!   tip — on a chain without aggregation, and nothing at inclusion on one with it, where the
//!   excess is bucketed for the aggregator exactly as before. Only the base burns: it is the one
//!   component every bundle pays and no proposer can steer, while a Call's gas and byte terms and
//!   a Deploy's per-word term stay the proposer's, so including priced work stays worth its while.
//!   Burning the whole floor is the third flag's rule, below.
//! - `burn_floor` (issue #135; needs `burn_base`, `GenesisError::BurnFloorWithoutBurnBase`): the
//!   full EIP-1559 form — the whole of the ledger's own floor for the bundle is destroyed, not only
//!   its base ([`crate::ledger::Ledger::settled_floor`]: `BUNDLE_BASE` for a transfer, base plus
//!   per-word for a Deploy, the tier-exact floor `validate_inner` held a Call to after decoding).
//!   A proposer then gains nothing from a block that lifts a price, which is what the burn is for;
//!   it keeps only the tip above the floor.
//! - `subsidy_net_of_fees`: an aggregate's subsidy is paid out of its covered proving shares
//!   first and minted only for the shortfall. It needs an `aggregation` section
//!   (`GenesisError::SubsidyNetOfFeesWithoutAggregation`).
//! - `proposer_share_bps` (`docs/compute-optimization.md` §6.2; needs `aggregation`,
//!   `GenesisError::ProposerShareWithoutAggregation`, and at most 10 000,
//!   `GenesisError::ProposerShareOutOfRange`): the proposer/aggregator split of the base. Of the
//!   base the proposer keeps at inclusion today (`BUNDLE_BASE`, or nothing under `burn_base`,
//!   where the base is burned and there is no share to split) it keeps `proposer_share_bps /
//!   10 000`; the rest is bucketed beside the excess, so a covering aggregate is paid it as
//!   proving share and an uncovered bundle's sweep pays it back to the proposer.
//! - `prove_base` (`docs/compute-optimization.md` §6.3; needs `aggregation`,
//!   `GenesisError::ProveBaseWithoutAggregation`): the aggregated lane's floor for the proving
//!   share. Every bundle's ledger floor rises by it ([`crate::ledger::Ledger::settled_floor`] and
//!   the pre-verify floor), and it is bucketed whole: proving share, never the proposer's at
//!   inclusion and never burned — `burn_floor` burns the floor *without* it.
//!
//! - `usd_subsidy` (needs `aggregation`, `GenesisError::UsdSubsidyWithoutAggregation`): the
//!   dollar-indexed sealing subsidy. While the ledger holds a fresh RAND/USD price — set by the
//!   validator set's vote, `Action::SetRandPrice` (`ledger::rand_price`), never a market oracle —
//!   an aggregate's schedule is `min(usd_micros_per_sealed_block · 10⁹ / price_micros,
//!   max_subsidy_per_block)` RAND units instead of `gas::subsidy(n)`; with no price, or a stale
//!   one, the RAND schedule. `subsidy_net_of_fees` nets either schedule the same way.
//!
//! A genesis parameter like `aggregation`: outside the state root and `Ledger`'s equality, set by
//! genesis, persisted by the node at genesis and restored from the genesis file on every restart.

use serde::{Deserialize, Serialize};

/// The genesis `fees` section. Every flag is an `Option<bool>` so a file that leaves one out
/// round-trips without it; [`FeesConfig::burn_base`], [`FeesConfig::subsidy_net_of_fees`] and
/// [`FeesConfig::burn_floor`] read `None` and `Some(false)` alike, as the genesis hash does.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeesConfig {
    /// Burn every bundle's `BUNDLE_BASE` instead of paying it to the proposer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_base: Option<bool>,
    /// Pay an aggregate's subsidy from its proving shares first, minting only the shortfall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsidy_net_of_fees: Option<bool>,
    /// Under `burn_base`, burn the bundle's whole settled floor rather than its base alone
    /// (issue #135). Meaningless without `burn_base`, so genesis refuses it alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_floor: Option<bool>,
    /// The proposer's part of the base it keeps at inclusion, in basis points (0..=10 000; the
    /// proposal's value is 4 000); the rest is bucketed as proving share. Aggregating chains only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposer_share_bps: Option<u32>,
    /// RAND units added to every bundle's floor and bucketed whole as proving share (the
    /// proposal's 0.0006 RAND is 600 000). Aggregating chains only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prove_base: Option<u64>,
    /// The dollar-indexed sealing subsidy (`docs/fees.md` §1.3): the schedule an aggregate is
    /// paid while a governance-set RAND/USD price is fresh. Aggregating chains only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd_subsidy: Option<UsdSubsidy>,
}

/// The genesis `fees.usd_subsidy` sub-section: the dollar target of one sealed block, the hard
/// cap in RAND units, how long a voted price stays usable, and optionally the price the chain
/// starts with. Every number but `initial_price_micros` is required and non-zero; a set
/// `initial_price_micros` is non-zero too (`Genesis::validate`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsdSubsidy {
    /// The target pay of one sealed block, in micro-dollars (10⁻⁶ USD).
    pub usd_micros_per_sealed_block: u64,
    /// The most RAND units one sealed block's schedule may be, whatever the price: the cap that
    /// binds when the price is low.
    pub max_subsidy_per_block: u64,
    /// A price set at height `h` is fresh at heights `h ..= h + price_max_age_blocks`; past that
    /// the schedule falls back to `gas::subsidy(n)`.
    pub price_max_age_blocks: u64,
    /// The RAND/USD price at genesis in micro-dollars per RAND (set at height 0, nonce 0); absent,
    /// the chain has no price until the first `SetRandPrice`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_price_micros: Option<u64>,
}

/// RAND units per RAND: the `10⁹` of the dollar conversion.
pub const UNITS_PER_RAND: u128 = 1_000_000_000;

impl UsdSubsidy {
    /// The dollar target converted at `price_micros` (micro-dollars per RAND), capped:
    /// `min(⌊usd_micros_per_sealed_block · 10⁹ / price_micros⌋, max_subsidy_per_block)`, in u128
    /// so the product cannot wrap; the quotient rounds down (floor). A zero price — which neither
    /// genesis nor `SetRandPrice` can produce — reads as the cap.
    pub fn amount_at(&self, price_micros: u64) -> u64 {
        if price_micros == 0 {
            return self.max_subsidy_per_block;
        }
        let units = u128::from(self.usd_micros_per_sealed_block).saturating_mul(UNITS_PER_RAND) / u128::from(price_micros);
        u64::try_from(units).unwrap_or(u64::MAX).min(self.max_subsidy_per_block)
    }
}

impl FeesConfig {
    /// Whether the burned-base rule is on: `true` only when the file says `true`.
    pub fn burn_base(&self) -> bool {
        self.burn_base == Some(true)
    }

    /// Whether the fee-first subsidy is on: `true` only when the file says `true`.
    pub fn subsidy_net_of_fees(&self) -> bool {
        self.subsidy_net_of_fees == Some(true)
    }

    /// Whether the full-floor burn is on: `true` only when the file says `true`. The ledger reads
    /// it only beside [`Self::burn_base`] — genesis refuses it alone, and a ledger handed it alone
    /// by a test burns nothing.
    pub fn burn_floor(&self) -> bool {
        self.burn_floor == Some(true)
    }

    /// The proposer/aggregator split of the base, when the file sets it (`Some(_)`, whatever
    /// the value: a set field is in the genesis hash). The ledger reads it only on an
    /// aggregating chain — genesis refuses it on any other.
    pub fn proposer_share_bps(&self) -> Option<u32> {
        self.proposer_share_bps
    }

    /// The proving-share floor, `0` when the file leaves it out. The ledger reads it only on an
    /// aggregating chain — genesis refuses it on any other.
    pub fn prove_base(&self) -> u64 {
        self.prove_base.unwrap_or(0)
    }

    /// The dollar-indexed subsidy, when the file sets it. The ledger reads it only on an
    /// aggregating chain — genesis refuses it on any other.
    pub fn usd_subsidy(&self) -> Option<&UsdSubsidy> {
        self.usd_subsidy.as_ref()
    }

    /// Whether any rule is on. A section with no true flag and neither numeric field set is the
    /// section's absence in every respect — the genesis hash, the ledger's behaviour and
    /// `rand_getLimits`' `fee_rules`.
    pub fn any(&self) -> bool {
        self.burn_base()
            || self.subsidy_net_of_fees()
            || self.burn_floor()
            || self.proposer_share_bps.is_some()
            || self.prove_base.is_some()
            || self.usd_subsidy.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flag_is_on_only_when_the_file_says_true() {
        assert!(!FeesConfig::default().any());
        let off = FeesConfig { burn_base: Some(false), subsidy_net_of_fees: Some(false), burn_floor: None, proposer_share_bps: None, prove_base: None, usd_subsidy: None };
        assert!(!off.burn_base() && !off.subsidy_net_of_fees() && !off.any());
        let on = FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: None, proposer_share_bps: None, prove_base: None, usd_subsidy: None };
        assert!(on.burn_base() && !on.subsidy_net_of_fees() && on.any());
        assert!(!on.burn_floor(), "an absent burn_floor is off");
        let floor = FeesConfig { burn_floor: Some(true), ..on };
        assert!(floor.burn_floor() && floor.any());
        assert!(!FeesConfig { burn_floor: Some(false), ..FeesConfig::default() }.any());
    }

    /// The fee split's two numeric fields: each is a rule once set (it hashes, and `fee_rules`
    /// serves it), absent reads as no split and a zero `prove_base`, and both round-trip.
    #[test]
    fn the_split_fields_are_rules_once_set_and_round_trip() {
        let none = FeesConfig::default();
        assert_eq!((none.proposer_share_bps(), none.prove_base()), (None, 0));
        let split = FeesConfig { proposer_share_bps: Some(4000), ..FeesConfig::default() };
        assert!(split.any() && split.proposer_share_bps() == Some(4000));
        let prove = FeesConfig { prove_base: Some(600_000), ..FeesConfig::default() };
        assert!(prove.any() && prove.prove_base() == 600_000);
        let both = FeesConfig { proposer_share_bps: Some(4000), prove_base: Some(600_000), ..FeesConfig::default() };
        let text = serde_json::to_string(&both).unwrap();
        assert_eq!(text, r#"{"proposer_share_bps":4000,"prove_base":600000}"#);
        assert_eq!(serde_json::from_str::<FeesConfig>(&text).unwrap(), both);
    }

    /// The dollar subsidy: a rule once set, round-trips as written, refuses unknown keys, and
    /// converts with floor rounding under its cap.
    #[test]
    fn the_usd_subsidy_round_trips_refuses_unknown_keys_and_converts_under_its_cap() {
        let usd = UsdSubsidy { usd_micros_per_sealed_block: 4_791, max_subsidy_per_block: 300_000_000, price_max_age_blocks: 72_000, initial_price_micros: Some(150_000) };
        let f = FeesConfig { usd_subsidy: Some(usd.clone()), ..FeesConfig::default() };
        assert!(f.any() && f.usd_subsidy() == Some(&usd));
        let text = serde_json::to_string(&f).unwrap();
        assert_eq!(text, r#"{"usd_subsidy":{"usd_micros_per_sealed_block":4791,"max_subsidy_per_block":300000000,"price_max_age_blocks":72000,"initial_price_micros":150000}}"#);
        assert_eq!(serde_json::from_str::<FeesConfig>(&text).unwrap(), f);
        let bare = r#"{"usd_subsidy":{"usd_micros_per_sealed_block":1,"max_subsidy_per_block":2,"price_max_age_blocks":3}}"#;
        assert_eq!(serde_json::from_str::<FeesConfig>(bare).unwrap().usd_subsidy.unwrap().initial_price_micros, None);
        assert!(serde_json::from_str::<FeesConfig>(r#"{"usd_subsidy":{"usd_micros_per_sealed_block":1,"max_subsidy_per_block":2,"price_max_age_blocks":3,"oracle":1}}"#).is_err());
        // $0.004791 a block at $0.15: ⌊4 791 · 10⁹ / 150 000⌋ = 31 940 000 units (0.03194 RAND).
        assert_eq!(usd.amount_at(150_000), 31_940_000);
        // Floor: 1 µ$ at 3 µ$/RAND is 333 333 333.3… units.
        let one = UsdSubsidy { usd_micros_per_sealed_block: 1, max_subsidy_per_block: u64::MAX, price_max_age_blocks: 1, initial_price_micros: None };
        assert_eq!(one.amount_at(3), 333_333_333);
        // At $0.01 the target is 0.4791 RAND, over the 0.3 RAND cap: the cap binds.
        assert_eq!(usd.amount_at(10_000), 300_000_000);
        // No overflow at the extremes: u64::MAX µ$ at 1 µ$/RAND saturates, then the cap.
        let max = UsdSubsidy { usd_micros_per_sealed_block: u64::MAX, max_subsidy_per_block: u64::MAX, price_max_age_blocks: 1, initial_price_micros: None };
        assert_eq!(max.amount_at(1), u64::MAX);
        assert_eq!(usd.amount_at(0), 300_000_000, "a zero price reads as the cap");
    }

    /// Unknown keys are refused: a misspelt consensus flag must not read as "off".
    #[test]
    fn an_unknown_key_is_refused() {
        assert!(serde_json::from_str::<FeesConfig>(r#"{"burn_bas": true}"#).is_err());
        assert_eq!(serde_json::to_string(&FeesConfig::default()).unwrap(), "{}");
    }
}
