//! The genesis `fees` section: the fee-feedback rules (`docs/fees.md` §1.3, plan
//! `docs/superpowers/plans/2026-10-05-fee-feedback.md`).
//!
//! Two genesis-gated consensus rules, each off by default and each following the pattern of
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
//!   Burning the whole floor is a follow-up, not this rule.
//! - `subsidy_net_of_fees`: an aggregate's subsidy is paid out of its covered proving shares
//!   first and minted only for the shortfall. It needs an `aggregation` section
//!   (`GenesisError::SubsidyNetOfFeesWithoutAggregation`).
//!
//! A genesis parameter like `aggregation`: outside the state root and `Ledger`'s equality, set by
//! genesis, persisted by the node at genesis and restored from the genesis file on every restart.

use serde::{Deserialize, Serialize};

/// The genesis `fees` section. Both flags are `Option<bool>` so a file that leaves one out
/// round-trips without it; [`FeesConfig::burn_base`] and [`FeesConfig::subsidy_net_of_fees`]
/// read `None` and `Some(false)` alike, as the genesis hash does.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeesConfig {
    /// Burn every bundle's `BUNDLE_BASE` instead of paying it to the proposer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_base: Option<bool>,
    /// Pay an aggregate's subsidy from its proving shares first, minting only the shortfall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsidy_net_of_fees: Option<bool>,
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

    /// Whether any rule is on. A section with no true flag is the section's absence in every
    /// respect — the genesis hash, the ledger's behaviour and `rand_getLimits`' `fee_rules`.
    pub fn any(&self) -> bool {
        self.burn_base() || self.subsidy_net_of_fees()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flag_is_on_only_when_the_file_says_true() {
        assert!(!FeesConfig::default().any());
        let off = FeesConfig { burn_base: Some(false), subsidy_net_of_fees: Some(false) };
        assert!(!off.burn_base() && !off.subsidy_net_of_fees() && !off.any());
        let on = FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None };
        assert!(on.burn_base() && !on.subsidy_net_of_fees() && on.any());
    }

    /// Unknown keys are refused: a misspelt consensus flag must not read as "off".
    #[test]
    fn an_unknown_key_is_refused() {
        assert!(serde_json::from_str::<FeesConfig>(r#"{"burn_bas": true}"#).is_err());
        assert_eq!(serde_json::to_string(&FeesConfig::default()).unwrap(), "{}");
    }
}
