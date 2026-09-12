//! Staking rules for `Bond`, `Unbond` and `Withdraw` (phase S2).
//!
//! Scaffold only: the variants are on the wire and reach these functions, which refuse them.
//! S2's Task 1 replaces the stubs with the register (`ValidatorEntry` v2, `derive_set`, epochs,
//! checkable withdraw notes) without touching the action shapes or the dispatch in
//! [`super::Ledger::validate`].

use super::{Ledger, TxError};
use crate::confidential::ConfidentialExecutor;
use crate::types::{Action, Transaction};

/// Why each staking action is refused today. One place, so `validate` and `apply` can never
/// disagree about which variants this module owns.
///
/// The catch-all fails closed: an action this module does not own can only arrive through a
/// routing mistake in [`super::Ledger::validate_inner`], and refusing it is the safe answer
/// even if that never happens. `Ok(())` here would let a mis-routed action skip its own rules.
fn unsupported(action: &Action) -> Result<(), TxError> {
    match action {
        Action::Bond { .. } => Err(TxError::UnsupportedAction("bond is not available until phase S2")),
        Action::Unbond { .. } => Err(TxError::UnsupportedAction("unbond is not available until phase S2")),
        Action::Withdraw { .. } => Err(TxError::UnsupportedAction("withdraw is not available until phase S2")),
        _ => Err(TxError::UnsupportedAction("staking")),
    }
}

/// The action step of admission (spec §7 step 7) for the three staking actions.
pub(super) fn validate(
    _ledger: &Ledger,
    _tx: &Transaction,
    action: &Action,
    _executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    unsupported(action)
}

/// The apply step for the three staking actions. Unreachable while [`validate`] refuses them —
/// `apply_tx` validates first — and kept in lockstep with it so S2 fills both halves in one place.
pub(super) fn apply(
    _ledger: &mut Ledger,
    _tx: &Transaction,
    action: &Action,
    _executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    unsupported(action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::types::{Validator, ValidatorSet};

    fn ledger() -> Ledger {
        let k = Keypair::from_seed([1; 32]).unwrap();
        let set = ValidatorSet::new(vec![Validator { public_key: k.public_key().clone(), stake: 10 }]);
        Ledger::new(7, [11; 8], &set, &StubExecutor)
    }

    /// Fail closed: an action this module does not own is refused rather than waved through,
    /// and `validate` and `apply` answer alike. Only a dispatch bug can get here, which is
    /// exactly the case where `Ok(())` would silently skip the action's real rules.
    #[test]
    fn a_non_staking_action_routed_here_is_refused() {
        let mut l = ledger();
        let tx = Transaction { chain_id: 7, bundle: None, action: Action::None };
        for a in [Action::None, Action::Deploy { base_pc: 0, words: vec![0x13; 2] }] {
            assert_eq!(validate(&l, &tx, &a, &StubExecutor), Err(TxError::UnsupportedAction("staking")), "{a:?}");
            assert_eq!(apply(&mut l, &tx, &a, &StubExecutor), Err(TxError::UnsupportedAction("staking")), "{a:?}");
        }
    }
}
