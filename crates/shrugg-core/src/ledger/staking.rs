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
fn unsupported(action: &Action) -> Result<(), TxError> {
    match action {
        Action::Bond { .. } => Err(TxError::UnsupportedAction("bond is not available until phase S2")),
        Action::Unbond { .. } => Err(TxError::UnsupportedAction("unbond is not available until phase S2")),
        Action::Withdraw { .. } => Err(TxError::UnsupportedAction("withdraw is not available until phase S2")),
        _ => Ok(()),
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
