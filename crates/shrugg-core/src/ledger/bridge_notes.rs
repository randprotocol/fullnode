//! The bridge as notes: `BridgeAttest` and `BridgeBurn` (phase S3).
//!
//! Scaffold only: the variants are on the wire and reach these functions, which refuse them.
//! S3's Task 2 fills them in — an attestation becomes a deposit note of the bridged asset, a
//! burn becomes a two-bundle admission — without changing the action shapes or the dispatch in
//! [`super::Ledger::validate`].

use super::{Ledger, TxError};
use crate::confidential::ConfidentialExecutor;
use crate::types::{Action, Transaction};

/// Why each bridge action is refused today. One place, so `validate` and `apply` can never
/// disagree about which variants this module owns.
fn unsupported(action: &Action) -> Result<(), TxError> {
    match action {
        Action::BridgeAttest { .. } => {
            Err(TxError::UnsupportedAction("bridge_attest is not available until phase S3"))
        }
        Action::BridgeBurn { .. } => Err(TxError::UnsupportedAction("bridge_burn is not available until phase S3")),
        _ => Ok(()),
    }
}

/// The action step of admission (spec §7 step 7) for the two bridge actions.
pub(super) fn validate(
    _ledger: &Ledger,
    _tx: &Transaction,
    action: &Action,
    _executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    unsupported(action)
}

/// The apply step for the two bridge actions. Unreachable while [`validate`] refuses them.
pub(super) fn apply(
    _ledger: &mut Ledger,
    _tx: &Transaction,
    action: &Action,
    _executor: &dyn ConfidentialExecutor,
) -> Result<(), TxError> {
    unsupported(action)
}
