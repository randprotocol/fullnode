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
///
/// The catch-all fails closed: an action this module does not own can only arrive through a
/// routing mistake in [`super::Ledger::validate_inner`], and refusing it is the safe answer
/// even if that never happens. `Ok(())` here would let a mis-routed action skip its own rules.
fn unsupported(action: &Action) -> Result<(), TxError> {
    match action {
        Action::BridgeAttest { .. } => {
            Err(TxError::UnsupportedAction("bridge_attest is not available until phase S3"))
        }
        Action::BridgeBurn { .. } => Err(TxError::UnsupportedAction("bridge_burn is not available until phase S3")),
        _ => Err(TxError::UnsupportedAction("bridge")),
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
///
/// When S3 fills this in, a `BridgeAttest` that deposits **asset 0** is value entering the
/// SHRUGG pool from outside and must be counted in `super::supply` — a counter of its own
/// beside `withdraw_deposited`, and part of `issued()`. A deposit of any other asset is not
/// SHRUGG and belongs in that asset's own audit, not this one.
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
    use crate::ledger::ValidatorEntry;

    fn ledger() -> Ledger {
        let k = Keypair::from_seed([1; 32]).unwrap();
        // Phase S2 gave the register its v2 entry; nothing here reads a field of it.
        let entry = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 10,
            pending: Vec::new(),
            rewards: 0,
            payout: crate::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
        };
        Ledger::new(7, [11; 8], [(k.address(), entry)].into_iter().collect(), &StubExecutor)
    }

    /// Fail closed: an action this module does not own is refused rather than waved through,
    /// and `validate` and `apply` answer alike. Only a dispatch bug can get here, which is
    /// exactly the case where `Ok(())` would silently skip the action's real rules.
    #[test]
    fn a_non_bridge_action_routed_here_is_refused() {
        let mut l = ledger();
        let tx = Transaction { chain_id: 7, bundle: None, action: Action::None };
        for a in [Action::None, Action::Bond { validator: crate::crypto::Address([1; 32]), amount: 1, registration: None }] {
            assert_eq!(validate(&l, &tx, &a, &StubExecutor), Err(TxError::UnsupportedAction("bridge")), "{a:?}");
            assert_eq!(apply(&mut l, &tx, &a, &StubExecutor), Err(TxError::UnsupportedAction("bridge")), "{a:?}");
        }
    }
}
