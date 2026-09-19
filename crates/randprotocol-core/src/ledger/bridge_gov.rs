//! The bridge's Rand-only governance actions (bridge hardening spec §2, B1): `PauseMints` and
//! `UnpauseMints`.
//!
//! Neither moves value. A pause flips [`crate::bridge::BridgeState::mint_paused`] on — every
//! transfer `BridgeAttest` is then refused `MintsPaused` in `check_attest`, while burns and
//! rotations stay open — and an unpause flips it off. Both carry the bridge's `pause_nonce` and
//! bump it, so neither message can be replayed; each refuses the no-op (`AlreadyPaused`,
//! `NotPaused`) rather than spend a nonce for nothing.
//!
//! The asymmetry is the point: the one genesis `pause_key` can only pause (its message,
//! [`crate::bridge::gov::pause_message`], has no unpause twin it can sign), and lifting a pause
//! needs a PQ guardian quorum over [`crate::bridge::gov::unpause_message`], judged by exactly the
//! co-signature's five rules ([`crate::bridge::pq`]).
//!
//! Cheap before expensive, as everywhere in admission: the gate, the list's structure (no
//! signature work), the nonce and the flag, and the Dilithium2 verification last. Every refusal
//! [`apply`] could make is made in [`validate`], so `apply` is infallible on an admitted
//! transaction — and two of them in one block are safe because block application re-validates
//! each against the ledger the ones before it left (the second's nonce is stale).

use super::{Ledger, TxError};
use crate::bridge::gov::{pause_message, unpause_message};
use crate::bridge::pq::{check_pq_structure, verify_pq_message};
use crate::bridge::BridgeError;
use crate::types::{Action, Transaction};

/// What a mis-routed action gets: only a routing mistake in `Ledger::validate_inner` can produce
/// one, and refusing is the safe answer.
const NOT_BRIDGE_GOV: TxError = TxError::UnsupportedAction("bridge governance");

/// The action step of admission (spec §7 step 7) for the bridge's governance actions.
pub(super) fn validate(ledger: &Ledger, tx: &Transaction, action: &Action) -> Result<(), TxError> {
    let bridge = || ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled));
    match action {
        Action::PauseMints { nonce, signature } => {
            let bridge = bridge()?;
            let key = bridge.pause_key.as_ref().ok_or(TxError::Bridge(BridgeError::NoPauseKey))?;
            // The nonce first: a replayed pause is a replay whatever the flag now says.
            if *nonce != bridge.pause_nonce {
                return Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: bridge.pause_nonce, got: *nonce }));
            }
            if bridge.mint_paused {
                return Err(TxError::Bridge(BridgeError::AlreadyPaused));
            }
            // Last: one Dilithium2 verification, over the fixed-layout message for this chain.
            if !key.verify(&pause_message(tx.chain_id, *nonce), signature) {
                return Err(TxError::Bridge(BridgeError::BadPauseSignature));
            }
            Ok(())
        }
        Action::UnpauseMints { nonce, pq_signatures } => {
            let bridge = bridge()?;
            // The quorum's structure before anything that reads state or keys: count, index
            // order, index range, every length — the co-signature's rules 1-3.
            check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
            if *nonce != bridge.pause_nonce {
                return Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: bridge.pause_nonce, got: *nonce }));
            }
            if !bridge.mint_paused {
                return Err(TxError::Bridge(BridgeError::NotPaused));
            }
            // Rule 4 last: one verification per listed signature.
            verify_pq_message(pq_signatures, &bridge.pq_guardians, &unpause_message(tx.chain_id, *nonce))
                .map_err(TxError::Bridge)
        }
        _ => Err(NOT_BRIDGE_GOV),
    }
}

/// The apply step, in lockstep with [`validate`], which decided every refusal against this same
/// state.
pub(super) fn apply(ledger: &mut Ledger, _tx: &Transaction, action: &Action) -> Result<(), TxError> {
    match action {
        Action::PauseMints { .. } => {
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            bridge.mint_paused = true;
            bridge.pause_nonce = bridge.pause_nonce.saturating_add(1);
            Ok(())
        }
        Action::UnpauseMints { .. } => {
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            bridge.mint_paused = false;
            bridge.pause_nonce = bridge.pause_nonce.saturating_add(1);
            Ok(())
        }
        _ => Err(NOT_BRIDGE_GOV),
    }
}
