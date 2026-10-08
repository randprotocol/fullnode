//! The bridge's Rand-only governance actions: B1's `PauseMints` and `UnpauseMints` (bridge
//! hardening spec §2) and B4's `RegisterBridgedToken` and `ListBacking` (spec §7) — the actions
//! the pause key or a PQ guardian quorum authorises without an attestation.
//!
//! **B1, the brake.** Neither action moves value. A pause flips
//! [`crate::bridge::BridgeState::mint_paused`] on — every transfer `BridgeAttest` is then refused
//! `MintsPaused` in `check_attest`, while burns and rotations stay open — and an unpause flips it
//! off. Both carry the bridge's `pause_nonce` and bump it, so neither message can be replayed;
//! each refuses the no-op (`AlreadyPaused`, `NotPaused`) rather than spend a nonce for nothing.
//! The asymmetry is the point: the one genesis `pause_key` can only pause (its message,
//! [`crate::bridge::gov::pause_message`], has no unpause twin it can sign), and lifting a pause
//! needs a PQ guardian quorum over [`crate::bridge::gov::unpause_message`], judged by exactly the
//! co-signature's five rules ([`crate::bridge::pq`]).
//!
//! **B4, listing after genesis.** A `RegisterBridgedToken` registers a `Bridge`-authority token at
//! the registry's next index (eight decimals on Rand, the genesis `mint_cap_per_day`) with its
//! first backing; a `ListBacking` adds a backing to one. Both carry `list_nonce` and bump it, both
//! pass the checks a genesis listing does (a registered emitter for the chain, a pair that backs
//! nothing yet, at most [`super::tokens::MAX_BACKINGS`] backings, source decimals ≤ 18, the
//! name/symbol rules), and both ride a RAND fee bundle their submitter pays — a registration owing
//! the registry's `registration_fee` on top of the base. The quorum is the authority, not the
//! payer. **List on Rand first, `setToken` on the endpoint second** (spec §7).
//!
//! **Bridge rules v2 (audit v4 BRG-14 / BR-4), gated on the genesis `bridge.rules_v2`.**
//! `RotatePqGuardians` replaces the whole PQ set and `RotatePauseKey` the pause key, each under a
//! PQ quorum of the *current* set over [`crate::bridge::gov::rotate_pq_message`] /
//! [`crate::bridge::gov::rotate_pause_message`] at the bridge's `rotation_nonce`, which both
//! spend. The new PQ set is held to the genesis rules — index-aligned with the current ECDSA set,
//! Dilithium2 keys, no duplicates, not the pause key — and the new pause key to its own (a
//! Dilithium2 key that is no guardian's). Bundle-less and fee-less like the pause. On a chain
//! without the section (chain 14) both are [`BridgeError::RulesV2Disabled`] before anything else
//! is read, so an old node's refusal of the unknown wire variant and a new node's refusal of the
//! action agree. Under the same gate a `RegisterBridgedToken` or `ListBacking` is refused
//! [`BridgeError::MintsPaused`] while minting is paused — after the nonce, before the quorum.
//!
//! Cheap before expensive, as everywhere in admission: the gate, the byte rules and the quorum's
//! structure (no signature work), the nonce and the state lookups, and the Dilithium2
//! verification last. Every refusal [`apply`] could make is made in [`validate`], so `apply` is
//! infallible on an admitted transaction — and two of them in one block are safe because block
//! application re-validates each against the ledger the ones before it left (the second's nonce
//! is stale).

use super::tokens::{
    bridged_asset_id, check_metadata, Backing, MintAuthority, TokenError, BRIDGE_DECIMALS,
    MAX_BACKING_DECIMALS,
};
use super::{Ledger, TxError};
use crate::bridge::gov::{
    cancel_rotation_message_in, list_message_in, pause_message_in, register_message_in, rotate_pause_message_in,
    rotate_pq_message_in, unpause_message_in,
};
use crate::bridge::{PendingPauseRotation, PendingPqRotation, RotationKind};
use crate::crypto::{PublicKey, Signature};
use crate::bridge::pq::{check_pq_structure, verify_pq_message};
use crate::bridge::{BridgeError, BridgeState};
use crate::gas;
use crate::types::{Action, Transaction};

/// A registry refusal, reported the way the bridge's other registry verdicts are: through
/// [`BridgeError::Token`], since the action that hit it is the bridge's.
fn token(e: TokenError) -> TxError {
    TxError::Bridge(BridgeError::Token(e))
}

/// The two listing actions' shared state rules: the nonce, then — under bridge rules v2 — no
/// listing while minting is paused, then a registered emitter for the backing's chain.
fn check_listing(bridge: &BridgeState, nonce: u64, chain: u16) -> Result<(), TxError> {
    if nonce != bridge.list_nonce {
        return Err(TxError::Bridge(BridgeError::BadListNonce { expected: bridge.list_nonce, got: nonce }));
    }
    // Bridge rules v2 only: chain 14's ledger must keep accepting what it accepts today.
    if bridge.rules_v2.is_some() && bridge.mint_paused {
        return Err(TxError::Bridge(BridgeError::MintsPaused));
    }
    if !bridge.emitters.contains_key(&chain) {
        return Err(TxError::Bridge(BridgeError::NoEmitter { chain }));
    }
    Ok(())
}

/// Spends one `rotation_nonce`: the last write of both rotations.
fn bump_rotation_nonce(bridge: &mut BridgeState) {
    bridge.rotation_nonce = bridge.rotation_nonce.saturating_add(1);
}

// ── BRG-14 (audit v6, issue #89): possession, the delay and the cancel ───────────────────────

/// The possession gate, a genesis constant read before the quorum's structure: under
/// `bridge.rotation.needs_possession` a rotation must be the `…V2` action (`carries` is true);
/// without it — no `bridge.rotation` at all, or one without the rule — the v1 action is the one
/// this chain admits.
fn check_possession_gate(bridge: &BridgeState, carries: bool) -> Result<(), TxError> {
    let required = bridge.rotation_rules.as_ref().is_some_and(|r| r.needs_possession());
    match (required, carries) {
        (true, false) => Err(TxError::Bridge(BridgeError::PossessionRequired)),
        (false, true) => Err(TxError::Bridge(BridgeError::PossessionNotEnabled)),
        _ => Ok(()),
    }
}

/// One rotation of each kind at a time under the delay: a second while one is pending is refused
/// until it takes effect or is cancelled.
fn check_nothing_pending(bridge: &BridgeState, kind: RotationKind) -> Result<(), TxError> {
    let pending = match kind {
        RotationKind::PqGuardians => bridge.pending_pq.as_ref().map(|p| p.effective_at_secs),
        RotationKind::PauseKey => bridge.pending_pause.as_ref().map(|p| p.effective_at_secs),
    };
    match pending {
        Some(effective_at_secs) => Err(TxError::Bridge(BridgeError::RotationPending { effective_at_secs })),
        None => Ok(()),
    }
}

/// The byte rules of a possession list, before any key is read: one signature per new key, each
/// exactly a Dilithium2 signature's length.
fn check_possession_shape(possession: &[Vec<u8>], keys: usize) -> Result<(), TxError> {
    if possession.len() != keys {
        return Err(TxError::Bridge(BridgeError::PossessionCountMismatch { expected: keys, got: possession.len() }));
    }
    if let Some((index, p)) = possession.iter().enumerate().find(|(_, p)| p.len() != crate::bridge::PQ_SIGNATURE_LEN) {
        return Err(TxError::Bridge(BridgeError::BadPossessionLength { index, len: p.len() }));
    }
    Ok(())
}

/// Every possession signature verifies `message` under its own new key: the holder of each key
/// signed the rotation that brings it in. Last — one Dilithium2 verify per new key.
fn verify_possession(keys: &[PublicKey], possession: &[Vec<u8>], message: &[u8]) -> Result<(), TxError> {
    for (index, (key, sig)) in keys.iter().zip(possession).enumerate() {
        let ok = Signature::from_bytes(sig).is_ok_and(|sig| key.verify(message, &sig));
        if !ok {
            return Err(TxError::Bridge(BridgeError::BadPossession { index }));
        }
    }
    Ok(())
}

/// The whole of a PQ-set rotation's validation, v1 and v2 (`possession` is `Some` for the V2
/// action): the gates, the quorum's structure, the nonce, nothing pending of this kind, the new
/// set's shape, then the quorum's verifies and, last, the possession verifies.
fn validate_pq_rotation(
    ledger: &Ledger,
    bridge: &BridgeState,
    tx: &Transaction,
    new_pq_guardians: &[PublicKey],
    nonce: u64,
    pq_signatures: &[crate::bridge::PqSignature],
    possession: Option<&[Vec<u8>]>,
) -> Result<(), TxError> {
    if bridge.rules_v2.is_none() {
        return Err(TxError::Bridge(BridgeError::RulesV2Disabled));
    }
    check_possession_gate(bridge, possession.is_some())?;
    check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
    if let Some(p) = possession {
        check_possession_shape(p, new_pq_guardians.len())?;
    }
    if nonce != bridge.rotation_nonce {
        return Err(TxError::Bridge(BridgeError::BadRotationNonce { expected: bridge.rotation_nonce, got: nonce }));
    }
    check_nothing_pending(bridge, RotationKind::PqGuardians)?;
    // The new set's shape, the genesis rules over again (`genesis::check_bridge`): one
    // PQ key per guardian of the current ECDSA set, each exactly a Dilithium2 key, none
    // repeated, and the pause key held apart. Byte rules and set lookups, before the quorum.
    let expected = bridge.guardian_sets.get(&bridge.current_set).map_or(0, |s| s.keys.len());
    if new_pq_guardians.len() != expected {
        return Err(TxError::Bridge(BridgeError::PqSetLengthMismatch { expected, got: new_pq_guardians.len() }));
    }
    if let Some((index, k)) = new_pq_guardians.iter().enumerate().find(|(_, k)| k.as_bytes().len() != crate::bridge::PQ_PUBLIC_KEY_LEN) {
        return Err(TxError::Bridge(BridgeError::BadPqGuardianKey { index, len: k.as_bytes().len() }));
    }
    let unique: std::collections::BTreeSet<&[u8]> = new_pq_guardians.iter().map(|k| k.as_bytes()).collect();
    if unique.len() != new_pq_guardians.len() {
        return Err(TxError::Bridge(BridgeError::DuplicatePqGuardian));
    }
    if bridge.pause_key.as_ref().is_some_and(|p| new_pq_guardians.contains(p)) {
        return Err(TxError::Bridge(BridgeError::GuardianIsPauseKey));
    }
    // The current set's quorum over the fixed-layout message, then each new holder's own
    // signature over the very same message.
    let message = rotate_pq_message_in(ledger.binding_domain(), tx.chain_id, nonce, new_pq_guardians);
    verify_pq_message(pq_signatures, &bridge.pq_guardians, &message).map_err(TxError::Bridge)?;
    if let Some(p) = possession {
        verify_possession(new_pq_guardians, p, &message)?;
    }
    Ok(())
}

/// [`validate_pq_rotation`]'s twin for the pause key.
fn validate_pause_rotation(
    ledger: &Ledger,
    bridge: &BridgeState,
    tx: &Transaction,
    new_pause_key: &PublicKey,
    nonce: u64,
    pq_signatures: &[crate::bridge::PqSignature],
    possession: Option<&[u8]>,
) -> Result<(), TxError> {
    if bridge.rules_v2.is_none() {
        return Err(TxError::Bridge(BridgeError::RulesV2Disabled));
    }
    check_possession_gate(bridge, possession.is_some())?;
    check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
    let possession = possession.map(|p| vec![p.to_vec()]);
    if let Some(p) = &possession {
        check_possession_shape(p, 1)?;
    }
    if nonce != bridge.rotation_nonce {
        return Err(TxError::Bridge(BridgeError::BadRotationNonce { expected: bridge.rotation_nonce, got: nonce }));
    }
    check_nothing_pending(bridge, RotationKind::PauseKey)?;
    let len = new_pause_key.as_bytes().len();
    if len != crate::bridge::PQ_PUBLIC_KEY_LEN {
        return Err(TxError::Bridge(BridgeError::BadPauseKeyLength { len }));
    }
    if bridge.pq_guardians.contains(new_pause_key) {
        return Err(TxError::Bridge(BridgeError::PauseKeyIsGuardian));
    }
    let message = rotate_pause_message_in(ledger.binding_domain(), tx.chain_id, nonce, new_pause_key);
    verify_pq_message(pq_signatures, &bridge.pq_guardians, &message).map_err(TxError::Bridge)?;
    if let Some(p) = &possession {
        verify_possession(std::slice::from_ref(new_pause_key), p, &message)?;
    }
    Ok(())
}

/// The apply step of a PQ-set rotation: under `bridge.rotation.delay_secs` it is recorded as
/// pending, effective at this block's time plus the delay (`BridgeState::activate_due_rotations`
/// replaces the set then, and spends the nonce then); otherwise the set is replaced now. Either
/// way this transaction spends one `rotation_nonce`.
fn apply_pq_rotation(ledger: &mut Ledger, new_pq_guardians: &[PublicKey]) -> Result<(), TxError> {
    let now = ledger.now_secs();
    let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
    // The second lock on the gate: `validate` refused a chain without the section, and a
    // direct caller must not move a counter chain 14 has no root for.
    if bridge.rules_v2.is_none() {
        return Err(TxError::Bridge(BridgeError::RulesV2Disabled));
    }
    match bridge.rotation_rules.as_ref().map(|r| r.delay_secs()).filter(|d| *d > 0) {
        Some(delay) => {
            bridge.pending_pq = Some(PendingPqRotation { keys: new_pq_guardians.to_vec(), effective_at_secs: now.saturating_add(delay) })
        }
        None => bridge.pq_guardians = new_pq_guardians.to_vec(),
    }
    bump_rotation_nonce(bridge);
    Ok(())
}

/// [`apply_pq_rotation`]'s twin for the pause key.
fn apply_pause_rotation(ledger: &mut Ledger, new_pause_key: &PublicKey) -> Result<(), TxError> {
    let now = ledger.now_secs();
    let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
    if bridge.rules_v2.is_none() {
        return Err(TxError::Bridge(BridgeError::RulesV2Disabled));
    }
    match bridge.rotation_rules.as_ref().map(|r| r.delay_secs()).filter(|d| *d > 0) {
        Some(delay) => {
            bridge.pending_pause = Some(PendingPauseRotation { key: new_pause_key.clone(), effective_at_secs: now.saturating_add(delay) })
        }
        None => bridge.pause_key = Some(new_pause_key.clone()),
    }
    bump_rotation_nonce(bridge);
    Ok(())
}

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
            if !key.verify(&pause_message_in(ledger.binding_domain(), tx.chain_id, *nonce), signature) {
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
            verify_pq_message(pq_signatures, &bridge.pq_guardians, &unpause_message_in(ledger.binding_domain(), tx.chain_id, *nonce))
                .map_err(TxError::Bridge)
        }
        Action::RegisterBridgedToken { name, symbol, salt, chain, token: coin, decimals, nonce, pq_signatures } => {
            let bridge = bridge()?;
            let registry = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
            // The bytes first: the registry's name/symbol rules at a bridged token's eight
            // decimals, the backing's source decimals, the quorum's structure.
            check_metadata(name, symbol, BRIDGE_DECIMALS).map_err(token)?;
            if *decimals > MAX_BACKING_DECIMALS {
                return Err(token(TokenError::BadBackingDecimals(*decimals)));
            }
            check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
            // The state lookups: the nonce, the chain's emitter, the pair, the identity, room.
            check_listing(bridge, *nonce, *chain)?;
            if registry.bridged(*chain, coin).is_some() {
                return Err(token(TokenError::BackingTaken { chain: *chain }));
            }
            let id = bridged_asset_id(name, symbol, salt);
            if registry.get_by_id(&id).is_some() {
                return Err(token(TokenError::AlreadyRegistered(id)));
            }
            if registry.is_full() {
                return Err(token(TokenError::RegistryFull));
            }
            // The fee: the base `fee_floor` took at step 3, plus the registry's registration fee —
            // what any registration owes, whoever authorises it. Saturating, as `RegisterToken`'s.
            let min = gas::BUNDLE_BASE.saturating_add(registry.registration_fee).saturating_add(ledger.prove_base());
            if tx.fee() < min {
                return Err(token(TokenError::RegistrationFeeTooLow { min, fee: tx.fee() }));
            }
            // Last: the quorum's Dilithium2 verifications over the fixed-layout message.
            let message = register_message_in(ledger.binding_domain(), tx.chain_id, *nonce, name, symbol, salt, *chain, coin, *decimals)
                .expect("check_metadata bounds the name and the symbol well under 255 bytes");
            verify_pq_message(pq_signatures, &bridge.pq_guardians, &message).map_err(TxError::Bridge)
        }
        Action::ListBacking { token_index, chain, token: coin, decimals, nonce, pq_signatures } => {
            let bridge = bridge()?;
            let registry = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
            if *decimals > MAX_BACKING_DECIMALS {
                return Err(token(TokenError::BadBackingDecimals(*decimals)));
            }
            check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
            check_listing(bridge, *nonce, *chain)?;
            // Everything `add_backing` would refuse: the pair free, the token registered and
            // bridged, under the cap on backings. The fee is the plain base, taken at step 3.
            registry.check_add_backing(*token_index, *chain, coin, *decimals).map_err(token)?;
            verify_pq_message(
                pq_signatures,
                &bridge.pq_guardians,
                &list_message_in(ledger.binding_domain(), tx.chain_id, *nonce, *token_index, *chain, coin, *decimals),
            )
            .map_err(TxError::Bridge)
        }
        Action::RotatePqGuardians { new_pq_guardians, nonce, pq_signatures } => {
            validate_pq_rotation(ledger, bridge()?, tx, new_pq_guardians, *nonce, pq_signatures, None)
        }
        Action::RotatePauseKey { new_pause_key, nonce, pq_signatures } => {
            validate_pause_rotation(ledger, bridge()?, tx, new_pause_key, *nonce, pq_signatures, None)
        }
        // BRG-14: the same rotations with each new key's own signature over the rotation message.
        Action::RotatePqGuardiansV2 { new_pq_guardians, possession, nonce, pq_signatures } => {
            validate_pq_rotation(ledger, bridge()?, tx, new_pq_guardians, *nonce, pq_signatures, Some(possession))
        }
        Action::RotatePauseKeyV2 { new_pause_key, possession, nonce, pq_signatures } => {
            validate_pause_rotation(ledger, bridge()?, tx, new_pause_key, *nonce, pq_signatures, Some(possession))
        }
        // BRG-14: the pause key drops a pending rotation. The gate (a genesis constant) and the
        // kind byte first, then the nonce and the pending lookup, then the one verify.
        Action::CancelRotation { kind, nonce, signature } => {
            let bridge = bridge()?;
            if bridge.rotation_rules.is_none() {
                return Err(TxError::Bridge(BridgeError::RotationRulesDisabled));
            }
            let kind = RotationKind::from_byte(*kind).ok_or(TxError::Bridge(BridgeError::BadRotationKind(*kind)))?;
            if *nonce != bridge.rotation_nonce {
                return Err(TxError::Bridge(BridgeError::BadRotationNonce { expected: bridge.rotation_nonce, got: *nonce }));
            }
            if check_nothing_pending(bridge, kind).is_ok() {
                return Err(TxError::Bridge(BridgeError::NoPendingRotation));
            }
            let key = bridge.pause_key.as_ref().ok_or(TxError::Bridge(BridgeError::NoPauseKey))?;
            if !key.verify(&cancel_rotation_message_in(ledger.binding_domain(), tx.chain_id, *nonce, kind), signature) {
                return Err(TxError::Bridge(BridgeError::BadCancelSignature));
            }
            Ok(())
        }
        _ => Err(NOT_BRIDGE_GOV),
    }
}

/// Spends one `list_nonce`: the last write of both listing actions.
fn bump_list_nonce(ledger: &mut Ledger) -> Result<(), TxError> {
    let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
    bridge.list_nonce = bridge.list_nonce.saturating_add(1);
    Ok(())
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
        Action::RegisterBridgedToken { name, symbol, salt, chain, token: coin, decimals, .. } => {
            let height = ledger.height();
            let registry = ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?;
            // The index `validate` checked room for, and the only place it is handed out;
            // `register` re-checks the metadata, the identity and the pair against this state.
            registry
                .register(
                    bridged_asset_id(name, symbol, salt),
                    name.clone(),
                    symbol.clone(),
                    BRIDGE_DECIMALS,
                    MintAuthority::Bridge { backings: vec![Backing::new(*chain, *coin, *decimals)] },
                    height,
                )
                .map_err(token)?;
            bump_list_nonce(ledger)
        }
        Action::ListBacking { token_index, chain, token: coin, decimals, .. } => {
            let registry = ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?;
            registry.add_backing(*token_index, *chain, *coin, *decimals).map_err(token)?;
            bump_list_nonce(ledger)
        }
        Action::RotatePqGuardians { new_pq_guardians, .. } | Action::RotatePqGuardiansV2 { new_pq_guardians, .. } => {
            apply_pq_rotation(ledger, new_pq_guardians)
        }
        Action::RotatePauseKey { new_pause_key, .. } | Action::RotatePauseKeyV2 { new_pause_key, .. } => {
            apply_pause_rotation(ledger, new_pause_key)
        }
        Action::CancelRotation { kind, .. } => {
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            if bridge.rotation_rules.is_none() {
                return Err(TxError::Bridge(BridgeError::RotationRulesDisabled));
            }
            match RotationKind::from_byte(*kind).ok_or(TxError::Bridge(BridgeError::BadRotationKind(*kind)))? {
                RotationKind::PqGuardians => bridge.pending_pq = None,
                RotationKind::PauseKey => bridge.pending_pause = None,
            }
            bump_rotation_nonce(bridge);
            Ok(())
        }
        _ => Err(NOT_BRIDGE_GOV),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::gov::{list_message, pause_message, register_message, rotate_pause_message, rotate_pq_message, unpause_message};
    use crate::bridge::pq::tests::{hex32, vector_keys, vector_sigs, vectors};
    use crate::bridge::{guardian_address, BridgeConfig, PqSignature};
    use crate::confidential::{ConfidentialExecutor, StubExecutor};
    use crate::crypto::{Keypair, PublicKey};
    use crate::ledger::tokens::TokenRegistry;
    use crate::ledger::{BlockError, ValidatorEntry};
    use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};

    const HC: Word8 = [11; 8];
    const CHAIN: u64 = 7;
    const FEE: u64 = 1_000_000_000;

    /// zUSD as chain 14 registers it (the bridge repo's `docs/mainnet-launch.md` §5): the name,
    /// the symbol, the salt `keccak256("rand-zusd-shielded-usd-chain-14")`, and its seven coins in
    /// their 32-byte wire forms with their source decimals — Ethereum USDT first (the
    /// registration's own backing), then the six `ListBacking`s in launch order.
    const NAME: &str = "Shielded USD";
    const SYMBOL: &str = "zUSD";
    fn salt() -> [u8; 32] {
        hex32(&serde_json::json!("27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60"))
    }
    fn coins() -> Vec<(u16, [u8; 32], u8)> {
        [
            (2, "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", 6), // Ethereum USDT
            (2, "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6), // Ethereum USDC
            (3, "00000000000000000000000055d398326f99059ff775485246999027b3197955", 18), // BSC USDT
            (3, "0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18), // BSC USDC
            (4, "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c", 6), // Tron USDT
            (5, "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264", 6), // Solana USDT
            (5, "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61", 6), // Solana USDC
        ]
        .into_iter()
        .map(|(c, t, d)| (c, hex32(&serde_json::json!(t)), d))
        .collect()
    }

    fn proposer() -> Keypair {
        Keypair::from_seed([1; 32]).unwrap()
    }

    fn pq_keys() -> Vec<Keypair> {
        (0..6u8).map(|i| Keypair::from_seed([0x70 + i; 32]).unwrap()).collect()
    }

    /// A bridged ledger at height 1 on `chain_id` with `pq_guardians`, source emitters on chains
    /// 2..=5, and an empty token registry — what chain 14 starts with: genesis lists no token.
    fn ledger_on(chain_id: u64, pq_guardians: Vec<PublicKey>) -> Ledger {
        let k = proposer();
        let entry = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 10,
            pending: Vec::new(),
            rewards: 0,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
            activation_epoch: 0,
        };
        let mut l = Ledger::new(chain_id, HC, [(k.address(), entry)].into_iter().collect(), &StubExecutor);
        let secrets: Vec<[u8; 32]> = (1u8..=6).map(|i| [i; 32]).collect();
        l.set_bridge(Some(BridgeState::from_config(&BridgeConfig {
            emitter: [1; 32],
            guardians: secrets.iter().map(guardian_address).collect(),
            emitters: (2u16..=5).map(|c| (c, [c as u8; 32])).collect(),
            pq_guardians,
            pause_key: Some(Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
            rules_v2: None,
            guardian_set_index: None,
            burn_sequence: None,
            min_inbound_sequence: None,
            rotation: None,
            fees: None,
        })));
        l.set_tokens(Some(TokenRegistry::new(FEE).with_mint_cap(100_000 * 100_000_000)));
        l.set_height(1);
        l.set_timestamp_ms(1_000_000);
        l
    }

    fn ledger() -> Ledger {
        ledger_on(CHAIN, pq_keys().iter().map(|k| k.public_key().clone()).collect())
    }

    /// A RAND fee bundle paying `fee`, burning nothing, whose four words start at `seed`; bound to
    /// the transaction by the stub executor.
    fn paid(l: &Ledger, seed: u32, fee: u64, action: Action) -> Transaction {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: crate::notes::pad4([[seed; 8], [seed + 1; 8]]),
            commitments: crate::notes::pad4([[seed + 2; 8], [seed + 3; 8]]),
            fee,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: l.height() as u32,
            envelopes: std::array::from_fn(|_| Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }),
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        StubExecutor::bound(Transaction::shielded(l.chain_id(), b, action))
    }

    /// The PQ guardians at `indices` over `message`.
    fn quorum(indices: &[u8], message: &[u8]) -> Vec<PqSignature> {
        let keys = pq_keys();
        indices.iter().map(|&i| PqSignature { index: i, signature: keys[i as usize].sign(message).as_bytes().to_vec() }).collect()
    }

    fn register(nonce: u64, coin: (u16, [u8; 32], u8), salt: [u8; 32]) -> Action {
        let (chain, token, decimals) = coin;
        let m = register_message(CHAIN, nonce, NAME, SYMBOL, &salt, chain, &token, decimals).unwrap();
        Action::RegisterBridgedToken {
            name: NAME.into(),
            symbol: SYMBOL.into(),
            salt,
            chain,
            token,
            decimals,
            nonce,
            pq_signatures: quorum(&[0, 1, 2, 3, 4], &m),
        }
    }

    fn list(nonce: u64, token_index: u32, coin: (u16, [u8; 32], u8)) -> Action {
        let (chain, token, decimals) = coin;
        let m = list_message(CHAIN, nonce, token_index, chain, &token, decimals);
        Action::ListBacking { token_index, chain, token, decimals, nonce, pq_signatures: quorum(&[1, 2, 3, 4, 5], &m) }
    }

    /// zUSD's whole deployment on chain 14, by transaction: one `RegisterBridgedToken` (its first
    /// backing, `list_nonce` 0) and six `ListBacking`s (`list_nonce` 1..6), each paid by the
    /// deployer's fee bundle — the seven real wire forms. The token lands at index 1 (RAND is 0)
    /// under the RPL bridged id, eight decimals, the genesis cap; every coin starts unlocked and
    /// resolves to it; and a deposit of each is then admissible under the cap.
    #[test]
    fn zusd_registers_by_transaction_and_lists_its_six_other_backings() {
        let mut l = ledger();
        let p = proposer().address();
        let coins = coins();
        let reg = paid(&l, 10, gas::BUNDLE_BASE + FEE, register(0, coins[0], salt()));
        l.apply_tx(&reg, &p, &StubExecutor).unwrap();
        let info = l.tokens().unwrap().get(1).unwrap().clone();
        assert_eq!(info.id, bridged_asset_id(NAME, SYMBOL, &salt()), "the RPL rule for a bridged id");
        assert_eq!((info.name.as_str(), info.symbol.as_str(), info.decimals, info.total_supply), (NAME, SYMBOL, 8, 0));
        assert_eq!(info.registered_at, 1);
        assert_eq!(info.authority, MintAuthority::Bridge { backings: vec![Backing::new(coins[0].0, coins[0].1, 6)] });
        assert_eq!(l.bridge().unwrap().list_nonce, 1);
        for (i, coin) in coins.iter().enumerate().skip(1) {
            let tx = paid(&l, 10 + 10 * i as u32, gas::BUNDLE_BASE, list(i as u64, 1, *coin));
            l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        }
        assert_eq!(l.bridge().unwrap().list_nonce, 7);
        let tokens = l.tokens().unwrap();
        let MintAuthority::Bridge { backings } = &tokens.get(1).unwrap().authority else { panic!("bridged") };
        assert_eq!(backings.len(), 7);
        for (coin, b) in coins.iter().zip(backings) {
            assert_eq!(b, &Backing::new(coin.0, coin.1, coin.2), "every coin starts unlocked");
            assert_eq!(tokens.bridged(coin.0, &coin.1).unwrap().index, 1);
            assert_eq!(tokens.check_lock(1, coin.0, &coin.1, 100_000 * 100_000_000, 0), Ok(()), "mintable under the cap");
        }
        assert!(tokens.backing_invariant_holds());
        assert_eq!(tokens.next_index(), 2);
    }

    /// The bridge repo's own `register` and `list` vectors, end to end through `validate` and
    /// `apply_tx`, on a ledger with the vectors' chain id (99) and PQ guardian set: the files
    /// `rand-bridge-gov pq-register` and `pq-list` write are what this chain admits.
    #[test]
    fn the_register_and_list_vectors_are_admitted_on_their_chain() {
        let file = vectors();
        let chain_id = file["rand_chain_id"].as_u64().unwrap();
        let mut l = ledger_on(chain_id, vector_keys(&file));
        let p = proposer().address();
        let g = &file["governance"];
        let r = &g["register"];
        let register = Action::RegisterBridgedToken {
            name: r["name"].as_str().unwrap().into(),
            symbol: r["symbol"].as_str().unwrap().into(),
            salt: hex32(&r["salt"]),
            chain: r["chain"].as_u64().unwrap() as u16,
            token: hex32(&r["token"]),
            decimals: r["decimals"].as_u64().unwrap() as u8,
            nonce: r["list_nonce"].as_u64().unwrap(),
            pq_signatures: vector_sigs(&r["pq_signatures"]),
        };
        l.apply_tx(&paid(&l, 10, gas::BUNDLE_BASE + FEE, register), &p, &StubExecutor).unwrap();
        let v = &g["list"];
        let listing = Action::ListBacking {
            token_index: v["token_index"].as_u64().unwrap() as u32,
            chain: v["chain"].as_u64().unwrap() as u16,
            token: hex32(&v["token"]),
            decimals: v["decimals"].as_u64().unwrap() as u8,
            nonce: v["list_nonce"].as_u64().unwrap(),
            pq_signatures: vector_sigs(&v["pq_signatures"]),
        };
        l.apply_tx(&paid(&l, 20, gas::BUNDLE_BASE, listing), &p, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().list_nonce, 2);
        assert_eq!(l.tokens().unwrap().bridged(5, &hex32(&v["token"])).unwrap().index, 1);
    }

    /// Audit v5 (TOK-2): a `RegisterBridgedToken` pays the registration fee the way a
    /// `RegisterToken` does — burned under the gate, the proposer keeping `fee − registration_fee`
    /// — where a `ListBacking`, which registers no token, pays its whole fee to the proposer.
    #[test]
    fn a_bridged_registration_burns_the_fee_under_the_gate() {
        let mut l = ledger();
        l.set_tokens(Some(l.tokens().unwrap().clone().with_burn_registration_fee(true)));
        let p = proposer().address();
        let coins = coins();
        l.apply_tx(&paid(&l, 10, gas::BUNDLE_BASE + FEE + 3, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        assert_eq!(l.validators()[&p].rewards, gas::BUNDLE_BASE + 3, "the proposer keeps fee − registration_fee");
        assert_eq!((l.supply().fees_paid, l.supply().burned), (gas::BUNDLE_BASE + 3, FEE));
        l.apply_tx(&paid(&l, 20, gas::BUNDLE_BASE + 1, list(1, 1, coins[1])), &p, &StubExecutor).unwrap();
        assert_eq!(l.validators()[&p].rewards, 2 * gas::BUNDLE_BASE + 4);
        assert_eq!(l.supply().burned, FEE, "a listing registers no token and burns nothing");
    }

    /// Every refusal a listing can meet, each reached before the Dilithium2 verification (the
    /// quorums below are garbage of the right shape unless the point is the quorum): the gate, the
    /// nonce, the chain's emitter, a pair that already backs a token, an asset id already
    /// registered, an unknown or unbridged index, source decimals past 18, the name rules, the fee
    /// floor — and last, a quorum over another message.
    #[test]
    fn every_listing_refusal_comes_before_the_quorum_is_verified() {
        let mut l = ledger();
        let p = proposer().address();
        let coins = coins();
        let garbage = |mut a: Action| {
            match &mut a {
                Action::RegisterBridgedToken { pq_signatures, .. } | Action::ListBacking { pq_signatures, .. } => {
                    for s in pq_signatures.iter_mut() {
                        s.signature = vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN];
                    }
                }
                _ => unreachable!(),
            }
            a
        };
        let err = |l: &Ledger, tx: &Transaction| l.validate(tx, &StubExecutor).unwrap_err();
        let full = gas::BUNDLE_BASE + FEE;

        // Before anything is registered: the nonce, the emitter, the fee, the name.
        assert_eq!(
            err(&l, &paid(&l, 10, full, garbage(register(1, coins[0], salt())))),
            TxError::Bridge(BridgeError::BadListNonce { expected: 0, got: 1 })
        );
        assert_eq!(
            err(&l, &paid(&l, 10, full, garbage(register(0, (6, [9; 32], 6), salt())))),
            TxError::Bridge(BridgeError::NoEmitter { chain: 6 })
        );
        assert_eq!(
            err(&l, &paid(&l, 10, full - 1, garbage(register(0, coins[0], salt())))),
            token(TokenError::RegistrationFeeTooLow { min: full, fee: full - 1 })
        );
        let mut long = garbage(register(0, coins[0], salt()));
        let Action::RegisterBridgedToken { name, .. } = &mut long else { panic!() };
        *name = "n".repeat(33);
        assert_eq!(err(&l, &paid(&l, 10, full, long)), token(TokenError::BadName));
        assert_eq!(
            err(&l, &paid(&l, 10, full, garbage(register(0, (2, [9; 32], 19), salt())))),
            token(TokenError::BadBackingDecimals(19))
        );
        // The quorum is the last thing looked at: a well-formed registration with a quorum over
        // another message (a listing's) is refused there, and only there.
        let mut swapped = register(0, coins[0], salt());
        let Action::RegisterBridgedToken { pq_signatures, .. } = &mut swapped else { panic!() };
        *pq_signatures = quorum(&[0, 1, 2, 3, 4], &list_message(CHAIN, 0, 1, coins[0].0, &coins[0].1, 6));
        assert_eq!(err(&l, &paid(&l, 10, full, swapped)), TxError::Bridge(BridgeError::PqBadSignature { index: 0 }));
        // A listing before any token exists names an unknown index.
        assert_eq!(err(&l, &paid(&l, 20, gas::BUNDLE_BASE, garbage(list(0, 1, coins[1])))), token(TokenError::UnknownToken(1)));

        l.apply_tx(&paid(&l, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        // The same registration again: its nonce is spent. At the right nonce, its identity is
        // taken (a different coin, so the pair is not what refuses it)…
        assert_eq!(
            err(&l, &paid(&l, 30, full, register(0, coins[0], salt()))),
            TxError::Bridge(BridgeError::BadListNonce { expected: 1, got: 0 })
        );
        assert_eq!(
            err(&l, &paid(&l, 30, full, garbage(register(1, coins[1], salt())))),
            token(TokenError::AlreadyRegistered(bridged_asset_id(NAME, SYMBOL, &salt())))
        );
        // …and a new token (another salt) cannot take a coin that already backs zUSD.
        assert_eq!(
            err(&l, &paid(&l, 30, full, garbage(register(1, coins[0], [1; 32])))),
            token(TokenError::BackingTaken { chain: 2 })
        );
        // A duplicate backing, an index that is not a token, too many source decimals, an
        // unregistered chain; and a listing's fee floor is the bundle base, taken at step 3.
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 1, coins[0])))), token(TokenError::BackingTaken { chain: 2 }));
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 2, coins[1])))), token(TokenError::UnknownToken(2)));
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 1, (3, [7; 32], 19))))), token(TokenError::BadBackingDecimals(19)));
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 1, (9, [7; 32], 6))))), TxError::Bridge(BridgeError::NoEmitter { chain: 9 }));
        assert_eq!(
            err(&l, &paid(&l, 40, gas::BUNDLE_BASE - 1, list(1, 1, coins[1]))),
            TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE - 1 }
        );
        assert_eq!(
            err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(0, 1, coins[1])))),
            TxError::Bridge(BridgeError::BadListNonce { expected: 1, got: 0 })
        );
        // A short quorum is refused on its count, before any state is read.
        let mut short = list(1, 1, coins[1]);
        let Action::ListBacking { pq_signatures, .. } = &mut short else { panic!() };
        pq_signatures.truncate(4);
        assert!(matches!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, short)), TxError::Bridge(BridgeError::PqNoQuorum { have: 4, .. })));
        assert_eq!(l.validate(&paid(&l, 40, gas::BUNDLE_BASE, list(1, 1, coins[1])), &StubExecutor), Ok(()));

        // A chain without a bridge refuses both before anything else.
        let mut plain = l.clone();
        plain.set_bridge(None);
        assert_eq!(err(&plain, &paid(&plain, 50, full, register(1, coins[1], [2; 32]))), TxError::Bridge(BridgeError::Disabled));
        assert_eq!(err(&plain, &paid(&plain, 50, gas::BUNDLE_BASE, list(1, 1, coins[1]))), TxError::Bridge(BridgeError::Disabled));
    }

    /// Audit v4 (TOK-1): a `RegisterBridgedToken` at a registry that holds `max_tokens` tokens is
    /// refused `RegistryFull` before its quorum is verified; a `ListBacking` adds no token and is
    /// still admitted at the cap.
    #[test]
    fn a_bridged_registration_at_max_tokens_is_refused_registry_full() {
        let mut l = ledger();
        l.set_tokens(Some(l.tokens().unwrap().clone().with_max_tokens(1)));
        let p = proposer().address();
        let coins = coins();
        let full = gas::BUNDLE_BASE + FEE;
        l.apply_tx(&paid(&l, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        assert!(l.tokens().unwrap().is_full());
        let mut garbage = register(1, coins[1], [2; 32]);
        let Action::RegisterBridgedToken { pq_signatures, .. } = &mut garbage else { panic!() };
        for s in pq_signatures.iter_mut() {
            s.signature = vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN];
        }
        assert_eq!(l.validate(&paid(&l, 20, full, garbage), &StubExecutor), Err(token(TokenError::RegistryFull)));
        l.apply_tx(&paid(&l, 30, gas::BUNDLE_BASE, list(1, 1, coins[1])), &p, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().list_nonce, 2);
    }

    // ---- audit v4, bridge rules v2: rotation, the gate, no listing while paused -----------------

    /// [`ledger`] with `rules_v2` on: the bridge carries the section and the registry its windows.
    fn ledger_v2() -> Ledger {
        let mut l = ledger();
        let rules = crate::bridge::BridgeRulesV2 { global_mint_cap_per_window: 1_000_000 * 100_000_000, cap_window_secs: 86_400 };
        l.bridge_mut().unwrap().rules_v2 = Some(rules.clone());
        let tokens = l.tokens().unwrap().clone().with_rules_v2(rules.cap_window_secs, rules.global_mint_cap_per_window);
        l.set_tokens(Some(tokens));
        l
    }

    /// Six fresh Dilithium2 keys that are no guardian's and not the pause key.
    fn fresh_pq_set(n: usize) -> Vec<Keypair> {
        (0..n as u8).map(|i| Keypair::from_seed([0xa0 + i; 32]).unwrap()).collect()
    }

    fn pks(keys: &[Keypair]) -> Vec<PublicKey> {
        keys.iter().map(|k| k.public_key().clone()).collect()
    }

    /// The PQ quorum `keys[indices]` over `message`.
    fn quorum_of(keys: &[Keypair], indices: &[u8], message: &[u8]) -> Vec<PqSignature> {
        indices.iter().map(|&i| PqSignature { index: i, signature: keys[i as usize].sign(message).as_bytes().to_vec() }).collect()
    }

    fn rotate_pq_tx(l: &Ledger, new: Vec<PublicKey>, nonce: u64, pq_signatures: Vec<PqSignature>) -> Transaction {
        Transaction { chain_id: l.chain_id(), bundle: None, action: Action::RotatePqGuardians { new_pq_guardians: new, nonce, pq_signatures } }
    }

    fn rotate_pause_tx(l: &Ledger, new: PublicKey, nonce: u64, pq_signatures: Vec<PqSignature>) -> Transaction {
        Transaction { chain_id: l.chain_id(), bundle: None, action: Action::RotatePauseKey { new_pause_key: new, nonce, pq_signatures } }
    }

    /// A `RotatePqGuardians` to `new` at the bridge's current `rotation_nonce`, signed by `signers`
    /// (the lowest five), applied.
    fn rotate_pq(l: &mut Ledger, new: Vec<PublicKey>, signers: &[Keypair]) -> Result<(), TxError> {
        let nonce = l.bridge().unwrap().rotation_nonce;
        let m = rotate_pq_message(l.chain_id(), nonce, &new);
        let tx = rotate_pq_tx(l, new, nonce, quorum_of(signers, &[0, 1, 2, 3, 4], &m));
        let p = proposer().address();
        l.apply_tx(&tx, &p, &StubExecutor).map(|_| ())
    }

    fn rotate_pause(l: &mut Ledger, new: PublicKey, signers: &[Keypair]) -> Result<(), TxError> {
        let nonce = l.bridge().unwrap().rotation_nonce;
        let m = rotate_pause_message(l.chain_id(), nonce, &new);
        let tx = rotate_pause_tx(l, new, nonce, quorum_of(signers, &[1, 2, 3, 4, 5], &m));
        let p = proposer().address();
        l.apply_tx(&tx, &p, &StubExecutor).map(|_| ())
    }

    fn bridge_err(e: BridgeError) -> Result<(), TxError> {
        Err(TxError::Bridge(e))
    }

    /// A `PublicKey` of `n` bytes, built the only way one can arrive: off the wire
    /// (`PublicKey::from_bytes` enforces the length; its `Deserialize` does not).
    fn wire_key(n: usize) -> PublicKey {
        bincode::deserialize(&bincode::serialize(&vec![7u8; n]).expect("bytes")).expect("a wire key")
    }

    /// A PQ rotation under the current PQ quorum moves the set and spends the rotation nonce;
    /// the superseded set can sign nothing further (its quorum over the next nonce is refused
    /// at the signature), and the new set can rotate again. Bundle-less, fee-less.
    #[test]
    fn a_pq_rotation_moves_the_set_and_the_old_set_cannot_sign_the_next_one() {
        let mut l = ledger_v2();
        let old = pq_keys();
        let new = fresh_pq_set(old.len());
        assert_eq!(rotate_pq(&mut l, pks(&new), &old), Ok(()));
        assert_eq!(l.bridge().unwrap().pq_guardians, pks(&new));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 1);
        let newer = fresh_pq_set(old.len()).into_iter().rev().collect::<Vec<_>>();
        assert_eq!(rotate_pq(&mut l, pks(&newer), &old), bridge_err(BridgeError::PqBadSignature { index: 0 }));
        assert_eq!(l.bridge().unwrap().pq_guardians, pks(&new), "refused, nothing moved");
        // A quorum signed for the spent nonce is refused on the nonce, before the signatures.
        let stale = rotate_pq_tx(&l, pks(&newer), 0, quorum_of(&new, &[0, 1, 2, 3, 4], &rotate_pq_message(CHAIN, 0, &pks(&newer))));
        assert_eq!(l.validate(&stale, &StubExecutor), bridge_err(BridgeError::BadRotationNonce { expected: 1, got: 0 }));
        assert_eq!(rotate_pq(&mut l, pks(&newer), &new), Ok(()));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 2);
        // The new set co-signs mints: a listing under it is admitted, one under the old set is not.
        let coins = coins();
        let nonce = l.bridge().unwrap().list_nonce;
        let m = register_message(CHAIN, nonce, NAME, SYMBOL, &salt(), coins[0].0, &coins[0].1, coins[0].2).unwrap();
        let mut reg = register(nonce, coins[0], salt());
        let Action::RegisterBridgedToken { pq_signatures, .. } = &mut reg else { panic!() };
        *pq_signatures = quorum_of(&newer, &[0, 1, 2, 3, 4], &m);
        assert_eq!(l.validate(&paid(&l, 10, gas::BUNDLE_BASE + FEE, reg), &StubExecutor), Ok(()));
        assert_eq!(
            l.validate(&paid(&l, 10, gas::BUNDLE_BASE + FEE, register(nonce, coins[0], salt())), &StubExecutor),
            bridge_err(BridgeError::PqBadSignature { index: 0 })
        );
    }

    /// Every structural refusal of a PQ rotation, each before the quorum is verified (the quorums
    /// are garbage of the right shape): the set's length against the ECDSA set's, a key that is
    /// not a Dilithium2 key's length, a duplicate, the pause key inside the set, a carried bundle.
    #[test]
    fn a_pq_rotation_is_refused_on_its_shape_before_its_quorum() {
        let l = ledger_v2();
        let old = pq_keys();
        let garbage = |n: usize| (0..n as u8).map(|i| PqSignature { index: i, signature: vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN] }).collect::<Vec<_>>();
        let err = |new: Vec<PublicKey>| l.validate(&rotate_pq_tx(&l, new, 0, garbage(5)), &StubExecutor);
        let new = pks(&fresh_pq_set(6));
        assert_eq!(err(new[..5].to_vec()), bridge_err(BridgeError::PqSetLengthMismatch { expected: 6, got: 5 }));
        assert_eq!(err(Vec::new()), bridge_err(BridgeError::PqSetLengthMismatch { expected: 6, got: 0 }));
        let mut short = new.clone();
        short[2] = wire_key(31);
        assert_eq!(err(short), bridge_err(BridgeError::BadPqGuardianKey { index: 2, len: 31 }));
        let mut dup = new.clone();
        dup[4] = dup[1].clone();
        assert_eq!(err(dup), bridge_err(BridgeError::DuplicatePqGuardian));
        let mut with_pause = new.clone();
        with_pause[0] = l.bridge().unwrap().pause_key.clone().unwrap();
        assert_eq!(err(with_pause), bridge_err(BridgeError::GuardianIsPauseKey));
        // A well-formed set with a garbage quorum reaches the signatures, and only then.
        assert_eq!(err(new.clone()), bridge_err(BridgeError::PqBadSignature { index: 0 }));
        // A short quorum is refused on its count.
        assert!(matches!(
            l.validate(&rotate_pq_tx(&l, new.clone(), 0, garbage(4)), &StubExecutor),
            Err(TxError::Bridge(BridgeError::PqNoQuorum { have: 4, need: 5, n: 6 }))
        ));
        // Bundle-less by shape.
        let mut with_bundle = rotate_pq_tx(&l, new.clone(), 0, quorum_of(&old, &[0, 1, 2, 3, 4], &rotate_pq_message(CHAIN, 0, &new)));
        with_bundle.bundle = paid(&l, 90, gas::BUNDLE_BASE, Action::None).bundle;
        assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::ActionCarriesBundle("rotate_pq_guardians")));
        assert_eq!(gas::fee_floor(&with_bundle.action), 0);
    }

    /// The pause key rotates under the PQ quorum: the old key can no longer pause, the new one
    /// can; a new key that is a PQ guardian, or not a Dilithium2 key's length, is refused before
    /// the quorum; the rotation nonce is shared with the PQ rotation.
    #[test]
    fn a_pause_key_that_is_a_pq_guardian_is_refused() {
        let mut l = ledger_v2();
        let guardians = pq_keys();
        let p = proposer().address();
        let garbage = (0..5u8).map(|i| PqSignature { index: i, signature: vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN] }).collect::<Vec<_>>();
        assert_eq!(
            l.validate(&rotate_pause_tx(&l, guardians[0].public_key().clone(), 0, garbage.clone()), &StubExecutor),
            bridge_err(BridgeError::PauseKeyIsGuardian)
        );
        assert_eq!(
            l.validate(&rotate_pause_tx(&l, wire_key(40), 0, garbage.clone()), &StubExecutor),
            bridge_err(BridgeError::BadPauseKeyLength { len: 40 })
        );
        let new_pause = Keypair::from_seed([0x99; 32]).unwrap();
        assert_eq!(
            l.validate(&rotate_pause_tx(&l, new_pause.public_key().clone(), 0, garbage), &StubExecutor),
            bridge_err(BridgeError::PqBadSignature { index: 0 })
        );
        assert_eq!(rotate_pause(&mut l, new_pause.public_key().clone(), &guardians), Ok(()));
        assert_eq!(l.bridge().unwrap().pause_key.as_ref(), Some(new_pause.public_key()));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 1);
        // The old pause key's signature no longer pauses; the new key's does.
        let old_pause = Keypair::from_seed([0x7f; 32]).unwrap();
        let pause = |k: &Keypair| Transaction { chain_id: CHAIN, bundle: None, action: Action::PauseMints { nonce: 0, signature: k.sign(&pause_message(CHAIN, 0)) } };
        assert_eq!(l.validate(&pause(&old_pause), &StubExecutor), bridge_err(BridgeError::BadPauseSignature));
        l.apply_tx(&pause(&new_pause), &p, &StubExecutor).unwrap();
        assert!(l.bridge().unwrap().mint_paused);
        // The two rotations share one nonce: a PQ rotation now needs nonce 1.
        let new_set = fresh_pq_set(6);
        assert_eq!(rotate_pq(&mut l, pks(&new_set), &guardians), Ok(()));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 2);
        // And with the set rotated, the new pause key inside the new set is refused as a guardian.
        let stale = rotate_pause_tx(&l, new_set[3].public_key().clone(), 2, Vec::new());
        assert!(matches!(l.validate(&stale, &StubExecutor), Err(TxError::Bridge(BridgeError::PqNoQuorum { .. }))), "the structure first");
    }

    /// Chain 14's shape: without `rules_v2` both rotations are `RulesV2Disabled` — before the
    /// quorum's structure, the nonce or anything else is looked at — and a chain without a
    /// bridge refuses them `Disabled` first.
    #[test]
    fn rotations_are_refused_without_rules_v2() {
        let l = ledger();
        let old = pq_keys();
        let new = pks(&fresh_pq_set(6));
        let m = rotate_pq_message(CHAIN, 0, &new);
        let honest = rotate_pq_tx(&l, new.clone(), 0, quorum_of(&old, &[0, 1, 2, 3, 4], &m));
        assert_eq!(l.validate(&honest, &StubExecutor), bridge_err(BridgeError::RulesV2Disabled));
        let pause = Keypair::from_seed([0x99; 32]).unwrap().public_key().clone();
        let honest_pause = rotate_pause_tx(&l, pause.clone(), 0, quorum_of(&old, &[0, 1, 2, 3, 4], &rotate_pause_message(CHAIN, 0, &pause)));
        assert_eq!(l.validate(&honest_pause, &StubExecutor), bridge_err(BridgeError::RulesV2Disabled));
        assert_eq!(l.validate(&rotate_pq_tx(&l, Vec::new(), 9, Vec::new()), &StubExecutor), bridge_err(BridgeError::RulesV2Disabled));
        let mut plain = l.clone();
        plain.set_bridge(None);
        assert_eq!(plain.validate(&honest, &StubExecutor), bridge_err(BridgeError::Disabled));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 0);
    }

    /// While minting is paused, `RegisterBridgedToken` and `ListBacking` are refused `MintsPaused`
    /// under `rules_v2` — after the nonce, before the quorum — and admitted on a chain-14-shaped
    /// ledger, which must keep accepting what it accepts today. Unpaused, both are admitted again.
    #[test]
    fn listing_is_refused_while_paused_under_rules_v2_and_admitted_without() {
        let coins = coins();
        let p = proposer().address();
        let pause = |l: &mut Ledger| {
            let k = Keypair::from_seed([0x7f; 32]).unwrap();
            let nonce = l.bridge().unwrap().pause_nonce;
            let tx = Transaction { chain_id: CHAIN, bundle: None, action: Action::PauseMints { nonce, signature: k.sign(&pause_message(CHAIN, nonce)) } };
            l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        };
        let unpause = |l: &mut Ledger| {
            let nonce = l.bridge().unwrap().pause_nonce;
            let tx = Transaction { chain_id: CHAIN, bundle: None, action: Action::UnpauseMints { nonce, pq_signatures: quorum(&[0, 1, 2, 3, 4], &unpause_message(CHAIN, nonce)) } };
            l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        };
        let full = gas::BUNDLE_BASE + FEE;

        let mut v2 = ledger_v2();
        v2.apply_tx(&paid(&v2, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        pause(&mut v2);
        assert_eq!(v2.validate(&paid(&v2, 20, full, register(1, coins[1], [2; 32])), &StubExecutor), bridge_err(BridgeError::MintsPaused));
        assert_eq!(v2.validate(&paid(&v2, 20, gas::BUNDLE_BASE, list(1, 1, coins[1])), &StubExecutor), bridge_err(BridgeError::MintsPaused));
        // The nonce is judged before the pause, the quorum after it.
        assert_eq!(
            v2.validate(&paid(&v2, 20, gas::BUNDLE_BASE, list(0, 1, coins[1])), &StubExecutor),
            bridge_err(BridgeError::BadListNonce { expected: 1, got: 0 })
        );
        unpause(&mut v2);
        assert_eq!(v2.validate(&paid(&v2, 20, gas::BUNDLE_BASE, list(1, 1, coins[1])), &StubExecutor), Ok(()));

        let mut v1 = ledger();
        v1.apply_tx(&paid(&v1, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        pause(&mut v1);
        assert_eq!(v1.validate(&paid(&v1, 20, full, register(1, coins[1], [2; 32])), &StubExecutor), Ok(()));
        v1.apply_tx(&paid(&v1, 20, gas::BUNDLE_BASE, list(1, 1, coins[1])), &p, &StubExecutor).unwrap();
        assert_eq!(v1.bridge().unwrap().list_nonce, 2);
    }

    /// Two listings signed at the same nonce cannot share a block: the second is refused where it
    /// sits (its nonce is spent) and the block leaves the ledger as it was; in order, at
    /// consecutive nonces, both apply.
    #[test]
    fn two_listings_in_one_block_apply_in_nonce_order_only() {
        let mut l = ledger();
        let p = proposer().address();
        let coins = coins();
        l.apply_tx(&paid(&l, 10, gas::BUNDLE_BASE + FEE, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        let a = paid(&l, 20, gas::BUNDLE_BASE, list(1, 1, coins[1]));
        let b = paid(&l, 30, gas::BUNDLE_BASE, list(1, 1, coins[2]));
        let before = l.clone();
        assert_eq!(
            l.apply_transactions(&[a.clone(), b], &p, &StubExecutor).unwrap_err(),
            BlockError::InvalidTx { index: 1, error: TxError::Bridge(BridgeError::BadListNonce { expected: 2, got: 1 }) }
        );
        assert_eq!((l.tokens(), l.bridge()), (before.tokens(), before.bridge()), "a refused block moved nothing");
        let c = paid(&l, 30, gas::BUNDLE_BASE, list(2, 1, coins[2]));
        l.apply_transactions(&[a, c], &p, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().list_nonce, 3);
    }

    /// BIND-1 (audit v6): under genesis `binding_domain: 1` each of the six governance messages
    /// carries the genesis hash. Two ledgers, one chain id, one guardian set, one pause key, the
    /// same nonces — what a re-cut looks like: the pause key's signature and every quorum made
    /// for genesis A are refused on B, today's chain-id messages are refused on both, and without
    /// the flag today's messages are the valid ones (every other test of this module).
    #[test]
    fn under_binding_domain_every_governance_message_binds_the_genesis() {
        use crate::bridge::gov::{list_message_in, pause_message_in, register_message_in, rotate_pause_message_in, rotate_pq_message_in, unpause_message_in};
        use crate::types::BindingDomain;
        let coins = coins();
        let p = proposer().address();
        // One token registered and minting not yet paused, in the chain-id world, then the same
        // state under two genesis hashes.
        let mut base = ledger_v2();
        base.apply_tx(&paid(&base, 10, gas::BUNDLE_BASE + FEE, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        base.record_anchor(base.height());
        let on = |l: &Ledger, g: u8| {
            let mut l = l.clone();
            l.set_binding_domain(BindingDomain::Genesis(crate::crypto::Hash([g; 32])));
            l
        };
        let (la, lb) = (on(&base, 0xa), on(&base, 0xb));
        let (da, v1) = (*la.binding_domain(), BindingDomain::ChainId);
        let pause_key = Keypair::from_seed([0x7f; 32]).unwrap();
        let bare = |action: Action| Transaction { chain_id: CHAIN, bundle: None, action };
        let bad_quorum = bridge_err(BridgeError::PqBadSignature { index: 0 });

        // Pause: the one key, its one message.
        let pause = |d: &BindingDomain| bare(Action::PauseMints { nonce: 0, signature: pause_key.sign(&pause_message_in(d, CHAIN, 0)) });
        assert_eq!(base.validate(&pause(&v1), &StubExecutor), Ok(()));
        assert_eq!(la.validate(&pause(&da), &StubExecutor), Ok(()));
        assert_eq!(lb.validate(&pause(&da), &StubExecutor), bridge_err(BridgeError::BadPauseSignature));
        assert_eq!(la.validate(&pause(&v1), &StubExecutor), bridge_err(BridgeError::BadPauseSignature));
        assert_eq!(base.validate(&pause(&da), &StubExecutor), bridge_err(BridgeError::BadPauseSignature));

        // The listings: a registration (list_nonce 1 after the base's own) and a further backing.
        let reg = |l: &Ledger, d: &BindingDomain| {
            let (chain, token, decimals) = coins[2];
            let m = register_message_in(d, CHAIN, 1, "Second USD", "zUSD2", &salt(), chain, &token, decimals).unwrap();
            let action = Action::RegisterBridgedToken {
                name: "Second USD".into(),
                symbol: "zUSD2".into(),
                salt: salt(),
                chain,
                token,
                decimals,
                nonce: 1,
                pq_signatures: quorum(&[0, 1, 2, 3, 4], &m),
            };
            StubExecutor::bound_in(paid(l, 30, gas::BUNDLE_BASE + FEE, action), l.binding_domain())
        };
        let list = |l: &Ledger, d: &BindingDomain| {
            let (chain, token, decimals) = coins[1];
            let m = list_message_in(d, CHAIN, 1, 1, chain, &token, decimals);
            let action = Action::ListBacking { token_index: 1, chain, token, decimals, nonce: 1, pq_signatures: quorum(&[0, 1, 2, 3, 4], &m) };
            StubExecutor::bound_in(paid(l, 40, gas::BUNDLE_BASE, action), l.binding_domain())
        };
        for (name, build) in [("register", &reg as &dyn Fn(&Ledger, &BindingDomain) -> Transaction), ("list", &list)] {
            assert_eq!(base.validate(&build(&base, &v1), &StubExecutor), Ok(()), "{name}: today");
            assert_eq!(la.validate(&build(&la, &da), &StubExecutor), Ok(()), "{name}");
            assert_eq!(lb.validate(&build(&lb, &da), &StubExecutor), bad_quorum, "{name}: A's quorum on B");
            assert_eq!(la.validate(&build(&la, &v1), &StubExecutor), bad_quorum, "{name}: a chain-id quorum under the flag");
        }

        // The two rotations, at rotation nonce 0 under the current set.
        let guardians = pq_keys();
        let new_set = pks(&fresh_pq_set(6));
        let new_pause = Keypair::from_seed([0x99; 32]).unwrap().public_key().clone();
        let rotate_pq = |l: &Ledger, d: &BindingDomain| {
            rotate_pq_tx(l, new_set.clone(), 0, quorum_of(&guardians, &[0, 1, 2, 3, 4], &rotate_pq_message_in(d, CHAIN, 0, &new_set)))
        };
        let rotate_pause = |l: &Ledger, d: &BindingDomain| {
            rotate_pause_tx(l, new_pause.clone(), 0, quorum_of(&guardians, &[0, 1, 2, 3, 4], &rotate_pause_message_in(d, CHAIN, 0, &new_pause)))
        };
        for (name, build) in [("rotate-pq", &rotate_pq as &dyn Fn(&Ledger, &BindingDomain) -> Transaction), ("rotate-pause", &rotate_pause)] {
            assert_eq!(base.validate(&build(&base, &v1), &StubExecutor), Ok(()), "{name}: today");
            assert_eq!(la.validate(&build(&la, &da), &StubExecutor), Ok(()), "{name}");
            assert_eq!(lb.validate(&build(&lb, &da), &StubExecutor), bad_quorum, "{name}: A's quorum on B");
            assert_eq!(la.validate(&build(&la, &v1), &StubExecutor), bad_quorum, "{name}: a chain-id quorum under the flag");
        }

        // Unpause: both chains paused by their own pause, then A's unpause quorum tried on B.
        let paused = |l: &Ledger| {
            let mut l = l.clone();
            let d = *l.binding_domain();
            l.apply_tx(&pause(&d), &p, &StubExecutor).unwrap();
            l
        };
        let (pa, pb, p0) = (paused(&la), paused(&lb), paused(&base));
        let unpause = |d: &BindingDomain| bare(Action::UnpauseMints { nonce: 1, pq_signatures: quorum(&[0, 1, 2, 3, 4], &unpause_message_in(d, CHAIN, 1)) });
        assert_eq!(p0.validate(&unpause(&v1), &StubExecutor), Ok(()));
        assert_eq!(pa.validate(&unpause(&da), &StubExecutor), Ok(()));
        assert_eq!(pb.validate(&unpause(&da), &StubExecutor), bad_quorum);
        assert_eq!(pa.validate(&unpause(&v1), &StubExecutor), bad_quorum);
    }

    // ── BRG-14 (audit v6, issue #89): possession, the delay, the cancel ──────────────────────

    fn ledger_rot(delay: Option<u32>, possession: bool) -> Ledger {
        let mut l = ledger_v2();
        l.bridge_mut().unwrap().rotation_rules =
            Some(crate::bridge::RotationRules { delay_secs: delay, needs_possession: possession.then_some(true) });
        l
    }

    fn possession_of(keys: &[Keypair], message: &[u8]) -> Vec<Vec<u8>> {
        keys.iter().map(|k| k.sign(message).as_bytes().to_vec()).collect()
    }

    fn rotate_pq_v2_tx(l: &Ledger, new: Vec<PublicKey>, possession: Vec<Vec<u8>>, nonce: u64, pq_signatures: Vec<PqSignature>) -> Transaction {
        Transaction { chain_id: l.chain_id(), bundle: None, action: Action::RotatePqGuardiansV2 { new_pq_guardians: new, possession, nonce, pq_signatures } }
    }

    fn rotate_pause_v2_tx(l: &Ledger, new: PublicKey, possession: Vec<u8>, nonce: u64, pq_signatures: Vec<PqSignature>) -> Transaction {
        Transaction { chain_id: l.chain_id(), bundle: None, action: Action::RotatePauseKeyV2 { new_pause_key: new, possession, nonce, pq_signatures } }
    }

    fn cancel_tx(l: &Ledger, kind: u8, nonce: u64, signer: &Keypair) -> Transaction {
        let message = crate::bridge::gov::cancel_rotation_message(l.chain_id(), nonce, crate::bridge::RotationKind::from_byte(kind).unwrap_or(crate::bridge::RotationKind::PqGuardians));
        Transaction { chain_id: l.chain_id(), bundle: None, action: Action::CancelRotation { kind, nonce, signature: signer.sign(&message) } }
    }

    /// The quorum's message for a v1/v2 PQ rotation at the ledger's current nonce, and the
    /// current set's quorum over it.
    fn pq_rotation_parts(l: &Ledger, new: &[PublicKey]) -> (u64, Vec<u8>, Vec<PqSignature>) {
        let nonce = l.bridge().unwrap().rotation_nonce;
        let m = rotate_pq_message(l.chain_id(), nonce, new);
        (nonce, m.clone(), quorum_of(&pq_keys(), &[0, 1, 2, 3, 4], &m))
    }

    /// BRG-14, possession. Under `rotation.needs_possession` a v1 rotation is refused before
    /// the quorum is read (a typo'd key could otherwise be rotated in); the V2 action with every
    /// new holder's own signature over the rotation message is admitted and applied; one signature
    /// by the wrong key, a missing one or a short one is refused by index; without the rule the
    /// V2 action is what is refused. The pause key the same way, one signature.
    #[test]
    fn under_needs_possession_a_rotation_carries_each_new_holders_signature() {
        let l = ledger_rot(None, true);
        let p = proposer().address();
        let new = fresh_pq_set(6);
        let (nonce, m, quorum) = pq_rotation_parts(&l, &pks(&new));
        assert_eq!(l.validate(&rotate_pq_tx(&l, pks(&new), nonce, quorum.clone()), &StubExecutor), bridge_err(BridgeError::PossessionRequired));
        let honest = rotate_pq_v2_tx(&l, pks(&new), possession_of(&new, &m), nonce, quorum.clone());
        assert_eq!(l.validate(&honest, &StubExecutor), Ok(()));
        // A signature by a key nobody in the new set holds, in slot 2.
        let stranger = Keypair::from_seed([0xee; 32]).unwrap();
        let mut forged = possession_of(&new, &m);
        forged[2] = stranger.sign(&m).as_bytes().to_vec();
        assert_eq!(l.validate(&rotate_pq_v2_tx(&l, pks(&new), forged, nonce, quorum.clone()), &StubExecutor), bridge_err(BridgeError::BadPossession { index: 2 }));
        // One signed over another nonce's message: the holder signed some rotation, not this one.
        let mut stale = possession_of(&new, &m);
        stale[0] = new[0].sign(&rotate_pq_message(l.chain_id(), nonce + 1, &pks(&new))).as_bytes().to_vec();
        assert_eq!(l.validate(&rotate_pq_v2_tx(&l, pks(&new), stale, nonce, quorum.clone()), &StubExecutor), bridge_err(BridgeError::BadPossession { index: 0 }));
        let mut short = possession_of(&new, &m);
        short.pop();
        assert_eq!(l.validate(&rotate_pq_v2_tx(&l, pks(&new), short, nonce, quorum.clone()), &StubExecutor), bridge_err(BridgeError::PossessionCountMismatch { expected: 6, got: 5 }));
        let mut cut = possession_of(&new, &m);
        cut[4].pop();
        assert_eq!(l.validate(&rotate_pq_v2_tx(&l, pks(&new), cut, nonce, quorum.clone()), &StubExecutor), bridge_err(BridgeError::BadPossessionLength { index: 4, len: 2419 }));
        // Without the rule the V2 action is the one refused, and a chain without the group too.
        let plain = ledger_rot(Some(60), false);
        assert_eq!(plain.validate(&honest, &StubExecutor), bridge_err(BridgeError::PossessionNotEnabled));
        assert_eq!(ledger_v2().validate(&honest, &StubExecutor), bridge_err(BridgeError::PossessionNotEnabled));
        // Applied: no delay, so the set moves now and the nonce is spent.
        let mut l = l;
        l.apply_tx(&honest, &p, &StubExecutor).unwrap();
        assert_eq!((l.bridge().unwrap().pq_guardians.clone(), l.bridge().unwrap().rotation_nonce), (pks(&new), 1));
        assert_eq!(l.bridge().unwrap().pending_pq, None);

        // The pause key: the new key's own signature over M_rotate_pause.
        let l = ledger_rot(None, true);
        let new_pause = Keypair::from_seed([0x99; 32]).unwrap();
        let m = rotate_pause_message(l.chain_id(), 0, new_pause.public_key());
        let quorum = quorum_of(&pq_keys(), &[0, 1, 2, 3, 4], &m);
        assert_eq!(l.validate(&rotate_pause_tx(&l, new_pause.public_key().clone(), 0, quorum.clone()), &StubExecutor), bridge_err(BridgeError::PossessionRequired));
        let honest = rotate_pause_v2_tx(&l, new_pause.public_key().clone(), new_pause.sign(&m).as_bytes().to_vec(), 0, quorum.clone());
        assert_eq!(l.validate(&honest, &StubExecutor), Ok(()));
        let wrong = rotate_pause_v2_tx(&l, new_pause.public_key().clone(), stranger.sign(&m).as_bytes().to_vec(), 0, quorum.clone());
        assert_eq!(l.validate(&wrong, &StubExecutor), bridge_err(BridgeError::BadPossession { index: 0 }));
        let short = rotate_pause_v2_tx(&l, new_pause.public_key().clone(), vec![1; 7], 0, quorum);
        assert_eq!(l.validate(&short, &StubExecutor), bridge_err(BridgeError::BadPossessionLength { index: 0, len: 7 }));
        let mut l = l;
        l.apply_tx(&honest, &p, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().pause_key.as_ref(), Some(new_pause.public_key()));
    }

    /// BRG-14, the delay. Under `rotation.delay_secs` an accepted rotation is pending: the set
    /// that signs is still the old one (a quorum of the old set verifies, one of the new does
    /// not), a second rotation of the same kind is refused, the other kind may pend beside it,
    /// and at the end of the first block whose time reaches `effective_at` the new set is in
    /// force, the pending slot empty, the nonce spent again and the root moved.
    #[test]
    fn under_a_delay_a_rotation_is_pending_until_its_time_and_the_old_set_signs_meanwhile() {
        use crate::bridge::pq::check_pq_quorum_message;
        let mut l = ledger_rot(Some(3_600), false);
        l.set_timestamp_ms(1_000_000);
        let p = proposer().address();
        let old = pq_keys();
        let new = fresh_pq_set(6);
        let root_before = l.state_root();
        assert_eq!(rotate_pq(&mut l, pks(&new), &old), Ok(()));
        let b = l.bridge().unwrap();
        assert_eq!(b.pq_guardians, pks(&old), "the old set still signs");
        assert_eq!(b.pending_pq, Some(crate::bridge::PendingPqRotation { keys: pks(&new), effective_at_secs: 1_000 + 3_600 }));
        assert_eq!(b.rotation_nonce, 1);
        assert_ne!(l.state_root(), root_before, "a pending rotation is in the root");
        // What an attestation's co-signature check does (`check_attest` → `verify_pq_signatures`
        // over `bridge.pq_guardians`): the old set's quorum passes, the new set's does not.
        let mu = [0x5a; 32];
        let chain_id = l.chain_id();
        let cosign = move |keys: &[Keypair]| -> Vec<PqSignature> {
            keys.iter().take(5).enumerate().map(|(i, k)| crate::bridge::pq_cosign(k, i as u8, chain_id, &mu)).collect()
        };
        let m = crate::bridge::pq_cosign_message(chain_id, &mu);
        assert_eq!(check_pq_quorum_message(&cosign(&old), &l.bridge().unwrap().pq_guardians, &m), Ok(()));
        assert!(check_pq_quorum_message(&cosign(&new), &l.bridge().unwrap().pq_guardians, &m).is_err());
        // A second PQ rotation is refused while one pends; a pause-key rotation is not.
        let newer = fresh_pq_set(6).into_iter().rev().collect::<Vec<_>>();
        let (nonce, m2, q2) = pq_rotation_parts(&l, &pks(&newer));
        assert_eq!(l.validate(&rotate_pq_tx(&l, pks(&newer), nonce, q2), &StubExecutor), bridge_err(BridgeError::RotationPending { effective_at_secs: 4_600 }));
        let _ = m2;
        let new_pause = Keypair::from_seed([0x99; 32]).unwrap();
        assert_eq!(rotate_pause(&mut l, new_pause.public_key().clone(), &old), Ok(()));
        assert_eq!(l.bridge().unwrap().pause_key.as_ref(), Some(Keypair::from_seed([0x7f; 32]).unwrap().public_key()), "the old pause key still holds");
        assert_eq!(l.bridge().unwrap().pending_pause.as_ref().map(|p| p.effective_at_secs), Some(4_600));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 2);
        // One second short: nothing moves at the block's end.
        l.set_timestamp_ms(4_599_999);
        let root = l.state_root();
        l.close_block(2, &p, 0, 0);
        assert_eq!(l.bridge().unwrap().pq_guardians, pks(&old));
        assert!(l.bridge().unwrap().pending_pq.is_some());
        // At its time: both take effect, each spending a nonce, and the root moves.
        l.set_timestamp_ms(4_600_000);
        l.close_block(3, &p, 0, 0);
        let b = l.bridge().unwrap();
        assert_eq!(b.pq_guardians, pks(&new), "the new set signs from the next block");
        assert_eq!(b.pause_key.as_ref(), Some(new_pause.public_key()));
        assert_eq!((b.pending_pq.clone(), b.pending_pause.clone()), (None, None));
        assert_eq!(b.rotation_nonce, 4, "each activation spends a nonce, so the pool's stamp on pooled attestations moves");
        assert_ne!(l.state_root(), root);
        assert_eq!(check_pq_quorum_message(&cosign(&new), &l.bridge().unwrap().pq_guardians, &m), Ok(()));
        assert!(check_pq_quorum_message(&cosign(&old), &l.bridge().unwrap().pq_guardians, &m).is_err(), "the old set's co-signatures fail after");
        // Without a delay (possession only, or no group) a rotation lands at once, as before.
        let mut at_once = ledger_rot(None, false);
        assert_eq!(rotate_pq(&mut at_once, pks(&new), &old), Ok(()));
        assert_eq!((at_once.bridge().unwrap().pq_guardians.clone(), at_once.bridge().unwrap().pending_pq.clone()), (pks(&new), None));
    }

    /// BRG-14, the cancel. The current pause key — the one key held apart from the quorum —
    /// drops a pending rotation of either kind by a signature over `M_cancel` at the rotation
    /// nonce, which the cancel spends; then nothing takes effect at the old time. A bad kind byte,
    /// nothing pending, a guardian's signature, a stale nonce and a chain without the group are
    /// each refused by name.
    #[test]
    fn the_pause_key_cancels_a_pending_rotation_and_the_nonce_moves() {
        let mut l = ledger_rot(Some(3_600), false);
        l.set_timestamp_ms(1_000_000);
        let p = proposer().address();
        let (old, new) = (pq_keys(), fresh_pq_set(6));
        let pause = Keypair::from_seed([0x7f; 32]).unwrap();
        assert_eq!(rotate_pq(&mut l, pks(&new), &old), Ok(()));
        assert_eq!(l.validate(&cancel_tx(&l, 1, 1, &pause), &StubExecutor), bridge_err(BridgeError::NoPendingRotation), "nothing pending of that kind");
        assert_eq!(l.validate(&cancel_tx(&l, 2, 1, &pause), &StubExecutor), bridge_err(BridgeError::BadRotationKind(2)));
        assert_eq!(l.validate(&cancel_tx(&l, 0, 0, &pause), &StubExecutor), bridge_err(BridgeError::BadRotationNonce { expected: 1, got: 0 }));
        assert_eq!(l.validate(&cancel_tx(&l, 0, 1, &old[0]), &StubExecutor), bridge_err(BridgeError::BadCancelSignature), "a guardian cannot cancel");
        let honest = cancel_tx(&l, 0, 1, &pause);
        assert_eq!(l.validate(&honest, &StubExecutor), Ok(()));
        assert_eq!(ledger_v2().validate(&honest, &StubExecutor), bridge_err(BridgeError::RotationRulesDisabled));
        l.apply_tx(&honest, &p, &StubExecutor).unwrap();
        let b = l.bridge().unwrap();
        assert_eq!((b.pending_pq.clone(), b.rotation_nonce), (None, 2));
        assert_eq!(b.pq_guardians, pks(&old));
        // The old time comes and goes: the cancelled set never takes effect.
        l.set_timestamp_ms(4_600_000);
        l.close_block(2, &p, 0, 0);
        assert_eq!(l.bridge().unwrap().pq_guardians, pks(&old));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 2);
        // The nonce having moved, the next rotation signs at 2 — and a cancel of a pending
        // pause-key rotation works the same way, by the current (still old) pause key.
        let new_pause = Keypair::from_seed([0x99; 32]).unwrap();
        assert_eq!(rotate_pause(&mut l, new_pause.public_key().clone(), &old), Ok(()));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 3);
        assert_eq!(l.validate(&cancel_tx(&l, 1, 3, &new_pause), &StubExecutor), bridge_err(BridgeError::BadCancelSignature), "the incoming key cannot cancel its own arrival");
        l.apply_tx(&cancel_tx(&l, 1, 3, &pause), &p, &StubExecutor).unwrap();
        assert_eq!((l.bridge().unwrap().pending_pause.clone(), l.bridge().unwrap().rotation_nonce), (None, 4));
    }
}
