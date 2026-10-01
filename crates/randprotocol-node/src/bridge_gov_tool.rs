//! Audit v6, BRG-14 (issue #89): the signer for the bridge's post-quantum rotations —
//! `rand-node bridge-gov rotate-pq|rotate-pause|cancel-rotation`.
//!
//! The ledger has carried `RotatePqGuardians`/`RotatePauseKey` since chain 15, but no tool built
//! or signed either message (`docs/bridge.md` §21.1 named two commands that do not exist). This is
//! that tool, in three steps any number of separate machines can run:
//!
//! - **message** prints the hex rotation message for the chain's current `rotation_nonce`
//!   (read from the node) in the chain's binding domain (BIND-1) — what every signer should see
//!   and compare before signing;
//! - **sign** signs it with one Dilithium2 key file and prints `index:signature` — a current PQ
//!   guardian's key for the quorum (its index in the current set), or a NEW key for the proof of
//!   possession (its index in the new set; 0 for a pause key);
//! - **submit** assembles the action from the collected lines and sends it: the V2 action
//!   (`…V2`, with possession) when possession lines are given, the v1 action otherwise.
//!
//! Everything here that is not I/O is a pure function of its inputs, so the assembled action is
//! tested against a real ledger below rather than against a node.

use anyhow::{anyhow, bail, Context, Result};
use randprotocol_core::bridge::gov::{cancel_rotation_message_in, rotate_pause_message_in, rotate_pq_message_in};
use randprotocol_core::bridge::{PqSignature, RotationKind};
use randprotocol_core::crypto::{Keypair, PublicKey, Signature};
use randprotocol_core::types::BindingDomain;
use randprotocol_core::Action;

/// One `index:signature-hex` line per signer, whitespace- or newline-separated, `#` comments
/// ignored — what `sign` prints, concatenated by whoever collects them. Refuses a repeated index
/// (one signer counted twice) and returns them in index order, the order the ledger requires.
pub fn parse_signature_lines(text: &str) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    for raw in text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).flat_map(|l| l.split_whitespace()) {
        let (index, sig) = raw.split_once(':').ok_or_else(|| anyhow!("{raw:.24}…: expected index:signature-hex"))?;
        let index: u8 = index.parse().with_context(|| format!("{index:?} is not a signer index (0-255)"))?;
        let sig = hex::decode(sig.strip_prefix("0x").unwrap_or(sig)).with_context(|| format!("signer {index}'s signature is not hex"))?;
        if out.iter().any(|(i, _)| *i == index) {
            bail!("signer index {index} appears twice");
        }
        out.push((index, sig));
    }
    out.sort_by_key(|(i, _)| *i);
    Ok(out)
}

/// `index:signature-hex`, what `sign` prints.
pub fn signature_line(index: u8, signature: &Signature) -> String {
    format!("{index}:{}", hex::encode(signature.as_bytes()))
}

/// The rotation message of `kind` for this chain at `nonce` (`new_pause_key` for a pause-key
/// rotation, `new_pq_guardians` for a set rotation).
pub fn rotation_message(domain: &BindingDomain, chain_id: u64, nonce: u64, rotation: &Rotation) -> Vec<u8> {
    match rotation {
        Rotation::Pq(keys) => rotate_pq_message_in(domain, chain_id, nonce, keys),
        Rotation::Pause(key) => rotate_pause_message_in(domain, chain_id, nonce, key),
    }
}

/// What is being rotated in.
#[derive(Clone, Debug)]
pub enum Rotation {
    Pq(Vec<PublicKey>),
    Pause(PublicKey),
}

/// The message a `CancelRotation` of `kind` signs at `nonce`.
pub fn cancel_message(domain: &BindingDomain, chain_id: u64, nonce: u64, kind: RotationKind) -> Vec<u8> {
    cancel_rotation_message_in(domain, chain_id, nonce, kind)
}

/// Sign `message` with `key`, as signer `index`, after checking the key is the one expected at
/// that index when `expected` names it — a quorum signer's key must be `pq_guardians[index]`, a
/// possession signer's the new key at `index`, so a mixed-up key file is caught before a line is
/// handed on.
pub fn sign_line(key: &Keypair, index: u8, message: &[u8], expected: Option<&PublicKey>) -> Result<String> {
    if let Some(want) = expected {
        if key.public_key() != want {
            bail!("this key file is not the key at index {index} (its public key differs): wrong file or wrong --index");
        }
    }
    Ok(signature_line(index, &key.sign(message)))
}

/// The action `submit` sends. `possession` empty means the v1 action; otherwise the V2 action,
/// whose possession lines must be one per new key at indices `0..n` (each new key's own
/// signature over the same message — checked here, so a wrong one is refused before sending).
pub fn assemble_rotation(
    rotation: Rotation,
    nonce: u64,
    quorum: Vec<(u8, Vec<u8>)>,
    possession: Vec<(u8, Vec<u8>)>,
    message: &[u8],
) -> Result<Action> {
    let pq_signatures: Vec<PqSignature> = quorum.into_iter().map(|(index, signature)| PqSignature { index, signature }).collect();
    let keys: Vec<PublicKey> = match &rotation {
        Rotation::Pq(keys) => keys.clone(),
        Rotation::Pause(key) => vec![key.clone()],
    };
    if !possession.is_empty() {
        if possession.len() != keys.len() || possession.iter().enumerate().any(|(i, (index, _))| *index as usize != i) {
            bail!("possession lines must be exactly one per new key, indices 0..{} (got {:?})", keys.len(), possession.iter().map(|(i, _)| *i).collect::<Vec<_>>());
        }
        for (key, (index, sig)) in keys.iter().zip(&possession) {
            let ok = Signature::from_bytes(sig).is_ok_and(|s| key.verify(message, &s));
            if !ok {
                bail!("possession signature {index} does not verify under new key {index} over this rotation message (wrong key, nonce or chain)");
            }
        }
    }
    let mut possession: Vec<Vec<u8>> = possession.into_iter().map(|(_, s)| s).collect();
    Ok(match (rotation, possession.is_empty()) {
        (Rotation::Pq(new_pq_guardians), true) => Action::RotatePqGuardians { new_pq_guardians, nonce, pq_signatures },
        (Rotation::Pq(new_pq_guardians), false) => Action::RotatePqGuardiansV2 { new_pq_guardians, possession, nonce, pq_signatures },
        (Rotation::Pause(new_pause_key), true) => Action::RotatePauseKey { new_pause_key, nonce, pq_signatures },
        (Rotation::Pause(new_pause_key), false) => {
            Action::RotatePauseKeyV2 { new_pause_key, possession: possession.remove(0), nonce, pq_signatures }
        }
    })
}

/// A `CancelRotation` from one `0:signature` line (or a bare hex signature) of the pause key.
pub fn assemble_cancel(kind: RotationKind, nonce: u64, signature_text: &str) -> Result<Action> {
    let text = signature_text.trim();
    let hex_part = text.split_once(':').map_or(text, |(_, s)| s);
    let bytes = hex::decode(hex_part.strip_prefix("0x").unwrap_or(hex_part)).context("the cancel signature is not hex")?;
    let signature = Signature::from_bytes(&bytes).map_err(|e| anyhow!("the cancel signature is not a Dilithium2 signature: {e}"))?;
    Ok(Action::CancelRotation { kind: kind as u8, nonce, signature })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures::{bridged_genesis_with_rotation, pq_keys};
    use randprotocol_core::bridge::{BridgeRulesV2, RotationRules};
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::{Ledger, Transaction};

    fn ledger(rotation: RotationRules) -> Ledger {
        let rules = BridgeRulesV2 { global_mint_cap_per_window: 1_000_000, cap_window_secs: 86_400 };
        let (gs, _) = bridged_genesis_with_rotation(9, Some(rules), None, Some(rotation));
        let mut l = gs.ledger;
        l.set_height(1);
        l.set_timestamp_ms(1_000);
        l
    }

    fn submit(l: &Ledger, action: Action) -> Result<(), randprotocol_core::TxError> {
        l.validate(&Transaction { chain_id: l.chain_id(), bundle: None, action }, &StubExecutor)
    }

    /// The tool end to end against a ledger with possession required: `message`, five quorum
    /// `sign`s by the current set, six possession `sign`s by the new keys, the lines collected in
    /// any order, `submit` → the V2 action the ledger admits. Without possession lines the v1
    /// action is built — and refused there, as it must be.
    #[test]
    fn the_signing_tool_builds_a_rotation_the_ledger_admits() {
        let l = ledger(RotationRules { delay_secs: None, needs_possession: Some(true) });
        let old = pq_keys();
        let new: Vec<Keypair> = (0..6u8).map(|i| Keypair::from_seed([0xa0 + i; 32]).unwrap()).collect();
        let new_pks: Vec<PublicKey> = new.iter().map(|k| k.public_key().clone()).collect();
        let nonce = l.bridge().unwrap().rotation_nonce;
        let rotation = Rotation::Pq(new_pks.clone());
        let message = rotation_message(l.binding_domain(), l.chain_id(), nonce, &rotation);
        let current = &l.bridge().unwrap().pq_guardians;
        let quorum: String = [4u8, 0, 2, 1, 3]
            .iter()
            .map(|&i| sign_line(&old[i as usize], i, &message, Some(&current[i as usize])).unwrap() + "\n")
            .collect();
        let possession: String = (0..6u8).rev().map(|i| sign_line(&new[i as usize], i, &message, Some(&new_pks[i as usize])).unwrap() + " ").collect();
        let action = assemble_rotation(rotation.clone(), nonce, parse_signature_lines(&quorum).unwrap(), parse_signature_lines(&possession).unwrap(), &message).unwrap();
        assert!(matches!(action, Action::RotatePqGuardiansV2 { .. }));
        assert_eq!(submit(&l, action), Ok(()));
        let v1 = assemble_rotation(rotation, nonce, parse_signature_lines(&quorum).unwrap(), Vec::new(), &message).unwrap();
        assert!(matches!(v1, Action::RotatePqGuardians { .. }));
        assert!(submit(&l, v1).is_err(), "possession is required on this chain");
        // A key file at the wrong index is caught at `sign`.
        assert!(sign_line(&old[1], 0, &message, Some(&current[0])).is_err());
        // A possession line by the wrong key is caught at `submit`, before anything is sent.
        let mut bad = parse_signature_lines(&possession).unwrap();
        bad[3].1 = old[0].sign(&message).as_bytes().to_vec();
        let e = assemble_rotation(Rotation::Pq(new_pks.clone()), nonce, parse_signature_lines(&quorum).unwrap(), bad, &message).unwrap_err();
        assert!(e.to_string().contains("possession signature 3"), "{e}");
    }

    /// The pause key: rotate it with possession, and — under a delay — cancel the pending
    /// rotation with the current pause key's `cancel-rotation sign` line.
    #[test]
    fn the_signing_tool_rotates_the_pause_key_and_cancels_a_pending_rotation() {
        let mut l = ledger(RotationRules { delay_secs: Some(600), needs_possession: Some(true) });
        let old = pq_keys();
        let new_pause = Keypair::from_seed([0x99; 32]).unwrap();
        let rotation = Rotation::Pause(new_pause.public_key().clone());
        let message = rotation_message(l.binding_domain(), l.chain_id(), 0, &rotation);
        let quorum: String = (0..5u8).map(|i| sign_line(&old[i as usize], i, &message, None).unwrap() + "\n").collect();
        let possession = sign_line(&new_pause, 0, &message, Some(new_pause.public_key())).unwrap();
        let action = assemble_rotation(rotation, 0, parse_signature_lines(&quorum).unwrap(), parse_signature_lines(&possession).unwrap(), &message).unwrap();
        assert!(matches!(action, Action::RotatePauseKeyV2 { .. }));
        let tx = Transaction { chain_id: l.chain_id(), bundle: None, action };
        let p = *l.validators().keys().next().unwrap();
        l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        assert!(l.bridge().unwrap().pending_pause.is_some());
        let nonce = l.bridge().unwrap().rotation_nonce;
        let pause = Keypair::from_seed([0x7f; 32]).unwrap();
        let line = sign_line(&pause, 0, &cancel_message(l.binding_domain(), l.chain_id(), nonce, RotationKind::PauseKey), l.bridge().unwrap().pause_key.as_ref()).unwrap();
        assert_eq!(submit(&l, assemble_cancel(RotationKind::PauseKey, nonce, &line).unwrap()), Ok(()));
    }

    #[test]
    fn signature_lines_parse_in_index_order_and_refuse_a_repeat() {
        let got = parse_signature_lines("2:0a0b # comment\n0:ff\n\n1:00 ").unwrap();
        assert_eq!(got, vec![(0, vec![0xff]), (1, vec![0]), (2, vec![0x0a, 0x0b])]);
        assert!(parse_signature_lines("1:00\n1:01").is_err());
        assert!(parse_signature_lines("x:00").is_err());
        assert!(parse_signature_lines("0:zz").is_err());
        assert!(parse_signature_lines("0000").is_err());
    }
}
