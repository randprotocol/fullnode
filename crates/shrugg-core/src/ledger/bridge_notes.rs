//! The bridge as notes: `BridgeAttest` and `BridgeBurn` (phase S3, spec §10).
//!
//! A bridged holding on the shielded chain is a note whose `asset` word is the bridge
//! registry's dense index for that asset, so the two bridge actions are the two places value
//! crosses between the pool and the bridge:
//!
//! - **`BridgeAttest`** turns a guardian-signed transfer into one deposit note. The amount is
//!   public in that transaction, like a `Mint` or a `Withdraw`; the note then sits in the tree
//!   indistinguishable from every other. The chain — not the submitter — computes the
//!   commitment, from the amount the guardians signed and the recipient the transaction names,
//!   so a submitter cannot mint a note for an amount or an owner the attestation does not say.
//! - **`BridgeBurn`** sends value the other way. A bundle balances one asset and the fee is
//!   always SHRUGG, so a burn is the chain's only two-bundle transaction: the transaction's own
//!   bundle pays the fee in SHRUGG, and the action carries an *asset* bundle that burns
//!   `amount + relayer_fee` of the bridged asset. Both bundles go through the same admission.
//!
//! The bridge's own public state lives in [`crate::bridge::BridgeState`] and is committed by
//! the fifth component of the state root; this module is only the ledger's half.

use super::{Ledger, TxError};
use crate::bridge::{
    asset_id, Attestation, AssetId, AttestOutcome, AttestPlan, BridgeError, BridgeState, CheckedAttestation, Payload,
};
use crate::confidential::ConfidentialExecutor;
use crate::notes::{Envelope, ShieldedAddress, Word8};
use crate::types::{Action, Transaction};

/// The `from` field of a deposit note: a deposit has no sender inside the pool, so the note
/// records the zero word rather than an address that does not exist. Shared by validate and
/// apply, which must compute the very same commitment.
const DEPOSIT_FROM: Word8 = [0; 8];

/// The action step of admission (spec §7 step 7) for the two bridge actions.
///
/// Returns the verified attestation, which [`apply`] consumes rather than verifying the
/// guardian quorum a second time — the same reason `validate_inner` hands `apply_tx` a call's
/// verified outcome.
pub(super) fn validate(
    ledger: &Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
) -> Result<Option<CheckedAttestation>, TxError> {
    match action {
        Action::BridgeAttest { attestation, recipient, r, time, envelope: _ } => {
            // The cheapest check this action has, and the one that must run before any decode or
            // signature recovery: the deposit note is stamped with this `time` rather than the
            // apply height (see [`Action::BridgeAttest`]), so it gets the window a bundle's
            // `time` gets. A comparison, bought before an attestation buys any work.
            ledger.check_time(*time)?;
            let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            // The attestation's size cap ran at step 1, before this decode. `check_attest` is
            // itself ordered cheap-before-expensive: it decodes, resolves the guardian set,
            // rejects a replayed digest and checks the payload before recovering a signature.
            let checked = bridge.check_attest(attestation, ledger.now_secs()).map_err(TxError::Bridge)?;
            if let AttestPlan::Transfer(t) = checked.plan() {
                // The wire format has 32 bytes for a recipient and a shielded address is
                // ~1.2 KB, so the depositor named a hash and this transaction carries the
                // address. Without this equality the submitter would choose who receives it.
                if recipient.recipient_hash() != t.to_hash {
                    return Err(TxError::BridgeRecipientMismatch);
                }
                // The deposit note is this transaction's third commitment, and `apply` appends
                // it after the fee bundle's two. Checking it against both the tree and that
                // bundle keeps `validate` and `apply` in agreement — the mempool admits on
                // `validate`, so a gap here would be a transaction that is accepted and then
                // fails the block it lands in.
                let cm = deposit_commitment(recipient, t.amount, t.info.index, *time, r, executor);
                let in_fee_bundle = tx.bundle.as_ref().is_some_and(|b| b.commitments.contains(&cm));
                if ledger.has_commitment(&cm) || in_fee_bundle {
                    return Err(TxError::CommitmentExists(cm));
                }
            }
            Ok(Some(checked))
        }
        Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, to } => {
            let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            // Cheap before expensive (spec §7), and across *both* bundles: everything here is
            // a comparison or a set lookup, and it all runs before either bundle's proof is
            // verified — the fee bundle's at step 9 of `validate_inner`, the asset bundle's at
            // the end of this arm. A burn that names the wrong asset costs no verification.
            if asset_bundle.asset != *asset {
                return Err(TxError::BurnAssetMismatch { expected: *asset, actual: asset_bundle.asset });
            }
            if asset_bundle.fee != 0 {
                return Err(TxError::BurnAssetBundleFee(asset_bundle.fee));
            }
            let expected = amount.checked_add(*relayer_fee).ok_or(TxError::Overflow)?;
            if asset_bundle.burn != expected {
                return Err(TxError::BurnAmountMismatch { expected, actual: asset_bundle.burn });
            }
            // `check_bundle` sees each bundle alone and the fee bundle's notes are not in the
            // ledger yet, so the pairs *between* the two bundles are checked here: all four
            // nullifiers and all four commitments of a burn must differ.
            if let Some(fee_bundle) = &tx.bundle {
                if fee_bundle.nullifiers.iter().any(|nf| asset_bundle.nullifiers.contains(nf)) {
                    return Err(TxError::DuplicateNullifierInBundle);
                }
                if fee_bundle.commitments.iter().any(|cm| asset_bundle.commitments.contains(cm)) {
                    return Err(TxError::DuplicateCommitmentInBundle);
                }
            }
            ledger.check_bundle(asset_bundle)?;
            bridge.check_burn(*asset, *amount, *to_chain, to, *relayer_fee).map_err(TxError::Bridge)?;
            ledger.check_bundle_proof(asset_bundle, executor)?;
            Ok(None)
        }
        // Fail closed: an action this module does not own can only arrive through a routing
        // mistake in [`super::Ledger::validate_inner`], and `Ok(())` would let it skip its own
        // rules.
        _ => Err(TxError::UnsupportedAction("bridge")),
    }
}

/// The apply step for the two bridge actions. Runs after [`validate`] has accepted the
/// transaction, so everything it can still fail on is a state write the ledger must not have
/// made twice; `apply_tx`'s caller discards the ledger on any error.
///
/// `checked` is what [`validate`] verified, for a `BridgeAttest`.
pub(super) fn apply(
    ledger: &mut Ledger,
    tx: &Transaction,
    action: &Action,
    executor: &dyn ConfidentialExecutor,
    checked: Option<CheckedAttestation>,
) -> Result<(), TxError> {
    match action {
        Action::BridgeAttest { recipient, r, time, .. } => {
            let checked = checked.expect("validate returns the checked attestation for an attest");
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            // Consumes the digest and registers the asset if this is its first sighting. No
            // signature work: the quorum was verified once, in `validate`, and this is the
            // token that proves it.
            match bridge.apply_attest(checked) {
                AttestOutcome::Minted(t) => {
                    let cm = deposit_commitment(recipient, t.amount, t.info.index, *time, r, executor);
                    ledger.deposit(cm, executor)?;
                }
                // Governance only: a rotation moves guardian keys and no value.
                AttestOutcome::GuardianSetUpgraded(_) => {}
            }
            Ok(())
        }
        Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, to } => {
            // The fee bundle's notes were written by `apply_tx`'s common path; the asset
            // bundle's are written here, through that same path, so a burn spends four
            // nullifiers and appends four commitments in total. The asset bundle's fee is zero,
            // so no proposer reward follows from it.
            ledger.apply_bundle_notes(asset_bundle, executor);
            let (height, timestamp) = (ledger.height(), ledger.now_secs() as u32);
            let tx_hash = tx.hash();
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            // The record's sender slot is the transaction hash: a burn is funded by notes, so
            // there is no sender identity to write there.
            bridge
                .apply_burn(tx_hash, *asset, *amount, *to_chain, *to, *relayer_fee, height, timestamp)
                .map_err(TxError::Bridge)?;
            Ok(())
        }
        _ => Err(TxError::UnsupportedAction("bridge")),
    }
}

/// The commitment of the note a transfer attestation deposits, computed identically by
/// [`validate`], [`apply`] and [`deposit_note`] — one function so the three cannot drift.
///
/// `time` is the action's own `time` word, never the height the transaction is applied at: the
/// depositor seals an envelope against this commitment before submitting, and cannot predict
/// which block will take it (see [`Action::BridgeAttest`]).
///
/// `amount` is the gross figure the guardians signed, not `amount - relayer_fee`: the wire
/// format's fee pays whoever relays the attestation, and on a shielded chain the submitter has
/// no identity to pay. Minting the gross keeps what the pool holds equal to what the source
/// chain locked; netting it would burn the difference forever.
fn deposit_commitment(
    recipient: &ShieldedAddress,
    amount: u64,
    asset: u32,
    time: u32,
    r: &Word8,
    executor: &dyn ConfidentialExecutor,
) -> Word8 {
    executor.note_commitment(&recipient.pk, &DEPOSIT_FROM, amount, asset, time, r)
}

/// What an attestation's payload would deposit, from the wire bytes alone: the asset it names
/// and the amount, with no reference to any state and no signature work.
///
/// `None` for a guardian-set rotation, which moves no value, for bytes that do not decode, and
/// for an amount no note could hold — all of which [`validate`] refuses before a transaction is
/// admitted, so on a *committed* transaction this only ever answers `Some`.
pub fn attested_transfer(attestation: &[u8]) -> Option<(AssetId, u64)> {
    let att = Attestation::decode(attestation).ok()?;
    let Payload::Transfer(t) = Payload::decode(&att.body.payload).ok()? else {
        return None;
    };
    let amount = u64::try_from(t.amount_u128()?).ok()?;
    Some((asset_id(t.token_chain, &t.token_address), amount))
}

/// The deposit note a `BridgeAttest` appended — the commitment and the envelope sealed against
/// it — recomputed from the transaction and the asset registry.
///
/// A deposit's commitment is the one note commitment the wire does not carry
/// ([`Transaction::commitments`]): the chain computes it so that a submitter cannot choose the
/// amount or the owner. A node that indexes every note for wallets to scan has to compute it
/// the same way, and this is that one function.
///
/// `bridge` may be the state from either side of the transaction: an asset index is assigned
/// once and never changes, so the registry *after* the attestation answers exactly as the
/// registry before it did.
///
/// `None` for any other action, and for an attestation that deposits nothing (a rotation) or
/// that does not decode — the latter being a torn block, not a live possibility, for a
/// transaction that was committed.
pub fn deposit_note(
    tx: &Transaction,
    bridge: &BridgeState,
    executor: &dyn ConfidentialExecutor,
) -> Option<(Word8, Envelope)> {
    let Action::BridgeAttest { attestation, recipient, r, time, envelope } = &tx.action else {
        return None;
    };
    let (asset, amount) = attested_transfer(attestation)?;
    let index = bridge.asset_index(&asset)?;
    Some((deposit_commitment(recipient, amount, index, *time, r, executor), envelope.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{
        asset_id, digest, guardian_address, sign_digest, Attestation, Body, BridgeConfig, BridgeState, Payload,
        Transfer, CHAIN_RAND,
    };
    use crate::confidential::StubExecutor;
    use crate::crypto::{Address, Keypair};
    use crate::gas;
    use crate::ledger::TIME_WINDOW;
    use crate::notes::{Bundle, Envelope, ShieldedAddress};
    use crate::types::{Validator, ValidatorSet};

    const HC: Word8 = [11; 8];
    /// The canonical test token, native to chain 2, which registers as asset index 1.
    const TOKEN: [u8; 32] = [0xaa; 32];
    /// A well-formed EVM burn destination: 12 zero bytes then 20 address bytes (spec 3.5).
    const EVM_TO: [u8; 32] = {
        let mut t = [0u8; 32];
        let mut i = 12;
        while i < 32 {
            t[i] = 0x22;
            i += 1;
        }
        t
    };

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn proposer() -> Keypair {
        Keypair::from_seed([1; 32]).unwrap()
    }

    /// Six guardian secrets and the config naming their addresses, with chains 2..=5 registered
    /// as source emitters.
    fn cfg() -> (BridgeConfig, Vec<[u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (1u8..=6).map(|i| [i; 32]).collect();
        let config = BridgeConfig {
            emitter: [1; 32],
            guardians: secrets.iter().map(guardian_address).collect(),
            emitters: (2u16..=5).map(|c| (c, [c as u8; 32])).collect(),
        };
        (config, secrets)
    }

    /// A ledger at height 1 with a bridge, and the guardian secrets that can attest to it.
    fn ledger() -> (Ledger, Vec<[u8; 32]>) {
        let k = proposer();
        let set = ValidatorSet::new(vec![Validator { public_key: k.public_key().clone(), stake: 10 }]);
        let mut l = Ledger::new(7, HC, &set, &StubExecutor);
        let (config, secrets) = cfg();
        l.set_bridge(Some(BridgeState::from_config(&config)));
        l.set_height(1);
        l.set_timestamp_ms(1_000_000);
        (l, secrets)
    }

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes. It anchors
    /// to the newest recorded block-end root, not to `l.root()`: notes appended mid-block move
    /// the live root, and only a recorded root is an anchor (spec §7 item 4).
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64, asset: u32, burn: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: nfs,
            commitments: cms,
            fee,
            burn,
            asset,
            time: l.height() as u32,
            envelopes: [env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        b
    }

    /// The SHRUGG fee bundle a bridge transaction carries, paying `fee`.
    fn fee_bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Bundle {
        bundle(l, nfs, cms, fee, 0, 0)
    }

    fn recipient() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] }
    }

    /// Signs `body` with five of the six guardian secrets (a quorum) and encodes it.
    fn attest(secrets: &[[u8; 32]], body: Body) -> Vec<u8> {
        let d = digest(&body.encode());
        let signatures = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
        Attestation { guardian_set_index: 0, signatures, body }.encode()
    }

    /// An inbound transfer of `amount` (relayer fee `fee`) of [`TOKEN`] to `to`, emitted by
    /// chain 2's registered emitter. `sequence` distinguishes otherwise identical bodies.
    fn transfer(amount: u128, fee: u128, to: [u8; 32], sequence: u64) -> Body {
        Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: 2,
            emitter_address: [2; 32],
            sequence,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: TOKEN,
                token_chain: 2,
                to,
                to_chain: CHAIN_RAND,
                fee: Transfer::u256_from_u128(fee),
            })
            .encode(),
        }
    }

    /// The transaction a relayer submits for `attestation`, naming `to` as the recipient. Its
    /// fee bundle's four words are `seed..seed + 3`, so transactions with different seeds never
    /// collide on a nullifier or a commitment.
    fn attest_tx(l: &Ledger, attestation: Vec<u8>, to: ShieldedAddress, seed: u32) -> Transaction {
        Transaction::shielded(
            7,
            fee_bundle(l, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], gas::BUNDLE_BASE),
            Action::BridgeAttest { attestation, recipient: to, r: [7; 8], time: l.height() as u32, envelope: env() },
        )
    }

    /// Applies one attestation of `amount` to `recipient()`, registering [`TOKEN`] as asset 1.
    fn deposit(l: &mut Ledger, secrets: &[[u8; 32]], amount: u128, sequence: u64, seed: u32) -> Transaction {
        let a = attest(secrets, transfer(amount, 0, recipient().recipient_hash(), sequence));
        let tx = attest_tx(l, a, recipient(), seed);
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        tx
    }

    /// What the ledger must have computed for the deposit note of `amount` in asset `asset`.
    fn expected_cm(height: u32, amount: u64, asset: u32) -> Word8 {
        StubExecutor.note_commitment(&recipient().pk, &[0; 8], amount, asset, height, &[7; 8])
    }

    /// The whole deposit path: the guardians' amount, the registry's index and the recipient's
    /// key become one note the recipient can recompute and find in the tree.
    #[test]
    fn an_attestation_deposits_a_note_the_recipient_can_check() {
        let (mut l, secrets) = ledger();
        let tx = deposit(&mut l, &secrets, 1_000, 0, 20);
        let cm = expected_cm(1, 1_000, 1);
        assert!(l.has_commitment(&cm), "the deposit note is in the tree");
        // The fee bundle's two notes plus the deposit note.
        assert_eq!(l.next_index(), 3);
        let bridge = l.bridge().unwrap();
        assert_eq!(bridge.asset_index(&asset_id(2, &TOKEN)), Some(1), "first sighting registers the asset");
        assert_eq!(bridge.spent.len(), 1, "the digest is consumed");
        // The relayer fee has no payee on a shielded chain, so the gross amount is deposited:
        // a second attestation of the same amount with a fee produces the same note.
        let a = attest(&secrets, transfer(1_000, 250, recipient().recipient_hash(), 1));
        let with_fee = attest_tx(&l, a, recipient(), 30);
        assert_eq!(l.validate(&with_fee, &StubExecutor), Err(TxError::CommitmentExists(cm)));
        assert_ne!(tx.hash(), with_fee.hash());
    }

    /// The deposit note's `time` word is the one the action published, never the height the
    /// transaction happened to be applied at. It has to be: the recipient's envelope is sealed
    /// against a commitment the depositor computed before submitting, and nobody can predict the
    /// block their transaction lands in. The two are deliberately different here.
    #[test]
    fn attest_note_uses_the_action_time_not_the_apply_height() {
        let (mut l, secrets) = ledger();
        l.set_height(9);
        l.record_anchor(9);
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let mut tx = attest_tx(&l, a, recipient(), 20);
        let Action::BridgeAttest { time, .. } = &mut tx.action else { panic!("an attest") };
        *time = 5;
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm(5, 1_000, 1)), "the note the action's time names");
        assert!(!l.has_commitment(&expected_cm(9, 1_000, 1)), "and not the one the apply height would");
        // The recompute-after-the-fact path reads the same word off the committed action, so a
        // node's note index agrees with the tree whatever height it asks about.
        let (cm, _) = deposit_note(&tx, l.bridge().unwrap(), &StubExecutor).expect("a transfer deposits a note");
        assert_eq!(cm, expected_cm(5, 1_000, 1));
    }

    /// `time` buys the depositor a predictable commitment, so it gets the window rule a bundle's
    /// `time` gets — and no more: a note stamped in the future, or older than the window, is
    /// refused before the attestation is even decoded.
    #[test]
    fn attest_time_outside_the_window_is_refused() {
        let (mut l, secrets) = ledger();
        let height = TIME_WINDOW + 20;
        l.set_height(height);
        l.record_anchor(height);
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let tx = attest_tx(&l, a, recipient(), 20);
        let at = |time: u32| {
            let mut tx = tx.clone();
            let Action::BridgeAttest { time: t, .. } = &mut tx.action else { panic!("an attest") };
            *t = time;
            l.validate(&tx, &StubExecutor)
        };
        let oldest = (height - TIME_WINDOW) as u32;
        assert_eq!(at(height as u32 + 1), Err(TxError::TimeOutOfWindow { time: height as u32 + 1, height }));
        assert_eq!(at(oldest - 1), Err(TxError::TimeOutOfWindow { time: oldest - 1, height }));
        assert_eq!(at(oldest), Ok(()), "exactly height - TIME_WINDOW is inside it");
        assert_eq!(at(height as u32), Ok(()));
        // Before any decode: a `time` outside the window is refused even with attestation bytes
        // no decoder would accept, which the same transaction proves would otherwise be reached.
        let junk = |time: u32| {
            let mut tx = tx.clone();
            let Action::BridgeAttest { attestation, time: t, .. } = &mut tx.action else { panic!("an attest") };
            *attestation = vec![0xff; 32];
            *t = time;
            l.validate(&tx, &StubExecutor)
        };
        assert_eq!(junk(height as u32 + 1), Err(TxError::TimeOutOfWindow { time: height as u32 + 1, height }));
        assert!(matches!(junk(height as u32), Err(TxError::Bridge(_))), "the decode is what refuses it now");
    }

    /// What a node's note index needs: the deposit note recomputed from the committed
    /// transaction alone, matching the one the ledger appended. The registry *after* the
    /// attestation is what a node has on disk, and it answers the same as the one before.
    #[test]
    fn a_deposit_note_is_recomputable_from_the_committed_transaction() {
        let (mut l, secrets) = ledger();
        let tx = deposit(&mut l, &secrets, 1_000, 0, 20);
        let bridge = l.bridge().unwrap();
        let (cm, envelope) = deposit_note(&tx, bridge, &StubExecutor).expect("a transfer deposits a note");
        assert_eq!(cm, expected_cm(1, 1_000, 1));
        assert!(l.has_commitment(&cm));
        assert_eq!(envelope, env(), "paired with the envelope that opens it");

        // A guardian-set rotation deposits nothing, and neither does any other action.
        let rotation = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: CHAIN_RAND,
            emitter_address: crate::bridge::GOVERNANCE_EMITTER,
            sequence: 9,
            consistency_level: 0,
            payload: Payload::GuardianSetUpgrade(crate::bridge::GuardianSetUpgrade {
                new_index: 1,
                keys: vec![guardian_address(&[9; 32])],
            })
            .encode(),
        };
        let upgrade = attest_tx(&l, attest(&secrets, rotation), recipient(), 30);
        assert_eq!(deposit_note(&upgrade, bridge, &StubExecutor), None);
        let plain = Transaction { chain_id: 7, bundle: None, action: Action::None };
        assert_eq!(deposit_note(&plain, bridge, &StubExecutor), None);
    }

    /// The 32-byte `to` field binds the deposit to one shielded address. A submitter who swaps
    /// in their own address is refused rather than handed someone else's deposit.
    #[test]
    fn an_attestation_for_a_different_recipient_is_refused() {
        let (l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let thief = ShieldedAddress { pk: [9; 8], kem_ek: vec![6; 32] };
        let tx = attest_tx(&l, a, thief, 20);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::BridgeRecipientMismatch));
    }

    /// A digest is spendable once: the same attestation resubmitted — in a fresh transaction,
    /// so nothing else refuses it first — is refused by the bridge's consumed-digest set.
    #[test]
    fn a_replayed_attestation_is_refused() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let again = attest_tx(&l, a, recipient(), 30);
        assert_eq!(l.validate(&again, &StubExecutor), Err(TxError::Bridge(BridgeError::Replay)));
    }

    /// A burn transaction whose asset bundle carries a proof that would never verify, so any
    /// error other than `InvalidBundleProof` proves the check that produced it ran first.
    fn burn_tx(l: &Ledger, asset: u32, amount: u64, relayer_fee: u64, mutate: impl FnOnce(&mut Bundle)) -> Transaction {
        burn_tx_paying(l, asset, amount, relayer_fee, BURN_FEE, mutate)
    }

    /// The fee a valid burn's outer bundle pays: the bundle base for each of its two bundles.
    const BURN_FEE: u64 = 2 * gas::BUNDLE_BASE;

    /// [`burn_tx`] with the outer bundle's fee chosen, for the fee-floor test.
    fn burn_tx_paying(
        l: &Ledger,
        asset: u32,
        amount: u64,
        relayer_fee: u64,
        fee: u64,
        mutate: impl FnOnce(&mut Bundle),
    ) -> Transaction {
        let mut asset_bundle = bundle(l, [[40; 8], [41; 8]], [[42; 8], [43; 8]], 0, asset, amount + relayer_fee);
        mutate(&mut asset_bundle);
        Transaction::shielded(
            7,
            fee_bundle(l, [[44; 8], [45; 8]], [[46; 8], [47; 8]], fee),
            Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain: 2, to: EVM_TO },
        )
    }

    /// Spec §7 item 3 charges the bundle base per verified bundle, and a burn has two. The
    /// floor is checked at step 3, before the anchor, the asset bundle's shape or any proof —
    /// so an underpaying burn is refused on a comparison even with a broken asset bundle.
    #[test]
    fn a_burn_pays_for_both_of_its_bundles() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let short = burn_tx_paying(&l, 1, 400, 100, gas::BUNDLE_BASE, |b| b.proof = vec![0xff; 16]);
        assert_eq!(
            l.validate(&short, &StubExecutor),
            Err(TxError::FeeTooLow { min: 2 * gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE })
        );
        // One unit short is still short; exactly the floor is accepted.
        let short = burn_tx_paying(&l, 1, 400, 100, BURN_FEE - 1, |_| {});
        assert_eq!(
            l.validate(&short, &StubExecutor),
            Err(TxError::FeeTooLow { min: 2 * gas::BUNDLE_BASE, fee: BURN_FEE - 1 })
        );
        assert_eq!(l.validate(&burn_tx_paying(&l, 1, 400, 100, BURN_FEE, |_| {}), &StubExecutor), Ok(()));
    }

    /// Spec §7's order across two bundles: an asset bundle that does not match the burn the
    /// action declares is refused on a comparison, before anything verifies a proof. Each case
    /// hands the asset bundle an unverifiable proof, so reaching step 9 would be visible.
    #[test]
    fn a_mismatched_asset_bundle_is_refused_before_any_proof_work() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let break_proof = |b: &mut Bundle| b.proof = vec![0xff; 16];

        // wrong asset: the bundle burns asset 2, the action declares 1
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.asset = 2;
            break_proof(b);
        });
        assert_eq!(
            l.validate(&t, &StubExecutor),
            Err(TxError::BurnAssetMismatch { expected: 1, actual: 2 })
        );
        // a fee on the asset bundle: the fee is SHRUGG and is paid by the other bundle
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.fee = 7;
            break_proof(b);
        });
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BurnAssetBundleFee(7)));
        // the burn must be exactly amount + relayer_fee
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.burn = 499;
            break_proof(b);
        });
        assert_eq!(
            l.validate(&t, &StubExecutor),
            Err(TxError::BurnAmountMismatch { expected: 500, actual: 499 })
        );
        // an unregistered asset is the bridge's own refusal, still before the proof
        let t = burn_tx(&l, 9, 400, 100, break_proof);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Bridge(BridgeError::UnknownAsset)));
        // and with every cheap check passing, the broken proof is what is left to refuse
        let t = burn_tx(&l, 1, 400, 100, break_proof);
        assert!(matches!(l.validate(&t, &StubExecutor), Err(TxError::InvalidBundleProof(_))));
        // the four nullifiers and the four commitments must each differ across the two bundles
        let t = burn_tx(&l, 1, 400, 100, |_| {});
        let Action::BridgeBurn { asset_bundle, .. } = &t.action else { panic!("a burn") };
        let (shared_nf, shared_cm) = (asset_bundle.nullifiers[0], asset_bundle.commitments[1]);
        let mut clash = t.clone();
        clash.bundle.as_mut().unwrap().nullifiers[0] = shared_nf;
        assert_eq!(l.validate(&clash, &StubExecutor), Err(TxError::DuplicateNullifierInBundle));
        let mut clash = t.clone();
        clash.bundle.as_mut().unwrap().commitments[1] = shared_cm;
        assert_eq!(l.validate(&clash, &StubExecutor), Err(TxError::DuplicateCommitmentInBundle));
    }

    /// The happy path: both bundles are admitted, four nullifiers are spent, four commitments
    /// are appended, and the bridge holds an outbound message stamped with this transaction.
    #[test]
    fn a_two_bundle_burn_spends_four_nullifiers_and_records_the_message() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let t = burn_tx(&l, 1, 400, 100, |_| {});
        l.apply_tx(&t, &proposer().address(), &StubExecutor).unwrap();
        for nf in [[40; 8], [41; 8], [44; 8], [45; 8]] {
            assert!(l.is_spent(&nf), "{nf:?} is spent");
        }
        for cm in [[42; 8], [43; 8], [46; 8], [47; 8]] {
            assert!(l.has_commitment(&cm), "{cm:?} is in the tree");
        }
        let bridge = l.bridge().unwrap();
        assert_eq!(bridge.burn_sequence, 1);
        let record = &bridge.burns[&0];
        assert_eq!(record.tx, t.hash(), "the transaction hash stands in for the absent sender");
        assert_eq!(record.height, 1);
        // Replay: the asset bundle's nullifiers are spent now.
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Spent([44; 8])));
    }

    /// Both actions are inadmissible on a chain whose genesis has no `bridge` section, and
    /// nothing this module owns can reach a bridge that is not there.
    #[test]
    fn the_bridge_actions_are_refused_without_a_bridge() {
        let (mut l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let tx = attest_tx(&l, a, recipient(), 20);
        let burn = burn_tx(&l, 1, 400, 100, |_| {});
        l.set_bridge(None);
        for t in [&tx, &burn] {
            assert_eq!(l.validate(t, &StubExecutor), Err(TxError::Bridge(BridgeError::Disabled)));
        }
    }

    /// Fail closed: an action this module does not own is refused rather than waved through,
    /// and `validate` and `apply` answer alike. Only a dispatch bug can get here, which is
    /// exactly the case where `Ok(())` would silently skip the action's real rules.
    #[test]
    fn a_non_bridge_action_routed_here_is_refused() {
        let (mut l, _) = ledger();
        let tx = Transaction { chain_id: 7, bundle: None, action: Action::None };
        for a in [Action::None, Action::Bond { validator: Address([1; 32]), amount: 1, registration: None }] {
            assert_eq!(validate(&l, &tx, &a, &StubExecutor), Err(TxError::UnsupportedAction("bridge")), "{a:?}");
            assert_eq!(apply(&mut l, &tx, &a, &StubExecutor, None), Err(TxError::UnsupportedAction("bridge")), "{a:?}");
        }
    }
}
