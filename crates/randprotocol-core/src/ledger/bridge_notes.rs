//! The bridge as notes: `BridgeAttest` and `BridgeBurn` (phase S3, spec §10).
//!
//! A bridged holding on the shielded chain is a note whose `asset` word is the token registry's
//! dense index for that asset ([`super::tokens`], the one registry for bridged and native assets
//! alike), so the two bridge actions are the two places value crosses between the pool and the
//! bridge — and the two places a bridged token's `total_supply` moves:
//!
//! - **`BridgeAttest`** turns a guardian-signed transfer into one deposit note. The amount is
//!   public in that transaction, like a `Mint` or a `Withdraw`; the note then sits in the tree
//!   indistinguishable from every other. The chain — not the submitter — computes the
//!   commitment, from the amount the guardians signed and the recipient the transaction names,
//!   so a submitter cannot mint a note for an amount or an owner the attestation does not say.
//! - **`BridgeBurn`** sends value the other way. A bundle balances one asset and the fee is
//!   always RAND, so a burn is the chain's only two-bundle transaction: the transaction's own
//!   bundle pays the fee in RAND, and the action carries an *asset* bundle that burns exactly
//!   `amount` of the bridged asset — the wire format's `relayer_fee` is a portion of that
//!   amount, paid on the destination chain. Both bundles go through the same admission.
//!
//! The bridge's own public state lives in [`crate::bridge::BridgeState`] and is committed by
//! the fifth component of the state root; this module is only the ledger's half.

use super::tokens::{TokenError, TokenRegistry};
use super::{Ledger, TxError};
use crate::bridge::{Attestation, AttestOutcome, AttestPlan, BridgeError, CheckedAttestation, Payload};
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
        Action::BridgeAttest { attestation, recipient, r, time, asset, envelope: _ } => {
            // The cheapest check this action has, and the one that must run before any decode or
            // signature recovery: the deposit note is stamped with this `time` rather than the
            // apply height (see [`Action::BridgeAttest`]), so it gets the window a bundle's
            // `time` gets. A comparison, bought before an attestation buys any work.
            ledger.check_time(*time)?;
            let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            // The one asset registry (the RPL token standard). A chain with a `bridge` section
            // always has a `tokens` section — genesis refuses the pair apart
            // (`GenesisError::BridgeNeedsTokens`) — so this is the same "not on this chain"
            // verdict as the line above, named for the half that is missing.
            let tokens = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
            // The `asset` compare, bought before the quorum. The action names the index its
            // envelope was sealed for, and `check_attest` below would not report it until after a
            // quorum of secp256k1 recoveries — which is exactly the cost that method's own
            // contract promises nothing unverified can buy. So the index is resolved here instead,
            // from the wire bytes and the registry alone: one extra decode of an already
            // size-capped attestation, no signature work, and the same two functions the mempool
            // screens pooled attests with (`Mempool::still_applies`).
            //
            // Silent on anything this pair cannot answer — a rotation, bytes that do not decode,
            // an amount no note could hold, a token nobody listed — each of which is
            // `check_attest`'s refusal to make and reports a better error than a mismatched index
            // would.
            if let Some((chain, token, _)) = attested_transfer(attestation) {
                if let Some(index) = tokens.bridged(chain, &token).map(|info| info.index) {
                    if index != *asset {
                        return Err(TxError::AttestAssetMismatch { expected: index, actual: *asset });
                    }
                }
            }
            // The attestation's size cap ran at step 1, before this decode. `check_attest` is
            // itself ordered cheap-before-expensive: it decodes, resolves the guardian set,
            // rejects a replayed digest and checks the payload before recovering a signature.
            let checked = bridge.check_attest(tokens, attestation, ledger.now_secs()).map_err(TxError::Bridge)?;
            if let AttestPlan::Transfer(t) = checked.plan() {
                // Redundant by construction with the pre-screen above — both read the same asset
                // id out of the same bytes and the same registry — and kept because it is a
                // single integer compare and it is *this* index that `apply` stamps into the note
                // (`AttestPlan::Transfer`'s own `index`). If the two paths ever drifted, a
                // deposit would land under a word the envelope was not sealed for, which is the
                // whole failure this field exists to prevent; free is a good price for ruling it
                // out.
                if t.index != *asset {
                    return Err(TxError::AttestAssetMismatch { expected: t.index, actual: *asset });
                }
                // No supply check here any more: the backing's `locked` and the token's supply
                // both take the gross amount at `apply`, and everything that could refuse that
                // move was decided inside `check_attest` (`TokenRegistry::check_lock`, run
                // before the guardian quorum). `apply` writes a deposit note before it locks, so
                // a refusal there would be a half-applied transaction — and the check is a
                // checked add, not a saturating one, because a bridged supply that stopped
                // counting would stop matching what the source chains have locked.

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
                let cm = deposit_commitment(recipient, t.amount, t.index, *time, r, executor);
                let in_fee_bundle = tx.bundle.as_ref().is_some_and(|b| b.commitments.contains(&cm));
                if ledger.has_commitment(&cm) || in_fee_bundle {
                    return Err(TxError::CommitmentExists(cm));
                }
            }
            Ok(Some(checked))
        }
        Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, token, to } => {
            let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            let tokens = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
            // Cheap before expensive (spec §7), and across *both* bundles: everything here is
            // a comparison or a set lookup, and it all runs before either bundle's proof is
            // verified — the fee bundle's at step 9 of `validate_inner`, the asset bundle's at
            // the end of this arm. A burn that names the wrong asset costs no verification.
            //
            // The two-bundle rule itself is [`super::tokens::check_asset_bundle`], shared with
            // the RPL transfer and holder burn, which have exactly this shape: the bundle's asset
            // matches, its fee is zero, it burns what the action declares, it shares no word with
            // the fee bundle, and `check_bundle`. A burn's `burn == amount` is this action's own
            // rule inside it: the wire format's `fee` is a *portion* of `amount` — that is what
            // `fee <= amount` means (`check_burn`, and inbound `check_attest` reads it the same
            // way) — so the release contract pays `amount - fee` to `to` and `fee` to the relayer,
            // releasing `amount` in total. Burning `amount + relayer_fee` would destroy more than
            // the far side ever releases and strand the difference in the source-chain contract
            // forever.
            super::tokens::check_asset_bundle(ledger, tx, asset_bundle, *asset, *amount)?;
            // The release `apply` makes, decided here for the same reason the deposit's lock is:
            // apply writes the asset bundle's notes before it touches the registry.
            // `check_burn` ends in `TokenRegistry::check_release`, which is exactly what the
            // apply step's `release` would refuse — the named pair being a backing of this token
            // at all, and that backing holding at least `amount`. A burn of more of one coin
            // than its own source contract is holding would ask that contract to release value it
            // never took in, so it is refused rather than clamped, even when the token's whole
            // supply (every other coin's `locked` included) would cover it. Still a comparison,
            // and still before the asset bundle's proof.
            bridge
                .check_burn(tokens, *asset, *amount, *to_chain, token, to, *relayer_fee)
                .map_err(TxError::Bridge)?;
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
            // Consumes the digest. It registers nothing — a bridged token is listed before any
            // attestation of it is admissible — and does no signature work: the quorum was
            // verified once, in `validate`, and this is the token that proves it.
            match bridge.apply_attest(checked) {
                AttestOutcome::Minted(t) => {
                    let cm = deposit_commitment(recipient, t.amount, t.index, *time, r, executor);
                    ledger.deposit(cm, executor)?;
                    // The deposited note is new supply of that token, and the coin the
                    // attestation named is what now backs it: `lock` moves the backing's
                    // `locked` and the token's `total_supply` together, which is what keeps
                    // `total_supply == Σ locked` true (spec §12). The gross amount the guardians
                    // signed is what the note carries — the relayer fee is a portion of it and is
                    // paid on the far side. `check_attest` ruled out every refusal `lock` has, so
                    // this cannot fail on a transaction that was admitted.
                    //
                    // The registry's refusal is reported through the bridge, exactly as the
                    // validate half reports it (`check_attest` ends in `TokenRegistry::check_lock`
                    // and carries its error as `BridgeError::Token`). One shape for one refusal:
                    // the unreachable path and the reachable one must not print differently.
                    ledger
                        .tokens_mut()
                        .ok_or(TxError::Token(TokenError::Disabled))?
                        .lock(t.index, t.chain, &t.token, t.amount)
                        .map_err(|e| TxError::Bridge(BridgeError::Token(e)))?;
                }
                // Governance only: a rotation moves guardian keys and no value.
                AttestOutcome::GuardianSetUpgraded(_) => {}
            }
            Ok(())
        }
        Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, token, to } => {
            // The fee bundle's notes were written by `apply_tx`'s common path; the asset
            // bundle's are written here, through that same path, so a burn spends four
            // nullifiers and appends four commitments in total. The asset bundle's fee is zero,
            // so no proposer reward follows from it.
            ledger.apply_bundle_notes(asset_bundle, executor);
            let (height, timestamp) = (ledger.height(), ledger.now_secs() as u32);
            let tx_hash = tx.hash();
            // The bridge to write and the registry to read in one borrow: the outbound message's
            // `(chain, token)` is the burned token's own mint authority.
            let (bridge, tokens) = ledger.bridge_and_tokens_mut()?;
            // The record's sender slot is the transaction hash: a burn is funded by notes, so
            // there is no sender identity to write there.
            bridge
                .apply_burn(tokens, tx_hash, *asset, *amount, *to_chain, *token, *to, *relayer_fee, height, timestamp)
                .map_err(TxError::Bridge)?;
            // What the asset bundle destroyed leaves the named backing and the token's supply
            // together, so each source contract's locked amount stays equal to what this chain
            // says it is holding — and their sum stays the token's supply (spec §12).
            // `validate` ruled out every refusal `release` has, so this cannot fail on a
            // transaction that was admitted — and if it somehow did, it says so in the shape
            // `validate` would have said it in (`BridgeError::Token`, through `check_burn`'s
            // `check_release`) rather than in a second shape for the same refusal.
            ledger
                .tokens_mut()
                .ok_or(TxError::Token(TokenError::Disabled))?
                .release(*asset, *to_chain, token, *amount, *relayer_fee)
                .map_err(|e| TxError::Bridge(BridgeError::Token(e)))?;
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
///
/// Public because every one of these five inputs is public on the wire, so a recipient can
/// rebuild the note the chain appended without opening any envelope — which is what the node's
/// `tx_json` renders the commitment from and what a wallet recovers a griefed deposit with
/// (`docs/bridge.md` §8).
pub fn deposit_commitment(
    recipient: &ShieldedAddress,
    amount: u64,
    asset: u32,
    time: u32,
    r: &Word8,
    executor: &dyn ConfidentialExecutor,
) -> Word8 {
    executor.note_commitment(&recipient.pk, &DEPOSIT_FROM, amount, asset, time, r)
}

/// What an attestation's payload would deposit, from the wire bytes alone: the source
/// `(chain, token)` pair it names and the amount, with no reference to any state and no
/// signature work.
///
/// The pair rather than a hash of it: since one bridged token has many backings (spec §12) the
/// registry is keyed on the pair itself ([`TokenRegistry::bridged`]), and the pair is also what
/// [`crate::bridge::BridgeError::UnlistedToken`] has to report.
///
/// `None` for a guardian-set rotation, which moves no value, for bytes that do not decode, and
/// for an amount no note could hold — all of which [`validate`] refuses before a transaction is
/// admitted, so on a *committed* transaction this only ever answers `Some`.
pub fn attested_transfer(attestation: &[u8]) -> Option<(u16, [u8; 32], u64)> {
    let att = Attestation::decode(attestation).ok()?;
    let Payload::Transfer(t) = Payload::decode(&att.body.payload).ok()? else {
        return None;
    };
    let amount = u64::try_from(t.amount_u128()?).ok()?;
    Some((t.token_chain, t.token_address, amount))
}

/// The deposit note a `BridgeAttest` appended — the commitment and the envelope sealed against
/// it — recomputed from the transaction and the asset registry.
///
/// A deposit's commitment is the one note commitment the wire does not carry
/// ([`Transaction::commitments`]): the chain computes it so that a submitter cannot choose the
/// amount or the owner. A node that indexes every note for wallets to scan has to compute it
/// the same way, and this is that one function.
///
/// `tokens` may be the registry from either side of the transaction: a listed token's index is
/// assigned once and never changes, and an attestation registers nothing, so the registry
/// *after* the attestation answers exactly as the registry before it did.
///
/// It takes the registry rather than the bridge because that is where a note's `asset` word now
/// comes from (the RPL token standard); the bridge holds no registry of its own to consult.
///
/// `None` for any other action, and for an attestation that deposits nothing (a rotation) or
/// that does not decode — the latter being a torn block, not a live possibility, for a
/// transaction that was committed.
pub fn deposit_note(
    tx: &Transaction,
    tokens: &TokenRegistry,
    executor: &dyn ConfidentialExecutor,
) -> Option<(Word8, Envelope)> {
    let Action::BridgeAttest { attestation, recipient, r, time, asset: _, envelope } = &tx.action else {
        return None;
    };
    let (chain, token, amount) = attested_transfer(attestation)?;
    let index = tokens.bridged(chain, &token)?.index;
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
    use crate::ledger::ValidatorEntry;

    const HC: Word8 = [11; 8];
    /// The canonical test token, native to chain 2, listed at genesis as asset index 1.
    const TOKEN: [u8; 32] = [0xaa; 32];
    /// A second token of the same chain, listed second and so asset index 2.
    const OTHER_TOKEN: [u8; 32] = [0xbb; 32];
    /// A chain-2 token that is deliberately *not* listed, for the refusal an unlisted token gets.
    const UNLISTED_TOKEN: [u8; 32] = [0xcc; 32];
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

    /// The registry a bridged chain's genesis leaves behind: [`TOKEN`] at index 1 and
    /// [`OTHER_TOKEN`] at index 2, both `Bridge`-authority tokens of chain 2 at eight decimals.
    /// [`UNLISTED_TOKEN`] is deliberately absent — listing is what makes a token depositable.
    fn token_registry() -> TokenRegistry {
        let mut t = TokenRegistry::new(1_000_000_000);
        for (i, token) in [TOKEN, OTHER_TOKEN].into_iter().enumerate() {
            let index = t
                .register(
                    crate::ledger::tokens::bridged_asset_id("Tether USD", "zUSDT", &token),
                    "Tether USD".into(),
                    "zUSDT".into(),
                    8,
                    crate::ledger::tokens::MintAuthority::Bridge {
                        backings: vec![crate::ledger::tokens::Backing { chain: 2, token, decimals: 8, locked: 0 }],
                    },
                    0,
                )
                .expect("a fresh listing");
            assert_eq!(index as usize, i + 1, "listing order is index order");
        }
        t
    }

    /// A ledger at height 1 with a bridge, and the guardian secrets that can attest to it.
    fn ledger() -> (Ledger, Vec<[u8; 32]>) {
        let k = proposer();
        // Phase S2's v2 register leaf; nothing in this module reads a field of it beyond the
        // proposer lookup `apply_tx` does.
        let entry = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 10,
            pending: Vec::new(),
            rewards: 0,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
        };
        let mut l = Ledger::new(7, HC, [(k.address(), entry)].into_iter().collect(), &StubExecutor);
        let (config, secrets) = cfg();
        l.set_bridge(Some(BridgeState::from_config(&config)));
        // A bridge without a token registry can deposit nothing: the two sections ride the same
        // genesis gate, and the index a note carries is the registry's.
        l.set_tokens(Some(token_registry()));
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

    /// The RAND fee bundle a bridge transaction carries, paying `fee`.
    fn fee_bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Bundle {
        bundle(l, nfs, cms, fee, 0, 0)
    }

    fn recipient() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] }
    }

    /// The same `body` signed by five keys that are in no guardian set. Everything about it
    /// decodes and passes every cheap check; only the quorum — the expensive half, one secp256k1
    /// recovery per signature — can tell that it is worthless.
    fn misattest(body: Body) -> Vec<u8> {
        let d = digest(&body.encode());
        let signatures = (0..5u8).map(|i| sign_digest(&[0x90 + i; 32], i, &d)).collect();
        Attestation { guardian_set_index: 0, signatures, body }.encode()
    }

    /// Signs `body` with five of the six guardian secrets (a quorum) and encodes it.
    fn attest(secrets: &[[u8; 32]], body: Body) -> Vec<u8> {
        let d = digest(&body.encode());
        let signatures = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
        Attestation { guardian_set_index: 0, signatures, body }.encode()
    }

    /// An inbound transfer of `amount` (relayer fee `fee`) of `token` to `to`, emitted by
    /// chain 2's registered emitter. `sequence` distinguishes otherwise identical bodies.
    fn transfer_of(token: [u8; 32], amount: u128, fee: u128, to: [u8; 32], sequence: u64) -> Body {
        Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: 2,
            emitter_address: [2; 32],
            sequence,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: token,
                token_chain: 2,
                to,
                to_chain: CHAIN_RAND,
                fee: Transfer::u256_from_u128(fee),
            })
            .encode(),
        }
    }

    /// [`transfer_of`] for the canonical [`TOKEN`].
    fn transfer(amount: u128, fee: u128, to: [u8; 32], sequence: u64) -> Body {
        transfer_of(TOKEN, amount, fee, to, sequence)
    }

    /// The `asset` word an honest submitter fills in: the index the registry says this
    /// attestation's token deposits under, or 0 for a rotation (which deposits nothing and binds
    /// no index) and for a token nobody listed (which deposits nothing either — the attestation
    /// is refused).
    fn expected_index(l: &Ledger, attestation: &[u8]) -> u32 {
        attested_transfer(attestation)
            .and_then(|(chain, token, _)| l.tokens().and_then(|t| t.bridged(chain, &token)).map(|info| info.index))
            .unwrap_or(0)
    }

    /// The transaction a relayer submits for `attestation`, naming `to` as the recipient and the
    /// index the ledger would deposit under. Its fee bundle's four words are `seed..seed + 3`, so
    /// transactions with different seeds never collide on a nullifier or a commitment.
    fn attest_tx(l: &Ledger, attestation: Vec<u8>, to: ShieldedAddress, seed: u32) -> Transaction {
        let asset = expected_index(l, &attestation);
        Transaction::shielded(
            7,
            fee_bundle(l, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], gas::BUNDLE_BASE),
            Action::BridgeAttest {
                attestation,
                recipient: to,
                r: [7; 8],
                time: l.height() as u32,
                asset,
                envelope: env(),
            },
        )
    }

    /// The same transaction with the `asset` word overwritten — a submitter that named an index
    /// other than the one its deposit will get.
    fn naming_asset(mut tx: Transaction, asset: u32) -> Transaction {
        let Action::BridgeAttest { asset: a, .. } = &mut tx.action else { panic!("an attest") };
        *a = asset;
        tx
    }

    /// Applies one attestation of `amount` of [`TOKEN`] — asset 1 — to `recipient()`.
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
    /// key become one note the recipient can recompute and find in the tree — and the token's
    /// supply moves by the gross amount, so what this chain says exists equals what the source
    /// chain has locked.
    #[test]
    fn an_attestation_deposits_a_note_the_recipient_can_check() {
        let (mut l, secrets) = ledger();
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 0, "nothing bridged yet");
        let tx = deposit(&mut l, &secrets, 1_000, 0, 20);
        let cm = expected_cm(1, 1_000, 1);
        assert!(l.has_commitment(&cm), "the deposit note is in the tree");
        // The fee bundle's two notes plus the deposit note.
        assert_eq!(l.next_index(), 3);
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 1_000, "the gross amount is new supply");
        let bridge = l.bridge().unwrap();
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
        // The same note, named before the transaction is applied: this is what a mempool claims
        // for an attest (`Ledger::derived_commitment`, one derivation for a withdraw and an attest
        // alike), and it reads the registry rather than the action's `asset` word.
        assert_eq!(l.derived_commitment(&tx.action, &StubExecutor), Some(expected_cm(5, 1_000, 1)));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm(5, 1_000, 1)), "the note the action's time names");
        assert!(!l.has_commitment(&expected_cm(9, 1_000, 1)), "and not the one the apply height would");
        // The recompute-after-the-fact path reads the same word off the committed action, so a
        // node's note index agrees with the tree whatever height it asks about.
        let (cm, _) = deposit_note(&tx, l.tokens().unwrap(), &StubExecutor).expect("a transfer deposits a note");
        assert_eq!(cm, expected_cm(5, 1_000, 1));
    }

    /// The size cap reaches the *pre-validation* derivation too. `derived_commitment` is what a
    /// mempool calls before it validates anything — it has to know what note a transaction would
    /// create in order to decide whether the transaction is worth validating — so an attestation
    /// over the cap must not buy a decode there either. Admission refuses it at step 1 regardless
    /// (`TxError::AttestationTooLarge`), which is what makes dropping the claim safe.
    #[test]
    fn an_oversized_attestation_derives_no_note() {
        let (l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let tx = attest_tx(&l, a, recipient(), 20);
        assert!(l.derived_commitment(&tx.action, &StubExecutor).is_some(), "the admissible one names its note");

        // Bytes that really do decode — the same body with its quorum's first signature repeated
        // to the codec's 255-signature ceiling — so what the check stops is the decode itself and
        // not a parse failure standing in for it.
        let body = transfer(1_000, 0, recipient().recipient_hash(), 0);
        let d = digest(&body.encode());
        let one = sign_digest(&secrets[0], 0, &d);
        let big = Attestation { guardian_set_index: 0, signatures: vec![one; 250], body }.encode();
        assert!(big.len() > gas::MAX_ATTESTATION_BYTES, "{} bytes", big.len());
        assert!(Attestation::decode(&big).is_ok(), "and they parse, which is the work being refused");
        assert!(attested_transfer(&big).is_some(), "all the way to a transfer");

        let mut oversized = tx.clone();
        let Action::BridgeAttest { attestation, .. } = &mut oversized.action else { panic!("an attest") };
        *attestation = big;
        assert_eq!(l.derived_commitment(&oversized.action, &StubExecutor), None, "over the cap, so no claim");
        assert_eq!(l.validate(&oversized, &StubExecutor), Err(TxError::AttestationTooLarge));
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
        let tokens = l.tokens().unwrap();
        let (cm, envelope) = deposit_note(&tx, tokens, &StubExecutor).expect("a transfer deposits a note");
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
        assert_eq!(deposit_note(&upgrade, tokens, &StubExecutor), None);
        let plain = Transaction { chain_id: 7, bundle: None, action: Action::None };
        assert_eq!(deposit_note(&plain, tokens, &StubExecutor), None);
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

    /// The index a deposit is given is state, and the action has to name it: an envelope is sealed
    /// against a commitment whose `asset` word is that index, so a transaction naming any other
    /// index is asking the chain to append a leaf its recipient cannot open. Refused instead —
    /// and refused without depositing the note or consuming the attestation.
    #[test]
    fn an_attest_with_the_wrong_asset_index_is_refused() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        // A second transfer of the same listed token: index 1 for as long as the chain exists,
        // which is what makes every other index a mistake rather than a race.
        let a = attest(&secrets, transfer(500, 0, recipient().recipient_hash(), 1));
        let honest = attest_tx(&l, a, recipient(), 30);
        assert_eq!(l.validate(&honest, &StubExecutor), Ok(()));
        let mu = honest.bridge_digests()[0];
        for wrong in [0, 2, 9] {
            let tx = naming_asset(honest.clone(), wrong);
            let expected = Err(TxError::AttestAssetMismatch { expected: 1, actual: wrong });
            assert_eq!(l.validate(&tx, &StubExecutor), expected, "asset {wrong}");
            // The same answer from apply, and nothing the action owns was written: the scratch
            // ledger `apply_tx` leaves behind holds no deposit note and has not consumed the
            // digest. (Its fee bundle's own notes are written before the action step runs, by
            // design — `apply_tx`'s caller discards the whole ledger on any error.)
            let mut scratch = l.clone();
            assert_eq!(scratch.apply_tx(&tx, &proposer().address(), &StubExecutor).map(|_| ()), expected);
            assert!(!scratch.has_commitment(&expected_cm(1, 500, 1)), "no deposit note under asset {wrong}");
            assert!(!scratch.is_digest_spent(&mu), "and the attestation is still unconsumed");
        }
    }

    /// And it is refused *cheaply*: an attestation nobody in the guardian set signed still comes
    /// back as a mismatched index, which is only possible if the compare happens before the quorum
    /// is verified. `BridgeState::check_attest`'s contract is that nothing unverified buys a round
    /// of secp256k1 recoveries, and resolving the index needs no signature work at all — the wire
    /// bytes and the registry answer it (`attested_transfer` + `TokenRegistry::get_by_id`).
    ///
    /// The second half is what makes the first half meaningful: the *same* transaction with the
    /// right index goes on to fail on the quorum, so the ordering is what the two answers differ
    /// by, not some earlier refusal both would have hit.
    #[test]
    fn a_wrong_asset_index_is_refused_before_any_signature_recovery() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let forged = misattest(transfer(500, 0, recipient().recipient_hash(), 1));
        let tx = attest_tx(&l, forged, recipient(), 30);
        assert_eq!(
            l.validate(&naming_asset(tx.clone(), 2), &StubExecutor),
            Err(TxError::AttestAssetMismatch { expected: 1, actual: 2 }),
            "the index compare gets there before a single recovery"
        );
        assert!(
            matches!(l.validate(&tx, &StubExecutor), Err(TxError::Bridge(BridgeError::Verify(_)))),
            "and with the index right, the quorum is what is left to refuse it"
        );
        // The second listed token is screened the same way, off its own row: index 2 is the one
        // the listing gave it, and still no signature is recovered to say so.
        let other = misattest(transfer_of(OTHER_TOKEN, 700, 0, recipient().recipient_hash(), 2));
        let tx = attest_tx(&l, other, recipient(), 40);
        assert_eq!(
            l.validate(&naming_asset(tx.clone(), 1), &StubExecutor),
            Err(TxError::AttestAssetMismatch { expected: 2, actual: 1 }),
            "index 1 is the first listing's; this token was listed second"
        );
        assert!(matches!(l.validate(&tx, &StubExecutor), Err(TxError::Bridge(BridgeError::Verify(_)))));
    }

    /// The rule this task installs, from the ledger's side: a bridged token is listed before any
    /// attestation of it is admissible, so an unlisted `(chain, token)` pair is refused outright
    /// rather than registered on sight. Nothing is deposited, no digest is consumed, and no index
    /// is invented — which is what removes the first-sighting race the `asset` word used to have
    /// to survive: a listed token's index is decided before the transaction exists and cannot be
    /// taken from it while its bundle is being proved.
    #[test]
    fn an_attestation_of_an_unlisted_token_is_refused_and_registers_nothing() {
        let (mut l, secrets) = ledger();
        let a = attest(&secrets, transfer_of(UNLISTED_TOKEN, 1_000, 0, recipient().recipient_hash(), 0));
        // `attest_tx` fills in the index the registry names, which for an unlisted token is 0 —
        // no row, no index — so the transaction is what an honest wallet could build at all.
        let tx = attest_tx(&l, a, recipient(), 40);
        let unlisted = Err(TxError::Bridge(BridgeError::UnlistedToken { chain: 2, token: UNLISTED_TOKEN }));
        assert_eq!(l.validate(&tx, &StubExecutor), unlisted);
        // Naming a listed token's index does not help: the attestation's own pair is what is
        // resolved, and it is still unlisted.
        assert_eq!(l.validate(&naming_asset(tx.clone(), 1), &StubExecutor), unlisted);

        let mu = tx.bridge_digests()[0];
        let mut scratch = l.clone();
        assert_eq!(scratch.apply_tx(&tx, &proposer().address(), &StubExecutor).map(|_| ()), unlisted);
        assert!(!scratch.is_digest_spent(&mu), "the attestation is unconsumed");
        assert_eq!(scratch.tokens().unwrap().len(), 2, "and nothing was registered on sight");
        assert!(scratch.tokens().unwrap().get_by_id(&asset_id(2, &UNLISTED_TOKEN)).is_none());

        // Listed — as genesis or a governance message would — the very same attestation deposits
        // under the index the listing gave it, with no re-proof and no race.
        let index = l
            .tokens_mut()
            .unwrap()
            .register(
                asset_id(2, &UNLISTED_TOKEN),
                "Late Coin".into(),
                "zLATE".into(),
                8,
                crate::ledger::tokens::MintAuthority::Bridge {
                    backings: vec![crate::ledger::tokens::Backing { chain: 2, token: UNLISTED_TOKEN, decimals: 8, locked: 0 }],
                },
                1,
            )
            .unwrap();
        assert_eq!(index, 3);
        let listed = naming_asset(tx, 3);
        assert_eq!(l.validate(&listed, &StubExecutor), Ok(()));
        l.apply_tx(&listed, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm(1, 1_000, 3)), "the note the listing's index names");
        assert_eq!(l.tokens().unwrap().get(3).unwrap().total_supply, 1_000);
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
    const BURN_FEE: u64 = gas::BRIDGE_BURN_FEE;

    /// [`burn_tx`] with the redeemed coin and the destination chosen, for the many-backings
    /// tests. `seed` picks the two bundles' four words apiece, so two burns in one test never
    /// collide on a nullifier or a commitment.
    #[allow(clippy::too_many_arguments)]
    fn burn_tx_to(
        l: &Ledger,
        asset: u32,
        amount: u64,
        relayer_fee: u64,
        to_chain: u16,
        token: [u8; 32],
        to: [u8; 32],
        seed: u32,
        mutate: impl FnOnce(&mut Bundle),
    ) -> Transaction {
        let s = |n: u32| [seed + n; 8];
        let mut asset_bundle = bundle(l, [s(0), s(1)], [s(2), s(3)], 0, asset, amount);
        mutate(&mut asset_bundle);
        Transaction::shielded(
            7,
            fee_bundle(l, [s(4), s(5)], [s(6), s(7)], BURN_FEE),
            Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, token, to },
        )
    }

    /// [`burn_tx`] with the outer bundle's fee chosen, for the fee-floor test.
    fn burn_tx_paying(
        l: &Ledger,
        asset: u32,
        amount: u64,
        relayer_fee: u64,
        fee: u64,
        mutate: impl FnOnce(&mut Bundle),
    ) -> Transaction {
        // `burn == amount`: the wire format's `fee` is a *portion* of the amount, paid to the
        // relayer on the far side out of what the release contract pays out (see `validate`).
        let mut asset_bundle = bundle(l, [[40; 8], [41; 8]], [[42; 8], [43; 8]], 0, asset, amount);
        mutate(&mut asset_bundle);
        Transaction::shielded(
            7,
            fee_bundle(l, [[44; 8], [45; 8]], [[46; 8], [47; 8]], fee),
            Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain: 2, token: TOKEN, to: EVM_TO },
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
            Err(TxError::FeeTooLow { min: gas::BRIDGE_BURN_FEE, fee: gas::BUNDLE_BASE })
        );
        // One unit short is still short; exactly the floor is accepted.
        let short = burn_tx_paying(&l, 1, 400, 100, BURN_FEE - 1, |_| {});
        assert_eq!(
            l.validate(&short, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::BRIDGE_BURN_FEE, fee: BURN_FEE - 1 })
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
        // a fee on the asset bundle: the fee is RAND and is paid by the other bundle
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.fee = 7;
            break_proof(b);
        });
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BurnAssetBundleFee(7)));
        // the burn must be exactly the amount the action sends
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.burn = 399;
            break_proof(b);
        });
        assert_eq!(
            l.validate(&t, &StubExecutor),
            Err(TxError::BurnAmountMismatch { expected: 400, actual: 399 })
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
        // What the asset bundle destroyed leaves the token's supply, so the registry keeps saying
        // what the source chain still holds locked: 1 000 deposited, 400 burned.
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 600);
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

    /// A burn destroys exactly what the outbound message sends, and the relayer fee is a
    /// portion of that — the meaning the wire format gives `fee` (`fee <= amount`, and inbound
    /// `check_attest` reads it the same way). A bundle burning `amount + relayer_fee` would
    /// destroy value the release contract never pays out: the far side releases `amount` in
    /// total, so the difference would be stranded in the source-chain contract forever.
    #[test]
    fn a_burn_destroys_its_amount_and_the_relayer_fee_is_a_portion_of_it() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        // The old rule, now refused: burning the amount *plus* the fee over-destroys.
        let over = burn_tx(&l, 1, 400, 100, |b| b.burn = 500);
        assert_eq!(
            l.validate(&over, &StubExecutor),
            Err(TxError::BurnAmountMismatch { expected: 400, actual: 500 })
        );
        // Exactly the amount, with a non-zero fee inside it, is what is admitted.
        let t = burn_tx(&l, 1, 400, 100, |_| {});
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        l.apply_tx(&t, &proposer().address(), &StubExecutor).unwrap();
        // And the message the guardians sign carries the two of them apart: `amount` is the
        // gross figure the pool destroyed, `fee` the part of it the relayer is paid out of.
        let body = Body::decode(&l.bridge().unwrap().burns[&0].body).expect("the record's body decodes");
        let Ok(Payload::Transfer(sent)) = Payload::decode(&body.payload) else { panic!("a transfer") };
        assert_eq!(sent.amount_u128(), Some(400), "what left the pool is what the far side releases");
        assert_eq!(sent.fee_u128(), Some(100), "and the relayer is paid out of it, not on top of it");
    }

    /// A burn cannot destroy more of a *coin* than the bridge ever deposited of it: a backing's
    /// `locked` is what this chain says that one source contract is holding, and a burn past it
    /// would ask that contract to release value it never took in. Refused in `validate` — so
    /// `apply` never half-applies one — and refused for a token that is registered but not
    /// bridged, which has no source chain to release on at all.
    #[test]
    fn a_burn_cannot_outrun_the_backing_or_name_a_token_that_is_not_bridged() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let over = burn_tx(&l, 1, 1_001, 0, |_| {});
        assert_eq!(
            l.validate(&over, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::InsufficientBacking { locked: 1_000, amount: 1_001 })))
        );

        // A `Key`-authority token — a native RPL token, no bridge behind it — is no asset of this
        // bridge's: `check_burn` resolves the outbound message's `(chain, token)` from a
        // `MintAuthority::Bridge` and there is none, so the index names nothing it can send.
        let pk = crate::crypto::Keypair::from_seed([9; 32]).unwrap().public_key().clone();
        let native = crate::ledger::tokens::native_asset_id("Native", "NTV", 9, &crate::ledger::tokens::MintAuthority::Key(pk.clone()), &None, &[7; 32]);
        let index = l
            .tokens_mut()
            .unwrap()
            .register(native, "Native".into(), "NTV".into(), 9, crate::ledger::tokens::MintAuthority::Key(pk), 1)
            .unwrap();
        l.tokens_mut().unwrap().add_supply(index, 5_000).unwrap();
        let t = burn_tx(&l, index, 400, 0, |_| {});
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Bridge(BridgeError::UnknownAsset)));

        // Exactly what the coin has locked is fine, and leaves both it and the supply at zero.
        let all = burn_tx(&l, 1, 1_000, 0, |_| {});
        assert_eq!(l.validate(&all, &StubExecutor), Ok(()));
        l.apply_tx(&all, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 0);
    }

    /// The amendment's whole shape, through the ledger (spec §12): one token — zUSD — backed by
    /// two coins on two chains. A deposit of either mints the *same* index and raises the same
    /// supply; each coin's own `locked` records which source contract is holding what; a burn
    /// names the coin it redeems and the outbound message carries that coin's chain and address.
    #[test]
    fn one_token_two_coins_mint_one_index_and_a_burn_names_the_coin_it_redeems() {
        /// USDT on chain 2 and USDC on chain 5, the two coins behind this test's zUSD.
        const USDT: [u8; 32] = [0xd7; 32];
        const USDC: [u8; 32] = [0xdc; 32];
        /// A 32-byte Solana recipient: chain 5 takes a whole pubkey, not a padded EVM address.
        const SOL_TO: [u8; 32] = [0x77; 32];

        let (mut l, secrets) = ledger();
        // One listing, two backings — what chain 14's genesis does with seven.
        let mut registry = TokenRegistry::new(1_000_000_000);
        let zusd = registry
            .register(
                crate::ledger::tokens::bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
                "Rand USD".into(),
                "zUSD".into(),
                8,
                crate::ledger::tokens::MintAuthority::Bridge {
                    backings: vec![
                        crate::ledger::tokens::Backing { chain: 2, token: USDT, decimals: 8, locked: 0 },
                        crate::ledger::tokens::Backing { chain: 5, token: USDC, decimals: 8, locked: 0 },
                    ],
                },
                0,
            )
            .unwrap();
        l.set_tokens(Some(registry));

        // An inbound transfer of `token` from `chain`, signed by that chain's registered emitter.
        let inbound = |chain: u16, token: [u8; 32], amount: u128, sequence: u64| Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: chain,
            emitter_address: [chain as u8; 32],
            sequence,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: token,
                token_chain: chain,
                to: recipient().recipient_hash(),
                to_chain: CHAIN_RAND,
                fee: Transfer::u256_from_u128(0),
            })
            .encode(),
        };
        // USDT on chain 2, then USDC on chain 5: both deposit under zUSD's one index.
        for (i, (chain, token, amount)) in [(2u16, USDT, 1_000u128), (5, USDC, 400)].into_iter().enumerate() {
            let tx = attest_tx(&l, attest(&secrets, inbound(chain, token, amount, i as u64)), recipient(), 20 + 10 * i as u32);
            let Action::BridgeAttest { asset, .. } = &tx.action else { panic!("an attest") };
            assert_eq!(*asset, zusd, "either coin deposits under the one token's index");
            l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
            assert!(l.has_commitment(&expected_cm(1, amount as u64, zusd)));
        }
        let t = l.tokens().unwrap();
        assert_eq!(t.get(zusd).unwrap().total_supply, 1_400, "one token, both coins' worth");
        assert_eq!(t.backing(zusd, 2, &USDT).unwrap().locked, 1_000);
        assert_eq!(t.backing(zusd, 5, &USDC).unwrap().locked, 400);
        assert!(t.backing_invariant_holds());

        // A burn of more USDC than chain 5 is holding, though 1 400 of zUSD exists.
        let over = burn_tx_to(&l, zusd, 700, 0, 5, USDC, SOL_TO, 50, |_| {});
        assert_eq!(
            l.validate(&over, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::InsufficientBacking { locked: 400, amount: 700 })))
        );
        // A coin that backs nothing on this chain, and the right chain with the wrong coin.
        let nothing = burn_tx_to(&l, zusd, 100, 0, 3, USDT, EVM_TO, 60, |_| {});
        assert_eq!(
            l.validate(&nothing, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::NotABacking { index: 1, chain: 3 })))
        );
        let swapped = burn_tx_to(&l, zusd, 100, 0, 2, USDC, EVM_TO, 70, |_| {});
        assert_eq!(
            l.validate(&swapped, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::NotABacking { index: 1, chain: 2 })))
        );

        // The same amount against the coin that does hold it is admitted, and the outbound
        // message names *that* coin — not the token's first backing, and not the other chain's.
        let ok = burn_tx_to(&l, zusd, 700, 0, 2, USDT, EVM_TO, 80, |_| {});
        assert_eq!(l.validate(&ok, &StubExecutor), Ok(()));
        l.apply_tx(&ok, &proposer().address(), &StubExecutor).unwrap();
        let body = Body::decode(&l.bridge().unwrap().burns[&0].body).expect("the record's body decodes");
        let Ok(Payload::Transfer(sent)) = Payload::decode(&body.payload) else { panic!("a transfer") };
        assert_eq!((sent.token_chain, sent.token_address, sent.to_chain), (2, USDT, 2));
        let t = l.tokens().unwrap();
        assert_eq!(t.backing(zusd, 2, &USDT).unwrap().locked, 300, "only the coin that was redeemed moved");
        assert_eq!(t.backing(zusd, 5, &USDC).unwrap().locked, 400);
        assert_eq!(t.get(zusd).unwrap().total_supply, 700);
        assert!(t.backing_invariant_holds());

        // Two burns into one coin that each fit alone but not together: block application
        // re-validates every transaction against the ledger the ones before it left, so the
        // second is refused rather than draining a backing past what its contract holds.
        let first = burn_tx_to(&l, zusd, 200, 0, 2, USDT, EVM_TO, 90, |_| {});
        let second = burn_tx_to(&l, zusd, 200, 0, 2, USDT, EVM_TO, 100, |_| {});
        assert_eq!(l.validate(&first, &StubExecutor), Ok(()), "each fits against the tip");
        assert_eq!(l.validate(&second, &StubExecutor), Ok(()));
        let mut block = l.clone();
        block.apply_tx(&first, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(block.tokens().unwrap().backing(zusd, 2, &USDT).unwrap().locked, 100);
        assert_eq!(
            block.apply_tx(&second, &proposer().address(), &StubExecutor).map(|_| ()),
            Err(TxError::Bridge(BridgeError::Token(TokenError::InsufficientBacking { locked: 100, amount: 200 }))),
            "300 - 200 - 200 would be -100, so the second is refused where it sits"
        );
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
