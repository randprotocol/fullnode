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
//! - **`BridgeBurn`** sends value the other way, on one hidden-asset bundle (spec §3.7): its
//!   private slots 0–1 spend the bridged asset and publish `burn_a == amount` and
//!   `burn_asset == asset`, its RAND slots 2–3 pay the fee — the wire format's `relayer_fee` is
//!   a portion of that amount, paid on the destination chain.
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
        Action::BridgeAttest { attestation, recipient, r, time, asset, envelope: _, pq_signatures } => {
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
            // F1: the deposit note's blinding is the attestation digest's, not the submitter's
            // (`derive_deposit_r`), so whoever submits an attestation names the same note at the
            // same `time` and a copier of a pooled attest cannot swap in a note of its own. Two
            // keccaks and a blake3 over the size-capped bytes — no key, no state, no signature —
            // so it runs here, before the PQ structure check and the quorum's recoveries inside
            // `check_attest`. Every attest, a rotation's included: it deposits nothing, but a free
            // `r` would still be a field a copier could vary. Silent on bytes with no body, which
            // `check_attest`'s decode refuses on its own.
            if let Some(expected) = deposit_r(attestation) {
                if *r != expected {
                    return Err(TxError::Bridge(BridgeError::WrongDepositBlinding));
                }
            }
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
            // itself ordered cheap-before-expensive: the PQ co-signature list's structure first
            // (B3), then it decodes, resolves the guardian set, rejects a replayed digest and
            // checks the payload before recovering a signature — and verifies the Dilithium2
            // co-signatures, over this chain's id, last of all.
            let checked = bridge
                .check_attest(tokens, attestation, pq_signatures, ledger.chain_id(), ledger.now_secs())
                .map_err(TxError::Bridge)?;
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
                // The deposit note is this transaction's fifth commitment, and `apply` appends
                // it after the bundle's four. Checking it against both the tree and that
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
        Action::BridgeBurn { asset, amount, relayer_fee, to_chain, token, to } => {
            let bridge = ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            let tokens = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
            // Cheap before expensive (spec §7): everything here is a comparison or a set lookup,
            // and it all runs before the bundle's proof is verified at steps 8-9 of
            // `validate_inner`, against the transaction binding. A burn that names the wrong
            // asset costs no verification.
            //
            // The burn rule itself is [`super::tokens::check_asset_burn`], shared with the RPL
            // holder burn: `burn_asset == asset != 0`, `burn_a == amount`, `burn_r == 0`. A burn's
            // `burn_a == amount` is this action's own rule inside it: the wire format's `fee` is a
            // *portion* of `amount` — that is what
            // `fee <= amount` means (`check_burn`, and inbound `check_attest` reads it the same
            // way) — so the release contract pays `amount - fee` to `to` and `fee` to the relayer,
            // releasing `amount` in total. Burning `amount + relayer_fee` would destroy more than
            // the far side ever releases and strand the difference in the source-chain contract
            // forever.
            super::tokens::check_asset_burn(tx, *asset, *amount)?;
            // The release `apply` makes, decided here for the same reason the deposit's lock is:
            // `apply_tx` writes the bundle's notes before this action touches the registry.
            // `check_burn` ends in `TokenRegistry::check_release`, which is exactly what the
            // apply step's `release` would refuse — the named pair being a backing of this token
            // at all, `amount` and `relayer_fee` each being a whole number of that coin's release
            // unit, and that backing holding at least `amount`. A burn of more of one coin than
            // its own source contract is holding would ask that contract to release value it
            // never took in, so it is refused rather than clamped, even when the token's whole
            // supply (every other coin's `locked` included) would cover it; and a burn that is
            // not a whole number of units would ask it to release a fraction of a native token,
            // which it rounds down — stranding the remainder in custody for ever, or releasing
            // nothing at all below one unit (bridge-06/audit O-5). Still comparisons, and still
            // before the bundle's proof.
            bridge
                .check_burn(tokens, *asset, *amount, *to_chain, token, to, *relayer_fee)
                .map_err(TxError::Bridge)?;
            // The bundle's proof is not verified here: `validate_inner`'s steps 8-9 verify it,
            // after every cheap check, against the transaction binding.
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
                        .lock(t.index, t.chain, &t.token, t.amount, t.day)
                        .map_err(|e| TxError::Bridge(BridgeError::Token(e)))?;
                }
                // Governance only: a rotation moves guardian keys and no value.
                AttestOutcome::GuardianSetUpgraded(_) => {}
            }
            Ok(())
        }
        Action::BridgeBurn { asset, amount, relayer_fee, to_chain, token, to } => {
            // The bundle's four nullifiers and four commitments were written by `apply_tx`'s
            // common path, like every bundle's.
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
            // What the bundle's `burn_a` destroyed leaves the named backing and the token's supply
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

/// The hash domain of a deposit note's blinding: `r = blake3("rand-deposit-r-1" ‖ mu)`, read as
/// eight little-endian `u32` words ([`crate::notes::word8_from_bytes`]).
pub const DEPOSIT_R_DOMAIN: &[u8] = b"rand-deposit-r-1";

/// The blinding `r` of the deposit note an attestation with digest `mu` mints (F1, chain 14):
/// `word8_from_bytes(blake3("rand-deposit-r-1" ‖ mu))`.
///
/// `mu = keccak256(keccak256(body))` is the 32 bytes the guardian quorum signs
/// ([`crate::bridge::digest`]), so it is fixed the moment the attestation exists, and the same
/// for every submitter. Before this rule the blinding was the submitter's choice, and anyone who
/// saw a relayer's pooled attest could submit the same attestation first under a blinding of its
/// own — a different note (still the recipient's: the wallet rebuilds it from the public fields),
/// the relayer's transaction dead on `Replay`, and the recipient's envelope replaced. With `r`
/// derived, two submissions at the same `time` name one note, and the pool conflicts them.
///
/// BLAKE3 with a domain tag, as every other derived word on the ledger side is
/// (`Hash::digest_domain`); `mu` is a keccak digest only because the wire format is frozen
/// (the source-chain contracts sign it). The 32 bytes are read little-endian, four per word,
/// exactly as a `Word8` is written on the wire, and every `u32` is a valid note word — the
/// wallet's own blindings are uniform `u32`s (`Note::new`).
///
/// `time` is deliberately *not* bound: see [`Action::BridgeAttest`] and `docs/bridge.md` §8.
pub fn derive_deposit_r(mu: &[u8; 32]) -> Word8 {
    crate::notes::word8_from_bytes(&crate::crypto::Hash::digest_domain(DEPOSIT_R_DOMAIN, mu).0)
        .expect("a blake3 hash is 32 bytes")
}

/// [`derive_deposit_r`] of an attestation's own bytes: the digest over its wire body, exactly as
/// [`Transaction::bridge_digests`] and `BridgeState::check_attest` compute it. `None` for bytes
/// with no body to hash, which admission refuses on their own (`check_attest`'s decode).
///
/// This is what a relayer puts in the action's `r` field, and what [`validate`] requires there.
pub fn deposit_r(attestation: &[u8]) -> Option<Word8> {
    Attestation::body_bytes(attestation).ok().map(|body| derive_deposit_r(&crate::bridge::digest(body)))
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
    let Action::BridgeAttest { attestation, recipient, r, time, asset: _, envelope, pq_signatures: _ } = &tx.action else {
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
        asset_id, digest, guardian_address, pq_cosign, sign_digest, Attestation, Body, BridgeConfig, BridgeState,
        Payload, PqSignature, Transfer, CHAIN_RAND,
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
            pq_guardians: pq_keys().iter().map(|k| k.public_key().clone()).collect(),
            pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
        };
        (config, secrets)
    }

    /// The six PQ guardians' Dilithium2 keys (B3), index-aligned with [`cfg`]'s guardians.
    fn pq_keys() -> Vec<Keypair> {
        (0..6u8).map(|i| Keypair::from_seed([0x70 + i; 32]).unwrap()).collect()
    }

    /// The PQ co-signatures by `indices` over `attestation`'s `mu` on this module's chain (7) —
    /// what a relayer collects from the guardians and submits beside the attestation.
    fn cosign_by(indices: &[u8], attestation: &[u8]) -> Vec<PqSignature> {
        let mu = Attestation::body_bytes(attestation).map(digest).unwrap_or([0; 32]);
        let keys = pq_keys();
        indices.iter().map(|&i| pq_cosign(&keys[i as usize], i, 7, &mu)).collect()
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
                        backings: vec![crate::ledger::tokens::Backing { chain: 2, token, decimals: 8, locked: 0, minted_today: 0, mint_day: 0 }],
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
    /// the live root, and only a recorded root is an anchor (spec §7 item 4). `nfs`/`cms` are its
    /// first two slots, the other two derived (`notes::pad4`); `burn_asset`/`burn_a` are the
    /// token burn it publishes (`0, 0` for none).
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64, burn_asset: u32, burn_a: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: crate::notes::pad4(nfs),
            commitments: crate::notes::pad4(cms),
            fee,
            burn_a,
            burn_r: 0,
            burn_asset,
            time: l.height() as u32,
            envelopes: [env(), env(), env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        b
    }

    /// A bundle that burns nothing, paying `fee` — what a bridge attest carries.
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
        attest_tx_cosigned(l, attestation, to, seed, &[0, 1, 2, 3, 4])
    }

    /// [`attest_tx`] with the PQ co-signatures of `pq` (the lowest five is what a relayer sends).
    fn attest_tx_cosigned(l: &Ledger, attestation: Vec<u8>, to: ShieldedAddress, seed: u32, pq: &[u8]) -> Transaction {
        let asset = expected_index(l, &attestation);
        let pq_signatures = cosign_by(pq, &attestation);
        // The one blinding the ledger admits (F1); bytes with no body keep a placeholder, since
        // their decode is what refuses them.
        let r = deposit_r(&attestation).unwrap_or([7; 8]);
        StubExecutor::bound(Transaction::shielded(
            7,
            fee_bundle(l, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], gas::BUNDLE_BASE),
            Action::BridgeAttest {
                attestation,
                recipient: to,
                r,
                time: l.height() as u32,
                asset,
                envelope: env(),
                pq_signatures,
            },
        ))
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

    /// What the ledger must have computed for `tx`'s deposit note of `amount` in asset `asset` at
    /// `time` — under the blinding its attestation's digest derives, which is the only one the
    /// ledger admits (F1).
    fn expected_cm(tx: &Transaction, time: u32, amount: u64, asset: u32) -> Word8 {
        let Action::BridgeAttest { attestation, .. } = &tx.action else { panic!("an attest") };
        let r = deposit_r(attestation).expect("an attestation with a body");
        StubExecutor.note_commitment(&recipient().pk, &[0; 8], amount, asset, time, &r)
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
        let cm = expected_cm(&tx, 1, 1_000, 1);
        assert!(l.has_commitment(&cm), "the deposit note is in the tree");
        // The bundle's four notes plus the deposit note.
        assert_eq!(l.next_index(), 5);
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 1_000, "the gross amount is new supply");
        let bridge = l.bridge().unwrap();
        assert_eq!(bridge.spent.len(), 1, "the digest is consumed");
        // The relayer fee has no payee on a shielded chain, so the gross amount is deposited:
        // a second attestation of the same amount with a fee deposits a note of the whole
        // 1 000. (A different note from the first, not the same one: its digest is different, and
        // so is the blinding that digest derives — F1.)
        let a = attest(&secrets, transfer(1_000, 250, recipient().recipient_hash(), 1));
        let with_fee = attest_tx(&l, a, recipient(), 30);
        l.apply_tx(&with_fee, &proposer().address(), &StubExecutor).unwrap();
        let gross = expected_cm(&with_fee, 1, 1_000, 1);
        assert!(l.has_commitment(&gross), "the gross amount, fee included");
        assert_ne!(gross, cm);
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 2_000);
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
        StubExecutor::bind(&mut tx);
        // The same note, named before the transaction is applied: this is what a mempool claims
        // for an attest (`Ledger::derived_commitment`, one derivation for a withdraw and an attest
        // alike), and it reads the registry rather than the action's `asset` word.
        assert_eq!(l.derived_commitment(&tx.action, &StubExecutor), Some(expected_cm(&tx, 5, 1_000, 1)));
        l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm(&tx, 5, 1_000, 1)), "the note the action's time names");
        assert!(!l.has_commitment(&expected_cm(&tx, 9, 1_000, 1)), "and not the one the apply height would");
        // The recompute-after-the-fact path reads the same word off the committed action, so a
        // node's note index agrees with the tree whatever height it asks about.
        let (cm, _) = deposit_note(&tx, l.tokens().unwrap(), &StubExecutor).expect("a transfer deposits a note");
        assert_eq!(cm, expected_cm(&tx, 5, 1_000, 1));
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
            StubExecutor::bind(&mut tx);
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

    /// The deposit blinding's definition, pinned: `blake3("rand-deposit-r-1" ‖ mu)` read as eight
    /// little-endian words, for two fixed digests — and `deposit_r` of an attestation is that of
    /// the very digest the guardians sign (`Transaction::bridge_digests`' `mu`). A wallet, a
    /// relayer or another implementation reproduces these words or its deposits are refused.
    #[test]
    fn the_deposit_blinding_is_pinned() {
        assert_eq!(DEPOSIT_R_DOMAIN, &b"rand-deposit-r-1"[..]);
        assert_eq!(
            crate::notes::word8_to_hex(&derive_deposit_r(&[0; 32])),
            "bcf6dc32f463ea7159250ae9209a413c4bf631658577aa0275037b765aa17902",
            "mu = 0^32"
        );
        let mu: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(crate::notes::word8_to_hex(&derive_deposit_r(&mu)), "a9d47b2f82ee0f38045a9c01a60d30b49fefc77746b2f3093966412acaa179e7", "mu = 00 01 .. 1f");
        let manual = crate::crypto::Hash::digest_domain(b"rand-deposit-r-1", &mu).0;
        assert_eq!(crate::notes::word8_to_bytes(&derive_deposit_r(&mu)), manual, "the hash's own bytes, LE words");

        let (l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let tx = attest_tx(&l, a.clone(), recipient(), 20);
        let mu = tx.bridge_digests()[0];
        assert_eq!(deposit_r(&a), Some(derive_deposit_r(&mu.0)));
        assert_eq!(deposit_r(&[0xff; 8]), None, "no body, no blinding");
    }

    /// The ledger rule (F1): the action's `r` must be the one the attestation's digest derives.
    /// Any other — one bit off, the old fixtures' constant, zero — is refused, by `validate` and by
    /// `apply` alike, with nothing written; the derived one deposits.
    #[test]
    fn an_attest_with_any_other_blinding_is_refused() {
        let (l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let honest = attest_tx(&l, a, recipient(), 20);
        let Action::BridgeAttest { r: derived, .. } = &honest.action else { panic!("an attest") };
        let derived = *derived;
        let mu = honest.bridge_digests()[0];
        let mut flipped = derived;
        flipped[3] ^= 1;
        for wrong in [flipped, [7; 8], [0; 8]] {
            let mut tx = honest.clone();
            let Action::BridgeAttest { r, .. } = &mut tx.action else { panic!("an attest") };
            *r = wrong;
            StubExecutor::bind(&mut tx);
            let refused = Err(TxError::Bridge(BridgeError::WrongDepositBlinding));
            assert_eq!(l.validate(&tx, &StubExecutor), refused, "r = {wrong:?}");
            let mut scratch = l.clone();
            assert_eq!(scratch.apply_tx(&tx, &proposer().address(), &StubExecutor).map(|_| ()), refused);
            assert!(!scratch.is_digest_spent(&mu), "the attestation is still unconsumed");
        }
        let mut l = l;
        l.apply_tx(&honest, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm(&honest, 1, 1_000, 1)), "the derived blinding deposits");
    }

    /// And it is refused before any signature work: an attestation nobody in the guardian set
    /// signed, and one with no PQ co-signatures at all, still come back as the wrong blinding —
    /// possible only if the compare runs before the PQ structure check and the secp256k1 quorum.
    /// A rotation is held to the same rule: `r` is always the digest's, so no attest transaction
    /// has a free field a copier can vary.
    #[test]
    fn a_wrong_blinding_is_refused_before_any_signature_work() {
        let (l, secrets) = ledger();
        let forged = misattest(transfer(1_000, 0, recipient().recipient_hash(), 0));
        let mut tx = attest_tx_cosigned(&l, forged, recipient(), 20, &[]);
        let Action::BridgeAttest { r, .. } = &mut tx.action else { panic!("an attest") };
        r[0] ^= 1;
        StubExecutor::bind(&mut tx);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::Bridge(BridgeError::WrongDepositBlinding)));

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
        let honest = attest_tx(&l, attest(&secrets, rotation), recipient(), 30);
        assert_eq!(l.validate(&honest, &StubExecutor), Ok(()), "the derived blinding rotates");
        let mut tx = honest;
        let Action::BridgeAttest { r, .. } = &mut tx.action else { panic!("an attest") };
        *r = [0; 8];
        StubExecutor::bind(&mut tx);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::Bridge(BridgeError::WrongDepositBlinding)));
    }

    /// The griefing F1 closes: two submitters of one attestation — different fee bundles, so
    /// different transactions — at the same `time` now name the *same* deposit note, so the pool's
    /// commitment claim conflicts them rather than letting a copier's note race the relayer's.
    /// `time` is the residual: it is still the submitter's (inside the window), so a copier who
    /// picks another `time` derives another note — still the recipient's, at the same amount and
    /// asset, rebuilt by the wallet from the public fields — and the digest claim is what
    /// conflicts the pair then.
    #[test]
    fn two_submitters_of_one_attestation_at_one_time_derive_one_note() {
        let (mut l, secrets) = ledger();
        l.set_height(9);
        l.record_anchor(9);
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let relayer = attest_tx(&l, a.clone(), recipient(), 20);
        let copier = attest_tx(&l, a, recipient(), 40);
        assert_ne!(relayer.hash(), copier.hash(), "two different transactions");
        let (cr, cc) = (
            l.derived_commitment(&relayer.action, &StubExecutor).unwrap(),
            l.derived_commitment(&copier.action, &StubExecutor).unwrap(),
        );
        assert_eq!(cr, cc, "one note, whoever submits it");
        assert_eq!(relayer.bridge_digests(), copier.bridge_digests());
        l.apply_tx(&relayer, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.validate(&copier, &StubExecutor).is_err(), "the second is refused once the first lands");

        // The residual: another `time` in the window is another note of the same recipient.
        let (l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let now = attest_tx(&l, a.clone(), recipient(), 20);
        let mut earlier = attest_tx(&l, a, recipient(), 40);
        let Action::BridgeAttest { time, .. } = &mut earlier.action else { panic!("an attest") };
        *time = 0;
        StubExecutor::bind(&mut earlier);
        assert_ne!(
            l.derived_commitment(&now.action, &StubExecutor),
            l.derived_commitment(&earlier.action, &StubExecutor),
            "time is the one word a copier still chooses"
        );
        assert_eq!(l.validate(&earlier, &StubExecutor), Ok(()));
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
        assert_eq!(cm, expected_cm(&tx, 1, 1_000, 1));
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
            assert!(!scratch.has_commitment(&expected_cm(&honest, 1, 500, 1)), "no deposit note under asset {wrong}");
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
                    backings: vec![crate::ledger::tokens::Backing { chain: 2, token: UNLISTED_TOKEN, decimals: 8, locked: 0, minted_today: 0, mint_day: 0 }],
                },
                1,
            )
            .unwrap();
        assert_eq!(index, 3);
        let listed = StubExecutor::bound(naming_asset(tx, 3));
        assert_eq!(l.validate(&listed, &StubExecutor), Ok(()));
        l.apply_tx(&listed, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm(&listed, 1, 1_000, 3)), "the note the listing's index names");
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

    /// A burn transaction on one bundle burning `amount` of `asset` and paying the bridge fee;
    /// `mutate` edits the bundle after its stub proof is made (a test that breaks the proof, or
    /// changes a burn field so that only a cheap rule can refuse it).
    fn burn_tx(l: &Ledger, asset: u32, amount: u64, relayer_fee: u64, mutate: impl FnOnce(&mut Bundle)) -> Transaction {
        burn_tx_paying(l, asset, amount, relayer_fee, BURN_FEE, mutate)
    }

    /// The fee a valid burn's bundle pays: the bridge's all-in fee.
    const BURN_FEE: u64 = gas::BRIDGE_BURN_FEE;

    /// [`burn_tx`] with the redeemed coin and the destination chosen, for the many-backings
    /// tests. `seed` picks the bundle's words, so two burns in one test never collide on a
    /// nullifier or a commitment.
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
        let mut b = bundle(l, [s(0), s(1)], [s(2), s(3)], BURN_FEE, asset, amount);
        mutate(&mut b);
        StubExecutor::bound(Transaction::shielded(7, b, Action::BridgeBurn { asset, amount, relayer_fee, to_chain, token, to }))
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
        // `burn_a == amount`: the wire format's `fee` is a *portion* of the amount, paid to the
        // relayer on the far side out of what the release contract pays out (see `validate`).
        let mut b = bundle(l, [[40; 8], [41; 8]], [[42; 8], [43; 8]], fee, asset, amount);
        mutate(&mut b);
        StubExecutor::bound(Transaction::shielded(
            7,
            b,
            Action::BridgeBurn { asset, amount, relayer_fee, to_chain: 2, token: TOKEN, to: EVM_TO },
        ))
    }

    /// A burn pays the bridge's all-in fee. The floor is checked at step 3, before the anchor,
    /// the burn fields or any proof — so an underpaying burn is refused on a comparison even
    /// with a broken proof.
    #[test]
    fn a_burn_pays_the_bridge_fee() {
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

    /// The burn rule (the hidden-asset bundle, spec §3.7) on a `BridgeBurn`'s one bundle:
    /// `burn_asset == asset`, `burn_a == amount`, `burn_r == 0`, and never RAND through
    /// `burn_a`. Each is refused on a comparison, before anything verifies a proof — every case
    /// hands the bundle an unverifiable proof, so reaching step 9 would be visible.
    #[test]
    fn a_mismatched_burn_is_refused_before_any_proof_work() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let break_proof = |b: &mut Bundle| b.proof = vec![0xff; 16];

        // wrong asset: the bundle burns asset 2, the action declares 1
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.burn_asset = 2;
            break_proof(b);
        });
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BurnAssetMismatch { expected: 1, actual: 2 }));
        // RAND burned alongside: a token burn burns no RAND
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.burn_r = 7;
            break_proof(b);
        });
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedBurn(7)));
        // the burn must be exactly the amount the action sends
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.burn_a = 399;
            break_proof(b);
        });
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BurnAmountMismatch { expected: 400, actual: 399 }));
        // RAND burned through `burn_a` (`burn_asset == 0`): non-canonical, refused at step 3
        let t = burn_tx(&l, 1, 400, 100, |b| {
            b.burn_asset = 0;
            break_proof(b);
        });
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::NonCanonicalRandBurn(400)));
        // …and a "bridge burn" of RAND itself is the same non-canonical burn
        let t = burn_tx(&l, 0, 400, 100, break_proof);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::NonCanonicalRandBurn(400)));
        // with nothing burned through `burn_a` either, asset 0 names no token
        let t = burn_tx(&l, 0, 0, 0, break_proof);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Token(TokenError::UnknownToken(0))));
        // an unregistered asset is the bridge's own refusal, still before the proof
        let t = burn_tx(&l, 9, 400, 100, break_proof);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Bridge(BridgeError::UnknownAsset)));
        // and with every cheap check passing, the broken proof is what is left to refuse
        let t = burn_tx(&l, 1, 400, 100, break_proof);
        assert!(matches!(l.validate(&t, &StubExecutor), Err(TxError::InvalidBundleProof(_))));
    }

    /// The happy path: the one bundle is admitted, its four nullifiers are spent, its four
    /// commitments are appended, and the bridge holds an outbound message stamped with this
    /// transaction.
    #[test]
    fn a_burn_spends_four_nullifiers_and_records_the_message() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let t = burn_tx(&l, 1, 400, 100, |_| {});
        let before = l.next_index();
        l.apply_tx(&t, &proposer().address(), &StubExecutor).unwrap();
        // What the bundle destroyed leaves the token's supply, so the registry keeps saying
        // what the source chain still holds locked: 1 000 deposited, 400 burned.
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 600);
        assert_eq!(t.nullifiers().len(), 4);
        for nf in t.nullifiers() {
            assert!(l.is_spent(&nf), "{nf:?} is spent");
        }
        for cm in t.commitments() {
            assert!(l.has_commitment(&cm), "{cm:?} is in the tree");
        }
        assert_eq!(l.next_index(), before + 4);
        // A token burn is not RAND: the RAND audit's burn counter does not move.
        assert_eq!(l.supply().burned, 0);
        let bridge = l.bridge().unwrap();
        assert_eq!(bridge.burn_sequence, 1);
        let record = &bridge.burns[&0];
        assert_eq!(record.tx, t.hash(), "the transaction hash stands in for the absent sender");
        assert_eq!(record.height, 1);
        // Replay: the bundle's nullifiers are spent now.
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Spent([40; 8])));
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
        let over = burn_tx(&l, 1, 400, 100, |b| b.burn_a = 500);
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
                        crate::ledger::tokens::Backing { chain: 2, token: USDT, decimals: 8, locked: 0, minted_today: 0, mint_day: 0 },
                        crate::ledger::tokens::Backing { chain: 5, token: USDC, decimals: 8, locked: 0, minted_today: 0, mint_day: 0 },
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
            assert!(l.has_commitment(&expected_cm(&tx, 1, amount as u64, zusd)));
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

    /// The release-unit rule through the whole ledger (bridge-06/audit O-5), which is where it
    /// has to hold: a coin whose source token declares **6** decimals against an eight-decimal
    /// attestation wire releases in units of 100, so a burn of 199 would release 1 native unit
    /// and strand 99 in that contract's custody for ever, and a burn of 99 would release nothing
    /// at all. `validate` refuses both before the bundle's proof is verified, and the
    /// relayer fee — which the far side carves out of the amount in native units — is held to the
    /// same unit.
    ///
    /// The registry's own tests cover the arithmetic; this one covers the wiring, because that is
    /// what a real burn travels through: `validate` → `BridgeState::check_burn` →
    /// `TokenRegistry::check_release`, and then `apply` reaching the very same verdict through
    /// `release`.
    #[test]
    fn a_burn_that_is_not_a_whole_release_unit_is_refused_in_validate() {
        /// Ethereum USDT's real wire address, and its real 6 decimals.
        const USDT: [u8; 32] = [0xd7; 32];

        let (mut l, secrets) = ledger();
        let mut registry = TokenRegistry::new(1_000_000_000);
        let zusd = registry
            .register(
                crate::ledger::tokens::bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
                "Rand USD".into(),
                "zUSD".into(),
                8,
                crate::ledger::tokens::MintAuthority::Bridge {
                    backings: vec![crate::ledger::tokens::Backing { chain: 2, token: USDT, decimals: 6, locked: 0, minted_today: 0, mint_day: 0 }],
                },
                0,
            )
            .unwrap();
        l.set_tokens(Some(registry));

        // A deposit always attests a whole number of units, so there is nothing to refuse
        // inbound: 10 000 wire units is 100 native USDT.
        let deposit = attest_tx(
            &l,
            attest(
                &secrets,
                Body {
                    timestamp: 1,
                    nonce: 0,
                    emitter_chain: 2,
                    emitter_address: [2; 32],
                    sequence: 0,
                    consistency_level: 0,
                    payload: Payload::Transfer(Transfer {
                        amount: Transfer::u256_from_u128(10_000),
                        token_address: USDT,
                        token_chain: 2,
                        to: recipient().recipient_hash(),
                        to_chain: CHAIN_RAND,
                        fee: Transfer::u256_from_u128(0),
                    })
                    .encode(),
                },
            ),
            recipient(),
            20,
        );
        l.apply_tx(&deposit, &proposer().address(), &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().backing(zusd, 2, &USDT).unwrap().release_unit(), 100);

        // 199 wire units: one native USDT released and 99 stranded. Refused.
        let ragged = burn_tx_to(&l, zusd, 199, 0, 2, USDT, EVM_TO, 30, |_| {});
        assert_eq!(
            l.validate(&ragged, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::NotReleasable { amount: 199, unit: 100 })))
        );
        // Below one unit: the endpoint would revert `ZeroAmount`. Same refusal, before it exists.
        let dust = burn_tx_to(&l, zusd, 99, 0, 2, USDT, EVM_TO, 40, |_| {});
        assert_eq!(
            l.validate(&dust, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::NotReleasable { amount: 99, unit: 100 })))
        );
        // A clean amount with a ragged fee is refused on the fee, naming the fee's own figure.
        let ragged_fee = burn_tx_to(&l, zusd, 1_000, 150, 2, USDT, EVM_TO, 50, |_| {});
        assert_eq!(
            l.validate(&ragged_fee, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::NotReleasable { amount: 150, unit: 100 })))
        );
        // Nothing moved through any of that.
        assert_eq!(l.tokens().unwrap().backing(zusd, 2, &USDT).unwrap().locked, 10_000);

        // Two whole units, with a whole-unit fee: admitted, applied, and custody still equals
        // `locked` to the last native unit.
        let ok = burn_tx_to(&l, zusd, 200, 100, 2, USDT, EVM_TO, 60, |_| {});
        assert_eq!(l.validate(&ok, &StubExecutor), Ok(()));
        l.apply_tx(&ok, &proposer().address(), &StubExecutor).unwrap();
        let t = l.tokens().unwrap();
        assert_eq!(t.backing(zusd, 2, &USDT).unwrap().locked, 9_800);
        assert_eq!(t.get(zusd).unwrap().total_supply, 9_800);
        assert_eq!(9_800 % 100, 0, "and what is left is still a whole number of native units");
        assert!(t.backing_invariant_holds());
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

    // ---- Task 5b: every bundle proof is bound to the transaction it rides in ----------------

    /// An EVM-shaped destination other than [`EVM_TO`]: 12 zero bytes then 20 bytes of `0x33`.
    const THIEF_TO: [u8; 32] = {
        let mut t = [0u8; 32];
        let mut i = 12;
        while i < 32 {
            t[i] = 0x33;
            i += 1;
        }
        t
    };

    /// `original` with `change` applied to its action, and no proof touched: what a gossip peer
    /// or a proposer can build from a transaction it has only seen.
    fn altered(original: &Transaction, change: impl FnOnce(&mut Action)) -> Transaction {
        let mut t = original.clone();
        change(&mut t.action);
        t
    }

    /// The bridge redirect (the defect Task 5b closes): a copy of an honest burn with its proofs
    /// kept byte for byte and its destination, its relayer fee, its amount or its asset changed.
    /// Before the binding, the `to` and `relayer_fee` copies were *admitted* — the source chain's
    /// release would then have paid the attacker. Each is refused now, and the original still
    /// validates.
    #[test]
    fn a_burns_proofs_cannot_ride_a_changed_destination_fee_amount_or_asset() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let original = burn_tx(&l, 1, 400, 100, |_| {});
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        // Every case is checked before anything is asserted, so a failure lists all of them.
        let mut wrong = Vec::new();
        let mut proof_refusal = |t: &Transaction, what: &str| match l.validate(t, &StubExecutor) {
            Err(TxError::InvalidBundleProof(_)) => {}
            other => wrong.push(format!("{what}: expected the bundle-proof refusal, got {other:?}")),
        };
        let to = altered(&original, |a| {
            let Action::BridgeBurn { to, .. } = a else { panic!("a burn") };
            *to = THIEF_TO;
        });
        proof_refusal(&to, "`to` swapped");
        let fee = altered(&original, |a| {
            let Action::BridgeBurn { relayer_fee, .. } = a else { panic!("a burn") };
            *relayer_fee = 200;
        });
        proof_refusal(&fee, "`relayer_fee` raised");
        assert!(wrong.is_empty(), "{wrong:#?}");
        // `amount` and `asset` are also bound by the bundle's own words (its `burn_a` and its
        // `burn_asset`), so a cheap rule may refuse them first — what matters is that they are
        // refused.
        let amount = altered(&original, |a| {
            let Action::BridgeBurn { amount, .. } = a else { panic!("a burn") };
            *amount = 500;
        });
        assert!(l.validate(&amount, &StubExecutor).is_err(), "`amount` changed");
        let asset = altered(&original, |a| {
            let Action::BridgeBurn { asset, .. } = a else { panic!("a burn") };
            *asset = 2;
        });
        assert!(l.validate(&asset, &StubExecutor).is_err(), "`asset` changed");
        // The binding covers the burn fields themselves: a copy whose `amount` *and* `burn_a`
        // both read 500 — the burn rule satisfied, and the proof re-issued for the new digest
        // but still bound to the original transaction (as a proof for those words, made for
        // another transaction, would be) — is refused on the binding.
        let mut burn_a = altered(&original, |a| {
            let Action::BridgeBurn { amount, .. } = a else { panic!("a burn") };
            *amount = 500;
        });
        {
            let binding = original.binding();
            let b = burn_a.bundle.as_mut().unwrap();
            b.burn_a = 500;
            b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &binding);
        }
        assert_eq!(
            l.validate(&burn_a, &StubExecutor),
            Err(TxError::InvalidBundleProof(crate::confidential::ConfidentialError::InvalidBundleProof("PublicValues".into())))
        );
        // The original is untouched by all of that.
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

    /// The same redirect across backings (spec §12): a burn of zUSD naming USDT on chain 2 copied
    /// to name USDC on chain 5 — another coin, another source contract.
    #[test]
    fn a_burns_proofs_cannot_ride_another_backing() {
        const USDT: [u8; 32] = [0xd7; 32];
        const USDC: [u8; 32] = [0xdc; 32];
        let (mut l, secrets) = ledger();
        let mut registry = TokenRegistry::new(1_000_000_000);
        let zusd = registry
            .register(
                crate::ledger::tokens::bridged_asset_id("Rand USD", "zUSD", &[0x5a; 32]),
                "Rand USD".into(),
                "zUSD".into(),
                8,
                crate::ledger::tokens::MintAuthority::Bridge {
                    backings: vec![
                        crate::ledger::tokens::Backing { chain: 2, token: USDT, decimals: 8, locked: 0, minted_today: 0, mint_day: 0 },
                        crate::ledger::tokens::Backing { chain: 5, token: USDC, decimals: 8, locked: 0, minted_today: 0, mint_day: 0 },
                    ],
                },
                0,
            )
            .unwrap();
        l.set_tokens(Some(registry));
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
        for (i, (chain, token, amount)) in [(2u16, USDT, 1_000u128), (5, USDC, 400)].into_iter().enumerate() {
            let tx = attest_tx(&l, attest(&secrets, inbound(chain, token, amount, i as u64)), recipient(), 20 + 10 * i as u32);
            l.apply_tx(&tx, &proposer().address(), &StubExecutor).unwrap();
        }
        let original = burn_tx_to(&l, zusd, 300, 0, 2, USDT, EVM_TO, 50, |_| {});
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        let other_coin = altered(&original, |a| {
            let Action::BridgeBurn { to_chain, token, to, .. } = a else { panic!("a burn") };
            (*to_chain, *token, *to) = (5, USDC, [0x77; 32]);
        });
        assert!(
            matches!(l.validate(&other_coin, &StubExecutor), Err(TxError::InvalidBundleProof(_))),
            "{:?}",
            l.validate(&other_coin, &StubExecutor)
        );
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

    /// An attestation's deposit fields are the relayer's to choose, and a copier could otherwise
    /// swap the ones the guardians do not sign — the blinding `r`, the note's `time`, the envelope
    /// the recipient needs to open the note (garbage there strands the deposit). The recipient is
    /// also bound by the attestation itself. Each copy is refused, and the original validates.
    #[test]
    fn an_attests_fee_bundle_cannot_ride_a_changed_deposit() {
        let (mut l, secrets) = ledger();
        l.set_height(9);
        l.record_anchor(9);
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let original = attest_tx(&l, a, recipient(), 20);
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        let recipient_swapped = altered(&original, |a| {
            let Action::BridgeAttest { recipient, .. } = a else { panic!("an attest") };
            *recipient = ShieldedAddress { pk: [9; 8], kem_ek: vec![6; 32] };
        });
        assert!(l.validate(&recipient_swapped, &StubExecutor).is_err(), "`recipient` changed");
        type Change = Box<dyn Fn(&mut Action)>;
        let cases: Vec<(&str, Change)> = vec![
            (
                "r",
                Box::new(|a| {
                    let Action::BridgeAttest { r, .. } = a else { panic!("an attest") };
                    *r = [8; 8];
                }),
            ),
            (
                "time",
                Box::new(|a| {
                    let Action::BridgeAttest { time, .. } = a else { panic!("an attest") };
                    *time = 5;
                }),
            ),
            (
                "envelope",
                Box::new(|a| {
                    let Action::BridgeAttest { envelope, .. } = a else { panic!("an attest") };
                    envelope.body = vec![0xee; 8];
                }),
            ),
        ];
        let accepted: Vec<String> = cases
            .into_iter()
            .map(|(what, change)| (what, l.validate(&altered(&original, change), &StubExecutor)))
            // A changed `r` is refused one step earlier since F1, by the blinding rule: no `r`
            // but the digest's is admissible at all, so there is no other one for the binding to
            // be the last line against.
            .filter(|(what, got)| {
                !matches!(got, Err(TxError::InvalidBundleProof(_)))
                    && !(*what == "r" && *got == Err(TxError::Bridge(BridgeError::WrongDepositBlinding)))
            })
            .map(|(what, got)| format!("`{what}` changed: {got:?}"))
            .collect();
        assert!(accepted.is_empty(), "{accepted:#?}");
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

    /// A bundle lifted whole — proof and all — off a plain transfer and put under an attest,
    /// and a burn's bundle lifted into another burn with a destination of the thief's choosing.
    /// Neither proof was made for the transaction it is now in.
    #[test]
    fn a_bundle_lifted_into_another_transaction_is_refused() {
        let (mut l, secrets) = ledger();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        let plain = StubExecutor::bound(Transaction::shielded(
            7,
            fee_bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], gas::BUNDLE_BASE),
            Action::None,
        ));
        assert_eq!(l.validate(&plain, &StubExecutor), Ok(()));
        let a = attest(&secrets, transfer(2_000, 0, recipient().recipient_hash(), 1));
        let honest_attest = attest_tx(&l, a, recipient(), 70);
        assert_eq!(l.validate(&honest_attest, &StubExecutor), Ok(()));
        let lifted_fee = Transaction { bundle: plain.bundle.clone(), ..honest_attest.clone() };

        let burn = burn_tx(&l, 1, 400, 100, |_| {});
        assert_eq!(l.validate(&burn, &StubExecutor), Ok(()));
        let lifted_burn = Transaction::shielded(
            7,
            burn.bundle.clone().unwrap(),
            Action::BridgeBurn { asset: 1, amount: 400, relayer_fee: 100, to_chain: 2, token: TOKEN, to: THIEF_TO },
        );
        let accepted: Vec<String> = [("a transfer's bundle onto an attest", &lifted_fee), ("a burn's bundle into a new burn", &lifted_burn)]
            .into_iter()
            .map(|(what, t)| (what, l.validate(t, &StubExecutor)))
            .filter(|(_, got)| !matches!(got, Err(TxError::InvalidBundleProof(_))))
            .map(|(what, got)| format!("{what}: {got:?}"))
            .collect();
        assert!(accepted.is_empty(), "{accepted:#?}");
        assert_eq!(l.validate(&plain, &StubExecutor), Ok(()));
        assert_eq!(l.validate(&honest_attest, &StubExecutor), Ok(()));
        assert_eq!(l.validate(&burn, &StubExecutor), Ok(()));
    }

    // ---- B3: the Dilithium2 co-signature ------------------------------------------------------

    /// A mint whose ECDSA quorum is valid but that carries no PQ co-signatures is refused at
    /// admission, and so is one short of the PQ quorum; the relayer's lowest five is admitted and
    /// deposits. The digest is not consumed by a refusal.
    #[test]
    fn a_mint_without_its_pq_quorum_is_refused() {
        let (mut l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let none = attest_tx_cosigned(&l, a.clone(), recipient(), 20, &[]);
        assert_eq!(
            l.validate(&none, &StubExecutor),
            Err(TxError::Bridge(BridgeError::PqNoQuorum { have: 0, need: 5, n: 6 }))
        );
        let four = attest_tx_cosigned(&l, a.clone(), recipient(), 20, &[0, 1, 2, 3]);
        assert!(matches!(l.validate(&four, &StubExecutor), Err(TxError::Bridge(BridgeError::PqNoQuorum { have: 4, .. }))));
        assert!(l.bridge().unwrap().spent.is_empty());
        let five = attest_tx_cosigned(&l, a, recipient(), 20, &[1, 2, 3, 4, 5]);
        l.apply_tx(&five, &proposer().address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&expected_cm(&five, 1, 1_000, 1)));
    }

    /// The co-signatures are inside the transaction binding: a copy of an honest attest whose PQ
    /// list is swapped for another *valid* quorum (so nothing but the binding can object) keeps
    /// none of the original's fee-bundle proof — and a copy with the list stripped is refused too.
    #[test]
    fn the_binding_covers_the_pq_signatures() {
        let (l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let original = attest_tx(&l, a.clone(), recipient(), 20);
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        let other_quorum = cosign_by(&[1, 2, 3, 4, 5], &a);
        let swapped = altered(&original, |act| {
            let Action::BridgeAttest { pq_signatures, .. } = act else { panic!("an attest") };
            *pq_signatures = other_quorum.clone();
        });
        assert!(matches!(l.validate(&swapped, &StubExecutor), Err(TxError::InvalidBundleProof(_))), "a swapped PQ quorum");
        let stripped = altered(&original, |act| {
            let Action::BridgeAttest { pq_signatures, .. } = act else { panic!("an attest") };
            pq_signatures.clear();
        });
        assert!(l.validate(&stripped, &StubExecutor).is_err(), "a stripped PQ quorum");
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

    /// The co-signature is over this chain's id: a quorum signed for another Rand chain is refused
    /// here, even with every other byte of the transaction honest.
    #[test]
    fn a_pq_quorum_for_another_chain_is_refused_at_admission() {
        let (l, secrets) = ledger();
        let a = attest(&secrets, transfer(1_000, 0, recipient().recipient_hash(), 0));
        let mu = digest(Attestation::body_bytes(&a).unwrap());
        let keys = pq_keys();
        let foreign: Vec<PqSignature> = (0..5u8).map(|i| pq_cosign(&keys[i as usize], i, 8, &mu)).collect();
        let mut tx = attest_tx(&l, a, recipient(), 20);
        let Action::BridgeAttest { pq_signatures, .. } = &mut tx.action else { panic!("an attest") };
        *pq_signatures = foreign;
        let tx = StubExecutor::bound(tx);
        assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::Bridge(BridgeError::PqBadSignature { index: 0 })));
    }

    // ---- bridge hardening B1 through the ledger: the pause, the unpause and the daily cap ------

    /// The genesis pause key of [`cfg`] — none of the PQ guardians' keys.
    fn pause_key() -> Keypair {
        Keypair::from_seed([0x7f; 32]).unwrap()
    }

    /// A bundle-less `PauseMints` at `nonce`, signed by `key` on chain 7.
    fn pause_tx(key: &Keypair, nonce: u64) -> Transaction {
        let signature = key.sign(&crate::bridge::gov::pause_message(7, nonce));
        Transaction { chain_id: 7, bundle: None, action: Action::PauseMints { nonce, signature } }
    }

    /// A bundle-less `UnpauseMints` at `nonce`, co-signed by the PQ guardians at `indices`.
    fn unpause_tx(indices: &[u8], nonce: u64) -> Transaction {
        let keys = pq_keys();
        let m = crate::bridge::gov::unpause_message(7, nonce);
        let pq_signatures = indices
            .iter()
            .map(|&i| PqSignature { index: i, signature: keys[i as usize].sign(&m).as_bytes().to_vec() })
            .collect();
        Transaction { chain_id: 7, bundle: None, action: Action::UnpauseMints { nonce, pq_signatures } }
    }

    fn paused(l: &Ledger) -> (bool, u64) {
        let b = l.bridge().unwrap();
        (b.mint_paused, b.pause_nonce)
    }

    /// The pause, end to end through `validate` and `apply_tx`: the pause key pauses (bundle-less,
    /// no fee), a replayed pause is refused, a transfer attest is refused `MintsPaused` while a
    /// burn and a rotation go through, the pause key can never unpause, a short or a stranger's
    /// quorum is refused, and a PQ quorum unpauses — after which the same attestation mints.
    #[test]
    fn the_pause_key_pauses_and_only_a_pq_quorum_unpauses() {
        let (mut l, secrets) = ledger();
        let proposer = proposer().address();
        deposit(&mut l, &secrets, 1_000, 0, 20);
        // A wrong key, then a pause signed for another nonce or another chain, are refused.
        let stranger = Keypair::from_seed([0x55; 32]).unwrap();
        assert_eq!(l.validate(&pause_tx(&stranger, 0), &StubExecutor), Err(TxError::Bridge(BridgeError::BadPauseSignature)));
        // The nonce is judged before the signature, so the one cached pause verdict
        // (`BadPauseSignature`, node admission's `is_permanent`) is reached only by a transaction
        // whose own nonce, chain id and signature bytes decide it.
        assert_eq!(
            l.validate(&pause_tx(&stranger, 3), &StubExecutor),
            Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: 0, got: 3 }))
        );
        assert_eq!(
            l.validate(&pause_tx(&pause_key(), 1), &StubExecutor),
            Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: 0, got: 1 }))
        );
        let mut other_chain = pause_tx(&pause_key(), 0);
        other_chain.action = Action::PauseMints {
            nonce: 0,
            signature: pause_key().sign(&crate::bridge::gov::pause_message(8, 0)),
        };
        assert_eq!(l.validate(&other_chain, &StubExecutor), Err(TxError::Bridge(BridgeError::BadPauseSignature)));
        // Unpausing an unpaused bridge is refused: it would only move the nonce past a pause the
        // key may already have signed.
        assert_eq!(l.validate(&unpause_tx(&[0, 1, 2, 3, 4], 0), &StubExecutor), Err(TxError::Bridge(BridgeError::NotPaused)));

        // The pause key pauses. No bundle, no fee.
        let pause = pause_tx(&pause_key(), 0);
        assert_eq!(pause.bundle, None);
        l.apply_tx(&pause, &proposer, &StubExecutor).unwrap();
        assert_eq!(paused(&l), (true, 1));
        // Replayed: the nonce moved on.
        assert_eq!(l.validate(&pause, &StubExecutor), Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: 1, got: 0 })));
        // The key's only other lever, a fresh pause at the current nonce, pauses nothing further.
        assert_eq!(l.validate(&pause_tx(&pause_key(), 1), &StubExecutor), Err(TxError::Bridge(BridgeError::AlreadyPaused)));

        // A transfer is refused while paused…
        let a = attest(&secrets, transfer(500, 0, recipient().recipient_hash(), 1));
        let mint = attest_tx(&l, a, recipient(), 70);
        assert_eq!(l.validate(&mint, &StubExecutor), Err(TxError::Bridge(BridgeError::MintsPaused)));
        // …while a burn and a guardian-set rotation go through.
        l.apply_tx(&burn_tx(&l, 1, 400, 0, |_| {}), &proposer, &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 600, "redemption is never trapped");
        let rotation = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: CHAIN_RAND,
            emitter_address: crate::bridge::GOVERNANCE_EMITTER,
            sequence: 9,
            consistency_level: 0,
            payload: Payload::GuardianSetUpgrade(crate::bridge::GuardianSetUpgrade {
                new_index: 1,
                keys: (1u8..=6).map(|i| guardian_address(&[i; 32])).collect(),
            })
            .encode(),
        };
        let rotate = attest_tx(&l, attest(&secrets, rotation), recipient(), 50);
        l.apply_tx(&rotate, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().current_set, 1);

        // The pause key cannot unpause: filed as a PQ quorum it is short, and in a full-length
        // list its signature is not a guardian's.
        let m = crate::bridge::gov::unpause_message(7, 1);
        let by_pause_key = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::UnpauseMints {
                nonce: 1,
                pq_signatures: vec![PqSignature { index: 0, signature: pause_key().sign(&m).as_bytes().to_vec() }],
            },
        };
        assert!(matches!(l.validate(&by_pause_key, &StubExecutor), Err(TxError::Bridge(BridgeError::PqNoQuorum { have: 1, need: 5, n: 6 }))));
        let mut padded = unpause_tx(&[0, 1, 2, 3, 4], 1);
        let Action::UnpauseMints { pq_signatures, .. } = &mut padded.action else { panic!() };
        pq_signatures[0].signature = pause_key().sign(&m).as_bytes().to_vec();
        assert_eq!(l.validate(&padded, &StubExecutor), Err(TxError::Bridge(BridgeError::PqBadSignature { index: 0 })));
        // A short quorum, and a quorum over the wrong nonce, are refused.
        assert!(matches!(
            l.validate(&unpause_tx(&[0, 1, 2, 3], 1), &StubExecutor),
            Err(TxError::Bridge(BridgeError::PqNoQuorum { have: 4, need: 5, n: 6 }))
        ));
        assert_eq!(
            l.validate(&unpause_tx(&[0, 1, 2, 3, 4], 0), &StubExecutor),
            Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: 1, got: 0 }))
        );
        // Still paused through all of that.
        assert_eq!(paused(&l), (true, 1));

        // Any quorum of the PQ guardians unpauses.
        let unpause = unpause_tx(&[1, 2, 3, 4, 5], 1);
        l.apply_tx(&unpause, &proposer, &StubExecutor).unwrap();
        assert_eq!(paused(&l), (false, 2));
        assert_eq!(
            l.validate(&unpause, &StubExecutor),
            Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: 2, got: 1 })),
            "an unpause is not replayable either"
        );
        // And the refused transfer, signed by the set the rotation superseded (still in its
        // grace window), now mints.
        l.apply_tx(&mint, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 1_100);
        assert!(l.tokens().unwrap().backing_invariant_holds());
    }

    /// Pause and unpause ride without a bundle: one carrying a bundle is refused by shape, and a
    /// chain without a bridge refuses both before anything else.
    #[test]
    fn pause_and_unpause_are_bundle_less_and_gated_on_the_bridge() {
        let (l, _) = ledger();
        let mut with_bundle = pause_tx(&pause_key(), 0);
        with_bundle.bundle = Some(fee_bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], gas::BUNDLE_BASE));
        assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::ActionCarriesBundle("pause_mints")));
        let mut plain = l.clone();
        plain.set_bridge(None);
        assert_eq!(plain.validate(&pause_tx(&pause_key(), 0), &StubExecutor), Err(TxError::Bridge(BridgeError::Disabled)));
        assert_eq!(plain.validate(&unpause_tx(&[0, 1, 2, 3, 4], 0), &StubExecutor), Err(TxError::Bridge(BridgeError::Disabled)));
    }

    /// The daily cap through the ledger, on the block's own timestamp: exactly the cap in one
    /// block is admitted; two attests that each fit but together pass it cannot share a block —
    /// the second is refused where it sits and the block leaves the ledger untouched; the next
    /// UTC day of the block time counts from zero; a second backing of the same token has its
    /// own allowance.
    #[test]
    fn the_daily_cap_binds_per_backing_across_a_block_and_resets_with_the_block_day() {
        let (mut l, secrets) = ledger();
        let proposer = proposer().address();
        // Token 1 gets a second coin, and the registry a cap of 1 000 per backing per day.
        let mut tokens = l.tokens().unwrap().clone().with_mint_cap(1_000);
        tokens.add_backing(1, 3, [0xdd; 32], 8).unwrap();
        l.set_tokens(Some(tokens));
        let day = |l: &Ledger| (l.timestamp_ms() / 86_400_000) as u32;
        let attest_of = |l: &Ledger, chain: u16, token: [u8; 32], amount: u128, seq: u64, seed: u32| {
            let mut body = transfer_of(token, amount, 0, recipient().recipient_hash(), seq);
            body.emitter_chain = chain;
            body.emitter_address = [chain as u8; 32];
            if let Payload::Transfer(mut t) = Payload::decode(&body.payload).unwrap() {
                t.token_chain = chain;
                body.payload = Payload::Transfer(t).encode();
            }
            attest_tx(l, attest(&secrets, body), recipient(), seed)
        };
        let one = attest_of(&l, 2, TOKEN, 600, 1, 100);
        let two = attest_of(&l, 2, TOKEN, 500, 2, 110);
        // Each fits on its own…
        assert_eq!(l.validate(&one, &StubExecutor), Ok(()));
        assert_eq!(l.validate(&two, &StubExecutor), Ok(()));
        // …and not both in one block: the second is refused by index, the ledger left as it was.
        let before = l.clone();
        let refused = l.apply_transactions(&[one.clone(), two.clone()], &proposer, &StubExecutor).unwrap_err();
        assert_eq!(
            refused,
            crate::ledger::BlockError::InvalidTx {
                index: 1,
                error: TxError::Bridge(BridgeError::Token(TokenError::MintCapExceeded { cap: 1_000, minted_today: 600, amount: 500 })),
            }
        );
        assert_eq!(l.tokens(), before.tokens(), "a refused block moved no counter");
        // Exactly the cap in one block is admitted; one unit more is refused.
        let rest = attest_of(&l, 2, TOKEN, 400, 3, 120);
        l.apply_transactions(&[one, rest], &proposer, &StubExecutor).unwrap();
        let b = l.tokens().unwrap().backing(1, 2, &TOKEN).unwrap().clone();
        assert_eq!((b.minted_today, b.mint_day, b.locked), (1_000, day(&l), 1_000));
        let over = attest_of(&l, 2, TOKEN, 1, 4, 130);
        assert_eq!(
            l.validate(&over, &StubExecutor),
            Err(TxError::Bridge(BridgeError::Token(TokenError::MintCapExceeded { cap: 1_000, minted_today: 1_000, amount: 1 })))
        );
        // The chain-3 coin backs the same token and has its own day's allowance.
        l.apply_tx(&attest_of(&l, 3, [0xdd; 32], 1_000, 5, 140), &proposer, &StubExecutor).unwrap();
        assert_eq!(l.tokens().unwrap().get(1).unwrap().total_supply, 2_000);
        // At the next UTC day of the block time the chain-2 coin counts from zero again.
        let next_day = (l.timestamp_ms() / 86_400_000 + 1) * 86_400_000;
        l.set_timestamp_ms(next_day);
        let over = attest_of(&l, 2, TOKEN, 1, 4, 130);
        l.apply_tx(&over, &proposer, &StubExecutor).unwrap();
        let b = l.tokens().unwrap().backing(1, 2, &TOKEN).unwrap().clone();
        assert_eq!((b.minted_today, b.mint_day, b.locked), (1, day(&l), 1_001));
        assert!(l.tokens().unwrap().backing_invariant_holds());
    }
}
