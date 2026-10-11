//! The viewing-key layer: how a note's plaintext travels with its transaction, who can open
//! it, and how an opened row is checked against the chain.
//!
//! Every transfer publishes an [`Envelope`] next to its proof. The envelope carries the
//! created note's plaintext under a fresh per-transaction key, and that key is wrapped twice:
//! once to the receiver's address (ML-KEM-768, so the receiver's *viewing key* — which owns
//! the decapsulation key — can open it) and once under the sender's outgoing viewing key
//! (`ViewingKey::ovk`). Three keys therefore open a transaction, and they are the three
//! scopes of disclosure:
//!
//! | key handed over | who holds it | what it opens |
//! |---|---|---|
//! | `ViewingKey` of a party | the party's wallet | every transaction the party sent or received — its history, nothing else |
//! | `TxKey` of one transaction | sender and receiver | that one transaction |
//! | `SpendKey` | the owner only | never needed to view; needed to prove |
//!
//! Every ciphertext is ChaCha20-Poly1305 with the on-chain commitment `cm_out` as associated
//! data, so an envelope cannot be re-attached to another transaction, and a wrong key fails
//! authentication instead of yielding garbage — which is what makes a scan with one party's
//! key silent about everyone else's transactions.
//!
//! Phase Z: a `ledger::Bundle` publishes *two* envelopes, one per output slot, each sealed
//! against its own slot's commitment by exactly the machinery above — nothing about an
//! envelope changes for a bundle. What changes is the indexing: a [`Row`] now says which
//! sequence it came from ([`RowSource`]) and which of a bundle's two slots it is about
//! (`Row::slot`), and [`scan`]/[`verify_row`] read `commitments[slot]`/`nullifiers[slot]`
//! where they used to read a transfer's single `cm_out`/`nf`.

use crate::ledger::Ledger;
use crate::notes::{words_to_bytes, Note, ViewingKey, Word8};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::FromSeed;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem768};
use rand::Rng;

type Dk = ml_kem::ml_kem_768::DecapsulationKey;
type Ek = ml_kem::ml_kem_768::EncapsulationKey;
type KemCt = ml_kem::ml_kem_768::Ciphertext;

/// A party's address as a sender needs it: the note owner field `pk` plus the ML-KEM
/// encapsulation key envelopes are sealed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address { pub pk: Word8, pub kem_ek: Vec<u8> }

impl ViewingKey {
    pub fn address(&self) -> Address { self.address_at(0) }
    /// The ML-KEM-768 keypair for key version `v`, from `kem_seed_at(v)` (`notes.rs`).
    pub fn kem_keys_at(&self, version: u32) -> (Dk, Ek) { MlKem768::from_seed(&ml_kem::Seed::from(self.kem_seed_at(version))) }
    /// The address a sender uses to seal an envelope under key version `v`: `pk` never
    /// changes with the version (it does not depend on the KEM key at all), only `kem_ek`
    /// does.
    pub fn address_at(&self, version: u32) -> Address {
        let (_, ek) = self.kem_keys_at(version);
        Address { pk: self.pk(), kem_ek: ek.to_bytes().to_vec() }
    }
    /// The keys a scan opens envelopes with, under KEM version 0. Equals `scan_key_at(0)`.
    pub fn scan_key(&self) -> ScanKey { self.scan_key_at(0) }
    /// The keys a scan opens envelopes with, under KEM key version `version`: derived once
    /// for the whole scan rather than once per leaf.
    pub fn scan_key_at(&self, version: u32) -> ScanKey {
        let (dk, _) = self.kem_keys_at(version);
        ScanKey { dk, ovk: self.ovk() }
    }
}

/// What a scan needs to open envelopes, derived from a [`ViewingKey`] once: the ML-KEM
/// decapsulation key of one key version and the outgoing viewing key. Deriving the KEM keypair
/// from its seed costs about as much as the decapsulation it serves (17 µs and 21 µs on an M4
/// Max), so a scan that derived it per leaf spent half its time re-deriving one key.
#[derive(Clone)]
pub struct ScanKey { dk: Dk, ovk: [u8; 32] }

/// The bytes of an [`EnvelopeHead`]: `kem_ct` (1 088) ‖ `to_receiver` (60) ‖ `to_sender` (60).
pub const ENVELOPE_HEAD_BYTES: usize = KEM_CT_BYTES + WRAPPED_KEY_BYTES + WRAPPED_KEY_BYTES;
const KEM_CT_BYTES: usize = 1088;
/// A wrapped `TxKey`: 12-byte nonce ‖ 32-byte key ‖ 16-byte tag.
const WRAPPED_KEY_BYTES: usize = 12 + 32 + 16;

/// An [`Envelope`] less its body: the parts that decide whether a key opens it, and yield the
/// transaction key if so. The same 1 208 bytes for both body layouts, so a scan can page heads
/// alone and fetch the body only of the leaves a key opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeHead {
    pub kem_ct: Vec<u8>,
    pub to_receiver: Vec<u8>,
    pub to_sender: Vec<u8>,
}

impl EnvelopeHead {
    /// `kem_ct ‖ to_receiver ‖ to_sender`.
    pub fn to_bytes(&self) -> Vec<u8> { [&self.kem_ct[..], &self.to_receiver, &self.to_sender].concat() }
    /// The head [`EnvelopeHead::to_bytes`] wrote; `None` unless exactly
    /// [`ENVELOPE_HEAD_BYTES`] long.
    pub fn from_bytes(b: &[u8]) -> Option<EnvelopeHead> {
        if b.len() != ENVELOPE_HEAD_BYTES { return None; }
        let (kem_ct, rest) = b.split_at(KEM_CT_BYTES);
        let (to_receiver, to_sender) = rest.split_at(WRAPPED_KEY_BYTES);
        Some(EnvelopeHead { kem_ct: kem_ct.to_vec(), to_receiver: to_receiver.to_vec(), to_sender: to_sender.to_vec() })
    }
    /// The transaction key, if `key`'s KEM version opens this head as its receiver.
    pub fn receiver_key(&self, cm: Word8, key: &ScanKey) -> Option<TxKey> {
        let ct = KemCt::try_from(&self.kem_ct[..]).ok()?;
        let ss: [u8; 32] = key.dk.decapsulate(&ct).into();
        Some(TxKey(open(&ss, &aad(AAD_RECEIVER, cm), &self.to_receiver)?.try_into().ok()?))
    }
    /// The transaction key, if `key`'s `ovk` opens this head as its sender.
    pub fn sender_key(&self, cm: Word8, key: &ScanKey) -> Option<TxKey> {
        Some(TxKey(open(&key.ovk, &aad(AAD_SENDER, cm), &self.to_sender)?.try_into().ok()?))
    }
}

/// The per-transaction disclosure key. Handing it over discloses exactly one transaction.
///
/// **Wallet obligation: one fresh key per sealed envelope, never reused.** A
/// [`Disclosure::Transaction`] carries a bare index `tx` that does not say which of the
/// ledger's two independently numbered sequences it means, so [`scan`] tries both. That is
/// unambiguous exactly as long as a key opens one envelope: each envelope binds its own
/// `cm_out` as AEAD associated data, so a key cannot open an envelope it did not seal — but
/// two envelopes sealed under the *same* key, one in `ledger.txs[i]` and one in
/// `ledger.bundles[i]`, would both open under `Disclosure::Transaction { tx: i, .. }`, and
/// both rows would pass `verify_row`. The disclosure would then be wider than the "exactly one
/// transaction" this type promises. Nothing in this module can prevent that — the key is the
/// caller's to generate and hand out — so it is the wallet's rule; `random` is how it is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxKey(pub [u8; 32]);
impl TxKey {
    pub fn random() -> Self { let mut k = [0u8; 32]; rand::rng().fill_bytes(&mut k); TxKey(k) }
}

/// What travels with a transaction besides its proof. Nothing in it is checked by the
/// ledger; it exists only so the right keys can open the note later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// ML-KEM-768 ciphertext to the receiver's address.
    pub kem_ct: Vec<u8>,
    /// `TxKey` under the KEM shared secret.
    pub to_receiver: Vec<u8>,
    /// `TxKey` under the sender's `ovk`.
    pub to_sender: Vec<u8>,
    /// The note plaintext under `TxKey`.
    pub body: Vec<u8>,
}

const AAD_RECEIVER: &[u8] = b"rand-envelope-receiver";
const AAD_SENDER: &[u8] = b"rand-envelope-sender";
const AAD_BODY: &[u8] = b"rand-envelope-body";

fn aad(tag: &[u8], cm: Word8) -> Vec<u8> { [tag, &words_to_bytes(&cm)].concat() }

/// Random-nonce ChaCha20-Poly1305; the 12-byte nonce is prepended to the ciphertext.
fn seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(*key)).encrypt(&Nonce::from(nonce), Payload { msg: pt, aad }).expect("aead");
    [&nonce[..], &ct].concat()
}
fn open(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < 12 { return None; }
    let nonce: [u8; 12] = ct[..12].try_into().ok()?;
    ChaCha20Poly1305::new(&Key::from(*key)).decrypt(&Nonce::from(nonce), Payload { msg: &ct[12..], aad }).ok()
}

/// The memo that rides in a note's body (fullnode spec 2026-09-26 §2.3): a fixed 512-byte field
/// so its presence and length never show on chain.
pub const MEMO_FIELD_BYTES: usize = 512;
/// `len` (u16 LE) ‖ text ‖ zero padding: at most 510 bytes of UTF-8.
pub const MEMO_TEXT_MAX_BYTES: usize = MEMO_FIELD_BYTES - 2;

/// The field for `text`, or `None` if it does not fit.
pub fn memo_field(text: &str) -> Option<[u8; MEMO_FIELD_BYTES]> {
    let t = text.as_bytes();
    if t.len() > MEMO_TEXT_MAX_BYTES { return None; }
    let mut f = [0u8; MEMO_FIELD_BYTES];
    f[..2].copy_from_slice(&(t.len() as u16).to_le_bytes());
    f[2..2 + t.len()].copy_from_slice(t);
    Some(f)
}

/// The text a field carries: `None` for an empty field and for any malformed one — a bad
/// length, invalid UTF-8, or non-zero padding. A malformed memo never costs the payee the note.
pub fn memo_text(field: &[u8]) -> Option<String> {
    if field.len() != MEMO_FIELD_BYTES { return None; }
    let len = u16::from_le_bytes([field[0], field[1]]) as usize;
    if len == 0 || len > MEMO_TEXT_MAX_BYTES { return None; }
    if field[2 + len..].iter().any(|&b| b != 0) { return None; }
    String::from_utf8(field[2..2 + len].to_vec()).ok()
}

/// The body plaintext: the note alone (the original layout) or the note and a memo field.
fn body_parts(pt: &[u8]) -> Option<(Note, Option<&[u8]>)> {
    match pt.len() {
        n if n == Note::BYTES => Some((Note::from_bytes(pt)?, None)),
        n if n == Note::BYTES + MEMO_FIELD_BYTES => Some((Note::from_bytes(&pt[..Note::BYTES])?, Some(&pt[Note::BYTES..]))),
        _ => None,
    }
}

impl Envelope {
    /// Seals `note` (which must be the note whose commitment the transaction publishes) to
    /// `receiver`, with a copy of `tx_key` for `sender`'s viewing key.
    pub fn seal(sender: &ViewingKey, receiver: &Address, note: &Note, tx_key: &TxKey) -> Envelope {
        let cm = note.commitment();
        let ek = Ek::new(&ml_kem::kem::Key::<Ek>::try_from(&receiver.kem_ek[..]).expect("1184-byte encapsulation key")).expect("valid encapsulation key");
        let (kem_ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
        let ss: [u8; 32] = ss.into();
        Envelope {
            kem_ct: kem_ct.to_vec(),
            to_receiver: seal(&ss, &aad(AAD_RECEIVER, cm), &tx_key.0),
            to_sender: seal(&sender.ovk(), &aad(AAD_SENDER, cm), &tx_key.0),
            body: seal(&tx_key.0, &aad(AAD_BODY, cm), &note.to_bytes()),
        }
    }

    /// Seals `note` and a memo field to `receiver`: the same four parts as [`Envelope::seal`],
    /// the body carrying `note ‖ memo` (1 860 bytes in all).
    pub fn seal_with_memo(sender: &ViewingKey, receiver: &Address, note: &Note, tx_key: &TxKey, memo: &[u8; MEMO_FIELD_BYTES]) -> Envelope {
        let mut e = Envelope::seal(sender, receiver, note, tx_key);
        let pt = [&note.to_bytes()[..], &memo[..]].concat();
        e.body = seal(&tx_key.0, &aad(AAD_BODY, note.commitment()), &pt);
        e
    }

    /// Opens the note with the transaction key. `cm` is the on-chain commitment the
    /// envelope was published with.
    pub fn open_with_tx_key(&self, cm: Word8, key: &TxKey) -> Option<Note> {
        let pt = open(&key.0, &aad(AAD_BODY, cm), &self.body)?;
        let (note, _) = body_parts(&pt)?;
        (note.commitment() == cm).then_some(note)
    }

    /// The memo sealed with the note, if any: open the body with the transaction key (from
    /// [`Envelope::open_as_receiver`], [`Envelope::open_as_sender`] or a disclosure).
    pub fn memo(&self, cm: Word8, key: &TxKey) -> Option<String> {
        let pt = open(&key.0, &aad(AAD_BODY, cm), &self.body)?;
        let (note, memo) = body_parts(&pt)?;
        if note.commitment() != cm { return None; }
        memo_text(memo?)
    }
    /// Opens as the receiver: decapsulate, unwrap the transaction key, open the body. Equals
    /// `open_as_receiver_at(cm, vk, 0)`.
    pub fn open_as_receiver(&self, cm: Word8, vk: &ViewingKey) -> Option<(TxKey, Note)> {
        self.open_as_receiver_at(cm, vk, 0)
    }
    /// Opens as the receiver under KEM key version `version`: only the address the envelope
    /// was actually sealed to (`ViewingKey::address_at(version)`) opens it — a wrong version,
    /// like a wrong key entirely, fails AEAD authentication and returns `None`.
    pub fn open_as_receiver_at(&self, cm: Word8, vk: &ViewingKey, version: u32) -> Option<(TxKey, Note)> {
        self.open_as_receiver_with(cm, &vk.scan_key_at(version))
    }
    /// Opens as the sender, through `ovk`.
    pub fn open_as_sender(&self, cm: Word8, vk: &ViewingKey) -> Option<(TxKey, Note)> {
        self.open_as_sender_with(cm, &vk.scan_key())
    }
    /// [`Envelope::open_as_receiver_at`] under a [`ScanKey`] derived once — what a scan
    /// opening leaf after leaf calls.
    pub fn open_as_receiver_with(&self, cm: Word8, key: &ScanKey) -> Option<(TxKey, Note)> {
        let tx_key = self.head().receiver_key(cm, key)?;
        Some((tx_key, self.open_with_tx_key(cm, &tx_key)?))
    }
    /// [`Envelope::open_as_sender`] under a [`ScanKey`] derived once.
    pub fn open_as_sender_with(&self, cm: Word8, key: &ScanKey) -> Option<(TxKey, Note)> {
        let tx_key = self.head().sender_key(cm, key)?;
        Some((tx_key, self.open_with_tx_key(cm, &tx_key)?))
    }
    /// The envelope less its body ([`EnvelopeHead`]).
    pub fn head(&self) -> EnvelopeHead {
        EnvelopeHead { kem_ct: self.kem_ct.clone(), to_receiver: self.to_receiver.clone(), to_sender: self.to_sender.clone() }
    }
}

/// What an auditor is handed. Scope is the type: a party, or one transaction.
#[derive(Clone, Debug)]
pub enum Disclosure {
    Party(ViewingKey),
    Transaction { tx: usize, key: TxKey },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { Received, Sent, Transaction }

/// Which of the ledger's two independently numbered transaction sequences a [`Row`]'s `tx`
/// indexes: `ledger.txs` (a transfer or a mint) or `ledger.bundles`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowSource { Transfer, Bundle }

/// One row of disclosed history: the travel-rule fields, and the openings that let anyone
/// holding the same disclosure check the row against the chain (`verify_row`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Index into `ledger.txs` or `ledger.bundles`, per `source`.
    pub tx: usize,
    pub source: RowSource,
    /// Which of a bundle's two slots this row is about — 0 or 1. Always 0 for a
    /// `RowSource::Transfer` row, which only ever had one commitment and one nullifier.
    ///
    /// A bundle's slots are paired positionally: slot `s` names `commitments[s]`,
    /// `envelopes[s]` and `nullifiers[s]`. The pairing is a convention, not a fact about the
    /// bundle — a 2-in-2-out bundle's two inputs and two outputs have no natural
    /// correspondence — but it is the *same* convention `scan` and `verify_row` use, so a row
    /// produced by one is checkable by the other.
    pub slot: u8,
    pub role: Role,
    pub sender: Word8,
    pub receiver: Word8,
    pub amount: u64,
    pub asset: u32,
    pub time: u32,
    /// The created note's on-chain commitment.
    pub cm_out: Word8,
    /// The spent note's nullifier, as the chain published it (mints have none). M3.3: the
    /// spent note's *commitment* is never public (`MERKLE_VERIFY` proves it in-circuit
    /// against an anchor) — only the nullifier is, which is enough to recompute and check
    /// (`verify_row`) since the nullifier is bound to the commitment.
    pub nf: Option<Word8>,
    /// The created note, opened.
    pub note: Note,
    /// For a `Sent` row: the note that was spent, opened — the party's own earlier `Received`
    /// note whose nullifier (under the party's `nk`) is `nf`. What lets the nullifier be
    /// recomputed.
    ///
    /// `None` on a transfer row means a mint, and only a mint (created from nothing, no
    /// nullifier at all): a transfer that spends a note the party received is always able to
    /// name it, whichever sequence paid it — `scan` collects the party's whole history across
    /// both before resolving any nullifier. On a
    /// bundle row it means the scan could not name the note behind `nullifiers[slot]` — either
    /// that slot held a *dummy* input (design spec §3: a dummy's nullifier is published like
    /// any other and is indistinguishable on chain), or the spent note never appeared in the
    /// history this disclosure covers. `verify_row` accordingly checks a bundle `Sent` row's
    /// nullifier only when the row actually claims a spent note.
    pub spent: Option<Note>,
}

impl Row {
    #[allow(clippy::too_many_arguments)]
    fn new(tx: usize, source: RowSource, slot: u8, cm_out: Word8, nf: Option<Word8>, role: Role, note: Note, spent: Option<Note>) -> Row {
        Row { tx, source, slot, role, sender: note.from, receiver: note.pk, amount: note.amount, asset: note.asset, time: note.time, cm_out, nf, note, spent }
    }
}

/// Everything the disclosure opens: every transfer/mint row first, in chain order, then every
/// bundle row, in chain order. A party's key yields one `Received` row per note it was paid and
/// one `Sent` row per note it created while spending; a transaction key yields the row(s) of
/// that one transaction. Nothing else on the chain opens, so nothing else is listed.
///
/// A bundle has two output slots and therefore up to four rows per party: each slot's envelope
/// is tried both as receiver and as sender, exactly as the transfer loop tries its single one.
/// A wallet that consolidates two of its own notes into one bundle and keeps the change gets
/// two `Sent` rows (one per output slot, carrying that slot's nullifier) and one `Received`
/// row (its change output) — all three naming the same bundle index with different `slot`s.
pub fn scan(ledger: &Ledger, d: &Disclosure) -> Vec<Row> {
    let mut rows = Vec::new();
    match d {
        Disclosure::Transaction { tx, key } => {
            if let Some(t) = ledger.txs.get(*tx) {
                if let Some(note) = t.envelope.open_with_tx_key(t.cm_out, key) {
                    rows.push(Row::new(*tx, RowSource::Transfer, 0, t.cm_out, t.nf, Role::Transaction, note, None));
                }
            }
            // `Disclosure::Transaction`'s `tx` does not say which sequence it indexes, so both
            // are tried. This is not ambiguous in practice: a `TxKey` only opens the envelope
            // it sealed, and every envelope is bound to its own `cm_out` as associated data, so
            // at most one of these attempts can succeed for a key that is not forged — PROVIDED
            // the wallet never seals two envelopes under one `TxKey`. A key reused across a
            // transfer and a bundle that happen to share an index would open both, and both
            // rows would verify; see `TxKey`'s doc comment for why that obligation lives with
            // the wallet and cannot be enforced here.
            if let Some(b) = ledger.bundles.get(*tx) {
                for slot in 0..2usize {
                    let cm = b.commitments[slot];
                    if let Some(note) = b.envelopes[slot].open_with_tx_key(cm, key) {
                        rows.push(Row::new(*tx, RowSource::Bundle, slot as u8, cm, Some(b.nullifiers[slot]), Role::Transaction, note, None));
                    }
                }
            }
        }
        Disclosure::Party(vk) => {
            // Pass 1: the party's whole note history, from BOTH sequences, before any `Sent`
            // row asks which note a nullifier belongs to. The spent note's *commitment* is
            // never public (M3.3: `MERKLE_VERIFY` proves it in-circuit), so this lookup is the
            // only way to recover it, and it works only for someone who already holds the
            // party's history.
            //
            // Collecting first is not an optimization, it is the correctness condition. The
            // two sequences are numbered independently and either can spend the other's
            // output: a transfer routinely spends a note a bundle paid out, and a bundle
            // spends notes transfers paid out. Accumulating `owned` while walking — one
            // sequence to completion and then the other — would leave every such spend with
            // `spent: None` in whichever sequence happened to be walked first, and
            // `verify_row` would then reject a transfer row `scan` itself had just produced
            // (its permissive "nullifier I cannot name" arm is for bundle *dummy inputs*
            // only). Walk order now cannot affect the result at all.
            let mut owned: Vec<Note> = Vec::new();
            for t in &ledger.txs {
                if let Some((_, note)) = t.envelope.open_as_receiver(t.cm_out, vk) { owned.push(note); }
            }
            for b in &ledger.bundles {
                for slot in 0..2usize {
                    if let Some((_, note)) = b.envelopes[slot].open_as_receiver(b.commitments[slot], vk) { owned.push(note); }
                }
            }
            let spent_for = |nf: Word8| owned.iter().copied().find(|n| vk.nullifier(&n.commitment()) == nf);
            // Pass 2: the rows, transfers in chain order then bundles in chain order. The
            // receiver openings are repeated here rather than cached from pass 1 — an ML-KEM
            // decapsulation per envelope, cheap enough at this crate's scale, and it keeps the
            // two passes independently readable.
            for (i, t) in ledger.txs.iter().enumerate() {
                if let Some((_, note)) = t.envelope.open_as_receiver(t.cm_out, vk) {
                    rows.push(Row::new(i, RowSource::Transfer, 0, t.cm_out, t.nf, Role::Received, note, None));
                }
                if let Some((_, note)) = t.envelope.open_as_sender(t.cm_out, vk) {
                    let spent = t.nf.and_then(spent_for);
                    rows.push(Row::new(i, RowSource::Transfer, 0, t.cm_out, t.nf, Role::Sent, note, spent));
                }
            }
            for (i, b) in ledger.bundles.iter().enumerate() {
                for slot in 0..2usize {
                    let (cm, nf) = (b.commitments[slot], b.nullifiers[slot]);
                    let env = &b.envelopes[slot];
                    if let Some((_, note)) = env.open_as_receiver(cm, vk) {
                        rows.push(Row::new(i, RowSource::Bundle, slot as u8, cm, Some(nf), Role::Received, note, None));
                    }
                    if let Some((_, note)) = env.open_as_sender(cm, vk) {
                        rows.push(Row::new(i, RowSource::Bundle, slot as u8, cm, Some(nf), Role::Sent, note, spent_for(nf)));
                    }
                }
            }
        }
    }
    rows
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowError {
    /// No such transaction on the chain.
    UnknownTx,
    /// The note in the row does not open the transaction's commitment.
    Commitment,
    /// The row's travel-rule fields disagree with the note that commits to them.
    Fields,
    /// The row's time is not the time the chain recorded for the transaction.
    Time,
    /// The row claims the party was sender/receiver but the note does not name the party's address.
    Party,
    /// A `Sent` row whose nullifier or spent commitment does not match the chain.
    Nullifier,
    /// The row's role is not one this disclosure can produce.
    Scope,
    /// The row names a slot the transaction it points at does not have — anything but 0 on a
    /// transfer/mint, anything but 0 or 1 on a bundle.
    Slot,
}

/// Checks `row` against the chain using nothing but `d` — the same key the row was
/// produced with — so a third party handed the disclosure and the rows can confirm every
/// row independently of whoever produced them.
pub fn verify_row(ledger: &Ledger, d: &Disclosure, row: &Row) -> Result<(), RowError> {
    // The three chain-side facts a row is checked against, read from whichever sequence and
    // slot the row names. Everything below is identical for both sources — a bundle row is the
    // same check, indexed by `(tx, slot)` instead of `tx` alone.
    let (cm_out, nf, time, envelope) = match row.source {
        RowSource::Transfer => {
            let t = ledger.txs.get(row.tx).ok_or(RowError::UnknownTx)?;
            if row.slot != 0 { return Err(RowError::Slot); }
            (t.cm_out, t.nf, t.time, &t.envelope)
        }
        RowSource::Bundle => {
            let b = ledger.bundles.get(row.tx).ok_or(RowError::UnknownTx)?;
            let s = usize::from(row.slot);
            if s >= 2 { return Err(RowError::Slot); }
            (b.commitments[s], Some(b.nullifiers[s]), b.time, &b.envelopes[s])
        }
    };
    let n = &row.note;
    if n.commitment() != cm_out || row.cm_out != cm_out { return Err(RowError::Commitment); }
    if (row.sender, row.receiver, row.amount, row.asset, row.time) != (n.from, n.pk, n.amount, n.asset, n.time) { return Err(RowError::Fields); }
    if row.time != time { return Err(RowError::Time); }
    if row.nf != nf { return Err(RowError::Nullifier); }
    match (d, row.role) {
        (Disclosure::Transaction { tx, key }, Role::Transaction) => {
            if *tx != row.tx { return Err(RowError::Scope); }
            if envelope.open_with_tx_key(cm_out, key).as_ref() != Some(n) { return Err(RowError::Commitment); }
        }
        (Disclosure::Party(vk), Role::Received) => {
            if n.pk != vk.pk() { return Err(RowError::Party); }
        }
        (Disclosure::Party(vk), Role::Sent) => {
            if n.from != vk.pk() { return Err(RowError::Party); }
            match (nf, row.spent) {
                // A mint: created from nothing, so there is no nullifier to check.
                (None, None) => {}
                (Some(nf), Some(spent)) => {
                    if spent.pk != vk.pk() { return Err(RowError::Party); }
                    if vk.nullifier(&spent.commitment()) != nf { return Err(RowError::Nullifier); }
                }
                // A bundle slot whose spent note the scan could not name — a dummy input, or a
                // note outside this disclosure's history (see `Row::spent`). The row simply
                // claims less; there is nothing to check, and nothing it could be lying about,
                // since `row.nf` was already pinned to the chain's `nullifiers[slot]` above.
                (Some(_), None) if row.source == RowSource::Bundle => {}
                _ => return Err(RowError::Nullifier),
            }
        }
        _ => return Err(RowError::Scope),
    }
    Ok(())
}
