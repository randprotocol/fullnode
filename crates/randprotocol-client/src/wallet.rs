//! The shielded wallet: the key file, the note store, scanning, coin selection and sending.
//!
//! What a wallet is, on a redacted chain (design spec §11): a spend key, a cache of the notes
//! that key can open, and the ability to turn some of them into a proved hidden-asset bundle —
//! four input and four output slots, slots 0–1 carrying one private asset and slots 2–3 RAND for
//! the fee (`docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md`). The chain answers
//! no question about ownership — `rand_getCommitments` hands out every leaf and every envelope to
//! everyone, and only a viewing key tells the two apart — so scanning is a local trial decryption
//! of the whole tree, and a balance is a fact about this file, not about the node.
//!
//! Nothing here ever sends a spend key, a viewing key or a note plaintext anywhere. What leaves
//! the process is exactly what a bundle publishes: an anchor, four nullifiers, four commitments,
//! the fee, the burn fields, and four envelopes nobody but their recipients can open — the
//! dummies' envelopes open to nobody at all.

use crate::{AssetRow, ChainLimits, CommitmentRow, RpcClient};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use randprotocol_core::bridge::{AssetId, Attestation, Payload};
use randprotocol_core::ledger::tokens::{MintAuthority, MINT_FROM};
use randprotocol_core::ledger::{bridge_notes, TIME_WINDOW};
use randprotocol_core::notes::{word8_from_hex, word8_to_hex, Bundle, Envelope, ShieldedAddress, Word8, DEPTH};
use randprotocol_core::types::TX_BINDING_WORDS;
use randprotocol_core::{format_amount, gas, Action, Hash, InitialMint, Keypair, PublicKey, Transaction};
use randprotocol_core::{set_authority_message, token_mint_message};
use randprotocol_zkvm::address::{address_of, envelope_from_core, seal_note};
use randprotocol_zkvm::executor::prove_hidden_bundle;
use randprotocol_zkvm::hidden::{self, HiddenDigestInput, HiddenOutput, A_SLOTS, SLOTS};
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::{Note, SpendKey, ViewingKey};
use randprotocol_zkvm::viewing::TxKey;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Rows per `getCommitments`/`getNullifiers` page. The node caps a page at 1000 however large
/// the request is, so this only has to be a number a wallet is happy to hold in memory.
const PAGE: usize = 500;

/// How long a `send` waits for its bundle to be committed. A bundle proof is ~0.9 MB, so the
/// block it rides in is large; 180 s leaves room for a few views of consensus.
pub const COMMIT_TIMEOUT: Duration = Duration::from_secs(180);

// ---------------------------------------------------------------- key file

/// The on-disk key file, version 2: the spend key and nothing else. Every other key — the
/// viewing key, the outgoing viewing key, the ML-KEM decapsulation key, the address — is a
/// pure derivation of it (`randprotocol_zkvm::notes`), so storing them would only widen what a
/// leaked file discloses without making anything recoverable that is not already.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyFile {
    pub version: u32,
    /// The spend key's eight words as 64 hex characters (`word8_to_hex`).
    pub spend_key: String,
}

pub const KEY_FILE_VERSION: u32 = 2;

/// A spend key and everything derived from it.
pub struct Wallet {
    pub sk: SpendKey,
    pub vk: ViewingKey,
    pub address: ShieldedAddress,
}

impl Wallet {
    pub fn from_spend_key(sk: SpendKey) -> Wallet {
        let vk = sk.viewing_key();
        Wallet { sk, vk, address: address_of(&vk) }
    }

    pub fn generate() -> Wallet {
        Wallet::from_spend_key(SpendKey::random())
    }

    pub fn load(path: &Path) -> Result<Wallet> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading key file {}", path.display()))?;
        let kf: KeyFile = serde_json::from_str(&text).with_context(|| format!("{} is not a wallet key file", path.display()))?;
        if kf.version != KEY_FILE_VERSION {
            return Err(anyhow!(
                "{} is a version {} key file; this wallet reads version {KEY_FILE_VERSION}",
                path.display(),
                kf.version
            ));
        }
        let words = word8_from_hex(&kf.spend_key).context("spend_key must be 64 hex characters")?;
        Ok(Wallet::from_spend_key(SpendKey(words)))
    }

    /// Write the key file, refusing to touch an existing path. There is no second copy of a
    /// spend key: overwriting one destroys every note it could still open.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        let kf = KeyFile { version: KEY_FILE_VERSION, spend_key: word8_to_hex(&self.sk.0) };
        let text = serde_json::to_string_pretty(&kf)? + "\n";
        // `create_new` closes the exists-then-write race and `mode(0o600)` makes the file
        // owner-only from the start: writing first and chmodding afterwards leaves the spend
        // key world-readable for a window.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("{} already exists or cannot be created; refusing to overwrite", path.display()))?;
            f.write_all(text.as_bytes())?;
            // The bytes reach the disk before this returns: a power loss right after a key is
            // handed out must not leave an empty file where the only copy of a secret should be
            // (node I1's companion).
            f.sync_all().with_context(|| format!("flushing {}", path.display()))?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            if path.exists() {
                return Err(anyhow!("{} already exists; refusing to overwrite", path.display()));
            }
            std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
        }
    }
}

/// Where a key file's note store lives: `<key path>.notes.json`, next to the key.
pub fn store_path(key: &Path) -> PathBuf {
    let mut s = key.as_os_str().to_os_string();
    s.push(".notes.json");
    PathBuf::from(s)
}

// ---------------------------------------------------------------- an RPL token's authority key
//
// A `Key`-authorised token's authority is a Dilithium2 keypair (`randprotocol_core::Keypair`),
// the same key kind a validator or a bridge guardian holds — unrelated to the shielded spend key
// above, which never signs anything. `rand-node keygen` already writes this exact shape
// (`crates/randprotocol-node/src/keyfile.rs`: `{"seed", "address", "public_key"}`), and duplicating
// it here rather than depending on that crate is deliberate: `rand-node`'s own binary already
// depends on `randprotocol_client` (its RPC client and this wallet module), so depending back
// would be the crate cycle `randprotocol-rvm`/`randprotocol-zkvm` avoids for the same reason
// (AGENTS.md). The two stay byte-compatible because both are exactly `{seed, address,
// public_key}`, so a file either tool writes is a file the other reads.

#[derive(Serialize, Deserialize)]
struct TokenAuthorityKeyFile {
    seed: String,
    address: String,
    public_key: String,
}

/// Read a token authority's Dilithium2 key file: `rand-node keygen`'s own shape, or `rand token
/// create --authority-key-out`'s. Only the seed is read back; `address` and `public_key` are
/// informational, exactly as `rand-node`'s own reader treats them.
pub fn load_authority_key(path: &Path) -> Result<Keypair> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let kf: TokenAuthorityKeyFile = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a Dilithium2 key file (rand-node keygen's shape)", path.display()))?;
    let seed = hex::decode(kf.seed.trim()).context("seed must be hex")?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| anyhow!("seed must be 32 bytes"))?;
    Keypair::from_seed(seed).map_err(|e| anyhow!("{e}"))
}

/// Write a fresh Dilithium2 authority key file at `path` for `rand token create
/// --authority-key-out`, refusing to overwrite an existing one. The same 0600-from-creation
/// discipline as [`Wallet::save_new`] and `rand-node keygen`'s own writer: the seed is a secret,
/// and writing the file then chmodding it afterwards would leave it world-readable for a window.
pub fn write_authority_key(kp: &Keypair, path: &Path) -> Result<()> {
    let kf = TokenAuthorityKeyFile { seed: hex::encode(kp.seed()), address: kp.address().to_base58(), public_key: kp.public_key().to_hex() };
    let text = serde_json::to_string_pretty(&kf)? + "\n";
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("{} already exists or cannot be created; refusing to overwrite", path.display()))?;
        f.write_all(text.as_bytes())?;
        // Durable before the caller submits anything against it (node I1).
        f.sync_all().with_context(|| format!("flushing {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            return Err(anyhow!("{} already exists; refusing to overwrite", path.display()));
        }
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }
}

/// Read only a Dilithium2 key file's `public_key` field — never its `seed` — for `rand token
/// set-authority --new-key`, which needs a successor's public key and nothing else about that key
/// (T8b review round 1): the file may hold a live secret this command has no reason to decode.
pub fn load_authority_public_key(path: &Path) -> Result<PublicKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a Dilithium2 key file (rand-node keygen's shape)", path.display()))?;
    let hex = v["public_key"].as_str().ok_or_else(|| anyhow!("{} has no public_key field", path.display()))?;
    PublicKey::from_hex(hex).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// `<path>.pending` — where `rand token create --authority-key-out <path>` writes its fresh
/// authority key *before* submitting the registration (T8b review round 1): a `RegisterToken` can
/// lose a race (`IndexMismatch`) only at submission, since another registration can commit
/// between `build_register_token`'s read of `next_index` and this wallet's own submission — so
/// the only copy of the key this command ever generates has to already be safely on disk before
/// that submission is attempted, never after. [`promote_pending_authority_key`] moves it to `path`
/// once the chain has accepted the registration; [`discard_pending_authority_key`] removes it on
/// a refusal the node itself made.
pub fn pending_authority_key_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".pending");
    PathBuf::from(s)
}

/// Promote an accepted registration's pending authority key to its final path. Refuses to
/// overwrite an existing file there — vanishingly unlikely (the same submission cannot have
/// landed twice), but if it ever happens the secret stays recoverable at `pending` rather than
/// being silently lost under a rename.
pub fn promote_pending_authority_key(pending: &Path, path: &Path) -> Result<()> {
    if path.exists() {
        return Err(anyhow!(
            "{} already exists; the registered token's authority key is still safe at {} — move it there by hand",
            path.display(),
            pending.display()
        ));
    }
    std::fs::rename(pending, path).with_context(|| format!("renaming {} to {}", pending.display(), path.display()))
}

/// Discard a pending authority key file after a refusal the *node itself* made
/// (`rand_sendTransaction`'s synchronous JSON-RPC error — nothing was admitted, so nothing was
/// ever registered under this key, an `IndexMismatch` lost race among them). Never call this for
/// a transport-level failure (a timeout, a dropped connection): the submission's fate is unknown
/// there, and discarding the only copy of a key that may have gone through would orphan a live
/// token for good.
pub fn discard_pending_authority_key(pending: &Path) -> Result<()> {
    std::fs::remove_file(pending).with_context(|| format!("removing {}", pending.display()))
}

// ---------------------------------------------------------------- the note store

mod hex_word8 {
    use super::*;
    pub fn serialize<S: Serializer>(w: &Word8, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&word8_to_hex(w))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Word8, D::Error> {
        let s = String::deserialize(d)?;
        word8_from_hex(&s).ok_or_else(|| serde::de::Error::custom("expected 64 hex characters"))
    }
}

mod hex_note {
    use super::*;
    pub fn serialize<S: Serializer>(n: &Note, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(n.to_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Note, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Note::from_bytes(&bytes).ok_or_else(|| serde::de::Error::custom("not a note"))
    }
}

/// A note this wallet can spend: the leaf it sits at, its plaintext, and the two values the
/// chain knows it by.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedNote {
    pub index: u64,
    #[serde(with = "hex_note")]
    pub note: Note,
    #[serde(with = "hex_word8")]
    pub cm: Word8,
    #[serde(with = "hex_word8")]
    pub nf: Word8,
    pub spent: bool,
    /// Set by a `--no-wait` submission to the `time` of the bundle that spends this note: the
    /// note is not spendable, but the chain has not confirmed the spend either. A later [`scan`]
    /// clears it once the chain answers — the nullifier appeared (`spent`), or the blocks this
    /// wallet has actually read the nullifiers of reach past `time + TIME_WINDOW`, past which
    /// that bundle can never be admitted at all (`Ledger::validate_inner`'s time check) so the
    /// note is spendable again.
    #[serde(default)]
    pub pending: Option<u32>,
    pub height: u64,
}

impl OwnedNote {
    /// Whether this note can be an input. A zero-value note is a real note and a real leaf, but
    /// it buys nothing, so it is neither counted in a balance nor selected.
    fn is_spendable(&self) -> bool {
        !self.spent && self.pending.is_none() && self.note.amount > 0
    }
}

/// A note this wallet created for someone else — history only, never spendable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SentRow {
    pub index: u64,
    #[serde(with = "hex_word8")]
    pub to_pk: Word8,
    pub amount: u64,
    pub height: u64,
}

/// Everything scanning has learned, as JSON at `<key path>.notes.json`.
///
/// Purely a cache of chain data: every row in it is recoverable by rescanning from leaf 0 with
/// the spend key, which is why [`NoteStore::load`] starts from empty rather than failing when
/// the file is missing or unreadable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NoteStore {
    /// The next leaf index to scan; every leaf below it has been tried against the viewing key.
    pub scanned_index: u64,
    /// The next block height to read nullifiers from.
    pub scanned_height: u64,
    /// The next block height to read committed deposits and mints from (`bridge_attest`,
    /// `token_mint`, `register_token`), for the public-rebuild path in [`scan`]. Zero on a store
    /// written before that path existed, which is what makes an older store re-read its blocks
    /// once and recover anything it missed. (The name is the first of those kinds'.)
    #[serde(default)]
    pub scanned_attest_height: u64,
    pub notes: Vec<OwnedNote>,
    #[serde(default)]
    pub sent: Vec<SentRow>,
}

impl NoteStore {
    pub fn load(path: &Path) -> NoteStore {
        let Ok(text) = std::fs::read_to_string(path) else { return NoteStore::default() };
        match serde_json::from_str(&text) {
            Ok(store) => store,
            Err(e) => {
                eprintln!("warning: {} is unreadable ({e}); rescanning from the start", path.display());
                NoteStore::default()
            }
        }
    }

    /// Write the store owner-only, through a temporary file. The store holds every note
    /// plaintext, nullifier and leaf index this wallet knows — a world-readable copy of it
    /// discloses the wallet's whole history to anyone on the machine, which is exactly what the
    /// envelope layer exists to prevent. The rename makes the replacement atomic, so a crash
    /// halfway through leaves the previous store intact instead of a truncated one.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)? + "\n";
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        write_private(&tmp, text.as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    }

    /// Spendable RAND. A zero-value note is a real note (a bundle whose change is zero still
    /// publishes a change output) but it buys nothing, so it is neither counted nor selected.
    pub fn balance(&self) -> u64 {
        self.balance_of(0)
    }

    /// The RAND notes this wallet can spend — the only ones that can pay a fee.
    pub fn spendable(&self) -> Vec<&OwnedNote> {
        self.spendable_of(0)
    }

    /// Spendable value in one asset: 0 is RAND, and every other index is a bridged asset as the
    /// registry numbered it (`rand_getAssets`).
    ///
    /// Never a sum across assets. A bundle balances one asset (the guest's own rule), so two
    /// assets added together are a number no transaction could ever spend — and on a chain where
    /// a bridged token's unit is not RAND's, not even a number that means anything.
    pub fn balance_of(&self, asset: u32) -> u64 {
        self.spendable_of(asset).iter().map(|n| n.note.amount).sum()
    }

    pub fn spendable_of(&self, asset: u32) -> Vec<&OwnedNote> {
        self.notes.iter().filter(|n| n.is_spendable() && n.note.asset == asset).collect()
    }

    /// Every asset this wallet holds something in, ascending by index, with its balance. The rows
    /// `rand asset-balance` prints; an asset whose notes are all spent does not appear.
    pub fn asset_balances(&self) -> Vec<(u32, u64)> {
        let mut assets: Vec<u32> = self.notes.iter().filter(|n| n.is_spendable()).map(|n| n.note.asset).collect();
        assets.sort_unstable();
        assets.dedup();
        assets.into_iter().map(|a| (a, self.balance_of(a))).collect()
    }
}

/// Create (or replace) `path` with mode 0600 from the start: writing first and chmodding
/// afterwards leaves the contents world-readable for a window.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(bytes)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

// ---------------------------------------------------------------- keys a holder hands out

impl Wallet {
    /// This wallet's viewing key `nk` as 64 hex — exactly the parameter `rand_importViewingKey`
    /// takes. It is one hash below the spend key (`docs/shielded.md` §1): it opens every note this
    /// wallet has sent or received, and it can spend none of them.
    pub fn viewing_key_hex(&self) -> String {
        word8_to_hex(&self.vk.nk)
    }
}

/// How one output of a transaction relates to the wallet looking at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole {
    /// This wallet sealed it for someone else: a payment.
    Sent,
    /// Someone else sealed it to this wallet, and the note names this wallet's `pk`.
    Received,
    /// This wallet sealed it to itself: change, or a merge.
    Change,
}

impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyRole::Sent => "sent",
            KeyRole::Received => "received",
            KeyRole::Change => "change",
        }
    }
}

/// One output of a transaction this wallet can open, with the per-transaction key its envelope
/// was sealed under. Handing `key` to anyone discloses exactly this output (`rand_checkTransaction`)
/// and nothing else the wallet holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputKey {
    /// `bundle` (the one bundle's slots 0–3) or `mint` — the same names `rand_checkTransaction`
    /// reports.
    pub output: &'static str,
    pub slot: u8,
    pub cm: Word8,
    pub role: KeyRole,
    pub note: Note,
    pub key: TxKey,
}

/// Every output of `tx` that carries a commitment and its envelope together, in the order and
/// under the names `rand_checkTransaction` uses: the bundle's four slots, dummies included (their
/// envelopes open to nobody), then a faucet mint's note. A bridge deposit is not here: its
/// commitment is derived by the ledger, not carried by the transaction.
fn sealed_outputs(tx: &Transaction) -> Vec<(&'static str, u8, Word8, &Envelope)> {
    let mut out = Vec::new();
    if let Some(b) = &tx.bundle {
        for (i, (cm, e)) in b.commitments.iter().zip(&b.envelopes).enumerate() {
            out.push(("bundle", i as u8, *cm, e));
        }
    }
    if let Action::Mint { cm, envelope, .. } = &tx.action {
        out.push(("mint", 0, *cm, envelope));
    }
    out
}

/// The per-transaction key of every output of `tx` this wallet sent or received, recovered from
/// the chain alone. Nothing is stored at send time: each envelope carries its key twice — under
/// the receiver's KEM secret and under the sender's `ovk` — so the sender reopens it through
/// `ovk` and the receiver through the KEM, and both arrive at the same key.
pub fn output_keys(w: &Wallet, tx: &Transaction) -> Vec<OutputKey> {
    let mut rows = Vec::new();
    for (output, slot, cm, e) in sealed_outputs(tx) {
        let env = envelope_from_core(e);
        // Opening under the KEM is not ownership (see [`Found`]): only a note naming this
        // wallet's `pk` is received.
        let received = env.open_as_receiver(cm, &w.vk).filter(|(_, n)| n.pk == w.vk.pk());
        let sent = env.open_as_sender(cm, &w.vk);
        let (role, (key, note)) = match (received, sent) {
            (Some(r), Some(_)) => (KeyRole::Change, r),
            (Some(r), None) => (KeyRole::Received, r),
            (None, Some(s)) => (KeyRole::Sent, s),
            (None, None) => continue,
        };
        // A zero-value output is a dummy slot: nothing to disclose, and no payment to prove.
        if is_dummy(&note) {
            continue;
        }
        rows.push(OutputKey { output, slot, cm, role, note, key });
    }
    rows
}

// ---------------------------------------------------------------- scanning

/// What one leaf turned out to be for this wallet.
///
/// The distinction the `Skipped` arm exists for: an envelope opening is *not* proof of
/// ownership. `Envelope::open_as_receiver` checks only that the note it decrypts commits to the
/// leaf it was published with, and anyone can seal an envelope to a published `kem_ek` — a
/// shielded address is public by design. So a stranger can hand this wallet a perfectly valid
/// envelope carrying a note owned by some *other* `pk`. Recording it would put value in
/// `balance()` that no proof can ever spend: the guest forces every input's owner to the derived
/// `pk_self`, so selecting such a note yields a bundle whose digest cannot match, and the wallet
/// would refuse its own proof after a minute and a half of work with a message blaming itself.
///
/// A note's `asset` word is *not* grounds for skipping it, since S3: a bridged holding is a note
/// whose asset is the registry's index for it (spec §10), and refusing those would make a deposit
/// invisible to the wallet it was deposited to. An asset no registry names is unspendable rather
/// than dangerous — a bundle of it is only admissible inside a `BridgeBurn`, and `check_burn`
/// refuses an unregistered asset — so it is recorded, and shows up under its own index in
/// `asset-balance` for the holder to make of what they will.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// A note this wallet owns and can spend.
    Received(Note),
    /// A note this wallet created for someone else — history only.
    Sent(Note),
    /// Not this wallet's, with the reason for the log.
    Skipped(&'static str),
}

/// Why [`classify`] skips a leaf no key of this wallet opens — the ordinary case, never logged.
const NOT_OURS: &str = "no key of this wallet opens it";
/// Why [`classify`] skips a zero-value note — a dummy slot's, never logged either.
const DUMMY: &str = "a zero-value dummy";

/// A zero-value note: what a bundle's unused slots carry. It is a real leaf with a real
/// nullifier-to-be, but it holds nothing, so it is neither a balance nor a payment.
fn is_dummy(note: &Note) -> bool {
    note.amount == 0
}

/// Decide what a single leaf is for `w`, with no I/O — the whole of [`scan`]'s per-row logic.
///
/// A four-slot bundle carries a dummy in every slot it does not need. This wallet seals its own
/// dummies to a throwaway key, so they open to nobody; a dummy that does open (another wallet's
/// choice, or a zero-value change) is recognised by its zero amount and skipped, so it is never a
/// balance, a spendable input or a history row.
pub fn classify(w: &Wallet, cm: Word8, envelope: &Envelope) -> Found {
    let env = envelope_from_core(envelope);
    let mut why = NOT_OURS;
    if let Some((_, note)) = env.open_as_receiver(cm, &w.vk) {
        if note.pk == w.vk.pk() {
            return if is_dummy(&note) { Found::Skipped(DUMMY) } else { Found::Received(note) };
        }
        why = "sealed to this wallet but owned by another key";
    }
    // Still worth the sender path: an envelope this wallet sealed for someone else is opened
    // through `ovk`, not through the KEM, so the two openings are independent.
    if let Some((_, note)) = env.open_as_sender(cm, &w.vk) {
        return if is_dummy(&note) { Found::Skipped(DUMMY) } else { Found::Sent(note) };
    }
    Found::Skipped(why)
}

/// Transaction kinds (`tx_json`'s `kind`) whose one chain-computed note is public in full.
const PUBLIC_NOTE_KINDS: [&str; 3] = ["bridge_attest", "token_mint", "register_token"];

/// The notes a committed transaction appended for `w` from its **public** fields alone: a bridge
/// deposit (`BridgeAttest`), a token mint (`TokenMint`) and a registration's initial mint
/// (`RegisterToken`'s `initial`).
///
/// Every word of each of those notes is public in the one transaction that appends it — the
/// recipient, the amount (a deposit's is the one the guardians signed), the asset index, the
/// action's `time` and its blinding `r`, and the `from` word the chain fixes (zero for a deposit,
/// [`MINT_FROM`] for a mint) — and nothing binds the envelope a submitter publishes to the note
/// the chain computes: anyone may relay an attestation, and a careless or hostile minter may seal
/// garbage. So the envelope layer is not what the recipient depends on here; this path finds the
/// note with nothing decrypted (`docs/bridge.md` §8, one action over for the two mints).
///
/// Empty for any other action, for a note to another key, and for a guardian-set rotation (which
/// deposits nothing). A rebuilt note is only a candidate: [`scan`] records it at the leaf whose
/// commitment it hashes to, so the chain's own tree is the authority on what was appended.
pub fn rebuilt_notes(w: &Wallet, tx: &Transaction) -> Vec<Note> {
    let me = w.vk.pk();
    match &tx.action {
        Action::BridgeAttest { attestation, recipient, r, time, asset, .. } if recipient.pk == me => {
            // The ledger's own reading of the wire, so the amount cannot disagree with the one the
            // chain deposited. `None` is a rotation, which deposits nothing.
            bridge_notes::attested_transfer(attestation)
                .map(|(_, _, amount)| Note { pk: me, from: [0; 8], amount, asset: *asset, time: *time, r: *r })
                .into_iter()
                .collect()
        }
        Action::TokenMint { asset, amount, recipient, r, time, .. } if recipient.pk == me => {
            vec![Note { pk: me, from: MINT_FROM, amount: *amount, asset: *asset, time: *time, r: *r }]
        }
        Action::RegisterToken { initial: Some(m), index, .. } if m.recipient.pk == me => {
            vec![Note { pk: me, from: MINT_FROM, amount: m.amount, asset: *index, time: m.time, r: m.r }]
        }
        _ => Vec::new(),
    }
}

/// Every note this wallet can rebuild out of blocks it has not read yet ([`rebuilt_notes`]),
/// keyed by the commitment the chain appended for it. [`scan`] matches each against the leaf
/// that carries that commitment, which is what turns a rebuilt note into an owned one at a known
/// index.
///
/// Blocks are read once: the height returned is where `scanned_attest_height` moves to, past them
/// whether or not they held a note for this wallet — but only once [`scan`] has placed every note
/// found here at its leaf. The cursor lives in a store that is saved even when a scan fails, so
/// moving it here, before the notes are placed, would let a failed scan persist a cursor past a
/// garbage-envelope deposit that was never recorded — and nothing would ever read it again. The pass reads headers 128 at a time (`rand_getBlocks`), a block only when it
/// carries a transaction, and a raw transaction only for the three kinds that append a public
/// note — so an idle chain costs a header page per 128 blocks.
async fn rebuildable_notes(rpc: &RpcClient, w: &Wallet, store: &NoteStore) -> Result<(BTreeMap<Word8, Note>, u64)> {
    let head = rpc.head().await?["height"].as_u64().context("getHead did not return a height")?;
    let mut out = BTreeMap::new();
    let mut from = store.scanned_attest_height;
    while from <= head {
        let headers = rpc.blocks(from, head.min(from.saturating_add(BLOCK_PAGE - 1))).await?;
        let Some(last) = headers.iter().filter_map(|h| h["height"].as_u64()).max() else {
            return Err(anyhow!("getBlocks returned no header from height {from} though the head is {head}"));
        };
        if last < from {
            return Err(anyhow!("getBlocks returned headers below height {from}"));
        }
        for header in &headers {
            if header["tx_count"].as_u64().unwrap_or(0) == 0 {
                continue;
            }
            let height = header["height"].as_u64().context("a block header without a height")?;
            let block = rpc.block_by_height(height).await?;
            let Some(txs) = block["transactions"].as_array() else { continue };
            for tx in txs {
                let kind = tx["action"]["kind"].as_str().unwrap_or_default();
                if !PUBLIC_NOTE_KINDS.contains(&kind) {
                    continue;
                }
                let hash = Hash::from_hex(tx["hash"].as_str().unwrap_or_default())
                    .map_err(|e| anyhow!("block {height} renders a transaction hash that does not parse: {e}"))?;
                let raw = rpc
                    .raw_transaction(&hash)
                    .await?
                    .with_context(|| format!("the node serves no raw transaction for {hash}, committed in block {height}"))?;
                for note in rebuilt_notes(w, &raw) {
                    out.insert(note.commitment(), note);
                }
            }
        }
        from = last + 1;
    }
    Ok((out, store.scanned_attest_height.max(head + 1)))
}

/// Headers per `rand_getBlocks` page: the node's own cap.
const BLOCK_PAGE: u64 = 128;

/// Record what one leaf is for this wallet. `rebuilt` is what [`rebuildable_notes`] found: a
/// leaf whose commitment is in it is this wallet's deposit or mint whatever its envelope says, so
/// it is tried first and the envelope is never consulted for it.
fn place_leaf(w: &Wallet, store: &mut NoteStore, row: &CommitmentRow, rebuilt: &mut BTreeMap<Word8, Note>) {
    let found = match rebuilt.remove(&row.cm) {
        Some(note) => Found::Received(note),
        None => classify(w, row.cm, &row.envelope),
    };
    match found {
        // A note can be re-offered by a rescan; the index is the leaf, so it is unique.
        Found::Received(note) => {
            if !store.notes.iter().any(|n| n.index == row.index) {
                store.notes.push(OwnedNote {
                    index: row.index,
                    cm: row.cm,
                    nf: w.vk.nullifier(&row.cm),
                    note,
                    spent: false,
                    pending: None,
                    height: row.height,
                });
            }
        }
        Found::Sent(note) => {
            if !store.sent.iter().any(|s| s.index == row.index) {
                store.sent.push(SentRow { index: row.index, to_pk: note.pk, amount: note.amount, height: row.height });
            }
        }
        Found::Skipped(why) => {
            if why != NOT_OURS && why != DUMMY {
                eprintln!("warning: ignoring leaf {}: {why}", row.index);
            }
        }
    }
}

/// Trial-decrypt every commitment this wallet has not seen yet, then mark as spent every note
/// whose nullifier the chain has published. Advances the store and saves nothing — the caller
/// owns the file.
pub async fn scan(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore) -> Result<()> {
    // What the envelope layer cannot be trusted to deliver, read off the wire instead. Done
    // before the leaves are paged, so a deposit or a mint is placed by the same pass that first sees its
    // leaf rather than a scan later.
    let (mut rebuilt, rebuilt_through) = rebuildable_notes(rpc, w, store).await?;

    loop {
        let rows = rpc.commitments(store.scanned_index, PAGE).await?;
        if rows.is_empty() {
            break;
        }
        let before = store.scanned_index;
        for row in &rows {
            place_leaf(w, store, row, &mut rebuilt);
            store.scanned_index = store.scanned_index.max(row.index + 1);
        }
        // A non-empty page that leaves the cursor where it was would loop forever.
        if store.scanned_index <= before {
            return Err(anyhow!(
                "getCommitments returned {} rows from index {before} without advancing past it",
                rows.len()
            ));
        }
    }

    // A rebuilt deposit whose leaf sits *below* the cursor — an attestation this wallet read the
    // blocks of only now, having scanned past its leaf with an older build — is placed by reading
    // the leaves again from the start. Re-offering a leaf costs nothing (every record here is
    // keyed by its index), and this loop runs at most once per recovered deposit, because the
    // deposit is in the store from then on.
    let mut from = 0;
    while !rebuilt.is_empty() {
        let rows = rpc.commitments(from, PAGE).await?;
        if rows.is_empty() {
            // Every leaf there is has been offered and some deposit still has no leaf: the node
            // rendered an attestation whose commitment its own tree does not hold.
            return Err(anyhow!(
                "{} rebuilt deposit or mint note(s) match no leaf of the tree; the node's blocks and notes disagree",
                rebuilt.len()
            ));
        }
        let before = from;
        for row in &rows {
            place_leaf(w, store, row, &mut rebuilt);
            from = from.max(row.index + 1);
        }
        // Same guard the forward pass has: a non-empty page that does not move the cursor would
        // loop forever.
        if from <= before {
            return Err(anyhow!(
                "getCommitments returned {} rows from index {before} without advancing past it",
                rows.len()
            ));
        }
    }

    // Every rebuilt note is at its leaf now, so the blocks they came from need not be read again.
    // Only here: any error above returns before this line, leaving the cursor where it was, and
    // the next scan re-reads those blocks and places what this one could not.
    debug_assert!(rebuilt.is_empty());
    store.scanned_attest_height = rebuilt_through;

    // The head as it stands *before* the nullifier pages below. The pages read every nullifier
    // that exists at read time from `scanned_height` upward, so once the loop has finished, every
    // block at or below this height has been read — whether or not it published a nullifier.
    // Reading the head afterwards instead would claim blocks that landed while the pages were in
    // flight and whose nullifiers this scan never saw.
    let head_before = rpc.head().await?["height"].as_u64().context("getHead did not return a height")?;

    // Nullifiers are keyed by height, and a page can in principle stop inside a height. Paging
    // back to `max_height` rather than past it is what keeps a truncated page from skipping the
    // rest of that block; re-reading rows is free, since marking a note spent is idempotent.
    let mut from = store.scanned_height;
    loop {
        let rows = rpc.nullifiers(from, PAGE).await?;
        let Some(max_height) = rows.iter().map(|(h, _)| *h).max() else { break };
        for (_, nf) in &rows {
            if let Some(n) = store.notes.iter_mut().find(|n| n.nf == *nf) {
                n.spent = true;
            }
        }
        if rows.len() < PAGE {
            from = max_height + 1;
            break;
        }
        // A full page that got no further than the height it started at means this block alone
        // has more nullifiers than a page holds. Advancing would silently skip the rest of it
        // and leave spent notes looking spendable, so say so instead.
        if max_height == from {
            return Err(anyhow!("block {from} published more than {PAGE} nullifiers; raise the page size"));
        }
        from = max_height;
    }
    store.scanned_height = advance_scanned_height(store.scanned_height, from, head_before);

    // Resolve anything a `--no-wait` submission left pending, now that the chain has answered.
    clear_pending(store, store.scanned_height.saturating_sub(1));
    Ok(())
}

/// Where a scan has read through after paging nullifiers, keeping the store's invariant that
/// every nullifier in a block below `scanned_height` has been matched against this store.
///
/// `paged_to` is where the nullifier pages stopped: one past the last height that published a
/// nullifier, or the cursor unmoved when no page returned a row. On a quiet chain that is the
/// cursor itself, which is why it cannot be the only bound — a wallet whose chain never spends
/// again would never advance, and a `--no-wait` note pending against it would never clear.
///
/// `head_before` is the head read *before* the pages, so the pages covered every block up to it
/// and `head_before + 1` is the first block this scan has not read. It is a bound, not a
/// replacement: a head fetched *after* the pages would run ahead of them and let a spend the
/// wallet has not looked at yet pass for "read", which is the race this rule exists to avoid.
fn advance_scanned_height(previous: u64, paged_to: u64, head_before: u64) -> u64 {
    previous.max(paged_to).max(head_before.saturating_add(1))
}

/// Clear the `pending` mark on every note the chain has now answered for, where `read_through`
/// is the last block height this scan has read (`scanned_height - 1`).
///
/// A note clears either because its spend landed (`spent`, set by the nullifier pages) or
/// because the blocks read reach past `time + TIME_WINDOW`, the last height at which a bundle
/// stamped `time` could still be admitted: after that the submission can never commit, so the
/// note is free again. The bound is what was read, never a head fetched later.
fn clear_pending(store: &mut NoteStore, read_through: u64) {
    for n in store.notes.iter_mut() {
        if let Some(time) = n.pending {
            if n.spent || read_through > time as u64 + TIME_WINDOW {
                n.pending = None;
            }
        }
    }
}

// ---------------------------------------------------------------- coin selection

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    /// The wallet holds enough, but not in two notes. Consolidate first: each group of a bundle
    /// (the asset's slots 0–1, RAND's slots 2–3) spends at most two inputs (design spec §3), so no
    /// amount of dust adds up to a third slot.
    #[error("need more than two notes; the largest two hold {largest_two} units — consolidate first")]
    NeedsMoreThanTwo { largest_two: u64 },
    #[error("insufficient balance: {have} units")]
    Insufficient { have: u64 },
}

/// Largest-first, at most two notes: take the biggest note, then the next biggest if the first
/// does not cover `need`. Largest-first minimises the number of notes a wallet fragments into,
/// which matters more here than change minimisation — a group of two input slots cannot spend a
/// third note, so a wallet that shreds itself into dust becomes unspendable.
///
/// One asset at a time: `spendable` is what `NoteStore::spendable_of` returned for a single asset,
/// and this does not look at the field — each group of a bundle balances one asset, so a mixed
/// list would select notes that cannot share a group at all. [`Plan::select`] calls it once per
/// group.
pub fn select_inputs(spendable: &[&OwnedNote], need: u64) -> Result<Vec<OwnedNote>, SelectError> {
    let mut sorted: Vec<&OwnedNote> = spendable.to_vec();
    sorted.sort_by(|a, b| b.note.amount.cmp(&a.note.amount));
    let have: u64 = sorted.iter().map(|n| n.note.amount).sum();
    if have < need {
        return Err(SelectError::Insufficient { have });
    }
    let mut chosen: Vec<OwnedNote> = Vec::new();
    let mut sum = 0u64;
    for n in sorted.iter().take(2) {
        if sum >= need {
            break;
        }
        sum += n.note.amount;
        chosen.push((*n).clone());
    }
    if sum < need {
        return Err(SelectError::NeedsMoreThanTwo { largest_two: sum });
    }
    Ok(chosen)
}

// ---------------------------------------------------------------- sending

/// What one group of a bundle's inputs must cover: the guest's balance equation for that group
/// (design spec §3.3) — `in0 + in1 = out0 + out1 + burn_a` in the asset's slots,
/// `in2 + in3 = out2 + out3 + fee + burn_r` in RAND's — so the wallet asks coin selection for
/// exactly that. The burn is the part that leaves the shielded pool instead of becoming somebody's
/// note: a `Bond`'s stake in RAND, a `BridgeBurn`'s or `TokenBurn`'s amount in its token.
fn bundle_need(amount: u64, fee: u64, burn: u64) -> Result<u64> {
    amount
        .checked_add(fee)
        .and_then(|n| n.checked_add(burn))
        .ok_or_else(|| anyhow!("amount + fee + burn overflows"))
}

/// What a bundle took out of the shielded pool, in the unit it is measured in.
///
/// The burns this chain has are denominated differently: a `Bond` (and a `RegisterAggregator`)
/// burns RAND through the bundle's `burn_r`, and a `BridgeBurn` or `TokenBurn` burns its token
/// through `burn_a`, in units that owe nothing to RAND's nine decimals. As one `u64` the field
/// was two values in a trench coat, disambiguated by [`Submission::asset`] and read correctly
/// only by a caller that remembered to look. Spelled as a sum type there is nothing to remember.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Burn {
    /// Nothing left the pool: every action but a bond, an aggregator registration and a burn.
    #[default]
    None,
    /// RAND out of the pool (`burn_r`): a `Bond`'s stake.
    Rand(u64),
    /// A token's amount out of the pool (`burn_a`, `burn_asset = index`): a `BridgeBurn` or a
    /// `TokenBurn`. `index` is the same as [`Submission::asset`], carried here too so a burn
    /// describes itself.
    Asset { index: u32, amount: u64 },
}

impl Burn {
    /// `amount` RAND out of the pool, or [`Burn::None`] when it is zero: burning nothing and
    /// burning zero are the same event, and a printer should not have to decide which.
    pub fn rand(amount: u64) -> Burn {
        if amount == 0 {
            Burn::None
        } else {
            Burn::Rand(amount)
        }
    }

    /// The units burned, zero when nothing is.
    pub fn units(self) -> u64 {
        match self {
            Burn::None => 0,
            Burn::Rand(amount) | Burn::Asset { amount, .. } => amount,
        }
    }
}

/// What a submitted transaction did, for the caller to print.
///
/// `amount`, `change` and `asset` describe the bundle's asset slots: for a RAND transfer, a bond,
/// a deploy or a call that is RAND (and `change` is all the RAND that came back); for a token
/// transfer or a burn it is the token — `amount` what was paid or burned, `change` what came back
/// as a note of it — and `rand_change` is what came back from the RAND slots that paid the fee.
/// `fee` is always RAND.
#[derive(Clone, Debug)]
pub struct Submission {
    pub hash: Hash,
    pub amount: u64,
    pub change: u64,
    pub fee: u64,
    /// What the bundle burned out of the pool, and in which unit (see [`Burn`]).
    pub burn: Burn,
    pub time: u32,
    pub asset: u32,
    /// RAND change from the fee slots when `asset` is a token; zero when `asset` is RAND, whose
    /// change is `change`.
    pub rand_change: u64,
    pub tier: u8,
    pub proof_bytes: usize,
    pub proving: Duration,
}

impl Submission {
    /// The two lines `rand` prints when a submission comes back, `what` naming the action
    /// ("transfer", "bond", "bridge burn"): the transaction hash, then what moved.
    ///
    /// Here rather than in `main` so that the one line a user reads after paying for a proof is
    /// covered by a test.
    pub fn summary(&self, what: &str) -> String {
        // A token's figures are in that token's own units; everything else moves RAND. The fee
        // is always RAND, and so is the change of the slots that paid it.
        let (out, change, fee_change) = if self.asset == 0 {
            (format!("{} RAND", format_amount(self.amount)), format!("{} RAND", format_amount(self.change)), String::new())
        } else {
            (
                format!("{} of asset {}", self.amount, self.asset),
                format!("{} of asset {}", self.change, self.asset),
                format!(", {} RAND change", format_amount(self.rand_change)),
            )
        };
        // What left the pool without becoming anybody's note. A bond's stake is RAND and says
        // so. A token burn's is the `out` figure above — the same number in the same units,
        // already printed — and repeating it would only raise the question of why two lines agree.
        let burned = match self.burn {
            Burn::None | Burn::Asset { .. } => String::new(),
            Burn::Rand(amount) => format!("{} RAND burned, ", format_amount(amount)),
        };
        format!(
            "submitted {what} {}\n  {out} out, {burned}{change} change, fee {} RAND{fee_change}, anchored at height {}",
            self.hash,
            format_amount(self.fee),
            self.time,
        )
    }
}

/// Who an output slot pays.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Payee {
    /// Someone else (or this wallet by its address): a payment.
    To(ShieldedAddress),
    /// This wallet: change.
    Me,
    /// Nobody: a zero-value dummy whose envelope is sealed to a throwaway key, so it opens to no
    /// one, the sender included.
    Nobody,
}

/// One hidden-asset bundle as the wallet plans it, before any witness or proof: the notes each
/// group spends and what each output slot pays.
///
/// Slots 0–1 carry the bundle's private asset `A` ([`Plan::asset`]); slots 2–3 carry RAND and pay
/// the fee. A bundle whose asset is RAND itself (`A = 0`: a RAND payment, a bond, a deploy, a
/// call) keeps today's shape — the value and the fee both in slots 2–3, slots 0–1 dummies (spec
/// §3.1) — so it can spend two RAND notes, as before. A token bundle spends up to two notes of
/// the token in slots 0–1 and up to two RAND notes for the fee in slots 2–3.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    asset: u32,
    /// The notes of `asset` spent in slots 0–1: empty when `asset` is RAND.
    a_notes: Vec<OwnedNote>,
    /// The RAND notes spent in slots 2–3.
    r_notes: Vec<OwnedNote>,
    /// The payment, if the bundle pays anyone: the recipient and the amount, in `asset`.
    to: Option<(ShieldedAddress, u64)>,
    fee: u64,
    /// Burned from the asset's slots (`asset` must then be a token).
    burn_a: u64,
    /// RAND burned from slots 2–3.
    burn_r: u64,
}

/// What [`Plan::select`] is asked for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Spend<'a> {
    /// The asset of slots 0–1: 0 for RAND, otherwise a token's registry index.
    pub asset: u32,
    /// The payment, in `asset`; `None` for a bundle that pays nobody (a deploy, a bond, a burn).
    pub to: Option<(&'a ShieldedAddress, u64)>,
    pub fee: u64,
    pub burn_a: u64,
    pub burn_r: u64,
}

impl Plan {
    /// Select both groups' notes in one plan, largest-first and at most two per group
    /// ([`select_inputs`]).
    ///
    /// The fee is RAND, always (spec §3.9): a token bundle whose wallet holds no spendable RAND is
    /// refused here, with the reason, before anything is proved.
    pub(crate) fn select(store: &NoteStore, spend: Spend<'_>) -> Result<Plan> {
        let Spend { asset, to, fee, burn_a, burn_r } = spend;
        let amount = to.map_or(0, |(_, a)| a);
        let (a_notes, r_notes) = if asset == 0 {
            // RAND is burned through `burn_r` only; the ledger refuses a RAND `burn_a`
            // (`NonCanonicalRandBurn`), so a plan that asked for one is this wallet's bug.
            if burn_a != 0 {
                return Err(anyhow!("a RAND burn goes through burn_r, never burn_a"));
            }
            let need = bundle_need(amount, fee, burn_r)?;
            (Vec::new(), select_inputs(&store.spendable_of(0), need)?)
        } else {
            let need_a = bundle_need(amount, 0, burn_a)?;
            if need_a == 0 {
                return Err(anyhow!("a bundle of asset {asset} that neither pays nor burns any of it"));
            }
            let need_r = bundle_need(0, fee, burn_r)?;
            let rand = store.spendable_of(0);
            if rand.is_empty() && need_r > 0 {
                // RAND held back by a `--no-wait` submission is not spendable yet, but it is not
                // missing either: say which, so the answer is "wait", not "go and get some".
                let pending: u64 =
                    store.notes.iter().filter(|n| n.note.asset == 0 && !n.spent && n.pending.is_some()).map(|n| n.note.amount).sum();
                if pending > 0 {
                    return Err(anyhow!(
                        "a transfer pays its fee in RAND, and this wallet holds no spendable RAND: {} RAND is held \
                         by a pending submission — `rand sync` once it commits (or expires) and retry",
                        format_amount(pending)
                    ));
                }
                return Err(anyhow!(
                    "a transfer pays its fee in RAND, and this wallet holds no spendable RAND: \
                     receive some RAND (on a testnet, `rand faucet`) and retry"
                ));
            }
            let a_notes = select_inputs(&store.spendable_of(asset), need_a).map_err(|e| anyhow!("asset {asset}: {e}"))?;
            let r_notes = select_inputs(&rand, need_r).map_err(|e| anyhow!("the RAND fee: {e}"))?;
            (a_notes, r_notes)
        };
        Ok(Plan { asset, a_notes, r_notes, to: to.map(|(d, a)| (d.clone(), a)), fee, burn_a, burn_r })
    }

    fn amount(&self) -> u64 {
        self.to.as_ref().map_or(0, |(_, a)| *a)
    }

    /// Every note this bundle spends, slot order: the asset's, then RAND's.
    fn inputs(&self) -> impl Iterator<Item = &OwnedNote> {
        self.a_notes.iter().chain(&self.r_notes)
    }

    /// The asset change (slots 0–1). Zero for a RAND bundle, whose change is all [`Plan::change_r`].
    fn change_a(&self) -> u64 {
        if self.asset == 0 {
            return 0;
        }
        let have: u64 = self.a_notes.iter().map(|n| n.note.amount).sum();
        have - self.amount() - self.burn_a
    }

    /// The RAND change (slots 2–3).
    fn change_r(&self) -> u64 {
        let have: u64 = self.r_notes.iter().map(|n| n.note.amount).sum();
        let paid_here = if self.asset == 0 { self.amount() } else { 0 };
        have - paid_here - self.fee - self.burn_r
    }

    /// What each output slot pays, and how much. A zero amount is a dummy sealed to nobody —
    /// including a change of exactly zero, which is worth nothing to keep.
    fn outputs(&self) -> [(Payee, u64); SLOTS] {
        let pay = |amount: u64| match &self.to {
            Some((dest, _)) if amount > 0 => (Payee::To(dest.clone()), amount),
            _ => (Payee::Nobody, 0),
        };
        let mine = |amount: u64| if amount > 0 { (Payee::Me, amount) } else { (Payee::Nobody, 0) };
        if self.asset == 0 {
            [(Payee::Nobody, 0), (Payee::Nobody, 0), pay(self.amount()), mine(self.change_r())]
        } else {
            [pay(self.amount()), mine(self.change_a()), mine(self.change_r()), (Payee::Nobody, 0)]
        }
    }

    /// The fields a [`Submission`] reports for this plan.
    fn report(&self, hash: Hash, burn: Burn, time: u32, proved: &Proved) -> Submission {
        let (amount, change, rand_change) = match burn {
            // A token burn's figures are the token's: what left the pool, and what came back.
            Burn::Asset { amount, .. } => (amount, self.change_a(), self.change_r()),
            _ if self.asset == 0 => (self.amount(), self.change_r(), 0),
            _ => (self.amount(), self.change_a(), self.change_r()),
        };
        Submission {
            hash,
            amount,
            change,
            fee: self.fee,
            burn,
            time,
            asset: self.asset,
            rand_change,
            tier: proved.tier,
            proof_bytes: proved.proof.len(),
            proving: proved.proving,
        }
    }
}

/// A fresh random word: a blinding `r`.
fn fresh_word() -> Word8 {
    SpendKey::random().0
}

/// A planned bundle with its witness built, its outputs chosen and its envelopes sealed — every
/// field of the bundle but its proof, which is left empty.
///
/// A bundle is proved only once the whole transaction around it exists (Task 5b): its proof
/// carries [`Transaction::binding`] as its public input segment, and the binding covers every
/// field of the transaction except the proof — the action, the four envelopes, the chain id. So
/// the wallet builds the transaction from this first, takes its binding, and then proves the
/// bundle with it ([`Prepared::prove`]).
struct Prepared {
    /// The bundle, `proof` empty.
    bundle: Bundle,
    /// The guest's private inputs (`hidden::hidden_bundle_inputs`).
    words: Vec<u32>,
    /// The digest this wallet computed from its own plaintext, which the proof must publish.
    expected: Word8,
}

/// One bundle's proof, made against its transaction's binding.
struct Proved {
    proof: Vec<u8>,
    tier: u8,
    proving: Duration,
}

/// The guest taints its digest instead of failing when a witness violates the relation, so a
/// proof that does not publish the digest this wallet computed from its own plaintext is a bug in
/// this wallet — not something the node would explain, since the node only ever sees a digest
/// that matches no plaintext.
fn check_published_digest(digest: &Word8, expected: &Word8) -> Result<()> {
    if digest != expected {
        return Err(anyhow!(
            "the bundle proof published digest {} but this wallet built {} — refusing to submit (wallet bug)",
            word8_to_hex(digest),
            word8_to_hex(expected),
        ));
    }
    Ok(())
}

impl Prepared {
    /// Prove this bundle with `binding` — the [`Transaction::binding`] of the transaction it has
    /// already been placed in — as the public input segment. The chain recomputes the binding from
    /// the transaction it receives and refuses a proof made for any other.
    fn prove(&self, binding: &[u32; TX_BINDING_WORDS], profile: FriProfile, backend: Backend) -> Result<Proved> {
        eprintln!("proving the bundle (tier 14; about a minute and a half on a laptop)…");
        let started = Instant::now();
        let (proof, digest, tier) = prove_hidden_bundle(profile, &self.words, binding, backend)
            .map_err(|e| anyhow!("proving the bundle failed: {e}"))?;
        let proving = started.elapsed();
        eprintln!("proved in {proving:.1?}: tier {tier}, {} bytes", proof.len());
        check_published_digest(&digest, &self.expected)?;
        Ok(Proved { proof, tier, proving })
    }
}

/// How a submission proves its bundle: the real prover at the chain's profile, or — in unit
/// tests — the guest run in the emulator, whose digest is checked exactly as a proof's is.
#[derive(Clone, Copy)]
enum Proving {
    Real(FriProfile, Backend),
    #[cfg(test)]
    Emulated,
}

impl Proving {
    fn prove(self, prepared: &Prepared, binding: &[u32; TX_BINDING_WORDS]) -> Result<Proved> {
        match self {
            Proving::Real(profile, backend) => prepared.prove(binding, profile, backend),
            #[cfg(test)]
            Proving::Emulated => tests::emulated_proof(prepared, binding),
        }
    }
}

/// Builds the one bundle of a transaction — witness, outputs, envelopes, everything but the proof
/// — from a plan, the anchor, one Merkle path per spent note (in [`Plan::inputs`] order, folded
/// against `anchor`) and the bundle's `time`. No I/O.
///
/// Every slot the plan does not fill is a dummy: a zero-value input under this wallet's own key
/// and a zero-value output to a throwaway key, **each with a fresh blinding** — two identical
/// dummies would repeat a nullifier or a commitment and taint the proof (spec §3.3), and a
/// repeated one across transactions would be refused as spent. Every output envelope is sealed
/// under its own fresh transaction key.
fn build_bundle(w: &Wallet, plan: &Plan, anchor: Word8, paths: &[[Word8; DEPTH]], time: u32) -> Result<Prepared> {
    let pk_self = w.vk.pk();
    let asset = plan.asset;
    if paths.len() != plan.inputs().count() {
        return Err(anyhow!("{} Merkle paths for {} spent notes", paths.len(), plan.inputs().count()));
    }
    let mut paths = paths.iter();
    let mut slot_input = |k: usize, spent: Option<&OwnedNote>| -> Result<(Note, [Word8; DEPTH], u32)> {
        match spent {
            Some(n) => {
                // The guest stages every input under this key; a note owned by any other would
                // nullify a note that is not the one this wallet holds (and the builder panics).
                if n.note.pk != pk_self {
                    return Err(anyhow!("note {} is not owned by this wallet's key", n.index));
                }
                let index = u32::try_from(n.index).map_err(|_| anyhow!("leaf index {} does not fit the witness", n.index))?;
                Ok((n.note, *paths.next().expect("counted above"), index))
            }
            None => Ok((Note::new(pk_self, [0; 8], 0, hidden::slot_asset(k, asset), time), [[0; 8]; DEPTH], 0)),
        }
    };
    let inputs: [(Note, [Word8; DEPTH], u32); SLOTS] = [
        slot_input(0, plan.a_notes.first())?,
        slot_input(1, plan.a_notes.get(1))?,
        slot_input(2, plan.r_notes.first())?,
        slot_input(3, plan.r_notes.get(1))?,
    ];
    debug_assert!(A_SLOTS == 2 && SLOTS == 4, "the slot layout this builder fills");

    let mut outs = [HiddenOutput { pk: [0; 8], amount: 0, r: [0; 8] }; SLOTS];
    let mut envelopes: Vec<Envelope> = Vec::with_capacity(SLOTS);
    let mut commitments = [[0u32; 8]; SLOTS];
    for (k, (payee, amount)) in plan.outputs().into_iter().enumerate() {
        // The throwaway key a dummy is sealed to — and owned by — exists only for this call.
        let nobody = matches!(payee, Payee::Nobody).then(Wallet::generate);
        let pk = match (&payee, &nobody) {
            (Payee::To(dest), _) => dest.pk,
            (Payee::Me, _) => pk_self,
            (Payee::Nobody, Some(t)) => t.vk.pk(),
            (Payee::Nobody, None) => unreachable!("a throwaway key for every dummy"),
        };
        outs[k] = HiddenOutput { pk, amount, r: fresh_word() };
        let note = outs[k].note(k, pk_self, asset, time);
        commitments[k] = note.commitment();
        let key = TxKey::random();
        let sealed = match (&payee, &nobody) {
            (Payee::To(dest), _) => seal_note(&w.vk, dest, &note, &key),
            (Payee::Me, _) => seal_note(&w.vk, &w.address, &note, &key),
            (Payee::Nobody, Some(t)) => seal_note(&t.vk, &t.address, &note, &key),
            (Payee::Nobody, None) => unreachable!("a throwaway key for every dummy"),
        };
        envelopes.push(sealed.map_err(|e| anyhow!("sealing output {k}'s envelope: {e}"))?);
    }
    let nullifiers: [Word8; SLOTS] = std::array::from_fn(|k| w.vk.nullifier(&inputs[k].0.commitment()));
    // The ledger refuses a repeated nullifier or commitment and the guest taints on one; with a
    // fresh blinding per slot neither can happen, so one here is a bug worth stopping on before
    // a proof is paid for.
    for i in 0..SLOTS {
        for j in i + 1..SLOTS {
            if nullifiers[i] == nullifiers[j] || commitments[i] == commitments[j] {
                return Err(anyhow!("slots {i} and {j} repeat a nullifier or a commitment (wallet bug)"));
            }
        }
    }
    let burn_asset = if plan.burn_a != 0 { asset } else { 0 };
    let expected = hidden::hidden_bundle_digest(&HiddenDigestInput {
        anchor,
        nullifiers,
        commitments,
        fee: plan.fee,
        burn_a: plan.burn_a,
        burn_r: plan.burn_r,
        burn_asset,
        time,
    });
    let words = hidden::hidden_bundle_inputs(&w.sk, &inputs, &outs, anchor, plan.fee, plan.burn_a, plan.burn_r, asset, time);
    let envelopes: [Envelope; SLOTS] = envelopes.try_into().map_err(|_| anyhow!("four envelopes"))?;
    let bundle = Bundle {
        anchor,
        nullifiers,
        commitments,
        fee: plan.fee,
        burn_a: plan.burn_a,
        burn_r: plan.burn_r,
        burn_asset,
        time,
        envelopes,
        proof: Vec::new(),
    };
    Ok(Prepared { bundle, words, expected })
}

/// Fetches the anchor and a witness for every spent note, then builds the bundle
/// ([`build_bundle`]), returning it with the `time` it carries.
///
/// One anchor, and every witness folded against it. A witness is folded against the tree's
/// *current* root, so a leaf appended between the calls makes the witness prove membership in a
/// tree the anchor does not name — and the bundle would be rejected as `UnknownAnchor` or taint.
/// Refetching all of it together is the fix; three attempts is enough unless the chain is
/// committing notes faster than this wallet can read them.
async fn prepare_bundle(rpc: &RpcClient, w: &Wallet, plan: &Plan) -> Result<(Prepared, u32)> {
    let mut attempt = 0;
    let (height, root, paths) = 'fetch: loop {
        attempt += 1;
        let (height, root) = rpc.anchor(None).await?;
        let mut paths = Vec::with_capacity(SLOTS);
        for n in plan.inputs() {
            let (witness_root, path) = rpc.witness(n.index).await?;
            if witness_root != root {
                if attempt >= 3 {
                    return Err(anyhow!("tree moved; retry"));
                }
                continue 'fetch;
            }
            paths.push(path);
        }
        break (height, root, paths);
    };
    let time = u32::try_from(height).map_err(|_| anyhow!("chain height {height} does not fit a bundle's time field"))?;
    Ok((build_bundle(w, plan, root, &paths, time)?, time))
}

/// Prove `tx`'s one bundle against `tx`'s own binding, in place. The binding is taken with the
/// proof still empty; filling the proof in cannot move it, because the binding blanks it.
///
/// `prove` is [`Prepared::prove`] at the caller's profile and backend; a unit test hands in a stub
/// prover, which is what lets the ordering be tested without a minute of proving.
fn prove_transaction(
    tx: &mut Transaction,
    prepared: &Prepared,
    prove: &dyn Fn(&Prepared, &[u32; TX_BINDING_WORDS]) -> Result<Proved>,
) -> Result<Proved> {
    let binding = tx.binding();
    let p = prove(prepared, &binding)?;
    tx.bundle.as_mut().context("a shielded transaction has a bundle")?.proof = p.proof.clone();
    debug_assert_eq!(tx.binding(), binding, "filling the proof in never moves the binding");
    Ok(p)
}

/// Wait for the commit, or hold the spent notes back: the tail of every submission.
async fn settle(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    hash: &Hash,
    plan: &Plan,
    time: u32,
    wait: bool,
) -> Result<()> {
    if wait {
        // The inputs are marked spent by the rescan, from the chain's own nullifier set — not
        // from this wallet's belief about what it just sent. That matters on the failure path:
        // a bundle that never commits (the wait times out, the mempool drops it) leaves its
        // notes spendable, where marking them here would strand them until the store is thrown
        // away and rebuilt.
        rpc.wait_for_transaction(hash, COMMIT_TIMEOUT).await?;
        scan(rpc, w, store).await?;
    } else {
        // Nothing will confirm these for the caller, so they are held back rather than declared
        // spent: `pending` keeps them out of coin selection without the one-way write that
        // stranded them when a bundle failed to commit. The next `scan` decides which it was.
        for n in store.notes.iter_mut() {
            if plan.inputs().any(|c| c.index == n.index) {
                n.pending = Some(time);
            }
        }
    }
    Ok(())
}

/// Every bundle-carrying submission goes through here: scan, plan both groups, fetch the anchor
/// and the witnesses, build the bundle, assemble the transaction with the proof empty, take its
/// binding, prove against it, fill the proof in, submit. One code path, so the fee, the anchor,
/// the witnesses and the digest check cannot drift apart between a transfer, a bond, a deploy, a
/// call, an attestation and a burn.
#[allow(clippy::too_many_arguments)]
async fn submit_spend(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    spend: Spend<'_>,
    action: Action,
    burn: Burn,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    scan(rpc, w, store).await?;
    let plan = Plan::select(store, spend)?;
    let (prepared, time) = prepare_bundle(rpc, w, &plan).await?;
    // The whole transaction first, its bundle's proof empty; then the proof, bound to it. Nothing
    // is set on the transaction after the proof but the proof itself.
    let mut tx = Transaction::shielded(chain_id, prepared.bundle.clone(), action);
    let proved = prove_transaction(&mut tx, &prepared, &|p, b| proving.prove(p, b))?;
    // `submit_refused` labels a JSON-RPC error reply *from this call* as `SubmitRefused`
    // (node I1): it is the only failure here that means nothing was admitted, and `rand token
    // create` deletes a freshly generated authority key on it and on nothing else. Everything
    // after this line — the wait, the rescan — can fail with an `RpcError` too, and must not be
    // mistaken for a refusal.
    let hash = rpc.send_transaction(&tx).await.map_err(crate::submit_refused)?;
    settle(rpc, w, store, &hash, &plan, time, wait).await?;
    Ok(plan.report(hash, burn, time, &proved))
}

/// A RAND-paying bundle for any action: a transfer (`to = Some(..)`), a deploy, a call, a bond or
/// a bridge attestation (`to = None`: the bundle pays nobody and exists to pay the action's fee
/// floor — and, for a bond, to burn the stake). The bundle's asset is RAND, so its value and fee
/// share slots 2–3 and slots 0–1 are dummies.
///
/// `burn` is what the bundle takes out of the shielded pool, which a `Bond` must set to the staked
/// amount (`burn_r`; the ledger refuses a bond whose bundle burns anything else) and every other
/// action here leaves at [`Burn::None`]. A burn of a *token* is not this path, so [`Burn::Asset`]
/// is an error here: it is [`submit_burn`] or [`submit_token_burn`].
#[allow(clippy::too_many_arguments)]
pub async fn submit(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: Option<(&ShieldedAddress, u64)>,
    action: Action,
    fee: u64,
    burn: Burn,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_with(rpc, w, store, to, action, fee, burn, Proving::Real(profile, backend), chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: Option<(&ShieldedAddress, u64)>,
    action: Action,
    fee: u64,
    burn: Burn,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    // This path burns only RAND. Answered before the chain is asked anything: a caller holding
    // notes of a token is one function away from what it meant, and a proof away from finding out
    // the hard way.
    let burn = match burn {
        Burn::Rand(amount) => Burn::rand(amount),
        Burn::None => Burn::None,
        Burn::Asset { index, amount } => {
            return Err(anyhow!(
                "burning {amount} of asset {index} is a token burn: that is `submit_burn` or `submit_token_burn`, not `submit`"
            ))
        }
    };
    let spend = Spend { asset: 0, to, fee, burn_a: 0, burn_r: burn.units() };
    submit_spend(rpc, w, store, spend, action, burn, proving, chain_id, wait).await
}

/// A bridge action on a fee bundle: `rand bridge-mint`'s and `rand bridge-rotate`'s
/// `BridgeAttest`, `rand token register-bridged`'s `RegisterBridgedToken` and `rand token
/// list-backing`'s `ListBacking`. The bundle pays nobody and burns nothing — the RAND fee from
/// slots 2–3, slots 0–1 dummies, `burn_a`/`burn_r`/`burn_asset` zero — and is built, bound and
/// proved by the one [`submit_spend`] path every other submission takes, so the action (its PQ
/// co-signatures included) sits inside the binding the proof is made against.
///
/// Every refusable check — the attestation's shape, the PQ quorum's structure against the node's
/// set, the deposit index, the governance nonce, the listing's metadata — is the caller's, and
/// runs before this is called: nothing here can refuse the action itself, only the wallet's funds.
#[allow(clippy::too_many_arguments)]
pub async fn submit_bridge_action(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_bridge_action_with(rpc, w, store, action, fee, Proving::Real(profile, backend), chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_bridge_action_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(
        action,
        Action::BridgeAttest { .. } | Action::RegisterBridgedToken { .. } | Action::ListBacking { .. }
    ) {
        return Err(anyhow!("submit_bridge_action carries a bridge attestation or a bridged-token listing, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, proving, chain_id, wait).await
}

/// The four facts about the chain a burn needs before any proving: the chain has a bridge at
/// all, the asset index it names is one the registry holds, the coin it asks to redeem —
/// `(to_chain, token)` — backs that asset, and both `amount` and `relayer_fee` are whole
/// numbers of that coin's release unit and within what it is holding.
///
/// None of them is something a wallet can know locally — all four are state — and getting any of
/// them wrong costs a bundle proof (minutes of a laptop) for a transaction the ledger
/// refuses outright: `Bridge(Disabled)` for a chain with no bridge, `Bridge(UnknownAsset)` for an
/// index nothing was ever registered under, `NotABacking` for a coin that does not back it,
/// `NotReleasable` for an amount or fee that is not a whole unit and `InsufficientBacking` for a
/// coin that does back it but is not holding enough. `rand bridge-mint` already reads the chain
/// before proving for the same reason (`deposit_index`); this is a burn's half of it, off the one
/// `rand_getBridgeState` reply, whose `assets` array is the registry — one row per coin, carrying
/// that coin's source `decimals` and its `locked`.
///
/// The `locked` check is the one the zUSD amendment added (spec §12): one bridged token is backed
/// by several coins, so a burn of 700 zUSD may be well within the token's supply and still more
/// than the chain it names is holding — and the far side would refuse to release it.
///
/// The release-unit check is bridge-06/audit O-5's: the attestation wire carries amounts at eight
/// decimals, so a source coin declaring `d < 8` releases in units of `10^(8-d)` and anything else
/// either strands the remainder in custody or, below one unit, releases nothing. It is checked
/// **before** the locked amount, the order [`randprotocol_core::ledger::tokens::TokenRegistry::check_release`]
/// itself uses — the cheap, state-independent half first — so the two say the same thing in the
/// same order.
///
/// Deliberately not the rest of `BridgeState::check_burn` — the recipient must be shaped for the
/// destination chain — which is the bridge's own policy and stays stated in one place.
fn burn_is_possible(
    bridge_state: &Value,
    asset: u32,
    to_chain: u16,
    token: &[u8; 32],
    amount: u64,
    relayer_fee: u64,
) -> Result<()> {
    if bridge_state["enabled"] != Value::Bool(true) {
        return Err(anyhow!("this chain has no bridge, so there is nothing to burn to"));
    }
    let rows = bridge_state["assets"].as_array().context("bridge state has no asset registry")?;
    let of_asset: Vec<&Value> = rows.iter().filter(|r| r["index"].as_u64() == Some(asset as u64)).collect();
    if of_asset.is_empty() {
        let known: Vec<String> = rows.iter().filter_map(|r| r["index"].as_u64()).map(|i| i.to_string()).collect();
        return Err(anyhow!(
            "asset {asset} is not in this chain's registry, so no note of it was ever deposited{}",
            if known.is_empty() {
                " (the registry is empty)".to_string()
            } else {
                format!(" (registered: {})", known.join(", "))
            }
        ));
    }
    let hex_token = hex::encode(token);
    let Some(backing) = of_asset
        .iter()
        .find(|r| r["chain"].as_u64() == Some(to_chain as u64) && r["token"].as_str() == Some(hex_token.as_str()))
    else {
        let coins: Vec<String> = of_asset
            .iter()
            .filter_map(|r| Some(format!("chain {} token {}", r["chain"].as_u64()?, r["token"].as_str()?)))
            .collect();
        return Err(anyhow!(
            "coin {hex_token} on chain {to_chain} does not back asset {asset}; its backings are: {}",
            coins.join(", ")
        ));
    };
    // The release unit, from the coin's own declared decimals. Derived through the chain's own
    // `tokens::release_unit` rather than by a second `10^(8-d)` written here, so the wallet and
    // the ledger can never disagree about what a whole unit is.
    let decimals = backing["decimals"].as_u64().context("an asset row without the coin's decimals")?;
    let decimals = u8::try_from(decimals).context("an asset row whose decimals is not a byte")?;
    let unit = randprotocol_core::ledger::tokens::release_unit(decimals);
    if amount % unit != 0 || relayer_fee % unit != 0 {
        return Err(anyhow!(
            "{hex_token} on chain {to_chain} has {decimals} decimals: \
             the amount and the relayer fee must be multiples of {unit}"
        ));
    }
    // `amount_field`, not `as_u64`: the node renders every amount as a decimal string since
    // chain 14 (node I3), and an older one as a number. Both are read here.
    let locked = crate::amount_field(&backing["locked"]).context("an asset row without a locked amount")?;
    if amount > locked {
        return Err(anyhow!(
            "only {locked} is locked in that coin on chain {to_chain}; choose another backing or a smaller amount"
        ));
    }
    Ok(())
}

/// Burn `amount` of a bridged asset to `to_chain`/`to` (spec §10): one hidden-asset bundle that
/// spends the asset in its slots 0–1 and burns exactly `amount` of it (`burn_a == amount`,
/// `burn_asset == asset`, `burn_r == 0`), paying the RAND fee from slots 2–3.
///
/// Everything that can refuse a burn before a proof is paid for runs first: the definitional
/// checks, then one read of the chain ([`burn_is_possible`] — the bridge, the registry, the
/// backing, the release unit and the locked amount), then note selection, which refuses a wallet
/// without the asset or without RAND for the fee.
#[allow(clippy::too_many_arguments)]
pub async fn submit_burn(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    asset: u32,
    amount: u64,
    relayer_fee: u64,
    to_chain: u16,
    token: [u8; 32],
    to: [u8; 32],
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    let burn = BurnRequest { asset, amount, relayer_fee, to_chain, token, to };
    submit_burn_with(rpc, w, store, burn, fee, Proving::Real(profile, backend), chain_id, wait).await
}

/// [`submit_burn`]'s arguments that become the action.
#[derive(Clone, Copy, Debug)]
struct BurnRequest {
    asset: u32,
    amount: u64,
    relayer_fee: u64,
    to_chain: u16,
    token: [u8; 32],
    to: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
async fn submit_burn_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    burn: BurnRequest,
    fee: u64,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    let BurnRequest { asset, amount, relayer_fee, to_chain, token, to } = burn;
    if asset == 0 {
        return Err(anyhow!("asset 0 is RAND, which is not a bridged asset and cannot be burned"));
    }
    // The bridge owns the rest of a burn's rules (`BridgeState::check_burn`: the destination must be
    // the asset's own chain, the recipient must be shaped for it) and this wallet deliberately does
    // not restate them. These two are the exception, because they are definitional rather than
    // policy and because the alternative is a bundle proof — a minute and a half of a laptop —
    // thrown away on a typo.
    if amount == 0 {
        return Err(anyhow!("a burn of zero moves nothing"));
    }
    if relayer_fee > amount {
        return Err(anyhow!("the relayer fee {relayer_fee} is more than the {amount} being burned"));
    }
    // One read of the chain, before any proving, for the facts only the chain knows — the coin's
    // release unit and its locked amount among them, since one token's backings are held apart.
    burn_is_possible(&rpc.bridge_state().await?, asset, to_chain, &token, amount, relayer_fee)?;
    let action = Action::BridgeBurn { asset, amount, relayer_fee, to_chain, token, to };
    let spend = Spend { asset, to: None, fee, burn_a: amount, burn_r: 0 };
    submit_spend(rpc, w, store, spend, action, Burn::Asset { index: asset, amount }, proving, chain_id, wait).await
}

/// Burn `amount` of token `asset` held in this wallet (`Action::TokenBurn`, RPL spec §4): the
/// token's public `total_supply` drops by exactly that. One hidden-asset bundle, shaped like a
/// bridge burn's (`burn_a == amount`, `burn_asset == asset`, `burn_r == 0`, the RAND fee from
/// slots 2–3).
///
/// Refused before any proof: RAND (which burns through `burn_r`, by a bond), a burn of zero, and a
/// *bridged* token — its supply moves only with one of its backings, so it leaves through
/// `rand bridge-burn`, which names the coin being released (`TokenError::BridgedToken`); the
/// bridged tokens are the rows `rand_getAssets` lists. An index nothing was ever minted under has
/// no notes here to burn, so note selection refuses it too.
#[allow(clippy::too_many_arguments)]
pub async fn submit_token_burn(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    asset: u32,
    amount: u64,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_token_burn_with(rpc, w, store, asset, amount, fee, Proving::Real(profile, backend), chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_token_burn_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    asset: u32,
    amount: u64,
    fee: u64,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if asset == 0 {
        return Err(anyhow!("asset 0 is RAND, which is not a token: RAND leaves the pool by a bond, not a burn"));
    }
    if amount == 0 {
        return Err(anyhow!("a burn of zero moves nothing"));
    }
    if rpc.assets().await?.iter().any(|a| a.index == asset) {
        return Err(anyhow!(
            "asset {asset} is a bridged token: its supply leaves through `rand bridge-burn`, which names the coin released"
        ));
    }
    let action = Action::TokenBurn { asset, amount };
    let spend = Spend { asset, to: None, fee, burn_a: amount, burn_r: 0 };
    submit_spend(rpc, w, store, spend, action, Burn::Asset { index: asset, amount }, proving, chain_id, wait).await
}

/// The facts a deploy needs from the chain before any proving: whether `words` code words fit this
/// chain's program cap (`max_program_words`, a genesis parameter — Task 1), and whether
/// `public_words` public-input words fit its public-input cap (`max_program_public_words`).
///
/// A public input is checked against `rand_getLimits` first, so the refusal names the cap; a node
/// without that method predates public inputs, and a deploy carrying one is refused outright.
/// Then `rand_estimateFee` applies the same checks the ledger's own `Action::Deploy` admission
/// does, so a program over either cap is refused here, for the price of an RPC call or two,
/// rather than after a proof — minutes on a laptop for a `deploy` the chain would then throw away.
/// The node's own reply names the code cap (`"words must be at most N (this chain's program
/// cap)"`), so it is passed through. Without a public input the node is asked exactly what it
/// always was, so an older node still answers. Returns the fee estimate.
pub async fn deploy_precheck(rpc: &RpcClient, words: usize, public_words: usize) -> Result<u64> {
    if public_words == 0 {
        return rpc.estimate_fee(serde_json::json!({ "kind": "deploy", "words": words })).await;
    }
    let limits = rpc.limits().await?.ok_or_else(|| {
        anyhow!("this node does not answer rand_getLimits, so it predates deploy-time public inputs; deploy without --public")
    })?;
    let cap = limits.max_program_public_words;
    if cap == 0 {
        return Err(anyhow!(
            "this chain admits no public input (max_program_public_words is 0); deploy without --public"
        ));
    }
    if public_words > cap {
        return Err(anyhow!(
            "a public input of {public_words} words is over this chain's cap of {cap} (max_program_public_words)"
        ));
    }
    rpc.estimate_fee(serde_json::json!({ "kind": "deploy", "words": words, "public_words": public_words })).await
}

/// `--public <file>` for `rand program deploy`, as the words the program's public input will be.
///
/// Two forms. An ELF (`\x7fELF` magic, or a `.so` name, which must then be an ELF) is
/// word-encoded by [`elf_public_words`], as the sBPF guest reads its program. Anything else is
/// text: u32 words separated by whitespace, each decimal or `0x` hex.
pub fn public_file_words(path: &Path) -> Result<Vec<u32>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let is_so = path.extension().and_then(|e| e.to_str()) == Some("so");
    if bytes.starts_with(b"\x7fELF") {
        return Ok(elf_public_words(&bytes));
    }
    if is_so {
        return Err(anyhow!("{} is named .so but is not an ELF (no \\x7fELF magic)", path.display()));
    }
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{} is neither an ELF nor text of u32 words", path.display()))?;
    let words = text
        .split_whitespace()
        .map(|t| {
            let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u32::from_str_radix(h, 16),
                None => t.parse::<u32>(),
            };
            parsed.map_err(|_| anyhow!("{}: {t:?} is not a u32 word", path.display()))
        })
        .collect::<Result<Vec<u32>>>()?;
    if words.is_empty() {
        return Err(anyhow!("{} has no words; a public input has at least one", path.display()));
    }
    Ok(words)
}

/// An ELF as public-input words, exactly as research's `SbpfCall::public_words` encodes it (the
/// vendored `randprotocol_zkvm::sbpf`, reused here rather than restated): the byte length, then
/// the bytes four per word, little-endian, the last word zero-padded.
pub fn elf_public_words(elf: &[u8]) -> Vec<u32> {
    randprotocol_zkvm::sbpf::SbpfCall { elf: elf.to_vec(), input: Vec::new() }.public_words()
}

/// The envelope caps a call is proved and sealed within: derived from the chain's
/// `max_call_envelope_bytes` (`CallCaps::for_envelope_bytes`: less the envelope's fixed overhead,
/// over four), or the old 4 096 words under the default byte cap when the node does not report
/// its limits.
pub fn call_caps(limits: Option<&ChainLimits>) -> randprotocol_zkvm::call_envelope::CallCaps {
    use randprotocol_zkvm::call_envelope::CallCaps;
    limits.map_or(CallCaps::FALLBACK, |l| CallCaps::for_envelope_bytes(l.max_call_envelope_bytes))
}

/// The largest call proof the chain admits: its `max_proof_bytes`, or the default 2 MiB from a
/// node that does not report its limits.
pub fn proof_cap(limits: Option<&ChainLimits>) -> usize {
    limits.map_or(gas::MAX_PROOF_BYTES, |l| l.max_proof_bytes)
}

/// The proof-size pre-check `rand call` makes after proving and before the paying bundle is
/// proved: a proof the chain refuses by size would cost that second proof for nothing.
pub fn check_proof_size(proof_bytes: usize, cap: usize) -> Result<()> {
    if proof_bytes > cap {
        return Err(anyhow!(
            "the call proof is {proof_bytes} bytes, over this chain's {cap}-byte cap (max_proof_bytes); \
             it would be refused, so nothing was submitted"
        ));
    }
    Ok(())
}

/// What `rand call` proves over: the program's code and its deploy-time public input
/// (`rand_getProgramCode`, `rand_getProgramPublic`), checked locally against the program id asked
/// for. The id commits to both (`program_id_with_public`), so a node serving any other code or
/// public input is caught here, before a proof the chain would refuse.
pub async fn load_call_program(
    rpc: &RpcClient,
    id: &randprotocol_core::program::ProgramId,
) -> Result<(randprotocol_zkvm::isa::Program, Vec<u32>)> {
    let (base_pc, words) = rpc.program_code(id).await?.context("program not found on chain")?;
    let public = rpc.program_public(id).await?.context("program not found on chain")?;
    let served = randprotocol_core::program::program_id_with_public(base_pc, &words, &public);
    if served != *id {
        return Err(anyhow!(
            "the node served code ({} words) and a public input ({} words) that do not hash to program {id} \
             (they hash to {served}); not proving against them",
            words.len(),
            public.len()
        ));
    }
    Ok((randprotocol_zkvm::isa::Program { base_pc, words }, public))
}

/// `rand call --expect-public <file>`: the caller's own copy of the public input it means to run
/// against, compared with the program's before anything is proved. A call carries no public words
/// of its own (spec §6) — this only refuses early.
pub fn check_expected_public(on_chain: &[u32], expected: &[u32]) -> Result<()> {
    if on_chain.len() != expected.len() {
        return Err(anyhow!(
            "the program's public input is {} words and --expect-public has {}; not proving",
            on_chain.len(),
            expected.len()
        ));
    }
    if let Some(i) = on_chain.iter().zip(expected).position(|(a, b)| a != b) {
        return Err(anyhow!(
            "the program's public input differs from --expect-public at word {i} ({} on chain, {} expected); not proving",
            on_chain[i],
            expected[i]
        ));
    }
    Ok(())
}

/// What a `deploy` pays by default: the bundle base plus the program's per-word charge, which
/// is exactly `gas::fee_floor` for a `Deploy`.
pub fn deploy_fee_default(action: &Action) -> u64 {
    gas::fee_floor(action)
}

/// What a `call` pays by default — and deliberately NOT `fee_floor(Call) + call_fee(..)`.
/// `fee_floor(Call)` is `BUNDLE_BASE + CALL_BASE`, and `CALL_BASE` is already `call_fee`'s own
/// constant term, so adding the two overpays by `CALL_BASE`. The node's floor, once it has
/// decoded the proof and knows the tier, is precisely this (`Ledger::validate_inner`).
///
/// `bytes` is the call's proof plus its input envelope (`gas::call_bytes`); only what is past
/// `gas::CALL_FREE_BYTES` costs anything, so a call under today's caps pays today's fee.
pub fn call_fee_default(tier: u8, bytes: usize) -> u64 {
    gas::BUNDLE_BASE + gas::call_fee(tier, bytes)
}

/// What a `bridge-burn` pays by default: the bridge fee (0.01 RAND, covering its bundle's base
/// and the bridge's charge), which is `gas::fee_floor` for a `BridgeBurn`.
pub fn burn_fee_default() -> u64 {
    gas::BRIDGE_BURN_FEE
}

// ---------------------------------------------------------------- the bridge

/// What a bridge attestation would deposit: everything [`attested_deposit`] can read out of the
/// wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedDeposit {
    /// The 32-byte stand-in for the recipient's shielded address that the source-chain depositor
    /// named and the guardians signed — `ShieldedAddress::recipient_hash`. The ledger refuses a
    /// transaction whose `recipient` does not hash to it.
    pub to_hash: [u8; 32],
    /// The token as the guardians named it, which is what `rand_bridgeAssetId` turns into an
    /// [`AttestedDeposit::asset`] — the registry's key, and from there the note's `asset` index.
    pub token_chain: u16,
    pub token: [u8; 32],
    pub asset: AssetId,
    pub amount: u64,
}

/// Read a bridge attestation's deposit out of the wire bytes alone.
///
/// No state, no signature work and no RPC: a wallet needs this *before* it can build the
/// transaction, because the deposit note's commitment is computed by the chain and the recipient's
/// envelope has to be sealed against it. The amount and the asset come from the ledger's own pure
/// helper (`bridge_notes::attested_transfer`), so the note this wallet seals for cannot disagree
/// with the note the chain appends.
///
/// An error for bytes that do not decode, for a rotation (which deposits nothing) and for an amount
/// no note could hold — each of which the ledger refuses too, and each of which a wallet is better
/// off hearing about before it pays for a proof.
pub fn attested_deposit(attestation: &[u8]) -> Result<AttestedDeposit> {
    let att = Attestation::decode(attestation).map_err(|e| anyhow!("not a bridge attestation: {e:?}"))?;
    let payload = Payload::decode(&att.body.payload).map_err(|e| anyhow!("attestation payload: {e:?}"))?;
    let Payload::Transfer(t) = payload else {
        return Err(anyhow!("this attestation is a guardian-set rotation; it deposits nothing"));
    };
    // Whatever this says about the amount and the coin, the ledger's helper is what the chain
    // itself will read, so it — not the decode above — is what the note is built from.
    let (token_chain, token, amount) = bridge_notes::attested_transfer(attestation)
        .ok_or_else(|| anyhow!("this attestation's amount does not fit a note"))?;
    // The per-backing wire id, which is what `rand_bridgeAssetId` computes and what a
    // `rand_getAssets` row is keyed by — one row per coin, whichever token they back.
    let asset = randprotocol_core::bridge::asset_id(token_chain, &token);
    Ok(AttestedDeposit { to_hash: t.to, token_chain, token, asset, amount })
}

/// The `asset` word a deposit note will carry: the index the registry holds for this token.
///
/// A fact, and only ever a fact. A bridged token is *listed* on the chain — at genesis, or by a
/// governance message — before any attestation of it is admissible, and a listing's index never
/// moves, so the number this reads off `rand_getAssets` is the number the ledger will stamp into
/// the note however long the fee bundle takes to prove. There is nothing left to predict: the
/// index used to be the registry's `next_index` for a token the chain had never seen, and a
/// competing first sighting could take it while this wallet was proving.
///
/// A token the registry does not name deposits nothing at all — the chain refuses the
/// attestation (`BridgeError::UnlistedToken`) rather than registering it on sight — so this is
/// an error, raised before a minute and a half of proving rather than after it.
pub fn deposit_index(bridge_state: &Value, assets: &[AssetRow], asset_id: &str) -> Result<u32> {
    if bridge_state["enabled"] != Value::Bool(true) {
        return Err(anyhow!("this chain has no bridge"));
    }
    match assets.iter().find(|a| a.asset_id == asset_id) {
        Some(a) => Ok(a.index),
        None => Err(anyhow!(
            "this token is not listed on this chain: asset {asset_id} is in no registry row, so an \
             attestation of it would be refused. Ask the chain's governance to list it (a bridged \
             token is listed, never registered on sight)."
        )),
    }
}

/// `rand bridge-mint`'s pre-check, the mirror of `burn_is_possible` (node M4): the two ledger
/// rules that can refuse an otherwise perfect attestation, read off the `rand_getBridgeState`
/// reply the command already fetches, *before* buying ~100 s of proving to hear
/// `Bridge(MintsPaused)` or `Token(MintCapExceeded)`.
///
/// - **The pause** (bridge hardening B1). Read only in the transfer arm, so a burn or a rotation
///   is unaffected — and only a PQ guardian quorum can lift it, so this is not a wait of seconds.
/// - **The backing's remaining daily cap.** `minted_today` on the reply is already
///   `Backing::minted_on(head day)` — the figure `check_lock` compares against, with a counter
///   left from an earlier day reading zero — so the headroom here is the ledger's own, at the
///   head this wallet just read. It can still move under the transaction (another relayer's
///   deposit, or the day rolling over, which only ever *adds* headroom), which is why this is a
///   pre-check and the ledger stays the authority.
///
/// A row this chain does not list is **not** an error here: `deposit_index` is the check for
/// that, and it says so far better than a missing cap row could.
pub fn mint_is_possible(bridge_state: &Value, token_chain: u16, token: &[u8; 32], amount: u64) -> Result<()> {
    if bridge_state["mint_paused"] == Value::Bool(true) {
        return Err(anyhow!(
            "bridge minting is paused on this chain; a PQ guardian quorum must lift the pause              (rand bridge-unpause) before any deposit can be minted"
        ));
    }
    let hex_token = hex::encode(token);
    let Some(row) = bridge_state["assets"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find(|r| {
                r["chain"].as_u64() == Some(token_chain as u64) && r["token"].as_str() == Some(hex_token.as_str())
            })
        })
    else {
        // No row, no cap to check: `deposit_index` reports an unlisted token.
        return Ok(());
    };
    let (Some(cap), Some(minted)) =
        (crate::amount_field(&row["mint_cap_per_day"]), crate::amount_field(&row["minted_today"]))
    else {
        // A node predating the cap (B1) serves neither field. Nothing to pre-check.
        return Ok(());
    };
    let left = cap.saturating_sub(minted);
    if amount > left {
        return Err(anyhow!(
            "that coin's daily mint cap is {cap} and {minted} has been minted against it today,              so only {left} is left and this deposit is {amount}; it becomes mintable on the next              UTC day of the chain's block timestamp"
        ));
    }
    Ok(())
}

/// What a committed `BridgeAttest` deposited under, against the index the wallet sealed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositIndexCheck {
    /// The chain deposited under the index the envelope was sealed for.
    Agrees,
    /// It did not, so the envelope opens nothing: the recipient has to rebuild the note from the
    /// `r` and `time` the mint printed, with `committed` as its `asset` word.
    ///
    /// Unreachable on a *committed* transaction: the action names its index, admission refuses a
    /// mismatch outright (`TxError::AttestAssetMismatch`), and a listed token's index cannot move
    /// under a transaction while it is being proved. Kept as belt and braces — this is the one
    /// check that would catch a node whose registry disagrees with the one the index was read
    /// from.
    Mismatch { predicted: u32, committed: u32 },
    /// The node cannot say: not an attest, or an attestation whose token its registry does not
    /// list (and a rotation, which deposits nothing).
    Unknown,
}

/// Check the sealed-for deposit index against the committed transaction, as `rand_getTransaction`
/// returns it — `result.tx.action.asset_index`, which the node computes the same way the ledger
/// does (`bridge_notes::attested_transfer` plus the registry).
pub fn deposit_index_check(predicted: u32, tx: &Value) -> DepositIndexCheck {
    let action = &tx["tx"]["action"];
    if action["kind"] != Value::String("bridge_attest".into()) {
        return DepositIndexCheck::Unknown;
    }
    match action["asset_index"].as_u64().and_then(|i| u32::try_from(i).ok()) {
        None => DepositIndexCheck::Unknown,
        Some(committed) if committed == predicted => DepositIndexCheck::Agrees,
        Some(committed) => DepositIndexCheck::Mismatch { predicted, committed },
    }
}

/// The deposit note a `BridgeAttest` will append, and an envelope only `recipient` can open.
///
/// The commitment is not on the wire: the chain computes it from the amount the guardians signed,
/// the recipient the action names, the asset the registry numbered and the action's own `r` and
/// `time` (`bridge_notes::deposit_commitment`). So this builds exactly that note, and the envelope
/// is sealed against it — which is why `time` is a field of the action and not the height the
/// transaction lands at: nobody can predict the latter, and an envelope sealed for the wrong note
/// leaves the recipient a leaf they cannot open.
///
/// `from` is the zero word: a deposit has no sender inside the pool. The blinding is not drawn:
/// since chain 14 (F1) the ledger admits exactly one, derived from the digest the guardians
/// signed (`bridge_notes::deposit_r`, `blake3("rand-deposit-r-1" ‖ mu)`), so it is computed here
/// from `attestation` and the caller reads it back off the note for the action's `r` — the one
/// place it is computed, so the note and the action cannot name different ones.
pub fn deposit_note_for(
    w: &Wallet,
    recipient: &ShieldedAddress,
    attestation: &[u8],
    amount: u64,
    asset: u32,
    time: u32,
) -> Result<(Note, Envelope)> {
    let r = bridge_notes::deposit_r(attestation).ok_or_else(|| anyhow!("the attestation has no body to derive the deposit blinding from"))?;
    let note = Note { pk: recipient.pk, from: [0; 8], amount, asset, time, r };
    let envelope =
        seal_note(&w.vk, recipient, &note, &TxKey::random()).map_err(|e| anyhow!("sealing the deposit envelope: {e}"))?;
    Ok((note, envelope))
}

/// The note an RPL mint creates — `rand token create`'s initial supply, or `rand token mint`'s —
/// and the envelope only its recipient can open. [`deposit_note_for`]'s twin, one action over:
/// same reasoning (`time` is chosen here so the commitment is predictable enough to seal against,
/// the blinding is drawn by `Note::new` and read back for the action's `r`), but from RPL's own
/// [`MINT_FROM`] word rather than a deposit's zero — a mint has no sender inside the pool either,
/// but a different constant, so the two note families can never collide at the same leaf.
pub fn mint_note_for(
    w: &Wallet,
    recipient: &ShieldedAddress,
    amount: u64,
    asset: u32,
    time: u32,
) -> Result<(Note, Envelope)> {
    let note = Note::new(recipient.pk, MINT_FROM, amount, asset, time);
    let envelope =
        seal_note(&w.vk, recipient, &note, &TxKey::random()).map_err(|e| anyhow!("sealing the mint envelope: {e}"))?;
    Ok((note, envelope))
}

/// Rows per `rand_getTokens` page when [`resolve_asset`] reads the registry.
const TOKEN_PAGE: u64 = 1000;

/// `--asset`: a registry index as a number (0 is RAND), or a token's id — its `rpl1…` text form or
/// 64 hex — looked up in the **whole** token registry (`rand_getTokens`, paged from index 0).
///
/// Never a per-token lookup: a transfer's asset is private on chain, and asking the node about the
/// one token a wallet is about to send (`rand_getToken <id>`) right before it submits would tell the
/// node's operator exactly what the hidden-asset bundle hides. Reading every row costs the same
/// whichever token is meant, so the reply carries nothing about the choice. A number never reaches
/// the node at all. A node without `rand_getTokens` is told to take the index instead.
pub async fn resolve_asset(rpc: &RpcClient, text: &str) -> Result<u32> {
    if let Ok(index) = text.parse::<u32>() {
        return Ok(index);
    }
    let want = text.trim().to_ascii_lowercase();
    let want_hex = want.strip_prefix("0x").unwrap_or(&want).to_string();
    let mut from = 0u64;
    loop {
        let reply = rpc.call("rand_getTokens", serde_json::json!([from, TOKEN_PAGE])).await.map_err(|e| {
            if crate::is_method_not_found(&e) {
                anyhow!("this node cannot list its token registry (it has no rand_getTokens); pass the token's registry index instead")
            } else {
                e
            }
        })?;
        // A page is a list of rows, or `{ "tokens": [...] }`.
        let rows = reply
            .as_array()
            .or_else(|| reply["tokens"].as_array())
            .context("rand_getTokens did not return a list of tokens")?;
        for row in rows {
            let names = [&row["id_text"], &row["id"], &row["asset_id"]];
            if names.iter().filter_map(|v| v.as_str()).any(|n| {
                let n = n.to_ascii_lowercase();
                n == want || n == want_hex
            }) {
                let index = row["index"].as_u64().context("a rand_getTokens row without an index")?;
                return u32::try_from(index).map_err(|_| anyhow!("rand_getTokens lists index {index}, which is not a u32"));
            }
        }
        let last = rows.iter().filter_map(|r| r["index"].as_u64()).max();
        match last {
            Some(last) if (rows.len() as u64) >= TOKEN_PAGE && last >= from => from = last + 1,
            _ => return Err(anyhow!("no token {text} in this chain's registry")),
        }
    }
}

/// One `rand_getTokens` row, found the way [`resolve_asset`] finds an index: by paging the whole
/// registry and matching `text` against a row's `index`, `id_text` or `id` (hex, `0x` optional,
/// case-insensitive) — never `rand_getToken`, so a wallet reading one token's row after
/// [`resolve_asset`] already read the same listing costs this node nothing more than asking after
/// any other token. `rand token info`'s reader; `rand token mint` and `rand token set-authority`
/// use it too, for the row's `mint_nonce`, id and authority key.
pub async fn find_token_row(rpc: &RpcClient, text: &str) -> Result<Value> {
    let want_index: Option<u64> = text.trim().parse::<u64>().ok();
    let want = text.trim().to_ascii_lowercase();
    let want_hex = want.strip_prefix("0x").unwrap_or(&want).to_string();
    let mut from = 0u64;
    loop {
        let reply = rpc.call("rand_getTokens", serde_json::json!([from, TOKEN_PAGE])).await.map_err(|e| {
            if crate::is_method_not_found(&e) {
                anyhow!("this node cannot list its token registry (it has no rand_getTokens)")
            } else {
                e
            }
        })?;
        let rows = reply
            .as_array()
            .or_else(|| reply["tokens"].as_array())
            .context("rand_getTokens did not return a list of tokens")?;
        for row in rows {
            let idx_match = want_index.is_some() && row["index"].as_u64() == want_index;
            let names = [&row["id_text"], &row["id"], &row["asset_id"]];
            let name_match = names.iter().filter_map(|v| v.as_str()).any(|n| {
                let n = n.to_ascii_lowercase();
                n == want || n == want_hex
            });
            if idx_match || name_match {
                return Ok(row.clone());
            }
        }
        let last = rows.iter().filter_map(|r| r["index"].as_u64()).max();
        match last {
            Some(last) if (rows.len() as u64) >= TOKEN_PAGE && last >= from => from = last + 1,
            _ => return Err(anyhow!("no token {text} in this chain's registry")),
        }
    }
}

/// `rand token create`'s action, plus the two registry facts it was built from: `index` (which
/// `IndexMismatch` on submission names, for the wallet's own "another token took index N first"
/// hint) and `registration_fee` (the default fee's other half, on top of `gas::fee_floor`).
#[derive(Debug)]
pub struct RegisterTokenPlan {
    pub action: Action,
    pub index: u32,
    pub registration_fee: u64,
}

/// Build `rand token create`'s `RegisterToken` action: `check_metadata` (the name/symbol/decimals
/// rules `register_bridged_action` already runs first, T8b review round 1 — a bad name would
/// otherwise burn a ~100 s proof before the chain ever saw a byte of it) before anything else,
/// then reads `next_index` and `registration_fee` from `rand_getTokens` — the index an `initial`
/// mint's envelope is sealed for, and the registry's own fee floor — before anything is proved.
/// `initial` is `(amount, recipient)`; `None` registers a `Key`-authorised token empty. The caller
/// has already refused `authority == MintAuthority::None` without an `initial` (the ledger's own
/// rule, `TokenError::InitialMintRequired`) and a zero `--fixed-supply`/`--initial` amount, so
/// this only checks the metadata, reads the chain and builds the note.
pub async fn build_register_token(
    rpc: &RpcClient,
    w: &Wallet,
    name: &str,
    symbol: &str,
    decimals: u8,
    authority: MintAuthority,
    initial: Option<(u64, ShieldedAddress)>,
    salt: [u8; 32],
) -> Result<RegisterTokenPlan> {
    randprotocol_core::ledger::tokens::check_metadata(name, symbol, decimals).map_err(|e| anyhow!("{e}"))?;
    let reply = rpc.call("rand_getTokens", serde_json::json!([0, 1])).await.map_err(|e| {
        if crate::is_method_not_found(&e) {
            anyhow!("this node cannot list its token registry (it has no rand_getTokens); this chain may not have RPL tokens enabled")
        } else {
            e
        }
    })?;
    if reply["enabled"] == Value::Bool(false) {
        return Err(anyhow!("this chain has no RPL token registry (genesis has no tokens section)"));
    }
    let index = u32::try_from(reply["next_index"].as_u64().context("rand_getTokens has no next_index")?)
        .context("next_index does not fit a u32")?;
    let registration_fee =
        crate::amount_field(&reply["registration_fee"]).context("rand_getTokens has no registration_fee")?;
    let initial = match initial {
        Some((amount, recipient)) => {
            if amount == 0 {
                return Err(anyhow!("an initial mint of zero mints nothing"));
            }
            let time = u32::try_from(rpc.head().await?["height"].as_u64().context("head height")?)
                .context("chain height does not fit a note's time field")?;
            let (note, envelope) = mint_note_for(w, &recipient, amount, index, time)?;
            Some(InitialMint { amount, recipient, r: note.r, time, envelope })
        }
        None => None,
    };
    let action = Action::RegisterToken { name: name.to_string(), symbol: symbol.to_string(), decimals, authority, initial, salt, index };
    Ok(RegisterTokenPlan { action, index, registration_fee })
}

/// The two refusals `build_token_mint` and `build_token_set_authority` share, against an
/// already-fetched `rand_getTokens` row (T8b review round 1 — one whole-listing read serves both
/// the index resolution and this, never two): the token is `Key`-authorised, and `authority` is
/// that very key.
fn check_key_authority(row: &Value, asset: u32, authority: &Keypair, verb: &str) -> Result<()> {
    if row["authority"]["kind"].as_str() != Some("key") {
        return Err(anyhow!("token {asset} is not Key-authorised: there is no authority to {verb}"));
    }
    let key_hex = row["authority"]["key"].as_str().context("a key-authority row without its key")?;
    if key_hex != authority.public_key().to_hex() {
        return Err(anyhow!("this key is not token {asset}'s mint authority"));
    }
    Ok(())
}

/// The token's [`AssetId`] and current `mint_nonce`, off an already-fetched `rand_getTokens` row.
fn row_id_and_nonce(row: &Value, asset: u32) -> Result<(Hash, u64)> {
    let asset_id =
        Hash::from_hex(row["id"].as_str().context("a token row without its id")?).map_err(|e| anyhow!("token {asset}'s id: {e}"))?;
    let nonce = row["mint_nonce"].as_u64().context("a token row without its mint_nonce")?;
    Ok((asset_id, nonce))
}

/// Build `rand token mint`'s `TokenMint` action against `row` — `asset`'s already-fetched
/// `rand_getTokens` row (the caller reads it once, with [`find_token_row`], and reuses it for the
/// index too — T8b review round 1) — refused up front if it is not `Key`-authorised or
/// `authority` is not that key, then the note the chain will compute and `authority`'s Dilithium2
/// signature over [`token_mint_message`], which binds the note's commitment and the envelope's
/// digest.
pub async fn build_token_mint(
    rpc: &RpcClient,
    w: &Wallet,
    chain_id: u64,
    asset: u32,
    row: &Value,
    recipient: &ShieldedAddress,
    amount: u64,
    authority: &Keypair,
) -> Result<Action> {
    if amount == 0 {
        return Err(anyhow!("a mint of zero moves nothing"));
    }
    check_key_authority(row, asset, authority, "mint with")?;
    let (asset_id, nonce) = row_id_and_nonce(row, asset)?;
    let time = u32::try_from(rpc.head().await?["height"].as_u64().context("head height")?)
        .context("chain height does not fit a note's time field")?;
    let (note, envelope) = mint_note_for(w, recipient, amount, asset, time)?;
    let cm = note.commitment();
    let signature = authority.sign(token_mint_message(chain_id, &asset_id, nonce, amount, &cm, &envelope).as_bytes());
    Ok(Action::TokenMint { asset, amount, recipient: recipient.clone(), r: note.r, time, envelope, nonce, signature })
}

/// Build `rand token set-authority`'s `SetAuthority` action against `row` — the same
/// already-fetched row and refusals as [`build_token_mint`] — then `authority`'s signature over
/// [`set_authority_message`] for `new`: a key to hand the token to, or `None` to renounce minting
/// for good.
pub fn build_token_set_authority(chain_id: u64, asset: u32, row: &Value, authority: &Keypair, new: Option<PublicKey>) -> Result<Action> {
    check_key_authority(row, asset, authority, "hand on")?;
    let (asset_id, nonce) = row_id_and_nonce(row, asset)?;
    let signature = authority.sign(set_authority_message(chain_id, &asset_id, nonce, &new).as_bytes());
    Ok(Action::SetAuthority { asset, new, nonce, signature })
}

/// `rand token create`'s submission: one RAND fee bundle, `to = None`, exactly a bridged
/// registration's shape ([`submit_bridge_action`]'s twin, one action over — `RegisterToken`
/// carries no PQ quorum, so it needs none of that path's checks).
#[allow(clippy::too_many_arguments)]
pub async fn submit_register_token(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_register_token_with(rpc, w, store, action, fee, Proving::Real(profile, backend), chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_register_token_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(action, Action::RegisterToken { .. }) {
        return Err(anyhow!("submit_register_token carries a RegisterToken action, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, proving, chain_id, wait).await
}

/// What `rand token create` reports: the submission, the index it registered at, the asset id it
/// registered under, and the fee it actually paid (the caller's `fee` override, or the default
/// [`build_register_token`]'s reads computed).
#[derive(Debug)]
pub struct CreateTokenResult {
    pub submission: Submission,
    pub index: u32,
    pub id: Hash,
    pub fee: u64,
}

/// `rand token create`, past its flags: build the action ([`build_register_token`], which checks
/// the metadata before any network read), write the `Key` branch's fresh authority key to
/// `pending_authority_key_path`, submit, then resolve the pending file (T8b review round 1) —
/// promoted to its final path on acceptance, discarded on a refusal the node itself made, left
/// exactly where it is on anything else, whose outcome this wallet cannot know. `authority` is
/// `(the fresh keypair, the file it will end up at)` for the `Key` branch, `None` for fixed
/// supply; `fee` is `None` for the default (`gas::fee_floor` plus the registry's
/// `registration_fee`).
#[allow(clippy::too_many_arguments)]
pub async fn create_token(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    name: &str,
    symbol: &str,
    decimals: u8,
    authority: Option<(&Keypair, &Path)>,
    initial: Option<(u64, ShieldedAddress)>,
    salt: [u8; 32],
    fee: Option<u64>,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<CreateTokenResult> {
    create_token_with(rpc, w, store, name, symbol, decimals, authority, initial, salt, fee, Proving::Real(profile, backend), chain_id, wait)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn create_token_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    name: &str,
    symbol: &str,
    decimals: u8,
    authority: Option<(&Keypair, &Path)>,
    initial: Option<(u64, ShieldedAddress)>,
    salt: [u8; 32],
    fee: Option<u64>,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<CreateTokenResult> {
    let mint_authority = match authority {
        Some((kp, _)) => MintAuthority::Key(kp.public_key().clone()),
        None => MintAuthority::None,
    };
    let plan = build_register_token(rpc, w, name, symbol, decimals, mint_authority, initial, salt).await?;
    let index = plan.index;
    let id = match &plan.action {
        Action::RegisterToken { name, symbol, decimals, authority, initial, salt, .. } => {
            randprotocol_core::ledger::tokens::native_asset_id(name, symbol, *decimals, authority, initial, salt)
        }
        _ => unreachable!("build_register_token always returns a RegisterToken action"),
    };
    let fee = fee.unwrap_or_else(|| gas::fee_floor(&plan.action).saturating_add(plan.registration_fee));

    // The only secret this command ever generates goes to disk before the one call that can
    // refuse the registration is even attempted — see `pending_authority_key_path`'s doc.
    let pending = match authority {
        Some((kp, path)) => {
            let pending = pending_authority_key_path(path);
            write_authority_key(kp, &pending)?;
            Some((pending, path))
        }
        None => None,
    };
    let result = submit_register_token_with(rpc, w, store, plan.action, fee, proving, chain_id, wait).await;
    match (&result, &pending) {
        (Ok(_), Some((pending_path, path))) => {
            if let Err(e) = promote_pending_authority_key(pending_path, path) {
                eprintln!("warning: the registration committed, but the authority key could not be promoted: {e}");
            }
        }
        (Err(e), Some((pending_path, _))) if e.downcast_ref::<crate::SubmitRefused>().is_some() => {
            // `rand_sendTransaction` *itself* answered with a JSON-RPC error, synchronously:
            // nothing was admitted, so nothing was ever registered under this key. The stage,
            // not the error type, is what decides this (node I1) — `RpcError` is what *every*
            // JSON-RPC error reply becomes, the wait's `rand_getTransactionStatus` and the
            // post-commit rescan's six methods included, and a `-32603` on a node restart or a
            // `-32000` on backpressure after a *committed* registration would otherwise delete
            // the only copy of the token's authority key.
            if let Err(re) = discard_pending_authority_key(pending_path) {
                eprintln!("warning: discarding the unused pending authority key {}: {re}", pending_path.display());
            }
        }
        // Anything else — a transport failure, a decode error, and every failure after the send
        // — leaves the submission's fate unknown, so the pending file stays exactly where it is
        // and the caller is told where to find it.
        (Err(e), Some((pending_path, path))) => {
            eprintln!(
                "warning: the registration's fate is unknown ({e}); the authority key is kept at {} \
                 — check whether the token registered, then rename it to {} or delete it",
                pending_path.display(),
                path.display()
            );
        }
        _ => {}
    }
    result.map(|submission| CreateTokenResult { submission, index, id, fee })
}

/// `rand token mint`'s submission: one RAND fee bundle, `to = None`, the mint's own Dilithium2
/// signature already inside the action.
#[allow(clippy::too_many_arguments)]
pub async fn submit_token_mint(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_token_mint_with(rpc, w, store, action, fee, Proving::Real(profile, backend), chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_token_mint_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(action, Action::TokenMint { .. }) {
        return Err(anyhow!("submit_token_mint carries a TokenMint action, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, proving, chain_id, wait).await
}

/// `rand token set-authority`'s submission: one RAND fee bundle, `to = None`.
#[allow(clippy::too_many_arguments)]
pub async fn submit_token_set_authority(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_token_set_authority_with(rpc, w, store, action, fee, Proving::Real(profile, backend), chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_token_set_authority_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(action, Action::SetAuthority { .. }) {
        return Err(anyhow!("submit_token_set_authority carries a SetAuthority action, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, proving, chain_id, wait).await
}

/// The PQ co-signature file `rand bridge-mint --pq` and `rand bridge-rotate --pq` read (bridge
/// hardening B3, `spec/PQ-COSIGNATURE.md` §6): a JSON array
/// `[{"index": 0, "signature": "<4840 hex>"}, …]`, as the relayer assembles it from the guardians'
/// `pq_signature` fields. Parsed as written — the order and lengths are the chain's to judge, and
/// [`check_pq_cosignatures`] judges them first, before any proving.
pub fn parse_pq_signatures(text: &str) -> Result<Vec<randprotocol_core::bridge::PqSignature>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Row {
        index: u8,
        signature: String,
    }
    let rows: Vec<Row> = serde_json::from_str(text)
        .context(r#"expected a JSON array of {"index": <0-255>, "signature": "<hex>"}"#)?;
    rows.into_iter()
        .enumerate()
        .map(|(i, r)| {
            let sig = r.signature.trim();
            let bytes = hex::decode(sig.strip_prefix("0x").unwrap_or(sig))
                .with_context(|| format!("PQ co-signature {i} (index {}) is not hex", r.index))?;
            Ok(randprotocol_core::bridge::PqSignature { index: r.index, signature: bytes })
        })
        .collect()
}

/// The chain's own five co-signature rules (`randprotocol_core::bridge::check_pq_quorum`), run
/// here against the PQ guardian set the node serves (`rand_getBridgeState.pq_guardians`) and this
/// chain's id, before a bundle is proved: a list the ledger would refuse is an error in seconds
/// rather than a refused transaction after a minute and a half of proving. The chain checks again
/// at admission; this only saves the proof.
pub fn check_pq_cosignatures(
    bridge_state: &Value,
    chain_id: u64,
    attestation: &[u8],
    sigs: &[randprotocol_core::bridge::PqSignature],
) -> Result<()> {
    if bridge_state["enabled"] != Value::Bool(true) {
        return Err(anyhow!("this chain has no bridge"));
    }
    let keys = bridge_state["pq_guardians"]
        .as_array()
        .ok_or_else(|| anyhow!("the node serves no pq_guardians (a node older than the PQ co-signature?)"))?
        .iter()
        .map(|k| {
            randprotocol_core::PublicKey::from_hex(k.as_str().unwrap_or_default())
                .map_err(|e| anyhow!("the node's pq_guardians entry is not a Dilithium2 key: {e}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let body = Attestation::body_bytes(attestation).map_err(|e| anyhow!("not a bridge attestation: {e:?}"))?;
    let mu = randprotocol_core::bridge::digest(body);
    randprotocol_core::bridge::check_pq_quorum(sigs, &keys, chain_id, &mu)
        .map_err(|e| anyhow!("the PQ co-signatures would be refused: {e}"))
}

/// A guardian-set rotation (payload 2) `rand bridge-rotate` submits: the index it rotates to.
/// Anything else — a transfer, bytes that do not decode — is an error, so the command cannot
/// spend a fee bundle on an attestation that is not a rotation.
pub fn attested_rotation(attestation: &[u8]) -> Result<u32> {
    let att = Attestation::decode(attestation).map_err(|e| anyhow!("not a bridge attestation: {e:?}"))?;
    match Payload::decode(&att.body.payload).map_err(|e| anyhow!("attestation payload: {e:?}"))? {
        Payload::GuardianSetUpgrade(g) => Ok(g.new_index),
        Payload::Transfer(_) => Err(anyhow!("this attestation is a transfer; submit it with `rand bridge-mint`")),
    }
}

/// A plain shielded RAND transfer: [`send_asset`] of asset 0.
#[allow(clippy::too_many_arguments)]
pub async fn send(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    amount: u64,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    send_asset(rpc, w, store, to, 0, amount, fee, profile, backend, chain_id, wait).await
}

/// A shielded transfer of any asset — RAND (`asset` 0) or a token by its registry index — as a
/// plain `Action::None` bundle. On chain it is indistinguishable from any other transfer: the
/// asset is a private word of the witness, and the fee is RAND whatever moves (spec §3–§4). A
/// token transfer therefore needs RAND for the fee, and is refused before proving without it.
#[allow(clippy::too_many_arguments)]
pub async fn send_asset(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    asset: u32,
    amount: u64,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    send_asset_with(rpc, w, store, to, asset, amount, fee, Proving::Real(profile, backend), chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn send_asset_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    asset: u32,
    amount: u64,
    fee: u64,
    proving: Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if amount == 0 {
        return Err(anyhow!("a transfer of zero moves nothing"));
    }
    let spend = Spend { asset, to: Some((to, amount)), fee, burn_a: 0, burn_r: 0 };
    submit_spend(rpc, w, store, spend, Action::None, Burn::None, proving, chain_id, wait).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_zkvm::notes::SpendKey;

    fn env() -> Envelope {
        Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] }
    }

    fn owned(index: u64, amount: u64, spent: bool) -> OwnedNote {
        owned_asset(index, amount, spent, 0)
    }

    fn owned_asset(index: u64, amount: u64, spent: bool, asset: u32) -> OwnedNote {
        let note = Note::new([1; 8], [2; 8], amount, asset, 3);
        OwnedNote { index, cm: note.commitment(), nf: [index as u32; 8], note, spent, pending: None, height: index }
    }

    /// The test token these attestations are about: chain 2's `0xaa…`.
    const TOKEN: [u8; 32] = [0xaa; 32];
    const TOKEN_CHAIN: u16 = 2;

    /// An inbound transfer of `amount` of [`TOKEN`] to the recipient hash `to`. Unsigned: nothing
    /// in the wallet verifies a quorum — that is the chain's job — and everything it *does* read
    /// comes out of the body.
    fn transfer_attestation(amount: u128, to: [u8; 32]) -> Vec<u8> {
        use randprotocol_core::bridge::{Body, Transfer, CHAIN_RAND};
        let body = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: TOKEN_CHAIN,
            emitter_address: [2; 32],
            sequence: 0,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: TOKEN,
                token_chain: TOKEN_CHAIN,
                to,
                to_chain: CHAIN_RAND,
                fee: Transfer::u256_from_u128(0),
            })
            .encode(),
        };
        Attestation { guardian_set_index: 0, signatures: Vec::new(), body }.encode()
    }

    /// A guardian-set rotation: a real attestation that deposits nothing.
    fn rotation_attestation() -> Vec<u8> {
        use randprotocol_core::bridge::{guardian_address, Body, GuardianSetUpgrade, CHAIN_RAND, GOVERNANCE_EMITTER};
        let body = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: CHAIN_RAND,
            emitter_address: GOVERNANCE_EMITTER,
            sequence: 9,
            consistency_level: 0,
            payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade {
                new_index: 1,
                keys: vec![guardian_address(&[9; 32])],
            })
            .encode(),
        };
        Attestation { guardian_set_index: 0, signatures: Vec::new(), body }.encode()
    }

    /// `--pq`'s file: the relayer's array, parsed as written; not-hex and a wrong shape are
    /// errors, and the chain's five rules then run locally against the node's PQ set and chain id
    /// — a short list, a foreign chain's list and an honest one each get the chain's verdict.
    #[test]
    fn a_pq_file_parses_and_is_checked_against_the_nodes_pq_set() {
        use randprotocol_core::bridge::{pq_cosign, PqSignature};
        let sig = hex::encode([7u8; 4]);
        let parsed = parse_pq_signatures(&format!(r#"[{{"index":0,"signature":"{sig}"}},{{"index":3,"signature":"0x{sig}"}}]"#)).unwrap();
        assert_eq!(
            parsed,
            vec![PqSignature { index: 0, signature: vec![7; 4] }, PqSignature { index: 3, signature: vec![7; 4] }]
        );
        assert!(parse_pq_signatures(r#"[{"index":0,"signature":"zz"}]"#).is_err());
        assert!(parse_pq_signatures(r#"[{"index":300,"signature":"00"}]"#).is_err());
        assert!(parse_pq_signatures(r#"{"index":0}"#).is_err());

        let keys: Vec<randprotocol_core::Keypair> =
            (0..6u8).map(|i| randprotocol_core::Keypair::from_seed([0x70 + i; 32]).unwrap()).collect();
        let state = serde_json::json!({
            "enabled": true,
            "pq_guardians": keys.iter().map(|k| k.public_key().to_hex()).collect::<Vec<_>>(),
        });
        let att = transfer_attestation(1_000, [4; 32]);
        let mu = randprotocol_core::bridge::digest(Attestation::body_bytes(&att).unwrap());
        let quorum = |chain: u64, n: usize| -> Vec<PqSignature> {
            keys.iter().take(n).enumerate().map(|(i, k)| pq_cosign(k, i as u8, chain, &mu)).collect()
        };
        check_pq_cosignatures(&state, 13, &att, &quorum(13, 5)).unwrap();
        // Round trip through the file format the relayer writes.
        let file = serde_json::to_string(
            &quorum(13, 5).iter().map(|s| serde_json::json!({"index": s.index, "signature": hex::encode(&s.signature)})).collect::<Vec<_>>(),
        )
        .unwrap();
        check_pq_cosignatures(&state, 13, &att, &parse_pq_signatures(&file).unwrap()).unwrap();
        let short = check_pq_cosignatures(&state, 13, &att, &quorum(13, 4)).unwrap_err().to_string();
        assert!(short.contains("need 5 of 6"), "{short}");
        let foreign = check_pq_cosignatures(&state, 13, &att, &quorum(14, 5)).unwrap_err().to_string();
        assert!(foreign.contains("does not verify"), "{foreign}");
        assert!(check_pq_cosignatures(&serde_json::json!({"enabled": false}), 13, &att, &quorum(13, 5)).is_err());
        assert!(check_pq_cosignatures(&serde_json::json!({"enabled": true}), 13, &att, &quorum(13, 5)).is_err());
    }

    /// `rand bridge-rotate` takes a rotation and nothing else.
    #[test]
    fn a_rotation_is_told_apart_from_a_transfer() {
        assert_eq!(attested_rotation(&rotation_attestation()).unwrap(), 1);
        assert!(attested_rotation(&transfer_attestation(1, [4; 32])).unwrap_err().to_string().contains("bridge-mint"));
        assert!(attested_rotation(&[1, 2, 3]).is_err());
    }

    #[test]
    fn key_file_v2_roundtrips_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.key.json");
        let w = Wallet::generate();
        w.save_new(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["version"], 2);
        assert_eq!(v["spend_key"].as_str().unwrap().len(), 64);
        let back = Wallet::load(&path).unwrap();
        assert_eq!(back.sk, w.sk);
        // Overwriting a key file destroys the only copy of the spend authority.
        let err = Wallet::generate().save_new(&path).unwrap_err().to_string();
        assert!(err.contains("refusing to overwrite"), "{err}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    /// A fresh authority key file is `{seed, address, public_key}` — `rand-node keygen`'s own
    /// shape — 0600 from creation, and refuses to overwrite; [`load_authority_key`] reads back a
    /// keypair that signs the way the one that wrote it would have.
    #[test]
    fn a_token_authority_key_file_roundtrips_rand_node_keygens_shape_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.key.json");
        let kp = Keypair::generate();
        write_authority_key(&kp, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["seed"].as_str().unwrap(), hex::encode(kp.seed()));
        assert_eq!(v["address"].as_str().unwrap(), kp.address().to_base58());
        assert_eq!(v["public_key"].as_str().unwrap(), kp.public_key().to_hex());
        let back = load_authority_key(&path).unwrap();
        assert_eq!(back.public_key(), kp.public_key());
        let msg = b"a message only the loaded key should be able to sign for";
        assert!(kp.public_key().verify(msg, &back.sign(msg)));

        let err = write_authority_key(&Keypair::generate(), &path).unwrap_err().to_string();
        assert!(err.contains("refusing to overwrite"), "{err}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn address_is_derived_from_the_spend_key() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.json");
        let b = dir.path().join("b.json");
        let w = Wallet::generate();
        w.save_new(&a).unwrap();
        Wallet::generate().save_new(&b).unwrap();
        let one = Wallet::load(&a).unwrap();
        let two = Wallet::load(&a).unwrap();
        assert_eq!(one.address, two.address);
        assert_eq!(one.address, w.address);
        assert_eq!(one.address.pk, one.vk.pk());
        assert_ne!(Wallet::load(&b).unwrap().address, one.address);
    }

    #[test]
    fn note_store_balance_ignores_spent_and_zero_notes() {
        let store = NoteStore {
            scanned_index: 4,
            scanned_height: 2,
            scanned_attest_height: 3,
            notes: vec![owned(0, 5, false), owned(1, 3, true), owned(2, 0, false), owned(3, 2, false)],
            sent: vec![],
        };
        assert_eq!(store.balance(), 7);
        let spendable: Vec<u64> = store.spendable().iter().map(|n| n.note.amount).collect();
        assert_eq!(spendable, vec![5, 2]);
    }

    /// A burn costs a bundle proof, so everything only the chain knows is checked before any
    /// of that work: the chain has a bridge, the registry holds the asset being burned, the coin
    /// named backs *that* asset, and that coin is holding at least what is being redeemed.
    #[test]
    fn a_burn_checks_the_bridge_the_registry_and_the_backing_before_proving() {
        // One zUSD (index 1) backed by USDT on chain 2 and USDC on chain 5, plus a second token
        // beside it — the shape `rand_getAssets` serves: one row per coin, `index` shared.
        let usdt = [0xd7u8; 32];
        let usdc = [0xdcu8; 32];
        let other = [0xeeu8; 32];
        // Eight decimals — the wire's own — so the release unit is 1 and cannot be what refuses
        // anything here; `a_burn_must_be_a_whole_number_of_the_coins_release_unit` is that rule.
        let registry = serde_json::json!([
            asset_row(1, 2, usdt, 8, 1_000),
            asset_row(1, 5, usdc, 8, 400),
            asset_row(2, 2, other, 8, 50),
        ]);
        let bridged = serde_json::json!({ "enabled": true, "assets": registry });
        burn_is_possible(&bridged, 1, 2, &usdt, 1_000, 0).expect("exactly what that coin holds");
        burn_is_possible(&bridged, 1, 5, &usdc, 1, 0).expect("the other coin of the same token");
        burn_is_possible(&bridged, 2, 2, &other, 50, 0).expect("and the token beside it");

        // Node I3: the same rows from a node older than chain 14, where `locked` is a JSON
        // number. `amount_field` reads either, so the pre-check is not "an asset row without a
        // locked amount" against every node on either side of the change.
        let old_node = serde_json::json!({
            "enabled": true,
            "assets": [asset_row_numeric(1, 2, usdt, 8, 1_000), asset_row_numeric(1, 5, usdc, 8, 400)],
        });
        burn_is_possible(&old_node, 1, 2, &usdt, 1_000, 0).expect("a numeric locked reads the same");
        assert!(burn_is_possible(&old_node, 1, 5, &usdc, 700, 0).unwrap_err().to_string().contains("only 400 is locked"));

        // More of one coin than its own contract is holding, though the token's supply (1 400
        // across its two coins) would cover it. This is the line a user reads.
        let e = burn_is_possible(&bridged, 1, 5, &usdc, 700, 0).unwrap_err().to_string();
        assert_eq!(
            e,
            "only 400 is locked in that coin on chain 5; choose another backing or a smaller amount"
        );
        // A coin that backs nothing, and one that backs the *other* token: both name the
        // backings the asset does have.
        let e = burn_is_possible(&bridged, 1, 3, &usdt, 1, 0).unwrap_err().to_string();
        assert!(e.contains("does not back asset 1") && e.contains("chain 5 token"), "{e}");
        let e = burn_is_possible(&bridged, 1, 2, &other, 1, 0).unwrap_err().to_string();
        assert!(e.contains("does not back asset 1"), "{e}");

        // An index the registry does not hold: no note of it was ever deposited, so the ledger
        // would refuse the transaction after the proof.
        let e = burn_is_possible(&bridged, 3, 2, &usdt, 1, 0).unwrap_err().to_string();
        assert!(e.contains("asset 3 is not in this chain's registry") && e.contains("registered: 1, 1, 2"), "{e}");

        // A chain with no bridge at all, which is what `rand_getBridgeState` says with one field.
        let e = burn_is_possible(&serde_json::json!({ "enabled": false }), 1, 2, &usdt, 1, 0).unwrap_err().to_string();
        assert!(e.contains("no bridge"), "{e}");
        // A bridged chain whose registry is still empty names that rather than listing nothing.
        let empty = serde_json::json!({ "enabled": true, "assets": [] });
        let e = burn_is_possible(&empty, 1, 2, &usdt, 1, 0).unwrap_err().to_string();
        assert!(e.contains("registry is empty"), "{e}");
        // And a reply with no registry at all is an error, not an empty registry.
        assert!(burn_is_possible(&serde_json::json!({ "enabled": true }), 1, 2, &usdt, 1, 0).is_err());
        // A row from a node that predates per-backing accounting has neither `decimals` nor
        // `locked` to check against, which is an error rather than a burn proved against numbers
        // nobody sent.
        let old = serde_json::json!({
            "enabled": true,
            "assets": [{ "index": 1, "chain": 2, "token": hex::encode(usdt), "asset_id": "00" }],
        });
        assert!(burn_is_possible(&old, 1, 2, &usdt, 1, 0).is_err());
        let no_locked = serde_json::json!({
            "enabled": true,
            "assets": [asset_row_without(1, 2, usdt, "locked")],
        });
        assert!(burn_is_possible(&no_locked, 1, 2, &usdt, 1, 0).is_err(), "no locked amount to bound the burn");
        let no_decimals = serde_json::json!({
            "enabled": true,
            "assets": [asset_row_without(1, 2, usdt, "decimals")],
        });
        assert!(burn_is_possible(&no_decimals, 1, 2, &usdt, 1, 0).is_err(), "no decimals to derive the unit from");
    }

    /// One `rand_getAssets` row, as the node serves it: the note's `asset` word, the coin's wire
    /// identity, that coin's **source** decimals and what its contract is holding.
    /// `locked` as the node renders it since chain 14: a decimal **string** (node I3). Every
    /// reader here goes through `crate::amount_field`, which takes either encoding, and
    /// [`asset_row_numeric`] is the same row as an older node sends it.
    fn asset_row(index: u32, chain: u16, token: [u8; 32], decimals: u8, locked: u64) -> serde_json::Value {
        serde_json::json!({
            "index": index, "chain": chain, "token": hex::encode(token),
            "asset_id": hex::encode([index as u8; 32]), "decimals": decimals, "locked": locked.to_string(),
        })
    }

    /// Node M4: `rand bridge-mint` hears the two ledger rules that can refuse a perfect
    /// attestation — the B1 pause and the backing's remaining daily cap — before it buys ~100 s
    /// of proving, off the `rand_getBridgeState` reply it already fetches.
    #[test]
    fn a_mint_checks_the_pause_and_the_daily_cap_before_proving() {
        let token = [0xd7u8; 32];
        let state = |paused: bool, cap: &str, minted: &str| {
            serde_json::json!({
                "enabled": true, "mint_paused": paused,
                "assets": [{
                    "index": 1, "chain": 2, "token": hex::encode(token),
                    "asset_id": "aa", "decimals": 8,
                    "locked": "1000", "mint_cap_per_day": cap, "minted_today": minted, "mint_day": 0,
                }],
            })
        };
        let cap = 100_000u64 * 100_000_000;
        let open = state(false, &cap.to_string(), "0");
        mint_is_possible(&open, 2, &token, cap).expect("exactly the day's cap");
        let e = mint_is_possible(&open, 2, &token, cap + 1).unwrap_err().to_string();
        assert!(e.contains("daily mint cap") && e.contains("UTC day"), "{e}");

        // Part of the day already spent: the headroom is what is left, not the whole cap.
        let partly = state(false, &cap.to_string(), "400");
        mint_is_possible(&partly, 2, &token, cap - 400).expect("the headroom");
        let e = mint_is_possible(&partly, 2, &token, cap - 399).unwrap_err().to_string();
        assert!(e.contains("400 has been minted against it today"), "{e}");

        // The pause is read first and is about the whole bridge, not this coin.
        let e = mint_is_possible(&state(true, &cap.to_string(), "0"), 2, &token, 1).unwrap_err().to_string();
        assert!(e.contains("paused") && e.contains("quorum"), "{e}");

        // A coin with no row is `deposit_index`'s error to report, not this one's; and a node
        // predating the cap serves neither field, which is nothing to pre-check.
        mint_is_possible(&open, 3, &token, u64::MAX).expect("an unlisted coin is not this check's refusal");
        let mut old_node = open.clone();
        let row = &mut old_node["assets"][0];
        row.as_object_mut().unwrap().remove("mint_cap_per_day");
        row.as_object_mut().unwrap().remove("minted_today");
        mint_is_possible(&old_node, 2, &token, u64::MAX).expect("a node predating B1 has no cap to check");
        // And the figures are read whichever way the node encodes them (node I3).
        let numeric = state(false, &cap.to_string(), "400");
        let mut numeric = numeric;
        numeric["assets"][0]["mint_cap_per_day"] = serde_json::json!(cap);
        numeric["assets"][0]["minted_today"] = serde_json::json!(400);
        assert!(mint_is_possible(&numeric, 2, &token, cap - 399).is_err(), "a numeric cap reads the same");
    }

    /// [`asset_row`] with `locked` as a JSON number — a node older than chain 14.
    fn asset_row_numeric(index: u32, chain: u16, token: [u8; 32], decimals: u8, locked: u64) -> serde_json::Value {
        let mut row = asset_row(index, chain, token, decimals, locked);
        row["locked"] = serde_json::json!(locked);
        row
    }

    /// [`asset_row`] with one field taken out — an older node's reply, or a corrupted one.
    fn asset_row_without(index: u32, chain: u16, token: [u8; 32], field: &str) -> serde_json::Value {
        let mut row = asset_row(index, chain, token, 6, 1_000);
        row.as_object_mut().unwrap().remove(field);
        row
    }

    /// A source coin with fewer decimals than the eight-decimal attestation wire releases in
    /// whole units of `10^(8-d)`, so an amount — or a relayer fee, which the far side carves out
    /// of it in native units — that is not a multiple of one would strand the remainder in
    /// custody forever, or below one unit release nothing at all. The chain refuses it
    /// (`TokenError::NotReleasable`); the wallet says so before buying a bundle proof.
    #[test]
    fn a_burn_must_be_a_whole_number_of_the_coins_release_unit() {
        // zUSD's real chain-2 (6 decimals) and chain-3 (18) USDT backings, the two sides of the
        // rule: a unit of 100 on Ethereum and a unit of 1 on BSC.
        let eth_usdt = [0xd7u8; 32];
        let bsc_usdt = [0xb5u8; 32];
        let bridged = serde_json::json!({
            "enabled": true,
            "assets": [asset_row(1, 2, eth_usdt, 6, 1_000_000), asset_row(1, 3, bsc_usdt, 18, 1_000_000)],
        });

        let e = burn_is_possible(&bridged, 1, 2, &eth_usdt, 199, 0).unwrap_err().to_string();
        assert_eq!(
            e,
            format!(
                "{} on chain 2 has 6 decimals: the amount and the relayer fee must be multiples of 100",
                hex::encode(eth_usdt)
            )
        );
        burn_is_possible(&bridged, 1, 2, &eth_usdt, 200, 0).expect("exactly two whole units");

        // The fee is released in native units too, so it is held to the same unit even when the
        // amount itself is a clean multiple.
        let e = burn_is_possible(&bridged, 1, 2, &eth_usdt, 1_000, 150).unwrap_err().to_string();
        assert!(e.contains("multiples of 100"), "{e}");
        burn_is_possible(&bridged, 1, 2, &eth_usdt, 1_000, 100).expect("a whole-unit fee");

        // At or above the wire's eight decimals the unit is 1 and nothing is ever refused for it.
        burn_is_possible(&bridged, 1, 3, &bsc_usdt, 199, 7).expect("every amount is a whole unit");

        // The unit is checked before the locked amount, as the chain checks it
        // (`TokenRegistry::check_release`): the cheap, state-independent half first.
        let e = burn_is_possible(&bridged, 1, 2, &eth_usdt, 9_999_999, 0).unwrap_err().to_string();
        assert!(e.contains("multiples of 100"), "the unit, not the locked amount: {e}");
    }

    /// One submission per shape of [`Burn`], as `rand` prints it. This is the line a user reads
    /// after paying for a proof, and the burn is the part of it that used to depend on the reader
    /// knowing which unit a `u64` was in: a bond's stake is RAND and is named as such; a bridge
    /// burn's is the `out` figure already printed, in asset units, so the line says it once; every
    /// other action burns nothing and says nothing.
    #[test]
    fn the_summary_line_names_a_burn_in_its_own_units() {
        let submission = |burn: Burn, asset: u32, amount: u64, change: u64| Submission {
            hash: Hash([0xab; 32]),
            amount,
            change,
            fee: gas::BUNDLE_BASE,
            burn,
            time: 42,
            asset,
            rand_change: if asset == 0 { 0 } else { 5 * randprotocol_core::UNITS_PER_RAND },
            tier: 14,
            proof_bytes: 1 << 20,
            proving: Duration::from_secs(98),
        };

        // A transfer: nothing burned, nothing said about burning.
        let unit = randprotocol_core::UNITS_PER_RAND;
        let transfer = submission(Burn::None, 0, unit, 3 * unit);
        assert_eq!(
            transfer.summary("transfer"),
            format!(
                "submitted transfer {}\n  1 RAND out, 3 RAND change, fee 0.001 RAND, anchored at height 42",
                Hash([0xab; 32])
            )
        );

        // A bond: the stake left the pool, in RAND, and the payment output is zero because a
        // bond pays nobody a note.
        let bond = submission(Burn::Rand(1_000 * unit), 0, 0, 2 * unit);
        assert!(
            bond.summary("bond").ends_with(
                "0 RAND out, 1000 RAND burned, 2 RAND change, fee 0.001 RAND, anchored at height 42"
            ),
            "{}",
            bond.summary("bond")
        );

        // A bridge burn: asset units throughout, and the burn is the `out` figure — said once. The
        // RAND that came back from the fee slots is named after the fee it paid.
        let burn = submission(Burn::Asset { index: 3, amount: 2_000 }, 3, 2_000, 3_000);
        assert!(
            burn.summary("bridge burn").ends_with(
                "2000 of asset 3 out, 3000 of asset 3 change, fee 0.001 RAND, 5 RAND change, anchored at height 42"
            ),
            "{}",
            burn.summary("bridge burn")
        );
        assert!(!burn.summary("bridge burn").contains("burned"), "an asset burn is not printed twice");
    }

    /// `Burn` answers the two questions the old `u64` beside an `asset` index could not: how many
    /// units the bundle's `burn` word carries, and whether a zero is a burn at all.
    #[test]
    fn a_burn_of_nothing_is_none() {
        assert_eq!(Burn::rand(0), Burn::None);
        assert_eq!(Burn::rand(7), Burn::Rand(7));
        assert_eq!(Burn::default(), Burn::None);
        assert_eq!(Burn::None.units(), 0);
        assert_eq!(Burn::Rand(7).units(), 7);
        assert_eq!(Burn::Asset { index: 2, amount: 9 }.units(), 9);
    }

    /// A bond pays its stake by *burning* it, not by sending it: the bundle's only output is the
    /// change, and the notes it spends still have to cover the whole of `out + fee + burn`.
    #[test]
    fn bond_bundle_balances_with_burn() {
        let units = randprotocol_core::UNITS_PER_RAND;
        let notes = [owned(0, 40 * units, false), owned(1, 10 * units, false)];
        let spendable: Vec<&OwnedNote> = notes.iter().collect();
        let stake = 45 * units;
        let fee = gas::BUNDLE_BASE;

        // A bond sends nothing to anybody, so the payment output is zero and the burn is the need.
        let need = bundle_need(0, fee, stake).unwrap();
        assert_eq!(need, stake + fee);
        let chosen = select_inputs(&spendable, need).unwrap();
        assert_eq!(chosen.len(), 2, "neither note alone covers the stake and the fee");
        let total: u64 = chosen.iter().map(|n| n.note.amount).sum();
        let change = total - need;
        assert_eq!(change, 50 * units - stake - fee);
        // The guest's balance equation, which is what the burn has to close: in = out + fee + burn,
        // with the payment output zero.
        assert_eq!(total, change + fee + stake);

        // A transfer of the same size is the same arithmetic with the burn on the other side —
        // the value goes to a note instead of out of the pool, so the change is identical.
        assert_eq!(bundle_need(stake, fee, 0).unwrap(), need);

        // Nothing is bonded that the wallet cannot cover, and the fee is part of what it covers.
        assert_eq!(
            select_inputs(&spendable, bundle_need(0, fee, 50 * units).unwrap()).unwrap_err(),
            SelectError::Insufficient { have: 50 * units }
        );
        assert!(bundle_need(0, fee, u64::MAX).unwrap_err().to_string().contains("overflows"));
    }

    #[test]
    fn select_inputs_takes_the_largest_two_or_fails_clearly() {
        let notes = [owned(0, 5, false), owned(1, 3, false), owned(2, 2, false)];
        let spendable: Vec<&OwnedNote> = notes.iter().collect();
        let amounts = |need| select_inputs(&spendable, need).map(|v| v.iter().map(|n| n.note.amount).collect::<Vec<_>>());
        assert_eq!(amounts(7).unwrap(), vec![5, 3]);
        assert_eq!(amounts(4).unwrap(), vec![5]);
        assert_eq!(amounts(9).unwrap_err(), SelectError::NeedsMoreThanTwo { largest_two: 8 });
        assert_eq!(amounts(11).unwrap_err(), SelectError::Insufficient { have: 10 });
    }

    /// Seal `note` to `to`, as whichever party `from` is — the wire an attacker has too, since
    /// a shielded address publishes the encapsulation key envelopes are sealed to.
    fn sealed(from: &Wallet, to: &Wallet, note: &Note) -> randprotocol_core::notes::Envelope {
        randprotocol_zkvm::address::seal_note(&from.vk, &to.address, note, &TxKey::random()).unwrap()
    }

    #[test]
    fn scan_only_records_notes_this_wallet_actually_owns() {
        let me = Wallet::from_spend_key(SpendKey([11; 8]));
        let stranger = Wallet::from_spend_key(SpendKey([12; 8]));

        // The genuine case: a note owned by me, sealed to me.
        let mine = Note::new(me.vk.pk(), stranger.vk.pk(), 5, 0, 1);
        assert_eq!(classify(&me, mine.commitment(), &sealed(&stranger, &me, &mine)), Found::Received(mine));

        // Sealed to my encapsulation key, which anyone can do, but owned by someone else. The
        // envelope opens and the commitment matches; the note is still not mine, and counting it
        // would put unspendable value in `balance()`.
        let theirs = Note::new(stranger.vk.pk(), stranger.vk.pk(), 1_000, 0, 1);
        let Found::Skipped(why) = classify(&me, theirs.commitment(), &sealed(&stranger, &me, &theirs)) else {
            panic!("a note owned by another key must not be recorded");
        };
        assert!(why.contains("owned by another key"), "{why}");

        // A bridged asset is recorded like any other note (S3): the `asset` word is the registry's
        // index for a token, and skipping it would make a bridge deposit invisible to its owner.
        let bridged = Note::new(me.vk.pk(), stranger.vk.pk(), 7, 3, 1);
        assert_eq!(classify(&me, bridged.commitment(), &sealed(&stranger, &me, &bridged)), Found::Received(bridged));

        // A note I created for someone else is history, reached through `ovk`, not the KEM.
        let paid = Note::new(stranger.vk.pk(), me.vk.pk(), 3, 0, 1);
        assert_eq!(classify(&me, paid.commitment(), &sealed(&me, &stranger, &paid)), Found::Sent(paid));

        // Someone else's transaction between two strangers opens with no key of mine.
        let elsewhere = Note::new(stranger.vk.pk(), stranger.vk.pk(), 9, 0, 1);
        assert!(matches!(classify(&me, elsewhere.commitment(), &sealed(&stranger, &stranger, &elsewhere)), Found::Skipped(_)));
    }

    /// A bridged holding is a note whose `asset` word is the registry's index for it, and a bundle
    /// balances one asset — so the two never appear in one sum, one balance or one selection.
    #[test]
    fn assets_are_counted_and_selected_apart_from_rand() {
        let store = NoteStore {
            notes: vec![
                owned_asset(0, 5, false, 0),
                owned_asset(1, 700, false, 3),
                owned_asset(2, 200, false, 3),
                owned_asset(3, 9, true, 3),
                owned_asset(4, 11, false, 7),
                owned_asset(5, 2, false, 0),
            ],
            ..NoteStore::default()
        };
        assert_eq!(store.balance(), 7, "RAND alone, not a sum across assets");
        assert_eq!(store.balance_of(0), store.balance());
        assert_eq!(store.balance_of(3), 900, "and the spent asset note is not in it");
        assert_eq!(store.balance_of(7), 11);
        assert_eq!(store.balance_of(9), 0, "an asset this wallet holds nothing in");
        assert_eq!(store.asset_balances(), vec![(0, 7), (3, 900), (7, 11)]);

        // Selection sees one asset's notes and no others: a burn of 850 of asset 3 is payable from
        // its two notes, while the RAND the same wallet holds is not part of the answer.
        let chosen = select_inputs(&store.spendable_of(3), 850).unwrap();
        assert_eq!(chosen.iter().map(|n| n.index).collect::<Vec<_>>(), vec![1, 2]);
        assert!(chosen.iter().all(|n| n.note.asset == 3));
        // 907 units exist in the wallet in total, but only 900 of them in asset 3.
        assert_eq!(select_inputs(&store.spendable_of(3), 901).unwrap_err(), SelectError::Insufficient { have: 900 });
    }

    /// What a `bridge-mint` reads off the wire before it builds anything: the recipient hash the
    /// guardians signed, the asset, and the amount — from the ledger's own helper, so the note this
    /// wallet seals an envelope for is the note the chain will append.
    #[test]
    fn an_attestation_names_its_recipient_its_asset_and_its_amount() {
        let me = Wallet::from_spend_key(SpendKey([21; 8]));
        let d = attested_deposit(&transfer_attestation(1_000, me.address.recipient_hash())).unwrap();
        assert_eq!(d.to_hash, me.address.recipient_hash(), "the 32-byte stand-in for the address");
        assert_eq!(d.amount, 1_000, "the gross amount, relayer fee and all");
        assert_eq!((d.token_chain, d.token), (TOKEN_CHAIN, TOKEN), "the token the guardians named");
        assert_eq!(d.asset, randprotocol_core::bridge::asset_id(TOKEN_CHAIN, &TOKEN), "the registry's key for the token");
        // The address the guardians named is one address: another wallet's does not hash to it,
        // which is what the ledger refuses with `BridgeRecipientMismatch`.
        let other = Wallet::from_spend_key(SpendKey([22; 8]));
        assert_ne!(d.to_hash, other.address.recipient_hash());
        // Bytes that are not an attestation, and one that deposits nothing, are refused by name.
        assert!(attested_deposit(&[0xff; 32]).unwrap_err().to_string().contains("not a bridge attestation"));
        assert!(attested_deposit(&rotation_attestation()).unwrap_err().to_string().contains("rotation"));
    }

    /// A listed token's index is a fact — that is the whole of it now. An unlisted token has no
    /// index to guess at: the chain would refuse an attestation of it, so the wallet says so
    /// before it proves anything rather than predicting the registry's next number and racing
    /// another first sighting for it.
    #[test]
    fn a_deposit_index_is_a_fact_for_a_listed_token_and_an_error_for_any_other() {
        let row = |index: u32, byte: u8| AssetRow {
            index,
            chain: 2,
            token: vec![byte; 32],
            asset_id: hex::encode([byte; 32]),
        };
        let assets = [row(1, 0xaa), row(2, 0xbb)];
        let state = serde_json::json!({ "enabled": true });
        let id = |byte: u8| hex::encode([byte; 32]);

        assert_eq!(deposit_index(&state, &assets, &id(0xaa)).unwrap(), 1);
        assert_eq!(deposit_index(&state, &assets, &id(0xbb)).unwrap(), 2);
        let err = deposit_index(&state, &assets, &id(0xcc)).unwrap_err();
        assert!(err.to_string().contains("not listed on this chain"), "{err}");

        // A chain with no bridge cannot deposit at all.
        let err = deposit_index(&serde_json::json!({ "enabled": false }), &assets, &id(0xaa)).unwrap_err();
        assert!(err.to_string().contains("no bridge"), "{err}");
    }

    /// The belt-and-braces check on a committed mint: the chain deposited under a different index
    /// than the envelope was sealed against. Unreachable while every node agrees on the registry
    /// — admission refuses such a transaction — so what it really catches is a node whose registry
    /// is not the one the index was read from.
    #[test]
    fn a_committed_deposit_index_is_checked_against_the_one_it_was_sealed_for() {
        let committed = |kind: &str, asset_index: serde_json::Value| {
            serde_json::json!({ "tx": { "action": { "kind": kind, "asset_index": asset_index } } })
        };
        assert_eq!(deposit_index_check(3, &committed("bridge_attest", serde_json::json!(3))), DepositIndexCheck::Agrees);
        assert_eq!(
            deposit_index_check(3, &committed("bridge_attest", serde_json::json!(4))),
            DepositIndexCheck::Mismatch { predicted: 3, committed: 4 },
            "this node's registry is not the one the index was read from"
        );
        // The node cannot always say, and "cannot say" is never "agrees": a rotation deposits
        // nothing, a token its registry does not list renders as null, and another action is not a
        // deposit at all.
        for tx in [
            committed("bridge_attest", serde_json::Value::Null),
            committed("bridge_burn", serde_json::json!(3)),
            serde_json::json!({ "tx": { "action": {} } }),
            serde_json::Value::Null,
        ] {
            assert_eq!(deposit_index_check(3, &tx), DepositIndexCheck::Unknown, "{tx}");
        }
    }

    /// The deposit note this wallet seals for has to be, word for word, the one the chain computes
    /// — the commitment is not on the wire, so a note built any other way leaves the recipient a
    /// leaf no key of theirs opens.
    #[test]
    fn a_bridge_deposit_note_is_the_one_the_ledger_will_append() {
        use randprotocol_core::confidential::ConfidentialExecutor;
        let me = Wallet::from_spend_key(SpendKey([23; 8]));
        let a = transfer_attestation(1_000, me.address.recipient_hash());
        let (note, envelope) = deposit_note_for(&me, &me.address, &a, 1_000, 3, 41).unwrap();
        // `ConfidentialExecutor::note_commitment` is the function `bridge_notes` computes the
        // deposit's commitment through, on the ledger's side of the same wire — over the action's
        // own `r`, which is this note's.
        let ex = randprotocol_zkvm::executor::ZkExecutor::new(FriProfile::Test);
        assert_eq!(note.commitment(), ex.note_commitment(&me.address.pk, &[0; 8], 1_000, 3, 41, &note.r));
        assert_eq!((note.amount, note.asset, note.time, note.from), (1_000, 3, 41, [0; 8]));
        // And the envelope published with it opens back to that note, as the recipient.
        assert_eq!(classify(&me, note.commitment(), &envelope), Found::Received(note));
        // A different `time` is a different note: this is why `time` is on the action.
        let (later, _) = deposit_note_for(&me, &me.address, &a, 1_000, 3, 42).unwrap();
        assert_ne!(later.commitment(), note.commitment());
        // The blinding is not drawn, it is derived (F1): this attestation's digest fixes it, so
        // every submitter of it builds the very same note — and the ledger admits no other `r`
        // (`bridge_notes::deposit_r`, the rule `validate` enforces).
        assert_eq!(note.r, bridge_notes::deposit_r(&a).unwrap());
        assert_eq!(deposit_note_for(&me, &me.address, &a, 1_000, 3, 41).unwrap().0.r, note.r);
        let other = transfer_attestation(999, me.address.recipient_hash());
        assert_ne!(bridge_notes::deposit_r(&other).unwrap(), note.r, "another attestation, another blinding");
        assert!(deposit_note_for(&me, &me.address, &[0xff; 4], 1_000, 3, 41).is_err(), "no body, no note");
    }

    // ------------------------------------------------ the hidden-asset bundle, end to end
    //
    // Every test below drives the real submission path — scan, plan, anchor and witnesses, build,
    // assemble, bind, prove, submit — against `FakeChain`, a node kept in memory behind a real
    // HTTP socket. "Proving" is the hidden guest run in the emulator on the witness the wallet
    // built, against the transaction's own binding: the digest it publishes is checked against
    // the wallet's exactly as a real proof's is, and it is what the stub proof then carries. So
    // a witness that would taint, a slot out of place or a digest the ledger would not recompute
    // fails here in a second rather than in the wallet flow after minutes.

    use crate::test_rpc::{rpc_fn, Reply};
    use randprotocol_core::confidential::{ConfidentialExecutor, StubExecutor};
    use randprotocol_zkvm::executor::ZkExecutor;
    use std::sync::{Arc, Mutex};

    /// The `hc` the emulated "proof" is made under — any word: the stub verifier only checks it
    /// is the one the proof names.
    const EMULATED_HC: Word8 = [0xe0; 8];

    /// [`Proving::Emulated`]: the hidden guest run on `p.words` against `binding`, its digest
    /// checked as a real proof's is, and a stub proof carrying it.
    pub(super) fn emulated_proof(p: &Prepared, binding: &[u32; TX_BINDING_WORDS]) -> Result<Proved> {
        let run = randprotocol_zkvm::emulator::execute(ZkExecutor::hidden_bundle_program(), &p.words, binding, 1 << 20)
            .map_err(|e| anyhow!("the hidden guest did not run: {e:?}"))?;
        let digest: Word8 = run.outputs;
        check_published_digest(&digest, &p.expected)?;
        Ok(Proved { proof: StubExecutor::make_bundle_proof(&EMULATED_HC, &digest, binding), tier: 14, proving: Duration::ZERO })
    }

    /// A node in memory: the commitment tree and its envelopes, the blocks, the nullifiers, what
    /// was submitted, and the bridge's two replies.
    struct FakeChain {
        tree: randprotocol_zkvm::ledger::CommitmentTree,
        leaves: Vec<(Word8, Envelope, u64)>,
        /// `blocks[h]` is block `h`'s transactions; block 0 is genesis.
        blocks: Vec<Vec<Transaction>>,
        sent: Vec<Transaction>,
        bridge: serde_json::Value,
        assets: serde_json::Value,
        /// `rand_getTokens`' whole reply, `{"enabled":.., "registration_fee":.., "next_index":..,
        /// "tokens":[..]}` — a token test sets it directly, since the registry itself lives on
        /// the real node this fake stands in for, not on this struct.
        tokens: serde_json::Value,
        /// A method that answers with an error, for the failure paths.
        fail: Option<&'static str>,
    }

    fn kind(a: &Action) -> &'static str {
        match a {
            Action::None => "none",
            Action::BridgeAttest { .. } => "bridge_attest",
            Action::TokenMint { .. } => "token_mint",
            Action::RegisterToken { .. } => "register_token",
            _ => "other",
        }
    }

    fn envelope_json(e: &Envelope) -> serde_json::Value {
        serde_json::json!({
            "kem_ct": hex::encode(&e.kem_ct), "to_receiver": hex::encode(&e.to_receiver),
            "to_sender": hex::encode(&e.to_sender), "body": hex::encode(&e.body),
        })
    }

    impl FakeChain {
        fn new() -> FakeChain {
            FakeChain {
                tree: randprotocol_zkvm::ledger::CommitmentTree::new(),
                leaves: Vec::new(),
                blocks: vec![Vec::new()],
                sent: Vec::new(),
                bridge: serde_json::json!({ "enabled": false }),
                assets: serde_json::json!([]),
                tokens: serde_json::json!({ "enabled": false, "tokens": [] }),
                fail: None,
            }
        }

        fn head(&self) -> u64 {
            self.blocks.len() as u64 - 1
        }

        /// A new block carrying `txs`, which appended the leaves `leaves`.
        fn commit(&mut self, txs: Vec<Transaction>, leaves: Vec<(Word8, Envelope)>) {
            let height = self.blocks.len() as u64;
            for (cm, e) in leaves {
                self.tree.append(cm);
                self.leaves.push((cm, e, height));
            }
            self.blocks.push(txs);
        }

        /// A note of `amount` of `asset` for `to`, sealed to it by a stranger, in a block of its own.
        fn fund(&mut self, to: &Wallet, amount: u64, asset: u32) {
            let stranger = Wallet::from_spend_key(SpendKey([77; 8]));
            let note = Note::new(to.vk.pk(), stranger.vk.pk(), amount, asset, self.head() as u32);
            self.commit(Vec::new(), vec![(note.commitment(), sealed(&stranger, to, &note))]);
        }

        fn answer(&mut self, method: &str, p: &serde_json::Value) -> Reply {
            use serde_json::json;
            if self.fail == Some(method) {
                return Reply::Err(-32000, "injected failure");
            }
            let n = |i: usize| p[i].as_u64().unwrap_or(0);
            let head = self.head();
            Reply::Ok(match method {
                "rand_getHead" => json!({ "height": head }),
                "rand_getBlocks" => json!((n(0)..=n(1).min(head).min(n(0) + 127))
                    .map(|h| json!({ "height": h, "tx_count": self.blocks[h as usize].len() }))
                    .collect::<Vec<_>>()),
                "rand_getBlockByHeight" => {
                    let txs: Vec<_> = self.blocks[n(0) as usize]
                        .iter()
                        .map(|t| json!({ "hash": t.hash().to_hex(), "action": { "kind": kind(&t.action) } }))
                        .collect();
                    json!({ "height": n(0), "transactions": txs })
                }
                "rand_getRawTransaction" => {
                    let want = p[0].as_str().unwrap_or_default();
                    self.blocks
                        .iter()
                        .flatten()
                        .find(|t| t.hash().to_hex() == want)
                        .map_or(serde_json::Value::Null, |t| json!(hex::encode(t.encode())))
                }
                "rand_getCommitments" => json!(self
                    .leaves
                    .iter()
                    .enumerate()
                    .skip(n(0) as usize)
                    .take(n(1) as usize)
                    .map(|(i, (cm, e, h))| json!({ "index": i, "cm": word8_to_hex(cm), "envelope": envelope_json(e), "height": h }))
                    .collect::<Vec<_>>()),
                "rand_getNullifiers" => json!([]),
                "rand_getAnchor" => json!({ "height": head, "root": word8_to_hex(&self.tree.root()) }),
                "rand_getWitness" => json!({
                    "root": word8_to_hex(&self.tree.root()),
                    "path": self.tree.path(n(0) as usize).iter().map(word8_to_hex).collect::<Vec<_>>(),
                }),
                "rand_sendTransaction" => {
                    let tx = Transaction::decode(&hex::decode(p[0].as_str().unwrap_or_default()).unwrap()).unwrap();
                    let hash = tx.hash().to_hex();
                    self.sent.push(tx);
                    json!(hash)
                }
                "rand_getBridgeState" => self.bridge.clone(),
                "rand_getAssets" => self.assets.clone(),
                "rand_getTokens" => self.tokens.clone(),
                _ => return Reply::Err(-32601, "unknown method"),
            })
        }
    }

    /// The chain behind a real socket, and a client for it.
    async fn serve(chain: &Arc<Mutex<FakeChain>>) -> RpcClient {
        let c = chain.clone();
        RpcClient::new(rpc_fn(move |m, p| c.lock().unwrap().answer(m, p)).await)
    }

    /// Everything the chain would check of a submitted bundle without its proof, plus the proof
    /// check the stub can make: every nullifier and commitment distinct, the digest the ledger
    /// recomputes (through the real executor) is the one the emulated guest published, and the
    /// proof verifies against the transaction's own binding.
    fn assert_admissible_shape(tx: &Transaction) {
        let b = tx.bundle.as_ref().expect("a bundle");
        for i in 0..SLOTS {
            for j in i + 1..SLOTS {
                assert_ne!(b.nullifiers[i], b.nullifiers[j], "nullifiers {i} and {j}");
                assert_ne!(b.commitments[i], b.commitments[j], "commitments {i} and {j}");
            }
        }
        let recomputed = ZkExecutor::new(FriProfile::Test).bundle_digest(&b.digest_input());
        assert_eq!(StubExecutor.bundle_proof_digest(&b.proof).unwrap(), recomputed, "the ledger's digest is the guest's");
        assert_eq!(StubExecutor.verify_bundle(&EMULATED_HC, &b.proof, &tx.binding()), Ok(()), "bound to this transaction");
    }

    /// What each slot of `tx`'s bundle is to `w`: the note it received, the note it sent, or
    /// nothing.
    fn slots_for(w: &Wallet, tx: &Transaction) -> Vec<Found> {
        let b = tx.bundle.as_ref().unwrap();
        (0..SLOTS).map(|k| classify(w, b.commitments[k], &b.envelopes[k])).collect()
    }

    fn opens_to_nobody(found: &Found) -> bool {
        *found == Found::Skipped(NOT_OURS)
    }

    /// A bundle for the actions a test commits to a block — never proved, never read.
    fn unread_bundle() -> Bundle {
        Bundle {
            anchor: [0; 8],
            nullifiers: [[1; 8], [2; 8], [3; 8], [4; 8]],
            commitments: [[5; 8], [6; 8], [7; 8], [8; 8]],
            fee: gas::BUNDLE_BASE,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 1,
            envelopes: [env(), env(), env(), env()],
            proof: vec![],
        }
    }

    fn garbage() -> Envelope {
        Envelope { kem_ct: vec![0xff; 8], to_receiver: vec![0xff; 16], to_sender: vec![], body: vec![0xff; 16] }
    }

    /// A deposit (asset 3), a token mint (asset 5) and a registration's initial mint (asset 6) to
    /// `me`, each published with a garbage envelope, each in a block of its own; plus the notes
    /// they append.
    fn public_notes_for(me: &Wallet) -> (Vec<Transaction>, Vec<Note>) {
        use randprotocol_core::ledger::tokens::MintAuthority;
        use randprotocol_core::types::actions::InitialMint;
        let attestation = transfer_attestation(1_000, me.address.recipient_hash());
        // The blinding the ledger admits (F1), so this fixture is the transaction a chain would
        // actually carry.
        let deposit_r = bridge_notes::deposit_r(&attestation).unwrap();
        let deposit = Transaction::shielded(
            7,
            unread_bundle(),
            Action::BridgeAttest {
                attestation,
                recipient: me.address.clone(),
                r: deposit_r,
                time: 1,
                asset: 3,
                envelope: garbage(),
                pq_signatures: vec![],
            },
        );
        let mint = Transaction::shielded(
            7,
            unread_bundle(),
            Action::TokenMint {
                asset: 5,
                amount: 250,
                recipient: me.address.clone(),
                r: [10; 8],
                time: 2,
                envelope: garbage(),
                nonce: 0,
                signature: randprotocol_core::Keypair::generate().sign(b"not checked by a wallet"),
            },
        );
        let register = Transaction::shielded(
            7,
            unread_bundle(),
            Action::RegisterToken {
                name: "Test".into(),
                symbol: "TST".into(),
                decimals: 6,
                authority: MintAuthority::None,
                initial: Some(InitialMint { amount: 90, recipient: me.address.clone(), r: [11; 8], time: 3, envelope: garbage() }),
                salt: [0; 32],
                index: 6,
            },
        );
        let pk = me.vk.pk();
        let notes = vec![
            Note { pk, from: [0; 8], amount: 1_000, asset: 3, time: 1, r: deposit_r },
            Note { pk, from: MINT_FROM, amount: 250, asset: 5, time: 2, r: [10; 8] },
            Note { pk, from: MINT_FROM, amount: 90, asset: 6, time: 3, r: [11; 8] },
        ];
        (vec![deposit, mint, register], notes)
    }

    /// The three notes a deposit and two mints append are rebuilt, word for word, as the notes the
    /// ledger computes (`deposit_commitment`, `mint_commitment`, through the real executor) — for
    /// their recipient and nobody else, and not for a rotation.
    #[test]
    fn deposits_and_mints_are_rebuilt_from_their_public_fields_as_the_ledger_computes_them() {
        let me = Wallet::from_spend_key(SpendKey([41; 8]));
        let stranger = Wallet::from_spend_key(SpendKey([42; 8]));
        let ex = ZkExecutor::new(FriProfile::Test);
        let (txs, notes) = public_notes_for(&me);
        assert_eq!(notes[0].commitment(), bridge_notes::deposit_commitment(&me.address, 1_000, 3, 1, &notes[0].r, &ex));
        assert_eq!(notes[1].commitment(), randprotocol_core::ledger::tokens::mint_commitment(&me.address, 250, 5, 2, &[10; 8], &ex));
        assert_eq!(notes[2].commitment(), randprotocol_core::ledger::tokens::mint_commitment(&me.address, 90, 6, 3, &[11; 8], &ex));
        for (tx, note) in txs.iter().zip(&notes) {
            assert_eq!(rebuilt_notes(&me, tx), vec![*note], "{}", kind(&tx.action));
            assert!(rebuilt_notes(&stranger, tx).is_empty(), "not the stranger's");
            // The envelope opens to nobody, which is the whole point of this path.
            assert!(matches!(classify(&me, note.commitment(), &garbage()), Found::Skipped(_)));
        }
        let rotation = Transaction::shielded(
            7,
            unread_bundle(),
            Action::BridgeAttest {
                attestation: rotation_attestation(),
                recipient: me.address.clone(),
                r: bridge_notes::deposit_r(&rotation_attestation()).unwrap(),
                time: 1,
                asset: 0,
                envelope: garbage(),
                pq_signatures: vec![],
            },
        );
        assert!(rebuilt_notes(&me, &rotation).is_empty(), "a rotation deposits nothing");
        assert!(rebuilt_notes(&me, &Transaction::shielded(7, unread_bundle(), Action::None)).is_empty());
    }

    /// A deposit and two mints whose envelopes are garbage are still found by their recipient —
    /// from the public action fields — and are spendable: the recipient sends 400 of the deposited
    /// token in a hidden-asset bundle the (emulated) guest accepts, paying the fee in RAND.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_garbage_envelope_deposit_is_still_found_and_spendable_by_its_recipient() {
        let me = Wallet::from_spend_key(SpendKey([41; 8]));
        let you = Wallet::from_spend_key(SpendKey([43; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        let (txs, notes) = public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            c.fund(&Wallet::from_spend_key(SpendKey([50; 8])), 5, 0); // someone else's leaf first
            for (tx, note) in txs.into_iter().zip(&notes) {
                c.commit(vec![tx], vec![(note.commitment(), garbage())]);
            }
            c.fund(&me, 2 * gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.asset_balances(), vec![(0, 2 * gas::BUNDLE_BASE), (3, 1_000), (5, 250), (6, 90)]);
        let deposit = store.spendable_of(3)[0].clone();
        assert_eq!((deposit.index, deposit.nf), (1, me.vk.nullifier(&notes[0].commitment())), "at its own leaf");
        // A second scan re-reads nothing and finds nothing new.
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.len(), 4);

        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 3, 400, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .expect("the deposit is spendable");
        assert_eq!((s.amount, s.change, s.asset, s.rand_change), (400, 600, 3, gas::BUNDLE_BASE));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert_eq!(tx.action, Action::None, "a token transfer is a plain bundle");
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!((b.fee, b.burn_a, b.burn_r, b.burn_asset), (gas::BUNDLE_BASE, 0, 0, 0), "nothing public names the asset");
        assert!(b.nullifiers.contains(&deposit.nf), "the deposit is what was spent");
        // The payee finds 400 of asset 3 in slot 0; the sender's change is slot 1 (asset) and slot 2
        // (RAND); slot 3 is a dummy nobody opens.
        let theirs = slots_for(&you, &tx);
        let Found::Received(paid) = theirs[0] else { panic!("slot 0 pays the payee: {theirs:?}") };
        assert_eq!((paid.amount, paid.asset, paid.from), (400, 3, me.vk.pk()));
        assert!(theirs[1..].iter().all(opens_to_nobody), "{theirs:?}");
        let mine = slots_for(&me, &tx);
        assert!(matches!(mine[0], Found::Sent(n) if n.amount == 400));
        assert!(matches!(mine[1], Found::Received(n) if n.amount == 600 && n.asset == 3));
        assert!(matches!(mine[2], Found::Received(n) if n.amount == gas::BUNDLE_BASE && n.asset == 0));
        assert!(opens_to_nobody(&mine[3]), "{:?}", mine[3]);
        // `--no-wait`: the two spent notes are held back until the chain answers.
        assert_eq!(store.balance_of(3), 0);
        assert_eq!(store.balance(), 0);
    }

    /// A save round trip, as `rand` does after every command whether or not it failed.
    fn saved(store: &NoteStore) -> NoteStore {
        serde_json::from_str(&serde_json::to_string(store).unwrap()).unwrap()
    }

    /// A scan that fails after reading the blocks but before placing the rebuilt notes at their
    /// leaves does not move the public-rebuild cursor — the store `rand` saves on that failure
    /// still re-reads those blocks, and the next scan finds the garbage-envelope deposit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_scan_never_saves_a_cursor_past_an_unplaced_deposit() {
        let me = Wallet::from_spend_key(SpendKey([55; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        let (txs, notes) = public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            for (tx, note) in txs.into_iter().zip(&notes) {
                c.commit(vec![tx], vec![(note.commitment(), garbage())]);
            }
            c.fail = Some("rand_getCommitments");
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        assert!(scan(&rpc, &me, &mut store).await.unwrap_err().to_string().contains("injected"));
        let mut store = saved(&store);
        assert_eq!(store.scanned_attest_height, 0, "the blocks are still unread as far as the store knows");
        assert!(store.notes.is_empty());

        // And a failure after the leaves were read but in the nullifier pages: the notes were placed,
        // so the cursor may move — but it did not have to for correctness; either way nothing is lost.
        chain.lock().unwrap().fail = Some("rand_getNullifiers");
        assert!(scan(&rpc, &me, &mut store).await.is_err());
        let mut store = saved(&store);

        chain.lock().unwrap().fail = None;
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.asset_balances(), vec![(3, 1_000), (5, 250), (6, 90)], "every public note found");
        assert_eq!(store.scanned_attest_height, chain.lock().unwrap().head() + 1);
    }

    /// The recovery pass: a store whose leaf cursor is already past a deposit's leaf (an older
    /// build scanned it, and its garbage envelope opened nothing) but whose block cursor is 0 —
    /// what a store written before the public-rebuild path looks like. The rescan reads the blocks,
    /// rebuilds the note, and places it by re-reading the leaves from the start.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rebuilt_note_below_the_leaf_cursor_is_placed_by_the_recovery_pass() {
        let me = Wallet::from_spend_key(SpendKey([56; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        let (txs, notes) = public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            let (tx, note) = (txs.into_iter().next().unwrap(), notes[0]);
            c.commit(vec![tx], vec![(note.commitment(), garbage())]);
            c.fund(&me, 5, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore { scanned_index: 2, scanned_height: 0, scanned_attest_height: 0, ..NoteStore::default() };
        scan(&rpc, &me, &mut store).await.unwrap();
        let deposit: Vec<(u64, u64, u32)> = store.notes.iter().map(|n| (n.index, n.note.amount, n.note.asset)).collect();
        // The deposit at leaf 0, below the cursor; the recovery pass re-offers every leaf, so the
        // RAND note at leaf 1 is recorded on the way (once — a leaf is keyed by its index).
        assert_eq!(deposit, vec![(0, 1_000, 3), (1, 5, 0)]);
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.len(), 2, "a second scan adds nothing");
        assert_eq!(store.scanned_index, 2);
    }

    /// RAND held by a `--no-wait` submission is not spendable, but it is not missing: the refusal
    /// says to wait, not to go and get RAND.
    #[test]
    fn a_fee_refusal_names_rand_held_by_a_pending_submission() {
        let you = Wallet::from_spend_key(SpendKey([57; 8]));
        let mut store = NoteStore { notes: vec![owned_asset(0, 500, false, 4), owned_asset(1, 3_000_000, false, 0)], ..NoteStore::default() };
        store.notes[1].pending = Some(9);
        let spend = Spend { asset: 4, to: Some((&you.address, 100)), fee: gas::BUNDLE_BASE, burn_a: 0, burn_r: 0 };
        let e = Plan::select(&store, spend).unwrap_err().to_string();
        assert!(e.contains("0.003 RAND is held by a pending submission") && e.contains("rand sync"), "{e}");
        store.notes[1].spent = true;
        let e = Plan::select(&store, spend).unwrap_err().to_string();
        assert!(e.contains("receive some RAND"), "{e}");
    }

    /// A RAND payment keeps today's shape: value and fee in slots 2–3, slots 0–1 dummies that open
    /// to nobody — the sender included — so they are never a balance or a history row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rand_payment_rides_slots_2_and_3_and_its_dummies_open_to_nobody() {
        let me = Wallet::from_spend_key(SpendKey([44; 8]));
        let you = Wallet::from_spend_key(SpendKey([45; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 3_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        // Needs both notes: neither alone covers 8 000 000 + the fee.
        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 8_000_000, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!((s.amount, s.change, s.asset, s.burn), (8_000_000, 2_000_000 - gas::BUNDLE_BASE, 0, Burn::None));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let theirs = slots_for(&you, &tx);
        assert!(matches!(theirs[2], Found::Received(n) if n.amount == 8_000_000 && n.asset == 0), "{theirs:?}");
        let mine = slots_for(&me, &tx);
        assert!(matches!(mine[3], Found::Received(n) if n.amount == 2_000_000 - gas::BUNDLE_BASE));
        for k in [0, 1] {
            assert!(opens_to_nobody(&mine[k]) && opens_to_nobody(&theirs[k]), "slot {k}: {:?} {:?}", mine[k], theirs[k]);
        }
        // Scanning the committed transaction back: the payee has one note, the sender one change
        // note and one history row — no dummy anywhere.
        {
            let mut c = chain.lock().unwrap();
            let b = tx.bundle.clone().unwrap();
            c.commit(vec![tx.clone()], b.commitments.iter().copied().zip(b.envelopes.iter().cloned()).collect());
        }
        let mut theirs = NoteStore::default();
        scan(&rpc, &you, &mut theirs).await.unwrap();
        assert_eq!((theirs.balance(), theirs.notes.len(), theirs.sent.len()), (8_000_000, 1, 0));
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.iter().filter(|n| n.note.amount == 2_000_000 - gas::BUNDLE_BASE).count(), 1);
        assert_eq!(store.notes.len(), 3, "two funding notes and the change");
        assert_eq!(store.sent.len(), 1, "one payment in the history");
        assert_eq!(output_keys(&me, &tx).len(), 2, "the payment and the change, never a dummy");
    }

    /// A token transfer pays its fee in RAND, so a wallet holding only the token is refused before
    /// anything is proved or submitted — and so is one short of the token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_transfer_without_rand_for_the_fee_is_refused_before_proving() {
        let me = Wallet::from_spend_key(SpendKey([46; 8]));
        let you = Wallet::from_spend_key(SpendKey([47; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        chain.lock().unwrap().fund(&me, 500, 4);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 4, 100, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("a transfer pays its fee in RAND"), "{e}");
        chain.lock().unwrap().fund(&me, gas::BUNDLE_BASE, 0);
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 4, 501, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("asset 4") && e.contains("insufficient"), "{e}");
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 4, 0, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("zero"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty(), "nothing was submitted");
        assert!(store.notes.iter().all(|n| n.pending.is_none()), "and nothing held back");
    }

    /// A bridge burn is one bundle: the asset's slots burn exactly the amount (`burn_a`,
    /// `burn_asset`), the RAND slots pay the fee, and nothing is burned in RAND. A burn the locked
    /// amount cannot cover is refused before proving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bridge_burn_is_one_bundle_burning_the_asset_and_paying_rand() {
        let me = Wallet::from_spend_key(SpendKey([48; 8]));
        let token = [0xd7u8; 32];
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        {
            let mut c = chain.lock().unwrap();
            c.bridge = serde_json::json!({ "enabled": true, "assets": [asset_row(3, 2, token, 8, 700)] });
            c.fund(&me, 1_000, 3);
            c.fund(&me, gas::BRIDGE_BURN_FEE + 5, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let burn = |amount| BurnRequest { asset: 3, amount, relayer_fee: 0, to_chain: 2, token, to: [1; 32] };
        let e = submit_burn_with(&rpc, &me, &mut store, burn(800), gas::BRIDGE_BURN_FEE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("only 700 is locked"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty());

        let s = submit_burn_with(&rpc, &me, &mut store, burn(400), gas::BRIDGE_BURN_FEE, Proving::Emulated, 7, false).await.unwrap();
        assert_eq!((s.amount, s.change, s.asset, s.burn, s.rand_change), (400, 600, 3, Burn::Asset { index: 3, amount: 400 }, 5));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!((b.fee, b.burn_a, b.burn_r, b.burn_asset), (gas::BRIDGE_BURN_FEE, 400, 0, 3));
        assert!(matches!(tx.action, Action::BridgeBurn { asset: 3, amount: 400, .. }));
    }

    /// A token burn is the same one bundle under `TokenBurn`; a bridged token is refused up front
    /// (its supply leaves through a bridge burn), and so is RAND.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_burn_burns_through_burn_a_and_a_bridged_token_is_refused_before_proving() {
        let me = Wallet::from_spend_key(SpendKey([49; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        {
            let mut c = chain.lock().unwrap();
            c.assets = serde_json::json!([{ "index": 2, "chain": 2, "token": hex::encode([1u8; 32]), "asset_id": hex::encode([2u8; 32]) }]);
            c.fund(&me, 300, 5);
            c.fund(&me, 300, 2);
            c.fund(&me, gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let e = submit_token_burn_with(&rpc, &me, &mut store, 2, 100, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("bridged token") && e.contains("bridge-burn"), "{e}");
        let e = submit_token_burn_with(&rpc, &me, &mut store, 0, 100, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("RAND"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty());

        let s = submit_token_burn_with(&rpc, &me, &mut store, 5, 300, gas::BUNDLE_BASE, Proving::Emulated, 7, false).await.unwrap();
        assert_eq!((s.amount, s.change, s.rand_change), (300, 0, 0));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!((b.burn_a, b.burn_r, b.burn_asset), (300, 0, 5));
        assert_eq!(tx.action, Action::TokenBurn { asset: 5, amount: 300 });
        // No change at all in either group: every output is a dummy nobody opens.
        assert!(slots_for(&me, &tx).iter().all(opens_to_nobody));
    }

    /// `build_register_token` refuses bad metadata (`check_metadata`, the same rule
    /// `register_bridged_action` already runs first) before any network read — T8b review round
    /// 1: a bad name, symbol or decimals count would otherwise burn a real proof before the chain
    /// ever saw a byte of it. The stub RPC panics if called at all, so a call reaching it would
    /// fail the test on its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_register_token_checks_metadata_before_any_network_read() {
        let me = Wallet::from_spend_key(SpendKey([65; 8]));
        let rpc =
            RpcClient::new(rpc_fn(|_m, _p| panic!("build_register_token must refuse bad metadata before any RPC call")).await);
        let e = build_register_token(&rpc, &me, "", "FIX", 6, MintAuthority::None, None, [0; 32]).await.unwrap_err().to_string();
        assert!(e.to_lowercase().contains("name"), "{e}");
        let e = build_register_token(&rpc, &me, "Fixed", "", 6, MintAuthority::None, None, [0; 32]).await.unwrap_err().to_string();
        assert!(e.to_lowercase().contains("symbol"), "{e}");
        let e = build_register_token(&rpc, &me, "Fixed", "FIX", 250, MintAuthority::None, None, [0; 32]).await.unwrap_err().to_string();
        assert!(e.to_lowercase().contains("decimals"), "{e}");
    }

    /// `create_token`'s authority-key lifecycle (T8b review round 1's fix): a node-side refusal
    /// of `rand_sendTransaction` (an `IndexMismatch` lost race is one of them) leaves no file at
    /// all — not at the target path, not at its `.pending` — so a re-run to the very same path
    /// works; an accepted registration promotes the pending file to the target path, and never
    /// touches the note the failed attempt did not spend (a submission error is raised before
    /// `settle` marks anything pending).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_token_discards_the_pending_key_on_a_node_refusal_and_promotes_it_on_acceptance() {
        let me = Wallet::from_spend_key(SpendKey([66; 8]));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("authority.key.json");
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        {
            let mut c = chain.lock().unwrap();
            c.tokens = serde_json::json!({ "enabled": true, "registration_fee": 0, "next_index": 1, "tokens": [] });
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
            c.fail = Some("rand_sendTransaction");
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let kp = Keypair::generate();

        let e = create_token_with(
            &rpc,
            &me,
            &mut store,
            "Fixed",
            "FIX",
            6,
            Some((&kp, out.as_path())),
            None,
            [3; 32],
            None,
            Proving::Emulated,
            7,
            false,
        )
        .await
        .unwrap_err();
        // The send itself was refused, so the failure carries the `SubmitRefused` label — which
        // is what the discard arm keys on (node I1) — with the node's reply inside it.
        let refused = e.downcast_ref::<crate::SubmitRefused>().unwrap_or_else(|| panic!("{e}"));
        assert_eq!(refused.0.code, -32000);
        assert!(!out.exists(), "no file at the target path after a node refusal");
        assert!(!pending_authority_key_path(&out).exists(), "the pending file is discarded, not stranded");
        // The failed submission never reached `settle`, so the note it would have spent is still
        // whole — no need to fund a second note for the re-run below.
        assert_eq!(store.balance(), 3 * gas::BUNDLE_BASE);

        // A re-run to the very same path, this time accepted.
        chain.lock().unwrap().fail = None;
        let result = create_token_with(
            &rpc,
            &me,
            &mut store,
            "Fixed",
            "FIX",
            6,
            Some((&kp, out.as_path())),
            None,
            [3; 32],
            None,
            Proving::Emulated,
            7,
            false,
        )
        .await
        .unwrap();
        assert_eq!(result.index, 1);
        assert!(out.exists(), "the accepted registration's key is promoted to the target path");
        assert!(!pending_authority_key_path(&out).exists());
        let saved = load_authority_key(&out).unwrap();
        assert_eq!(saved.public_key(), kp.public_key());
    }

    /// Node I1: the discard is decided by the **stage**, not by the error type. `RpcError` is
    /// what every JSON-RPC error reply becomes — the wait's `rand_getTransactionStatus` and the
    /// post-commit rescan's six methods included — so keying on it deleted the only copy of a
    /// committed token's authority key whenever a node answered a *later* call with `-32603`
    /// ("node loop closed" on a restart), `-32000` (backpressure) or anything else. Only
    /// `rand_sendTransaction` itself refusing means nothing was admitted, and only that is
    /// labelled `SubmitRefused`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_token_keeps_the_pending_key_when_a_call_after_the_send_fails() {
        let me = Wallet::from_spend_key(SpendKey([67; 8]));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("authority.key.json");
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        {
            let mut c = chain.lock().unwrap();
            c.tokens = serde_json::json!({ "enabled": true, "registration_fee": 0, "next_index": 1, "tokens": [] });
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
            // The send goes through; the wait's very first call does not.
            c.fail = Some("rand_getTransactionStatus");
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let kp = Keypair::generate();

        let e = create_token_with(
            &rpc,
            &me,
            &mut store,
            "Fixed",
            "FIX",
            6,
            Some((&kp, out.as_path())),
            None,
            [3; 32],
            None,
            Proving::Emulated,
            7,
            true,
        )
        .await
        .unwrap_err();

        // It is an `RpcError`, exactly as a refusal is — and it is not a `SubmitRefused`.
        assert!(e.downcast_ref::<crate::RpcError>().is_some(), "{e}");
        assert!(e.downcast_ref::<crate::SubmitRefused>().is_none(), "a post-send failure is not a refusal: {e}");
        // The registration did reach the node, so the key is kept.
        assert_eq!(chain.lock().unwrap().sent.len(), 1, "the transaction was submitted");
        let pending = pending_authority_key_path(&out);
        assert!(pending.exists(), "the authority key of a possibly-committed registration is kept");
        assert!(!out.exists(), "and it is not promoted either — the fate is unknown");
        assert_eq!(load_authority_key(&pending).unwrap().public_key(), kp.public_key());

        // The refusal arm is still the refusal arm: a `rand_sendTransaction` error discards.
        let dir2 = tempfile::tempdir().unwrap();
        let out2 = dir2.path().join("authority.key.json");
        {
            let mut c = chain.lock().unwrap();
            c.fail = Some("rand_sendTransaction");
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
        }
        let e = create_token_with(
            &rpc, &me, &mut store, "Fixed", "FIX", 6, Some((&kp, out2.as_path())), None, [3; 32], None,
            Proving::Emulated, 7, true,
        )
        .await
        .unwrap_err();
        assert!(e.downcast_ref::<crate::SubmitRefused>().is_some(), "{e}");
        assert!(!out2.exists() && !pending_authority_key_path(&out2).exists());
    }

    /// `rand token create`'s two authority branches build a `RegisterToken` that rides one RAND
    /// fee bundle, `to = None`, nothing burned — exactly a bridged registration's shape — reading
    /// `next_index` and `registration_fee` off `rand_getTokens` first: fixed supply
    /// (`authority = None`) with its required initial mint, and a `Key`-authorised token
    /// registering empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_token_fixed_supply_and_key_authority_ride_a_rand_fee_bundle() {
        let me = Wallet::from_spend_key(SpendKey([61; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        {
            let mut c = chain.lock().unwrap();
            c.tokens = serde_json::json!({ "enabled": true, "registration_fee": 1_000, "next_index": 1, "tokens": [] });
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();

        // ---- fixed supply: authority None, the whole initial mint required ----
        let plan = build_register_token(&rpc, &me, "Fixed", "FIX", 6, MintAuthority::None, Some((1_000, me.address.clone())), [1; 32])
            .await
            .unwrap();
        assert_eq!((plan.index, plan.registration_fee), (1, 1_000));
        let fee = gas::fee_floor(&plan.action) + plan.registration_fee;
        let id1 = match &plan.action {
            Action::RegisterToken { name, symbol, decimals, authority, initial, salt, .. } => {
                randprotocol_core::ledger::tokens::native_asset_id(name, symbol, *decimals, authority, initial, salt)
            }
            _ => unreachable!(),
        };
        submit_register_token_with(&rpc, &me, &mut store, plan.action, fee, Proving::Emulated, 7, false).await.unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!((b.fee, b.burn_a, b.burn_r, b.burn_asset), (fee, 0, 0, 0));
        match tx.action {
            Action::RegisterToken { authority: MintAuthority::None, index: 1, initial: Some(m), .. } => {
                assert_eq!((m.amount, m.recipient), (1_000, me.address.clone()));
            }
            other => panic!("{other:?}"),
        }

        // ---- Key authority, registering empty: a second next_index, a different id ----
        chain.lock().unwrap().tokens["next_index"] = serde_json::json!(2);
        let authority_kp = Keypair::generate();
        let plan = build_register_token(&rpc, &me, "Keyed", "KEY", 6, MintAuthority::Key(authority_kp.public_key().clone()), None, [2; 32])
            .await
            .unwrap();
        assert_eq!(plan.index, 2);
        let fee = gas::fee_floor(&plan.action) + plan.registration_fee;
        let id2 = match &plan.action {
            Action::RegisterToken { name, symbol, decimals, authority, initial, salt, .. } => {
                randprotocol_core::ledger::tokens::native_asset_id(name, symbol, *decimals, authority, initial, salt)
            }
            _ => unreachable!(),
        };
        assert_ne!(id1, id2, "two different registrations are two different assets");
        submit_register_token_with(&rpc, &me, &mut store, plan.action, fee, Proving::Emulated, 7, false).await.unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert!(matches!(tx.action, Action::RegisterToken { authority: MintAuthority::Key(_), index: 2, initial: None, .. }));

        // A submission of anything but a `RegisterToken` is refused outright.
        let e = submit_register_token_with(&rpc, &me, &mut store, Action::None, fee, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("RegisterToken"), "{e}");
    }

    /// `rand token mint` and `rand token set-authority` both start from the token's own
    /// `rand_getTokens` row (never `rand_getToken`): refused up front, before any note is built
    /// or any RAND is touched, for a token that is not `Key`-authorised or for a key that is not
    /// its authority — then, against the right key, each rides one RAND fee bundle carrying the
    /// authority's own Dilithium2 signature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_mint_and_set_authority_refuse_the_wrong_key_and_a_non_key_token_first() {
        let me = Wallet::from_spend_key(SpendKey([62; 8]));
        let authority_kp = Keypair::generate();
        let id = Hash([9; 32]);
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        {
            let mut c = chain.lock().unwrap();
            c.tokens = serde_json::json!({
                "enabled": true, "registration_fee": 0, "next_index": 3,
                "tokens": [
                    { "index": 1, "id": hex::encode([1u8; 32]), "authority": { "kind": "none" }, "mint_nonce": 0 },
                    { "index": 2, "id": id.to_hex(), "authority": { "kind": "key", "key": authority_kp.public_key().to_hex() }, "mint_nonce": 0 },
                ],
            });
            // Two separate notes: a `wait: false` submission only marks its input pending (it
            // does not scan for the change), so the mint and the rotation below each need their
            // own spendable note rather than sharing one via unseen change.
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let row = |index: u32| {
            let c = chain.lock().unwrap();
            c.tokens["tokens"].as_array().unwrap().iter().find(|r| r["index"].as_u64() == Some(index as u64)).unwrap().clone()
        };

        // A non-`Key` token refuses a mint and a rotation alike, before any network read past the
        // registry itself.
        let e = build_token_mint(&rpc, &me, 7, 1, &row(1), &me.address, 500, &authority_kp).await.unwrap_err().to_string();
        assert!(e.contains("not Key-authorised"), "{e}");
        let e = build_token_set_authority(7, 1, &row(1), &authority_kp, None).unwrap_err().to_string();
        assert!(e.contains("not Key-authorised"), "{e}");

        // A stranger's key is refused too, against the `Key` token.
        let stranger = Keypair::generate();
        let e = build_token_mint(&rpc, &me, 7, 2, &row(2), &me.address, 500, &stranger).await.unwrap_err().to_string();
        assert!(e.contains("not token 2's mint authority"), "{e}");

        // Zero moves nothing either way, refused before the registry is even read.
        let e = build_token_mint(&rpc, &me, 7, 2, &row(2), &me.address, 0, &authority_kp).await.unwrap_err().to_string();
        assert!(e.contains("zero"), "{e}");

        // The right key mints: `TokenMint` at `mint_nonce` 0, signed, riding a fee bundle.
        let action = build_token_mint(&rpc, &me, 7, 2, &row(2), &me.address, 500, &authority_kp).await.unwrap();
        assert!(matches!(&action, Action::TokenMint { asset: 2, amount: 500, nonce: 0, .. }));
        submit_token_mint_with(&rpc, &me, &mut store, action, gas::BUNDLE_BASE, Proving::Emulated, 7, false).await.unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert!(matches!(tx.action, Action::TokenMint { asset: 2, amount: 500, nonce: 0, .. }));

        // And hands the token on: `SetAuthority` at the same nonce it reads, signed by the
        // current key over the new one.
        let successor = Keypair::generate();
        let action = build_token_set_authority(7, 2, &row(2), &authority_kp, Some(successor.public_key().clone())).unwrap();
        assert!(matches!(&action, Action::SetAuthority { asset: 2, new: Some(pk), nonce: 0, .. } if *pk == *successor.public_key()));
        submit_token_set_authority_with(&rpc, &me, &mut store, action, gas::BUNDLE_BASE, Proving::Emulated, 7, false).await.unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert!(matches!(tx.action, Action::SetAuthority { asset: 2, new: Some(_), .. }));

        // A submission of anything but the right variant is refused outright.
        let e = submit_token_mint_with(&rpc, &me, &mut store, Action::None, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("TokenMint"), "{e}");
        let e = submit_token_set_authority_with(&rpc, &me, &mut store, Action::None, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("SetAuthority"), "{e}");
    }

    /// Every bridge command's action — a deposit's and a rotation's `BridgeAttest`, a
    /// `RegisterBridgedToken`, a `ListBacking` — rides one fee bundle built by the shared path: the
    /// fee in RAND from slots 2–3, slots 0–1 dummies, nothing burned, the proof bound to the whole
    /// transaction, PQ co-signatures included (swap them after proving and the proof no longer
    /// verifies). Any other action is refused before anything is read or proved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_bridge_action_rides_a_rand_fee_bundle_bound_to_its_pq_quorum() {
        use randprotocol_core::bridge::PqSignature;
        let me = Wallet::from_spend_key(SpendKey([54; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        for _ in 0..8 {
            chain.lock().unwrap().fund(&me, 3 * gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let pq = || vec![PqSignature { index: 0, signature: vec![0xab; 16] }, PqSignature { index: 2, signature: vec![0xcd; 16] }];
        let empty = Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] };
        let actions = vec![
            Action::BridgeAttest {
                attestation: transfer_attestation(1_000, me.address.recipient_hash()),
                recipient: me.address.clone(),
                r: [9; 8],
                time: 1,
                asset: 3,
                envelope: garbage(),
                pq_signatures: pq(),
            },
            Action::BridgeAttest {
                attestation: rotation_attestation(),
                recipient: me.address.clone(),
                r: [0; 8],
                time: 1,
                asset: 0,
                envelope: empty,
                pq_signatures: pq(),
            },
            Action::RegisterBridgedToken {
                name: "Zed Dollar".into(),
                symbol: "ZUSD".into(),
                salt: [7; 32],
                chain: 2,
                token: [8; 32],
                decimals: 6,
                nonce: 0,
                pq_signatures: pq(),
            },
            Action::ListBacking { token_index: 3, chain: 5, token: [9; 32], decimals: 6, nonce: 1, pq_signatures: pq() },
        ];
        for (what, action) in ["deposit", "rotation", "register_bridged", "list_backing"].into_iter().zip(actions) {
            let s = submit_bridge_action_with(&rpc, &me, &mut store, action.clone(), gas::BUNDLE_BASE, Proving::Emulated, 7, false)
                .await
                .unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!((s.amount, s.asset, s.burn), (0, 0, Burn::None), "{what}");
            let tx = chain.lock().unwrap().sent.pop().unwrap();
            assert_admissible_shape(&tx);
            assert_eq!(tx.action, action, "{what}: the action is carried as built");
            let b = tx.bundle.as_ref().unwrap();
            assert_eq!((b.fee, b.burn_a, b.burn_r, b.burn_asset), (gas::BUNDLE_BASE, 0, 0, 0), "{what}");
            let mine = slots_for(&me, &tx);
            assert!(opens_to_nobody(&mine[0]) && opens_to_nobody(&mine[1]), "{what}: slots 0-1 are dummies: {mine:?}");
            assert!(matches!(mine[3], Found::Received(n) if n.asset == 0 && n.amount > 0), "{what}: RAND change in slot 3: {mine:?}");
            // The PQ quorum is inside the binding: a relayer cannot swap it after the proof.
            let mut swapped = tx.clone();
            match &mut swapped.action {
                Action::BridgeAttest { pq_signatures, .. }
                | Action::RegisterBridgedToken { pq_signatures, .. }
                | Action::ListBacking { pq_signatures, .. } => pq_signatures[1].signature[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(StubExecutor.verify_bundle(&EMULATED_HC, &b.proof, &swapped.binding()).is_err(), "{what}: a swapped quorum unbinds the proof");
        }
        let e = submit_bridge_action_with(&rpc, &me, &mut store, Action::None, gas::BUNDLE_BASE, Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("nothing else"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty());
    }

    /// A bond burns RAND through `burn_r`, never `burn_a`, and names no asset.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bond_burns_rand_through_burn_r() {
        let me = Wallet::from_spend_key(SpendKey([51; 8]));
        let chain = Arc::new(Mutex::new(FakeChain::new()));
        chain.lock().unwrap().fund(&me, 10_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let action = Action::Bond { validator: randprotocol_core::Keypair::generate().address(), amount: 4_000_000, registration: None };
        let s = submit_with(&rpc, &me, &mut store, None, action, gas::BUNDLE_BASE, Burn::Rand(4_000_000), Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!((s.amount, s.change, s.burn), (0, 6_000_000 - gas::BUNDLE_BASE, Burn::Rand(4_000_000)));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!((b.burn_a, b.burn_r, b.burn_asset), (0, 4_000_000, 0));
    }

    /// One plan covers both groups, largest-first and at most two notes each; a RAND bundle uses
    /// the RAND slots alone; and the change of each group is what its inputs held over its need.
    #[test]
    fn the_plan_selects_both_groups_largest_first() {
        let me = Wallet::from_spend_key(SpendKey([52; 8]));
        let you = Wallet::from_spend_key(SpendKey([53; 8]));
        let store = NoteStore {
            notes: vec![
                owned_asset(0, 50, false, 7),
                owned_asset(1, 30, false, 7),
                owned_asset(2, 10, false, 7),
                owned_asset(3, 4, false, 0),
                owned_asset(4, 9, false, 0),
            ],
            ..NoteStore::default()
        };
        let spend = |asset, amount, fee| Spend { asset, to: Some((&you.address, amount)), fee, burn_a: 0, burn_r: 0 };
        let plan = Plan::select(&store, spend(7, 60, 5)).unwrap();
        assert_eq!(plan.a_notes.iter().map(|n| n.index).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(plan.r_notes.iter().map(|n| n.index).collect::<Vec<_>>(), vec![4]);
        assert_eq!((plan.change_a(), plan.change_r()), (20, 4));
        let slots = plan.outputs();
        assert_eq!(slots[0], (Payee::To(you.address.clone()), 60));
        assert_eq!(slots[1], (Payee::Me, 20));
        assert_eq!(slots[2], (Payee::Me, 4));
        assert_eq!(slots[3], (Payee::Nobody, 0));
        // A RAND payment: both RAND notes in slots 2–3, and slots 0–1 empty.
        let plan = Plan::select(&store, spend(0, 10, 3)).unwrap();
        assert!(plan.a_notes.is_empty());
        assert_eq!(plan.r_notes.iter().map(|n| n.index).collect::<Vec<_>>(), vec![4, 3]);
        assert_eq!(plan.outputs()[2], (Payee::To(you.address.clone()), 10));
        assert_eq!(plan.outputs()[3], (Payee::Nobody, 0), "13 in, 10 + 3 out: no change, so a dummy");
        // Three notes of the token would be needed: a group spends two at most.
        assert!(Plan::select(&store, spend(7, 85, 5)).unwrap_err().to_string().contains("consolidate"));
        // A RAND burn through `burn_a` is never planned.
        let bad = Spend { asset: 0, to: None, fee: 1, burn_a: 1, burn_r: 0 };
        assert!(Plan::select(&store, bad).is_err());
        let _ = me;
    }

    /// `--asset`: a number is the index as it stands and never reaches the node; a token id is
    /// found in the whole registry listing (`rand_getTokens`), never by a per-token lookup that
    /// would name the token about to move; a node without the listing is told to take the index.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_asset_is_an_index_or_a_token_id_found_in_the_whole_registry() {
        let asked = Arc::new(Mutex::new(Vec::<(String, serde_json::Value)>::new()));
        let log = asked.clone();
        let rows = serde_json::json!([
            { "index": 1, "id": "aa".repeat(32), "id_text": "rpl1first" },
            { "index": 5, "id": "bb".repeat(32), "id_text": "rpl1fifth" },
        ]);
        let rpc = RpcClient::new(
            rpc_fn(move |m, p| {
                log.lock().unwrap().push((m.to_string(), p.clone()));
                match m {
                    "rand_getTokens" => Reply::Ok(rows.clone()),
                    _ => Reply::Err(-32601, "unknown method"),
                }
            })
            .await,
        );
        assert_eq!(resolve_asset(&rpc, "0").await.unwrap(), 0);
        assert_eq!(resolve_asset(&rpc, "7").await.unwrap(), 7);
        assert!(asked.lock().unwrap().is_empty(), "a number never reaches the node");
        assert_eq!(resolve_asset(&rpc, "rpl1fifth").await.unwrap(), 5);
        assert_eq!(resolve_asset(&rpc, &format!("0x{}", "AA".repeat(32))).await.unwrap(), 1);
        assert!(resolve_asset(&rpc, "rpl1nothere").await.unwrap_err().to_string().contains("no token rpl1nothere"));
        // Every request was the same whole-registry page: nothing in any of them names a token.
        for (method, params) in asked.lock().unwrap().iter() {
            assert_eq!((method.as_str(), params), ("rand_getTokens", &serde_json::json!([0, TOKEN_PAGE])));
        }
        let older = RpcClient::new(crate::test_rpc::scripted_rpc(vec![]).await);
        let e = resolve_asset(&older, "rpl1fifth").await.unwrap_err().to_string();
        assert!(e.contains("registry index instead"), "{e}");
    }

    /// `find_token_row` — `rand token info`'s reader, and `token mint`/`set-authority`'s way to
    /// the row's `mint_nonce` and authority — matches by index, hex id or `rpl1…`, exactly as
    /// `resolve_asset` does, and only ever calls `rand_getTokens`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn find_token_row_matches_index_hex_or_rpl1_over_the_whole_listing() {
        let asked = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = asked.clone();
        let rows = serde_json::json!({
            "enabled": true,
            "tokens": [
                { "index": 1, "id": "aa".repeat(32), "id_text": "rpl1first", "authority": { "kind": "key", "key": "k1" }, "mint_nonce": 3 },
                { "index": 5, "id": "bb".repeat(32), "id_text": "rpl1fifth", "authority": { "kind": "none" }, "mint_nonce": 0 },
            ],
        });
        let rpc = RpcClient::new(
            rpc_fn(move |m, _p| {
                log.lock().unwrap().push(m.to_string());
                match m {
                    "rand_getTokens" => Reply::Ok(rows.clone()),
                    _ => Reply::Err(-32601, "unknown method"),
                }
            })
            .await,
        );
        assert_eq!(find_token_row(&rpc, "1").await.unwrap()["mint_nonce"], 3);
        assert_eq!(find_token_row(&rpc, "rpl1fifth").await.unwrap()["index"], 5);
        assert_eq!(find_token_row(&rpc, &format!("0x{}", "AA".repeat(32))).await.unwrap()["index"], 1);
        assert!(find_token_row(&rpc, "9").await.unwrap_err().to_string().contains("no token 9"));
        assert!(asked.lock().unwrap().iter().all(|m| m == "rand_getTokens"), "never a per-token lookup");
    }

    /// Every dummy is fresh: two bundles built from the same plan share no nullifier and no
    /// commitment, and inside one bundle the four of each are distinct (the ledger's rule, and the
    /// guest's taint).
    #[test]
    fn every_dummy_is_fresh() {
        let me = Wallet::from_spend_key(SpendKey([54; 8]));
        let mut tree = randprotocol_zkvm::ledger::CommitmentTree::new();
        let note = Note::new(me.vk.pk(), [1; 8], 50, 0, 1);
        tree.append(note.commitment());
        let store = NoteStore {
            notes: vec![OwnedNote { index: 0, cm: note.commitment(), nf: me.vk.nullifier(&note.commitment()), note, spent: false, pending: None, height: 1 }],
            ..NoteStore::default()
        };
        let plan = Plan::select(&store, Spend { asset: 0, to: None, fee: 50, burn_a: 0, burn_r: 0 }).unwrap();
        let build = || build_bundle(&me, &plan, tree.root(), &[tree.path(0)], 2).unwrap();
        let (one, two) = (build(), build());
        for k in 0..SLOTS {
            if k != 2 {
                assert!(!two.bundle.nullifiers.contains(&one.bundle.nullifiers[k]), "dummy input {k} repeated");
            }
            assert!(!two.bundle.commitments.contains(&one.bundle.commitments[k]), "output {k} repeated");
        }
        assert_eq!(one.bundle.nullifiers[2], two.bundle.nullifiers[2], "the real input is the same note both times");
        // The blinding itself, not only the throwaway key a dummy is owned by: every output's `r`
        // is drawn afresh, in one bundle and across two.
        use randprotocol_zkvm::hidden::hidden_input::{out, O_R};
        let r = |p: &Prepared, k: usize| p.words[out(k) + O_R..out(k) + O_R + 8].to_vec();
        let all: Vec<Vec<u32>> = (0..SLOTS).flat_map(|k| [r(&one, k), r(&two, k)]).collect();
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j], "two outputs share a blinding");
            }
        }
        // And the witness is one the guest accepts: every output a dummy, the one input real.
        let run = randprotocol_zkvm::emulator::execute(ZkExecutor::hidden_bundle_program(), &one.words, &[0; TX_BINDING_WORDS], 1 << 20).unwrap();
        assert_eq!(run.outputs, one.expected);
    }

    #[test]
    fn the_fee_defaults_are_the_schedule_floors_and_no_more() {
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x13; 40], public: vec![] };
        assert_eq!(deploy_fee_default(&deploy), gas::fee_floor(&deploy));
        assert_eq!(deploy_fee_default(&deploy), gas::BUNDLE_BASE + gas::deploy_fee(40));
        for tier in [10u8, 12, 14, 20] {
            assert_eq!(call_fee_default(tier, 0), gas::BUNDLE_BASE + gas::call_fee(tier, 0));
            // The floor `Ledger::validate_inner` applies, not a cent over it: adding
            // `fee_floor(Call)` to `call_fee` would double-count `CALL_BASE`.
            let floor = gas::fee_floor(&Action::Call { program: randprotocol_core::Hash::ZERO, proof: vec![], input_envelope: None });
            let doubled = floor + gas::call_fee(tier, 0);
            assert_eq!(doubled - call_fee_default(tier, 0), gas::CALL_BASE, "tier {tier}");
            // The byte term (spec §7): nothing at or under the free allowance, so every call a
            // chain-12 node admits pays what it paid before, and `CALL_PER_KIB` per KiB past it.
            assert_eq!(call_fee_default(tier, gas::CALL_FREE_BYTES), call_fee_default(tier, 0));
            assert_eq!(call_fee_default(tier, gas::CALL_FREE_BYTES + 1024), call_fee_default(tier, 0) + gas::CALL_PER_KIB);
            assert_eq!(
                call_fee_default(tier, 5 << 20),
                gas::BUNDLE_BASE + gas::call_fee(tier, 5 << 20),
                "the wallet pays the ledger's step-10 floor exactly"
            );
        }
        // A burn pays the bridge fee, the schedule's floor for it.
        let burn = Action::BridgeBurn {
            asset: 3,
            amount: 400,
            relayer_fee: 100,
            to_chain: 2,
            token: [9; 32],
            to: [0; 32],
        };
        assert_eq!(burn_fee_default(), gas::fee_floor(&burn));
        assert_eq!(burn_fee_default(), gas::BRIDGE_BURN_FEE);
    }

    /// The three things a burn is refused for before it costs anything: RAND, which is not a
    /// bridged asset at all; a burn of nothing; and a relayer fee larger than the burn. Refused
    /// before the wallet so much as reads the chain, which is the point — everything after that
    /// point is a bundle proof.
    #[tokio::test]
    async fn a_burn_that_could_never_be_admitted_is_refused_before_any_proving() {
        // Pointed at a port nothing listens on: reaching the network at all is the failure this
        // test is looking for, and it would show up as a connection error instead.
        let attempt = |asset: u32, amount: u64, relayer_fee: u64| async move {
            let rpc = RpcClient::new("http://127.0.0.1:1");
            let w = Wallet::from_spend_key(SpendKey([31; 8]));
            let mut store = NoteStore::default();
            submit_burn(
                &rpc,
                &w,
                &mut store,
                asset,
                amount,
                relayer_fee,
                2,
                [0xaa; 32],
                [1; 32],
                burn_fee_default(),
                FriProfile::Test,
                Backend::Cpu,
                7,
                false,
            )
            .await
            .expect_err("refused")
            .to_string()
        };
        assert!(attempt(0, 100, 0).await.contains("not a bridged asset"));
        assert!(attempt(1, 0, 0).await.contains("moves nothing"));
        assert!(attempt(1, 100, 101).await.contains("more than the 100"));
    }

    /// A minimal one-shot JSON-RPC mock: answers exactly one HTTP request with `body`, no delay.
    /// Adapted from `RpcClient`'s own `slow_server` test helper (`lib.rs`) with the artificial
    /// delay dropped — this is only ever used to hand back an error reply fast, never to test
    /// timing.
    async fn one_shot_rpc(body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 16 * 1024];
            let header_end = loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
            let len: usize = headers
                .split("content-length:")
                .nth(1)
                .and_then(|r| r.split("\r\n").next())
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut got = buf.len() - header_end;
            while got < len {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                got += n;
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
        format!("http://{addr}")
    }

    /// `deploy_precheck` is the wallet's whole defence against paying for a proof the chain will
    /// then refuse: it is one `rand_estimateFee` call, made before any bundle is proved, and it
    /// surfaces the node's own cap-naming message rather than inventing its own. Modelled on
    /// `rand_estimateFee`'s actual reply for an over-cap deploy (`randprotocol-node/src/rpc.rs`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_over_cap_deploy_is_refused_by_one_fee_estimate_before_any_proving() {
        let reply = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"words must be at most 4096 (this chain's program cap)"}}"#;
        let url = one_shot_rpc(reply).await;
        let rpc = RpcClient::new(url);
        let err = deploy_precheck(&rpc, 5000, 0).await.expect_err("refused").to_string();
        assert!(err.contains("at most 4096"), "{err}");
        assert!(err.contains("program cap"), "{err}");
    }

    /// And a program within the cap is not refused: the estimate comes back as the fee.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_in_cap_deploy_gets_back_the_fee_estimate() {
        let reply = r#"{"jsonrpc":"2.0","id":1,"result":"1000000"}"#;
        let url = one_shot_rpc(reply).await;
        let rpc = RpcClient::new(url);
        assert_eq!(deploy_precheck(&rpc, 100, 0).await.unwrap(), 1_000_000);
    }

    #[test]
    fn a_pending_note_is_held_back_but_not_spent() {
        let mut store = NoteStore { notes: vec![owned(0, 5, false), owned(1, 3, false)], ..NoteStore::default() };
        store.notes[1].pending = Some(9);
        assert_eq!(store.balance(), 5, "a pending note buys nothing while the chain has not answered");
        assert_eq!(store.spendable().len(), 1);
        // ...and unlike `spent`, it is not a one-way write: clearing it restores the note.
        store.notes[1].pending = None;
        assert_eq!(store.balance(), 8);
    }

    /// The scan cursor must move on a chain that publishes no further nullifiers, or a note left
    /// pending by a `--no-wait` submission never clears and stays out of coin selection forever.
    #[test]
    fn the_scan_cursor_advances_past_the_head_even_when_no_block_spends() {
        // Quiet chain: the pages returned nothing, so `paged_to` is the cursor unmoved. The head
        // read before the pages is what says how far the scan actually got.
        assert_eq!(advance_scanned_height(4, 4, 40), 41);
        // A busy chain moves the cursor past the head only if a spend landed above it while the
        // pages were in flight; the higher of the two wins either way.
        assert_eq!(advance_scanned_height(4, 39, 40), 41);
        assert_eq!(advance_scanned_height(4, 44, 40), 44);
        // The cursor never goes backwards: a node that answers from behind our own store (a
        // lagging peer, a fresh replica) must not re-open blocks we have already accounted for.
        assert_eq!(advance_scanned_height(50, 4, 7), 50);
        // Genesis: nothing read yet, head 0 — block 0 has been read, block 1 has not.
        assert_eq!(advance_scanned_height(0, 0, 0), 1);
        assert_eq!(advance_scanned_height(0, 0, u64::MAX), u64::MAX);
    }

    /// The pending rule itself, against what the scan read rather than a fresh head.
    #[test]
    fn pending_clears_once_the_blocks_read_pass_the_time_window() {
        let pending_at = |time: u32, spent: bool| {
            let mut n = owned(0, 5, spent);
            n.pending = Some(time);
            NoteStore { notes: vec![n], ..NoteStore::default() }
        };

        // One block short of the last height at which the bundle could still be admitted.
        let mut store = pending_at(9, false);
        clear_pending(&mut store, 9 + TIME_WINDOW);
        assert_eq!(store.notes[0].pending, Some(9), "the bundle can still commit at this height");
        assert_eq!(store.balance(), 0);

        // One past it: the submission can never be admitted now, so the note is free again.
        clear_pending(&mut store, 9 + TIME_WINDOW + 1);
        assert_eq!(store.notes[0].pending, None);
        assert_eq!(store.balance(), 5);

        // A spend that did land clears the mark immediately, whatever the height reached.
        let mut store = pending_at(9, true);
        clear_pending(&mut store, 0);
        assert_eq!(store.notes[0].pending, None);
        assert_eq!(store.balance(), 0, "but a spent note is still spent");
    }

    #[test]
    fn the_note_store_roundtrips_through_its_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("w.key.json");
        let path = store_path(&key);
        assert_eq!(path.file_name().unwrap(), "w.key.json.notes.json");
        // A missing store is an empty one: every row in it is recoverable by rescanning.
        assert_eq!(NoteStore::load(&path).scanned_index, 0);
        let store = NoteStore {
            scanned_index: 9,
            scanned_height: 4,
            scanned_attest_height: 5,
            notes: vec![owned(0, 5, false), owned(1, 3, true)],
            sent: vec![SentRow { index: 7, to_pk: [4; 8], amount: 11, height: 2 }],
        };
        store.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // The store holds every note plaintext this wallet knows; it is as private as the key.
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert!(!path.with_extension("json.tmp").exists(), "the temp file is renamed away");
        }
        // Saving over an existing store replaces it (and keeps the mode).
        store.save(&path).unwrap();
        let back = NoteStore::load(&path);
        assert_eq!(back.scanned_index, 9);
        assert_eq!(back.scanned_height, 4);
        assert_eq!(back.scanned_attest_height, 5, "the deposit-rebuild cursor survives the round trip");
        assert_eq!(back.notes.len(), 2);
        assert_eq!(back.notes[0].note, store.notes[0].note);
        assert_eq!(back.notes[1].spent, true);
        assert_eq!(back.sent[0].amount, 11);
        assert_eq!(back.balance(), 5);
    }

    // ---------------------------------------------------------------- keys a holder hands out

    #[test]
    fn the_viewing_key_is_nk_as_the_node_imports_it() {
        let w = Wallet::from_spend_key(SpendKey([11; 8]));
        let hex = w.viewing_key_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(word8_from_hex(&hex), Some(w.vk.nk), "rand_importViewingKey parses exactly this");
        assert_ne!(hex, Wallet::from_spend_key(SpendKey([12; 8])).viewing_key_hex());
    }

    /// A payment from `me` to `you` with change back to `me`, each output under its own key, in
    /// slots 0–1 of a four-slot bundle; slots 2–3 carry envelopes nobody can open (stand-ins for
    /// the dummies `build_bundle` seals to a throwaway key).
    fn payment(me: &Wallet, you: &Wallet) -> (Transaction, TxKey, TxKey, Note, Note) {
        let pay = Note::new(you.vk.pk(), me.vk.pk(), 7, 0, 1);
        let change = Note::new(me.vk.pk(), me.vk.pk(), 3, 0, 1);
        let (k_pay, k_change) = (TxKey::random(), TxKey::random());
        let bundle = Bundle {
            anchor: [0; 8],
            nullifiers: [[1; 8], [2; 8], [3; 8], [4; 8]],
            commitments: [pay.commitment(), change.commitment(), [5; 8], [6; 8]],
            fee: 1,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 1,
            envelopes: [
                seal_note(&me.vk, &you.address, &pay, &k_pay).unwrap(),
                seal_note(&me.vk, &me.address, &change, &k_change).unwrap(),
                env(),
                env(),
            ],
            proof: vec![],
        };
        (Transaction::shielded(7, bundle, Action::None), k_pay, k_change, pay, change)
    }

    #[test]
    fn the_sender_recovers_each_outputs_key_from_the_chain_alone() {
        let (me, you) = (Wallet::from_spend_key(SpendKey([11; 8])), Wallet::from_spend_key(SpendKey([12; 8])));
        let (tx, k_pay, k_change, pay, change) = payment(&me, &you);
        let rows = output_keys(&me, &tx);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!((rows[0].output, rows[0].slot, rows[0].role), ("bundle", 0, KeyRole::Sent));
        assert_eq!((rows[0].key, rows[0].note.clone()), (k_pay, pay.clone()));
        assert_eq!((rows[1].output, rows[1].slot, rows[1].role), ("bundle", 1, KeyRole::Change));
        assert_eq!((rows[1].key, rows[1].note.clone()), (k_change, change));
        // The recovered key is the disclosure key: it opens that output and no other.
        let env = envelope_from_core(&tx.bundle.as_ref().unwrap().envelopes[0]);
        assert_eq!(env.open_with_tx_key(pay.commitment(), &rows[0].key), Some(pay));
        let other = envelope_from_core(&tx.bundle.as_ref().unwrap().envelopes[1]);
        assert_eq!(other.open_with_tx_key(rows[1].note.commitment(), &rows[0].key), None);
    }

    #[test]
    fn the_receiver_recovers_the_same_key_and_a_stranger_recovers_none() {
        let (me, you) = (Wallet::from_spend_key(SpendKey([11; 8])), Wallet::from_spend_key(SpendKey([12; 8])));
        let (tx, k_pay, _, pay, _) = payment(&me, &you);
        let rows = output_keys(&you, &tx);
        assert_eq!(rows.len(), 1, "the change is none of the receiver's business: {rows:?}");
        assert_eq!((rows[0].role, rows[0].key, rows[0].note.clone()), (KeyRole::Received, k_pay, pay));
        assert!(output_keys(&Wallet::from_spend_key(SpendKey([13; 8])), &tx).is_empty());
    }

    #[test]
    fn a_faucet_mint_is_an_output_its_recipient_can_key() {
        let (minter, me) = (Wallet::from_spend_key(SpendKey([14; 8])), Wallet::from_spend_key(SpendKey([11; 8])));
        let note = Note::new(me.vk.pk(), [0; 8], 100, 0, 1);
        let k = TxKey::random();
        let env = seal_note(&minter.vk, &me.address, &note, &k).unwrap();
        let ex = randprotocol_zkvm::executor::ZkExecutor::new(FriProfile::Test);
        let tx = Transaction::mint(7, note.pk, note.time, note.r, env, 100, &randprotocol_core::Keypair::generate(), &ex);
        let rows = output_keys(&me, &tx);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].output, rows[0].slot, rows[0].role, rows[0].key), ("mint", 0, KeyRole::Received, k));
    }


    // ---------------------------------------------------- the call limits (Task 5)

    fn limits(max_call_envelope_bytes: usize, max_proof_bytes: usize) -> ChainLimits {
        ChainLimits {
            max_program_words: 4096,
            max_proof_bytes,
            max_block_bytes: 4 << 20,
            max_call_envelope_bytes,
            max_program_public_words: 64,
        }
    }

    /// The input cap comes from the chain's envelope cap, less the envelope's fixed overhead, over
    /// four; a node without `rand_getLimits` gets the old 4 096 words under the default byte cap.
    #[test]
    fn the_call_caps_derive_from_the_chains_limits_and_fall_back_to_4096_words() {
        use randprotocol_zkvm::call_envelope::{CallCaps, ENVELOPE_FIXED_BYTES};
        assert_eq!(call_caps(None), CallCaps { max_input_words: 4096, max_envelope_bytes: 18_432 });
        assert_eq!(call_caps(Some(&limits(18_432, 2 << 20))), CallCaps { max_input_words: 4295, max_envelope_bytes: 18_432 });
        let raised = call_caps(Some(&limits(65_536, 8 << 20)));
        assert_eq!(raised, CallCaps { max_input_words: (65_536 - ENVELOPE_FIXED_BYTES) / 4, max_envelope_bytes: 65_536 });
        assert_eq!(raised.max_input_words, 16_071, "chain 13's 65 536-byte envelope admits SPL's 10 458 private words");

        assert_eq!(proof_cap(None), gas::MAX_PROOF_BYTES);
        assert_eq!(proof_cap(Some(&limits(18_432, 8 << 20))), 8 << 20);
    }

    /// The proof-size pre-check, at the boundary: exactly the cap is fine, one byte over is refused
    /// with both numbers named — before the bundle that would pay for it is proved.
    #[test]
    fn a_proof_over_the_chains_cap_is_refused_before_submitting() {
        check_proof_size(2 << 20, 2 << 20).expect("exactly at the cap");
        let e = check_proof_size((2 << 20) + 1, 2 << 20).unwrap_err().to_string();
        assert!(e.contains("2097153") && e.contains("2097152") && e.contains("max_proof_bytes"), "{e}");
    }

    /// `--public <file>` as words: whitespace-separated u32s, decimal or `0x` hex, any layout.
    #[test]
    fn a_public_file_of_words_parses() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("public.txt");
        std::fs::write(&p, "1 2\n0x10\t4294967295\n").unwrap();
        assert_eq!(public_file_words(&p).unwrap(), vec![1, 2, 16, u32::MAX]);
        std::fs::write(&p, "1 two").unwrap();
        assert!(public_file_words(&p).unwrap_err().to_string().contains("two"));
        std::fs::write(&p, "4294967296").unwrap();
        assert!(public_file_words(&p).is_err(), "over u32");
        std::fs::write(&p, " \n").unwrap();
        assert!(public_file_words(&p).unwrap_err().to_string().contains("no words"));
        assert!(public_file_words(&dir.path().join("missing")).is_err());
    }

    /// `--public <file.so>`: the ELF is word-encoded exactly as research's
    /// `SbpfCall::public_words` does — its byte length, then its bytes four per word,
    /// little-endian, zero-padded. The committed SPL Token ELF is 108 600 bytes, so 27 151 words.
    #[test]
    fn a_public_elf_is_word_encoded_as_the_sbpf_guest_reads_it() {
        use randprotocol_zkvm::sbpf::{SbpfCall, SPL_TOKEN_ELF};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("spl_token.so");
        std::fs::write(&p, SPL_TOKEN_ELF).unwrap();
        let words = public_file_words(&p).unwrap();
        assert_eq!(words.len(), 27_151);
        assert_eq!(&words[..8], &[108_600, 1_179_403_647, 65_794, 0, 0, 17_235_971, 1, 2_088]);
        assert_eq!(words, SbpfCall { elf: SPL_TOKEN_ELF.to_vec(), input: vec![] }.public_words());
        // The ELF magic decides, not only the extension.
        let bare = dir.path().join("program");
        std::fs::write(&bare, SPL_TOKEN_ELF).unwrap();
        assert_eq!(public_file_words(&bare).unwrap(), words);
        // A zero-padded tail: 5 bytes are the length and two words.
        assert_eq!(elf_public_words(&[0x7f, b'E', b'L', b'F', 9]), vec![5, 0x464c_457f, 9]);
        // A `.so` that is not an ELF is an error, not a text file of words.
        let fake = dir.path().join("fake.so");
        std::fs::write(&fake, "1 2 3").unwrap();
        assert!(public_file_words(&fake).unwrap_err().to_string().contains("ELF"));
    }

    /// The deploy pre-check with a public input: over this chain's cap it is refused from
    /// `rand_getLimits` before any proof, and a node without `rand_getLimits` predates public
    /// inputs altogether. Within the cap the fee estimate names the public words.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deploys_public_input_is_checked_against_the_chains_cap() {
        use crate::test_rpc::{scripted_rpc, Reply};
        let limits = serde_json::json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64
        });
        let rpc = RpcClient::new(
            scripted_rpc(vec![("rand_getLimits", Reply::Ok(limits.clone())), ("rand_estimateFee", Reply::Ok(serde_json::json!("7400000")))])
                .await,
        );
        assert_eq!(deploy_precheck(&rpc, 10, 64).await.unwrap(), 7_400_000);
        let e = deploy_precheck(&rpc, 10, 65).await.unwrap_err().to_string();
        assert!(e.contains("65") && e.contains("64") && e.contains("max_program_public_words"), "{e}");

        let mut closed = limits.clone();
        closed["max_program_public_words"] = serde_json::json!(0);
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(closed))]).await);
        let e = deploy_precheck(&rpc, 10, 1).await.unwrap_err().to_string();
        assert!(e.contains("admits no public input"), "{e}");

        let older = RpcClient::new(scripted_rpc(vec![("rand_estimateFee", Reply::Ok(serde_json::json!("2000000")))]).await);
        let e = deploy_precheck(&older, 10, 1).await.unwrap_err().to_string();
        assert!(e.contains("rand_getLimits"), "{e}");
        // Without a public input an older node is asked exactly what it always was.
        assert_eq!(deploy_precheck(&older, 10, 0).await.unwrap(), 2_000_000);
    }

    /// What a call proves over is what the chain holds, checked locally: the code and the public
    /// input the node serves must hash to the program id asked for. A node that serves a
    /// different public input would otherwise cost a whole proof the chain then refuses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_proves_over_the_public_input_the_program_id_commits_to() {
        use crate::test_rpc::{scripted_rpc, Reply};
        use randprotocol_core::program::program_id_with_public;
        let (base_pc, words, public) = (0u32, vec![0x13u32, 0x73], vec![1u32, 2, 3, 4]);
        let id = program_id_with_public(base_pc, &words, &public);
        let code = serde_json::json!({ "base_pc": base_pc, "words": words });
        let hex = |p: &[u32]| hex::encode(p.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>());
        let node = |public: &[u32]| {
            vec![("rand_getProgramCode", Reply::Ok(code.clone())), ("rand_getProgramPublic", Reply::Ok(serde_json::json!(hex(public))))]
        };

        let rpc = RpcClient::new(scripted_rpc(node(&public)).await);
        let (prog, got) = load_call_program(&rpc, &id).await.unwrap();
        assert_eq!((prog.base_pc, prog.words, got), (base_pc, words.clone(), public.clone()));

        let lying = RpcClient::new(scripted_rpc(node(&[1, 2, 3, 5])).await);
        let e = load_call_program(&lying, &id).await.unwrap_err().to_string();
        assert!(e.contains("do not hash to"), "{e}");
        let dropped = RpcClient::new(scripted_rpc(node(&[])).await);
        assert!(load_call_program(&dropped, &id).await.is_err(), "a public input the node forgets is caught too");

        // A plain program: no public input, and the old id rule.
        let plain = randprotocol_core::program::program_id(base_pc, &words);
        let rpc = RpcClient::new(scripted_rpc(node(&[])).await);
        assert_eq!(load_call_program(&rpc, &plain).await.unwrap().1, Vec::<u32>::new());
        // An unknown program is an error, not an empty public input.
        let none = RpcClient::new(
            scripted_rpc(vec![("rand_getProgramCode", Reply::Ok(serde_json::Value::Null)), ("rand_getProgramPublic", Reply::Ok(serde_json::Value::Null))])
                .await,
        );
        assert!(load_call_program(&none, &id).await.unwrap_err().to_string().contains("not found"));
    }

    /// `rand call --expect-public`: a caller who knows which public input it means to run against
    /// is refused before proving when the program on chain carries another one.
    #[test]
    fn an_expected_public_input_that_differs_is_refused_before_proving() {
        check_expected_public(&[1, 2, 3, 4], &[1, 2, 3, 4]).expect("the same words");
        let e = check_expected_public(&[1, 2, 3, 4], &[1, 2, 3, 5]).unwrap_err().to_string();
        assert!(e.contains("word 3"), "{e}");
        let e = check_expected_public(&[1, 2, 3, 4], &[1, 2, 3]).unwrap_err().to_string();
        assert!(e.contains("4 words") && e.contains("3"), "{e}");
    }

    /// Task 5b, the wallet's half: a burn is assembled whole — destination, relayer fee, the
    /// bundle's envelopes — before its bundle is proved, the bundle is proved with the finished
    /// transaction's own binding, and the proof lands in its slot. So the transaction the wallet
    /// submits verifies against the binding the ledger will recompute from it, and a copy with its
    /// destination changed does not. (A stub prover stands in for the minute of proving; the real
    /// one's binding is `tests/shielded.rs`'s in the zkVM crate.)
    #[test]
    fn a_submitted_transactions_proof_verifies_against_its_own_binding() {
        use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
        const HC: Word8 = [11; 8];
        let prepared = Prepared {
            bundle: Bundle {
                anchor: [1; 8],
                nullifiers: [[10; 8], [11; 8], [12; 8], [13; 8]],
                commitments: [[14; 8], [15; 8], [16; 8], [17; 8]],
                fee: gas::BRIDGE_BURN_FEE,
                burn_a: 400,
                burn_r: 0,
                burn_asset: 3,
                time: 9,
                envelopes: [env(), env(), env(), env()],
                proof: Vec::new(),
            },
            words: Vec::new(),
            expected: [0; 8],
        };
        let action = Action::BridgeBurn { asset: 3, amount: 400, relayer_fee: 100, to_chain: 2, token: [7; 32], to: [1; 32] };
        let mut tx = Transaction::shielded(13, prepared.bundle.clone(), action);
        let stub = |p: &Prepared, binding: &[u32; TX_BINDING_WORDS]| -> Result<Proved> {
            let d = StubExecutor.bundle_digest(&p.bundle.digest_input());
            Ok(Proved { proof: StubExecutor::make_bundle_proof(&HC, &d, binding), tier: 14, proving: Duration::ZERO })
        };
        prove_transaction(&mut tx, &prepared, &stub).unwrap();
        let binding = tx.binding();
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!(StubExecutor.bundle_proof_digest(&b.proof).unwrap(), StubExecutor.bundle_digest(&b.digest_input()));
        assert_eq!(StubExecutor.verify_bundle(&HC, &b.proof, &binding), Ok(()));
        // The copied-proof attack against what the wallet built: the destination changed, the
        // proof kept. It does not verify for the copy.
        let mut copy = tx.clone();
        let Action::BridgeBurn { to, .. } = &mut copy.action else { panic!("a burn") };
        *to = [2; 32];
        let refused = Err(ConfidentialError::InvalidBundleProof("PublicValues".into()));
        assert_eq!(StubExecutor.verify_bundle(&HC, &copy.bundle.as_ref().unwrap().proof, &copy.binding()), refused);
    }

}
