//! The shielded wallet: the key file, the note store, scanning, coin selection and sending.
//!
//! What a wallet is, on a redacted chain (design spec §11): a spend key, a cache of the notes
//! that key can open, and the ability to turn some of them into a proved 2-in-2-out bundle. The
//! chain answers no question about ownership — `shrugg_getCommitments` hands out every leaf and
//! every envelope to everyone, and only a viewing key tells the two apart — so scanning is a
//! local trial decryption of the whole tree, and a balance is a fact about this file, not about
//! the node.
//!
//! Nothing here ever sends a spend key, a viewing key or a note plaintext anywhere. What leaves
//! the process is exactly what a bundle publishes: an anchor, two nullifiers, two commitments,
//! the fee, and two envelopes nobody but their recipients can open.

use crate::{AssetRow, RpcClient};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use shrugg_core::bridge::{AssetId, Attestation, Payload};
use shrugg_core::ledger::{bridge_notes, TIME_WINDOW};
use shrugg_core::notes::{word8_from_hex, word8_to_hex, Bundle, Envelope, ShieldedAddress, Word8, DEPTH};
use shrugg_core::{gas, Action, Hash, Transaction};
use shrugg_zkvm::address::{address_of, envelope_from_core, seal_note};
use shrugg_zkvm::executor::prove_bundle;
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::notes::{bundle_inputs, expected_bundle_outputs, Note, SpendKey, ViewingKey};
use shrugg_zkvm::viewing::TxKey;
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
/// pure derivation of it (`shrugg_zkvm::notes`), so storing them would only widen what a
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

    /// Spendable SHRUGG. A zero-value note is a real note (a bundle whose change is zero still
    /// publishes a change output) but it buys nothing, so it is neither counted nor selected.
    pub fn balance(&self) -> u64 {
        self.balance_of(0)
    }

    /// The SHRUGG notes this wallet can spend — the only ones that can pay a fee.
    pub fn spendable(&self) -> Vec<&OwnedNote> {
        self.spendable_of(0)
    }

    /// Spendable value in one asset: 0 is SHRUGG, and every other index is a bridged asset as the
    /// registry numbered it (`shrugg_getAssets`).
    ///
    /// Never a sum across assets. A bundle balances one asset (the guest's own rule), so two
    /// assets added together are a number no transaction could ever spend — and on a chain where
    /// a bridged token's unit is not SHRUGG's, not even a number that means anything.
    pub fn balance_of(&self, asset: u32) -> u64 {
        self.spendable_of(asset).iter().map(|n| n.note.amount).sum()
    }

    pub fn spendable_of(&self, asset: u32) -> Vec<&OwnedNote> {
        self.notes.iter().filter(|n| n.is_spendable() && n.note.asset == asset).collect()
    }

    /// Every asset this wallet holds something in, ascending by index, with its balance. The rows
    /// `shrugg asset-balance` prints; an asset whose notes are all spent does not appear.
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

/// Decide what a single leaf is for `w`, with no I/O — the whole of [`scan`]'s per-row logic.
pub fn classify(w: &Wallet, cm: Word8, envelope: &Envelope) -> Found {
    let env = envelope_from_core(envelope);
    let mut why = "no key of this wallet opens it";
    if let Some((_, note)) = env.open_as_receiver(cm, &w.vk) {
        if note.pk == w.vk.pk() {
            return Found::Received(note);
        }
        why = "sealed to this wallet but owned by another key";
    }
    // Still worth the sender path: an envelope this wallet sealed for someone else is opened
    // through `ovk`, not through the KEM, so the two openings are independent.
    if let Some((_, note)) = env.open_as_sender(cm, &w.vk) {
        return Found::Sent(note);
    }
    Found::Skipped(why)
}

/// Trial-decrypt every commitment this wallet has not seen yet, then mark as spent every note
/// whose nullifier the chain has published. Advances the store and saves nothing — the caller
/// owns the file.
pub async fn scan(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore) -> Result<()> {
    loop {
        let rows = rpc.commitments(store.scanned_index, PAGE).await?;
        if rows.is_empty() {
            break;
        }
        let before = store.scanned_index;
        for row in &rows {
            match classify(w, row.cm, &row.envelope) {
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
                    if why != "no key of this wallet opens it" {
                        eprintln!("warning: ignoring leaf {}: {why}", row.index);
                    }
                }
            }
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
    /// The wallet holds enough, but not in two notes. Consolidate first: a bundle spends
    /// exactly two inputs (design spec §3), so no amount of dust adds up to a third slot.
    #[error("need more than two notes; the largest two hold {largest_two} units — consolidate first")]
    NeedsMoreThanTwo { largest_two: u64 },
    #[error("insufficient balance: {have} units")]
    Insufficient { have: u64 },
}

/// Largest-first, at most two notes: take the biggest note, then the next biggest if the first
/// does not cover `need`. Largest-first minimises the number of notes a wallet fragments into,
/// which matters more here than change minimisation — a two-input bundle cannot spend a third
/// note, so a wallet that shreds itself into dust becomes unspendable.
///
/// One asset at a time: `spendable` is what `NoteStore::spendable_of` returned for a single asset,
/// and this does not look at the field — a bundle balances one asset, so a mixed list would select
/// notes that cannot go in one bundle at all.
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

/// What a submitted transaction did, for the caller to print.
///
/// A `BridgeBurn` carries two bundles, and its figures are the *asset* bundle's: `amount` is what
/// left the pool (the burn), `change` what came back as a note, `asset` the index both are
/// denominated in. `fee` is always the SHRUGG the fee bundle paid. With two proofs, `tier` is the
/// larger of the two and `proof_bytes`/`proving` are the totals.
#[derive(Clone, Debug)]
pub struct Submission {
    pub hash: Hash,
    pub amount: u64,
    pub change: u64,
    pub fee: u64,
    pub time: u32,
    pub asset: u32,
    pub tier: u8,
    pub proof_bytes: usize,
    pub proving: Duration,
}

/// One bundle of a transaction as the wallet plans it, before any witness or proof: the notes it
/// spends, the payment its first output carries, and the three words that say what kind of bundle
/// it is.
///
/// Every transaction has exactly one of these except a `BridgeBurn`, which has two (spec §10): a
/// SHRUGG bundle that pays the fee and an asset bundle that burns.
struct Plan {
    /// One or two notes, all of `asset`; a second slot the wallet does not need becomes a dummy.
    chosen: Vec<OwnedNote>,
    dest: ShieldedAddress,
    amount: u64,
    fee: u64,
    burn: u64,
    asset: u32,
    /// `amount + fee + burn` — what the chosen notes had to cover.
    need: u64,
}

impl Plan {
    /// Select the notes of one asset that cover what this bundle pays out. A bundle that pays
    /// nobody inside the pool (a deploy, a call, a burn) sends zero to this wallet's own address,
    /// which is what `dest = &w.address, amount = 0` means.
    ///
    /// Only ever one asset's notes: SHRUGG cannot pay a burn of a bridged asset, nor the reverse,
    /// and a bundle balances one asset (`NoteStore::spendable_of`).
    fn select(
        store: &NoteStore,
        asset: u32,
        dest: &ShieldedAddress,
        amount: u64,
        fee: u64,
        burn: u64,
    ) -> Result<Plan> {
        let need = amount
            .checked_add(fee)
            .and_then(|n| n.checked_add(burn))
            .ok_or_else(|| anyhow!("amount + fee + burn overflows"))?;
        let chosen = select_inputs(&store.spendable_of(asset), need)?;
        Ok(Plan { chosen, dest: dest.clone(), amount, fee, burn, asset, need })
    }

    /// What comes back as this wallet's own note: everything the inputs held over `need`.
    fn change(&self) -> u64 {
        self.chosen.iter().map(|n| n.note.amount).sum::<u64>() - self.need
    }
}

/// A planned bundle, proved.
struct Proved {
    bundle: Bundle,
    tier: u8,
    proving: Duration,
}

/// Proves every bundle of one transaction and returns them in order, with the `time` they all
/// carry.
///
/// One anchor for all of them, and one witness per real input folded against it. A witness is
/// folded against the tree's *current* root, so a leaf appended between the calls makes the
/// witness prove membership in a tree the anchor does not name — and the bundle would be rejected
/// as `UnknownAnchor` or fail `MERKLE_VERIFY`. Refetching all of it together is the fix; three
/// attempts is enough unless the chain is committing notes faster than this wallet can read them.
async fn prove_bundles(
    rpc: &RpcClient,
    w: &Wallet,
    plans: &[Plan],
    profile: FriProfile,
    backend: Backend,
) -> Result<(Vec<Proved>, u32)> {
    let mut attempt = 0;
    let (height, root, paths) = loop {
        attempt += 1;
        let (height, root) = rpc.anchor(None).await?;
        let mut paths: Vec<Vec<[Word8; DEPTH]>> = Vec::with_capacity(plans.len());
        let mut moved = false;
        for plan in plans {
            let mut bundle_paths = Vec::with_capacity(plan.chosen.len());
            for n in &plan.chosen {
                let (witness_root, path) = rpc.witness(n.index).await?;
                if witness_root != root {
                    moved = true;
                    break;
                }
                bundle_paths.push(path);
            }
            if moved {
                break;
            }
            paths.push(bundle_paths);
        }
        if !moved {
            break (height, root, paths);
        }
        if attempt >= 3 {
            return Err(anyhow!("tree moved; retry"));
        }
    };
    let time = u32::try_from(height).map_err(|_| anyhow!("chain height {height} does not fit a bundle's time field"))?;

    let mut proved = Vec::with_capacity(plans.len());
    for (i, (plan, paths)) in plans.iter().zip(&paths).enumerate() {
        let which = if plans.len() > 1 { format!("bundle {} of {}", i + 1, plans.len()) } else { "bundle".to_string() };
        proved.push(prove_one(w, plan, paths, root, time, &which, profile, backend)?);
    }
    Ok((proved, time))
}

/// One planned bundle's proof: the slots, the two outputs, the digest check and the two envelopes.
#[allow(clippy::too_many_arguments)]
fn prove_one(
    w: &Wallet,
    plan: &Plan,
    paths: &[[Word8; DEPTH]],
    root: Word8,
    time: u32,
    which: &str,
    profile: FriProfile,
    backend: Backend,
) -> Result<Proved> {
    // A dummy input is a zero-value note owned by this wallet with an all-zero path at index 0:
    // the guest forces every input's owner to the derived `pk_self` and skips `MERKLE_VERIFY` (and
    // the asset check) for a zero-amount slot, so the path is never dereferenced. `Note::new` is
    // what gives it a fresh `r`, without which two dummies would share a commitment (and hence a
    // nullifier).
    let pk_self = w.vk.pk();
    let dummy = || (Note::new(pk_self, [0; 8], 0, plan.asset, time), [[0u32; 8]; DEPTH], 0u32);
    let mut slots: Vec<(Note, [Word8; DEPTH], u32)> = plan
        .chosen
        .iter()
        .zip(paths)
        .map(|(n, path)| (n.note, *path, u32::try_from(n.index).expect("a leaf index fits 32 bits at DEPTH = 32")))
        .collect();
    while slots.len() < 2 {
        slots.push(dummy());
    }
    let inputs: [(Note, [Word8; DEPTH], u32); 2] = [slots[0], slots[1]];

    // Both outputs are real notes, and both carry the bundle's own asset — the guest binds them to
    // it structurally, so no other value could produce a matching digest. A zero-value change note
    // is still published (and scanned back as an owned note the wallet then ignores): the bundle
    // shape is fixed at two outputs, and a slot that looked different when change happened to be
    // zero would leak it.
    let out1 = Note::new(plan.dest.pk, pk_self, plan.amount, plan.asset, time);
    let out2 = Note::new(pk_self, pk_self, plan.change(), plan.asset, time);
    let outputs = [out1, out2];

    let (fee, burn, asset) = (plan.fee, plan.burn, plan.asset);
    let words = bundle_inputs(&w.sk, &inputs, &outputs, root, fee, burn, asset, time);
    let expected = expected_bundle_outputs(&w.sk, &inputs, &outputs, root, fee, burn, asset, time);

    eprintln!("proving {which} (tier 14; about a minute on a laptop)…");
    let started = Instant::now();
    let (proof, digest, tier) = prove_bundle(profile, &words, backend).map_err(|e| anyhow!("proving the bundle failed: {e}"))?;
    let proving = started.elapsed();
    eprintln!("proved in {proving:.1?}: tier {tier}, {} bytes", proof.len());
    // The guest taints its digest instead of failing when a witness violates the relation, so a
    // proof that does not publish the digest this wallet computed from its own plaintext is a
    // bug in this wallet — not something the node would explain, since the node only ever sees
    // a digest that matches no plaintext.
    if digest != expected {
        return Err(anyhow!(
            "the bundle proof published digest {} but this wallet built {} — refusing to submit (wallet bug)",
            word8_to_hex(&digest),
            word8_to_hex(&expected),
        ));
    }

    // One fresh transaction key per envelope: two envelopes sealed under one key would both
    // open under a single-transaction disclosure (see `viewing::TxKey`).
    let envelopes = [
        seal_note(&w.vk, &plan.dest, &out1, &TxKey::random()).map_err(|e| anyhow!("sealing the payment envelope: {e}"))?,
        seal_note(&w.vk, &w.address, &out2, &TxKey::random()).map_err(|e| anyhow!("sealing the change envelope: {e}"))?,
    ];
    let bundle = Bundle {
        anchor: root,
        nullifiers: [w.vk.nullifier(&inputs[0].0.commitment()), w.vk.nullifier(&inputs[1].0.commitment())],
        commitments: [out1.commitment(), out2.commitment()],
        fee,
        burn,
        asset,
        time,
        envelopes,
        proof,
    };
    Ok(Proved { bundle, tier, proving })
}

/// Wait for the commit, or hold the spent notes back: the tail of every submission.
async fn settle(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    hash: &Hash,
    plans: &[Plan],
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
            if plans.iter().any(|p| p.chosen.iter().any(|c| c.index == n.index)) {
                n.pending = Some(time);
            }
        }
    }
    Ok(())
}

/// Everything that rides on one bundle goes through here: a transfer (`to = Some(..)`), a deploy,
/// a call or a bridge attestation (`to = None`, i.e. a self-transfer of zero whose only purpose is
/// to pay the action's fee floor). One code path, so the fee, the anchor, the witnesses and the
/// digest check cannot drift apart between them.
#[allow(clippy::too_many_arguments)]
pub async fn submit(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: Option<(&ShieldedAddress, u64)>,
    action: Action,
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    scan(rpc, w, store).await?;
    let (dest, amount) = to.unwrap_or((&w.address, 0));
    // The transaction's own bundle is always SHRUGG and never burns (`Ledger::validate_inner`).
    let plans = [Plan::select(store, 0, dest, amount, fee, 0)?];
    let (proved, time) = prove_bundles(rpc, w, &plans, profile, backend).await?;
    let [one] = <[Proved; 1]>::try_from(proved).ok().expect("one plan, one proof");

    let proof_bytes = one.bundle.proof.len();
    let tx = Transaction::shielded(chain_id, one.bundle, action);
    let hash = rpc.send_transaction(&tx).await?;
    settle(rpc, w, store, &hash, &plans, time, wait).await?;
    Ok(Submission {
        hash,
        amount,
        change: plans[0].change(),
        fee,
        time,
        asset: 0,
        tier: one.tier,
        proof_bytes,
        proving: one.proving,
    })
}

/// The chain's one two-bundle transaction (spec §10): burn `amount` of a bridged asset to
/// `to_chain`/`to`, paying the SHRUGG fee from a second bundle.
///
/// The asset bundle burns `amount + relayer_fee` and pays no fee — the fee is always SHRUGG, and
/// the guest's own rule is that a non-SHRUGG bundle's fee is zero — so this wallet has to hold
/// notes of *both*: the asset to burn and the SHRUGG to pay with. Both bundles are proved before
/// either is submitted, and both go through the same admission the fee bundle does.
#[allow(clippy::too_many_arguments)]
pub async fn submit_burn(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    asset: u32,
    amount: u64,
    relayer_fee: u64,
    to_chain: u16,
    to: [u8; 32],
    fee: u64,
    profile: FriProfile,
    backend: Backend,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if asset == 0 {
        return Err(anyhow!("asset 0 is SHRUGG, which is not a bridged asset and cannot be burned"));
    }
    // The bridge owns the rest of a burn's rules (`BridgeState::check_burn`: the destination must be
    // the asset's own chain, the recipient must be shaped for it) and this wallet deliberately does
    // not restate them. These two are the exception, because they are definitional rather than
    // policy and because the alternative is two bundle proofs — minutes of a laptop — thrown away
    // on a typo.
    if amount == 0 {
        return Err(anyhow!("a burn of zero moves nothing"));
    }
    if relayer_fee > amount {
        return Err(anyhow!("the relayer fee {relayer_fee} is more than the {amount} being burned"));
    }
    scan(rpc, w, store).await?;
    let burn = amount.checked_add(relayer_fee).ok_or_else(|| anyhow!("amount + relayer fee overflows"))?;
    // The asset bundle first, so its notes and the fee bundle's are selected from the same store
    // read; they can never collide, since they hold different assets.
    let plans = [
        Plan::select(store, asset, &w.address, 0, 0, burn)
            .with_context(|| format!("selecting notes of asset {asset} to burn"))?,
        Plan::select(store, 0, &w.address, 0, fee, 0).context("selecting SHRUGG notes for the fee bundle")?,
    ];
    let (proved, time) = prove_bundles(rpc, w, &plans, profile, backend).await?;
    let [asset_proof, fee_proof] = <[Proved; 2]>::try_from(proved).ok().expect("two plans, two proofs");

    let proof_bytes = asset_proof.bundle.proof.len() + fee_proof.bundle.proof.len();
    let action = Action::BridgeBurn { asset_bundle: asset_proof.bundle, asset, amount, relayer_fee, to_chain, to };
    let tx = Transaction::shielded(chain_id, fee_proof.bundle, action);
    let hash = rpc.send_transaction(&tx).await?;
    settle(rpc, w, store, &hash, &plans, time, wait).await?;
    Ok(Submission {
        hash,
        amount: burn,
        change: plans[0].change(),
        fee,
        time,
        asset,
        tier: asset_proof.tier.max(fee_proof.tier),
        proof_bytes,
        proving: asset_proof.proving + fee_proof.proving,
    })
}

/// What a `deploy` pays by default: the bundle base plus the program's per-word charge, which
/// is exactly `gas::fee_floor` for a `Deploy`.
pub fn deploy_fee_default(action: &Action) -> u64 {
    gas::fee_floor(action)
}

/// What a `call` pays by default — and deliberately NOT `fee_floor(Call) + call_fee(tier)`.
/// `fee_floor(Call)` is `BUNDLE_BASE + CALL_BASE`, and `CALL_BASE` is already `call_fee`'s own
/// constant term, so adding the two overpays by `CALL_BASE`. The node's floor, once it has
/// decoded the proof and knows the tier, is precisely this (`Ledger::validate_inner`).
pub fn call_fee_default(tier: u8) -> u64 {
    gas::BUNDLE_BASE + gas::call_fee(tier)
}

/// What a `bridge-burn` pays by default: the bundle base for each of its two bundles, which is
/// `gas::fee_floor` for a `BridgeBurn`. Written as the arithmetic rather than by calling
/// `fee_floor` because the action does not exist yet — the asset bundle inside it is the thing
/// this fee is being selected in order to prove.
pub fn burn_fee_default() -> u64 {
    2 * gas::BUNDLE_BASE
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
    /// The token as the guardians named it, which is what `shrugg_bridgeAssetId` turns into an
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
    // Whatever this says about the amount and the asset, the ledger's helper is what the chain
    // itself will read, so it — not the decode above — is what the note is built from.
    let (asset, amount) = bridge_notes::attested_transfer(attestation)
        .ok_or_else(|| anyhow!("this attestation's amount does not fit a note"))?;
    Ok(AttestedDeposit { to_hash: t.to, token_chain: t.token_chain, token: t.token_address, asset, amount })
}

/// The `asset` word a deposit note will carry, and how sure a wallet can be of it.
///
/// [`DepositIndex::Registered`] is a fact: an index is assigned once and never changes, so a token
/// the registry already names deposits under that index whenever the transaction lands.
///
/// [`DepositIndex::FirstSighting`] is a *prediction*, and the one number in a `bridge-mint` this
/// wallet cannot be certain of. The ledger gives a new asset the registry's `next_index` as it
/// stands when the transaction is applied (`BridgeState::asset_entry`), and proving the fee bundle
/// takes a minute and a half — so another first-sighting attestation committing in that window
/// moves the index, and the note this wallet sealed an envelope for is not the note the chain
/// would append. The chain refuses that transaction rather than depositing it
/// (`TxError::AttestAssetMismatch`, against the `asset` the action names), so a lost race costs
/// this wallet a fee bundle and a re-proof and never a note. What the prediction still buys is
/// printing `r` and `time` (both public on the wire, so printing discloses nothing) so the note is
/// reconstructible by hand, and [`deposit_index_check`] on the committed transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositIndex {
    Registered(u32),
    FirstSighting(u32),
}

impl DepositIndex {
    pub fn index(self) -> u32 {
        match self {
            DepositIndex::Registered(i) | DepositIndex::FirstSighting(i) => i,
        }
    }

    pub fn is_first_sighting(self) -> bool {
        matches!(self, DepositIndex::FirstSighting(_))
    }
}

/// The index a deposit of `asset_id` will carry, from the node's own two answers: the registry
/// (`shrugg_getAssets`) and, for a token it does not name, the `next_index` that registry would
/// hand out (`shrugg_getBridgeState`).
pub fn deposit_index(bridge_state: &Value, assets: &[AssetRow], asset_id: &str) -> Result<DepositIndex> {
    if bridge_state["enabled"] != Value::Bool(true) {
        return Err(anyhow!("this chain has no bridge"));
    }
    match assets.iter().find(|a| a.asset_id == asset_id) {
        Some(a) => Ok(DepositIndex::Registered(a.index)),
        None => {
            let next = bridge_state["next_index"].as_u64().context("bridge state has no next_index")?;
            Ok(DepositIndex::FirstSighting(u32::try_from(next).context("next_index does not fit an asset word")?))
        }
    }
}

/// What a committed `BridgeAttest` deposited under, against what the wallet predicted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositIndexCheck {
    /// The chain deposited under the index the envelope was sealed for.
    Agrees,
    /// It did not, so the envelope opens nothing: the recipient has to rebuild the note from the
    /// `r` and `time` the mint printed, with `committed` as its `asset` word.
    ///
    /// Unreachable on a *committed* transaction since the action names its index: admission
    /// refuses a mismatch outright (`TxError::AttestAssetMismatch`), so a lost race shows up as a
    /// rejected submission, not as a deposit under the wrong index. Kept as belt and braces —
    /// this is the one check that would catch a node whose registry disagrees with the one the
    /// prediction was read from.
    Mismatch { predicted: u32, committed: u32 },
    /// The node cannot say: not an attest, or an attestation whose asset its registry does not hold
    /// (and a rotation, which deposits nothing).
    Unknown,
}

/// Check a predicted deposit index against the committed transaction, as `shrugg_getTransaction`
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
/// `from` is the zero word: a deposit has no sender inside the pool. The blinding is drawn here,
/// by `Note::new`, and the caller reads it back off the note for the action's `r` — the one place
/// it is generated, so the note and the action cannot name different ones.
pub fn deposit_note_for(
    w: &Wallet,
    recipient: &ShieldedAddress,
    amount: u64,
    asset: u32,
    time: u32,
) -> Result<(Note, Envelope)> {
    let note = Note::new(recipient.pk, [0; 8], amount, asset, time);
    let envelope =
        seal_note(&w.vk, recipient, &note, &TxKey::random()).map_err(|e| anyhow!("sealing the deposit envelope: {e}"))?;
    Ok((note, envelope))
}

/// A plain shielded transfer: `submit` with `Action::None`.
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
    submit(rpc, w, store, Some((to, amount)), Action::None, fee, profile, backend, chain_id, wait).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use shrugg_zkvm::notes::SpendKey;

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
        use shrugg_core::bridge::{Body, Transfer, CHAIN_RAND};
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
        use shrugg_core::bridge::{guardian_address, Body, GuardianSetUpgrade, CHAIN_RAND, GOVERNANCE_EMITTER};
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
            notes: vec![owned(0, 5, false), owned(1, 3, true), owned(2, 0, false), owned(3, 2, false)],
            sent: vec![],
        };
        assert_eq!(store.balance(), 7);
        let spendable: Vec<u64> = store.spendable().iter().map(|n| n.note.amount).collect();
        assert_eq!(spendable, vec![5, 2]);
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
    fn sealed(from: &Wallet, to: &Wallet, note: &Note) -> shrugg_core::notes::Envelope {
        shrugg_zkvm::address::seal_note(&from.vk, &to.address, note, &TxKey::random()).unwrap()
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
    fn assets_are_counted_and_selected_apart_from_shrugg() {
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
        assert_eq!(store.balance(), 7, "SHRUGG alone, not a sum across assets");
        assert_eq!(store.balance_of(0), store.balance());
        assert_eq!(store.balance_of(3), 900, "and the spent asset note is not in it");
        assert_eq!(store.balance_of(7), 11);
        assert_eq!(store.balance_of(9), 0, "an asset this wallet holds nothing in");
        assert_eq!(store.asset_balances(), vec![(0, 7), (3, 900), (7, 11)]);

        // Selection sees one asset's notes and no others: a burn of 850 of asset 3 is payable from
        // its two notes, while the SHRUGG the same wallet holds is not part of the answer.
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
        assert_eq!(d.asset, shrugg_core::bridge::asset_id(TOKEN_CHAIN, &TOKEN), "the registry's key for the token");
        // The address the guardians named is one address: another wallet's does not hash to it,
        // which is what the ledger refuses with `BridgeRecipientMismatch`.
        let other = Wallet::from_spend_key(SpendKey([22; 8]));
        assert_ne!(d.to_hash, other.address.recipient_hash());
        // Bytes that are not an attestation, and one that deposits nothing, are refused by name.
        assert!(attested_deposit(&[0xff; 32]).unwrap_err().to_string().contains("not a bridge attestation"));
        assert!(attested_deposit(&rotation_attestation()).unwrap_err().to_string().contains("rotation"));
    }

    /// A registered asset's index is a fact; an unregistered one's is the registry's `next_index`,
    /// and only a prediction — the ledger assigns it when the transaction is *applied*, which is
    /// after this wallet has spent a minute and a half proving the fee bundle.
    #[test]
    fn a_deposit_index_is_a_fact_for_a_registered_asset_and_a_prediction_for_a_new_one() {
        let row = |index: u32, byte: u8| AssetRow {
            index,
            chain: 2,
            token: vec![byte; 32],
            asset_id: hex::encode([byte; 32]),
        };
        let assets = [row(1, 0xaa), row(2, 0xbb)];
        let state = serde_json::json!({ "enabled": true, "next_index": 3 });
        let id = |byte: u8| hex::encode([byte; 32]);

        assert_eq!(deposit_index(&state, &assets, &id(0xaa)).unwrap(), DepositIndex::Registered(1));
        assert_eq!(deposit_index(&state, &assets, &id(0xbb)).unwrap(), DepositIndex::Registered(2));
        let new = deposit_index(&state, &assets, &id(0xcc)).unwrap();
        assert_eq!(new, DepositIndex::FirstSighting(3), "the index this attestation's own registration will assign");
        assert_eq!((new.index(), new.is_first_sighting()), (3, true));
        assert!(!DepositIndex::Registered(1).is_first_sighting());

        // A chain with no bridge cannot deposit at all, and a reply missing `next_index` is not one
        // a note may be built from — neither is a number to guess at.
        let err = deposit_index(&serde_json::json!({ "enabled": false }), &assets, &id(0xcc)).unwrap_err();
        assert!(err.to_string().contains("no bridge"), "{err}");
        assert!(deposit_index(&serde_json::json!({ "enabled": true }), &assets, &id(0xcc)).is_err());
    }

    /// The check that catches the one way a first-sighting mint can go wrong: the chain deposited
    /// under a different index than the envelope was sealed against, because another first sighting
    /// registered while this wallet was proving.
    #[test]
    fn a_committed_deposit_index_is_checked_against_the_predicted_one() {
        let committed = |kind: &str, asset_index: serde_json::Value| {
            serde_json::json!({ "tx": { "action": { "kind": kind, "asset_index": asset_index } } })
        };
        assert_eq!(deposit_index_check(3, &committed("bridge_attest", serde_json::json!(3))), DepositIndexCheck::Agrees);
        assert_eq!(
            deposit_index_check(3, &committed("bridge_attest", serde_json::json!(4))),
            DepositIndexCheck::Mismatch { predicted: 3, committed: 4 },
            "another first sighting took index 3 first"
        );
        // The node cannot always say, and "cannot say" is never "agrees": a rotation deposits
        // nothing, an asset its registry does not hold renders as null, and another action is not a
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
        use shrugg_core::confidential::ConfidentialExecutor;
        let me = Wallet::from_spend_key(SpendKey([23; 8]));
        let (note, envelope) = deposit_note_for(&me, &me.address, 1_000, 3, 41).unwrap();
        // `ConfidentialExecutor::note_commitment` is the function `bridge_notes` computes the
        // deposit's commitment through, on the ledger's side of the same wire — over the action's
        // own `r`, which is this note's.
        let ex = shrugg_zkvm::executor::ZkExecutor::new(FriProfile::Test);
        assert_eq!(note.commitment(), ex.note_commitment(&me.address.pk, &[0; 8], 1_000, 3, 41, &note.r));
        assert_eq!((note.amount, note.asset, note.time, note.from), (1_000, 3, 41, [0; 8]));
        // And the envelope published with it opens back to that note, as the recipient.
        assert_eq!(classify(&me, note.commitment(), &envelope), Found::Received(note));
        // A different `time` is a different note: this is why `time` is on the action. (So is a
        // different blinding, which is why every deposit draws a fresh one.)
        let (later, _) = deposit_note_for(&me, &me.address, 1_000, 3, 42).unwrap();
        assert_ne!(later.commitment(), note.commitment());
        assert_ne!(deposit_note_for(&me, &me.address, 1_000, 3, 41).unwrap().0.r, note.r);
    }

    #[test]
    fn the_fee_defaults_are_the_schedule_floors_and_no_more() {
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x13; 40] };
        assert_eq!(deploy_fee_default(&deploy), gas::fee_floor(&deploy));
        assert_eq!(deploy_fee_default(&deploy), gas::BUNDLE_BASE + gas::deploy_fee(40));
        for tier in [10u8, 12, 14, 20] {
            assert_eq!(call_fee_default(tier), gas::BUNDLE_BASE + gas::call_fee(tier));
            // The floor `Ledger::validate_inner` applies, not a cent over it: adding
            // `fee_floor(Call)` to `call_fee` would double-count `CALL_BASE`.
            let floor = gas::fee_floor(&Action::Call { program: shrugg_core::Hash::ZERO, proof: vec![], input_envelope: None });
            let doubled = floor + gas::call_fee(tier);
            assert_eq!(doubled - call_fee_default(tier), gas::CALL_BASE, "tier {tier}");
        }
        // A burn pays the bundle base per verified bundle, and it has two. Checked against the
        // schedule itself, since `burn_fee_default` cannot ask `fee_floor` — the action it would
        // ask about contains the very bundle this fee is being selected to prove.
        let burn = Action::BridgeBurn {
            asset_bundle: Bundle {
                anchor: [0; 8],
                nullifiers: [[0; 8], [1; 8]],
                commitments: [[2; 8], [3; 8]],
                fee: 0,
                burn: 500,
                asset: 3,
                time: 0,
                envelopes: [env(), env()],
                proof: vec![],
            },
            asset: 3,
            amount: 400,
            relayer_fee: 100,
            to_chain: 2,
            to: [0; 32],
        };
        assert_eq!(burn_fee_default(), gas::fee_floor(&burn));
        assert_eq!(burn_fee_default(), 2 * gas::BUNDLE_BASE);
    }

    /// The three things a burn is refused for before it costs anything: SHRUGG, which is not a
    /// bridged asset at all; a burn of nothing; and a relayer fee larger than the burn. Refused
    /// before the wallet so much as reads the chain, which is the point — everything after that
    /// point is two bundle proofs.
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
        assert_eq!(back.notes.len(), 2);
        assert_eq!(back.notes[0].note, store.notes[0].note);
        assert_eq!(back.notes[1].spent, true);
        assert_eq!(back.sent[0].amount, 11);
        assert_eq!(back.balance(), 5);
    }
}
