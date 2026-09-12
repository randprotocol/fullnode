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

use crate::RpcClient;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shrugg_core::notes::{word8_from_hex, word8_to_hex, Bundle, ShieldedAddress, Word8, DEPTH};
use shrugg_core::{Action, Hash, Transaction};
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
    pub height: u64,
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

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)? + "\n";
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }

    /// Spendable value. A zero-value note is a real note (a bundle whose change is zero still
    /// publishes a change output) but it buys nothing, so it is neither counted nor selected.
    pub fn balance(&self) -> u64 {
        self.spendable().iter().map(|n| n.note.amount).sum()
    }

    pub fn spendable(&self) -> Vec<&OwnedNote> {
        self.notes.iter().filter(|n| !n.spent && n.note.amount > 0).collect()
    }
}

// ---------------------------------------------------------------- scanning

/// Trial-decrypt every commitment this wallet has not seen yet, then mark as spent every note
/// whose nullifier the chain has published. Advances the store and saves nothing — the caller
/// owns the file.
pub async fn scan(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore) -> Result<()> {
    loop {
        let rows = rpc.commitments(store.scanned_index, PAGE).await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let env = envelope_from_core(&row.envelope);
            if let Some((_, note)) = env.open_as_receiver(row.cm, &w.vk) {
                // A note can be re-offered by a rescan; index is the leaf, so it is unique.
                if !store.notes.iter().any(|n| n.index == row.index) {
                    store.notes.push(OwnedNote {
                        index: row.index,
                        cm: row.cm,
                        nf: w.vk.nullifier(&row.cm),
                        note,
                        spent: false,
                        height: row.height,
                    });
                }
            } else if let Some((_, note)) = env.open_as_sender(row.cm, &w.vk) {
                if !store.sent.iter().any(|s| s.index == row.index) {
                    store.sent.push(SentRow { index: row.index, to_pk: note.pk, amount: note.amount, height: row.height });
                }
            }
            store.scanned_index = store.scanned_index.max(row.index + 1);
        }
    }

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
        from = if max_height > from { max_height } else { max_height + 1 };
    }
    store.scanned_height = store.scanned_height.max(from);
    Ok(())
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

/// What a submitted bundle did, for the caller to print.
#[derive(Clone, Debug)]
pub struct Submission {
    pub hash: Hash,
    pub amount: u64,
    pub change: u64,
    pub fee: u64,
    pub time: u32,
    pub tier: u8,
    pub proof_bytes: usize,
    pub proving: Duration,
}

/// Everything that rides on a bundle goes through here: a transfer (`to = Some(..)`), a deploy
/// or a call (`to = None`, i.e. a self-transfer of zero whose only purpose is to pay the
/// action's fee floor). One code path, so the fee, the anchor, the witnesses and the digest
/// check cannot drift apart between the three.
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
    let need = amount.checked_add(fee).ok_or_else(|| anyhow!("amount + fee overflows"))?;
    let chosen = select_inputs(&store.spendable(), need)?;
    let total: u64 = chosen.iter().map(|n| n.note.amount).sum();
    let change = total - need;

    // One anchor, then a witness per real input against it. A witness is folded against the
    // tree's *current* root, so a leaf appended between the two calls makes the witness prove
    // membership in a tree the anchor does not name — and the bundle would be rejected as
    // `UnknownAnchor` or fail `MERKLE_VERIFY`. Refetching both is the fix; three attempts is
    // enough unless the chain is committing notes faster than this wallet can read them.
    let mut attempt = 0;
    let (height, root, paths) = loop {
        attempt += 1;
        let (height, root) = rpc.anchor(None).await?;
        let mut paths = Vec::with_capacity(chosen.len());
        let mut moved = false;
        for n in &chosen {
            let (witness_root, path) = rpc.witness(n.index).await?;
            if witness_root != root {
                moved = true;
                break;
            }
            paths.push(path);
        }
        if !moved {
            break (height, root, paths);
        }
        if attempt >= 3 {
            return Err(anyhow!("tree moved; retry"));
        }
    };
    let time = u32::try_from(height).map_err(|_| anyhow!("chain height {height} does not fit a bundle's time field"))?;

    // A dummy input is a zero-value note owned by this wallet with an all-zero path at index 0:
    // the guest forces every input's owner to the derived `pk_self` and skips `MERKLE_VERIFY`
    // for a zero-amount slot, so the path is never dereferenced. `Note::new` is what gives it a
    // fresh `r`, without which two dummies would share a commitment (and hence a nullifier).
    let pk_self = w.vk.pk();
    let dummy = || (Note::new(pk_self, [0; 8], 0, 0, time), [[0u32; 8]; DEPTH], 0u32);
    let mut slots: Vec<(Note, [Word8; DEPTH], u32)> = chosen
        .iter()
        .zip(&paths)
        .map(|(n, path)| (n.note, *path, u32::try_from(n.index).expect("a leaf index fits 32 bits at DEPTH = 32")))
        .collect();
    while slots.len() < 2 {
        slots.push(dummy());
    }
    let inputs: [(Note, [Word8; DEPTH], u32); 2] = [slots[0], slots[1]];

    // Both outputs are real notes. A zero-value change note is still published (and scanned
    // back as an owned note the wallet then ignores): the bundle shape is fixed at two outputs,
    // and a slot that looked different when change happened to be zero would leak it.
    let out1 = Note::new(dest.pk, pk_self, amount, 0, time);
    let out2 = Note::new(pk_self, pk_self, change, 0, time);
    let outputs = [out1, out2];

    let words = bundle_inputs(&w.sk, &inputs, &outputs, root, fee, 0, 0, time);
    let expected = expected_bundle_outputs(&w.sk, &inputs, &outputs, root, fee, 0, 0, time);

    eprintln!("proving bundle (tier 14; about a minute on a laptop)…");
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
        seal_note(&w.vk, dest, &out1, &TxKey::random()).map_err(|e| anyhow!("sealing the payment envelope: {e}"))?,
        seal_note(&w.vk, &w.address, &out2, &TxKey::random()).map_err(|e| anyhow!("sealing the change envelope: {e}"))?,
    ];
    let bundle = Bundle {
        anchor: root,
        nullifiers: [w.vk.nullifier(&inputs[0].0.commitment()), w.vk.nullifier(&inputs[1].0.commitment())],
        commitments: [out1.commitment(), out2.commitment()],
        fee,
        burn: 0,
        asset: 0,
        time,
        envelopes,
        proof,
    };
    let tx = Transaction::shielded(chain_id, bundle, action);
    let hash = rpc.send_transaction(&tx).await?;

    if wait {
        // The inputs are marked spent by the rescan, from the chain's own nullifier set — not
        // from this wallet's belief about what it just sent. That matters on the failure path:
        // a bundle that never commits (the wait times out, the mempool drops it) leaves its
        // notes spendable, where marking them here would strand them until the store is thrown
        // away and rebuilt.
        rpc.wait_for_transaction(&hash, COMMIT_TIMEOUT).await?;
        scan(rpc, w, store).await?;
    } else {
        // Nothing will confirm these for the caller, so the wallet has to assume they landed;
        // the next scan replaces the assumption with the chain's answer either way.
        for n in store.notes.iter_mut() {
            if chosen.iter().any(|c| c.index == n.index) {
                n.spent = true;
            }
        }
    }
    Ok(Submission { hash, amount, change, fee, time, tier, proof_bytes: tx.bundle.map_or(0, |b| b.proof.len()), proving })
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

    fn owned(index: u64, amount: u64, spent: bool) -> OwnedNote {
        let note = Note::new([1; 8], [2; 8], amount, 0, 3);
        OwnedNote { index, cm: note.commitment(), nf: [index as u32; 8], note, spent, height: index }
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
