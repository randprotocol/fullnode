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
//! The scan also grows the wallet's own copy of the commitment tree ([`crate::tree`], audit v3
//! PRIV-1), and every bundle takes its Merkle witnesses from that copy. Before it, the wallet
//! asked the node for the witnesses of exactly the notes it was about to spend — the one request
//! that told the operator which leaves were its own. Now the only tree question that leaves the
//! process is `rand_getAnchor`, which names no leaf.
//!
//! Nothing here ever sends a spend key, a viewing key or a note plaintext anywhere. What leaves
//! the process is exactly what a bundle publishes: an anchor, four nullifiers, four commitments,
//! the fee, the burn fields, and four envelopes nobody but their recipients can open — the
//! dummies' envelopes open to nobody at all.

use crate::prover::RemoteProver;
use crate::tree::LocalTree;
use crate::{AssetRow, ChainLimits, CommitmentRow, RpcClient};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use randprotocol_core::bridge::{AssetId, Attestation, Payload};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::ledger::tokens::{MintAuthority, MINT_FROM};
use randprotocol_core::ledger::{bridge_notes, MAX_PROOF_WINDOW_BLOCKS, MIN_PROOF_WINDOW_BLOCKS, TIME_WINDOW};
use randprotocol_core::notes::{word8_from_hex, word8_to_hex, Bundle, Envelope, EnvelopeFormat, ShieldedAddress, Word8, DEPTH};
use randprotocol_core::types::TX_BINDING_WORDS;
use randprotocol_core::{format_amount, gas, Action, BindingDomain, Hash, InitialMint, Keypair, PublicKey, Transaction};
use randprotocol_zkvm::address::{address_of, envelope_from_core, seal_note_as};
// `seal_note` (the format-less, always-`Legacy` sealer) is only used by test fixtures now that
// every production sealing site goes through `seal_note_as` with the chain's format.
#[cfg(test)]
use randprotocol_zkvm::address::seal_note;
use randprotocol_zkvm::executor::{prove_auth, prove_bundle_for, ZkExecutor};
use randprotocol_zkvm::hidden::{self, HiddenDigestInput, HiddenDigestInputV3, HiddenOutput, A_SLOTS, SLOTS};
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::{Note, SpendKey, ViewingKey};
use randprotocol_zkvm::viewing::TxKey;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

    /// Reads a key file written by [`Wallet::save_new`]. On unix one that group or other can
    /// read is refused, as `rand-prover` refuses its `prover.key.json` (VK-6, audit v6): the file
    /// is the wallet, the same spend key opens every chain, and a copy restored or moved at 0644
    /// is otherwise never noticed. `metadata` follows a symlink, so the mode checked is the key
    /// file's own.
    pub fn load(path: &Path) -> Result<Wallet> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).with_context(|| format!("reading key file {}", path.display()))?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(anyhow!(
                    "{} is group/world readable (mode {:o}): it holds this wallet's spend key — run `chmod 600 {}`, then try again",
                    path.display(),
                    mode & 0o777,
                    path.display()
                ));
            }
        }
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

/// An optional genesis hash as hex, like every other word in the store file.
mod hex_hash_opt {
    use super::*;
    pub fn serialize<S: Serializer>(h: &Option<Hash>, s: S) -> Result<S::Ok, S::Error> {
        match h {
            Some(h) => s.serialize_some(&h.to_hex()),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Hash>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(text) => Hash::from_hex(&text).map(Some).map_err(|e| serde::de::Error::custom(format!("genesis: {e}"))),
            None => Ok(None),
        }
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

/// A deposit or mint rebuilt from a block and not yet placed at its leaf ([`NoteStore::
/// pending_public_notes`]), in the store's own note encoding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingNote {
    #[serde(with = "hex_note")]
    pub note: Note,
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
    /// wallet has actually read the nullifiers of reach past `time + TIME_WINDOW` (or the chain's
    /// genesis `proof_window_blocks`, issue #118), past which
    /// that bundle can never be admitted at all (`Ledger::validate_inner`'s time check) so the
    /// note is spendable again.
    #[serde(default)]
    pub pending: Option<u32>,
    pub height: u64,
    /// The memo sealed with this note, on a chain whose genesis carries `envelope_bytes`
    /// (spec 2026-09-26 §2.3). `#[serde(default)]` so a store written before the memo existed
    /// still loads, at `None` — the same as a genuinely memo-less output.
    #[serde(default)]
    pub memo: Option<String>,
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
    /// The memo this wallet sealed with the note, on a chain whose genesis carries
    /// `envelope_bytes`. `#[serde(default)]` so a store written before the memo existed still
    /// loads, at `None`.
    #[serde(default)]
    pub memo: Option<String>,
}

/// Everything scanning has learned, as JSON at `<key path>.notes.json`.
///
/// Purely a cache of chain data: every row in it is recoverable by rescanning from leaf 0 with
/// the spend key, which is why [`NoteStore::load`] starts from empty rather than failing when
/// the file is missing or unreadable.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NoteStore {
    /// The chain every row and cursor here was read from: the node's `rand_getGenesisHash` at the
    /// first scan. A store is a cache of one chain's tree, and its cursors mean nothing on
    /// another — carried across a chain cut, a store's leaf cursor sat past every leaf of the
    /// new chain, every page came back empty, and the wallet reported `0 RAND, 0 notes` with no
    /// warning while its notes sat on chain. [`NoteStore::bind`] starts the store over when the
    /// node's chain is not this one. `None` on a store written before the binding existed, which
    /// is started over once, the same way.
    #[serde(default, with = "hex_hash_opt")]
    pub genesis: Option<Hash>,
    /// The next leaf index to scan; every leaf below it has been tried against the viewing key.
    pub scanned_index: u64,
    /// The next block height to read nullifiers from.
    pub scanned_height: u64,
    /// The next block height to read committed deposits and mints from (`bridge_attest`,
    /// `token_mint`, `register_token`), for the public-rebuild path in [`scan`]. Zero on a store
    /// written before that path existed, which is what makes an older store re-read its blocks
    /// once and recover anything it missed. (The name is the first of those kinds'.)
    pub scanned_attest_height: u64,
    /// Deposits and mints rebuilt from blocks the walk has read but not yet placed at their leaf
    /// (issue #117): the walk advances `scanned_attest_height` page by page and keeps what it
    /// found here, so an interrupted first sync — the public endpoint's rate limit, a dropped
    /// connection — resumes where it stopped instead of re-reading every block. Emptied once the
    /// leaf pass has placed each. Keyed by the note's commitment, as hex.
    #[serde(default)]
    pub pending_public_notes: BTreeMap<String, PendingNote>,
    pub notes: Vec<OwnedNote>,
    pub sent: Vec<SentRow>,
    /// The wallet's own copy of the commitment tree and a witness per owned note (audit v3
    /// PRIV-1): what every send takes its Merkle paths from, instead of asking the node for the
    /// witnesses of exactly the notes it spends.
    pub tree: LocalTree,
}

impl<'de> Deserialize<'de> for NoteStore {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<NoteStore, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default, with = "hex_hash_opt")]
            genesis: Option<Hash>,
            scanned_index: u64,
            scanned_height: u64,
            #[serde(default)]
            scanned_attest_height: u64,
            #[serde(default)]
            pending_public_notes: BTreeMap<String, PendingNote>,
            notes: Vec<OwnedNote>,
            #[serde(default)]
            sent: Vec<SentRow>,
            #[serde(default)]
            tree: Option<LocalTree>,
        }
        let w = Wire::deserialize(d)?;
        // A store written before the tree existed: its cursor says the leaves below
        // `scanned_index` were read, but no tree was kept for them, so beside a nonzero
        // cursor a default-empty tree would silently miss every leaf below the cursor and
        // produce wrong witnesses. Rescan from 0 once instead: re-offering is idempotent
        // (every record is keyed by its index) and the tree is rebuilt whole.
        let scanned_index = if w.tree.is_some() { w.scanned_index } else { 0 };
        Ok(NoteStore {
            genesis: w.genesis,
            scanned_index,
            scanned_height: w.scanned_height,
            scanned_attest_height: w.scanned_attest_height,
            pending_public_notes: w.pending_public_notes,
            notes: w.notes,
            sent: w.sent,
            tree: w.tree.unwrap_or_default(),
        })
    }
}

/// What [`NoteStore::bind`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    /// The store was already this chain's.
    Same,
    /// The store was another chain's (`previous`), or from before stores named their chain
    /// (`None`), and has been emptied: every cursor at zero, no notes, bound to this chain now.
    Reset { previous: Option<Hash> },
}

impl NoteStore {
    /// Make this store `chain`'s. A store bound to `chain` already is untouched; any other is
    /// started over, because nothing in it can be trusted to be `chain`'s: its rows are
    /// recoverable by rescanning, and its cursors are what hides the new chain's notes.
    pub fn bind(&mut self, chain: Hash) -> Bound {
        if self.genesis == Some(chain) {
            return Bound::Same;
        }
        let previous = self.genesis;
        *self = NoteStore { genesis: Some(chain), ..NoteStore::default() };
        Bound::Reset { previous }
    }

    /// Forget everything scanning has learned — notes, spent marks, pending holds, sent rows,
    /// the tree and every cursor — and keep only the chain binding, so the next [`scan`] rebuilds
    /// the store from leaf 0 (`rand sync --rescan`, audit WAL-3). A scan only ever marks a note
    /// spent, from the nullifiers the node reports; a node that reported one of this wallet's own
    /// wrongly leaves that note stranded until the store is started over, and this is how.
    pub fn reset(&mut self) {
        *self = NoteStore { genesis: self.genesis, ..NoteStore::default() };
    }

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
    /// halfway through leaves the previous store intact instead of a truncated one. The
    /// temporary file is always a fresh one, 0600 and synced ([`write_private`], VK-6).
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

/// Write `bytes` to the new file `path`, owner-only and on disk before this returns (VK-6, audit
/// v6; the approach of `Contacts::save` and `PairedProver::save`, 2b6da966). Whatever sits at
/// `path` already — a stale temporary file from a crash, or one somebody else planted — is
/// removed first, never reused: `open(create)` applies its mode only to a file it creates, so a
/// stale 0644 file stayed 0644, and it follows a symlink, so a link planted at the (predictable)
/// temporary name had the store written into whatever it pointed at. `remove_file` deletes a
/// link itself, not its target, and `create_new` (`O_EXCL`) refuses to open through one, so a
/// link planted between the two fails the save instead of redirecting it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    // Pinned on the descriptor as well: the mode above is masked by the umask, never widened by
    // it, but this says 0600 whatever created the file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    // Before the rename that follows: without it a power loss can leave the new name pointing
    // at a file whose bytes never reached the disk — an empty store where the old one was.
    f.sync_all()?;
    Ok(())
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
    /// The memo sealed with this output, if any (on a chain whose genesis carries
    /// `envelope_bytes`).
    pub memo: Option<String>,
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
        let memo = env.memo(cm, &key);
        rows.push(OutputKey { output, slot, cm, role, note, key, memo });
    }
    rows
}

// ---------------------------------------------------------------- scanning

/// The hash the wallet's local commitment tree is folded with: the executor's own `node_hash`, so
/// a path computed here is exactly what the hidden guest's `MERKLE_VERIFY` checks against the
/// anchor and what the ledger's tree records. A bare Poseidon2 evaluation has no FRI in it, so
/// the profile is irrelevant; the closure just hands `tree.rs` the function without the executor
/// type leaking into it.
fn tree_hash() -> impl Fn(&Word8, &Word8) -> Word8 {
    let ex = ZkExecutor::new(FriProfile::Test);
    move |left: &Word8, right: &Word8| ex.node_hash(left, right)
}

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
    /// A note this wallet owns and can spend, with its memo if the sender sealed one.
    Received(Note, Option<String>),
    /// A note this wallet created for someone else — history only — with the memo it carried.
    Sent(Note, Option<String>),
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
    if let Some((key, note)) = env.open_as_receiver(cm, &w.vk) {
        if note.pk == w.vk.pk() {
            return if is_dummy(&note) { Found::Skipped(DUMMY) } else { Found::Received(note, env.memo(cm, &key)) };
        }
        why = "sealed to this wallet but owned by another key";
    }
    // Still worth the sender path: an envelope this wallet sealed for someone else is opened
    // through `ovk`, not through the KEM, so the two openings are independent.
    if let Some((key, note)) = env.open_as_sender(cm, &w.vk) {
        return if is_dummy(&note) { Found::Skipped(DUMMY) } else { Found::Sent(note, env.memo(cm, &key)) };
    }
    Found::Skipped(why)
}

/// Transaction kinds (`tx_json`'s `kind`) whose chain-computed notes are public in full: one each
/// for the first three, up to four (an invoke's payouts) for the last.
const PUBLIC_NOTE_KINDS: [&str; 4] = ["bridge_attest", "token_mint", "register_token", "invoke"];

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
    rebuilt_notes_with(w, tx, None, None)
}

/// A chain's `bridge.fees` (v0.6.8) as a wallet needs it to rebuild bridge notes: the group, and
/// the release unit of every backing (`10^(8 − decimals)`, from `rand_getBridgeState.assets`).
/// Read from the node and never trusted: a rebuilt note is placed only at a leaf whose commitment
/// it hashes to, so a node lying about either only makes a note go unfound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeFeeCtx {
    pub fees: randprotocol_core::bridge::BridgeFees,
    pub units: BTreeMap<(u16, [u8; 32]), u64>,
}

impl BridgeFeeCtx {
    /// From a `rand_getBridgeState` reply: `None` without a bridge, without `fees` (a chain
    /// without the group, or a node older than v0.6.8) or with a field that does not parse.
    pub fn from_bridge_state(state: &Value) -> Option<BridgeFeeCtx> {
        let f = state.get("fees").filter(|f| !f.is_null())?;
        let fees = randprotocol_core::bridge::BridgeFees {
            mint_bps: u16::try_from(f["mint_bps"].as_u64()?).ok()?,
            burn_bps: u16::try_from(f["burn_bps"].as_u64()?).ok()?,
            recipient: ShieldedAddress::parse(f["recipient"].as_str()?).ok()?,
        };
        let mut units = BTreeMap::new();
        for row in state["assets"].as_array()? {
            let (Some(chain), Some(token), Some(decimals)) = (row["chain"].as_u64(), row["token"].as_str(), row["decimals"].as_u64()) else {
                continue;
            };
            let (Ok(chain), Some(token), Ok(decimals)) = (u16::try_from(chain), crate::hex32(token).ok(), u8::try_from(decimals)) else {
                continue;
            };
            units.insert((chain, token), randprotocol_core::ledger::tokens::release_unit(decimals));
        }
        Some(BridgeFeeCtx { fees, units })
    }

    fn unit(&self, chain: u16, token: &[u8; 32]) -> Option<u64> {
        self.units.get(&(chain, *token)).copied()
    }
}

/// [`rebuilt_notes`] on a chain with `bridge.fees` (v0.6.8, `ctx`): a deposit to this wallet is
/// the gross less the chain's fee, and when this wallet **is** the fee recipient it also rebuilds
/// the treasury's fee notes — a deposit's (blinding over the attestation's `mu`) and a burn's
/// (blinding over the burn's transaction id; `tx_hash` is that id when `tx` is a proof-stripped
/// copy, which hashes differently — the header's `public_notes` carries burns that way). `ctx`
/// `None` is [`rebuilt_notes`] exactly.
pub fn rebuilt_notes_with(w: &Wallet, tx: &Transaction, tx_hash: Option<&Hash>, ctx: Option<&BridgeFeeCtx>) -> Vec<Note> {
    let me = w.vk.pk();
    let fees = ctx.map(|c| &c.fees);
    let treasury = fees.is_some_and(|f| f.recipient.pk == me);
    let unit = |c: u16, t: &[u8; 32]| ctx.and_then(|x| x.unit(c, t));
    let fee_note = |n: bridge_notes::BridgeFeeNote| Note { pk: me, from: [0; 8], amount: n.amount, asset: n.asset, time: n.time, r: n.r };
    match &tx.action {
        Action::BridgeAttest { attestation, recipient, r, time, asset, .. } if recipient.pk == me || treasury => {
            // The ledger's own reading of the wire, so the amount cannot disagree with the one the
            // chain deposited. `None` is a rotation, which deposits nothing.
            let Some(split) = bridge_notes::attest_split_with(fees, attestation, *asset, *time, unit) else {
                return Vec::new();
            };
            let mut out = Vec::new();
            if recipient.pk == me {
                out.push(Note { pk: me, from: [0; 8], amount: split.net, asset: *asset, time: *time, r: *r });
            }
            if treasury {
                out.extend(split.fee.map(fee_note));
            }
            out
        }
        Action::BridgeBurn { .. } if treasury => {
            let hash = tx_hash.copied().unwrap_or_else(|| tx.hash());
            bridge_notes::burn_fee_note_with(fees, tx, &hash, unit).map(fee_note).into_iter().collect()
        }
        Action::TokenMint { asset, amount, recipient, r, time, .. } if recipient.pk == me => {
            vec![Note { pk: me, from: MINT_FROM, amount: *amount, asset: *asset, time: *time, r: *r }]
        }
        Action::RegisterToken { initial: Some(m), index, .. } if m.recipient.pk == me => {
            vec![Note { pk: me, from: MINT_FROM, amount: m.amount, asset: *index, time: m.time, r: m.r }]
        }
        // RPL-2: every note an invoke pays out or mints is public the same way — recipient,
        // amount, asset, blinding — with the chain's `PROGRAM_FROM` word and the *bundle's*
        // time (`program_state::payout_commitment`). Pays then mints, each to whoever it names.
        Action::Invoke { transition, .. } => {
            let Some(b) = &tx.bundle else { return Vec::new() };
            transition
                .payouts()
                .filter(|p| p.recipient.pk == me)
                .map(|p| Note { pk: me, from: randprotocol_core::ledger::program_state::PROGRAM_FROM, amount: p.amount, asset: p.asset, time: b.time, r: p.r })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Every note this wallet can rebuild out of blocks it has not read yet ([`rebuilt_notes`]),
/// keyed by the commitment the chain appended for it. [`scan`] matches each against the leaf
/// that carries that commitment, which is what turns a rebuilt note into an owned one at a known
/// index.
///
/// The pass reads headers [`BLOCK_PAGE`] at a time (`rand_getBlocks`). A node since audit v6
/// carries every public-note transaction raw beside its header (`public_notes`, issue #117), so
/// a page is all the walk reads; an older node's headers say only `tx_count`, and a block with
/// a transaction is fetched to look, and a raw transaction read for the three kinds that append
/// a public note. An idle chain costs a header page per `BLOCK_PAGE` blocks either way.
///
/// **The walk is resumable** (issue #117): `scanned_attest_height` moves past each page as it is
/// read, and what the page yielded is kept in `store.pending_public_notes` until the leaf pass
/// places it — the store is saved by every caller whether or not the scan finished, so a first
/// sync stopped by a rate limit or a dropped connection continues from the last page rather than
/// from block 0. Returns the notes to place: what earlier walks left pending, plus this one's.
///
/// A node started with `--prune-history` (every validator: one day) answers a page reaching below
/// its retention floor `-32010`, naming the floor — a fresh or rescanned store starts at 0, so
/// that is the first page it asks for. The walk resumes at the floor, and the scan warns once
/// ([`warn_pruned`]): what lies below it cannot be read from this node, and the cursor still
/// passes it, because asking again would only be refused again.
///
/// A page answered past this client's reply cap ([`crate::ReplyTooLarge`], a node without the
/// audit v7 RPC-5 reply budget) is asked again at half the range, down to one height, rather
/// than asked again whole — which would be refused again, for ever.
async fn rebuildable_notes(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore) -> Result<BTreeMap<Word8, Note>> {
    let head = rpc.head().await?["height"].as_u64().context("getHead did not return a height")?;
    // v0.6.8: the chain's `bridge.fees`, once per walk — what values this wallet's deposits and,
    // if it is the treasury, finds its fee notes. Any failure (no bridge, an older node) is a
    // chain without the group: deposits are the gross, as before.
    let fee_ctx = match rpc.bridge_state().await {
        Ok(state) => BridgeFeeCtx::from_bridge_state(&state),
        Err(_) => None,
    };
    let treasury = fee_ctx.as_ref().is_some_and(|c| c.fees.recipient.pk == w.vk.pk());
    let mut from = store.scanned_attest_height;
    // The highest floor a refusal named, if any page was refused.
    let mut pruned: Option<u64> = None;
    // How many heights the next page asks for. A node without a reply budget (before audit v7,
    // RPC-5) can answer a page past this client's reply cap — a dozen bridge deposits carried
    // whole did — and asking for the same page again only gets the same refusal, for ever: the
    // range is halved instead, down to one height, and grows back after each page that fits.
    let mut span = BLOCK_PAGE;
    'pages: while from <= head {
        let headers = match rpc.blocks(from, head.min(from.saturating_add(span - 1))).await {
            Ok(headers) => headers,
            // A page refused for its size, or still downloading when the read timeout ran out
            // (a slow link and a page of proof-carrying deposits): asked again at half the range.
            Err(e) if (crate::reply_too_large(&e) || crate::read_timed_out(&e)) && span > 1 => {
                span /= 2;
                continue;
            }
            Err(e) if crate::reply_too_large(&e) => {
                return Err(e.context(format!("the header of block {from} alone is larger than this wallet reads")));
            }
            Err(e) => {
                from = past_the_floor(e, from, &mut pruned)?;
                continue;
            }
        };
        span = span.saturating_mul(2).min(BLOCK_PAGE);
        let Some(last) = headers.iter().filter_map(|h| h["height"].as_u64()).max() else {
            return Err(anyhow!("getBlocks returned no header from height {from} though the head is {head}"));
        };
        if last < from {
            return Err(anyhow!("getBlocks returned headers below height {from}"));
        }
        let mut found: Vec<Note> = Vec::new();
        for header in &headers {
            let height = header["height"].as_u64().context("a block header without a height")?;
            if let Some(carried) = header.get("public_notes").and_then(|v| v.as_array()) {
                // A node that carries the transactions beside the header: nothing else to read.
                for entry in carried {
                    let raw = hex::decode(entry["raw"].as_str().unwrap_or_default())
                        .map_err(|e| anyhow!("block {height} carries a public-note transaction that is not hex: {e}"))?;
                    let tx = Transaction::decode(&raw).map_err(|e| anyhow!("block {height} carries a public-note transaction that does not decode: {e}"))?;
                    // A proof-stripped burn (v0.6.8) hashes differently: the entry names its id.
                    let hash = entry["hash"].as_str().and_then(|h| Hash::from_hex(h).ok());
                    found.extend(rebuilt_notes_with(w, &tx, hash.as_ref(), fee_ctx.as_ref()));
                }
                continue;
            }
            if header["tx_count"].as_u64().unwrap_or(0) == 0 {
                continue;
            }
            // A pruning pass can raise the floor between the header page and this read. The page
            // restarts at the floor and the cursor will pass every block below it, so what the
            // page already read is kept now, not dropped with it (audit v7, CLI-18).
            let block = match rpc.block_by_height(height).await {
                Ok(block) => block,
                Err(e) => {
                    from = past_the_floor(e, height, &mut pruned)?;
                    for note in found.drain(..) {
                        store.pending_public_notes.insert(word8_to_hex(&note.commitment()), PendingNote { note });
                    }
                    continue 'pages;
                }
            };
            let Some(txs) = block["transactions"].as_array() else { continue };
            for tx in txs {
                let kind = tx["action"]["kind"].as_str().unwrap_or_default();
                // A burn appends a public note only on a chain with `bridge.fees`, and only for
                // the treasury: nobody else fetches burns (they are megabytes of proof).
                if !PUBLIC_NOTE_KINDS.contains(&kind) && !(treasury && kind == "bridge_burn") {
                    continue;
                }
                let hash = Hash::from_hex(tx["hash"].as_str().unwrap_or_default())
                    .map_err(|e| anyhow!("block {height} renders a transaction hash that does not parse: {e}"))?;
                let raw = rpc
                    .raw_transaction(&hash)
                    .await?
                    .with_context(|| format!("the node serves no raw transaction for {hash}, committed in block {height}"))?;
                found.extend(rebuilt_notes_with(w, &raw, Some(&hash), fee_ctx.as_ref()));
            }
        }
        // The page is read whole: keep what it held and move the cursor past it together, so a
        // store saved after this point neither re-reads the page nor forgets its notes.
        for note in found {
            store.pending_public_notes.insert(word8_to_hex(&note.commitment()), PendingNote { note });
        }
        from = last + 1;
        store.scanned_attest_height = store.scanned_attest_height.max(from);
    }
    store.scanned_attest_height = store.scanned_attest_height.max(head + 1);
    if let Some(floor) = pruned {
        warn_pruned(floor);
    }
    Ok(store.pending_public_notes.values().map(|p| (p.note.commitment(), p.note)).collect())
}

/// Where the block walk resumes after `e`, an error answered for a read at height `at`: the floor
/// a pruned node's `-32010` names, when it lies above `at` (recorded in `pruned`). Any other error
/// is the scan's — as is a floor at or below `at`, which would not move the walk.
fn past_the_floor(e: anyhow::Error, at: u64, pruned: &mut Option<u64>) -> Result<u64> {
    match crate::pruned_floor(&e) {
        Some(floor) if floor > at => {
            *pruned = Some(pruned.map_or(floor, |p| p.max(floor)));
            Ok(floor)
        }
        _ => Err(e),
    }
}

/// The one warning a scan against a pruned node prints. Only the public-rebuild pass is short:
/// the commitment and nullifier pages come from the node's ledger, which pruning never touches,
/// so every note whose envelope opens is found and every spend is seen. What the pass exists for
/// — a deposit or mint published with an envelope that does not open — is lost below the floor
/// for this scan, and since the cursor has passed it, only a rescan against an archive reads it.
fn warn_pruned(floor: u64) {
    eprintln!(
        "warning: this node has pruned its blocks below height {floor}, so they were not read. A bridge deposit \
         (bridge_attest), token mint (token_mint), registration's initial mint (register_token) or program payout (invoke) to this wallet \
         committed below that height is still found if its envelope opens, as an honestly sealed one does, but one \
         whose envelope does not open cannot be recovered from this node. Shielded notes and spends are unaffected \
         (the node never prunes its commitments or nullifiers). For a complete scan, run \
         `rand --rpc <archive node> sync --rescan`."
    );
}

/// Headers per `rand_getBlocks` page: the node's own cap (`rpc::MAX_BLOCK_HEADERS`). An older
/// node clamps a page to its 128 and the walk above advances from the last header it got, so
/// asking for the larger page costs nothing against one.
const BLOCK_PAGE: u64 = 1024;

/// What one leaf turned out to be for the store, for the tree half of [`offer_row`].
enum Placement {
    /// Not this wallet's to spend (a note it sent, a stranger's, a dummy).
    NotMine,
    /// An owned note the store already had: the tree owes it nothing new (it was appended as
    /// this wallet's, or its witness was deliberately forgotten when it was spent).
    MineKnown,
    /// An owned note, newly recorded. If the tree already holds this leaf it was appended as
    /// not-mine — a scan placed it before the wallet knew it was ours, which no completed scan
    /// leaves behind — and owes it a witness it does not have: [`Offered::RebuildTree`].
    MineNew,
}

/// Record what one leaf is for this wallet, returning its [`Placement`]. `rebuilt` is what
/// [`rebuildable_notes`] found: a leaf whose commitment is in it is this wallet's deposit or mint
/// whatever its envelope says, so it is tried first and the envelope is never consulted for it.
fn place_leaf(w: &Wallet, store: &mut NoteStore, row: &CommitmentRow, rebuilt: &mut BTreeMap<Word8, Note>) -> Placement {
    let found = match rebuilt.remove(&row.cm) {
        // A rebuilt note (a deposit or a mint) is found from the transaction's public fields,
        // never its envelope — there is nothing to open a memo out of.
        Some(note) => Found::Received(note, None),
        None => classify(w, row.cm, &row.envelope),
    };
    match found {
        // A note can be re-offered by a rescan; the index is the leaf, so it is unique.
        Found::Received(note, memo) => {
            if store.notes.iter().any(|n| n.index == row.index) {
                Placement::MineKnown
            } else {
                store.notes.push(OwnedNote {
                    index: row.index,
                    cm: row.cm,
                    nf: w.vk.nullifier(&row.cm),
                    note,
                    spent: false,
                    pending: None,
                    height: row.height,
                    memo,
                });
                Placement::MineNew
            }
        }
        Found::Sent(note, memo) => {
            if !store.sent.iter().any(|s| s.index == row.index) {
                store.sent.push(SentRow { index: row.index, to_pk: note.pk, amount: note.amount, height: row.height, memo });
            }
            Placement::NotMine
        }
        Found::Skipped(why) => {
            if why != NOT_OURS && why != DUMMY {
                eprintln!("warning: ignoring leaf {}: {why}", row.index);
            }
            Placement::NotMine
        }
    }
}

/// What [`offer_row`] did with a leaf.
enum Offered {
    /// The tree took it.
    Appended,
    /// The tree already had it (a re-offer); nothing moved.
    Skipped,
    /// The tree already had it, but as not-mine, and the leaf just turned out to be this
    /// wallet's own note — a deposit recovered from public fields at a leaf an earlier, torn
    /// scan placed without the wallet knowing. The tree owes it a witness and cannot grow one
    /// backwards, so the scan restarts from 0 and rebuilds it.
    RebuildTree,
}

/// Offer one leaf to the store: record what it is to this wallet, and append it to the wallet's
/// own commitment tree — the tree every send now takes its witnesses from, rather than asking the
/// node for the witnesses of exactly the notes it spends (audit v3 PRIV-1).
///
/// The tree half is keyed on the leaf's index, so a re-offer is idempotent: a row the tree
/// already holds — the recovery pass re-reads leaves from 0, and a rescan re-reads everything —
/// is skipped, never double-appended; a row *past* the end means the node skipped a leaf, which
/// no correct node does. Before a row of height `h` is appended, every block below `h` is
/// provably complete — rows arrive in index order, which is height order — so the tree's root is
/// recorded as that block end's root first ([`LocalTree::checkpoint`]). Those checkpoints are the
/// block-end roots a send anchors against.
fn offer_row(w: &Wallet, store: &mut NoteStore, row: &CommitmentRow, rebuilt: &mut BTreeMap<Word8, Note>, h: &dyn Fn(&Word8, &Word8) -> Word8) -> Result<Offered> {
    let placement = place_leaf(w, store, row, rebuilt);
    if row.index < store.tree.next_index() {
        return Ok(match placement {
            Placement::MineNew if store.tree.path(row.index).is_none() => Offered::RebuildTree,
            _ => Offered::Skipped,
        });
    }
    if row.index > store.tree.next_index() {
        return Err(anyhow!(
            "getCommitments served leaf {} where leaf {} comes next; the node's leaves and this wallet's tree disagree",
            row.index,
            store.tree.next_index()
        ));
    }
    if let Some(complete) = row.height.checked_sub(1) {
        store.tree.checkpoint(complete, h);
    }
    store.tree.append(row.cm, !matches!(placement, Placement::NotMine), h);
    Ok(Offered::Appended)
}

/// Trial-decrypt every commitment this wallet has not seen yet, growing the wallet's own
/// commitment tree with every leaf read, then mark as spent every note whose nullifier the chain
/// has published. Advances the store and saves nothing — the caller owns the file.
pub async fn scan(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore) -> Result<()> {
    // Which chain this node serves, before any cursor of the store is trusted: a store carried
    // across a chain cut is started over here, not scanned past the end of the new tree.
    let chain = rpc.genesis_hash().await?;
    let had_rows = store.scanned_index > 0 || !store.notes.is_empty();
    match store.bind(chain) {
        Bound::Same => {}
        Bound::Reset { previous: Some(previous) } => eprintln!(
            "warning: the note store was scanned against chain {}, but this node serves chain {}; rescanning from the start",
            previous.to_hex(),
            chain.to_hex()
        ),
        Bound::Reset { previous: None } if had_rows => eprintln!(
            "warning: the note store does not say which chain it was scanned against; rescanning from the start to bind it to chain {}",
            chain.to_hex()
        ),
        Bound::Reset { previous: None } => {}
    }

    // The tree and the leaf cursor advance together (every append is a row the cursor then
    // passes), so the tree is never behind the cursor — a store that says otherwise is torn or
    // hand-edited, and would serve wrong witnesses. Rebuild both from 0, the same repair
    // `NoteStore::load` makes of an unreadable store. (The tree being *ahead* is fine: it means
    // a recovery pass ran ahead of the cursor, and the forward pass skips what it already has.)
    if store.tree.next_index() < store.scanned_index {
        eprintln!(
            "warning: the note store's tree ({} leaves) is behind its scan cursor ({}); rescanning from the start",
            store.tree.next_index(),
            store.scanned_index
        );
        store.tree = LocalTree::default();
        store.scanned_index = 0;
    }

    // One pass in every ordinary scan. The second is the repair for the torn corner
    // [`Offered::RebuildTree`] names: the pass restarts with a fresh tree and cursor, so the
    // recovered note is re-offered — already in `notes`, so this time appended as this wallet's —
    // and gets its witness. Twice is a bound, never an expectation.
    for rebuilds in 0..2 {
        match scan_pass(rpc, w, store).await? {
            ScanPass::Done => return Ok(()),
            ScanPass::RebuildTree if rebuilds == 0 => {
                eprintln!("warning: a recovered note has no witness in the store's tree; rebuilding the tree from the start");
                store.tree = LocalTree::default();
                store.scanned_index = 0;
            }
            ScanPass::RebuildTree => {
                return Err(anyhow!("the note store's tree cannot be repaired; move it away and rescan from the start"));
            }
        }
    }
    unreachable!("the loop returns on the second rebuild at the latest")
}

/// The outcome of one [`scan_pass`]: the scan is complete, or the tree must be rebuilt from 0
/// and the pass restarted.
enum ScanPass {
    Done,
    RebuildTree,
}

/// One scan pass: page every commitment this wallet has not seen yet, growing the wallet's own
/// commitment tree with every leaf read, then mark as spent every note whose nullifier the chain
/// has published. Advances the store and saves nothing — the caller owns the file.
async fn scan_pass(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore) -> Result<ScanPass> {
    // What the envelope layer cannot be trusted to deliver, read off the wire instead. Done
    // before the leaves are paged, so a deposit or a mint is placed by the same pass that first sees its
    // leaf rather than a scan later.
    let mut rebuilt = rebuildable_notes(rpc, w, store).await?;
    let h = tree_hash();
    // The height of the last leaf the tree took this scan — the tip its freshest checkpoint is
    // recorded at below.
    let mut tip: Option<u64> = None;

    loop {
        let rows = rpc.commitments(store.scanned_index, PAGE).await?;
        if rows.is_empty() {
            break;
        }
        let before = store.scanned_index;
        for row in &rows {
            match offer_row(w, store, row, &mut rebuilt, &h)? {
                Offered::Appended => tip = Some(row.height),
                Offered::Skipped => {}
                Offered::RebuildTree => return Ok(ScanPass::RebuildTree),
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

    // A rebuilt deposit whose leaf sits *below* the cursor — an attestation this wallet read the
    // blocks of only now, having scanned past its leaf with an older build — is placed by reading
    // the leaves again from the start. Re-offering a leaf costs nothing (every record here is
    // keyed by its index), and this loop runs at most once per recovered deposit, because the
    // deposit is in the store from then on.
    let mut from = 0;
    while !rebuilt.is_empty() {
        let rows = rpc.commitments(from, PAGE).await?;
        if rows.is_empty() {
            // Every leaf there is has been offered and some rebuilt note still has no leaf: the
            // node rendered a public-note transaction whose commitment its own tree does not hold.
            // The note is not credited — only a leaf makes a rebuilt note owned — and it is not
            // kept pending either: one planted transaction would otherwise fail every later scan,
            // against an honest node too, until `rand sync --rescan` (audit v7, CLI-19).
            for cm in rebuilt.keys() {
                eprintln!(
                    "warning: dropping a rebuilt deposit or mint note with commitment {}: it matches no leaf of the tree, \
                     so the node's blocks and leaves disagree; it is not credited",
                    word8_to_hex(cm)
                );
            }
            rebuilt.clear();
            break;
        }
        let before = from;
        for row in &rows {
            match offer_row(w, store, row, &mut rebuilt, &h)? {
                Offered::Appended => tip = Some(row.height),
                Offered::Skipped => {}
                Offered::RebuildTree => return Ok(ScanPass::RebuildTree),
            }
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

    // Every rebuilt note is at its leaf now, or was dropped above for having none; the walk's
    // cursor already passed the blocks they came from, so nothing is pending any more. Any error
    // above returns before this line and leaves the pending set in the store, for the next scan
    // to place without re-reading a block (issue #117).
    debug_assert!(rebuilt.is_empty());
    store.pending_public_notes.clear();

    // The leaf pass paged to empty, so the tree holds every committed leaf the node had — the
    // last leaf's own block is provably complete, and the root at its end is the freshest anchor
    // a send can use. (The tip block still accepting leaves is never checkpointed; only block
    // ends the node's replies prove complete are.)
    if let Some(tip) = tip {
        store.tree.checkpoint(tip, &h);
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
                // A spent note can never be an input again, so its witness is dead weight: the
                // tree keeps only what unspent owned notes still need.
                store.tree.forget(n.index);
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

    // Resolve anything a `--no-wait` submission left pending, now that the chain has answered —
    // after the chain's own window (issue #118), read only when something is pending.
    let window = if store.notes.iter().any(|n| n.pending.is_some()) { pending_window(rpc.limits().await?.as_ref()) } else { TIME_WINDOW };
    clear_pending(store, store.scanned_height.saturating_sub(1), window);
    Ok(ScanPass::Done)
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
/// because the blocks read reach past `time + window` (the chain's proof window, [`TIME_WINDOW`]
/// without a genesis `proof_window_blocks`), the last height at which a bundle stamped `time`
/// could still be admitted: after that the submission can never commit, so the
/// note is free again. The bound is what was read, never a head fetched later.
fn clear_pending(store: &mut NoteStore, read_through: u64, window: u64) {
    for n in store.notes.iter_mut() {
        if let Some(time) = n.pending {
            if n.spent || read_through > time as u64 + window {
                n.pending = None;
            }
        }
    }
}

/// The window [`clear_pending`] waits out (issue #118): the chain's `proof_window_blocks` from
/// `rand_getLimits`, or [`TIME_WINDOW`] where the node serves none (no field, or a node that
/// predates it or the method).
///
/// The node's word is unauthenticated, and it decides only this wallet's own bookkeeping: when a
/// `--no-wait` spend that never showed up is given up on. Clamped to the bounds a genesis can
/// carry, so a lying node can move that moment only inside [256, 4096] blocks: too early, and the
/// wallet may try to spend the note again — the chain refuses the second spend if the first one
/// committed (`Spent`), so nothing is lost but a fee-less refusal; too late, and the note looks
/// unspendable for at most 4 096 blocks. It changes nothing the chain checks.
fn pending_window(limits: Option<&ChainLimits>) -> u64 {
    limits
        .and_then(|l| l.proof_window_blocks)
        .map_or(TIME_WINDOW, |w| w.clamp(MIN_PROOF_WINDOW_BLOCKS, MAX_PROOF_WINDOW_BLOCKS))
}

// ---------------------------------------------------------------- coin selection

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    /// The wallet holds enough, but not in two notes. Consolidate first: each group of a bundle
    /// (the asset's slots 0–1, RAND's slots 2–3) spends at most two inputs (design spec §3), so no
    /// amount of dust adds up to a third slot.
    #[error("need more than two notes; the largest two hold {largest_two} units — consolidate first")]
    NeedsMoreThanTwo { largest_two: u64 },
    #[error("insufficient balance: {have} units (if notes this wallet holds show as spent, `rand sync --rescan` rebuilds the store from the chain)")]
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
    sorted.sort_by_key(|n| std::cmp::Reverse(n.note.amount));
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
    /// RPL-2: an `Invoke`'s bundle may burn both at once — `burn_r` RAND and `burn_a` of the
    /// token at `index` — into the program's vault (or, for the program's own token, out of
    /// existence). `index` is [`Submission::asset`] when `amount` is non-zero; `rand` is what
    /// the RAND slots burned.
    Both { rand: u64, index: u32, amount: u64 },
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

    /// What an invoke's bundle burns: `rand` RAND and `amount` of the token at `index`, either
    /// zero — collapsed to the one-sided variants (or [`Burn::None`]) so a printer sees one
    /// event.
    pub fn invoke(rand: u64, index: u32, amount: u64) -> Burn {
        match (rand, amount) {
            (0, 0) => Burn::None,
            (_, 0) => Burn::Rand(rand),
            (0, _) => Burn::Asset { index, amount },
            _ => Burn::Both { rand, index, amount },
        }
    }

    /// The units burned, zero when nothing is: a token's units where a token is burned, else RAND's.
    pub fn units(self) -> u64 {
        match self {
            Burn::None => 0,
            Burn::Rand(amount) | Burn::Asset { amount, .. } | Burn::Both { amount, .. } => amount,
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
    /// How long the bundle proof took (here or on the paired prover).
    pub proving: Duration,
    /// How long the auth proof took, on this machine — `None` on a chain without split
    /// authorisation, whose transactions carry none.
    pub auth_proving: Option<Duration>,
    /// The RAND paid to the paired prover by one output of this bundle (spec §5), zero when the
    /// bundle was proved here or by a prover that charges nothing.
    pub prover_fee: u64,
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
            Burn::Rand(amount) | Burn::Both { rand: amount, .. } => format!("{} RAND burned, ", format_amount(amount)),
        };
        // A v3 transaction carries two proofs; both times are reported. Every other chain's
        // line is unchanged.
        let proved = match self.auth_proving {
            Some(auth) => format!(", proved in {:.1?} (bundle) + {auth:.1?} (auth)", self.proving),
            None => String::new(),
        };
        let prover_fee = match self.prover_fee {
            0 => String::new(),
            p => format!(", prover fee {} RAND", format_amount(p)),
        };
        format!(
            "submitted {what} {}\n  {out} out, {burned}{change} change, fee {} RAND{prover_fee}{fee_change}, anchored at height {}{proved}",
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
    /// The paired prover's fee (spec §5): a RAND output to its address, sealed with no memo.
    Prover(ShieldedAddress),
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
///
/// A paired prover's fee (spec §5, [`Plan::prover_fee`]) is one more RAND output: slot 2 of a
/// token transfer, a burn or a RAND bundle that pays nobody (the RAND change moves to slot 3);
/// slot 0 of a RAND transfer, whose slots 2–3 already hold the payment and its change — so that
/// transfer spends a RAND note in slots 0–1 for the fee (its change in slot 1) and another in
/// slots 2–3, and a wallet holding one RAND note must split it first.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    asset: u32,
    /// The notes of `asset` spent in slots 0–1: empty when `asset` is RAND.
    a_notes: Vec<OwnedNote>,
    /// The RAND notes spent in slots 2–3.
    r_notes: Vec<OwnedNote>,
    /// The payment, if the bundle pays anyone: the recipient and the amount, in `asset`.
    to: Option<(ShieldedAddress, u64)>,
    /// The memo sealed with the payment slot, `""` for none — never sealed with a change or
    /// dummy slot, which is why this lives beside `to` rather than beside the whole plan.
    memo: String,
    fee: u64,
    /// Burned from the asset's slots (`asset` must then be a token).
    burn_a: u64,
    /// RAND burned from slots 2–3.
    burn_r: u64,
    /// The paired prover's address and fee, in RAND, when it charges one.
    prover_fee: Option<(ShieldedAddress, u64)>,
}

/// What [`Plan::select`] is asked for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Spend<'a> {
    /// The asset of slots 0–1: 0 for RAND, otherwise a token's registry index.
    pub asset: u32,
    /// The payment, in `asset`; `None` for a bundle that pays nobody (a deploy, a bond, a burn).
    pub to: Option<(&'a ShieldedAddress, u64)>,
    /// The memo to seal with the payment, `""` for none. A chain that predates `envelope_bytes`
    /// refuses a non-empty one before anything is proved ([`seal_note_as`]).
    pub memo: &'a str,
    pub fee: u64,
    pub burn_a: u64,
    pub burn_r: u64,
    /// The paired prover's fee (spec §5): its address and the RAND it quotes. [`submit_spend`]
    /// fills it from the prover's `prover_info`; every caller passes `None`.
    pub prover_fee: Option<(&'a ShieldedAddress, u64)>,
}

/// The refusal for a RAND transfer through a fee-charging prover from a wallet with one RAND note.
pub const SPLIT_FIRST: &str = "a RAND transfer through a prover that charges a fee spends two RAND notes — one for the \
     prover's fee (slots 0–1), one for the payment (slots 2–3) — and this wallet holds one spendable RAND note: split it \
     first with a self-transfer proved without --prover (`rand send <your address> <part of it>`), then retry";

impl Plan {
    /// Select both groups' notes in one plan, largest-first and at most two per group
    /// ([`select_inputs`]).
    ///
    /// The fee is RAND, always (spec §3.9): a token bundle whose wallet holds no spendable RAND is
    /// refused here, with the reason, before anything is proved.
    pub(crate) fn select(store: &NoteStore, spend: Spend<'_>) -> Result<Plan> {
        let Spend { asset, to, memo, fee, burn_a, burn_r, prover_fee } = spend;
        let amount = to.map_or(0, |(_, a)| a);
        let pf = prover_fee.map_or(0, |(_, f)| f);
        let (a_notes, r_notes) = if asset == 0 {
            // RAND is burned through `burn_r` only; the ledger refuses a RAND `burn_a`
            // (`NonCanonicalRandBurn`), so a plan that asked for one is this wallet's bug.
            if burn_a != 0 {
                return Err(anyhow!("a RAND burn goes through burn_r, never burn_a"));
            }
            if pf > 0 && to.is_some() {
                // A RAND transfer: the payment and its change fill slots 2–3, so the prover's fee
                // is paid from slots 0–1 — a second RAND note, disjoint from the first group.
                select_rand_pair(&store.spendable_of(0), bundle_need(amount, fee, burn_r)?, pf)?
            } else {
                // Anything else in RAND pays the prover from slots 2–3, beside the change.
                let need = bundle_need(amount, fee, burn_r)?.checked_add(pf).ok_or_else(|| anyhow!("amount + fees overflow"))?;
                (Vec::new(), select_inputs(&store.spendable_of(0), need)?)
            }
        } else {
            let need_a = bundle_need(amount, 0, burn_a)?;
            if need_a == 0 {
                return Err(anyhow!("a bundle of asset {asset} that neither pays nor burns any of it"));
            }
            let need_r = bundle_need(0, fee, burn_r)?.checked_add(pf).ok_or_else(|| anyhow!("fee + prover fee overflows"))?;
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
        let prover_fee = prover_fee.filter(|(_, f)| *f > 0).map(|(d, f)| (d.clone(), f));
        Ok(Plan { asset, a_notes, r_notes, to: to.map(|(d, a)| (d.clone(), a)), memo: memo.to_string(), fee, burn_a, burn_r, prover_fee })
    }

    fn prover_fee_amount(&self) -> u64 {
        self.prover_fee.as_ref().map_or(0, |(_, f)| *f)
    }

    /// The prover's fee is paid from slots 0–1: a RAND transfer, whose slots 2–3 hold the payment
    /// and its change (spec §5's table).
    fn prover_fee_in_a(&self) -> bool {
        self.asset == 0 && self.to.is_some() && self.prover_fee.is_some()
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
        let have: u64 = self.a_notes.iter().map(|n| n.note.amount).sum();
        if self.asset == 0 {
            // RAND in slots 0–1 only to pay a prover's fee (a RAND transfer's).
            return if self.prover_fee_in_a() { have - self.prover_fee_amount() } else { 0 };
        }
        have - self.amount() - self.burn_a
    }

    /// The RAND change (slots 2–3).
    fn change_r(&self) -> u64 {
        let have: u64 = self.r_notes.iter().map(|n| n.note.amount).sum();
        let paid_here = if self.asset == 0 { self.amount() } else { 0 };
        let prover_here = if self.prover_fee_in_a() { 0 } else { self.prover_fee_amount() };
        have - paid_here - self.fee - self.burn_r - prover_here
    }

    /// What each output slot pays, and how much. A zero amount is a dummy sealed to nobody —
    /// including a change of exactly zero, which is worth nothing to keep.
    fn outputs(&self) -> [(Payee, u64); SLOTS] {
        let pay = |amount: u64| match &self.to {
            Some((dest, _)) if amount > 0 => (Payee::To(dest.clone()), amount),
            _ => (Payee::Nobody, 0),
        };
        let mine = |amount: u64| if amount > 0 { (Payee::Me, amount) } else { (Payee::Nobody, 0) };
        let prover = self.prover_fee.as_ref().map(|(d, f)| (Payee::Prover(d.clone()), *f));
        match (self.asset == 0, prover) {
            (true, None) => [(Payee::Nobody, 0), (Payee::Nobody, 0), pay(self.amount()), mine(self.change_r())],
            // A RAND transfer: the prover in slot 0, the fee note's change in slot 1.
            (true, Some(p)) if self.to.is_some() => [p, mine(self.change_a()), pay(self.amount()), mine(self.change_r())],
            // A RAND bundle that pays nobody (a bond, a deploy, a call, a bridge action).
            (true, Some(p)) => [(Payee::Nobody, 0), (Payee::Nobody, 0), p, mine(self.change_r())],
            (false, None) => [pay(self.amount()), mine(self.change_a()), mine(self.change_r()), (Payee::Nobody, 0)],
            // A token transfer or a burn: the prover in slot 2, the RAND change in slot 3.
            (false, Some(p)) => [pay(self.amount()), mine(self.change_a()), p, mine(self.change_r())],
        }
    }

    /// The fields a [`Submission`] reports for this plan.
    fn report(&self, hash: Hash, burn: Burn, time: u32, proved: &Proved) -> Submission {
        let (amount, change, rand_change) = match burn {
            // A token burn's figures are the token's: what left the pool, and what came back.
            Burn::Asset { amount, .. } | Burn::Both { amount, .. } => (amount, self.change_a(), self.change_r()),
            // Every RAND that came back: slots 2–3's, and slot 1's when a prover's fee note sat there.
            _ if self.asset == 0 => (self.amount(), self.change_r() + self.change_a(), 0),
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
            auth_proving: proved.auth_proving,
            prover_fee: self.prover_fee_amount(),
        }
    }
}

/// Two disjoint groups of RAND notes, at most two each: one covering `need_r` (slots 2–3: the
/// payment, the chain fee, any burn) and one covering `prover_fee` (slots 0–1). The larger group is
/// served largest-first; if what is left cannot pay the prover, the smallest note that does is set
/// aside for it first and the rest tried again. One spendable note can never make two groups:
/// [`SPLIT_FIRST`].
fn select_rand_pair(rand: &[&OwnedNote], need_r: u64, prover_fee: u64) -> Result<(Vec<OwnedNote>, Vec<OwnedNote>)> {
    let total: u64 = rand.iter().map(|n| n.note.amount).sum();
    if total < need_r.saturating_add(prover_fee) {
        return Err(anyhow!(
            "insufficient balance: the payment and chain fee need {} RAND and the prover's fee {} RAND more, and this wallet holds {} RAND",
            format_amount(need_r),
            format_amount(prover_fee),
            format_amount(total)
        ));
    }
    if rand.len() == 1 {
        return Err(anyhow!(SPLIT_FIRST));
    }
    let without = |taken: &[OwnedNote]| -> Vec<&OwnedNote> { rand.iter().copied().filter(|n| !taken.iter().any(|t| t.index == n.index)).collect() };
    if let Ok(r) = select_inputs(rand, need_r) {
        if let Ok(a) = select_inputs(&without(&r), prover_fee) {
            return Ok((a, r));
        }
    }
    let mut by_size: Vec<&OwnedNote> = rand.to_vec();
    by_size.sort_by_key(|n| n.note.amount);
    if let Some(fee_note) = by_size.iter().find(|n| n.note.amount >= prover_fee) {
        let a = vec![(*fee_note).clone()];
        if let Ok(r) = select_inputs(&without(&a), need_r) {
            return Ok((a, r));
        }
    }
    Err(anyhow!(
        "a RAND transfer through a prover that charges a fee pays it from a second group of at most two RAND notes, \
         and this wallet's notes do not divide into two such groups: send yourself one note that covers the payment \
         and the chain fee (a self-transfer proved without --prover), then retry"
    ))
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
    /// The chain's bundle guest — its genesis `hc_bundle`, as `rand_status` names it — which is
    /// the program this bundle is proved with ([`ZkExecutor::bundle_program_for`]). Chains 14 and
    /// 15 run the v1 hidden guest; a later genesis may name the branch-free v2 (INT-2 / GV-1).
    /// Both read this witness and publish this digest, so only the program differs — and a proof
    /// of the other one would be refused by every validator. v3 (split authorisation) reads its
    /// own witness and publishes its own digest: see `v3`.
    guest: Word8,
    /// The chain runs split authorisation (spec 2026-09-28 §4.1): `guest` is bundle guest v3, the
    /// witness carries `nk` and `salt` instead of the spend key, `expected` is the v3 digest, and
    /// the transaction needs a second proof — the auth proof, made by this wallet over its spend
    /// key and `salt`, publishing `auth_commit`. False on every chain without genesis `hc_auth`.
    v3: bool,
    /// 256 fresh random bits, drawn for this bundle alone: a repeated salt repeats `auth_commit`
    /// and links two transactions to one wallet, and no guest can tell. Zero when not `v3`.
    salt: Word8,
    /// `auth::auth_commit(nk, salt)` — the bundle's `auth_commit`, which the auth proof must
    /// publish and the v3 digest folds in. Zero when not `v3`.
    auth_commit: Word8,
}

/// The witness carries a long-term secret — `nk` on v3, the spend key on v1/v2 — and `salt` is
/// what keeps `auth_commit` unlinkable, so both are wiped when the bundle is dropped (review M-9),
/// on every path, the error returns included. `zeroize` writes through volatile stores the
/// optimiser cannot elide; a copy the prover or the RPC client took is theirs to wipe. Not unit
/// tested: reading freed memory to prove the wipe is undefined behaviour.
impl Drop for Prepared {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.words.zeroize();
        self.salt.zeroize();
    }
}

/// One transaction's proofs, made against its binding: the bundle's, and on a v3 chain the auth
/// proof (empty elsewhere).
struct Proved {
    proof: Vec<u8>,
    tier: u8,
    proving: Duration,
    auth_proof: Vec<u8>,
    /// How long the auth proof took; `None` when the chain has no split authorisation.
    auth_proving: Option<Duration>,
}

/// The auth proof's half of [`check_published_digest`]: the `c` it publishes must be the bundle's
/// `auth_commit`, or the ledger refuses the pair — and since this wallet computed both from its
/// own `nk` and `salt`, a mismatch is a bug here.
fn check_published_auth(c: &Word8, auth_commit: &Word8) -> Result<()> {
    if c != auth_commit {
        return Err(anyhow!(
            "the auth proof published {} but this bundle's auth_commit is {} — refusing to submit (wallet bug)",
            word8_to_hex(c),
            word8_to_hex(auth_commit),
        ));
    }
    Ok(())
}

/// Makes the auth proof on this machine — always here, never on a prover, because its witness is
/// the spend key. Tier 10, seconds.
fn prove_auth_locally(prepared: &Prepared, sk: &SpendKey, binding: &[u32; TX_BINDING_WORDS], profile: FriProfile, backend: Backend) -> Result<(Vec<u8>, Duration)> {
    eprintln!("proving the spend authorisation on this machine (tier 10; seconds)…");
    let started = Instant::now();
    let (proof, c, tier) = prove_auth(profile, sk, &prepared.salt, binding, backend).map_err(|e| anyhow!("proving the spend authorisation failed: {e}"))?;
    let took = started.elapsed();
    eprintln!("authorisation proved in {took:.1?}: tier {tier}, {} bytes", proof.len());
    check_published_auth(&c, &prepared.auth_commit)?;
    Ok((proof, took))
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
    /// the transaction it receives and refuses a proof made for any other. The auth proof, on a
    /// v3 chain, is [`prove_auth_locally`]'s and not made here.
    fn prove(&self, binding: &[u32; TX_BINDING_WORDS], profile: FriProfile, backend: Backend) -> Result<Proved> {
        eprintln!("proving the bundle (tier 14; about a minute and a half on a laptop)…");
        let started = Instant::now();
        let (proof, digest, tier) = prove_bundle_for(&self.guest, profile, &self.words, binding, backend)
            .map_err(|e| anyhow!("proving the bundle failed: {e}"))?;
        let proving = started.elapsed();
        eprintln!("proved in {proving:.1?}: tier {tier}, {} bytes", proof.len());
        check_published_digest(&digest, &self.expected)?;
        Ok(Proved { proof, tier, proving, auth_proof: Vec::new(), auth_proving: None })
    }
}

/// Test-only (the chain-18 capstone, `randprotocol-node`'s `tests/cluster.rs`): a plain RAND
/// transfer built and proved exactly as [`send`] builds and proves one — the same scan, plan,
/// anchor, envelopes and binding — except that its bundle proof declares `bundle_gas_limit` as
/// its `GAS_LIMIT` rather than the guest's ceiling. Returned unsubmitted, so the caller submits
/// it and reads the refusal by hash. The store is left as though nothing was sent: the spent
/// notes are not marked pending, so a caller that did get the transaction committed must rescan. Never a wallet path: every honest bundle declares the
/// ceiling ([`check_bundle_gas_limit`]).
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn build_transfer_declaring_bundle_gas(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    amount: u64,
    fee: u64,
    profile: FriProfile,
    chain_id: u64,
    bundle_gas_limit: u64,
) -> Result<Transaction> {
    scan(rpc, w, store).await?;
    let guest = chain_bundle_guest(rpc).await?;
    let plan = Plan::select(store, Spend { asset: 0, to: Some((to, amount)), memo: "", fee, burn_a: 0, burn_r: 0, prover_fee: None })?;
    let format = rpc.envelope_format(chain_id).await?;
    let (prepared, _) = prepare_bundle(rpc, w, store, &plan, format, &guest).await?;
    let mut tx = Transaction::shielded(chain_id, prepared.bundle.clone(), Action::None);
    let domain = scanned_binding_domain(rpc, store, chain_id).await?;
    let p = &prepared;
    prove_transaction_by(&mut tx, &domain, |binding| async move {
        // On a v3 chain the auth proof rides beside the bundle, exactly as `send` makes it.
        let auth = p.v3.then(|| prove_auth_locally(p, &w.sk, &binding, profile, Backend::Cpu)).transpose()?;
        let started = Instant::now();
        let (proof, digest, tier) =
            randprotocol_zkvm::executor::prove_bundle_for_with_limit(&p.guest, profile, &p.words, &binding, bundle_gas_limit)
                .map_err(|e| anyhow!("proving the bundle failed: {e}"))?;
        check_published_digest(&digest, &p.expected)?;
        Ok(with_auth(Proved { proof, tier, proving: started.elapsed(), auth_proof: Vec::new(), auth_proving: None }, auth))
    })
    .await?;
    Ok(tx)
}

/// How a submission proves its bundle: on this machine ([`Proving::Local`]), on a paired prover
/// ([`Proving::Remote`], `rand --prover`), or — in unit tests — the guest run in the emulator,
/// whose digest is checked exactly as a proof's is. The FRI profile is the chain's and travels
/// beside it, not inside it.
///
/// On a v3 chain (split authorisation) the transaction's second proof, the auth proof, is made on
/// this machine whichever is chosen — its witness is the spend key, which never leaves the wallet
/// — and a remote prover is sent the v3 witness, which carries the viewing key's `nk` instead.
/// On a chain whose bundle guest is v1 or v2 the bundle's own witness carries the spend key, so
/// there [`Proving::Remote`] is refused ([`Proving::refuse_remote_before_v3`], VK-4) and only a
/// local proof is made.
#[derive(Clone)]
pub enum Proving {
    Local(Backend),
    Remote(Arc<RemoteProver>),
    #[cfg(test)]
    Emulated,
    /// [`Proving::Emulated`] by a prover that quotes this fee (spec §5), whose admission check
    /// (`randprotocol_prover::service::check_fee`) is run on the witness before the emulation.
    /// The third field is the wallet's cap (`--max-prover-fee`), applied as for a real prover.
    #[cfg(test)]
    EmulatedFee(ShieldedAddress, u64, u64),
}

impl Proving {
    pub fn local(b: Backend) -> Proving {
        Proving::Local(b)
    }

    /// The fee the prover proving this bundle charges — its address and the RAND it quotes in
    /// `prover_info` — or `None` for a local proof and a prover that charges nothing.
    pub async fn fee(&self) -> Result<Option<(ShieldedAddress, u64)>> {
        match self {
            Proving::Local(_) => Ok(None),
            Proving::Remote(remote) => remote.fee().await,
            #[cfg(test)]
            Proving::Emulated => Ok(None),
            #[cfg(test)]
            Proving::EmulatedFee(to, amount, cap) => {
                crate::prover::check_fee_cap(*amount, *cap)?;
                Ok(Some((to.clone(), *amount)))
            }
        }
    }

    /// VK-4 (audit v6, decision D33): a paired prover proves only on a split-authorisation chain.
    /// `guest` is the chain's bundle guest as the node named it ([`chain_bundle_guest`]); for v1
    /// or v2 the witness is the spend key's, and no wallet of this build sends one to anybody —
    /// whatever the pairing's `own` says, since that is the prover's own link's word. Called
    /// before the prover is asked anything (its fee included) and before a bundle is built, so
    /// on such a chain `--prover` costs nothing and discloses nothing. A node that lies the other
    /// way (v3 for a v1/v2 chain) gets a viewing-key witness proved for a guest the chain refuses:
    /// a wasted proof, never a key.
    fn refuse_remote_before_v3(&self, guest: &Word8) -> Result<()> {
        if matches!(self, Proving::Remote(_)) && *guest != ZkExecutor::hc_hidden_bundle_v3() {
            return Err(anyhow!(crate::prover::PRE_V3_REFUSAL));
        }
        Ok(())
    }

    /// Whether the "prover fee" line is still to be shown: once per prover, so `rand send`, which
    /// shows it in its confirmation, does not print it again when the bundle is built.
    fn announce_fee(&self) -> bool {
        match self {
            Proving::Remote(remote) => remote.announce_fee(),
            _ => true,
        }
    }

    /// Proves `prepared` against `binding`: the bundle, and on a v3 chain the auth proof over
    /// `sk` (first — seconds, so a failure there costs no bundle proof). `proof_cap` is the
    /// chain's `max_proof_bytes`, which a remote prover's reply is held to before it is used (a
    /// local proof is this build's own).
    async fn prove(&self, prepared: &Prepared, sk: &SpendKey, binding: &[u32; TX_BINDING_WORDS], profile: FriProfile, proof_cap: usize) -> Result<Proved> {
        match self {
            Proving::Local(backend) => {
                let auth = prepared.v3.then(|| prove_auth_locally(prepared, sk, binding, profile, *backend)).transpose()?;
                let proved = prepared.prove(binding, profile, *backend)?;
                Ok(with_auth(proved, auth))
            }
            Proving::Remote(remote) => {
                // The prover never sees the spend key: it gets a v3 bundle's viewing-key witness
                // and nothing else. `submit_spend` refused a v1/v2 chain before this bundle was
                // built; held again here, where the witness would leave, so no later caller can
                // hand a spend-key witness (`prepared.words` of a v1/v2 bundle) to a prover (VK-4).
                self.refuse_remote_before_v3(&prepared.guest)?;
                // The auth proof is made here, on the CPU (tier 10, seconds).
                let auth = Some(prove_auth_locally(prepared, sk, binding, profile, Backend::Cpu)?);
                eprintln!("proving the bundle on {} (paired prover {})…", remote.paired().label(), remote.paired().fingerprint);
                let started = Instant::now();
                let (proof, tier) = remote.prove(&prepared.guest, profile, &prepared.words, binding, &prepared.expected, proof_cap).await?;
                let proving = started.elapsed();
                eprintln!("proved remotely in {proving:.1?}: tier {tier}, {} bytes", proof.len());
                Ok(with_auth(Proved { proof, tier, proving, auth_proof: Vec::new(), auth_proving: None }, auth))
            }
            #[cfg(test)]
            Proving::Emulated => tests::emulated_proof(prepared, sk, binding),
            #[cfg(test)]
            Proving::EmulatedFee(to, amount, _) => {
                let fee = randprotocol_prover::service::Fee { amount: *amount, address: to.clone() };
                randprotocol_prover::service::check_fee(&prepared.words, &fee).map_err(|e| anyhow!("the prover would refuse this witness: {e:?}"))?;
                tests::emulated_proof(prepared, sk, binding)
            }
        }
    }
}

/// `proved` with the auth proof, when there is one, beside it.
fn with_auth(proved: Proved, auth: Option<(Vec<u8>, Duration)>) -> Proved {
    match auth {
        Some((auth_proof, took)) => Proved { auth_proof, auth_proving: Some(took), ..proved },
        None => proved,
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
/// under its own fresh transaction key, in the chain's envelope `format`: only the payment slot
/// (`Payee::To`) ever carries `plan.memo` — change (`Payee::Me`) and every dummy (`Payee::Nobody`)
/// are sealed with `""`, so every slot is the same size whether or not this transaction pays
/// anyone a memo (spec 2026-09-26 §2.4).
///
/// `guest` is the chain's bundle guest ([`chain_bundle_guest`]). On bundle guest v3 (split
/// authorisation) the bundle draws a fresh salt, carries `auth_commit = H(AUTH, nk, salt)`, and its
/// witness is the v3 one — `nk` and the salt, never the spend key — with the v3 digest expected;
/// on every other guest the bundle is exactly what it always was, `auth_commit` zero.
#[allow(clippy::too_many_arguments)]
fn build_bundle(w: &Wallet, plan: &Plan, anchor: Word8, paths: &[[Word8; DEPTH]], time: u32, format: EnvelopeFormat, guest: &Word8) -> Result<Prepared> {
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
    const { assert!(A_SLOTS == 2 && SLOTS == 4, "the slot layout this builder fills") };

    let mut outs = [HiddenOutput { pk: [0; 8], amount: 0, r: [0; 8] }; SLOTS];
    let mut envelopes: Vec<Envelope> = Vec::with_capacity(SLOTS);
    let mut commitments = [[0u32; 8]; SLOTS];
    for (k, (payee, amount)) in plan.outputs().into_iter().enumerate() {
        // The throwaway key a dummy is sealed to — and owned by — exists only for this call.
        let nobody = matches!(payee, Payee::Nobody).then(Wallet::generate);
        let pk = match (&payee, &nobody) {
            (Payee::To(dest), _) | (Payee::Prover(dest), _) => dest.pk,
            (Payee::Me, _) => pk_self,
            (Payee::Nobody, Some(t)) => t.vk.pk(),
            (Payee::Nobody, None) => unreachable!("a throwaway key for every dummy"),
        };
        outs[k] = HiddenOutput { pk, amount, r: fresh_word() };
        let note = outs[k].note(k, pk_self, asset, time);
        commitments[k] = note.commitment();
        let key = TxKey::random();
        let sealed = match (&payee, &nobody) {
            (Payee::To(dest), _) => seal_note_as(format, &w.vk, dest, &note, &key, &plan.memo),
            // The prover's fee is a plain note to its address; the payment's memo is never its.
            (Payee::Prover(dest), _) => seal_note_as(format, &w.vk, dest, &note, &key, ""),
            (Payee::Me, _) => seal_note_as(format, &w.vk, &w.address, &note, &key, ""),
            (Payee::Nobody, Some(t)) => seal_note_as(format, &t.vk, &t.address, &note, &key, ""),
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
    let digest_input = HiddenDigestInput {
        anchor,
        nullifiers,
        commitments,
        fee: plan.fee,
        burn_a: plan.burn_a,
        burn_r: plan.burn_r,
        burn_asset,
        time,
    };
    let v3 = *guest == ZkExecutor::hc_hidden_bundle_v3();
    let (salt, auth_commit, expected, words) = if v3 {
        // Fresh for every bundle, never derived from anything: a repeated salt repeats
        // `auth_commit` and links the two transactions to one wallet (spec §4.1).
        let salt = fresh_word();
        let auth_commit = randprotocol_zkvm::auth::auth_commit(&w.vk.nk, &salt);
        let expected = hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 { base: digest_input, auth_commit });
        let words = hidden::hidden_bundle_inputs_v3(&w.vk, &salt, &inputs, &outs, anchor, plan.fee, plan.burn_a, plan.burn_r, asset, time);
        (salt, auth_commit, expected, words)
    } else {
        let expected = hidden::hidden_bundle_digest(&digest_input);
        let words = hidden::hidden_bundle_inputs(&w.sk, &inputs, &outs, anchor, plan.fee, plan.burn_a, plan.burn_r, asset, time);
        ([0; 8], [0; 8], expected, words)
    };
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
        // Set before the transaction around it exists, so the binding both proofs are made over
        // covers it. Zero on a chain without genesis `hc_auth`, which that chain requires.
        auth_commit,
        auth_proof: Vec::new(),
    };
    Ok(Prepared { bundle, words, expected, guest: *guest, v3, salt, auth_commit })
}

/// The chain's bundle guest: `rand_status`'s `hc_bundle` (the genesis pin) — and for v3, its
/// `hc_auth` too — refused unless this build can prove it — asked before a bundle is built, so a wallet too old for its chain says so
/// instead of spending a minute and a half on a proof every validator refuses.
async fn chain_bundle_guest(rpc: &RpcClient) -> Result<Word8> {
    let status = rpc.status().await?;
    let named = status["hc_bundle"].as_str().ok_or_else(|| anyhow!("the node's rand_status names no hc_bundle"))?;
    let hc = randprotocol_core::notes::word8_from_hex(named).ok_or_else(|| anyhow!("the node's hc_bundle {named} is not a 32-byte digest"))?;
    if ZkExecutor::bundle_program_for(&hc).is_none() {
        return Err(anyhow!(
            "this chain's bundle guest is {named}, which this wallet cannot prove (it carries {}); update the wallet",
            ZkExecutor::known_hc_bundles().map(|h| word8_to_hex(&h)).join(" and ")
        ));
    }
    // Bundle guest v3 needs its auth proof, made by the auth guest the genesis pins as `hc_auth`:
    // an auth proof of any other guest is refused by every validator, so a chain naming another
    // one (or, inconsistently, none) is refused here — before a proof is paid for.
    // A v1/v2 guest beside a named auth guest is no genesis this build knows how to cut: every
    // `hc_auth` chain runs bundle guest v3.
    if hc != ZkExecutor::hc_hidden_bundle_v3() && !status["hc_auth"].is_null() {
        return Err(anyhow!(
            "this chain names an auth guest but a v1/v2 bundle guest ({named}); the node is misconfigured or lying — refusing to prove"
        ));
    }
    if hc == ZkExecutor::hc_hidden_bundle_v3() {
        let ours = ZkExecutor::hc_auth();
        let theirs = status["hc_auth"].as_str().and_then(randprotocol_core::notes::word8_from_hex);
        if theirs != Some(ours) {
            let named = status["hc_auth"].as_str().map_or_else(|| "not named (rand_status has no hc_auth)".to_string(), str::to_string);
            return Err(anyhow!(
                "this chain's auth guest is {named}; this wallet carries {} — refusing to prove a v3 bundle it cannot authorise; update the wallet",
                word8_to_hex(&ours)
            ));
        }
    }
    check_bundle_gas_limit(rpc.limits().await?.and_then(|l| l.bundle_gas_limit))?;
    Ok(hc)
}

/// The lines `rand send` shows beside its recipient before the y/N, when a paired prover makes
/// the bundle proof: the prover's fee ("prover fee: X RAND to <fingerprint>", spec §5) and the
/// history warning, once ([`RemoteProver::history_warning`]; the proof itself then says nothing
/// more) — for every pairing, `own=1` or not (VK-4). Empty for a local proof. On a chain whose
/// bundle guest is v1 or v2 a paired prover is refused here ([`PRE_V3_REFUSAL`]), before the
/// prover is asked for its fee and before anything is asked of the user.
///
/// [`PRE_V3_REFUSAL`]: crate::prover::PRE_V3_REFUSAL
pub async fn prover_confirmation(rpc: &RpcClient, proving: &Proving) -> Result<Vec<String>> {
    let Proving::Remote(remote) = proving else { return Ok(Vec::new()) };
    proving.refuse_remote_before_v3(&chain_bundle_guest(rpc).await?)?;
    let mut lines = Vec::new();
    if let Some((to, amount)) = remote.fee().await? {
        lines.push(format!("prover fee: {} RAND to {}", format_amount(amount), to.fingerprint()));
        remote.announce_fee();
    }
    lines.extend(remote.history_warning());
    Ok(lines)
}

/// Builds the bundle's witness from the wallet's own tree and picks its anchor, then builds the
/// bundle ([`build_bundle`]), returning it with the `time` it carries.
///
/// The tree is the wallet's local copy, grown by every [`scan`] (audit v3 PRIV-1): no
/// `rand_getWitness` call leaves the process, so the node never learns which leaves a spend
/// touches. The anchor is the freshest block-end root the chain confirms equals the local root —
/// and the witnesses are against the local root, so the anchor must equal it. The head's anchor
/// is tried first: a current tree is the head's root (a quiet chain's head root is the same root
/// however long ago the last leaf landed, which is the case a checkpoint alone cannot cover).
/// Failing that, the newest checkpoint the node still serves — the local tree is frozen at its
/// checkpoints, so where the old code looped on "tree moved; retry" this one rescans once.
async fn prepare_bundle(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore, plan: &Plan, format: EnvelopeFormat, guest: &Word8) -> Result<(Prepared, u32)> {
    let guest = *guest;
    let h = tree_hash();
    for attempt in 0..2 {
        let live = store.tree.root(&h);
        let (head_height, head_root) = rpc.anchor(None).await?;
        let mut anchor = (head_root == live).then_some((head_height, head_root));
        if anchor.is_none() {
            // The chain moved since the scan. Only a checkpoint holding the *current* local root
            // can anchor the bundle; ask the node for each in turn, newest first. A height the
            // node no longer serves — pruned out of its window, or a sync gap in its anchor
            // table — is a miss, not a failure.
            for (height, root) in store.tree.checkpoints_newest() {
                if root != live {
                    continue;
                }
                match rpc.anchor(Some(height)).await {
                    Ok((_, node_root)) if node_root == live => {
                        anchor = Some((height, live));
                        break;
                    }
                    Ok(_) => {}
                    Err(e) if is_anchor_miss(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        if let Some((height, root)) = anchor {
            let time = u32::try_from(height).map_err(|_| anyhow!("chain height {height} does not fit a bundle's time field"))?;
            let mut paths = Vec::with_capacity(SLOTS);
            for n in plan.inputs() {
                let path = store
                    .tree
                    .path(n.index)
                    .with_context(|| format!("no local witness for note {}; the store's tree is incomplete", n.index))?;
                paths.push(path);
            }
            let prepared = build_bundle(w, plan, root, &paths, time, format, &guest)?;
            return Ok((prepared, time));
        }
        if attempt == 1 {
            return Err(anyhow!(
                "the wallet's tree matches none of the node's anchors, even after a rescan; the store's tree and the node's leaves disagree — `rand sync --rescan` rebuilds the store from leaf 0"
            ));
        }
        // No recorded block-end root matches the local root: the picture is stale. Rescan once
        // and retry.
        scan(rpc, w, store).await?;
    }
    unreachable!("the attempt loop returns the bundle or an error")
}

/// `-32001`, the node's "no anchor at height h" (`rand_getAnchor`): a miss for the checkpoint
/// walk in [`prepare_bundle`], not a failure.
fn is_anchor_miss(e: &anyhow::Error) -> bool {
    e.downcast_ref::<crate::RpcError>().is_some_and(|r| r.code == -32001)
}

/// Prove `tx`'s one bundle — and on a v3 chain its auth proof, over `sk` — against `tx`'s own
/// binding, in place, with `proving` at `profile`.
///
/// BIND-1: `domain` is the chain's binding domain as this wallet decided it ([`binding_domain`]):
/// what the binding the proofs are made over carries — the chain id, or the genesis hash too.
async fn prove_transaction(tx: &mut Transaction, domain: &BindingDomain, prepared: &Prepared, sk: &SpendKey, proving: &Proving, profile: FriProfile, proof_cap: usize) -> Result<Proved> {
    prove_transaction_by(tx, domain, |binding| async move { proving.prove(prepared, sk, &binding, profile, proof_cap).await }).await
}

/// The [`BindingDomain`] of a transaction this wallet builds for `chain_id` (BIND-1, audit v6):
/// the chain-id domain on the chains cut before genesis `binding_domain`
/// ([`crate::CHAIN_ID_BINDING_CHAIN_IDS`], 14–19), and on every other chain id the genesis-bound
/// one over **the genesis hash this wallet's note store is bound to** — never the node's
/// `binding_domain` claim, and [`crate::binding_domain_for`] says why a node lying about the
/// hash can only make this wallet's own transactions invalid.
///
/// `store` must have been scanned against the node this transaction goes to ([`scan`] binds it,
/// and starts a store bound to another chain over). On a chain outside the list the node's claim
/// is read once, only to refuse early — before a minute and a half of proving — a chain whose
/// ledger would refuse the genesis-bound form ([`RpcClient::require_binding_domain`]).
async fn scanned_binding_domain(rpc: &RpcClient, store: &NoteStore, chain_id: u64) -> Result<BindingDomain> {
    if crate::CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id) {
        return Ok(BindingDomain::ChainId);
    }
    rpc.require_binding_domain(chain_id).await?;
    let genesis = store.genesis.context("the note store is bound to no chain yet (wallet bug: scan before binding)")?;
    Ok(crate::binding_domain_for(chain_id, genesis))
}

/// [`scanned_binding_domain`] for a caller that has not scanned yet — one that signs an action
/// message before its fee bundle is built (`rand token mint`, `rand token set-authority`, a
/// bridge governance submission): scans first, so the hash is the one the submission's own scan
/// binds the store to, then answers. On a chain cut before `binding_domain` it answers without
/// touching the node.
pub async fn binding_domain(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore, chain_id: u64) -> Result<BindingDomain> {
    if crate::CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id) {
        return Ok(BindingDomain::ChainId);
    }
    scan(rpc, w, store).await?;
    scanned_binding_domain(rpc, store, chain_id).await
}

/// The order [`prove_transaction`] keeps: the binding is taken with both proofs still empty, the
/// bundle (and the auth proof, on a v3 chain) proved against it, the proofs filled in; filling
/// them in cannot move the binding, because the binding blanks both. `prove` is handed the binding — a unit test hands in a stub
/// prover, which is what lets the ordering be tested without a minute of proving.
async fn prove_transaction_by<F, Fut>(tx: &mut Transaction, domain: &BindingDomain, prove: F) -> Result<Proved>
where
    F: FnOnce([u32; TX_BINDING_WORDS]) -> Fut,
    Fut: std::future::Future<Output = Result<Proved>>,
{
    let binding = tx.binding(domain);
    let p = prove(binding).await?;
    let bundle = tx.bundle.as_mut().context("a shielded transaction has a bundle")?;
    bundle.proof = p.proof.clone();
    bundle.auth_proof = p.auth_proof.clone();
    debug_assert_eq!(tx.binding(domain), binding, "filling the proofs in never moves the binding");
    Ok(p)
}

/// Proves a call against its transaction's call binding: what [`submit_bound_call`] takes
/// (INT-4). Handed the eight binding words, returns the call proof.
pub type CallProver<'a> = dyn Fn(&[u32; TX_BINDING_WORDS]) -> Result<Vec<u8>> + Send + Sync + 'a;

/// RPL-2: proves an invoke's call against its transaction — handed the eight binding words and
/// the transition's context words (`Transition::context` with the bundle's burn fields), the
/// segment `prove_invoke` is made over — and returns the call proof. What
/// [`submit_bound_invoke`] takes.
pub type InvokeProver<'a> = dyn Fn(&[u32; TX_BINDING_WORDS], &[u32]) -> Result<Vec<u8>> + Send + Sync + 'a;

/// The hook [`submit_spend`] runs between assembling the transaction and proving its bundle:
/// handed the whole transaction (both proofs empty) and the chain's binding domain (BIND-1),
/// returns its call proof. A `Call`'s reads the call binding off it; an `Invoke`'s the binding
/// and the context.
type BoundProver<'a> = dyn Fn(&Transaction, &BindingDomain) -> Result<Vec<u8>> + Send + Sync + 'a;

/// INT-4 (genesis `hardening_v6`): prove `tx`'s call against `tx`'s own
/// [`Transaction::call_binding`], in place — the call binding blanks the call proof and the bundle
/// proof, so filling the call proof in cannot move it, and the bundle's binding, taken next, then
/// covers the finished call. The chain refuses the proof under any other fee bundle. An RPL-2
/// `Invoke` carries a call proof and is bound the same way: its binding covers the transition,
/// the payouts and their recipients too.
fn bind_call(tx: &mut Transaction, domain: &BindingDomain, prove: &BoundProver<'_>) -> Result<()> {
    let binding = tx.call_binding(domain);
    let proof = prove(tx, domain)?;
    match &mut tx.action {
        Action::Call { proof: p, .. } | Action::Invoke { proof: p, .. } => *p = proof,
        _ => return Err(anyhow!("a call binding for an action that is not a call (wallet bug)")),
    }
    debug_assert_eq!(tx.call_binding(domain), binding, "filling the call proof in never moves the call binding");
    Ok(())
}

/// A call on a chain whose genesis sets `hardening_v6` (INT-4): the RAND fee bundle is built
/// first, the transaction assembled with both proofs empty, the call proved over its
/// [`Transaction::call_binding`] by `prove_call`, and only then the bundle proved over the whole —
/// [`submit_spend`]'s one path, with the hook. `action` is the `Call` with its proof empty and its
/// input envelope already sealed (the envelope is inside the call binding). `fee` was fixed before
/// the call proof existed, from its tier ([`randprotocol_zkvm::executor::call_tier`]); a proof that
/// comes out larger than the fee pays for is refused here, before the bundle is proved.
#[allow(clippy::too_many_arguments)]
pub async fn submit_bound_call(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    prove_call: &CallProver<'_>,
    limits: Option<&ChainLimits>,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    let envelope = match &action {
        Action::Call { input_envelope, .. } => input_envelope.clone(),
        _ => return Err(anyhow!("submit_bound_call takes a call")),
    };
    let checked = |tx: &Transaction, domain: &BindingDomain| -> Result<Vec<u8>> {
        let proof = prove_call(&tx.call_binding(domain))?;
        // One decode for the tier and both hash-table heights, off the REAL proof.
        let header = randprotocol_zkvm::executor::decode_canonical(&proof).map_err(|e| anyhow!("the call proof does not decode: {e}"))?;
        let tier = header.tier.0 as u8;
        let gas_limit = declared_gas(&header.public_values)?;
        refuse_if_under_the_floor(limits, tier, header.keccak_log_height, header.sha256_log_height, gas_limit, &proof, envelope.as_ref(), fee, 0)?;
        Ok(proof)
    };
    let spend = Spend { asset: 0, to: None, memo: "", fee, burn_a: 0, burn_r: 0, prover_fee: None };
    submit_spend(rpc, w, store, spend, action, Burn::None, profile, proving, Some(&checked), chain_id, wait).await
}

/// One note an invoke asks the chain to create, before the note exists: the asset, the amount
/// and who is paid. [`submit_bound_invoke`] seals it into a [`Payout`] once the bundle's `time`
/// is fixed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutRequest {
    pub asset: u32,
    pub amount: u64,
    pub to: ShieldedAddress,
}

/// An `Invoke` as the caller plans it (RPL-2): the program, the transition's cells and inflow
/// kind, what the bundle burns into the vault, and the payouts as requests — their notes are
/// sealed inside the submission, against the bundle's own `time`.
#[derive(Clone, Debug)]
pub struct InvokePlan {
    pub program: randprotocol_core::program::ProgramId,
    pub reads: Vec<randprotocol_core::ledger::program_state::Cell>,
    pub writes: Vec<randprotocol_core::ledger::program_state::Cell>,
    pub inflow: randprotocol_core::ledger::program_state::Inflow,
    pub pays: Vec<PayoutRequest>,
    pub mints: Vec<PayoutRequest>,
    /// RAND the bundle burns into the program's vault.
    pub burn_r: u64,
    /// The token the bundle burns (`inflow` says whether into the vault or out of existence),
    /// `burn_a` of asset `burn_asset`; `burn_asset` is 0 when `burn_a` is.
    pub burn_asset: u32,
    pub burn_a: u64,
    /// The sealed call-input transcript, as a call's — inside the call binding, so fixed here.
    pub input_envelope: Option<randprotocol_core::types::CallEnvelope>,
    /// The cells the writes would create on the chain as read before proving, for the fee's
    /// cell term. The chain charges what it finds at inclusion; a count that is short is a
    /// refusal there, one that is long an overpayment.
    pub created_cells: u64,
}

/// The note an RPL-2 invoke pays out — `pays` (out of the vault) or `mints` (new units of the
/// program's token) — and the envelope only its recipient can open. [`mint_note_for`]'s twin:
/// the same reasoning, from [`PROGRAM_FROM`] instead of `MINT_FROM`, and stamped with the
/// **bundle's** `time`, which is what the chain stamps a payout note with
/// (`program_state::payout_commitment`) — so it can only be sealed once that time is fixed.
pub fn payout_note_for(
    w: &Wallet,
    recipient: &ShieldedAddress,
    amount: u64,
    asset: u32,
    time: u32,
    format: EnvelopeFormat,
) -> Result<(Note, Envelope)> {
    let note = Note::new(recipient.pk, randprotocol_core::ledger::program_state::PROGRAM_FROM, amount, asset, time);
    let envelope = seal_note_as(format, &w.vk, recipient, &note, &TxKey::random(), "")
        .map_err(|e| anyhow!("sealing the payout envelope: {e}"))?;
    Ok((note, envelope))
}

/// The transition `plan` declares, its payout notes sealed against `time`.
fn seal_transition(w: &Wallet, plan: &InvokePlan, time: u32, format: EnvelopeFormat) -> Result<randprotocol_core::ledger::program_state::Transition> {
    use randprotocol_core::ledger::program_state::{Payout, Transition};
    let seal = |requests: &[PayoutRequest]| -> Result<Vec<Payout>> {
        requests
            .iter()
            .map(|p| {
                let (note, envelope) = payout_note_for(w, &p.to, p.amount, p.asset, time, format)?;
                Ok(Payout { asset: p.asset, amount: p.amount, recipient: p.to.clone(), r: note.r, envelope })
            })
            .collect()
    };
    Ok(Transition { reads: plan.reads.clone(), writes: plan.writes.clone(), inflow: plan.inflow, pays: seal(&plan.pays)?, mints: seal(&plan.mints)? })
}

/// RPL-2: an `Invoke` end to end, [`submit_bound_call`]'s twin. One bundle pays the RAND fee and
/// burns `plan.burn_r` RAND and/or `plan.burn_a` of `plan.burn_asset` — `Plan::select`'s
/// token-and-RAND shape, the token in slots 0–1, the fee and the RAND burn in slots 2–3 — and
/// the order is the hardened call's: the bundle's notes are chosen and its `time` fixed, the
/// payout notes sealed against that time and the transition assembled, the call proved over
/// `Transaction::call_binding` and the transition's context by `prove` (the binding covers the
/// transition, the recipients and the fee bundle), then the auth proof and the bundle proof over
/// the whole. `fee` is fixed before the proof exists; the real proof's header is re-priced —
/// the call's floor plus `cell_fee · created_cells` — and refused under it, naming the fee to
/// retry with. Returns the submission and the transition as sent, with its payout blindings.
#[allow(clippy::too_many_arguments)]
pub async fn submit_bound_invoke(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    plan: &InvokePlan,
    fee: u64,
    prove: &InvokeProver<'_>,
    limits: Option<&ChainLimits>,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<(Submission, randprotocol_core::ledger::program_state::Transition)> {
    use randprotocol_core::ledger::program_state::{Inflow, MAX_PAYOUTS, MAX_READS, MAX_WRITES};
    // The cheap shape rules the ledger applies first, before any note is chosen or sealed.
    if plan.reads.len() > MAX_READS || plan.writes.len() > MAX_WRITES {
        return Err(anyhow!("a transition reads at most {MAX_READS} cells and writes at most {MAX_WRITES}"));
    }
    if plan.pays.len() + plan.mints.len() > MAX_PAYOUTS {
        return Err(anyhow!("a transition creates at most {MAX_PAYOUTS} notes (pays and mints together)"));
    }
    if plan.pays.iter().chain(&plan.mints).any(|p| p.amount == 0) {
        return Err(anyhow!("a payout of zero creates nothing; the chain refuses it"));
    }
    if (plan.burn_a == 0) != matches!(plan.inflow, Inflow::None) {
        return Err(anyhow!("the inflow is `none` exactly when the bundle burns no token (burn_a == 0)"));
    }
    if plan.burn_a != 0 && plan.burn_asset == 0 {
        return Err(anyhow!("RAND goes into the vault through burn_r, never burn_a"));
    }
    let cell_fee = limits.and_then(|l| l.program_state).map_or(0, |p| p.cell_fee);
    let cells = cell_fee.saturating_mul(plan.created_cells);
    let format = rpc.envelope_format(chain_id).await?;
    let envelope = plan.input_envelope.clone();
    let sent = std::sync::Mutex::new(None);
    let mut make_action = |time: u32| -> Result<Action> {
        let transition = seal_transition(w, plan, time, format)?;
        *sent.lock().unwrap_or_else(|e| e.into_inner()) = Some(transition.clone());
        Ok(Action::Invoke { program: plan.program, proof: Vec::new(), input_envelope: envelope.clone(), transition })
    };
    let checked = |tx: &Transaction, domain: &BindingDomain| -> Result<Vec<u8>> {
        let (Action::Invoke { transition, .. }, Some(b)) = (&tx.action, &tx.bundle) else {
            return Err(anyhow!("an invoke binding for a transaction that is not an invoke (wallet bug)"));
        };
        let context = transition.context(b.burn_r, b.burn_asset, b.burn_a);
        let proof = prove(&tx.call_binding(domain), &context)?;
        let header = randprotocol_zkvm::executor::decode_canonical(&proof).map_err(|e| anyhow!("the call proof does not decode: {e}"))?;
        let tier = header.tier.0 as u8;
        let gas_limit = declared_gas(&header.public_values)?;
        refuse_if_under_the_floor(limits, tier, header.keccak_log_height, header.sha256_log_height, gas_limit, &proof, envelope.as_ref(), fee, cells)?;
        Ok(proof)
    };
    let spend = Spend {
        asset: if plan.burn_a != 0 { plan.burn_asset } else { 0 },
        to: None,
        memo: "",
        fee,
        burn_a: plan.burn_a,
        burn_r: plan.burn_r,
        prover_fee: None,
    };
    let burn = Burn::invoke(plan.burn_r, plan.burn_asset, plan.burn_a);
    let submission = submit_spend_at(rpc, w, store, spend, &mut make_action, burn, profile, proving, Some(&checked), chain_id, wait).await?;
    let transition = sent.into_inner().unwrap_or_else(|e| e.into_inner()).ok_or_else(|| anyhow!("the transition was never sealed (wallet bug)"))?;
    Ok((submission, transition))
}

/// A decoded call proof's declared `GAS_LIMIT` (`pv::GAS`). Fail-closed: a proof whose public
/// values stop short of it is an error, never priced as zero gas.
pub fn declared_gas(public_values: &[u64]) -> Result<u64> {
    let at = randprotocol_zkvm::tables::cpu::pv::GAS;
    public_values
        .get(at)
        .copied()
        .ok_or_else(|| anyhow!("the call proof carries {} public values, none at GAS (index {at}); refusing to price it", public_values.len()))
}

/// The guard `submit_bound_call`'s `checked` closure applies to the REAL proof once it exists
/// (INT-4): priced under the caller's gas policy exactly as `rand call`'s unhardened path prices
/// one (spec 2026-09-28 §4.1), so an under-quote — a keccak-bearing proof, a raised cap, anything
/// the pre-price at `main.rs` could not know before the proof existed — is refused here, naming
/// the floor to retry with.
#[allow(clippy::too_many_arguments)]
fn refuse_if_under_the_floor(
    limits: Option<&ChainLimits>,
    tier: u8,
    keccak_log_height: u8,
    sha256_log_height: u8,
    gas_limit: u64,
    proof: &[u8],
    envelope: Option<&randprotocol_core::types::CallEnvelope>,
    fee: u64,
    cells: u64,
) -> Result<()> {
    // `cells` is an invoke's cell term (`cell_fee · created_cells`), zero for a call.
    let need = call_floor(limits, tier, keccak_log_height, sha256_log_height, gas_limit, gas::call_bytes(proof, envelope))?.saturating_add(cells);
    if need > fee {
        return Err(anyhow!(
            "the call proof came out at tier {tier}, {} bytes, whose fee is {} RAND — more than the {} RAND the fee bundle was built for; retry with --fee {}",
            proof.len(),
            format_amount(need),
            format_amount(fee),
            format_amount(need)
        ));
    }
    Ok(())
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

/// Every bundle-carrying submission goes through here: scan, plan both groups, take the anchor
/// and the witnesses from the wallet's own tree, build the bundle, assemble the transaction with
/// the proof empty, take its binding, prove against it, fill the proof in, submit. One code path,
/// so the fee, the anchor, the witnesses and the digest check cannot drift apart between a
/// transfer, a bond, a deploy, a call, an attestation and a burn.
///
/// `call_prover` is the INT-4 hook (genesis `hardening_v6`): for a `Call` it is handed the
/// transaction's [`Transaction::call_binding`] — taken with both proofs empty — and returns the
/// call proof made over it, which is filled in before the bundle's own binding is taken
/// ([`bind_call`]). `None` everywhere else, and for a call on a chain without the flag, whose proof
/// the caller made beforehand.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_spend(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    spend: Spend<'_>,
    action: Action,
    burn: Burn,
    profile: FriProfile,
    proving: &Proving,
    call_prover: Option<&BoundProver<'_>>,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    let mut action = Some(action);
    let mut fixed = |_time: u32| Ok(action.take().expect("the action is asked for once"));
    submit_spend_at(rpc, w, store, spend, &mut fixed, burn, profile, proving, call_prover, chain_id, wait).await
}

/// [`submit_spend`] for an action that cannot exist before the bundle's `time` is fixed: an
/// RPL-2 `Invoke`, whose payout notes the chain stamps with that time
/// (`program_state::payout_commitment`) and whose blindings and envelopes sit inside the action —
/// inside the call binding, so they must be final before the call is proved. `make_action` is
/// handed the time [`prepare_bundle`] chose and returns the action; every other action ignores
/// it.
#[allow(clippy::too_many_arguments)]
async fn submit_spend_at(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    spend: Spend<'_>,
    make_action: &mut (dyn FnMut(u32) -> Result<Action> + Send),
    burn: Burn,
    profile: FriProfile,
    proving: &Proving,
    call_prover: Option<&BoundProver<'_>>,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    scan(rpc, w, store).await?;
    // The chain's guest first: it decides whether a paired prover may prove this bundle at all
    // (VK-4: never on a v1/v2 chain — refused before the prover is asked anything), and whether a
    // prover's fee can ride in it.
    let guest = chain_bundle_guest(rpc).await?;
    proving.refuse_remote_before_v3(&guest)?;
    let quoted = proving.fee().await?;
    if let Some((to, amount)) = &quoted {
        if guest != ZkExecutor::hc_hidden_bundle_v3() {
            return Err(anyhow!(
                "the paired prover charges {} RAND, which only a split-authorisation chain's (bundle guest v3) witness can carry; \
                 this chain's is v1/v2 — prove on this machine (drop --prover) or use a prover that charges nothing",
                format_amount(*amount)
            ));
        }
        if proving.announce_fee() {
            eprintln!("prover fee: {} RAND to {}", format_amount(*amount), to.fingerprint());
        }
    }
    let spend = Spend { prover_fee: quoted.as_ref().map(|(d, f)| (d, *f)), ..spend };
    let plan = Plan::select(store, spend)?;
    // One `rand_getLimits` read (cached after the first) decides the envelope every slot of this
    // bundle is sealed in — before any proof is paid for, a memo this chain cannot carry is
    // refused inside `build_bundle`. Checked against this transaction's own chain id: a node's
    // memo claim on a chain pinned as pre-`envelope_bytes` is not believed (issue #64).
    let format = rpc.envelope_format(chain_id).await?;
    let (prepared, time) = prepare_bundle(rpc, w, store, &plan, format, &guest).await?;
    // The action last, once the bundle's `time` is known (an invoke's payout notes carry it);
    // then the whole transaction, its bundle's proof empty; then the proof, bound to it. Nothing
    // is set on the transaction after the proof but the proof itself.
    let action = make_action(time)?;
    let mut tx = Transaction::shielded(chain_id, prepared.bundle.clone(), action);
    // BIND-1: what both bindings carry — decided by this transaction's chain id and, off the
    // chains cut before `binding_domain`, the genesis hash the scan above bound the store to.
    let domain = scanned_binding_domain(rpc, store, chain_id).await?;
    if let Some(prove_call) = call_prover {
        bind_call(&mut tx, &domain, prove_call)?;
    }
    // A remote prover's reply is held to the chain's proof cap; a local proof needs no read.
    let cap = match proving {
        Proving::Remote(_) => proof_cap(rpc.limits().await?.as_ref()),
        _ => gas::MAX_PROOF_BYTES,
    };
    let proved = prove_transaction(&mut tx, &domain, &prepared, &w.sk, proving, profile, cap).await?;
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
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_with(rpc, w, store, to, action, fee, burn, profile, proving, chain_id, wait).await
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
    profile: FriProfile,
    proving: &Proving,
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
        Burn::Both { index, amount, .. } => {
            return Err(anyhow!("burning {amount} of asset {index} beside RAND is an invoke's bundle: that is `submit_bound_invoke`, not `submit`"))
        }
    };
    // `submit`/`submit_with` carries no memo of its own: every caller in this workspace passes
    // `to: None` (a deploy, a bond, a bridge action), and the one path that pays someone a memo
    // is `send`/`send_asset`, below.
    let spend = Spend { asset: 0, to, memo: "", fee, burn_a: 0, burn_r: burn.units(), prover_fee: None };
    submit_spend(rpc, w, store, spend, action, burn, profile, proving, None, chain_id, wait).await
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
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_bridge_action_with(rpc, w, store, action, fee, profile, proving, chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_bridge_action_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(
        action,
        Action::BridgeAttest { .. } | Action::RegisterBridgedToken { .. } | Action::ListBacking { .. }
    ) {
        return Err(anyhow!("submit_bridge_action carries a bridge attestation or a bridged-token listing, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, profile, proving, chain_id, wait).await
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
    if !amount.is_multiple_of(unit) || !relayer_fee.is_multiple_of(unit) {
        return Err(anyhow!(
            "{hex_token} on chain {to_chain} has {decimals} decimals: \
             the amount and the relayer fee must be multiples of {unit}"
        ));
    }
    // `amount_field`, not `as_u64`: the node renders every amount as a decimal string since
    // chain 14 (node I3), and an older one as a number. Both are read here.
    let locked = crate::amount_field(&backing["locked"]).context("an asset row without a locked amount")?;
    // v0.6.8: under `bridge.fees` the release — what is checked against `locked` and what the
    // relayer is paid out of — is the burn less the chain's fee.
    let release = amount - burn_fee_quote(bridge_state, to_chain, token, amount);
    if relayer_fee > release {
        return Err(anyhow!("the relayer fee {relayer_fee} is more than the {release} this burn releases"));
    }
    if release > locked {
        return Err(anyhow!(
            "only {locked} is locked in that coin on chain {to_chain}; choose another backing or a smaller amount"
        ));
    }
    Ok(())
}

/// The chain's fee on a burn of `amount` releasing `(to_chain, token)` (v0.6.8, `bridge.fees`):
/// `⌊amount·burn_bps/10⁴⌋` down to a whole release unit — the ledger's own `bridge_fee` — read
/// off a `rand_getBridgeState` reply. `0` on a chain without the group (or a node that does not
/// serve it), which is then exactly what the chain charges. `release = amount − this`.
pub fn burn_fee_quote(bridge_state: &Value, to_chain: u16, token: &[u8; 32], amount: u64) -> u64 {
    BridgeFeeCtx::from_bridge_state(bridge_state)
        .and_then(|c| Some(bridge_notes::bridge_fee(amount, c.fees.burn_bps, c.unit(to_chain, token)?)))
        .unwrap_or(0)
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
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    let burn = BurnRequest { asset, amount, relayer_fee, to_chain, token, to };
    submit_burn_with(rpc, w, store, burn, fee, profile, proving, chain_id, wait).await
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
    profile: FriProfile,
    proving: &Proving,
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
    let spend = Spend { asset, to: None, memo: "", fee, burn_a: amount, burn_r: 0, prover_fee: None };
    submit_spend(rpc, w, store, spend, action, Burn::Asset { index: asset, amount }, profile, proving, None, chain_id, wait).await
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
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_token_burn_with(rpc, w, store, asset, amount, fee, profile, proving, chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_token_burn_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    asset: u32,
    amount: u64,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
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
    let spend = Spend { asset, to: None, memo: "", fee, burn_a: amount, burn_r: 0, prover_fee: None };
    submit_spend(rpc, w, store, spend, action, Burn::Asset { index: asset, amount }, profile, proving, None, chain_id, wait).await
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

/// CPU-1's residual (issue #57): the deploy bound (`TxError::ProgramUncallable`, the pool's
/// `admission::deploy_uncallable`) is the prover's limit for a call with **no** private inputs, so
/// a program under it can still be uncallable at every tier once a call's inputs are digested too
/// (one Poseidon2 slot a few input words, before a single instruction runs) — or once it runs
/// longer than the call tier cap allows. `rand program deploy --input …` runs the call the deployer
/// has in mind through the emulator first (`executor::call_tier`, no proving) and refuses, before
/// the deploy is paid for, unless it lands at or under `MAX_CALL_TIER`. The public segment is
/// taken at the length the chain will prove over — the program's public input, followed by the
/// eight-word call binding under genesis `hardening_v6` (`program::hardened_call_segment`) — with
/// zero words, as `call_tier` does; a guest that branches on its public words may land elsewhere.
/// Returns the tier the call would prove at.
/// The public segment a committed call's proof was made over, for `rand open-call`'s re-run
/// (issue #116): the program's public words, then — under genesis `hardening_v6` — the call's own
/// eight-word binding, exactly as `program::hardened_call_segment` builds it for the ledger and
/// `deploy_dry_run` sizes it. A guest reads its public words from this segment, so a re-run over
/// an empty one traps at the first `READ_PUBLIC` of any program deployed with a public input.
///
/// BIND-1: `domain` is the chain's binding domain for `tx.chain_id` — the call binding the ledger
/// recomputed carries the genesis hash under `binding_domain: 1`.
pub fn open_call_public_segment(public: &[u32], hardened: bool, tx: &Transaction, domain: &BindingDomain) -> Vec<u32> {
    if hardened {
        randprotocol_core::program::hardened_call_segment(public, &tx.call_binding(domain))
    } else {
        public.to_vec()
    }
}

pub fn deploy_dry_run(program: &randprotocol_zkvm::isa::Program, public: &[u32], inputs: &[u32], hardened: bool) -> Result<u8> {
    let segment = if hardened { public.len() + TX_BINDING_WORDS } else { public.len() };
    let max = randprotocol_zkvm::executor::MAX_CALL_TIER;
    let tier = randprotocol_zkvm::executor::call_tier(program, inputs, segment).map_err(|e| {
        anyhow!("a call over these {} input words cannot be proved at any tier ({e}); not deploying", inputs.len())
    })?;
    if tier > max {
        return Err(anyhow!(
            "a call over these {} input words needs tier {tier}, past the call tier cap {max}: no validator would admit it; not deploying",
            inputs.len()
        ));
    }
    Ok(tier)
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

/// The bytes a hardened `rand call` (INT-4) prices its fee on before its proof exists. Under the
/// node's gas policy every byte prices in, so the chain's proof cap stands in for the unproved
/// proof (it can only overpay). Without a policy the ledger charges only bytes past the free
/// allowance, so the quote is `call_bytes(&[], envelope)` — the envelope alone, as before the gas
/// work — and a raised-cap chain is not charged for proof bytes no real proof carries.
pub fn hardened_call_quote_bytes(limits: Option<&ChainLimits>, envelope_bytes: usize) -> usize {
    match limits.and_then(|l| l.gas_policy()) {
        Some(_) => proof_cap(limits) + envelope_bytes,
        None => envelope_bytes,
    }
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

/// What a `call` pays by default: the node's gas policy over the proof's header (spec 2026-09-28
/// §4.1) when it announces one, else deliberately NOT `fee_floor(Call) + call_fee(..)`.
/// `fee_floor(Call)` is `BUNDLE_BASE + CALL_BASE`, and `CALL_BASE` is already `call_fee`'s own
/// constant term, so adding the two overpays by `CALL_BASE`. The node's floor, once it has
/// decoded the proof and knows the tier, is precisely this (`Ledger::validate_inner`) — never
/// under either.
///
/// `bytes` is the call's proof plus its input envelope (`gas::call_bytes`); under `limits`'
/// gas policy every byte prices in (the free allowance is gone), and without one only what is
/// past `gas::CALL_FREE_BYTES` costs anything, so a call under today's caps pays today's fee.
///
/// On a chain whose genesis carries a `gas` section (`limits.gas_circuit`, spec §3.3) the floor
/// is `gas::circuit_call_floor` of the call's declared `gas_limit` at the served prices — the
/// header and its heights no longer price it. Under the dynamic controller (`limits.adjust_bps`,
/// spec §7.1) the default pays two price steps of headroom over that floor — `rand_getLimits`
/// serves the committed head's prices and a transaction lands two or three certified blocks
/// later, so two raises before it lands still admit it; `--fee` overrides. `gas_limit` is
/// ignored everywhere else. The served `fees.prove_base` is added after the headroom: it is a
/// fixed term no price controller moves, so the headroom does not scale it.
pub fn call_fee_default(
    limits: Option<&ChainLimits>,
    tier: u8,
    keccak_log_height: u8,
    sha256_log_height: u8,
    gas_limit: u64,
    bytes: usize,
) -> Result<u64> {
    let priced = priced_call_floor(limits, tier, keccak_log_height, sha256_log_height, gas_limit, bytes)?;
    Ok(with_headroom(limits, priced).saturating_add(limits.map_or(0, |l| l.prove_base)))
}

/// The floor itself, no headroom: what the chain (or the node's policy) refuses a call under.
/// [`call_fee_default`] is this plus the dynamic headroom; the post-proof guard
/// ([`refuse_if_under_the_floor`]) compares a fee with this, so a `--fee` that pays the floor
/// exactly is not refused for lacking headroom the caller chose not to buy.
///
/// Fail-closed under a `gas` section: a node that reports the section but leaves out
/// `gas_price` or `byte_price` is an error naming the field, never a price of zero.
///
/// Every rule's floor is raised by the chain's served `fees.prove_base`
/// ([`ChainLimits::prove_base`], `0` without it), as the ledger's own floor is.
pub fn call_floor(
    limits: Option<&ChainLimits>,
    tier: u8,
    keccak_log_height: u8,
    sha256_log_height: u8,
    gas_limit: u64,
    bytes: usize,
) -> Result<u64> {
    // `fees.prove_base` (`docs/compute-optimization.md` §6.3) raises every floor on an
    // aggregating chain; `0` wherever the node serves none.
    let prove_base = limits.map_or(0, |l| l.prove_base);
    Ok(priced_call_floor(limits, tier, keccak_log_height, sha256_log_height, gas_limit, bytes)?.saturating_add(prove_base))
}

/// [`call_floor`] without `prove_base`: the part the prices (and so the dynamic headroom) move.
fn priced_call_floor(
    limits: Option<&ChainLimits>,
    tier: u8,
    keccak_log_height: u8,
    sha256_log_height: u8,
    gas_limit: u64,
    bytes: usize,
) -> Result<u64> {
    if let Some(l) = limits.filter(|l| l.gas_circuit) {
        let missing = |field: &str| anyhow!("the node reports a gas section (gas_metering \"circuit\") but no {field}: refusing to price the call at zero");
        let gas_price = l.gas_price.ok_or_else(|| missing("gas_price"))?;
        let byte_price = l.byte_price.ok_or_else(|| missing("byte_price"))?;
        return Ok(gas::circuit_call_floor(gas_price, byte_price, gas_limit, bytes));
    }
    Ok(match limits.and_then(|l| l.gas_policy()) {
        Some(p) => p.call_floor(tier, keccak_log_height, sha256_log_height, bytes),
        None => gas::BUNDLE_BASE + gas::call_fee(tier, bytes),
    })
}

/// The default fee for an action priced by the schedule alone (`gas::fee_floor`): that floor plus
/// the chain's `fees.prove_base` (`docs/compute-optimization.md` §6.3, [`RpcClient::prove_base`],
/// `0` on every chain without it), so a default fee pays the floor the ledger holds it to.
pub async fn schedule_floor(rpc: &RpcClient, action: &Action) -> Result<u64> {
    Ok(gas::fee_floor(action).saturating_add(rpc.prove_base().await?))
}

/// Spec §7.1: `⌊floor·(10 000 + adjust_bps)²/10 000²⌋` under the dynamic controller — two of the
/// largest moves one block can make (`gas::next_price` caps a block's move at `adjust_bps`) —
/// else `floor`. Two, not one: `rand_getLimits` serves the committed head's prices, and a
/// transaction submitted now is priced at the parent of the block that includes it, two or three
/// certified blocks past that head. u128, then saturating to `u64::MAX`.
fn with_headroom(limits: Option<&ChainLimits>, floor: u64) -> u64 {
    match limits.and_then(|l| l.adjust_bps) {
        Some(a) => {
            let step = 10_000u128 + a as u128;
            u64::try_from(floor as u128 * step * step / 100_000_000).unwrap_or(u64::MAX)
        }
        None => floor,
    }
}

/// Spec 2026-09-28 §5, §9: the `GAS_LIMIT` a call declares by default — the dry run's `exact`
/// gas rounded up to the next multiple of `2^(tier−2)` (five values a tier under the ceiling —
/// two bits beyond what the tier already leaks — the top one being the ceiling itself), capped at
/// the tier's hash-free ceiling `gas_max(tier, 0, 0)`.
/// A call that hashes has a higher ceiling; [`gas_bucket`] takes it explicitly.
pub fn default_gas_limit(exact: u64, tier: u8) -> u64 {
    gas_bucket(exact, tier, gas::gas_max(tier, 0, 0))
}

/// [`default_gas_limit`] under an explicit `ceiling` (the header's `gas_max`, which a keccak or
/// sha256 table raises). Never under `exact` while `exact ≤ ceiling`.
pub fn gas_bucket(exact: u64, tier: u8, ceiling: u64) -> u64 {
    let step = 1u64 << tier.saturating_sub(2).min(62);
    exact.div_ceil(step).saturating_mul(step).min(ceiling)
}

/// The exact gas a call spends and the tier it proves at, from a dry run in the emulator
/// (`executor::dry_run_call` — `gas::gas_of` over the run's events). `public` is the segment the
/// proof commits to: the program's public input, followed under `hardening_v6` by
/// `TX_BINDING_WORDS` zeros. Witness only — the wallet prints it, the chain never sees it.
pub fn exact_call_gas(program: &randprotocol_zkvm::isa::Program, inputs: &[u32], public: &[u32]) -> Result<(u64, u8)> {
    let run = randprotocol_zkvm::executor::dry_run_call(program, inputs, public).map_err(|e| anyhow!("the call does not run: {e}"))?;
    Ok((run.gas, run.tier))
}

/// `rand call --gas-limit N`: a declared limit under the run's exact gas cannot be proved (the
/// circuit refuses `gas_at_halt > GAS_LIMIT`), and one over the header's ceiling is refused by
/// every verifier — both said before minutes of proving, naming the bound.
pub fn check_gas_limit(declared: u64, exact: u64, ceiling: u64) -> Result<()> {
    if declared < exact {
        return Err(anyhow!("--gas-limit {declared} is under this call's exact gas {exact}; declare at least {exact}"));
    }
    if declared > ceiling {
        return Err(anyhow!("--gas-limit {declared} is over this call's ceiling {ceiling} (gas_max of its header); declare at most {ceiling}, or `max`"));
    }
    Ok(())
}

/// Under a `gas` section every bundle declares the chain's `bundle_gas_limit` (spec §4.3), which
/// is the bundle guest's own ceiling `gas_max(BUNDLE_PROOF_TIER, 0, 0)` — the prover's default,
/// and the only value genesis accepts (`gas::bundle_gas_limit_pin`). A chain naming any other
/// value runs a bundle guest this wallet does not have: refused before proving.
pub fn check_bundle_gas_limit(bundle_gas_limit: Option<u64>) -> Result<()> {
    let ours = gas::bundle_gas_limit_pin();
    match bundle_gas_limit {
        Some(b) if b != ours => Err(anyhow!(
            "this chain pins every bundle at {b} gas, but this wallet's bundle guest declares {ours}; update the wallet"
        )),
        _ => Ok(()),
    }
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
            "bridge minting is paused on this chain; a PQ guardian quorum must lift the pause \
             (rand bridge-unpause) before any deposit can be minted"
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
            "that coin's daily mint cap is {cap} and {minted} has been minted against it today, \
             so only {left} is left and this deposit is {amount}; it becomes mintable on the next \
             UTC day of the chain's block timestamp"
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
    format: EnvelopeFormat,
) -> Result<(Note, Envelope)> {
    let r = bridge_notes::deposit_r(attestation).ok_or_else(|| anyhow!("the attestation has no body to derive the deposit blinding from"))?;
    let note = Note { pk: recipient.pk, from: [0; 8], amount, asset, time, r };
    let envelope = seal_note_as(format, &w.vk, recipient, &note, &TxKey::random(), "")
        .map_err(|e| anyhow!("sealing the deposit envelope: {e}"))?;
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
    format: EnvelopeFormat,
) -> Result<(Note, Envelope)> {
    let note = Note::new(recipient.pk, MINT_FROM, amount, asset, time);
    let envelope = seal_note_as(format, &w.vk, recipient, &note, &TxKey::random(), "")
        .map_err(|e| anyhow!("sealing the mint envelope: {e}"))?;
    Ok((note, envelope))
}

/// Rows per `rand_getTokens` page when [`resolve_asset`] reads the registry.
const TOKEN_PAGE: u64 = 1000;

/// `--asset`: a registry index as a number (0 is RAND), `rand`, or a token's id — its `rpl1…` text
/// form or 64 hex — looked up in the **whole** token registry (`rand_getTokens`, paged from index 0).
///
/// Never a per-token lookup: a transfer's asset is private on chain, and asking the node about the
/// one token a wallet is about to send (`rand_getToken <id>`) right before it submits would tell the
/// node's operator exactly what the hidden-asset bundle hides. Reading every row costs the same
/// whichever token is meant, so the reply carries nothing about the choice. A number never reaches
/// the node at all. A node without `rand_getTokens` is told to take the index instead.
///
/// A token id never resolves to RAND (audit WAL-1): the matched row must name the typed id in
/// every id field it carries, and sit at an index the registry can hand out (at least
/// `FIRST_TOKEN_INDEX`). Before, a node answering a token's id with index 0 turned
/// `send --asset rpl1… --amount 5` into five whole RAND — the amount parsed with RAND's decimals.
pub async fn resolve_asset(rpc: &RpcClient, text: &str) -> Result<u32> {
    if let Ok(index) = text.trim().parse::<u32>() {
        return Ok(index);
    }
    if text.trim().eq_ignore_ascii_case("rand") {
        return Ok(0);
    }
    let want = parse_token_id(text)?;
    let row = find_row_by_id(rpc, text, &want, "pass the token's registry index instead").await?;
    row_index(&row)
}

/// Whether `--asset`'s text names RAND itself — `0` (in any spelling a number parses to) or
/// `rand` — rather than a token. What decides whether `--amount` may be read as RAND at all:
/// `send` refuses a typed token whose listing row answers RAND's index 0, whatever the node says,
/// and reads a token's amount in its registry `decimals` ([`parse_asset_amount`]).
pub fn names_rand(text: &str) -> bool {
    let t = text.trim();
    t.parse::<u32>() == Ok(0) || t.eq_ignore_ascii_case("rand")
}

/// A token id as typed: `rpl1…` (checksummed) or 64 hex, `0x` optional. A malformed id is refused
/// here, before the node is asked anything, so a typo can never match some other row.
fn parse_token_id(text: &str) -> Result<AssetId> {
    let t = text.trim();
    if t.len() >= 4 && t[..4].eq_ignore_ascii_case("rpl1") {
        return randprotocol_core::token_id::decode(t).map_err(|e| anyhow!("{text} is not a token id: {e}"));
    }
    Hash::from_hex(t).map_err(|_| anyhow!("{text} is not an asset: pass a registry index, rand, an rpl1… id or 64 hex"))
}

/// A `rand_getTokens` row's index, held to the registry's range: at least `FIRST_TOKEN_INDEX`,
/// because index 0 is RAND's and the registry never hands it out — a row claiming it is a node
/// lying about what a token id pays in (WAL-1).
fn row_index(row: &Value) -> Result<u32> {
    use randprotocol_core::ledger::tokens::FIRST_TOKEN_INDEX;
    let index = row["index"].as_u64().context("a rand_getTokens row without an index")?;
    let index = u32::try_from(index).map_err(|_| anyhow!("rand_getTokens lists index {index}, which is not a u32"))?;
    if index < FIRST_TOKEN_INDEX {
        return Err(anyhow!(
            "the node lists a token at index {index}, which is RAND's and never a token's (the registry starts at {FIRST_TOKEN_INDEX}); refusing its listing"
        ));
    }
    Ok(index)
}

/// Every id a `rand_getTokens` row carries (`id`, `asset_id` as hex, `id_text` as `rpl1…`),
/// decoded. `None` for a field that is present but does not decode.
fn row_ids(row: &Value) -> Vec<Option<AssetId>> {
    let mut ids = Vec::new();
    for key in ["id", "asset_id"] {
        if let Some(s) = row[key].as_str() {
            ids.push(Hash::from_hex(s).ok());
        }
    }
    if let Some(s) = row["id_text"].as_str() {
        ids.push(randprotocol_core::token_id::decode(s).ok());
    }
    ids
}

/// The row's own id fields name one token, or the row is refused: a listing whose `id` and
/// `id_text` disagree could match a typed id through one field and be some other token through
/// the other.
fn check_row_ids(row: &Value) -> Result<()> {
    let ids = row_ids(row);
    let first = ids.first().copied().flatten();
    if ids.is_empty() || ids.iter().any(|i| i.is_none() || *i != first) {
        return Err(anyhow!("rand_getTokens row {}: its id fields disagree (or do not decode); refusing its listing", row["index"]));
    }
    Ok(())
}

/// Page the whole registry for the row naming `want` (in any of its id fields), then hold that row
/// to [`check_row_ids`] and [`row_index`]. `hint` finishes the no-`rand_getTokens` error.
async fn find_row_by_id(rpc: &RpcClient, text: &str, want: &AssetId, hint: &str) -> Result<Value> {
    find_row(rpc, text, hint, |row| row_ids(row).contains(&Some(*want))).await
}

/// The paging loop [`resolve_asset`] and [`find_token_row`] share: the first row `hit` accepts,
/// checked (ids agree, index in the registry's range) before it is returned.
async fn find_row(rpc: &RpcClient, text: &str, hint: &str, hit: impl Fn(&Value) -> bool) -> Result<Value> {
    let mut from = 0u64;
    loop {
        let reply = rpc.call("rand_getTokens", serde_json::json!([from, TOKEN_PAGE])).await.map_err(|e| {
            if crate::is_method_not_found(&e) && hint.is_empty() {
                anyhow!("this node cannot list its token registry (it has no rand_getTokens)")
            } else if crate::is_method_not_found(&e) {
                anyhow!("this node cannot list its token registry (it has no rand_getTokens); {hint}")
            } else {
                e
            }
        })?;
        // A page is a list of rows, or `{ "tokens": [...] }`.
        let rows = reply
            .as_array()
            .or_else(|| reply["tokens"].as_array())
            .context("rand_getTokens did not return a list of tokens")?;
        if let Some(row) = rows.iter().find(|r| hit(r)) {
            check_row_ids(row)?;
            row_index(row)?;
            return Ok(row.clone());
        }
        let last = rows.iter().filter_map(|r| r["index"].as_u64()).max();
        match last {
            Some(last) if (rows.len() as u64) >= TOKEN_PAGE && last >= from => from = last + 1,
            _ => return Err(anyhow!("no token {text} in this chain's registry")),
        }
    }
}

/// The pure core of [`parse_asset_amount`]: a decimal string (`"1.5"`, `"2"`, and — as RAND's
/// old `parse_amount` took them — `".5"` and `"2."`) at `decimals` fractional digits, scaled to
/// the smallest unit. Surrounding whitespace is ignored; no sign, no exponent, no junk — `int`
/// and `frac` are each all-ASCII-digit or empty, but not both empty (`""` and `"."` are
/// refused). More fraction digits than the asset carries is the one error message worth naming
/// precisely, because it is the one a caller can fix by rounding; anything else just is not a
/// decimal amount.
pub fn parse_decimal(text: &str, decimals: u8) -> Result<u64> {
    let (int, frac) = text.trim().split_once('.').unwrap_or((text.trim(), ""));
    if (int.is_empty() && frac.is_empty()) || !int.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("{text} is not a decimal amount"));
    }
    let int = if int.is_empty() { "0" } else { int };
    if frac.len() > decimals as usize {
        return Err(anyhow!("{text}: this asset has at most {decimals} decimals"));
    }
    let scaled = format!("{int}{frac:0<width$}", width = decimals as usize);
    scaled.parse::<u64>().map_err(|_| anyhow!("{text} is too large"))
}

/// `units` at `decimals` fractional digits, every digit shown (`1000000000` at 8 is
/// `"10.00000000"`, at 0 `"1000000000"`): [`parse_decimal`]'s inverse.
pub fn format_decimal(units: u64, decimals: u8) -> String {
    if decimals == 0 {
        return units.to_string();
    }
    let digits = format!("{units:0>width$}", width = decimals as usize + 1);
    let (int, frac) = digits.split_at(digits.len() - decimals as usize);
    format!("{int}.{frac}")
}

/// An amount as `rand send`'s confirmation shows it: display units with the asset's decimals,
/// its symbol, and the base units the proof will actually carry — `10.00000000 zUSD (1000000000
/// units)` — so a node that lies about a token's `decimals` shows up before anything is sent
/// (the display figure and the typed one disagree).
pub fn display_amount(units: u64, decimals: u8, symbol: &str) -> String {
    format!("{} {symbol} ({units} units)", format_decimal(units, decimals))
}

/// A token row's `decimals`, held to a `u8`.
fn row_decimals(row: &Value, asset: u32) -> Result<u8> {
    let decimals = row["decimals"].as_u64().context("a rand_getTokens row without decimals")?;
    u8::try_from(decimals).map_err(|_| anyhow!("token {asset} reports {decimals} decimals, which is not plausible"))
}

/// An asset's display decimals and symbol: RAND's nine and `RAND` without asking the node, or a
/// token's registry row — found in the same whole `rand_getTokens` listing [`resolve_asset`]
/// pages, never a per-token lookup. The symbol is the node's text: show it sanitised.
pub async fn asset_units(rpc: &RpcClient, asset: u32) -> Result<(u8, String)> {
    if asset == 0 {
        return Ok((9, "RAND".to_string()));
    }
    let row = find_token_row(rpc, &asset.to_string()).await?;
    let symbol = row["symbol"].as_str().map(str::to_string).unwrap_or_else(|| format!("asset {asset}"));
    Ok((row_decimals(&row, asset)?, symbol))
}

/// [`parse_decimal`] at a token row's own `decimals` — `rand token mint`'s reader, which already
/// holds the row.
pub fn parse_row_amount(row: &Value, asset: u32, text: &str) -> Result<u64> {
    parse_decimal(text, row_decimals(row, asset)?)
}

/// `--amount`/a `randpay:` link's `amount`, in the asset's own display units: RAND (asset 0) at
/// this chain's nine decimals via [`parse_amount`](randprotocol_core::parse_amount)'s scale, and
/// any other asset at its registry row's own `decimals` — the same whole-listing
/// [`rand_getTokens`] page [`resolve_asset`] already reads, never a per-token lookup (the same
/// privacy reason: asking the node about the one token this amount is about, right before a
/// transfer of it, would tell the node's operator what [`resolve_asset`] already keeps from it).
///
/// **Behaviour change**: before this, a token amount on the command line was a whole number of
/// the asset's smallest unit; it is now the same display-unit form a `randpay:` link's `amount`
/// takes, matching every other amount this wallet prints or parses.
pub async fn parse_asset_amount(rpc: &RpcClient, asset: u32, text: &str) -> Result<u64> {
    let (decimals, _) = asset_units(rpc, asset).await?;
    parse_decimal(text, decimals)
}

/// One `rand_getTokens` row, found the way [`resolve_asset`] finds an index: by paging the whole
/// registry and matching `text` against a row's `index`, `id_text` or `id` (hex, `0x` optional,
/// case-insensitive) — never `rand_getToken`, so a wallet reading one token's row after
/// [`resolve_asset`] already read the same listing costs this node nothing more than asking after
/// any other token. `rand token info`'s reader; `rand token mint` and `rand token set-authority`
/// use it too, for the row's `mint_nonce`, id and authority key. The row is held to the same
/// checks as [`resolve_asset`]'s (WAL-1): its id fields agree and its index is a token's.
pub async fn find_token_row(rpc: &RpcClient, text: &str) -> Result<Value> {
    if let Ok(index) = text.trim().parse::<u64>() {
        return find_row(rpc, text, "", |row| row["index"].as_u64() == Some(index)).await;
    }
    let want = parse_token_id(text)?;
    find_row_by_id(rpc, text, &want, "").await
}

/// The most a default fee may pay as a node-reported registration fee (audit WAL-2): 10 RAND, ten
/// times chain 14's. `registration_fee` is read from the node (`rand_getTokens`,
/// `rand_getBridgeState`), and the default fee adds it on top of the floor with nothing to check it
/// against; above this, [`default_registration_fee`] refuses and the caller passes `--fee` to pay
/// it deliberately.
pub const MAX_DEFAULT_REGISTRATION_FEE: u64 = 10 * randprotocol_core::UNITS_PER_RAND;

/// The default fee of a registration: `floor` plus the node-reported `registration_fee`, refused
/// when the latter is above [`MAX_DEFAULT_REGISTRATION_FEE`] — a lying or misconfigured node
/// could otherwise set any fee the wallet can cover, and the wallet would prove and pay it.
pub fn default_registration_fee(floor: u64, registration_fee: u64) -> Result<u64> {
    if registration_fee > MAX_DEFAULT_REGISTRATION_FEE {
        return Err(anyhow!(
            "the node reports a registration fee of {} RAND, above the {} RAND this wallet pays by default; if that is really this chain's fee, pass it with --fee",
            format_amount(registration_fee),
            format_amount(MAX_DEFAULT_REGISTRATION_FEE)
        ));
    }
    Ok(floor.saturating_add(registration_fee))
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
/// this only checks the metadata, reads the chain and builds the note. `chain_id` is the one the
/// transaction is built for, which decides the initial mint's envelope format (issue #64).
#[allow(clippy::too_many_arguments)]
pub async fn build_register_token(
    rpc: &RpcClient,
    w: &Wallet,
    chain_id: u64,
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
            let (note, envelope) = mint_note_for(w, &recipient, amount, index, time, rpc.envelope_format(chain_id).await?)?;
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
///
/// BIND-1: `domain` is [`binding_domain`]'s answer for `chain_id` — under genesis
/// `binding_domain: 1` the authority's message carries the genesis hash.
#[allow(clippy::too_many_arguments)]
pub async fn build_token_mint(
    rpc: &RpcClient,
    w: &Wallet,
    domain: &BindingDomain,
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
    let (note, envelope) = mint_note_for(w, recipient, amount, asset, time, rpc.envelope_format(chain_id).await?)?;
    let cm = note.commitment();
    let signature = authority.sign(domain.token_mint_message(chain_id, &asset_id, nonce, amount, &cm, &envelope).as_bytes());
    Ok(Action::TokenMint { asset, amount, recipient: recipient.clone(), r: note.r, time, envelope, nonce, signature })
}

/// Build `rand token set-authority`'s `SetAuthority` action against `row` — the same
/// already-fetched row and refusals as [`build_token_mint`] — then `authority`'s signature over
/// [`set_authority_message`] for `new`: a key to hand the token to, or `None` to renounce minting
/// for good.
/// `domain` as in [`build_token_mint`] (BIND-1).
pub fn build_token_set_authority(
    domain: &BindingDomain,
    chain_id: u64,
    asset: u32,
    row: &Value,
    authority: &Keypair,
    new: Option<PublicKey>,
) -> Result<Action> {
    check_key_authority(row, asset, authority, "hand on")?;
    let (asset_id, nonce) = row_id_and_nonce(row, asset)?;
    let signature = authority.sign(domain.set_authority_message(chain_id, &asset_id, nonce, &new).as_bytes());
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
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_register_token_with(rpc, w, store, action, fee, profile, proving, chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_register_token_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(action, Action::RegisterToken { .. }) {
        return Err(anyhow!("submit_register_token carries a RegisterToken action, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, profile, proving, chain_id, wait).await
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
    program: Option<randprotocol_core::program::ProgramId>,
    initial: Option<(u64, ShieldedAddress)>,
    salt: [u8; 32],
    fee: Option<u64>,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<CreateTokenResult> {
    create_token_with(rpc, w, store, name, symbol, decimals, authority, program, initial, salt, fee, profile, proving, chain_id, wait)
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
    program: Option<randprotocol_core::program::ProgramId>,
    initial: Option<(u64, ShieldedAddress)>,
    salt: [u8; 32],
    fee: Option<u64>,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<CreateTokenResult> {
    // RPL-2: a token a program mints and burns through its invokes (`MintAuthority::Program`),
    // registered with no initial supply — the chain refuses one — and no key on disk.
    let mint_authority = match (authority, program) {
        (Some(_), Some(_)) => return Err(anyhow!("a token has one authority: a key or a program, not both")),
        (_, Some(id)) if initial.is_some() => {
            return Err(anyhow!("a program token ({id}) starts at zero supply: only the program's invokes mint it, so no --initial"))
        }
        (_, Some(id)) => MintAuthority::Program(id),
        (Some((kp, _)), None) => MintAuthority::Key(kp.public_key().clone()),
        (None, None) => MintAuthority::None,
    };
    let plan = build_register_token(rpc, w, chain_id, name, symbol, decimals, mint_authority, initial, salt).await?;
    let index = plan.index;
    let id = match &plan.action {
        Action::RegisterToken { name, symbol, decimals, authority, initial, salt, .. } => {
            randprotocol_core::ledger::tokens::native_asset_id(name, symbol, *decimals, authority, initial, salt)
        }
        _ => unreachable!("build_register_token always returns a RegisterToken action"),
    };
    let fee = match fee {
        Some(fee) => fee,
        None => default_registration_fee(schedule_floor(rpc, &plan.action).await?, plan.registration_fee)?,
    };
    eprintln!(
        "registering {symbol} at index {index}: fee {} RAND (the node reports a registration fee of {} RAND)",
        format_amount(fee),
        format_amount(plan.registration_fee)
    );

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
    let result = submit_register_token_with(rpc, w, store, plan.action, fee, profile, proving, chain_id, wait).await;
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
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_token_mint_with(rpc, w, store, action, fee, profile, proving, chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_token_mint_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(action, Action::TokenMint { .. }) {
        return Err(anyhow!("submit_token_mint carries a TokenMint action, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, profile, proving, chain_id, wait).await
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
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    submit_token_set_authority_with(rpc, w, store, action, fee, profile, proving, chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn submit_token_set_authority_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    action: Action,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if !matches!(action, Action::SetAuthority { .. }) {
        return Err(anyhow!("submit_token_set_authority carries a SetAuthority action, nothing else"));
    }
    submit_with(rpc, w, store, None, action, fee, Burn::None, profile, proving, chain_id, wait).await
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
    memo: &str,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    send_asset(rpc, w, store, to, 0, amount, memo, fee, profile, proving, chain_id, wait).await
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
    memo: &str,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    send_asset_with(rpc, w, store, to, asset, amount, memo, fee, profile, proving, chain_id, wait).await
}

#[allow(clippy::too_many_arguments)]
async fn send_asset_with(
    rpc: &RpcClient,
    w: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    asset: u32,
    amount: u64,
    memo: &str,
    fee: u64,
    profile: FriProfile,
    proving: &Proving,
    chain_id: u64,
    wait: bool,
) -> Result<Submission> {
    if amount == 0 {
        return Err(anyhow!("a transfer of zero moves nothing"));
    }
    let spend = Spend { asset, to: Some((to, amount)), memo, fee, burn_a: 0, burn_r: 0, prover_fee: None };
    submit_spend(rpc, w, store, spend, Action::None, Burn::None, profile, proving, None, chain_id, wait).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_zkvm::notes::SpendKey;

    /// Issue #116: `rand open-call` re-ran a program over an empty public segment, so any program
    /// deployed with `--public` trapped at its first `READ_PUBLIC`. The segment is the program's
    /// public words, plus the call's own binding under `hardening_v6`.
    #[test]
    fn the_open_call_re_run_uses_the_programs_public_words_and_the_hardened_binding() {
        let tx = Transaction::shielded(7, unread_bundle(), Action::Call { program: Hash::ZERO, proof: vec![1, 2, 3], input_envelope: None });
        let public = [61u32, 62, 63];
        let d = BindingDomain::ChainId;
        assert_eq!(open_call_public_segment(&public, false, &tx, &d), vec![61, 62, 63]);
        let hardened = open_call_public_segment(&public, true, &tx, &d);
        assert_eq!(hardened.len(), 3 + randprotocol_core::types::TX_BINDING_WORDS);
        assert_eq!(&hardened[..3], &public);
        assert_eq!(&hardened[3..], &tx.call_binding(&d)[..], "the binding the ledger verified the call against");
        assert_eq!(open_call_public_segment(&[], true, &tx, &d), tx.call_binding(&d).to_vec(), "a program without a public input: the binding alone");
        // BIND-1: under `binding_domain: 1` the segment carries the genesis-bound binding.
        let g = BindingDomain::Genesis(Hash([0xa; 32]));
        assert_eq!(&open_call_public_segment(&public, true, &tx, &g)[3..], &tx.call_binding(&g)[..]);
        assert_ne!(tx.call_binding(&g), tx.call_binding(&d));
    }

    fn env() -> Envelope {
        Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] }
    }

    fn owned(index: u64, amount: u64, spent: bool) -> OwnedNote {
        owned_asset(index, amount, spent, 0)
    }

    fn owned_asset(index: u64, amount: u64, spent: bool, asset: u32) -> OwnedNote {
        let note = Note::new([1; 8], [2; 8], amount, asset, 3);
        OwnedNote { index, cm: note.commitment(), nf: [index as u32; 8], note, spent, pending: None, height: index, memo: None }
    }

    /// CPU-1's residual (issue #57): a program inside the deploy bound — which is the prover's
    /// limit for a call with no inputs — is still uncallable once a call's private inputs are
    /// digested as well. The dry run refuses it before the deploy is paid for, and passes the same
    /// call a few words shorter.
    #[test]
    fn a_deploy_dry_run_refuses_a_program_its_inputs_push_past_the_call_tier_cap() {
        let mut program = randprotocol_zkvm::guests::private_payment(1000);
        let bound = randprotocol_zkvm::executor::max_callable_program_words(TX_BINDING_WORDS);
        program.words.resize(bound, 0x13);
        let inputs = [400, 250, 300, 75];
        let refused = deploy_dry_run(&program, &[], &inputs, true).unwrap_err().to_string();
        assert!(refused.contains("not deploying"), "{refused}");
        program.words.truncate(bound - 16);
        assert_eq!(deploy_dry_run(&program, &[], &inputs, true).unwrap(), randprotocol_zkvm::executor::MAX_CALL_TIER);
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

    /// VK-6 (audit v6): a spend-key file anyone else on the machine can read is refused on load,
    /// with the fix named, exactly as `rand-prover` refuses its `prover.key.json`. The file is the
    /// wallet — a copy of it spends every note on every chain — and nothing else notices a key that
    /// was restored from a backup, or copied by hand, at 0644.
    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_key_file_is_refused_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.key.json");
        let w = Wallet::generate();
        w.save_new(&path).unwrap();
        for mode in [0o644, 0o640, 0o604, 0o660] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let Err(e) = Wallet::load(&path) else { panic!("a key file at mode {mode:o} was loaded") };
            let e = format!("{e:#}");
            assert!(e.contains("group/world readable") && e.contains(&format!("(mode {mode:o})")), "{e}");
            assert!(e.contains("chmod 600") && e.contains("w.key.json"), "the fix is named: {e}");
        }
        for mode in [0o600, 0o400] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(Wallet::load(&path).unwrap().sk, w.sk, "mode {mode:o}");
        }
        // Through a symlink (the cut scripts scan a curated directory of them) the mode that
        // counts is the key file's own, not the link's.
        let link = dir.path().join("link.key.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(Wallet::load(&link).unwrap().sk, w.sk);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Wallet::load(&link).is_err());
    }

    /// VK-6 (audit v6): `NoteStore::save` opened `<store>.tmp` with `create(true).truncate(true)`,
    /// which follows a symlink — so a link planted at that name (the path is predictable: the key
    /// file's, plus `.notes.json.tmp`) had the wallet's whole history written through it into
    /// whatever it pointed at, and was then renamed over the store. The stale name is removed and
    /// the temporary file created with `create_new`, which never follows one.
    #[cfg(unix)]
    #[test]
    fn a_pre_planted_symlink_temp_file_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.key.json.notes.json");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "not the wallet's to write").unwrap();
        let tmp = dir.path().join("w.key.json.notes.json.tmp");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        let store = NoteStore { genesis: Some(Hash([7; 32])), scanned_index: 41, ..NoteStore::default() };
        store.save(&path).unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "not the wallet's to write", "the store was written through the symlink");
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink(), "the store is a file of its own, not the planted link");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(std::fs::symlink_metadata(&tmp).is_err(), "no temporary file is left behind");
        let back = NoteStore::load(&path);
        assert_eq!((back.genesis, back.scanned_index), (Some(Hash([7; 32])), 41));
    }

    /// The other half of VK-6: a stale `.tmp` left world-readable (a crash between write and
    /// rename, or a file someone else made) kept its mode through `open(create)` — a mode applies
    /// only at creation — and carried it over the store by the rename. As `Contacts::save`
    /// (2b6da966).
    #[cfg(unix)]
    #[test]
    fn a_stale_world_readable_temp_file_does_not_leak_its_mode_into_the_store() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.key.json.notes.json");
        let tmp = dir.path().join("w.key.json.notes.json.tmp");
        std::fs::write(&tmp, "stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        NoteStore::default().save(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // And a save over an existing store replaces it (the rename), still owner-only.
        let store = NoteStore { scanned_index: 9, ..NoteStore::default() };
        store.save(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"scanned_index\": 9"));
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
            genesis: None,
            scanned_index: 4,
            scanned_height: 2,
            scanned_attest_height: 3,
            notes: vec![owned(0, 5, false), owned(1, 3, true), owned(2, 0, false), owned(3, 2, false)],
            sent: vec![],
            ..NoteStore::default()
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
            auth_proving: None,
            prover_fee: 0,
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
        assert_eq!(classify(&me, mine.commitment(), &sealed(&stranger, &me, &mine)), Found::Received(mine, None));

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
        assert_eq!(classify(&me, bridged.commitment(), &sealed(&stranger, &me, &bridged)), Found::Received(bridged, None));

        // A note I created for someone else is history, reached through `ovk`, not the KEM.
        let paid = Note::new(stranger.vk.pk(), me.vk.pk(), 3, 0, 1);
        assert_eq!(classify(&me, paid.commitment(), &sealed(&me, &stranger, &paid)), Found::Sent(paid, None));

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
        let (note, envelope) = deposit_note_for(&me, &me.address, &a, 1_000, 3, 41, EnvelopeFormat::Legacy).unwrap();
        // `ConfidentialExecutor::note_commitment` is the function `bridge_notes` computes the
        // deposit's commitment through, on the ledger's side of the same wire — over the action's
        // own `r`, which is this note's.
        let ex = randprotocol_zkvm::executor::ZkExecutor::new(FriProfile::Test);
        assert_eq!(note.commitment(), ex.note_commitment(&me.address.pk, &[0; 8], 1_000, 3, 41, &note.r));
        assert_eq!((note.amount, note.asset, note.time, note.from), (1_000, 3, 41, [0; 8]));
        // And the envelope published with it opens back to that note, as the recipient.
        assert_eq!(classify(&me, note.commitment(), &envelope), Found::Received(note, None));
        // A different `time` is a different note: this is why `time` is on the action.
        let (later, _) = deposit_note_for(&me, &me.address, &a, 1_000, 3, 42, EnvelopeFormat::Legacy).unwrap();
        assert_ne!(later.commitment(), note.commitment());
        // The blinding is not drawn, it is derived (F1): this attestation's digest fixes it, so
        // every submitter of it builds the very same note — and the ledger admits no other `r`
        // (`bridge_notes::deposit_r`, the rule `validate` enforces).
        assert_eq!(note.r, bridge_notes::deposit_r(&a).unwrap());
        assert_eq!(deposit_note_for(&me, &me.address, &a, 1_000, 3, 41, EnvelopeFormat::Legacy).unwrap().0.r, note.r);
        let other = transfer_attestation(999, me.address.recipient_hash());
        assert_ne!(bridge_notes::deposit_r(&other).unwrap(), note.r, "another attestation, another blinding");
        assert!(deposit_note_for(&me, &me.address, &[0xff; 4], 1_000, 3, 41, EnvelopeFormat::Legacy).is_err(), "no body, no note");
    }

    // ------------------------------------------------ the hidden-asset bundle, end to end
    //
    // Every test below drives the real submission path — scan, plan, anchor and witnesses, build,
    // assemble, bind, prove, submit — against `ChainState`, a node kept in memory behind a real
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

    /// The `hc_auth` the emulated auth "proof" is made under — any word, as [`EMULATED_HC`].
    const EMULATED_AUTH_HC: Word8 = [0xa0; 8];

    /// [`Proving::Emulated`]: the hidden guest run on `p.words` against `binding`, its digest
    /// checked as a real proof's is, and a stub proof carrying it. On a v3 chain the auth guest
    /// is run too, on `auth_inputs(sk, salt)`, its `c` checked against `auth_commit` as a real
    /// auth proof's is, and a stub auth proof carrying it.
    pub(super) fn emulated_proof(p: &Prepared, sk: &SpendKey, binding: &[u32; TX_BINDING_WORDS]) -> Result<Proved> {
        let program = ZkExecutor::bundle_program_for(&p.guest).expect("prepare_bundle refuses a guest this build lacks");
        let run = randprotocol_zkvm::emulator::execute(program, &p.words, binding, 1 << 20)
            .map_err(|e| anyhow!("the hidden guest did not run: {e:?}"))?;
        let digest: Word8 = run.outputs;
        check_published_digest(&digest, &p.expected)?;
        let (auth_proof, auth_proving) = if p.v3 {
            let words = randprotocol_zkvm::auth::auth_inputs(sk, &p.salt);
            let run = randprotocol_zkvm::emulator::execute(ZkExecutor::auth_program(), &words, binding, 1 << 16)
                .map_err(|e| anyhow!("the auth guest did not run: {e:?}"))?;
            check_published_auth(&run.outputs, &p.auth_commit)?;
            (StubExecutor::make_auth_proof(&EMULATED_AUTH_HC, &run.outputs, binding), Some(Duration::ZERO))
        } else {
            (Vec::new(), None)
        };
        Ok(Proved { proof: StubExecutor::make_bundle_proof(&EMULATED_HC, &digest, binding), tier: 14, proving: Duration::ZERO, auth_proof, auth_proving })
    }

    /// A node in memory: the commitment tree and its envelopes, the blocks, the nullifiers, what
    /// was submitted, and the bridge's two replies.
    struct ChainState {
        tree: randprotocol_zkvm::ledger::CommitmentTree,
        leaves: Vec<(Word8, Envelope, u64)>,
        /// `roots[h]` is the tree root at the end of block `h` — what `rand_getAnchor(h)` answers,
        /// mirroring the real node's anchor table.
        roots: Vec<Word8>,
        /// `blocks[h]` is block `h`'s transactions; block 0 is genesis.
        blocks: Vec<Vec<Transaction>>,
        /// `(height, nullifier)` in chain order, as `rand_getNullifiers` pages them.
        nullifiers: Vec<(u64, Word8)>,
        sent: Vec<Transaction>,
        bridge: serde_json::Value,
        assets: serde_json::Value,
        /// `rand_getTokens`' whole reply, `{"enabled":.., "registration_fee":.., "next_index":..,
        /// "tokens":[..]}` — a token test sets it directly, since the registry itself lives on
        /// the real node this fake stands in for, not on this struct.
        tokens: serde_json::Value,
        /// A method that answers with an error, for the failure paths.
        fail: Option<&'static str>,
        /// The error code `fail` answers with — `-32000` by default (a verdict, as `rejected`
        /// replies are), overridden to exercise `-32603` (node N-2: not a verdict, so not
        /// `SubmitRefused`).
        fail_code: i64,
        /// The node's retention floor (`--prune-history`): a block below it, genesis excepted, is
        /// answered `-32010` by height, as the real node's `refuse_pruned` does. 0 is an archive.
        floor: u64,
        /// What `rand_getGenesisHash` answers: the chain this fake is.
        genesis: Hash,
        /// How many `rand_getWitness` calls this node has answered. A wallet that keeps its own
        /// tree (audit v3 PRIV-1) never makes one, so every send asserts this stays at zero.
        witness_calls: usize,
        /// Whether this fake's headers carry the public-note transactions raw (`public_notes`,
        /// issue #117 — a node since audit v6), or only `tx_count`, as an older node's do.
        headers_carry_public_notes: bool,
        /// How many `rand_getBlockByHeight` calls this node has answered (issue #117).
        block_reads: usize,
        /// Whether the carried public-note transactions come stripped, as a node since audit v7
        /// (RPC-5) carries them ([`public_rebuild_copy`]): proofs and co-signatures emptied,
        /// `proofs_stripped`, the real `hash` beside the copy.
        strip_public_notes: bool,
        /// The most heights a `rand_getBlocks` page may span before this fake answers it too large
        /// for the client to read, as a node without a reply budget did with a page of whole
        /// deposits (audit v7, RPC-5). `None`: every page fits.
        max_header_page: Option<u64>,
        /// Header pages longer than this stall until the client's read timeout runs out.
        stall_header_page: Option<u64>,
        /// The span of every `rand_getBlocks` range this node was asked for, in order.
        header_pages: Vec<u64>,
        /// `rand_getLimits`' `envelope_bytes` (task 7): `None` — this fake's default — is a chain
        /// that predates the field, same as a genuinely absent one; `Some(MEMO_ENVELOPE_BYTES)`
        /// is the memo format.
        envelope_bytes: Option<u32>,
        /// `rand_status`'s `hc_bundle`: the chain's bundle guest, v1 unless a test says otherwise.
        hc_bundle: Word8,
        /// `rand_status`'s `hc_auth`: `None` (served as null) unless a test runs split
        /// authorisation.
        hc_auth: Option<Word8>,
        /// `rand_getLimits`' `binding_domain` claim (BIND-1): `1` by default — this fake is chain
        /// 7, outside `CHAIN_ID_BINDING_CHAIN_IDS`, so the wallet proves the genesis-bound form
        /// there and a node claiming otherwise only gets a refusal.
        binding_domain: u32,
        /// `rand_getLimits`' `proof_window_blocks` (issue #118): `None`, served as null, unless a
        /// test runs a wider window.
        proof_window_blocks: Option<u64>,
        /// `Some((n, floor))`: the `n`-th `rand_getBlockByHeight` this node is asked (counting from
        /// 1, refused reads included) finds a pruning pass has just raised the floor to `floor` —
        /// a floor rising between a header page and a block read (CLI-18).
        raise_floor_at_read: Option<(usize, u64)>,
        /// How many `rand_getBlockByHeight` calls this node has been asked, refused ones included.
        block_asks: usize,
    }

    /// The node's `rpc::public_rebuild_copy` (audit v7, RPC-5), mirrored for this fake: the
    /// transaction with its bundle proof, auth proof, call proof and a deposit's co-signatures
    /// emptied — what a header carries since then.
    fn public_rebuild_copy(t: &Transaction) -> Transaction {
        let mut s = t.clone();
        if let Some(b) = s.bundle.as_mut() {
            b.proof = Vec::new();
            b.auth_proof = Vec::new();
        }
        match &mut s.action {
            Action::Invoke { proof, .. } => *proof = Vec::new(),
            Action::BridgeAttest { pq_signatures, .. } => *pq_signatures = Vec::new(),
            _ => {}
        }
        s
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

    impl ChainState {
        fn new() -> ChainState {
            let tree = randprotocol_zkvm::ledger::CommitmentTree::new();
            ChainState {
                roots: vec![tree.root()],
                tree,
                leaves: Vec::new(),
                blocks: vec![Vec::new()],
                nullifiers: Vec::new(),
                sent: Vec::new(),
                bridge: serde_json::json!({ "enabled": false }),
                assets: serde_json::json!([]),
                tokens: serde_json::json!({ "enabled": false, "tokens": [] }),
                fail: None,
                fail_code: -32000,
                floor: 0,
                genesis: Hash([9; 32]),
                witness_calls: 0,
                headers_carry_public_notes: false,
                block_reads: 0,
                strip_public_notes: false,
                max_header_page: None,
                stall_header_page: None,
                header_pages: Vec::new(),
                envelope_bytes: None,
                hc_bundle: ZkExecutor::hc_bundle(),
                hc_auth: None,
                binding_domain: 1,
                proof_window_blocks: None,
                raise_floor_at_read: None,
                block_asks: 0,
            }
        }

        /// BIND-1: the domain every transaction this fake accepts is bound under — the wallet's
        /// own answer for chain 7 over the genesis this fake serves.
        fn domain(&self) -> BindingDomain {
            crate::binding_domain_for(7, self.genesis)
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
            self.roots.push(self.tree.root());
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
                return Reply::Err(self.fail_code, "injected failure");
            }
            let n = |i: usize| p[i].as_u64().unwrap_or(0);
            let head = self.head();
            if method == "rand_getBlockByHeight" {
                self.block_asks += 1;
                if let Some((_, floor)) = self.raise_floor_at_read.filter(|(at, _)| *at == self.block_asks) {
                    self.floor = floor;
                }
            }
            // The real node's check: `rand_getBlocks` refuses the whole range when its first
            // non-genesis height is pruned; `rand_getBlockByHeight` refuses a pruned height.
            let first = match method {
                "rand_getBlocks" if n(1) >= n(0).max(1) => Some(n(0).max(1)),
                "rand_getBlockByHeight" if n(0) != 0 => Some(n(0)),
                _ => None,
            };
            if let Some(h) = first.filter(|h| *h < self.floor) {
                let floor = self.floor;
                return Reply::ErrData(
                    -32010,
                    format!("pruned: height {h} is below this node's retention floor {floor}"),
                    json!({ "floor": floor }),
                );
            }
            if method == "rand_getBlocks" {
                let span = (n(1).min(head).min(n(0) + 127) + 1).saturating_sub(n(0));
                self.header_pages.push(span);
                if self.max_header_page.is_some_and(|max| span > max) {
                    return Reply::TooLarge;
                }
                if self.stall_header_page.is_some_and(|max| span > max) {
                    return Reply::Stall;
                }
            }
            Reply::Ok(match method {
                "rand_getHead" => json!({ "height": head }),
                "rand_getGenesisHash" => json!(self.genesis.to_hex()),
                "rand_getBlocks" => json!((n(0)..=n(1).min(head).min(n(0) + 127))
                    .map(|h| {
                        let mut header = json!({ "height": h, "tx_count": self.blocks[h as usize].len() });
                        if self.headers_carry_public_notes {
                            header["public_notes"] = json!(self.blocks[h as usize]
                                .iter()
                                .filter(|t| kind(&t.action) != "other" && kind(&t.action) != "none")
                                .map(|t| match self.strip_public_notes {
                                    true => json!({
                                        "hash": t.hash().to_hex(), "raw": hex::encode(public_rebuild_copy(t).encode()),
                                        "proofs_stripped": true,
                                    }),
                                    false => json!({ "hash": t.hash().to_hex(), "raw": hex::encode(t.encode()) }),
                                })
                                .collect::<Vec<_>>());
                        }
                        header
                    })
                    .collect::<Vec<_>>()),
                "rand_getBlockByHeight" => {
                    self.block_reads += 1;
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
                "rand_getNullifiers" => json!(self
                    .nullifiers
                    .iter()
                    .filter(|(h, _)| *h >= n(0))
                    .take(n(1) as usize)
                    .map(|(h, nf)| json!({ "height": h, "nullifier": word8_to_hex(nf) }))
                    .collect::<Vec<_>>()),
                "rand_getAnchor" => match p.get(0).and_then(|h| h.as_u64()) {
                    // The head's anchor.
                    None => json!({ "height": head, "root": word8_to_hex(&self.tree.root()) }),
                    // A named height, as the real node's anchor table answers it (`-32001` when
                    // the chain has not reached it or has pruned it).
                    Some(h) => match self.roots.get(h as usize) {
                        Some(root) => json!({ "height": h, "root": word8_to_hex(root) }),
                        None => return Reply::Err(-32001, "no anchor at height"),
                    },
                },
                "rand_getWitness" => {
                    self.witness_calls += 1;
                    json!({
                        "root": word8_to_hex(&self.tree.root()),
                        "path": self.tree.path(n(0) as usize).iter().map(word8_to_hex).collect::<Vec<_>>(),
                    })
                }
                "rand_sendTransaction" => {
                    let tx = Transaction::decode(&hex::decode(p[0].as_str().unwrap_or_default()).unwrap()).unwrap();
                    let hash = tx.hash().to_hex();
                    self.sent.push(tx);
                    json!(hash)
                }
                "rand_status" => json!({ "hc_bundle": word8_to_hex(&self.hc_bundle), "hc_auth": self.hc_auth.as_ref().map(word8_to_hex) }),
                "rand_getBridgeState" => self.bridge.clone(),
                "rand_getAssets" => self.assets.clone(),
                "rand_getTokens" => self.tokens.clone(),
                "rand_getLimits" => json!({
                    "max_program_words": 4096, "max_proof_bytes": 2_097_152, "max_block_bytes": 4_194_304,
                    "max_call_envelope_bytes": 18_432, "max_program_public_words": 64,
                    "envelope_bytes": self.envelope_bytes,
                    "binding_domain": self.binding_domain,
                    "proof_window_blocks": self.proof_window_blocks,
                }),
                _ => return Reply::Err(-32601, "unknown method"),
            })
        }
    }

    /// The chain behind a real socket, and a client for it.
    async fn serve(chain: &Arc<Mutex<ChainState>>) -> RpcClient {
        let c = chain.clone();
        RpcClient::new(rpc_fn(move |m, p| c.lock().unwrap().answer(m, p)).await)
    }

    /// A whole [`ChainState`] plus a ready client for it, for the memo tests' one-call shape: fund
    /// a wallet, send with a memo, and look at what went out and what the payee scanned — every
    /// other test in this module drives `ChainState` and [`serve`] directly, because it wants to
    /// reach in at some step no send hides (a stale root, a garbage envelope, a second submission
    /// against the same plan); this is for the tests that just want a send to have happened.
    ///
    /// [`FakeChain::send`] uses a fee of 1, not [`gas::BUNDLE_BASE`]: this fake never checks a fee
    /// floor (there is no ledger behind it, only `ChainState::answer`), and a real floor would
    /// swallow whole the small `funded_wallet` amounts the memo tests fund with.
    struct FakeChain {
        inner: Arc<Mutex<ChainState>>,
    }

    impl FakeChain {
        /// A fresh chain whose `rand_getLimits` answers `envelope_bytes` as given:
        /// `Some(notes::MEMO_ENVELOPE_BYTES as u32)` is the memo format, `None` is the legacy one
        /// (chain 14's shape, and every chain that predates the field).
        fn with_envelope_bytes(bytes: Option<u32>) -> FakeChain {
            let mut c = ChainState::new();
            c.envelope_bytes = bytes;
            FakeChain { inner: Arc::new(Mutex::new(c)) }
        }

        /// A fresh wallet funded with `amount` RAND (asset 0), in a block of its own.
        fn funded_wallet(&self, amount: u64) -> Wallet {
            let w = Wallet::generate();
            self.inner.lock().unwrap().fund(&w, amount, 0);
            w
        }

        /// A fresh wallet this chain has never funded — a payee with nothing to scan yet.
        fn fresh_wallet(&self) -> Wallet {
            Wallet::generate()
        }

        /// `wallet::send_asset` (the emulated prover, so this takes no proving slot), then commits
        /// the sent transaction's own outputs as the next block — the real node's job, which this
        /// fake otherwise leaves to the caller (see every other test's manual `commit`) — so a
        /// scan of the payee finds it without a second, separate step.
        async fn send(&self, from: &Wallet, to: &ShieldedAddress, amount: u64, memo: &str) -> Result<Submission> {
            self.send_on(7, from, to, amount, memo).await
        }

        /// [`send`](Self::send), with the transaction built for `chain_id` rather than the
        /// fake's usual 7 (issue #64: a chain id this build knows predates `envelope_bytes`).
        async fn send_on(&self, chain_id: u64, from: &Wallet, to: &ShieldedAddress, amount: u64, memo: &str) -> Result<Submission> {
            let rpc = serve(&self.inner).await;
            let mut store = NoteStore::default();
            let submission = send_asset_with(&rpc, from, &mut store, to, 0, amount, memo, 1, FriProfile::Test, &Proving::Emulated, chain_id, false).await?;
            let tx = self.last_tx();
            let b = tx.bundle.as_ref().expect("a plain transfer has a bundle");
            let leaves: Vec<(Word8, Envelope)> = b.commitments.iter().zip(&b.envelopes).map(|(cm, e)| (*cm, e.clone())).collect();
            self.inner.lock().unwrap().commit(vec![tx], leaves);
            Ok(submission)
        }

        /// The last transaction this chain admitted (`rand_sendTransaction`).
        fn last_tx(&self) -> Transaction {
            self.inner.lock().unwrap().sent.last().expect("a transaction has been sent").clone()
        }

        /// A fresh scan of `w` against this chain, from an empty store.
        async fn scan(&self, w: &Wallet) -> NoteStore {
            let rpc = serve(&self.inner).await;
            let mut store = NoteStore::default();
            scan(&rpc, w, &mut store).await.expect("scan");
            store
        }
    }

    /// Task 7: a chain whose genesis carries `envelope_bytes` seals every output at exactly
    /// `MEMO_ENVELOPE_BYTES` (spec 2026-09-26 §2.4) — the payment slot's memo included — and the
    /// payee (from the envelope) and the sender (from their own `sent` row) both read it back.
    #[tokio::test]
    async fn on_a_memo_chain_every_output_is_1860_bytes_and_the_payee_reads_the_memo() {
        let chain = FakeChain::with_envelope_bytes(Some(1860)); // add this constructor: sets rand_getLimits' field
        let (alice, bob) = (chain.funded_wallet(10), chain.fresh_wallet());
        chain.send(&alice, &bob.address, 1, "coffee").await.unwrap();
        for e in chain.last_tx().bundle.unwrap().envelopes.iter() {
            assert_eq!(e.len(), 1860);
        }
        let bob_store = chain.scan(&bob).await;
        assert_eq!(bob_store.notes[0].memo.as_deref(), Some("coffee"));
        let alice_store = chain.scan(&alice).await;
        assert_eq!(alice_store.sent[0].memo.as_deref(), Some("coffee"));
    }

    /// Chain 14 (and every chain whose `rand_getLimits` carries no `envelope_bytes` at all) stays
    /// on the 1 348-byte legacy shape, and a non-empty memo is refused before anything is proved
    /// — never silently dropped.
    #[tokio::test]
    async fn on_chain_14_the_wallet_seals_the_old_format_and_refuses_a_memo() {
        let chain = FakeChain::with_envelope_bytes(None);
        let (alice, bob) = (chain.funded_wallet(10), chain.fresh_wallet());
        let err = chain.send(&alice, &bob.address, 1, "coffee").await.unwrap_err();
        assert!(err.to_string().contains("no memo"));
        chain.send(&alice, &bob.address, 1, "").await.unwrap();
        for e in chain.last_tx().bundle.unwrap().envelopes.iter() {
            assert_eq!(e.len(), 1348, "an old wallet can open it");
        }
    }

    /// Issue #64: `rand_getLimits` is the node's word, not the genesis'. A node (or anything
    /// between the wallet and it) that answers `envelope_bytes: 1860` for a chain whose genesis
    /// has no such field — chain 15 here — must not make the wallet seal 1,860-byte envelopes:
    /// the chain would admit them (≤ 2,048) and every transaction this wallet sent would carry a
    /// permanent public tag among everyone else's 1,348-byte ones. The chain id is the
    /// transaction's own (a lie about it gets the transaction refused `WrongChain`), so it is
    /// what the wallet checks the claim against.
    #[tokio::test]
    async fn a_node_claiming_the_memo_format_on_a_pre_memo_chain_is_not_believed() {
        let chain = FakeChain::with_envelope_bytes(Some(1860)); // the lie
        let (alice, bob) = (chain.funded_wallet(10), chain.fresh_wallet());
        let err = chain.send_on(15, &alice, &bob.address, 1, "coffee").await.unwrap_err();
        assert!(err.to_string().contains("no memo"), "{err}");
        chain.send_on(15, &alice, &bob.address, 1, "").await.unwrap();
        for e in chain.last_tx().bundle.unwrap().envelopes.iter() {
            assert_eq!(e.len(), 1348, "chain 15's genesis has no envelope_bytes, whatever the node says");
        }
    }

    /// Task 8 (T7 review round 1): a memo one byte over [`MEMO_TEXT_MAX_BYTES`] (510) is refused
    /// while the bundle is still being sealed, before `rand_sendTransaction` is ever called —
    /// nothing is admitted for a send that was going to fail anyway.
    #[tokio::test]
    async fn a_memo_over_the_limit_is_refused_before_anything_is_submitted() {
        let chain = FakeChain::with_envelope_bytes(Some(1860));
        let (alice, bob) = (chain.funded_wallet(10), chain.fresh_wallet());
        let memo = "x".repeat(randprotocol_zkvm::viewing::MEMO_TEXT_MAX_BYTES + 1);
        let err = chain.send(&alice, &bob.address, 1, &memo).await.unwrap_err();
        assert!(err.to_string().contains("memo"), "{err}");
        assert!(chain.inner.lock().unwrap().sent.is_empty(), "nothing was submitted");
    }

    /// A note store written before the memo existed has no `memo` key at all; it still loads,
    /// at `None` — the same `#[serde(default)]` `pending` already relies on.
    #[test]
    fn a_store_written_before_the_memo_loads() {
        let note = Note::new([1; 8], [2; 8], 5, 0, 3);
        let json = format!(
            r#"{{"index":1,"note":"{}","cm":"{}","nf":"{}","spent":false,"height":3}}"#,
            hex::encode(note.to_bytes()),
            word8_to_hex(&note.commitment()),
            word8_to_hex(&[9; 8]),
        );
        let n: OwnedNote = serde_json::from_str(&json).unwrap();
        assert_eq!(n.memo, None);
    }

    /// Everything the chain would check of a submitted bundle without its proof, plus the proof
    /// check the stub can make: every nullifier and commitment distinct, the digest the ledger
    /// recomputes (through the real executor) is the one the emulated guest published, and the
    /// proof verifies against the transaction's own binding.
    ///
    /// BIND-1: the binding is the one the wallet chose for `tx.chain_id` — the genesis-bound form
    /// over the fake chain's default genesis ([`ChainState::new`]) off chains 14–19, the chain-id
    /// form on them — so a wallet that proved the wrong form fails here.
    fn assert_admissible_shape(tx: &Transaction) {
        assert_admissible_shape_on(tx, &crate::binding_domain_for(tx.chain_id, ChainState::new().genesis))
    }

    fn assert_admissible_shape_on(tx: &Transaction, domain: &BindingDomain) {
        let b = tx.bundle.as_ref().expect("a bundle");
        for i in 0..SLOTS {
            for j in i + 1..SLOTS {
                assert_ne!(b.nullifiers[i], b.nullifiers[j], "nullifiers {i} and {j}");
                assert_ne!(b.commitments[i], b.commitments[j], "commitments {i} and {j}");
            }
        }
        let recomputed = ZkExecutor::new(FriProfile::Test).bundle_digest(&b.digest_input());
        assert_eq!(StubExecutor.bundle_proof_digest(&[0; 8], &b.proof).unwrap(), recomputed, "the ledger's digest is the guest's");
        assert_eq!(StubExecutor.verify_bundle(&EMULATED_HC, &b.proof, &tx.binding(domain)), Ok(()), "bound to this transaction");
        if let BindingDomain::Genesis(_) = domain {
            assert!(StubExecutor.verify_bundle(&EMULATED_HC, &b.proof, &tx.binding(&BindingDomain::ChainId)).is_err(), "not the chain-id form");
        }
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
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
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

    /// v0.6.8, `bridge.fees`: the depositor rebuilds its deposit at the net amount, and the
    /// treasury — the wallet named `fees.recipient` — rebuilds both of its fee notes, the deposit's
    /// and a burn's, from the transactions' public fields alone (the burn's from a proof-stripped
    /// copy, given its real id), each word for word the note the ledger appended. A stranger gets
    /// nothing; with no fee context the deposit is the gross, as on every earlier chain.
    #[test]
    fn the_treasury_rebuilds_both_fee_notes_and_the_depositor_its_net_deposit() {
        let me = Wallet::from_spend_key(SpendKey([41; 8]));
        let treasury = Wallet::from_spend_key(SpendKey([43; 8]));
        let stranger = Wallet::from_spend_key(SpendKey([42; 8]));
        let ex = ZkExecutor::new(FriProfile::Test);
        let state = serde_json::json!({
            "enabled": true,
            "fees": { "mint_bps": 10, "burn_bps": 10, "recipient": treasury.address.to_string() },
            "assets": [{ "index": 3, "chain": TOKEN_CHAIN, "token": hex::encode(TOKEN), "decimals": 6, "locked": "0" }],
        });
        let ctx = BridgeFeeCtx::from_bridge_state(&state).expect("a fee context");
        assert_eq!(ctx.units.get(&(TOKEN_CHAIN, TOKEN)), Some(&100));
        assert_eq!(BridgeFeeCtx::from_bridge_state(&serde_json::json!({ "enabled": true, "fees": null, "assets": [] })), None);

        // 1 USDT in: 0.999 to me, 0.001 to the treasury.
        let attestation = transfer_attestation(100_000_000, me.address.recipient_hash());
        let r = bridge_notes::deposit_r(&attestation).unwrap();
        let deposit = Transaction::shielded(
            7,
            unread_bundle(),
            Action::BridgeAttest { attestation: attestation.clone(), recipient: me.address.clone(), r, time: 4, asset: 3, envelope: garbage(), pq_signatures: vec![] },
        );
        let mine = rebuilt_notes_with(&me, &deposit, None, Some(&ctx));
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].amount, 99_900_000);
        assert_eq!(mine[0].commitment(), bridge_notes::deposit_commitment(&me.address, 99_900_000, 3, 4, &r, &ex));
        assert_eq!(rebuilt_notes(&me, &deposit)[0].amount, 100_000_000, "no fee context: the gross, as before");
        let fee = rebuilt_notes_with(&treasury, &deposit, None, Some(&ctx));
        assert_eq!(fee.len(), 1, "the treasury's fee note, and not the deposit");
        let mu = randprotocol_core::bridge::digest(Attestation::body_bytes(&attestation).unwrap());
        let ledger_fee = bridge_notes::BridgeFeeNote { amount: 100_000, asset: 3, time: 4, r: bridge_notes::derive_mint_fee_r(&mu) };
        assert_eq!(fee[0].commitment(), ledger_fee.commitment(&treasury.address, &ex), "the ledger's own fee note");
        assert!(rebuilt_notes_with(&stranger, &deposit, None, Some(&ctx)).is_empty());

        // 0.5 zUSD out: the treasury's 0.0005, blinded over the burn's real id.
        let mut bundle = unread_bundle();
        bundle.burn_asset = 3;
        bundle.burn_a = 50_000_000;
        bundle.time = 9;
        bundle.proof = vec![7; 64];
        let burn = Transaction::shielded(
            7,
            bundle,
            Action::BridgeBurn { asset: 3, amount: 50_000_000, relayer_fee: 0, to_chain: TOKEN_CHAIN, token: TOKEN, to: [1; 32] },
        );
        let ledger_fee = bridge_notes::BridgeFeeNote { amount: 50_000, asset: 3, time: 9, r: bridge_notes::derive_burn_fee_r(&burn.hash()) };
        let fee = rebuilt_notes_with(&treasury, &burn, None, Some(&ctx));
        assert_eq!(fee.len(), 1);
        assert_eq!(fee[0].commitment(), ledger_fee.commitment(&treasury.address, &ex));
        let mut stripped = burn.clone();
        stripped.bundle.as_mut().unwrap().proof = Vec::new();
        assert_ne!(stripped.hash(), burn.hash());
        assert_eq!(rebuilt_notes_with(&treasury, &stripped, Some(&burn.hash()), Some(&ctx)), fee, "the header's stripped copy, under the real id");
        assert!(rebuilt_notes_with(&me, &burn, None, Some(&ctx)).is_empty(), "only the treasury rebuilds a burn");
        assert!(rebuilt_notes(&treasury, &burn).is_empty(), "and only on a chain with the group");

        // The quote a burner sees before confirming.
        assert_eq!(burn_fee_quote(&state, TOKEN_CHAIN, &TOKEN, 50_000_000), 50_000);
        assert_eq!(burn_fee_quote(&serde_json::json!({ "enabled": true, "assets": [] }), TOKEN_CHAIN, &TOKEN, 50_000_000), 0);
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
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

        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 3, 400, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
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
        let Found::Received(paid, _) = theirs[0] else { panic!("slot 0 pays the payee: {theirs:?}") };
        assert_eq!((paid.amount, paid.asset, paid.from), (400, 3, me.vk.pk()));
        assert!(theirs[1..].iter().all(opens_to_nobody), "{theirs:?}");
        let mine = slots_for(&me, &tx);
        assert!(matches!(mine[0], Found::Sent(n, _) if n.amount == 400));
        assert!(matches!(mine[1], Found::Received(n, _) if n.amount == 600 && n.asset == 3));
        assert!(matches!(mine[2], Found::Received(n, _) if n.amount == gas::BUNDLE_BASE && n.asset == 0));
        assert!(opens_to_nobody(&mine[3]), "{:?}", mine[3]);
        // `--no-wait`: the two spent notes are held back until the chain answers.
        assert_eq!(store.balance_of(3), 0);
        assert_eq!(store.balance(), 0);
    }

    /// RS-1: a fresh wallet pointed at a pruned node (every validator keeps one day) walks the
    /// blocks from height 0, and the node answers `-32010` with its floor for the whole range. The
    /// scan resumes the walk at the floor instead of failing: a note sealed honestly below it is
    /// still found through the commitment pages (never pruned), a deposit above it is rebuilt, and
    /// the block cursor passes the head so the next scan does not walk into the floor again. The
    /// one thing lost is a garbage-envelope public note below the floor — which `sync --rescan`
    /// against an archive recovers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_scan_against_a_pruned_node_resumes_at_its_floor() {
        let me = Wallet::from_spend_key(SpendKey([57; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        let (txs, notes) = public_notes_for(&me);
        let mut txs = txs.into_iter();
        {
            let mut c = chain.lock().unwrap();
            c.fund(&me, 5, 0); // block 1: a shielded note, sealed to me
            c.commit(vec![txs.next().unwrap()], vec![(notes[0].commitment(), garbage())]); // block 2: a deposit
            for _ in 0..4 {
                c.commit(Vec::new(), Vec::new());
            }
            c.commit(vec![txs.next().unwrap()], vec![(notes[1].commitment(), garbage())]); // block 7: a mint
            c.floor = 5;
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.expect("a pruned node's floor is not a failed scan");
        assert_eq!(store.asset_balances(), vec![(0, 5), (5, 250)], "the shielded note and the mint above the floor");
        let head = chain.lock().unwrap().head();
        assert_eq!(store.scanned_attest_height, head + 1);
        // The next scan starts past the floor and neither fails nor walks into it.
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.len(), 2);

        // `rand sync --rescan` against an archive recovers the deposit below the floor.
        chain.lock().unwrap().floor = 0;
        store.reset();
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.asset_balances(), vec![(0, 5), (3, 1_000), (5, 250)]);
    }

    /// A save round trip, as `rand` does after every command whether or not it failed.
    fn saved(store: &NoteStore) -> NoteStore {
        serde_json::from_str(&serde_json::to_string(store).unwrap()).unwrap()
    }

    /// A scan that fails after reading the blocks but before placing the rebuilt notes at their
    /// leaves loses nothing: since issue #117 the cursor moves past the blocks as they are read,
    /// and what they held stays pending in the store `rand` saves on that failure, so the next
    /// scan places the garbage-envelope deposit without reading the blocks again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_scan_never_saves_a_cursor_past_an_unplaced_deposit() {
        let me = Wallet::from_spend_key(SpendKey([55; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
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
        assert_eq!(store.scanned_attest_height, chain.lock().unwrap().head() + 1, "the blocks were read and the cursor says so");
        assert_eq!(store.pending_public_notes.len(), notes.len(), "their notes wait in the saved store");
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

    /// The recovery pass, for a store whose leaf cursor is already past a deposit's leaf (an older
    /// build scanned it, and its garbage envelope opened nothing) but whose block cursor is 0 —
    /// what a store written before the public-rebuild path looks like. It is also a store with no
    /// tree (every store written before PRIV-1), so the scan's torn-store repair resets the leaf
    /// cursor to 0 and the *forward* pass re-reads every leaf, placing the deposit and its witness
    /// on the way. (The same recovery against a store whose tree *is* current is
    /// `a_recovered_note_at_a_leaf_the_tree_misfiled_gets_its_witness_back`.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rebuilt_note_below_the_leaf_cursor_is_placed_by_the_recovery_pass() {
        let me = Wallet::from_spend_key(SpendKey([56; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
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
        // The deposit at leaf 0, below the old cursor; the rescan re-offers every leaf, so the
        // RAND note at leaf 1 is recorded on the way (once — a leaf is keyed by its index).
        assert_eq!(deposit, vec![(0, 1_000, 3), (1, 5, 0)]);
        assert_eq!(store.tree.next_index(), 2, "the tree was rebuilt too");
        assert!(store.tree.path(0).is_some(), "the recovered deposit has its witness");
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.len(), 2, "a second scan adds nothing");
        assert_eq!(store.scanned_index, 2);
    }

    /// Issue #117: a node since audit v6 carries the public-note transactions beside their
    /// headers, so the walk reads a header page and no block; an older node's headers say only
    /// `tx_count`, and the walk still fetches every block with a transaction.
    #[tokio::test]
    async fn the_block_walk_reads_no_block_when_the_headers_carry_the_public_notes() {
        for carried in [false, true] {
            let me = Wallet::from_spend_key(SpendKey([57; 8]));
            let chain = Arc::new(Mutex::new(ChainState::new()));
            let (txs, notes) = public_notes_for(&me);
            {
                let mut c = chain.lock().unwrap();
                c.headers_carry_public_notes = carried;
                for (tx, note) in txs.into_iter().zip(notes.iter()) {
                    c.commit(vec![tx], vec![(note.commitment(), garbage())]);
                }
                c.fund(&me, 5, 0);
            }
            let rpc = serve(&chain).await;
            let mut store = NoteStore::default();
            scan(&rpc, &me, &mut store).await.unwrap();
            assert_eq!(store.notes.len(), notes.len() + 1, "carried {carried}: every public note is placed");
            let reads = chain.lock().unwrap().block_reads;
            match carried {
                true => assert_eq!(reads, 0, "the headers carried the transactions: no block was read"),
                false => assert_eq!(reads, notes.len(), "an older node: one read per block with a transaction"),
            }
            assert!(store.pending_public_notes.is_empty(), "nothing left pending after a finished scan");
        }
    }

    /// [`public_notes_for`]'s transactions as a chain would carry them: real-sized proofs on every
    /// bundle and a deposit co-signed by eight guardians.
    fn proved_public_notes_for(me: &Wallet) -> (Vec<Transaction>, Vec<Note>) {
        let (mut txs, notes) = public_notes_for(me);
        for t in &mut txs {
            let b = t.bundle.as_mut().unwrap();
            b.proof = vec![7; 1 << 16];
            b.auth_proof = vec![8; 1 << 16];
            if let Action::BridgeAttest { pq_signatures, .. } = &mut t.action {
                pq_signatures.extend((0..8).map(|i| randprotocol_core::bridge::PqSignature { index: i, signature: vec![9; 2420] }));
            }
        }
        (txs, notes)
    }

    /// Audit v7, RPC-5: a header carries a deposit, a mint and a registration stripped of their
    /// proofs and co-signatures; each note rebuilt from the stripped copy is word for word the
    /// one rebuilt from the whole transaction — the commitment the chain appended — for the
    /// recipient, and for the treasury its deposit fee note.
    #[test]
    fn every_public_note_rebuilds_from_a_stripped_copy() {
        let me = Wallet::from_spend_key(SpendKey([61; 8]));
        let (txs, notes) = proved_public_notes_for(&me);
        for (tx, note) in txs.iter().zip(&notes) {
            let copy = public_rebuild_copy(tx);
            assert!(copy.encoded_len() < tx.encoded_len() / 4, "the copy sheds the proofs");
            assert_ne!(copy.hash(), tx.hash(), "a stripped copy hashes differently");
            let rebuilt = rebuilt_notes_with(&me, &copy, Some(&tx.hash()), None);
            assert_eq!(rebuilt, rebuilt_notes(&me, tx));
            assert_eq!(rebuilt.iter().map(Note::commitment).collect::<Vec<_>>(), vec![note.commitment()], "the leaf the chain appended");
        }
        // The treasury's deposit fee note: its blinding is over the attestation's `mu`, which the
        // copy keeps whole.
        let treasury = Wallet::from_spend_key(SpendKey([62; 8]));
        let state = serde_json::json!({
            "enabled": true,
            "fees": { "mint_bps": 10, "burn_bps": 10, "recipient": treasury.address.to_string() },
            "assets": [{ "index": 3, "chain": TOKEN_CHAIN, "token": hex::encode(TOKEN), "decimals": 6, "locked": "0" }],
        });
        let ctx = BridgeFeeCtx::from_bridge_state(&state).unwrap();
        // 1 USDT, so the fee does not round to nothing.
        let mut deposit = txs[0].clone();
        let Action::BridgeAttest { attestation, r, .. } = &mut deposit.action else { unreachable!() };
        *attestation = transfer_attestation(100_000_000, me.address.recipient_hash());
        *r = bridge_notes::deposit_r(attestation).unwrap();
        let whole = rebuilt_notes_with(&treasury, &deposit, None, Some(&ctx));
        assert_eq!(whole.len(), 1, "the deposit's fee note");
        assert_eq!(rebuilt_notes_with(&treasury, &public_rebuild_copy(&deposit), Some(&deposit.hash()), Some(&ctx)), whole);
        assert_eq!(rebuilt_notes_with(&me, &public_rebuild_copy(&deposit), Some(&deposit.hash()), Some(&ctx)), rebuilt_notes_with(&me, &deposit, None, Some(&ctx)));
    }

    /// Audit v7, RPC-5: a node without a reply budget answers a page past this wallet's reply cap.
    /// Asking again for the same page was refused the same way for ever, so a first sync stopped
    /// for good; the walk now halves the range until a page fits, and every public note is
    /// placed. A header too large alone is an error, not a loop.
    #[tokio::test]
    async fn the_block_walk_halves_a_page_the_node_answers_too_large() {
        let me = Wallet::from_spend_key(SpendKey([63; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        let (txs, notes) = proved_public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            c.headers_carry_public_notes = true;
            c.strip_public_notes = true;
            c.max_header_page = Some(3);
            for (tx, note) in txs.into_iter().zip(notes.iter()) {
                c.commit(vec![tx], vec![(note.commitment(), garbage())]);
            }
            for _ in 0..6 {
                c.commit(Vec::new(), Vec::new());
            }
            c.fund(&me, 5, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.len(), notes.len() + 1, "every public note is placed");
        assert!(store.pending_public_notes.is_empty());
        let pages = chain.lock().unwrap().header_pages.clone();
        assert!(pages.iter().filter(|s| **s <= 3).count() >= 4, "the walk went on in pages that fit: {pages:?}");
        assert!(pages.iter().filter(|s| **s > 3).count() < 20, "a refusal is never asked again as it was: {pages:?}");

        // Nothing fits: the walk halves down to one height, and then says so.
        chain.lock().unwrap().max_header_page = Some(0);
        let e = scan(&rpc, &me, &mut NoteStore::default()).await.unwrap_err();
        assert!(format!("{e:#}").contains("alone is larger than this wallet reads"), "{e:#}");
        assert!(crate::reply_too_large(&e));
    }

    /// A header page still downloading when the read timeout runs out — a 29 MB page of
    /// proof-carrying deposits over a slow link did on chain 20, and every fresh wallet's first
    /// sync failed at once with "error decoding response body … operation timed out" — is asked
    /// again at half the range, like a page refused for its size, rather than asked again whole
    /// and timed out again for ever.
    #[tokio::test]
    async fn the_block_walk_halves_a_page_that_times_out() {
        let me = Wallet::from_spend_key(SpendKey([64; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        let (txs, notes) = proved_public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            c.headers_carry_public_notes = true;
            c.strip_public_notes = true;
            c.stall_header_page = Some(3);
            for (tx, note) in txs.into_iter().zip(notes.iter()) {
                c.commit(vec![tx], vec![(note.commitment(), garbage())]);
            }
            for _ in 0..6 {
                c.commit(Vec::new(), Vec::new());
            }
            c.fund(&me, 5, 0);
        }
        let rpc = serve(&chain).await.with_read_timeout(std::time::Duration::from_millis(300));
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.expect("the walk goes on in pages that arrive in time");
        assert_eq!(store.notes.len(), notes.len() + 1, "every public note is placed");
        let pages = chain.lock().unwrap().header_pages.clone();
        assert!(pages.iter().filter(|s| **s <= 3).count() >= 4, "the walk went on in pages that fit: {pages:?}");
    }

    /// Issue #117: a first sync stopped part-way — here the leaf page after the block walk fails
    /// — keeps the walk's progress: the cursor is past the blocks it read and their notes are
    /// pending in the store, so the next scan places them without reading a block again, and
    /// the wallet ends with exactly the notes it would have had in one go.
    #[tokio::test]
    async fn an_interrupted_first_sync_resumes_from_the_walks_last_page() {
        let me = Wallet::from_spend_key(SpendKey([58; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        let (txs, notes) = public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            for (tx, note) in txs.into_iter().zip(notes.iter()) {
                c.commit(vec![tx], vec![(note.commitment(), garbage())]);
            }
            c.fund(&me, 5, 0);
            c.fail = Some("rand_getCommitments");
            c.fail_code = -32005;
        }
        let rpc = serve(&chain).await.with_rate_limit_wait(Duration::from_millis(1));
        let mut store = NoteStore::default();
        let err = scan(&rpc, &me, &mut store).await.unwrap_err();
        assert!(err.to_string().contains("injected failure"), "{err}");
        let head = chain.lock().unwrap().head();
        assert_eq!(store.scanned_attest_height, head + 1, "the walk's cursor is past every block it read");
        assert_eq!(store.pending_public_notes.len(), notes.len(), "and what it found is kept for the next scan");
        assert!(store.notes.is_empty(), "nothing placed yet");
        // The store as a caller saves and reloads it (`rand balance` saves whether or not the
        // scan finished).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.notes.json");
        store.save(&path).unwrap();
        let mut store = NoteStore::load(&path);
        assert_eq!(store.pending_public_notes.len(), notes.len(), "pending notes survive the file");
        let reads_before = chain.lock().unwrap().block_reads;
        chain.lock().unwrap().fail = None;
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(chain.lock().unwrap().block_reads, reads_before, "the second scan read no block again");
        assert_eq!(store.notes.len(), notes.len() + 1, "every note placed");
        assert!(store.pending_public_notes.is_empty());
        assert!(store.tree.path(0).is_some(), "with its witness");
    }

    /// CLI-18 (audit v7): on a node whose headers do not carry the public notes, a pruning pass
    /// that raises the floor between the header page and a block read restarts the page at the
    /// floor. The notes the page had already read, from blocks below the new floor, were dropped
    /// with it while the cursor passed them; they are kept now.
    #[tokio::test]
    async fn a_floor_rising_mid_page_keeps_the_notes_the_page_already_read() {
        let me = Wallet::from_spend_key(SpendKey([64; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        let (txs, notes) = public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            // Blocks 1, 2, 3: a deposit, a mint, a registration's initial mint, garbage envelopes.
            for (tx, note) in txs.into_iter().zip(notes.iter()) {
                c.commit(vec![tx], vec![(note.commitment(), garbage())]);
            }
            c.fund(&me, 5, 0); // block 4
            // The third block read finds the floor raised past block 3.
            c.raise_floor_at_read = Some((3, 4));
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.expect("a floor is not a failed scan");
        assert_eq!(
            store.asset_balances(),
            vec![(0, 5), (3, 1_000), (5, 250)],
            "the deposit and the mint the page read before the floor rose are kept"
        );
        assert_eq!(store.scanned_attest_height, chain.lock().unwrap().head() + 1);
        assert!(store.pending_public_notes.is_empty());
    }

    /// CLI-19 (audit v7): a lying node serves a public-note transaction for this wallet with no
    /// leaf behind it. The rebuilt note is never credited, and it is not kept pending either: a
    /// pending note that no leaf matches made every later scan fail "match no leaf" — against an
    /// honest node too — until `rand sync --rescan`. It is dropped with a warning instead.
    #[tokio::test]
    async fn a_planted_public_note_with_no_leaf_does_not_fail_every_later_scan() {
        let me = Wallet::from_spend_key(SpendKey([65; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        let (txs, _) = public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            c.fund(&me, 5, 0); // block 1: a real note
            // Block 2, as the lying node serves it: a deposit to me whose leaf it never appended.
            c.commit(vec![txs.into_iter().next().unwrap()], Vec::new());
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        // Whatever the first scan says, `rand` saves the store it leaves.
        let _ = scan(&rpc, &me, &mut store).await;
        let mut store = saved(&store);
        assert_eq!(store.asset_balances(), vec![(0, 5)], "the planted note is never credited");

        // The honest node: the same chain, without the planted transaction.
        chain.lock().unwrap().blocks[2].clear();
        chain.lock().unwrap().fund(&me, 7, 0);
        scan(&rpc, &me, &mut store).await.expect("a scan against an honest node succeeds");
        assert_eq!(store.asset_balances(), vec![(0, 12)]);
        assert!(store.pending_public_notes.is_empty(), "nothing unplaceable is kept");
    }

    /// A store scanned against one chain is a cache of that chain alone. Carried to a node on
    /// another (a wallet file kept across a chain cut), its cursors point past leaves the new
    /// chain has not appended yet, every page comes back empty, and the wallet reports nothing
    /// without a word — a real note on the new chain stays invisible for as long as the file
    /// lives. Binding the store to the genesis it was scanned against, and starting over when
    /// the node's differs, is what makes a carried-over store find its notes.
    #[test]
    fn binding_a_store_to_another_chain_starts_it_over() {
        let this = Hash([1; 32]);
        let other = Hash([2; 32]);
        let mut store = NoteStore {
            genesis: Some(other),
            scanned_index: 60_000,
            scanned_height: 240_000,
            scanned_attest_height: 240_000,
            notes: vec![owned(0, 5, false)],
            sent: vec![SentRow { index: 7, to_pk: [4; 8], amount: 11, height: 2, memo: None }],
            ..NoteStore::default()
        };
        assert_eq!(store.bind(this), Bound::Reset { previous: Some(other) });
        assert_eq!(store.genesis, Some(this));
        assert_eq!((store.scanned_index, store.scanned_height, store.scanned_attest_height), (0, 0, 0));
        assert!(store.notes.is_empty() && store.sent.is_empty(), "nothing from the other chain survives");
        // Bound to this chain already: untouched.
        store.scanned_index = 9;
        assert_eq!(store.bind(this), Bound::Same);
        assert_eq!(store.scanned_index, 9);
        // A store from before the binding existed says nothing about its chain, so it is started
        // over once — the only way to know its rows are this chain's.
        let mut unbound = NoteStore { scanned_index: 60_000, ..NoteStore::default() };
        assert_eq!(unbound.bind(this), Bound::Reset { previous: None });
        assert_eq!((unbound.genesis, unbound.scanned_index), (Some(this), 0));
    }

    /// WAL-3: a node can report this wallet's own nullifiers as published, and the scan marks
    /// those notes spent for good — nothing ever un-spends one. `rand sync --rescan` is the way
    /// back short of deleting the file: `reset` empties everything learned (spent marks, pending
    /// holds, cursors, the tree, sent rows) and keeps only the chain the store is bound to, so
    /// the next scan rebuilds the whole picture from leaf 0 (ideally against another node).
    #[test]
    fn a_reset_store_forgets_its_spent_marks_and_cursors_but_keeps_its_chain() {
        let this = Hash([1; 32]);
        let mut pending = owned(1, 7, false);
        pending.pending = Some(40);
        let mut store = NoteStore {
            genesis: Some(this),
            scanned_index: 60_000,
            scanned_height: 240_000,
            scanned_attest_height: 240_000,
            notes: vec![owned(0, 5, true), pending],
            sent: vec![SentRow { index: 7, to_pk: [4; 8], amount: 11, height: 2, memo: None }],
            ..NoteStore::default()
        };
        store.reset();
        assert_eq!(store.genesis, Some(this), "the chain binding survives");
        assert_eq!((store.scanned_index, store.scanned_height, store.scanned_attest_height), (0, 0, 0));
        assert!(store.notes.is_empty() && store.sent.is_empty(), "every spent mark and hold is gone");
        assert_eq!(store.tree.next_index(), 0, "the tree is rebuilt from leaf 0 too");
        assert_eq!(store.bind(this), Bound::Same, "and the next scan does not treat it as a foreign store");
    }

    /// Issue #118, through a whole scan: a `--no-wait` spend 400 blocks old is still pending on a
    /// chain whose `rand_getLimits` says `proof_window_blocks: 1024` (the bundle can still commit
    /// there), and released on one that serves none (256).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_scan_holds_a_pending_spend_for_the_chains_proof_window() {
        let me = Wallet::from_spend_key(SpendKey([59; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.fund(&me, 5, 0);
            for _ in 0..400 {
                c.commit(Vec::new(), Vec::new());
            }
            c.proof_window_blocks = Some(1024);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.unwrap();
        store.notes[0].pending = Some(1);
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes[0].pending, Some(1), "400 blocks is inside the chain's 1 024-block window");
        chain.lock().unwrap().proof_window_blocks = None;
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes[0].pending, None, "and past today's 256");
    }

    /// The reproduction from 2026-09-23: a store whose leaf cursor sat past every leaf of the
    /// node's chain scanned to `0 RAND, 0 notes` in under two seconds, no warning. A scan now
    /// asks the node its genesis first, and a foreign store is rescanned from leaf 0.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_store_carried_from_another_chain_finds_its_notes_on_this_one() {
        let me = Wallet::from_spend_key(SpendKey([58; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 5, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore {
            genesis: Some(Hash([2; 32])),
            scanned_index: 60_000,
            scanned_height: 240_000,
            scanned_attest_height: 240_000,
            ..NoteStore::default()
        };
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.balance(), 5, "the note on this chain, below the carried-over cursor");
        assert_eq!(store.genesis, Some(chain.lock().unwrap().genesis), "bound to the node's chain now");
        assert_eq!(store.scanned_index, 1);
        // And a second scan against the same chain keeps what it has.
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.len(), 1);
    }

    #[test]
    fn the_chain_binding_survives_the_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(&dir.path().join("w.key.json"));
        let store = NoteStore { genesis: Some(Hash([3; 32])), ..NoteStore::default() };
        store.save(&path).unwrap();
        assert_eq!(NoteStore::load(&path).genesis, Some(Hash([3; 32])));
        // As hex in the file, like every other word in it.
        assert!(std::fs::read_to_string(&path).unwrap().contains(&Hash([3; 32]).to_hex()));
    }

    /// The wallet's block walk asks for the node's whole header page; a smaller ask is a
    /// round trip wasted per page, a larger one is clamped by the node anyway.
    #[test]
    fn the_header_page_is_the_nodes_cap() {
        assert_eq!(BLOCK_PAGE, randprotocol_node::rpc::MAX_BLOCK_HEADERS);
    }

    /// RAND held by a `--no-wait` submission is not spendable, but it is not missing: the refusal
    /// says to wait, not to go and get RAND.
    #[test]
    fn a_fee_refusal_names_rand_held_by_a_pending_submission() {
        let you = Wallet::from_spend_key(SpendKey([57; 8]));
        let mut store = NoteStore { notes: vec![owned_asset(0, 500, false, 4), owned_asset(1, 3_000_000, false, 0)], ..NoteStore::default() };
        store.notes[1].pending = Some(9);
        let spend = Spend { asset: 4, to: Some((&you.address, 100)), memo: "", fee: gas::BUNDLE_BASE, burn_a: 0, burn_r: 0, prover_fee: None };
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 3_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        // Needs both notes: neither alone covers 8 000 000 + the fee.
        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 8_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!((s.amount, s.change, s.asset, s.burn), (8_000_000, 2_000_000 - gas::BUNDLE_BASE, 0, Burn::None));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let theirs = slots_for(&you, &tx);
        assert!(matches!(theirs[2], Found::Received(n, _) if n.amount == 8_000_000 && n.asset == 0), "{theirs:?}");
        let mine = slots_for(&me, &tx);
        assert!(matches!(mine[3], Found::Received(n, _) if n.amount == 2_000_000 - gas::BUNDLE_BASE));
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

    /// The wallet proves the chain's bundle guest, not the one it was built around: on a chain
    /// whose genesis names the branch-free guest (INT-2 / GV-1) the bundle is proved with v2 —
    /// the emulated proof runs `bundle_program_for` of the `hc_bundle` `rand_status` names, and
    /// its digest still matches what the wallet built — and on a chain naming a guest this build
    /// does not carry the send is refused before anything is proved or sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_proves_the_bundle_guest_the_chain_names() {
        let me = Wallet::from_spend_key(SpendKey([46; 8]));
        let you = Wallet::from_spend_key(SpendKey([47; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        // Two notes: the first send leaves its note pending, the second spends the other.
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().hc_bundle = ZkExecutor::hc_hidden_bundle_v2();
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        chain.lock().unwrap().hc_bundle = [0xbad; 8];
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("which this wallet cannot prove"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty(), "nothing sent for a guest the wallet cannot prove");
    }

    /// Audit v3 PRIV-1: a wallet that asks the node for the witnesses of exactly the notes it
    /// spends tells the operator which leaves are its own. The wallet keeps the commitment tree
    /// itself (built during `scan` from the `rand_getCommitments` pages it already reads) and
    /// computes its own witnesses, so a send makes **no** `rand_getWitness` call at all — the
    /// only tree question it still asks is `rand_getAnchor`, which names no leaf.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_makes_no_witness_call() {
        let me = Wallet::from_spend_key(SpendKey([61; 8]));
        let you = Wallet::from_spend_key(SpendKey([62; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 3_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        // Two inputs, the shape that asked for two witnesses before this change.
        send_asset_with(&rpc, &me, &mut store, &you.address, 0, 8_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!(chain.lock().unwrap().witness_calls, 0, "the wallet computes its own witnesses (PRIV-1)");
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        // The scan grew the tree over both leaves and checkpointed the last block's end: the
        // freshest anchor, and the one this send used.
        assert_eq!(store.tree.next_index(), 2);
        assert!(store.tree.path(0).is_some() && store.tree.path(1).is_some(), "a witness per owned note");
        let root = store.tree.root(&tree_hash());
        assert_eq!(root, tx.bundle.as_ref().unwrap().anchor, "the send anchored at the local root");
        assert_eq!(store.tree.checkpoints_newest().next(), Some((2, root)), "the scan's last block end");
    }

    /// A store written before the tree existed (every store a pre-PRIV-1 build saved) has no
    /// `tree` key; loading it must reset the leaf cursor to 0 so the next scan rebuilds the whole
    /// tree — a default-empty tree beside the old cursor would silently miss every leaf below it
    /// and produce wrong witnesses.
    #[test]
    fn a_store_written_before_the_tree_rescans_from_zero() {
        let old = serde_json::json!({
            "scanned_index": 9,
            "scanned_height": 4,
            "scanned_attest_height": 5,
            "notes": [serde_json::to_value(owned(3, 5, false)).unwrap()],
            "sent": [],
        });
        let store: NoteStore = serde_json::from_value(old).unwrap();
        assert_eq!(store.scanned_index, 0, "the leaf cursor resets so the tree is rebuilt");
        assert_eq!(store.scanned_height, 4, "the nullifier cursor survives");
        assert_eq!(store.scanned_attest_height, 5, "the deposit-rebuild cursor survives");
        assert_eq!(store.notes.len(), 1, "the notes survive — they are re-offered, not lost");
        assert_eq!(store.tree.next_index(), 0, "and the tree is rebuilt from the start");
        // A store written *with* a tree keeps its cursor: no rescan tax on every later build.
        let current = NoteStore { scanned_index: 9, scanned_height: 4, notes: vec![owned(3, 5, false)], ..NoteStore::default() };
        let back: NoteStore = serde_json::from_str(&serde_json::to_string(&current).unwrap()).unwrap();
        assert_eq!(back.scanned_index, 9);
    }

    /// The migration end to end: a store saved by a pre-tree build still scans (rebuilding the
    /// tree once, without duplicating a note) and then sends without a witness call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pre_tree_store_scans_and_sends_without_a_witness_call() {
        let me = Wallet::from_spend_key(SpendKey([63; 8]));
        let you = Wallet::from_spend_key(SpendKey([64; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 3_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.unwrap();
        // Strip the `tree` key: exactly the store a build before this change wrote.
        let mut json = serde_json::to_value(&store).unwrap();
        json.as_object_mut().unwrap().remove("tree");
        let mut store: NoteStore = serde_json::from_value(json).unwrap();
        assert_eq!(store.scanned_index, 0, "the migration reset the leaf cursor");
        assert_eq!(store.notes.len(), 2, "the notes themselves survive");

        // The next scan rebuilds the tree once; re-offering the leaves is idempotent.
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!((store.scanned_index, store.tree.next_index()), (2, 2));
        assert_eq!(store.notes.len(), 2, "no note was duplicated");
        assert!(store.tree.path(0).is_some() && store.tree.path(1).is_some());
        // And a send takes its witnesses from the rebuilt tree, never from the node.
        send_asset_with(&rpc, &me, &mut store, &you.address, 0, 8_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!(chain.lock().unwrap().witness_calls, 0);
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
    }

    /// A leaf the wallet has not scanned lands between the scan and the send: the head root no
    /// longer matches the local tree, so the bundle anchors at the freshest checkpoint the node
    /// confirms — a block-end root, good for the chain's whole anchor window — with no rescan and
    /// still no witness call. A full send rescans first, so it anchors at the moved head instead.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_after_the_chain_moved_anchors_at_a_checkpoint() {
        let me = Wallet::from_spend_key(SpendKey([65; 8]));
        let you = Wallet::from_spend_key(SpendKey([66; 8]));
        let stranger = Wallet::from_spend_key(SpendKey([67; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 3_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.unwrap();
        let scanned_root = store.tree.root(&tree_hash());
        // Block 3 brings a leaf the wallet has not seen: the head's root moves off the local one.
        chain.lock().unwrap().fund(&stranger, 5, 0);

        // Preparing against the stale store anchors at the freshest checkpoint the node confirms.
        let spend = Spend { asset: 0, to: Some((&you.address, 8_000_000)), memo: "", fee: gas::BUNDLE_BASE, burn_a: 0, burn_r: 0, prover_fee: None };
        let plan = Plan::select(&store, spend).unwrap();
        let (prepared, time) = prepare_bundle(&rpc, &me, &mut store, &plan, EnvelopeFormat::Legacy, &ZkExecutor::hc_bundle()).await.unwrap();
        assert_eq!(time, 2, "the checkpoint's height, not the moved head's");
        assert_eq!(prepared.bundle.anchor, scanned_root, "frozen at the checkpoint");
        assert_eq!(chain.lock().unwrap().witness_calls, 0);

        // A full send rescans first and anchors at the moved head: the (emulated) guest still
        // accepts every witness, because the appends advanced them.
        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 8_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!(s.time, 3);
        assert_eq!(chain.lock().unwrap().witness_calls, 0);
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert_eq!(tx.bundle.as_ref().unwrap().anchor, store.tree.root(&tree_hash()));
    }

    /// The torn corner: a store whose leaf cursor is past a garbage-envelope deposit's leaf,
    /// whose tree already holds that leaf as a stranger's, and whose block cursor is 0 — what an
    /// interrupted scan can leave behind. The recovery pass finds the deposit from its public
    /// fields, the tree owes it a witness it cannot grow backwards, so the scan rebuilds the
    /// tree once and the note is spendable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_recovered_note_at_a_leaf_the_tree_misfiled_gets_its_witness_back() {
        let me = Wallet::from_spend_key(SpendKey([69; 8]));
        let you = Wallet::from_spend_key(SpendKey([70; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        let (txs, notes) = public_notes_for(&me);
        {
            let mut c = chain.lock().unwrap();
            let (tx, note) = (txs.into_iter().next().unwrap(), notes[0]);
            c.commit(vec![tx], vec![(note.commitment(), garbage())]); // the deposit, block 1
            c.fund(&me, 7_000_000, 0);
            c.fund(&me, 3_000_000, 0);
        }
        let rpc = serve(&chain).await;
        // A scan that cannot know about the deposit (its block cursor starts past block 1) files
        // its leaf as a stranger's garbage envelope. The store names this chain: an unbound one
        // is started over by the chain binding, which would read block 1 after all.
        let genesis = Some(chain.lock().unwrap().genesis);
        let mut store = NoteStore { genesis, scanned_attest_height: 2, ..NoteStore::default() };
        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.notes.len(), 2, "the two RAND notes only");
        assert!(store.tree.path(0).is_none(), "the deposit's leaf went in as not-mine");
        // The torn store: the leaf cursor and the tree are at the tip, the block cursor is at 0.
        store.scanned_attest_height = 0;

        scan(&rpc, &me, &mut store).await.unwrap();
        assert_eq!(store.asset_balances(), vec![(0, 10_000_000), (3, 1_000)], "the deposit recovered");
        assert!(store.tree.path(0).is_some(), "and it has a witness after the rebuild");
        // Spendable, and its witness comes from the rebuilt tree — never from the node.
        send_asset_with(&rpc, &me, &mut store, &you.address, 3, 400, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .expect("the recovered deposit is spendable");
        assert_eq!(chain.lock().unwrap().witness_calls, 0);
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
    }

    /// When the chain publishes a note's nullifier the note stops being spendable-owned, and its
    /// witness leaves the store (`LocalTree::forget`) — the tree itself, root included, does not
    /// move, and every other note's witness stays.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spent_notes_witness_is_forgotten() {
        let me = Wallet::from_spend_key(SpendKey([68; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 3_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        scan(&rpc, &me, &mut store).await.unwrap();
        assert!(store.tree.path(0).is_some() && store.tree.path(1).is_some());
        let root_before = store.tree.root(&tree_hash());

        let nf = store.notes.iter().find(|n| n.index == 0).unwrap().nf;
        {
            let mut c = chain.lock().unwrap();
            c.commit(Vec::new(), Vec::new()); // block 3, no leaves
            c.nullifiers.push((3, nf));
        }
        scan(&rpc, &me, &mut store).await.unwrap();
        assert!(store.notes.iter().find(|n| n.index == 0).unwrap().spent);
        assert_eq!(store.tree.path(0), None, "the spent note's witness is dropped");
        assert!(store.tree.path(1).is_some(), "the unspent one keeps its witness");
        assert_eq!(store.tree.root(&tree_hash()), root_before, "forgetting moves no leaf");
        assert_eq!(store.balance(), 3_000_000);
    }

    /// A token transfer pays its fee in RAND, so a wallet holding only the token is refused before
    /// anything is proved or submitted — and so is one short of the token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_transfer_without_rand_for_the_fee_is_refused_before_proving() {
        let me = Wallet::from_spend_key(SpendKey([46; 8]));
        let you = Wallet::from_spend_key(SpendKey([47; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 500, 4);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 4, 100, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("a transfer pays its fee in RAND"), "{e}");
        chain.lock().unwrap().fund(&me, gas::BUNDLE_BASE, 0);
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 4, 501, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("asset 4") && e.contains("insufficient"), "{e}");
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 4, 0, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.bridge = serde_json::json!({ "enabled": true, "assets": [asset_row(3, 2, token, 8, 700)] });
            c.fund(&me, 1_000, 3);
            c.fund(&me, gas::BRIDGE_BURN_FEE + 5, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let burn = |amount| BurnRequest { asset: 3, amount, relayer_fee: 0, to_chain: 2, token, to: [1; 32] };
        let e = submit_burn_with(&rpc, &me, &mut store, burn(800), gas::BRIDGE_BURN_FEE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("only 700 is locked"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty());

        let s = submit_burn_with(&rpc, &me, &mut store, burn(400), gas::BRIDGE_BURN_FEE, FriProfile::Test, &Proving::Emulated, 7, false).await.unwrap();
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.assets = serde_json::json!([{ "index": 2, "chain": 2, "token": hex::encode([1u8; 32]), "asset_id": hex::encode([2u8; 32]) }]);
            c.fund(&me, 300, 5);
            c.fund(&me, 300, 2);
            c.fund(&me, gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let e = submit_token_burn_with(&rpc, &me, &mut store, 2, 100, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("bridged token") && e.contains("bridge-burn"), "{e}");
        let e = submit_token_burn_with(&rpc, &me, &mut store, 0, 100, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("RAND"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty());

        let s = submit_token_burn_with(&rpc, &me, &mut store, 5, 300, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false).await.unwrap();
        assert_eq!((s.amount, s.change, s.rand_change), (300, 0, 0));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!((b.burn_a, b.burn_r, b.burn_asset), (300, 0, 5));
        assert_eq!(tx.action, Action::TokenBurn { asset: 5, amount: 300 });
        // No change at all in either group: every output is a dummy nobody opens.
        assert!(slots_for(&me, &tx).iter().all(opens_to_nobody));
    }

    /// RPL-3: `perps::submit_perp_deposit`'s bundle burns the collateral where the ledger's
    /// `PerpDeposit` rule reads it — RAND through `burn_r` (the `Bond` shape), a token through
    /// `burn_a`/`burn_asset` (the `TokenBurn` shape) — and carries the deposit action.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_perp_deposit_burns_the_collateral_through_the_slot_the_ledger_reads() {
        let me = Wallet::from_spend_key(SpendKey([53; 8]));
        let trading_key = Keypair::generate().public_key().clone();
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.fund(&me, 300, 5);
            c.fund(&me, 500 + gas::BUNDLE_BASE, 0);
            c.fund(&me, gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let deposit = crate::perps::submit_perp_deposit;
        let (fee, p) = (gas::BUNDLE_BASE, FriProfile::Test);
        deposit(
            &rpc,
            &me,
            &mut store,
            &trading_key,
            500,
            0,
            fee,
            p,
            &Proving::Emulated,
            7,
            false,
        )
        .await
        .unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!(
            (b.burn_r, b.burn_a, b.burn_asset),
            (500, 0, 0),
            "RAND through burn_r"
        );
        assert_eq!(
            tx.action,
            Action::PerpDeposit {
                trading_key: trading_key.clone()
            }
        );

        deposit(
            &rpc,
            &me,
            &mut store,
            &trading_key,
            300,
            5,
            fee,
            p,
            &Proving::Emulated,
            7,
            false,
        )
        .await
        .unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!(
            (b.burn_r, b.burn_a, b.burn_asset),
            (0, 300, 5),
            "a token through burn_a/burn_asset"
        );
        assert_eq!(
            tx.action,
            Action::PerpDeposit {
                trading_key: trading_key.clone()
            }
        );
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
        let e = build_register_token(&rpc, &me, 7, "", "FIX", 6, MintAuthority::None, None, [0; 32]).await.unwrap_err().to_string();
        assert!(e.to_lowercase().contains("name"), "{e}");
        let e = build_register_token(&rpc, &me, 7, "Fixed", "", 6, MintAuthority::None, None, [0; 32]).await.unwrap_err().to_string();
        assert!(e.to_lowercase().contains("symbol"), "{e}");
        let e = build_register_token(&rpc, &me, 7, "Fixed", "FIX", 250, MintAuthority::None, None, [0; 32]).await.unwrap_err().to_string();
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
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
            None,
            [3; 32],
            None,
            FriProfile::Test, &Proving::Emulated,
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
            None,
            [3; 32],
            None,
            FriProfile::Test, &Proving::Emulated,
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

    /// WAL-2: the default fee of `rand token create` is `fee_floor + registration_fee`, and the
    /// registration fee is the node's word. A node reporting an absurd one (here 5 000 000 RAND,
    /// against chain 14's 1) is refused above `MAX_DEFAULT_REGISTRATION_FEE` before anything is
    /// written, proved or sent; an explicit `--fee` is the caller's own decision and goes through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_reported_registration_fee_above_the_ceiling_needs_an_explicit_fee() {
        let me = Wallet::from_spend_key(SpendKey([67; 8]));
        let absurd: u64 = 5_000_000_000_000_000;
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.tokens = serde_json::json!({ "enabled": true, "registration_fee": absurd.to_string(), "next_index": 1, "tokens": [] });
            c.fund(&me, absurd + 10 * gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let initial = Some((1_000, me.address.clone()));
        let e = create_token_with(&rpc, &me, &mut store, "Fixed", "FIX", 6, None, None, initial.clone(), [4; 32], None, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .expect_err("an absurd node-reported registration fee is refused")
            .to_string();
        assert!(e.contains("--fee"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty(), "nothing was sent");
        let fee = 2 * gas::BUNDLE_BASE + absurd;
        create_token_with(&rpc, &me, &mut store, "Fixed", "FIX", 6, None, None, initial, [4; 32], Some(fee), FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .expect("an explicit --fee is the caller's own decision");
        assert_eq!(chain.lock().unwrap().sent.pop().unwrap().bundle.unwrap().fee, fee);
        // The shared helper `token register-bridged` uses too: the ceiling itself is admitted.
        assert_eq!(default_registration_fee(7, MAX_DEFAULT_REGISTRATION_FEE).unwrap(), 7 + MAX_DEFAULT_REGISTRATION_FEE);
        assert!(default_registration_fee(7, MAX_DEFAULT_REGISTRATION_FEE + 1).is_err());
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
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
            None,
            [3; 32],
            None,
            FriProfile::Test, &Proving::Emulated,
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
            &rpc, &me, &mut store, "Fixed", "FIX", 6, Some((&kp, out2.as_path())), None, None, [3; 32], None,
            FriProfile::Test, &Proving::Emulated, 7, true,
        )
        .await
        .unwrap_err();
        assert!(e.downcast_ref::<crate::SubmitRefused>().is_some(), "{e}");
        assert!(!out2.exists() && !pending_authority_key_path(&out2).exists());
    }

    /// Node N-2: a `-32603` reply **to `rand_sendTransaction` itself** is not a verdict either.
    /// `Node::on_verdict`'s RPC arm pools and broadcasts the transaction before it replies, so a
    /// node that stops (or drops the reply channel) inside that window answers `-32603` ("node
    /// loop closed" / "node loop dropped reply") for a registration it may already have admitted
    /// and gossiped. `submit_refused` must not label that `SubmitRefused` — only `-32000`
    /// (rejected) and `-32602` (undecodable) are verdicts on the send.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_token_keeps_the_pending_key_when_the_send_itself_answers_internal_error() {
        let me = Wallet::from_spend_key(SpendKey([68; 8]));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("authority.key.json");
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.tokens = serde_json::json!({ "enabled": true, "registration_fee": 0, "next_index": 1, "tokens": [] });
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
            c.fail = Some("rand_sendTransaction");
            c.fail_code = -32603;
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
            None,
            [3; 32],
            None,
            FriProfile::Test, &Proving::Emulated,
            7,
            true,
        )
        .await
        .unwrap_err();

        // It is an `RpcError` carrying `-32603` — and it is not a `SubmitRefused`.
        let rpc_err = e.downcast_ref::<crate::RpcError>().unwrap_or_else(|| panic!("{e}"));
        assert_eq!(rpc_err.code, -32603);
        assert!(e.downcast_ref::<crate::SubmitRefused>().is_none(), "a -32603 send reply is not a refusal: {e}");
        // Fate unknown: the key is kept at `.pending`, not discarded, not promoted.
        let pending = pending_authority_key_path(&out);
        assert!(pending.exists(), "the authority key of a possibly-admitted registration is kept");
        assert!(!out.exists());
        assert_eq!(load_authority_key(&pending).unwrap().public_key(), kp.public_key());
    }

    /// `rand token create`'s two authority branches build a `RegisterToken` that rides one RAND
    /// fee bundle, `to = None`, nothing burned — exactly a bridged registration's shape — reading
    /// `next_index` and `registration_fee` off `rand_getTokens` first: fixed supply
    /// (`authority = None`) with its required initial mint, and a `Key`-authorised token
    /// registering empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_token_fixed_supply_and_key_authority_ride_a_rand_fee_bundle() {
        let me = Wallet::from_spend_key(SpendKey([61; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.tokens = serde_json::json!({ "enabled": true, "registration_fee": 1_000, "next_index": 1, "tokens": [] });
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
            c.fund(&me, 3 * gas::BUNDLE_BASE, 0);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();

        // ---- fixed supply: authority None, the whole initial mint required ----
        let plan = build_register_token(&rpc, &me, 7, "Fixed", "FIX", 6, MintAuthority::None, Some((1_000, me.address.clone())), [1; 32])
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
        submit_register_token_with(&rpc, &me, &mut store, plan.action, fee, FriProfile::Test, &Proving::Emulated, 7, false).await.unwrap();
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
        let plan = build_register_token(&rpc, &me, 7, "Keyed", "KEY", 6, MintAuthority::Key(authority_kp.public_key().clone()), None, [2; 32])
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
        submit_register_token_with(&rpc, &me, &mut store, plan.action, fee, FriProfile::Test, &Proving::Emulated, 7, false).await.unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert!(matches!(tx.action, Action::RegisterToken { authority: MintAuthority::Key(_), index: 2, initial: None, .. }));

        // A submission of anything but a `RegisterToken` is refused outright.
        let e = submit_register_token_with(&rpc, &me, &mut store, Action::None, fee, FriProfile::Test, &Proving::Emulated, 7, false)
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
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
        let domain = binding_domain(&rpc, &me, &mut store, 7).await.unwrap();
        assert_eq!(domain, chain.lock().unwrap().domain(), "BIND-1: genesis-bound on chain 7, over the store's genesis");
        let e = build_token_mint(&rpc, &me, &domain, 7, 1, &row(1), &me.address, 500, &authority_kp).await.unwrap_err().to_string();
        assert!(e.contains("not Key-authorised"), "{e}");
        let e = build_token_set_authority(&domain, 7, 1, &row(1), &authority_kp, None).unwrap_err().to_string();
        assert!(e.contains("not Key-authorised"), "{e}");

        // A stranger's key is refused too, against the `Key` token.
        let stranger = Keypair::generate();
        let e = build_token_mint(&rpc, &me, &domain, 7, 2, &row(2), &me.address, 500, &stranger).await.unwrap_err().to_string();
        assert!(e.contains("not token 2's mint authority"), "{e}");

        // Zero moves nothing either way, refused before the registry is even read.
        let e = build_token_mint(&rpc, &me, &domain, 7, 2, &row(2), &me.address, 0, &authority_kp).await.unwrap_err().to_string();
        assert!(e.contains("zero"), "{e}");

        // The right key mints: `TokenMint` at `mint_nonce` 0, signed, riding a fee bundle.
        let action = build_token_mint(&rpc, &me, &domain, 7, 2, &row(2), &me.address, 500, &authority_kp).await.unwrap();
        assert!(matches!(&action, Action::TokenMint { asset: 2, amount: 500, nonce: 0, .. }));
        submit_token_mint_with(&rpc, &me, &mut store, action, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false).await.unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert!(matches!(tx.action, Action::TokenMint { asset: 2, amount: 500, nonce: 0, .. }));

        // And hands the token on: `SetAuthority` at the same nonce it reads, signed by the
        // current key over the new one.
        let successor = Keypair::generate();
        let action = build_token_set_authority(&domain, 7, 2, &row(2), &authority_kp, Some(successor.public_key().clone())).unwrap();
        assert!(matches!(&action, Action::SetAuthority { asset: 2, new: Some(pk), nonce: 0, .. } if *pk == *successor.public_key()));
        submit_token_set_authority_with(&rpc, &me, &mut store, action, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false).await.unwrap();
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        assert!(matches!(tx.action, Action::SetAuthority { asset: 2, new: Some(_), .. }));

        // A submission of anything but the right variant is refused outright.
        let e = submit_token_mint_with(&rpc, &me, &mut store, Action::None, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("TokenMint"), "{e}");
        let e = submit_token_set_authority_with(&rpc, &me, &mut store, Action::None, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
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
        let chain = Arc::new(Mutex::new(ChainState::new()));
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
            let s = submit_bridge_action_with(&rpc, &me, &mut store, action.clone(), gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
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
            assert!(matches!(mine[3], Found::Received(n, _) if n.asset == 0 && n.amount > 0), "{what}: RAND change in slot 3: {mine:?}");
            // The PQ quorum is inside the binding: a relayer cannot swap it after the proof.
            let mut swapped = tx.clone();
            match &mut swapped.action {
                Action::BridgeAttest { pq_signatures, .. }
                | Action::RegisterBridgedToken { pq_signatures, .. }
                | Action::ListBacking { pq_signatures, .. } => pq_signatures[1].signature[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(StubExecutor.verify_bundle(&EMULATED_HC, &b.proof, &swapped.binding(&chain.lock().unwrap().domain())).is_err(), "{what}: a swapped quorum unbinds the proof");
        }
        let e = submit_bridge_action_with(&rpc, &me, &mut store, Action::None, gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("nothing else"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty());
    }

    /// RPL-2: an invoke end to end against the fake chain, with a real call proof of the counter
    /// guest (a few seconds at the test profile) and the emulated bundle prover. The order the
    /// chain requires holds: the payout notes are sealed against the bundle's own `time`, the
    /// call is proved over the finished transition's binding and context, and the bundle's
    /// proof covers the whole — so the proof verifies under `verify_invoke` with the segment the
    /// ledger will build, the bundle burns both what the transition deposits, and each
    /// recipient's wallet rebuilds its note from the transaction's public fields alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invoke_seals_its_payouts_against_the_bundles_time_and_binds_the_call() {
        use randprotocol_core::ledger::program_state::{invoke_segment, payout_commitment, Cell, Inflow};
        use randprotocol_core::program::ProgramRecord;
        let me = Wallet::from_spend_key(SpendKey([54; 8]));
        let you = Wallet::from_spend_key(SpendKey([55; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 10_000_000, 0);
        chain.lock().unwrap().fund(&me, 500, 2);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let program = randprotocol_zkvm::guests::rpl2_counter();
        let pid = randprotocol_core::program::program_id(program.base_pc, &program.words);
        let cell = |v: u32| Cell { key: [1, 0, 0, 0, 0, 0, 0, 0], value: [v, 0, 0, 0, 0, 0, 0, 0] };
        let plan = InvokePlan {
            program: pid,
            reads: vec![cell(41)],
            writes: vec![cell(42)],
            inflow: Inflow::Deposit,
            pays: vec![PayoutRequest { asset: 0, amount: 600, to: you.address.clone() }],
            mints: vec![PayoutRequest { asset: 3, amount: 40, to: me.address.clone() }],
            burn_r: 1_000,
            burn_asset: 2,
            burn_a: 300,
            input_envelope: None,
            created_cells: 0,
        };
        let seen = Mutex::new(None);
        let prove = |binding: &[u32; TX_BINDING_WORDS], context: &[u32]| -> Result<Vec<u8>> {
            *seen.lock().unwrap() = Some((*binding, context.to_vec()));
            let (proof, outputs, _) =
                randprotocol_zkvm::executor::prove_invoke(FriProfile::Test, &program, &[], &[], binding, context, [1, 2, 3, 4], None, None)
                    .map_err(|e| anyhow!(e))?;
            assert_eq!(outputs[0], 42, "the counter's new count");
            Ok(proof)
        };
        let (s, sent) = submit_bound_invoke(&rpc, &me, &mut store, &plan, gas::BUNDLE_BASE + gas::CALL_BASE, &prove, None, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!((s.asset, s.burn), (2, Burn::Both { rand: 1_000, index: 2, amount: 300 }));
        assert_eq!((s.amount, s.change, s.rand_change), (300, 200, 10_000_000 - 1_000 - s.fee));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!((b.burn_r, b.burn_asset, b.burn_a), (1_000, 2, 300));
        let Action::Invoke { transition, proof, .. } = &tx.action else { panic!("an invoke") };
        assert_eq!(transition, &sent, "the transition returned is the one sent");
        assert_eq!((transition.reads.clone(), transition.writes.clone(), transition.inflow), (vec![cell(41)], vec![cell(42)], Inflow::Deposit));
        // The prover saw the finished transaction's binding and context, and the proof verifies
        // under the ledger's own segment for it — nothing was changed after it was proved.
        let (binding, context) = seen.lock().unwrap().clone().expect("the call was proved");
        // BIND-1: the domain the wallet chose for chain 7 over the fake chain's genesis — the
        // genesis-bound form, so a wallet that proved the invoke over the chain-id form fails here.
        let domain = chain.lock().unwrap().domain();
        assert!(matches!(domain, BindingDomain::Genesis(_)), "chain 7 is not one of 14–19");
        assert_eq!(binding, tx.call_binding(&domain));
        assert_eq!(context, transition.context(1_000, 2, 300));
        let zk = ZkExecutor::new(FriProfile::Test);
        let record = ProgramRecord {
            id: pid,
            base_pc: program.base_pc,
            words: program.words.clone(),
            code_hash: zk.check_program(program.base_pc, &program.words).unwrap(),
            deployed_at: 0,
            public_digest: None,
            public_len: 0,
        };
        zk.verify_invoke(&record, proof, &invoke_segment(&[], &tx.call_binding(&domain), &context)).expect("bound to this transaction");
        // Each payout note is stamped with the bundle's time, and each recipient rebuilds it
        // from the transaction alone at the commitment the chain will append.
        assert_eq!(b.time, s.time);
        let paid = rebuilt_notes(&you, &tx);
        assert_eq!(paid.len(), 1);
        assert_eq!((paid[0].amount, paid[0].asset, paid[0].time, paid[0].from), (600, 0, b.time, randprotocol_core::ledger::program_state::PROGRAM_FROM));
        assert_eq!(paid[0].commitment(), payout_commitment(&transition.pays[0], b.time, &zk));
        let minted = rebuilt_notes(&me, &tx);
        assert_eq!(minted.len(), 1);
        assert_eq!((minted[0].amount, minted[0].asset), (40, 3));
        assert_eq!(minted[0].commitment(), payout_commitment(&transition.mints[0], b.time, &zk));
        assert!(rebuilt_notes(&Wallet::from_spend_key(SpendKey([56; 8])), &tx).is_empty(), "a stranger rebuilds nothing");
        // And the envelope beside each note opens for its recipient, as an honest mint's does.
        assert!(matches!(classify(&you, paid[0].commitment(), &transition.pays[0].envelope), Found::Received(n, None) if n == paid[0]));
        assert!(matches!(classify(&me, minted[0].commitment(), &transition.mints[0].envelope), Found::Received(n, None) if n == minted[0]));
    }

    /// `Burn::invoke` collapses to the one-sided variants, and the summary line names the RAND
    /// that left the pool beside a token deposit.
    #[test]
    fn an_invokes_burn_is_reported_in_both_units() {
        assert_eq!(Burn::invoke(0, 0, 0), Burn::None);
        assert_eq!(Burn::invoke(5, 0, 0), Burn::Rand(5));
        assert_eq!(Burn::invoke(0, 2, 7), Burn::Asset { index: 2, amount: 7 });
        assert_eq!(Burn::invoke(5, 2, 7), Burn::Both { rand: 5, index: 2, amount: 7 });
        assert_eq!(Burn::invoke(5, 2, 7).units(), 7);
        let s = Submission {
            hash: Hash::ZERO,
            amount: 7,
            change: 3,
            fee: gas::BUNDLE_BASE,
            burn: Burn::Both { rand: 5_000_000_000, index: 2, amount: 7 },
            time: 4,
            asset: 2,
            rand_change: 1_000_000_000,
            tier: 14,
            proof_bytes: 0,
            proving: Duration::ZERO,
            auth_proving: None,
            prover_fee: 0,
        };
        let line = s.summary("invoke");
        assert!(line.contains("7 of asset 2 out, 5 RAND burned, 3 of asset 2 change"), "{line}");
        assert!(line.contains("1 RAND change"), "{line}");
    }

    /// A bond burns RAND through `burn_r`, never `burn_a`, and names no asset.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bond_burns_rand_through_burn_r() {
        let me = Wallet::from_spend_key(SpendKey([51; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 10_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let action = Action::Bond { validator: randprotocol_core::Keypair::generate().address(), amount: 4_000_000, registration: None };
        let s = submit_with(&rpc, &me, &mut store, None, action, gas::BUNDLE_BASE, Burn::Rand(4_000_000), FriProfile::Test, &Proving::Emulated, 7, false)
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
        let spend = |asset, amount, fee| Spend { asset, to: Some((&you.address, amount)), memo: "", fee, burn_a: 0, burn_r: 0, prover_fee: None };
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
        let bad = Spend { asset: 0, to: None, memo: "", fee: 1, burn_a: 1, burn_r: 0, prover_fee: None };
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
        let (first, fifth) = (Hash([0xaa; 32]), Hash([0xbb; 32]));
        let (first_text, fifth_text) = (randprotocol_core::token_id::encode(&first), randprotocol_core::token_id::encode(&fifth));
        let absent_text = randprotocol_core::token_id::encode(&Hash([0xcc; 32]));
        let rows = serde_json::json!([
            { "index": 1, "id": first.to_hex(), "id_text": first_text },
            { "index": 5, "id": fifth.to_hex(), "id_text": fifth_text.clone() },
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
        assert_eq!(resolve_asset(&rpc, "rand").await.unwrap(), 0);
        assert!(asked.lock().unwrap().is_empty(), "nor does rand");
        assert!(resolve_asset(&rpc, "rpl1typo").await.unwrap_err().to_string().contains("not a token id"));
        assert!(asked.lock().unwrap().is_empty(), "a malformed id is refused before the node is asked");
        assert_eq!(resolve_asset(&rpc, &fifth_text).await.unwrap(), 5);
        assert_eq!(resolve_asset(&rpc, &format!("0x{}", "AA".repeat(32))).await.unwrap(), 1);
        let e = resolve_asset(&rpc, &absent_text).await.unwrap_err().to_string();
        assert!(e.contains(&format!("no token {absent_text}")), "{e}");
        // Every request was the same whole-registry page: nothing in any of them names a token.
        for (method, params) in asked.lock().unwrap().iter() {
            assert_eq!((method.as_str(), params), ("rand_getTokens", &serde_json::json!([0, TOKEN_PAGE])));
        }
        let older = RpcClient::new(crate::test_rpc::scripted_rpc(vec![]).await);
        let e = resolve_asset(&older, &fifth_text).await.unwrap_err().to_string();
        assert!(e.contains("registry index instead"), "{e}");
    }

    /// `find_token_row` — `rand token info`'s reader, and `token mint`/`set-authority`'s way to
    /// the row's `mint_nonce` and authority — matches by index, hex id or `rpl1…`, exactly as
    /// `resolve_asset` does, and only ever calls `rand_getTokens`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn find_token_row_matches_index_hex_or_rpl1_over_the_whole_listing() {
        let asked = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = asked.clone();
        let fifth_text = randprotocol_core::token_id::encode(&Hash([0xbb; 32]));
        let rows = serde_json::json!({
            "enabled": true,
            "tokens": [
                { "index": 1, "id": "aa".repeat(32), "id_text": randprotocol_core::token_id::encode(&Hash([0xaa; 32])), "authority": { "kind": "key", "key": "k1" }, "mint_nonce": 3 },
                { "index": 5, "id": "bb".repeat(32), "id_text": fifth_text.clone(), "authority": { "kind": "none" }, "mint_nonce": 0 },
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
        assert_eq!(find_token_row(&rpc, &fifth_text).await.unwrap()["index"], 5);
        assert_eq!(find_token_row(&rpc, &format!("0x{}", "AA".repeat(32))).await.unwrap()["index"], 1);
        assert!(find_token_row(&rpc, "9").await.unwrap_err().to_string().contains("no token 9"));
        assert!(asked.lock().unwrap().iter().all(|m| m == "rand_getTokens"), "never a per-token lookup");
    }

    /// WAL-1: a token id the node's listing answers with index 0 — RAND's, which the registry never
    /// hands out (`FIRST_TOKEN_INDEX`) — is refused, by `resolve_asset` and `find_token_row` alike.
    /// Before, `send --asset rpl1… --amount 5` took the row's 0 at its word and `main.rs` parsed the
    /// amount with RAND's nine decimals: a lying node turned "5 units of a token" into 5 whole RAND.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_id_the_node_maps_to_rand_is_refused() {
        let id = Hash::digest_domain(b"test", b"victim token");
        let text = randprotocol_core::token_id::encode(&id);
        let rows = serde_json::json!([{ "index": 0, "id": id.to_hex(), "id_text": text.clone() }]);
        let rpc = RpcClient::new(
            rpc_fn(move |m, _p| match m {
                "rand_getTokens" => Reply::Ok(rows.clone()),
                _ => Reply::Err(-32601, "unknown method"),
            })
            .await,
        );
        let e = resolve_asset(&rpc, &text).await.expect_err("index 0 is RAND's, never a token's").to_string();
        assert!(e.contains("index 0"), "{e}");
        let e = resolve_asset(&rpc, &id.to_hex()).await.expect_err("the hex form too").to_string();
        assert!(e.contains("index 0"), "{e}");
        let e = find_token_row(&rpc, &text).await.expect_err("and the row reader").to_string();
        assert!(e.contains("index 0"), "{e}");
    }

    /// WAL-1: a row whose own `id` and `id_text` name two different tokens is refused, whichever of
    /// the two the user typed — the node's listing is not trusted to be self-consistent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_row_whose_id_and_id_text_disagree_is_refused() {
        let wanted = Hash::digest_domain(b"test", b"wanted");
        let other = Hash::digest_domain(b"test", b"other");
        let text = randprotocol_core::token_id::encode(&wanted);
        let rows = serde_json::json!([{ "index": 3, "id": other.to_hex(), "id_text": text.clone() }]);
        let rpc = RpcClient::new(
            rpc_fn(move |m, _p| match m {
                "rand_getTokens" => Reply::Ok(rows.clone()),
                _ => Reply::Err(-32601, "unknown method"),
            })
            .await,
        );
        for asked in [text.clone(), other.to_hex()] {
            let e = resolve_asset(&rpc, &asked).await.expect_err("an inconsistent row is refused").to_string();
            assert!(e.contains("disagree"), "{e}");
            let e = find_token_row(&rpc, &asked).await.expect_err("by the row reader too").to_string();
            assert!(e.contains("disagree"), "{e}");
        }
    }

    /// [`parse_decimal`]'s pure core: a decimal string at `decimals` fractional digits, scaled to
    /// the smallest unit — RAND's nine, or a whole-number asset's zero.
    #[test]
    fn parse_decimal_scales_to_the_smallest_unit_and_refuses_too_many_digits() {
        assert_eq!(parse_decimal("1.5", 9).unwrap(), 1_500_000_000);
        let e = parse_decimal("1.1234567891", 9).unwrap_err().to_string();
        assert!(e.contains("at most 9 decimals"), "{e}");
        assert_eq!(parse_decimal("2", 0).unwrap(), 2);
        assert!(parse_decimal("0.5", 0).is_err());
        // The forms the old RAND `parse_amount` took (final review B4): a bare fraction and a
        // trailing point; nothing at all, or a point alone, is still not an amount.
        assert_eq!(parse_decimal(".5", 9).unwrap(), 500_000_000);
        assert_eq!(parse_decimal("2.", 9).unwrap(), 2_000_000_000);
        assert_eq!(parse_decimal("2.", 0).unwrap(), 2);
        for bad in ["", ".", "1.2.3", "-1", "+1", "1e3", " ", "0x10"] {
            assert!(parse_decimal(bad, 9).is_err(), "{bad:?}");
        }
        assert!(parse_decimal(".1234567891", 9).unwrap_err().to_string().contains("at most 9 decimals"));
    }

    /// [`format_decimal`] / [`display_amount`]: every digit at the asset's decimals, and the base
    /// units beside them (final review B3: a node lying about `decimals` shows before sending).
    #[test]
    fn the_confirmation_amount_shows_display_and_base_units() {
        assert_eq!(format_decimal(1_000_000_000, 8), "10.00000000");
        assert_eq!(format_decimal(1_500_000_000, 9), "1.500000000");
        assert_eq!(format_decimal(5, 9), "0.000000005");
        assert_eq!(format_decimal(42, 0), "42");
        assert_eq!(format_decimal(u64::MAX, 19), "1.8446744073709551615");
        assert_eq!(display_amount(1_000_000_000, 8, "zUSD"), "10.00000000 zUSD (1000000000 units)");
        assert_eq!(display_amount(1_500_000_000, 9, "RAND"), "1.500000000 RAND (1500000000 units)");
        for (units, decimals) in [(0u64, 9u8), (1, 9), (123_456_789_012, 6), (7, 0)] {
            assert_eq!(parse_decimal(&format_decimal(units, decimals), decimals).unwrap(), units, "round trip");
        }
    }

    /// [`parse_asset_amount`]: RAND (asset 0) never touches the node; any other asset reads its
    /// `decimals` off the same whole `rand_getTokens` listing [`resolve_asset`] pages, never a
    /// per-token lookup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parse_asset_amount_reads_decimals_off_the_whole_token_listing() {
        let asked = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = asked.clone();
        // A self-consistent row: `id` and `id_text` name the same token, as WAL-1's row check
        // requires of every row `find_token_row` returns.
        let id = Hash::digest_domain(b"test", b"fifth token");
        let rows = serde_json::json!({
            "enabled": true,
            "tokens": [
                { "index": 5, "id": id.to_hex(), "id_text": randprotocol_core::token_id::encode(&id), "authority": { "kind": "none" }, "mint_nonce": 0, "decimals": 6 },
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
        assert_eq!(parse_asset_amount(&rpc, 5, "1.5").await.unwrap(), 1_500_000);
        assert!(asked.lock().unwrap().iter().all(|m| m == "rand_getTokens"), "never a per-token lookup");
        let e = parse_asset_amount(&rpc, 5, "1.1234567").await.unwrap_err().to_string();
        assert!(e.contains("at most 6 decimals"), "{e}");

        let no_rpc = RpcClient::new(crate::test_rpc::scripted_rpc(vec![]).await);
        assert_eq!(parse_asset_amount(&no_rpc, 0, "3.5").await.unwrap(), 3_500_000_000, "RAND never asks the node");
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
            notes: vec![OwnedNote { index: 0, cm: note.commitment(), nf: me.vk.nullifier(&note.commitment()), note, spent: false, pending: None, height: 1, memo: None }],
            ..NoteStore::default()
        };
        let plan = Plan::select(&store, Spend { asset: 0, to: None, memo: "", fee: 50, burn_a: 0, burn_r: 0, prover_fee: None }).unwrap();
        let build = || build_bundle(&me, &plan, tree.root(), &[tree.path(0)], 2, EnvelopeFormat::Legacy, &ZkExecutor::hc_bundle()).unwrap();
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

    /// A one-note store and the self-transfer plan over it, for the split-authorisation tests
    /// that build a bundle without a chain.
    fn one_note_plan(me: &Wallet) -> (randprotocol_zkvm::ledger::CommitmentTree, Plan) {
        let mut tree = randprotocol_zkvm::ledger::CommitmentTree::new();
        let note = Note::new(me.vk.pk(), [1; 8], 50, 0, 1);
        tree.append(note.commitment());
        let store = NoteStore {
            notes: vec![OwnedNote { index: 0, cm: note.commitment(), nf: me.vk.nullifier(&note.commitment()), note, spent: false, pending: None, height: 1, memo: None }],
            ..NoteStore::default()
        };
        let plan = Plan::select(&store, Spend { asset: 0, to: None, memo: "", fee: 50, burn_a: 0, burn_r: 0, prover_fee: None }).unwrap();
        (tree, plan)
    }

    /// Split authorisation (spec 2026-09-28 §4.1): a repeated salt repeats `c = H(AUTH, nk, salt)`
    /// and links two transactions to one wallet, and the guest cannot tell — so the wallet draws a
    /// fresh salt for every bundle it builds. Two bundles from the same plan carry distinct salts
    /// and distinct `auth_commit`s, each the commitment of its own salt, and the salt the v3
    /// witness hands the prover is that salt.
    #[test]
    fn two_sends_never_share_a_salt() {
        let me = Wallet::from_spend_key(SpendKey([56; 8]));
        let (tree, plan) = one_note_plan(&me);
        let v3 = ZkExecutor::hc_hidden_bundle_v3();
        let build = || build_bundle(&me, &plan, tree.root(), &[tree.path(0)], 2, EnvelopeFormat::Legacy, &v3).unwrap();
        let (one, two) = (build(), build());
        assert!(one.v3 && two.v3);
        assert_ne!(one.salt, [0; 8], "a v3 bundle draws a salt");
        assert_ne!(one.salt, two.salt, "two bundles, two salts");
        assert_ne!(one.auth_commit, two.auth_commit, "two salts, two commitments");
        for p in [&one, &two] {
            assert_eq!(p.auth_commit, randprotocol_zkvm::auth::auth_commit(&me.vk.nk, &p.salt));
            assert_eq!(p.bundle.auth_commit, p.auth_commit, "the bundle carries the commitment");
            use randprotocol_zkvm::hidden::hidden_input_v3::{COUNT, NK, SALT};
            assert_eq!(p.words.len(), COUNT);
            assert_eq!(p.words[SALT..SALT + 8], p.salt, "the witness carries this bundle's salt");
            assert_eq!(p.words[NK..NK + 8], me.vk.nk, "the witness carries nk");
            assert!(p.words.windows(8).all(|w| w != me.sk.0), "and never the spend key");
        }
        // The v3 witness is one the v3 guest accepts, publishing the v3 digest the wallet built.
        let program = ZkExecutor::bundle_program_for(&v3).unwrap();
        let run = randprotocol_zkvm::emulator::execute(program, &one.words, &[0; TX_BINDING_WORDS], 1 << 20).unwrap();
        assert_eq!(run.outputs, one.expected);
    }

    /// A v3 chain (`rand_status` names `hc_hidden_bundle_v3` and this build's `hc_auth`): the
    /// bundle carries its `auth_commit` before the binding is taken — so the binding, which both
    /// proofs are made over, covers it — and the submitted transaction carries both proofs: the
    /// bundle's publishing the v3 digest, the auth proof publishing `auth_commit`, both bound to
    /// the transaction. A v3 chain whose `hc_auth` is not this build's (or is missing) is refused
    /// before anything is proved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_v3_bundle_carries_auth_commit_before_binding() {
        let me = Wallet::from_spend_key(SpendKey([57; 8]));
        let (tree, plan) = one_note_plan(&me);
        let v3 = ZkExecutor::hc_hidden_bundle_v3();
        let p = build_bundle(&me, &plan, tree.root(), &[tree.path(0)], 2, EnvelopeFormat::Legacy, &v3).unwrap();
        let tx = Transaction::shielded(7, p.bundle.clone(), Action::None);
        let mut moved = tx.clone();
        moved.bundle.as_mut().unwrap().auth_commit[0] ^= 1;
        assert_ne!(tx.binding(&randprotocol_core::BindingDomain::ChainId), moved.binding(&randprotocol_core::BindingDomain::ChainId), "the binding covers auth_commit");

        // The whole path against a v3 chain.
        let you = Wallet::from_spend_key(SpendKey([58; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        chain.lock().unwrap().hc_bundle = v3;
        chain.lock().unwrap().hc_auth = Some(ZkExecutor::hc_auth());
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert!(s.auth_proving.is_some(), "a v3 send reports the auth proof's time");
        assert!(s.summary("transfer").contains("auth"), "{}", s.summary("transfer"));
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        let b = tx.bundle.as_ref().unwrap();
        assert_ne!(b.auth_commit, [0; 8]);
        assert!(!b.auth_proof.is_empty(), "the auth proof rides in the bundle");
        let recomputed = ZkExecutor::new(FriProfile::Test).bundle_digest_v3(&b.digest_input());
        assert_eq!(StubExecutor.bundle_proof_digest(&[0; 8], &b.proof).unwrap(), recomputed, "the v3 digest, auth_commit inside");
        let domain = chain.lock().unwrap().domain();
        assert_eq!(StubExecutor.verify_bundle(&EMULATED_HC, &b.proof, &tx.binding(&domain)), Ok(()));
        assert_eq!(StubExecutor.verify_auth(&EMULATED_AUTH_HC, &b.auth_proof, &tx.binding(&domain)), Ok(b.auth_commit), "auth bound to this transaction");

        // Another auth guest, or none, on a v3 chain: refused before any proof.
        for hc_auth in [Some([0xbad; 8]), None] {
            chain.lock().unwrap().hc_auth = hc_auth;
            let e = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
                .await
                .unwrap_err()
                .to_string();
            assert!(e.contains("this chain's auth guest is") && e.contains("this wallet carries"), "{e}");
        }
        assert!(chain.lock().unwrap().sent.is_empty(), "nothing sent under a foreign auth guest");
    }

    /// Chains 14–16 (no `hc_auth`, a v1 or v2 bundle guest) are unchanged: no salt, a zero
    /// `auth_commit`, an empty `auth_proof`, the 1 204-word witness with the spend key in it and
    /// the v1 digest — what every such chain's ledger requires (`TxError::AuthUnexpected`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pre_v3_chain_builds_the_old_shape() {
        let me = Wallet::from_spend_key(SpendKey([59; 8]));
        let (tree, plan) = one_note_plan(&me);
        for hc in [ZkExecutor::hc_hidden_bundle(), ZkExecutor::hc_hidden_bundle_v2()] {
            let p = build_bundle(&me, &plan, tree.root(), &[tree.path(0)], 2, EnvelopeFormat::Legacy, &hc).unwrap();
            assert!(!p.v3);
            assert_eq!((p.salt, p.auth_commit, p.bundle.auth_commit), ([0; 8], [0; 8], [0; 8]));
            assert!(p.bundle.auth_proof.is_empty());
            assert_eq!(p.words.len(), randprotocol_zkvm::hidden::hidden_input::COUNT);
            assert_eq!(p.expected, hidden::hidden_bundle_digest(&HiddenDigestInput {
                anchor: p.bundle.anchor,
                nullifiers: p.bundle.nullifiers,
                commitments: p.bundle.commitments,
                fee: p.bundle.fee,
                burn_a: p.bundle.burn_a,
                burn_r: p.bundle.burn_r,
                burn_asset: p.bundle.burn_asset,
                time: p.bundle.time,
            }));
        }
        let you = Wallet::from_spend_key(SpendKey([60; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
            .await
            .unwrap();
        assert_eq!(s.auth_proving, None);
        assert!(!s.summary("transfer").contains("auth"), "the summary line is the old one");
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        assert_admissible_shape(&tx);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!(b.auth_commit, [0; 8]);
        assert!(b.auth_proof.is_empty());
    }

    // ---- The prover fee (spec §5): one RAND output to the paired prover, in a RAND slot.

    /// The slot table, per transaction kind: a token transfer and a burn pay the prover in slot 2
    /// with the RAND change in slot 3; a RAND transfer pays it in slot 0 from a RAND note of its
    /// own (change in slot 1), the payment and its change in slots 2–3; a RAND bundle that pays
    /// nobody (a bond, say) pays it in slot 2. No output other than the prover's carries its pk.
    #[test]
    fn the_prover_fee_takes_a_rand_slot_in_each_transaction_kind() {
        let you = Wallet::from_spend_key(SpendKey([61; 8]));
        let prover = Wallet::from_spend_key(SpendKey([62; 8]));
        let pf = Some((&prover.address, 3));
        let store = NoteStore {
            notes: vec![owned_asset(0, 100, false, 7), owned_asset(1, 20, false, 0), owned_asset(2, 5, false, 0)],
            ..NoteStore::default()
        };
        let to_prover = (Payee::Prover(prover.address.clone()), 3);
        // A token transfer: RAND covers the chain fee and the prover's.
        let plan = Plan::select(&store, Spend { asset: 7, to: Some((&you.address, 60)), memo: "hi", fee: 4, burn_a: 0, burn_r: 0, prover_fee: pf }).unwrap();
        assert_eq!(plan.r_notes.iter().map(|n| n.index).collect::<Vec<_>>(), vec![1]);
        assert_eq!(plan.outputs(), [(Payee::To(you.address.clone()), 60), (Payee::Me, 40), to_prover.clone(), (Payee::Me, 20 - 4 - 3)]);
        // The prover's fee is part of what the RAND group must cover: 5 alone pays the chain fee
        // of 4, not the prover's 3 as well.
        let small = NoteStore {
            notes: vec![owned_asset(0, 100, false, 7), owned_asset(1, 5, false, 0), owned_asset(2, 3, false, 0)],
            ..NoteStore::default()
        };
        let plan = Plan::select(&small, Spend { asset: 7, to: Some((&you.address, 60)), memo: "", fee: 4, burn_a: 0, burn_r: 0, prover_fee: pf }).unwrap();
        assert_eq!(plan.r_notes.iter().map(|n| n.index).collect::<Vec<_>>(), vec![1, 2], "both RAND notes: 4 + 3 > 5");
        assert_eq!(plan.outputs()[2..], [to_prover.clone(), (Payee::Me, 1)]);
        // A burn: the same RAND slots.
        let plan = Plan::select(&store, Spend { asset: 7, to: None, memo: "", fee: 4, burn_a: 30, burn_r: 0, prover_fee: pf }).unwrap();
        assert_eq!(plan.outputs(), [(Payee::Nobody, 0), (Payee::Me, 70), to_prover.clone(), (Payee::Me, 13)]);
        // A RAND transfer: the payment group (slots 2–3) takes the 20, the prover's (0–1) the 5.
        let plan = Plan::select(&store, Spend { asset: 0, to: Some((&you.address, 10)), memo: "", fee: 4, burn_a: 0, burn_r: 0, prover_fee: pf }).unwrap();
        assert_eq!(plan.a_notes.iter().map(|n| n.index).collect::<Vec<_>>(), vec![2], "the fee note, slots 0–1");
        assert_eq!(plan.r_notes.iter().map(|n| n.index).collect::<Vec<_>>(), vec![1], "the payment note, slots 2–3");
        assert_eq!(plan.outputs(), [to_prover.clone(), (Payee::Me, 2), (Payee::To(you.address.clone()), 10), (Payee::Me, 6)]);
        let s = plan.report(Hash::ZERO, Burn::None, 1, &Proved { proof: vec![], tier: 14, proving: Duration::ZERO, auth_proof: vec![], auth_proving: None });
        assert_eq!((s.change, s.prover_fee), (8, 3), "every RAND that came back, slot 1's included");
        assert!(s.summary("transfer").contains("prover fee 0.000000003 RAND"), "{}", s.summary("transfer"));
        // When the largest note would leave nothing for the prover, a small note is set aside first.
        let tight = NoteStore { notes: vec![owned_asset(1, 14, false, 0), owned_asset(2, 3, false, 0)], ..NoteStore::default() };
        let plan = Plan::select(&tight, Spend { asset: 0, to: Some((&you.address, 10)), memo: "", fee: 4, burn_a: 0, burn_r: 0, prover_fee: pf }).unwrap();
        assert_eq!((plan.a_notes[0].index, plan.r_notes[0].index), (2, 1));
        assert_eq!(plan.outputs(), [to_prover.clone(), (Payee::Nobody, 0), (Payee::To(you.address.clone()), 10), (Payee::Nobody, 0)]);
        // A RAND bundle that pays nobody: slot 2, beside the change; one note is enough.
        let one = NoteStore { notes: vec![owned_asset(1, 20, false, 0)], ..NoteStore::default() };
        let plan = Plan::select(&one, Spend { asset: 0, to: None, memo: "", fee: 4, burn_a: 0, burn_r: 5, prover_fee: pf }).unwrap();
        assert_eq!(plan.outputs(), [(Payee::Nobody, 0), (Payee::Nobody, 0), to_prover, (Payee::Me, 8)]);
        // Not enough RAND for both fees: refused with the balance.
        let e = Plan::select(&tight, Spend { asset: 0, to: Some((&you.address, 15)), memo: "", fee: 4, burn_a: 0, burn_r: 0, prover_fee: pf }).unwrap_err();
        assert!(e.to_string().contains("insufficient"), "{e}");
    }

    /// A RAND transfer through a fee-charging prover from one RAND note: told to split it first.
    #[test]
    fn a_rand_transfer_through_a_charging_prover_from_one_note_is_told_to_split() {
        let you = Wallet::from_spend_key(SpendKey([63; 8]));
        let prover = Wallet::from_spend_key(SpendKey([64; 8]));
        let one = NoteStore { notes: vec![owned_asset(1, 1_000, false, 0)], ..NoteStore::default() };
        let e = Plan::select(&one, Spend { asset: 0, to: Some((&you.address, 10)), memo: "", fee: 4, burn_a: 0, burn_r: 0, prover_fee: Some((&prover.address, 3)) })
            .unwrap_err()
            .to_string();
        assert_eq!(e, SPLIT_FIRST);
        assert!(e.contains("split it first") && e.contains("without --prover"), "{e}");
        // Without a fee the same note pays as it always did.
        Plan::select(&one, Spend { asset: 0, to: Some((&you.address, 10)), memo: "", fee: 4, burn_a: 0, burn_r: 0, prover_fee: None }).unwrap();
    }

    /// The whole path, on a v3 chain, for each kind: the witness the wallet builds passes the
    /// prover's own admission check (`check_fee`, run by [`Proving::EmulatedFee`]) and the guest;
    /// the prover opens exactly one output — its fee, in RAND — and nothing else. A pre-v3 chain
    /// refuses a charging prover before anything is proved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_prover_fee_bundle_passes_the_provers_check_and_the_guest() {
        let me = Wallet::from_spend_key(SpendKey([65; 8]));
        let you = Wallet::from_spend_key(SpendKey([66; 8]));
        let prover = Wallet::from_spend_key(SpendKey([67; 8]));
        let pf = 2_000_000;
        let charging = Proving::EmulatedFee(prover.address.clone(), pf, crate::prover::DEFAULT_MAX_PROVER_FEE);
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.hc_bundle = ZkExecutor::hc_hidden_bundle_v3();
            c.hc_auth = Some(ZkExecutor::hc_auth());
            for _ in 0..4 {
                c.fund(&me, 7_000_000, 0);
            }
            c.fund(&me, 500, 3);
            c.fund(&me, 300, 5);
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let paid_once = |tx: &Transaction, slot: usize| {
            let theirs = slots_for(&prover, tx);
            let Found::Received(n, memo) = &theirs[slot] else { panic!("slot {slot} pays the prover: {theirs:?}") };
            assert_eq!((n.amount, n.asset, memo.as_deref()), (pf, 0, None), "RAND, the quote, no memo");
            assert_eq!(theirs.iter().filter(|f| !opens_to_nobody(f)).count(), 1, "only its fee: {theirs:?}");
        };
        // A RAND transfer: slot 0.
        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &charging, 7, false)
            .await
            .unwrap();
        assert_eq!(s.prover_fee, pf);
        let tx = chain.lock().unwrap().sent.pop().unwrap();
        paid_once(&tx, 0);
        let Found::Received(paid, memo) = &slots_for(&you, &tx)[2] else { panic!() };
        assert_eq!((paid.amount, memo.as_deref()), (1_000_000, None), "the payment is slot 2");
        // A token transfer: slot 2.
        send_asset_with(&rpc, &me, &mut store, &you.address, 3, 400, "", gas::BUNDLE_BASE, FriProfile::Test, &charging, 7, false).await.unwrap();
        paid_once(&chain.lock().unwrap().sent.pop().unwrap(), 2);
        // A token burn: slot 2.
        submit_token_burn_with(&rpc, &me, &mut store, 5, 300, gas::BUNDLE_BASE, FriProfile::Test, &charging, 7, false).await.unwrap();
        paid_once(&chain.lock().unwrap().sent.pop().unwrap(), 2);

        // A v1 chain: its witness carries the spend key, which no charging prover takes.
        {
            let mut c = chain.lock().unwrap();
            c.hc_bundle = ZkExecutor::hc_bundle();
            c.hc_auth = None;
        }
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000, "", gas::BUNDLE_BASE, FriProfile::Test, &charging, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("split-authorisation") && e.contains("drop --prover"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty());
    }

    /// Review I-1: a quote above `--max-prover-fee` is refused before any bundle is built — on
    /// `send` and on a command that asks nothing (a deploy here; bond, burn and the bridge
    /// actions share the same `submit_spend`). A quote at the cap passes; a cap of 0 refuses any.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_quote_above_the_cap_is_refused_before_any_bundle_on_every_command() {
        let me = Wallet::from_spend_key(SpendKey([71; 8]));
        let you = Wallet::from_spend_key(SpendKey([72; 8]));
        let prover = Wallet::from_spend_key(SpendKey([73; 8]));
        let unit = randprotocol_core::UNITS_PER_RAND;
        let chain = Arc::new(Mutex::new(ChainState::new()));
        {
            let mut c = chain.lock().unwrap();
            c.hc_bundle = ZkExecutor::hc_hidden_bundle_v3();
            c.hc_auth = Some(ZkExecutor::hc_auth());
            for _ in 0..3 {
                c.fund(&me, 20 * unit, 0);
            }
        }
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        let greedy = Proving::EmulatedFee(prover.address.clone(), 14 * unit, unit);
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 0, unit, "", gas::BUNDLE_BASE, FriProfile::Test, &greedy, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("the prover quotes 14 RAND; the cap is 1 RAND (--max-prover-fee)"), "{e}");
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x13; 4], public: vec![] };
        let e = submit_with(&rpc, &me, &mut store, None, deploy.clone(), gas::fee_floor(&deploy), Burn::None, FriProfile::Test, &greedy, 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("the cap is 1 RAND (--max-prover-fee)"), "{e}");
        assert!(chain.lock().unwrap().sent.is_empty(), "nothing proved, nothing sent");
        assert!(store.notes.iter().all(|n| n.pending.is_none() && !n.spent), "no note held back");
        // A cap of 0 refuses even one base unit.
        let e = send_asset_with(&rpc, &me, &mut store, &you.address, 0, unit, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::EmulatedFee(prover.address.clone(), 1, 0), 7, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("the cap is 0 RAND"), "{e}");
        // Exactly the cap: paid.
        let s = send_asset_with(&rpc, &me, &mut store, &you.address, 0, unit, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::EmulatedFee(prover.address.clone(), unit, unit), 7, false)
            .await
            .unwrap();
        assert_eq!(s.prover_fee, unit);
        assert_eq!(chain.lock().unwrap().sent.len(), 1);
    }

    /// Review M-4: one RAND note too small for both fees is "insufficient", with the amounts — not
    /// told to split a note that could not pay anyway.
    #[test]
    fn one_note_short_of_both_fees_is_insufficient_not_split() {
        let you = Wallet::from_spend_key(SpendKey([74; 8]));
        let prover = Wallet::from_spend_key(SpendKey([75; 8]));
        let one = NoteStore { notes: vec![owned_asset(1, 12, false, 0)], ..NoteStore::default() };
        let e = Plan::select(&one, Spend { asset: 0, to: Some((&you.address, 10)), memo: "", fee: 2, burn_a: 0, burn_r: 0, prover_fee: Some((&prover.address, 3)) })
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("insufficient balance") && e.contains("0.000000012 RAND") && e.contains("0.000000003 RAND"), "{e}");
        assert_ne!(e, SPLIT_FIRST);
    }

    /// Carried from the Task 6 review: a v1/v2 bundle guest beside a named `hc_auth` is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_v1_or_v2_guest_beside_an_hc_auth_is_refused() {
        let me = Wallet::from_spend_key(SpendKey([68; 8]));
        let you = Wallet::from_spend_key(SpendKey([69; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().fund(&me, 7_000_000, 0);
        let rpc = serve(&chain).await;
        let mut store = NoteStore::default();
        for hc in [ZkExecutor::hc_hidden_bundle(), ZkExecutor::hc_hidden_bundle_v2()] {
            {
                let mut c = chain.lock().unwrap();
                c.hc_bundle = hc;
                c.hc_auth = Some(ZkExecutor::hc_auth());
            }
            let e = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
                .await
                .unwrap_err()
                .to_string();
            assert!(e.contains("names an auth guest but a v1/v2 bundle guest") && e.contains("misconfigured or lying"), "{e}");
        }
        assert!(chain.lock().unwrap().sent.is_empty());
        // The same guest with no hc_auth: the chain it always was.
        chain.lock().unwrap().hc_auth = None;
        send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false).await.unwrap();
    }

    /// A prover answering `prover_info` only, quoting `fee`.
    async fn info_only_prover(fee: serde_json::Value, own: bool) -> Proving {
        let key = randprotocol_prover::key::ProverKey::generate();
        let info = serde_json::json!({
            "kem_fingerprint": key.fingerprint().to_string(),
            "hc_bundles": [], "profiles": [], "witness_kinds": ["viewing_key"], "fee": fee,
        });
        let url = rpc_fn(move |method, _| match method {
            "prover_info" => Reply::Ok(info.clone()),
            _ => Reply::Err(-32601, "method not found"),
        })
        .await;
        let link = randprotocol_prover::pairing::PairingLink { kem_ek: key.kem_ek().to_vec(), url, token: [9; 32], own };
        Proving::Remote(Arc::new(RemoteProver::new(crate::prover::PairedProver::from_link(&link, Some("box".into())))))
    }

    /// Carried from the Task 6 review: what `rand send` shows before its y/N — the prover's fee
    /// and the history warning, once (the proof then prints no second one), for an `own=1`
    /// pairing as for any other (VK-4). A local proof shows nothing; on a pre-v3 chain a paired
    /// prover is refused here, before the question.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_send_confirmation_names_the_prover_fee_and_the_history_warning_once() {
        let prover = Wallet::from_spend_key(SpendKey([70; 8]));
        let chain = Arc::new(Mutex::new(ChainState::new()));
        chain.lock().unwrap().hc_bundle = ZkExecutor::hc_hidden_bundle_v3();
        chain.lock().unwrap().hc_auth = Some(ZkExecutor::hc_auth());
        let rpc = serve(&chain).await;
        assert!(prover_confirmation(&rpc, &Proving::local(Backend::Cpu)).await.unwrap().is_empty());
        let fee = serde_json::json!({ "amount": "500000000", "address": prover.address.to_string() });
        let remote = info_only_prover(fee.clone(), false).await;
        let lines = prover_confirmation(&rpc, &remote).await.unwrap();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0], format!("prover fee: 0.5 RAND to {}", prover.address.fingerprint()));
        assert!(lines[1].contains(crate::prover::VIEWING_KEY_WARNING) && lines[1].contains("box"), "{lines:?}");
        let Proving::Remote(r) = &remote else { unreachable!() };
        assert!(r.warned_history(), "shown once: the proof prints no second warning");
        assert!(!remote.announce_fee(), "the fee line was shown here: building the bundle does not print it again (M-1)");
        assert_eq!(prover_confirmation(&rpc, &remote).await.unwrap(), vec![lines[0].clone()]);
        // A pairing whose link said own=1, charging nothing: the history warning all the same —
        // `own` is the link's word, and no pairing is exempt from being told (VK-4).
        let own = prover_confirmation(&rpc, &info_only_prover(serde_json::Value::Null, true).await).await.unwrap();
        assert_eq!(own.len(), 1, "{own:?}");
        assert!(own[0].contains(crate::prover::VIEWING_KEY_WARNING), "{own:?}");
        // A pre-v3 chain: a paired prover is refused outright, charging or not, own or not (the
        // witness there carries the spend key, which goes nowhere).
        chain.lock().unwrap().hc_bundle = ZkExecutor::hc_bundle();
        chain.lock().unwrap().hc_auth = None;
        for (f, own) in [(serde_json::Value::Null, false), (serde_json::Value::Null, true), (fee.clone(), false)] {
            let e = prover_confirmation(&rpc, &info_only_prover(f, own).await).await.unwrap_err().to_string();
            assert_eq!(e, crate::prover::PRE_V3_REFUSAL);
        }
        assert!(prover_confirmation(&rpc, &Proving::local(Backend::Cpu)).await.unwrap().is_empty(), "a local proof there is as before");
        // Above the default cap (1 RAND): refused before the y/N (I-1).
        chain.lock().unwrap().hc_bundle = ZkExecutor::hc_hidden_bundle_v3();
        chain.lock().unwrap().hc_auth = Some(ZkExecutor::hc_auth());
        let greedy = serde_json::json!({ "amount": "14000000000", "address": prover.address.to_string() });
        let e = prover_confirmation(&rpc, &info_only_prover(greedy, false).await).await.unwrap_err().to_string();
        assert!(e.contains("the prover quotes 14 RAND; the cap is 1 RAND (--max-prover-fee)"), "{e}");
    }

    /// VK-4 (audit v6, decision D33): the spend-key witness path is retired. On a chain whose
    /// bundle guest is v1 or v2 the only witness a prover could be sent carries the spend key, and
    /// which guest the chain runs is `rand_status.hc_bundle` as the node says it — so a hostile
    /// prover's `own=1` link, beside a node answering v1 or v2, used to get the spend key sealed to
    /// itself. `--prover` on such a chain is now refused before the prover is asked anything
    /// (not even `prover_info`) and before anything is proved or submitted, whatever the pairing's
    /// `own` says. The fake prover here is the hostile one: it advertises the chain's guest and
    /// `spend_key`, and records whether a job it opens holds this wallet's spend key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pre_v3_chain_refuses_a_paired_prover_before_anything_is_sent() {
        use randprotocol_prover::wire::open_job;
        for hc in [ZkExecutor::hc_hidden_bundle(), ZkExecutor::hc_hidden_bundle_v2()] {
            let me = Wallet::from_spend_key(SpendKey([77; 8]));
            let you = Wallet::from_spend_key(SpendKey([78; 8]));
            let chain = Arc::new(Mutex::new(ChainState::new()));
            chain.lock().unwrap().hc_bundle = hc;
            chain.lock().unwrap().hc_auth = None;
            chain.lock().unwrap().fund(&me, 10 * randprotocol_core::UNITS_PER_RAND, 0);
            let rpc = serve(&chain).await;

            let key = randprotocol_prover::key::ProverKey::generate();
            let info = serde_json::json!({
                "kem_fingerprint": key.fingerprint().to_string(),
                "hc_bundles": ZkExecutor::known_hc_bundles().iter().map(word8_to_hex).collect::<Vec<_>>(),
                "profiles": ["test", "production"], "witness_kinds": ["viewing_key", "spend_key"], "fee": null,
            });
            let kem_ek = key.kem_ek().to_vec();
            // (every method asked, whether an opened job carried the spend key)
            let seen: Arc<Mutex<(Vec<String>, bool)>> = Arc::default();
            let (s, sk) = (seen.clone(), me.sk.0);
            let url = rpc_fn(move |method, params| {
                let mut g = s.lock().unwrap();
                g.0.push(method.to_string());
                match method {
                    "prover_info" => Reply::Ok(info.clone()),
                    "prover_submit" => {
                        let sealed = hex::decode(params[0].as_str().unwrap()).unwrap();
                        let job = open_job(key.dk(), &sealed).expect("sealed to this prover");
                        g.1 |= job.inputs.windows(8).any(|w| w == sk);
                        Reply::Err(-32000, "bad job")
                    }
                    _ => Reply::Err(-32601, "method not found"),
                }
            })
            .await;
            // The hostile link says own=1.
            let link = randprotocol_prover::pairing::PairingLink { kem_ek, url, token: [9; 32], own: true };
            let remote = Proving::Remote(Arc::new(RemoteProver::new(crate::prover::PairedProver::from_link(&link, Some("box".into())))));

            let mut store = NoteStore::default();
            let e = send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &remote, 7, false)
                .await
                .unwrap_err()
                .to_string();
            let (asked, got_the_spend_key) = seen.lock().unwrap().clone();
            assert!(!got_the_spend_key, "the prover was sent this wallet's spend key (asked: {asked:?})");
            assert!(asked.is_empty(), "the prover was asked {asked:?} before the refusal");
            assert_eq!(e, crate::prover::PRE_V3_REFUSAL);
            assert!(e.contains("bundle guest v3") && e.contains("spend key never leaves the wallet") && e.contains("--prover"), "{e}");
            assert!(chain.lock().unwrap().sent.is_empty(), "nothing was submitted");
            assert!(store.notes.iter().all(|n| n.pending.is_none()), "and nothing held back");
            // `rand send`'s confirmation refuses the same way, before its y/N.
            let e = prover_confirmation(&rpc, &remote).await.unwrap_err().to_string();
            assert_eq!(e, crate::prover::PRE_V3_REFUSAL);
            assert!(seen.lock().unwrap().0.is_empty(), "nor for the confirmation");
            // Proving on this machine there is unchanged.
            send_asset_with(&rpc, &me, &mut store, &you.address, 0, 1_000_000, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::Emulated, 7, false)
                .await
                .expect("a local proof on a pre-v3 chain");
            assert_eq!(chain.lock().unwrap().sent.len(), 1);
        }
    }

    /// Final review minor 1: the hardened pre-price stands the proof cap in for the unproved
    /// proof only under a gas policy, where every byte prices in. Without one the ledger's byte
    /// term charges only past the free allowance, and on a chain whose cap is raised past it the
    /// cap would buy a byte charge no real proof pays: there the quote is the envelope alone, as
    /// before the gas work.
    #[test]
    fn the_hardened_quote_prices_the_proof_cap_only_under_a_policy() {
        let raised = ChainLimits {
            max_program_words: 4096, max_proof_bytes: 20 << 20, max_block_bytes: 24 << 20, max_call_envelope_bytes: 18_432,
            max_program_public_words: 0, envelope_bytes: None, hardening_v6: true,
            gas_price: None, byte_price: None, gas_circuit: false, bundle_gas_limit: None, adjust_bps: None, proof_window_blocks: None,
            program_state: None,
            prove_base: 0,
            perps: None,
        };
        let priced = ChainLimits { gas_price: Some(100), byte_price: Some(800), ..raised };
        assert_eq!(hardened_call_quote_bytes(Some(&raised), 1_000), 1_000, "no policy: the envelope, as before");
        assert_eq!(hardened_call_quote_bytes(None, 0), 0);
        assert_eq!(hardened_call_quote_bytes(Some(&priced), 1_000), (20 << 20) + 1_000, "a policy: the cap in the proof's place");
        // The overcharge the no-policy rule avoids is real: the cap alone is past the free allowance.
        assert!(call_fee_default(Some(&raised), 14, 0, 0, 0, (20 << 20) + 1_000).unwrap() > call_fee_default(Some(&raised), 14, 0, 0, 0, 1_000).unwrap());
    }

    /// `fees.prove_base` (`docs/compute-optimization.md` §6.3) in the wallet's own floors: the
    /// call floor (and so `call_fee_default` and the post-proof guard) adds the served
    /// `prove_base` under every pricing rule, and `schedule_floor` adds it to `gas::fee_floor` —
    /// read off the node's cached `rand_getLimits.fee_rules`, `0` from a node that serves none.
    #[tokio::test]
    async fn the_wallets_floors_include_the_served_prove_base() {
        let plain = limits(18_432, 2 << 20);
        let proving = ChainLimits { prove_base: 600_000, ..plain };
        assert_eq!(call_floor(Some(&proving), 12, 0, 0, 0, 0).unwrap(), call_floor(Some(&plain), 12, 0, 0, 0, 0).unwrap() + 600_000);
        let circuit = ChainLimits { gas_circuit: true, gas_price: Some(100), byte_price: Some(800), ..proving };
        assert_eq!(call_floor(Some(&circuit), 12, 0, 0, 3_000, 0).unwrap(), gas::circuit_call_floor(100, 800, 3_000, 0) + 600_000);
        let policy = ChainLimits { gas_price: Some(100), byte_price: Some(800), ..proving };
        assert_eq!(
            call_fee_default(Some(&policy), 14, 0, 0, 0, 1_000).unwrap(),
            gas::GasPolicy { gas_price: 100, byte_price: 800 }.call_floor(14, 0, 0, 1_000) + 600_000
        );

        use crate::test_rpc::{scripted_rpc, Reply};
        let reply = serde_json::json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
            "fee_rules": { "burn_base": false, "subsidy_net_of_fees": false, "burn_floor": false, "proposer_share_bps": 4000, "prove_base": "600000" }
        });
        // Under the dynamic controller the headroom scales the priced floor, never prove_base.
        let dynamic = ChainLimits { adjust_bps: Some(1_250), ..circuit };
        let priced = gas::circuit_call_floor(100, 800, 3_000, 0);
        assert_eq!(call_fee_default(Some(&dynamic), 12, 0, 0, 3_000, 0).unwrap(), with_headroom(Some(&dynamic), priced) + 600_000);
        assert_eq!(call_floor(Some(&dynamic), 12, 0, 0, 3_000, 0).unwrap(), priced + 600_000, "the floor itself, no headroom");

        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(reply))]).await);
        let bond = Action::None;
        assert_eq!(schedule_floor(&rpc, &bond).await.unwrap(), gas::BUNDLE_BASE + 600_000);
        let old = RpcClient::new(scripted_rpc(vec![]).await);
        assert_eq!(schedule_floor(&old, &bond).await.unwrap(), gas::BUNDLE_BASE, "no prove_base served, the schedule alone");
    }

    #[test]
    fn the_fee_defaults_are_the_schedule_floors_and_no_more() {
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x13; 40], public: vec![] };
        assert_eq!(deploy_fee_default(&deploy), gas::fee_floor(&deploy));
        assert_eq!(deploy_fee_default(&deploy), gas::BUNDLE_BASE + gas::deploy_fee(40));
        use randprotocol_core::gas::GasPolicy;
        let policy = ChainLimits {
            max_program_words: 4096, max_proof_bytes: 2 << 20, max_block_bytes: 4 << 20, max_call_envelope_bytes: 18_432,
            max_program_public_words: 0, envelope_bytes: None, hardening_v6: false,
            gas_price: Some(100), byte_price: Some(800), gas_circuit: false, bundle_gas_limit: None, adjust_bps: None, proof_window_blocks: None,
            program_state: None,
            prove_base: 0,
            perps: None,
        };
        let old = ChainLimits { gas_price: None, byte_price: None, ..policy };
        for tier in [10u8, 12, 14, 20] {
            // Review focus 4: no node, or an old node, prices the ledger's floor, nothing over it.
            assert_eq!(call_fee_default(None, tier, 0, 0, 0, 0).unwrap(), gas::BUNDLE_BASE + gas::call_fee(tier, 0));
            assert_eq!(call_fee_default(Some(&old), tier, 0, 0, 0, 1_300_000).unwrap(), gas::BUNDLE_BASE + gas::call_fee(tier, 1_300_000));
            // Under a policy: its floor of the header, exactly.
            assert_eq!(call_fee_default(Some(&policy), tier, 0, 0, 0, 1_300_000).unwrap(), GasPolicy::DEFAULT.call_floor(tier, 0, 0, 1_300_000));
            assert_eq!(call_fee_default(Some(&policy), tier, 12, 13, 0, 3_200_000).unwrap(), GasPolicy::DEFAULT.call_floor(tier, 12, 13, 3_200_000));
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
                &Proving::local(Backend::Cpu),
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
        clear_pending(&mut store, 9 + TIME_WINDOW, TIME_WINDOW);
        assert_eq!(store.notes[0].pending, Some(9), "the bundle can still commit at this height");
        assert_eq!(store.balance(), 0);

        // One past it: the submission can never be admitted now, so the note is free again.
        clear_pending(&mut store, 9 + TIME_WINDOW + 1, TIME_WINDOW);
        assert_eq!(store.notes[0].pending, None);
        assert_eq!(store.balance(), 5);

        // A spend that did land clears the mark immediately, whatever the height reached.
        let mut store = pending_at(9, true);
        clear_pending(&mut store, 0, TIME_WINDOW);
        assert_eq!(store.notes[0].pending, None);
        assert_eq!(store.balance(), 0, "but a spent note is still spent");
    }

    /// Issue #118: on a chain whose genesis sets `proof_window_blocks`, a pending spend stays
    /// pending until the blocks read pass *that* window — the bundle can still commit up to it.
    /// The window comes from `rand_getLimits`, a node's unauthenticated word, so it is clamped to
    /// what a genesis can carry: a lying node can move the release only inside [256, 4096].
    #[test]
    fn pending_waits_out_the_chains_proof_window() {
        let mut n = owned(0, 5, false);
        n.pending = Some(9);
        let mut store = NoteStore { notes: vec![n], ..NoteStore::default() };
        clear_pending(&mut store, 9 + TIME_WINDOW + 1, 1024);
        assert_eq!(store.notes[0].pending, Some(9), "past 256 but inside the chain's 1 024: it can still commit");
        clear_pending(&mut store, 9 + 1024, 1024);
        assert_eq!(store.notes[0].pending, Some(9));
        clear_pending(&mut store, 9 + 1024 + 1, 1024);
        assert_eq!(store.notes[0].pending, None);
        let with = |w: Option<u64>| ChainLimits { proof_window_blocks: w, ..limits(18_432, 2 << 20) };
        assert_eq!(pending_window(None), TIME_WINDOW, "a node without rand_getLimits");
        assert_eq!(pending_window(Some(&with(None))), TIME_WINDOW, "a chain without the field");
        assert_eq!(pending_window(Some(&with(Some(1024)))), 1024);
        assert_eq!(pending_window(Some(&with(Some(3)))), MIN_PROOF_WINDOW_BLOCKS, "never released before 256");
        assert_eq!(pending_window(Some(&with(Some(u64::MAX)))), MAX_PROOF_WINDOW_BLOCKS, "never held past 4 096");
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
            genesis: None,
            scanned_index: 9,
            scanned_height: 4,
            scanned_attest_height: 5,
            notes: vec![owned(0, 5, false), owned(1, 3, true)],
            sent: vec![SentRow { index: 7, to_pk: [4; 8], amount: 11, height: 2, memo: None }],
            ..NoteStore::default()
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
        assert!(back.notes[1].spent);
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
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
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
        assert_eq!((rows[0].key, rows[0].note), (k_pay, pay));
        assert_eq!((rows[1].output, rows[1].slot, rows[1].role), ("bundle", 1, KeyRole::Change));
        assert_eq!((rows[1].key, rows[1].note), (k_change, change));
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
        assert_eq!((rows[0].role, rows[0].key, rows[0].note), (KeyRole::Received, k_pay, pay));
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

    /// Task 8 (T7 review round 1): [`output_keys`] carries the memo through for whichever output
    /// sealed one, and leaves it `None` for one that did not — the payee's row reads the memo the
    /// sender sealed, the change row (sealed in the legacy, memo-less form here) reads `None`,
    /// never the payee's memo leaking onto it. `rand tx-key` prints exactly this column.
    #[test]
    fn output_keys_carries_the_memo_for_the_output_that_has_one_and_none_for_the_one_that_does_not() {
        let (me, you) = (Wallet::from_spend_key(SpendKey([11; 8])), Wallet::from_spend_key(SpendKey([12; 8])));
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
                seal_note_as(EnvelopeFormat::Memo, &me.vk, &you.address, &pay, &k_pay, "coffee").unwrap(),
                seal_note(&me.vk, &me.address, &change, &k_change).unwrap(),
                env(),
                env(),
            ],
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let tx = Transaction::shielded(7, bundle, Action::None);
        let rows = output_keys(&me, &tx);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!((rows[0].role, rows[0].memo.as_deref()), (KeyRole::Sent, Some("coffee")));
        assert_eq!((rows[1].role, rows[1].memo.as_deref()), (KeyRole::Change, None));
    }

    // ---------------------------------------------------- the call limits (Task 5)

    fn limits(max_call_envelope_bytes: usize, max_proof_bytes: usize) -> ChainLimits {
        ChainLimits {
            max_program_words: 4096,
            max_proof_bytes,
            max_block_bytes: 4 << 20,
            max_call_envelope_bytes,
            max_program_public_words: 64,
            envelope_bytes: None,
            hardening_v6: false,
            gas_price: None,
            byte_price: None,
            gas_circuit: false,
            bundle_gas_limit: None,
            adjust_bps: None,
            proof_window_blocks: None,
            program_state: None,
            prove_base: 0,
            perps: None,
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
    #[tokio::test]
    async fn a_submitted_transactions_proof_verifies_against_its_own_binding() {
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
                auth_commit: [0; 8],
                auth_proof: Vec::new(),
            },
            words: Vec::new(),
            expected: [0; 8],
            guest: ZkExecutor::hc_bundle(),
            v3: false,
            salt: [0; 8],
            auth_commit: [0; 8],
        };
        let action = Action::BridgeBurn { asset: 3, amount: 400, relayer_fee: 100, to_chain: 2, token: [7; 32], to: [1; 32] };
        let mut tx = Transaction::shielded(13, prepared.bundle.clone(), action);
        let stub = |p: &Prepared, binding: &[u32; TX_BINDING_WORDS]| -> Result<Proved> {
            let d = StubExecutor.bundle_digest(&p.bundle.digest_input());
            Ok(Proved { proof: StubExecutor::make_bundle_proof(&HC, &d, binding), tier: 14, proving: Duration::ZERO, auth_proof: Vec::new(), auth_proving: None })
        };
        prove_transaction_by(&mut tx, &BindingDomain::ChainId, |b| std::future::ready(stub(&prepared, &b))).await.unwrap();
        let binding = tx.binding(&BindingDomain::ChainId);
        let b = tx.bundle.as_ref().unwrap();
        assert_eq!(StubExecutor.bundle_proof_digest(&[0; 8], &b.proof).unwrap(), StubExecutor.bundle_digest(&b.digest_input()));
        assert_eq!(StubExecutor.verify_bundle(&HC, &b.proof, &binding), Ok(()));
        // The copied-proof attack against what the wallet built: the destination changed, the
        // proof kept. It does not verify for the copy.
        let mut copy = tx.clone();
        let Action::BridgeBurn { to, .. } = &mut copy.action else { panic!("a burn") };
        *to = [2; 32];
        let refused = Err(ConfidentialError::InvalidBundleProof("PublicValues".into()));
        assert_eq!(StubExecutor.verify_bundle(&HC, &copy.bundle.as_ref().unwrap().proof, &copy.binding(&randprotocol_core::BindingDomain::ChainId)), refused);
    }

    /// INT-4, the wallet's order under genesis `hardening_v6`: the call is proved over the
    /// transaction's call binding (both proofs empty), filled in, and only then the bundle is
    /// proved over the finished transaction — so the call proof verifies under the hardened rule
    /// for this transaction and the bundle's binding covers the call proof. Lifted onto another
    /// fee bundle, the call proof is refused.
    #[tokio::test]
    async fn a_bound_call_is_proved_before_its_bundle_and_verifies_for_its_own_transaction() {
        use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
        use randprotocol_core::program::ProgramRecord;
        const HC: Word8 = [11; 8];
        let bundle = |nf: u32| Bundle {
            anchor: [1; 8],
            nullifiers: [[nf; 8], [nf + 1; 8], [nf + 2; 8], [nf + 3; 8]],
            commitments: [[14; 8], [15; 8], [16; 8], [17; 8]],
            fee: gas::BUNDLE_BASE + gas::call_fee(12, 0),
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 9,
            envelopes: [env(), env(), env(), env()],
            proof: Vec::new(),
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let prepared =
            Prepared { bundle: bundle(10), words: Vec::new(), expected: [0; 8], guest: ZkExecutor::hc_bundle(), v3: false, salt: [0; 8], auth_commit: [0; 8] };
        let id = Hash::digest(b"program");
        let record = ProgramRecord { id, base_pc: 0, words: vec![0x13; 4], code_hash: vec![], deployed_at: 0, public_digest: None, public_len: 0 };
        let call = Action::Call { program: id, proof: Vec::new(), input_envelope: None };
        let mut tx = Transaction::shielded(13, prepared.bundle.clone(), call);
        let prove_call = |t: &Transaction, d: &BindingDomain| -> Result<Vec<u8>> { Ok(StubExecutor::make_proof_with_public(&id, 12, [5; 8], &t.call_binding(d))) };
        bind_call(&mut tx, &BindingDomain::ChainId, &prove_call).unwrap();
        let stub = |p: &Prepared, binding: &[u32; TX_BINDING_WORDS]| -> Result<Proved> {
            let d = StubExecutor.bundle_digest(&p.bundle.digest_input());
            Ok(Proved { proof: StubExecutor::make_bundle_proof(&HC, &d, binding), tier: 14, proving: Duration::ZERO, auth_proof: Vec::new(), auth_proving: None })
        };
        prove_transaction_by(&mut tx, &BindingDomain::ChainId, |b| std::future::ready(stub(&prepared, &b))).await.unwrap();
        let Action::Call { proof, .. } = &tx.action else { panic!("a call") };
        assert!(StubExecutor.verify_call_hardened(&record, proof, &tx.call_binding(&randprotocol_core::BindingDomain::ChainId)).is_ok(), "bound to its own transaction");
        assert_eq!(StubExecutor.verify_bundle(&HC, &tx.bundle.as_ref().unwrap().proof, &tx.binding(&randprotocol_core::BindingDomain::ChainId)), Ok(()));
        let mut lifted = Transaction::shielded(13, bundle(40), tx.action.clone());
        StubExecutor::bind(&mut lifted);
        let Action::Call { proof, .. } = &lifted.action else { panic!("a call") };
        assert_eq!(
            StubExecutor.verify_call_hardened(&record, proof, &lifted.call_binding(&randprotocol_core::BindingDomain::ChainId)),
            Err(ConfidentialError::InvalidProof("PublicValues".into())),
            "the same call proof under another fee bundle"
        );
        assert!(bind_call(&mut Transaction::shielded(13, bundle(50), Action::None), &BindingDomain::ChainId, &prove_call).is_err(), "only a call is bound");
    }

    /// Review finding (fix round 1 of 5): under a node's gas policy, `submit_bound_call`'s guard
    /// must price the REAL proof's bytes, not the pre-price `main.rs` made before the proof
    /// existed — a fee that covers only the ledger floor of the same proof is refused, naming the
    /// policy floor to retry with; the same fee, no policy, still passes (the old rule).
    #[test]
    fn the_bound_call_guard_refuses_a_policy_under_quote() {
        use randprotocol_core::gas::GasPolicy;
        let proof = vec![0u8; 1_300_000];
        let tier = 12u8;
        let bytes = gas::call_bytes(&proof, None);
        let ledger_floor = gas::BUNDLE_BASE + gas::call_fee(tier, bytes);
        let policy = ChainLimits {
            max_program_words: 4096,
            max_proof_bytes: 2 << 20,
            max_block_bytes: 4 << 20,
            max_call_envelope_bytes: 18_432,
            max_program_public_words: 0,
            envelope_bytes: None,
            hardening_v6: true,
            gas_price: Some(100),
            byte_price: Some(800),
            gas_circuit: false,
            bundle_gas_limit: None,
            adjust_bps: None,
            proof_window_blocks: None,
            program_state: None,
            prove_base: 0,
            perps: None,
        };
        let want = GasPolicy::DEFAULT.call_floor(tier, 0, 0, bytes);
        assert!(want > ledger_floor, "the policy floor must exceed the ledger floor for this test to say anything");
        let e = refuse_if_under_the_floor(Some(&policy), tier, 0, 0, 0, &proof, None, ledger_floor, 0).unwrap_err().to_string();
        assert!(e.contains(&format_amount(want)), "{e}");
        // The same fee, no policy at all: the old rule, unchanged.
        assert!(refuse_if_under_the_floor(None, tier, 0, 0, 0, &proof, None, ledger_floor, 0).is_ok());
    }

    // ---------------------------------------------------- the declared gas limit (B5, B7)

    fn circuit_limits(adjust_bps: Option<u32>) -> ChainLimits {
        ChainLimits {
            gas_price: Some(100),
            byte_price: Some(800),
            gas_circuit: true,
            bundle_gas_limit: Some(gas::gas_max(14, 0, 0)),
            adjust_bps,
            ..limits(18_432, 2 << 20)
        }
    }

    /// Spec §5: the exact gas rounded up to a multiple of `2^(t−2)` (five values a tier under the
    /// ceiling, the top one being the ceiling itself, since the ceiling is `5·2^(t−2) − 1`), capped
    /// at the tier's own ceiling.
    #[test]
    fn the_wallet_declares_a_quarter_tier_bucket() {
        assert_eq!(default_gas_limit(1, 10), 256);
        assert_eq!(default_gas_limit(256, 10), 256);
        assert_eq!(default_gas_limit(257, 10), 512);
        // Tier 10's ceiling is gas_max(10, 0, 0) = 1 279 (1 023 cycles + the 2^8 absorb term), so
        // 1 024 is a bucket under it and the next bucket, 1 280, is capped to it.
        assert_eq!(default_gas_limit(1_000, 10), 1_024);
        assert_eq!(default_gas_limit(1_200, 10), 1_279, "capped at the tier's own ceiling");
        // 2^14 steps at tier 16 (the brief's 40 960 is not a multiple of 2^14; see the report).
        assert_eq!(default_gas_limit(38_412, 16), 49_152);
        assert_eq!(default_gas_limit(60_000, 16), 65_536);
        assert_eq!(default_gas_limit(70_000, 16), 81_919, "capped at gas_max(16, 0, 0)");
        // A hashing call's ceiling is its header's, not the hash-free one.
        let ceiling = gas::gas_max(10, 7, 0);
        assert_eq!(gas_bucket(1_500, 10, ceiling), 1_536);
        for exact in [1u64, 255, 256, 257, 700, 1_023, 1_279] {
            assert!(default_gas_limit(exact, 10) >= exact, "never under the exact gas");
        }
    }

    #[test]
    fn a_declared_limit_outside_the_run_and_the_ceiling_is_refused_naming_the_bound() {
        let ceiling = gas::gas_max(10, 0, 0);
        assert!(check_gas_limit(500, 500, ceiling).is_ok());
        assert!(check_gas_limit(1_279, 500, ceiling).is_ok());
        let e = check_gas_limit(499, 500, ceiling).unwrap_err().to_string();
        assert!(e.contains("exact gas 500"), "{e}");
        let e = check_gas_limit(1_280, 500, ceiling).unwrap_err().to_string();
        assert!(e.contains("ceiling 1279"), "{e}");
    }

    /// Under a `gas` section the default is the declared limit's floor, whatever the header.
    #[test]
    fn the_circuit_fee_is_the_declared_limits_floor() {
        let l = circuit_limits(None);
        for (tier, klh, slh) in [(10u8, 0u8, 0u8), (12, 0, 0), (14, 12, 13)] {
            assert_eq!(call_fee_default(Some(&l), tier, klh, slh, 3_000, 1_300_000).unwrap(), gas::circuit_call_floor(100, 800, 3_000, 1_300_000));
        }
        assert!(call_fee_default(Some(&l), 12, 0, 0, 3_000, 0).unwrap() < call_fee_default(Some(&l), 12, 0, 0, 4_000, 0).unwrap(), "the limit prices it");
        // Without the section, the gas limit is ignored (Phase 0's header rule).
        let header = ChainLimits { gas_circuit: false, bundle_gas_limit: None, ..l };
        assert_eq!(call_fee_default(Some(&header), 12, 0, 0, 3_000, 1_300_000).unwrap(), call_fee_default(Some(&header), 12, 0, 0, 9, 1_300_000).unwrap());
        // The post-proof guard prices the proof's own declared limit.
        let proof = vec![0u8; 1_300_000];
        let floor = gas::circuit_call_floor(100, 800, 3_000, gas::call_bytes(&proof, None));
        assert!(refuse_if_under_the_floor(Some(&l), 12, 0, 0, 3_000, &proof, None, floor, 0).is_ok());
        let e = refuse_if_under_the_floor(Some(&l), 12, 0, 0, 3_001, &proof, None, floor, 0).unwrap_err().to_string();
        assert!(e.contains(&format_amount(floor + 100)), "{e}");
    }

    /// Final-review minor 3: under a `gas` section a price the node left out is not zero — the
    /// floor fails closed, naming the missing field, rather than pricing the call at nothing.
    #[test]
    fn a_missing_price_under_a_gas_section_fails_closed() {
        let no_gas_price = ChainLimits { gas_price: None, ..circuit_limits(None) };
        let no_byte_price = ChainLimits { byte_price: None, ..circuit_limits(None) };
        let e = call_floor(Some(&no_gas_price), 12, 0, 0, 3_000, 0).unwrap_err().to_string();
        assert!(e.contains("gas_price"), "{e}");
        let e = call_fee_default(Some(&no_byte_price), 12, 0, 0, 3_000, 1_300_000).unwrap_err().to_string();
        assert!(e.contains("byte_price"), "{e}");
        let proof = vec![0u8; 1_000];
        let e = refuse_if_under_the_floor(Some(&no_gas_price), 12, 0, 0, 3_000, &proof, None, u64::MAX, 0).unwrap_err().to_string();
        assert!(e.contains("gas_price"), "the post-proof guard fails closed too: {e}");
        // Without a section the prices are the node's optional policy, as before.
        let header = ChainLimits { gas_circuit: false, gas_price: None, byte_price: None, ..circuit_limits(None) };
        assert!(call_floor(Some(&header), 12, 0, 0, 3_000, 0).is_ok());
    }

    /// Spec §7.1 (task B7, final-review I2c): two price steps of headroom under `dynamic`, none
    /// otherwise — `rand_getLimits` serves the committed head's prices and a transaction lands two
    /// or three certified blocks later; the guard still accepts a `--fee` of the bare floor.
    #[test]
    fn the_wallet_pays_two_price_steps_of_headroom_under_dynamic_prices() {
        let fixed = circuit_limits(None);
        let dynamic = circuit_limits(Some(1_250));
        let floor = gas::circuit_call_floor(100, 800, 3_000, 1_300_000);
        assert_eq!(call_fee_default(Some(&fixed), 12, 0, 0, 3_000, 1_300_000).unwrap(), floor);
        let two_steps = (floor as u128 * 11_250 * 11_250 / 100_000_000) as u64;
        assert_eq!(call_fee_default(Some(&dynamic), 12, 0, 0, 3_000, 1_300_000).unwrap(), two_steps, "floor · 1.125²");
        assert!(two_steps > floor + floor * 1_250 / 10_000, "more than one step");
        assert_eq!(call_floor(Some(&dynamic), 12, 0, 0, 3_000, 1_300_000).unwrap(), floor, "the floor itself carries no headroom");
        let proof = vec![0u8; 1_300_000];
        let exact = gas::circuit_call_floor(100, 800, 3_000, gas::call_bytes(&proof, None));
        assert!(refuse_if_under_the_floor(Some(&dynamic), 12, 0, 0, 3_000, &proof, None, exact, 0).is_ok());
        assert_eq!(call_fee_default(Some(&ChainLimits { adjust_bps: Some(5_000), ..dynamic }), 12, 0, 0, u64::MAX, 0).unwrap(), u64::MAX, "saturating");
    }

    #[test]
    fn exact_call_gas_is_the_emulators_gas_of() {
        let p = randprotocol_zkvm::guests::fib(10);
        let (g, tier) = exact_call_gas(&p, &[], &[]).unwrap();
        let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], 1 << 22).unwrap();
        assert_eq!(g, randprotocol_zkvm::gas::gas_of(&p, &[], &[], &exec.events));
        assert_eq!(tier, randprotocol_zkvm::executor::call_tier(&p, &[], 0).unwrap());
        // The segment length is part of the digest prefix, so it is part of the gas.
        let (padded, _) = exact_call_gas(&p, &[], &[0; 8]).unwrap();
        assert!(padded > g);
    }

    /// B5 review ruling: the hardened guard reads `pv[GAS]` fail-closed — a public-value list
    /// short of it is refused, not priced at zero gas.
    #[test]
    fn the_declared_gas_is_read_fail_closed() {
        let gas_ix = randprotocol_zkvm::tables::cpu::pv::GAS;
        let mut pv = vec![0u64; randprotocol_zkvm::tables::cpu::pv::NUM];
        pv[gas_ix] = 3_000;
        assert_eq!(declared_gas(&pv).unwrap(), 3_000);
        let e = declared_gas(&pv[..gas_ix]).unwrap_err().to_string();
        assert!(e.contains("GAS"), "{e}");
        assert!(declared_gas(&[]).is_err());
    }

    #[test]
    fn a_bundle_gas_limit_other_than_the_guests_ceiling_is_refused() {
        assert!(check_bundle_gas_limit(None).is_ok());
        assert!(check_bundle_gas_limit(Some(gas::gas_max(14, 0, 0))).is_ok());
        assert!(check_bundle_gas_limit(Some(20_479)).is_ok());
        // The pre-absorb-term value is another guest's now.
        let e = check_bundle_gas_limit(Some(16_383)).unwrap_err().to_string();
        assert!(e.contains("16383") && e.contains("20479"), "{e}");
    }

}
