//! Persistent chain storage: one RocksDB with column families.
//!
//! Every commit is a single atomic, fsynced `WriteBatch` covering blocks,
//! certificates, indexes, transaction locations, the notes and nullifiers the
//! block created, its end-of-block anchor, the proposer's validator entry, the
//! commitment-tree frontier, and the head.

use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, WriteOptions, DB};
use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::consensus::{CommittedBlock, SafetyState};
use shrugg_core::genesis::GenesisState;
use shrugg_core::ledger::ValidatorEntry;
use shrugg_core::notes::{word8_from_bytes, word8_to_bytes, CommitmentTree, Envelope, FullTree, Word8, DEPTH};
use shrugg_core::{Action, Address, Block, CallReceipt, Hash, Ledger, ProgramId, ProgramRecord, QuorumCertificate};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CF_BLOCKS: &str = "blocks";
const CF_QCS: &str = "qcs";
const CF_BLOCK_INDEX: &str = "block_index";
const CF_TXS: &str = "txs";
const CF_META: &str = "meta";
const CF_PROGRAMS: &str = "programs";
const CF_RECEIPTS: &str = "receipts";
/// Leaf index (big-endian u64, so the family iterates in tree order) -> `bincode(NoteRow)`.
/// Dense from zero: `notes_count` is the last key plus one, and a wallet pages it to scan.
const CF_NOTES: &str = "notes";
/// Nullifier (32 bytes) -> the height of the block that spent it (big-endian u64).
const CF_NULLIFIERS: &str = "nullifiers";
/// Block height (big-endian u64) -> the commitment-tree root at the end of that block.
const CF_ANCHORS: &str = "anchors";
/// Validator address (32 bytes) -> `bincode(ValidatorEntry)`.
const CF_VALIDATORS: &str = "validators";
const ALL_CFS: [&str; 11] = [
    CF_BLOCKS,
    CF_QCS,
    CF_BLOCK_INDEX,
    CF_TXS,
    CF_META,
    CF_PROGRAMS,
    CF_RECEIPTS,
    CF_NOTES,
    CF_NULLIFIERS,
    CF_ANCHORS,
    CF_VALIDATORS,
];

const META_HEAD_HEIGHT: &str = "head_height";
const META_GENESIS_HASH: &str = "genesis_hash";
const META_CHAIN_ID: &str = "chain_id";
const META_SAFETY: &str = "safety";
/// `bincode(CommitmentTree)`: the depth-32 frontier, the only form of the note tree consensus
/// state keeps. The leaves themselves live in `notes` and rebuild a `FullTree` for witnesses.
const META_TREE: &str = "tree";
/// The genesis `hc_bundle` (32 bytes): the bundle guest commitment every bundle proof on this
/// chain is verified against.
const META_HC_BUNDLE: &str = "hc_bundle";

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("rocksdb: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("encoding: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("storage not initialized with genesis")]
    NotInitialized,
    #[error("already initialized with a different genesis {existing}")]
    AlreadyInitialized { existing: Hash },
    #[error("corrupt storage: {0}")]
    Corrupt(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub height: u64,
    pub hash: Hash,
}

/// One leaf of the commitment tree as it is served to wallets: the commitment, the envelope
/// sealed against it, and the height of the block that appended it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NoteRow {
    pub cm: Word8,
    pub envelope: Envelope,
    pub height: u64,
}

pub struct Storage {
    db: DB,
}

fn height_key(h: u64) -> [u8; 8] {
    h.to_be_bytes()
}

fn be_u64(bytes: &[u8], what: &str) -> Result<u64> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| StorageError::Corrupt(format!("{what} is not 8 bytes")))?;
    Ok(u64::from_be_bytes(arr))
}

fn word8(bytes: &[u8], what: &str) -> Result<Word8> {
    word8_from_bytes(bytes).ok_or_else(|| StorageError::Corrupt(format!("{what} is not 32 bytes")))
}

fn sync_opts() -> WriteOptions {
    let mut w = WriteOptions::default();
    w.set_sync(true);
    w
}

/// Every note a transaction creates, paired with the envelope that opens it: the bundle's two
/// output slots in that order, then a mint's single note — exactly `Transaction::commitments`'
/// order, so the index a leaf gets on disk is the index the ledger gave it.
fn created_notes(tx: &shrugg_core::Transaction) -> Vec<(Word8, Envelope)> {
    let mut out = Vec::new();
    if let Some(b) = &tx.bundle {
        for i in 0..2 {
            out.push((b.commitments[i], b.envelopes[i].clone()));
        }
    }
    if let Action::Mint { cm, envelope, .. } = &tx.action {
        out.push((*cm, envelope.clone()));
    }
    out
}

impl Storage {
    /// Open (creating if needed) the database at `<path>/db`.
    pub fn open(path: &Path) -> Result<Storage> {
        let db_path = path.join("db");
        std::fs::create_dir_all(&db_path)
            .map_err(|e| StorageError::Corrupt(format!("create {}: {e}", db_path.display())))?;
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()));
        let db = DB::open_cf_descriptors(&opts, &db_path, cfs)?;
        Ok(Storage { db })
    }

    fn cf(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(name).expect("column family opened at startup")
    }

    fn get<T: serde::de::DeserializeOwned>(&self, cf: &str, key: &[u8]) -> Result<Option<T>> {
        match self.db.get_cf(self.cf(cf), key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    fn get_meta_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get_cf(self.cf(CF_META), key.as_bytes())?)
    }

    pub fn is_initialized(&self) -> Result<bool> {
        Ok(self.get_meta_raw(META_GENESIS_HASH)?.is_some())
    }

    /// Write the genesis block and initial state. Idempotent for the same genesis.
    pub fn init_genesis(&self, gs: &GenesisState) -> Result<()> {
        let genesis_hash = gs.hash();
        if let Some(existing) = self.get_meta_raw(META_GENESIS_HASH)? {
            let existing = Hash(existing.as_slice().try_into().map_err(|_| {
                StorageError::Corrupt("genesis_hash meta has wrong length".into())
            })?);
            if existing == genesis_hash {
                return Ok(());
            }
            return Err(StorageError::AlreadyInitialized { existing });
        }
        let mut batch = WriteBatch::default();
        let block = &gs.block;
        batch.put_cf(self.cf(CF_BLOCKS), height_key(0), block.encode());
        batch.put_cf(
            self.cf(CF_QCS),
            height_key(0),
            bincode::serialize(&QuorumCertificate::genesis(genesis_hash))?,
        );
        batch.put_cf(self.cf(CF_BLOCK_INDEX), genesis_hash.as_bytes(), height_key(0));
        // The alloc notes are leaves 0..n of the tree, in file order, all at height 0.
        for (index, (cm, envelope, _amount)) in gs.notes.iter().enumerate() {
            let row = NoteRow { cm: *cm, envelope: envelope.clone(), height: 0 };
            batch.put_cf(self.cf(CF_NOTES), height_key(index as u64), bincode::serialize(&row)?);
        }
        for (addr, entry) in gs.ledger.validators() {
            batch.put_cf(self.cf(CF_VALIDATORS), addr.as_bytes(), bincode::serialize(entry)?);
        }
        batch.put_cf(self.cf(CF_ANCHORS), height_key(0), word8_to_bytes(&gs.ledger.root()));
        batch.put_cf(self.cf(CF_META), META_TREE, bincode::serialize(gs.ledger.tree())?);
        batch.put_cf(self.cf(CF_META), META_HC_BUNDLE, word8_to_bytes(&gs.hc_bundle));
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(0));
        batch.put_cf(self.cf(CF_META), META_GENESIS_HASH, genesis_hash.as_bytes());
        batch.put_cf(self.cf(CF_META), META_CHAIN_ID, gs.chain_id.to_be_bytes());
        self.db.write_opt(batch, &sync_opts())?;
        Ok(())
    }

    // ---- the shielded pool ----------------------------------------------

    /// The leaf at `index`, or `None` past the end of the tree.
    pub fn note(&self, index: u64) -> Result<Option<NoteRow>> {
        self.get(CF_NOTES, &height_key(index))
    }

    /// Up to `limit` consecutive leaves starting at `from`, in tree order: what a wallet pages
    /// through to trial-decrypt.
    pub fn notes_from(&self, from: u64, limit: usize) -> Result<Vec<(u64, NoteRow)>> {
        let mode = IteratorMode::From(&height_key(from), rocksdb::Direction::Forward);
        let mut out = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_NOTES), mode) {
            if out.len() >= limit {
                break;
            }
            let (k, v) = item?;
            out.push((be_u64(k.as_ref(), "note key")?, bincode::deserialize(&v)?));
        }
        Ok(out)
    }

    /// The number of leaves, i.e. the index the next note gets. The family is dense from zero,
    /// so this is the last key plus one rather than a scan.
    pub fn notes_count(&self) -> Result<u64> {
        match self.db.iterator_cf(self.cf(CF_NOTES), IteratorMode::End).next() {
            Some(item) => Ok(be_u64(item?.0.as_ref(), "note key")? + 1),
            None => Ok(0),
        }
    }

    /// The height of the block that spent `nf`, or `None` if it is unspent.
    pub fn nullifier_height(&self, nf: &Word8) -> Result<Option<u64>> {
        match self.db.get_cf(self.cf(CF_NULLIFIERS), word8_to_bytes(nf))? {
            Some(v) => Ok(Some(be_u64(&v, "nullifier height")?)),
            None => Ok(None),
        }
    }

    pub fn nullifiers_count(&self) -> Result<u64> {
        Ok(self.db.iterator_cf(self.cf(CF_NULLIFIERS), IteratorMode::Start).count() as u64)
    }

    /// Nullifiers spent at or after `from_height`, oldest first, at most `limit` of them.
    ///
    /// The family is keyed by nullifier (membership is what admission asks of it), so a
    /// height-ordered listing is a scan and a sort. That is affordable at testnet sizes and is
    /// the price of not keeping a second index consistent across commit and truncation.
    pub fn nullifiers_from(&self, from_height: u64, limit: usize) -> Result<Vec<(u64, Word8)>> {
        let mut out = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_NULLIFIERS), IteratorMode::Start) {
            let (k, v) = item?;
            let height = be_u64(&v, "nullifier height")?;
            if height >= from_height {
                out.push((height, word8(k.as_ref(), "nullifier key")?));
            }
        }
        out.sort();
        out.truncate(limit);
        Ok(out)
    }

    /// The commitment-tree root at the end of block `height`, if it is still in the window.
    pub fn anchor(&self, height: u64) -> Result<Option<Word8>> {
        match self.db.get_cf(self.cf(CF_ANCHORS), height_key(height))? {
            Some(v) => Ok(Some(word8(&v, "anchor")?)),
            None => Ok(None),
        }
    }

    /// The newest stored anchor: the root a prover should build against.
    pub fn latest_anchor(&self) -> Result<Option<(u64, Word8)>> {
        match self.db.iterator_cf(self.cf(CF_ANCHORS), IteratorMode::End).next() {
            Some(item) => {
                let (k, v) = item?;
                Ok(Some((be_u64(k.as_ref(), "anchor key")?, word8(&v, "anchor")?)))
            }
            None => Ok(None),
        }
    }

    /// The commitment-tree frontier at the committed head.
    pub fn tree(&self) -> Result<CommitmentTree> {
        let bytes = self.get_meta_raw(META_TREE)?.ok_or(StorageError::NotInitialized)?;
        Ok(bincode::deserialize(&bytes)?)
    }

    /// The bundle guest commitment this chain's genesis pinned.
    pub fn hc_bundle(&self) -> Result<Word8> {
        let bytes = self.get_meta_raw(META_HC_BUNDLE)?.ok_or(StorageError::NotInitialized)?;
        word8(&bytes, "hc_bundle meta")
    }

    pub fn validator(&self, a: &Address) -> Result<Option<ValidatorEntry>> {
        self.get(CF_VALIDATORS, a.as_bytes())
    }

    /// Every leaf in tree order. The witness source, and the check `load_ledger` runs the
    /// stored frontier against.
    fn leaves(&self) -> Result<Vec<Word8>> {
        let mut out = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_NOTES), IteratorMode::Start) {
            let (k, v) = item?;
            let index = be_u64(k.as_ref(), "note key")?;
            if index != out.len() as u64 {
                return Err(StorageError::Corrupt(format!("notes family has a gap at index {}", out.len())));
            }
            let row: NoteRow = bincode::deserialize(&v)?;
            out.push(row.cm);
        }
        Ok(out)
    }

    /// The Merkle witness of leaf `index` against the current root: `(root, siblings)` with the
    /// leaf level first, the layout the bundle guest's `MERKLE_VERIFY` reads. `None` past the
    /// end of the tree. Rebuilds a `FullTree` from `notes`, so it is `O(leaves)`.
    pub fn witness(&self, index: u64, executor: &dyn ConfidentialExecutor) -> Result<Option<(Word8, [Word8; DEPTH])>> {
        let leaves = self.leaves()?;
        if index >= leaves.len() as u64 {
            return Ok(None);
        }
        let tree = FullTree::new(leaves, executor);
        Ok(tree.path(index).map(|p| (tree.root(), p)))
    }

    pub fn genesis_hash(&self) -> Result<Hash> {
        let bytes = self.get_meta_raw(META_GENESIS_HASH)?.ok_or(StorageError::NotInitialized)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Corrupt("genesis_hash meta has wrong length".into()))?;
        Ok(Hash(arr))
    }

    pub fn chain_id(&self) -> Result<u64> {
        let bytes = self.get_meta_raw(META_CHAIN_ID)?.ok_or(StorageError::NotInitialized)?;
        be_u64(&bytes, "chain_id meta")
    }

    pub fn head(&self) -> Result<Head> {
        let bytes = self.get_meta_raw(META_HEAD_HEIGHT)?.ok_or(StorageError::NotInitialized)?;
        let height = be_u64(&bytes, "head_height meta")?;
        let block = self
            .block_by_height(height)?
            .ok_or_else(|| StorageError::Corrupt(format!("head block {height} missing")))?;
        Ok(Head { height, hash: block.hash() })
    }

    pub fn head_block(&self) -> Result<Block> {
        let head = self.head()?;
        self.block_by_height(head.height)?
            .ok_or_else(|| StorageError::Corrupt(format!("head block {} missing", head.height)))
    }

    pub fn head_qc(&self) -> Result<QuorumCertificate> {
        let head = self.head()?;
        self.qc_by_height(head.height)?
            .ok_or_else(|| StorageError::Corrupt(format!("head qc {} missing", head.height)))
    }

    pub fn block_by_height(&self, h: u64) -> Result<Option<Block>> {
        match self.db.get_cf(self.cf(CF_BLOCKS), height_key(h))? {
            Some(bytes) => Ok(Some(Block::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn qc_by_height(&self, h: u64) -> Result<Option<QuorumCertificate>> {
        self.get(CF_QCS, &height_key(h))
    }

    pub fn committed_block(&self, h: u64) -> Result<Option<CommittedBlock>> {
        let Some(block) = self.block_by_height(h)? else { return Ok(None) };
        let qc = self
            .qc_by_height(h)?
            .ok_or_else(|| StorageError::Corrupt(format!("qc for block {h} missing")))?;
        // Every call transaction has exactly one receipt; a missing one means
        // the receipts CF is damaged, and serving a short list would make
        // peers reject the batch and drop us as a sync source.
        let mut receipts = Vec::new();
        for tx in &block.transactions {
            match self.receipt(&tx.hash())? {
                Some(r) => receipts.push(r),
                None => {
                    if matches!(tx.action, Action::Call { .. }) {
                        return Err(StorageError::Corrupt(format!(
                            "receipt for call {} in block {h} missing",
                            tx.hash()
                        )));
                    }
                }
            }
        }
        Ok(Some(CommittedBlock { block, qc, receipts }))
    }

    pub fn height_by_hash(&self, h: &Hash) -> Result<Option<u64>> {
        match self.db.get_cf(self.cf(CF_BLOCK_INDEX), h.as_bytes())? {
            Some(bytes) => Ok(Some(be_u64(&bytes, "block_index value")?)),
            None => Ok(None),
        }
    }

    pub fn block_by_hash(&self, h: &Hash) -> Result<Option<Block>> {
        match self.height_by_hash(h)? {
            Some(height) => self.block_by_height(height),
            None => Ok(None),
        }
    }

    pub fn tx_location(&self, h: &Hash) -> Result<Option<(u64, u32)>> {
        self.get(CF_TXS, h.as_bytes())
    }

    pub fn program(&self, id: &ProgramId) -> Result<Option<ProgramRecord>> {
        self.get(CF_PROGRAMS, id.as_bytes())
    }

    pub fn programs_count(&self) -> Result<u64> {
        Ok(self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start).count() as u64)
    }

    pub fn receipt(&self, tx: &Hash) -> Result<Option<CallReceipt>> {
        self.get(CF_RECEIPTS, tx.as_bytes())
    }

    /// Rebuild the in-memory ledger from the note, nullifier, anchor, validator and program
    /// families plus the stored frontier.
    ///
    /// The frontier is checked against `executor` here rather than trusted: a tree written by a
    /// different hash function (a database carried over from another build, or a damaged blob)
    /// would otherwise be accepted and every anchor this node published afterwards would be one
    /// no other node recognises. Rebuilding a `FullTree` from the leaves is `O(leaves)` hashing,
    /// paid once at startup.
    ///
    /// The faucet and confidential switches come from genesis, not from storage, so the caller
    /// sets them afterwards.
    pub fn load_ledger(&self, executor: &dyn ConfidentialExecutor) -> Result<Ledger> {
        let chain_id = self.chain_id()?;
        let hc_bundle = self.hc_bundle()?;
        let tree = self.tree()?;

        let leaves = self.leaves()?;
        if tree.next_index() != leaves.len() as u64 {
            return Err(StorageError::Corrupt(format!(
                "stored tree has {} leaves but the notes family has {}",
                tree.next_index(),
                leaves.len()
            )));
        }
        // With no leaves the two sides of this are `CommitmentTree::empty_root(executor)`.
        let commitments: BTreeSet<Word8> = leaves.iter().copied().collect();
        let rebuilt = FullTree::new(leaves, executor).root();
        if rebuilt != tree.root() {
            return Err(StorageError::Corrupt(
                "stored commitment tree does not hash to the notes it claims to cover".into(),
            ));
        }

        let mut nullifiers = BTreeSet::new();
        for item in self.db.iterator_cf(self.cf(CF_NULLIFIERS), IteratorMode::Start) {
            let (k, _) = item?;
            nullifiers.insert(word8(k.as_ref(), "nullifier key")?);
        }
        // The window is the newest ANCHOR_WINDOW heights; the family may hold older rows if a
        // commit wrote more than a window's worth of blocks at once.
        let mut anchors: Vec<(u64, Word8)> = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_ANCHORS), IteratorMode::End) {
            if anchors.len() >= shrugg_core::ledger::ANCHOR_WINDOW {
                break;
            }
            let (k, v) = item?;
            anchors.push((be_u64(k.as_ref(), "anchor key")?, word8(&v, "anchor")?));
        }
        anchors.reverse();
        let mut validators = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_VALIDATORS), IteratorMode::Start) {
            let (k, v) = item?;
            let arr: [u8; 32] = k
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Corrupt("validator key has wrong length".into()))?;
            validators.insert(Address(arr), bincode::deserialize::<ValidatorEntry>(&v)?);
        }
        let mut programs = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start) {
            let (_, v) = item?;
            let rec: ProgramRecord = bincode::deserialize(&v)?;
            programs.insert(rec.id, rec);
        }
        Ok(Ledger::from_parts(chain_id, hc_bundle, tree, commitments, nullifiers, anchors, validators, programs))
    }

    /// Atomically append committed blocks and the state they produced.
    pub fn commit(&self, blocks: &[CommittedBlock], ledger_after: &Ledger) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let head = self.head()?;
        let first_height = head.height + 1;
        let mut expected_height = first_height;
        let mut expected_parent = head.hash;
        let mut next_index = self.notes_count()?;
        let mut proposers: BTreeSet<Address> = BTreeSet::new();
        let mut batch = WriteBatch::default();

        for cb in blocks {
            let block = &cb.block;
            let hash = block.hash();
            if block.height() != expected_height {
                return Err(StorageError::Corrupt(format!(
                    "non-contiguous commit: expected height {expected_height}, got {}",
                    block.height()
                )));
            }
            if block.parent() != expected_parent {
                return Err(StorageError::Corrupt(format!(
                    "block {} parent {} does not match head {expected_parent}",
                    block.height(),
                    block.parent()
                )));
            }
            if cb.qc.block_hash != hash {
                return Err(StorageError::Corrupt(format!(
                    "qc for block {} certifies {} not {hash}",
                    block.height(),
                    cb.qc.block_hash
                )));
            }
            let hk = height_key(block.height());
            batch.put_cf(self.cf(CF_BLOCKS), hk, block.encode());
            batch.put_cf(self.cf(CF_QCS), hk, bincode::serialize(&cb.qc)?);
            batch.put_cf(self.cf(CF_BLOCK_INDEX), hash.as_bytes(), hk);
            for (index, tx) in block.transactions.iter().enumerate() {
                batch.put_cf(
                    self.cf(CF_TXS),
                    tx.hash().as_bytes(),
                    bincode::serialize(&(block.height(), index as u32))?,
                );
                for nf in tx.nullifiers() {
                    batch.put_cf(self.cf(CF_NULLIFIERS), word8_to_bytes(&nf), hk);
                }
                for (cm, envelope) in created_notes(tx) {
                    let row = NoteRow { cm, envelope, height: block.height() };
                    batch.put_cf(self.cf(CF_NOTES), height_key(next_index), bincode::serialize(&row)?);
                    next_index += 1;
                }
            }
            for r in &cb.receipts {
                if r.height != block.height() {
                    return Err(StorageError::Corrupt(format!(
                        "receipt for block {} attached to block {}",
                        r.height,
                        block.height()
                    )));
                }
                batch.put_cf(self.cf(CF_RECEIPTS), r.tx.as_bytes(), bincode::serialize(r)?);
            }
            proposers.insert(block.proposer());
            expected_height += 1;
            expected_parent = hash;
        }
        let last_height = expected_height - 1;

        // The end-of-block root of every block this commit covers, as the ledger recorded it.
        // A batch longer than the anchor window drops its oldest entries, which is exactly what
        // `load_ledger` would discard anyway.
        for (h, root) in ledger_after.anchors() {
            if (first_height..=last_height).contains(h) {
                batch.put_cf(self.cf(CF_ANCHORS), height_key(*h), word8_to_bytes(root));
            }
        }
        if next_index != ledger_after.next_index() {
            return Err(StorageError::Corrupt(format!(
                "commit wrote {next_index} notes across heights {first_height}..={last_height} \
                 but `ledger_after` holds {}; the ledger does not describe exactly these blocks",
                ledger_after.next_index()
            )));
        }
        // Only a proposer's entry changes (it collects the block's fees); stakes are genesis
        // state until phase S2 puts bonding on chain.
        for addr in &proposers {
            let entry = ledger_after.validators().get(addr).ok_or_else(|| {
                StorageError::Corrupt(format!("committed block proposer {addr} is not in the validator register"))
            })?;
            batch.put_cf(self.cf(CF_VALIDATORS), addr.as_bytes(), bincode::serialize(entry)?);
        }
        for rec in ledger_after.programs().values() {
            if rec.deployed_at >= first_height {
                batch.put_cf(self.cf(CF_PROGRAMS), rec.id.as_bytes(), bincode::serialize(rec)?);
            }
        }
        batch.put_cf(self.cf(CF_META), META_TREE, bincode::serialize(ledger_after.tree())?);
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(last_height));
        self.db.write_opt(batch, &sync_opts())?;
        Ok(())
    }

    /// Persist consensus safety state with fsync; must complete before a vote is sent.
    pub fn save_safety(&self, s: &SafetyState) -> Result<()> {
        self.db
            .put_cf_opt(self.cf(CF_META), META_SAFETY, bincode::serialize(s)?, &sync_opts())?;
        Ok(())
    }

    pub fn load_safety(&self) -> Result<Option<SafetyState>> {
        self.get(CF_META, META_SAFETY.as_bytes())
    }
}

/// How much of the chain to verify at startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    /// Skip verification.
    Off,
    /// Structural checks on every block (hash links, indexes, QC/block match,
    /// tx roots) plus a full ledger replay against every header's state root.
    /// Bundle proofs are re-verified; QC votes are not.
    Quick,
    /// `Quick` plus every QC's votes.
    Full,
}

impl std::str::FromStr for VerifyMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "off" => Ok(VerifyMode::Off),
            "quick" => Ok(VerifyMode::Quick),
            "full" => Ok(VerifyMode::Full),
            other => Err(format!("unknown verify mode {other} (off|quick|full)")),
        }
    }
}

/// Result of `verify_chain`.
#[derive(Debug)]
pub struct ChainCheck {
    /// Head height according to metadata.
    pub head: u64,
    /// Highest height such that blocks 0..=last_good are all consistent.
    pub last_good: u64,
    /// First problem found, if any.
    pub problem: Option<String>,
    /// Ledger state after replaying blocks 0..=last_good.
    pub ledger: Ledger,
    /// False if even the genesis block is damaged.
    pub genesis_ok: bool,
}

impl ChainCheck {
    pub fn is_ok(&self) -> bool {
        self.problem.is_none()
    }
}

impl Storage {
    /// Walk the committed chain from genesis and check it against itself and
    /// the genesis state. Stops at the first inconsistency and reports the
    /// last good height so the caller can `truncate_to` it and resync the rest
    /// from peers.
    pub fn verify_chain(&self, gs: &GenesisState, mode: VerifyMode, executor: &dyn ConfidentialExecutor) -> Result<ChainCheck> {
        let head = match self.get_meta_raw(META_HEAD_HEIGHT)? {
            Some(b) if b.len() == 8 => u64::from_be_bytes(b.as_slice().try_into().unwrap()),
            _ => 0,
        };
        let mut ledger = gs.ledger.clone();
        let mut check = ChainCheck { head, last_good: 0, problem: None, ledger: ledger.clone(), genesis_ok: true };

        // Genesis block must be byte-for-byte what the genesis file derives.
        match self.block_by_height(0) {
            Ok(Some(b)) if b.hash() == gs.hash() => {}
            Ok(Some(b)) => {
                check.genesis_ok = false;
                check.problem = Some(format!("genesis block hash {} != expected {}", b.hash(), gs.hash()));
                return Ok(check);
            }
            Ok(None) => {
                check.genesis_ok = false;
                check.problem = Some("genesis block missing".into());
                return Ok(check);
            }
            Err(e) => {
                check.genesis_ok = false;
                check.problem = Some(format!("genesis block unreadable: {e}"));
                return Ok(check);
            }
        }
        if mode == VerifyMode::Off {
            check.last_good = head;
            check.ledger = self.load_ledger(executor)?;
            return Ok(check);
        }

        let mut prev_hash = gs.hash();
        for h in 1..=head {
            let problem = (|| -> std::result::Result<(), String> {
                let block = self
                    .block_by_height(h)
                    .map_err(|e| format!("block {h} unreadable: {e}"))?
                    .ok_or_else(|| format!("block {h} missing"))?;
                if block.height() != h {
                    return Err(format!("block at height {h} claims height {}", block.height()));
                }
                if block.parent() != prev_hash {
                    return Err(format!("block {h} parent {} != previous hash {}", block.parent(), prev_hash));
                }
                let hash = block.hash();
                match self.height_by_hash(&hash) {
                    Ok(Some(idx)) if idx == h => {}
                    Ok(other) => return Err(format!("block {h} index points to {other:?}")),
                    Err(e) => return Err(format!("block {h} index unreadable: {e}")),
                }
                let qc = self
                    .qc_by_height(h)
                    .map_err(|e| format!("qc {h} unreadable: {e}"))?
                    .ok_or_else(|| format!("qc {h} missing"))?;
                if qc.block_hash != hash || qc.view != block.view() {
                    return Err(format!("qc {h} does not certify block {h}"));
                }
                if block.proposer() != gs.validators.leader(block.view()) {
                    return Err(format!("block {h} proposer is not the leader of view {}", block.view()));
                }
                if mode == VerifyMode::Full && !qc.verify(&gs.validators, &gs.hash()) {
                    return Err(format!("qc {h} has invalid or insufficient votes"));
                }
                for (i, tx) in block.transactions.iter().enumerate() {
                    match self.tx_location(&tx.hash()) {
                        Ok(Some((bh, bi))) if bh == h && bi == i as u32 => {}
                        Ok(other) => return Err(format!("tx {} in block {h} indexed as {other:?}", tx.hash())),
                        Err(e) => return Err(format!("tx index unreadable at block {h}: {e}")),
                    }
                }
                // Re-execute. `apply_block` is the consensus rule itself — proposer signature,
                // tx root, every transaction including its bundle proof, the end-of-block
                // anchor and the header's state root — so the replay cannot drift from it.
                let mut next = ledger.clone();
                let receipts = next
                    .apply_block(&block, executor)
                    .map_err(|e| format!("block {h} does not apply: {e}"))?;
                for r in &receipts {
                    match self.receipt(&r.tx) {
                        Ok(Some(stored)) if stored == *r => {}
                        Ok(_) => return Err(format!("receipt for tx {} in block {h} missing or wrong", r.tx)),
                        Err(e) => return Err(format!("receipt unreadable at block {h}: {e}")),
                    }
                }
                ledger = next;
                prev_hash = hash;
                Ok(())
            })();
            if let Err(p) = problem {
                check.problem = Some(p);
                check.last_good = h - 1;
                check.ledger = ledger;
                return Ok(check);
            }
        }
        check.last_good = head;
        // The snapshot families must match the replayed chain. `Ledger`'s equality covers the
        // tree, the commitment and nullifier sets, the anchors, the validators and the programs
        // — everything these families hold.
        match self.load_ledger(executor) {
            Ok(stored) if stored == ledger => {}
            Ok(_) => check.problem = Some("state snapshot does not match replayed chain".into()),
            Err(e) => check.problem = Some(format!("state snapshot unreadable: {e}")),
        }
        check.ledger = ledger;
        Ok(check)
    }

    /// Drop everything above `height`, rewrite the state snapshot from `ledger` (the replayed
    /// state at `height`), and reset the head. With `height == 0` the genesis block and
    /// certificate are rewritten too, which is the only repair for a damaged genesis — hence
    /// `gs`. Safety state is preserved. One fsynced batch.
    pub fn truncate_to(&self, gs: &GenesisState, height: u64, ledger: &Ledger) -> Result<()> {
        let head = match self.get_meta_raw(META_HEAD_HEIGHT)? {
            Some(b) if b.len() == 8 => u64::from_be_bytes(b.as_slice().try_into().unwrap()),
            _ => 0,
        };
        let mut batch = WriteBatch::default();
        for h in (height + 1)..=head.max(height + 1) {
            let hk = height_key(h);
            if let Ok(Some(block)) = self.block_by_height(h) {
                batch.delete_cf(self.cf(CF_BLOCK_INDEX), block.hash().as_bytes());
                for tx in &block.transactions {
                    batch.delete_cf(self.cf(CF_TXS), tx.hash().as_bytes());
                }
            }
            batch.delete_cf(self.cf(CF_BLOCKS), hk);
            batch.delete_cf(self.cf(CF_QCS), hk);
        }
        // Also drop any index entries that point above `height` (blocks we could not decode).
        for item in self.db.iterator_cf(self.cf(CF_BLOCK_INDEX), IteratorMode::Start) {
            let (k, v) = item?;
            if v.len() == 8 && u64::from_be_bytes(v.as_ref().try_into().unwrap()) > height {
                batch.delete_cf(self.cf(CF_BLOCK_INDEX), k);
            }
        }
        // Notes are append-only and indexed by leaf position, so rewinding the tree is exactly
        // dropping the leaves the replayed ledger no longer has.
        for item in self.db.iterator_cf(self.cf(CF_NOTES), IteratorMode::End) {
            let (k, _) = item?;
            if be_u64(k.as_ref(), "note key")? < ledger.next_index() {
                break;
            }
            batch.delete_cf(self.cf(CF_NOTES), k);
        }
        for item in self.db.iterator_cf(self.cf(CF_NULLIFIERS), IteratorMode::Start) {
            let (k, v) = item?;
            if be_u64(&v, "nullifier height")? > height {
                batch.delete_cf(self.cf(CF_NULLIFIERS), k);
            }
        }
        // The anchor window is rewritten wholesale from the replayed ledger: truncating can
        // shrink it below `ANCHOR_WINDOW`, and a stale row above `height` would let a prover
        // anchor to a root this chain no longer passes through.
        for item in self.db.iterator_cf(self.cf(CF_ANCHORS), IteratorMode::Start) {
            let (k, _) = item?;
            batch.delete_cf(self.cf(CF_ANCHORS), k);
        }
        for (h, root) in ledger.anchors() {
            batch.put_cf(self.cf(CF_ANCHORS), height_key(*h), word8_to_bytes(root));
        }
        for item in self.db.iterator_cf(self.cf(CF_VALIDATORS), IteratorMode::Start) {
            let (k, _) = item?;
            batch.delete_cf(self.cf(CF_VALIDATORS), k);
        }
        for (addr, entry) in ledger.validators() {
            batch.put_cf(self.cf(CF_VALIDATORS), addr.as_bytes(), bincode::serialize(entry)?);
        }
        for item in self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start) {
            let (k, _) = item?;
            batch.delete_cf(self.cf(CF_PROGRAMS), k);
        }
        for rec in ledger.programs().values() {
            batch.put_cf(self.cf(CF_PROGRAMS), rec.id.as_bytes(), bincode::serialize(rec)?);
        }
        for item in self.db.iterator_cf(self.cf(CF_RECEIPTS), IteratorMode::Start) {
            let (k, v) = item?;
            let keep = bincode::deserialize::<CallReceipt>(&v).map(|r| r.height <= height).unwrap_or(false);
            if !keep {
                batch.delete_cf(self.cf(CF_RECEIPTS), k);
            }
        }
        batch.put_cf(self.cf(CF_META), META_TREE, bincode::serialize(ledger.tree())?);
        if height == 0 {
            let hk = height_key(0);
            batch.put_cf(self.cf(CF_BLOCKS), hk, gs.block.encode());
            batch.put_cf(self.cf(CF_QCS), hk, bincode::serialize(&QuorumCertificate::genesis(gs.hash()))?);
            batch.put_cf(self.cf(CF_BLOCK_INDEX), gs.hash().as_bytes(), hk);
            batch.put_cf(self.cf(CF_META), META_GENESIS_HASH, gs.hash().as_bytes());
            batch.put_cf(self.cf(CF_META), META_CHAIN_ID, gs.chain_id.to_be_bytes());
            batch.put_cf(self.cf(CF_META), META_HC_BUNDLE, word8_to_bytes(&gs.hc_bundle));
        }
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(height));
        self.db.write_opt(batch, &sync_opts())?;
        Ok(())
    }

    /// Test hook: overwrite the raw bytes stored for a block height to simulate
    /// on-disk corruption. Never called by the node itself.
    pub fn overwrite_block_bytes_for_testing(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.db.put_cf(self.cf(CF_BLOCKS), height_key(height), bytes)?;
        Ok(())
    }

    /// Test hook: overwrite a validator entry to simulate snapshot corruption.
    pub fn overwrite_validator_for_testing(&self, addr: &Address, entry: &ValidatorEntry) -> Result<()> {
        self.db.put_cf(self.cf(CF_VALIDATORS), addr.as_bytes(), bincode::serialize(entry)?)?;
        Ok(())
    }
}

/// Fixtures shared by the storage tests and the RPC tests, which need a database holding a real
/// shielded chain to answer against. Everything here is built with `StubExecutor`, whose bundle
/// "proof" is the digest it publishes: these tests are about storage, not about the zkVM.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisValidator};
    use shrugg_core::notes::{word8_to_hex, Bundle};
    use shrugg_core::{gas, BlockHeader, Keypair, Transaction};

    /// The bundle guest commitment the fixture chains pin. Arbitrary: `StubExecutor` checks a
    /// proof carries it, nothing more.
    pub(crate) const HC: Word8 = [11; 8];

    pub(crate) fn key(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    pub(crate) fn env(tag: u8) -> Envelope {
        Envelope { kem_ct: vec![tag; 8], to_receiver: vec![tag; 4], to_sender: vec![], body: vec![tag; 16] }
    }

    pub(crate) fn alloc_note(seed: u8, amount: u64) -> GenesisNote {
        GenesisNote {
            cm: word8_to_hex(&[seed as u32; 8]),
            envelope: EnvelopeHex::from_envelope(&env(seed)),
            amount,
        }
    }

    pub(crate) fn genesis_with(chain_id: u64, alloc: Vec<GenesisNote>) -> GenesisState {
        let k = key(1);
        Genesis {
            chain_id,
            timestamp_ms: 0,
            validators: vec![GenesisValidator { public_key: k.public_key().clone(), stake: 10, payout: None }],
            alloc,
            faucet: true,
            confidential: true,
            fri_profile: "test".into(),
            hc_bundle: word8_to_hex(&HC),
            bridge: None,
            epoch_blocks: shrugg_core::genesis::EPOCH_BLOCKS_DEFAULT,
        }
        .build(&StubExecutor)
        .unwrap()
    }

    /// A chain with no alloc notes: the empty tree.
    pub(crate) fn genesis(chain_id: u64) -> GenesisState {
        genesis_with(chain_id, Vec::new())
    }

    /// An unopened database plus a genesis holding two deposit notes.
    pub(crate) fn genesis_with_two_notes() -> (tempfile::TempDir, Storage, GenesisState) {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)]);
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        (dir, s, gs)
    }

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes, anchored to
    /// the newest root `ledger` has recorded and timed at its current height.
    pub(crate) fn bundle_tx(ledger: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Transaction {
        let mut b = Bundle {
            anchor: ledger.anchors().back().expect("a ledger always has an anchor").1,
            nullifiers: nfs,
            commitments: cms,
            fee,
            burn: 0,
            asset: 0,
            time: ledger.height() as u32,
            envelopes: [env(cms[0][0] as u8), env(cms[1][0] as u8)],
            proof: Vec::new(),
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        Transaction::shielded(ledger.chain_id(), b, Action::None)
    }

    /// A faucet mint of `amount` to a note nobody can open; the envelope is a placeholder, which
    /// the chain never inspects.
    pub(crate) fn mint_tx(chain_id: u64, cm: Word8, amount: u64, minter: &Keypair) -> Transaction {
        Transaction::mint(chain_id, cm, env(cm[0] as u8), amount, minter)
    }

    pub(crate) fn bundle_fee() -> u64 {
        gas::BUNDLE_BASE
    }

    /// Apply `txs` to `ledger` as block `parent.height() + 1` and build the committed block that
    /// results, exactly as `Ledger::apply_block` would accept it.
    pub(crate) fn make_block(parent: &Block, ledger: &mut Ledger, txs: Vec<Transaction>, k: &Keypair) -> CommittedBlock {
        let height = parent.height() + 1;
        ledger.set_height(height);
        ledger.set_timestamp_ms(height);
        ledger.apply_transactions(&txs, &k.address(), &StubExecutor).unwrap();
        ledger.record_anchor(height);
        make_block_unchecked(parent, ledger, txs, k)
    }

    /// `make_block` without executing the transactions: the only way to build a block carrying a
    /// transaction the ledger would have rejected, which is what a torn block on disk looks like.
    pub(crate) fn make_block_unchecked(parent: &Block, ledger: &Ledger, txs: Vec<Transaction>, k: &Keypair) -> CommittedBlock {
        let height = parent.height() + 1;
        let header = BlockHeader {
            height,
            view: parent.view() + 1,
            parent: parent.hash(),
            proposer: k.public_key().clone(),
            timestamp_ms: height,
            tx_root: Block::tx_root(&txs),
            state_root: ledger.state_root(),
            justify: QuorumCertificate { view: parent.view(), block_hash: parent.hash(), votes: vec![] },
        };
        let block = Block::sign(header, txs, k);
        let qc = QuorumCertificate { view: block.view(), block_hash: block.hash(), votes: vec![] };
        CommittedBlock { block, qc, receipts: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::ledger::ANCHOR_WINDOW;
    use shrugg_core::Transaction;

    /// Fold a witness back to the root, the way the bundle guest's `MERKLE_VERIFY` does.
    fn fold(leaf: Word8, index: u64, path: &[Word8; DEPTH]) -> Word8 {
        let mut node = leaf;
        let mut pos = index;
        for sib in path {
            node = if pos & 1 == 0 { StubExecutor.node_hash(&node, sib) } else { StubExecutor.node_hash(sib, &node) };
            pos >>= 1;
        }
        node
    }

    #[test]
    fn genesis_notes_land_in_the_notes_family_and_the_tree_reloads() {
        let (dir, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        assert_eq!(s.notes_count().unwrap(), 2);
        let row = s.note(1).unwrap().unwrap();
        assert_eq!(row.cm, gs.notes[1].0);
        assert_eq!(row.envelope, gs.notes[1].1);
        assert_eq!(row.height, 0);
        assert_eq!(s.note(2).unwrap(), None);
        assert_eq!(&s.tree().unwrap(), gs.ledger.tree());
        assert_eq!(s.anchor(0).unwrap(), Some(gs.ledger.root()));
        assert_eq!(s.latest_anchor().unwrap(), Some((0, gs.ledger.root())));
        assert_eq!(s.hc_bundle().unwrap(), gs.hc_bundle);
        let l = s.load_ledger(&StubExecutor).unwrap();
        assert_eq!(l, gs.ledger);
        // Paging is in tree order and stops at the end.
        let page = s.notes_from(0, 10).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].0, 0);
        assert_eq!(page[1].1.cm, gs.notes[1].0);
        assert_eq!(s.notes_from(1, 10).unwrap().len(), 1);
        assert_eq!(s.notes_from(0, 1).unwrap().len(), 1);
        assert!(s.notes_from(2, 10).unwrap().is_empty());
        drop(dir);
    }

    /// A chain that starts with no notes still round trips: the stored frontier is the empty
    /// tree and `load_ledger` checks it against `CommitmentTree::empty_root`.
    #[test]
    fn an_empty_chain_reloads_to_the_empty_tree() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis(3);
        s.init_genesis(&gs).unwrap();
        assert_eq!(s.notes_count().unwrap(), 0);
        assert_eq!(s.tree().unwrap().root(), CommitmentTree::empty_root(&StubExecutor));
        assert_eq!(s.load_ledger(&StubExecutor).unwrap(), gs.ledger);
        assert!(s.witness(0, &StubExecutor).unwrap().is_none());
    }

    #[test]
    fn init_and_reopen_preserves_meta() {
        let dir = tempfile::tempdir().unwrap();
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        {
            let s = Storage::open(dir.path()).unwrap();
            assert!(!s.is_initialized().unwrap());
            assert!(matches!(s.head(), Err(StorageError::NotInitialized)));
            s.init_genesis(&gs).unwrap();
            assert!(s.is_initialized().unwrap());
        }
        let s = Storage::open(dir.path()).unwrap();
        assert_eq!(s.genesis_hash().unwrap(), gs.hash());
        assert_eq!(s.chain_id().unwrap(), 7);
        assert_eq!(s.head().unwrap(), Head { height: 0, hash: gs.hash() });
        assert_eq!(s.head_block().unwrap().hash(), gs.hash());
        assert_eq!(s.head_qc().unwrap(), QuorumCertificate::genesis(gs.hash()));
        assert_eq!(s.height_by_hash(&gs.hash()).unwrap(), Some(0));
        assert_eq!(s.validator(&key(1).address()).unwrap().unwrap().stake, 10);
        assert_eq!(s.load_ledger(&StubExecutor).unwrap(), gs.ledger);
        assert_eq!(s.load_safety().unwrap(), None);
    }

    #[test]
    fn double_init_same_ok_different_errors() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis(1);
        s.init_genesis(&gs).unwrap();
        s.init_genesis(&gs).unwrap();
        let other = genesis(2);
        match s.init_genesis(&other) {
            Err(StorageError::AlreadyInitialized { existing }) => assert_eq!(existing, gs.hash()),
            r => panic!("expected AlreadyInitialized, got {r:?}"),
        }
        assert_eq!(s.chain_id().unwrap(), 1);
    }

    /// One committed block carrying one bundle: two notes appended, two nullifiers recorded,
    /// the block's end root anchored, the proposer paid, and the whole thing reloads.
    #[test]
    fn commit_writes_notes_nullifiers_anchors_and_rewards_and_reloads_equal() {
        let (_d, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        let proposer = key(1);
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);
        let tx = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![tx.clone()], &proposer);
        s.commit(std::slice::from_ref(&b1), &ledger).unwrap();

        assert_eq!(s.head().unwrap(), Head { height: 1, hash: b1.block.hash() });
        assert_eq!(s.notes_count().unwrap(), 4);
        assert_eq!(s.note(2).unwrap().unwrap().cm, [3; 8]);
        assert_eq!(s.note(3).unwrap().unwrap(), NoteRow { cm: [4; 8], envelope: env(4), height: 1 });
        assert_eq!(s.nullifier_height(&[1; 8]).unwrap(), Some(1));
        assert_eq!(s.nullifier_height(&[2; 8]).unwrap(), Some(1));
        assert_eq!(s.nullifier_height(&[9; 8]).unwrap(), None);
        assert_eq!(s.nullifiers_count().unwrap(), 2);
        assert_eq!(s.nullifiers_from(0, 10).unwrap(), vec![(1, [1; 8]), (1, [2; 8])]);
        assert_eq!(s.anchor(1).unwrap(), Some(ledger.root()));
        assert_eq!(s.validator(&proposer.address()).unwrap().unwrap().rewards, bundle_fee());
        assert_eq!(s.tx_location(&tx.hash()).unwrap(), Some((1, 0)));
        assert_eq!(s.committed_block(1).unwrap().unwrap(), b1);

        let reloaded = s.load_ledger(&StubExecutor).unwrap();
        assert_eq!(reloaded, ledger);
        assert_eq!(reloaded.state_root(), ledger.state_root());
        assert!(s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().is_ok());
    }

    /// A faucet mint creates its note through the action rather than a bundle slot, and the row
    /// that lands carries the mint's own envelope.
    #[test]
    fn a_committed_mint_appends_its_note() {
        let (_d, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        let minter = key(1);
        let mut ledger = gs.ledger.clone();
        let tx = mint_tx(gs.chain_id, [77; 8], 5_000, &minter);
        let b1 = make_block(&gs.block, &mut ledger, vec![tx.clone()], &minter);
        s.commit(std::slice::from_ref(&b1), &ledger).unwrap();
        assert_eq!(s.notes_count().unwrap(), 3);
        assert_eq!(s.note(2).unwrap().unwrap(), NoteRow { cm: [77; 8], envelope: env(77), height: 1 });
        // A mint spends nothing and pays no fee.
        assert_eq!(s.nullifiers_count().unwrap(), 0);
        assert_eq!(s.validator(&minter.address()).unwrap().unwrap().rewards, 0);
        assert_eq!(s.load_ledger(&StubExecutor).unwrap(), ledger);
    }

    #[test]
    fn witness_paths_verify_against_the_current_root() {
        let (_d, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        let proposer = key(1);
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);
        let tx = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![tx], &proposer);
        s.commit(std::slice::from_ref(&b1), &ledger).unwrap();

        for index in 0..4 {
            let (root, path) = s.witness(index, &StubExecutor).unwrap().expect("leaf exists");
            assert_eq!(root, ledger.root(), "witness root at {index}");
            let leaf = s.note(index).unwrap().unwrap().cm;
            assert_eq!(fold(leaf, index, &path), root, "path at {index}");
        }
        assert_eq!(s.witness(4, &StubExecutor).unwrap(), None);
    }

    #[test]
    fn truncate_rewinds_notes_nullifiers_anchors_and_the_tree() {
        let (_d, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        let proposer = key(1);
        let mut ledger = gs.ledger.clone();
        // A real vote on each certificate, so the `VerifyMode::Full` check at the end of this
        // test is actually checking something: `make_block`'s placeholder QC carries no votes
        // and would fail the quorum check for reasons that have nothing to do with truncation.
        let certify = |cb: CommittedBlock| {
            let qc = QuorumCertificate {
                view: cb.block.view(),
                block_hash: cb.block.hash(),
                votes: vec![shrugg_core::Vote::sign(cb.block.view(), cb.block.hash(), &key(1))],
            };
            CommittedBlock { qc, ..cb }
        };
        ledger.set_height(1);
        let tx1 = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let b1 = certify(make_block(&gs.block, &mut ledger, vec![tx1], &proposer));
        s.commit(std::slice::from_ref(&b1), &ledger).unwrap();
        let ledger_at_1 = ledger.clone();

        ledger.set_height(2);
        let tx2 = bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee());
        let b2 = certify(make_block(&b1.block, &mut ledger, vec![tx2.clone()], &proposer));
        s.commit(std::slice::from_ref(&b2), &ledger).unwrap();
        assert_eq!(s.notes_count().unwrap(), 6);
        assert_eq!(s.nullifier_height(&[5; 8]).unwrap(), Some(2));

        s.truncate_to(&gs, 1, &ledger_at_1).unwrap();
        assert_eq!(s.head().unwrap().height, 1);
        assert_eq!(s.notes_count().unwrap(), ledger_at_1.next_index());
        assert_eq!(s.notes_count().unwrap(), 4);
        assert_eq!(s.note(4).unwrap(), None);
        assert_eq!(s.nullifier_height(&[5; 8]).unwrap(), None);
        assert_eq!(s.nullifier_height(&[1; 8]).unwrap(), Some(1));
        assert_eq!(s.anchor(2).unwrap(), None);
        assert_eq!(s.anchor(1).unwrap(), Some(ledger_at_1.root()));
        assert_eq!(&s.tree().unwrap(), ledger_at_1.tree());
        assert_eq!(s.load_ledger(&StubExecutor).unwrap(), ledger_at_1);
        assert!(s.tx_location(&tx2.hash()).unwrap().is_none());
        assert_eq!(s.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().problem, None);
    }

    #[test]
    fn non_contiguous_commit_rejected() {
        let (_d, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        let k = key(1);
        let mut ledger = gs.ledger.clone();
        let b1 = make_block(&gs.block, &mut ledger, vec![], &k);
        let b2 = make_block(&b1.block, &mut ledger, vec![], &k);
        assert!(matches!(s.commit(std::slice::from_ref(&b2), &ledger), Err(StorageError::Corrupt(_))));
        assert_eq!(s.head().unwrap().height, 0);
        let mut bad = b1.clone();
        bad.qc.block_hash = Hash::ZERO;
        assert!(matches!(s.commit(&[bad], &ledger), Err(StorageError::Corrupt(_))));
        s.commit(&[b1, b2], &ledger).unwrap();
        assert_eq!(s.head().unwrap().height, 2);
    }

    /// Two blocks in one `commit`, against the ledger that describes both.
    ///
    /// This is the shape `Node::handle_actions` produces when a replica resolves a run of
    /// orphans and commits in one step, and the shape that was silently writing the wrong
    /// snapshot before: `hs.committed_ledger()` is the state after the *last* block of the
    /// batch, so every per-height thing the batch writes — anchors above all — has to be taken
    /// from the right place rather than from that final ledger's tip.
    #[test]
    fn a_two_block_commit_records_each_height_from_the_right_state() {
        let (_d, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        let k = key(1);
        let mut ledger = gs.ledger.clone();

        // Block 1: a bundle (2 commitments, 2 nullifiers). Block 2: a mint (1 commitment).
        ledger.set_height(1);
        let tx1 = bundle_tx(&ledger, [[41; 8], [42; 8]], [[43; 8], [44; 8]], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![tx1], &k);
        let root_at_1 = ledger.root();
        let tx2 = mint_tx(gs.chain_id, [45; 8], 7, &k);
        let b2 = make_block(&b1.block, &mut ledger, vec![tx2], &k);
        let root_at_2 = ledger.root();
        assert_ne!(root_at_1, root_at_2, "each block moved the tree");

        // One commit, both blocks, the ledger after block 2 — exactly what the node does.
        s.commit(&[b1.clone(), b2.clone()], &ledger).unwrap();
        assert_eq!(s.head().unwrap().height, 2);

        // Each height's anchor is that height's own end-of-block root, not the batch's last.
        assert_eq!(s.anchor(0).unwrap(), Some(gs.ledger.root()));
        assert_eq!(s.anchor(1).unwrap(), Some(root_at_1));
        assert_eq!(s.anchor(2).unwrap(), Some(root_at_2));
        assert_eq!(s.anchor(3).unwrap(), None);

        // Two genesis notes, then the bundle's two outputs, then the mint's note — dense, in
        // order, each stamped with the height that created it.
        assert_eq!(s.notes_count().unwrap(), 5);
        assert_eq!(s.notes_count().unwrap(), ledger.next_index());
        for (index, (cm, height)) in
            [([20; 8], 0), ([21; 8], 0), ([43; 8], 1), ([44; 8], 1), ([45; 8], 2)].into_iter().enumerate()
        {
            let row = s.note(index as u64).unwrap().unwrap_or_else(|| panic!("note {index} missing"));
            assert_eq!(row.cm, cm, "note {index} commitment");
            assert_eq!(row.height, height, "note {index} height");
        }
        assert_eq!(s.note(5).unwrap(), None);

        // Nullifiers carry the height that spent them.
        assert_eq!(s.nullifier_height(&[41; 8]).unwrap(), Some(1));
        assert_eq!(s.nullifier_height(&[42; 8]).unwrap(), Some(1));
        assert_eq!(s.nullifiers_count().unwrap(), 2);

        // And the whole snapshot reloads to exactly the ledger the batch was committed against.
        let reloaded = s.load_ledger(&StubExecutor).unwrap();
        assert_eq!(reloaded, ledger);
        assert_eq!(reloaded.state_root(), ledger.state_root());
        assert!(s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().is_ok());
    }

    #[test]
    fn safety_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis(1);
        s.init_genesis(&gs).unwrap();
        let state = SafetyState {
            view: 9,
            high_qc: QuorumCertificate::genesis(gs.hash()),
            locked_qc: QuorumCertificate::genesis(gs.hash()),
            last_voted_view: 8,
        };
        s.save_safety(&state).unwrap();
        assert_eq!(s.load_safety().unwrap(), Some(state));
    }

    /// `n` blocks, each carrying one bundle that spends a fresh pair of nullifiers.
    fn chain_fixture(n: u64) -> (tempfile::TempDir, Storage, GenesisState, Vec<CommittedBlock>) {
        use shrugg_core::Vote;
        let (dir, st, gs) = genesis_with_two_notes();
        st.init_genesis(&gs).unwrap();
        let k = key(1);
        let mut ledger = gs.ledger.clone();
        let mut parent = gs.block.clone();
        let mut out = Vec::new();
        for h in 1..=n {
            let seed = (h * 4) as u32;
            ledger.set_height(h);
            let txs = vec![bundle_tx(
                &ledger,
                [[seed; 8], [seed + 1; 8]],
                [[seed + 2; 8], [seed + 3; 8]],
                bundle_fee(),
            )];
            let cb = make_block(&parent, &mut ledger, txs, &k);
            let block = cb.block.clone();
            let qc = QuorumCertificate { view: block.view(), block_hash: block.hash(), votes: vec![Vote::sign(block.view(), block.hash(), &k)] };
            let cb = CommittedBlock { qc, ..cb };
            st.commit(std::slice::from_ref(&cb), &ledger).unwrap();
            out.push(cb);
            parent = block;
        }
        (dir, st, gs, out)
    }

    #[test]
    fn verify_chain_accepts_a_good_chain_in_both_modes() {
        let (_d, st, gs, _) = chain_fixture(6);
        for mode in [VerifyMode::Quick, VerifyMode::Full] {
            let c = st.verify_chain(&gs, mode, &StubExecutor).unwrap();
            assert!(c.is_ok(), "{:?}", c.problem);
            assert_eq!(c.last_good, 6);
            assert_eq!(c.ledger.state_root(), st.load_ledger(&StubExecutor).unwrap().state_root());
            assert_eq!(c.ledger.next_index(), 14, "2 alloc notes + 2 per block");
        }
    }

    #[test]
    fn corrupted_block_is_detected_and_truncated() {
        let (_d, st, gs, blocks) = chain_fixture(6);
        st.overwrite_block_bytes_for_testing(4, b"garbage").unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!c.is_ok());
        assert_eq!(c.last_good, 3);
        assert!(c.genesis_ok);
        st.truncate_to(&gs, c.last_good, &c.ledger).unwrap();
        assert_eq!(st.head().unwrap().height, 3);
        assert!(st.block_by_height(4).unwrap().is_none());
        assert!(st.block_by_hash(&blocks[4].block.hash()).unwrap().is_none());
        assert!(st.tx_location(&blocks[5].block.transactions[0].hash()).unwrap().is_none());
        assert!(st.tx_location(&blocks[2].block.transactions[0].hash()).unwrap().is_some());
        // The pool rewound with the chain: 2 alloc notes plus 2 per surviving block.
        assert_eq!(st.notes_count().unwrap(), 8);
        assert_eq!(st.nullifiers_count().unwrap(), 6);
        let again = st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap();
        assert!(again.is_ok(), "{:?}", again.problem);
        assert_eq!(again.last_good, 3);
        // Chain can be re-extended from the truncated head.
        let mut ledger = again.ledger.clone();
        let cb = &blocks[3]; // height 4 again
        ledger.apply_block(&cb.block, &StubExecutor).unwrap();
        st.commit(std::slice::from_ref(cb), &ledger).unwrap();
        assert_eq!(st.head().unwrap().height, 4);
        assert!(st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().is_ok());
    }

    #[test]
    fn swapped_block_with_wrong_parent_is_detected() {
        let (_d, st, gs, blocks) = chain_fixture(5);
        // Put block 2's bytes at height 3: decodes fine, but height/parent are wrong.
        st.overwrite_block_bytes_for_testing(3, &blocks[1].block.encode()).unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert_eq!(c.last_good, 2);
        assert!(c.problem.unwrap().contains("block at height 3"));
    }

    #[test]
    fn validator_snapshot_corruption_is_detected_and_repaired() {
        let (_d, st, gs, _) = chain_fixture(3);
        let addr = key(1).address();
        let good = st.validator(&addr).unwrap().unwrap();
        st.overwrite_validator_for_testing(&addr, &ValidatorEntry { rewards: 99, ..good.clone() }).unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!c.is_ok());
        assert_eq!(c.last_good, 3, "blocks are fine, only the snapshot is wrong");
        st.truncate_to(&gs, 3, &c.ledger).unwrap();
        assert_eq!(st.validator(&addr).unwrap().unwrap(), good);
        assert!(st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().is_ok());
    }

    /// The tree meta is the one piece of consensus state the families do not re-derive, so a
    /// damaged frontier must be caught rather than believed.
    #[test]
    fn a_frontier_that_does_not_match_the_notes_is_corrupt() {
        let (_d, st, gs, _) = chain_fixture(2);
        let other = genesis_with(7, vec![alloc_note(30, 1)]);
        st.db
            .put_cf(st.cf(CF_META), META_TREE, bincode::serialize(other.ledger.tree()).unwrap())
            .unwrap();
        match st.load_ledger(&StubExecutor) {
            Err(StorageError::Corrupt(m)) => assert!(m.contains("leaves"), "{m}"),
            other => panic!("expected Corrupt, got {other:?}"),
        }
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!c.is_ok());
        st.truncate_to(&gs, 2, &c.ledger).unwrap();
        assert!(st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().is_ok());
    }

    #[test]
    fn corrupted_genesis_is_rewritten() {
        let (_d, st, gs, _) = chain_fixture(2);
        st.overwrite_block_bytes_for_testing(0, b"zzz").unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!c.genesis_ok);
        st.truncate_to(&gs, 0, &gs.ledger).unwrap();
        assert_eq!(st.head().unwrap(), Head { height: 0, hash: gs.hash() });
        assert_eq!(st.notes_count().unwrap(), 2);
        assert_eq!(st.nullifiers_count().unwrap(), 0);
        assert_eq!(st.load_ledger(&StubExecutor).unwrap(), gs.ledger);
        assert!(st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().is_ok());
        assert!(st.load_safety().is_ok());
    }

    /// More blocks than the anchor window: the stored window is what a reloaded ledger accepts
    /// as an anchor, and it is exactly the newest `ANCHOR_WINDOW` roots.
    #[test]
    fn the_anchor_window_slides_with_the_chain() {
        let n = ANCHOR_WINDOW as u64 + 5;
        let (_d, st, _gs, blocks) = chain_fixture(n);
        let l = st.load_ledger(&StubExecutor).unwrap();
        assert_eq!(l.anchors().len(), ANCHOR_WINDOW);
        assert_eq!(l.anchors().back().map(|(h, _)| *h), Some(n));
        assert_eq!(l.anchors().front().map(|(h, _)| *h), Some(n - ANCHOR_WINDOW as u64 + 1));
        assert!(l.is_anchor(&st.anchor(n).unwrap().unwrap()));
        assert_eq!(st.latest_anchor().unwrap().map(|(h, _)| h), Some(n));
        let _ = blocks;
    }

    #[test]
    fn programs_and_receipts_round_trip_and_truncate() {
        let (_d, st, gs, blocks) = chain_fixture(2);
        let k = key(1);
        let mut ledger = st.load_ledger(&StubExecutor).unwrap();
        ledger.set_faucet(true);
        let words = vec![0x13u32; 3];
        ledger.set_height(3);
        let deploy_bundle = bundle_tx(&ledger, [[90; 8], [91; 8]], [[92; 8], [93; 8]], shrugg_core::gas::fee_floor(&Action::Deploy { base_pc: 0, words: words.clone() }));
        let deploy = Transaction::shielded(gs.chain_id, deploy_bundle.bundle.clone().unwrap(), Action::Deploy { base_pc: 0, words: words.clone() });
        // The bundle's digest commits to its own fields only, so swapping the action is fine.
        let cb3 = make_block(&blocks[1].block, &mut ledger, vec![deploy.clone()], &k);
        let pid = shrugg_core::program::program_id(0, &words);
        st.commit(std::slice::from_ref(&cb3), &ledger).unwrap();
        let rec = st.program(&pid).unwrap().expect("program stored");
        assert_eq!(rec.words, words);
        assert_eq!(rec.deployed_at, 3);
        assert_eq!(st.load_ledger(&StubExecutor).unwrap().programs().len(), 1);
        assert_eq!(st.programs_count().unwrap(), 1);
        // truncating below the deploy removes it
        let two = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(two.is_ok(), "{:?}", two.problem);
        let at_two = {
            let mut l = gs.ledger.clone();
            for cb in &blocks {
                l.apply_block(&cb.block, &StubExecutor).unwrap();
            }
            l
        };
        st.truncate_to(&gs, 2, &at_two).unwrap();
        assert!(st.program(&pid).unwrap().is_none());
        assert_eq!(st.load_ledger(&StubExecutor).unwrap(), at_two);
    }
}
