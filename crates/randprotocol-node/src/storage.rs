//! Persistent chain storage: one RocksDB with column families.
//!
//! Every commit is a single atomic, fsynced `WriteBatch` covering blocks,
//! certificates, indexes, transaction locations, the notes and nullifiers the
//! block created, its end-of-block anchor, the proposer's validator entry, the
//! commitment-tree frontier, the bridge rows the block's transactions produced,
//! and the head.

use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, WriteOptions, DB};
use randprotocol_core::bridge::{BridgeBurnRecord, BridgeMeta, BridgeState};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::consensus::{CommittedBlock, EpochSets, SafetyState};
use randprotocol_core::genesis::GenesisState;
use randprotocol_core::ledger::tokens::TokenRegistry;
use randprotocol_core::ledger::{Supply, ValidatorEntry};
use randprotocol_core::notes::{word8_from_bytes, word8_to_bytes, CommitmentTree, Envelope, FullTree, Word8, DEPTH};
use randprotocol_core::{
    Action, Address, Block, CallReceipt, Hash, Ledger, ProgramId, ProgramRecord, QuorumCertificate, Transaction,
    ValidatorSet,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CF_BLOCKS: &str = "blocks";
const CF_QCS: &str = "qcs";
const CF_BLOCK_INDEX: &str = "block_index";
const CF_TXS: &str = "txs";
/// Sealing marks (block aggregation, spec §6.1), three key shapes: `b't' + bundle_hash` ->
/// `bincode((aggregate_tx_hash, sealed_at_height))` per covered bundle; `b'b' + block_hash` ->
/// `bincode(bool)` once every bundle in the block has one; `b'p' + proof_hash` ->
/// `bincode(tx_hash)`, the proof-hash index the sealed form is served by (a marker-form
/// transaction's hash is not its raw hash, so the record cannot be found without it); and
/// `b'a' + aggregate_hash` -> `bincode((subsidy, proving_shares, n))`, the payment facts of a
/// committed aggregate (spec §5.4), written with its block so `rand_getAggregate` can report
/// them without a historical ledger. All derived state, never consensus.
const CF_SEALS: &str = "seals";
const CF_META: &str = "meta";
const CF_PROGRAMS: &str = "programs";
const CF_RECEIPTS: &str = "receipts";
/// Program id (32 bytes) -> `bincode(Vec<u32>)`: the public input a program was deployed with
/// (the call limits, spec §5), for provers to fetch. Only programs deployed with a non-empty one
/// have a row; the record in `programs` carries just its digest, so it stays small.
const CF_PROGRAM_PUBLIC: &str = "program_public";
/// Receipts by program: `program (32) || height (8 BE) || index (4 BE)` -> the transaction hash.
/// Serves `rand_getReceipts`; built from `receipts` on first open (`META_RECEIPTS_INDEX_BUILT`).
const CF_RECEIPTS_BY_PROGRAM: &str = "receipts_by_program";
const META_RECEIPTS_INDEX_BUILT: &str = "receipts_by_program_built";
/// Leaf index (big-endian u64, so the family iterates in tree order) -> `bincode(NoteRow)`.
/// Dense from zero: `notes_count` is the last key plus one, and a wallet pages it to scan.
const CF_NOTES: &str = "notes";
/// Nullifier (32 bytes) -> the height of the block that spent it (big-endian u64).
const CF_NULLIFIERS: &str = "nullifiers";
/// Block height (big-endian u64) -> the commitment-tree root at the end of that block.
const CF_ANCHORS: &str = "anchors";
/// Validator address (32 bytes) -> `bincode(ValidatorEntry)`.
const CF_VALIDATORS: &str = "validators";
/// Epoch (big-endian u64) -> `bincode(ValidatorSet)`: the set that epoch's blocks are proposed,
/// voted and certified by (spec §8). Epoch 0 is written by `init_genesis`; every later epoch is
/// written when its first block commits, in the same batch as that block.
///
/// Without this family a node that restarts past an epoch boundary cannot verify the QCs of the
/// epoch it is in: the register the set was derived from has moved on, and the blocks it would
/// re-derive from are no longer in the speculative tree.
const CF_EPOCH_SETS: &str = "epoch_sets";

/// Consumed attestation digest (32 bytes) -> empty. A key set: the bridge's `spent`.
const CF_BRIDGE_SPENT: &str = "bridge_spent";
/// Burn sequence (big-endian u64) -> `bincode(BridgeBurnRecord)`: the outbound messages
/// guardians read back, oldest first.
const CF_BRIDGE_BURNS: &str = "bridge_burns";
const ALL_CFS: [&str; 17] = [
    CF_BLOCKS,
    CF_QCS,
    CF_BLOCK_INDEX,
    CF_TXS,
    CF_SEALS,
    CF_META,
    CF_PROGRAMS,
    CF_PROGRAM_PUBLIC,
    CF_RECEIPTS,
    CF_RECEIPTS_BY_PROGRAM,
    CF_NOTES,
    CF_NULLIFIERS,
    CF_ANCHORS,
    CF_VALIDATORS,
    CF_EPOCH_SETS,
    CF_BRIDGE_SPENT,
    CF_BRIDGE_BURNS,
];
/// The bridge families, which (unlike notes and anchors) have no per-height key and so are
/// rewritten wholesale wherever the state is installed rather than appended to.
const BRIDGE_CFS: [&str; 2] = [CF_BRIDGE_SPENT, CF_BRIDGE_BURNS];

/// One stored transaction record (`CF_TXS`'s value, block aggregation's R3): the location and
/// the transaction itself, in one of two forms. `Raw` is every record at commit. `Pruned` is
/// the form a sealed bundle takes once the pruning pass (spec §6.2) has dropped its raw proof
/// bytes — the transaction with `bundle.proof` replaced by [`PRUNED_PROOF_MARKER`] plus the
/// proof's hash, the proof's hash again on its own, the 34 public values, and the declared
/// shape, which is everything admission (§4 step 6) and the replay ever read of it afterwards.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TxRecord {
    Raw {
        height: u64,
        index: u32,
        tx: Transaction,
    },
    Pruned {
        height: u64,
        index: u32,
        /// The raw transaction's hash — what the sealed form's side table and every `covers`
        /// list names. Equal to the marker form's own `hash()` (the proof enters by digest),
        /// kept explicit so the record and the side table attest it rather than recompute it.
        tx_hash: Hash,
        tx: Transaction,
        proof_hash: Hash,
        /// The proof's 34 public values, in `pv` order — a `Vec` because serde's built-in array
        /// impls stop at 32; always exactly 34 (the pruning pass writes it, the readers assert it).
        public_values: Vec<u64>,
        shape: randprotocol_core::types::DeclaredShape,
    },
}

impl TxRecord {
    /// The block and the index inside it the record belongs to, either form.
    pub fn location(&self) -> (u64, u32) {
        match self {
            TxRecord::Raw { height, index, .. } | TxRecord::Pruned { height, index, .. } => (*height, *index),
        }
    }

    /// The transaction, either form — a `Pruned` one's bundle proof is the marker form.
    pub fn transaction(&self) -> &Transaction {
        match self {
            TxRecord::Raw { tx, .. } | TxRecord::Pruned { tx, .. } => tx,
        }
    }
}

/// What a pruned bundle's `proof` field carries (spec §6.2, the 2026-09-13 form): this marker
/// then the proof's 32-byte hash. Never a decodable proof, so a pruned record can never be
/// mistaken for a raw one — and 46 bytes stands in for ~1.3 MB.
pub const PRUNED_PROOF_MARKER: &[u8] = b"rand-pruned\0";

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
/// `bincode(Supply)`: the public supply counters as of the head (`ledger::supply`). Derived
/// state, not covered by any state root, which is why it lives in `meta` beside the frontier
/// rather than in a family of its own — and why `verify_chain` recomputes it from a full replay
/// instead of trusting it.
const META_SUPPLY: &str = "supply";
/// `bincode(BTreeMap<Hash, (u64, Address, u64)>)`: the proving-share bucket as of the head
/// (`ledger::unsealed_fees`). `META_SUPPLY`'s twin in every respect — derived state, no root
/// covers it, `verify_chain` replays it — persisted because the payout an aggregate must pay
/// is computed from it: a restarted node that lost it would disagree with its peers about the
/// very next aggregate's state root.
const META_UNSEALED_FEES: &str = "unsealed_fees";
/// `bincode(BTreeMap<Address, AggregatorEntry>)`: the aggregator register as of the head.
/// `META_SUPPLY`'s twin in kind — derived, replay-audited — but unlike the bucket this one is
/// hashed into the state root, so a restarted node that lost it would fork at the next block.
const META_AGGREGATORS: &str = "aggregators";
/// `bincode(Option<AggregationConfig>)`: the genesis section itself. The register and the
/// bucket are persisted derived state, but the config is genesis truth — `load_ledger` restores
/// it from here so every reader of the store (RPC included, which has no genesis file to hand)
/// sees the same gate the node sees.
const META_AGGREGATION: &str = "aggregation";
/// `bincode(BridgeMeta)`: the whole-state half of the bridge — emitter, source emitters,
/// guardian sets, the asset registry with its indices and `next_index`, and the burn sequence.
/// Its presence is what makes a chain "bridged" on disk; the two collections it leaves out live
/// in [`CF_BRIDGE_SPENT`] and [`CF_BRIDGE_BURNS`].
const META_BRIDGE_STATE: &str = "bridge_state";
/// `bincode(Option<TokenRegistry>)`: the RPL token registry as of the head, whole — `by_index`,
/// `index_of`, `next_index` and `registration_fee` all together, the same shape `Ledger::tokens`
/// holds and `TokenRegistry::root` hashes into the state root. `META_AGGREGATORS`'s twin, not
/// `META_AGGREGATION`'s: unlike the aggregation *config*, a genesis `tokens` section has no
/// separate immutable half — the whole registry is state, and `load_ledger` restores it from
/// here so a restarted node does not fork at its own first block.
const META_TOKENS: &str = "tokens";

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

/// What [`Storage::drop_receipts_index`] found and removed: whether the `receipts_by_program`
/// family was there to drop, and whether its built marker was there to delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DroppedReceiptsIndex {
    pub family: bool,
    pub marker: bool,
}

fn height_key(h: u64) -> [u8; 8] {
    h.to_be_bytes()
}

/// `CF_RECEIPTS_BY_PROGRAM`'s key: `program || height (BE) || index (BE)`. Big-endian height
/// and index put a program's receipts in call order under the iterator, which is what
/// `receipts_for_program` and the backfill both rely on.
fn receipt_index_key(program: &ProgramId, height: u64, index: u32) -> [u8; 44] {
    let mut k = [0u8; 44];
    k[..32].copy_from_slice(program.as_bytes());
    k[32..40].copy_from_slice(&height.to_be_bytes());
    k[40..].copy_from_slice(&index.to_be_bytes());
    k
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
/// output slots in that order, then a mint's single note or a bridge deposit, then — for a
/// two-bundle action ([`Action::asset_bundle`]: a `BridgeBurn`, a `TokenTransfer` or a
/// `TokenBurn`) — its asset bundle's two slots. Exactly the order the ledger appends them in, so
/// the index a leaf gets on disk is the index the ledger gave it.
///
/// A `BridgeAttest`'s deposit is the one commitment the wire does not carry: the chain computes
/// it from the amount the guardians signed, the `time` the action published and the index the
/// token registry holds for the asset, so this recomputes it the same way, through the ledger's
/// own function. `tokens` is that registry (the RPL token standard — the bridge keeps none of
/// its own) — absent only on a chain without a `tokens` section, which is a chain without a
/// bridge, where a `BridgeAttest` is inadmissible.
fn created_notes(
    tx: &randprotocol_core::Transaction,
    tokens: Option<&TokenRegistry>,
    executor: &dyn ConfidentialExecutor,
) -> Result<Vec<(Word8, Envelope)>> {
    let mut out = Vec::new();
    if let Some(b) = &tx.bundle {
        for i in 0..2 {
            out.push((b.commitments[i], b.envelopes[i].clone()));
        }
    }
    match &tx.action {
        Action::Mint { cm, envelope, .. } => out.push((*cm, envelope.clone())),
        Action::BridgeAttest { attestation, .. } => {
            let tokens = tokens.ok_or_else(|| {
                StorageError::Corrupt("committed block has a bridge attestation but no token registry".into())
            })?;
            // A guardian-set rotation is the one attestation that deposits nothing. Everything
            // else was admitted, so it decodes and its token is listed; failing to find the
            // note here is a torn block, and leaving the leaf out would put the notes family one
            // short of the tree the ledger committed to.
            if randprotocol_core::ledger::bridge_notes::attested_transfer(attestation).is_some() {
                let note = randprotocol_core::ledger::bridge_notes::deposit_note(tx, tokens, executor)
                    .ok_or_else(|| {
                        StorageError::Corrupt(
                            "committed attestation deposits an asset the registry does not hold".into(),
                        )
                    })?;
                out.push(note);
            }
        }
        // RPL (spec §4): a minted note is chain-computed exactly as a bridge deposit is, so it is
        // not on the wire either and has to be recomputed here — from the action's own public
        // fields alone, with no registry lookup: a mint names its asset index and a registration
        // names the index it was held to (`TokenError::IndexMismatch`), so both are facts on a
        // *committed* transaction. A registration without an initial mint creates no note.
        Action::TokenMint { asset, amount, recipient, r, time, envelope, .. } => {
            let cm = randprotocol_core::ledger::tokens::mint_commitment(recipient, *amount, *asset, *time, r, executor);
            out.push((cm, envelope.clone()));
        }
        Action::RegisterToken { initial: Some(m), index, .. } => {
            let cm = randprotocol_core::ledger::tokens::mint_commitment(
                &m.recipient,
                m.amount,
                *index,
                m.time,
                &m.r,
                executor,
            );
            out.push((cm, m.envelope.clone()));
        }
        _ => {}
    }
    // The asset bundle of a two-bundle action — a `BridgeBurn`, a `TokenTransfer` or a
    // `TokenBurn` — appends its two notes after the fee bundle's, which is the order
    // `Ledger::apply_tx` writes them in: the fee bundle on the common path, the asset bundle in
    // the action step. One list of those actions ([`Action::asset_bundle`]), so a fourth cannot
    // silently leave two leaves out of the notes family and slide every wallet's leaf indices
    // after it.
    if let Some(asset_bundle) = tx.action.asset_bundle() {
        for i in 0..2 {
            out.push((asset_bundle.commitments[i], asset_bundle.envelopes[i].clone()));
        }
    }
    Ok(out)
}

/// How many notes of a block's slice belong to `tx` beyond the ones it carries on the wire: the
/// deposit note the ledger derives for a `Withdraw`, and for a `BridgeAttest` the deposit it
/// derives from the attestation — none for a guardian-set rotation, which deposits nothing.
///
/// The function this must agree with is **`created_notes` above, plus `commit`'s `cb.deposits`
/// drain** — those two together are what actually appended the block's leaves, so this is a count
/// of them, not of anything else: `created_notes` emits the `BridgeAttest` deposit, and the
/// `Withdraw` deposit arrives as a `cb.deposits` entry immediately after that transaction's own
/// notes. `Transaction::commitments()` deliberately omits both, which is why
/// `tx.commitments().len() + derived_note_count(tx)` is exactly the slice `tx` owns.
///
/// One deliberate difference from `created_notes`: the attestation size cap is applied here
/// *before* the decode, as `Ledger::derived_commitment` applies it, so a caller holding an
/// unvalidated transaction cannot be made to parse an oversized blob. `created_notes` calls
/// `attested_transfer` with no cap and the two still agree, because `validate` refuses an
/// attestation over `gas::MAX_ATTESTATION_BYTES` (`TxError::AttestationTooLarge`) and a committed
/// block therefore holds none. That is the invariant to keep: relax the cap in `validate` and
/// these two stop agreeing on a committed block.
pub fn derived_note_count(tx: &randprotocol_core::Transaction) -> usize {
    match &tx.action {
        Action::Withdraw { .. } => 1,
        // The size cap before the decode, exactly as `Ledger::derived_commitment` applies it;
        // `created_notes` needs no cap because it only ever sees a committed block.
        Action::BridgeAttest { attestation, .. } if attestation.len() > randprotocol_core::gas::MAX_ATTESTATION_BYTES => 0,
        Action::BridgeAttest { attestation, .. } => {
            usize::from(randprotocol_core::ledger::bridge_notes::attested_transfer(attestation).is_some())
        }
        // RPL: the minted note `created_notes` recomputes above — one per `TokenMint`, one per
        // registration that carries an initial mint, none for a registration without one. Get
        // this wrong and every wallet leaf index after the transaction slides.
        Action::TokenMint { .. } => 1,
        Action::RegisterToken { initial, .. } => usize::from(initial.is_some()),
        _ => 0,
    }
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
        let storage = Storage { db };
        storage.backfill_receipts_index()?;
        Ok(storage)
    }

    /// Undo v0.3's one on-disk addition so a pre-v0.3 build can open the database again (the
    /// rollback path, `rand-node db drop-receipts-index`): drop the `receipts_by_program` family
    /// and delete its built marker.
    ///
    /// RocksDB refuses to open a database holding a column family the caller does not list,
    /// and the old build lists fifteen, so the family itself has to go — emptying it is not
    /// enough. This opens raw, with whatever families are on disk, and never through
    /// [`Storage::open`], which would re-create the family and backfill it first. The marker
    /// goes before the family: a crash between the two leaves a family with no marker, which
    /// the next `open` simply rebuilds over (the rows are idempotent), and which a rerun of this
    /// drops. Either half already absent is not an error, so a rerun is harmless.
    ///
    /// Takes the data directory, like `open`. Fails while a node holds the database's lock.
    pub fn drop_receipts_index(path: &Path) -> Result<DroppedReceiptsIndex> {
        let db_path = path.join("db");
        if !db_path.join("CURRENT").exists() {
            return Err(StorageError::Corrupt(format!("no database at {}", db_path.display())));
        }
        let names = DB::list_cf(&Options::default(), &db_path)?;
        let mut db = DB::open_cf(&Options::default(), &db_path, &names)?;
        let meta = db
            .cf_handle(CF_META)
            .ok_or_else(|| StorageError::Corrupt("database has no meta family".into()))?;
        let marker = db.get_cf(meta, META_RECEIPTS_INDEX_BUILT.as_bytes())?.is_some();
        if marker {
            db.delete_cf_opt(meta, META_RECEIPTS_INDEX_BUILT.as_bytes(), &sync_opts())?;
        }
        let family = names.iter().any(|n| n == CF_RECEIPTS_BY_PROGRAM);
        if family {
            db.drop_cf(CF_RECEIPTS_BY_PROGRAM)?;
        }
        Ok(DroppedReceiptsIndex { family, marker })
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
        // Epoch 0 runs with the genesis set, by definition (spec §8); every later epoch's set is
        // derived and written when its first block commits.
        batch.put_cf(self.cf(CF_EPOCH_SETS), height_key(0), bincode::serialize(&gs.validators)?);
        batch.put_cf(self.cf(CF_META), META_SUPPLY, bincode::serialize(&gs.ledger.supply())?);
        batch.put_cf(self.cf(CF_META), META_UNSEALED_FEES, bincode::serialize(gs.ledger.unsealed_fees())?);
        batch.put_cf(self.cf(CF_META), META_AGGREGATORS, bincode::serialize(gs.ledger.aggregators())?);
        batch.put_cf(self.cf(CF_META), META_AGGREGATION, bincode::serialize(&gs.ledger.aggregation().cloned())?);
        batch.put_cf(self.cf(CF_META), META_TOKENS, bincode::serialize(&gs.ledger.tokens().cloned())?);
        batch.put_cf(self.cf(CF_ANCHORS), height_key(0), word8_to_bytes(&gs.ledger.root()));
        batch.put_cf(self.cf(CF_META), META_TREE, bincode::serialize(gs.ledger.tree())?);
        batch.put_cf(self.cf(CF_META), META_HC_BUNDLE, word8_to_bytes(&gs.hc_bundle));
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(0));
        batch.put_cf(self.cf(CF_META), META_GENESIS_HASH, genesis_hash.as_bytes());
        batch.put_cf(self.cf(CF_META), META_CHAIN_ID, gs.chain_id.to_be_bytes());
        // A genesis `bridge` section is state like any other: persisted here rather than
        // re-derived from the genesis file at every startup, so that what a restarted node
        // reloads is the bridge as the chain left it.
        if let Some(bridge) = gs.ledger.bridge() {
            self.put_bridge(&mut batch, bridge)?;
        }
        self.db.write_opt(batch, &sync_opts())?;
        Ok(())
    }

    // ---- the bridge ------------------------------------------------------

    /// Write a whole bridge state — the `meta` blob and every row of the two families — into
    /// `batch`. Used where the state is installed wholesale (genesis, truncation); `commit`
    /// writes only what a block touched.
    fn put_bridge(&self, batch: &mut WriteBatch, bridge: &BridgeState) -> Result<()> {
        batch.put_cf(self.cf(CF_META), META_BRIDGE_STATE, bincode::serialize(&bridge.meta())?);
        for digest in &bridge.spent {
            batch.put_cf(self.cf(CF_BRIDGE_SPENT), digest.as_bytes(), []);
        }
        for (sequence, rec) in &bridge.burns {
            batch.put_cf(self.cf(CF_BRIDGE_BURNS), height_key(*sequence), bincode::serialize(rec)?);
        }
        Ok(())
    }

    /// Delete every bridge row and the `meta` blob into `batch`.
    fn clear_bridge(&self, batch: &mut WriteBatch) -> Result<()> {
        for name in BRIDGE_CFS {
            for item in self.db.iterator_cf(self.cf(name), IteratorMode::Start) {
                let (k, _) = item?;
                batch.delete_cf(self.cf(name), k);
            }
        }
        batch.delete_cf(self.cf(CF_META), META_BRIDGE_STATE);
        Ok(())
    }

    /// The bridge's whole-state half — the emitter, the source emitters, the guardian sets and
    /// the burn sequence — or `None` on a chain without a bridge.
    ///
    /// Decoded **strictly**: the blob lost two fields with the RPL token standard (the asset
    /// registry and its `next_index`, which moved to [`META_TOKENS`]), and plain
    /// `bincode::deserialize` ignores trailing bytes — it would read a pre-RPL blob's `assets`
    /// map length as this struct's `burn_sequence` and answer `Ok` with a bridge that never
    /// existed. Rejecting the trailing bytes turns that into the decode error it is. Chain 14 is
    /// a fresh datadir, so no live node has such a blob; what this rules out is a node pointed at
    /// an old one reading nonsense as state.
    pub fn bridge_meta(&self) -> Result<Option<BridgeMeta>> {
        use bincode::Options as _;
        match self.get_meta_raw(META_BRIDGE_STATE)? {
            // `with_fixint_encoding` is what plain `bincode::serialize` writes (`put_bridge`);
            // `DefaultOptions` rejects trailing bytes, which is the whole point here.
            Some(bytes) => Ok(Some(
                bincode::DefaultOptions::new().with_fixint_encoding().deserialize(&bytes)?,
            )),
            None => Ok(None),
        }
    }

    /// The outbound burn message with this sequence, for guardians to sign.
    pub fn bridge_burn(&self, sequence: u64) -> Result<Option<BridgeBurnRecord>> {
        self.get(CF_BRIDGE_BURNS, &height_key(sequence))
    }

    /// Rebuild the bridge from the `meta` blob plus the two families. `None` when the blob is
    /// absent, which is how a chain without a bridge — and, once `init_genesis` has run, only
    /// such a chain — looks on disk.
    fn load_bridge(&self) -> Result<Option<BridgeState>> {
        let Some(meta) = self.bridge_meta()? else { return Ok(None) };
        let mut spent = BTreeSet::new();
        for item in self.db.iterator_cf(self.cf(CF_BRIDGE_SPENT), IteratorMode::Start) {
            let (k, _) = item?;
            let arr: [u8; 32] = k
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Corrupt("bridge_spent key has wrong length".into()))?;
            spent.insert(Hash(arr));
        }
        let mut burns = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_BRIDGE_BURNS), IteratorMode::Start) {
            let (_, v) = item?;
            let rec: BridgeBurnRecord = bincode::deserialize(&v)?;
            burns.insert(rec.sequence, rec);
        }
        Ok(Some(BridgeState::from_parts(meta, spent, burns)))
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

    /// The lowest leaf index whose row is at height >= `height`, or `notes_count()` if none is.
    ///
    /// Binary search: the `notes` family is dense from zero and its rows' heights are
    /// non-decreasing in index, because `commit` appends blocks in ascending height and
    /// `truncate_to` only deletes a suffix.
    pub(crate) fn first_note_at_or_after(&self, height: u64) -> Result<u64> {
        let count = self.notes_count()?;
        let (mut lo, mut hi) = (0u64, count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let row = self
                .note(mid)?
                .ok_or_else(|| StorageError::Corrupt(format!("notes family has a gap at index {mid}")))?;
            if row.height >= height {
                hi = mid
            } else {
                lo = mid + 1
            }
        }
        Ok(lo)
    }

    /// Every leaf appended by blocks in `from_height..=to_height`, in tree order, at most
    /// `max_rows` of them (truncated, never an error). One binary search, then a forward scan.
    pub fn notes_in_heights(&self, from_height: u64, to_height: u64, max_rows: usize) -> Result<Vec<(u64, NoteRow)>> {
        if from_height > to_height || max_rows == 0 {
            return Ok(Vec::new());
        }
        let start = self.first_note_at_or_after(from_height)?;
        let mode = IteratorMode::From(&height_key(start), rocksdb::Direction::Forward);
        let mut out = Vec::new();
        for item in self.db.iterator_cf(self.cf(CF_NOTES), mode) {
            if out.len() >= max_rows {
                break;
            }
            let (k, v) = item?;
            let row: NoteRow = bincode::deserialize(&v)?;
            // Heights are non-decreasing in index, so the first row past the range ends the scan.
            if row.height > to_height {
                break;
            }
            out.push((be_u64(k.as_ref(), "note key")?, row));
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

    /// The whole register, in address order. Small by construction (`MAX_VALIDATORS` rows plus
    /// whatever has fallen below the minimum), so RPC reads it directly rather than through a
    /// ledger reload.
    pub fn register(&self) -> Result<BTreeMap<Address, ValidatorEntry>> {
        let mut out = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_VALIDATORS), IteratorMode::Start) {
            let (k, v) = item?;
            let arr: [u8; 32] = k
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Corrupt("validator key has wrong length".into()))?;
            out.insert(Address(arr), bincode::deserialize::<ValidatorEntry>(&v)?);
        }
        Ok(out)
    }

    /// The validator set of `epoch`, as it was recorded when that epoch's first block committed.
    pub fn epoch_set(&self, epoch: u64) -> Result<Option<ValidatorSet>> {
        self.get(CF_EPOCH_SETS, &height_key(epoch))
    }

    /// Every recorded epoch set, for a resuming replica (`HotStuff::resume`).
    pub fn load_epoch_sets(&self) -> Result<EpochSets> {
        let mut sets = EpochSets::default();
        for item in self.db.iterator_cf(self.cf(CF_EPOCH_SETS), IteratorMode::Start) {
            let (k, v) = item?;
            sets.insert(be_u64(k.as_ref(), "epoch set key")?, bincode::deserialize(&v)?);
        }
        Ok(sets)
    }

    /// The supply counters as of the head. A database written before this family existed has
    /// none; zeros are what `verify_chain` then reports a mismatch against, and a repair
    /// rewrites them from the replay.
    pub fn supply(&self) -> Result<Supply> {
        Ok(self.get_meta_raw(META_SUPPLY)?.map(|b| bincode::deserialize(&b)).transpose()?.unwrap_or_default())
    }

    /// The proving-share bucket as of the head — `supply()`'s twin, with the same rule for a
    /// database written before the key existed: empty, and `verify_chain`'s replay reports or
    /// repairs the mismatch.
    pub fn unsealed_fees(&self) -> Result<std::collections::BTreeMap<Hash, (u64, randprotocol_core::Address, u64)>> {
        Ok(self.get_meta_raw(META_UNSEALED_FEES)?.map(|b| bincode::deserialize(&b)).transpose()?.unwrap_or_default())
    }

    /// The aggregator register as of the head — the same rule again.
    pub fn aggregators(&self) -> Result<std::collections::BTreeMap<randprotocol_core::Address, randprotocol_core::ledger::aggregation::AggregatorEntry>> {
        Ok(self.get_meta_raw(META_AGGREGATORS)?.map(|b| bincode::deserialize(&b)).transpose()?.unwrap_or_default())
    }

    /// The chain's genesis aggregation section, `None` without one — and equally for a database
    /// written before the key existed, which is what `Ledger::from_parts` would have left it.
    /// Genesis truth, never changed after `init_genesis`, so a reader that needs only the config
    /// (`rand_getEmission`) reads it here rather than rebuilding the ledger through `load_ledger`.
    pub fn aggregation_config(&self) -> Result<Option<randprotocol_core::ledger::aggregation::AggregationConfig>> {
        Ok(self.get_meta_raw(META_AGGREGATION)?.map(|b| bincode::deserialize(&b)).transpose()?.flatten())
    }

    /// The RPL token registry as of the head, `None` on a chain without a `tokens` section — and
    /// equally for a database written before the key existed, which is what `Ledger::from_parts`
    /// would have left it.
    pub fn tokens(&self) -> Result<Option<randprotocol_core::ledger::tokens::TokenRegistry>> {
        Ok(self.get_meta_raw(META_TOKENS)?.map(|b| bincode::deserialize(&b)).transpose()?.flatten())
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

    /// Paths for many leaves from one tree build (`rand_getWitnesses`); `None` for an index past
    /// the tree. The root is the same for every path, so it is returned once.
    pub fn witnesses(&self, indices: &[u64], executor: &dyn ConfidentialExecutor) -> Result<(Word8, Vec<Option<[Word8; DEPTH]>>)> {
        let leaves = self.leaves()?;
        let len = leaves.len() as u64;
        let tree = FullTree::new(leaves, executor);
        let paths = indices.iter().map(|&i| if i < len { tree.path(i) } else { None }).collect();
        Ok((tree.root(), paths))
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
        // `deposits` stays empty: this is how a block is served to a peer, and the peer
        // recomputes them by applying the block itself.
        Ok(Some(CommittedBlock { block, pruned: Vec::new(), qc, receipts, deposits: Vec::new() }))
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

    /// Where a committed transaction sits, `(height, index)`, read without decoding the rest of
    /// its record: a `Raw` one carries the whole ~1.2 MB proof, and this is the lookup
    /// `rand_getTransactionStatus` makes up to 64 times a call and every `transaction`
    /// subscription makes once. Bincode's leading enum tag then `height` and `index` are the
    /// same two fields in the same order in both forms, and bincode 1's `deserialize` stops
    /// once the mirror's fields are read, ignoring the bytes after them.
    pub fn tx_location(&self, h: &Hash) -> Result<Option<(u64, u32)>> {
        /// `TxRecord`'s two variants cut down to their first two fields. The variant order and
        /// the field order must stay `TxRecord`'s (the test pins both forms to the full decode).
        #[derive(serde::Deserialize)]
        enum TxLocation {
            Raw { height: u64, index: u32 },
            Pruned { height: u64, index: u32 },
        }
        Ok(self.get::<TxLocation>(CF_TXS, h.as_bytes())?.map(|l| match l {
            TxLocation::Raw { height, index } | TxLocation::Pruned { height, index } => (height, index),
        }))
    }

    /// The transaction itself, either record form (a pruned one's proof is the marker form).
    pub fn tx_by_hash(&self, h: &Hash) -> Result<Option<Transaction>> {
        Ok(self.tx_record(h)?.map(|r| r.transaction().clone()))
    }

    /// The stored record for a transaction — `Raw` until it is sealed and pruned, `Pruned`
    /// after (spec §6.2's two forms).
    pub fn tx_record(&self, h: &Hash) -> Result<Option<TxRecord>> {
        self.get(CF_TXS, h.as_bytes())
    }

    /// One covered bundle's admission record (spec §3.2's data half): its 34 public values and
    /// declared shape — the `Raw` form's read off the stored proof, the `Pruned` form's off the
    /// record, so admission and the replay read one way regardless of pruning (spec §6.2's
    /// promise). No policy attached: finality, the window and sealing are the caller's checks
    /// (`node::assemble_covered` has admission's, `verify_chain` attaches none). `None` when
    /// the hash names no transaction or one with no bundle.
    pub fn covered_record(
        &self,
        cover: &Hash,
        profile: randprotocol_core::types::FriProfile,
    ) -> Result<Option<randprotocol_core::types::CoveredBundle>> {
        use randprotocol_core::types::{CoveredBundle, DeclaredShape};
        let Some(record) = self.tx_record(cover)? else { return Ok(None) };
        match record {
            TxRecord::Raw { tx, .. } => {
                let Some(bundle) = &tx.bundle else { return Ok(None) };
                let proof: randprotocol_zkvm::machine::Proof = postcard::from_bytes(&bundle.proof)
                    .map_err(|_| StorageError::Corrupt(format!("covered bundle {cover}'s proof does not decode")))?;
                let public_values: [u64; 34] = proof
                    .public_values
                    .clone()
                    .try_into()
                    .map_err(|_| StorageError::Corrupt(format!("covered bundle {cover}'s public values are not 34 words")))?;
                Ok(Some(CoveredBundle {
                    public_values,
                    shape: DeclaredShape {
                        profile,
                        tier: proof.tier.0 as u8,
                        program_log_height: proof.program_log_height,
                        input_log_height: proof.input_log_height,
                        keccak_log_height: proof.keccak_log_height,
                        sha256_log_height: proof.sha256_log_height,
                        public_log_height: proof.public_log_height,
                        mem_log_height: proof.mem_log_height,
                    },
                }))
            }
            TxRecord::Pruned { tx, public_values, shape, .. } => {
                if tx.bundle.is_none() {
                    return Ok(None);
                }
                let public_values: [u64; 34] = public_values.try_into().map_err(|_| {
                    StorageError::Corrupt(format!("pruned record for {cover} does not carry 34 public values"))
                })?;
                Ok(Some(CoveredBundle { public_values, shape }))
            }
        }
    }

    /// Mark a covered bundle sealed by an aggregate (spec §6.1): the per-bundle mark lands,
    /// and once every bundle in its block has one, the block's flag does. `sealed_at` is the
    /// committing block's height, which the pruning gate measures against the head.
    pub fn mark_sealed(&self, bundle_hash: Hash, aggregate_tx: Hash, sealed_at: u64) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        let mut key = Vec::with_capacity(33);
        key.push(b't');
        key.extend_from_slice(bundle_hash.as_bytes());
        batch.put_cf(self.cf(CF_SEALS), &key, bincode::serialize(&(aggregate_tx, sealed_at))?);
        self.db.write_opt(batch, &sync_opts())?;
        self.refresh_block_sealed_flag(&bundle_hash)
    }

    /// The per-block half of sealing: once every bundle-carrying transaction in the bundle's
    /// block has a mark, the block's `sealed` flag lands (spec §6.1). Split from
    /// [`Storage::mark_sealed`] because the commit path writes the bundle marks in its own
    /// batch — atomically with the block — and refreshes the flags right after it lands.
    fn refresh_block_sealed_flag(&self, bundle_hash: &Hash) -> Result<()> {
        let Some((height, _)) = self.tx_location(bundle_hash)? else { return Ok(()) };
        let block = self
            .block_by_height(height)?
            .ok_or_else(|| StorageError::Corrupt(format!("sealed bundle's block {height} missing")))?;
        let mut all_sealed = true;
        for tx in &block.transactions {
            if tx.bundle.is_some() && self.sealed_by(&tx.hash())?.is_none() {
                all_sealed = false;
                break;
            }
        }
        if all_sealed {
            let block_hash = block.hash();
            let mut key = Vec::with_capacity(33);
            key.push(b'b');
            key.extend_from_slice(block_hash.as_bytes());
            let mut batch = rocksdb::WriteBatch::default();
            batch.put_cf(self.cf(CF_SEALS), &key, bincode::serialize(&true)?);
            self.db.write_opt(batch, &sync_opts())?;
        }
        Ok(())
    }

    /// The aggregate that sealed a bundle, if one has (spec §6.1): its hash and the height it
    /// committed at.
    pub fn sealed_by(&self, bundle_hash: &Hash) -> Result<Option<(Hash, u64)>> {
        let mut key = Vec::with_capacity(33);
        key.push(b't');
        key.extend_from_slice(bundle_hash.as_bytes());
        match self.db.get_cf(self.cf(CF_SEALS), &key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// The raw transaction hash a pruned proof hash maps to, if any — the sealed form's
    /// serving index by proof hash (the marker form hashes to the raw hash too; this index
    /// answers the question from the proof's side).
    pub fn tx_hash_by_proof_hash(&self, proof_hash: &Hash) -> Result<Option<Hash>> {
        let mut key = Vec::with_capacity(33);
        key.push(b'p');
        key.extend_from_slice(proof_hash.as_bytes());
        match self.db.get_cf(self.cf(CF_SEALS), &key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// The payment facts of a committed aggregate (spec §5.4), written with its block:
    /// `(subsidy, proving_shares, n)` — the minted part, the covered excesses' sum, and the
    /// schedule index it minted at.
    pub fn aggregate_payment(&self, aggregate: &Hash) -> Result<Option<(u64, u64, u64)>> {
        let mut key = Vec::with_capacity(33);
        key.push(b'a');
        key.extend_from_slice(aggregate.as_bytes());
        match self.db.get_cf(self.cf(CF_SEALS), &key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Whether every bundle in a block is sealed (spec §6.1's per-block flag).
    pub fn block_sealed(&self, block_hash: &Hash) -> Result<bool> {
        let mut key = Vec::with_capacity(33);
        key.push(b'b');
        key.extend_from_slice(block_hash.as_bytes());
        match self.db.get_cf(self.cf(CF_SEALS), &key)? {
            Some(bytes) => Ok(bincode::deserialize(&bytes)?),
            None => Ok(false),
        }
    }

    /// The pruning pass (spec §6.2 — policy, never consensus): every bundle sealed for at
    /// least `window` blocks whose record is still `Raw` becomes its `Pruned` form, the 34
    /// public values and the declared shape filled from the stored proof. Aggregate
    /// transactions and unsealed bundles are never touched — the first are bundle-less, the
    /// second have no mark. Returns how many records it rewrote.
    pub fn prune_sealed(&self, head_height: u64, window: u64, profile: randprotocol_core::types::FriProfile) -> Result<u64> {
        let mut pruned = 0u64;
        let seals: Vec<(Box<[u8]>, Box<[u8]>)> = self
            .db
            .iterator_cf(self.cf(CF_SEALS), IteratorMode::Start)
            .collect::<std::result::Result<_, _>>()?;
        for (k, _) in seals {
            if k.first() != Some(&b't') {
                continue;
            }
            let bundle_hash = Hash(k[1..].try_into().map_err(|_| StorageError::Corrupt("seal key has wrong length".into()))?);
            let Some((_, sealed_at)) = self.sealed_by(&bundle_hash)? else { continue };
            if sealed_at.saturating_add(window) > head_height {
                continue;
            }
            let Some(TxRecord::Raw { height, index, tx }) = self.tx_record(&bundle_hash)? else { continue };
            let Some(bundle) = &tx.bundle else { continue };
            let proof: randprotocol_zkvm::machine::Proof = postcard::from_bytes(&bundle.proof)
                .map_err(|_| StorageError::Corrupt(format!("sealed bundle {}'s proof does not decode", bundle_hash)))?;
            let public_values: [u64; 34] = proof
                .public_values
                .clone()
                .try_into()
                .map_err(|_| StorageError::Corrupt(format!("sealed bundle {}'s public values are not 34 words", bundle_hash)))?;
            let shape = randprotocol_core::types::DeclaredShape {
                profile,
                tier: proof.tier.0 as u8,
                program_log_height: proof.program_log_height,
                input_log_height: proof.input_log_height,
                keccak_log_height: proof.keccak_log_height,
                sha256_log_height: proof.sha256_log_height,
                public_log_height: proof.public_log_height,
                mem_log_height: proof.mem_log_height,
            };
            let proof_hash = Hash::digest(&bundle.proof);
            let mut pruned_tx = tx.clone();
            let mut marker = PRUNED_PROOF_MARKER.to_vec();
            marker.extend_from_slice(proof_hash.as_bytes());
            pruned_tx.bundle.as_mut().expect("checked above").proof = marker;
            let record = TxRecord::Pruned {
                height,
                index,
                tx_hash: bundle_hash,
                tx: pruned_tx,
                proof_hash,
                public_values: public_values.to_vec(),
                shape,
            };
            let mut batch = rocksdb::WriteBatch::default();
            batch.put_cf(self.cf(CF_TXS), bundle_hash.as_bytes(), bincode::serialize(&record)?);
            batch.put_cf(
                self.cf(CF_SEALS),
                [b"p".as_slice(), proof_hash.as_bytes()].concat(),
                bincode::serialize(&bundle_hash)?,
            );
            self.db.write_opt(batch, &sync_opts())?;
            pruned += 1;
        }
        Ok(pruned)
    }

    pub fn program(&self, id: &ProgramId) -> Result<Option<ProgramRecord>> {
        self.get(CF_PROGRAMS, id.as_bytes())
    }

    /// The public input `id` was deployed with; `None` for a program deployed without one (or
    /// not deployed at all).
    pub fn program_public(&self, id: &ProgramId) -> Result<Option<Vec<u32>>> {
        self.get(CF_PROGRAM_PUBLIC, id.as_bytes())
    }

    pub fn programs_count(&self) -> Result<u64> {
        Ok(self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start).count() as u64)
    }

    pub fn receipt(&self, tx: &Hash) -> Result<Option<CallReceipt>> {
        self.get(CF_RECEIPTS, tx.as_bytes())
    }

    pub fn receipts_index_built(&self) -> Result<bool> {
        Ok(self.get_meta_raw(META_RECEIPTS_INDEX_BUILT)?.is_some())
    }

    /// Builds `receipts_by_program` from `receipts` once. The marker, not the family's
    /// emptiness, is the guard, so a node killed mid-backfill finishes on its next open.
    fn backfill_receipts_index(&self) -> Result<()> {
        if self.receipts_index_built()? {
            return Ok(());
        }
        let mut batch = WriteBatch::default();
        let mut n = 0u64;
        for item in self.db.iterator_cf(self.cf(CF_RECEIPTS), IteratorMode::Start) {
            let (_, v) = item?;
            let r: CallReceipt = bincode::deserialize(&v)?;
            batch.put_cf(self.cf(CF_RECEIPTS_BY_PROGRAM), receipt_index_key(&r.program, r.height, r.index), r.tx.as_bytes());
            n += 1;
            if n % 1_000 == 0 {
                self.db.write(std::mem::take(&mut batch))?;
            }
        }
        batch.put_cf(self.cf(CF_META), META_RECEIPTS_INDEX_BUILT.as_bytes(), [1u8]);
        self.db.write(batch)?;
        if n > 0 {
            tracing::info!("built the receipts-by-program index from {n} receipts");
        }
        Ok(())
    }

    /// Receipts a program's calls produced, height then index, from `from` up to and including
    /// `to`, at least `limit` of them: `limit` is a soft floor at height granularity, so a page
    /// never splits a height — once it is reached, the page keeps taking the rest of the height
    /// already in progress before it stops, which can exceed `limit` by the rest of that
    /// height's calls (bounded by however many calls one block can hold). The second return is
    /// `None` when the page reached `to` or ran out of receipts, and otherwise the first height
    /// this page did not serve at all — always strictly above every height it did, so a caller
    /// resuming from it never sees a receipt twice.
    pub fn receipts_for_program(&self, program: &ProgramId, from: u64, to: u64, limit: usize) -> Result<(Vec<CallReceipt>, Option<u64>)> {
        // A zero limit never consumes a receipt, so it must never hand back a `next` either —
        // otherwise a caller that follows the cursor loops forever on the same height.
        if limit == 0 {
            return Ok((Vec::new(), None));
        }
        let start = receipt_index_key(program, from, 0);
        let mut out = Vec::new();
        let mut next = None;
        let mut last_height = None;
        for item in self.db.iterator_cf(self.cf(CF_RECEIPTS_BY_PROGRAM), IteratorMode::From(&start, rocksdb::Direction::Forward)) {
            let (k, v) = item?;
            if k.len() != 44 || &k[..32] != program.as_bytes() {
                break;
            }
            let height = u64::from_be_bytes(k[32..40].try_into().unwrap());
            if height > to {
                break;
            }
            // The floor is reached: stop, but only at the first row from a height that is not
            // the one already in progress, so this height's remaining rows are still served.
            if out.len() >= limit && last_height != Some(height) {
                next = Some(height);
                break;
            }
            let tx = Hash(v[..].try_into().map_err(|_| StorageError::Corrupt("receipt index value".into()))?);
            if let Some(r) = self.receipt(&tx)? {
                out.push(r);
                last_height = Some(height);
            }
        }
        Ok((out, next))
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
    /// The genesis parameters — the faucet and confidential switches, `epoch_blocks` and
    /// `max_program_words` — come from the genesis file, not from storage, so the ledger this
    /// returns carries their defaults. It is not a ledger to run a chain on:
    /// [`crate::node::reload_ledger`] is the one way to get a runnable one, and it sets them.
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
            if anchors.len() >= randprotocol_core::ledger::ANCHOR_WINDOW {
                break;
            }
            let (k, v) = item?;
            anchors.push((be_u64(k.as_ref(), "anchor key")?, word8(&v, "anchor")?));
        }
        anchors.reverse();
        let validators = self.register()?;
        let mut programs = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start) {
            let (_, v) = item?;
            let rec: ProgramRecord = bincode::deserialize(&v)?;
            programs.insert(rec.id, rec);
        }
        let mut ledger =
            Ledger::from_parts(chain_id, hc_bundle, tree, commitments, nullifiers, anchors, validators, programs);
        ledger.set_supply(self.supply()?);
        ledger.set_unsealed_fees(self.unsealed_fees()?);
        ledger.set_aggregators(self.aggregators()?);
        ledger.set_aggregation(self.aggregation_config()?);
        ledger.set_bridge(self.load_bridge()?);
        ledger.set_tokens(self.tokens()?);
        Ok(ledger)
    }

    /// Atomically append committed blocks, the state they produced, and the epoch sets the
    /// replica recorded while committing them.
    ///
    /// `epoch_sets` is `Action::RecordEpochSet` distilled: `(epoch, set)` for every epoch whose
    /// first block is in `blocks`. They go into the same batch as the blocks on purpose — a set
    /// written after the block it belongs to would be lost by a crash in between, and the epoch's
    /// QCs would become unverifiable on the next replay.
    ///
    /// `executor` is here for one reason: a bridge deposit's note commitment is computed by the
    /// chain rather than carried on the wire, so indexing it means hashing it (`created_notes`).
    pub fn commit(
        &self,
        blocks: &[CommittedBlock],
        ledger_after: &Ledger,
        epoch_sets: &[(u64, ValidatorSet)],
        executor: &dyn ConfidentialExecutor,
    ) -> Result<()> {
        if blocks.is_empty() {
            // A record without a block should not happen (the replica emits them together), but
            // dropping one silently would cost an epoch's verifiability.
            if !epoch_sets.is_empty() {
                let mut batch = WriteBatch::default();
                for (epoch, set) in epoch_sets {
                    batch.put_cf(self.cf(CF_EPOCH_SETS), height_key(*epoch), bincode::serialize(set)?);
                }
                self.db.write_opt(batch, &sync_opts())?;
            }
            return Ok(());
        }
        let head = self.head()?;
        let first_height = head.height + 1;
        let mut expected_height = first_height;
        let mut expected_parent = head.hash;
        let mut next_index = self.notes_count()?;
        // Register rows this commit must rewrite: the proposers and every validator an action
        // named.
        let mut touched: BTreeSet<Address> = BTreeSet::new();
        // The bridge rows these blocks add. Digests are read off the transactions rather than
        // diffed against the previous state, so a commit stays O(block); the burn log is a
        // suffix of the ledger's, taken from the sequence the last commit left behind.
        let mut has_bridge_tx = false;
        let mut spent_digests: BTreeSet<Hash> = BTreeSet::new();
        let first_burn_sequence = self.bridge_meta()?.map(|m| m.burn_sequence).unwrap_or(0);
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
            // The notes the ledger created itself, in append order (see `CommittedBlock`). They
            // are interleaved with the transactions' own: a `Withdraw` carries no bundle, so its
            // deposit is the next leaf after whatever the transaction before it appended, and
            // each one knows the index it was given — which is what this loop checks as it goes.
            let mut deposits = cb.deposits.iter().peekable();
            for (index, tx) in block.transactions.iter().enumerate() {
                // A block that arrived in sealed form (spec §7) carries its pruned bundles in
                // marker form with a side table keyed by proof hash: those txs become their
                // Pruned records — the form the pruning pass would have produced, keyed by the
                // *raw* tx hash the table attests — and everything else a Raw record, keyed by
                // its own hash. The block itself is stored as served (marker forms included).
                let pruned = tx
                    .bundle
                    .as_ref()
                    .and_then(|b| randprotocol_core::notes::pruned_proof_hash(&b.proof))
                    .and_then(|ph| cb.pruned.iter().find(|p| p.proof_hash == ph));
                let (key, record) = match pruned {
                    Some(p) => (
                        p.tx_hash,
                        TxRecord::Pruned {
                            height: block.height(),
                            index: index as u32,
                            tx_hash: p.tx_hash,
                            tx: tx.clone(),
                            proof_hash: p.proof_hash,
                            public_values: p.public_values.clone(),
                            shape: p.shape,
                        },
                    ),
                    None => (tx.hash(), TxRecord::Raw { height: block.height(), index: index as u32, tx: tx.clone() }),
                };
                batch.put_cf(self.cf(CF_TXS), key.as_bytes(), bincode::serialize(&record)?);
                if let Some(p) = pruned {
                    batch.put_cf(
                        self.cf(CF_SEALS),
                        [b"p".as_slice(), p.proof_hash.as_bytes()].concat(),
                        bincode::serialize(&p.tx_hash)?,
                    );
                }
            }
            // The sealing marks land in the same batch (spec §6.1): atomically with the block
            // that carries the aggregate — their per-block flags refresh after it lands. The
            // aggregate's payment facts land too (spec §5.4): the schedule index is the
            // post-block counter less the one this aggregate minted (at most one per block,
            // spec §3.4), and the proving share is the covered bundles' excess over the floor,
            // read off their own public fee fields.
            for tx in &block.transactions {
                if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                    for cover in covers {
                        batch.put_cf(
                            self.cf(CF_SEALS),
                            [b"t".as_slice(), cover.as_bytes()].concat(),
                            bincode::serialize(&(tx.hash(), block.height()))?,
                        );
                    }
                    if let Some(cfg) = ledger_after.aggregation() {
                        let n = ledger_after.supply().sealed_blocks.saturating_sub(1);
                        let subsidy = randprotocol_core::gas::subsidy(n, cfg);
                        let mut shares = 0u64;
                        for cover in covers {
                            if let Some(covered_tx) = self.tx_by_hash(cover)? {
                                if let Some(b) = &covered_tx.bundle {
                                    shares = shares.saturating_add(b.fee.saturating_sub(randprotocol_core::gas::BUNDLE_BASE));
                                }
                            }
                        }
                        batch.put_cf(
                            self.cf(CF_SEALS),
                            [b"a".as_slice(), tx.hash().as_bytes()].concat(),
                            bincode::serialize(&(subsidy, shares, n))?,
                        );
                    }
                }
            }
            for tx in &block.transactions {
                for nf in tx.nullifiers() {
                    batch.put_cf(self.cf(CF_NULLIFIERS), word8_to_bytes(&nf), hk);
                }
                for (cm, envelope) in created_notes(tx, ledger_after.tokens(), executor)? {
                    let row = NoteRow { cm, envelope, height: block.height() };
                    batch.put_cf(self.cf(CF_NOTES), height_key(next_index), bincode::serialize(&row)?);
                    next_index += 1;
                }
                while deposits.peek().is_some_and(|d| d.index == next_index) {
                    let d = deposits.next().expect("peeked");
                    let row = NoteRow { cm: d.cm, envelope: d.envelope.clone(), height: block.height() };
                    batch.put_cf(self.cf(CF_NOTES), height_key(next_index), bincode::serialize(&row)?);
                    next_index += 1;
                }
                if matches!(tx.action, Action::BridgeAttest { .. } | Action::BridgeBurn { .. }) {
                    has_bridge_tx = true;
                    // An admitted attestation names exactly one digest; none at all means the
                    // bytes no longer decode, which for a committed block is a torn block.
                    if matches!(tx.action, Action::BridgeAttest { .. }) && tx.bridge_digests().is_empty() {
                        return Err(StorageError::Corrupt(format!(
                            "committed attestation in block {} does not decode",
                            block.height()
                        )));
                    }
                    spent_digests.extend(tx.bridge_digests());
                }
            }
            if let Some(d) = deposits.next() {
                return Err(StorageError::Corrupt(format!(
                    "block {} reports a deposit at leaf {} that no transaction of it accounts for",
                    block.height(),
                    d.index
                )));
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
                batch.put_cf(self.cf(CF_RECEIPTS_BY_PROGRAM), receipt_index_key(&r.program, r.height, r.index), r.tx.as_bytes());
            }
            touched.insert(block.proposer());
            for tx in &block.transactions {
                match &tx.action {
                    Action::Bond { validator, .. }
                    | Action::Unbond { validator, .. }
                    | Action::Withdraw { validator, .. } => {
                        touched.insert(*validator);
                    }
                    _ => {}
                }
            }
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
        // A proposer's entry changes because it collects the block's fees; since phase S2 a
        // staking action changes the entry it names, and a registration adds one that was not
        // there at all. `touched` is both.
        for addr in &touched {
            match ledger_after.validators().get(addr) {
                Some(entry) => batch.put_cf(self.cf(CF_VALIDATORS), addr.as_bytes(), bincode::serialize(entry)?),
                // A proposer must be in the register (`apply_block` rejects a block otherwise);
                // an action's target may not be, if the transaction was refused — but a refused
                // transaction is not in a committed block either.
                None => {
                    return Err(StorageError::Corrupt(format!(
                        "committed block touches validator {addr}, which is not in the register"
                    )))
                }
            }
        }
        for rec in ledger_after.programs().values() {
            if rec.deployed_at >= first_height {
                batch.put_cf(self.cf(CF_PROGRAMS), rec.id.as_bytes(), bincode::serialize(rec)?);
            }
        }
        // The public words are read off the deploys themselves — the ledger keeps only their
        // digest. A redeploy of a program already on chain rewrites the same words under the
        // same content-addressed id, which is harmless.
        for tx in blocks.iter().flat_map(|cb| cb.block.transactions.iter()) {
            if let Action::Deploy { base_pc, words, public } = &tx.action {
                let id = randprotocol_core::program::program_id_with_public(*base_pc, words, public);
                if !public.is_empty() && ledger_after.program(&id).is_some() {
                    batch.put_cf(self.cf(CF_PROGRAM_PUBLIC), id.as_bytes(), bincode::serialize(public)?);
                }
            }
        }
        for (epoch, set) in epoch_sets {
            batch.put_cf(self.cf(CF_EPOCH_SETS), height_key(*epoch), bincode::serialize(set)?);
        }
        // The bridge's own rows, in the same batch as the blocks that produced them: a node
        // that reloaded a consumed-digest set older than its head would re-admit an attestation
        // the chain has already paid out.
        if has_bridge_tx {
            let bridge = ledger_after.bridge().ok_or_else(|| {
                StorageError::Corrupt("committed block has a bridge transaction but the ledger has no bridge".into())
            })?;
            for digest in &spent_digests {
                batch.put_cf(self.cf(CF_BRIDGE_SPENT), digest.as_bytes(), []);
            }
            for (sequence, rec) in bridge.burns.range(first_burn_sequence..) {
                batch.put_cf(self.cf(CF_BRIDGE_BURNS), height_key(*sequence), bincode::serialize(rec)?);
            }
            batch.put_cf(self.cf(CF_META), META_BRIDGE_STATE, bincode::serialize(&bridge.meta())?);
        }
        batch.put_cf(self.cf(CF_META), META_TREE, bincode::serialize(ledger_after.tree())?);
        batch.put_cf(self.cf(CF_META), META_SUPPLY, bincode::serialize(&ledger_after.supply())?);
        batch.put_cf(self.cf(CF_META), META_UNSEALED_FEES, bincode::serialize(ledger_after.unsealed_fees())?);
        batch.put_cf(self.cf(CF_META), META_AGGREGATORS, bincode::serialize(ledger_after.aggregators())?);
        batch.put_cf(self.cf(CF_META), META_TOKENS, bincode::serialize(&ledger_after.tokens().cloned())?);
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(last_height));
        self.db.write_opt(batch, &sync_opts())?;
        // The sealing marks' per-block half (spec §6.1): the bundle marks went in with the
        // batch above; the flags read them, so they refresh after it lands.
        for cb in blocks {
            for tx in &cb.block.transactions {
                if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                    for cover in covers {
                        self.refresh_block_sealed_flag(cover)?;
                    }
                }
            }
        }
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
        // The chain's FRI profile as the ledger's mirror enum (genesis-validated at load),
        // for the declared shapes the covered-carrying replay reads off raw proofs.
        let profile = match gs.fri_profile.as_str() {
            "test" => randprotocol_core::types::FriProfile::Test,
            "production" => randprotocol_core::types::FriProfile::Production,
            other => panic!("genesis fri_profile {other} was validated at load"),
        };
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
        // The set each epoch runs with, re-derived from the replay rather than read from the
        // database: the database's copy is exactly what this check is auditing. Epoch 0 is the
        // genesis set by definition.
        let epoch_blocks = gs.epoch_blocks.max(1);
        // Epoch 0 is the genesis set by definition, but `resume` reads its set from the stored
        // row like any other epoch (`epoch_set(0)`) — so a corrupt row there would be invisible
        // to everything below, which only ever consults `sets`, never the database's copy.
        let epoch0_problem = match self.epoch_set(0) {
            Ok(Some(stored)) if stored == gs.validators => None,
            Ok(Some(_)) => Some("the stored validator set for epoch 0 is not the genesis set".to_string()),
            Ok(None) => Some("no stored validator set for epoch 0".to_string()),
            Err(e) => Some(format!("epoch 0 set unreadable: {e}")),
        };
        if let Some(problem) = epoch0_problem {
            check.problem = Some(problem);
            check.last_good = 0;
            check.ledger = ledger.clone();
            return Ok(check);
        }
        let mut sets: BTreeMap<u64, ValidatorSet> = BTreeMap::new();
        sets.insert(0, gs.validators.clone());
        for h in 1..=head {
            let problem = (|| -> std::result::Result<(), String> {
                // A block at the first height of an epoch fixes that epoch's set, from the
                // register as of its parent — the same rule consensus used
                // (`HotStuff::shared_set_for_height`), including carrying a previous set forward
                // when the register derives nothing.
                let epoch = h / epoch_blocks;
                if h % epoch_blocks == 0 {
                    let mut derived = ledger.derive_next_set();
                    if derived.is_empty() {
                        derived = sets
                            .get(&(epoch - 1))
                            .cloned()
                            .ok_or_else(|| format!("epoch {} has no set to carry into epoch {epoch}", epoch - 1))?;
                    }
                    match self.epoch_set(epoch) {
                        Ok(Some(stored)) if stored == derived => {}
                        Ok(Some(_)) => {
                            return Err(format!(
                                "the stored validator set for epoch {epoch} is not the one block {h} derives"
                            ))
                        }
                        Ok(None) => return Err(format!("no stored validator set for epoch {epoch}")),
                        Err(e) => return Err(format!("epoch {epoch} set unreadable: {e}")),
                    }
                    sets.insert(epoch, derived);
                }
                let set = sets
                    .get(&epoch)
                    .ok_or_else(|| format!("no validator set for epoch {epoch} at block {h}"))?;
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
                if block.proposer() != set.leader(block.view()) {
                    return Err(format!("block {h} proposer is not the leader of view {}", block.view()));
                }
                // A QC certifies the block it is stored with, so it is verified against the set
                // of *that block's* epoch — not the current one, and not genesis's.
                if mode == VerifyMode::Full && !qc.verify(set, &gs.hash()) {
                    return Err(format!("qc {h} has invalid or insufficient votes for epoch {epoch}"));
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
                // anchor and the header's state root — so the replay cannot drift from it. A
                // block carrying an `Aggregate` replays through the covered-carrying path, its
                // records read from the store with no admission policy attached: the covered
                // bundles may be sealed or pruned *now*, which says nothing about the block
                // then — and the pruned record carries exactly the 34 public values and the
                // shape the apply reads (spec §6.2's proof, as code).
                let mut sidecar = BTreeMap::new();
                for (index, tx) in block.transactions.iter().enumerate() {
                    if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                        let mut records = Vec::with_capacity(covers.len());
                        for cover in covers {
                            let record = self
                                .covered_record(cover, profile)
                                .map_err(|e| format!("cover {cover} unreadable at block {h}: {e}"))?
                                .ok_or_else(|| format!("cover {cover} of block {h} names no stored bundle"))?;
                            records.push(record);
                        }
                        sidecar.insert(index, records);
                    }
                }
                let mut next = ledger.clone();
                let receipts = next
                    .apply_block_with_covered(&block, &sidecar, executor)
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
            // The supply counters are outside `Ledger`'s equality (nothing hashes them), so they
            // are audited here explicitly: this is the replay the RPC's numbers are worth.
            Ok(stored) if stored == ledger && stored.supply() != ledger.supply() => {
                check.problem = Some(format!(
                    "stored supply {:?} does not match the replayed chain's {:?}",
                    stored.supply(),
                    ledger.supply()
                ))
            }
            // The bucket is outside `Ledger`'s equality for the same reason, so it is audited
            // beside the counters: the next aggregate's payout is computed from it.
            Ok(stored) if stored == ledger && stored.unsealed_fees() != ledger.unsealed_fees() => {
                check.problem = Some(format!(
                    "stored unsealed fees {:?} do not match the replayed chain's {:?}",
                    stored.unsealed_fees(),
                    ledger.unsealed_fees()
                ))
            }
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
        // The replayed ledger holds no public words to rewrite, only which programs survive: a
        // row whose program is gone goes with it, and the rest are content-addressed, so still
        // right.
        for item in self.db.iterator_cf(self.cf(CF_PROGRAM_PUBLIC), IteratorMode::Start) {
            let (k, _) = item?;
            let keep = <[u8; 32]>::try_from(&k[..]).is_ok_and(|id| ledger.program(&Hash(id)).is_some());
            if !keep {
                batch.delete_cf(self.cf(CF_PROGRAM_PUBLIC), k);
            }
        }
        // The bridge families have no per-height key — a consumed digest does not say which
        // block consumed it — so they are rebuilt wholesale from the replayed ledger rather
        // than pruned.
        self.clear_bridge(&mut batch)?;
        if let Some(bridge) = ledger.bridge() {
            self.put_bridge(&mut batch, bridge)?;
        }
        for item in self.db.iterator_cf(self.cf(CF_RECEIPTS), IteratorMode::Start) {
            let (k, v) = item?;
            let keep = bincode::deserialize::<CallReceipt>(&v).map(|r| r.height <= height).unwrap_or(false);
            if !keep {
                batch.delete_cf(self.cf(CF_RECEIPTS), k);
                if let Ok(r) = bincode::deserialize::<CallReceipt>(&v) {
                    batch.delete_cf(self.cf(CF_RECEIPTS_BY_PROGRAM), receipt_index_key(&r.program, r.height, r.index));
                }
            }
        }
        // Epoch sets above the epoch the new head is in describe blocks this chain no longer
        // has. The epoch the head is *in* stays: its first block is still on the chain (or is
        // the head itself), and its set is what verifies the QCs of the blocks that remain.
        let head_epoch = height / gs.epoch_blocks.max(1);
        for item in self.db.iterator_cf(self.cf(CF_EPOCH_SETS), IteratorMode::End) {
            let (k, _) = item?;
            if be_u64(k.as_ref(), "epoch set key")? <= head_epoch {
                break;
            }
            batch.delete_cf(self.cf(CF_EPOCH_SETS), k);
        }
        if height == 0 {
            // A rewritten genesis is a rewritten epoch 0.
            batch.put_cf(self.cf(CF_EPOCH_SETS), height_key(0), bincode::serialize(&gs.validators)?);
        }
        batch.put_cf(self.cf(CF_META), META_TREE, bincode::serialize(ledger.tree())?);
        batch.put_cf(self.cf(CF_META), META_SUPPLY, bincode::serialize(&ledger.supply())?);
        batch.put_cf(self.cf(CF_META), META_UNSEALED_FEES, bincode::serialize(ledger.unsealed_fees())?);
        batch.put_cf(self.cf(CF_META), META_AGGREGATORS, bincode::serialize(ledger.aggregators())?);
        batch.put_cf(self.cf(CF_META), META_TOKENS, bincode::serialize(&ledger.tokens().cloned())?);
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

    /// Test hook: overwrite the certificate stored for a block height, so a chain can be given a
    /// QC that was signed by the wrong epoch's validators.
    pub fn overwrite_qc_for_testing(&self, height: u64, qc: &QuorumCertificate) -> Result<()> {
        self.db.put_cf(self.cf(CF_QCS), height_key(height), bincode::serialize(qc)?)?;
        Ok(())
    }
}

/// Fixtures shared by the storage tests and the RPC tests, which need a database holding a real
/// shielded chain to answer against. Everything here is built with `StubExecutor`, whose bundle
/// "proof" is the digest it publishes: these tests are about storage, not about the zkVM.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::bridge::{guardian_address, BridgeConfig};
    use randprotocol_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisToken, GenesisValidator, TokensConfig};
    use randprotocol_core::notes::{word8_to_hex, Bundle, ShieldedAddress};
    use randprotocol_core::{gas, BlockHeader, Keypair, Transaction};

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
        genesis_with_epochs(chain_id, alloc, randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT)
    }

    pub(crate) fn genesis_with_epochs(chain_id: u64, alloc: Vec<GenesisNote>, epoch_blocks: u64) -> GenesisState {
        genesis_of(chain_id, &[&key(1)], alloc, epoch_blocks)
    }

    /// A validator's payout address. It only has to parse and be a fixed width; nothing in these
    /// tests opens the note a withdraw would seal to it.
    pub(crate) fn payout(i: u8) -> randprotocol_core::notes::ShieldedAddress {
        randprotocol_core::notes::ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i; randprotocol_core::notes::KEM_EK_BYTES] }
    }

    /// A genesis staking each of `validators` at the minimum — below it an entry is in the
    /// register but in no epoch's set, which genesis refuses.
    pub(crate) fn genesis_of(
        chain_id: u64,
        validators: &[&Keypair],
        alloc: Vec<GenesisNote>,
        epoch_blocks: u64,
    ) -> GenesisState {
        genesis_file_of(chain_id, validators, alloc, epoch_blocks).build(&StubExecutor).unwrap()
    }

    /// The genesis file [`genesis_of`] builds, for a test that needs to set a field first.
    pub(crate) fn genesis_file_of(
        chain_id: u64,
        validators: &[&Keypair],
        alloc: Vec<GenesisNote>,
        epoch_blocks: u64,
    ) -> Genesis {
        Genesis {
            chain_id,
            timestamp_ms: 0,
            validators: validators
                .iter()
                .enumerate()
                .map(|(i, k)| GenesisValidator {
                    public_key: k.public_key().clone(),
                    stake: randprotocol_core::ledger::staking::MIN_STAKE as u128,
                    payout: payout(i as u8 + 1).to_string(),
                })
                .collect(),
            alloc,
            faucet: true,
            confidential: true,
            fri_profile: "test".into(),
            hc_bundle: word8_to_hex(&HC),
            bridge: None,
            tokens: None,
            aggregation: None,
            epoch_blocks,
            max_program_words: None,
            max_proof_bytes: None,
            max_block_bytes: None,
            max_call_envelope_bytes: None,
            max_program_public_words: None,
        }
    }

    /// A chain with no alloc notes: the empty tree.
    pub(crate) fn genesis(chain_id: u64) -> GenesisState {
        genesis_with(chain_id, Vec::new())
    }

    /// Six guardian secrets and the `bridge` section naming their addresses, with chain 2
    /// registered as a source emitter.
    pub(crate) fn bridge_config() -> (BridgeConfig, Vec<[u8; 32]>) {
        let secrets: Vec<[u8; 32]> = (1u8..=6).map(|i| [i; 32]).collect();
        let config = BridgeConfig {
            emitter: [1; 32],
            guardians: secrets.iter().map(guardian_address).collect(),
            emitters: std::collections::BTreeMap::from([(2u16, [2u8; 32])]),
        };
        (config, secrets)
    }

    /// [`genesis`] with a `bridge` section, and the guardian secrets that can attest to it.
    /// Its state root has the fifth component, which is what makes it useful for the reload test.
    pub(crate) fn bridged_genesis(chain_id: u64) -> (GenesisState, Vec<[u8; 32]>) {
        let (config, secrets) = bridge_config();
        let k = key(1);
        let gs = Genesis {
            chain_id,
            timestamp_ms: 0,
            validators: vec![GenesisValidator {
                public_key: k.public_key().clone(),
                // Phase S2: at least the staking minimum, and a payout address — both required,
                // and both part of the genesis binding.
                stake: randprotocol_core::ledger::staking::MIN_STAKE as u128,
                payout: payout(1).to_string(),
            }],
            alloc: Vec::new(),
            faucet: true,
            confidential: true,
            fri_profile: "test".into(),
            hc_bundle: word8_to_hex(&HC),
            bridge: Some(config),
            // A bridge section needs a tokens section (the RPL gate rides the same fork), and a
            // bridged token is *listed* there before any attestation of it is admissible. The
            // fixture lists [`TOKEN`] and nothing else, so it takes index 1 — the number every
            // bridge fixture below deposits and burns under, which used to come from first
            // sighting and now comes from this line.
            tokens: Some(TokensConfig {
                registration_fee: 1_000_000_000,
                tokens: vec![GenesisToken {
                    name: "Tether USD".into(),
                    symbol: "zUSDT".into(),
                    salt: [0x5a; 32],
                    // Eight decimals — the attestation wire's own — so this coin's release unit is 1 and no
                    // fixture burn here is ever refused for it; the release-unit rule itself is
                    // `randprotocol-core`'s to test.
                    backings: vec![randprotocol_core::genesis::GenesisBacking { chain: 2, token: TOKEN, decimals: 8 }],
                }],
            }),
            aggregation: None,
            epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
            max_program_words: None,
            max_proof_bytes: None,
            max_block_bytes: None,
            max_call_envelope_bytes: None,
            max_program_public_words: None,
        }
        .build(&StubExecutor)
        .unwrap();
        (gs, secrets)
    }

    /// The canonical test token, native to chain 2. The first asset any attestation below
    /// names, so the registry gives it note index 1.
    pub(crate) const TOKEN: [u8; 32] = [0xaa; 32];

    /// A well-formed EVM burn destination: twelve zero bytes then twenty address bytes.
    pub(crate) const EVM_TO: [u8; 32] = {
        let mut t = [0u8; 32];
        let mut i = 12;
        while i < 32 {
            t[i] = 0x22;
            i += 1;
        }
        t
    };

    /// The shielded address every fixture deposit is addressed to.
    pub(crate) fn recipient() -> ShieldedAddress {
        ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] }
    }

    /// An attestation of `amount` units of [`TOKEN`] to `to`, emitted by chain 2's registered
    /// emitter and signed by five of the six guardians in [`bridge_config`]. `sequence`
    /// distinguishes otherwise identical bodies, and so their digests.
    pub(crate) fn attestation(secrets: &[[u8; 32]], to: &ShieldedAddress, amount: u128, sequence: u64) -> Vec<u8> {
        use randprotocol_core::bridge::{digest, sign_digest, Attestation, Body, Payload, Transfer, CHAIN_RAND};
        let body = Body {
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
                to: to.recipient_hash(),
                to_chain: CHAIN_RAND,
                fee: Transfer::u256_from_u128(0),
            })
            .encode(),
        };
        let d = digest(&body.encode());
        let signatures = (0..5u8).map(|i| sign_digest(&secrets[i as usize], i, &d)).collect();
        Attestation { guardian_set_index: 0, signatures, body }.encode()
    }

    /// The transaction a relayer submits for `attestation`, naming the asset index the registry
    /// would deposit under — what an honest wallet fills in. Its fee bundle's four words are
    /// `seed..seed + 3`, so two fixtures with different seeds never collide.
    pub(crate) fn attest_tx(ledger: &Ledger, attestation: Vec<u8>, seed: u32) -> Transaction {
        let asset = deposit_index(ledger, &attestation);
        Transaction::shielded(
            ledger.chain_id(),
            bundle(ledger, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], gas::BUNDLE_BASE),
            Action::BridgeAttest {
                attestation,
                recipient: recipient(),
                r: [7; 8],
                time: ledger.height() as u32,
                asset,
                envelope: env(seed as u8),
            },
        )
    }

    /// The `asset` word an honest submitter fills in: the index `ledger`'s token registry says
    /// this attestation deposits under, or 0 for a rotation (which deposits nothing) and for a
    /// token this chain has not listed (which is refused outright).
    pub(crate) fn deposit_index(ledger: &Ledger, attestation: &[u8]) -> u32 {
        randprotocol_core::ledger::bridge_notes::attested_transfer(attestation)
            .and_then(|(chain, token, _)| ledger.tokens().and_then(|t| t.bridged(chain, &token)).map(|info| info.index))
            .unwrap_or(0)
    }

    /// A burn of `amount` of asset index `asset` to chain 2, paying the bundle base for each of
    /// its two bundles. The asset bundle's words are `seed..seed + 3` and the fee bundle's
    /// `seed + 4..seed + 7`.
    pub(crate) fn burn_tx(ledger: &Ledger, asset: u32, amount: u64, relayer_fee: u64, seed: u32) -> Transaction {
        let mut asset_bundle =
            bundle(ledger, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], 0);
        asset_bundle.asset = asset;
        asset_bundle.burn = amount;
        let d = StubExecutor.bundle_digest(&asset_bundle.digest_input());
        asset_bundle.proof = StubExecutor::make_bundle_proof(&HC, &d);
        Transaction::shielded(
            ledger.chain_id(),
            bundle(ledger, [[seed + 4; 8], [seed + 5; 8]], [[seed + 6; 8], [seed + 7; 8]], gas::BRIDGE_BURN_FEE),
            Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain: 2, token: TOKEN, to: EVM_TO },
        )
    }

    /// A `TokenTransfer` of asset index `asset` whose asset bundle spends `nfs` and creates `cms`,
    /// with a RAND fee bundle at `fee_seed..fee_seed + 3` paying for both bundles.
    pub(crate) fn transfer_tx_with(
        ledger: &Ledger,
        asset: u32,
        nfs: [Word8; 2],
        cms: [Word8; 2],
        fee_seed: u32,
        memo: Option<Vec<u8>>,
    ) -> Transaction {
        let mut asset_bundle = bundle(ledger, nfs, cms, 0);
        asset_bundle.asset = asset;
        let d = StubExecutor.bundle_digest(&asset_bundle.digest_input());
        asset_bundle.proof = StubExecutor::make_bundle_proof(&HC, &d);
        Transaction::shielded(
            ledger.chain_id(),
            bundle(
                ledger,
                [[fee_seed; 8], [fee_seed + 1; 8]],
                [[fee_seed + 2; 8], [fee_seed + 3; 8]],
                2 * gas::BUNDLE_BASE,
            ),
            Action::TokenTransfer { asset_bundle, memo },
        )
    }

    /// [`transfer_tx_with`] laid out like [`burn_tx`]: the asset bundle's words are
    /// `seed..seed + 3` and the fee bundle's `seed + 4..seed + 7`.
    pub(crate) fn transfer_tx(ledger: &Ledger, asset: u32, seed: u32, memo: Option<Vec<u8>>) -> Transaction {
        transfer_tx_with(ledger, asset, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], seed + 4, memo)
    }

    /// A bridged chain funded for a withdraw (one bundle fee, one validator staked) — the shared
    /// setup under the S2×S3 seam tests, their `BridgeBurn` variant, and the RPC test that renders
    /// both derived-note mechanisms through a compact block.
    pub(crate) fn bridged_chain_funded_for_a_withdraw(
        chain_id: u64,
    ) -> (tempfile::TempDir, Storage, GenesisState, Vec<[u8; 32]>, CommittedBlock, Ledger, Keypair) {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let (gs, secrets) = bridged_genesis(chain_id);
        s.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let v = key(1);
        // Two fees, not one: `Withdraw` pays the bundle base to the block's proposer out of the
        // amount withdrawn, so an amount equal to just one fee is entirely eaten by that base
        // and rejected as `BelowBundleBase`.
        let fees = vec![
            bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee()),
            bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee()),
        ];
        let b1 = make_block_voted(&gs.block, &mut ledger, fees, &v, &[&v]);
        (dir, s, gs, secrets, b1, ledger, v)
    }

    /// An unopened database plus a genesis holding two deposit notes.
    pub(crate) fn genesis_with_two_notes() -> (tempfile::TempDir, Storage, GenesisState) {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)]);
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        (dir, s, gs)
    }

    /// [`genesis_with_two_notes`]'s genesis alone, for a test that opens its own database more
    /// than once and so cannot reuse that fixture's tempdir.
    pub(crate) fn genesis_with_two_notes_state() -> GenesisState {
        genesis_with(1, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)])
    }

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes, anchored to
    /// the newest root `ledger` has recorded and timed at its current height.
    pub(crate) fn bundle_tx(ledger: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Transaction {
        Transaction::shielded(ledger.chain_id(), bundle(ledger, nfs, cms, fee), Action::None)
    }

    /// A bundle anchored to the ledger's newest recorded root, whose stub proof publishes
    /// exactly the digest the ledger recomputes from its plaintext fields.
    pub(crate) fn bundle(ledger: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Bundle {
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
        b
    }

    /// A bundle-less `Withdraw` signed by `v` (ruling B of S2 task 3): it pays a note worth
    /// `amount - BUNDLE_BASE` to the register's payout address at `time`, and the base to the
    /// proposer of whichever block applies it.
    pub(crate) fn withdraw_tx(
        chain_id: u64,
        v: &Keypair,
        amount: u64,
        nonce: u64,
        time: u32,
        r: Word8,
    ) -> Transaction {
        let envelope = env(r[0] as u8);
        let signature = v.sign(
            randprotocol_core::withdraw_message(chain_id, &v.address(), amount, nonce, time, &r, &envelope).as_bytes(),
        );
        Transaction {
            chain_id,
            bundle: None,
            action: Action::Withdraw { validator: v.address(), amount, nonce, time, r, envelope, signature },
        }
    }

    /// A faucet mint of `amount` to a note nobody can open, owner and blinding both `tag`, its
    /// commitment the stub's; the envelope is a placeholder, which the chain never inspects.
    pub(crate) fn mint_tx(chain_id: u64, tag: Word8, amount: u64, minter: &Keypair) -> Transaction {
        Transaction::mint(chain_id, tag, 0, tag, env(tag[0] as u8), amount, minter, &StubExecutor)
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

    /// Which of `keys` leads `view` in `set`. A block proposed by anyone else is rejected as
    /// "not the leader", so a fixture chain with more than one validator cannot simply always
    /// propose with the same key.
    pub(crate) fn leader_among<'a>(set: &ValidatorSet, view: u64, keys: &[&'a Keypair]) -> &'a Keypair {
        let want = set.leader(view);
        keys.iter().copied().find(|k| k.address() == want).expect("the leader is one of these keys")
    }

    /// `make_block`, but with a quorum certificate really signed by `voters` — what a chain
    /// verified in `VerifyMode::Full` needs, and what makes a QC's validity depend on which
    /// epoch's set it is checked against.
    pub(crate) fn make_block_voted(
        parent: &Block,
        ledger: &mut Ledger,
        txs: Vec<Transaction>,
        k: &Keypair,
        voters: &[&Keypair],
    ) -> CommittedBlock {
        let mut cb = make_block(parent, ledger, txs, k);
        cb.qc.votes = voters.iter().map(|v| randprotocol_core::Vote::sign(cb.qc.view, cb.qc.block_hash, v)).collect();
        cb
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
        CommittedBlock { block, pruned: Vec::new(), qc, receipts: Vec::new(), deposits: ledger.deposits().to_vec() }
    }

    /// `n` blocks, each carrying one bundle that spends a fresh pair of nullifiers.
    pub(crate) fn chain_fixture(n: u64) -> (tempfile::TempDir, Storage, GenesisState, Vec<CommittedBlock>) {
        use randprotocol_core::Vote;
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
            st.commit(std::slice::from_ref(&cb), &ledger, &[], &StubExecutor).unwrap();
            out.push(cb);
            parent = block;
        }
        (dir, st, gs, out)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::ledger::ANCHOR_WINDOW;
    use randprotocol_core::Transaction;

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

    /// A restart must come back on the chain's own epoch length. `epoch_blocks` lives in the
    /// genesis file, not in the database, and `Unbond` writes `epoch() + UNBONDING_EPOCHS` into
    /// a register the state root hashes — so a node that reloaded with the default would
    /// compute a state root nobody else does and never rejoin.
    #[test]
    fn a_reloaded_ledger_comes_back_on_the_chains_own_epoch_length() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis_with_epochs(7, vec![alloc_note(20, 1_000)], 4);
        s.init_genesis(&gs).unwrap();
        assert_eq!(gs.ledger.epoch_blocks(), 4);
        // What the database alone knows: the state, and nothing the genesis file decides.
        assert_eq!(s.load_ledger(&StubExecutor).unwrap().epoch_blocks(), randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT);
        // What a restarting node runs on, through the one function `node::start` uses.
        let reloaded = crate::node::reload_ledger(&s, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.epoch_blocks(), 4, "the chain's epoch length, not the default");
        assert_eq!(reloaded.epoch(), gs.ledger.epoch());
        assert!(reloaded.faucet_enabled() && reloaded.confidential_enabled(), "and the other two switches");
        assert_eq!(reloaded, gs.ledger);
    }

    /// S3: the bridge column families, end to end. A bridged chain's state root has a fifth
    /// component, so a node that reloaded without the bridge would compute a different root
    /// than the blocks it produced before the restart — and one that reloaded only the
    /// *genesis* bridge would forget every asset registered, digest consumed and message
    /// emitted since.
    ///
    /// The chain here applies an attestation and a burn, so the registry, the consumed-digest
    /// set and the outbound log are all non-genesis by the time it is reloaded.
    #[test]
    fn a_bridged_genesis_reloads_to_the_same_state_root() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let (gs, secrets) = bridged_genesis(9);
        s.init_genesis(&gs).unwrap();
        assert!(gs.ledger.bridge().is_some());
        // The genesis bridge is on disk before any block: the `bridge` section is persisted,
        // not merely derived from the genesis file at every startup.
        assert_eq!(s.bridge_meta().unwrap().as_ref(), Some(&gs.ledger.bridge().unwrap().meta()));

        let mut ledger = gs.ledger.clone();
        let att = attest_tx(&ledger, attestation(&secrets, &recipient(), 1_000, 0), 20);
        let b1 = make_block(&gs.block, &mut ledger, vec![att.clone()], &key(1));
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        let burn = burn_tx(&ledger, 1, 400, 100, 30);
        let b2 = make_block(&b1.block, &mut ledger, vec![burn], &key(1));
        s.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        let live = ledger.bridge().unwrap();
        assert_eq!(
            ledger.tokens().unwrap().bridged(2, &TOKEN).map(|t| (t.index, t.total_supply)),
            Some((1, 600)),
            "the listed token's index, and the deposit less the burn"
        );
        assert_eq!(live.spent.len(), 1);
        assert_eq!(live.burns.len(), 1);

        // The two lines `node.rs` still runs after `load_ledger` are the genesis switches; the
        // bridge now comes from storage.
        let mut reloaded = s.load_ledger(&StubExecutor).unwrap();
        reloaded.set_faucet(gs.faucet);
        reloaded.set_confidential(gs.confidential);
        assert_eq!(reloaded.state_root(), ledger.state_root());
        assert_eq!(reloaded, ledger);
        let back = reloaded.bridge().expect("the bridge reloaded");
        assert_eq!(back.spent, live.spent, "the consumed digests survive the restart");
        assert_eq!(back.burns, live.burns, "and so does the outbound log");
        assert_eq!(
            reloaded.tokens().unwrap(),
            ledger.tokens().unwrap(),
            "and the token registry — indices and supplies — comes back whole"
        );

        // The deposit note is leaf 2 — after the fee bundle's two — and is served like any
        // other, so a wallet scanning the tree finds its bridged deposit.
        let deposit =
            randprotocol_core::ledger::bridge_notes::deposit_note(&att, reloaded.tokens().unwrap(), &StubExecutor)
                .unwrap();
        let row = s.note(2).unwrap().expect("the deposit note is indexed");
        assert_eq!((row.cm, row.envelope), deposit);
        assert_eq!(row.height, 1);

        // Guardians read the outbound message by sequence.
        let rec = s.bridge_burn(0).unwrap().expect("the burn record");
        assert_eq!(rec.digest, randprotocol_core::bridge::digest(&rec.body));
        assert_eq!(rec.height, 2);
        assert_eq!(s.bridge_burn(1).unwrap(), None);

        // Truncating back to genesis puts the bridge back to the genesis state exactly: no
        // registered asset, no consumed digest, no burn.
        let replayed = gs.ledger.clone();
        s.truncate_to(&gs, 0, &replayed).unwrap();
        assert_eq!(s.load_ledger(&StubExecutor).unwrap().bridge(), gs.ledger.bridge());
        assert_eq!(s.bridge_burn(0).unwrap(), None);
    }

    /// `--verify-chain` replays every block and compares the result to the stored snapshot,
    /// which on a bridged chain includes the bridge (`Ledger`'s equality covers it). A replay
    /// that did not reproduce the registry, the consumed digests or the burn log would truncate
    /// a chain that is perfectly good.
    #[test]
    fn verify_chain_replays_a_bridged_chain() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let (gs, secrets) = bridged_genesis(11);
        s.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let att = attest_tx(&ledger, attestation(&secrets, &recipient(), 1_000, 0), 20);
        let b1 = make_block(&gs.block, &mut ledger, vec![att], &key(1));
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        let burn = burn_tx(&ledger, 1, 400, 100, 30);
        let b2 = make_block(&b1.block, &mut ledger, vec![burn], &key(1));
        s.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        // Quick, not Full: `make_block` leaves the certificates unsigned, which is a vote
        // check, not a state check.
        let check = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert_eq!(check.problem, None);
        assert_eq!(check.last_good, 2);
        assert_eq!(check.ledger.bridge(), ledger.bridge(), "the replay rebuilt the bridge");
    }

    /// A `TokenTransfer` creates **four** notes — its fee bundle's two and its asset bundle's two
    /// — and the note index has to agree with the ledger leaf for leaf: a count one short would
    /// slide every wallet's leaf index after it, and every merkle path with them. All four are on
    /// the wire, so the ledger derives none of them.
    #[test]
    fn a_token_transfer_indexes_four_notes_in_the_ledgers_order() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let (gs, secrets) = bridged_genesis(12);
        s.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let att = attest_tx(&ledger, attestation(&secrets, &recipient(), 1_000, 0), 20);
        let b1 = make_block(&gs.block, &mut ledger, vec![att], &key(1));
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        let before = ledger.next_index();
        let t = transfer_tx(&ledger, 1, 30, Some(vec![9; 32]));
        let b2 = make_block(&b1.block, &mut ledger, vec![t.clone()], &key(1));
        s.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        assert_eq!(ledger.next_index(), before + 4, "two bundles, four leaves");
        assert_eq!(t.commitments().len(), 4, "and the wire carries all four");
        assert_eq!(derived_note_count(&t), 0, "so the ledger derives none of them");
        let notes = created_notes(&t, ledger.tokens(), &StubExecutor).unwrap();
        assert_eq!(
            notes.iter().map(|(cm, _)| *cm).collect::<Vec<_>>(),
            t.commitments(),
            "the fee bundle's two slots, then the asset bundle's — the order the ledger appends"
        );
        let rows = s.notes_in_heights(2, 2, 100).unwrap();
        assert_eq!(
            rows.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            (before..before + 4).collect::<Vec<_>>(),
            "and the four rows on disk carry the indices the ledger gave them"
        );
        // A transfer moves notes and nothing else: the token's public count is the deposit's.
        assert_eq!(ledger.tokens().unwrap().get(1).unwrap().total_supply, 1_000);
    }

    /// A chain whose genesis has no `bridge` section stores no bridge state at all, and
    /// reloads without one — which is what keeps its state root the four components phase S1
    /// hashed.
    #[test]
    fn a_chain_without_a_bridge_stores_none() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis(4);
        s.init_genesis(&gs).unwrap();
        assert_eq!(s.bridge_meta().unwrap(), None);
        assert!(s.load_ledger(&StubExecutor).unwrap().bridge().is_none());
    }

    /// The `BridgeMeta` blob lost two fields with the RPL token standard — the asset registry and
    /// its `next_index`, which live in the token registry now. A pre-RPL blob must therefore fail
    /// to decode rather than be *mis*-decoded: the fields left line up until `current_set`, and
    /// the next eight bytes of an old blob are the `assets` map's length, which plain bincode
    /// (which ignores trailing bytes) would hand back as `burn_sequence`. Chain 14 is a fresh
    /// datadir, so nothing live holds one; what must never happen is a node reading one as state.
    #[test]
    fn a_pre_rpl_bridge_blob_is_refused_rather_than_misread() {
        use randprotocol_core::bridge::GuardianSet;
        /// The blob as it was written before the registry moved out.
        #[derive(serde::Serialize)]
        struct OldBridgeMeta {
            emitter: [u8; 32],
            emitters: std::collections::BTreeMap<u16, [u8; 32]>,
            guardian_sets: std::collections::BTreeMap<u32, GuardianSet>,
            current_set: u32,
            /// `AssetId -> (chain, token, index)`, keyed by the 32-byte asset id.
            assets: std::collections::BTreeMap<[u8; 32], (u16, [u8; 32], u32)>,
            next_index: u32,
            burn_sequence: u64,
        }
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let (gs, _) = bridged_genesis(21);
        s.init_genesis(&gs).unwrap();
        assert!(s.bridge_meta().unwrap().is_some(), "a blob this build wrote decodes");

        let old = OldBridgeMeta {
            emitter: [1; 32],
            emitters: std::collections::BTreeMap::from([(2u16, [2u8; 32])]),
            guardian_sets: std::collections::BTreeMap::new(),
            current_set: 0,
            assets: std::collections::BTreeMap::from([([0xaa; 32], (2u16, [0xaa; 32], 1u32))]),
            next_index: 2,
            burn_sequence: 7,
        };
        let bytes = bincode::serialize(&old).unwrap();
        // Plain bincode is exactly the trap: it stops at the last field it wants and drops the
        // rest, reading the one-entry `assets` map's length as the burn sequence.
        let loose: BridgeMeta = bincode::deserialize(&bytes).unwrap();
        assert_eq!(loose.burn_sequence, 1, "a map length read as a sequence — the silent mis-decode");
        // The strict decode `bridge_meta` uses refuses it instead.
        s.db.put_cf(s.cf(CF_META), META_BRIDGE_STATE, &bytes).unwrap();
        assert!(s.bridge_meta().is_err(), "a pre-RPL blob is a decode error, never a bridge");
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
        assert_eq!(
            s.validator(&key(1).address()).unwrap().unwrap().stake,
            randprotocol_core::ledger::staking::MIN_STAKE
        );
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
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

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

    /// A v0.4 chain's raised program cap holds through replay and restart. The block below
    /// carries a deploy only a raised cap admits, so `verify_chain` passing proves the replay
    /// starts from the genesis ledger (which carries the cap) rather than from `load_ledger`
    /// (which comes back at 4 096 words), and `reload_ledger` admitting a second one proves a
    /// restarted node runs the genesis cap too — either one missed forks the node off at the
    /// first large program.
    #[test]
    fn a_raised_program_cap_holds_through_replay_and_restart() {
        let mut file = genesis_file_of(
            7,
            &[&key(1)],
            vec![alloc_note(20, 1_000), alloc_note(21, 2_000)],
            randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        );
        file.max_program_words = Some(65_535);
        let gs = file.build(&StubExecutor).unwrap();
        assert_eq!(gs.ledger.max_program_words(), 65_535);
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        s.init_genesis(&gs).unwrap();

        let deploy_tx = |ledger: &Ledger, seed: u32, word: u32| {
            let action = Action::Deploy { base_pc: 0, words: vec![word; 5_000], public: vec![] };
            let fee = randprotocol_core::gas::fee_floor(&action);
            let b = bundle(ledger, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], fee);
            Transaction::shielded(ledger.chain_id(), b, action)
        };
        let proposer = key(1);
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);
        let tx = deploy_tx(&ledger, 1, 0x13);
        let b1 = make_block(&gs.block, &mut ledger, vec![tx], &proposer);
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        assert_eq!(ledger.programs().len(), 1, "the 5 000-word program landed");

        // The stored snapshot alone is at the default: this is what replay must not start from.
        assert_eq!(s.load_ledger(&StubExecutor).unwrap().max_program_words(), randprotocol_core::gas::MAX_PROGRAM_WORDS);
        let check = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(check.is_ok(), "replay refused the chain's own block: {:?}", check.problem);
        assert_eq!(check.last_good, 1);

        let mut reloaded = crate::node::reload_ledger(&s, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.max_program_words(), 65_535);
        reloaded.set_height(2);
        // A different program (`addi x0, x0, 1`), so it is a new deploy rather than a no-op.
        let again = deploy_tx(&reloaded, 10, 0x0010_0013);
        assert_eq!(reloaded.validate(&again, &StubExecutor), Ok(()));
    }

    /// The four call-limits parameters hold through replay and restart the way the program cap
    /// does. This pins the plumbing (the rules that read them have their own ledger tests): a chain
    /// with chain 13's values replays its own committed block from the genesis ledger, the
    /// stored snapshot alone is at today's caps, and `reload_ledger` restores all four.
    #[test]
    fn the_call_limits_hold_through_replay_and_restart() {
        use randprotocol_core::gas;
        let mut file = genesis_file_of(
            7,
            &[&key(1)],
            vec![alloc_note(20, 1_000), alloc_note(21, 2_000)],
            randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        );
        file.max_proof_bytes = Some(8 << 20);
        file.max_block_bytes = Some(20 << 20);
        file.max_call_envelope_bytes = Some(65_536);
        file.max_program_public_words = Some(32_768);
        let gs = file.build(&StubExecutor).unwrap();
        let limits = |l: &Ledger| (l.max_proof_bytes(), l.max_block_bytes(), l.max_call_envelope_bytes(), l.max_program_public_words());
        let chain13 = (8 << 20, 20 << 20, 65_536, 32_768);
        assert_eq!(limits(&gs.ledger), chain13);
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        s.init_genesis(&gs).unwrap();

        let proposer = key(1);
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);
        let action = Action::Deploy { base_pc: 0, words: vec![0x13; 16], public: vec![] };
        let fee = gas::fee_floor(&action);
        let b = bundle(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee);
        let tx = Transaction::shielded(ledger.chain_id(), b, action);
        let b1 = make_block(&gs.block, &mut ledger, vec![tx], &proposer);
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        assert_eq!(limits(&ledger), chain13, "applying a block keeps them");

        // The stored snapshot alone is at today's caps: this is what replay must not start from.
        assert_eq!(
            limits(&s.load_ledger(&StubExecutor).unwrap()),
            (
                gas::MAX_PROOF_BYTES,
                gas::MAX_BLOCK_BYTES,
                randprotocol_core::types::actions::MAX_CALL_ENVELOPE_BYTES,
                gas::MAX_PROGRAM_PUBLIC_WORDS
            )
        );
        let check = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(check.is_ok(), "replay refused the chain's own block: {:?}", check.problem);
        assert_eq!(check.last_good, 1);

        let reloaded = crate::node::reload_ledger(&s, &gs, &StubExecutor).unwrap();
        assert_eq!(limits(&reloaded), chain13);
        assert_eq!(reloaded, ledger);
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
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        assert_eq!(s.notes_count().unwrap(), 3);
        assert_eq!(s.note(2).unwrap().unwrap(), NoteRow { cm: tx.commitments()[0], envelope: env(77), height: 1 });
        // A mint spends nothing and pays no fee.
        assert_eq!(s.nullifiers_count().unwrap(), 0);
        assert_eq!(s.validator(&minter.address()).unwrap().unwrap().rewards, 0);
        assert_eq!(s.load_ledger(&StubExecutor).unwrap(), ledger);
    }

    /// Phase S2 storage: a v2 register entry survives a round trip with every field it gained,
    /// and so does the set of every epoch the chain has seen start.
    #[test]
    fn v2_validator_entries_and_epoch_sets_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1), &key(2)], vec![], 4);
        s.init_genesis(&gs).unwrap();

        // Genesis rows carry the v2 shape: an empty unbonding queue, the payout address the
        // genesis file named, and a zero nonce.
        let row = s.validator(&key(1).address()).unwrap().unwrap();
        assert_eq!(row.stake, randprotocol_core::ledger::staking::MIN_STAKE);
        assert_eq!(row.pending, Vec::new());
        assert_eq!(row.rewards, 0);
        assert_eq!(row.nonce, 0);
        assert_eq!(row.payout, payout(1));
        assert_eq!(s.register().unwrap().len(), 2);

        // Every field of a written entry comes back, including a multi-entry queue.
        let mut changed = row.clone();
        changed.stake = 41;
        changed.pending = vec![(3, 100), (4, 250)];
        changed.rewards = 7;
        changed.nonce = 9;
        s.overwrite_validator_for_testing(&key(1).address(), &changed).unwrap();
        assert_eq!(s.validator(&key(1).address()).unwrap().unwrap(), changed);

        // Epoch 0 is the genesis set, written by `init_genesis`; nothing else is known yet.
        assert_eq!(s.epoch_set(0).unwrap().as_ref(), Some(&gs.validators));
        assert_eq!(s.epoch_set(1).unwrap(), None);
        let sets = s.load_epoch_sets().unwrap();
        assert_eq!(sets.get(0), Some(&gs.validators));
        assert_eq!(sets.known().count(), 1);
    }

    /// A chain whose block 2 carries a bundle *and* a `Withdraw`: the one shape in which the
    /// ledger creates a note no transaction carries, so storage has to interleave it with the
    /// notes the transactions do carry. Block 1's two bundles are what give the single validator
    /// the rewards it withdraws. Nothing is committed here — each test commits it itself.
    fn chain_with_a_withdraw() -> (tempfile::TempDir, Storage, GenesisState, [CommittedBlock; 2], Ledger) {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis_with(7, vec![alloc_note(20, 5 * randprotocol_core::UNITS_PER_RAND)]);
        s.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let v = key(1);

        let fees = vec![
            bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee()),
            bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee()),
        ];
        let b1 = make_block_voted(&gs.block, &mut ledger, fees, &v, &[&v]);
        assert_eq!(ledger.released(&v.address()), 2 * bundle_fee(), "two fees, both this proposer's");

        // The withdraw's `time` is a height the chain has reached, not the one that applies it —
        // the node seals its envelope before that height exists (ruling A).
        let amount = 2 * bundle_fee();
        let time = ledger.height() as u32;
        let txs = vec![
            bundle_tx(&ledger, [[9; 8], [10; 8]], [[11; 8], [12; 8]], bundle_fee()),
            withdraw_tx(gs.chain_id, &v, amount, 0, time, [13; 8]),
        ];
        let b2 = make_block_voted(&b1.block, &mut ledger, txs, &v, &[&v]);
        assert_eq!(b2.deposits.len(), 1, "the withdraw's note is the block's one ledger-made deposit");
        (dir, s, gs, [b1, b2], ledger)
    }

    /// The deposit a committed `Withdraw` made lands on disk at the leaf the ledger gave it —
    /// after the notes of the bundle ahead of it in the block — and a ledger reloaded from those
    /// rows has the same tree. That leaf order is a consensus fact: every node's tree has to
    /// append the same notes in the same order, and this is the one note that is not on the wire.
    #[test]
    fn a_committed_withdraw_writes_its_deposit_at_the_leaf_the_ledger_named() {
        let (_d, s, gs, blocks, ledger) = chain_with_a_withdraw();
        let deposit = blocks[1].deposits[0].clone();
        // The bundle ahead of the deposit carries two note slots and the withdraw carries none,
        // so the ledger gave the deposit the last leaf of the block.
        let on_the_wire: usize = blocks[1].block.transactions.iter().map(|t| t.commitments().len()).sum();
        assert_eq!(on_the_wire, 2, "one bundle's two slots, and nothing from the withdraw");
        s.commit(&blocks, &ledger, &[], &StubExecutor).unwrap();
        assert_eq!(deposit.index, ledger.next_index() - 1);
        let row = s.note(deposit.index).unwrap().expect("the deposit is a note row like any other");
        assert_eq!(row.cm, deposit.cm);
        assert_eq!(row.envelope, deposit.envelope, "the envelope the action carried, beside its note");
        assert_eq!(row.height, blocks[1].block.height());
        assert_eq!(s.notes_count().unwrap(), ledger.next_index(), "no leaf written twice or skipped");

        let reloaded = s.load_ledger(&StubExecutor).unwrap();
        assert_eq!(reloaded, ledger);
        assert!(reloaded.has_commitment(&deposit.cm));
        assert_eq!(s.supply().unwrap(), ledger.supply(), "the withdraw's counters are committed too");
        assert_eq!(s.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().problem, None);
    }

    /// And a block that reports a deposit at a leaf none of its transactions accounts for is
    /// refused outright. Without that guard the note would be written at whatever index the block
    /// claimed, and every later leaf would be off by one against the tree the ledger built.
    #[test]
    fn a_block_reporting_a_deposit_at_the_wrong_leaf_is_refused() {
        let (_d, s, _gs, blocks, ledger) = chain_with_a_withdraw();
        let [b1, mut b2] = blocks;
        b2.deposits[0].index += 1;
        let err = s.commit(&[b1, b2], &ledger, &[], &StubExecutor).unwrap_err();
        assert!(
            matches!(&err, StorageError::Corrupt(m) if m.contains("no transaction of it accounts for")),
            "{err:?}"
        );
    }

    /// The S2×S3 seam: a block carrying both a `Withdraw` (S2 — its deposit arrives through
    /// `cb.deposits`) and a `BridgeAttest` (S3 — its note arrives through `created_notes`), in
    /// both orders. `commit`'s per-transaction loop appends `created_notes` first and then drains
    /// `cb.deposits` entries that match the running `next_index`, so whichever mechanism's tx
    /// comes first in the block must still land its note at the leaf the ledger actually gave it
    /// — this was true by reading the code, but nothing committed a block that exercised both at
    /// once.
    #[test]
    fn a_withdraw_and_a_bridge_attest_interleave_in_either_order() {
        for attest_first in [false, true] {
            let (_d, s, gs, secrets, b1, mut ledger, v) = bridged_chain_funded_for_a_withdraw(40);
            let base = ledger.next_index();
            let amount = 2 * bundle_fee();
            let time = ledger.height() as u32;
            let withdraw = withdraw_tx(gs.chain_id, &v, amount, 0, time, [13; 8]);
            let att = attest_tx(&ledger, attestation(&secrets, &recipient(), 1_000, 0), 20);
            let txs = if attest_first { vec![att.clone(), withdraw] } else { vec![withdraw, att.clone()] };
            let b2 = make_block_voted(&b1.block, &mut ledger, txs, &v, &[&v]);
            assert_eq!(
                b2.deposits.len(),
                1,
                "attest_first={attest_first}: only the withdraw's note is ledger-made; the \
                 attest's goes through created_notes, not cb.deposits"
            );
            let withdraw_leaf = b2.deposits[0].index;
            // Four new leaves either way: the withdraw's deposit, the attest's fee bundle's two
            // output slots, and the attest's own deposit note — just in a different order.
            assert_eq!(ledger.next_index(), base + 4, "attest_first={attest_first}");

            s.commit(&[b1, b2], &ledger, &[], &StubExecutor).unwrap();

            assert_eq!(s.notes_count().unwrap(), ledger.next_index(), "attest_first={attest_first}");
            let reloaded = s.load_ledger(&StubExecutor).unwrap();
            assert_eq!(
                reloaded, ledger,
                "attest_first={attest_first}: tree root, next_index and bridge state all round-trip"
            );

            let withdraw_row =
                s.note(withdraw_leaf).unwrap().expect("the withdraw's deposit is indexed at the leaf it named");
            assert_eq!(withdraw_row.height, 2, "attest_first={attest_first}");

            let bridge = ledger.bridge().expect("bridged genesis");
            let expected_deposit =
                randprotocol_core::ledger::bridge_notes::deposit_note(&att, ledger.tokens().unwrap(), &StubExecutor)
                .expect("the attestation registered an asset and deposits into it");
            let deposit_leaf = (base..base + 4)
                .find(|&i| s.note(i).unwrap().expect("leaf in range").cm == expected_deposit.0)
                .unwrap_or_else(|| panic!("attest_first={attest_first}: the attest's deposit note is not on disk"));
            assert_ne!(
                deposit_leaf, withdraw_leaf,
                "attest_first={attest_first}: the two mechanisms must not collide on the same leaf"
            );
            let deposit_row = s.note(deposit_leaf).unwrap().unwrap();
            assert_eq!(deposit_row.envelope, expected_deposit.1, "attest_first={attest_first}");
            assert_eq!(deposit_row.height, 2, "attest_first={attest_first}");

            assert_eq!(
                s.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().problem,
                None,
                "attest_first={attest_first}"
            );
        }
    }

    /// The same seam with a third mechanism folded in: a `BridgeBurn` of the asset the attest in
    /// the same block just registered. Cheap to add because `apply_transactions` applies the
    /// block's transactions sequentially into the same scratch ledger, so a burn textually after
    /// its funding attest sees the registry already updated — no second block needed.
    #[test]
    fn a_withdraw_a_bridge_attest_and_a_bridge_burn_share_a_block() {
        let (_d, s, gs, secrets, b1, mut ledger, v) = bridged_chain_funded_for_a_withdraw(41);
        let base = ledger.next_index();
        let amount = 2 * bundle_fee();
        let time = ledger.height() as u32;
        let withdraw = withdraw_tx(gs.chain_id, &v, amount, 0, time, [13; 8]);
        let att = attest_tx(&ledger, attestation(&secrets, &recipient(), 1_000, 0), 20);
        // `burn_tx` only needs `ledger` for its anchor/height/chain_id, so the asset index (1,
        // this chain's first registered asset) can be hardcoded ahead of applying `att`.
        let burn = burn_tx(&ledger, 1, 400, 100, 30);
        let b2 = make_block_voted(&b1.block, &mut ledger, vec![att, withdraw, burn], &v, &[&v]);
        assert_eq!(b2.deposits.len(), 1, "still only the withdraw's note is ledger-made");

        s.commit(&[b1, b2], &ledger, &[], &StubExecutor).unwrap();

        assert_eq!(s.notes_count().unwrap(), ledger.next_index());
        let reloaded = s.load_ledger(&StubExecutor).unwrap();
        assert_eq!(reloaded, ledger, "tree root, next_index and bridge state all round-trip");
        assert!(ledger.next_index() > base, "the block did add leaves");
        let bridge = ledger.bridge().expect("bridged genesis");
        assert_eq!(bridge.burns.len(), 1, "the burn landed in the outbound log");
        assert_eq!(s.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().problem, None);
    }

    /// A chain that crosses an epoch boundary, with the epoch's set derived from the register as
    /// of the last block of the epoch before (spec §8). Block 1 unbonds validator 2 out of the
    /// set, so epoch 1 runs with validator 1 alone.
    fn chain_across_a_boundary() -> (tempfile::TempDir, Storage, GenesisState, ValidatorSet, Ledger) {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        // Two blocks per epoch, so block 2 is the first block of epoch 1.
        let gs = genesis_of(7, &[&key(1), &key(2)], vec![alloc_note(20, 5 * randprotocol_core::UNITS_PER_RAND)], 2);
        s.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);

        let leaving = key(2);
        let amount = randprotocol_core::ledger::staking::MIN_STAKE;
        let signature =
            leaving.sign(randprotocol_core::unbond_message(gs.chain_id, &leaving.address(), amount, 0).as_bytes());
        let action = Action::Unbond { validator: leaving.address(), amount, nonce: 0, signature };
        // Bundle-less and free, like every validator-signed action: the block carries it alone.
        let unbond = Transaction { chain_id: gs.chain_id, bundle: None, action };

        // Block 1 is in epoch 0: led and certified by that epoch's set, both validators.
        let both = [&key(1), &key(2)];
        let b1 = make_block_voted(&gs.block, &mut ledger, vec![unbond], leader_among(&gs.validators, 1, &both), &both);
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        // Block 2 opens epoch 1, whose set the register now derives as validator 1 alone.
        let epoch1 = ledger.derive_next_set();
        assert_eq!(epoch1.len(), 1, "validator 2 unbonded out of the set");
        assert_eq!(epoch1.leader(2), key(1).address());
        ledger.set_height(2);
        let tx = bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee());
        let b2 = make_block_voted(&b1.block, &mut ledger, vec![tx], &key(1), &[&key(1)]);
        s.commit(std::slice::from_ref(&b2), &ledger, &[(1, epoch1.clone())], &StubExecutor).unwrap();
        (dir, s, gs, epoch1, ledger)
    }

    #[test]
    fn an_epoch_set_is_written_with_the_block_that_starts_the_epoch() {
        let (_d, s, gs, epoch1, ledger) = chain_across_a_boundary();
        assert_eq!(s.epoch_set(0).unwrap().as_ref(), Some(&gs.validators));
        assert_eq!(s.epoch_set(1).unwrap().as_ref(), Some(&epoch1));
        assert_eq!(s.load_epoch_sets().unwrap().known().count(), 2);
        // The unbonded stake is in the register's queue, and the whole chain verifies against
        // the per-epoch sets it recorded.
        let e = s.validator(&key(2).address()).unwrap().unwrap();
        assert_eq!(e.stake, 0);
        assert_eq!(e.pending, vec![(2, randprotocol_core::ledger::staking::MIN_STAKE)]);
        assert_eq!(e.nonce, 1);
        assert_eq!(s.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().problem, None);
        assert_eq!(s.load_ledger(&StubExecutor).unwrap(), ledger);
        assert_eq!(s.supply().unwrap(), ledger.supply(), "the counters are committed with the state");

        // Rewinding to the last block of epoch 0 drops epoch 1's set: those blocks are gone.
        let replayed = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        let mut at_one = gs.ledger.clone();
        at_one.apply_block(&s.block_by_height(1).unwrap().unwrap(), &StubExecutor).unwrap();
        assert!(replayed.is_ok());
        s.truncate_to(&gs, 1, &at_one).unwrap();
        assert_eq!(s.epoch_set(0).unwrap().as_ref(), Some(&gs.validators), "epoch 0 outlives any truncation");
        assert_eq!(s.epoch_set(1).unwrap(), None);
        assert_eq!(s.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().problem, None);
    }

    /// The point of storing a set per epoch: a certificate is only valid against the set of the
    /// epoch its own block belonged to. This QC would pass under epoch 0's set and must not pass
    /// under epoch 1's.
    #[test]
    fn verify_chain_rejects_a_qc_signed_by_the_wrong_epochs_set() {
        let (_d, s, gs, epoch1, _) = chain_across_a_boundary();
        let b2 = s.block_by_height(2).unwrap().unwrap();
        let wrong = QuorumCertificate {
            view: b2.view(),
            block_hash: b2.hash(),
            votes: [&key(1), &key(2)].iter().map(|k| randprotocol_core::Vote::sign(b2.view(), b2.hash(), k)).collect(),
        };
        // Under the set that ran epoch 0 it is a perfectly good certificate.
        assert!(wrong.verify(&gs.validators, &gs.hash()));
        assert!(!wrong.verify(&epoch1, &gs.hash()), "validator 2 is not in epoch 1's set");
        s.overwrite_qc_for_testing(2, &wrong).unwrap();

        let c = s.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap();
        assert_eq!(c.last_good, 1, "the chain is good up to the block before");
        assert!(c.problem.as_deref().unwrap_or_default().contains("epoch 1"), "{:?}", c.problem);
    }

    /// The other half of the audit: the set a boundary block ran with has to be *there*, and it
    /// has to be the one the replayed register derives.
    #[test]
    fn verify_chain_rejects_an_epoch_set_that_is_missing_or_not_the_one_the_replay_derives() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1), &key(2)], vec![], 2);
        s.init_genesis(&gs).unwrap();
        let both = [&key(1), &key(2)];
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);
        let b1 = make_block(&gs.block, &mut ledger, vec![], leader_among(&gs.validators, 1, &both));
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        // Nobody unbonded, so epoch 1's set is still both validators.
        let epoch1 = ledger.derive_next_set();
        ledger.set_height(2);
        let b2 = make_block(&b1.block, &mut ledger, vec![], leader_among(&epoch1, 2, &both));
        s.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        let missing = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert_eq!(missing.last_good, 1, "the chain is good up to the block before the boundary");
        assert_eq!(missing.problem.as_deref(), Some("no stored validator set for epoch 1"));

        // A set that is there but is not the one this register derives is no better.
        let wrong = ValidatorSet::from_entries([(key(1).public_key(), randprotocol_core::ledger::staking::MIN_STAKE)]);
        s.commit(&[], &ledger, &[(1, wrong)], &StubExecutor).unwrap();
        let c = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert_eq!(c.last_good, 1);
        assert!(c.problem.as_deref().unwrap_or_default().contains("epoch 1"), "{:?}", c.problem);

        // Writing what the replay does derive is what repairs it.
        s.commit(&[], &ledger, &[(1, epoch1)], &StubExecutor).unwrap();
        assert_eq!(s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().problem, None);
    }

    /// Epoch 0 is seeded from `gs.validators` by definition, but `resume` reads its set from the
    /// stored row like any other epoch — so a corrupt row there is invisible to a chain with no
    /// epoch boundaries yet unless the audit compares the two. It must.
    #[test]
    fn verify_chain_rejects_a_tampered_epoch_0_row() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1), &key(2)], vec![], 2);
        s.init_genesis(&gs).unwrap();
        assert_eq!(s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().problem, None);

        let tampered = ValidatorSet::from_entries([(key(1).public_key(), randprotocol_core::ledger::staking::MIN_STAKE)]);
        s.commit(&[], &gs.ledger, &[(0, tampered)], &StubExecutor).unwrap();
        let c = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert_eq!(c.last_good, 0);
        assert!(c.problem.as_deref().unwrap_or_default().contains("epoch 0"), "{:?}", c.problem);

        // Writing the genesis set back is what repairs it.
        s.commit(&[], &gs.ledger, &[(0, gs.validators.clone())], &StubExecutor).unwrap();
        assert_eq!(s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().problem, None);
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
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

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
                votes: vec![randprotocol_core::Vote::sign(cb.block.view(), cb.block.hash(), &key(1))],
            };
            CommittedBlock { qc, ..cb }
        };
        ledger.set_height(1);
        let tx1 = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let b1 = certify(make_block(&gs.block, &mut ledger, vec![tx1], &proposer));
        s.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        let ledger_at_1 = ledger.clone();

        ledger.set_height(2);
        let tx2 = bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee());
        let b2 = certify(make_block(&b1.block, &mut ledger, vec![tx2.clone()], &proposer));
        s.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();
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
        assert!(matches!(s.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor), Err(StorageError::Corrupt(_))));
        assert_eq!(s.head().unwrap().height, 0);
        let mut bad = b1.clone();
        bad.qc.block_hash = Hash::ZERO;
        assert!(matches!(s.commit(&[bad], &ledger, &[], &StubExecutor), Err(StorageError::Corrupt(_))));
        s.commit(&[b1, b2], &ledger, &[], &StubExecutor).unwrap();
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
        s.commit(&[b1.clone(), b2.clone()], &ledger, &[], &StubExecutor).unwrap();
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
            [([20; 8], 0), ([21; 8], 0), ([43; 8], 1), ([44; 8], 1), (b2.block.transactions[0].commitments()[0], 2)]
                .into_iter()
                .enumerate()
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
        st.commit(std::slice::from_ref(cb), &ledger, &[], &StubExecutor).unwrap();
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
        let deploy_bundle = bundle_tx(&ledger, [[90; 8], [91; 8]], [[92; 8], [93; 8]], randprotocol_core::gas::fee_floor(&Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] }));
        let deploy = Transaction::shielded(gs.chain_id, deploy_bundle.bundle.clone().unwrap(), Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] });
        // The bundle's digest commits to its own fields only, so swapping the action is fine.
        let cb3 = make_block(&blocks[1].block, &mut ledger, vec![deploy.clone()], &k);
        let pid = randprotocol_core::program::program_id(0, &words);
        st.commit(std::slice::from_ref(&cb3), &ledger, &[], &StubExecutor).unwrap();
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

    /// The call limits (spec §5): a deploy's public words land in `program_public` under the
    /// program's id, with the record holding only their digest; a plain deploy stores none; a
    /// restart keeps them, and truncating below the deploy removes them with the program.
    #[test]
    fn program_public_words_round_trip_survive_a_restart_and_truncate() {
        let (dir, st, gs, blocks) = chain_fixture(2);
        let k = key(1);
        let mut ledger = st.load_ledger(&StubExecutor).unwrap();
        ledger.set_faucet(true);
        ledger.set_max_program_public_words(8);
        ledger.set_height(3);
        let words = vec![0x13u32; 3];
        let public = vec![7u32, 8, 9];
        let with = Action::Deploy { base_pc: 0, words: words.clone(), public: public.clone() };
        let plain = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let b1 = bundle_tx(&ledger, [[90; 8], [91; 8]], [[92; 8], [93; 8]], randprotocol_core::gas::fee_floor(&with));
        let b2 = bundle_tx(&ledger, [[94; 8], [95; 8]], [[96; 8], [97; 8]], randprotocol_core::gas::fee_floor(&plain));
        let txs = vec![
            Transaction::shielded(gs.chain_id, b1.bundle.clone().unwrap(), with),
            Transaction::shielded(gs.chain_id, b2.bundle.clone().unwrap(), plain),
        ];
        let cb3 = make_block(&blocks[1].block, &mut ledger, txs, &k);
        st.commit(std::slice::from_ref(&cb3), &ledger, &[], &StubExecutor).unwrap();
        let pid = randprotocol_core::program::program_id_with_public(0, &words, &public);
        let plain_id = randprotocol_core::program::program_id(0, &words);
        assert_eq!(st.program_public(&pid).unwrap(), Some(public.clone()));
        assert_eq!(st.program(&pid).unwrap().unwrap().public_digest, Some(StubExecutor.public_digest(&public)));
        assert_eq!(st.program_public(&plain_id).unwrap(), None, "no public input, no row");
        assert!(st.program(&plain_id).unwrap().is_some());
        // A restart keeps them.
        drop(st);
        let st = Storage::open(dir.path()).unwrap();
        assert_eq!(st.program_public(&pid).unwrap(), Some(public.clone()));
        assert_eq!(st.load_ledger(&StubExecutor).unwrap().program(&pid).unwrap().public_digest, Some(StubExecutor.public_digest(&public)));
        // Truncating below the deploy removes them with the program.
        let at_two = {
            let mut l = gs.ledger.clone();
            for cb in &blocks {
                l.apply_block(&cb.block, &StubExecutor).unwrap();
            }
            l
        };
        st.truncate_to(&gs, 2, &at_two).unwrap();
        assert!(st.program(&pid).unwrap().is_none());
        assert_eq!(st.program_public(&pid).unwrap(), None);
    }

    #[test]
    fn receipts_by_program_index_round_trips_pages_and_truncates() {
        let (_d, st, gs, blocks) = chain_fixture(2);
        let k = key(1);
        let mut ledger = st.load_ledger(&StubExecutor).unwrap();
        ledger.set_faucet(true);
        ledger.set_height(3);
        // Two programs, three calls at height 3 (index order 1, 2 for pid_a; 3 for pid_b), plus
        // one more pid_a call alone at height 4 — enough for a `limit` that lands inside height
        // 3's pair to prove a page never splits a height.
        // Build receipts by hand: the index only needs (program, height, index, tx).
        let pid_a = randprotocol_core::program::program_id(0, &[0x13u32; 3]);
        let pid_b = randprotocol_core::program::program_id(0, &[0x14u32; 3]);
        let mut cb3 = make_block(&blocks[1].block, &mut ledger, vec![], &k);
        let rec = |pid, height, index, tx: u8| randprotocol_core::program::CallReceipt {
            tx: Hash([tx; 32]), program: pid, tier: 1, outputs: [0; 8], height, index, h_in: [0; 8], h_pub: None,
            input_envelope: None,
        };
        cb3.receipts = vec![rec(pid_a, 3, 1, 1), rec(pid_a, 3, 2, 2), rec(pid_b, 3, 3, 3)];
        st.commit(std::slice::from_ref(&cb3), &ledger, &[], &StubExecutor).unwrap();
        let mut cb4 = make_block(&cb3.block, &mut ledger, vec![], &k);
        cb4.receipts = vec![rec(pid_a, 4, 0, 4)];
        st.commit(std::slice::from_ref(&cb4), &ledger, &[], &StubExecutor).unwrap();

        let (page, next) = st.receipts_for_program(&pid_a, 0, 10, 10).unwrap();
        assert_eq!(page.iter().map(|r| (r.height, r.index)).collect::<Vec<_>>(), vec![(3, 1), (3, 2), (4, 0)]);
        assert_eq!(next, None);
        // `limit` 1 lands inside height 3's pair: the page keeps both rather than splitting the
        // height, and `next` is the first height it did not serve at all.
        let (page, next) = st.receipts_for_program(&pid_a, 0, 10, 1).unwrap();
        assert_eq!(page.iter().map(|r| (r.height, r.index)).collect::<Vec<_>>(), vec![(3, 1), (3, 2)]);
        assert_eq!(next, Some(4), "next is strictly above every height the page served");
        // Resuming from that cursor picks up exactly where the last page left off.
        let (page, next) = st.receipts_for_program(&pid_a, 4, 10, 1).unwrap();
        assert_eq!(page.iter().map(|r| (r.height, r.index)).collect::<Vec<_>>(), vec![(4, 0)]);
        assert_eq!(next, None, "nothing above height 4 to resume from");
        let (page, next) = st.receipts_for_program(&pid_a, 0, 10, 0).unwrap();
        assert!(page.is_empty(), "limit 0 consumes nothing");
        assert_eq!(next, None, "and must not hand back a cursor a caller could loop on forever");
        let (page, _) = st.receipts_for_program(&pid_b, 4, 10, 10).unwrap();
        assert!(page.is_empty(), "from above the receipt's height");
        // Truncating below height 3 drops both heights' index rows with the receipts.
        let at_two = { let mut l = gs.ledger.clone(); for cb in &blocks { l.apply_block(&cb.block, &StubExecutor).unwrap(); } l };
        st.truncate_to(&gs, 2, &at_two).unwrap();
        assert!(st.receipts_for_program(&pid_a, 0, 10, 10).unwrap().0.is_empty());
    }

    #[test]
    fn receipts_index_is_backfilled_once_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let gs = genesis_with_two_notes_state();
        let pid = randprotocol_core::program::program_id(0, &[0x13u32; 3]);
        {
            let st = Storage::open(dir.path()).unwrap();
            st.init_genesis(&gs).unwrap();
            // Write a receipt straight into the receipts family, as a pre-v0.3 node would have.
            let r = randprotocol_core::program::CallReceipt {
                tx: Hash([9; 32]), program: pid, tier: 1, outputs: [0; 8], height: 1, index: 0, h_in: [0; 8], h_pub: None,
                input_envelope: None,
            };
            st.db.put_cf(st.cf(CF_RECEIPTS), r.tx.as_bytes(), bincode::serialize(&r).unwrap()).unwrap();
            st.db.delete_cf(st.cf(CF_META), META_RECEIPTS_INDEX_BUILT.as_bytes()).unwrap();
        }
        let st = Storage::open(dir.path()).unwrap();
        assert!(st.receipts_index_built().unwrap());
        assert_eq!(st.receipts_for_program(&pid, 0, 5, 10).unwrap().0.len(), 1);
    }

    /// A chain without an aggregation section reads back `None`, and so does a database whose
    /// meta predates the key; the gated half of this is in `seal_tests`.
    #[test]
    fn aggregation_config_is_none_on_an_ungated_genesis() {
        let (_d, s, gs) = genesis_with_two_notes();
        assert!(gs.ledger.aggregation().is_none());
        s.init_genesis(&gs).unwrap();
        assert_eq!(s.aggregation_config().unwrap(), None);
        s.db.delete_cf(s.cf(CF_META), META_AGGREGATION.as_bytes()).unwrap();
        assert_eq!(s.aggregation_config().unwrap(), None, "a key never written is no section");
    }

    /// `tx_location` decodes only the two leading fields of a record; for both forms it must
    /// agree with the full decode, including when the rest of the record is a large proof it
    /// never reads.
    #[test]
    fn tx_location_reads_the_location_of_either_record_form_without_the_rest() {
        let (_d, s, gs) = genesis_with_two_notes();
        s.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);
        let mut tx = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        // A proof the size a real one is, so the record's tail is nowhere near empty.
        tx.bundle.as_mut().unwrap().proof = vec![0xab; 1 << 20];
        let raw = TxRecord::Raw { height: 7, index: 3, tx: tx.clone() };
        let pruned = TxRecord::Pruned {
            height: u64::MAX - 1,
            index: u32::MAX,
            tx_hash: Hash([5; 32]),
            tx,
            proof_hash: Hash([6; 32]),
            public_values: vec![11; 34],
            shape: randprotocol_core::types::DeclaredShape {
                profile: randprotocol_core::types::FriProfile::Test,
                tier: 14,
                program_log_height: 13,
                input_log_height: 12,
                keccak_log_height: 0,
                sha256_log_height: 0,
                public_log_height: 2,
                mem_log_height: 18,
            },
        };
        for (key, rec) in [(Hash([1; 32]), &raw), (Hash([2; 32]), &pruned)] {
            s.db.put_cf(s.cf(CF_TXS), key.as_bytes(), bincode::serialize(rec).unwrap()).unwrap();
            let full = s.tx_record(&key).unwrap().unwrap();
            assert_eq!(&full, rec);
            assert_eq!(s.tx_location(&key).unwrap(), Some(full.location()));
        }
        assert_eq!(s.tx_location(&Hash([1; 32])).unwrap(), Some((7, 3)));
        assert_eq!(s.tx_location(&Hash([2; 32])).unwrap(), Some((u64::MAX - 1, u32::MAX)));
        assert_eq!(s.tx_location(&Hash([3; 32])).unwrap(), None);
    }

    /// The column families a pre-v0.3 build opens with: `ALL_CFS` without
    /// `receipts_by_program` — and without `program_public`, which arrived later still (the call
    /// limits, on a fresh chain, so no database ever needs rolling back across it). Exactly the
    /// list the build the fleet rolls back to passes RocksDB.
    fn pre_v03_cfs() -> Vec<&'static str> {
        let cfs: Vec<&str> =
            ALL_CFS.iter().copied().filter(|c| *c != CF_RECEIPTS_BY_PROGRAM && *c != CF_PROGRAM_PUBLIC).collect();
        assert_eq!(cfs.len(), 15);
        cfs
    }

    /// Open `<dir>/db` the way a pre-v0.3 binary does: its fifteen families, nothing else.
    fn open_as_pre_v03(dir: &Path, create: bool) -> std::result::Result<DB, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(create);
        opts.create_missing_column_families(create);
        let cfs = pre_v03_cfs().into_iter().map(|n| ColumnFamilyDescriptor::new(n, Options::default()));
        DB::open_cf_descriptors(&opts, dir.join("db"), cfs)
    }

    fn a_receipt(pid: ProgramId) -> CallReceipt {
        randprotocol_core::program::CallReceipt {
            tx: Hash([9; 32]), program: pid, tier: 1, outputs: [0; 8], height: 1, index: 0, h_in: [0; 8], h_pub: None,
            input_envelope: None,
        }
    }

    /// The forward path: a database a pre-v0.3 build wrote — fifteen families, a genesis, a
    /// receipt — gains the family and the marker on its first v0.3 open, and the receipt is
    /// served by program.
    #[test]
    fn a_pre_v03_database_gains_the_receipts_index_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let gs = genesis_with_two_notes_state();
        let pid = randprotocol_core::program::program_id(0, &[0x13u32; 3]);
        {
            // `init_genesis` touches no family the old build lacks, so it runs over the raw
            // fifteen-family handle exactly as the old build's own did.
            let old = Storage { db: open_as_pre_v03(dir.path(), true).unwrap() };
            old.init_genesis(&gs).unwrap();
            let r = a_receipt(pid);
            old.db.put_cf(old.cf(CF_RECEIPTS), r.tx.as_bytes(), bincode::serialize(&r).unwrap()).unwrap();
        }
        let names = DB::list_cf(&Options::default(), dir.path().join("db")).unwrap();
        assert!(!names.iter().any(|n| n == CF_RECEIPTS_BY_PROGRAM), "the old layout has no index family");

        let st = Storage::open(dir.path()).unwrap();
        let names = DB::list_cf(&Options::default(), dir.path().join("db")).unwrap();
        assert!(names.iter().any(|n| n == CF_RECEIPTS_BY_PROGRAM), "open created the family");
        assert!(st.receipts_index_built().unwrap(), "and set the marker");
        let (page, _) = st.receipts_for_program(&pid, 0, 5, 10).unwrap();
        assert_eq!(page, vec![a_receipt(pid)]);
        assert_eq!(st.genesis_hash().unwrap(), gs.hash());
    }

    /// The rollback path: once v0.3 has opened a database the old build cannot, the drop makes
    /// it openable with the old fifteen-family list again, and a later v0.3 open rebuilds the
    /// index from scratch because the marker went with the family.
    #[test]
    fn dropping_the_receipts_index_lets_the_old_build_open_and_v03_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let gs = genesis_with_two_notes_state();
        let pid = randprotocol_core::program::program_id(0, &[0x13u32; 3]);
        {
            // A v0.3 database, as `Storage::open` wrote it before `program_public` existed: the
            // rollback this command serves is v0.3 to pre-v0.3, and a database with the call
            // limits' family belongs to a later chain no pre-v0.3 build could follow anyway.
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let cfs = ALL_CFS
                .iter()
                .filter(|c| **c != CF_PROGRAM_PUBLIC)
                .map(|n| ColumnFamilyDescriptor::new(*n, Options::default()));
            let st = Storage { db: DB::open_cf_descriptors(&opts, dir.path().join("db"), cfs).unwrap() };
            st.backfill_receipts_index().unwrap();
            st.init_genesis(&gs).unwrap();
            let r = a_receipt(pid);
            st.db.put_cf(st.cf(CF_RECEIPTS), r.tx.as_bytes(), bincode::serialize(&r).unwrap()).unwrap();
            st.db.put_cf(st.cf(CF_RECEIPTS_BY_PROGRAM), receipt_index_key(&pid, 1, 0), r.tx.as_bytes()).unwrap();
            assert!(st.receipts_index_built().unwrap());
        }
        // This is the halt C1 is about: the old build's list no longer opens the database.
        assert!(open_as_pre_v03(dir.path(), false).is_err(), "sixteen families on disk, fifteen listed");

        let dropped = Storage::drop_receipts_index(dir.path()).unwrap();
        assert_eq!(dropped, DroppedReceiptsIndex { family: true, marker: true });
        {
            let old = open_as_pre_v03(dir.path(), false).expect("the old build opens it again");
            assert!(old.get_cf(old.cf_handle(CF_META).unwrap(), META_RECEIPTS_INDEX_BUILT.as_bytes()).unwrap().is_none());
            assert!(old.get_cf(old.cf_handle(CF_RECEIPTS).unwrap(), Hash([9; 32]).as_bytes()).unwrap().is_some(), "the receipts themselves stay");
        }
        // A rerun finds nothing left to remove and says so.
        assert_eq!(Storage::drop_receipts_index(dir.path()).unwrap(), DroppedReceiptsIndex { family: false, marker: false });

        let st = Storage::open(dir.path()).unwrap();
        assert!(st.receipts_index_built().unwrap(), "the marker was deleted, so the backfill ran again");
        assert_eq!(st.receipts_for_program(&pid, 0, 5, 10).unwrap().0, vec![a_receipt(pid)]);
    }

    #[test]
    fn dropping_the_receipts_index_refuses_a_directory_with_no_database() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(Storage::drop_receipts_index(dir.path()), Err(StorageError::Corrupt(_))));
        assert!(!dir.path().join("db").exists(), "and does not create one");
    }

    #[test]
    fn notes_in_heights_returns_one_blocks_slice() {
        // Genesis with two deposit notes (height 0), then two blocks each spending two
        // notes and creating two: leaves 0,1 at height 0; 2,3 at height 1; 4,5 at height 2.
        let gs = genesis_with(1, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)]);
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let t1 = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![t1], &key(1));
        storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        let t2 = bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee());
        let b2 = make_block(&b1.block, &mut ledger, vec![t2], &key(1));
        storage.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        let all = storage.notes_in_heights(0, 2, 1000).unwrap();
        assert_eq!(all.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 1, 2, 3, 4, 5]);
        let one = storage.notes_in_heights(1, 1, 1000).unwrap();
        assert_eq!(one.iter().map(|(i, r)| (*i, r.height)).collect::<Vec<_>>(), vec![(2, 1), (3, 1)]);
        // A height past the head, and an empty height, are empty rather than errors.
        assert!(storage.notes_in_heights(9, 9, 1000).unwrap().is_empty());
        // max_rows truncates rather than failing.
        assert_eq!(storage.notes_in_heights(0, 2, 3).unwrap().len(), 3);
    }

    #[test]
    fn derived_note_count_covers_the_notes_the_wire_does_not_carry() {
        let envelope = Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] };
        let w = Transaction {
            chain_id: 1,
            bundle: None,
            action: Action::Withdraw {
                validator: Address([3; 32]), amount: 9, nonce: 0, time: 1, r: [5; 8],
                envelope: envelope.clone(), signature: randprotocol_core::Signature::empty(),
            },
        };
        assert_eq!(derived_note_count(&w), 1, "the ledger derives a withdraw's deposit note");
        assert_eq!(w.commitments().len(), 0, "and the wire does not carry it");
        // A plain transfer carries both its notes itself.
        let gs = fixtures::genesis_with(1, vec![]);
        let t = fixtures::bundle_tx(&gs.ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        assert_eq!(derived_note_count(&t), 0);
        assert_eq!(t.commitments().len(), 2);

        // An attestation that decodes to a transfer deposits one note the wire does not carry,
        // on top of the two its fee bundle does.
        let (bgs, secrets) = bridged_genesis(3);
        let att = attest_tx(&bgs.ledger, attestation(&secrets, &recipient(), 1_000, 0), 20);
        assert_eq!(derived_note_count(&att), 1, "the ledger derives the attestation's deposit note");
        assert_eq!(att.commitments().len(), 2, "and the wire carries only the fee bundle's slots");
        let with_attestation = |bytes: Vec<u8>| {
            let mut t = att.clone();
            if let Action::BridgeAttest { attestation, .. } = &mut t.action {
                *attestation = bytes;
            }
            t
        };

        // A guardian-set rotation decodes and deposits nothing, so its transaction owns only what
        // it carries. (No signature is recovered here, so the body alone decides.)
        let rotation = {
            use randprotocol_core::bridge::{Attestation, Body, GuardianSetUpgrade, Payload};
            let body = Body {
                timestamp: 1,
                nonce: 0,
                emitter_chain: 1,
                emitter_address: [9; 32],
                sequence: 0,
                consistency_level: 0,
                payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade { new_index: 1, keys: vec![] }).encode(),
            };
            Attestation { guardian_set_index: 0, signatures: vec![], body }.encode()
        };
        assert!(
            randprotocol_core::ledger::bridge_notes::attested_transfer(&rotation).is_none(),
            "a rotation is not a transfer"
        );
        assert_eq!(derived_note_count(&with_attestation(rotation)), 0);

        // Over `MAX_ATTESTATION_BYTES` the blob is never decoded at all — the cap comes first,
        // exactly as `Ledger::derived_commitment` applies it, so an unvalidated transaction
        // cannot buy the parse. `created_notes` has no cap and agrees anyway, because `validate`
        // refuses such a transaction and a committed block never holds one.
        let mut oversized = attestation(&secrets, &recipient(), 1_000, 1);
        assert!(
            randprotocol_core::ledger::bridge_notes::attested_transfer(&oversized).is_some(),
            "the unpadded attestation does decode to a transfer"
        );
        oversized.resize(randprotocol_core::gas::MAX_ATTESTATION_BYTES + 1, 0);
        assert_eq!(derived_note_count(&with_attestation(oversized)), 0);
    }
}

// ── sealing and pruning (block aggregation, spec §6) ─────────────────────────────────────────
#[cfg(test)]
mod seal_tests {
    use super::fixtures::*;
    use super::*;
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
    use randprotocol_core::types::actions::{aggregate_signing_hash, aggregator_register_message, AggregatorRegistration};
    use randprotocol_core::types::{CoveredBundle, DeclaredShape, FriProfile};
    use randprotocol_core::{Keypair, Transaction};

    fn fixture_shape(p: &randprotocol_zkvm::machine::Proof) -> DeclaredShape {
        DeclaredShape {
            profile: FriProfile::Test,
            tier: p.tier.0 as u8,
            program_log_height: p.program_log_height,
            input_log_height: p.input_log_height,
            keccak_log_height: p.keccak_log_height,
            sha256_log_height: p.sha256_log_height,
            public_log_height: p.public_log_height,
            mem_log_height: p.mem_log_height,
        }
    }

    fn fixture_hc(p: &randprotocol_zkvm::machine::Proof) -> Hash {
        let words: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(p.public_values[randprotocol_core::types::pv::HC0 + k]).expect("a guest digest word is u32-range")
        });
        Hash(randprotocol_core::notes::word8_to_bytes(&words))
    }

    fn gated_cfg(shape: DeclaredShape, hc: Hash, window: u64) -> AggregationConfig {
        AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window,
            admitted_shapes: vec![AdmittedShape { shape, hc, aggregate_program_digest: [1; 4] }],
        }
    }

    fn aggregate_tx(kp: &Keypair, nonce: u64, time: u32, covers: Vec<Hash>, proof: Vec<u8>) -> Transaction {
        let aggregator = kp.public_key().address();
        let r = [9; 8];
        let signature = kp.sign(aggregate_signing_hash(7, nonce, time, &r, &covers, &Hash::digest(&proof)).as_bytes());
        Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::Aggregate { covers, proof, aggregator, nonce, time, r, envelope: env(9), signature },
        }
    }

    fn register_tx(l: &Ledger, kp: &Keypair, bond: u64) -> Transaction {
        let payout = randprotocol_core::notes::ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(7, &payout).as_bytes()),
        };
        let mut b = randprotocol_core::notes::Bundle {
            anchor: l.root(),
            nullifiers: [[11; 8], [12; 8]],
            commitments: [[13; 8], [14; 8]],
            fee: randprotocol_core::gas::BUNDLE_BASE,
            burn: bond,
            asset: 0,
            time: 1,
            envelopes: [env(1), env(2)],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        Transaction::shielded(7, b, Action::RegisterAggregator { registration })
    }

    /// A gated chain of two committed blocks: block 1 carries the covered bundle (a real
    /// fixture proof) and the aggregator's registration; block 2 carries the aggregate covering
    /// it — committed atomically with the sealing marks. The applied sets use the stub twins
    /// where the stored bytes are a real proof, exactly the worker-arm tests' construction.
    fn chain_with_an_aggregate(window: u64) -> (tempfile::TempDir, Storage, GenesisState, Transaction, Transaction) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let proof = crate::agg_executor::fixture_proof(0);
        let cfg = gated_cfg(fixture_shape(&proof), fixture_hc(&proof), window);
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_aggregation(Some(cfg.clone()));
        storage.init_genesis(&gs).unwrap();

        let fee = randprotocol_core::gas::BUNDLE_BASE + 60;
        let mut covered_tx = bundle_tx(&gs.ledger, [[21; 8], [22; 8]], [[23; 8], [24; 8]], fee);
        covered_tx.bundle.as_mut().unwrap().proof = proof.to_bytes();
        let stub_twin = bundle_tx(&gs.ledger, [[21; 8], [22; 8]], [[23; 8], [24; 8]], fee);
        let register = register_tx(&gs.ledger, &key(7), cfg.bond);
        let mut l1 = gs.ledger.clone();
        l1.set_height(1);
        l1.set_timestamp_ms(1);
        l1.apply_transactions(&[stub_twin.clone(), register.clone()], &key(1).address(), &StubExecutor).unwrap();
        l1.record_anchor(1);
        // The ledger applied the stub twin, so its coverable entry is keyed by the twin's hash;
        // the stored bundle (and the aggregate's cover) is the real-proof one. Re-key it.
        let mut fees = l1.unsealed_fees().clone();
        let entry = fees.remove(&stub_twin.hash()).expect("the twin was bucketed");
        fees.insert(covered_tx.hash(), entry);
        l1.set_unsealed_fees(fees);
        let b1 = make_block_unchecked(&gs.block, &l1, vec![covered_tx.clone(), register], &key(1));
        storage.commit(std::slice::from_ref(&b1), &l1, &[], &StubExecutor).unwrap();

        let aggregate = aggregate_tx(&key(7), 0, 2, vec![covered_tx.hash()], b"ok".to_vec());
        let record = storage.covered_record(&covered_tx.hash(), FriProfile::Test).unwrap().unwrap();
        let sidecar: BTreeMap<usize, Vec<CoveredBundle>> = [(0usize, vec![record])].into_iter().collect();
        let mut l2 = l1.clone();
        l2.set_height(2);
        l2.set_timestamp_ms(2);
        l2.apply_transactions_with_covered(&[aggregate.clone()], &key(1).address(), &sidecar, &StubExecutor).unwrap();
        l2.record_anchor(2);
        let b2 = make_block_unchecked(&b1.block, &l2, vec![aggregate.clone()], &key(1));
        storage.commit(std::slice::from_ref(&b2), &l2, &[], &StubExecutor).unwrap();
        (dir, storage, gs, covered_tx, aggregate)
    }

    /// The sealing marks (spec §6.1): the per-bundle mark lands atomically with the committing
    /// block, and the block's flag only once every bundle in it has one.
    #[test]
    fn the_sealing_marks_land_per_bundle_and_per_block() {
        let (_d, storage, _gs, covered_tx, aggregate) = chain_with_an_aggregate(256);
        assert_eq!(
            storage.sealed_by(&covered_tx.hash()).unwrap(),
            Some((aggregate.hash(), 2)),
            "the mark: sealed by this aggregate, at its block"
        );
        // Block 1 carries the register's bundle too, which nobody covers: its flag stays down...
        let block1 = storage.block_by_height(1).unwrap().unwrap();
        assert!(!storage.block_sealed(&block1.hash()).unwrap(), "a bundle short of full coverage keeps the flag down");
        // ...until a second aggregate covers the register's bundle as well.
        let register_tx = &block1.transactions[1];
        let second = aggregate_tx(&key(7), 1, 3, vec![register_tx.hash()], b"ok".to_vec());
        let l3 = {
            let mut l = storage.load_ledger(&StubExecutor).unwrap();
            l.set_height(3);
            l.set_timestamp_ms(3);
            l.record_anchor(3);
            l
        };
        let block2 = storage.block_by_height(2).unwrap().unwrap();
        let b3 = make_block_unchecked(&block2, &l3, vec![second], &key(1));
        storage.commit(std::slice::from_ref(&b3), &l3, &[], &StubExecutor).unwrap();
        assert!(storage.block_sealed(&block1.hash()).unwrap(), "every bundle in it sealed: the flag lands");
    }

    /// The pruning gate (spec §6.2): before `sealed_at + window` the record stays raw; at it,
    /// the pass rewrites it — and the never-prune list (the aggregate's own record, every
    /// unsealed bundle) is untouched either way.
    #[test]
    fn the_gate_holds_then_the_pruned_record_round_trips_and_the_never_prune_list_holds() {
        let (_d, storage, _gs, covered_tx, aggregate) = chain_with_an_aggregate(4);
        let raw = storage.covered_record(&covered_tx.hash(), FriProfile::Test).unwrap().unwrap();

        assert_eq!(storage.prune_sealed(5, 4, FriProfile::Test).unwrap(), 0, "sealed at 2, gated until 6");
        assert!(matches!(storage.tx_record(&covered_tx.hash()).unwrap().unwrap(), TxRecord::Raw { .. }));

        assert_eq!(storage.prune_sealed(6, 4, FriProfile::Test).unwrap(), 1, "the window passed: one record rewrites");
        let record = storage.tx_record(&covered_tx.hash()).unwrap().unwrap();
        let TxRecord::Pruned { height, index, tx_hash, tx, proof_hash, public_values, shape } = record else {
            panic!("expected the pruned form, got {record:?}")
        };
        assert_eq!((height, index), (1, 0));
        assert_eq!(tx_hash, covered_tx.hash(), "the raw hash rides the record");
        let fixture = crate::agg_executor::fixture_proof(0);
        let expect: Vec<u64> = fixture.public_values.clone();
        assert_eq!(public_values, expect, "the 34 public values ride the record");
        assert_eq!(shape, fixture_shape(&fixture), "and the declared shape, 7 bytes' worth");
        let stored_proof = crate::agg_executor::fixture_proof(0).to_bytes();
        assert_eq!(proof_hash, Hash::digest(&stored_proof));
        let proof_field = tx.bundle.as_ref().unwrap().proof.clone();
        assert!(proof_field.starts_with(PRUNED_PROOF_MARKER), "the marker form, not a proof");
        assert_eq!(proof_field.len(), PRUNED_PROOF_MARKER.len() + 32);
        // The two forms read one way: admission's record is identical before and after pruning.
        let pruned = storage.covered_record(&covered_tx.hash(), FriProfile::Test).unwrap().unwrap();
        assert_eq!(pruned, raw);

        // The never-prune list: the aggregate's own (bundle-less) record and the register's
        // unsealed bundle both stay raw.
        assert!(matches!(storage.tx_record(&aggregate.hash()).unwrap().unwrap(), TxRecord::Raw { .. }), "an aggregate is never pruned");
        let block1 = storage.block_by_height(1).unwrap().unwrap();
        let register_tx = &block1.transactions[1];
        assert!(matches!(storage.tx_record(&register_tx.hash()).unwrap().unwrap(), TxRecord::Raw { .. }), "an unsealed bundle is never pruned");
    }

    /// A gated genesis's section round-trips through the accessor `rand_getEmission` reads, and
    /// agrees with what `load_ledger` restores.
    #[test]
    fn aggregation_config_round_trips_a_gated_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let shape = DeclaredShape {
            profile: FriProfile::Test,
            tier: 14,
            program_log_height: 13,
            input_log_height: 12,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 2,
            mem_log_height: 18,
        };
        let cfg = gated_cfg(shape, Hash::digest(b"the bundle guest"), 256);
        let mut gs = genesis_of(7, &[&key(1)], vec![], 100);
        gs.ledger.set_aggregation(Some(cfg.clone()));
        storage.init_genesis(&gs).unwrap();
        assert_eq!(storage.aggregation_config().unwrap(), Some(cfg.clone()));
        assert_eq!(storage.load_ledger(&StubExecutor).unwrap().aggregation(), Some(&cfg));
    }

    /// `verify_chain` on a pruned store recomputes the direct ledger exactly (spec §6.2's
    /// proof, as a test): the replay's covered-carrying apply reads the pruned record's 34
    /// public values and declared shape where the raw proof's bytes are gone — and without the
    /// record the replay refuses the aggregate's block, so the record is load-bearing, not
    /// decoration. The chain is stub-consistent end to end (a synthetic plaintext can never
    /// replay a real fixture proof — the digest compare binds them — so the pruned record is
    /// written directly; the Raw form's equivalence to it is the round-trip test above's claim).
    #[test]
    fn verify_chain_on_a_pruned_store_recomputes_the_direct_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let shape = DeclaredShape {
            profile: FriProfile::Test,
            tier: 14,
            program_log_height: 13,
            input_log_height: 12,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 2,
            mem_log_height: 18,
        };
        let hc = Hash::digest(b"the bundle guest");
        let mut gs = genesis_of(7, &[&key(1)], vec![], 100);
        gs.ledger.set_aggregation(Some(gated_cfg(shape, hc, 256)));
        storage.init_genesis(&gs).unwrap();

        // Block 1: the bundle the aggregate will cover (stub-proven, so the chain replays) and
        // the registration.
        let fee = randprotocol_core::gas::BUNDLE_BASE + 60;
        let covered_tx = bundle_tx(&gs.ledger, [[21; 8], [22; 8]], [[23; 8], [24; 8]], fee);
        let register = register_tx(&gs.ledger, &key(7), 100 * randprotocol_core::UNITS_PER_RAND);
        let mut l1 = gs.ledger.clone();
        l1.set_height(1);
        l1.set_timestamp_ms(1);
        l1.apply_transactions(&[covered_tx.clone(), register.clone()], &key(1).address(), &StubExecutor).unwrap();
        l1.record_anchor(1);
        let b1 = make_block_unchecked(&gs.block, &l1, vec![covered_tx.clone(), register], &key(1));
        storage.commit(std::slice::from_ref(&b1), &l1, &[], &StubExecutor).unwrap();

        // The covered record as the pruned form carries it: the 34 public values (with the
        // guest's hc at HC0..7) and the registered shape.
        let hc_words: [u32; 8] = randprotocol_core::notes::word8_from_bytes(hc.as_bytes()).unwrap();
        let mut pv = [0u64; 34];
        pv[randprotocol_core::types::pv::TIER] = shape.tier as u64;
        for k in 0..8 {
            pv[randprotocol_core::types::pv::OUT0 + k] = 100 + k as u64;
            pv[randprotocol_core::types::pv::HC0 + k] = hc_words[k] as u64;
        }
        let covered = CoveredBundle { public_values: pv, shape };

        // Block 2: the aggregate, applied against that record.
        let aggregate = aggregate_tx(&key(7), 0, 2, vec![covered_tx.hash()], b"ok".to_vec());
        let sidecar: BTreeMap<usize, Vec<CoveredBundle>> = [(0usize, vec![covered.clone()])].into_iter().collect();
        let mut l2 = l1.clone();
        l2.set_height(2);
        l2.set_timestamp_ms(2);
        l2.apply_transactions_with_covered(&[aggregate.clone()], &key(1).address(), &sidecar, &StubExecutor).unwrap();
        l2.record_anchor(2);
        let b2 = make_block_unchecked(&b1.block, &l2, vec![aggregate.clone()], &key(1));
        storage.commit(std::slice::from_ref(&b2), &l2, &[], &StubExecutor).unwrap();

        // Without the record, the replay refuses the aggregate's block: it is load-bearing.
        let without = storage.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(without.problem.is_some(), "the replay must refuse without the covered record");

        // Write the pruned record directly — the form the pruning pass would have produced.
        let proof_hash = Hash::digest(&covered_tx.bundle.as_ref().unwrap().proof);
        let mut pruned_tx = covered_tx.clone();
        let mut marker = PRUNED_PROOF_MARKER.to_vec();
        marker.extend_from_slice(proof_hash.as_bytes());
        pruned_tx.bundle.as_mut().unwrap().proof = marker;
        let record = TxRecord::Pruned {
            height: 1,
            index: 0,
            tx_hash: covered_tx.hash(),
            tx: pruned_tx,
            proof_hash,
            public_values: pv.to_vec(),
            shape,
        };
        storage
            .db
            .put_cf(storage.cf(CF_TXS), covered_tx.hash().as_bytes(), bincode::serialize(&record).unwrap())
            .unwrap();

        let replayed = storage.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(replayed.problem.is_none(), "pruned replay: {:?}", replayed.problem);
        assert_eq!(replayed.last_good, 2);
        assert_eq!(replayed.ledger, l2, "the same ledger the direct apply computed");
        assert_eq!(replayed.ledger.state_root(), l2.state_root(), "the same root");
        assert_eq!(replayed.ledger.supply(), l2.supply(), "the same counters");
        assert_eq!(replayed.ledger.unsealed_fees(), l2.unsealed_fees(), "the same bucket");
    }
}
