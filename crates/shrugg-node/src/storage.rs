//! Persistent chain storage: one RocksDB with column families.
//!
//! Every commit is a single atomic, fsynced `WriteBatch` covering blocks,
//! certificates, indexes, transaction locations, touched accounts, and the head.

use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, WriteOptions, DB};
use shrugg_core::bridge::{asset_id, AssetId, Attestation, BridgeBurnRecord, BridgeMeta, BridgeState, Payload};
use shrugg_core::consensus::{CommittedBlock, SafetyState};
use shrugg_core::genesis::GenesisState;
use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::{Account, Address, Block, CallReceipt, Hash, Ledger, ProgramId, ProgramRecord, QuorumCertificate, TxKind};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CF_BLOCKS: &str = "blocks";
const CF_QCS: &str = "qcs";
const CF_BLOCK_INDEX: &str = "block_index";
const CF_TXS: &str = "txs";
const CF_ACCOUNTS: &str = "accounts";
const CF_META: &str = "meta";
const CF_PROGRAMS: &str = "programs";
const CF_RECEIPTS: &str = "receipts";
/// `asset(32) || address(32)` -> `bincode(u128)`. A zero balance has no row,
/// matching the bridge state root, which prunes zero balances.
const CF_BRIDGE_BALANCES: &str = "bridge_balances";
/// Consumed attestation digest -> empty. Membership is the whole value.
const CF_BRIDGE_SPENT: &str = "bridge_spent";
/// Burn sequence (big-endian u64, so the family iterates in order) ->
/// `bincode(BridgeBurnRecord)`.
const CF_BRIDGE_BURNS: &str = "bridge_burns";
const ALL_CFS: [&str; 11] = [
    CF_BLOCKS,
    CF_QCS,
    CF_BLOCK_INDEX,
    CF_TXS,
    CF_ACCOUNTS,
    CF_META,
    CF_PROGRAMS,
    CF_RECEIPTS,
    CF_BRIDGE_BALANCES,
    CF_BRIDGE_SPENT,
    CF_BRIDGE_BURNS,
];
const BRIDGE_CFS: [&str; 3] = [CF_BRIDGE_BALANCES, CF_BRIDGE_SPENT, CF_BRIDGE_BURNS];

const META_HEAD_HEIGHT: &str = "head_height";
const META_GENESIS_HASH: &str = "genesis_hash";
const META_CHAIN_ID: &str = "chain_id";
const META_SAFETY: &str = "safety";
/// `bincode(BridgeMeta)`: the whole-state half of the bridge (emitter, emitter
/// table, guardian sets, current index, asset registry, burn sequence). Its
/// presence is what makes a chain "bridged" on disk.
const META_BRIDGE_STATE: &str = "bridge_state";

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

type Result<T> = std::result::Result<T, StorageError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub height: u64,
    pub hash: Hash,
}

pub struct Storage {
    db: DB,
}

fn height_key(h: u64) -> [u8; 8] {
    h.to_be_bytes()
}

/// Key of a bridged-asset balance row: `asset || address`.
fn balance_key(asset: &AssetId, addr: &Address) -> [u8; 64] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(asset.as_bytes());
    k[32..].copy_from_slice(addr.as_bytes());
    k
}

/// The inverse of [`balance_key`].
fn split_balance_key(k: &[u8]) -> Result<(AssetId, Address)> {
    if k.len() != 64 {
        return Err(StorageError::Corrupt("bridge_balances key has wrong length".into()));
    }
    let mut asset = [0u8; 32];
    let mut addr = [0u8; 32];
    asset.copy_from_slice(&k[..32]);
    addr.copy_from_slice(&k[32..]);
    Ok((Hash(asset), Address(addr)))
}

fn sync_opts() -> WriteOptions {
    let mut w = WriteOptions::default();
    w.set_sync(true);
    w
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
        for (addr, acct) in gs.ledger.accounts() {
            batch.put_cf(self.cf(CF_ACCOUNTS), addr.as_bytes(), bincode::serialize(acct)?);
        }
        if let Some(bridge) = gs.ledger.bridge() {
            self.put_bridge(&mut batch, bridge)?;
        }
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(0));
        batch.put_cf(self.cf(CF_META), META_GENESIS_HASH, genesis_hash.as_bytes());
        batch.put_cf(self.cf(CF_META), META_CHAIN_ID, gs.chain_id.to_be_bytes());
        self.db.write_opt(batch, &sync_opts())?;
        Ok(())
    }

    // ---- bridged assets --------------------------------------------------

    /// Write a whole bridge state — the `meta` blob and every row of the three
    /// families — into `batch`. Used where the state is installed wholesale
    /// (genesis, truncation); `commit` writes only what a block touched.
    fn put_bridge(&self, batch: &mut WriteBatch, bridge: &BridgeState) -> Result<()> {
        batch.put_cf(self.cf(CF_META), META_BRIDGE_STATE, bincode::serialize(&bridge.meta())?);
        for ((asset, addr), balance) in &bridge.balances {
            if *balance == 0 {
                continue;
            }
            batch.put_cf(self.cf(CF_BRIDGE_BALANCES), balance_key(asset, addr), bincode::serialize(balance)?);
        }
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

    /// The bridge's whole-state half, or `None` on a chain without a bridge.
    pub fn bridge_meta(&self) -> Result<Option<BridgeMeta>> {
        match self.get_meta_raw(META_BRIDGE_STATE)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// `addr`'s balance of bridged asset `asset` at the committed head; zero
    /// if there is no row (or no bridge at all).
    pub fn asset_balance(&self, asset: &AssetId, addr: &Address) -> Result<u128> {
        Ok(self.get::<u128>(CF_BRIDGE_BALANCES, &balance_key(asset, addr))?.unwrap_or(0))
    }

    /// Every bridged asset `addr` holds a non-zero balance of, with its home
    /// chain and token address from the registry.
    ///
    /// The balance key is `asset || address`, so this scans the family rather
    /// than seeking: bridged holdings are few, and the alternative (a second
    /// index keyed the other way round) would be state to keep consistent.
    pub fn assets_of(&self, addr: &Address) -> Result<Vec<(AssetId, u16, [u8; 32], u128)>> {
        // One snapshot for the registry and the balances: a commit landing
        // between the two reads could otherwise show a balance whose asset was
        // registered by that same commit, which reads as corruption below.
        let snap = self.db.snapshot();
        let raw = snap.get_cf(self.cf(CF_META), META_BRIDGE_STATE.as_bytes())?;
        let Some(meta) = raw.map(|b| bincode::deserialize::<BridgeMeta>(&b)).transpose()? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for item in snap.iterator_cf(self.cf(CF_BRIDGE_BALANCES), IteratorMode::Start) {
            let (k, v) = item?;
            let (asset, holder) = split_balance_key(k.as_ref())?;
            if holder != *addr {
                continue;
            }
            let balance: u128 = bincode::deserialize(&v)?;
            let (chain, token) = meta
                .assets
                .get(&asset)
                .copied()
                .ok_or_else(|| StorageError::Corrupt(format!("balance of unregistered asset {asset}")))?;
            out.push((asset, chain, token, balance));
        }
        Ok(out)
    }

    /// The outbound burn message with this sequence, for guardians to sign.
    pub fn bridge_burn(&self, sequence: u64) -> Result<Option<BridgeBurnRecord>> {
        self.get(CF_BRIDGE_BURNS, &height_key(sequence))
    }

    /// Rebuild the bridge state from the `meta` blob plus the three families.
    /// `None` when the blob is absent, which is how a chain without a bridge
    /// (and only such a chain, once `init_genesis` has run) looks on disk.
    fn load_bridge(&self) -> Result<Option<BridgeState>> {
        let Some(meta) = self.bridge_meta()? else { return Ok(None) };
        let mut balances = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_BRIDGE_BALANCES), IteratorMode::Start) {
            let (k, v) = item?;
            balances.insert(split_balance_key(k.as_ref())?, bincode::deserialize::<u128>(&v)?);
        }
        let mut spent = BTreeSet::new();
        for item in self.db.iterator_cf(self.cf(CF_BRIDGE_SPENT), IteratorMode::Start) {
            let (k, _) = item?;
            let arr: [u8; 32] =
                k.as_ref().try_into().map_err(|_| StorageError::Corrupt("bridge_spent key has wrong length".into()))?;
            spent.insert(Hash(arr));
        }
        let mut burns = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_BRIDGE_BURNS), IteratorMode::Start) {
            let (_, v) = item?;
            let rec: BridgeBurnRecord = bincode::deserialize(&v)?;
            burns.insert(rec.sequence, rec);
        }
        Ok(Some(BridgeState::from_parts(meta, balances, spent, burns)))
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
        let arr: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Corrupt("chain_id meta has wrong length".into()))?;
        Ok(u64::from_be_bytes(arr))
    }

    pub fn head(&self) -> Result<Head> {
        let bytes = self.get_meta_raw(META_HEAD_HEIGHT)?.ok_or(StorageError::NotInitialized)?;
        let arr: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Corrupt("head_height meta has wrong length".into()))?;
        let height = u64::from_be_bytes(arr);
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
        let receipts = block
            .transactions
            .iter()
            .filter_map(|tx| self.receipt(&tx.hash()).ok().flatten())
            .collect();
        Ok(Some(CommittedBlock { block, qc, receipts }))
    }

    pub fn height_by_hash(&self, h: &Hash) -> Result<Option<u64>> {
        match self.db.get_cf(self.cf(CF_BLOCK_INDEX), h.as_bytes())? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::Corrupt("block_index value has wrong length".into()))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
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

    /// Account state at the committed head; default (zero) if absent.
    pub fn program(&self, id: &ProgramId) -> Result<Option<ProgramRecord>> {
        self.get(CF_PROGRAMS, id.as_bytes())
    }

    pub fn programs_count(&self) -> Result<u64> {
        Ok(self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start).count() as u64)
    }

    pub fn receipt(&self, tx: &Hash) -> Result<Option<CallReceipt>> {
        self.get(CF_RECEIPTS, tx.as_bytes())
    }

    pub fn account(&self, a: &Address) -> Result<Account> {
        Ok(self.get::<Account>(CF_ACCOUNTS, a.as_bytes())?.unwrap_or_default())
    }

    /// Load every account, program and bridge row into an in-memory ledger.
    pub fn load_ledger(&self) -> Result<Ledger> {
        let chain_id = self.chain_id()?;
        let mut accounts = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_ACCOUNTS), IteratorMode::Start) {
            let (k, v) = item?;
            let arr: [u8; 32] = k
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Corrupt("account key has wrong length".into()))?;
            let acct: Account = bincode::deserialize(&v)?;
            accounts.insert(Address(arr), acct);
        }
        let mut programs = BTreeMap::new();
        for item in self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start) {
            let (_, v) = item?;
            let rec: ProgramRecord = bincode::deserialize(&v)?;
            programs.insert(rec.id, rec);
        }
        let mut ledger = Ledger::from_parts(chain_id, accounts, programs);
        ledger.set_bridge(self.load_bridge()?);
        Ok(ledger)
    }

    /// Atomically append committed blocks and the accounts they touched.
    pub fn commit(&self, blocks: &[CommittedBlock], ledger_after: &Ledger) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let head = self.head()?;
        let mut expected_height = head.height + 1;
        let mut expected_parent = head.hash;
        let mut batch = WriteBatch::default();
        let mut touched: BTreeSet<Address> = BTreeSet::new();
        // Bridge rows a block's transactions can have moved. Attestations are
        // re-decoded here rather than diffed against the previous state so a
        // commit stays O(block), like the account path above.
        let mut bridge_touched: BTreeSet<(AssetId, Address)> = BTreeSet::new();
        let mut spent_digests: BTreeSet<Hash> = BTreeSet::new();
        let mut has_bridge_tx = false;
        let first_burn_sequence = self.bridge_meta()?.map(|m| m.burn_sequence).unwrap_or(0);

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
                touched.insert(tx.sender());
                match &tx.body.kind {
                    TxKind::Transfer { to, .. } | TxKind::Mint { to, .. } => {
                        touched.insert(*to);
                    }
                    // Bridge kinds move bridged-asset balances, not SHRUGG
                    // accounts beyond the sender, so they touch the bridge
                    // families instead. A committed attestation decoded and
                    // applied, so anything that fails to decode here would be
                    // a torn block, not a rejected transaction; the balances
                    // written below come from `ledger_after` either way.
                    TxKind::BridgeAttest { attestation } => {
                        has_bridge_tx = true;
                        let att = Attestation::decode(attestation).map_err(|e| {
                            StorageError::Corrupt(format!("committed attestation does not decode: {e:?}"))
                        })?;
                        spent_digests.insert(Hash(shrugg_core::bridge::digest(&att.body.encode())));
                        match Payload::decode(&att.body.payload) {
                            Ok(Payload::Transfer(t)) => {
                                let asset = asset_id(t.token_chain, &t.token_address);
                                bridge_touched.insert((asset, Address(t.to)));
                                bridge_touched.insert((asset, tx.sender()));
                            }
                            // A guardian-set upgrade moves no balances.
                            Ok(Payload::GuardianSetUpgrade(_)) => {}
                            // Same reasoning as the attestation above: this
                            // decoded once already, so failing now is a torn
                            // block. Skipping it would write no balance rows
                            // and leave disk disagreeing with memory.
                            Err(e) => {
                                let m = format!("committed attestation payload does not decode: {e:?}");
                                return Err(StorageError::Corrupt(m));
                            }
                        }
                    }
                    TxKind::BridgeBurn { asset, .. } => {
                        has_bridge_tx = true;
                        bridge_touched.insert((*asset, tx.sender()));
                    }
                    TxKind::Deploy { .. } | TxKind::Call { .. } => {}
                }
            }
            for r in &cb.receipts {
                if r.height != block.height() {
                    return Err(StorageError::Corrupt(format!("receipt for block {} attached to block {}", r.height, block.height())));
                }
                batch.put_cf(self.cf(CF_RECEIPTS), r.tx.as_bytes(), bincode::serialize(r)?);
                if let Some((to, _)) = r.effect {
                    touched.insert(to);
                }
            }
            touched.insert(block.proposer());
            expected_height += 1;
            expected_parent = hash;
        }

        for addr in &touched {
            let acct = ledger_after.account(addr);
            batch.put_cf(self.cf(CF_ACCOUNTS), addr.as_bytes(), bincode::serialize(&acct)?);
        }
        let first_height = head.height + 1;
        for rec in ledger_after.programs().values() {
            if rec.deployed_at >= first_height {
                batch.put_cf(self.cf(CF_PROGRAMS), rec.id.as_bytes(), bincode::serialize(rec)?);
            }
        }
        if has_bridge_tx {
            let bridge = ledger_after.bridge().ok_or_else(|| {
                StorageError::Corrupt("committed block has a bridge transaction but the ledger has no bridge state".into())
            })?;
            for (asset, addr) in &bridge_touched {
                let key = balance_key(asset, addr);
                match bridge.balance(asset, addr) {
                    // A drained holder has no row, so a reloaded state equals
                    // the one in memory and commits to the same root.
                    0 => batch.delete_cf(self.cf(CF_BRIDGE_BALANCES), key),
                    balance => batch.put_cf(self.cf(CF_BRIDGE_BALANCES), key, bincode::serialize(&balance)?),
                }
            }
            for digest in &spent_digests {
                batch.put_cf(self.cf(CF_BRIDGE_SPENT), digest.as_bytes(), []);
            }
            for (sequence, rec) in bridge.burns.range(first_burn_sequence..) {
                batch.put_cf(self.cf(CF_BRIDGE_BURNS), height_key(*sequence), bincode::serialize(rec)?);
            }
            batch.put_cf(self.cf(CF_META), META_BRIDGE_STATE, bincode::serialize(&bridge.meta())?);
        }
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(expected_height - 1));
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
    /// No signature verification.
    Quick,
    /// `Quick` plus proposer signatures and every QC's votes.
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
            check.ledger = self.load_ledger()?;
            return Ok(check);
        }

        let mut prev_hash = gs.hash();
        // The genesis block is the baseline for both chained checks below.
        let mut parent_timestamp_ms = gs.block.header.timestamp_ms;
        ledger.set_timestamp_ms(parent_timestamp_ms);
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
                if !block.verify_tx_root() {
                    return Err(format!("block {h} tx root mismatch"));
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
                if mode == VerifyMode::Full {
                    if !block.verify_signature() {
                        return Err(format!("block {h} proposer signature invalid"));
                    }
                    if !qc.verify(&gs.validators, &gs.hash()) {
                        return Err(format!("qc {h} has invalid or insufficient votes"));
                    }
                }
                for (i, tx) in block.transactions.iter().enumerate() {
                    match self.tx_location(&tx.hash()) {
                        Ok(Some((bh, bi))) if bh == h && bi == i as u32 => {}
                        Ok(other) => return Err(format!("tx {} in block {h} indexed as {other:?}", tx.hash())),
                        Err(e) => return Err(format!("tx index unreadable at block {h}: {e}")),
                    }
                }
                // Re-execute; checks the header's state root as well. This
                // replay uses `apply_transactions`, not `apply_block`, so the
                // bridged-chain rule that time never runs backwards has to be
                // restated here rather than inherited.
                if ledger.bridge().is_some() && block.header.timestamp_ms < parent_timestamp_ms {
                    return Err(format!(
                        "block {h} timestamp {} is before its parent's {parent_timestamp_ms}",
                        block.header.timestamp_ms
                    ));
                }
                parent_timestamp_ms = block.header.timestamp_ms;
                let mut next = ledger.clone();
                next.set_height(h);
                next.set_timestamp_ms(block.header.timestamp_ms);
                let receipts = next
                    .apply_transactions(&block.transactions, &block.proposer(), executor)
                    .map_err(|e| format!("block {h} does not apply: {e}"))?;
                if next.state_root() != block.header.state_root {
                    return Err(format!("block {h} state root mismatch"));
                }
                for (index, r) in receipts {
                    let tx = &block.transactions[index];
                    match self.receipt(&tx.hash()) {
                        Ok(Some(stored)) if stored.program == r.program && stored.outputs == r.outputs && stored.effect == r.effect && stored.height == h => {}
                        Ok(_) => return Err(format!("receipt for tx {} in block {h} missing or wrong", tx.hash())),
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
        // The accounts column family must match the replayed ledger.
        let stored = self.load_ledger()?;
        if stored.state_root() != ledger.state_root() {
            check.problem = Some("accounts/programs snapshot does not match replayed chain".into());
        } else if stored.programs() != ledger.programs() {
            check.problem = Some("programs snapshot does not match replayed chain".into());
        } else if stored.bridge() != ledger.bridge() {
            // The state root covers most of the bridge but not the outbound
            // burn log, which is derived from the same blocks and must be
            // there for guardians to read; compare the whole thing.
            check.problem = Some("bridge snapshot does not match replayed chain".into());
        }
        check.ledger = ledger;
        Ok(check)
    }

    /// Drop everything above `height`, rewrite the accounts snapshot from
    /// `ledger` (the replayed state at `height`), and reset the head. With
    /// `height == 0` the genesis block and certificate are rewritten too.
    /// Safety state is preserved. One fsynced batch.
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
        for item in self.db.iterator_cf(self.cf(CF_ACCOUNTS), IteratorMode::Start) {
            let (k, _) = item?;
            batch.delete_cf(self.cf(CF_ACCOUNTS), k);
        }
        for (addr, acct) in ledger.accounts() {
            batch.put_cf(self.cf(CF_ACCOUNTS), addr.as_bytes(), bincode::serialize(acct)?);
        }
        for item in self.db.iterator_cf(self.cf(CF_PROGRAMS), IteratorMode::Start) {
            let (k, _) = item?;
            batch.delete_cf(self.cf(CF_PROGRAMS), k);
        }
        for rec in ledger.programs().values() {
            batch.put_cf(self.cf(CF_PROGRAMS), rec.id.as_bytes(), bincode::serialize(rec)?);
        }
        // The bridge families have no per-height key, so they are rebuilt
        // wholesale from the replayed ledger rather than pruned.
        self.clear_bridge(&mut batch)?;
        if let Some(bridge) = ledger.bridge() {
            self.put_bridge(&mut batch, bridge)?;
        }
        for item in self.db.iterator_cf(self.cf(CF_RECEIPTS), IteratorMode::Start) {
            let (k, v) = item?;
            let keep = bincode::deserialize::<CallReceipt>(&v).map(|r| r.height <= height).unwrap_or(false);
            if !keep {
                batch.delete_cf(self.cf(CF_RECEIPTS), k);
            }
        }
        if height == 0 {
            let hk = height_key(0);
            batch.put_cf(self.cf(CF_BLOCKS), hk, gs.block.encode());
            batch.put_cf(self.cf(CF_QCS), hk, bincode::serialize(&QuorumCertificate::genesis(gs.hash()))?);
            batch.put_cf(self.cf(CF_BLOCK_INDEX), gs.hash().as_bytes(), hk);
            batch.put_cf(self.cf(CF_META), META_GENESIS_HASH, gs.hash().as_bytes());
            batch.put_cf(self.cf(CF_META), META_CHAIN_ID, gs.chain_id.to_be_bytes());
        }
        batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(height));
        let mut wo = WriteOptions::default();
        wo.set_sync(true);
        self.db.write_opt(batch, &wo)?;
        Ok(())
    }

    /// Test hook: overwrite the raw bytes stored for a block height to simulate
    /// on-disk corruption. Never called by the node itself.
    pub fn overwrite_block_bytes_for_testing(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.db.put_cf(self.cf(CF_BLOCKS), height_key(height), bytes)?;
        Ok(())
    }

    /// Test hook: overwrite a stored account to simulate snapshot corruption.
    pub fn overwrite_account_for_testing(&self, addr: &Address, acct: &Account) -> Result<()> {
        self.db.put_cf(self.cf(CF_ACCOUNTS), addr.as_bytes(), bincode::serialize(acct)?)?;
        Ok(())
    }

    /// Test hook: overwrite a bridged-asset balance to simulate snapshot
    /// corruption. Never called by the node itself.
    pub fn overwrite_asset_balance_for_testing(&self, asset: &AssetId, addr: &Address, balance: u128) -> Result<()> {
        self.db.put_cf(self.cf(CF_BRIDGE_BALANCES), balance_key(asset, addr), bincode::serialize(&balance)?)?;
        Ok(())
    }
}

/// Fixtures shared by the storage tests and the RPC tests, which need a
/// database holding a real bridged chain to answer against.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::genesis::{Genesis, GenesisValidator};
    use shrugg_core::{BlockHeader, Keypair, Transaction};

    pub(crate) fn key(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    pub(crate) fn genesis(chain_id: u64) -> GenesisState {
        let k = key(1);
        Genesis {
            chain_id,
            timestamp_ms: 0,
            validators: vec![GenesisValidator { public_key: k.public_key().clone(), stake: 10 }],
            alloc: [(k.address().to_base58(), 1_000u128)].into_iter().collect(),
            faucet: false,
            confidential: true,
            fri_profile: "test".into(),
            bridge: None,
        }
        .build()
        .unwrap()
    }

    // ---- bridge fixtures -------------------------------------------------

    /// Four guardian secrets (scalars 1..=4); quorum is `4 * 2 / 3 + 1 = 3`.
    pub(crate) fn guardian_secrets() -> Vec<[u8; 32]> {
        (1u8..=4)
            .map(|i| {
                let mut s = [0u8; 32];
                s[31] = i;
                s
            })
            .collect()
    }

    pub(crate) const SOURCE_EMITTER: [u8; 32] = [0xee; 32];
    pub(crate) const TOKEN: [u8; 32] = [0xaa; 32];

    pub(crate) fn bridge_config() -> shrugg_core::bridge::BridgeConfig {
        shrugg_core::bridge::BridgeConfig {
            emitter: [1u8; 32],
            guardians: guardian_secrets().iter().map(shrugg_core::bridge::guardian_address).collect(),
            emitters: [(2u16, SOURCE_EMITTER)].into_iter().collect(),
        }
    }

    /// A genesis with a bridge section, funding `key(1)` for fees.
    pub(crate) fn bridged_genesis(chain_id: u64) -> GenesisState {
        let k = key(1);
        Genesis {
            chain_id,
            timestamp_ms: 0,
            validators: vec![GenesisValidator { public_key: k.public_key().clone(), stake: 10 }],
            alloc: [(k.address().to_base58(), 1_000u128)].into_iter().collect(),
            faucet: false,
            confidential: true,
            fri_profile: "test".into(),
            bridge: Some(bridge_config()),
        }
        .build()
        .unwrap()
    }

    /// A quorum-signed transfer attestation crediting `to` with `amount - fee`.
    pub(crate) fn attestation(sequence: u64, to: &Address, amount: u128, fee: u128) -> Vec<u8> {
        use shrugg_core::bridge::{digest, sign_digest, Attestation, Body, Payload, Transfer};
        let body = Body {
            timestamp: 0,
            nonce: 0,
            emitter_chain: 2,
            emitter_address: SOURCE_EMITTER,
            sequence,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(amount),
                token_address: TOKEN,
                token_chain: 2,
                to: *to.as_bytes(),
                to_chain: 1,
                fee: Transfer::u256_from_u128(fee),
            })
            .encode(),
        };
        let d = digest(&body.encode());
        let secrets = guardian_secrets();
        let signatures = (0..3u8).map(|i| sign_digest(&secrets[i as usize], i, &d)).collect();
        Attestation { guardian_set_index: 0, signatures, body }.encode()
    }

    pub(crate) fn bridged_asset() -> shrugg_core::bridge::AssetId {
        shrugg_core::bridge::asset_id(2, &TOKEN)
    }

    /// A well-formed, correctly signed envelope wrapping a payload whose id
    /// byte no version of the codec knows: the envelope decodes, the payload
    /// does not.
    pub(crate) fn attestation_with_undecodable_payload() -> Vec<u8> {
        use shrugg_core::bridge::{digest, sign_digest, Attestation, Body};
        let body = Body {
            timestamp: 0,
            nonce: 0,
            emitter_chain: 2,
            emitter_address: SOURCE_EMITTER,
            sequence: 7,
            consistency_level: 0,
            payload: vec![0xff; 40],
        };
        let d = digest(&body.encode());
        let secrets = guardian_secrets();
        let signatures = (0..3u8).map(|i| sign_digest(&secrets[i as usize], i, &d)).collect();
        Attestation { guardian_set_index: 0, signatures, body }.encode()
    }

    pub(crate) fn make_block(parent: &Block, ledger: &mut Ledger, txs: Vec<Transaction>, k: &Keypair) -> CommittedBlock {
        ledger.apply_transactions(&txs, &k.address(), &StubExecutor).unwrap();
        make_block_unchecked(parent, ledger, txs, k)
    }

    /// `make_block` without executing the transactions: the only way to build a
    /// block carrying a transaction the ledger would have rejected, which is
    /// what a torn block on disk looks like.
    pub(crate) fn make_block_unchecked(parent: &Block, ledger: &Ledger, txs: Vec<Transaction>, k: &Keypair) -> CommittedBlock {
        let header = BlockHeader {
            height: parent.height() + 1,
            view: parent.view() + 1,
            parent: parent.hash(),
            proposer: k.public_key().clone(),
            timestamp_ms: 1,
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

    /// A well-formed EVM recipient: 12 zero bytes then 20 address bytes
    /// (spec 3.5), the shape `BridgeState::check_burn` requires for the
    /// EVM-family chains 2, 3 and 4.
    fn evm_to() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[12..].copy_from_slice(&[0x22u8; 20]);
        t
    }
    use super::fixtures::*;
    use super::*;
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::Transaction;

    #[test]
    fn init_and_reopen_preserves_meta() {
        let dir = tempfile::tempdir().unwrap();
        let gs = genesis(7);
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
        let head = s.head().unwrap();
        assert_eq!(head, Head { height: 0, hash: gs.hash() });
        assert_eq!(s.head_block().unwrap().hash(), gs.hash());
        assert_eq!(s.head_qc().unwrap(), QuorumCertificate::genesis(gs.hash()));
        assert_eq!(s.height_by_hash(&gs.hash()).unwrap(), Some(0));
        assert_eq!(s.account(&key(1).address()).unwrap().balance, 1_000);
        assert_eq!(s.load_ledger().unwrap(), gs.ledger);
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

    #[test]
    fn commit_two_blocks_updates_everything() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis(1);
        s.init_genesis(&gs).unwrap();
        let alice = key(1);
        let bob = key(2);
        let mut ledger = gs.ledger.clone();

        let tx1 = Transaction::transfer(&alice, 1, 0, bob.address(), 100, 5);
        let b1 = make_block(&gs.block, &mut ledger, vec![tx1.clone()], &alice);
        let tx2 = Transaction::transfer(&alice, 1, 1, bob.address(), 50, 1);
        let b2 = make_block(&b1.block, &mut ledger, vec![tx2.clone()], &alice);

        s.commit(&[b1.clone(), b2.clone()], &ledger).unwrap();

        let head = s.head().unwrap();
        assert_eq!(head, Head { height: 2, hash: b2.block.hash() });
        assert_eq!(s.head_qc().unwrap(), b2.qc);
        assert_eq!(s.block_by_height(1).unwrap().unwrap(), b1.block);
        assert_eq!(s.block_by_hash(&b2.block.hash()).unwrap().unwrap(), b2.block);
        assert_eq!(s.committed_block(1).unwrap().unwrap(), b1);
        assert_eq!(s.committed_block(3).unwrap(), None);
        assert_eq!(s.tx_location(&tx1.hash()).unwrap(), Some((1, 0)));
        assert_eq!(s.tx_location(&tx2.hash()).unwrap(), Some((2, 0)));
        assert_eq!(s.tx_location(&Hash::ZERO).unwrap(), None);
        // alice: 1000 - 105 - 51 + fees back as proposer (5 + 1)
        assert_eq!(s.account(&alice.address()).unwrap(), Account { nonce: 2, balance: 850 });
        assert_eq!(s.account(&bob.address()).unwrap(), Account { nonce: 0, balance: 150 });
        assert_eq!(s.load_ledger().unwrap(), ledger);

        // reopen keeps it
        drop(s);
        let s = Storage::open(dir.path()).unwrap();
        assert_eq!(s.head().unwrap().height, 2);
    }

    #[test]
    fn non_contiguous_commit_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis(1);
        s.init_genesis(&gs).unwrap();
        let alice = key(1);
        let mut ledger = gs.ledger.clone();
        let b1 = make_block(&gs.block, &mut ledger, vec![], &alice);
        let b2 = make_block(&b1.block, &mut ledger, vec![], &alice);
        // skipping b1
        assert!(matches!(s.commit(&[b2.clone()], &ledger), Err(StorageError::Corrupt(_))));
        assert_eq!(s.head().unwrap().height, 0);
        // wrong qc hash
        let mut bad = b1.clone();
        bad.qc.block_hash = Hash::ZERO;
        assert!(matches!(s.commit(&[bad], &ledger), Err(StorageError::Corrupt(_))));
        // correct order works
        s.commit(&[b1, b2], &ledger).unwrap();
        assert_eq!(s.head().unwrap().height, 2);
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

    fn chain_fixture(n: u64) -> (tempfile::TempDir, Storage, GenesisState, Vec<CommittedBlock>) {
        chain_fixture_with(n, 1_000)
    }

    fn chain_fixture_with(n: u64, alloc: u128) -> (tempfile::TempDir, Storage, GenesisState, Vec<CommittedBlock>) {
        use shrugg_core::consensus::CommittedBlock;
        use shrugg_core::genesis::{Genesis, GenesisValidator};
        use shrugg_core::{BlockHeader, Keypair, Transaction, Vote};
        let k = Keypair::from_seed([9u8; 32]).unwrap();
        let bob = Keypair::from_seed([10u8; 32]).unwrap().address();
        let gen = Genesis {
            chain_id: 5,
            timestamp_ms: 0,
            validators: vec![GenesisValidator { public_key: k.public_key().clone(), stake: 1 }],
            alloc: [(k.address().to_base58(), alloc)].into_iter().collect(),
            faucet: false,
            confidential: true,
            fri_profile: "test".into(),
            bridge: None,
        };
        let gs = gen.build().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let st = Storage::open(dir.path()).unwrap();
        st.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let mut parent = gs.block.clone();
        let mut qc = QuorumCertificate::genesis(gs.hash());
        let mut out = Vec::new();
        for h in 1..=n {
            let txs = vec![Transaction::transfer(&k, 5, h - 1, bob, 10, 1)];
            ledger.apply_transactions(&txs, &k.address(), &StubExecutor).unwrap();
            let header = BlockHeader {
                height: h,
                view: h,
                parent: parent.hash(),
                proposer: k.public_key().clone(),
                timestamp_ms: h,
                tx_root: Block::tx_root(&txs),
                state_root: ledger.state_root(),
                justify: qc.clone(),
            };
            let block = Block::sign(header, txs, &k);
            qc = QuorumCertificate { view: h, block_hash: block.hash(), votes: vec![Vote::sign(h, block.hash(), &k)] };
            let cb = CommittedBlock { block: block.clone(), qc: qc.clone(), receipts: Vec::new() };
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
            assert_eq!(c.ledger.state_root(), st.load_ledger().unwrap().state_root());
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
        let again = st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap();
        assert!(again.is_ok(), "{:?}", again.problem);
        assert_eq!(again.last_good, 3);
        // Chain can be re-extended from the truncated head.
        let mut ledger = again.ledger.clone();
        let cb = &blocks[3]; // height 4 again
        ledger.apply_transactions(&cb.block.transactions, &cb.block.proposer(), &StubExecutor).unwrap();
        st.commit(std::slice::from_ref(cb), &ledger).unwrap();
        assert_eq!(st.head().unwrap().height, 4);
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
    fn account_snapshot_corruption_is_detected_and_repaired() {
        let (_d, st, gs, _) = chain_fixture(3);
        let k = shrugg_core::Keypair::from_seed([9u8; 32]).unwrap().address();
        st.overwrite_account_for_testing(&k, &Account { nonce: 99, balance: 1 }).unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!c.is_ok());
        assert_eq!(c.last_good, 3, "blocks are fine, only the snapshot is wrong");
        st.truncate_to(&gs, 3, &c.ledger).unwrap();
        assert_eq!(st.account(&k).unwrap().nonce, 3);
        assert!(st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().is_ok());
    }

    #[test]
    fn corrupted_genesis_is_rewritten() {
        let (_d, st, gs, _) = chain_fixture(2);
        st.overwrite_block_bytes_for_testing(0, b"zzz").unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!c.genesis_ok);
        st.truncate_to(&gs, 0, &gs.ledger).unwrap();
        assert_eq!(st.head().unwrap().height, 0);
        assert_eq!(st.head().unwrap().hash, gs.hash());
        assert!(st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap().is_ok());
        assert!(st.load_safety().is_ok());
    }

    /// The whole point of the bridge column families: whatever the ledger
    /// holds after a commit is what `load_ledger` gives back, across a reopen,
    /// and `truncate_to` puts it back to the genesis bridge state.
    #[test]
    fn a_committed_attestation_with_an_undecodable_payload_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let gs = bridged_genesis(1);
        let alice = key(1);
        let s = Storage::open(dir.path()).unwrap();
        s.init_genesis(&gs).unwrap();

        // Admission decoded this payload once, so a commit that cannot is a
        // torn block. Treating it as "moves no balances" would write no rows
        // and leave the snapshot disagreeing with the ledger.
        let tx = Transaction::bridge_attest(&alice, 1, 0, attestation_with_undecodable_payload(), 1);
        let cb = make_block_unchecked(&gs.block, &gs.ledger, vec![tx], &alice);
        let err = s
            .commit(std::slice::from_ref(&cb), &gs.ledger)
            .expect_err("a payload that does not decode must not commit");
        assert!(
            matches!(&err, StorageError::Corrupt(m) if m.contains("payload does not decode")),
            "{err:?}"
        );
    }

    #[test]
    fn bridge_state_round_trips_through_commit_reopen_and_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let gs = bridged_genesis(1);
        let alice = key(1);
        let bob = key(2);
        let asset = bridged_asset();
        {
            let s = Storage::open(dir.path()).unwrap();
            s.init_genesis(&gs).unwrap();
            // The genesis bridge section is persisted, not just derived.
            assert_eq!(s.load_ledger().unwrap(), gs.ledger);

            let mut ledger = gs.ledger.clone();
            // Position the ledger exactly as a replay would: `make_block`
            // stamps every header with `timestamp_ms: 1`, and the burn record
            // it produces carries the block height.
            ledger.set_timestamp_ms(1);
            ledger.set_height(1);
            // Block 1: mint 1000 (fee 10) to bob, submitted by alice.
            let att = Transaction::bridge_attest(&alice, 1, 0, attestation(0, &bob.address(), 1_000, 10), 1);
            let b1 = make_block(&gs.block, &mut ledger, vec![att.clone()], &alice);
            s.commit(std::slice::from_ref(&b1), &ledger).unwrap();
            assert_eq!(ledger.asset_balance(&asset, &bob.address()), 990);
            assert_eq!(ledger.asset_balance(&asset, &alice.address()), 10);
            assert_eq!(s.load_ledger().unwrap(), ledger);

            // Block 2: alice burns her whole fee back out to chain 2, and a
            // second attestation credits bob again.
            let burn = Transaction::bridge_burn(&alice, 1, 1, asset, 10, 2, evm_to(), 1, 1);
            let att2 = Transaction::bridge_attest(&alice, 1, 2, attestation(1, &bob.address(), 500, 0), 1);
            ledger.set_height(2);
            let b2 = make_block(&b1.block, &mut ledger, vec![burn.clone(), att2.clone()], &alice);
            s.commit(std::slice::from_ref(&b2), &ledger).unwrap();
            // alice's balance hit zero, so its row must be gone, not stale
            assert_eq!(ledger.asset_balance(&asset, &alice.address()), 0);
            assert_eq!(ledger.asset_balance(&asset, &bob.address()), 1_490);
            assert_eq!(ledger.bridge().unwrap().burn_sequence, 1);
            assert_eq!(s.load_ledger().unwrap(), ledger);
            let c = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
            assert!(c.is_ok(), "{:?}", c.problem);
        }
        // Reopening the database changes nothing.
        let s = Storage::open(dir.path()).unwrap();
        let reloaded = s.load_ledger().unwrap();
        let bridge = reloaded.bridge().expect("bridge reloaded");
        assert_eq!(bridge.balance(&asset, &bob.address()), 1_490);
        assert_eq!(bridge.balance(&asset, &alice.address()), 0);
        assert_eq!(bridge.spent.len(), 2);
        assert_eq!(bridge.burns.len(), 1);
        assert_eq!(bridge.burns[&0].height, 2);
        assert_eq!(bridge.assets.get(&asset), Some(&(2u16, TOKEN)));

        // The point queries the RPC layer uses agree with the reloaded state.
        assert_eq!(s.asset_balance(&asset, &bob.address()).unwrap(), 1_490);
        assert_eq!(s.asset_balance(&asset, &alice.address()).unwrap(), 0);
        assert_eq!(s.assets_of(&bob.address()).unwrap(), vec![(asset, 2u16, TOKEN, 1_490u128)]);
        assert!(s.assets_of(&alice.address()).unwrap().is_empty());
        let meta = s.bridge_meta().unwrap().expect("bridge meta");
        assert_eq!(meta, bridge.meta());
        assert_eq!(meta.burn_sequence, 1);
        let rec = s.bridge_burn(0).unwrap().expect("burn record");
        assert_eq!((rec.sequence, rec.height), (0, 2));
        assert_eq!(rec.digest, shrugg_core::bridge::digest(&rec.body));
        assert_eq!(s.bridge_burn(1).unwrap(), None);

        // Truncating to genesis restores the genesis bridge state exactly.
        s.truncate_to(&gs, 0, &gs.ledger).unwrap();
        assert_eq!(s.load_ledger().unwrap(), gs.ledger);
        let back = s.load_ledger().unwrap().bridge().unwrap().clone();
        assert!(back.balances.is_empty() && back.spent.is_empty() && back.burns.is_empty());
        assert_eq!(back.burn_sequence, 0);
        let c = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(c.is_ok(), "{:?}", c.problem);
    }

    /// A damaged bridge balance is caught by the same startup check that
    /// catches a damaged account, and truncation repairs it.
    #[test]
    fn bridge_snapshot_corruption_is_detected_and_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = bridged_genesis(1);
        s.init_genesis(&gs).unwrap();
        let (alice, bob, asset) = (key(1), key(2), bridged_asset());
        let mut ledger = gs.ledger.clone();
        ledger.set_timestamp_ms(1);
        ledger.set_height(1);
        let att = Transaction::bridge_attest(&alice, 1, 0, attestation(0, &bob.address(), 1_000, 0), 1);
        let b1 = make_block(&gs.block, &mut ledger, vec![att], &alice);
        s.commit(std::slice::from_ref(&b1), &ledger).unwrap();
        assert!(s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().is_ok());

        s.overwrite_asset_balance_for_testing(&asset, &bob.address(), 1).unwrap();
        let check = s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!check.is_ok());
        assert_eq!(check.last_good, 1, "only the snapshot is damaged, not the blocks");
        // Rewriting the snapshot from the replayed ledger repairs it.
        s.truncate_to(&gs, 1, &check.ledger).unwrap();
        assert_eq!(s.asset_balance(&asset, &bob.address()).unwrap(), 1_000);
        assert!(s.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap().is_ok());
    }

    /// A chain whose genesis has no `bridge` section stores no bridge state.
    #[test]
    fn a_chain_without_a_bridge_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let gs = genesis(1);
        s.init_genesis(&gs).unwrap();
        assert!(s.load_ledger().unwrap().bridge().is_none());
        assert_eq!(s.load_ledger().unwrap(), gs.ledger);
    }

    #[test]
    fn programs_and_receipts_round_trip_and_truncate() {
        let (_d, st, gs, blocks) = chain_fixture_with(2, 1_000_000_000);
        let k = shrugg_core::Keypair::from_seed([9u8; 32]).unwrap();
        let mut ledger = st.load_ledger().unwrap();
        // block 3 deploys a program and (in the same block) carries a call receipt
        let words = vec![0x13u32; 3];
        let deploy = Transaction::deploy(&k, 5, 2, 0, words.clone(), shrugg_core::gas::deploy_fee(3));
        ledger.set_height(3);
        let cb3 = make_block(&blocks[1].block, &mut ledger, vec![deploy.clone()], &k);
        let pid = shrugg_core::program::program_id(0, &words);
        let receipt = CallReceipt { tx: deploy.hash(), program: pid, tier: 10, outputs: [1, 0, 5, 0, 0, 0, 0, 0], effect: Some((k.address(), 5)), height: 3, index: 0 };
        let cb3 = CommittedBlock { receipts: vec![receipt.clone()], ..cb3 };
        st.commit(std::slice::from_ref(&cb3), &ledger).unwrap();
        let rec = st.program(&pid).unwrap().expect("program stored");
        assert_eq!(rec.words, words);
        assert_eq!(rec.deployed_at, 3);
        assert_eq!(st.receipt(&receipt.tx).unwrap().unwrap(), receipt);
        assert_eq!(st.load_ledger().unwrap().programs().len(), 1);
        assert_eq!(st.programs_count().unwrap(), 1);
        assert_eq!(st.committed_block(3).unwrap().unwrap().receipts, vec![receipt.clone()]);
        // truncating below the deploy removes both
        let two = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        st.truncate_to(&gs, 2, &gs.ledger).unwrap();
        assert!(st.program(&pid).unwrap().is_none());
        assert!(st.receipt(&receipt.tx).unwrap().is_none());
        let _ = two;
    }
}
