# History Pruning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `rand-node run --prune-history 24h` flag under which a node deletes the per-block history of every block older than the window while keeping the ledger, advertises its retention floor to peers, verifies structurally at startup, and answers a distinct RPC error for pruned heights; nodes without the flag (every mainnet node, the testnet archive) are byte-for-byte unchanged.

**Architecture:** One storage pass (`Storage::prune_history`) deletes the height-keyed and transaction-keyed rows of old blocks in a single synced batch and records the floor in `meta`; the node schedules it beside the existing proof-pruning pass. The floor rides in the `Status` gossip so `pick_sync_peer` never asks a peer for a height it has pruned, `verify_chain` switches to a structural walk from the floor when one is set, and the RPC layer turns "below the floor" into error `-32010`.

**Tech Stack:** Rust 2021, RocksDB via the `rocksdb` crate (`delete_range_cf`, `compact_range_cf`), `bincode` 1.x for wire and rows, `serde_json`, `clap` derive, `tokio`; tests with `tempfile` and the existing storage/RPC/cluster fixtures.

**Spec:** `docs/superpowers/specs/2026-09-24-history-pruning-design.md` (this worktree). Two deviations, both recorded in the spec's own text by Task 0:

1. The flag's duration is parsed by a 20-line parser accepting `<n>m`, `<n>h`, `<n>d` (no `humantime` dependency exists in the tree and one line of syntax does not justify one).
2. A pruned node that fails structural verification does **not** truncate: the only ledger it holds is the head's, so truncating to an earlier height would pair blocks with a state they did not produce. It exits with a message naming the archive re-sync.

## Global Constraints

- The flag is absent by default; a store that never pruned has no `prune_floor` meta key and reads as floor 0. Nothing is keyed on `chain_id`.
- Block 0 and its QC are never deleted. No block at or above `keep_from = head - max(aggregation.window, 2)` is deleted.
- Every delete of a pass and the new floor land in one `WriteBatch` written with `sync_opts()`.
- `PRUNE_PASS_MAX = 4096` blocks per pass; the pass runs when `head % 16 == 0`, in `spawn_blocking`, after the proof-pruning pass.
- Range compaction of `blocks` and `qcs` every 64th pass that deleted something.
- `Status` gains exactly one trailing field `floor: u64`.
- RPC error for a pruned height: code `-32010`, message `pruned: height {h} is below this node's retention floor {floor}`, `data: {"floor": floor}`.
- `rand_status` gains `prune_floor: u64` and `prune_history_secs: Option<u64>`.
- CLI minimum window `1h`; a window shorter than `aggregation.window × block_interval` refuses to start. The minimum is enforced in the CLI parser only, so tests can run the node with a two-second window.
- Every test is written before the code it pins and is run red first.
- Commit after each task; commit messages follow the repo's style (`storage: …`, `node: …`, `rpc: …`, `docs: …`), each ending with the attribution lines the session carries.

## Review Focus

Inputs the spec implies but no task's tests exercised before this section was written. Each now has a test in the task named.

1. A block above the floor missing on disk (a torn store) while pruning runs: the pass must stop at the gap rather than skip over it and move the floor past a hole → Task 1, `prune_history_stops_at_a_gap_and_leaves_the_floor_below_it`.
2. `--prune-history` on a chain whose aggregation window is longer than the window in blocks → Task 2, `a_window_shorter_than_the_aggregation_window_refuses_to_start`.
3. A peer whose `Status` says floor above our next height but height far ahead (the old picker would choose it) → Task 3, `pick_sync_peer_never_picks_a_peer_that_pruned_our_next_height`.
4. `rand_getTransaction` for a transaction whose `txs` row survived but whose block is pruned (a row keyed by the raw hash of a marker-form transaction the pass could not resolve) → Task 5, `a_transaction_whose_block_is_pruned_answers_32010_not_block_missing`.
5. Restart of a pruned node with `--verify-chain full` on a store whose floor row exists but whose floor block is missing (crash between compaction and the next pass cannot cause it, but an operator `rm` can) → Task 4, `a_pruned_store_missing_its_floor_block_is_fatal_not_truncated`.

---

### Task 0: Record the two deviations in the spec

**Files:**
- Modify: `docs/superpowers/specs/2026-09-24-history-pruning-design.md` (§1 "Flag", §3 "Repair on a structural failure")

- [ ] **Step 1: Edit §1 "Flag"**

Replace the sentence beginning "`rand-node run --prune-history <duration>` (`humantime` syntax" with:

```
`rand-node run --prune-history <duration>`, where `<duration>` is `<n>m`, `<n>h` or `<n>d` (`24h`,
`36h`, `2d`), parsed by `parse_prune_history` in `main.rs`; no dependency is added for it.
```

- [ ] **Step 2: Edit §3 repair bullet**

Replace the bullet beginning "**Repair on a structural failure**" with:

```
- **A structural failure on a pruned node is fatal.** The node holds one ledger, the head's;
  truncating to an earlier height would pair the remaining blocks with a state they did not
  produce. `check_and_repair_chain` exits with
  `pruned node: {problem}; history cannot be repaired locally — re-sync from the archive`, and
  `verify --repair` prints the same and exits 2.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-09-24-history-pruning-design.md
git commit -m "spec: history pruning — the flag's own parser; a pruned node never truncates"
```

---

### Task 1: Storage — the floor and the retention pass

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs` (constants near line 144; new methods after `prune_sealed`, ~line 1257; tests in `mod tests` after `the_write_ahead_log_is_capped_not_pinned_by_a_quiet_family`)

**Interfaces:**
- Consumes: `Storage::block_by_height`, `receipt`, `get_meta_raw`, `cf`, `height_key`, `sync_opts`, `receipt_index_key`, `randprotocol_core::notes::pruned_proof_hash`, the test fixtures `chain_fixture(n)`, `make_block_at`, `genesis_with_two_notes`, `key`, `bundle_tx`, `bundle_fee`, `StubExecutor`.
- Produces:
  - `pub const PRUNE_PASS_MAX: u64 = 4096;`
  - `pub fn prune_floor(&self) -> Result<u64>`
  - `pub fn prune_history(&self, cutoff_ms: u64, keep_from: u64, max_blocks: u64) -> Result<u64>`
  - `pub fn compact_pruned_history(&self) -> Result<()>`
  - `#[cfg(test)] pub(crate) fn put_history_rows_for_test(&self, block_hash: &Hash, tx: &Hash, proof_hash: &Hash, cover: &Hash, receipt: &CallReceipt) -> Result<()>`

- [ ] **Step 1: Write the failing tests**

Append inside `mod tests` in `storage.rs`:

```rust
    /// (In `fixtures`.) A chain of `n` bundle blocks whose timestamps are `h * 1000` ms, so a
    /// cutoff in milliseconds names a height directly.
    pub(crate) fn timed_chain(n: u64) -> (tempfile::TempDir, Storage, GenesisState, Vec<CommittedBlock>) {
        let (dir, st, gs) = genesis_with_two_notes();
        st.init_genesis(&gs).unwrap();
        let k = key(1);
        let mut ledger = gs.ledger.clone();
        let mut parent = gs.block.clone();
        let mut out = Vec::new();
        for h in 1..=n {
            let seed = (h * 4) as u32;
            let txs = vec![bundle_tx(&ledger, [[seed; 8], [seed + 1; 8]], [[seed + 2; 8], [seed + 3; 8]], bundle_fee())];
            let cb = make_block_at(&parent, &mut ledger, txs, &k, h * 1000);
            st.commit(std::slice::from_ref(&cb), &ledger, &[], &StubExecutor).unwrap();
            parent = cb.block.clone();
            out.push(cb);
        }
        (dir, st, gs, out)
    }

    #[test]
    fn a_store_that_never_pruned_reads_floor_zero() {
        let (_dir, st, _gs, _blocks) = timed_chain(3);
        assert_eq!(st.prune_floor().unwrap(), 0);
    }

    #[test]
    fn prune_history_deletes_exactly_the_per_block_rows_and_keeps_the_ledger() {
        let (_dir, st, _gs, blocks) = timed_chain(10);
        let before = st.load_ledger(&StubExecutor).unwrap();
        let notes_before = st.notes_count().unwrap();
        // Cutoff 6 000 ms: blocks 1..=5 are older; keep_from 9 lets them all go; cap generous.
        assert_eq!(st.prune_history(6_000, 9, PRUNE_PASS_MAX).unwrap(), 5);
        assert_eq!(st.prune_floor().unwrap(), 6);
        for h in 1..=5 {
            assert!(st.block_by_height(h).unwrap().is_none(), "block {h} should be gone");
            assert!(st.qc_by_height(h).unwrap().is_none(), "qc {h} should be gone");
            let b = &blocks[(h - 1) as usize].block;
            assert!(st.height_by_hash(&b.hash()).unwrap().is_none(), "index {h} should be gone");
            assert!(st.tx_location(&b.transactions[0].hash()).unwrap().is_none(), "tx of {h} should be gone");
        }
        for h in 6..=10 {
            assert!(st.block_by_height(h).unwrap().is_some(), "block {h} must stay");
            assert!(st.qc_by_height(h).unwrap().is_some(), "qc {h} must stay");
        }
        // Genesis never goes.
        assert!(st.block_by_height(0).unwrap().is_some());
        assert!(st.qc_by_height(0).unwrap().is_some());
        // The ledger families are untouched: same snapshot, same leaves, nullifiers still known.
        assert_eq!(st.load_ledger(&StubExecutor).unwrap(), before);
        assert_eq!(st.notes_count().unwrap(), notes_before);
        assert_eq!(st.head().unwrap().height, 10);
        assert!(st.witness(0, &StubExecutor).unwrap().is_some());
    }

    #[test]
    fn prune_history_honours_keep_from_the_cap_and_is_idempotent() {
        let (_dir, st, _gs, _blocks) = timed_chain(10);
        // Everything is older than the cutoff, but keep_from 4 protects 4..=10.
        assert_eq!(st.prune_history(u64::MAX, 4, PRUNE_PASS_MAX).unwrap(), 3);
        assert_eq!(st.prune_floor().unwrap(), 4);
        // The cap: two more would be allowed by keep_from 8, only one is taken.
        assert_eq!(st.prune_history(u64::MAX, 8, 1).unwrap(), 1);
        assert_eq!(st.prune_floor().unwrap(), 5);
        // Nothing older than the cutoff: no change, floor stays, no error.
        assert_eq!(st.prune_history(5_000, 8, PRUNE_PASS_MAX).unwrap(), 0);
        assert_eq!(st.prune_floor().unwrap(), 5);
        // keep_from at or below the floor: nothing to do.
        assert_eq!(st.prune_history(u64::MAX, 5, PRUNE_PASS_MAX).unwrap(), 0);
    }

    #[test]
    fn prune_history_stops_at_a_gap_and_leaves_the_floor_below_it() {
        let (_dir, st, _gs, _blocks) = timed_chain(6);
        // Tear block 3 out by hand: a torn store, not a pruned one.
        st.db.delete_cf(st.cf(CF_BLOCKS), height_key(3)).unwrap();
        assert_eq!(st.prune_history(u64::MAX, 6, PRUNE_PASS_MAX).unwrap(), 2);
        assert_eq!(st.prune_floor().unwrap(), 3, "the floor must not jump the hole");
        assert!(st.block_by_height(4).unwrap().is_some(), "nothing past the hole is touched");
    }

    #[test]
    fn prune_history_removes_the_seal_and_receipt_rows_a_block_owns() {
        let (_dir, st, _gs, blocks) = timed_chain(3);
        let b1 = &blocks[0].block;
        let tx = b1.transactions[0].hash();
        let proof_hash = Hash([0x11; 32]);
        let cover = Hash([0x22; 32]);
        let receipt = randprotocol_core::program::CallReceipt {
            tx, program: Hash([0x33; 32]), tier: 1, outputs: [0; 8], height: 1, index: 0, h_in: [0; 8], h_pub: None, input_envelope: None,
        };
        st.put_history_rows_for_test(&b1.hash(), &tx, &proof_hash, &cover, &receipt).unwrap();
        assert!(st.block_sealed(&b1.hash()).unwrap());
        assert!(st.receipt(&tx).unwrap().is_some());
        assert!(st.sealed_by(&cover).unwrap().is_some());
        assert_eq!(st.prune_history(2_500, 3, PRUNE_PASS_MAX).unwrap(), 2);
        assert!(!st.block_sealed(&b1.hash()).unwrap(), "the 'b' row goes with the block");
        assert!(st.receipt(&tx).unwrap().is_none(), "the receipt goes with the tx");
        assert!(st.sealed_by(&cover).unwrap().is_none(), "the 't' row goes with the aggregate");
        assert!(st.aggregate_payment(&tx).unwrap().is_none(), "the 'a' row goes with the aggregate");
        assert!(st.db.get_cf(st.cf(CF_SEALS), [b"p".as_slice(), proof_hash.as_bytes()].concat()).unwrap().is_none());
        assert!(st.receipts_for_program(&receipt.program, 0, 10, 10).unwrap().0.is_empty());
    }

    #[test]
    fn compacting_pruned_history_is_a_no_op_on_an_archive_and_succeeds_after_a_pass() {
        let (_dir, st, _gs, _blocks) = timed_chain(4);
        st.compact_pruned_history().unwrap();
        assert_eq!(st.prune_history(u64::MAX, 3, PRUNE_PASS_MAX).unwrap(), 2);
        st.compact_pruned_history().unwrap();
        assert!(st.block_by_height(3).unwrap().is_some());
    }
```

`timed_chain` goes in the `pub(crate) mod fixtures` block beside `chain_fixture` (as `pub(crate) fn`), not in `mod tests`, because Tasks 4 and 5 use it from `node.rs` and `rpc.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p randprotocol-node --lib storage::tests::prune_history -- --nocapture`
Expected: compile errors naming `prune_floor`, `prune_history`, `PRUNE_PASS_MAX`, `put_history_rows_for_test`, `compact_pruned_history`.

- [ ] **Step 3: Implement**

Near the other meta constants (after `META_TOKENS_V2`):

```rust
/// The history-retention floor (history pruning spec §1): the lowest height, other than genesis,
/// whose block this store still holds. Absent on a store that never pruned — an archive.
const META_PRUNE_FLOOR: &str = "prune_floor";
/// Blocks one `prune_history` pass deletes at most, so enabling the flag on a node holding days
/// of history drains it over minutes of passes rather than one long stall.
pub const PRUNE_PASS_MAX: u64 = 4096;
```

After `prune_sealed` / `put_pruned` in `impl Storage`:

```rust
    /// The retention floor: 0 on a store that never pruned.
    pub fn prune_floor(&self) -> Result<u64> {
        match self.get_meta_raw(META_PRUNE_FLOOR)? {
            Some(b) => be_u64(&b, "prune_floor meta"),
            None => Ok(0),
        }
    }

    /// The history-retention pass (history pruning spec §1 — policy, never consensus). Walks up
    /// from the floor and deletes the per-block rows of every block whose timestamp is older
    /// than `cutoff_ms`, stopping at `keep_from`, after `max_blocks`, at the first block at or
    /// past the cutoff, or at a hole (a torn store is not pruned over). Block 0 is never
    /// deleted. The deletes and the new floor land in one synced batch. Returns the number of
    /// blocks deleted; the ledger families are never touched.
    pub fn prune_history(&self, cutoff_ms: u64, keep_from: u64, max_blocks: u64) -> Result<u64> {
        let mut h = self.prune_floor()?.max(1);
        let mut batch = WriteBatch::default();
        let mut deleted = 0u64;
        while h < keep_from && deleted < max_blocks {
            let Some(block) = self.block_by_height(h)? else { break };
            if block.header.timestamp_ms >= cutoff_ms {
                break;
            }
            self.stage_block_delete(&mut batch, &block)?;
            deleted += 1;
            h += 1;
        }
        if deleted == 0 {
            return Ok(0);
        }
        batch.put_cf(self.cf(CF_META), META_PRUNE_FLOOR, height_key(h));
        self.db.write_opt(batch, &sync_opts())?;
        Ok(deleted)
    }

    /// Every row a committed block owns, staged for deletion: the block, its QC, its hash
    /// index, its sealed flag, and per transaction the record, the receipt and its program
    /// index row, the aggregate's cover marks and payment facts, and the pruned form's
    /// proof-hash row. Ledger families are not the block's to delete.
    fn stage_block_delete(&self, batch: &mut WriteBatch, block: &Block) -> Result<()> {
        let hk = height_key(block.height());
        let hash = block.hash();
        batch.delete_cf(self.cf(CF_BLOCKS), hk);
        batch.delete_cf(self.cf(CF_QCS), hk);
        batch.delete_cf(self.cf(CF_BLOCK_INDEX), hash.as_bytes());
        batch.delete_cf(self.cf(CF_SEALS), [b"b".as_slice(), hash.as_bytes()].concat());
        for tx in &block.transactions {
            // A block served in sealed form carries a marker-form bundle whose record is keyed by
            // the raw hash the 'p' row names; everything else is keyed by its own hash.
            let key = match tx.bundle.as_ref().and_then(|b| randprotocol_core::notes::pruned_proof_hash(&b.proof)) {
                Some(ph) => {
                    let pkey = [b"p".as_slice(), ph.as_bytes()].concat();
                    match self.db.get_cf(self.cf(CF_SEALS), &pkey)? {
                        Some(v) => bincode::deserialize::<Hash>(&v)?,
                        None => tx.hash(),
                    }
                }
                None => tx.hash(),
            };
            // A record the proof-pruning pass rewrote also owns a 'p' row.
            if let Some(v) = self.db.get_cf(self.cf(CF_TXS), key.as_bytes())? {
                if let Ok(TxRecord::Pruned { proof_hash, .. }) = bincode::deserialize::<TxRecord>(&v) {
                    batch.delete_cf(self.cf(CF_SEALS), [b"p".as_slice(), proof_hash.as_bytes()].concat());
                }
            }
            batch.delete_cf(self.cf(CF_TXS), key.as_bytes());
            if let Some(r) = self.receipt(&key)? {
                batch.delete_cf(self.cf(CF_RECEIPTS), key.as_bytes());
                batch.delete_cf(self.cf(CF_RECEIPTS_BY_PROGRAM), receipt_index_key(&r.program, r.height, r.index));
            }
            if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                for cover in covers {
                    batch.delete_cf(self.cf(CF_SEALS), [b"t".as_slice(), cover.as_bytes()].concat());
                }
                batch.delete_cf(self.cf(CF_SEALS), [b"a".as_slice(), tx.hash().as_bytes()].concat());
            }
        }
        Ok(())
    }

    /// Give the disk back: RocksDB only frees a deleted range at compaction. Compacts `blocks`
    /// and `qcs` over `[1, floor)`. A no-op on an archive.
    pub fn compact_pruned_history(&self) -> Result<()> {
        let floor = self.prune_floor()?;
        if floor <= 1 {
            return Ok(());
        }
        for cf in [CF_BLOCKS, CF_QCS] {
            self.db.compact_range_cf(self.cf(cf), Some(height_key(1)), Some(height_key(floor)));
        }
        Ok(())
    }

    /// Test hook: the seal and receipt rows a block would own after sealing and a call, written
    /// by hand so the retention pass can be seen removing them without an aggregate fixture.
    #[cfg(test)]
    pub(crate) fn put_history_rows_for_test(
        &self,
        block_hash: &Hash,
        tx: &Hash,
        proof_hash: &Hash,
        cover: &Hash,
        receipt: &randprotocol_core::program::CallReceipt,
    ) -> Result<()> {
        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_SEALS), [b"b".as_slice(), block_hash.as_bytes()].concat(), bincode::serialize(&true)?);
        batch.put_cf(self.cf(CF_SEALS), [b"p".as_slice(), proof_hash.as_bytes()].concat(), bincode::serialize(tx)?);
        batch.put_cf(self.cf(CF_SEALS), [b"t".as_slice(), cover.as_bytes()].concat(), bincode::serialize(&(*tx, 1u64))?);
        batch.put_cf(self.cf(CF_SEALS), [b"a".as_slice(), tx.as_bytes()].concat(), bincode::serialize(&(0u64, 0u64, 0u64))?);
        batch.put_cf(self.cf(CF_RECEIPTS), tx.as_bytes(), bincode::serialize(receipt)?);
        batch.put_cf(self.cf(CF_RECEIPTS_BY_PROGRAM), receipt_index_key(&receipt.program, receipt.height, receipt.index), tx.as_bytes());
        self.db.write_opt(batch, &sync_opts())?;
        Ok(())
    }
```

The test for the 'a' row asserts via `aggregate_payment(&tx)`, which reads `'a' ‖ tx`; the hook writes that key for `tx`, and `stage_block_delete` deletes `'a' ‖ tx.hash()` only for an `Aggregate` action. The fixture's transaction is a bundle, not an aggregate, so add to `stage_block_delete`, after the aggregate branch, an unconditional `batch.delete_cf(self.cf(CF_SEALS), [b"a".as_slice(), tx.hash().as_bytes()].concat());` — a delete of an absent key is free and it keeps the pass total.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p randprotocol-node --lib storage::tests -- prune_history floor compact`
Expected: all six new tests PASS; `cargo test -p randprotocol-node --lib storage::tests` still green.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-node/src/storage.rs
git commit -m "storage: the history-retention pass — a floor in meta, per-block rows deleted below it, the ledger untouched"
```

---

### Task 2: Node — the flag, the guard rails, and the scheduled pass

**Files:**
- Modify: `crates/randprotocol-node/src/main.rs` (the `Run` args after `min_free_disk_mb`, ~line 361; the `Cmd::Run` destructure and `NodeConfig` literal, ~lines 662–679; a `parse_prune_history` fn with tests)
- Modify: `crates/randprotocol-node/src/node.rs` (`NodeConfig` ~line 78; `start` where `min_free_disk_bytes` is checked ~line 741; the post-commit handler ~line 1390; `Node` struct gains `prune_passes: u64`)
- Modify: `crates/randprotocol-node/tests/common/cluster.rs` (`start_in_at` gains a `prune_history` argument via a new `start_in_pruned`), `tests/cluster.rs:585` and every other `NodeConfig` literal gains `prune_history: None`

**Interfaces:**
- Consumes: `Storage::prune_history`, `PRUNE_PASS_MAX`, `compact_pruned_history` (Task 1).
- Produces: `NodeConfig.prune_history: Option<Duration>`; `pub fn parse_prune_history(s: &str) -> Result<Duration, String>` in `main.rs`; `pub const MIN_PRUNE_HISTORY: Duration = Duration::from_secs(3600)`; `tests/common/cluster.rs::start_in_pruned(dir, key, bootstrap, validator, block_interval, prune_history: Option<Duration>) -> TestNode`.

- [ ] **Step 1: Write the failing parser tests (main.rs)**

Add at the bottom of `main.rs`:

```rust
#[cfg(test)]
mod prune_flag_tests {
    use super::*;

    #[test]
    fn the_flag_takes_minutes_hours_and_days() {
        assert_eq!(parse_prune_history("24h").unwrap(), Duration::from_secs(24 * 3600));
        assert_eq!(parse_prune_history("2d").unwrap(), Duration::from_secs(2 * 86_400));
        assert_eq!(parse_prune_history("90m").unwrap(), Duration::from_secs(90 * 60));
    }

    #[test]
    fn the_flag_refuses_under_an_hour_and_bad_syntax() {
        assert_eq!(parse_prune_history("59m").unwrap_err(), "prune-history must be at least 1h");
        assert!(parse_prune_history("24").unwrap_err().contains("<n>m, <n>h or <n>d"));
        assert!(parse_prune_history("h").unwrap_err().contains("<n>m, <n>h or <n>d"));
        assert!(parse_prune_history("0h").unwrap_err().contains("at least 1h"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p randprotocol-node --bin rand-node prune_flag_tests`
Expected: FAIL to compile, `parse_prune_history` not found.

- [ ] **Step 3: Implement the flag and parser**

In the `Run` variant after `min_free_disk_mb`:

```rust
        /// Keep only this much block history (history pruning spec §1): `<n>m`, `<n>h` or
        /// `<n>d`, at least `1h`. Blocks whose timestamp is older than the head's minus this
        /// window lose their block, QC, transactions and receipts; the ledger stays. Never set
        /// on a mainnet node or on the testnet's archive.
        #[arg(long, value_parser = parse_prune_history)]
        prune_history: Option<Duration>,
```

At module level in `main.rs`:

```rust
/// The shortest history a node may keep: shorter than an hour and a node that restarts on the
/// hour has nothing for a peer to sync from.
pub const MIN_PRUNE_HISTORY: Duration = Duration::from_secs(3600);

/// `<n>m`, `<n>h` or `<n>d`.
pub fn parse_prune_history(s: &str) -> Result<Duration, String> {
    let usage = "prune-history takes <n>m, <n>h or <n>d";
    let (num, unit) = s.split_at(s.len().checked_sub(1).ok_or(usage)?);
    let n: u64 = num.parse().map_err(|_| usage.to_string())?;
    let secs = match unit {
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        "d" => n.checked_mul(86_400),
        _ => return Err(usage.to_string()),
    }
    .ok_or(usage)?;
    let d = Duration::from_secs(secs);
    if d < MIN_PRUNE_HISTORY {
        return Err("prune-history must be at least 1h".to_string());
    }
    Ok(d)
}
```

Add `prune_history` to the `Cmd::Run { … }` destructure and `prune_history,` to the `NodeConfig` literal.

In `node.rs` `NodeConfig`, after `min_free_disk_bytes`:

```rust
    /// Keep only this much block history (history pruning spec §1); `None` keeps everything.
    pub prune_history: Option<Duration>,
```

- [ ] **Step 4: Run the parser tests**

Run: `cargo test -p randprotocol-node --bin rand-node prune_flag_tests`
Expected: PASS. `cargo build -p randprotocol-node` will now fail on every `NodeConfig` literal missing the field: fix `tests/common/cluster.rs` (`prune_history: None` in `start_in_at`), `tests/cluster.rs:585`, and any other literal `grep -rn "min_free_disk_bytes:" crates/randprotocol-node` finds.

- [ ] **Step 5: Write the failing guard test (node.rs tests)**

In `node.rs`'s `mod tests`, next to the disk-guard test if one exists (grep `min_free_disk` in the tests module; otherwise beside `pick_sync_peer_prefers_fresh_and_falls_back_to_any_connected`):

```rust
    #[test]
    fn a_window_shorter_than_the_aggregation_window_refuses_to_start() {
        // 256-block window at 1 s blocks is 256 s; a 100 s history cannot hold it.
        let err = prune_window_check(Some(Duration::from_secs(100)), Some(256), Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("shorter than the aggregation window"), "{err}");
        assert!(prune_window_check(Some(Duration::from_secs(300)), Some(256), Duration::from_secs(1)).is_ok());
        assert!(prune_window_check(None, Some(256), Duration::from_secs(1)).is_ok());
        assert!(prune_window_check(Some(Duration::from_secs(10)), None, Duration::from_secs(1)).is_ok());
    }
```

- [ ] **Step 6: Implement the guard and the scheduled pass**

In `node.rs`, a free function near `check_and_repair_chain`:

```rust
/// The retention window must hold the aggregation window (history pruning spec §5): a cover's
/// aggregate is read within it, and pruning it would make sealed blocks unservable.
fn prune_window_check(prune_history: Option<Duration>, window: Option<u64>, block_interval: Duration) -> std::result::Result<(), String> {
    let (Some(keep), Some(window)) = (prune_history, window) else { return Ok(()) };
    let needed = block_interval.saturating_mul(u32::try_from(window).unwrap_or(u32::MAX));
    if keep < needed {
        return Err(format!(
            "prune-history {keep:?} is shorter than the aggregation window ({window} blocks at {block_interval:?} = {needed:?})"
        ));
    }
    Ok(())
}
```

In `start`, right after the `min_free_disk_bytes` guard (the `if disk_free_bytes < cfg.min_free_disk_bytes` block), where `gs` is already loaded:

```rust
    prune_window_check(cfg.prune_history, gs.ledger.aggregation().map(|a| a.window), cfg.block_interval)
        .map_err(|e| anyhow::anyhow!(e))?;
```

Add `prune_passes: u64,` to `struct Node` and `prune_passes: 0,` where the struct is built (grep `fetch_attempts:` in the constructor and add beside it).

In the post-commit handler, directly after the proof-pruning block (after its closing `}` and before `self.mempool.prune(self.hs.tip_ledger());`):

```rust
        // The history-retention pass (history pruning spec §1): every 16 blocks, the blocks
        // older than the window measured on the chain's own clock lose their history. Never
        // inside the aggregation window, never the head or its parent, never genesis.
        if let Some(keep) = self.cfg.prune_history {
            if head % 16 == 0 {
                let head_ms = self.storage.head_block()?.header.timestamp_ms;
                let cutoff_ms = head_ms.saturating_sub(keep.as_millis() as u64);
                let window = self.hs.committed_ledger().aggregation().map(|a| a.window).unwrap_or(0);
                let keep_from = head.saturating_sub(window.max(2));
                let storage = self.storage.clone();
                let pruned = tokio::task::spawn_blocking(move || storage.prune_history(cutoff_ms, keep_from, crate::storage::PRUNE_PASS_MAX))
                    .await
                    .map_err(|e| anyhow::anyhow!("history pruning task: {e}"))??;
                if pruned > 0 {
                    self.prune_passes += 1;
                    tracing::info!("pruned {pruned} blocks below height {} at head {head}", self.storage.prune_floor()?);
                    if self.prune_passes % 64 == 0 {
                        let storage = self.storage.clone();
                        tokio::task::spawn_blocking(move || storage.compact_pruned_history())
                            .await
                            .map_err(|e| anyhow::anyhow!("history compaction task: {e}"))??;
                    }
                }
            }
        }
```

In `tests/common/cluster.rs`:

```rust
pub async fn start_in_pruned(
    dir: tempfile::TempDir,
    key: &Keypair,
    bootstrap: Vec<libp2p::Multiaddr>,
    validator: bool,
    block_interval: Duration,
    prune_history: Option<Duration>,
) -> TestNode {
    // identical to start_in_at except `prune_history,` in the NodeConfig literal
}
```

Refactor `start_in_at` to call `start_in_pruned(dir, key, bootstrap, validator, block_interval, None)` so the literal exists once.

- [ ] **Step 7: Run the tests**

Run: `cargo test -p randprotocol-node --lib a_window_shorter && cargo test -p randprotocol-node --bin rand-node prune_flag_tests && cargo build -p randprotocol-node --tests`
Expected: PASS, PASS, builds.

- [ ] **Step 8: Commit**

```bash
git add crates/randprotocol-node/src/main.rs crates/randprotocol-node/src/node.rs crates/randprotocol-node/tests/common/cluster.rs crates/randprotocol-node/tests/cluster.rs
git commit -m "node: --prune-history — the window flag, its guard rails, and the retention pass beside proof pruning"
```

---

### Task 3: Sync — the floor in `Status`, the peer picker, and `rand_status`

**Files:**
- Modify: `crates/randprotocol-node/src/network/wire.rs` (`Status`)
- Modify: `crates/randprotocol-node/src/node.rs` (`broadcast_status` ~line 1270; `pick_sync_peer` ~line 419; `sync_from`'s final warn ~line 1850; `publish_status` ~line 1044; the `pick_sync_peer_prefers_fresh…` test's `Status` literals)
- Modify: `crates/randprotocol-node/src/rpc.rs` (`NodeStatus` ~line 85 gains two fields; grep every `NodeStatus {` literal and add them)

**Interfaces:**
- Consumes: `Storage::prune_floor` (Task 1), `NodeConfig.prune_history` (Task 2).
- Produces: `Status.floor: u64`; `NodeStatus.prune_floor: u64`, `NodeStatus.prune_history_secs: Option<u64>`.

- [ ] **Step 1: Write the failing tests**

In `wire.rs` (a new `#[cfg(test)] mod tests` at the bottom if none exists):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The roll caveat, pinned (history pruning spec §2): a v0.5.4 `Status` has three fields.
    #[derive(Serialize, Deserialize)]
    struct OldStatus {
        height: u64,
        head_hash: Hash,
        view: u64,
    }

    #[test]
    fn a_new_node_cannot_decode_an_old_status_and_an_old_node_reads_the_new_ones_prefix() {
        let old = bincode::serialize(&GossipMessage::Status(Status { height: 7, head_hash: Hash::ZERO, view: 9, floor: 0 })).unwrap();
        // Old shape from a new payload: bincode reads the prefix and ignores the tail.
        let as_old: (u32, OldStatus) = bincode::deserialize(&old).unwrap();
        assert_eq!(as_old.1.height, 7);
        // New shape from an old payload: four bytes short — refused, never misread.
        let short = bincode::serialize(&OldStatus { height: 7, head_hash: Hash::ZERO, view: 9 }).unwrap();
        let mut framed = bincode::serialize(&2u32).unwrap();
        framed.extend_from_slice(&short);
        assert!(bincode::deserialize::<GossipMessage>(&framed).is_err());
    }
}
```

`GossipMessage::Status` is the third variant, so its bincode tag is `2u32`; the `(u32, OldStatus)` tuple decode above relies on the same layout. If the assertion on the tag fails, print `&old[..4]` and use that value.

In `node.rs` tests, extend the picker test with a new test:

```rust
    #[test]
    fn pick_sync_peer_never_picks_a_peer_that_pruned_our_next_height() {
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let p = |seed: u8, height: u64, floor: u64| {
            (pid(seed), Peer { status: Some(Status { height, head_hash: Hash::ZERO, view: height, floor }), connected: true, tx_bucket: Default::default() })
        };
        // We are at 43 and need 44. Peer 1 is far ahead but pruned everything below 100;
        // peer 2 is lower but still holds 44.
        let peers: HashMap<PeerId, Peer> = [p(1, 500, 100), p(2, 120, 0)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 500, &[]), Some(pid(2)));
        // A floor exactly at our next height is fine.
        let peers: HashMap<PeerId, Peer> = [p(1, 500, 44)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 500, &[]), Some(pid(1)));
        // Every candidate pruned it: no pick, even though the chain is ahead.
        let peers: HashMap<PeerId, Peer> = [p(1, 500, 100), p(2, 300, 60)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 500, &[]), None);
    }
```

Update the existing picker test's `Status { height, head_hash: Hash::ZERO, view: height }` literals to add `floor: 0`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p randprotocol-node --lib wire::tests pick_sync_peer`
Expected: compile error, no field `floor`.

- [ ] **Step 3: Implement**

`wire.rs`:

```rust
pub struct Status {
    pub height: u64,
    pub head_hash: Hash,
    pub view: u64,
    /// The lowest height this node still serves, other than genesis (history pruning spec §2);
    /// 0 on an archive. Appended last so an older node reads the fields it knows.
    pub floor: u64,
}
```

`node.rs` `broadcast_status`:

```rust
            .broadcast(GossipMessage::Status(Status {
                height: self.hs.committed_height(),
                head_hash: self.hs.committed_hash(),
                view: self.hs.view(),
                floor: self.storage.prune_floor().unwrap_or(0),
            }))
```

`pick_sync_peer`: a peer serves us only if its floor is at or below the height we ask for:

```rust
fn pick_sync_peer(peers: &HashMap<PeerId, Peer>, my_height: u64, best_peer_height: u64, skipped: &[PeerId]) -> Option<PeerId> {
    let serves = |s: &Status| s.floor <= my_height.saturating_add(1);
    let best = peers
        .iter()
        .filter(|(p, peer)| peer.connected && !skipped.contains(p))
        .filter_map(|(p, peer)| peer.status.as_ref().filter(|s| serves(s)).map(|s| (*p, s.height)))
        .filter(|(_, h)| *h > my_height)
        .max_by_key(|(_, h)| *h)
        .map(|(p, _)| p);
    best.or_else(|| {
        if best_peer_height > my_height + 1 {
            peers
                .iter()
                .filter(|(p, peer)| peer.connected && !skipped.contains(p))
                .find(|(_, peer)| peer.status.as_ref().map_or(true, serves))
                .map(|(p, _)| *p)
        } else {
            None
        }
    })
}
```

In `sync_from`'s final `tracing::warn!` (the "sync wanted but every candidate refused" one), add a field `floors = ?self.peers.values().filter_map(|p| p.status.as_ref().map(|s| s.floor)).collect::<Vec<_>>()` and change the message to `"sync wanted but no candidate can serve our next height (a peer that pruned it, or none connected) — a node behind every peer's retention must sync from the archive"`.

`rpc.rs` `NodeStatus`, after `disk_low`:

```rust
    /// The lowest height this node still serves besides genesis (history pruning spec §4); 0
    /// on an archive.
    pub prune_floor: u64,
    /// The configured retention window in seconds, `null` when this node keeps everything.
    pub prune_history_secs: Option<u64>,
```

`publish_status`: `s.prune_floor = self.storage.prune_floor().unwrap_or(0); s.prune_history_secs = self.cfg.prune_history.map(|d| d.as_secs());`. Where `NodeStatus` is first built in `start` (grep `NodeStatus {`), add `prune_floor: 0, prune_history_secs: cfg.prune_history.map(|d| d.as_secs()),`. Fix every other `NodeStatus {` literal (rpc tests' `state_over`) with `prune_floor: 0, prune_history_secs: None`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p randprotocol-node --lib wire::tests pick_sync_peer publish && cargo test -p randprotocol-node --lib rpc::tests::a_client_over_its_allowance`
Expected: PASS; the whole `--lib` suite still green.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-node/src/network/wire.rs crates/randprotocol-node/src/node.rs crates/randprotocol-node/src/rpc.rs
git commit -m "node: a peer advertises its retention floor; sync never asks for a height a peer pruned; rand_status carries the floor"
```

---

### Task 4: Startup verification on a pruned node

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs` (`ChainCheck` ~line 1861 gains `floor`; `verify_chain` ~line 1885 gains the structural path)
- Modify: `crates/randprotocol-node/src/node.rs` (`check_and_repair_chain` ~line 218)
- Modify: `crates/randprotocol-node/src/main.rs` (`Cmd::Verify`, ~line 644)

**Interfaces:**
- Consumes: `Storage::prune_floor`, `PRUNE_PASS_MAX`, the `timed_chain` fixture (Task 1).
- Produces: `ChainCheck.floor: u64`; `verify_chain` on a floor > 0 store returns `last_good == head` and `ledger == load_ledger()` when structure holds, and `problem = Some(…)` with `last_good < floor` never used for truncation.

- [ ] **Step 1: Write the failing tests (storage.rs tests)**

```rust
    #[test]
    fn a_pruned_store_verifies_structurally_and_reports_its_floor() {
        let (_dir, st, gs, _blocks) = timed_chain(12);
        assert_eq!(st.prune_history(u64::MAX, 10, PRUNE_PASS_MAX).unwrap(), 9);
        for mode in [VerifyMode::Quick, VerifyMode::Full] {
            let check = st.verify_chain(&gs, mode, &StubExecutor).unwrap();
            assert_eq!(check.problem, None, "{mode:?}");
            assert_eq!(check.floor, 10);
            assert_eq!(check.last_good, 12);
            assert_eq!(check.ledger, st.load_ledger(&StubExecutor).unwrap());
        }
        // Off still needs genesis and the snapshot, nothing else.
        let check = st.verify_chain(&gs, VerifyMode::Off, &StubExecutor).unwrap();
        assert_eq!(check.problem, None);
    }

    #[test]
    fn a_gap_above_the_floor_is_reported_at_its_height() {
        let (_dir, st, gs, _blocks) = timed_chain(12);
        st.prune_history(u64::MAX, 10, PRUNE_PASS_MAX).unwrap();
        st.db.delete_cf(st.cf(CF_QCS), height_key(11)).unwrap();
        let check = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert_eq!(check.problem.as_deref(), Some("qc 11 missing"));
        assert_eq!(check.last_good, 10);
        assert_eq!(check.floor, 10);
    }

    #[test]
    fn a_pruned_store_missing_its_floor_block_is_reported_below_the_floor() {
        let (_dir, st, gs, _blocks) = timed_chain(12);
        st.prune_history(u64::MAX, 10, PRUNE_PASS_MAX).unwrap();
        st.db.delete_cf(st.cf(CF_BLOCKS), height_key(10)).unwrap();
        let check = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert_eq!(check.problem.as_deref(), Some("block 10 missing"));
        assert!(check.last_good < check.floor);
    }

    #[test]
    fn an_archive_still_replays_from_genesis() {
        let (_dir, st, gs, _blocks) = timed_chain(4);
        let check = st.verify_chain(&gs, VerifyMode::Full, &StubExecutor).unwrap();
        assert_eq!(check.problem, None);
        assert_eq!(check.floor, 0);
    }
```

In `node.rs` tests:

```rust
    #[test]
    fn a_pruned_store_missing_its_floor_block_is_fatal_not_truncated() {
        let (_dir, st, gs, _blocks) = crate::storage::fixtures::timed_chain(12);
        st.prune_history(u64::MAX, 10, crate::storage::PRUNE_PASS_MAX).unwrap();
        st.db_for_test().delete_cf(st.cf_for_test("blocks"), crate::storage::height_key_for_test(10)).unwrap();
        let err = check_and_repair_chain(&st, &gs, VerifyMode::Quick, &StubExecutor).unwrap_err().to_string();
        assert!(err.contains("re-sync from the archive"), "{err}");
        assert_eq!(st.head().unwrap().height, 12, "nothing was truncated");
    }
```

Add to the `fixtures` module an `impl Storage` block with three hooks the node test uses: `pub(crate) fn db_for_test(&self) -> &DB { &self.db }`, `pub(crate) fn cf_for_test(&self, name: &str) -> &rocksdb::ColumnFamily { self.cf(name) }`, and a free `pub(crate) fn height_key_for_test(h: u64) -> [u8; 8] { height_key(h) }`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p randprotocol-node --lib pruned_store floor_block an_archive_still`
Expected: compile error, no field `floor` on `ChainCheck`.

- [ ] **Step 3: Implement**

`ChainCheck` gains:

```rust
    /// The store's retention floor (history pruning spec §3): 0 on an archive. Above 0 the
    /// check was structural from this height and `ledger` is the trusted snapshot.
    pub floor: u64,
```

Set `floor: 0` in the existing `ChainCheck { … }` literal and immediately after it:

```rust
        let floor = self.prune_floor()?;
        check.floor = floor;
```

After the `VerifyMode::Off` early return, insert the structural path:

```rust
        if floor > 0 {
            return self.verify_pruned(gs, mode, executor, check, floor, head);
        }
```

and add the method:

```rust
    /// Structural verification from the floor (history pruning spec §3): every retained block
    /// exists with its index, QC and leader, and the QC verifies in `Full`; the epoch sets are
    /// the stored rows (there is no replay to derive them from) and the ledger is the snapshot.
    fn verify_pruned(
        &self,
        gs: &GenesisState,
        mode: VerifyMode,
        executor: &dyn ConfidentialExecutor,
        mut check: ChainCheck,
        floor: u64,
        head: u64,
    ) -> Result<ChainCheck> {
        let epoch_blocks = gs.epoch_blocks.max(1);
        let mut prev_hash: Option<Hash> = None;
        for h in floor..=head {
            let problem = (|| -> std::result::Result<(), String> {
                let epoch = h / epoch_blocks;
                let set = match self.epoch_set(epoch) {
                    Ok(Some(s)) => s,
                    Ok(None) => return Err(format!("no stored validator set for epoch {epoch}")),
                    Err(e) => return Err(format!("epoch {epoch} set unreadable: {e}")),
                };
                let block = self
                    .block_by_height(h)
                    .map_err(|e| format!("block {h} unreadable: {e}"))?
                    .ok_or_else(|| format!("block {h} missing"))?;
                if block.height() != h {
                    return Err(format!("block at height {h} claims height {}", block.height()));
                }
                if let Some(prev) = prev_hash {
                    if block.parent() != prev {
                        return Err(format!("block {h} parent {} != previous hash {}", block.parent(), prev));
                    }
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
                if mode == VerifyMode::Full && !qc.verify(&gs.signing_domain(), &set) {
                    return Err(format!("qc {h} has invalid or insufficient votes for epoch {epoch}"));
                }
                prev_hash = Some(hash);
                Ok(())
            })();
            if let Err(p) = problem {
                check.problem = Some(p);
                check.last_good = h.saturating_sub(1);
                check.ledger = self.load_ledger(executor)?;
                return Ok(check);
            }
        }
        check.last_good = head;
        check.ledger = self.load_ledger(executor)?;
        Ok(check)
    }
```

`gs.signing_domain()` and `qc.verify(&domain, &set)` are what the replay path already calls; copy their exact spelling from the existing loop.

`check_and_repair_chain` in `node.rs`: after `let check = …;` and before the `match`:

```rust
    if check.floor > 0 {
        return match &check.problem {
            None => {
                tracing::info!(
                    "pruned node: history verified from {} to {} ({:?}, {:.1?}); ledger snapshot trusted",
                    check.floor, check.head, mode, t.elapsed()
                );
                Ok(check.head)
            }
            Some(problem) => anyhow::bail!(
                "pruned node: {problem}; history cannot be repaired locally — re-sync from the archive"
            ),
        };
    }
```

`main.rs` `Cmd::Verify`: in the `Some(p)` arm, before `if repair`, add:

```rust
                    if check.floor > 0 {
                        println!("pruned node (floor {}): history cannot be repaired locally — re-sync from the archive", check.floor);
                        std::process::exit(2);
                    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p randprotocol-node --lib pruned_store floor_block an_archive_still a_gap_above && cargo test -p randprotocol-node --lib storage::tests`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-node/src/storage.rs crates/randprotocol-node/src/node.rs crates/randprotocol-node/src/main.rs
git commit -m "storage, node: a pruned store verifies structurally from its floor and trusts the snapshot; a failure there is fatal, never a truncation"
```

---

### Task 5: RPC — error `-32010` for pruned heights

**Files:**
- Modify: `crates/randprotocol-node/src/rpc.rs` (`RpcError` ~line 392 gains `data`; `error_json` ~line 596; handlers `rand_getBlockByHeight` ~1938, `rand_getBlockByHash` ~1944, `rand_getBlocks` ~1952, `rand_getCompactBlocks` ~1532, `rand_getTransaction` ~1865, `rand_checkTransaction` ~1890, `rand_getReceipt` ~1748, `rand_getCallEnvelope` ~1777, `rand_getAggregate` ~1976, `rand_getRawTransaction` ~2022, `rand_getFinality` ~2284, `rand_getTransactionStatus` ~2238; tests)
- Modify: `docs/rpc.md` (a dated entry and the per-method notes)

**Interfaces:**
- Consumes: `Storage::prune_floor`, `fixtures::timed_chain`, `PRUNE_PASS_MAX`, rpc test helpers `state_over`, `call`, `ok`.
- Produces: `RpcError { code, message, data: Option<Value> }`; `RpcError::pruned(h: u64, floor: u64) -> RpcError`; `fn floor_of(st: &RpcState) -> Result<u64, RpcError>`.

- [ ] **Step 1: Write the failing tests (rpc.rs tests)**

```rust
    /// Twelve timed blocks, pruned to a floor of 10, behind the RPC.
    fn pruned_state() -> (tempfile::TempDir, RpcState, GenesisState, Vec<randprotocol_core::consensus::CommittedBlock>) {
        let (dir, st, gs, blocks) = crate::storage::fixtures::timed_chain(12);
        assert_eq!(st.prune_history(u64::MAX, 10, crate::storage::PRUNE_PASS_MAX).unwrap(), 9);
        let st = Arc::new(st);
        let state = state_over(st, &gs);
        (dir, state, gs, blocks)
    }

    #[tokio::test]
    async fn a_pruned_height_answers_32010_with_the_floor_and_an_unknown_height_above_it_does_not() {
        let (_dir, st, _gs, blocks) = pruned_state();
        let e = call(&st, "rand_getBlockByHeight", json!([3])).await.unwrap_err();
        assert_eq!(e.code, -32010);
        assert_eq!(e.message, "pruned: height 3 is below this node's retention floor 10");
        assert_eq!(e.data, Some(json!({ "floor": 10 })));
        assert_eq!(ok(&st, "rand_getBlockByHeight", json!([99])).await, Value::Null);
        assert!(ok(&st, "rand_getBlockByHeight", json!([11])).await.is_object());
        // Ranges starting below the floor are refused rather than served empty.
        assert_eq!(call(&st, "rand_getBlocks", json!([3, 11])).await.unwrap_err().code, -32010);
        assert_eq!(call(&st, "rand_getCompactBlocks", json!([3, 11])).await.unwrap_err().code, -32010);
        assert_eq!(ok(&st, "rand_getBlocks", json!([10, 12])).await.as_array().unwrap().len(), 3);
        // Finality by height, and by a pruned hash (null + floor).
        assert_eq!(call(&st, "rand_getFinality", json!([3])).await.unwrap_err().code, -32010);
        let pruned_hash = blocks[2].block.hash().to_hex();
        let e = call(&st, "rand_getBlockByHash", json!([pruned_hash])).await;
        assert_eq!(e.unwrap(), Value::Null);
        // Genesis is never pruned.
        assert!(ok(&st, "rand_getBlockByHeight", json!([0])).await.is_object());
    }

    #[tokio::test]
    async fn a_transaction_whose_block_is_pruned_answers_32010_not_block_missing() {
        let (_dir, st, _gs, blocks) = pruned_state();
        let tx = blocks[2].block.transactions[0].hash();
        // Re-insert the location row by hand: the shape of a row the pass could not resolve.
        st.storage.put_tx_location_for_test(&tx, 3, 0).unwrap();
        let e = call(&st, "rand_getTransaction", json!([tx.to_hex()])).await.unwrap_err();
        assert_eq!(e.code, -32010);
        assert_eq!(e.data, Some(json!({ "floor": 10 })));
        let e = call(&st, "rand_checkTransaction", json!([tx.to_hex(), hex::encode([1u8; 32])])).await.unwrap_err();
        assert_eq!(e.code, -32010);
        // A hash with no row at all keeps today's null, and status keeps `unknown` with the floor.
        assert_eq!(ok(&st, "rand_getTransaction", json!([Hash::ZERO.to_hex()])).await, Value::Null);
        let v = ok(&st, "rand_getTransactionStatus", json!([[Hash::ZERO.to_hex()]])).await;
        assert_eq!(v[0]["status"], "unknown");
        assert_eq!(v[0]["floor"], 10);
    }

    #[tokio::test]
    async fn rand_status_reports_the_floor_and_the_window() {
        let (_dir, st, _gs, _blocks) = pruned_state();
        let v = ok(&st, "rand_status", json!([])).await;
        assert_eq!(v["prune_floor"], 0, "the status struct is filled by the node loop, absent here");
        assert!(v.get("prune_history_secs").is_some());
    }
```

`state_over` spawns a task, so the tests stay `#[tokio::test]`. Add to `storage.rs`'s `fixtures` module (inside its `impl Storage` block):

```rust
    #[cfg(test)]
    pub(crate) fn put_tx_location_for_test(&self, tx: &Hash, height: u64, index: u32) -> Result<()> {
        let record = TxRecord::Raw { height, index, tx: self.block_by_height(self.head()?.height)?.unwrap().transactions[0].clone() };
        self.db.put_cf_opt(self.cf(CF_TXS), tx.as_bytes(), bincode::serialize(&record)?, &sync_opts())?;
        Ok(())
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p randprotocol-node --lib rpc::tests::a_pruned_height rpc::tests::a_transaction_whose rpc::tests::rand_status_reports`
Expected: compile errors (`data` field, `put_tx_location_for_test`).

- [ ] **Step 3: Implement**

`RpcError`:

```rust
struct RpcError {
    code: i64,
    message: String,
    /// JSON-RPC `error.data`; today only the pruned error carries one (history pruning spec §4).
    data: Option<Value>,
}
```

Every existing constructor gains `data: None`. Add:

```rust
    /// Code `-32010`: the height is below this node's retention floor (history pruning spec §4).
    fn pruned(h: u64, floor: u64) -> RpcError {
        RpcError {
            code: -32010,
            message: format!("pruned: height {h} is below this node's retention floor {floor}"),
            data: Some(json!({ "floor": floor })),
        }
    }
```

`error_json` (line ~596): build the error object, then `if let Some(d) = &e.data { err["data"] = d.clone(); }`. Every `RpcError { code: …, message: … }` literal elsewhere (the `-32601` one at ~2421, tests) gains `data: None`; `grep -n "RpcError {" src/rpc.rs`.

A helper beside `blocking`:

```rust
/// The store's retention floor, for the pruned answer (history pruning spec §4).
fn floor_of(st: &RpcState) -> Result<u64, RpcError> {
    st.storage.prune_floor().map_err(RpcError::internal)
}

/// `Err(pruned)` when `h` is below the floor and not genesis.
fn refuse_pruned(st: &RpcState, h: u64) -> Result<(), RpcError> {
    let floor = floor_of(st)?;
    if h != 0 && h < floor {
        return Err(RpcError::pruned(h, floor));
    }
    Ok(())
}
```

Handlers:

- `rand_getBlockByHeight`: first line after parsing `h`: `refuse_pruned(st, h)?;`.
- `rand_getBlocks` and `rand_getCompactBlocks`: after the `to < from` check: `refuse_pruned(st, from)?;`.
- `rand_getFinality` height branch: `refuse_pruned(st, h)?;` before the storage read.
- `rand_getTransaction` and `rand_checkTransaction`: in the `Some((height, index))` arm, replace `.ok_or_else(|| RpcError::not_found("block missing"))?` with

  ```rust
  .ok_or_else(|| match floor_of(st) {
      Ok(floor) if height < floor => RpcError::pruned(height, floor),
      _ => RpcError::not_found("block missing"),
  })?
  ```

  (`floor_of` inside a closure returns `Result`; match on it as shown.)
- `rand_getReceipt`, `rand_getCallEnvelope`, `rand_getAggregate`, `rand_getRawTransaction`, `rand_getBlockByHash`: when the storage read is `None`, keep `Value::Null` — the spec keeps null for hash-addressed lookups; no change to the value. (The `data.floor` on a null result has nowhere to go in JSON-RPC's success shape; the spec's "add `data.floor`" for these applies to `rand_getTransactionStatus` only, which returns an object per hash.)
- `rand_getTransactionStatus`: compute `let floor = floor_of(st)?;` once; in the `PoolStatus::Unknown` arm, if `floor > 0` emit `json!({ "hash": h, "status": "unknown", "floor": floor })`, else today's object.

`docs/rpc.md`: add under the existing method notes for `rand_getBlockByHeight`, `rand_getBlocks`, `rand_getCompactBlocks`, `rand_getFinality`, `rand_getTransaction`, `rand_checkTransaction`:

```
On a node started with `--prune-history`, a height below `rand_status.prune_floor` (genesis
excepted) answers error `-32010` `pruned: height h is below this node's retention floor f`
with `data: {"floor": f}` — ask the archive for it.
```

and a dated section at the end:

```
### 2026-09-24 — history pruning: `--prune-history`, `rand_status.prune_floor`, error `-32010`

A node started with `--prune-history 24h` keeps the ledger and only the last day of blocks.
`rand_status` carries `prune_floor` (0 on an archive) and `prune_history_secs` (`null` when the
node keeps everything). Height-addressed lookups below the floor answer `-32010` with the floor
in `data`; hash-addressed lookups still answer `null` for a hash the node does not hold, and only
an archive can say whether it was pruned or never existed. `rand_getTransactionStatus` adds
`floor` to an `unknown` entry on a pruned node. Wallet scanning (`rand_getCommitments`,
`rand_getNullifiers`, `rand_getWitness`) is unaffected: the notes and nullifiers families are
never pruned.
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p randprotocol-node --lib rpc::tests`
Expected: the three new tests PASS and the suite stays green (the existing `rand_getBlocks`/`getCompactBlocks` tests start at 0 or 1 on unpruned stores and are unaffected).

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-node/src/rpc.rs crates/randprotocol-node/src/storage.rs docs/rpc.md
git commit -m "rpc: a height below the retention floor answers -32010 with the floor; rand_status and getTransactionStatus name it"
```

---

### Task 6: Cluster test — a pruned validator keeps committing, a late joiner syncs from the archives

**Files:**
- Modify: `crates/randprotocol-node/tests/cluster.rs` (new test after `four_validators_plus_late_observer_syncs`)

**Interfaces:**
- Consumes: `start_in_pruned` (Task 2), `wait_height`, `start_node`, `bootstrap_addr`, `keys`, `genesis`, `init_tracing` from `tests/common`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pruned_validator_keeps_committing_and_a_late_joiner_syncs_from_the_archives() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks[..3]);
    // n0 and n1 keep everything; n2 keeps two seconds of blocks (FAST is 150 ms a block).
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let dir2 = tempfile::tempdir().unwrap();
    std::fs::write(dir2.path().join("genesis.json"), gen.to_json()).unwrap();
    let n2 = start_in_pruned(dir2, &ks[2], boot.clone(), true, FAST, Some(Duration::from_secs(2))).await;
    wait_height(&[&n0, &n1, &n2], 80, Duration::from_secs(90)).await;

    // The pruned node's floor rose and block 1 is gone there, while the archives hold it.
    let floor = n2.handle.storage.prune_floor().unwrap();
    assert!(floor > 1, "floor {floor} never rose");
    assert!(n2.handle.storage.block_by_height(1).unwrap().is_none());
    assert!(n0.handle.storage.block_by_height(1).unwrap().is_some());
    assert!(n2.handle.storage.block_by_height(0).unwrap().is_some(), "genesis stays");
    // Its status advertises the floor.
    let s = n2.rpc.call("rand_status", serde_json::json!([])).await.unwrap();
    assert_eq!(s["prune_floor"].as_u64().unwrap(), floor);
    assert_eq!(s["prune_history_secs"].as_u64().unwrap(), 2);
    // And it still takes part: the chain keeps moving with it as a validator.
    wait_height(&[&n2], n2.height() + 10, Duration::from_secs(30)).await;

    // A late observer joins through the pruned node's address only, and still ends up with
    // the whole chain: the picker must route it to an archive for the heights n2 pruned.
    let obs = start_node(&ks[3], &gen, vec![bootstrap_addr(&n2)], false).await;
    let target = n0.height();
    wait_height(&[&obs], target, Duration::from_secs(90)).await;
    assert!(obs.handle.storage.block_by_height(1).unwrap().is_some(), "the observer got block 1 from an archive");
    for h in [1, floor, target] {
        assert_eq!(
            obs.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            n0.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            "height {h}"
        );
    }
    // A pruned node restarts and verifies structurally.
    let dir2 = stop(n2).await;
    let n2 = start_in_pruned(dir2, &ks[2], boot, true, FAST, Some(Duration::from_secs(2))).await;
    wait_height(&[&n2], target, Duration::from_secs(60)).await;
    assert!(n2.handle.storage.prune_floor().unwrap() >= floor);
}
```

`FAST` is the block interval constant in `tests/common/cluster.rs`; import it as the other tests import their helpers. mDNS is off in the harness, so the observer discovers n0 and n1 only through n2's peer exchange; if the harness has no peer exchange and the observer never learns of n0/n1, give the observer both `bootstrap_addr(&n2)` and `bootstrap_addr(&n0)` — the assertion that it holds block 1 still proves the picker skipped n2 for that height, since n2 cannot serve it.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p randprotocol-node --test cluster a_pruned_validator -- --nocapture`
Expected: before Tasks 2–5 land this would not compile; after them it must PASS on the first run — if it fails on the observer's block 1, read the observer's log for the "no candidate can serve" warning and check `pick_sync_peer`'s fallback branch.

- [ ] **Step 3: Run the whole cluster suite**

Run: `cargo test -p randprotocol-node --test cluster`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/randprotocol-node/tests/cluster.rs
git commit -m "tests: a pruned validator keeps committing, advertises its floor, and a late joiner syncs the pruned heights from the archives"
```

---

### Task 7: Docs, deploy templates, changelog, version

**Files:**
- Modify: `docs/deploy.md` (the unit template near line 19 and the archive note near line 214)
- Modify: `deploy/cutover-droplet-chain14.sh:98-109` (a `PRUNE_ARGS` variable appended to `ExecStart`), `deploy/update-droplet.sh` (an optional unit edit), `deploy/run-a.sh:16`, `deploy/nodes.env` (an `ARCHIVE=` line)
- Modify: `CHANGELOG.md`, `Cargo.toml` (workspace version), `crates/randprotocol-node/src/main.rs` (the version pin, see commit `d0778d8` for the two places)
- Modify: `AGENTS.md` (a short project-memory entry)

- [ ] **Step 1: `docs/deploy.md`**

Under the observer sentence at line 19 add:

```
- **History pruning (testnet only).** `--prune-history 24h` keeps the ledger and one day of
  blocks; the rest is deleted every 16 blocks (`docs/superpowers/specs/2026-09-24-history-pruning-design.md`).
  Exactly one node keeps everything — the archive, `ARCHIVE` in `deploy/nodes.env` (obs1 on
  randbridge-web, data dir on a volume) — and a node that falls more than a day behind must sync
  from it. **Mainnet units never pass the flag.** A pruned node that fails its startup check does
  not repair itself: re-sync it from the archive.
```

- [ ] **Step 2: Deploy scripts**

`deploy/cutover-droplet-chain14.sh`: add `PRUNE_ARGS=${PRUNE_ARGS:-}` beside the other variables and append `$PRUNE_ARGS` at the end of the `ExecStart=` line. `deploy/update-droplet.sh`: after `install -m 755 …`, add

```bash
  if [ -n \"${PRUNE_ARGS:-}\" ] && ! grep -q -- '--prune-history' /etc/systemd/system/$SERVICE.service; then
    sed -i \"s|^ExecStart=\\(.*\\)\$|ExecStart=\\1 ${PRUNE_ARGS}|\" /etc/systemd/system/$SERVICE.service
    systemctl daemon-reload
  fi
```

(inside the existing `$SSH "set -e … "` string, so the escaping matches its neighbours). `deploy/run-a.sh:16`: append `${PRUNE_ARGS:-}` to the `exec` line. `deploy/nodes.env`: `ARCHIVE=/ip4/168.144.46.203/tcp/30303/p2p/12D3KooWS5usdMPvsbaWSaT2xtKndHvDYurwmueoNvaRRarb2wRf   # obs1, keeps every block`.

- [ ] **Step 3: Changelog, version, memory**

`CHANGELOG.md`: a `## 0.5.5` entry in the file's style: the flag, the floor in `Status` (wire-coordinated: roll in one pass), `rand_status` fields, error `-32010`, structural verify, the archive rule. `Cargo.toml` workspace `version = "0.5.5"` and the pin in `main.rs` (`git show d0778d8` shows the two lines). `AGENTS.md`: under "Project memory", a 6-line entry: what pruning keeps, the archive, the roll caveat, mainnet never passes the flag.

- [ ] **Step 4: Build and test everything**

Run: `cargo build --release -p randprotocol-node && cargo test -p randprotocol-node && cargo clippy -p randprotocol-node --all-targets -- -D warnings`
Expected: build ok, all tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add docs/deploy.md deploy/cutover-droplet-chain14.sh deploy/update-droplet.sh deploy/run-a.sh deploy/nodes.env CHANGELOG.md Cargo.toml Cargo.lock crates/randprotocol-node/src/main.rs AGENTS.md
git commit -m "docs, deploy: history pruning — the flag in the unit templates, obs1 as the archive, the roll caveat; version 0.5.5"
```

---

## Rollout (operator-run; not an implementer task)

Follows the spec's §7 and the release rule in `docs/deploy.md`.

1. Merge `feat/history-pruning` to `main` after review; CI green; `cargo test --workspace --release` on the release machine; tag `v0.5.5`.
2. Archive first: on the randbridge-web droplet, create and attach a 500 GB volume in sgp1, `systemctl stop rand-node`, move `/root/data-obs1-1cff3b7d` onto the volume, symlink or edit the unit's `--datadir`, start, confirm `rand_status.prune_floor == 0` and the head follows the fleet.
3. Wait for the chain to commit again.
4. Build on E (`deploy/rebuild-vps.sh 188.166.235.187` from the tagged commit). Then, one droplet at a time, `PRUNE_ARGS="--prune-history 24h" deploy/update-droplet.sh <ip>`; wait for `rand_status.height` to reach the head and one more block before the next.
5. Node A: `BINDIR=bin-<tag> PRUNE_ARGS="--prune-history 24h"` in `run-a.sh`'s environment, then `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a`.
6. Verify: every validator's `prune_floor` about a day behind the head within an hour, `du -ch db/*.sst` under 15 GB after compaction and flat, obs1 answering `rand_getBlockByHeight(1000)` while a validator answers `-32010`, a fresh observer synced from obs1 reaching the head.
