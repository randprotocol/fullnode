# History pruning: a node keeps one day of blocks

Date: 2026-09-24. Status: approved design, awaiting the implementation plan.

## Why

Every chain-14 validator writes about 110 KB per block: an 18-signature Dilithium2 quorum
certificate (18 × 2 420 B), stored once in the block's `justify` and once in the `qcs` row, on
blocks that are almost always empty. At the fleet's measured 1.4 s per block that is ~6.6 GB of
SST per day per node. On 2026-09-24 the twelve 48 GB droplets were at 93–100 %, five of them
crash-looping on ENOSPC, and the chain lost its 13-of-18 quorum at height 248 953 (the
write-ahead-log half of that incident is fixed by `d187df4`, which the fleet now runs as v0.5.4).

The operator's decision: **on this testnet every full node keeps the last day of blocks and
prunes everything older; one archive node keeps everything; mainnet keeps everything.** The
shape of the storage (the QC stored twice, 1 s idle blocks) is not changed by this work.

## What is kept and what goes

The ledger is the state a node needs to validate and to serve wallets; history is the blocks
that produced it. Pruning deletes history and never touches the ledger.

| Column family | Key | Under pruning |
|---|---|---|
| `blocks`, `qcs` | height | deleted below the floor |
| `block_index` | block hash → height | deleted (hash from the deleted block) |
| `txs` | tx hash → location | deleted for the deleted block's transactions |
| `receipts`, `receipts_by_program` | tx hash; program‖height‖index | deleted for those transactions |
| `seals` `'p'`, `'t'`, `'a'`, `'b'` | proof hash; cover; aggregate tx; block hash | deleted for those transactions and that block |
| `notes`, `nullifiers`, `anchors`, `validators`, `epoch_sets`, `programs`, `program_public`, `bridge_spent`, `bridge_burns`, `meta` | — | never touched |

Block 0 (genesis) and its QC are never deleted: `verify_chain` and `init` key on them. The head
block and its parent are never deleted. Nothing inside the aggregation window is deleted (a
cover's aggregate must stay resolvable for `assemble_covered`, `StoreCovered` and
`refresh_block_sealed_flag`, all of which read within the window).

The **floor** is the lowest height whose block is still on disk, other than genesis. It is
persisted in `meta` under `META_PRUNE_FLOOR`. A store that has never pruned has no key, which
reads as floor 0: an archive node. The floor only ever rises.

## 1. The retention pass

**Flag.** `rand-node run --prune-history <duration>`, where `<duration>` is `<n>m`, `<n>h` or `<n>d`
(`24h`, `36h`, `2d`), parsed by `parse_prune_history` in `main.rs`; no dependency is added for it.
Absent means never prune. It flows through the three usual edits: the clap field, the `Cmd::Run`
destructure in `main.rs`, and `NodeConfig.prune_history: Option<Duration>` in `node.rs`, beside
`keep_raw_proofs` and `min_free_disk_bytes`.

**Cadence.** In the post-commit handler, next to the proof-pruning pass, when
`prune_history` is set and `head % 16 == 0`, the node runs
`storage.prune_history(cutoff_ms, keep_from, PRUNE_PASS_MAX)` in `spawn_blocking`, where:

- `cutoff_ms = head_block.header.timestamp_ms - prune_history`. Block time is the chain's own
  clock (monotonic, bounded by `MAX_TIMESTAMP_STEP_MS` on a bridged chain), so the pass never
  reads the wall clock and every node prunes the same heights for the same head.
- `keep_from = head.saturating_sub(max(aggregation.window, 2))` when the chain has an
  aggregation section, else `head - 2`. No block at or above `keep_from` is deleted.
- `PRUNE_PASS_MAX = 4096` blocks per pass, so enabling the flag on a node holding four days of
  history drains it over ~60 passes (~16 minutes at 1 s blocks) without stalling commits.

**The pass** (`Storage::prune_history`) walks `h` from `max(floor, 1)` upward while
`h < keep_from` and `block_by_height(h).timestamp_ms < cutoff_ms`, up to `PRUNE_PASS_MAX`
blocks. For each block it collects the keys to delete (the block's hash for `block_index` and
`seals 'b'`; each transaction's hash for `txs` and `receipts`; each `Aggregate`'s covers for
`seals 't'` and its own hash for `seals 'a'`; each bundle's proof hash for `seals 'p'`; each
`Call`'s `receipts_by_program` key). All deletes for the pass and the new floor
(`META_PRUNE_FLOOR = last deleted height + 1`) go in **one synced `WriteBatch`**, so a crash
mid-pass leaves either the old floor with its blocks or the new floor without them, never a gap.
Height-keyed families (`blocks`, `qcs`) use `delete_range_cf`. It returns the number of blocks
pruned and logs `pruned {n} blocks below height {floor} at head {head}` when `n > 0`.

**Disk comes back only after compaction.** Every 64th pass that deleted anything calls
`compact_range_cf` on `blocks` and `qcs` over `[genesis+1, floor)`. Between compactions
`df` lags the floor; `rand_status` reports the floor, not free space.

**Idempotence.** A pass at the same head deletes nothing the second time. A pass on an archive
node (`prune_history` unset) is never scheduled; `prune_history` itself is safe to call on any
store.

## 2. Sync between nodes (wire-coordinated)

`Status` gains `floor: u64` (the node's prune floor; 0 on an archive). `pick_sync_peer` skips a
peer whose `floor > my_height + 1` and, when that leaves no candidate, logs once per minute
`no peer holds height {h}: every candidate has pruned it (floors: …)` — the operator's cue that
the node fell behind every pruned peer's window and must sync from the archive.
`serve_sync` is unchanged: `committed_block` below the floor is `None`, `map_while` stops, the
batch is empty, and the client already ignores an empty batch (`batch_decision(None, …)`).
`BlockByHash` for a pruned block returns `Block(None)` as it does for an unknown hash.

This changes the `Status` wire shape. The codec is not self-describing, so the working
assumption is that a v0.5.6 node and a v0.5.7 node cannot decode each other's `Status` and
therefore cannot choose each other for batch sync during the roll; the plan pins the actual
behaviour with a decode test either way, and the roll is planned for the worse case. Consensus
messages are untouched and blocks keep committing. The roll is done in one pass (see §7) and
the mixed window is minutes per node.

## 3. Startup verification on a pruned node

`Storage::verify_chain` reads the floor first.

- **Floor 0 (archive, every mainnet node):** exactly today's behaviour — replay from genesis,
  compare with the ledger snapshot, truncate to the last good height on failure.
- **Floor > 0:** structural verification. Block 0 must hash to the genesis hash and
  `epoch_set(0)` must equal the genesis set. For every `h` in `floor..=head`: the block and its
  QC exist, the parent link and `block_index` agree, the proposer is the view's leader for the
  epoch set, and in `Full` mode the QC's votes verify. No `apply_block`, no receipt comparison,
  no ledger replay: `load_ledger` is trusted and the node logs
  `pruned node: history verified from {floor} to {head}; ledger snapshot trusted`. `Off` keeps
  requiring block 0 and `load_ledger`.
- **A structural failure on a pruned node is fatal.** The node holds one ledger, the head's;
  truncating to an earlier height would pair the remaining blocks with a state they did not
  produce. `check_and_repair_chain` exits with
  `pruned node: {problem}; history cannot be repaired locally — re-sync from the archive`, and
  `verify --repair` prints the same and exits 2.

`verify --mode full --repair` (the offline command) follows the same rule.

## 4. RPC behaviour

- `rand_status` gains `prune_floor` (u64) and `prune_history_secs` (null when unset).
- A lookup **below the floor** answers a distinct JSON-RPC error, code `-32010`,
  message `pruned: height {h} is below this node's retention floor {floor}`, with
  `data: {"floor": floor}`. Only height-addressed lookups answer it: `rand_getBlockByHeight`,
  `rand_getFinality` by height, `rand_getBlocks`/`rand_getCompactBlocks` when the range reaches
  a non-genesis height below the floor, and `rand_getTransaction`/`rand_checkTransaction` when
  the `txs` row names a height below the floor. `rand_getReceipt`, `rand_getCallEnvelope`,
  `rand_getAggregate`, `rand_getRawTransaction` and `rand_getBlockByHash` keep answering null
  for a hash the node does not hold; a caller can tell "pruned" from "never existed" only by
  asking an archive, and `docs/rpc.md` says so. An unknown height **above** the floor keeps
  today's answer.
- `rand_getBlocks(from, to)` and `rand_getCompactBlocks(from, …)` with `from < floor` answer
  the same error instead of an empty page. A wallet that scans with `rand_getCommitments`,
  `rand_getNullifiers` and `rand_getWitness` (the `randprotocol-client` path) is unaffected:
  those read `notes` and `nullifiers`, which are never pruned.
- `rand_getTransactionStatus` reads only the `txs` row, which pruning deletes, so a pruned
  transaction is indistinguishable from one the node never saw: it keeps answering `unknown`,
  and the result gains a `floor` field on a node whose floor is above 0 so the caller knows to
  ask the archive. The bridge status service and randscan read the archive for anything older
  than the window.

## 5. Guard rails

- `--prune-history` below `1h` is refused at startup (`prune-history must be at least 1h`).
- If the genesis has an aggregation section and `window × block_interval > prune_history`, the
  node refuses to start (`prune-history {d} is shorter than the aggregation window`).
- Nothing is keyed on `chain_id`. Mainnet keeps everything because its units never pass the
  flag; `docs/deploy.md` says so in the unit template and the release note.
- The archive node (obs1) runs without the flag and is listed in `deploy/nodes.env` as
  `ARCHIVE=` so operators know where full history lives.

## 6. Tests (red first)

Storage (`storage.rs`):
- `prune_history` on a store of N blocks with a mix of empty blocks, `Call`s with receipts, a
  bundle with a seal and an `Aggregate` with covers: deletes exactly the per-block rows of the
  blocks below the cutoff, keeps every ledger row (compare `load_ledger` before and after),
  keeps block 0 and its QC, keeps `keep_from..=head`, honours `PRUNE_PASS_MAX`, persists the
  floor, and a second call at the same head prunes 0.
- After pruning, `committed_block(h)` below the floor is `Ok(None)`; `head()`, `head_qc()`,
  `load_epoch_sets()`, `witness()` and `notes_from()` are unchanged.
- `verify_chain` on a pruned store: `Quick` and `Full` pass without truncating; a block deleted
  by hand above the floor is reported and repaired to the floor; a hand-deleted block at the
  floor is `history missing below the floor`.

Node (`node.rs`, `tests/cluster.rs`):
- `pick_sync_peer` never picks a peer whose floor is above our next height; with no candidate it
  returns `None` and the log line names the floors.
- A cluster of three where one validator runs `prune_history = 1s` at a test block interval:
  it keeps committing, its floor rises, its disk-backed store shrinks, and a fourth node that
  joins late syncs to the head from the archive peers and never from the pruned one (assert on
  the chosen peer).
- The mixed-`Status` decode: an old-shape `Status` fails to decode and the peer is skipped
  without a panic (pinning the roll caveat).

RPC (`rpc.rs`):
- Each listed method answers `-32010` with `data.floor` for a pruned height and today's
  answer for an unknown height above the floor.
- `rand_status` reports the floor and the window.

## 7. Rollout (the operator's runbook, not code)

The fleet is already on v0.5.6 with the WAL cap. Pruning ships as the next node patch release
under the release rule (`docs/deploy.md`, audit v4 PROC-3): green CI, full release test on the
release machine, tagged.

1. **Archive first.** Create a 500 GB volume in sgp1, attach it to randbridge-web
   (602163447), stop `rand-node` (obs1), move `/root/data-obs1-1cff3b7d` onto the volume, point
   the unit at it, start, confirm it verifies and follows the head. obs1 stays on the archive
   configuration (no flag) forever; the randbridge status service and randscan already read it.
2. **Wait for the chain to commit again** (it is still halted at 248 953 at the time of
   writing, under the other session's livelock fix). Never roll a wire change onto a halted
   chain.
3. **Roll the seventeen validators one at a time** with `deploy/rebuild-vps.sh` or
   `update-droplet.sh`: new binary, `--prune-history 24h` appended to `ExecStart`, restart,
   wait for `rand_status.height` to reach the head and one more block to commit before the next.
   More than two thirds of stake stays up throughout.
4. **Node A** through `deploy/run-a.sh` (`BINDIR` to the new build, the flag added) and
   `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a`.
5. **Verify:** every validator's `prune_floor` rises to ~one day behind the head within an
   hour; `du -ch db/*.sst` falls below 15 GB after the compactions and stays flat; obs1 answers
   `rand_getBlockByHeight(1000)` while a validator answers `-32010`; a fresh observer synced
   from obs1 reaches the head.

## Out of scope

Storing the QC once, slower idle blocks, checkpoint or snapshot sync, and any change to what
mainnet stores. Those are the storage redesign items in `AGENTS.md` (2026-09-24).
