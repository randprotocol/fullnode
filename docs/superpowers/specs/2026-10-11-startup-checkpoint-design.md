# Startup checkpoint — design

Date: 2026-10-11. Branch `feat/startup-checkpoint`, cut from `origin/main` 6f1cd272.

## 1. Problem

`rand-node run` verifies the chain before the RPC opens (`check_and_repair_chain`, node.rs:475).
With the default `--verify-chain quick`:

- **Archive** (`floor == 0`): `Storage::verify_chain` re-executes every block from genesis.
  That includes proposer signatures, bundle and call proofs through the real executor, and a
  full `state_root()` per block. Documented cost: 239 s at 59 183 blocks (chain 12), and up to
  30 min at 259 k blocks on the 48 GB droplets (AGENTS.md, roll of 2026-09-25).
- **Pruned** (`floor > 0`): `verify_pruned` runs a structural walk from the floor (links,
  indexes, QC/block match, leader), with no apply.
- **Both:** `load_ledger` runs twice, once at the end of `verify_chain` (storage.rs:3762 and
  3981) and once in `reload_ledger` (node.rs:164). Each run rebuilds the note `FullTree` with
  O(leaves) Poseidon2 hashing and scans every nullifier. `resume_consensus` then computes
  `state_root()` once more for `snapshot_is_the_head_state` (OPS-5). On chains without
  `incremental_nullifier_root` (every chain through 20), that root sorts every nullifier.

Every block the node holds was already state-root-checked when this node committed it, by the
consensus apply or by `apply_block_for_sync`. The startup replay repeats that work on every
restart.

## 2. Goal and non-goals

**Goal:** restarting the *same clean build* on a store it has already verified opens the RPC
after one `load_ledger` and one `state_root()`, with no per-block work.

**Decided with the user (2026-10-11):**

- **Checkpoint + tail:** a node re-proves nothing about blocks it committed itself under the
  same build.
- **The checkpoint is bound to the build's git SHA.** A new binary replays once on its first
  start; only restarts after that are fast. This keeps today's guarantee that a binary which
  disagrees with history is caught at startup.

**Non-goals:**

- A serialized whole-ledger blob. `load_ledger`'s note-tree rebuild and the nullifier sort stay.
- Changing `off`, `full` or `rand-node verify`.
- Faster first-start-after-upgrade. Rolls still pay one replay per node.

## 3. The marker

A new `CF_META` row, `META_VERIFIED_HEAD = "verified_head"`, bincode of:

```rust
pub struct VerifiedHead {
    pub height: u64,
    pub block_hash: Hash,
    pub state_root: Hash, // the head header's state_root, copied, not recomputed
    pub build_sha: String, // rpc::GIT_SHA of the build that wrote it
}
```

**What it means:** "the build `build_sha` verified this store's history through `height`
(replay on an archive, structural walk on a pruned node), or committed the blocks after its
own verification itself."

### 3.1 Trusted build

A build may write or honour the marker only if `GIT_SHA` is exactly 40 lowercase hex
characters. A `-dirty` or `unknown` SHA doesn't change when the code does, so such builds never
write the marker and always take the full path. Helper: `fn checkpoint_build() -> Option<&'static str>`.

### 3.2 Who writes it

1. **Startup verification** (`check_and_repair_chain`): after `verify_chain` succeeds in
   `quick`, `replay` or `full`, write the marker for the verified head, if the build is trusted.
2. **`Storage::commit`**, in the same `WriteBatch` as `META_HEAD_HEIGHT`. It *carries the
   marker forward*: if the stored marker equals the pre-commit head (height and hash) and
   carries this build's SHA, the batch rewrites it at the new head (`last` block's height,
   hash and header `state_root`). Otherwise it writes nothing.

   So `commit` never creates trust; it only extends trust this build already has. Blocks one
   build committed on top of another build's verification never count as verified. The two
   production callers (consensus `Node::commit`, node.rs:3126, and sync, node.rs:4594) both pass
   ledgers whose state roots were checked against the headers. Carrying forward adds one
   META read per commit.

### 3.3 Who clears it

- `truncate_to` deletes the marker in its batch. The archive repair path then re-verifies and
  rewrites it per §3.2.1.
- `init_genesis` writes no marker. A fresh store's first startup verify (height 0, trivial)
  writes it.
- `prune_history` doesn't touch it. Pruning stops at `keep_from`, below the head.

## 4. Startup

### 4.1 Modes

`--verify-chain` accepts `off | quick | replay | full`:

| mode | marker valid | marker missing or invalid |
|---|---|---|
| `off` | unchanged: no verify | unchanged: no verify |
| `quick` (default) | **skip `verify_chain`** | today's `quick` (replay or structural), then write the marker |
| `replay` (new) | ignored: today's `quick` | today's `quick`, then write the marker |
| `full` | ignored: today's `full` | today's `full`, then write the marker |

`VerifyMode` gains `Replay`. Inside `Storage::verify_chain`, `Replay` behaves exactly like
`Quick`. The marker decision lives in `check_and_repair_chain`, not in `verify_chain`, so
`rand-node verify` and the storage tests keep their meaning.

### 4.2 Marker valid

The marker is valid iff all of these hold:

- the build is trusted (§3.1);
- `marker.build_sha == GIT_SHA`;
- `marker.height == head.height`;
- `marker.block_hash == head.hash`.

Both store kinds use this rule.

### 4.3 What still runs on the fast path

- `snapshot_is_the_head_state` in `resume_consensus`. A snapshot corrupted on disk is still
  refused, because its recomputed root no longer matches the head header's.
- Every other check in `start_with` before and after verification (genesis/build check, disk
  guard, prune-window check, halted store, the startup pin checks).

### 4.4 Logging

One line, either:

- `chain verified: checkpoint at {h} (build {sha12}), replay skipped`, or
- `startup verify ({mode}): {reason}`, where `{reason}` is one of `no checkpoint`,
  `checkpoint from build {old12}`, `untrusted build {sha}`, `checkpoint at {h} but head is {h'}`,
  or `forced by --verify-chain {mode}`.

The existing `"chain verified: … blocks ok"` line follows when the walk runs.

### 4.5 One `load_ledger`

`ChainCheck.ledger` is the *replayed* ledger on an archive. The stored ledger `verify_chain`
loads is the local `loaded` (storage.rs:3762, with `set_gas`, `restore_proof_window` and
`set_tokens_incremental_root` applied), and on a pruned store it is `check.ledger` (3981).

- `ChainCheck` gains `stored: Option<Ledger>`: the successfully loaded stored ledger on either
  path, `None` when the load failed.
- `check_and_repair_chain` hands it on, or `None` when it skipped `verify_chain`.
- `reload_ledger` takes that `Option<Ledger>` and calls `storage.load_ledger` only on `None`.
  Its genesis setters run either way: they set values from the genesis file, so applying them
  over `verify_chain`'s three is idempotent. `restore_proof_window`'s second anchor read is
  bounded by the window.

Tests:

- On every path the handed-over ledger after `reload_ledger` equals a fresh
  `load_ledger` plus `reload_ledger`.
- One `load_ledger` per startup on each path, pinned with a `#[cfg(test)]` counter like
  `tree_builds()`.

## 5. Failure handling

- **Marker row fails to decode:** treat as missing (full path), log a warning, then overwrite it
  after verifying.
- **Marker valid but `snapshot_is_the_head_state` fails:** fatal, as today. The marker doesn't
  weaken OPS-5.
- **`verify_chain` fails:** unchanged (fatal when pruned, truncate-and-reverify on an archive).
  No marker is written on failure.
- **Crash between verify and the marker write:** the next start repeats the verify. That is
  safe and only slower.

## 6. Tests

All must fail before the change where that's meaningful.

**storage.rs:**

- `commit` carries a valid marker forward to the new head in the same batch.
- `commit` writes nothing when there's no marker, when the marker's head is stale, or when it
  holds another build's SHA.
- `truncate_to` deletes the marker.

**node.rs:**

- A restart with a valid marker never enters `verify_chain` (counter) and still runs OPS-5.
- Each invalidation forces the walk and then rewrites the marker: a different `build_sha`, an
  untrusted SHA, a head moved past the marker (marker written by hand), a missing marker (an
  old store), and an undecodable row.
- With a valid marker and a tampered snapshot row (the existing
  `a_ledger_snapshot_that_is_not_the_head_blocks_state_is_refused_at_resume` setup), startup is
  refused.
- `--verify-chain replay` and `full` ignore a valid marker.
- `load_ledger` runs exactly once per startup on the fast path, the replay path and the pruned
  path.

The build SHA is injected for tests through a `#[cfg(test)]` override, because `GIT_SHA` is a
compile-time constant.

**tests/cluster.rs:** stop one validator, restart it on the same binary, assert the
`replay skipped` log line, and assert it rejoins and commits.

## 7. Docs

- `docs/cli.md`:
  - the `--verify-chain` modes table (add `replay` and the checkpoint);
  - fix the claim that only `full` checks proposer signatures (`quick` does too, through
    `apply_block_for_sync`; `full` adds only QC votes).
- `docs/architecture.md`: the startup section and the same signature fix at :346 and :657.
- `docs/node-hardware.md` and `deploy/README.md`: startup is fast on a restart of the same
  build; the first start after an upgrade still replays, and the documented 4–30 min figures
  apply there.
- `AGENTS.md`: the same one-line note next to "Node startup is ~4 min".

## 8. Rollout

Old stores have no marker, so the first start of this build takes today's path and writes it.
Nothing is consensus-visible: the marker is local META state, and no genesis flag or wire
change is needed. It ships in the next release with compact blocks. The flag-day roll pays one
replay per node as before; restarts after that are fast.
