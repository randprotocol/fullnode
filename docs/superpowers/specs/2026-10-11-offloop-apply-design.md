# Off-loop proposal apply — design

Date: 2026-10-11. Branch `feat/offloop-verify`, cut from `origin/main` 10fff634, which includes the verify cache.
This is the open half of `docs/compute-optimization.md` §3.3: "the consensus loop only ever looks up".

## 1. Problem

`Node::run` is one tokio task. Every select arm runs on it: network events, RPC, admission
verdicts, the view timeout, the propose timer and the status/sync ticks. An incoming proposal
reaches `HotStuff::on_proposal`, whose `execute_and_insert` (`hotstuff.rs:1099`) does three
things in turn: clone the parent's `ledger_after`, build the aggregate sidecar, and call
`apply_block_for_sync`. The apply runs every proof verifier and every Dilithium check, then
computes the state root.

The verify cache makes the verifiers free for proofs this node admitted. An aggregate or
transaction it never saw is still verified on the loop: about 1–2 s for an aggregate in the
test profile, against a ≤ 150 ms budget. The state work still runs there too: about 56 ms of
apply at block 10 000 with 2 000 bundles. While that work runs, the node cannot count votes,
fire its timeout or answer RPC.

## 2. Goal and non-goals

**Goal:** the apply of an incoming proposal runs on a blocking thread. The loop does only the
cheap checks and the insert. The verdict is identical: the same function runs on the same parent
ledger with the same executor.

**Non-goals:**

- Sync's `apply_synced`, which applies batches on the loop. A catching-up node does not vote.
- The leader's own proposal. `HotStuff::propose` trial-applies and then self-delivers on the loop.
  Its transactions come from the admitted pool, so they are all cache hits.
- Orphan children re-run inside HotStuff (`hotstuff.rs:1085`), `offer_pending` and
  `restore_pending`. They keep today's on-loop apply. §4.4 keeps the common chain case out of the
  orphan path.
- Caching Dilithium checks.

## 3. HotStuff: a pre-applied entry point (core)

```rust
pub struct PreApplied {
    pub parent: Hash,                                   // the parent hash the ledger was cloned from
    pub result: Result<(Ledger, Vec<Receipt>), LedgerError>, // apply_block_for_sync's outcome on that clone
}
impl HotStuff {
    /// The parent's post-state for an off-loop apply, or None when the parent isn't in the tree
    /// (an orphan — deliver it plainly) .
    pub fn ledger_after(&self, hash: &Hash) -> Option<&Ledger>;
    /// The aggregate sidecar `execute_and_insert` would build, for an off-loop apply.
    pub fn covered_sidecar(&self, block: &Block) -> Result<BTreeMap<usize, Vec<CoveredBundle>>, ConsensusError>;
    /// `on_proposal`, but `execute_and_insert` takes `pre` instead of applying when
    /// `pre.parent == block.parent()` and the parent is still in the tree. Otherwise it applies as today.
    pub fn on_proposal_with(&mut self, block: Block, now_ms: u64, pre: Option<PreApplied>) -> Result<Vec<Action>, ConsensusError>;
}
```

`on_proposal(block, now)` becomes `on_proposal_with(block, now, None)`. Every check before
`execute_and_insert` still runs on the loop, unchanged and in the same order:

- dedupe;
- view windows;
- stale;
- signature;
- parent lookup and orphaning;
- leader;
- equivocation;
- justify;
- the QC check;
- tree room.

Everything after it is also unchanged. Use the exact types `execute_and_insert` uses today; the
names above are illustrative.

In `execute_and_insert`, a usable `pre` is either an `Ok((ledger, receipts))`, which is inserted
as the entry, or an `Err(e)`, which is returned as the apply error. The two paths must map that
error exactly as the on-loop apply does. Deterministic apply makes this sound: the parent's
`ledger_after` doesn't change while it sits in the tree, and the executor is the same object. On
`SharedSet`: a commit while the apply runs absorbs ancestors' deltas into the shared base. If the
parent descends from the committed block, the clone already holds those elements. If it doesn't,
the commit prunes the parent from the tree, and `pre` is then unusable and dropped.

## 4. Node: apply off the loop

### 4.1 Interception

`on_consensus(ConsensusMessage::Proposal(block))` is the choke point for full gossip, compact
rebuilds, completed parks and by-hash fetches. On that path:

1. If `hs.has_block(hash)` holds or the hash is in flight, return. That duplicate is dropped
   silently.
2. Look up the parent with `hs.ledger_after(&block.parent())`. If the parent is absent:
   - if it is in flight, queue this block behind it (§4.4);
   - otherwise deliver plainly (`hs.on_message`, today's path, which orphans it and fetches the
     parent).
3. If the in-flight count is at the cap (`OFFLOOP_APPLIES = 4`), deliver plainly. A burst then
   costs no more than today.
4. Otherwise build the sidecar on the loop with `hs.covered_sidecar(&block)`. If that fails,
   deliver plainly. Then clone the parent ledger on the loop, as today's `execute_and_insert`
   does. Clone `executor` (the `CachingExecutor` `Arc`), `verified` and an `applied_tx` sender,
   and `spawn_blocking`:
   `catch_unwind(|| ledger.apply_block_for_sync(&block, &sidecar, &[], executor, verified))`.
   Send `Applied { block, parent, result: Option<Result<..>> }` back, with `None` meaning a panic.
   Record the hash in `in_flight` and return.

### 4.2 Completion arm

`Node::run` gains a select arm, `applied = applied_rx.recv()`, that calls `on_applied`:

1. Remove the hash from `in_flight`.
2. If the result is `None` (a panic), deliver plainly through `hs.on_message`. The on-loop apply
   then panics or fails exactly as it would today.
3. Otherwise call `hs.on_proposal_with(block, now, Some(PreApplied{..}))`, through the same
   result handling `on_consensus` uses: evidence, `last_block_at`, `handle_actions`,
   `UnknownParent` to fetch, warnings. Factor that handling into one function both callers use.
4. Then release the children queued behind this hash (§4.4) by running each through §4.1 again.

### 4.3 Fetch suppression

`fetch_block(h)` and the compact path's `has_block` checks also treat an in-flight hash as held.
Without this, a vote-driven fetch would re-request a block that is being applied.

### 4.4 Chains

`waiting: HashMap<Hash /*parent*/, Vec<Block>>`, capped at 8 blocks in total; beyond the cap,
deliver plainly. A child whose parent is in flight waits here. When the parent completes, the
child goes through §4.1 and gets its own off-loop apply on the newly inserted parent. If the
parent's apply failed, the children are delivered plainly and HotStuff orphans or refuses them as
today.

### 4.5 Kill switch

`rand-node run --apply-proposals-inline` (`NodeConfig.apply_inline: bool`, default false) restores
today's path exactly: `on_consensus` delivers directly. Tests use it to compare the two paths.

### 4.6 Observability

`debug!("proposal {h} applied off the loop in {ms} ms")` on completion. `NodeStatus` gains no
field.

## 5. Tests

**Core (HotStuff):**

1. On the same proposal, `on_proposal_with(Some(Ok(pre)))` gives a tree entry, actions and a
   committed result identical to `on_proposal`'s. The executor is not called (counting).
2. `pre` with the wrong parent hash, or with the parent pruned, falls back to the plain apply.
3. `pre = Err(e)` returns the same error `on_proposal` returns for that block, without calling
   the executor.
4. Every pre-execute refusal still fires with `pre` present: a bad signature, the wrong leader,
   equivocation.

**Node (`bare_node`):** the harness keeps an `applied_rx`, and tests drive `on_applied` by hand.

5. A proposal goes off-loop: right after `on_consensus`, `hs.has_block` is false. After
   `on_applied`, the node has voted exactly as the inline path would, and holds the same entry.
6. **The loop is not blocked:** an executor whose `verify_bundle` waits on a barrier. The node
   handles a second message (a vote, or a gossiped transaction) before the barrier is released.
7. Chain: N and N+1 arrive back to back. N+1 waits, then gets its own off-loop apply. Neither is
   orphaned.
8. A duplicate proposal during flight starts no second apply. `fetch_block` of an in-flight hash
   sends nothing.
9. At the cap, the fifth proposal is delivered inline.
10. A panic in the off-loop apply is delivered plainly, and the node survives to handle the next
    message. Use a test executor that panics once; the plain apply then succeeds.
11. `apply_inline` gives the old behaviour.

**Cluster:** the full suite is green.

## 6. Docs

- `docs/compute-optimization.md` §3.3: change the status to shipped. Say what still runs on the
  loop: sync, the leader's own apply, and orphan re-runs.
- `docs/architecture.md`: the consensus loop paragraph.
- `docs/cli.md`: `--apply-proposals-inline`.
- `CHANGELOG.md` v0.8.0: one bullet.

## 7. Rollout

The change is node-local: no wire, genesis or consensus-rule change. It ships in v0.8.0, which
runs chain 21 onward.
