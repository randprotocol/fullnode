# Off-loop Proposal Apply Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An incoming proposal's `apply_block_for_sync` runs on a blocking thread. The consensus
loop runs only HotStuff's cheap checks and inserts the pre-applied result.

**Architecture:** In core, HotStuff gains a `PreApplied` entry point: `on_proposal_with`, plus the
`ledger_after` and `covered_sidecar` accessors. `execute_and_insert` uses a matching pre-applied
result instead of applying. In the node, `on_consensus` diverts proposals whose parent is in the
tree to `spawn_blocking`. A new select arm feeds the results back. An in-flight table dedupes
proposals and suppresses fetches, a waiting map queues children behind in-flight parents, and a
cap bounds the in-flight applies. A kill switch restores the inline path.

**Tech Stack:** Rust, tokio (`spawn_blocking`, `mpsc`), `std::panic::catch_unwind`.

**Spec:** `docs/superpowers/specs/2026-10-11-offloop-apply-design.md`

## Global Constraints

- Every check `on_proposal` runs before `execute_and_insert` stays on the loop, unchanged and in
  the same order. Only the clone, sidecar and apply step may be replaced, and only by a result
  computed with the same function on the same parent ledger and executor.
- A pre-applied `Err` must be mapped to `ConsensusError` exactly as the on-loop apply maps it.
- Constants: `OFFLOOP_APPLIES = 4` in-flight, and `WAITING_BLOCKS = 8` blocks queued behind
  in-flight parents. Over either cap the proposal is delivered inline.
- Kill switch: `rand-node run --apply-proposals-inline`, mapped to `NodeConfig.apply_inline: bool`
  (default false).
- The off-loop closure uses the node's `executor` Arc (the `CachingExecutor`). It never uses the
  bare one.
- A panic in the off-loop apply delivers the proposal plainly, and the node keeps running.
- Clippy gate: `cargo clippy -p randprotocol-node -p randprotocol-core --all-targets --no-deps -- -D warnings`.
- Commit trailers:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01Lrko8eEwLbCppJ2pBMG6Qa`
- Coordination: private multisig (randprotocol-0e) may edit `node::warm` and `start_with`'s warm
  plumbing; don't restructure those. Don't edit `verify_cache.rs`.

## Review Focus

1. **A pre-applied result used against a different parent state.** This would be a consensus
   split. The parent hash must match and the parent must still be in the tree at use. Test 2.
2. **A refusal that moved or got skipped.** Test 4: signature, leader and equivocation with `pre`
   present.
3. **A lost proposal.** In-flight bookkeeping must leave no block that is never delivered: on a
   panic, a send failure, or a parent failure with children waiting. Tests 7 and 10.
4. **A fetch storm or double apply** for an in-flight hash. Test 8.
5. **An error-mapping drift** between the pre-applied `Err` and the inline apply. Test 3.

---

### Task 1: HotStuff pre-applied entry point (core)

**Files:**
- Modify: `crates/randprotocol-core/src/consensus/hotstuff.rs`: `PreApplied`, `ledger_after`,
  `covered_sidecar` made `pub` (it is private today, ≈ line 512), `on_proposal_with`;
  `on_proposal` delegates to it; `execute_and_insert` takes `Option<PreApplied>`.
- Test: `crates/randprotocol-core/src/consensus/tests.rs`, or the hotstuff test module, wherever
  `on_proposal` tests already live.

**Interfaces (produced):**
```rust
pub struct PreApplied { pub parent: Hash, pub result: Result<(Ledger, <receipts type execute_and_insert stores>), <apply_block_for_sync's error type>> }
impl HotStuff {
    pub fn ledger_after(&self, hash: &Hash) -> Option<&Ledger>;
    pub fn covered_sidecar(&self, block: &Block) -> Result<BTreeMap<usize, Vec<CoveredBundle>>, ConsensusError>; // existing body
    pub fn on_proposal_with(&mut self, block: Block, now_ms: u64, pre: Option<PreApplied>) -> Result<Vec<Action>, ConsensusError>;
}
```
Read `execute_and_insert` (≈ 1099–1118) and use its exact receipts and error types. `pre` is used
only when `pre.parent == block.parent()` and `self.tree` still holds that parent. Otherwise the
plain path runs. Re-export `PreApplied` wherever `HotStuff` is re-exported.

- [ ] **Step 1:** Write failing tests (spec §5, tests 1–4), using the existing consensus test
  fixtures and a counting executor, such as core's `CountingExecutor` or a small local wrapper
  over `StubExecutor`:
  1. `a_pre_applied_proposal_inserts_what_the_plain_path_inserts`: two identical replicas; one
     takes `on_proposal`, the other takes `on_proposal_with(Some(PreApplied{parent, result:
     Ok(apply on a clone of ledger_after(parent))}))`. Compare the actions, the
     `tip_ledger().state_root()` and the receipts. The second replica's executor counter does not
     move during `on_proposal_with`.
  2. `a_pre_applied_result_for_another_parent_is_ignored`: `pre.parent` = some other hash; the
     plain apply runs (the counter moves) and the result matches.
  3. `a_pre_applied_error_is_the_plain_error`: a block whose apply fails (e.g. a stub bundle with
     a bad proof). The plain path's `Err` equals the pre-applied path's `Err`, with the
     pre-applied `Err` produced by running `apply_block_for_sync` on the clone. The counter does
     not move on the pre path.
  4. `pre_execute_refusals_still_fire_with_a_pre_applied_result`: bad signature, wrong leader,
     and equivocation (a second block for the same (view, leader)). Each is refused with the same
     error as the plain path.
- [ ] **Step 2:** `cargo test -p randprotocol-core pre_appl` fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test -p randprotocol-core` passes; `cargo test -p randprotocol-node --lib`
  passes; clippy gate clean.
- [ ] **Step 5:** Commit: `consensus: PreApplied — on_proposal_with inserts an apply computed off the loop on the same parent ledger; ledger_after, covered_sidecar public`.

### Task 2: Node off-loop apply

**Files:**
- Modify: `crates/randprotocol-node/src/node.rs`:
  - `Applied` struct, channel, `Node` fields (`applied_tx`, `in_flight: HashSet<Hash>`,
    `waiting: HashMap<Hash, Vec<Block>>`, `apply_inline: bool`);
  - the select arm in `run`;
  - `on_consensus` diversion, `on_applied`, and the shared result handler factored out of
    `on_consensus`;
  - `fetch_block` and compact `has_block` checks that also consult `in_flight`;
  - `NodeConfig.apply_inline`;
  - `bare_node*` harness: keep the receiver and expose it, e.g. a returned `mpsc::Receiver<Applied>`
    or a field.
- Modify: `crates/randprotocol-node/src/main.rs`: the `--apply-proposals-inline` flag on `run`
  (follow `--verify-workers`' pattern, main.rs ≈ 836 / 2911 / 2977).
- Modify: `tests/common/*.rs`, only if `NodeConfig` construction needs the new field (default
  false).

**Interfaces (consumed):** Task 1's `HotStuff::{ledger_after, covered_sidecar, on_proposal_with}`
and `PreApplied`.

Flow per spec §4.1–4.4. Notes:
- The closure moves `ledger: Ledger` (cloned on the loop from `ledger_after`), `block`, `sidecar`,
  `executor: Arc<dyn ConfidentialExecutor>`, `verified` (the `Arc` the replica uses) and `tx`. It
  calls `std::panic::catch_unwind(AssertUnwindSafe(|| { let mut l = ledger; l.apply_block_for_sync(&block, &sidecar, &[], executor.as_ref(), verified.as_ref()).map(|r| (l, r)) }))`.
  It sends `Applied { block, parent, result: res.ok() }` with `blocking_send`; if the send fails,
  the node is shutting down and the result is ignored.
- `on_applied` uses the shared result handler, so `UnknownParent`, evidence, `last_block_at` and
  `handle_actions` behave exactly as for a plain proposal.
- Release waiting children after the parent's completion is handled, whether it succeeded or
  failed.
- With `apply_inline`, `on_consensus` delivers directly, as today.

- [ ] **Step 1:** Write the failing node tests (spec §5, tests 5–11) in node.rs's test module,
  using `bare_node`, `replica_past_a_boundary`, `block_on`, `voted_for` and `drain`. For test 6,
  write a test executor wrapping `StubExecutor` whose `verify_bundle` waits on a
  `std::sync::Barrier` (or a channel). The bare node built with it handles a gossiped
  transaction or a vote before the barrier is released; assert it via `drain`'s output or node
  state. Tests drive completion with
  `let a = applied_rx.recv().await.unwrap(); node.on_applied(a)`.
- [ ] **Step 2:** Run them; they fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Gates:
  - `cargo test -p randprotocol-node --lib` passes;
  - `cargo test -p randprotocol-node --test cli_datadir` passes;
  - `cargo test -p randprotocol-core` passes;
  - the clippy gate is clean.

  The controller runs the cluster suite.
- [ ] **Step 5:** Commit: `node: apply incoming proposals off the consensus loop — spawn_blocking on the parent's ledger, PreApplied back on a select arm; in-flight dedupe, children queued behind their parent, cap 4, --apply-proposals-inline`.

### Task 3: Docs and CHANGELOG

**Files:**
- `docs/compute-optimization.md` §3.3: the status is now shipped. Say what still applies on the
  loop: sync batches, the leader's own block, orphan re-runs, `offer_pending` and
  `restore_pending`.
- `docs/architecture.md`: the consensus loop / proposal handling paragraph (grep "on_proposal" or
  "consensus loop").
- `docs/cli.md`: `--apply-proposals-inline`, next to `--verify-workers`.
- `CHANGELOG.md` v0.8.0: one bullet after the verify-cache bullet.
- [ ] Commit: `docs: off-loop proposal apply — §3.3 shipped, architecture, cli, CHANGELOG`.
