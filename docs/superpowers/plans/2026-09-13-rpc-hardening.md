# RPC hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

## Reconciliation 2026-09-13

This plan was written against main `3c0f119`. Two branches have merged since — **review-followups**
(`170a8d9..a58c080`) and **fix-sync-stall** (`a58c080..9ffdd43`) — and they touched every file the
plan edits. What moved, and what each task now has to do about it:

- **`rpc.rs::handle` already has a shape.** It is no longer `Json<Request> -> Json<Value>`: it takes
  `Result<Json<Request>, axum::extract::rejection::JsonRejection>` and returns
  `(StatusCode, Json<Value>)`, so a body axum refuses comes back as JSON-RPC rather than plain text
  (`rejection_error`, rpc.rs:222). **Task 2 wraps that shape instead of replacing it** — the request
  type becomes `Result<Json<Value>, JsonRejection>`, the rejection arm and the non-`OK` status stay,
  and the batch tests destructure `(StatusCode, Json(v))`.
- **`-32600` already exists.** `RpcError::invalid_request` (rpc.rs:139) was added for oversized and
  malformed bodies, and `docs/rpc.md`'s Errors table still does not list it. Task 2 reuses the
  constructor rather than writing the code inline, and its doc step adds the one row covering all
  three uses (oversized body, batch shape, notification). The Global Constraint that said this plan
  *adds* the code is amended below.
- **The body limit is derived now.** `RPC_MAX_BODY_BYTES` (rpc.rs:154–175) is
  `2 * (2*MAX_PROOF_BYTES + 2*MAX_ENVELOPE_BYTES + MAX_CALL_ENVELOPE_BYTES + MAX_ATTESTATION_BYTES +
  64 KiB) + 256 KiB` ≈ **8.86 MB**, sized for one transaction carrying two proofs, and `serve`
  layers it with `DefaultBodyLimit`. Task 2's `MAX_BATCH` is the *request-count* bound and this is
  the *byte* bound; Task 3's route merge must keep the layer.
- **A transaction bigger than a block is refused twice.** `rand_sendTransaction` pre-checks
  `tx.encoded_len() > gas::MAX_BLOCK_BYTES` (rpc.rs:475) and `Ledger::validate` step 1 returns the
  new `TxError::TransactionTooLarge(usize)`. Task 1 maps no `TxError` variants, so it is unaffected;
  **Task 4's `is_permanent` allowlist gains `TransactionTooLarge(_)`** — a byte length is a function
  of the bytes.
- **`NodeStatus` grew four fields**: `sync_inflight_age_ms`, `sync_failures`, `sync_late_batches`,
  `connected_peers`. Tasks 3 and 5 add `ws_clients` / `refused_cache` / `verify_queue` **into that
  same block, in the same doc-commented style**, and set them in `publish_status` (node.rs:512)
  beside `s.sync_failures`. No task adds a counter that duplicates one of the four.
- **`Node::peers` is `HashMap<PeerId, Peer>`** now, where `Peer { status: Option<Status>, connected:
  bool }` (node.rs:230). **The per-peer token bucket becomes a third field on `Peer`**, not a map
  inside `PeerLimiter`: `PeerDisconnected` already does `self.peers.remove(&p)`, so the bucket dies
  with the peer and `PeerLimiter::forget` is dropped. That arm also calls `maybe_sync()` now, which
  must stay.
- **Gossip `from` is the author, not the forwarder.** `Peer`'s doc comment states it: a validator
  several hops away, with no connection to us, lands in `peers` purely as the author of relayed
  gossip — which is what `connected_peers` exists to expose. So the rate limit is keyed on
  `GossipId.propagation_source`. Ruling amended below.
- **`network/mod.rs` grew a lot that is out of scope**: `pub mod codec`, `SYNC_REQUEST_TIMEOUT`,
  `SYNC_MAX_WIRE_BYTES`, `SYNC_RESPONSE_WIRE_LIMIT`, `SYNC_REQUEST_WIRE_LIMIT`, `addr_scope`,
  `is_dialable_advertised_addr`, and a `lan_peers` set threaded through `handle_swarm_event`.
  `ValidationMode::Permissive` moved from line 139 to **247**. Task 5 touches only the gossipsub
  `ConfigBuilder` (245–250) and the `Event::Message` arm (486–493).
- **`mempool.rs` claims a `BridgeAttest`'s derived note too.** `claimed_commitments` calls
  `Ledger::derived_commitment` (randprotocol-core `ledger/staking.rs:161`) for `Withdraw` *and*
  `BridgeAttest`, so Task 4's `precheck` keeps its `&dyn ConfidentialExecutor` argument, and Task 1's
  `derived_note_count` must cover the same two arms. `candidates_within` also continues past an
  oversized candidate now; no task here touches it.
- **The cluster suite is serialised by a proving-slot file lock** (`<target-dir>/tmp/rand-proving-slot.lock`,
  `crates/randprotocol-node/tests/proving_slot/`). It is **17 tests / 19m59s**, not 16 / 6m28s. Task 6's one
  `--test cluster` run is sized accordingly and its proving test must take the slot.
- **The client sizes its POST timeout by body** (`randprotocol-client` `READ_TIMEOUT` 15 s flat for reads,
  `upload_timeout` = 30 s + body/32 KiB/s for uploads). Task 1's page caps sit under the 15 s read
  budget; Task 5's extra submission latency sits inside `upload_timeout`.
- **`docs/rpc.md` gained a `rand_status` block** documenting the four sync fields. Tasks 3 and 6
  **append** to it and to the Errors table; nothing in this plan rewrites what fix-sync-stall wrote.

Scope is unchanged: the same six tasks, the same rulings, with the two amendments named below.

**Goal:** Give the node the four read/serve capabilities a light wallet and an explorer need and a chain under load survives — a compact-block range read, a WebSocket `newHeads` subscription, JSON-RPC batch requests, and an admission path that refuses a known-bad transaction for free, rate-limits gossiped submissions per peer, and verifies proofs off the consensus event loop under gossipsub application-level validation — **without a hard fork**.

**Architecture:** Everything here is node-local. `rand_getCompactBlocks` derives its rows from the block store and the `notes` family already on disk — no new column family, so it answers on a database written by the current binary and needs no migration. Batching wraps the existing `dispatch`; the WebSocket lives in a new `src/ws.rs` served on the same axum router and fed by a `tokio::sync::broadcast` channel the node loop publishes one head into per committed block. The admission work splits `Mempool::insert` into a cheap `precheck` (pool conflicts + the state-dependent half of `Ledger::validate`) and an `insert_verified`, so the expensive half — the bundle and call proofs — can run on `tokio::task::spawn_blocking` against an `Arc<Ledger>` snapshot while the node loop keeps turning; the verdict comes back on a channel, decides the gossipsub `MessageAcceptance`, and feeds a bounded refused-hash cache.

**Tech Stack:** Rust 1.98.1, tokio, axum 0.7.9 (+ its `ws` feature), libp2p 0.54 / libp2p-gossipsub 0.47, RocksDB. One new dev-dependency: `tokio-tungstenite` 0.24 (the version axum 0.7.9's `ws` feature already pulls in), for the WebSocket integration test's client side. No new runtime dependency.

**Spec:** `docs/rpc-comparison.md` §2 ("Where this node is behind, and why it matters for explorers and wallets") and §4 (the Monero/Zcash table's *subscriptions* and *note stream* rows), plus `AGENTS.md` → "Open follow-ups" → the consensus-loop bullet, which is the S1 final review's item I2. `docs/rpc.md` is the reference the result must match.

## Global Constraints

- **No hard fork.** Nothing in this plan may change block validity, the transaction wire format, the genesis hash, any consensus rule, or the gossip topic names / `GossipMessage` encoding. The result deploys onto the running **chain 8** fleet (18 validators) by rolling restart, with old and new binaries coexisting indefinitely.
- **Do not change `ValidationMode::Permissive`** in `crates/randprotocol-node/src/network/mod.rs:247` (it moved from :139 when fix-sync-stall added the wire constants above it). A Strict/Permissive mix across a fleet drops messages. What this plan turns on is `ConfigBuilder::validate_messages()` — *application*-level validation, which is local to one node and invisible on the wire.
- **The sync wire is out of scope.** `network/codec.rs`, `SYNC_REQUEST_TIMEOUT`, `SYNC_MAX_WIRE_BYTES`, `SYNC_RESPONSE_WIRE_LIMIT`, `SYNC_REQUEST_WIRE_LIMIT`, `addr_scope` / `is_dialable_advertised_addr` and the `lan_peers` set are fix-sync-stall's, and nothing here reads or changes them. Task 5's only edit in `network/mod.rs` is the gossipsub `ConfigBuilder` (lines 245–250) and the `Event::Message` arm (486–493). Likewise the sync counters (`sync_failures`, `sync_late_batches`, `sync_inflight_age_ms`) are read-only to this plan: no task increments them, and no task adds a counter that shadows one.
- `validate_messages()` makes every delivered gossipsub message require exactly one `report_message_validation_result` call, or it is never forwarded by this node. **Every `NetworkEvent::Gossip` must be reported exactly once, on every path, including error paths.** Consensus and status messages are reported `Accept` immediately (that is today's behaviour); only transactions wait for a verdict.
- The gossipsub message cache holds an unvalidated message for `history_length` (5) heartbeats at a `heartbeat_interval` of 500 ms = **2.5 s**. A verdict later than that reports into nothing. Every queue size below is chosen against that budget.
- Tests: `cargo test --release -p randprotocol-node` for node-only work. **Per-task verification uses focused runs** (`--lib <filter>`, or one `--test <file>`); the full workspace suite is 466 tests / 22 min — measured *before* the proving slot below, so longer now — and proves real bundles. **The cluster suite (`--test cluster`) is run once, in the final task.** Never run the whole workspace suite mid-plan.
- **The proving slot, and what it costs.** Every proving test in the workspace takes one permit through a file lock at `<target-dir>/tmp/rand-proving-slot.lock` (`crates/randprotocol-node/tests/proving_slot/`, twinned in `crates/randprotocol-client/tests/proving_slot/`), so no two unrelated bundle proofs run at once — **across test binaries and across two sessions' concurrent `cargo test` runs**. Consequences for this plan:
  - The cluster suite is **17 tests / 19m59s measured 2026-09-13**, serialised, not the 16 / 6m28s this plan was written against. Task 6's single `--test cluster` run should be expected to take **~20 minutes plus whatever its new proof adds**, and must not be reported as hung before then.
  - **Do not start it while another session's `--test cluster` or `--test wallet_flow` holds the lock**: the two runs will not overlap their proofs, they will queue, and the wall time adds. Check first (`lsof <target-dir>/tmp/rand-proving-slot.lock`, or just ask) and wait.
  - Any new test in this plan that proves a real bundle must take the slot the same way the file's other proving tests do — `let _slot = proving_slot().await;` around the whole `wallet::send` / `submit` call, taken before the anchor is read and released after the commit. A test that proves without it breaks the bound for everyone else's tests, not just its own.
  - Everything else in this plan is FAST-paced or `--lib`, proves nothing, and needs no slot.
- **Memory, on a shared machine.** Before and after any release build or test run, check nothing has run away: `ps -eo rss= | awk '$1>8000000'` should print nothing (an 8 GB resident process is a runaway `rustc` or a leaked node). Other sessions share this machine.
- New RPC tests go at the bottom of `crates/randprotocol-node/src/rpc.rs`, in the existing style: `state_for(&gs)` / `chain()` fixtures and the `ok(&st, "rand_…", json!([…]))` / `call(…)` helpers.
- Error conventions are the existing ones (`docs/rpc.md` → Errors): `-32601` unknown method, `-32602` bad parameter, `-32000` rejected, `-32001` not found, `-32603` internal. **Amended 2026-09-13:** `-32600` is no longer new — fix-sync-stall added `RpcError::invalid_request` (rpc.rs:139) for a body that is oversized or not JSON at all, and it is the one code `docs/rpc.md`'s Errors table still does not list. This plan adds two *uses* of it (batch shape, notification), reuses the existing constructor, and Task 2's doc step adds the single row covering all three.
- Commit style from `git log`: a lowercase area prefix (`node: …`, `docs: …`), then a body that explains the *why*. One commit per task. Every commit message ends with:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UbMQFrbUmLvWA2PWWwTeZh
  ```
- TDD, every task: failing test first → run it and see it fail → minimal implementation → run the focused tests green → commit.

## Rulings made in this plan

| ruling | why | cost if wrong |
|---|---|---|
| `rand_getCompactBlocks` derives everything from `blocks` + `notes`; **no new column family** | a new family would be empty for every block already on chain-8 disks, so a rolling restart would serve holes until a resync. The `notes` family is dense, ordered by leaf index, and each row carries its `height` — one binary search plus a forward scan recovers the per-block slice exactly | a block's notes cost `O(log n)` gets instead of one; if the heights-are-monotone-in-index assumption ever broke, the scan would stop early (caught by the test that walks a three-block chain) |
| range cap `MAX_COMPACT_BLOCKS = 128` blocks per call | half the 256-block anchor window, so a wallet syncing forward never crosses more than one anchor window per call, and a 128-block reply of typical chain-8 blocks (3 bundles) is ~2 MB of JSON | a wallet pages twice as often as it could; raising it later is a one-constant change |
| the reply also stops after `MAX_PAGE` (1000) note rows, **but always returns at least one whole block** (the reply is a *response*, so `RPC_MAX_BODY_BYTES` does not bound it — these two caps are the only bound, and `randprotocol-client`'s flat 15 s `READ_TIMEOUT` for a small-bodied request is what a too-generous page would actually hit) | a block may hold up to ~800 mints (4 MiB / 5181 bytes), each with a 1380-byte envelope — a 128-block range of those is gigabytes. Row-capping bounds the reply; the always-one-block rule keeps a client able to make progress past a fat block | a client that assumes it got the range it asked for skips blocks — which is why the reply is truncated, never padded, and a client resumes from `last returned height + 1` |
| a block-level `commitments` array carries notes of that height no transaction of it accounts for | height 0's genesis deposits belong to no transaction, and it doubles as the safety net if per-transaction attribution ever desynchronises: leftover leaves still reach the wallet rather than vanishing | one always-empty array on every block above 0 |
| batch cap `MAX_BATCH = 20` | the batch is a request amplifier and `rand_getWitness` rebuilds the whole tree per call; 20 leaves room for the realistic batch (head + treeInfo + a commitments page + a nullifiers page = 4) without turning one POST into 20 full-tree rebuilds. It is the *request-count* bound only: `RPC_MAX_BODY_BYTES` (≈8.86 MB, rpc.rs:154) is the byte bound and is sized for **one** proof-carrying transaction, so a batch of 20 submissions is refused by the body limit — also `-32600`, from `rejection_error` — long before the count cap is reached | an explorer batching 50 reads gets `-32600` and splits; the body limit already caps bytes |
| **notifications are refused**, not silently dropped: a request object with no `id` member gets an error with `"id": null`, code `-32600` | every method here either reads (the answer is the point) or submits (a silently-dropped submission is an invisible wallet bug). Refusing also keeps `responses.len() == requests.len()`, which makes client-side batch correlation trivial | a spec-strict client sending notifications sees errors instead of silence — visible and diagnosable, which is the intent. `"id": null` *present* is still a normal request, exactly as today |
| WebSocket on the **same port**, upgrading on `GET /` and `GET /ws`; `POST /` stays JSON-RPC | one URL and one firewall rule for operators; `/ws` for clients that want it explicit | none; an operator wanting a separate port is not served, and no one asked |
| the socket serves **only** `rand_subscribe` / `rand_unsubscribe`; any other method on it is `-32601` | reads on the socket would need their own blocking-pool and per-connection concurrency discipline, and HTTP already serves them | a client that wants one transport for everything keeps two |
| `MAX_WS_CONNECTIONS = 64` per node, `MAX_WS_SUBSCRIPTIONS = 8` per connection, `WS_MAX_FRAME_BYTES = 64 KiB` | a chain-8 node serves one explorer and a handful of wallets; 64 sockets is two orders of magnitude of headroom and still a hard bound on an unauthenticated endpoint. Subscribe frames are ~100 bytes, so 64 KiB is generous | the 65th client is refused at upgrade with HTTP 503; raising it is one constant |
| backpressure: one `broadcast::channel(256)`, **a lagging subscriber is closed** (code 1008) rather than buffered | `broadcast` gives lag detection for free, and 256 absorbs a whole 100-block sync batch plus slack (13 min at 3 s blocks). A subscriber that cannot keep up is a client problem, and buffering it is how a node runs out of memory | a client on a bad link is disconnected and must reconnect and re-sync from `rand_getCompactBlocks` — which is the documented recovery |
| one notification **per committed block**, in order (a sync batch emits one per block) | a light wallet tracking heads must not silently skip heights; the 256-slot channel is sized for exactly this | a burst during sync; a client that lags through it is dropped and resyncs |
| refused cache: `REFUSED_CACHE_ENTRIES = 8192`, FIFO eviction, in memory only, **no new dependency** | the mempool holds 10 000, so the refused set is the same order of magnitude and a flood of distinct bad proofs cannot evict the live ones. ~8192 × ~160 B ≈ 1.3 MB. Recency ordering buys nothing here — a refused hash is looked up on arrival, not repeatedly — so FIFO, hand-rolled, beats pulling in an `lru` crate | a flood wider than 8192 distinct bad transactions re-verifies the oldest; the per-peer rate limit is the bound that actually holds |
| only **permanent** verdicts are cached (an explicit `is_permanent(&TxError)` allowlist, which now includes fix-sync-stall's `TransactionTooLarge(_)` — a byte length is a function of the bytes) | `UnknownAnchor`, `Spent`, `UnknownProgram`, `Staking(..)`, `Bridge(..)` are statements about *this node's state at this moment* — a node one block behind would poison itself against transactions that are about to be valid. The allowlist is the set of verdicts that are functions of the transaction bytes alone | caching too little costs a re-verification; caching too much loses a valid transaction until restart, which is why the allowlist is explicit and tested |
| per-peer gossip rate limit: token bucket, **burst 16, refill 4/s**, gossiped transactions only, keyed on the **forwarding** peer (`GossipId.propagation_source`) and held on `Peer` — **amended 2026-09-13** | the chain commits ~3 transactions per 3 s block, so 4/s per peer is well above any honest peer's share, and a burst of 16 covers a peer forwarding a block's worth at once. RPC submissions are *not* limited: they are the operator's own port, already bounded by `RPC_MAX_BODY_BYTES`. **Why the key changed:** the draft metered `NetworkEvent::Gossip.from`, and fix-sync-stall's `Peer` doc comment (node.rs:230) now states that `from` is the gossip *author* — a validator several hops away with no connection to us at all, which is exactly why `connected_peers` was added beside `peer_count`. Metering the author would bill one peer for what N forwarders relayed, would leave a flooding neighbour unmetered, and would grow a bucket for every peer whose messages we merely relay. `propagation_source` is a peer we hold an open connection to, which is the thing a rate limit can actually push back on | an honest peer in a genuine burst has a transaction Ignored (not Rejected, no penalty) and re-gossips it on the next heartbeat |
| verification off-loop: `MAX_VERIFY_IN_FLIGHT = 4` blocking tasks, `MAX_VERIFY_QUEUE = 64`; a full queue reports `Ignore` | 4 concurrent × ~20 ms warm keeps the blocking pool available for `rand_getWitness` and the storage reads that already use it; 64 queued × 20 ms / 4 = 320 ms worst-case wait, comfortably inside the 2.5 s gossipsub validation window | a flood past the queue is Ignored — not propagated, not penalised — which is the correct shed |
| the verification snapshot is an `Arc<Ledger>` refreshed **lazily**, when the tip's `(height, root)` has moved and a transaction is actually waiting | a clone per consensus message would cost a full ledger clone per vote; keyed on the tip this is at most one clone per block, and none at all on an idle chain | a transaction verified against a one-block-stale snapshot can get `UnknownProgram` for a program deployed in the block in between — transient, so not cached, and the peer re-gossips. Everything state-dependent that *can* go stale is re-checked by `precheck` on the live tip at insert time |
| `Reject` is reported for a permanent verdict even though **no peer-score parameters are installed** | `Reject` is the honest signal and costs nothing today (the P₄ penalty needs `with_peer_score`, which this node does not configure); it is the right thing already in place if scoring is ever turned on | none today |
| **proposal** (consensus-message) verification stays on the loop | a proposal is signed by a scheduled leader and paced by the block interval, so it is not the DoS vector; moving it would be a consensus-path change, which this plan is forbidden | the ~20 ms per bundle in a proposal still lands on the loop — the same as today, and named in "Out of scope" below |

## Out of scope / needs a fork

Nothing in this plan needs one, and these are the things that would:

- **Proof pruning and proof aggregation** (`docs/block-space.md`, the block-space memory): both change what a block carries, so both are hard forks. A compact-block read is the non-fork half of the same problem and is what this plan ships.
- **A fee-ordered mempool with a real fee market**: the fee floors are consensus (`gas::fee_floor`), so changing them forks. The pool's existing fee ordering is untouched here.
- **Gossipsub `ValidationMode::Strict`**: the AGENTS.md follow-up names it, but it is a wire-level change — a Strict node drops a Permissive node's messages — so it cannot be rolled out onto a live fleet without co-ordinated restart, and it is explicitly forbidden by this plan's constraints. Application-level validation gets the DoS property without the wire change.
- **Moving block-application proof verification off the loop**: `Ledger::apply_block` is the consensus rule; running it anywhere but synchronously in `on_proposal` changes when a vote is emitted. Out.

## Out of scope, pending the user's decision

Candidates from `docs/rpc-comparison.md` deliberately **not** in this plan. They are not forks — they are product decisions the user has not made:

- **Node-side viewing-key import for explorers** (`docs/rpc-comparison.md` §4, "Keys in the node" and "What RAND should borrow"): the Zcash `z_importviewingkey` equivalent. It breaks the "the node never holds a key" model, which is a stated property of this chain, not an oversight.
  **Decided 2026-09-14: built** on the `rpc-viewing` branch — `rand_importViewingKey` /
  `rand_getViewingNotes`, viewing keys only, in memory (never on disk), capped at 64 keys and
  10 000 scanned leaves per call, cleared at restart. The property is narrowed by an explicit
  operator decision, per key, per node; the RPC layer still has no type for a spend key.
- **`rand_checkTransaction(tx, key)`**, the Monero `check_tx_proof` shape for third-party payment proofs (§4). A `TxKey` already gives the capability client-side; the RPC would make it one call for an explorer — and would put a viewing key in a request body.
  **Decided 2026-09-14: built** on the `rpc-viewing` branch as `rand_checkTransaction(hash, key)`
  — stateless, one call, no key retention (nothing is imported or stored; unlike
  `rand_importViewingKey` the key is dropped with the request). It is a per-transaction `TxKey`
  in the body, never a party viewing key, so the request discloses exactly the one envelope that
  key already opens.
- **A mempool-aware `next_nonce` RPC** (`AGENTS.md` → Open follow-ups, the wallet's stale-nonce race on fast double-sends). Node-only and fork-free, but it is a wallet-protocol decision paired with a `randprotocol-client` change, and the user scoped this task to the four items above.

## File structure

```
crates/randprotocol-node/src/
  storage.rs      [edit] notes_in_heights(), first_note_at_or_after(), derived_note_count()  — reads only
  rpc.rs          [edit] MAX_COMPACT_BLOCKS/MAX_BATCH consts; compact_block_json(); head_summary();
                         rand_getCompactBlocks; batch-aware handle() *wrapping* the existing
                         Result<Json<_>, JsonRejection> -> (StatusCode, Json<Value>) shape and its
                         rejection_error path; RpcState.heads + .ws_conns; serve() merges the ws
                         routes and keeps the RPC_MAX_BODY_BYTES layer; NodeStatus gains ws_clients /
                         refused_cache / verify_queue beside the four sync fields; tests at the bottom
  ws.rs           [new]  the WebSocket half: upgrade handler, connection cap, per-connection
                         subscription table, broadcast fan-out, lag close. Kept out of rpc.rs
                         (1414 lines already, and worked on by parallel sessions)
  admission.rs    [new]  RefusedCache (FIFO, bounded), is_permanent(&TxError), TokenBucket +
                         PeerLimiter (policy only — the bucket lives on node.rs's Peer),
                         VerifySource / Verdict — the pure, unit-testable half
  mempool.rs      [edit] precheck() + insert_verified() split out of insert(); applies() shared
                         with still_applies()
  network/mod.rs  [edit] ConfigBuilder::validate_messages() at :245-250 only; NetworkEvent::Gossip
                         carries { message_id, propagation_source }; NetworkCommand::ReportValidation;
                         NetworkHandle::report_validation(). codec.rs, the SYNC_* wire limits and the
                         address filter are NOT touched.
  node.rs         [edit] heads broadcast sender; tip snapshot; verify queue + in-flight counter;
                         verdict channel in the select! (:486); report exactly once per gossip
                         message; Peer (:230) gains the token bucket; publish_status (:512) fills
                         the three new NodeStatus fields beside s.sync_failures
  lib.rs          [edit] `pub mod ws;` `mod admission;`
crates/randprotocol-node/tests/
  ws.rs           [new]  the WebSocket integration test: a real listener, a real tokio-tungstenite client
  cluster.rs      [edit] one compact-block assertion, preferably folded into the existing
                         two_validators_commit_and_shielded_transfer (:732) so the serialised
                         suite gains no thirteenth bundle proof; one refused-cache assertion on a
                         FAST chain. Anything that proves takes proving_slot().
Cargo.toml (workspace)      [edit] axum features = ["ws"]; tokio-tungstenite = "0.24" (dev)
crates/randprotocol-node/Cargo.toml [edit] tokio-tungstenite in [dev-dependencies]
docs/rpc.md                 [edit] the three new methods/notifications, the -32600 row, a Changelog section
docs/rpc-comparison.md      [edit] §2 "scheduled as an RPC hardening task" → done, with the shapes
docs/architecture.md        [edit] §8 mempool: the split admission path and gossip validation
AGENTS.md                   [edit] the consensus-loop follow-up rewritten to what shipped
README.md                   [edit] the Interfaces row: JSON-RPC over HTTP *and* WebSocket
```

---

### Task 1: `rand_getCompactBlocks`

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs` (read helpers, near `notes_from`, ~line 358)
- Modify: `crates/randprotocol-node/src/rpc.rs` (a const near `MAX_PAGE` at :26, a renderer near `block_json` at :334 — `envelope_json` is at :297 — and a dispatch arm after `rand_getNullifiers`, whose arm is at :531 inside `dispatch` at :465)
- Modify: `docs/rpc.md` (a method section after `rand_getNullifiers`)
- Test: `crates/randprotocol-node/src/storage.rs` `mod tests`, `crates/randprotocol-node/src/rpc.rs` `mod tests`

**Interfaces:**

```rust
// storage.rs — produces
/// The lowest leaf index whose row is at height >= `height`, or `notes_count()` if none is.
/// Binary search: the `notes` family is dense from zero and its rows' heights are non-decreasing
/// in index, because `commit` appends blocks in ascending height and `truncate_to` only deletes
/// a suffix.
fn first_note_at_or_after(&self, height: u64) -> Result<u64>;

/// Every leaf appended by blocks in `from_height..=to_height`, in tree order, at most `max_rows`
/// of them (truncated, never an error). One binary search, then a forward scan.
pub fn notes_in_heights(&self, from_height: u64, to_height: u64, max_rows: usize)
    -> Result<Vec<(u64, NoteRow)>>;

/// How many notes of a block's slice belong to `tx` beyond the ones it carries on the wire: the
/// deposit note the ledger derives for a `Withdraw`, and for a `BridgeAttest` the deposit it
/// derives from the attestation — none for a guardian-set rotation, which deposits nothing.
///
/// This is the count of `Ledger::derived_commitment` (randprotocol-core `ledger/staking.rs:161`), and the
/// two must stay in step: those are the only two actions that mint a note out of public words, and
/// `Mempool::claimed_commitments` reads the same function for the pool's conflict index. Applying
/// the attestation size cap before the decode mirrors it exactly; in a *committed* block both arms
/// always produced a note, since a transaction that could not derive one was refused by `validate`.
/// `Transaction::commitments()` deliberately omits both, and `commit` appends them immediately
/// after that transaction's own, so `tx.commitments().len() + derived_note_count(tx)` is exactly
/// the slice `tx` owns.
pub fn derived_note_count(tx: &Transaction) -> usize;

// rpc.rs — produces
/// The most blocks one `rand_getCompactBlocks` call may cover. Half the 256-block anchor
/// window, so a syncing wallet never crosses more than one window per call.
const MAX_COMPACT_BLOCKS: u64 = 128;
fn compact_block_json(b: &Block, notes: &[(u64, NoteRow)]) -> Value;
```

Result shape (documented in `docs/rpc.md`):

```json
[ { "height": 192, "hash": "63f6…08", "timestamp_ms": 1788000123456,
    "commitments": [],
    "transactions": [
      { "hash": "4f2c…e7",
        "commitments": [ { "index": 40, "cm": "2a9f…07",
          "envelope": { "kem_ct": "…", "to_receiver": "…", "to_sender": "…", "body": "…" } } ],
        "nullifiers": ["8c04…d1", "5e77…20"] } ] } ]
```

- [ ] **Step 1: Write the failing storage tests**

In `storage.rs`'s `mod tests` (use the `fixtures` this module already has — `genesis_with`, `alloc_note`, `bundle_tx`, `make_block`, `key`):

```rust
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
    let payout = ShieldedAddress { pk: [3; 8], kem_ek: vec![4; randprotocol_core::notes::KEM_EK_BYTES] };
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
    let _ = payout;
    // A plain transfer carries both its notes itself.
    let gs = fixtures::genesis_with(1, vec![]);
    let t = fixtures::bundle_tx(&gs.ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
    assert_eq!(derived_note_count(&t), 0);
    assert_eq!(t.commitments().len(), 2);
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `cargo test --release -p randprotocol-node --lib storage::tests::notes_in_heights storage::tests::derived_note`
Expected: FAIL — `no method named notes_in_heights`, `cannot find function derived_note_count`.

- [ ] **Step 3: Implement the storage helpers**

In `storage.rs`, beside `notes_from`:

```rust
fn first_note_at_or_after(&self, height: u64) -> Result<u64> {
    let count = self.notes_count()?;
    let (mut lo, mut hi) = (0u64, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let row = self.note(mid)?.ok_or_else(|| {
            StorageError::Corrupt(format!("notes family has a gap at index {mid}"))
        })?;
        if row.height >= height { hi = mid } else { lo = mid + 1 }
    }
    Ok(lo)
}

pub fn notes_in_heights(&self, from_height: u64, to_height: u64, max_rows: usize)
    -> Result<Vec<(u64, NoteRow)>>
{
    if from_height > to_height || max_rows == 0 {
        return Ok(Vec::new());
    }
    let start = self.first_note_at_or_after(from_height)?;
    let mode = IteratorMode::From(&height_key(start), rocksdb::Direction::Forward);
    let mut out = Vec::new();
    for item in self.db.iterator_cf(self.cf(CF_NOTES), mode) {
        if out.len() >= max_rows { break }
        let (k, v) = item?;
        let row: NoteRow = bincode::deserialize(&v)?;
        // Heights are non-decreasing in index, so the first row past the range ends the scan.
        if row.height > to_height { break }
        out.push((be_u64(k.as_ref(), "note key")?, row));
    }
    Ok(out)
}

pub fn derived_note_count(tx: &randprotocol_core::Transaction) -> usize {
    match &tx.action {
        Action::Withdraw { .. } => 1,
        // The size cap before the decode, exactly as `Ledger::derived_commitment` applies it.
        Action::BridgeAttest { attestation, .. } if attestation.len() > randprotocol_core::gas::MAX_ATTESTATION_BYTES => 0,
        Action::BridgeAttest { attestation, .. } => {
            usize::from(randprotocol_core::ledger::bridge_notes::attested_transfer(attestation).is_some())
        }
        _ => 0,
    }
}
```

(`derived_note_count` is a free function in the module, beside `created_notes`.)

- [ ] **Step 4: Run the storage tests green**

Run: `cargo test --release -p randprotocol-node --lib storage::tests::notes_in_heights storage::tests::derived_note`
Expected: PASS (2 tests).

- [ ] **Step 5: Write the failing RPC test**

At the bottom of `rpc.rs`'s `mod tests` (`chain()` gives genesis with 2 notes plus one block spending 2 and creating 2):

```rust
/// Everything a light wallet needs to trial-decrypt and track spends, per block, with no proof
/// bytes: the leaf index, the commitment, the envelope, and the nullifiers the transaction spent.
#[tokio::test]
async fn compact_blocks_carry_every_note_and_nullifier_per_transaction() {
    let (_d, st, _gs) = chain();
    let v = ok(&st, "rand_getCompactBlocks", json!([0, 1])).await;
    let blocks = v.as_array().unwrap();
    assert_eq!(blocks.len(), 2, "genesis and the one committed block");

    // Height 0 owns the genesis deposits, which belong to no transaction.
    assert_eq!(blocks[0]["height"], 0);
    assert_eq!(blocks[0]["transactions"], json!([]));
    let genesis_notes = blocks[0]["commitments"].as_array().unwrap();
    assert_eq!(genesis_notes.len(), 2);
    assert_eq!(genesis_notes[0]["index"], 0);

    let b1 = &blocks[1];
    let head = st.storage.block_by_height(1).unwrap().unwrap();
    assert_eq!(b1["hash"], head.hash().to_hex());
    assert_eq!(b1["timestamp_ms"], head.header.timestamp_ms);
    assert_eq!(b1["commitments"], json!([]), "every note of this block belongs to a transaction");
    let txs = b1["transactions"].as_array().unwrap();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0]["hash"], head.transactions[0].hash().to_hex());
    assert_eq!(txs[0]["nullifiers"], json!([word8_to_hex(&nf(1)), word8_to_hex(&nf(2))]));
    let cms = txs[0]["commitments"].as_array().unwrap();
    assert_eq!(cms.len(), 2);
    assert_eq!((&cms[0]["index"], &cms[0]["cm"]), (&json!(2), &json!(word8_to_hex(&cm(1)))));
    assert_eq!((&cms[1]["index"], &cms[1]["cm"]), (&json!(3), &json!(word8_to_hex(&cm(2)))));
    // The envelope goes out in its four hex parts, exactly as getCommitments serves it.
    assert!(cms[0]["envelope"]["kem_ct"].is_string());
    // And no proof bytes anywhere: that is the whole point of a compact block.
    let text = serde_json::to_string(&v).unwrap();
    assert!(!text.contains("proof"), "a compact block carries no proof: {}", &text[..200.min(text.len())]);
}

/// The range is clamped, not refused; a backwards range is a parameter error.
#[tokio::test]
async fn compact_blocks_clamp_the_range_and_stop_at_the_head() {
    let (_d, st, _gs) = chain();
    // Past the head: a short reply, never an error.
    let v = ok(&st, "rand_getCompactBlocks", json!([0, 99])).await;
    assert_eq!(v.as_array().unwrap().len(), 2);
    // A range longer than the cap is truncated to MAX_COMPACT_BLOCKS blocks, from `from_height`.
    let v = ok(&st, "rand_getCompactBlocks", json!([0, MAX_COMPACT_BLOCKS + 500])).await;
    assert_eq!(v.as_array().unwrap().len(), 2, "the head stops it first here");
    // Backwards is a parameter error, and so is a missing bound.
    assert_eq!(call(&st, "rand_getCompactBlocks", json!([1, 0])).await.unwrap_err().code, -32602);
    assert_eq!(call(&st, "rand_getCompactBlocks", json!([0])).await.unwrap_err().code, -32602);
    // A range that starts past the head is empty, not an error.
    assert_eq!(ok(&st, "rand_getCompactBlocks", json!([50, 60])).await, json!([]));
}
```

- [ ] **Step 6: Run it and see it fail**

Run: `cargo test --release -p randprotocol-node --lib rpc::tests::compact_blocks`
Expected: FAIL — `unknown method rand_getCompactBlocks` (the `ok` helper panics with that message).

- [ ] **Step 7: Implement the RPC method**

In `rpc.rs`, beside `MAX_PAGE`:

```rust
/// The most blocks one `rand_getCompactBlocks` call may cover. Half the 256-block anchor
/// window (`ledger::ANCHOR_WINDOW`), so a wallet syncing forward never crosses more than one
/// window per request.
const MAX_COMPACT_BLOCKS: u64 = 128;
```

Beside `block_json`:

```rust
/// One block as a light wallet reads it: the header fields it chains on, and per transaction
/// the notes it created (leaf index, commitment, envelope) and the nullifiers it spent. No
/// proof, no action, no receipt — those are `rand_getBlockByHeight`'s job.
///
/// `notes` is this block's slice of the tree in append order. Each transaction owns
/// `commitments().len() + derived_note_count()` of it, in the order `Storage::commit` appended
/// them; anything left over goes into the block-level `commitments`, which is where genesis
/// deposits live and where a future note the attribution does not know about would still surface
/// rather than disappear.
fn compact_block_json(b: &randprotocol_core::Block, notes: &[(u64, crate::storage::NoteRow)]) -> Value {
    let row = |(index, r): &(u64, crate::storage::NoteRow)| {
        json!({ "index": index, "cm": word8_to_hex(&r.cm), "envelope": envelope_json(&r.envelope) })
    };
    let mut at = 0usize;
    let mut txs = Vec::with_capacity(b.transactions.len());
    for tx in &b.transactions {
        let want = tx.commitments().len() + crate::storage::derived_note_count(tx);
        let end = (at + want).min(notes.len());
        txs.push(json!({
            "hash": tx.hash().to_hex(),
            "commitments": notes[at..end].iter().map(row).collect::<Vec<_>>(),
            "nullifiers": tx.nullifiers().iter().map(word8_to_hex).collect::<Vec<_>>(),
        }));
        at = end;
    }
    json!({
        "height": b.height(),
        "hash": b.hash().to_hex(),
        "timestamp_ms": b.header.timestamp_ms,
        "commitments": notes[at.min(notes.len())..].iter().map(row).collect::<Vec<_>>(),
        "transactions": txs,
    })
}
```

The dispatch arm, after `rand_getNullifiers`:

```rust
// A range of blocks with everything a light wallet needs and nothing it does not: the
// commitments each transaction created with their leaf indices and envelopes, and the
// nullifiers it spent. Zcash's `CompactBlock` by another name (`docs/rpc-comparison.md` §4),
// and the reason a sync is one round-trip per page instead of two per block.
"rand_getCompactBlocks" => {
    let from: u64 = param(p, 0, "from_height")?;
    let to: u64 = param(p, 1, "to_height")?;
    if to < from {
        return Err(RpcError::invalid_params(format!(
            "to_height {to} is below from_height {from}"
        )));
    }
    let to = to.min(from.saturating_add(MAX_COMPACT_BLOCKS - 1));
    let storage = st.storage.clone();
    // Reads every block in the range and scans a slice of the notes family: linear in the
    // range, so it goes on the blocking pool like the other unbounded reads here.
    let out = blocking(move || {
        let head = storage.head()?.height;
        let to = to.min(head);
        let mut rows: Vec<Value> = Vec::new();
        let mut emitted = 0usize;
        for h in from..=to {
            let Some(b) = storage.block_by_height(h)? else { break };
            // Always emit the first block whole, however many notes it holds, so a client
            // is never stuck behind one fat block; after that the page cap ends the reply.
            if !rows.is_empty() && emitted >= MAX_PAGE {
                break;
            }
            let notes = storage.notes_in_heights(h, h, usize::MAX)?;
            emitted += notes.len();
            rows.push(compact_block_json(&b, &notes));
        }
        Ok(rows)
    })
    .await?;
    Ok(json!(out))
}
```

Note `from > head` falls out of the `for h in from..=to` loop with `to = to.min(head) < from`, giving `[]`.

**Two things about size, both new since this plan was drafted:**

- `RPC_MAX_BODY_BYTES` (rpc.rs:154) and the `DefaultBodyLimit` layer in `serve` bound the *request*, not the reply. A `rand_getCompactBlocks` request is two integers, so it is nowhere near the limit and needs nothing from this task; `MAX_COMPACT_BLOCKS` and `MAX_PAGE` remain the only bound on the *reply*.
- What a too-generous reply actually hits is the client: `randprotocol-client`'s `RpcClient::call` gives a request under `UPLOAD_THRESHOLD` (64 KiB) the flat 15 s `READ_TIMEOUT`, and only an upload gets `upload_timeout`. A compact-block read is a small request with a large answer, so it has 15 s to be served end to end — which the 128-block / 1000-note caps sit comfortably inside, and which is the number to revisit before either cap is raised.

This method maps no `TxError`, so fix-sync-stall's new `TxError::TransactionTooLarge(usize)` does not reach it; the variant is Task 4's business (`is_permanent`).

- [ ] **Step 8: Run the RPC tests green**

Run: `cargo test --release -p randprotocol-node --lib rpc::tests::compact_blocks storage::tests::notes_in_heights storage::tests::derived_note`
Expected: PASS (4 tests).

- [ ] **Step 9: Document it in `docs/rpc.md`**

Add a `### rand_getCompactBlocks` section after `rand_getNullifiers`, carrying: the params (`[from_height, to_height]`, both required), the 128-block cap and the 1000-note early stop with the always-one-whole-block rule, the JSON shape above, the "resume from the last returned height + 1" instruction, the note that the block-level `commitments` array holds the genesis deposits at height 0 and is empty everywhere else, the note that a `Withdraw`'s and a `BridgeAttest`'s deposit notes appear under their transaction even though the wire does not carry their commitments, and the errors (`-32602` for a backwards range or a missing bound).

- [ ] **Step 10: Commit**

```bash
git add crates/randprotocol-node/src/storage.rs crates/randprotocol-node/src/rpc.rs docs/rpc.md
git commit -m "$(cat <<'EOF'
node: rand_getCompactBlocks, a one-round-trip note stream for light wallets

A wallet syncing this chain made two requests per page and then had to fetch
whole blocks to learn which transaction a note came from. This serves the
whole thing per block: every commitment with its leaf index and envelope,
every nullifier, grouped by the transaction that produced them, with no proof
bytes — Zcash's CompactBlock by another name.

It reads the blocks and the notes family it already has rather than a new
index, so it answers correctly on a database the current binary wrote and
needs no migration on the rolling restart. A block's slice of the tree is one
binary search plus a forward scan; each transaction owns commitments() plus
the deposit note the ledger derives for a Withdraw or a BridgeAttest, in the
order commit appended them, and anything left over — the genesis deposits at
height 0 — goes to the block itself rather than being dropped.

Capped at 128 blocks (half the anchor window) and, past the first block,
1000 notes, so one request cannot pull a fat block range into memory.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UbMQFrbUmLvWA2PWWwTeZh
EOF
)"
```

---

### Task 2: JSON-RPC batch requests

**Files:**
- Modify: `crates/randprotocol-node/src/rpc.rs` (`Request` at :119, `handle` at :194, `rejection_error` at :222, a const near `MAX_PAGE` at :26)
- Modify: `docs/rpc.md` (the intro line "batches are not supported" at :4, the Errors table at :382)
- Test: `crates/randprotocol-node/src/rpc.rs` `mod tests`

**What `handle` already is (changed since this plan was drafted).** fix-sync-stall gave it a
rejection path, and this task must keep every part of it:

```rust
async fn handle(
    State(st): State<RpcState>,
    req: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> (StatusCode, Json<Value>) { … }

fn rejection_error(rejection: &JsonRejection) -> RpcError   // -32600, names RPC_MAX_BODY_BYTES on a 413
```

So the batch work **wraps** it: the extractor becomes `Result<Json<Value>, JsonRejection>`, the
rejection arm and its non-`OK` status code are untouched, and only the `Ok` arm learns about arrays.
An oversized or non-JSON body keeps returning axum's status (413 / 400) with a `-32600` body; every
*parsed* body, batch or not, keeps returning `StatusCode::OK`.

**Interfaces:**

```rust
// rpc.rs — produces
/// The most request objects one batch may carry. The *byte* bound is RPC_MAX_BODY_BYTES, which is
/// sized for one proof-carrying transaction, so a batch of submissions is refused on size first.
const MAX_BATCH: usize = 20;
/// A request object's `id`. `None` is a *missing* `id` member — a JSON-RPC notification, which
/// this node refuses (see `docs/rpc.md`); `Some(Value::Null)` is an explicit null id and is a
/// normal request, as it has always been here. (Today `id` is `#[serde(default)] id: Value`;
/// keep `#[serde(default)]` on `params` and drop it from `id`.)
struct Request { jsonrpc: Option<String>, method: String, params: Value, id: Option<Value> }
fn error_value(id: Value, e: RpcError) -> Value;           // built from RpcError::invalid_request etc.
async fn dispatch_one(st: &RpcState, v: Value) -> Value;   // one request object -> one response object
```

- [ ] **Step 1: Write the failing tests**

`handle` is not reachable through the `call`/`ok` helpers (`state_for` at :865, `call` at :893, `ok` at :897, `chain` at :911 — they go straight to `dispatch`), so these tests drive the axum handler by calling it directly. **It returns `(StatusCode, Json<Value>)` and takes a `Result<Json<Value>, _>`**, so every call below destructures the tuple and wraps the body in `Ok(Json(…))`:

```rust
/// A JSON array of request objects comes back as an array of responses, in order, one per
/// request — including the errors, so a client can correlate by position as well as by id.
#[tokio::test]
async fn a_batch_answers_every_request_in_order() {
    let (_d, st, _gs) = chain();
    let (code, Json(v)) = handle(State(st.clone()), Ok(Json(json!([
        { "jsonrpc": "2.0", "id": 1, "method": "rand_chainId", "params": [] },
        { "jsonrpc": "2.0", "id": "two", "method": "rand_getTreeInfo", "params": [] },
        { "jsonrpc": "2.0", "id": 3, "method": "rand_nope", "params": [] }
    ])))).await;
    assert_eq!(code, StatusCode::OK, "a parsed body is always 200, errors inside it or not");
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!((&rows[0]["id"], &rows[0]["result"]), (&json!(1), &json!(st.chain_id)));
    assert_eq!(rows[1]["id"], json!("two"));
    assert_eq!(rows[1]["result"]["next_index"], 4);
    assert_eq!((&rows[2]["id"], &rows[2]["error"]["code"]), (&json!(3), &json!(-32601)));
    // A single request object still answers with a single object, exactly as before.
    let (_, Json(one)) = handle(State(st.clone()), Ok(Json(json!(
        { "jsonrpc": "2.0", "id": 9, "method": "rand_chainId", "params": [] }
    )))).await;
    assert_eq!(one["result"], json!(st.chain_id));
    assert!(one.get("error").is_none());
}

/// The three shapes a batch can get wrong, each a single error object rather than an array —
/// there is no per-request id to attach them to.
#[tokio::test]
async fn a_malformed_batch_is_one_invalid_request_error() {
    let (_d, st, _gs) = chain();
    let err = |v: Value| async { let (_, Json(r)) = handle(State(st.clone()), Ok(Json(v))).await; r };

    let empty = err(json!([])).await;
    assert_eq!(empty["error"]["code"], -32600);
    assert_eq!(empty["id"], Value::Null);

    let over: Vec<Value> = (0..=MAX_BATCH)
        .map(|i| json!({ "jsonrpc": "2.0", "id": i, "method": "rand_chainId", "params": [] }))
        .collect();
    let big = err(json!(over)).await;
    assert_eq!(big["error"]["code"], -32600);
    assert!(big["error"]["message"].as_str().unwrap().contains(&MAX_BATCH.to_string()));

    // Not an object and not an array.
    assert_eq!(err(json!("hello")).await["error"]["code"], -32600);
}

/// Notifications are refused rather than silently dropped: every request here either reads (the
/// answer is the point) or submits (a dropped submission is an invisible wallet bug), and
/// refusing keeps one response per request so a client can correlate by position.
#[tokio::test]
async fn a_notification_is_refused_with_a_null_id() {
    let (_d, st, _gs) = chain();
    let (_, Json(v)) = handle(State(st.clone()), Ok(Json(json!([
        { "jsonrpc": "2.0", "method": "rand_chainId", "params": [] },
        { "jsonrpc": "2.0", "id": null, "method": "rand_chainId", "params": [] }
    ])))).await;
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 2, "one response per request, notifications included");
    assert_eq!(rows[0]["error"]["code"], -32600);
    assert!(rows[0]["error"]["message"].as_str().unwrap().contains("notification"));
    assert_eq!(rows[0]["id"], Value::Null);
    // An explicit null id is a request, not a notification, and is answered as always.
    assert_eq!(rows[1]["result"], json!(st.chain_id));
}

/// A request object that does not deserialize at all still gets a response, with the id it
/// carried if it carried a readable one.
#[tokio::test]
async fn an_undecodable_request_object_still_gets_a_response() {
    let (_d, st, _gs) = chain();
    let (_, Json(v)) = handle(State(st.clone()), Ok(Json(json!([
        { "jsonrpc": "2.0", "id": 4 },                       // no method
        { "jsonrpc": "2.0", "id": 5, "method": 7 }            // method is not a string
    ])))).await;
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row["error"]["code"], -32600, "row {i}");
        assert_eq!(row["id"], json!(4 + i as u64), "the id is echoed even when nothing else parses");
    }
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `cargo test --release -p randprotocol-node --lib rpc::tests::a_batch rpc::tests::a_malformed rpc::tests::a_notification rpc::tests::an_undecodable`
Expected: FAIL to compile — `handle` takes `Result<Json<Request>, JsonRejection>`, not `Result<Json<Value>, _>`; `MAX_BATCH` is undefined.

There is also an existing test block at the bottom of `rpc.rs` (from :1497) whose subject is the
request body limit. **Leave it alone** — it exercises `RPC_MAX_BODY_BYTES` and `rejection_error`,
which this task must not change — and run it alongside the new ones as the regression that says the
rejection path survived.

- [ ] **Step 3: Implement batching**

In `rpc.rs`:

```rust
/// The most request objects one batch may carry. A batch is a request amplifier and
/// `rand_getWitness` rebuilds the whole commitment tree per call, so this is deliberately
/// small: the realistic batch is a head, a tree info and two pages, which is four.
const MAX_BATCH: usize = 20;
```

`Request.id` becomes `Option<Value>` (drop the `#[serde(default)]` on it; keep it on `params`), and:

```rust
/// One error response object. Built from an `RpcError` so every `-32600` in this file comes from
/// `RpcError::invalid_request` — including the oversized-body one `rejection_error` already makes.
fn error_value(id: Value, e: RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": e.code, "message": e.message } })
}

/// One request object in, one response object out. Every failure mode — an object that does not
/// deserialize, a notification, an unknown method — is a response, so a batch's replies always
/// line up one-for-one with its requests.
async fn dispatch_one(st: &RpcState, v: Value) -> Value {
    // Echo whatever id the object carried even if nothing else about it parses.
    let raw_id = v.get("id").cloned();
    let req: Request = match serde_json::from_value(v) {
        Ok(r) => r,
        Err(e) => {
            return error_value(raw_id.unwrap_or(Value::Null), RpcError::invalid_request(format!("invalid request: {e}")))
        }
    };
    let Some(id) = req.id.clone() else {
        return error_value(
            Value::Null,
            RpcError::invalid_request("this node does not accept notifications; every request must carry an id"),
        );
    };
    match dispatch(st, &req).await {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(e) => error_value(id, e),
    }
}

async fn handle(
    State(st): State<RpcState>,
    // Unchanged in shape from what fix-sync-stall left here, only `Request` -> `Value`: a body axum
    // refuses — over `RPC_MAX_BODY_BYTES`, or not JSON at all — must still come back as JSON-RPC
    // rather than plain text, with the status axum chose.
    req: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> (StatusCode, Json<Value>) {
    let body = match req {
        Err(rejection) => {
            return (rejection.status(), Json(error_value(Value::Null, rejection_error(&rejection))))
        }
        Ok(Json(body)) => body,
    };
    // Everything past here parsed, so the HTTP status is 200 and the errors are in the body.
    let out = match body {
        Value::Array(items) if items.is_empty() => {
            error_value(Value::Null, RpcError::invalid_request("invalid request: empty batch"))
        }
        Value::Array(items) if items.len() > MAX_BATCH => error_value(
            Value::Null,
            RpcError::invalid_request(format!(
                "batch of {} requests exceeds the limit of {MAX_BATCH}",
                items.len()
            )),
        ),
        // Sequential on purpose: a batch must not multiply this node's concurrency, and the
        // expensive reads inside already hand themselves to the blocking pool one at a time.
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(dispatch_one(&st, it).await);
            }
            Value::Array(out)
        }
        obj @ Value::Object(_) => dispatch_one(&st, obj).await,
        _ => error_value(
            Value::Null,
            RpcError::invalid_request("invalid request: expected an object or an array"),
        ),
    };
    (StatusCode::OK, Json(out))
}
```

`rejection_error` and `RPC_MAX_BODY_BYTES` are untouched: the byte bound on a batch is still the
body limit, which is sized for one proof-carrying transaction, so a batch of 20 `rand_sendTransaction`
calls is refused at the extractor with a 413 and a `-32600` body naming the limit — before
`MAX_BATCH` is ever consulted. That is the intended layering, and the doc step says so.

- [ ] **Step 4: Run the tests green**

Run: `cargo test --release -p randprotocol-node --lib rpc::tests`
Expected: PASS — the four new tests and every existing `rpc::tests` case (they call `dispatch` directly and are unaffected).

- [ ] **Step 5: Document it in `docs/rpc.md`**

Replace "One request per HTTP POST to `/`; batches are not supported." (docs/rpc.md:4) with a paragraph: a POST body may be one request object or an array of at most 20; the reply is an array of the same length, in request order; every element gets a response, errors included; notifications (a request object with no `id` member) are refused with `-32600` and a null id, and the reasoning; an explicit `"id": null` is a normal request. Say that the count cap is not the byte cap — the whole body is still bounded by the node's request-body limit, which is sized for a single proof-carrying transaction, so batching submissions does not work and batching reads is what this is for. Add a `curl` example of a two-request batch.

Add the `-32600` row to the Errors table (docs/rpc.md:382). **It is not there today** even though the code already returns it for an oversized or unparseable body, so write the row to cover all three uses: "invalid request — the body is over the size limit, is not JSON, is a malformed batch, or is a notification". Append the row; do not reorder or reword the five that fix-sync-stall and earlier work left there.

- [ ] **Step 6: Commit**

```bash
git add crates/randprotocol-node/src/rpc.rs docs/rpc.md
git commit -m "$(cat <<'EOF'
node: JSON-RPC batch requests

An explorer syncing this chain makes four reads per page — head, tree info,
commitments, nullifiers — and paid four round trips for them. A JSON array of
request objects now comes back as an array of responses in request order, one
per request, capped at 20: a batch is a request amplifier and getWitness
rebuilds the whole commitment tree per call, so the cap stays well under what
the body limit would otherwise allow.

Notifications are refused rather than dropped. Every method here either reads,
where the answer is the point, or submits, where a silently dropped request is
an invisible wallet bug — and refusing keeps one response per request, so a
client can correlate by position as well as by id. An explicit "id": null is
still a normal request, as it has always been.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UbMQFrbUmLvWA2PWWwTeZh
EOF
)"
```

---

### Task 3: WebSocket `newHeads` subscription

**Files:**
- Create: `crates/randprotocol-node/src/ws.rs`
- Create: `crates/randprotocol-node/tests/ws.rs`
- Modify: `Cargo.toml` (workspace: `axum` gains `features = ["ws"]`; add `tokio-tungstenite = "0.24"`), `crates/randprotocol-node/Cargo.toml` (dev-dependency)
- Modify: `crates/randprotocol-node/src/lib.rs` (`pub mod ws;`), `crates/randprotocol-node/src/rpc.rs` (`HeadSummary`, `head_summary`, `RpcState` at :110 gains `.heads`/`.ws_conns`, `serve` routes at :180, `NodeStatus.ws_clients` — added to the block at :38 that now also carries `sync_inflight_age_ms`, `sync_failures`, `sync_late_batches` and `connected_peers`), `crates/randprotocol-node/src/node.rs` (publish a head per committed block; build the channel; `publish_status` at :512 sets `ws_clients` beside `s.connected_peers`)
- Modify: `docs/rpc.md`
- Test: `crates/randprotocol-node/tests/ws.rs`

**Interfaces:**

```rust
// rpc.rs — produces
/// One committed head, as `rand_getHead` reports it. What a `newHeads` notification carries.
#[derive(Clone, Debug, Serialize)]
pub struct HeadSummary { pub height: u64, pub hash: String, pub view: u64 }

#[derive(Clone)]
pub struct RpcState {
    /* existing: storage, status, node, chain_id, executor */
    /// Committed heads, one per block, fanned out to WebSocket subscribers. Bounded: a
    /// subscriber that falls more than `HEAD_CHANNEL` behind is closed, not buffered.
    pub heads: tokio::sync::broadcast::Sender<HeadSummary>,
    /// Live WebSocket connections, against `ws::MAX_WS_CONNECTIONS`.
    pub ws_conns: Arc<std::sync::atomic::AtomicUsize>,
}
/// Slots in the head broadcast channel: a whole 100-block sync batch plus slack.
pub const HEAD_CHANNEL: usize = 256;

// ws.rs — produces
pub const MAX_WS_CONNECTIONS: usize = 64;
pub const MAX_WS_SUBSCRIPTIONS: usize = 8;
pub const WS_MAX_FRAME_BYTES: usize = 64 * 1024;
/// The upgrade handler. Mounted by `rpc::serve` on `GET /` and `GET /ws`.
pub async fn upgrade(State(st): State<RpcState>, ws: WebSocketUpgrade) -> axum::response::Response;
```

Wire shapes (documented in `docs/rpc.md`):

```jsonc
// client -> node
{ "jsonrpc": "2.0", "id": 1, "method": "rand_subscribe",   "params": ["newHeads"] }
{ "jsonrpc": "2.0", "id": 2, "method": "rand_unsubscribe", "params": ["1"] }
// node -> client
{ "jsonrpc": "2.0", "id": 1, "result": "1" }        // the subscription id, a decimal string
{ "jsonrpc": "2.0", "id": 2, "result": true }
{ "jsonrpc": "2.0", "method": "rand_subscription",
  "params": { "subscription": "1", "result": { "height": 1998, "hash": "…", "view": 2251 } } }
```

- [ ] **Step 1: Add the dependencies**

Workspace `Cargo.toml`: `axum = { version = "0.7", features = ["ws"] }`, and under `# test`: `tokio-tungstenite = "0.24"`.
`crates/randprotocol-node/Cargo.toml` `[dev-dependencies]`: `tokio-tungstenite = { workspace = true }`, `futures = { workspace = true }`.

Run: `cargo check --release -p randprotocol-node` — expected: clean (feature only, no code change yet).

- [ ] **Step 2: Write the failing integration test**

`crates/randprotocol-node/tests/ws.rs` — a real node on a real listener, a real WebSocket client:

```rust
//! The WebSocket half of the RPC: a real listener, a real client, and a head that arrives
//! without anyone polling for it.

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

mod common;   // reuse the cluster harness's genesis/keys helpers via a small shared module

/// Read frames until one satisfies `f`, or time out.
async fn wait_frame<S, T>(sock: &mut S, timeout: Duration, mut f: impl FnMut(Value) -> Option<T>) -> Option<T>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() { return None }
        match tokio::time::timeout(left, sock.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                if let Some(v) = serde_json::from_str::<Value>(&t).ok().and_then(&mut f) { return Some(v) }
            }
            Ok(Some(Ok(_))) => {}
            _ => return None,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscriber_is_pushed_every_committed_head() {
    let node = common::start_one_validator().await;   // FAST (150 ms) blocks, no proving
    let url = format!("ws://{}/ws", node.rpc_addr);
    let (mut sock, _) = tokio_tungstenite::connect_async(&url).await.expect("upgrade");

    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_subscribe", "params": ["newHeads"] }).to_string(),
    )).await.unwrap();
    let sub = wait_frame(&mut sock, Duration::from_secs(5), |v| {
        (v["id"] == json!(1)).then(|| v["result"].as_str().unwrap().to_string())
    }).await.expect("a subscription id");

    // Three heads arrive, strictly ascending, with the shape rand_getHead returns.
    let mut heights = Vec::new();
    while heights.len() < 3 {
        let h = wait_frame(&mut sock, Duration::from_secs(15), |v| {
            (v["method"] == json!("rand_subscription") && v["params"]["subscription"] == json!(sub.clone()))
                .then(|| v["params"]["result"].clone())
        }).await.expect("a head notification");
        assert!(h["hash"].as_str().unwrap().len() == 64);
        assert!(h["view"].is_u64());
        heights.push(h["height"].as_u64().unwrap());
    }
    assert!(heights.windows(2).all(|w| w[1] > w[0]), "heads ascend: {heights:?}");

    // Unsubscribing stops them: nothing more arrives in three block intervals.
    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 2, "method": "rand_unsubscribe", "params": [sub] }).to_string(),
    )).await.unwrap();
    assert_eq!(
        wait_frame(&mut sock, Duration::from_secs(2), |v| (v["id"] == json!(2)).then(|| v["result"].clone())).await,
        Some(json!(true))
    );
    assert!(
        wait_frame(&mut sock, Duration::from_millis(600), |v| {
            (v["method"] == json!("rand_subscription")).then_some(())
        }).await.is_none(),
        "an unsubscribed socket is quiet"
    );
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_socket_serves_only_subscribe_and_unsubscribe() {
    let node = common::start_one_validator().await;
    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{}/", node.rpc_addr))
        .await.expect("the bare path upgrades too");
    for (id, method, params) in [
        (1, "rand_getHead", json!([])),                 // a read: HTTP's job
        (2, "rand_subscribe", json!(["logs"])),          // an unknown topic
        (3, "rand_unsubscribe", json!(["99"])),          // an id this socket never held
    ] {
        sock.send(Message::Text(
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string(),
        )).await.unwrap();
    }
    let code = |id: u64| async move { /* read the reply with that id, return error.code or result */ };
    let first = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(1)).then(|| v.clone()))
        .await.expect("a reply");
    assert_eq!(first["error"]["code"], -32601, "reads stay on HTTP POST");
    let second = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(2)).then(|| v.clone()))
        .await.expect("a reply");
    assert_eq!(second["error"]["code"], -32602, "newHeads is the only topic");
    let third = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(3)).then(|| v.clone()))
        .await.expect("a reply");
    assert_eq!(third["result"], json!(false), "unsubscribing something you do not hold is false, not an error");
    let _ = code;
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_cap_refuses_the_sixty_fifth_socket() {
    let node = common::start_one_validator().await;
    let url = format!("ws://{}/ws", node.rpc_addr);
    let mut held = Vec::new();
    for i in 0..randprotocol_node::ws::MAX_WS_CONNECTIONS {
        held.push(tokio_tungstenite::connect_async(&url).await.unwrap_or_else(|e| panic!("socket {i}: {e}")).0);
    }
    assert!(tokio_tungstenite::connect_async(&url).await.is_err(), "the cap is a hard bound");
    // And the count is visible to an operator.
    assert_eq!(node.status.read().unwrap().ws_clients, randprotocol_node::ws::MAX_WS_CONNECTIONS);
    drop(held);
    node.shutdown().await;
}
```

`crates/randprotocol-node/tests/common/mod.rs` (new, small): `start_one_validator()` builds a one-validator `Genesis` with `FAST` (150 ms) blocks in a `tempfile::tempdir`, calls `node::start`, and returns the `NodeHandle`. Copy the shape of `cluster.rs`'s `genesis`/`start_node_at`; do **not** import `cluster.rs` (integration test binaries do not share modules).

- [ ] **Step 3: Run it and see it fail**

Run: `cargo test --release -p randprotocol-node --test ws`
Expected: FAIL to compile — `randprotocol_node::ws` does not exist; `NodeStatus` has no `ws_clients`.

(`NodeHandle` exposes `pub status: Arc<RwLock<NodeStatus>>` and `pub rpc_addr: SocketAddr`, which is
what the third test reads.)

- [ ] **Step 4: Implement the head channel and the socket**

`rpc.rs`:

```rust
/// Slots in the head broadcast channel. A 100-block sync batch fits with slack, and at 3 s
/// blocks 256 heads is thirteen minutes: a subscriber that falls further behind than that is
/// not going to catch up, and is closed rather than buffered.
pub const HEAD_CHANNEL: usize = 256;

#[derive(Clone, Debug, Serialize)]
pub struct HeadSummary { pub height: u64, pub hash: String, pub view: u64 }

/// The head as `rand_getHead` reports it — one function, so the RPC and the subscription can
/// never drift apart.
pub fn head_summary(storage: &Storage, status: &RwLock<NodeStatus>) -> crate::storage::Result<HeadSummary> {
    let head = storage.head()?;
    let view = status.read().unwrap_or_else(|e| e.into_inner()).view;
    Ok(HeadSummary { height: head.height, hash: head.hash.to_hex(), view })
}
```

`rand_getHead`'s arm (rpc.rs:717, today `json!({ "height", "hash", "view" })` built inline from
`storage.head()` and `status.view`) becomes
`Ok(serde_json::to_value(head_summary(&st.storage, &st.status).map_err(RpcError::internal)?).map_err(RpcError::internal)?)`
— same three fields, same order, so no client sees a change. `NodeStatus` gains `pub ws_clients:
usize`, written into the field block at rpc.rs:38 **after** `connected_peers`, with a doc comment in
the style fix-sync-stall used for the sync fields (those four are `Serialize`d into `rand_status`,
so an added field is an added key and nothing else).

`serve` merges the routes, **keeping the derived body limit**:

```rust
let app = Router::new()
    .route("/", post(handle).get(crate::ws::upgrade))
    .route("/ws", axum::routing::get(crate::ws::upgrade))
    // RPC_MAX_BODY_BYTES, unchanged — it bounds the POST. A WebSocket upgrade is a GET with no
    // body, so the layer costs it nothing; frames are bounded by WS_MAX_FRAME_BYTES instead.
    .layer(axum::extract::DefaultBodyLimit::max(RPC_MAX_BODY_BYTES))
    .with_state(state);
```

`ws.rs`:

```rust
//! The WebSocket half of the RPC: a `newHeads` subscription, so an explorer or a wallet stops
//! polling `rand_getHead`.
//!
//! Three bounds hold this endpoint, because it is unauthenticated: a per-node connection cap, a
//! per-connection subscription cap, and a bounded broadcast channel whose lagging receivers are
//! *closed* rather than buffered. Buffering a slow subscriber is how a node runs out of memory;
//! a dropped one reconnects and resyncs from `rand_getCompactBlocks`, which is the documented
//! recovery.

pub const MAX_WS_CONNECTIONS: usize = 64;
pub const MAX_WS_SUBSCRIPTIONS: usize = 8;
pub const WS_MAX_FRAME_BYTES: usize = 64 * 1024;
/// WebSocket close code 1008 "policy violation": what a subscriber that could not keep up is
/// closed with, so the reason reaches the client rather than looking like a dropped TCP link.
const CLOSE_POLICY: u16 = 1008;

pub async fn upgrade(State(st): State<RpcState>, ws: WebSocketUpgrade) -> Response {
    // Claim a slot before upgrading: an upgrade the node then closes looks like a network fault
    // to the client, while a 503 says exactly what happened.
    let prev = st.ws_conns.fetch_update(SeqCst, SeqCst, |n| (n < MAX_WS_CONNECTIONS).then_some(n + 1));
    if prev.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE,
                format!("this node serves at most {MAX_WS_CONNECTIONS} websocket clients")).into_response();
    }
    ws.max_message_size(WS_MAX_FRAME_BYTES)
      .max_frame_size(WS_MAX_FRAME_BYTES)
      .on_upgrade(move |socket| run(socket, st))
}

async fn run(mut socket: WebSocket, st: RpcState) {
    let mut heads = st.heads.subscribe();
    // subscription id -> topic. One topic today; the map is what makes unsubscribe a lookup
    // rather than a boolean, and what the per-connection cap counts.
    let mut subs: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut next_id = 1u64;
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                let Message::Text(text) = msg else { continue };   // pings are answered by axum
                let reply = on_request(&text, &mut subs, &mut next_id);
                if socket.send(Message::Text(reply)).await.is_err() { break }
            }
            head = heads.recv() => match head {
                Ok(h) => {
                    for id in subs.keys() {
                        let frame = json!({ "jsonrpc": "2.0", "method": "rand_subscription",
                                            "params": { "subscription": id, "result": h } }).to_string();
                        if socket.send(Message::Text(frame)).await.is_err() { return cleanup(&st) }
                    }
                }
                // The subscriber missed `n` heads: it cannot be made whole from here, and
                // buffering it is what this cap exists to prevent.
                Err(RecvError::Lagged(n)) => {
                    tracing::debug!("closing a websocket subscriber that fell {n} heads behind");
                    let _ = socket.send(Message::Close(Some(CloseFrame {
                        code: CLOSE_POLICY,
                        reason: format!("subscriber fell {n} heads behind").into(),
                    }))).await;
                    break;
                }
                Err(RecvError::Closed) => break,
            }
        }
    }
    cleanup(&st);
}

fn cleanup(st: &RpcState) { st.ws_conns.fetch_sub(1, SeqCst); }
```

`on_request` parses one text frame into a `Request` (reusing `rpc::Request` shape via `serde_json::from_str::<Value>`), then:
- `rand_subscribe` with `params[0] == "newHeads"` → if `subs.len() >= MAX_WS_SUBSCRIPTIONS` reply `-32000` "at most 8 subscriptions per connection"; else allocate `next_id.to_string()`, insert, reply `result: "<id>"`.
- `rand_subscribe` with any other topic → `-32602` `"unknown subscription topic <x>; this node serves newHeads"`.
- `rand_unsubscribe` with `params[0]` a string → `result: subs.remove(&id).is_some()` (a bool, `false` for one this socket never held — not an error, which is what Ethereum clients expect).
- anything else → `-32601` `"the websocket serves rand_subscribe and rand_unsubscribe; reads go to POST /"`.
- an unparseable frame or a notification → `-32600`, as on HTTP.

`node.rs`: build the channel in `start` (`let (heads, _) = tokio::sync::broadcast::channel(rpc::HEAD_CHANNEL);`), put the sender and an `Arc<AtomicUsize>` into `RpcState`, keep both on `Node`, and publish in exactly the two places a block becomes committed — at the end of `Node::commit` and at the end of `apply_synced`, after `storage.commit` has succeeded:

```rust
/// One notification per committed block, in order — a light wallet tracking heads must not
/// silently skip heights. `send` fails only when nobody is subscribed, which is the normal case.
fn publish_heads(&self, blocks: &[CommittedBlock]) {
    for cb in blocks {
        let _ = self.heads.send(rpc::HeadSummary {
            height: cb.block.height(),
            hash: cb.block.hash().to_hex(),
            view: cb.block.view(),
        });
    }
}
```

and `publish_status` (node.rs:512) sets `s.ws_clients = self.ws_conns.load(SeqCst);` in the same run of assignments as `s.connected_peers` and `s.sync_failures` — one place fills the whole status, and the three fields this plan adds belong beside the four fix-sync-stall added, not in a second pass.

- [ ] **Step 5: Run the integration test green**

Run: `cargo test --release -p randprotocol-node --test ws`
Expected: PASS (3 tests). These run on 150 ms blocks and prove nothing, so the whole file is seconds, not minutes.

- [ ] **Step 6: Check nothing else broke**

Run: `cargo test --release -p randprotocol-node --lib`
Expected: PASS — `rpc::tests` compiles against the new `RpcState` fields (add `heads`/`ws_conns` to the `state_for` fixture at rpc.rs:865). Task 2's batch tests and the body-limit block at :1497 both go through `handle`, so they are the check that the route merge did not disturb the POST path.

- [ ] **Step 7: Document it in `docs/rpc.md`**

New section `## Subscriptions (WebSocket)` after the methods: the endpoint (`ws://host:8545/` or `/ws`, same port as HTTP), the three frame shapes above, that `newHeads` is the only topic and its payload is exactly `rand_getHead`'s, one notification per committed block including during sync, the caps (64 connections per node — the 65th gets HTTP 503 —, 8 subscriptions per connection, 64 KiB frames), and the backpressure rule: a subscriber that falls more than 256 heads behind is closed with code 1008 and a reason, and should reconnect and catch up with `rand_getCompactBlocks`. **Append** `ws_clients` to the `rand_status` example object and add one line for it after the four sync bullets fix-sync-stall wrote (`sync_inflight_age_ms`, `sync_failures`, `sync_late_batches`, `connected_peers`) — do not rewrite that block, and do not drop the new keys from the example.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/randprotocol-node/Cargo.toml crates/randprotocol-node/src/ws.rs \
        crates/randprotocol-node/src/lib.rs crates/randprotocol-node/src/rpc.rs crates/randprotocol-node/src/node.rs \
        crates/randprotocol-node/tests/ws.rs crates/randprotocol-node/tests/common/mod.rs docs/rpc.md
git commit -m "$(cat <<'EOF'
node: WebSocket newHeads subscription

Everything watching this chain polled rand_getHead — the explorer, every
wallet waiting on a commit, the deploy scripts. A JSON-RPC subscribe over a
WebSocket on the same port now pushes the same head summary once per committed
block instead, sync batches included, so nothing has to guess an interval.

The endpoint is unauthenticated, so it is bounded three ways: 64 connections
per node (the 65th gets a 503 at upgrade, not a silent close), 8 subscriptions
per connection, and a 256-slot broadcast channel whose lagging receivers are
closed with 1008 and a reason rather than buffered. Buffering a slow subscriber
is how a node runs out of memory; a closed one reconnects and catches up with
rand_getCompactBlocks.

Reads stay on POST: the socket answers rand_subscribe and
rand_unsubscribe and -32601 for anything else, because serving reads there
would need its own blocking-pool and concurrency discipline for no gain.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UbMQFrbUmLvWA2PWWwTeZh
EOF
)"
```

---

### Task 4: The refused-hash cache and the per-peer rate limit

**Files:**
- Create: `crates/randprotocol-node/src/admission.rs`
- Modify: `crates/randprotocol-node/src/mempool.rs` (split `insert` at :136; `still_applies` is at :227, `claimed_commitments` at :97, `claimed_nonce` at :59), `crates/randprotocol-node/src/lib.rs` (`mod admission;`)
- Test: `crates/randprotocol-node/src/admission.rs` `mod tests`, `crates/randprotocol-node/src/mempool.rs` `mod tests`

This task ships the two pure, unit-testable pieces and the mempool split they need. Task 5 wires them into the loop.

**Two things review-followups and fix-sync-stall changed here, both of which this task must respect:**

- `claimed_commitments` (mempool.rs:97) now asks `Ledger::derived_commitment` for a `BridgeAttest`'s
  deposit as well as a `Withdraw`'s, which is why it takes `&dyn ConfidentialExecutor`. `precheck`
  keeps that argument and keeps returning the claimed commitments, so the caller never recomputes
  either derivation. `candidates_within` (mempool.rs:202), which now continues past an oversized
  candidate, is not touched by this split.
- **The per-peer bucket does not get its own map.** `Node::peers` is already
  `HashMap<PeerId, Peer>` (node.rs:203/230) and `PeerDisconnected` already removes the entry, so the
  bucket is a field on `Peer` and `PeerLimiter` keeps only the policy. That is why there is no
  `PeerLimiter::forget` below: there is nothing for it to forget.

**Interfaces:**

```rust
// admission.rs — produces
/// Transaction hashes whose verification already failed for a reason that is a statement about
/// the transaction's bytes, not about this node's state. Bounded and FIFO: a refused hash is
/// looked up once, on arrival, so recency ordering buys nothing an insertion order does not.
pub struct RefusedCache { seen: HashMap<Hash, TxError>, order: VecDeque<Hash>, cap: usize }
impl RefusedCache {
    pub fn new(cap: usize) -> RefusedCache;
    pub fn get(&self, h: &Hash) -> Option<&TxError>;
    /// No-op for a verdict `is_permanent` refuses, so a caller cannot poison the cache by
    /// forwarding the wrong error.
    pub fn insert(&mut self, h: Hash, e: TxError);
    pub fn len(&self) -> usize;
}

/// Is this verdict a function of the transaction's bytes alone?
///
/// `UnknownAnchor`, `TimeOutOfWindow`, `Spent`, `CommitmentExists`, `UnknownProgram`,
/// `MinterNotValidator`, `Bridge`, `AttestAssetMismatch`, `Staking` and `UnknownProposer` are
/// all statements about *this node's state at this moment*: a node one block behind would
/// otherwise poison itself against transactions that are about to be valid.
pub fn is_permanent(e: &TxError) -> bool;

/// One peer's allowance. Lives on `node::Peer`, which the node already keys by `PeerId` and already
/// drops on `PeerDisconnected` — so this type holds no peer id, no map and no lifetime rule of its
/// own. `None` for the tokens means "not yet used": a fresh bucket starts full.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokenBucket { tokens: Option<f64>, last: Option<Instant> }

/// The policy over those buckets: a token bucket on gossiped transaction submissions, metered
/// against the peer that **forwarded** the message (`GossipId.propagation_source`), never the peer
/// that authored it — `NetworkEvent::Gossip.from` is the author and may be a peer we hold no
/// connection to at all (see `node::Peer`'s doc comment, and `connected_peers` in `rand_status`).
/// RPC submissions are not metered: that port is the operator's own and is bounded by
/// `rpc::RPC_MAX_BODY_BYTES`.
pub struct PeerLimiter { burst: f64, per_sec: f64 }
impl PeerLimiter {
    pub fn new(burst: u32, per_sec: f64) -> PeerLimiter;
    /// Spend one token from `bucket`, refilling it first. `false` means "over the limit right now".
    pub fn allow(&self, bucket: &mut TokenBucket, now: Instant) -> bool;
}

pub const REFUSED_CACHE_ENTRIES: usize = 8192;
pub const PEER_TX_BURST: u32 = 16;
pub const PEER_TX_PER_SEC: f64 = 4.0;

// mempool.rs — produces
impl Mempool {
    /// Everything `insert` decides without verifying a proof: pool conflicts, capacity, and the
    /// state-dependent half of `Ledger::validate` (anchor, time, nullifiers, commitments,
    /// attestation digests, the register nonce). Returns the commitments the transaction claims —
    /// including the note the ledger would derive for a `Withdraw` **or a `BridgeAttest`**, which is
    /// why the executor is a parameter — so the caller never recomputes either. Safe to run twice:
    /// once before a verification is scheduled, once against the tip it will actually be pooled on.
    pub fn precheck(&self, tx: &Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor)
        -> Result<Vec<Word8>, MempoolError>;
    /// Insert a transaction whose proof has already been verified. Re-runs `precheck`, because
    /// the tip has moved since the verification was scheduled.
    pub fn insert_verified(&mut self, tx: Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor)
        -> Result<Hash, MempoolError>;
    /* insert() keeps its signature and becomes precheck + ledger.validate + admit */
}
```

- [ ] **Step 1: Write the failing `admission.rs` tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash { Hash::digest(&[n]) }

    #[test]
    fn the_refused_cache_is_bounded_and_evicts_oldest_first() {
        let mut c = RefusedCache::new(3);
        for n in 0..3 { c.insert(h(n), TxError::BadDigest) }
        assert_eq!(c.len(), 3);
        assert!(c.get(&h(0)).is_some());
        c.insert(h(3), TxError::BadDigest);
        assert_eq!(c.len(), 3, "the cap holds");
        assert!(c.get(&h(0)).is_none(), "the oldest went first");
        assert!(c.get(&h(3)).is_some());
        // Re-inserting a hash already held does not grow the queue.
        c.insert(h(3), TxError::BadDigest);
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn only_a_verdict_about_the_bytes_is_cached() {
        // A bad proof is a bad proof on every node forever.
        for e in [
            TxError::BadDigest,
            TxError::InvalidProof(ConfidentialError::BadProof),
            TxError::InvalidBundleProof(ConfidentialError::BadProof),
            TxError::BadMintSignature,
            TxError::ProofTooLarge,
            TxError::EnvelopeTooLarge,
            TxError::TransactionTooLarge(9_000_000),
            TxError::DuplicateNullifierInBundle,
            TxError::WrongChain { expected: 7, actual: 8 },
        ] {
            assert!(is_permanent(&e), "{e} is a statement about the bytes");
        }
        // These are statements about this node's state right now. A node one block behind that
        // cached them would refuse transactions that are about to be valid — for good, since
        // nothing evicts on a state change.
        for e in [
            TxError::UnknownAnchor,
            TxError::TimeOutOfWindow { time: 3, height: 900 },
            TxError::Spent([1; 8]),
            TxError::CommitmentExists([2; 8]),
            TxError::UnknownProgram(Hash::ZERO),
            TxError::MinterNotValidator(Address([3; 32])),
        ] {
            assert!(!is_permanent(&e), "{e} depends on state and must not be cached");
        }
        // And the cache itself refuses one, so a wrong caller cannot poison it.
        let mut c = RefusedCache::new(4);
        c.insert(h(1), TxError::UnknownAnchor);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn the_peer_limiter_allows_a_burst_then_refills() {
        let l = PeerLimiter::new(4, 2.0);
        let mut b = TokenBucket::default();
        let t0 = Instant::now();
        for i in 0..4 { assert!(l.allow(&mut b, t0), "burst {i}") }
        assert!(!l.allow(&mut b, t0), "the bucket is empty");
        // Half a second at 2/s is one token.
        assert!(l.allow(&mut b, t0 + Duration::from_millis(500)));
        assert!(!l.allow(&mut b, t0 + Duration::from_millis(500)));
        // It never refills past the burst.
        assert!(l.allow(&mut b, t0 + Duration::from_secs(60)));
        for _ in 0..3 { assert!(l.allow(&mut b, t0 + Duration::from_secs(60))) }
        assert!(!l.allow(&mut b, t0 + Duration::from_secs(60)), "burst is the ceiling");
        // Buckets are per peer because the *peer table* is: a second peer's bucket is a second
        // `TokenBucket` on a second `node::Peer`, and a disconnected peer's goes with the entry.
        let mut other = TokenBucket::default();
        assert!(l.allow(&mut other, t0 + Duration::from_secs(60)), "an untouched bucket starts full");
        assert!(l.allow(&mut TokenBucket::default(), t0), "and so does a fresh one at any time");
    }
}
```

- [ ] **Step 2: Run and see them fail**

Run: `cargo test --release -p randprotocol-node --lib admission::`
Expected: FAIL — `file not found for module admission` / unresolved names.

- [ ] **Step 3: Implement `admission.rs`**

Straight implementations of the three types above. `RefusedCache::insert` returns early when `!is_permanent(&e)`; on eviction it pops `order.front()` and removes it from `seen`; on a repeat insert of a hash already in `seen` it replaces the error and leaves `order` alone. `PeerLimiter::allow` treats an unused bucket as full (`tokens.unwrap_or(burst)`), refills `min(burst, tokens + elapsed_secs * per_sec)` before spending 1.0, and writes the new tokens and `now` back into the bucket. It holds no state itself, so a `&self` receiver is enough.

`is_permanent` is an explicit `matches!` allowlist:

```rust
pub fn is_permanent(e: &TxError) -> bool {
    matches!(
        e,
        TxError::InvalidProof(_)
            | TxError::InvalidBundleProof(_)
            | TxError::BadDigest
            | TxError::BadMintSignature
            | TxError::BadProgram(_)
            | TxError::WrongChain { .. }
            | TxError::MissingBundle
            | TxError::ActionCarriesBundle(_)
            | TxError::EnvelopeTooLarge
            | TxError::ProofTooLarge
            | TxError::AttestationTooLarge
            // fix-sync-stall's: the whole transaction is bigger than a block. A byte length is a
            // function of the bytes, and `validate` refuses it at step 1 before anything about
            // this node's state is consulted, so it is as permanent as a size cap gets.
            | TxError::TransactionTooLarge(_)
            | TxError::ProgramTooLarge
            | TxError::DuplicateNullifierInBundle
            | TxError::DuplicateCommitmentInBundle
            | TxError::BurnAssetMismatch { .. }
            | TxError::BurnAssetBundleFee(_)
            | TxError::BurnAmountMismatch { .. }
            | TxError::BridgeRecipientMismatch
    )
}
```

Every arm is a function of the transaction's own bytes: the chain id is a per-chain constant, the sizes are byte lengths, the digest and the proofs are over the transaction's own fields, and a burn's asset-bundle arithmetic is entirely within the transaction. Anything not listed is state.

- [ ] **Step 4: Run them green**

Run: `cargo test --release -p randprotocol-node --lib admission::`
Expected: PASS (3 tests).

- [ ] **Step 5: Write the failing mempool split test**

```rust
/// The split the off-loop verification needs: `precheck` decides everything that does not cost
/// a proof verification, and `insert_verified` does the rest without paying for one. Together
/// they must accept and reject exactly what `insert` does.
#[test]
fn precheck_and_insert_verified_agree_with_insert() {
    let gs = fixtures::genesis_with(1, vec![alloc_note(20, 5 * UNITS_PER_RAND)]);
    let ledger = gs.ledger.clone();
    let tx = fixtures::bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());

    let mut a = Mempool::new(10);
    let mut b = Mempool::new(10);
    assert!(a.precheck(&tx, &ledger, &StubExecutor).is_ok());
    let via_split = b.insert_verified(tx.clone(), &ledger, &StubExecutor).unwrap();
    let via_insert = a.insert(tx.clone(), &ledger, &StubExecutor).unwrap();
    assert_eq!(via_split, via_insert);
    assert_eq!((a.len(), b.len()), (1, 1));

    // A duplicate is refused by both halves, with the same error.
    assert_eq!(b.precheck(&tx, &ledger, &StubExecutor).unwrap_err(), MempoolError::Duplicate);
    assert_eq!(b.insert_verified(tx.clone(), &ledger, &StubExecutor).unwrap_err(), MempoolError::Duplicate);

    // And a state change between the precheck and the insert is caught at the insert: this is
    // the race the off-loop verification opens, and re-running precheck is what closes it.
    let mut moved = ledger.clone();
    moved.insert_nullifier_for_testing([1; 8]);
    let mut c = Mempool::new(10);
    assert!(c.precheck(&tx, &ledger, &StubExecutor).is_ok(), "fine against the tip it was scheduled on");
    assert_eq!(
        c.insert_verified(tx, &moved, &StubExecutor).unwrap_err(),
        MempoolError::Invalid(TxError::Spent([1; 8])),
        "and refused against the tip it would be pooled on"
    );
}

/// `precheck` must refuse a stale anchor without ever reaching a proof — that is the whole
/// point of the split.
#[test]
fn precheck_refuses_a_stale_anchor_before_any_proof_work() {
    let gs = fixtures::genesis_with(1, vec![alloc_note(20, 5 * UNITS_PER_RAND)]);
    let ledger = gs.ledger.clone();
    let mut tx = fixtures::bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
    tx.bundle.as_mut().unwrap().anchor = [0xdead; 8];
    let pool = Mempool::new(10);
    assert_eq!(
        pool.precheck(&tx, &ledger, &StubExecutor).unwrap_err(),
        MempoolError::Invalid(TxError::UnknownAnchor)
    );
}
```

(If `insert_nullifier_for_testing` does not exist, add a `#[cfg(any(test, feature = "..."))]`-free `pub fn insert_nullifier_for_testing` beside `Storage::overwrite_validator_for_testing`'s equivalent on `Ledger`, or build the moved ledger by applying a block — whichever the crate already does. Confirm with `cargo check --release -p randprotocol-core` before writing the implementation.)

- [ ] **Step 6: Run and see them fail**

Run: `cargo test --release -p randprotocol-node --lib mempool::tests::precheck`
Expected: FAIL — `no method named precheck` / `insert_verified`.

- [ ] **Step 7: Implement the split**

In `mempool.rs`, factor the body of `insert`:

```rust
/// The staleness half of `Ledger::validate`, over the fields a `Pooled` already holds. Shared by
/// `precheck` (before a transaction is pooled) and `still_applies` (after), because they ask the
/// same question a block apart.
fn applies(tx: &Transaction, commitments: &[Word8], claim: Option<(Address, u64)>, ledger: &Ledger)
    -> Result<(), TxError>
{ /* the body of today's still_applies, returning the TxError each check stands for:
     UnknownAnchor, TimeOutOfWindow, Spent, CommitmentExists, Bridge(AttestationSpent),
     AttestAssetMismatch, Staking(BadNonce) */ }

fn still_applies(p: &Pooled, ledger: &Ledger) -> bool {
    Self::applies(&p.tx, &p.commitments, p.claim, ledger).is_ok()
}

pub fn precheck(&self, tx: &Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor)
    -> Result<Vec<Word8>, MempoolError>
{ /* today's insert() body down to (but not including) `ledger.validate`, then
     Self::applies(..).map_err(MempoolError::Invalid)?, returning `commitments` */ }

fn admit(&mut self, tx: Transaction, commitments: Vec<Word8>, claim: Option<(Address, u64)>) -> Hash
{ /* today's insert() body from the first index write onwards */ }

pub fn insert_verified(&mut self, tx: Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor)
    -> Result<Hash, MempoolError>
{
    let commitments = self.precheck(&tx, ledger, executor)?;
    let claim = claimed_nonce(&tx.action);
    Ok(self.admit(tx, commitments, claim))
}

pub fn insert(&mut self, tx: Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor)
    -> Result<Hash, MempoolError>
{
    let commitments = self.precheck(&tx, ledger, executor)?;
    ledger.validate(&tx, executor).map_err(MempoolError::Invalid)?;
    let claim = claimed_nonce(&tx.action);
    Ok(self.admit(tx, commitments, claim))
}
```

`insert`'s external behaviour is unchanged: the same checks in the same order, with the staleness ones now run twice (once in `precheck`, once inside `validate`) — which is free, and keeps `validate` the authority.

- [ ] **Step 8: Run the mempool tests green**

Run: `cargo test --release -p randprotocol-node --lib mempool::`
Expected: PASS — the two new tests and all 12 existing `mempool::tests` cases unchanged.

- [ ] **Step 9: Commit**

```bash
git add crates/randprotocol-node/src/admission.rs crates/randprotocol-node/src/mempool.rs crates/randprotocol-node/src/lib.rs
git commit -m "$(cat <<'EOF'
node: a refused-hash cache, a per-peer rate limit, and the mempool split they need

S1's review item I2, the first half. A transaction whose proof failed was
re-verified every time another peer forwarded it — about 20 ms of warm
verification per copy, on the consensus loop, for a transaction this node has
already decided about. The cache answers those for free.

Only verdicts about the transaction's own bytes are cached, from an explicit
allowlist: a bad proof, a bad digest, a bad signature, a size cap, a wrong
chain id. UnknownAnchor, Spent, UnknownProgram and the rest are statements
about this node's state at this moment — a node one block behind that cached
them would refuse, permanently, transactions that are about to be valid. The
cache refuses to hold one even if a caller offers it.

8192 entries, FIFO. The pool holds 10 000, so a flood of distinct bad proofs
cannot evict the live entries, and a refused hash is looked up once on arrival,
so insertion order is as good as recency and costs no dependency.

The per-peer token bucket (burst 16, refill 4/s) meters gossiped submissions
only: the RPC port is the operator's own and is bounded by the body limit. The
chain commits about one transaction a second, so 4/s per peer is far above any
honest peer's share. It meters the peer that *forwarded* the message, not the
one that authored it — gossip's `from` is the author, which may be a peer this
node holds no connection to at all — and the bucket lives on the peer table
entry the node already keeps, so a disconnect drops it with the peer and the
limiter needs no map of its own.

Mempool::insert is split into precheck (pool conflicts, capacity, and the
state-dependent half of Ledger::validate) and insert_verified, so the next
commit can put the proof verification on a blocking task and re-check
everything that can go stale against the tip it actually pools on.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UbMQFrbUmLvWA2PWWwTeZh
EOF
)"
```

---

### Task 5: Proof verification off the consensus loop, under gossipsub application validation

**Files:**
- Modify: `crates/randprotocol-node/src/network/mod.rs` — **only** the gossipsub `ConfigBuilder` (:245–250), `NetworkEvent`/`NetworkCommand` (:149–167), `NetworkHandle`, and the `Event::Message` arm of `handle_swarm_event` (:486–493). `codec.rs`, `SYNC_REQUEST_TIMEOUT`, the `SYNC_*_WIRE_LIMIT`s, `addr_scope` / `is_dialable_advertised_addr` and `lan_peers` are fix-sync-stall's and stay exactly as they are.
- Modify: `crates/randprotocol-node/src/node.rs` (the queue, the snapshot, the verdict channel as a new arm of the `select!` at :486, reporting; `Peer` at :230 gains the bucket; `publish_status` at :512)
- Modify: `crates/randprotocol-node/src/rpc.rs` (`NodeStatus` at :38 gains `refused_cache`, `verify_queue`, beside `connected_peers` and the three sync counters)
- Modify: `crates/randprotocol-node/src/admission.rs` (the `VerifySource` / `Verdict` types)
- Test: `crates/randprotocol-node/src/network/mod.rs` `mod tests`, `crates/randprotocol-node/src/node.rs` `mod tests`

**Interfaces:**

```rust
// network/mod.rs — produces
/// Everything `report_message_validation_result` needs, carried alongside every gossip event so
/// the node loop can report after it has decided. `propagation_source` is the peer that
/// forwarded the message, which is not always `NetworkEvent::Gossip.from` (the author) — and it is
/// also the peer the rate limit meters, for the same reason `node::Peer` distinguishes `connected`
/// from having published a `Status`. The `message_id` is content-addressed (blake3 of the message
/// bytes, network/mod.rs:249), so two peers forwarding one transaction produce the same id and each
/// delivery is reported against its own `(message_id, propagation_source)` pair.
#[derive(Clone, Debug)]
pub struct GossipId { pub message_id: MessageId, pub propagation_source: PeerId }

pub enum NetworkEvent { /* … */ Gossip { from: PeerId, msg: GossipMessage, id: GossipId } }
pub enum NetworkCommand { /* … */ ReportValidation { id: GossipId, acceptance: gossipsub::MessageAcceptance } }
impl NetworkHandle {
    pub async fn report_validation(&self, id: GossipId, acceptance: gossipsub::MessageAcceptance);
}
pub use libp2p::gossipsub::MessageAcceptance;

// admission.rs — produces
/// Who is waiting on a verification, and what has to happen when it lands.
pub enum VerifySource {
    /// Gossip: the verdict decides the message's `MessageAcceptance`, so the transaction is
    /// propagated only once it has verified here.
    Gossip(GossipId),
    /// RPC: the verdict is the caller's answer, and an accepted transaction is broadcast.
    Rpc(tokio::sync::oneshot::Sender<Result<Hash, MempoolError>>),
}
pub struct Verdict { pub tx: Transaction, pub result: Result<(), TxError>, pub source: VerifySource }
pub const MAX_VERIFY_IN_FLIGHT: usize = 4;
pub const MAX_VERIFY_QUEUE: usize = 64;
```

- [ ] **Step 1: Write the failing network test**

Extend `network/mod.rs`'s existing two-node test (or add a second one beside it) — this is the regression that catches the whole-network failure mode of `validate_messages()`:

```rust
/// With application-level validation on, gossipsub holds a message until the application
/// reports on it. A node that forgets to report stops forwarding — so this asserts the round
/// trip: B publishes, A receives with an id, A reports Accept, and A can then report again
/// without the swarm having lost the message.
#[tokio::test]
async fn a_gossiped_message_carries_the_id_its_validation_is_reported_with() {
    /* the same two-node setup as two_nodes_connect_gossip_and_sync */
    let (from, id) = /* broadcast a Status from B, wait for A's Gossip event */;
    assert_eq!(from, b.local_peer_id);
    assert_eq!(id.propagation_source, b.local_peer_id, "one hop, so the forwarder is the author");
    assert!(!id.message_id.0.is_empty());
    a.report_validation(id, MessageAcceptance::Accept).await;
    // The mesh still works afterwards: a second message arrives the same way.
    /* publish again from B, assert A receives it with a different message id */
}
```

- [ ] **Step 2: Run and see it fail**

Run: `cargo test --release -p randprotocol-node --lib network::tests`
Expected: FAIL to compile — `NetworkEvent::Gossip` has no `id` field, `report_validation` does not exist. The four address-filter tests fix-sync-stall added to `network::tests` (`loopback_is_never_a_dialable_advertised_address` and friends) must still compile and pass untouched — they are the check that this task stayed out of the sync wire.

- [ ] **Step 3: Implement the network side**

```rust
// in start(), on the ConfigBuilder at network/mod.rs:245 — beside `.heartbeat_interval(500ms)`
// (:246) and `.message_id_fn(blake3)` (:249), and NOT touching `.validation_mode(Permissive)` (:247):
    .validate_messages()   // application-level: this node forwards a transaction only after it
                           // has verified here. Local to this node; the wire is unchanged, so it
                           // rolls out onto a mixed fleet. ValidationMode stays Permissive — a
                           // Strict/Permissive mix across the fleet drops messages.
```

In `handle_swarm_event`, the `Event::Message` arm (network/mod.rs:486, today
`SwarmEvent::Behaviour(RandEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. }))`
with `let from = message.source.unwrap_or(propagation_source)`) destructures `message_id` as well —
replacing the `..` — and sends `NetworkEvent::Gossip { from, msg, id: GossipId { message_id, propagation_source } }`.
Note that `from` falls back to `propagation_source` when the message carries no source, which is the
only case where the two coincide by construction; the rate limit still keys on `propagation_source`. An **undecodable** message must still be reported, right there, or it sits in the cache forever:

The existing `Err(e) => tracing::debug!(%propagation_source, "undecodable gossip: {e}")` arm
(network/mod.rs:492) becomes:

```rust
Err(e) => {
    tracing::debug!(%propagation_source, "undecodable gossip: {e}");
    // Reject rather than Ignore: bytes that are not a GossipMessage at all are this peer's
    // fault, and leaving them unreported would stop this node forwarding them for anyone.
    let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
        &message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
}
```

`NetworkCommand::ReportValidation` is handled in `run`'s command arm with the same call, logging at debug when it returns `Err` (the message aged out of the cache).

- [ ] **Step 4: Run the network test green**

Run: `cargo test --release -p randprotocol-node --lib network::tests`
Expected: PASS — the new round-trip test, the existing two-node gossip/sync test, and the four address-filter unit tests, ~20 s (the first two build real swarms).

- [ ] **Step 5: Write the failing node-loop test**

In `node.rs`'s `mod tests` — a unit test over the decision function rather than a live node, so it runs in milliseconds:

```rust
/// The one invariant `validate_messages()` imposes: every gossip message this node accepts from
/// the swarm is reported exactly once, whatever happens to it. A message that is rate-limited,
/// found in the refused cache, queued, dropped for a full queue, or verified all report; a
/// consensus or status message reports immediately.
#[test]
fn every_gossip_outcome_names_exactly_one_acceptance() {
    use crate::admission::{GossipOutcome, PeerLimiter, RefusedCache, TokenBucket};
    let mut refused = RefusedCache::new(4);
    let limiter = PeerLimiter::new(1, 1.0);
    // One forwarding peer's bucket, as it is held on `node::Peer::tx_bucket`.
    let mut bucket = TokenBucket::default();
    let t = Instant::now();
    let tx = /* a fixture transfer */;
    let bad = /* its hash, pre-refused */;
    refused.insert(bad, TxError::BadDigest);

    // A consensus or status message is accepted at once — this node does not validate them at
    // the application level, exactly as before validate_messages() was turned on.
    assert_eq!(GossipOutcome::for_consensus(), GossipOutcome::Report(MessageAcceptance::Accept));
    // A transaction already refused here is rejected without any verification.
    assert_eq!(
        GossipOutcome::for_transaction(&tx, Some(&mut bucket), &mut refused, &limiter, 0, t),
        GossipOutcome::Report(MessageAcceptance::Reject)
    );
    // A fresh one is queued (and the caller must report when the verdict lands).
    let fresh = /* a second fixture transfer */;
    assert_eq!(
        GossipOutcome::for_transaction(&fresh, Some(&mut bucket), &mut refused, &limiter, 0, t),
        GossipOutcome::Verify
    );
    // The same *forwarder's* next one is over the rate limit: ignored, not rejected — an honest
    // peer in a burst must not be penalised.
    assert_eq!(
        GossipOutcome::for_transaction(&fresh, Some(&mut bucket), &mut refused, &limiter, 0, t),
        GossipOutcome::Report(MessageAcceptance::Ignore)
    );
    // A different forwarder has its own bucket, because it has its own `node::Peer`.
    let mut other = TokenBucket::default();
    assert_eq!(
        GossipOutcome::for_transaction(&fresh, Some(&mut other), &mut refused, &limiter, 0, t),
        GossipOutcome::Verify
    );
    // And a full queue sheds the same way (no bucket: this is the RPC path).
    assert_eq!(
        GossipOutcome::for_transaction(&fresh, None, &mut refused, &limiter, MAX_VERIFY_QUEUE, t),
        GossipOutcome::Report(MessageAcceptance::Ignore)
    );
}

/// A verdict decides the acceptance, and only a permanent one reaches the cache.
#[test]
fn a_verdict_reports_and_caches_by_permanence() {
    let mut refused = RefusedCache::new(8);
    assert_eq!(acceptance_for(&Ok(()), Hash::ZERO, &mut refused), MessageAcceptance::Accept);
    assert_eq!(refused.len(), 0);
    assert_eq!(
        acceptance_for(&Err(TxError::BadDigest), Hash::digest(b"a"), &mut refused),
        MessageAcceptance::Reject
    );
    assert_eq!(refused.len(), 1, "a bad digest is worth remembering");
    assert_eq!(
        acceptance_for(&Err(TxError::UnknownAnchor), Hash::digest(b"b"), &mut refused),
        MessageAcceptance::Ignore
    );
    assert_eq!(refused.len(), 1, "a stale anchor is not this transaction's fault");
}
```

- [ ] **Step 6: Run and see it fail**

Run: `cargo test --release -p randprotocol-node --lib node::tests::every_gossip node::tests::a_verdict`
Expected: FAIL — `GossipOutcome` / `acceptance_for` undefined.

- [ ] **Step 7: Implement the node-loop wiring**

In `admission.rs`:

```rust
/// What to do with one gossip message, decided without touching the pool or a proof.
#[derive(Debug, PartialEq, Eq)]
pub enum GossipOutcome { Report(MessageAcceptance), Verify }

impl GossipOutcome {
    pub fn for_consensus() -> GossipOutcome { GossipOutcome::Report(MessageAcceptance::Accept) }

    /// `bucket` is the **forwarding** peer's allowance (`node::Peer::tx_bucket`, looked up by
    /// `GossipId.propagation_source`), and `None` for an RPC submission, which is not metered.
    /// `queued` is the current verification queue depth.
    pub fn for_transaction(
        tx: &Transaction, bucket: Option<&mut TokenBucket>, refused: &mut RefusedCache,
        limiter: &PeerLimiter, queued: usize, now: Instant,
    ) -> GossipOutcome {
        if refused.get(&tx.hash()).is_some() {
            return GossipOutcome::Report(MessageAcceptance::Reject);
        }
        if let Some(b) = bucket {
            if !limiter.allow(b, now) { return GossipOutcome::Report(MessageAcceptance::Ignore) }
        }
        if queued >= MAX_VERIFY_QUEUE { return GossipOutcome::Report(MessageAcceptance::Ignore) }
        GossipOutcome::Verify
    }
}

/// The acceptance a verdict earns, and the cache entry it leaves behind. `Accept` even when the
/// pool then refuses the transaction as a conflict: it verified, so propagating it is right —
/// some other node's pool may have room for it.
pub fn acceptance_for(result: &Result<(), TxError>, hash: Hash, refused: &mut RefusedCache)
    -> MessageAcceptance
{
    match result {
        Ok(()) => MessageAcceptance::Accept,
        Err(e) if is_permanent(e) => { refused.insert(hash, e.clone()); MessageAcceptance::Reject }
        Err(_) => MessageAcceptance::Ignore,
    }
}
```

In `node.rs`, `Node` gains:

```rust
refused: RefusedCache,
/// Policy only — every bucket lives on its `Peer`, so nothing here has to track the peer set.
limiter: PeerLimiter,
/// The tip the pending verifications are running against, refreshed lazily: a full ledger
/// clone per consensus message would cost one per vote, so it is taken only when a transaction
/// is waiting and the tip's (height, root) has moved since the last one.
snapshot: Option<(u64, Word8, Arc<Ledger>)>,
verify_in_flight: usize,
verify_queue: VecDeque<(Transaction, VerifySource)>,
verdicts_tx: mpsc::Sender<Verdict>,
```

and `Peer` (node.rs:230) gains a third field beside `status` and `connected`:

```rust
/// This peer's gossip-submission allowance. Metered only when the peer is the *forwarder* of a
/// transaction; a peer we know of only as the author of relayed gossip never spends from it.
/// Dropped with the entry on `PeerDisconnected`, which is why the limiter keeps no map.
tx_bucket: admission::TokenBucket,
```

with `verdicts_rx` added as a **seventh** arm of the `select!` at node.rs:486 (which already has
`events`, `cmds`, the timeout sleep, the propose sleep, `status_tick` and `sync_tick`). The flow:

```rust
fn snapshot(&mut self) -> Arc<Ledger> {
    let tip = self.hs.tip_ledger();
    let key = (tip.height(), tip.root());
    if self.snapshot.as_ref().map(|(h, r, _)| (*h, *r)) != Some(key) {
        self.snapshot = Some((key.0, key.1, Arc::new(tip.clone())));
    }
    self.snapshot.as_ref().expect("just set").2.clone()
}

/// Schedule a verification, or run one from the queue if a slot is free.
fn pump_verify(&mut self) {
    while self.verify_in_flight < MAX_VERIFY_IN_FLIGHT {
        let Some((tx, source)) = self.verify_queue.pop_front() else { break };
        let (ledger, executor, out) = (self.snapshot(), self.executor.clone(), self.verdicts_tx.clone());
        self.verify_in_flight += 1;
        tokio::task::spawn_blocking(move || {
            let result = ledger.validate(&tx, executor.as_ref());
            // The loop is the only receiver and outlives every task it spawned, so a send
            // failure means the node is already shutting down.
            let _ = out.blocking_send(Verdict { tx, result, source });
        });
    }
}
```

`NetworkEvent::Gossip`'s transaction arm (node.rs:747, today a bare
`let _ = self.mempool.insert(tx, self.hs.tip_ledger(), self.executor.as_ref());`) becomes: `precheck`
against the tip first (a duplicate or a conflict is Ignored, free, and never queued), then
`GossipOutcome::for_transaction`, whose bucket argument is
`self.peers.entry(id.propagation_source).or_default().tx_bucket` — the forwarder's, not `from`'s;
`Report(a)` → `self.net.report_validation(id, a).await`; `Verify` → push onto the queue and
`pump_verify()`. The `Status` arm (:749) and the consensus arm report `Accept` immediately, before
handling, and must keep the `entry(from).or_default().status = Some(s)` write and the `ahead &&
sync_inflight.is_none()` sync kick exactly as they are. `NodeCommand::SubmitTx` (node.rs:665) takes
the same path with `VerifySource::Rpc(reply)` and no bucket, except that a `precheck` failure answers
the caller directly (so the RPC error messages in `docs/rpc.md` are unchanged) — and it keeps
broadcasting only on success, as it does today.

On a verdict:

```rust
async fn on_verdict(&mut self, v: Verdict) -> Result<()> {
    self.verify_in_flight -= 1;
    let hash = v.tx.hash();
    let acceptance = admission::acceptance_for(&v.result, hash, &mut self.refused);
    // A verified transaction is pooled against the *current* tip, not the snapshot it was
    // verified on: precheck re-runs every state-dependent check there.
    let pooled = match &v.result {
        Ok(()) => self.mempool.insert_verified(v.tx.clone(), self.hs.tip_ledger(), self.executor.as_ref()),
        Err(e) => Err(MempoolError::Invalid(e.clone())),
    };
    match v.source {
        VerifySource::Gossip(id) => self.net.report_validation(id, acceptance).await,
        VerifySource::Rpc(reply) => {
            if pooled.is_ok() { self.net.broadcast(GossipMessage::Transaction(v.tx)).await }
            let _ = reply.send(pooled);
        }
    }
    self.pump_verify();
    Ok(())
}
```

`NetworkEvent::PeerDisconnected` (node.rs:736) needs **no change at all**: it already does
`self.peers.remove(&p)`, which drops the peer's `tx_bucket` with it, and it also clears
`sync_inflight` and calls `maybe_sync()` — leave both alone. That is the whole reason the bucket
lives on `Peer` rather than in a map inside `PeerLimiter`.

`publish_status` (node.rs:512) sets `s.refused_cache = self.refused.len()` and `s.verify_queue =
self.verify_queue.len()` in the same run of assignments that already fills `s.connected_peers`,
`s.sync_failures`, `s.sync_late_batches` and `s.sync_inflight_age_ms`. Nothing here increments or
reinterprets those four: a verification that is shed or refused is not a sync failure, and the two
sets of numbers answer different questions for an operator.

- [ ] **Step 8: Run the focused tests green**

Run: `cargo test --release -p randprotocol-node --lib`
Expected: PASS — the new node and admission tests, plus every existing `--lib` test (network, mempool, storage, rpc, node).

- [ ] **Step 9: Commit**

```bash
git add crates/randprotocol-node/src/network/mod.rs crates/randprotocol-node/src/node.rs \
        crates/randprotocol-node/src/admission.rs crates/randprotocol-node/src/rpc.rs
git commit -m "$(cat <<'EOF'
node: verify transaction proofs off the consensus loop

S1's review item I2, the rest of it. Every gossiped transaction cost the
consensus event loop a ~20 ms warm proof verification, synchronously, before
the loop could touch a vote or a proposal — the real DoS surface, with the fee
floor and the key cache as mitigations only.

The verify now runs on spawn_blocking against an Arc<Ledger> snapshot of the
tip, at most four at a time behind a 64-deep queue, and the loop keeps turning.
The snapshot is taken lazily — only when a transaction is actually waiting and
the tip's (height, root) has moved — so it costs at most one ledger clone per
block and none on an idle chain. Everything state-dependent is re-checked by
Mempool::precheck against the tip the transaction is actually pooled on, so the
snapshot being a block stale can only delay a transaction, never admit a bad
one.

Gossipsub gets application-level validation (validate_messages), so a
transaction is forwarded only once it has verified here. ValidationMode stays
Permissive on purpose: a Strict/Permissive mix across the fleet drops messages,
and validate_messages is local to one node, so this rolls out on a mixed fleet
by ordinary restart. The cost of that switch is that every delivered message
must be reported exactly once or this node silently stops forwarding it, so
consensus and status messages are accepted immediately, undecodable bytes are
rejected in the network task, and every transaction path — rate-limited,
already refused, queued, shed, verified — ends in exactly one report. There is
a test for that.

A verdict that is a statement about the bytes is Reject and is cached; one
about this node's state is Ignore and is not. A transaction that verified but
then lost a pool conflict is still Accept: it is a valid message, and another
node's pool may have room.

Proposal verification stays on the loop. A proposal is signed by a scheduled
leader and paced by the block interval, so it is not the vector, and moving it
would change when a vote is emitted — a consensus change this cannot make.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UbMQFrbUmLvWA2PWWwTeZh
EOF
)"
```

---

### Task 6: End-to-end on a cluster, and the documentation

**Files:**
- Modify: `crates/randprotocol-node/tests/cluster.rs`
- Modify: `docs/rpc.md` (a new `## Changelog` section), `docs/rpc-comparison.md` (§2), `docs/architecture.md` (§8), `AGENTS.md` (Open follow-ups), `README.md` (the Interfaces row)

- [x] **Step 1: Write the failing cluster tests**

Two additions, both on chains the file already builds. `cluster.rs` gives you `keys` (:105),
`genesis` (:148), `genesis_funding` (:164), `start_node` (:276, FAST) / `start_node_at` (:280, takes
the pace), `wait_height` (:343), `wait_for` (:335), `stop` (:323), `bootstrap_addr` (:329), and
`TestNode { handle, dir, rpc }` (:270) — so `n.handle.status.read().unwrap()` is the `NodeStatus`
and `n.rpc.call(method, params)` the raw JSON-RPC.

**The proving slot applies to the first one.** Anything that proves a real bundle takes
`let _slot = proving_slot().await;` around the whole `wallet::` call (the module is already imported
at cluster.rs:40–41 and every proving test in the file holds it) — taken before the anchor is read,
released after the commit. The second test is FAST-paced and proves nothing, so it takes no slot.

```rust
/// The compact-block read against a real chain: a wallet that has only ever called
/// getCompactBlocks sees exactly the leaves and nullifiers getCommitments and getNullifiers
/// report, and the rows are grouped by the transaction that produced them.
/// **Prefer extending `two_validators_commit_and_shielded_transfer` (cluster.rs:732) in place** to
/// writing this as a separate test: since the proving slot serialises the suite, a second copy of
/// that opening is a thirteenth bundle proof and ~95–100 s of wall time added to a run that already
/// takes ~20 minutes, for assertions that need no chain of their own. Write it standalone only if
/// the existing test's shape genuinely will not carry it; if you do, it takes the slot like the
/// rest, at PROVING pace, and this doc comment should say why.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn compact_blocks_agree_with_the_paged_reads() {
    /* start two validators on genesis_funding, mint, send one shielded transfer, wait for the
       commit — the same opening as two_validators_commit_and_shielded_transfer */
    let head = n0.rpc.head().await.unwrap()["height"].as_u64().unwrap();
    let compact = n0.rpc.call("rand_getCompactBlocks", json!([0, head])).await.unwrap();

    // Every leaf, in the same order and with the same envelopes, as the paged read.
    let flat: Vec<Value> = compact.as_array().unwrap().iter().flat_map(|b| {
        b["commitments"].as_array().unwrap().iter().cloned()
            .chain(b["transactions"].as_array().unwrap().iter()
                .flat_map(|t| t["commitments"].as_array().unwrap().iter().cloned()))
    }).collect();
    let paged = n0.rpc.call("rand_getCommitments", json!([0, 1000])).await.unwrap();
    let paged = paged.as_array().unwrap();
    assert_eq!(flat.len(), paged.len(), "the same leaves");
    for (a, b) in flat.iter().zip(paged) {
        assert_eq!((&a["index"], &a["cm"], &a["envelope"]), (&b["index"], &b["cm"], &b["envelope"]));
    }
    // And every nullifier, attributed to the transaction that spent it.
    let nfs: Vec<&str> = compact.as_array().unwrap().iter()
        .flat_map(|b| b["transactions"].as_array().unwrap())
        .flat_map(|t| t["nullifiers"].as_array().unwrap())
        .map(|n| n.as_str().unwrap()).collect();
    let paged_nfs = n0.rpc.call("rand_getNullifiers", json!([0, 1000])).await.unwrap();
    assert_eq!(nfs.len(), paged_nfs.as_array().unwrap().len());
    for row in paged_nfs.as_array().unwrap() {
        assert!(nfs.contains(&row["nullifier"].as_str().unwrap()));
    }
    // Every node answers the same way.
    assert_eq!(n1.rpc.call("rand_getCompactBlocks", json!([0, head])).await.unwrap(), compact);
}

/// The refused cache end to end: a mint whose signature does not check is a permanent verdict,
/// so the second copy of the same bytes is refused without a second verification — and the
/// count an operator reads says so. No proving: a bad mint signature needs no bundle, which is
/// why this runs on a FAST chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_transaction_is_not_verified_twice() {
    let ks = keys(2);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    wait_height(&[&n0], 2, Duration::from_secs(20)).await;
    assert_eq!(n0.handle.status.read().unwrap().refused_cache, 0);

    // A mint that names a real validator as its minter and carries a signature over nothing.
    let bad = Transaction {
        chain_id: CHAIN_ID,
        bundle: None,
        action: Action::Mint {
            cm: [9; 8],
            envelope: Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] },
            amount: 1_000,
            minter: ks[0].public_key().clone(),
            signature: randprotocol_core::Signature::empty(),
        },
    };
    let first = n0.rpc.send_transaction(&bad).await.unwrap_err().to_string();
    assert!(first.contains("mint signature"), "{first}");
    wait_for("the refusal to be cached", Duration::from_secs(5), || {
        n0.handle.status.read().unwrap().refused_cache == 1
    }).await;
    // The same bytes again: the same refusal, and the cache did not grow — it answered.
    let again = n0.rpc.send_transaction(&bad).await.unwrap_err().to_string();
    assert!(again.contains("mint signature"), "{again}");
    assert_eq!(n0.handle.status.read().unwrap().refused_cache, 1);
    // A legitimate transaction still goes through, so the cache is not a blanket refusal.
    n0.mint(7, 5 * UNITS_PER_RAND).await;
    stop(n0).await;
}
```

- [x] **Step 2: Run the two new cluster tests and see them fail**

Run: `cargo test --release -p randprotocol-node --test cluster -- compact_blocks_agree a_refused_transaction`
Expected: the compact-block one fails on the assertion (or compiles and passes if Task 1 landed correctly — in which case assert it *does* pass and move on); the refused-cache one fails on `refused_cache` not existing if Task 5 missed the status field.

Even this focused run takes the proving slot for the compact-block half, so it will wait if another
session holds the lock. Budget minutes, not seconds, and check the lock before blaming the test.

- [x] **Step 3: Make them pass**

Fix whatever the two tests surface. No new production code should be needed; if something is, it belongs to the task that owns that file and the commit message should say so.

- [x] **Step 4: Run the whole cluster suite, once**

Run: `cargo test --release -p randprotocol-node --test cluster`
Expected: PASS — **19 tests (17 existing + 2), about 20 minutes**, or ~22 if the compact-block assertion was written as its own proving test rather than folded into `two_validators_commit_and_shielded_transfer`. The suite measured 17 tests / 19m59s on 2026-09-13 *because* the proving slot serialises its twelve bundle proofs and two program proofs; the 16 tests / 6m28s this plan was drafted against is the pre-slot number and will not be seen again.

This is the only full-cluster run in the plan. Before starting it, make sure no other session's
`--test cluster` or `--test wallet_flow` holds `<target-dir>/tmp/rand-proving-slot.lock` — the runs
will not fail, they will queue, and the wall times add. While it runs, `ps -eo rss= | awk '$1>8000000'`
should stay silent.

`faucet_mint_via_rpc_reaches_every_node` (cluster.rs:633) is the load-bearing one: if
`validate_messages()` broke propagation, it fails here. `node_behind_by_more_than_one_sync_batch_catches_up`
(:553) and `four_validators_plus_late_observer_syncs` (:418) are the ones that would catch a
regression in fix-sync-stall's batch sizing if this plan touched it — they should be untouched and
green, which is the evidence that it did not.

- [x] **Step 5: Write the documentation**

0. **Everywhere in `docs/rpc.md`: append, never overwrite.** fix-sync-stall rewrote the `rand_status` section (the example object at :258 now carries `sync_inflight_age_ms`, `sync_failures`, `sync_late_batches` and `connected_peers`, with four explanatory bullets after it) and added the behaviour `-32600` describes without adding its Errors row. The new keys, the new bullets and the sync prose all stay exactly as they are; this plan adds `ws_clients` / `refused_cache` / `verify_queue` to that example and one bullet each, and adds the `-32600` row.
1. **`docs/rpc.md`** — add a `## Changelog` section at the end, headed "what changed for clients", listing in one place: `rand_getCompactBlocks` (new; the shape and the caps); batch requests (new; the 20 cap; notifications refused with `-32600`); the WebSocket endpoint and `newHeads` (new; same port, the caps, the drop-on-lag rule); `rand_status` gains `ws_clients`, `refused_cache`, `verify_queue` (beside the four sync fields fix-sync-stall added, which are unchanged); the `-32600` error code is newly *documented* — it already existed for an oversized or unparseable body, and this plan adds the batch-shape and notification uses; and the one behaviour change an existing client can notice — **a transaction submitted over RPC is now answered after its proof has verified on a worker rather than on the consensus loop, so the reply can take a few hundred milliseconds longer under load, and the error messages are unchanged**. Note explicitly that no wire format, block, or consensus rule changed and that old and new nodes interoperate.
2. **`docs/rpc-comparison.md` §2** — replace "Two cheap, non-consensus additions close most of that and are scheduled as an RPC hardening task after phase S3" and its two bullets with the shipped shapes: `rand_getCompactBlocks(from_height, to_height)` → per block its height, hash, timestamp and per transaction its note commitments (leaf index + envelope) and nullifiers, 128 blocks per call; and the WebSocket `newHeads` subscription (`rand_subscribe`/`rand_unsubscribe`, same port). Update the §1 table's *subscriptions* row (RAND: `newHeads` over WebSocket) and its *batching and paging* row (RAND: JSON-RPC batch, cap 20, plus limit-based paging and the compact-block range). Update §4's *subscriptions* row the same way and drop "(planned: WebSocket `newHeads`)". Leave §4's viewing-key-import and `check_tx_proof` paragraphs as candidates — they are this plan's "pending the user's decision" list.
3. **`AGENTS.md`** — rewrite the Open-follow-ups bullet. It currently reads "Proof verification still runs on the consensus event loop (~20 ms warm); moving it to `spawn_blocking` + gossipsub `Strict` validation is the real DoS fix (fee floor and FIFO key cache are mitigations only)." It becomes a statement of what shipped, under the review-state section rather than the follow-ups: transaction proof verification runs on `spawn_blocking` behind a bounded queue, gossipsub uses application-level validation (`validate_messages`, **`ValidationMode` deliberately still `Permissive` — a Strict/Permissive mix across a fleet drops messages**), a bounded refused-hash cache answers a repeat refusal for free, and a per-peer token bucket meters gossiped submissions. Keep one line under Open follow-ups: **block-application proof verification is still on the loop and needs a consensus decision to move**.
4. **`docs/architecture.md` §8** — the Mempool numbered list becomes the new order (duplicate hash → pool conflicts → capacity → the staleness half of `Ledger::validate` → *queue for off-loop verification* → the proofs on a blocking task → `insert_verified` against the tip), with the gossipsub application-validation paragraph and the report-exactly-once invariant. §9c's sentence about the RPC handler is updated the same way.
5. **`README.md`** — the Interfaces row: "JSON-RPC 2.0 over HTTP with batch requests, a WebSocket `newHeads` subscription on the same port (`rand-node`), `rand` wallet CLI with a local prover, Rust client library".

- [x] **Step 6: Verify the docs against the code**

Run: `cargo test --release -p randprotocol-node --lib` and re-read `docs/rpc.md`'s new sections against the constants in `rpc.rs`, `ws.rs` and `admission.rs`. Every number in the docs (128, 1000, 20, 64, 8, 256, 8192, 16, 4) must be the constant's value. Fix any drift.

Also check what you did **not** write: the body-limit prose must still describe `RPC_MAX_BODY_BYTES`
as derived from `2 * MAX_PROOF_BYTES` and the envelope caps (it is a `const` expression, so quote the
formula, not a stale byte count), and the four sync bullets must read exactly as fix-sync-stall left
them. A docs diff that touches those lines is a mistake in this step.

- [x] **Step 7: Commit**

```bash
git add crates/randprotocol-node/tests/cluster.rs docs/rpc.md docs/rpc-comparison.md \
        docs/architecture.md AGENTS.md README.md
git commit -m "$(cat <<'EOF'
docs: RPC hardening shipped — compact blocks, batch, newHeads, admission

Two cluster tests for the parts only a real chain exercises: a compact-block
read that agrees leaf for leaf and nullifier for nullifier with the paged
reads on every node, and a refusal that is answered from the cache the second
time rather than re-verified.

docs/rpc.md gains a changelog section so a client author can see what is new
in one place, including the one behaviour change they can notice — an RPC
submission is now answered after its proof verified on a worker, so it can
take a little longer under load, with the same error messages.

rpc-comparison.md §2 said these were scheduled; it now says what they are.
AGENTS.md's follow-up about proof verification on the consensus loop becomes a
statement of what shipped, with the one piece that is still open — block
application — named as needing a consensus decision, and with the reason
ValidationMode stays Permissive written down where the next person will look.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UbMQFrbUmLvWA2PWWwTeZh
EOF
)"
```

---

## Self-review

**Spec coverage.** Scope item 1 (`rand_getCompactBlocks`, per-block height/hash/timestamp, per-transaction commitments with tree index and envelope bytes, nullifiers, a documented page cap, existing error conventions, reusing today's storage) → Task 1, which reuses `CF_NOTES`/`NoteRow`/`envelope_json` and adds no column family. Item 2 (WebSocket `newHeads` on axum's `ws` feature, JSON-RPC subscribe/unsubscribe, the `rand_getHead` payload, documented backpressure and a connection cap) → Task 3. Item 3 (array in, array out, a batch cap, notifications documented) → Task 2, which chooses explicit refusal and says why. Item 4 (a) refused-hash cache and (b) per-peer rate limit → Task 4; (c) `spawn_blocking` verification plus `validate_messages()` + `report_message_validation_result`, with `ValidationMode` untouched, and the mempool interaction (one entry per verified transaction, a bounded cache, sized with reasoning) → Tasks 4 and 5 together. The three comparison candidates the user excluded are in "Out of scope, pending the user's decision". The no-fork constraint has its own section naming what *would* fork.

**Placeholder scan.** Every step names its file, its test, its command and its expected output. The one deliberate "confirm before writing" is Task 4 Step 5's `insert_nullifier_for_testing`, which is a named `cargo check` against a helper that may or may not exist under that name in `randprotocol-core` — the user permitted `cargo check`, and the alternative (build the moved ledger by applying a block) is stated. `docs/rpc.md`'s prose is described by content rather than transcribed, because it is documentation, not code.

**Type consistency.** `HeadSummary` / `head_summary` / `HEAD_CHANNEL` (rpc.rs) are used identically in ws.rs and node.rs. `GossipId { message_id, propagation_source }` is produced in network/mod.rs and consumed in admission.rs (`VerifySource::Gossip`) and node.rs. `RefusedCache::{new,get,insert,len}`, `is_permanent`, `PeerLimiter::{new,allow,forget}`, `GossipOutcome::{for_consensus,for_transaction}`, `acceptance_for`, `Verdict { tx, result, source }` keep one spelling across Tasks 4 and 5. `Mempool::{precheck, insert_verified, insert}` and the private `applies`/`admit` are named the same in Task 4's implementation and Task 5's `on_verdict`. `Storage::{notes_in_heights, first_note_at_or_after}` and the free `derived_note_count` are named the same in Task 1's storage code, its RPC renderer and its tests. `NodeStatus`'s three new fields (`ws_clients`, `refused_cache`, `verify_queue`) are added in Tasks 3 and 5 and read by Task 6's cluster tests and the docs.

**Reconciliation with main `9ffdd43`.** Every file:line above was re-checked against the merged head
on 2026-09-13: `rpc.rs` `MAX_PAGE`:26, `NodeStatus`:38, `RpcState`:110, `Request`:119,
`invalid_request`:139, `RPC_MAX_BODY_BYTES`:154, `handle`:194, `rejection_error`:222, `blocking`:237,
`envelope_json`:297, `block_json`:334, `dispatch`:465, the `sendTransaction` size pre-check:475,
`rand_getNullifiers`:531, `rand_getHead`:717, the test fixtures:865–911, the body-limit tests:1497;
`network/mod.rs` `NetworkEvent`:149, `ConfigBuilder`:245–250, `Event::Message`:486; `node.rs`
`peers`:203, `Peer`:230, `run`'s `select!`:486, `publish_status`:512, `SubmitTx`:665,
`PeerDisconnected`:736, the gossip transaction arm:747; `mempool.rs` `claimed_nonce`:59,
`claimed_commitments`:97, `insert`:136, `candidates_within`:202, `still_applies`:227;
`randprotocol-core` `ledger/staking.rs::derived_commitment`:161 and `TxError::TransactionTooLarge` in
`ledger/mod.rs`. The two amendments the new code forced are named at the top and marked in place:
the `-32600` constraint, and the rate limit's key.

**One gap found and closed while reviewing:** the first draft reported gossip validation only for transactions, which would have left every consensus and status message unvalidated in the gossipsub cache and silently stopped this node forwarding them — a whole-network failure from a local switch. Task 5 now reports `Accept` for those immediately, rejects undecodable bytes inside the network task, and has a test whose whole subject is "exactly one report per message".
