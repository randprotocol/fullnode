# Compact blocks: proposals as header plus transaction hashes

Status: design, 2026-10-08. Implements `docs/compute-optimization.md` §3.4 with the scope widened
to every transaction, as decided on 2026-10-08: a proposal on the wire carries the header, the
leader's signature and the transaction hashes; a validator rebuilds the body from what it already
holds and fetches only what it lacks. **Wire change only; no consensus change; no genesis change.**
A flag-day roll: every node runs this release at once (decided 2026-10-08; see §7).

Branch `feat/compact-blocks`, worktree `~/rand-worktrees/fullnode-compact-blocks`, from `main`
at `d6cc16f5`.

## 0. Amendments from planning (2026-10-08)

The implementation plan (`docs/superpowers/plans/2026-10-08-compact-blocks.md`, "Spec
amendments") amends this spec where the code differed from what it assumed: no tree index (the
recent-transactions cache also remembers every proposal body, cap `4 × max_block_bytes`); the
hash list is checked against the signed `tx_root` before any fetch, so a rebuilt block cannot
fail the root check; the fetch server stays on the consensus loop like `BlockByHash`; a parked
proposal is reported `Accept` to gossipsub after the pre-screen; the missing-body test is a node
unit test, the cluster test measures frames and a late validator's fetches.

The review rounds of the build amended it further, and the code is the authority where the text
below differs:

- **Rebuild sources are the pool and the recent-transactions cache only** (§5.2), not committed
  storage: a live block cannot re-include a committed transaction, and storage returns the
  pruned marker form of a body.
- **Marker forms are excluded.** A pruned (marker-form) body shares the real transaction's id. It
  is never cached, never used in a rebuild and never accepted from a fetch response; the fetch
  then finds the real body.
- **The park band is `hs.view()` and `hs.view() + 1`.** One park at a time; a newer view replaces
  it, a same or older view does not (a same-view proposal keeps the park). A proposal for any
  other view is not parked, so a future-view leader cannot take the park over; a node that lags
  by more than one view gets the block by `BlockByHash` or batch sync as before.
- **Fetch order** is the leader's bound peer, then the forwarder, then peers at or above our
  height, then any, at most 8 peers; when the leader is unbound the forwarder is asked first.
  Expiry runs from the 3 s status tick. A completed park whose block the replica already holds
  is dropped.
- **Serving** is from the pool and the recent cache only, never a marker form, on the consensus
  loop (§6). A request over `TX_FETCH_BATCH` is `Busy` without spending a node-wide token.

## 1. Goal and success criteria

The leader's outbound bytes per block fall from the block size to the header plus 32 bytes a
transaction, and each transaction's proofs cross the network once (on the transaction topic)
rather than twice (again inside the proposal). Nothing a validator votes on changes: HotStuff
receives the same full `Proposal` it receives today, rebuilt locally.

| criterion | bound |
|---|---|
| consensus-topic frame for a proposal | hashes 32 B a transaction plus the header and justify: ~104 KB for a typical block and ~168 KB at the 2 000-transaction cap on chain 20 at 26 validators, where today's is up to 20 MiB; the cluster test pins ≤ 200 KB at the cap with 4 validators (≤ 80 KB) |
| a validator that holds every transaction | rebuilds and votes with no fetch and no added latency beyond the rebuild (sub-millisecond) |
| a validator missing k transactions | fetches them in ⌈k/512⌉ requests and votes; if they cannot be obtained, the view times out as an unknown parent does today |
| liveness and safety | unchanged: the consensus crate, the ledger and the simulator are not modified |

Measured in a multi-node cluster test and recorded in `docs/node-hardware.md`.

## 2. What the code does today (verified on `67cbb08b`, the explorer's read of 2026-10-08)

- A proposal is `Action::Broadcast(ConsensusMessage::Proposal(block))`, published as
  `GossipMessage::Consensus(..)` on `rand/{chain_id}/consensus` with bincode, no version byte;
  variants are numbered by position and an unknown tag is a decode error reported `Reject`
  (`network/mod.rs:742-757`, `:851-859`; `wire.rs:21-30`).
- `Block { header, transactions, signature }`; `Block::hash()` is the header's hash;
  `signature` is over the header alone (`domain.block_message(&header)`); the body is bound
  only through `header.tx_root = merkle_root(tx.hash() for tx in transactions)`
  (`types/block.rs:185-226`). `transaction_list_fault()` checks duplicates and the root.
- The gossip precheck for a proposal (`consensus/hotstuff/precheck.rs:146-200`) reads the full
  body: count ≤ `MAX_BLOCK_TXS`, bytes ≤ `max_block_bytes`, justify matches parent, QC
  well-formed, height/view window, proposer leads the view, header signature, transaction list.
- Transactions reach validators on `rand/{chain_id}/tx` before any leader proposes them; the
  pool is `txs: HashMap<Hash, Pooled>` with `get(&Hash)`; nothing removes a transaction on
  proposal — it leaves on commit, prune or byte-cap eviction (`mempool.rs:281, 433, 473`).
- The sync channel is request-response `/rand/{chain_id}/sync/1`, CBOR with named variants
  (`wire.rs:95-119`): `SyncRequest::{Blocks, BlockByHash}`, `SyncResponse::{Blocks, Block,
  NotHeld, Busy}`; request limit 64 KiB, response limit `2 × (max_block_bytes + 2 MiB) + 256 KiB`,
  timeout `max(30 s, ⌈limit/MiB⌉ s)`. Per-peer `sync_bucket` (burst 8, 2/s); `Blocks` is also
  charged to the node-wide `SyncServeBudget` (burst 32, 8/s, `MAX_SYNC_SERVES_IN_FLIGHT = 4`)
  and served off-loop by `spawn_sync_serve`; `BlockByHash` is answered on-loop from `hs.block`
  or `storage.block_by_hash` (`node.rs:3203-3255, 373`).
- `fetch_block(hash)` asks connected peers at or above our height one at a time,
  `MAX_FETCH_ATTEMPTS = 8`, then `unobtainable` → `hs.fallback_high_qc` (`node.rs:3351, 1064`).
- The consensus byte limiter (CN-4) allows one full block plus 2 MiB per view per forwarder
  (`node.rs:1155-1188`); the gossip transmit size is `max(16 MiB, max_block_bytes + 1 MiB)`.
- Caps on chain 20: `max_block_bytes` 20 MiB, `max_proof_bytes` 4 MiB, `MAX_BLOCK_TXS` 2 000,
  26 validators.

## 3. Wire format

### 3.1 The compact proposal

```rust
/// A proposal with its body elided (spec 2026-10-08 §3): the header and the leader's
/// signature — everything `Block::hash` and `Block::verify_signature` need — and the hashes
/// of the transactions in block order. The receiver rebuilds `Block` from transactions it
/// already holds and checks `header.tx_root` over the rebuilt list.
pub struct CompactBlock {
    pub header: BlockHeader,
    pub signature: Signature,
    pub tx_hashes: Vec<Hash>,
}
```

`GossipMessage` gains a fifth variant, appended, `CompactProposal(CompactBlock)`, published on
the consensus topic. `ConsensusMessage` is unchanged. The existing `Consensus(Proposal(..))`
form is still accepted on receipt (it is what `BlockByHash` answers with and what a test
harness may inject) but is no longer what a node publishes for its own proposals.

Size: 2 000 hashes = 64 000 bytes, plus the header — ~3.7 KB of proposer key and signature
plus the justify at ~3.8 KB a vote, ~100 KB at 26 validators — so ~168 KB at the transaction
cap on chain 20 and ~104 KB for a typical block, where today's full proposal is up to 20 MiB.
The justify is the same bytes a full proposal carries today; the §1 bound of 128 KB is for a
block at today's typical fill, and a block at the 2 000-transaction cap is ~168 KB.

### 3.2 The transaction fetch

```rust
SyncRequest::Transactions(Vec<Hash>)          // ≤ TX_FETCH_BATCH = 512 hashes, in block order
SyncResponse::Transactions(Vec<Transaction>)  // the ones held, any order; absent ones omitted
```

Both are appended variants of the CBOR enums. A request of 512 hashes is 16 KB, under the
64 KiB request limit. A response is bounded by the block byte cap plus one transaction's slack
(`max_block_bytes + max_aggregate_bytes`), under the existing response limit.

## 4. Sending

In `node.rs`'s action handler, `Action::Broadcast(ConsensusMessage::Proposal(block))` publishes
`GossipMessage::CompactProposal(CompactBlock::from(&block))`. Every other action is unchanged.
The leader keeps serving the body: its transactions are in its pool until commit and the block
is in its consensus tree, so a `Transactions` request from any validator is answered from local
state (§6).

`Action::SendTo(_, Proposal)` (today broadcast anyway) takes the same path.

## 5. Receiving

### 5.1 Pre-screen (on-loop, before any fetch)

`classify_compact_proposal`, mirroring `classify_consensus_gossip`'s count and byte buckets,
then a header-only precheck added to `HotStuff` as `precheck_compact(&CompactBlock)`:

1. `tx_hashes.len() ≤ MAX_BLOCK_TXS`, else Reject.
2. `header.justify.block_hash == header.parent`, else Reject; `precheck_qc(justify)` as today.
3. height ≤ committed height → Ignore; view beyond `PROPOSAL_VIEW_WINDOW` → Ignore.
4. the proposer leads the view in a known set, else Ignore.
5. `Block::verify_signature` over the header, else Reject.

Only a proposal that passes all five can cause a fetch. That is the same power a leader has
today by sending a full block: the scheduled leader can make every validator download one
block's worth of bytes per view.

### 5.2 Rebuild

For each hash in order: the mempool (`Mempool::get`), then the node's **recent-transactions
cache** (§5.4), then the consensus tree's blocks (`hs` entries, by hash — an index
`tree_txs: HashMap<Hash, (block_hash, index)>` maintained in the node on insert/prune), then
committed storage (`storage.tx_by_hash`). If every hash resolves, build
`Block { header, transactions, signature }`, and hand it to the existing path:
`classify_consensus_gossip` (which runs the full precheck, including `transaction_list_fault`,
the byte cap and the root) and `on_consensus`. A rebuilt block that fails the root check is
reported `Reject` against the forwarder, like a malformed full proposal.

### 5.3 Park and fetch

If hashes are missing, the compact proposal is parked in `pending_compact: Option<Parked>` —
**one per node**, the newest view wins, dropped on `on_timeout` for its view and when the view
advances past it — and the missing hashes are requested in batches of `TX_FETCH_BATCH` from the
proposer's peer id first (the gossip source is the forwarder, not necessarily the leader; the
leader's peer id is known from the peer-binding table when bound, else the forwarder), then from
connected peers at or above our height, in the order `fetch_block` uses, with the same
`MAX_FETCH_ATTEMPTS` and the same per-peer `sync_bucket`. Each `Transactions` response is
checked hash-by-hash (`tx.hash()` must be one of the requested hashes; anything else is
discarded and the peer is treated as having answered `None`). When the parked proposal is
complete it is rebuilt and handled as in §5.2. When attempts are exhausted it is dropped and
logged; the view then times out as an unknown parent does today, and the next leader proposes.

Batch sync and `BlockByHash` keep delivering full blocks; a node that fell behind never fetches
transactions one block at a time.

### 5.4 Recent-transactions cache

`RecentTxs`: a FIFO of `(hash, Transaction)` for every gossiped transaction this node decoded,
whatever the verdict, capped at `RECENT_TXS_MAX = 4 096` entries and `RECENT_TXS_BYTES = 2 ×
max_block_bytes`. It exists for the window between a transaction's arrival and its verdict (the
verify queue is 16 deep per worker; a proposal can name a transaction the node is still
verifying) and for transactions this node refused for a state reason (a stale anchor) that the
leader nevertheless included — the rebuilt block is still verified in full by `apply_block_for_sync`
on the consensus loop, exactly as a full proposal is today, so a refused transaction in the
cache cannot make the node vote for a block it would have refused. A transaction refused for a
bytes-only reason (`RefusedCache`) is not cached.

## 6. Serving

`SyncRequest::Transactions(hashes)` is admitted by the per-peer `sync_bucket`, then, if it is
served, one node-wide sync-serve token. It is answered on the consensus loop, like `BlockByHash`,
from the pool and the recent-transactions cache only; storage is not consulted, and a marker
form is never served. Over the limit it answers `Busy`. A request over `TX_FETCH_BATCH` hashes
is answered `Busy` without spending a node-wide token. The response carries only transactions
found, so a peer missing some lets the client move to the next peer for the rest.

## 7. Roll-out

Flag day. An old node receiving `CompactProposal` cannot decode it and reports `Reject`, so it
never votes on or relays a new leader's proposal (the node configures no gossipsub peer scoring,
so a Reject only drops the message; old nodes between new ones are relay holes); a new node receiving an old leader's full `Proposal`
handles it as today. The fleet is therefore rolled in one pass, validators last, exactly as
v0.7.0 was rolled; during the pass the chain keeps liveness while more than two thirds of the
stake runs the same format, so the roll order is: observers and archives first, then the
validators quickly. `CHANGELOG` and `docs/deploy.md` say so. No genesis field, no chain cut.

## 8. Bounds and limits

| item | value | why |
|---|---|---|
| `TX_FETCH_BATCH` | 512 hashes | 16 KB request under the 64 KiB request limit; ≤ 4 round-trips for a full block |
| parked compact proposals | 1, newest view | a view has one leader; an older one is moot |
| `RECENT_TXS_MAX`, `RECENT_TXS_BYTES` | 4 096 entries, `2 × max_block_bytes` | two blocks of gossip in flight |
| tree index | `O(transactions in the tree)` | ≤ 3 blocks in steady state, 512 under stalls (`max_tree_blocks`) |
| fetch attempts | `MAX_FETCH_ATTEMPTS` (8) per parked proposal | as `fetch_block` |
| serve budget | shared with `Blocks` | a `Transactions` request can be a whole block |

The consensus byte limiter (CN-4) is unchanged: a compact proposal is far under one view's
allowance, and the full-block allowance still covers a `Proposal` arriving by `BlockByHash`.

## 9. Testing

- `wire.rs`: the appended gossip and sync variants encode after the existing ones (the
  `PeerBinding` precedent's test shape); `CompactBlock::from(&Block)` round-trips through
  bincode; an unknown-tag test for the old reader is kept.
- `HotStuff::precheck_compact`: each of the five pre-screen rules, Reject vs Ignore as listed.
- Node unit tests (the `node.rs` test fixtures): rebuild from the pool; rebuild from the recent
  cache; rebuild from the tree; a missing hash parks and emits one `Transactions` request per
  512 hashes; a response with a wrong hash is discarded; a complete response rebuilds and votes;
  exhausted attempts drop the park; a newer view replaces the park; the serve path answers from
  pool/tree/storage and `Busy` over budget.
- `tests/cluster.rs`: a four-validator cluster commits blocks with real transactions over the
  compact path (every existing cluster test now runs it); a new test withholds one transaction
  from one validator's gossip (its tx topic subscription delayed) and asserts it fetches and
  votes; a new test measures the consensus-topic frame size for a block at the transaction cap (≤ 80 KB with four validators).
- The existing e2e suites (`zusd_e2e`, `split_auth`, wallet flows) run through the path by
  construction.

## 10. Docs

`docs/architecture.md` §8 (the proposal path and the sync enums), `docs/node-hardware.md` (the
measured frame size and fetch latency), `docs/compute-optimization.md` §3.4 (*shipped*, with the
widened scope), `docs/deploy.md` (the flag-day roll order), `CHANGELOG.md`, `AGENTS.md`.

## 11. Out of scope

Short ids (BIP152-style) — full hashes are 64 KB a block and avoid collision handling; compact
batch sync (`CommittedBlock` stays full); erasure-coded propagation (§5.4 of the compute page);
the aggregated lane's records (phase 3); a capability handshake for mixed fleets.
