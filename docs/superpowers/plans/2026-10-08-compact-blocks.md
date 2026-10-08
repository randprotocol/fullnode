# Compact Blocks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A proposal on the wire is the header, the leader's signature and the transaction hashes; a validator rebuilds the body from what it holds, fetches what it lacks by hash over the sync channel, and hands HotStuff the same full `Proposal` it handles today.

**Architecture:** All changes are in the node crate's network boundary plus one header-only precheck in the consensus crate. `GossipMessage::CompactProposal` is appended to the gossip enum; `SyncRequest::Transactions` / `SyncResponse::Transactions` are appended to the CBOR sync enums. A new module `crates/randprotocol-node/src/compact.rs` holds the pure pieces (the recent-transactions cache, the parked proposal, the rebuild) with unit tests; `node.rs` wires them into the gossip arm, the action handler, the sync client and the sync server. HotStuff, the ledger and the simulator are untouched.

**Tech Stack:** Rust 1.98.1 (`rust-toolchain.toml`), libp2p 0.54 gossipsub + request-response, bincode (gossip), cbor4ii (sync). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-08-compact-blocks-design.md` — read it first. Where this plan and the spec differ, this plan wins; the differences are the "Spec amendments" below.

**Worktree:** `~/rand-worktrees/fullnode-compact-blocks`, branch `feat/compact-blocks`, from `main` at `d6cc16f5`. Every path below is relative to it. Commit messages end with the two attribution lines of the session reminder.

## Spec amendments (found while planning)

1. **No tree index (§5.2).** The recent-transactions cache also remembers every transaction of every proposal this node sends or rebuilds (`RecentTxs::remember_block`), so a transaction in an uncommitted block is served from the cache, the pool or committed storage. Its byte cap is raised to `4 × max_block_bytes` to hold the three in-flight blocks plus gossip. `HotStuff` gains nothing.
2. **The hash list is checked against `tx_root` before any fetch (§5.1 gains rule 6).** `merkle_root(tx_hashes) == header.tx_root` and no duplicate hash, else Reject. A compact proposal that passes the pre-screen therefore always rebuilds into a block that passes `transaction_list_fault`, provided every fetched transaction's `hash()` equals the hash it was requested under (checked on receipt). The spec's "a rebuilt block that fails the root check is Rejected" cannot happen and is dropped.
3. **The fetch server stays on the consensus loop (§6),** as `BlockByHash` does: at most 512 hash-map / RocksDB gets, no snapshot, no `spawn_sync_serve`. It is still charged to the node-wide `SyncServeBudget` like a `Blocks` request. If measurement shows it matters it moves off-loop later.
4. **The parked proposal's fetch reports `Accept` to gossipsub.** After the pre-screen the message is provably the scheduled leader's (signature over the header, root over the hash list); forwarding it is correct whether or not this node holds the bodies yet, and withholding it would stall propagation while every node fetches. The rebuild outcome never changes the report.
5. **The missing-transaction cluster test is a node unit test (§9),** because the cluster harness has no way to deliver a transaction to some nodes only (subscriptions are hard-coded; RPC submissions are rebroadcast). The deterministic `bare_node` fixture covers park → request → response → vote. The cluster gets the frame-size measurement and the all-nodes-commit path.
6. **Line numbers**: `network/mod.rs` decode-Reject is at `:883-891`; `classify_consensus_gossip` `:1221`; `on_consensus` `:3295`; `fetch_block` `:3356`; `on_sync_response` `:3534`; sync server arm `:3208-3251`; `block_by_hash_response` `:378`; `handle_actions` `:2732` with the Broadcast arm at `:2770`.

## Global Constraints

- Toolchain pinned `1.98.1`; run cargo from the worktree root. No new dependencies.
- Clippy gate per touched crate: `cargo clippy -p randprotocol-core -p randprotocol-node --all-targets --no-deps -- -D warnings`.
- Node unit suite baseline: 471 passed / 21 failed (the 21 are the documented `RECURSION_FIXTURES` gap, AGENTS.md); core suite fully green. The cluster/e2e suites share a proving-slot lock file: never run two of them concurrently.
- Disk: ~29 GB free at planning time; a debug build of core+node is ~15 GB. Do not build release. Do not run `cargo clean` on other worktrees.
- Every gossip delivery is reported to gossipsub exactly once (Accept/Ignore/Reject), on every path including errors — `network/mod.rs` `NetworkEvent::Gossip` doc.
- The consensus crate changes only in `consensus/hotstuff/precheck.rs` (one new method) — nothing else in core.
- Doc comments are prose saying what and why, with spec references, in the repo's style; no TODOs.

## Review Focus

1. **A compact proposal whose hash list repeats a hash or does not match `tx_root`** → rejected before any fetch, forwarder penalised. (Task 2 test.)
2. **A `Transactions` response carrying a transaction whose hash was not requested, or one whose bytes hash to a different id** → discarded, never placed in the block, the peer treated as not holding it. (Task 5 test.)
3. **Two compact proposals for different views arriving while one is parked** → the newer view replaces the older park; the older's in-flight responses are ignored. (Task 4 test.)
4. **A validator that receives the compact form of a block it already holds in its tree** (a duplicate) → precheck/`on_message` handle it as today (`Stale`/duplicate), no fetch. (Task 4 test.)
5. **A `Transactions` request of more than 512 hashes or from a peer over its sync limit** → `Busy`, nothing served. (Task 5 test.)

---

### Task 1: wire types

**Files:**
- Modify: `crates/randprotocol-node/src/network/wire.rs` (enums at `:19-30` and `:95-119`; tests `:146-191`, `:242-272`, `:360`, `:406`, `:477`, `:525-539`, `:543`)
- Modify: `crates/randprotocol-node/src/network/mod.rs:504-511` (`Topics::for_message`), `:14` (re-export `CompactBlock`)
- Modify: `crates/randprotocol-node/tests/cluster.rs:2221-2226` and `:2321-2326` (exhaustive matches on `SyncRequest` in fake sync peers)
- Test: `wire.rs` tests

**Interfaces:**
- Produces:
  ```rust
  pub struct CompactBlock { pub header: BlockHeader, pub signature: Signature, pub tx_hashes: Vec<Hash> }
  impl CompactBlock {
      pub fn of(block: &Block) -> CompactBlock;
      pub fn into_block(self, transactions: Vec<Transaction>) -> Block;   // caller guarantees the list matches
      pub fn hash(&self) -> Hash;                                           // header.hash()
  }
  GossipMessage::CompactProposal(CompactBlock)   // tag 4, consensus topic
  SyncRequest::Transactions(Vec<Hash>)
  SyncResponse::Transactions(Vec<Transaction>)
  pub const TX_FETCH_BATCH: usize = 512;          // in wire.rs
  ```

- [ ] **Step 1: Failing tests** (in `wire.rs` `mod tests`, beside the PeerBinding test)

```rust
    /// Spec 2026-10-08 §3.1: `CompactProposal` is appended, so the four existing variants
    /// encode as before and the new one is tag 4; a build without it cannot decode it (the
    /// flag-day roll, §7).
    #[test]
    fn the_compact_proposal_variant_is_appended_as_the_fifth() {
        let ks = keys(4);
        let b = block(3, &ks);
        let compact = CompactBlock::of(&b);
        assert_eq!(compact.tx_hashes.len(), b.transactions.len());
        assert_eq!(compact.hash(), b.hash());
        let bytes = bincode::serialize(&GossipMessage::CompactProposal(compact.clone())).unwrap();
        assert_eq!(&bytes[..4], &[4, 0, 0, 0], "the new variant is the fifth");
        assert!(bincode::deserialize::<OldGossipMessage>(&bytes).is_err(), "an old node cannot read it");
        let GossipMessage::CompactProposal(read) = bincode::deserialize::<GossipMessage>(&bytes).unwrap() else { panic!("another variant") };
        assert_eq!(read.header, compact.header);
        assert_eq!(read.tx_hashes, compact.tx_hashes);
        // The rebuild is the block, byte for byte.
        assert_eq!(read.into_block(b.transactions.clone()), b);
        // A status still encodes as before (the shared variants did not move).
        let status = Status { height: 7, head_hash: Hash::digest(b"h"), view: 9, floor: 1 };
        assert_eq!(
            bincode::serialize(&GossipMessage::Status(status.clone())).unwrap(),
            bincode::serialize(&OldGossipMessage::Status(status)).unwrap()
        );
    }

    /// Spec 2026-10-08 §3.2: the transaction fetch is appended on both CBOR enums; the
    /// existing variants encode as before, and an old node fails to decode the new ones.
    #[test]
    fn the_transaction_fetch_variants_are_appended() {
        let req = SyncRequest::Transactions(vec![Hash::digest(b"a"), Hash::digest(b"b")]);
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &req).unwrap();
        assert!(matches!(cbor4ii::serde::from_slice::<SyncRequest>(&bytes).unwrap(), SyncRequest::Transactions(v) if v.len() == 2));
        assert!(cbor4ii::serde::from_slice::<OldSyncRequest>(&bytes).is_err(), "an old node cannot decode it");
        let resp = SyncResponse::Transactions(vec![]);
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &resp).unwrap();
        assert!(matches!(cbor4ii::serde::from_slice::<SyncResponse>(&bytes).unwrap(), SyncResponse::Transactions(v) if v.is_empty()));
        assert!(cbor4ii::serde::from_slice::<OldSyncResponse>(&bytes).is_err());
        assert_eq!(
            cbor4ii::serde::to_vec(Vec::new(), &SyncRequest::BlockByHash(Hash::ZERO)).unwrap(),
            cbor4ii::serde::to_vec(Vec::new(), &OldSyncRequest::BlockByHash(Hash::ZERO)).unwrap()
        );
        // 512 hashes fit the 64 KiB request limit with room.
        let big = SyncRequest::Transactions(vec![Hash::ZERO; TX_FETCH_BATCH]);
        assert!((cbor4ii::serde::to_vec(Vec::new(), &big).unwrap().len() as u64) < super::super::SYNC_REQUEST_WIRE_LIMIT / 2);
    }
```
Add an `OldSyncRequest` test enum beside `OldSyncResponse` (`Blocks { from_height: u64, max: u32 }`, `BlockByHash(Hash)`), if one does not exist. Update `an_unknown_gossip_variant_tag_is_rejected`: the unknown tags become `[5u32, 6, 100, u32::MAX]` and the comment says five known tags. Extend `every_gossip_variant_round_trips_through_bincode`, `every_sync_variant_round_trips_through_cbor` and `an_unknown_sync_variant_is_rejected`'s `FutureRequest`/`FutureResponse` enums so the new variants are covered the way the existing ones are.

- [ ] **Step 2: Run** `cargo test -p randprotocol-node wire:: 2>&1 | tail -5` → compile errors.

- [ ] **Step 3: Implement**

In `wire.rs`, after `PeerBinding`'s variant:
```rust
    /// A proposal with its body elided (spec 2026-10-08 §3.1): the header and the leader's
    /// signature — everything `Block::hash` and `Block::verify_signature` need — and the
    /// transaction hashes in block order. The receiver rebuilds the block from transactions it
    /// already holds and fetches the rest by hash (`SyncRequest::Transactions`). Appended last,
    /// so the four variants above encode as before; a build without it cannot decode it, which
    /// is why the roll is a flag day (§7).
    CompactProposal(CompactBlock),
```
and the type:
```rust
/// The wire form of a proposal (spec 2026-10-08 §3.1). `tx_hashes` is in block order; the
/// signed header's `tx_root` commits to it, so the list is checked before anything is fetched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactBlock {
    pub header: randprotocol_core::BlockHeader,
    pub signature: Signature,
    pub tx_hashes: Vec<Hash>,
}

/// The most hashes one `SyncRequest::Transactions` carries: 16 KB, under the request limit, and
/// at most four requests for a block at the transaction cap.
pub const TX_FETCH_BATCH: usize = 512;

impl CompactBlock {
    pub fn of(block: &Block) -> CompactBlock {
        CompactBlock {
            header: block.header.clone(),
            signature: block.signature.clone(),
            tx_hashes: block.transactions.iter().map(|t| t.hash()).collect(),
        }
    }

    /// The block this compact form elided, given its transactions in order. The caller has
    /// checked that each transaction hashes to the hash at its position (`compact::rebuild`).
    pub fn into_block(self, transactions: Vec<Transaction>) -> Block {
        Block { header: self.header, transactions, signature: self.signature }
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}
```
`SyncRequest` gains, appended:
```rust
    /// Transactions by hash (spec 2026-10-08 §3.2), at most [`TX_FETCH_BATCH`]: what a compact
    /// proposal named that this node does not hold. Appended last; an older node cannot decode
    /// it and reports an inbound failure.
    Transactions(Vec<Hash>),
```
`SyncResponse` gains, appended:
```rust
    /// The transactions this node holds of the hashes asked (any order; absent ones omitted, so
    /// the asker moves to the next peer for the rest). Appended last.
    Transactions(Vec<Transaction>),
```
Check `BlockHeader` is exported from `randprotocol_core` (`wire.rs` imports `Block, Hash, Keypair, PublicKey, Signature, Transaction` from the crate root; `BlockHeader` is used by tests as `randprotocol_core::types::block::BlockHeader` — use whichever path compiles, preferring the crate root if `lib.rs` re-exports it).

`network/mod.rs`: re-export `CompactBlock` and `TX_FETCH_BATCH` at `:14`; `Topics::for_message` gains `GossipMessage::CompactProposal(_) => &self.consensus,`.

`tests/cluster.rs:2221-2226` and `:2321-2326`: the fake sync peers' `match request { Blocks.., BlockByHash.. }` gain `SyncRequest::Transactions(_) => SyncResponse::Transactions(vec![]),` (a fake peer holds nothing).

- [ ] **Step 4: Run** `cargo test -p randprotocol-node wire:: 2>&1 | tail -5` → all PASS; `cargo build -p randprotocol-node --all-targets 2>&1 | grep -E "^error" | head` → the exhaustive-match errors in `node.rs` (`admit_sync_request`, `refused_sync_response`, the server arm, `serve_sync`, `on_sync_response`, the gossip arm) remain — **add minimal arms now** so the crate compiles: `SyncRequest::Transactions(_)` → `SyncAdmission::NodeBusy`-equivalent refusal (`SyncResponse::Busy`) in `admit_sync_request` (treat like `Blocks` for the budget), `refused_sync_response` (→ `Busy`), server arm and `serve_sync` (→ `SyncResponse::Busy` with a `// filled in by Task 5` comment is NOT allowed — write the real refusal: `Busy`), `on_sync_response`'s `SyncResponse::Transactions(_)` → `tracing::debug!("transactions response before the compact path is wired; ignored")` and `retry_fetch`-free return, and the gossip arm `GossipMessage::CompactProposal(_)` → report `Ignore` and log. These are replaced by Tasks 4–5; they keep the branch green in between.

- [ ] **Step 5: Clippy, commit**
```bash
cargo clippy -p randprotocol-node --all-targets --no-deps -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-node/src/network crates/randprotocol-node/src/node.rs crates/randprotocol-node/tests/cluster.rs
git commit -m "network: the compact-proposal gossip variant and the transaction-fetch sync variants, appended; CompactBlock::of / into_block

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 2: the header-only precheck

**Files:**
- Modify: `crates/randprotocol-core/src/consensus/hotstuff/precheck.rs` (new method after `precheck_gossip` `:117-201`; tests beside `replica()` `:247`)
- Test: `precheck.rs` tests

**Interfaces:**
- Produces: `pub fn precheck_compact(&self, header: &BlockHeader, signature: &Signature, tx_hashes: &[Hash]) -> GossipPrecheck` on `HotStuff`. Rules, in order: (1) `well_formed(proposer, signature)` else Reject; (2) `tx_hashes.len() > MAX_BLOCK_TXS` → Reject; (3) duplicate hash → Reject("a transaction appears twice in the block"); `merkle_root(tx_hashes) != header.tx_root` → Reject("the hashes are not the ones the header's root commits to"); (4) justify certifies parent, `precheck_qc`; (5) height ≤ committed → Ignore; view beyond window → Ignore; (6) proposer leads the view in a known set else Ignore; (7) header signature verifies else Reject. The byte cap cannot be checked without bodies; it is checked on the rebuilt block by the existing `precheck_gossip`.

- [ ] **Step 1: Failing tests** (precheck.rs tests, using `replica()`, `leader_key(hs, view)`, `proposal(hs, view, signer)`, `is_reject`, `is_ignore`)

```rust
    fn compact_of(b: &Block) -> (BlockHeader, Signature, Vec<Hash>) {
        (b.header.clone(), b.signature.clone(), b.transactions.iter().map(|t| t.hash()).collect())
    }

    /// Spec 2026-10-08 §5.1 and plan amendment 2: the header-only precheck admits the leader's
    /// signed proposal and refuses, before any fetch, what a full proposal's precheck refuses
    /// without a body: a bad key, too many hashes, a hash list the root does not commit to, a
    /// justify that does not certify the parent, a forged signature; and ignores what is stale,
    /// too far ahead, or from no known leader.
    #[test]
    fn the_compact_precheck_mirrors_the_full_one() {
        let hs = replica();
        let leader = leader_key(&hs, VIEW);
        let good = proposal(&hs, VIEW, &leader);
        let (h, s, hashes) = compact_of(&good);
        assert_eq!(hs.precheck_compact(&h, &s, &hashes), GossipPrecheck::Accept);

        let mut too_many = hashes.clone();
        too_many.resize(crate::gas::MAX_BLOCK_TXS + 1, Hash::ZERO);
        assert!(is_reject(hs.precheck_compact(&h, &s, &too_many)));

        let mut dup = hashes.clone();
        dup.push(Hash::digest(b"x"));
        dup.push(Hash::digest(b"x"));
        assert!(is_reject(hs.precheck_compact(&h, &s, &dup)), "a duplicate is rejected before the root");

        let mut swapped = hashes.clone();
        swapped.push(Hash::digest(b"not in the root"));
        assert!(is_reject(hs.precheck_compact(&h, &s, &swapped)), "a list the signed root does not commit to");

        let mut forged = s.clone();
        forged = crate::crypto::Keypair::from_seed([9; 32]).unwrap().sign(b"x"); // any other signature
        assert!(is_reject(hs.precheck_compact(&h, &forged, &hashes)));

        let stale = proposal(&hs, VIEW, &leader); // then lower its height below the committed head
        let mut sh = stale.header.clone();
        sh.height = hs.committed_height();
        assert!(is_ignore(hs.precheck_compact(&sh, &stale.signature, &hashes)), "at or under the head: ignored");

        let far = proposal(&hs, VIEW + PROPOSAL_VIEW_WINDOW + 1, &leader_key(&hs, VIEW + PROPOSAL_VIEW_WINDOW + 1));
        let (fh, fs, fx) = compact_of(&far);
        assert!(is_ignore(hs.precheck_compact(&fh, &fs, &fx)));

        let outsider = crate::crypto::Keypair::from_seed([77; 32]).unwrap();
        let nobody = proposal(&hs, VIEW, &outsider);
        let (nh, ns, nx) = compact_of(&nobody);
        assert!(is_ignore(hs.precheck_compact(&nh, &ns, &nx)), "leads no known set");
    }
```
(Adapt the forged-signature construction to the crate's `Signature` type: the simplest valid construction is signing a different message with the leader's key, `leader.sign(b"another message")`, which yields a well-formed signature that does not verify over the header.)

- [ ] **Step 2: Run** `cargo test -p randprotocol-core the_compact_precheck 2>&1 | tail -4` → compile error.

- [ ] **Step 3: Implement** in `precheck.rs`, after `precheck_gossip`:

```rust
    /// The header-only precheck of a compact proposal (spec 2026-10-08 §5.1; plan amendment
    /// 2): every rule of [`Self::precheck_gossip`]'s proposal arm that needs no body, in the
    /// same order and with the same verdicts, plus the one the compact form makes possible
    /// before any fetch — the hash list is what the signed `tx_root` commits to. What passes
    /// here is provably the scheduled leader's proposal; only then may a node fetch bodies for
    /// it, which is no more than a leader can make it download today by sending a full block.
    /// The byte cap waits for the rebuilt block, which goes through `precheck_gossip` in full.
    pub fn precheck_compact(&self, header: &BlockHeader, signature: &Signature, tx_hashes: &[Hash]) -> GossipPrecheck {
        if !well_formed(&header.proposer, signature) {
            return GossipPrecheck::Reject("proposal with a malformed key or signature");
        }
        if tx_hashes.len() > crate::gas::MAX_BLOCK_TXS {
            return GossipPrecheck::Reject("proposal over the block's transaction cap");
        }
        let mut seen = std::collections::HashSet::with_capacity(tx_hashes.len());
        if !tx_hashes.iter().all(|h| seen.insert(*h)) {
            return GossipPrecheck::Reject("a transaction appears twice in the block");
        }
        if crate::crypto::merkle_root(tx_hashes) != header.tx_root {
            return GossipPrecheck::Reject("the hashes are not the ones the header's root commits to");
        }
        if header.justify.block_hash != header.parent {
            return GossipPrecheck::Reject("proposal whose justify does not certify its parent");
        }
        let qc = self.precheck_qc(&header.justify);
        if qc != GossipPrecheck::Accept {
            return qc;
        }
        if header.height <= self.committed_height {
            return GossipPrecheck::Ignore("proposal at or under the committed head");
        }
        if header.view > self.view.saturating_add(PROPOSAL_VIEW_WINDOW) {
            return GossipPrecheck::Ignore("proposal too far ahead of this replica's view");
        }
        let proposer = header.proposer.address();
        if !self.any_known_set(|s| s.leader(header.view) == proposer) {
            return GossipPrecheck::Ignore("proposer leads the view in no validator set this replica knows");
        }
        if !header.proposer.verify(self.cfg.domain.block_message(header).as_bytes(), signature) {
            return GossipPrecheck::Reject("proposal signature does not verify");
        }
        GossipPrecheck::Accept
    }
```
Imports: `BlockHeader`, `Signature`, `Hash` as the file already imports its types (check the `use` block at the top). `merkle_root` over `&[Hash]` is `crate::crypto::merkle_root` — the same function `Block::tx_root` uses, so an empty list hashes to `Hash::ZERO` exactly as an empty block's `tx_root` does.

- [ ] **Step 4: Run, clippy, commit**
```bash
cargo test -p randprotocol-core precheck 2>&1 | tail -4
cargo clippy -p randprotocol-core --all-targets --no-deps -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-core/src/consensus/hotstuff/precheck.rs
git commit -m "consensus: precheck_compact — the header-only precheck of a compact proposal, with the hash list checked against the signed tx_root before any fetch

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 3: `compact.rs` — the cache, the park and the rebuild

**Files:**
- Create: `crates/randprotocol-node/src/compact.rs`
- Modify: `crates/randprotocol-node/src/lib.rs` (`pub mod compact;`)
- Test: unit tests in `compact.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const RECENT_TXS_MAX: usize = 4_096;
  pub fn recent_txs_bytes(max_block_bytes: usize) -> usize;        // 4 × max_block_bytes

  /// FIFO of gossiped and proposed transactions by hash, capped by count and bytes.
  pub struct RecentTxs;
  impl RecentTxs {
      pub fn new(max_entries: usize, max_bytes: usize) -> RecentTxs;
      pub fn remember(&mut self, tx: Transaction);                   // no-op if present; evicts oldest past either cap
      pub fn remember_block(&mut self, block: &Block);              // every transaction of the block
      pub fn get(&self, h: &Hash) -> Option<&Transaction>;
      pub fn len(&self) -> usize; pub fn bytes(&self) -> usize;
  }

  /// What a rebuild found: the block, or the hashes still missing in block order.
  pub enum Rebuilt { Block(Block), Missing { compact: CompactBlock, have: Vec<Option<Transaction>>, missing: Vec<Hash> } }
  pub fn rebuild(compact: CompactBlock, lookup: impl FnMut(&Hash) -> Option<Transaction>) -> Rebuilt;

  /// A compact proposal waiting for its bodies (spec §5.3): one per node, the newest view wins.
  pub struct Parked {
      pub compact: CompactBlock,            // header, signature, hashes
      pub have: Vec<Option<Transaction>>,   // by position
      pub from: PeerId,                     // the forwarder
      pub attempts: usize,                  // peers asked (≤ MAX_FETCH_ATTEMPTS)
      pub asked: Vec<PeerId>,
      pub inflight: HashMap<OutboundRequestId, (Vec<Hash>, Instant)>,  // request → the hashes it asked for
      pub since: Instant,
  }
  impl Parked {
      pub fn new(compact: CompactBlock, have: Vec<Option<Transaction>>, from: PeerId, now: Instant) -> Parked;
      pub fn view(&self) -> u64;
      pub fn missing(&self) -> Vec<Hash>;                                      // positions still None, block order
      pub fn next_batches(&self) -> Vec<Vec<Hash>>;                            // missing, chunked by TX_FETCH_BATCH, minus hashes already in flight
      /// Place the transactions a peer returned: only those whose `hash()` is a missing hash of
      /// this park. Returns how many were placed.
      pub fn accept(&mut self, txs: Vec<Transaction>) -> usize;
      pub fn complete(&self) -> bool;
      pub fn into_block(self) -> Option<Block>;                                 // Some iff complete
  }
  ```

- [ ] **Step 1: Failing tests** (`compact.rs` `#[cfg(test)] mod tests`; build transactions with `crate::storage::fixtures::bundle_tx` or `Transaction::mint(..)` as the node tests do — look at `node.rs:4363` for the mint form)

```rust
    #[test]
    fn the_recent_cache_is_fifo_by_count_and_bytes() {
        let mut c = RecentTxs::new(3, usize::MAX);
        let txs: Vec<Transaction> = (1..=4u8).map(mint).collect();
        for t in &txs[..3] { c.remember(t.clone()); }
        assert_eq!(c.len(), 3);
        c.remember(txs[3].clone());
        assert!(c.get(&txs[0].hash()).is_none(), "the oldest went");
        assert!(c.get(&txs[3].hash()).is_some());
        let one = bincode::serialized_size(&txs[0]).unwrap() as usize;
        let mut b = RecentTxs::new(usize::MAX, one * 2);
        for t in &txs[..3] { b.remember(t.clone()); }
        assert_eq!(b.len(), 2, "two fit the byte cap");
        assert!(b.bytes() <= one * 2);
        b.remember(txs[1].clone());
        assert_eq!(b.len(), 2, "remembering a held transaction is a no-op");
    }

    #[test]
    fn rebuild_finds_what_it_can_and_lists_the_rest_in_order() {
        let txs: Vec<Transaction> = (1..=3u8).map(mint).collect();
        let block = block_of(txs.clone());
        let compact = CompactBlock::of(&block);
        let all = rebuild(compact.clone(), |h| txs.iter().find(|t| &t.hash() == h).cloned());
        let Rebuilt::Block(b) = all else { panic!("complete") };
        assert_eq!(b, block);
        let some = rebuild(compact, |h| if *h == txs[1].hash() { None } else { txs.iter().find(|t| &t.hash() == h).cloned() });
        let Rebuilt::Missing { have, missing, .. } = some else { panic!("incomplete") };
        assert_eq!(missing, vec![txs[1].hash()]);
        assert_eq!(have.iter().filter(|t| t.is_some()).count(), 2);
    }

    #[test]
    fn a_park_accepts_only_what_it_asked_for_and_completes() {
        let txs: Vec<Transaction> = (1..=3u8).map(mint).collect();
        let block = block_of(txs.clone());
        let compact = CompactBlock::of(&block);
        let have = vec![Some(txs[0].clone()), None, None];
        let mut p = Parked::new(compact, have, PeerId::random(), Instant::now());
        assert_eq!(p.missing(), vec![txs[1].hash(), txs[2].hash()]);
        assert_eq!(p.next_batches(), vec![vec![txs[1].hash(), txs[2].hash()]]);
        let stranger = mint(9);
        assert_eq!(p.accept(vec![stranger, txs[2].clone()]), 1, "the stranger is discarded");
        assert!(!p.complete());
        assert_eq!(p.accept(vec![txs[1].clone()]), 1);
        assert!(p.complete());
        assert_eq!(p.into_block().unwrap(), block);
    }

    #[test]
    fn batches_are_chunked_and_skip_what_is_in_flight() {
        let txs: Vec<Transaction> = (1..=5u8).map(mint).collect();
        let block = block_of(txs.clone());
        let compact = CompactBlock::of(&block);
        let mut p = Parked::new(compact, vec![None; 5], PeerId::random(), Instant::now());
        // Pretend the batch size is 2 for this test by chunking the result ourselves: the
        // real TX_FETCH_BATCH is 512, so five hashes are one batch.
        assert_eq!(p.next_batches().len(), 1);
        p.inflight.insert(fake_request_id(), (vec![txs[0].hash(), txs[1].hash()], Instant::now()));
        assert_eq!(p.next_batches(), vec![txs[2..].iter().map(|t| t.hash()).collect::<Vec<_>>()]);
    }
```
Helpers in the test module: `mint(i: u8) -> Transaction` (the `node.rs:4363` form with `StubExecutor` and `key(1)` from `crate::storage::fixtures`), `block_of(txs) -> Block` (a header with `tx_root: Block::tx_root(&txs)`, `justify: QuorumCertificate::genesis(Hash::ZERO)`, signed with `key(1)` under `SigningDomain::v0(Hash::ZERO)` — the `wire.rs` test helper `block(height, ks)` is the shape), and `fake_request_id()` — `OutboundRequestId` has no public constructor; if it cannot be built in a test, make `inflight` generic-free by keying it on a `u64` the node maps from the request id (`Parked::inflight: HashMap<u64, ..>` with the node passing `request_id` through a `HashMap<OutboundRequestId, u64>`), or simpler: store `inflight: Vec<(OutboundRequestId, Vec<Hash>, Instant)>` and give `next_batches` an explicit `in_flight: &[Vec<Hash>]` argument the test can pass. Choose the explicit-argument form: `pub fn next_batches(&self, in_flight: &[Vec<Hash>]) -> Vec<Vec<Hash>>`.

- [ ] **Step 2: Run** `cargo test -p randprotocol-node compact:: 2>&1 | tail -4` → compile errors.

- [ ] **Step 3: Implement** (`compact.rs`)

```rust
//! Compact blocks (spec 2026-10-08): the pieces of the proposal path that need no node state —
//! the cache of recently seen transaction bodies, the rebuild of a block from a compact
//! proposal, and a parked proposal waiting for the bodies it lacks. `node.rs` wires them to
//! gossip, the sync channel and the replica; HotStuff never sees a compact proposal.

use crate::network::{CompactBlock, TX_FETCH_BATCH};
use libp2p::PeerId;
use randprotocol_core::{Block, Hash, Transaction};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// How many transaction bodies the node keeps beside its pool, by count. With the byte cap it
/// is the window between a transaction's arrival on gossip and its verdict, plus the bodies of
/// the three blocks in flight (plan amendment 1).
pub const RECENT_TXS_MAX: usize = 4_096;

/// The cache's byte cap: four blocks' worth on the chain's cap.
pub fn recent_txs_bytes(max_block_bytes: usize) -> usize {
    max_block_bytes.saturating_mul(4)
}

pub struct RecentTxs {
    by_hash: HashMap<Hash, Transaction>,
    order: VecDeque<(Hash, usize)>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl RecentTxs {
    pub fn new(max_entries: usize, max_bytes: usize) -> RecentTxs {
        RecentTxs { by_hash: HashMap::new(), order: VecDeque::new(), bytes: 0, max_entries, max_bytes }
    }

    pub fn remember(&mut self, tx: Transaction) {
        let h = tx.hash();
        if self.by_hash.contains_key(&h) {
            return;
        }
        let len = bincode::serialized_size(&tx).map_or(0, |n| n as usize);
        self.by_hash.insert(h, tx);
        self.order.push_back((h, len));
        self.bytes = self.bytes.saturating_add(len);
        while self.order.len() > self.max_entries || self.bytes > self.max_bytes {
            let Some((old, old_len)) = self.order.pop_front() else { break };
            self.by_hash.remove(&old);
            self.bytes = self.bytes.saturating_sub(old_len);
        }
    }

    pub fn remember_block(&mut self, block: &Block) {
        for tx in &block.transactions {
            self.remember(tx.clone());
        }
    }

    pub fn get(&self, h: &Hash) -> Option<&Transaction> {
        self.by_hash.get(h)
    }

    pub fn len(&self) -> usize { self.order.len() }
    pub fn is_empty(&self) -> bool { self.order.is_empty() }
    pub fn bytes(&self) -> usize { self.bytes }
}

pub enum Rebuilt {
    Block(Block),
    Missing { compact: CompactBlock, have: Vec<Option<Transaction>>, missing: Vec<Hash> },
}

/// Rebuild the block a compact proposal elided from `lookup`, or say which hashes are missing,
/// in block order. The hash list was checked against the signed root by `precheck_compact`, so
/// a complete rebuild is the block the leader signed.
pub fn rebuild(compact: CompactBlock, mut lookup: impl FnMut(&Hash) -> Option<Transaction>) -> Rebuilt {
    let have: Vec<Option<Transaction>> = compact.tx_hashes.iter().map(|h| lookup(h)).collect();
    if have.iter().all(Option::is_some) {
        let txs = have.into_iter().map(|t| t.expect("all present")).collect();
        return Rebuilt::Block(compact.into_block(txs));
    }
    let missing = compact.tx_hashes.iter().zip(&have).filter(|(_, t)| t.is_none()).map(|(h, _)| *h).collect();
    Rebuilt::Missing { compact, have, missing }
}

pub struct Parked {
    pub compact: CompactBlock,
    pub have: Vec<Option<Transaction>>,
    pub from: PeerId,
    pub attempts: usize,
    pub asked: Vec<PeerId>,
    pub inflight: Vec<(libp2p::request_response::OutboundRequestId, Vec<Hash>, Instant)>,
    pub since: Instant,
}

impl Parked {
    pub fn new(compact: CompactBlock, have: Vec<Option<Transaction>>, from: PeerId, now: Instant) -> Parked {
        Parked { compact, have, from, attempts: 0, asked: Vec::new(), inflight: Vec::new(), since: now }
    }

    pub fn view(&self) -> u64 { self.compact.header.view }

    pub fn missing(&self) -> Vec<Hash> {
        self.compact.tx_hashes.iter().zip(&self.have).filter(|(_, t)| t.is_none()).map(|(h, _)| *h).collect()
    }

    /// The hashes still to ask for, in block order, chunked by [`TX_FETCH_BATCH`], minus those
    /// a request already in flight asked for.
    pub fn next_batches(&self, in_flight: &[Vec<Hash>]) -> Vec<Vec<Hash>> {
        let pending: HashSet<Hash> = in_flight.iter().flatten().copied().collect();
        let wanted: Vec<Hash> = self.missing().into_iter().filter(|h| !pending.contains(h)).collect();
        wanted.chunks(TX_FETCH_BATCH).map(|c| c.to_vec()).collect()
    }

    /// Place what a peer returned: a transaction goes in only at a position whose hash is
    /// still missing and equals `tx.hash()` — a stranger, a duplicate or a body that hashes to
    /// something else is discarded (review focus 2). Returns how many were placed.
    pub fn accept(&mut self, txs: Vec<Transaction>) -> usize {
        let mut placed = 0;
        for tx in txs {
            let h = tx.hash();
            if let Some(i) = self.compact.tx_hashes.iter().position(|x| *x == h) {
                if self.have[i].is_none() {
                    self.have[i] = Some(tx);
                    placed += 1;
                }
            }
        }
        placed
    }

    pub fn complete(&self) -> bool { self.have.iter().all(Option::is_some) }

    pub fn into_block(self) -> Option<Block> {
        if !self.complete() { return None; }
        let txs = self.have.into_iter().map(|t| t.expect("complete")).collect();
        Some(self.compact.into_block(txs))
    }
}
```
`position` over 2 000 hashes per returned transaction is O(n·k); build a `HashMap<Hash, usize>` once in `accept` if `tx_hashes.len() > 64`. Keep it simple but not quadratic at the cap: build the map unconditionally.

- [ ] **Step 4: Run, clippy, commit**
```bash
cargo test -p randprotocol-node compact:: 2>&1 | tail -6
cargo clippy -p randprotocol-node --all-targets --no-deps -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-node/src/compact.rs crates/randprotocol-node/src/lib.rs
git commit -m "node: compact — the recent-transactions cache, the rebuild of a block from a compact proposal, and the parked proposal that waits for its bodies

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 4: the receive path — pre-screen, rebuild, park, request

**Files:**
- Modify: `crates/randprotocol-node/src/node.rs` — `Node` fields (~`:924-1067`), the node constructor where `fetch_inflight` etc. are initialised (search `fetch_inflight: HashMap::new()`), the gossip arm `:3146-3207` (replace Task 1's placeholder `CompactProposal` arm), `handle_actions` `:2770-2784` (`ScheduleTimeout` arm drops a stale park), `on_gossiped_tx` `:2603` (remember the decoded transaction), `bare_node` `:5626` (also capture `Broadcast`)
- Test: `node.rs` tests beside `fetch_block_measures_the_gate_from_the_pending_tip` `:5788`

**Interfaces:**
- Consumes: `compact::{RecentTxs, Parked, Rebuilt, rebuild, RECENT_TXS_MAX, recent_txs_bytes}`, `HotStuff::precheck_compact`, `CompactBlock`.
- Produces on `Node`: fields `recent_txs: compact::RecentTxs`, `parked: Option<compact::Parked>`; methods `async fn on_compact_proposal(&mut self, c: CompactBlock, id: GossipId) -> Result<()>`, `async fn handle_rebuilt(&mut self, block: Block) -> Result<()>` (runs `hs.precheck_gossip(&Proposal)` for the byte cap and the rest, logs an Ignore/Reject, else `highest_proposal_seen` + `on_consensus`), `async fn request_parked_bodies(&mut self)` (sends the next batches to the next candidate peer; on exhaustion drops the park and logs), `fn fetch_candidates(&self, asked: &[PeerId], prefer: Option<PeerId>) -> Vec<PeerId>` (factored out of `fetch_block`'s two filters, with `prefer` first when connected and not asked). `fetch_block` is rewritten to call `fetch_candidates(&asked, None)` so the two share one policy.

- [ ] **Step 1: Failing tests** (node.rs tests; extend `bare_node` first so it also forwards `NetworkCommand::Broadcast(m)` as `Seen::Broadcast(m)` and `SendSyncRequest` as `Seen::Sync(peer, request)` on one `mpsc::UnboundedReceiver<Seen>`; keep `sent_by_hash` working by filtering)

```rust
    /// A compact proposal naming only transactions in the pool rebuilds and is handled as a
    /// full proposal: the replica holds the block and no request goes out (spec §5.2).
    #[tokio::test]
    async fn a_compact_proposal_rebuilds_from_the_pool() {
        let (_d, storage, gs, hs) = chain_past_a_boundary_with_replica(); // chain_past_a_boundary + resume_consensus
        let (mut node, mut seen) = bare_node(storage, gs, hs);
        let tx = mint_for(&node, 1);
        node.mempool.insert_verified(tx.clone(), node.hs.tip_ledger(), node.executor.as_ref()).unwrap();
        let block = next_block_with(&node.storage.head_block().unwrap(), node.hs.tip_ledger(), &key(1), vec![tx]);
        let compact = CompactBlock::of(&block);
        let id = gossip_id();
        node.on_compact_proposal(compact, id).await.unwrap();
        assert!(node.hs.has_block(&block.hash()), "handled as a proposal");
        assert!(node.parked.is_none());
        assert!(sent_sync(&mut seen).await.is_empty(), "nothing fetched");
    }

    /// A missing body parks the proposal and asks the proposer's peer first (spec §5.3).
    #[tokio::test]
    async fn a_missing_body_parks_and_asks_the_leader_first() {
        let (_d, storage, gs, hs) = chain_past_a_boundary_with_replica();
        let (mut node, mut seen) = bare_node(storage, gs, hs);
        let tx = mint_for(&node, 1);
        let block = next_block_with(&node.storage.head_block().unwrap(), node.hs.tip_ledger(), &key(1), vec![tx.clone()]);
        let leader_peer = claiming_peer(&mut node, 4);
        node.peer_bindings.insert_for_test(key(1).address(), leader_peer);   // add this test hook if absent
        let other = claiming_peer(&mut node, 4);
        node.on_compact_proposal(CompactBlock::of(&block), gossip_id()).await.unwrap();
        assert!(!node.hs.has_block(&block.hash()));
        let p = node.parked.as_ref().expect("parked");
        assert_eq!(p.missing(), vec![tx.hash()]);
        let sent = sent_sync(&mut seen).await;
        assert_eq!(sent, vec![(leader_peer, SyncRequest::Transactions(vec![tx.hash()]))], "the leader's peer first, not {other}");
    }

    /// A newer view's compact proposal replaces an older park (review focus 3).
    #[tokio::test]
    async fn a_newer_view_replaces_the_park() { /* two compact proposals for views v and v+1 from the right leaders, both missing a body; after the second, parked.view() == v+1 */ }

    /// A compact proposal for a block the replica already holds makes no fetch (review focus 4).
    #[tokio::test]
    async fn a_held_block_is_not_fetched_again() { /* rebuild from the pool, handle, then send the same compact again: no park, no request */ }

    /// The park is dropped when the view moves on (spec §5.3).
    #[tokio::test]
    async fn a_park_is_dropped_on_view_change() { /* park, then handle_actions(vec![Action::ScheduleTimeout { view: parked_view + 1, .. }]) → parked is None */ }

    /// A gossiped transaction is remembered whatever its verdict, so a proposal that names it
    /// rebuilds while it is still in the verify queue (spec §5.4).
    #[tokio::test]
    async fn a_gossiped_transaction_is_remembered_before_its_verdict() { /* on_gossiped_tx(tx) then recent_txs.get(&tx.hash()).is_some() */ }
```
Write the four sketched tests in full in the same style as the two full ones.

- [ ] **Step 2: Run** → compile errors (`on_compact_proposal`, `parked`, `recent_txs`).

- [ ] **Step 3: Implement**

Fields on `Node`: `recent_txs: compact::RecentTxs` (constructed `RecentTxs::new(RECENT_TXS_MAX, recent_txs_bytes(gs.ledger.max_block_bytes()))`), `parked: Option<compact::Parked>`.

Gossip arm:
```rust
                GossipMessage::CompactProposal(c) => self.on_compact_proposal(c, id).await?,
```
```rust
    /// A compact proposal (spec 2026-10-08 §5): metered like any consensus message, prechecked
    /// on its header and hash list, reported once, then rebuilt from the pool, the recent cache
    /// and committed storage; what is missing is fetched by hash (§5.3), with the proposal
    /// parked meanwhile. The report is the pre-screen's verdict, never the rebuild's (plan
    /// amendment 4): a proposal that passed is provably the scheduled leader's.
    async fn on_compact_proposal(&mut self, c: CompactBlock, id: GossipId) -> Result<()> {
        use admission::Acceptance;
        use randprotocol_core::consensus::GossipPrecheck;
        let now = Instant::now();
        let forwarder = id.propagation_source;
        if on_consensus_gossip(&mut self.peers, &self.consensus_limiter, forwarder, now) != GossipOutcome::for_consensus() {
            self.report(id, GossipOutcome::Report(Acceptance::Ignore)).await;
            return Ok(());
        }
        let bytes = bincode::serialized_size(&c).unwrap_or(u64::MAX) as f64;
        let bucket = &mut self.peers.entry(forwarder).or_default().consensus_byte_bucket;
        if !self.consensus_byte_limiter.allow_n(bucket, bytes, now) {
            self.report(id, GossipOutcome::Report(Acceptance::Ignore)).await;
            return Ok(());
        }
        match self.hs.precheck_compact(&c.header, &c.signature, &c.tx_hashes) {
            GossipPrecheck::Accept => self.report(id, GossipOutcome::Report(Acceptance::Accept)).await,
            GossipPrecheck::Ignore(why) => {
                tracing::debug!(%forwarder, "compact proposal not forwarded: {why}");
                self.report(id, GossipOutcome::Report(Acceptance::Ignore)).await;
                return Ok(());
            }
            GossipPrecheck::Reject(why) => {
                tracing::debug!(%forwarder, "compact proposal rejected: {why}");
                self.report(id, GossipOutcome::Report(Acceptance::Reject)).await;
                return Ok(());
            }
        }
        if self.hs.has_block(&c.hash()) {
            return Ok(());
        }
        let (pool, recent, storage) = (&self.mempool, &self.recent_txs, &self.storage);
        let total = c.tx_hashes.len();
        let mut hits = 0usize;
        let rebuilt = compact::rebuild(c, |h| {
            let found = pool.get(h).cloned().or_else(|| recent.get(h).cloned()).or_else(|| storage.tx_by_hash(h).ok().flatten());
            hits += found.is_some() as usize;
            found
        });
        match rebuilt {
            compact::Rebuilt::Block(block) => {
                tracing::info!("compact proposal height {} view {}: {total} transactions, {hits} held, 0 fetched", block.height(), block.view());
                self.handle_rebuilt(block).await
            }
            compact::Rebuilt::Missing { compact, have, missing } => {
                tracing::info!("compact proposal height {} view {}: {total} transactions, {hits} held, {} to fetch", compact.header.height, compact.header.view, missing.len());
                if self.parked.as_ref().is_some_and(|p| p.view() > compact.header.view) {
                    tracing::debug!("a newer view is already parked; dropping the older compact proposal");
                    return Ok(());
                }
                self.parked = Some(compact::Parked::new(compact, have, forwarder, now));
                self.request_parked_bodies().await
            }
        }
    }

    /// The rebuilt block goes through the full precheck (the byte cap, which needs the bodies)
    /// and then the replica, exactly as a full proposal does.
    async fn handle_rebuilt(&mut self, block: Block) -> Result<()> {
        use randprotocol_core::consensus::GossipPrecheck;
        let m = ConsensusMessage::Proposal(block);
        match self.hs.precheck_gossip(&m) {
            GossipPrecheck::Accept | GossipPrecheck::Ignore(_) => {}
            GossipPrecheck::Reject(why) => {
                tracing::warn!("rebuilt proposal refused: {why}");
                return Ok(());
            }
        }
        if let ConsensusMessage::Proposal(b) = &m {
            self.recent_txs.remember_block(b);
            self.highest_proposal_seen = self.highest_proposal_seen.max(b.height());
        }
        self.on_consensus(m).await
    }

    /// Ask the next peer for the parked proposal's missing bodies (spec §5.3): the leader's
    /// bound peer first, then peers at or above our height, then any — the policy
    /// `fetch_block` uses, with the same attempt cap. Nothing left to ask: the park is dropped
    /// and the view times out as an unknown parent does.
    async fn request_parked_bodies(&mut self) -> Result<()> {
        let Some(p) = self.parked.as_mut() else { return Ok(()) };
        let in_flight: Vec<Vec<Hash>> = p.inflight.iter().map(|(_, h, _)| h.clone()).collect();
        let batches = p.next_batches(&in_flight);
        if batches.is_empty() {
            return Ok(());
        }
        if p.attempts >= MAX_FETCH_ATTEMPTS {
            tracing::warn!("compact proposal view {}: no peer supplied its bodies after {} attempts; dropped", p.view(), p.attempts);
            self.parked = None;
            return Ok(());
        }
        let leader_peer = self.peer_bindings.get(&p.compact.header.proposer.address()).map(|b| b.peer);
        let asked = p.asked.clone();
        let Some(peer) = self.fetch_candidates(&asked, leader_peer).first().copied() else {
            tracing::warn!("compact proposal view {}: no peer left to ask for its bodies; dropped", p.view());
            self.parked = None;
            return Ok(());
        };
        let p = self.parked.as_mut().expect("checked");
        p.attempts += 1;
        p.asked.push(peer);
        for batch in batches {
            if let Some(rid) = self.net.send_sync_request(peer, SyncRequest::Transactions(batch.clone())).await {
                if let Some(p) = self.parked.as_mut() { p.inflight.push((rid, batch, Instant::now())); }
            }
        }
        Ok(())
    }
```
`fetch_candidates`:
```rust
    /// Peers to ask for a body, in order: `prefer` (the leader's bound peer) if connected and
    /// not yet asked; then connected peers not yet asked whose status is at or past our
    /// committed height; then any connected peer not yet asked.
    fn fetch_candidates(&self, asked: &[PeerId], prefer: Option<PeerId>) -> Vec<PeerId> { .. }
```
and `fetch_block` uses it. `handle_actions`'s `ScheduleTimeout { view, .. }` arm: `if self.parked.as_ref().is_some_and(|p| p.view() < view) { self.parked = None; }`. `on_gossiped_tx`: first line after decoding, `self.recent_txs.remember(tx.clone());` (before the limiter — the bytes were already received; keep it after the `RefusedCache` check so bytes-only junk is not cached, per spec §5.4: place it right after `GossipOutcome::for_transaction` returns `Verify`).

`peer_bindings.insert_for_test` — add a `#[cfg(test)] pub(crate) fn insert_for_test(&mut self, validator: Address, peer: PeerId)` to `peer_bindings.rs` if no setter exists.

- [ ] **Step 4: Run, clippy, commit**
```bash
cargo test -p randprotocol-node compact_proposal 2>&1 | tail -8   # the new tests
cargo test -p randprotocol-node fetch_block 2>&1 | tail -3         # the refactor kept them
cargo clippy -p randprotocol-node --all-targets --no-deps -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-node/src/node.rs crates/randprotocol-node/src/peer_bindings.rs
git commit -m "node: receive a compact proposal — metered, prechecked on the header and hash list, rebuilt from pool/cache/storage, or parked while its bodies are fetched from the leader's peer first

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 5: the sync channel — client responses and the server

**Files:**
- Modify: `crates/randprotocol-node/src/node.rs` — `admit_sync_request` `:1293-1315`, `refused_sync_response` `:1345-1350`, the server arm `:3208-3251`, `serve_sync` `:3337-3350`, `on_sync_response` `:3534-3667`, the `SyncFailed` arm `:3285`, `fetch_block`'s `expire_stale_fetches` call (also expire parked in-flight requests)
- Test: `node.rs` tests

**Interfaces:**
- Produces: `fn serve_transactions(&self, hashes: &[Hash]) -> SyncResponse` (pool → recent → storage; `Busy` over `TX_FETCH_BATCH`); `async fn on_transactions_response(&mut self, peer: PeerId, request_id: OutboundRequestId, txs: Vec<Transaction>) -> Result<()>`.

- [ ] **Step 1: Failing tests**

```rust
    /// The bodies a peer returns complete the park; the proposal is handled and the replica
    /// votes (spec §5.3). A stranger in the response is discarded (review focus 2).
    #[tokio::test]
    async fn a_transactions_response_completes_the_park() { /* park (as in Task 4's test), then node.on_sync_response(peer, rid, SyncResponse::Transactions(vec![stranger, tx])) with the rid taken from node.parked.inflight; assert hs.has_block(&block.hash()) and parked.is_none() */ }

    /// A response missing some hashes keeps the park and asks the next peer for the rest.
    #[tokio::test]
    async fn a_partial_response_moves_to_the_next_peer() { /* two missing; response has one; a new SyncRequest::Transactions with the other hash goes to a different peer */ }

    /// A body whose hash differs from what was asked is not placed, and the peer counts as not
    /// holding it (review focus 2).
    #[tokio::test]
    async fn a_wrong_body_is_discarded() { /* response carries a tx with another hash; park unchanged; next peer asked */ }

    /// The server answers from the pool, the recent cache and committed storage, and `Busy`
    /// over the batch size or the peer's limit (spec §6, review focus 5).
    #[tokio::test]
    async fn the_server_answers_from_pool_cache_and_storage_and_refuses_oversize() { /* insert one tx in the pool, one in recent_txs, one committed (storage.tx_by_hash of a block-2 tx from chain_past_a_boundary); serve_transactions over the three plus an unknown hash returns exactly the three; a request of TX_FETCH_BATCH + 1 hashes returns Busy; admit_sync_request charges the global budget like Blocks */ }
```
Write them in full.

- [ ] **Step 2: Run** → the placeholder arms from Task 1 make these fail at assertions, not compile. Confirm the failures.

- [ ] **Step 3: Implement**

`admit_sync_request`: `SyncRequest::Transactions(h) if h.len() <= TX_FETCH_BATCH && global.allow(validator, now) => Serve`, `SyncRequest::Transactions(_) => NodeBusy` (an oversize request is refused as busy and costs the peer its per-peer token, which `allow` already spent). `refused_sync_response`: `Transactions(_) => Busy`. Server arm and `serve_sync`: `SyncRequest::Transactions(h) => self.serve_transactions(&h)`:
```rust
    /// The bodies of `hashes` this node holds (spec 2026-10-08 §6): the pool, the recent cache,
    /// then committed storage. On the loop, as `BlockByHash` is: at most TX_FETCH_BATCH map and
    /// store reads (plan amendment 3). Over the batch size it is `Busy`, never a partial answer
    /// — the asker's batches are bounded, so an oversize request is not an honest one.
    fn serve_transactions(&self, hashes: &[Hash]) -> SyncResponse {
        if hashes.len() > TX_FETCH_BATCH {
            return SyncResponse::Busy;
        }
        let txs = hashes
            .iter()
            .filter_map(|h| {
                self.mempool.get(h).cloned().or_else(|| self.recent_txs.get(h).cloned()).or_else(|| self.storage.tx_by_hash(h).ok().flatten())
            })
            .collect();
        SyncResponse::Transactions(txs)
    }
```
`on_sync_response`: `SyncResponse::Transactions(txs) => self.on_transactions_response(peer, request_id, txs).await?`:
```rust
    async fn on_transactions_response(&mut self, peer: PeerId, request_id: OutboundRequestId, txs: Vec<Transaction>) -> Result<()> {
        let Some(p) = self.parked.as_mut() else {
            tracing::debug!(%peer, "transactions for no parked proposal; ignored");
            return Ok(());
        };
        let Some(i) = p.inflight.iter().position(|(rid, _, _)| *rid == request_id) else {
            tracing::debug!(%peer, "transactions for a request this park did not make; ignored");
            return Ok(());
        };
        let (_, asked, _) = p.inflight.remove(i);
        let placed = p.accept(txs);
        tracing::debug!(%peer, asked = asked.len(), placed, "transactions received for the parked proposal");
        if p.complete() {
            let block = self.parked.take().and_then(|p| p.into_block()).expect("complete");
            return self.handle_rebuilt(block).await;
        }
        if p.inflight.is_empty() {
            self.request_parked_bodies().await?;   // the rest, from the next peer
        }
        Ok(())
    }
```
`SyncFailed { request_id, .. }` arm: besides `retry_fetch`, if the park has that request in flight, remove it and call `request_parked_bodies`. `fetch_block`'s stale-expiry: also expire parked in-flight requests older than `self.wire.sync_request_timeout` (a small helper on `Parked`: `pub fn expire(&mut self, timeout: Duration, now: Instant) -> usize`), then `request_parked_bodies` if anything expired — call it from the same timer tick that drives `fetch_block` expiries (the `sleep_until` timeout arm in `run`, or wherever `expire_stale_fetches` is reached periodically; if only inside `fetch_block`, add the expiry at the top of `request_parked_bodies` and call `request_parked_bodies` from the status-gossip tick (every 3 s) when a park exists).

- [ ] **Step 4: Run, clippy, commit**
```bash
cargo test -p randprotocol-node "transactions_response|the_server_answers|partial_response|wrong_body" 2>&1 | tail -8
cargo test -p randprotocol-node 2>&1 | tail -3     # 471+N passed / 21 failed
cargo clippy -p randprotocol-node --all-targets --no-deps -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-node/src/node.rs crates/randprotocol-node/src/compact.rs
git commit -m "node: the transaction fetch — responses complete the parked proposal or move to the next peer; the server answers by hash from pool, cache and storage under the sync budget

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 6: the send path

**Files:**
- Modify: `crates/randprotocol-node/src/node.rs` `handle_actions` `:2770-2772`
- Test: `node.rs` tests (with `bare_node`'s `Broadcast` capture from Task 4)

- [ ] **Step 1: Failing test**
```rust
    /// The leader publishes its proposal in compact form and remembers the bodies to serve them
    /// (spec §4); votes and NewViews go out as before.
    #[tokio::test]
    async fn a_proposal_is_broadcast_compact_and_remembered() {
        let (_d, storage, gs, hs) = chain_past_a_boundary_with_replica();
        let (mut node, mut seen) = bare_node(storage, gs, hs);
        let tx = mint_for(&node, 1);
        let block = next_block_with(&node.storage.head_block().unwrap(), node.hs.tip_ledger(), &key(1), vec![tx.clone()]);
        node.handle_actions(vec![Action::Broadcast(ConsensusMessage::Proposal(block.clone()))]).await.unwrap();
        let out = broadcasts(&mut seen).await;
        assert!(matches!(&out[..], [GossipMessage::CompactProposal(c)] if c.tx_hashes == vec![tx.hash()] && c.header == block.header));
        assert!(node.recent_txs.get(&tx.hash()).is_some());
        let vote = Vote::sign(node.hs.domain(), 1, block.hash(), &key(1));
        node.handle_actions(vec![Action::Broadcast(ConsensusMessage::Vote(vote))]).await.unwrap();
        assert!(matches!(&broadcasts(&mut seen).await[..], [GossipMessage::Consensus(ConsensusMessage::Vote(_))]));
    }
```
- [ ] **Step 2: Run** → fails (a full `Consensus(Proposal)` is broadcast).
- [ ] **Step 3: Implement**
```rust
                Action::Broadcast(ConsensusMessage::Proposal(b)) | Action::SendTo(_, ConsensusMessage::Proposal(b)) => {
                    // Spec 2026-10-08 §4: the body stays here (the pool until commit, the tree,
                    // the recent cache) and the wire carries the hashes; validators that lack a
                    // body fetch it by hash.
                    self.recent_txs.remember_block(&b);
                    self.net.broadcast(GossipMessage::CompactProposal(CompactBlock::of(&b))).await;
                }
                Action::Broadcast(m) | Action::SendTo(_, m) => {
                    self.net.broadcast(GossipMessage::Consensus(m)).await;
                }
```
- [ ] **Step 4: Run, clippy, commit** (message: "node: a proposal is broadcast compact — header, signature and transaction hashes — and its bodies remembered to serve").

---

### Task 7: cluster run and measurement

**Files:**
- Modify: `crates/randprotocol-node/tests/common/cluster.rs` (move the `Observer` from `tests/network.rs:135-213` into `common` as `pub struct Observer` with `pub async fn start(chain_id, bootstrap) -> Observer` and `pub async fn pump(&mut self, dur) -> Vec<Seen>`; `tests/network.rs` uses the shared one)
- Modify: `crates/randprotocol-node/tests/cluster.rs` (two new tests)
- Modify: `docs/node-hardware.md` (a §8 "Compact proposals on the wire")
- Test: the two cluster tests; the existing cluster suite

- [ ] **Step 1: The tests**
```rust
/// Spec 2026-10-08 §1: a proposal carrying N transactions is on the consensus topic as hashes.
/// With four validators the frame is the header and justify (~20 KB) plus 32 bytes a
/// transaction; the full block would be the transactions' bytes. The observer reads the raw
/// gossipsub frames.
#[tokio::test]
async fn a_proposal_frame_carries_hashes_not_bodies() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 3, Duration::from_secs(60)).await;
    let mut obs = Observer::start(CHAIN_ID, boot.clone()).await;
    // 40 faucet mints through n0, then the frames of the next proposals.
    for i in 1..=40u8 { n0.mint(i, 1_000).await; }
    let seen = obs.pump(Duration::from_secs(10)).await;
    let proposals: Vec<&Seen> = seen.iter().filter(|s| s.topic.ends_with("/consensus") && s.data.first() == Some(&4)).collect(); // tag 4 = CompactProposal
    assert!(!proposals.is_empty(), "saw compact proposals");
    let biggest = proposals.iter().map(|s| s.data.len()).max().unwrap();
    assert!(biggest < 80 * 1024, "a compact proposal frame is {biggest} bytes");
    // The bodies were on the tx topic once.
    let tx_frames = seen.iter().filter(|s| s.topic.ends_with("/tx")).count();
    assert!(tx_frames >= 40);
    // And every node committed them.
    wait_for("all nodes hold the mints", Duration::from_secs(60), || (1..=40u8).all(|i| n3.holds(i))).await; // use the holds/note helpers as the other tests do
    for n in [n0, n1, n2, n3] { stop(n).await; }
}

/// A late validator that joins after the mints were gossiped still votes: its first compact
/// proposals name bodies it never saw, and it fetches them (spec §5.3) instead of waiting for
/// batch sync.
#[tokio::test]
async fn a_late_validator_fetches_bodies_it_never_saw() { /* start three validators of a four-validator genesis, mint 20 through n0, then start the fourth; assert its height catches up within 30 s and its log (init_tracing with the test writer; or its status RPC) shows it committed blocks it proposed/voted on; assert the chains are equal (assert_chains_equal) */ }
```
The second test's assertion that fetching happened: expose a counter in `NodeStatus`? Add `compact_fetched: u64` to the node's status (`rpc.rs:205` `NodeStatus`) incremented in `on_transactions_response` by `placed`, and assert `n3.rpc.status().compact_fetched > 0`. (One small field; document it in `docs/rpc.md` under `rand_status`.)

- [ ] **Step 2: Run** (serially, never beside another e2e suite): `cargo test -p randprotocol-node --test cluster a_proposal_frame 2>&1 | tail -5` and `a_late_validator` → PASS. Then the whole cluster suite once: `cargo test -p randprotocol-node --test cluster 2>&1 | tail -4`.

- [ ] **Step 3: Record** in `docs/node-hardware.md` a new §8: the measured frame sizes (the test prints `biggest`; also run the harness-free measurement: `bincode::serialized_size` of a `CompactBlock` for a 2 000-hash block in a unit test and record it), the fetch counter from the late-validator test, and the comparison with today's full proposal on chain 20 (20 MiB cap, ~2.85 MB a transfer).

- [ ] **Step 4: Commit** (message: "tests, docs: compact proposals measured on a four-validator cluster — frames of hashes, bodies on the tx topic once, a late validator fetches what it never saw").

---

### Task 8: docs and the flag-day note

**Files:**
- Modify: `docs/architecture.md` §8 (the proposal path: compact on the wire, rebuild, fetch; the sync enums; the recent cache), `docs/compute-optimization.md` §3.4 (shipped, scope widened, measured), `docs/deploy.md` (the roll: observers and archives first, then validators in one pass; an old node rejects the new variant), `docs/rpc.md` (`compact_fetched`), `CHANGELOG.md` (Unreleased), `AGENTS.md` (project memory: the flag-day trap — a mixed fleet loses the new leaders' proposals; the report-exactly-once rule applies to the new arm; `bare_node` now captures broadcasts).

- [ ] **Step 1: Write**, in each page's prose style, with the numbers from Task 7.
- [ ] **Step 2: Whole-branch check**
```bash
cargo test -p randprotocol-core 2>&1 | tail -3
cargo test -p randprotocol-node 2>&1 | tail -3          # unit: 471+N / 21
cargo clippy -p randprotocol-core -p randprotocol-node --all-targets --no-deps -- -D warnings 2>&1 | tail -2
cargo deny check licenses 2>&1 | tail -1
git log --oneline d6cc16f5..HEAD
```
- [ ] **Step 3: Commit** (message: "docs: compact blocks — architecture §8, compute-optimization §3.4 shipped, the flag-day roll in deploy.md, changelog, project memory").

---

## Self-review notes

- Spec coverage: §3 → Task 1; §5.1 → Task 2 (+ amendment 2); §5.2/5.4 → Tasks 3–4; §5.3 → Tasks 4–5; §4 → Task 6; §6 → Task 5; §7 → Task 8; §8 bounds → Tasks 3–5 constants; §9 tests → each task + Task 7; §10 docs → Task 8.
- Names consistent across tasks: `CompactBlock::{of, into_block, hash}`, `TX_FETCH_BATCH`, `compact::{RecentTxs, Parked, Rebuilt, rebuild, RECENT_TXS_MAX, recent_txs_bytes}`, `HotStuff::precheck_compact`, `Node::{on_compact_proposal, handle_rebuilt, request_parked_bodies, fetch_candidates, serve_transactions, on_transactions_response}`, fields `recent_txs`, `parked`, status `compact_fetched`.
- Review Focus: 1 → Task 2; 2 → Tasks 3 and 5; 3 → Task 4; 4 → Task 4; 5 → Task 5.
