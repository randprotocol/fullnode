# Validator hot path: harness, incremental nullifier root, shared-base ledger, worker sizing

Status: design, 2026-10-05. Implements `docs/compute-optimization.md` §3 (phase 1) items 3.1,
3.2, 3.3 (the worker count only), 3.5 and 3.6, in the order the user set: harness first, then the
two changes that go superlinear, then the two afternoon changes. Compact blocks (§3.4), the
digest-keyed verify cache for every proof kind (the rest of §3.3), envelope slimming (§5.3), the
startup snapshot, moving the commitment set out of memory, and parameterising the raw block cap
are **out of scope** here and stay on the §3 list.

Branch `feat/hot-path`, worktree `~/rand-worktrees/fullnode-hot-path`, from `main` at `4c03dcb1`.

## 0. Amendments from planning (2026-10-05)

The implementation plan (`docs/superpowers/plans/2026-10-05-validator-hot-path.md`, "Spec
corrections") amends this spec where the code differed from what it assumed:

1. §3: the covered path adds no nullifiers today (an aggregate covers bundles already applied
   raw), so the harness has one shape — raw bundles at the 2 000 cap, two nullifiers and four
   commitments each, 40 M nullifiers at 10 000 blocks. `--bundles` replaces `--records`;
   `--shape` is dropped. A `propose_ms` column is added.
2. §5 gains a fifth change: `HotStuff::propose` clones the ledger once per candidate; it now
   applies candidates directly and replays the accepted set on a failure, at most eight times a
   block.
3. §4.1: this branch has no perps section; the new tag follows `tokens_incremental_root`, the
   last tag today. The slot swap happens in `state_root_leaves`.
4. §5.1: `SharedSet` implements `PartialEq` (the ledger's hand-written equality uses it);
   `len()` is exact always. `HotStuff::new` detaches the base; `HotStuff::resume` folds the delta.
5. §8: no `proptest` in the workspace; randomised tests use seeded `rand::rngs::StdRng`.
6. §1, the resident-memory row (amended at the final review, 2026-10-05). It read "flat after
   warm-up (the last 1 000 blocks within 5 % of the first 1 000 after block 1 000)", which no
   run can meet while the commitment and nullifier sets live in memory: the measured run went
   from 961 MB at block 1 000 to 8 954 MB at block 10 000 because the sets grew tenfold (8 M to 80 M nullifiers), not
   because of the speculative tree. The criterion is now what this spec's changes can promise
   and the run shows (`docs/node-hardware.md` §7): resident memory linear in the entries, 117 to
   121 bytes per nullifier across the run, with no term in the speculative tree or in height.

## 1. Goal and success criteria

The validator applies a 4 096-record block inside a slot at the 10 000th block as fast as at the
first, with resident memory that does not grow with the speculative tree. Nothing here raises
throughput on its own (§2.3 of the compute page: phase 1 is a prerequisite); everything here is
measurable now with the `StubExecutor`.

Acceptance (§3.6 of the compute page, unchanged): a one-validator chain on the `StubExecutor`,
4 096 synthetic records a block for 10 000 blocks —

| quantity | bound |
|---|---|
| block apply at the 10 000th block | ≤ 300 ms |
| resident memory | grows only with the entries (bytes per nullifier constant across the run); no term in the speculative tree or in height (amended, §0 item 6) |
| nullifier set | ≥ 40 M entries at the end |

The run's table is recorded in `docs/node-hardware.md` with the date and host.

## 2. What the code does today (verified 2026-10-05 on `4c03dcb1`)

- `Ledger::state_root_leaves` (`core/src/ledger/mod.rs:3096`) hashes every entry of
  `nullifiers: BTreeSet<Word8>` into a sorted BLAKE3 Merkle root on every block: `O(n)`.
- `Ledger` is `#[derive(Clone)]` over `commitments` and `nullifiers`, both `BTreeSet<Word8>` of
  every entry the chain ever produced. It is cloned per speculative block (`hotstuff.rs:244`,
  `Entry.ledger_after`), per trial apply (`hotstuff.rs:1322`, `:1335`), per block apply
  (`apply_block_with_covered`'s `scratch`), and at commit (`hotstuff.rs:1543`). The audit-v6
  review measured 28 ms a clone at 10⁶ entries.
- `HotStuff::prune_off_chain` (`hotstuff.rs:1578`) drops every tree entry that does not descend
  from the new committed head, at every commit.
- `MAX_VERIFY_IN_FLIGHT = 4`, `MAX_VERIFY_QUEUE = 64` (`node/src/admission.rs:606`).
- `QuorumCertificate::verify` (`core/src/types/block.rs:124`) verifies votes in one loop; called
  on every proposal (`hotstuff.rs:944`) and every NewView (`hotstuff.rs:1149`).
- `MAX_BLOCK_TXS = 2_000` is a constant (`core/src/gas.rs:94`); an aggregate covers up to
  `aggregation.max_covers` bundles, applied through `apply_block_with_covered`.
- Nullifier rows in RocksDB are keyed by nullifier with the height as value
  (`CF_NULLIFIERS`); insertion order is not recoverable from the store. The commitment-tree
  frontier is written to `CF_META` every commit and restored by `load_ledger`.
- TOK-1 (#86) is the precedent for a genesis-gated incremental root: `tokens.incremental_root`,
  committed into the genesis hash under its own tag, the incremental root in the legacy root's
  slot of the preimage, and the composite re-domained (`rand-state-tokens-1`).

## 3. Component 1 — `rand-node bench apply`

A subcommand of the node binary (module `crates/randprotocol-node/src/bench.rs`, wired in
`main.rs`), so the harness ships in the one binary and runs with `cargo run --release`.

```
rand-node bench apply [--records 4096] [--blocks 10000] [--report-every 500]
                      [--shape covered|raw] [--incremental-nullifier-root]
                      [--fail-over-ms 300]
```

**What it builds.** An in-memory one-validator genesis (`GenesisState` from a `Genesis` the
harness constructs, with an `aggregation` section sized so `--records` fits: `max_covers =
records / 4`, four aggregates a block) and a `HotStuff` over the `StubExecutor`, constructed the
way `consensus/tests.rs` constructs a single replica. No network, no RocksDB: what is measured
is the consensus-side ledger path (trial apply, tree entry, commit, prune) that `node.rs` calls,
and nothing else.

**What a block carries.**

- `covered` (default): four `Aggregate` transactions, each covering `records / 4` synthetic
  bundles (two nullifiers and four commitments each, stub proofs from `StubExecutor`), applied
  through the covered path exactly as a validator applies a sealed block. This is phase 3's shape.
- `raw`: `min(records, MAX_BLOCK_TXS)` synthetic bundle transactions, today's shape, capped at
  2 000 by the constant.

Synthetic nullifiers and commitments are distinct across the whole run (a counter hashed under
a harness-only domain), so the sets grow by the block's count every block and the double-spend
and duplicate-commitment checks are exercised at their real cost.

**What it drives per block.** The harness is the one validator: it builds the proposal from the
tip ledger, applies it, votes, forms the single-signer QC, and lets `HotStuff` commit on the
three-chain rule, so the tree holds the same three speculative entries a live chain holds.

**What it prints.** One header line, then one row every `--report-every` blocks and at the end:

```
height  apply_ms  root_ms  clone_ms  commit_ms  nullifiers  rss_mb  peak_rss_mb
```

`apply_ms` is the whole block (what §3.6 bounds), `root_ms` is `state_root()` alone,
`clone_ms` is one `Ledger::clone()` of the tip, `commit_ms` is the commit step. Resident memory
is read from the OS (Linux: `/proc/self/statm`; macOS: `task_info`; both through `libc`, already
a dependency), peak from `getrusage`. The last line is the acceptance verdict; the process exits
non-zero if the final `apply_ms` exceeds `--fail-over-ms`, so a small run (`--blocks 200`) can sit
in CI.

The harness is also the regression test for components 2 and 3: the same flags run before and
after, and the before numbers go in the hardware page beside the after.

## 4. Component 2 — incremental nullifier root (consensus-visible, genesis-gated)

### 4.1 Genesis

`Genesis.incremental_nullifier_root: Option<bool>` (serde default `None`). `Some(true)` is
committed into the genesis hash under its own tag, `b"incremental_nullifier_root" ‖ 1`, appended
after every existing tag (after `perps`, the last today), exactly as `tokens_incremental_root`
is; `None`/`Some(false)` adds nothing, so every existing genesis hash is unchanged.
`GenesisState` carries the flag into the ledger (`Ledger::with_incremental_nullifier_root`), and
`node::reload_ledger` restores it from the genesis as `load_ledger` restores the token flag.

### 4.2 The accumulator

`core/src/ledger/nullifier_mmr.rs`: a Merkle Mountain Range over nullifiers in **insertion
order**.

- leaf = `blake3("rand-nullifier-leaf" ‖ nf)` — the leaf hash the sorted root uses today.
- node = `blake3("rand-nullifier-mmr-node" ‖ left ‖ right)`.
- root = `blake3("rand-nullifier-mmr-1" ‖ count_be(8) ‖ bag)`, where `bag` folds the peaks from
  the rightmost (smallest) to the leftmost: `bag = peak_0` for one peak, else
  `blake3("rand-nullifier-mmr-node" ‖ peak_i ‖ bag_{i+1})`. An empty range has root
  `blake3("rand-nullifier-mmr-1" ‖ 0)`.
- state: `Vec<Hash>` of peaks (at most 64) and `count: u64`. `append` is `O(log n)` amortised
  and allocation-free in the common case; `root` is `O(log n)`. The struct is `Clone` (a few
  hundred bytes) and `Serialize`.

**Insertion order** is defined as: block order of transactions, action order within a
transaction, nullifier slot order within an action; for a covered aggregate, cover order, then
slot order. This is the order `apply_transactions_for_sync` already visits nullifiers in, and it
is identical on the proposer, the replica and the sync path because all three run the same
function over the same block.

### 4.3 In the state root

Under the flag, `state_root_leaves` returns the MMR root in the nullifier slot instead of the
sorted root — the `O(n)` iteration disappears — and `state_root` re-domains the composite:
`root = blake3("rand-state-nf-mmr-1" ‖ base)`, applied after the `rand-state-tokens-1` wrapper
and before the staking wrappers, so the wrapper order is fixed and documented in the function's
comment. Without the flag, nothing changes: chains 1–20 commit byte-identical roots (a test holds
a chain-20-shaped ledger's root constant across the change).

The MMR commits to the multiset in order; the sorted set still exists for membership (the
double-spend check) and is unchanged by this component.

### 4.4 Persistence

The peaks and count are one `CF_META` row, `META_NULLIFIER_MMR = "nullifier_mmr"`, written in
the same `WriteBatch` as the block (beside the frontier). `load_ledger` restores it when the
genesis flag is on; a flag-on chain whose store lacks the row (impossible after this change, but
a corrupt store is not) refuses to start with a named error rather than rebuild silently —
insertion order cannot be recovered from `CF_NULLIFIERS`. The quick startup check compares the
restored ledger's state root with the head's, as it does today, so a wrong row is caught there.

Pruning (`prune_history`, `prune_sealed`) does not touch the row: the accumulator is consensus
state, not history.

### 4.5 Where it is on

Nowhere yet. The flag is a genesis cut like `rand-state-5` was; `deploy/` scripts gain the option
in a later change. The harness turns it on with `--incremental-nullifier-root`.

## 5. Component 3 — the shared-base set (not consensus-visible)

### 5.1 The type

`core/src/ledger/shared_set.rs`:

```rust
pub struct SharedSet {
    base: Arc<RwLock<BTreeSet<Word8>>>,   // the committed entries; one per chain, shared by every clone
    added: BTreeSet<Word8>,               // this ledger's entries since the base
}
```

- `contains(x)`: `added.contains(x) || base.read().contains(x)`.
- `insert(x) -> bool`: `false` if `contains(x)`, else `added.insert(x)`.
- `len()`: `base.len() + added.len()`; exact because `insert` never adds an entry the base has
  and `absorb` removes entries the base gained (below).
- `Clone`: clones the `Arc` and `added`. `O(|added|)`.
- `iter()`: a merge of `base` and `added` in sorted order, deduplicated, for the legacy sorted
  root, `nullifiers_from`-style readers and tests. Holds the read lock for the iteration; it is
  used on the consensus thread only.
- `commit(&mut self)`: `base.write().extend(added.drain())`. `O(|added|)`; no copy of the base.
- `absorb(&mut self)`: `added.retain(|x| !base.read().contains(x))`. `O(|added| log n)`.
- `from_set(BTreeSet<Word8>) -> SharedSet` for `from_parts` and `load_ledger`;
  `snapshot(&self) -> BTreeSet<Word8>` (a full copy) for the storage paths that write the set
  out, if any need one after the change — the plan checks and prefers `iter()`.

`commitments` and `nullifiers` on `Ledger` become `SharedSet`. The API `Ledger` exposes
(`nullifiers()` returning `&BTreeSet`) changes to `nullifiers()` returning `&SharedSet` with
`contains`/`len`/`iter`; the plan lists every caller (`node.rs:2489` and the storage/RPC paths).

### 5.2 Who calls `commit` and `absorb`

`HotStuff::commit` (the step at `hotstuff.rs:1543`), after `committed_ledger` is set and after
`prune_off_chain` has run:

1. `committed_ledger.commit_shared()` — drains both sets' deltas into the shared bases.
2. For every surviving tree entry, `entry.ledger_after.absorb_shared()`.

The order matters for soundness: after `prune_off_chain` every surviving entry descends from
the new head, so each one's `added` already contains the committed delta; `absorb` removes the
now-redundant entries and leaves each entry's `added` at `O(blocks above the head)`. A trial
ledger (`hotstuff.rs:1322`) is dropped after use and never commits. `apply_block*`'s `scratch`
clones the delta, applies, and replaces `*self`: unchanged logic, `O(delta)` cost.

No other path writes the base. `Ledger` keeps `Clone`; the derive is replaced by a manual impl
only if a field needs it (the plan decides; `SharedSet: Clone` is enough as designed).

### 5.3 Why it is sound

Consensus state is the committed ledger. Every speculative ledger is `base ∪ added`, where
`base` is the committed set at some commit height `h₀ ≤ h` and `added` is every entry its
ancestors above `h₀` inserted. A commit at `h₁ > h₀` only ever moves entries from the deltas of
the chain's own ancestors into the base; a speculative ledger that survives the commit descends
from `h₁`, so its view `base ∪ added` is unchanged as a set. A speculative ledger on a dropped
fork is gone before the base changes. The single-threaded consensus loop is the only writer and
the only reader during a commit, so no clone observes a half-applied base.

What it does not do: `Ledger::clone()` no longer snapshots the committed sets in isolation from
later commits. No code relied on that (a clone is either a tree entry, a trial, or a scratch,
all of which descend from the committed head); a test asserts it with two clones and a commit.

### 5.4 Cost

| operation | before | after |
|---|---|---|
| `Ledger::clone()` | `O(state)` (28 ms at 10⁶) | `O(delta)` (microseconds) |
| commit | one `O(state)` clone | `O(block)` drain + `O(Σ deltas)` absorb |
| `contains` | one `BTreeSet` probe | two probes and an uncontended read lock |
| memory, 3 speculative entries + committed | 4 × state | 1 × state + 3 × delta |

## 6. Component 4 — verify workers sized to the host

`admission.rs`: `MAX_VERIFY_IN_FLIGHT` and `MAX_VERIFY_QUEUE` become `VerifyLimits { in_flight,
queue }` with `VerifyLimits::for_host()` = `in_flight = max(4, available_parallelism − 2)`,
`queue = 16 × in_flight` (the 4/64 ratio today), and `VerifyLimits::fixed(n)` from `rand-node
run --verify-workers N` (`0` refused, as `--threads 0` is). The limits are read once at startup
and logged. The constants stay as the floor so a two-core droplet behaves exactly as today. The
comment at `admission.rs:601` is rewritten to say what the number now is and why the floor is
four.

## 7. Component 5 — certificate verification

### 7.1 Parallel

`QuorumCertificate::verify` keeps its structure and guards (view and hash match, known voter,
no duplicate, quorum) and moves the signature checks to `std::thread::scope` over chunks of
votes, `chunks = min(votes, available_parallelism)`, with a sequential path under 8 votes so a
test chain pays no thread cost. No new dependency; `rayon` is not a `core` dependency and is not
added for one loop. The result is bit-identical to the sequential function (a test runs both on
the same certificates, valid and each kind of invalid).

### 7.2 Once per certificate

`HotStuff` gains `verified_qcs: BoundedSet<Hash>` (the existing bounded-set idiom in the crate,
1 024 entries, oldest first) keyed by `blake3(bincode(qc) ‖ bincode(validator set))`. `verify_qc(&qc, &set)` looks up,
else verifies and inserts on success. A QC that arrives as a proposal's `justify` and again as
a NewView's `high_qc` is verified once. The key is over the whole certificate bytes, so a
different vote set for the same block is a different key, and over the validator set it was
verified against, so a QC is never vouched for under a set it did not pass under. If the crate
has no bounded-set type the plan adds a `VecDeque` + `HashSet` pair of 1 024 entries. Invalid certificates are not cached (the refusal path is
rate-limited elsewhere and must not fill the set).

## 8. Testing

- **MMR**: unit tests for 0, 1, 2, 3, 2ᵏ and 2ᵏ+1 leaves against a from-scratch reference that
  builds the same peaks by hand; a property test (`proptest`, already a dev-dependency) that
  appending the same sequence to two instances gives equal roots and a permuted sequence does
  not; a test that a chain-20-shaped ledger's state root is unchanged with the flag off; a test
  that the flag flips the root and the `rand-state-nf-mmr-1` wrapper is present exactly once.
- **Persistence**: the node test shape of `reload_ledger_restores_the_incremental_token_root…`
  for the MMR row; the refusal when the row is missing on a flag-on store.
- **SharedSet**: property test against a `BTreeSet` oracle over random insert/contains/clone/
  commit/absorb sequences across several clones; the two-clones-and-a-commit test of §5.3; a
  `len()` exactness test.
- **HotStuff**: the existing consensus simulator suite runs unchanged (it is the regression net
  for §5.2's commit order); one new test asserts that after a commit the surviving entries'
  `added` sizes are `O(blocks above head)`.
- **Workers**: `for_host()` on a mocked core count; `--verify-workers 0` refused.
- **QC**: §7.1's equivalence test; §7.2's once-per-certificate test and the different-set key
  test.
- **Harness**: `bench apply --blocks 50 --records 256` runs in the test suite as a smoke test of
  both shapes and both flag states.
- **Acceptance**: the §1 run, recorded.

## 9. Order of work and what ships together

1. Harness (§3) — measured baseline on `main`'s code, recorded.
2. Shared-base set (§5) — rerun; the `clone_ms` and `commit_ms` columns are the proof.
3. Incremental nullifier root (§4) — rerun with the flag; the `root_ms` column is the proof.
4. Workers (§6) and certificates (§7) — unit-tested; not visible in the harness.
5. `docs/node-hardware.md` gains the table; `docs/compute-optimization.md` §3 rows gain
   *measured* where they are; `docs/architecture.md` §5 and §6 describe the new root and the
   shared base; `CHANGELOG.md` entry; `AGENTS.md` project memory paragraph.

Steps 2 and 3 are independent and can be executed in parallel by two implementers; both touch
`ledger/mod.rs` and are merged in that order.

Nothing here rolls onto chain 20: §4 waits for a genesis cut, and §5–§7 are node-only changes
that ride the next release.
