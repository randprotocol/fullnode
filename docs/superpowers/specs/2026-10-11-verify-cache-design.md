# Digest-keyed verify cache — design

Date: 2026-10-11. Branch `feat/verify-cache`, cut from `origin/main` 37c4fdd3.
Implements the open half of `docs/compute-optimization.md` §3.3. The worker count shipped in
`feat/hot-path`; this adds the digest-keyed cache.

## 1. Problem

The node verifies the same STARK more than once.

- **Aggregates are never cached.** An aggregate's rVM verify takes about 1–2 s warm in the test
  profile, against a ≤ 150 ms target. `validate_aggregate`/`apply_aggregate` take no verified
  set. Today the leader verifies a gossiped aggregate three times: once in admission, once in its
  trial apply (`hotstuff.rs:1449`) and once applying its own proposal (`execute_and_insert`). Each
  follower verifies it twice: once in admission, once in apply. The apply-time verifies run on the
  consensus loop.
- **Ordinary transactions** skip their proof at apply only through `VerifiedSet`, which records
  whole transaction hashes (8192, FIFO). A transaction whose admission verify has not finished,
  was shed from the queue or was evicted is verified cold on the loop.
- **Paths that pass `NoVerified`** get no reuse at all. That covers `Ledger::validate`, sync,
  `apply_block` and the startup walk.

## 2. Goal and non-goals

**Goal:** each distinct proof statement is verified at most once per process while it stays in
the cache, on every path, for every proof kind:

- bundle, auth;
- call, hardened call, invoke;
- perp state proof;
- flat aggregate and tree aggregate.

A repeat costs one hash of the inputs and a map lookup.

**Non-goals:**

- Moving the uncached apply-time verify off the consensus loop. §3.3's "the loop only ever looks
  up" needs apply to await a worker. That is a separate change to the HotStuff driver. With this
  cache, a proposal whose proofs this node already admitted applies without verifying, which is
  the common case.
- Caching Dilithium signature checks. They are cheap per check, and their keys and messages come
  from ledger state.
- Negative caching. `RefusedCache` and `ProofRefusedCache` already exist, and errors can be
  transient (a key build that failed, a panic).
- Removing `VerifiedSet`. It stays as is: a hit there skips the verifier call entirely, and a
  miss there now falls through to this cache. Folded later: see `2026-10-12-verified-fold-design.md`.

## 3. Design

### 3.1 A caching executor

A new `crates/randprotocol-node/src/verify_cache.rs` holds:

```rust
pub struct VerifyCache { /* Mutex<{ map: HashMap<Hash, Verdict>, order: VecDeque<Hash> }>, cap, hits, misses */ }
pub struct CachingExecutor { inner: Arc<dyn ConfidentialExecutor>, cache: VerifyCache }
impl ConfidentialExecutor for CachingExecutor { /* every method */ }
```

The ledger already calls every verifier through `&dyn ConfidentialExecutor`, so wrapping the
executor reaches every path without touching ledger code or adding parameters: admission
workers, propose, follower apply, sync, and `validate_aggregate`. Any path that verifies fills
the cache, and every other path reads it.

### 3.2 Which methods it caches

These eight expensive verifiers are cached. The `Ok` value is stored, and on a hit a clone of it
is returned without calling `inner`:

| method | value |
|---|---|
| `verify_bundle(hc_bundle, proof, binding)` | `()` |
| `verify_auth(hc_auth, proof, binding)` | `Word8` (the `c`) |
| `verify_call(record, proof)` | `CallOutcome` |
| `verify_call_hardened(record, proof, segment)` | `CallOutcome` |
| `verify_invoke(record, proof, segment)` | `CallOutcome` |
| `verify_perp(engine_hc, max_tier, segment, proof)` | `CallOutcome` |
| `verify_aggregate(shape, covered, proof, binding)` | `Vec<[u32; 8]>` |
| `verify_tree(tree, covered, proof, binding, depth)` | `Vec<[u32; 8]>` |

Every other method forwards to `inner` unchanged, including all `decode_*`, `warm*`, digests,
gas decodes, `non_canonical_proof`, headers and `tree_digests`. That includes **every method
that has a default in the trait.** A default left in place on the wrapper would silently
replace `AggExecutor`'s implementation with the trait default. That is the hazard
`agg_executor.rs:456` warns about: for some methods the default refuses, and for others it
switches a rule off. The trait gets a one-line doc note: a new method must be forwarded in
`CachingExecutor` as well.

`Err` results are returned and never stored. A panic in `inner` propagates, as today, and leaves
no entry.

### 3.3 The key

`key = Hash::digest_domain(b"rand-verify-cache-1", bytes)`, where `bytes` is a one-byte kind tag
followed by every input the method receives, each length-prefixed (`u64` little-endian length,
then the bytes):

| kind | tag | inputs hashed, in order |
|---|---|---|
| bundle | 1 | hc_bundle words, proof, binding words |
| auth | 2 | hc_auth words, proof, binding words |
| call | 3 | bincode(record), proof |
| call_hardened | 4 | bincode(record), proof, segment words |
| invoke | 5 | bincode(record), proof, segment words |
| perp | 6 | engine_hc words, max_tier, segment words, proof |
| aggregate | 7 | bincode(shape), covered (each: 35 public values LE, bincode(shape)), proof, binding words |
| tree | 8 | bincode(tree), covered (as above), proof, binding words, depth |

Words are hashed as little-endian bytes. The tag keeps different methods apart even when their
inputs coincide. Hashing the program hc and the record keeps the single-key auth guest apart from
private multisig's planned second auth guest (`hc_auth_multisig`), as randprotocol-0e asked. Every
argument the verifier sees is in the key. Everything else a verdict depends on is fixed for the
life of the process: the FRI profile, the compiled constraint set, the pinned heights. So a hit
returns exactly what `inner` would return, and two validators with different cache contents reach
the same verdict.

Hashing a 1.2 MB production bundle proof with blake3 takes well under 1 ms, against 16 ms warm or
838 ms cold for its verify.

### 3.4 Size and eviction

`VERIFY_CACHE_ENTRIES = 16_384`, twice the pool's 8192-entry verified set, to cover both proofs
of a split-auth transaction. Eviction is FIFO by insertion, as in `VerifiedSet`; a hit does not
reorder. Values are at most a `CallOutcome` or an `outs` list (32 bytes per cover). Memory stays
under a few MB at the cap.

### 3.5 Concurrency

There is one `std::sync::Mutex`, held only for the map operations, never across `inner`. Two
threads missing the same key both verify, and the second insert is a no-op. A poisoned lock
counts as a miss and skips the insert, so the node pays only the cost of verifying.

### 3.6 Where it is installed

`node::start_with` wraps the executor `load_genesis` returns:
`let executor: Arc<dyn ConfidentialExecutor> = Arc::new(CachingExecutor::new(executor));`, before
any other use. Each running node has its own cache, including each in-process cluster node.
`executor_for_profile` and `load_genesis` keep returning the bare `AggExecutor`, so CLI tools
(`rand-node verify`, `genesis`, `aggregate`) are unchanged.

### 3.7 Observability

`VerifyCache::hits()` and `misses()` are public `u64` accessors. `CachingExecutor::cache()`
returns `&VerifyCache`. Every 1024th lookup (hit or miss) logs
`verify cache: {hits} hits, {misses} misses, {len} entries` at `debug`.

## 4. Tests

**verify_cache.rs unit tests** use a counting inner executor that wraps `StubExecutor` and counts
calls per verifier.

1. For each of the eight kinds: a second identical call returns the same value and does not reach
   `inner`.
2. For each kind, changing any single input (each row of §3.3) misses and reaches `inner`.
3. An `Err` from `inner` is not stored: the same failing call reaches `inner` twice.
4. Different `hc_auth` values with the same proof and binding are distinct entries.
5. Bundle and auth with identical bytes (the same hc, proof and binding) are distinct entries.
6. At `cap + 1` distinct inserts, the oldest key misses again and the newest hits.
7. Forwarding: every non-cached method returns what `inner` returns. For the defaulted ones, the
   inner must return something other than the default. The test executor overrides `decode_call`,
   `bundle_gas_limit`, `non_canonical_proof`, `check_aggregate_header`, `aggregate_proof_tier`,
   `max_callable_program_words` and `verify_call_hardened` with distinguishable values.

**node.rs test:** a ledger applying a stub aggregate block twice, through one `CachingExecutor`
over a counting inner (the admission verify, then the apply), reaches `verify_aggregate` once.
The same holds for a bundle transaction with `NoVerified`.

**Cluster:** the existing `verification_count()` assertions stay unchanged. Each node owns its
cache, and a joiner still verifies a synced root once. The full suite must stay green.

## 5. Docs

- `docs/compute-optimization.md` §3.3: change the status line to shipped (the cache), and keep the
  off-loop await as the open part.
- `docs/architecture.md`: one paragraph next to the verified-set description.
- `CHANGELOG.md` v0.8.0: one bullet.

## 6. Rollout

The cache is node-local memory: no store, wire, genesis or consensus change. It ships in v0.8.0.
