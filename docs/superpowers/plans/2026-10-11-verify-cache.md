# Verify Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every expensive proof verification goes through a node-local cache keyed by a digest of
all its inputs, so each statement is verified once per process.

**Architecture:** `CachingExecutor` is a decorator over `Arc<dyn ConfidentialExecutor>` in a new
`crates/randprotocol-node/src/verify_cache.rs`. It caches the `Ok` results of the eight verifiers
and forwards every other trait method. `node::start_with` installs it, so admission, propose,
apply, sync and aggregate validation all share it, with no change to ledger code.

**Tech Stack:** Rust; `randprotocol_core::{ConfidentialExecutor, crypto::Hash}`, bincode, std `Mutex`.

**Spec:** `docs/superpowers/specs/2026-10-11-verify-cache-design.md`

## Global Constraints

- Key domain: `b"rand-verify-cache-1"`. Kind tags: bundle 1, auth 2, call 3, call_hardened 4,
  invoke 5, perp 6, aggregate 7, tree 8.
- Each key input is length-prefixed (`u64` LE length, then the bytes); words are LE.
- `VERIFY_CACHE_ENTRIES = 16_384`, FIFO eviction, a hit does not reorder.
- Only `Ok` results are stored. Never hold the lock across a call to `inner`. A poisoned lock
  counts as a miss and skips the insert.
- `CachingExecutor` explicitly implements **every** `ConfidentialExecutor` method, defaulted ones
  included, forwarding to `inner`. No trait default may be inherited.
- Install only in `node::start_with`. `executor_for_profile` and `load_genesis` stay unchanged.
- Clippy gate: `cargo clippy -p randprotocol-node --all-targets --no-deps -- -D warnings`.
- Commit trailers:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01Lrko8eEwLbCppJ2pBMG6Qa`
- Do not edit `storage.rs` or `main.rs`. Other sessions avoid `node.rs`; this branch owns its
  `start_with` wrap and one test.

## Review Focus

1. **A trait default inherited by the wrapper.** It silently replaces `AggExecutor`'s rule. Test 7
   pins this with distinguishable inner values.
2. **A key missing an input.** Two different statements would share a verdict, which is a
   soundness bug. Test 2 changes each input once.
3. **Same bytes under different kinds or hcs** (bundle vs auth, `hc_auth` vs a multisig hc).
   Tests 4 and 5.
4. **An `Err` stored as a pass.** Test 3.
5. **The lock held across `inner`** would serialize the admission workers. Review by reading the
   code.

---

### Task 1: `VerifyCache` and `CachingExecutor`

**Files:**
- Create: `crates/randprotocol-node/src/verify_cache.rs`
- Modify: `crates/randprotocol-node/src/lib.rs` (add `pub mod verify_cache;` in alphabetical
  position, after `pub mod viewing;`)
- Modify: `crates/randprotocol-core/src/confidential.rs`: a doc line on `pub trait
  ConfidentialExecutor`: "A method added here must also be forwarded in the node's
  `verify_cache::CachingExecutor`, or that wrapper inherits the default."

**Interfaces (produced):**
```rust
pub const VERIFY_CACHE_ENTRIES: usize = 16_384;
#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict { Unit, Word(Word8), Outcome(CallOutcome), Outs(Vec<[u32; 8]>) }
pub struct VerifyCache { .. }
impl VerifyCache {
    pub fn new(cap: usize) -> Self;
    pub fn hits(&self) -> u64;
    pub fn misses(&self) -> u64;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    fn get(&self, key: &Hash) -> Option<Verdict>;     // counts hit/miss; poisoned → None (a miss)
    fn insert(&self, key: Hash, v: Verdict);          // FIFO evict at cap; present key → no-op; poisoned → skip
}
pub struct CachingExecutor { inner: Arc<dyn ConfidentialExecutor>, cache: VerifyCache }
impl CachingExecutor {
    pub fn new(inner: Arc<dyn ConfidentialExecutor>) -> Self;          // cap VERIFY_CACHE_ENTRIES
    pub fn with_capacity(inner: Arc<dyn ConfidentialExecutor>, cap: usize) -> Self;
    pub fn cache(&self) -> &VerifyCache;
}
impl ConfidentialExecutor for CachingExecutor { /* every method */ }
```

Key builder: a small private `struct KeyBuf(Vec<u8>)` with `tag(u8)`, `bytes(&[u8])` (length
prefix plus bytes), `words(&[u32])` (length prefix plus LE words), `u64s(&[u64])` (likewise) and
`finish() -> Hash` (`Hash::digest_domain(b"rand-verify-cache-1", &self.0)`). Use
`bincode::serialize(..).expect(..)` for `ProgramRecord`, `DeclaredShape` and `TreeConfig`; their
serialization cannot fail. Encode a `CoveredBundle` as `u64s(&public_values)` followed by
`bytes(&bincode(shape))`, and prefix the covered list with its count. Find the exact types of
`Word8`, `TX_BINDING_WORDS` and the `tree` parameter in `confidential.rs`. Match the bincode
version the node crate already uses.

Each cached method follows the same shape:
```rust
fn verify_bundle(&self, hc: &Word8, proof: &[u8], binding: &[u32; TX_BINDING_WORDS]) -> Result<(), ConfidentialError> {
    let key = KeyBuf::new(1).words(hc).bytes(proof).words(binding).finish();
    if let Some(Verdict::Unit) = self.cache.get(&key) { return Ok(()); }
    self.inner.verify_bundle(hc, proof, binding)?;
    self.cache.insert(key, Verdict::Unit);
    Ok(())
}
```
A hit whose variant doesn't match the method can't happen, because the tag differs. Treat it as a
miss: fall through to `inner`.

Log at `tracing::debug!` from `get` when `(hits + misses) % 1024 == 0`:
`verify cache: {hits} hits, {misses} misses, {len} entries`.

- [ ] **Step 1: Write the failing tests** in `#[cfg(test)] mod tests` of `verify_cache.rs`.
  `Counting` wraps `StubExecutor`, holds one `AtomicUsize` per verifier, and overrides the
  defaulted methods with distinguishable values. These tests use the stub's proof helpers
  (`StubExecutor::make_bundle_proof`, `make_auth_proof`, `make_proof*`, `make_perp_proof`,
  `make_aggregate_proof`, `make_tree_proof`) to make inputs that pass. Where building a passing
  input for a kind is awkward, `Counting` may return a fixed `Ok` for that kind, since the
  cache's behaviour, not the stub's, is under test.
  1. `each_kind_verifies_once`: call each of the eight methods twice with identical inputs; each
     counter is 1, and the two results are equal.
  2. `every_input_is_in_the_key`: for each kind and each input in its §3.3 row, flip one byte or
     word, or change the number; that call reaches inner. Use a table of closures.
  3. `errors_are_not_cached`: an inner that returns `Err` for bundle; two calls give two
     inner calls and two errors.
  4. `hc_separates_auth_entries`: verify_auth with hc A, then hc B, same proof and binding;
     2 inner calls.
  5. `bundle_and_auth_do_not_share`: identical hc, proof and binding through verify_bundle and
     verify_auth; each inner counter is 1.
  6. `fifo_eviction_at_capacity`: `with_capacity(inner, 4)`, 5 distinct bundle keys, then key 1
     misses (counter rises) and key 5 hits.
  7. `non_cached_methods_forward`: each forwarded method returns `Counting`'s distinguishable
     value, not the trait default, and calling decode_* twice reaches inner twice.
  8. `hits_and_misses_count`: after test 1's pattern, `hits() == 8` and `misses() == 8`.
- [ ] **Step 2:** `cargo test -p randprotocol-node --lib verify_cache` fails to compile or fails.
- [ ] **Step 3:** Implement as above.
- [ ] **Step 4:** `cargo test -p randprotocol-node --lib verify_cache` passes; clippy gate clean.
- [ ] **Step 5:** Commit: `node: verify cache — CachingExecutor caches the eight STARK verifiers' Ok verdicts by a digest of every input, forwards every other method`.

### Task 2: Install it in `start_with`, plus a ledger-level reuse test

**Files:**
- Modify: `crates/randprotocol-node/src/node.rs`. Right after
  `let (gs, executor) = load_genesis(&cfg.datadir)?;` in `start_with` (≈ line 2378), add:
  ```rust
  // Every verifier the node runs, on every path, through one digest-keyed cache
  // (docs/compute-optimization.md §3.3): admission fills it, apply reads it.
  let executor: Arc<dyn ConfidentialExecutor> = Arc::new(crate::verify_cache::CachingExecutor::new(executor));
  ```
  Check that nothing between there and the rest of `start_with` needs the bare type. It is
  already `Arc<dyn ConfidentialExecutor>`.
- Test: `crates/randprotocol-node/src/verify_cache.rs` (the tests module), or node.rs tests if it
  needs node-private helpers. Prefer verify_cache.rs.

- [ ] **Step 1: Write the failing tests**
  1. `a_ledger_apply_after_validate_reuses_the_bundle_verdict`: build a genesis ledger and a valid
     stub bundle transaction. Copy the pattern of an existing core test that does
     `ledger.validate(tx, exec)` then `apply_tx`; look in
     `crates/randprotocol-core/src/ledger/mod.rs` tests near `CountingExecutor` (≈ 4433–4575).
     Through one `CachingExecutor` over `Counting`: `ledger.validate(&tx, &cx)` then
     `ledger.clone().apply_tx(&tx, .., &cx)`, which passes `NoVerified`. The bundle counter is 1.
  2. `an_aggregate_validated_then_applied_verifies_once`: use the core aggregation test fixture
     (an aggregate over stub-sealed covers; see `ledger/aggregation.rs` tests for
     `validate_aggregate` / `apply_aggregate` helpers). Validate, then apply, through one
     `CachingExecutor`; `verify_aggregate` reaches inner once. If the core fixtures are
     `#[cfg(test)]`-private to the core crate and can't be reached from the node crate, test at
     the executor level instead: call `cx.verify_aggregate` with the exact arguments
     `validate_aggregate` would pass, twice, and assert 1. Ledger case: Ruling recorded by the
     controller.
- [ ] **Step 2:** Run them; with the wrap absent they still pass (the tests construct the
  wrapper). That's fine. These pin the reuse contract the wrap relies on. Then add the wrap.
- [ ] **Step 3:** `cargo test -p randprotocol-node --lib` all green (678+ passed, 0 failed);
  `cargo test -p randprotocol-node --test cli_datadir` green; clippy gate clean.
- [ ] **Step 4:** Commit: `node: start_with runs every verifier through the verify cache`.

### Task 3: Docs and CHANGELOG

**Files:**
- Modify: `docs/compute-optimization.md` §3.3. Change the status paragraph to: **Shipped**: the
  worker count, and the digest-keyed cache (`verify_cache::CachingExecutor`, every verifier, keyed
  by a digest of all its inputs, 16 384 entries). Still open: moving an uncached apply-time
  verify off the consensus loop.
- Modify: `docs/architecture.md`. Next to the verified-set description (grep `VerifiedSet` or
  "verified set"), add one paragraph covering:
  - what the cache is;
  - its key;
  - that it holds `Ok` verdicts only;
  - why it is sound: every input is in the key, and everything else is fixed for the process;
  - the leader's aggregate went from 3 verifies to 1, and a follower's from 2 to 1, when admission
    saw it.
- Modify: `CHANGELOG.md`, the v0.8.0 section, under the node's performance bullets (or the
  closest equivalent heading). Add one bullet in the same style as the startup-checkpoint bullet.
- [ ] **Step 1:** Edit the three files.
- [ ] **Step 2:** Commit: `docs: the verify cache (§3.3 shipped), architecture paragraph, CHANGELOG`.
