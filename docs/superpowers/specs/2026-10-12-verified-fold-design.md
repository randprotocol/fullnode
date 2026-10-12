# Fold the verified set into the verify cache — design

2026-10-12. Follows `2026-10-11-verify-cache-design.md` (whose §"Not in scope" left this as "a
later cleanup") and `2026-10-11-offloop-apply-design.md`. Base: fullnode local `main` 9b014927
(private multisig merged).

## 0. Summary

A node keeps two caches of "this proof verified":

- `admission::VerifiedSet` (audit v3, B5): transaction hashes whose proofs admission verified.
  The ledger reads it through `randprotocol_core::VerifiedProofs`; on a hit it *skips* the bundle
  and auth verifies and *decodes* the call / invoke / perp proof (`decode_*`) instead of
  verifying it.
- `verify_cache::CachingExecutor`: the `Ok` verdict of each STARK verifier, keyed by a digest of
  every input.

The second subsumes the first. This change deletes the first: the ledger always calls the
`verify_*` methods, and on a node the `CachingExecutor` answers a proof admission already
verified from its cache. The consensus path then never reads a proof through a decoder, so the
`decode_*` mirrors (hand-copies of the verifier's header checks, which private multisig had to
patch for the MODQ chip) can no longer make a block valid that a re-verifying validator refuses.

## 1. What changes

**Core (`randprotocol-core`).**

- `ledger::VerifiedProofs`, `NoVerified`, and the `RwLock<T>` impl are removed, and so is every
  `verified_proofs` / `verified` parameter that carried one: `validate_inner`, `apply_tx_with`,
  `apply_tx_checked`, `apply_transactions_for_sync`, `apply_block_with`, `apply_block_with_covered`,
  `apply_block_for_sync`. A `*_with` variant that differed from its plain twin only by that
  parameter is removed and its callers use the plain one.
- `check_bundle_proof` loses `admitted`: the bundle and auth proofs are verified every time
  (pruned bundles: the auth proof every time).
- Step 10 always calls `verify_invoke` / `verify_call_hardened` / `verify_call`;
  `perps::verify_state_proof` always calls `verify_perp`.
- `HotStuff` loses its `verified` field and `set_verified_proofs`.
- `ConfidentialExecutor::decode_call`, `decode_call_hardened`, `decode_invoke`, `decode_perp`
  **stay**: admission's `call_pricing` reads a call's header to price it *before* paying for a
  verify. Their docs change from "called only for a transaction a VerifiedProofs set vouches
  for" to "admission pricing only; the ledger never calls them". A ledger test pins that: an
  executor whose `decode_*` panic applies every kind of proof-carrying transaction.

**Node (`randprotocol-node`).**

- `admission::VerifiedSet`, `VERIFIED_SET_ENTRIES`, `Node::verified`, and the admission worker's
  `insert(tx.hash())` are removed. Admission already verifies through `self.executor`, which in
  `rand-node run` is the `CachingExecutor`; that verify is what fills the cache.
- `VERIFY_CACHE_ENTRIES` 16 384 → **32 768**. The set held 8192 transactions; a transaction now
  occupies up to three entries (bundle, auth, and one call / invoke / perp), so 3 × 8192 rounded
  up to a power of two keeps the same coverage. A verdict is a few hundred bytes at most.
- The off-loop apply (`spawn_apply`) and the propose path lose the verified-set argument.

## 2. Equivalence: why every former hit is still a hit

A hit needs apply's verifier arguments to equal admission's byte for byte.

- Bundle: `(hc_bundle, proof, binding)`; `binding` is `tx.binding(binding_domain)`, a function of
  the transaction and a genesis constant.
- Auth: `(hc_auth or hc_auth_multisig by shape, proof, binding)`; same.
- Call: the record (immutable once deployed), the proof, and `hardened_call_segment(record,
  call_binding)` — transaction + record only.
- Invoke: `invoke_segment(record, tx)` — "built from the transaction alone" (ledger step 10).
- Perp: the segment holds the ledger's proved root. Admission and apply build it on the ledger
  they run on; if the state moved, the old path's `decode_perp` refused too (it compares
  `H_PUB`), so a miss there is a refusal either way, not a lost hit.

The leader's propose ledger is not the tip admission ran on: it is the parent plus the earlier
transactions of the same block. That is harmless, because no bundle, auth, call or invoke argument
above reads ledger state (and a perp proof's does only through the proved root, which only another
state proof moves).

The acceptance test (Task 1) proves it on the real admission path: through a `CachingExecutor`
over a counting executor, admitting one transaction of each kind and then applying a block of
them runs each inner verifier exactly once.

## 3. Cost, measured

The one cost is that a hit now hashes the proof for the cache key, where the set looked up a
transaction hash apply computed anyway. blake3 on this machine (M-series, single thread,
`blake3 1.8.7`, release): 100 KiB 87 µs, 400 KiB 232 µs, 1.3 MiB 556 µs, 3.4 MiB 1.44 ms,
6 MiB 2.6 ms — about 2.4 GB/s. A full 19 MiB chain-21 block is ≈ 8 ms of hashing on a hit-only
apply. On a follower that runs off the loop (off-loop apply). On the leader it is on the loop, and
more than once: each proof is hashed at least twice — the trial apply (`apply_tx_checked` in
`HotStuff::propose`) and then `on_proposal` re-applying the leader's own block — so ≈ 16 ms at a
maximal block (≈ 10 % of the 150 ms budget), well under 1 % at today's sizes. Each half-apply
replay (at most `MAX_PROPOSE_REPLAYS` = 8) re-hashes the accepted set again (and a half-applied candidate hashes its own proofs), so the
worst case is about ten block-hashes, ≈ 80 ms at a maximal block. A call or invoke key also
bincode-serializes the whole `ProgramRecord` (its words: up to ≈ 256 KB at
`MAX_PROGRAM_WORDS_LIMIT` = 65 535) on every lookup. Against it, a call / invoke / perp hit no
longer decodes its proof at all (the cached outcome is returned), and decoding a proof costs at least as much as hashing it.

## 4. Not in scope

- Removing `decode_*` (admission pricing needs them).
- Changing the verify cache's key or eviction.
- The startup walk and CLI tools keep the bare executor (no cache), as before: they always
  verified in full and still do.

## 5. Risks

- A miss where the set used to hit costs one full verify at apply (never a wrong verdict). §2's
  test is the guard; a cluster run is the end-to-end check.
- Signature churn across ~90 call sites; mechanical.

## 6. Follow-ups

- (a) Feed the leader's trial post-state into `on_proposal_with` as a `PreApplied`, so the
  leader's own block is not applied (and its proofs not re-hashed) a second time on the loop.
- (b) Key a call / invoke entry by the record's `id`, `code_hash`, `public_digest` and
  `public_len` instead of the serialized record, with a `KEY_DOMAIN` bump.
- (c) The vendored zkvm crate's `decode_*` wording (`randprotocol-zkvm/src/executor.rs`,
  `tests/executor.rs`) still describes the verified-set path; fix it at the next circuits
  re-vendor.
