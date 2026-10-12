# Verified-set fold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete `admission::VerifiedSet` / `VerifiedProofs`; the ledger always calls `verify_*`, and the node's `CachingExecutor` answers what admission already verified.

**Architecture:** Core loses the `VerifiedProofs` trait, the `admitted` flag and every `verified_proofs` parameter; the ledger never calls `decode_*` (they stay for admission pricing). Node loses `VerifiedSet` and its insert; `VERIFY_CACHE_ENTRIES` doubles to 32 768.

**Tech Stack:** Rust 1.98.1 (`cargo +1.98.1`), workspace crates `randprotocol-core`, `randprotocol-node`.

**Spec:** `docs/superpowers/specs/2026-10-12-verified-fold-design.md`

## Global Constraints

- Toolchain `cargo +1.98.1`; `cargo +1.98.1 clippy --workspace --all-targets` clean (pre-existing rvm/zkvm warnings excepted).
- No consensus rule changes: every verdict a block gets is the one it got before (a former hit is now a cached verify of the same arguments).
- `decode_call`, `decode_call_hardened`, `decode_invoke`, `decode_perp` stay on `ConfidentialExecutor` and in every wrapper; only their doc comments change.
- `CachingExecutor` keeps forwarding every trait method explicitly (no defaults).
- The startup walk and CLI tools keep the bare executor.
- Match the surrounding code's comment density and style (long-form doc comments citing the audit/spec item).
- Commit messages in the repo's style (`area: what — why`), ending with the attribution lines.

## Review Focus

1. A transaction admitted, then applied in a block (propose replay, follower apply, off-loop apply): each inner verifier runs once in total — not twice.
2. A pruned bundle (aggregate-covered) at apply: the auth proof is verified (via the cache), the bundle proof is not touched.
3. A perp state proof admitted on one tip and applied on the same tip: one inner verify.
4. An executor whose `decode_*` panic: every ledger apply path (validate, apply_tx, apply_block, apply_block_for_sync, apply_transactions_for_sync) works.
5. Eviction: with the cache at capacity, the oldest verdict is evicted and the transaction still applies (one extra verify).

---

### Task 1: The fold (core + node)

**Files:**
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (`VerifiedProofs`, `NoVerified`, the `RwLock` impl ~:520-570; `check_bundle_proof` ~:2377; `validate_inner` ~:2552 and step 8-10 ~:2925-2990; `apply_tx_with` / `apply_tx_checked` ~:3006-3030; `apply_transactions_for_sync` ~:3345; `apply_block_with` / `apply_block_with_covered` / `apply_block_for_sync` ~:3428-3530; tests ~:4500-4640)
- Modify: `crates/randprotocol-core/src/ledger/perps.rs` (`verify_state_proof` ~:1092)
- Modify: `crates/randprotocol-core/src/lib.rs` (re-export), `crates/randprotocol-core/src/confidential.rs` (`decode_*` docs), `crates/randprotocol-core/src/consensus/hotstuff.rs` (`verified` field, `set_verified_proofs`, the three apply call sites), `crates/randprotocol-core/src/consensus/tests.rs`, `crates/randprotocol-core/src/ledger/program_state.rs` (test `the_verified_set_does_not_vouch_for_a_read`), `crates/randprotocol-core/src/ledger/aggregation.rs` (tests)
- Modify: `crates/randprotocol-node/src/admission.rs` (`VerifiedSet`, `VERIFIED_SET_ENTRIES`, its test), `crates/randprotocol-node/src/node.rs` (`Node::verified`, `start_with` ~:2557, `pump_verify` ~:3084-3098, `spawn_apply` ~:4103, ~:5132, test helpers ~:7282 and ~:9179-9270), `crates/randprotocol-node/src/verify_cache.rs` (`VERIFY_CACHE_ENTRIES` → 32_768 and its doc), `crates/randprotocol-node/src/storage.rs`, `crates/randprotocol-node/src/bench.rs`
- Any other file `cargo +1.98.1 check --workspace --all-targets` names.

**Interfaces:**
- Produces: ledger apply/validate functions without a verified-set parameter. Where `apply_tx_with(tx, proposer, executor, verified)` duplicated `apply_tx(tx, proposer, executor)`, keep `apply_tx` and delete the `_with` variant; same for `apply_block_with` vs `apply_block`. `apply_tx_checked(tx, proposer, executor)`, `apply_transactions_for_sync(txs, proposer, covered, pruned, executor)`, `apply_block_for_sync(block, covered, pruned, executor)`, `apply_block_with_covered(block, covered, executor)` (or whatever its non-verified arguments are today, in the same order).
- `HotStuff::set_verified_proofs` removed.

- [ ] **Step 1: Write the failing tests first.**
  - Core, `ledger/mod.rs` tests: replace `apply_skips_the_proof_of_an_admitted_transaction` (and the call-decode one beside it, ~:4608-4640) with `apply_never_decodes_a_proof`: a test executor wrapping `StubExecutor` whose `decode_call`, `decode_call_hardened`, `decode_invoke`, `decode_perp` `panic!("the ledger decoded a proof")`; apply a block with a bundle transaction and a call through `apply_block` and through `apply_block_for_sync`, and `validate` a call. Existing fixtures in that test module build these transactions; reuse them.
  - Node, `verify_cache.rs` tests (or `node.rs` tests where a full admission fixture already exists — `the admission cache that counts its hits` helper at ~:9179 is the model): `admission_then_apply_verifies_each_proof_once`: a `CachingExecutor` over a counting executor; run the node's admission validation (`validate_for_pool` or the function `pump_verify` calls) on a split-auth bundle transaction and on a call transaction, then apply a block holding both on the same ledger with the same executor; assert the inner `verify_bundle`, `verify_auth`, `verify_call` (or `verify_call_hardened`, whichever the fixture chain uses) counts are each exactly 1.
  - Run: `cargo +1.98.1 test -p randprotocol-core --lib apply_never_decodes` → FAIL (decode panics / compile error once the old API is gone is fine as RED).

- [ ] **Step 2: Remove the verified set from core.** Delete the trait, `NoVerified`, the `RwLock` impl and re-export; remove the `admitted` parameter and both `if !admitted` guards in `check_bundle_proof` (verify unconditionally); step 10 calls only `verify_invoke` / `verify_call_hardened` / `verify_call`; `perps::verify_state_proof` loses `admitted` and calls `verify_perp`. Rewrite the doc comments that mention B5 / the verified set to say the node's verify cache (`randprotocol-node`'s `CachingExecutor`) is what spares a re-verification, citing this spec. `decode_*` docs in `confidential.rs`: "admission pricing only — the ledger never calls this".

- [ ] **Step 3: Remove it from HotStuff and the node.** `HotStuff::verified` / `set_verified_proofs` go; its apply calls drop the argument. Node: delete `VerifiedSet`, `VERIFIED_SET_ENTRIES` and its test, `Node::verified`, the insert in `pump_verify` (keep the comment's point as one line: admission's verify through `self.executor` fills the verify cache), the argument in `spawn_apply` and the `set_verified_proofs` call. `VERIFY_CACHE_ENTRIES = 32_768` with the doc: "three entries per transaction (bundle, auth, one call / invoke / perp) for the 8192 transactions the retired verified set held, rounded up to a power of two".

- [ ] **Step 4: Fix every remaining call site and test** the compiler names (tests passing `&NoVerified` just drop the argument; tests that asserted a skip on a hit move to asserting a cache hit or are deleted if Step 1's tests cover them — say which in the report).

- [ ] **Step 5: Verify.**
  - `cargo +1.98.1 test -p randprotocol-core --lib` — all pass.
  - `cargo +1.98.1 test -p randprotocol-node --lib` — all pass.
  - `cargo +1.98.1 test -p randprotocol-node --test cli_datadir` — pass.
  - `cargo +1.98.1 clippy --workspace --all-targets` — no new warnings.
  - `grep -rn "VerifiedProofs\|NoVerified\|VerifiedSet\|verified_proofs\|set_verified_proofs" crates docs --include='*.rs'` — nothing.

- [ ] **Step 6: Commit** `ledger, node: fold the verified set into the verify cache — the ledger always verifies (never decodes) a proof at apply; CachingExecutor answers what admission verified; VERIFY_CACHE_ENTRIES 32 768`.

### Task 2: Docs

**Files:**
- Modify: `docs/compute-optimization.md` (§3.3: the verified set is retired; one cache), `docs/architecture.md` (wherever the verified set / B5 skip is described), `CHANGELOG.md` (v0.8.0: extend the verify-cache bullet with one sentence — "The admission verified set (B5) is folded in: the ledger never decodes a proof at apply, and the cache holds 32 768 verdicts."), `docs/superpowers/specs/2026-10-11-verify-cache-design.md` (the "Folding the two together is a later cleanup" line → points to `2026-10-12-verified-fold-design.md`).
- Find others: `grep -rn -i "verified set\|VerifiedSet\|B5" docs/ *.md`.

- [ ] **Step 1:** Edit each hit so it describes the fold; keep each file's style. Do not touch other CHANGELOG bullets.
- [ ] **Step 2:** `grep` again — only historical mentions (audit reports, dated specs) remain.
- [ ] **Step 3: Commit** `docs: the verified set is folded into the verify cache`.
