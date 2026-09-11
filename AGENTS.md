# AGENTS.md

Guidance for agents working in this repository. The README is the user-facing
overview; this file is the durable project memory: review state, load-bearing
invariants, and known traps.

## Project memory (state as of 2026-09-10)

### Security review: done, fixes merged

A full review of the four crates against the Draft 3 whitepaper was done on
2026-09-10. Findings: `../concerns/fullnode-review-2026-09-10.md` (severity-
ordered, each verified against code, with a "verified OK" section — read it
before re-reporting suspected issues). Fixes merged into `main`:

- `1d24bf9` consensus: three-consecutive-view commit rule, local QC assembly, view/state bounds
- `d5143a6` hardening: cheap-before-expensive checks, block size as a consensus rule
- `a44d3f4` robustness: key file permissions, RPC limits, storage receipts, genesis validation

### Zk-side audit: fixes on branch `zk-audit-fixes-sep12` (2026-09-12)

A zk-focused audit (all eight AIRs, the emulator, host prover glue, chain
integration, and the cheating-test suite) found two **critical soundness holes**
in `tables/cpu.rs`'s hash row-group routing, plus a batch of completeness bugs:

- Free-standing `IS_HASH`/`IS_HASH_OUT` rows had **no entry gate** — a cheating
  prover could splice write-back rows anywhere, giving 4 arbitrary RAM writes per
  row at a free, unbounded `HASH_PTR` with no permutation consumed (a total break
  of execution integrity). Fixed with three transition gates (absorb/write-back
  predecessors, and nothing after the second write-back row).
- `HASH_FIN` was never pinned to write-back rows — setting it on the ecall row
  detached the group's `HASH_PTR` from its range-checked source (the same hole,
  one row later) and shifted the PC chain by one instruction. Fixed with
  `HASH_FIN·(1 − IS_HASH_OUT) = 0`.
- Both have full attack-witness regression tests in `tests/cheating.rs` that
  **verify against the pre-fix constraints** and are rejected after (confirmed by
  running them with the gates removed).
- **The M2.2 FRI retune (27 queries) is reverted to the whitepaper's 80/8/20**:
  it met the ethSTARK conjectured 100-bit target but dropped the proven
  proximity-gaps floor to ~42 bits (vs ~86 at q=80). The paper's reconciliation
  keeps q=80 for exactly this reason.
- Completeness/robustness: memory-table sort key now matches the AIR's key
  arithmetic (honest ≥2^30 hash addresses were unprovable); the emulator rejects
  `ptr ≥ 2^30`; the poseidon2 permutation budget is a `ProveError`, not a panic
  (auto-tier fits both budgets); the 16-bit `HASH_LEFT` cap (65 535 words) is
  enforced host-side; prove-side tier/`base_pc`-wrap/immediate-truncation
  guards. Docs call this **constraint set 5** — a hard fork like every set
  before it; fleets must run the same build.
- Also on this branch: `genesis.rs`'s pinned live-testnet hash was stale on
  `main` (chain 4's `7e6271a3`; chain 5 is `3a82b0c7` per `deploy/README.md`) —
  `main`'s own suite was red before this branch.

### Load-bearing consensus invariants (do not regress)

- **The commit rule needs three consecutive-view QCs.** Any relaxation
  re-opens the conflicting-finality bug (regression test:
  `commit_rule_requires_three_consecutive_views`).
- **Every validator assembles QCs locally.** Votes already flood the gossip
  topic; the old `on_vote` gate that dropped them at non-leaders is what
  stalled finality whenever a collector was down (regression test:
  `one_validator_down_keeps_committing`). Do not reintroduce collector-only
  QC assembly. This likely root-causes the "views advance but nothing
  commits" stall worked around in `f5b8dfd`; fleets must run the same build
  (old collectors still eat QCs).
- **Views are bounded** (`MAX_VIEW_AHEAD = 1e6`) and all `view + 1` math is
  saturating. A signed NewView for `u64::MAX` used to halt every node.
- **Speculative state is capped**: `max_tree_blocks` (512), vote map (4096
  keys), NewView map (2048 views), orphans (256). Each tree entry clones the
  full ledger — revisit the clone-per-block design when state grows.

### Open follow-ups (not fixed, see concerns doc)

- `deploy/*.key.json` holds the live testnet validator seeds, whitelisted in
  `.gitignore`. Decide: rotate + scrub, or document as throwaway-public.
- Proof verification still runs on the consensus event loop (~20 ms warm);
  moving it to `spawn_blocking` + gossipsub `Strict` validation is the real
  DoS fix (fee floor and FIFO key cache are mitigations only).
- Lock promises are not durable across restarts (`resume` discards persisted
  `locked_qc`; `extends_locked` relaxes when the locked block is unknown) —
  deliberate liveness choice, needs a protocol-level decision.
- Wallet uses committed nonce (stale-nonce race on fast double-send); the
  clean fix is a mempool-aware `next_nonce` RPC.

### Repo workflow traps

- **This repo is worked on by multiple agents/sessions in parallel**, in the
  same checkout. Branches and the worktree HEAD move mid-task. Before
  committing, re-check `git worktree list` and `git log main`; for anything
  non-trivial, do your work in a separate worktree
  (`git worktree add /tmp/fullnode-<name> <branch>`).
- History alternates squashed mega-commits with small linear ones; branches
  get merged and deleted quickly. `main` is the only durable line.
- Full test suite: `cargo test --release` (~6 min: zkvm proving and the
  TCP cluster tests dominate). Doctest flakiness ("extern location ...
  does not exist") means a concurrent cargo run raced the cache; rerun.
- The whitepaper is `../whitepapers/randprotocol.tex` (Draft 3) — its
  AGENTS.md has the parameter table (FRI 80/8/20, Poseidon2 width 8,
  384-bit soundness-bearing hashes) that this repo's docs should stay
  consistent with.
