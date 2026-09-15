# AGENTS.md

Guidance for agents working in this repository. The README is the user-facing
overview; this file is the durable project memory: review state, load-bearing
invariants, and known traps.

## Project memory (state as of 2026-09-15)

### Block aggregation: implementation in flight on `aggregation-spec` (user-owned hardware tasks gate activation)

The chain-side block aggregation spec is **approved by the user (2026-09-15)** —
`docs/superpowers/specs/2026-09-15-block-aggregation.md` — with its ten-task plan at
`docs/superpowers/plans/2026-09-15-block-aggregation.md`. Work happens on branch
`aggregation-spec`; **the finish line is merge to main + push** (T7–T10 remain at this writing:
sealed sync, RPC/CLI, chain-9 genesis, end-to-end). Everything is genesis-gated on
`genesis.aggregation`: a chain without the section behaves byte-for-byte as today, and the branch
lands dark — activation waits on hardware below. Landed so far: the five actions and the
genesis-gated `aggregators_root` (`shrugg-state-3`); the register actions mirrored on S2;
`crates/shrugg-rvm` vendored from `circuits/recursion` `271679d` via `deploy/sync-zkvm.sh`'s
two-step rename (a **path dep would fork `rand_zkvm` into two distinct crates — never do it**);
the nine-step admission with the pinned hex conformance vectors reproduced byte-for-byte; the
crate-cycle rule (shrugg-rvm → shrugg-zkvm, so the real `AggExecutor` lives in shrugg-node);
subsidy + the four audit counters; sealing and pruning (CF_SEALS, pruned = full tx + 34 pv + 7
shape bytes). Two traps already caught and pinned: `main.rs`'s genesis command must set
`genesis.aggregation`, and `reload_ledger` must restore the gate on restart (fork-at-first-restart
otherwise).

**User-owned hardware tasks (accepted 2026-09-15, scheduled 2026-09-16 — see `docs/deploy.md`
"Deferred proof runs and hardware tasks" and README's "Open ops tasks"):** ① the ≥ 64 GB batch
(runbook rows 1–6 in `circuits/recursion/docs/03-gpu-and-self-recursion.md` Appendix A) — its
measurements fill chain-9's `admitted_shapes[0]`, which is what activates chain 9 (the zero-digest
placeholder refuses to init); production proofs run *after* chain-side aggregation lands, per the
user's 2026-09-15 ruling. ② A fleet GPU node (Linux, R580+, CUDA 13, LLVM 21, sm_80+, 80 GB
device, ≥ 160 GB host) for the rVM CUDA backend's PTX build and the production N re-measurement
(M5.4's only open tasks, T3/T4).

### Block aggregation, Tasks 1–4 (2026-09-15, `aggregation-spec` branch): the rVM vendored, admission live

The block-aggregation plan (`docs/superpowers/plans/2026-09-15-block-aggregation.md`, ten
tasks) is landing task-by-task on `aggregation-spec`. State and traps a later session needs:

- `crates/shrugg-rvm/` is **vendored** from `circuits/recursion` (pin `271679d`) by
  `deploy/sync-zkvm.sh`'s recursion section (`RVM_SRC` env override) — never hand-edit it; the
  same two-step `rand_zkvm → shrugg_zkvm` rename as the research section makes the two
  vendored crates' `Proof` types one type. Re-running the script re-vendors both sections.
- **The crate cycle decides where executor code lives**: `shrugg-rvm → shrugg-zkvm`, so
  `ZkExecutor` cannot touch the rVM. Its three aggregate arms return
  `ConfidentialError::AggregationUnsupported`; the real implementation is
  `shrugg_node::agg_executor::AggExecutor`, which `node::executor_for_profile` always wraps.
  `AggregationUnsupported`/`BadDeclaredShape` are never permanent admission verdicts.
- `shrugg_core::types::pv` **mirrors** the zkVM's `pv` layout (core cannot name zkvm types);
  `shrugg-zkvm/src/executor.rs`'s test pins mirror == real.
- Interims by design until the later tasks land: `validate_inner`/`apply_tx` refuse
  `Action::Aggregate` with `TxError::AggregateNeedsCovered` (a proposer's trial-apply skips
  pooled aggregates; no block can carry one until T6's covered pre-pass); admission runs
  through `Ledger::validate_aggregate`/`apply_aggregate` with the covered records assembled
  node-side (`node::assemble_covered`, from CF_TXS); the payout amount is `subsidy(0)` (no
  excess buckets, `sealed_blocks` unincremented) until T5.
- **Gate gap this branch already fell into once**: `cargo test -p shrugg-node --lib` compiles
  neither `src/main.rs` nor `tests/`, so T1's new `Genesis` field silently broke both. Fixed
  in T3/T4; run `cargo check --tests` (or the T10 full suite) before trusting a `--lib`-only
  gate after touching shared types.
- Recursion-heavy tests stay out of gates: `cargo test --release -p shrugg-rvm -- --skip
  round_trips --skip two_test_profile` with `RECURSION_FIXTURES` pointing at a recursion
  fixture cache (the conformance vectors ride on the fixtures' random notes — the cache that
  produced `circuits/recursion/docs/02-aggregate.md`'s pins reproduces them byte-for-byte).

### Constraint set 6 re-vendor (2026-09-14, upstream 0200877): the public input segment, carrying M4.3 + M4.4

`crates/shrugg-zkvm/` is re-vendored to `research`'s constraint-set-6 merge (the public input
segment), which also carries milestones 4.3 (the EVM interpreter guest) and 4.4 (the `sha256`
table, `SYS_SHA256 = 5`, and the sBPF interpreter guest) into this crate. A hard fork like every
set before it; fleets must run the same build (`docs/confidential.md`, "Constraint set 6").

- The zk side: a ninth **mandatory** table, `public` (the `PUBLIC_DIGEST`/`PUBLIC_READ` bus pair,
  sixteen buses in all), `SYS_READ_PUBLIC = 6`, and `H_PUB` in `pv::PUB0..7` — **unsalted**,
  unlike `H_IN`, so `Machine::verify_public(hc, public_words, proof)` recomputes
  `hash::public_digest(words)` natively and compares. `pv::NUM` 26 → 34, cpu `col::WIDTH`
  224 → 275, `Machine::verifier_key` a 6-tuple `(tier, program, input, keccak, sha256, public)`,
  and `Proof` gains `sha256_log_height` (optional, `0` = no table, the keccak table's exact
  terms) and `public_log_height` (mandatory; an empty segment is four rows, height 2).
- **The chain admits only the empty public segment**: `ZkExecutor::verify_call`/`verify_bundle`
  both call `verify_public(hc, &[], proof)`. Plain `verify` would leave `pv::PUB0..7` bound only
  in-circuit — to a segment the chain never saw — and today's guests read no public words
  anyway. A future action type that publishes words passes them in place of `&[]`.
- `MAX_PROOF_BYTES` **stays 2 MiB**, re-measured on this tree (see the commit message and
  `docs/confidential.md`): the mandatory public table + 51 new cpu columns grow a keccak-free
  production proof by a few percent over set 5's 1 202 416 bytes (tier 10), still far under the
  cap, and a keccak-carrying proof is still far over it.
- Vendoring mechanics worth knowing before the next resync (all in `deploy/sync-zkvm.sh`'s
  header): the `log_ext_degrees_pub` patch is re-anchored on the six-parameter `verifier_key`
  line and forwards all seven `log_ext_degrees` arguments; the domain-tag inlining gained a
  third tag (`PUB_DOMAIN = 15`, in `hash.rs` and `tables/cpu.rs`); `call_envelope.rs` (src and
  tests) had to be **added to the rsync exclude list** — it is node-local S3 code that did not
  exist when the list was written, and `--delete` would have removed it; three vendored files
  (`src/evm.rs`, `src/sbpf.rs`, `tests/isa.rs`) `include!` assets at upstream's two-levels-up
  `guests-compiled/` layout and get a sed to this crate's shallower one; the guest copy step is
  four bins (`fib`, `keccak256`, `evm`, `sbpf`) plus two assets (`erc20.runtime.hex`,
  `spl_token.so`).
- **New build requirement**: `evm-core` and `sbpf-core` are *path* dependencies of
  `shrugg-zkvm` (`../../../circuits/guests-compiled/{evm-core,sbpf-core}`) and, unlike
  `rand-zkvm-cuda`, they are NOT optional — `circuits/` must sit beside `fullnode/` for any
  build of the crate. In a `/tmp/fullnode-*` worktree that means `ln -s
  <real circuits checkout> /tmp/circuits` first, or `cargo metadata` fails on the (already
  pre-existing) optional cuda path dep too. Dev-oracles at upstream's exact pins: `revm
  =43.0.2`, `solana-sbpf =0.11.1`, `sha2 =0.10.9`, `num-bigint 0.4`.
- The vendored suite grows by the EVM/sBPF/sha256 test files (`tests/evm_*.rs`, `tests/sbpf_*.rs`,
  `tests/sha256.rs`, a much bigger `tests/e2e.rs` including a tier-16 EVM call proof).
  `cargo test --workspace --release` at the re-vendor: **678 passed, 0 failed, 6 ignored**
  (upstream's three production measurements, the sBPF cycle breakdown, and the two
  memory-bound interpreter exit proofs), ~43½ min wall from a cold release target on a loaded
  machine — wallet flow 9m37s, cluster 22m44s (18 tests), zkvm e2e 7m25s.

### Security review: done, fixes merged

A full review of the four crates against the Draft 3 whitepaper was done on
2026-09-10. Findings: `../concerns/fullnode-review-2026-09-10.md` (severity-
ordered, each verified against code, with a "verified OK" section — read it
before re-reporting suspected issues). Fixes merged into `main`:

- `1d24bf9` consensus: three-consecutive-view commit rule, local QC assembly, view/state bounds
- `d5143a6` hardening: cheap-before-expensive checks, block size as a consensus rule
- `a44d3f4` robustness: key file permissions, RPC limits, storage receipts, genesis validation

### Zk-side audit: fixes ported upstream, vendored back as constraint set 5 (2026-09-12)

A zk-focused audit (every AIR, the emulator, the host prover glue, chain
integration, and the cheating-test suite) found two **critical soundness holes**
in `tables/cpu.rs`'s hash row-group routing, plus a batch of completeness bugs.
Findings: `../concerns/fullnode-zk-audit-2026-09-12.md` (severity-ordered, each
verified against code, the two Critical items confirmed with attack witnesses
that verify pre-fix — read it before re-reporting suspected issues).

Every zk-side fix below was **ported into `research` upstream** and arrives here
through the constraint-set-5 re-vendor, not as a local patch — so read
`crates/shrugg-zkvm/` as vendored code and take a fix back to `research` first.

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
  keeps q=80 for exactly this reason. `MAX_PROOF_BYTES` is 2 MiB because of it —
  at 80 queries the old 1 MiB cap rejected every production proof.
- Completeness/robustness: memory-table sort key now matches the AIR's key
  arithmetic (honest ≥2^30 hash addresses were unprovable); the emulator rejects
  `ptr ≥ 2^30`; the poseidon2 permutation budget is a `ProveError`, not a panic
  (auto-tier fits both budgets); the 16-bit `HASH_LEFT` cap (65 535 words) is
  enforced host-side; prove-side tier and immediate-truncation guards.
- **ZH4 is the one fix that is ours, not `research`'s**, because the function is:
  `ZkExecutor::check_program` (`crates/shrugg-zkvm/src/executor.rs`) rejects a
  program whose `base_pc + 4·len` wraps the u32 pc space — deployable, provable
  by nothing, and paid for per word.
- The re-vendor that carried these also carried **milestone 4.2** (the `keccak`
  table and `KECCAK` syscall, optional per proof; proof-declared `mem_log_height`;
  a four-keyed verifier key), so constraint set 5 is both at once. A hard fork
  like every set before it; fleets must run the same build
  (`docs/confidential.md`, "Constraint set 5").

### RPC hardening: admission verification off the consensus loop (2026-09-14)

S1's review item I2, shipped on `rpc-hardening`. A gossiped or RPC-submitted
transaction's proofs now verify on `spawn_blocking` against a lazily refreshed
`Arc<Ledger>` snapshot — four workers behind a 64-deep queue — while the
consensus loop keeps turning; `Mempool` is split into a cheap `precheck` and an
`insert_verified` that re-runs the state-dependent half against the tip the
transaction is actually pooled on. Gossipsub uses application-level validation
(`validate_messages`), so a transaction is forwarded only once it has verified
here — **`ValidationMode` deliberately stays `Permissive`: a Strict/Permissive
mix across a fleet drops messages, and application validation is local to one
node**. The cost of that switch: every delivered message must be reported back
to gossipsub **exactly once** (accept / reject / ignore) or this node silently
stops forwarding it — consensus and status messages are accepted immediately,
and every transaction path, error paths included, ends in exactly one report. A
bounded refused-hash cache (8192 entries, FIFO, permanent verdicts only — the
`is_permanent` allowlist) answers a repeat refusal for free, and a per-peer
token bucket (burst 16, refill 4/s, keyed on the forwarding peer's
`propagation_source`, held on `node::Peer`) meters gossiped submissions. The RPC
grew `shrugg_getCompactBlocks`, batch requests (cap 20, notifications refused
`-32600`) and a WebSocket `newHeads` subscription on the same port;
`docs/rpc.md`'s changelog is the client-facing list.

Same day, the key property narrowed: a node may hold **viewing keys** — never
spend keys; the RPC layer has no type for those — for explorer-side scanning
(`shrugg_importViewingKey` / `shrugg_getViewingNotes`, in memory, 64 keys, 10 000
leaves a call, cleared at restart) and answer one-call payment proofs
(`shrugg_checkTransaction`, stateless). An imported key can disclose notes but
never move them.

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
- Block-application proof verification (`Ledger::apply_block`, synchronous
  inside `on_proposal`) still runs on the consensus event loop; moving it
  changes when a vote is emitted, so it needs a consensus decision. Admission
  verification left the loop on 2026-09-14 — see the RPC-hardening note above.
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
- Full test suite: `cargo test --workspace --release` — 466 tests across 27
  binaries, **22 min measured 2026-09-13** on a machine also running another
  session's build, and measured *before* the proving slot below. Cargo runs the
  test binaries one after another and the two that prove real bundles dominate:
  the wallet flow 9m19s (six bundle proofs plus a call proof, after S2's bond
  stage and S3's call-envelope stage were merged into it) and the TCP cluster
  suite 6m28s (16 tests, proofs overlapping).
- **Proving concurrency is capped, and that cap — not block spacing — is what
  keeps a proof inside its window.** `crates/shrugg-node/tests/proving_slot/`
  and `crates/shrugg-client/tests/proving_slot/` (one module, two copies: both
  test binaries need it and they are different crates) hand out one permit at a
  time through a file lock in `<target-dir>/tmp`, so no two *unrelated* bundle
  proofs run at once anywhere in the workspace — across test binaries, and
  across two sessions' concurrent `cargo test` runs. Every proving test takes it
  around the whole `wallet::send`/`submit`/`submit_burn` call; the one test whose
  subject is a race takes it once for its pair, so the bound the windows have to
  outlive is a *two-way* contended proof (~190–255 s against 768 s at 3 s
  blocks), not a lone one — `PROVING`'s doc comment states it. With it the
  cluster suite measures **19m59s, 17 tests, 2026-09-13** — slower in wall time, because
  the proofs no longer overlap, and each proof correspondingly faster. That is
  where the 20 minutes go: the suite's ten holds carry **12 bundle proofs and 2
  program proofs**, and a bundle now measures 94.6–97.9 s alone (against ~255 s
  contended), with the double-spend race's two concurrent bundles at 114 s each
  and the burn's two sequential ones 190 s together — ~19 min of proving, plus
  the structural tests. The **wallet flow** measures **9m40s** with the slot
  (579.84 s, five bundles at 99.6–107.7 s plus a call proof) against 9m19s
  without it: that suite was already one test proving in sequence, so the slot
  costs it nothing and it never waited once. `PROVING` stays at **3 s blocks**
  (S2 had raised it to 2, S3 to 3) and its doc comment now says why rather than what;
  read it before making that chain faster again.
- Doctest flakiness ("extern location ... does not exist") means a concurrent
  cargo run raced the cache; rerun.
- The whitepaper is `../whitepapers/randprotocol.tex` (Draft 3) — its
  AGENTS.md has the parameter table (FRI 80/8/20, Poseidon2 width 8,
  384-bit soundness-bearing hashes) that this repo's docs should stay
  consistent with.
