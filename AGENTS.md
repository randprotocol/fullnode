# AGENTS.md

Guidance for agents working in this repository. The README is the user-facing
overview; this file is the durable project memory: review state, load-bearing
invariants, and known traps.

## Project memory (state as of 2026-09-17)

### Chain 11 (RAND, short shielded addresses) is LIVE — tag v0.2 (2026-09-17)

Main at `255618f` (pinned build `ee716d7`, tag **`v0.2`**): the short-address feature merged
linear (ff) from `short-address`. Chain 11 genesis `79123fa7…` (23 receiver records), rolled
out to 16 droplets + A with `deploy/cutover-droplet.sh` (service `rand-node`, peer ids
unchanged); explorer redeployed with `/api/v1/receivers` (randscan main `d580e5b`); the
activity wallets registered. **B still needs `bin-ee716d7/` and `.update-pin` = `ee716d7`.**
Deferred after merge (the final review's list, in `docs/superpowers/plans/…` history and the
review): a dedicated explorer `TxKind::RegisterReceiver`; `docs/architecture.md`'s stale txid /
action-count / state-domain lines; `--chain-id` for `rand address --record` so the next cut
needs no bootstrap node; a mempool claim key for first registrations; the explorer's address
length pre-check and `receiver_history` limit; `PaymentRequest.record` accessor; http registry
warning; the research repo's own RAND rename.

### Short shielded addresses (2026-09-17): implemented on branch `short-address`, chain 11

Spec approved 2026-09-17 (`docs/superpowers/specs/2026-09-17-short-shielded-address.md`, design
Anish Mohammad); the plan (`docs/superpowers/plans/2026-09-17-short-shielded-address.md`) refined
it with four rulings, R1–R4, all implemented as ruled, not as the spec first drafted:

- **R1** — retired ML-KEM secrets are **re-derived by version, not stored**: `ViewingKey::
  kem_seed_at(v)` (`crates/randprotocol-zkvm/src/notes.rs`) is `kem_seed()` itself at `v = 0`
  (domain `KEM_SEED`, unchanged, so every pre-chain-11 wallet and envelope keeps its meaning) and
  a fresh `domain::KEM_SEED_VERSION` hash of `(nk, v)` for every `v ≥ 1` — never layered on top of
  `kem_seed()`'s output. The key file (`KeyFile` v3, `randprotocol-client/src/wallet.rs`) stores
  only the highest `kem_version` reached; opening an envelope tries every version down to 0,
  newest first.
- **R2** — sender-paid registration **needs no note-to-pk tie**: `Action::RegisterReceiver`'s
  validity is `record.verify(id, chain_id)` plus the version-step rule alone
  (`ledger/receivers.rs`); nothing checks that the paying bundle also creates a note for the
  record's `pk` (the spec §6.3 draft's proposed tie — see the note at the end of this entry).
- **R3** — registrations (validator and aggregator) **must name a registered id**:
  `StakingError::UnknownReceiver` / `AggregationError::UnknownReceiver` refuse a `Bond`/
  `RegisterAggregator` whose payout id has no record in the registry at check time — no same-
  transaction carry-in exists in the implemented code.
- **R4** — `ShieldedAddress` (`crates/randprotocol-core/src/notes.rs`) **stays the in-memory
  pk/kem_ek pair**; only its text form (`Display`/`parse`/`recipient_hash`/`ADDRESS_PREFIX`) was
  removed. `impl From<&ReceiverRecord> for ShieldedAddress` is the bridge from a resolved record
  to what sealing an envelope needs.

Per crate:

- **core** (`crates/randprotocol-core/src/receiver.rs`): `ReceiverId` (32 bytes, `rand1…` text,
  53–55 chars, checksummed) and `ReceiverRecord` (`version`, `pk`, `kem_ek`, `signing_key`,
  `signature`, `MAX_RECORD_BYTES = 8192`), one `verify()` used by core, client and the explorer
  (`randprotocol_core::ReceiverRecord::verify`, confirmed in randscan's own `docs/api.md`). New
  hash domains: `rand-receiver-sign-1` (the signing key seed), `rand-receiver-
  addr-1` (the address checksum), `rand-receiver-record-1` (the signing hash). `ledger/
  receivers.rs`: the registry `BTreeMap<ReceiverId, ReceiverRecord>`, `rand-receiver-leaf-1`
  merkle leaves, folded into the state root as `rand-state-4` (bumped from `rand-state-3`).
  `ledger/staking.rs` / `ledger/aggregation.rs`: `payout: ReceiverId` throughout, resolved via
  `resolve_pk`/`resolve_record`, `UnknownReceiver` on a miss; leaf domains bumped to
  `rand-validator-leaf-3` and `rand-aggregator-leaf-2`. `ledger/bridge_notes.rs`:
  `BridgeAttest.recipient: ReceiverId`, the wire's 32-byte `to` field *is* the id (no more
  `blake3` hash of a long address), `BridgeError::UnknownReceiver` on an unregistered recipient.
  `genesis.rs`: `Genesis::receivers: Vec<ReceiverRecordHex>`, registered before any validator
  payout or alloc owner is resolved.
- **zkVM** (`crates/randprotocol-zkvm/src/viewing.rs`, `notes.rs`): `kem_seed_at`/`address_at`/
  `open_as_receiver_at`, versioned KEM keys (R1 above); nothing about the receiver id enters a
  proof.
- **node** (`crates/randprotocol-node/src/rpc.rs`): `rand_getReceiver`/`rand_getReceivers`,
  `rand_mint`'s optional third `record` param, `record_json`/`tx_json`'s `register_receiver`
  kind. `main.rs`: `genesis --receiver <RECORD.JSON>` (repeatable, registered first), the
  withdraw/aggregate commands resolve records through `resolve_receiver`.
- **client** (`crates/randprotocol-client`): `receiver.rs` (the payment-request URI, the registry
  lookup, the §4 error text verbatim: *"no receiver record for {id}: ask the receiver for a
  payment request, or for them to register"*), `wallet.rs` (`KeyFile` v3 with `kem_version`,
  `Wallet::rotate`/`record`/`record_at`, record version = KEM version + 1), `main.rs` (`address
  [--record]`, `request`, `register [--rotate]`, `send [--record|--registry|--register]`,
  `bridge-deposit-address` refusing until registered, `call --auditor-record/--registry`).
- **explorer** (`randprotocol/randscan`, branch `receivers`): `GET /api/v1/receivers/:address`
  and `/history`, re-verifying every record with the same `verify()` before indexing
  (`../randscan/docs/api.md` "Receivers").

**Chain 11 is not yet cut.** This is a hard fork (address text form, register/registry state,
bridge wire format, state root domain) and ships alongside the next chain cut, not before it —
`deploy/cut-chain11-genesis.sh` does not exist yet. Docs updated to match this branch's code:
`docs/shielded.md` (new §2), `docs/staking.md`, `docs/bridge.md` (§§5, 6, 10–12), `docs/rpc.md`
(new methods, wire format, changelog), `docs/cli.md`, `README.md`.

Note for anyone reading the spec document itself: its §6.3 draft proposed that a sender-paid
`RegisterReceiver` "must sit on a bundle that also creates a note for the record's `pk`" — the
plan's ruling R2 dropped that tie, and `validate_register_receiver` (`ledger/receivers.rs`)
implements exactly that: `verify()` plus the version-step rule, nothing about the bundle's
commitments. `docs/shielded.md` §6 and `docs/bridge.md` describe the code as it is (no tie), per
R2, not the spec's original §6.3 text.

### Session close 2026-09-16: M5 complete, aggregation merged, papers synced — all three repos at their final commits

Everything below is merged and pushed; nothing is pending in any working tree.

- **circuits** `main` at **271679d** (origin): the recursion VM complete — M5.1 (ISA,
  emulator, DSL, verifier program; 50/50 real proofs accepted/refused; 5 682 847 rows per
  inner proof measured), M5.2 (the machine: 8 instances, three gated cuts to **1 968 619
  rows**, tier 21; 26/26 cheating; test-profile exit passed), M5.3 (the N-generic aggregate
  program + chain API + admission stub vectors; machine classes N=1/2/3 → ≥64/128/160 GB),
  M5.4 (CUDA backend split with **zero new kernels**, tier-23 rung, measured device model,
  self-verifier written with its measured requirement). Open only: the PTX first build and
  the production N re-measurement — **blocked on the user provisioning a fleet GPU node**
  (Linux, R580+, CUDA 13, LLVM 21, sm_80+, 80 GB device, ≥160 GB host; `PTX_BUILD.md`).
- **fullnode** `main` at **faef139** (origin): RPC hardening, constraint set 6, viewing-key
  import + `rand_checkTransaction`, and the full block-aggregation pipeline (see the merged
  entry below). `docs/zkvm-m4-m5-progress.md` is the consolidated M4+M5 record with every
  measured number and the 11-row deferred-proof runbook.
- **whitepapers** `main` at **f31277c** (origin): both papers synced to `faef139` —
  `randprotocol.tex` (third pass: abstract + changes list, reconciliation at cs6/M5/aggregation,
  remarks updated) and `randprotocol_implementation.tex` (Implementation Draft 3, new
  `sec:aggregation`); all three PDFs regenerated and committed. Both compile clean, zero
  undefined refs.
- **Outstanding, user-owned**: ① the ≥64 GB proof batch (runbook rows 1–6; fills chain-9's
  `admitted_shapes[0]` — the zero-digest placeholder refuses to init, so this activates
  aggregation) and ② the GPU node above. Full checklists: `docs/deploy.md` ("Deferred proof
  runs and hardware tasks", "Chain 9 activation") and the README's "Open ops tasks".

### Block aggregation: MERGED to main (856887a, 2026-09-16, linear rebase) — user-owned hardware tasks gate activation

The chain-side block aggregation spec is **approved by the user (2026-09-15)** —
`docs/superpowers/specs/2026-09-15-block-aggregation.md` — and all ten plan tasks landed on main
(15 commits, rebased linear off 5748642; the full workspace suite green, the cluster capstone
included). Everything is genesis-gated on `genesis.aggregation`: a chain without the section
behaves byte-for-byte as today, so **chain 8 is unaffected and chain 9 activates only after the
hardware batch below** (its measurements fill `admitted_shapes[0]`; the zero-digest placeholder
refuses to init). What landed: the five actions and the genesis-gated `aggregators_root`
(`rand-state-3`); the register actions mirrored on S2; `crates/randprotocol-rvm` vendored from
`circuits/recursion` `271679d` via `deploy/sync-zkvm.sh`'s two-step rename (a **path dep would
fork `rand_zkvm` into two distinct crates — never do it**); the nine-step admission with the
pinned hex conformance vectors reproduced byte-for-byte; the crate-cycle rule (randprotocol-rvm →
randprotocol-zkvm, so the real `AggExecutor` lives in rand-node); subsidy + the four audit counters;
sealing and pruning (CF_SEALS, pruned = full tx + 34 pv + 7 shape bytes); sealed-form sync with
coverage-closed serving and the robust sync picker; the RPC surface and the `aggregate --watch`
daemon; the chain-9 cut script. Traps already caught and pinned: `main.rs`'s genesis command must
set `genesis.aggregation`; `reload_ledger` must restore the gate on restart (fork-at-first-restart
otherwise); a resumed replica must re-register its `CoveredSource`; the replay path gets the
record-only flavor of the window check, admission keeps the policy flavor; the aggregation tests
need `RECURSION_FIXTURES` set (`docs/aggregation.md`).

**User-owned hardware tasks (accepted 2026-09-15, scheduled 2026-09-16 — see `docs/deploy.md`
"Deferred proof runs and hardware tasks" and README's "Open ops tasks"):** ① the ≥ 64 GB batch
(runbook rows 1–6 in `circuits/recursion/docs/03-gpu-and-self-recursion.md` Appendix A) — its
measurements fill chain-9's `admitted_shapes[0]`, which is what activates chain 9 (the zero-digest
placeholder refuses to init); production proofs run *after* chain-side aggregation lands, per the
user's 2026-09-15 ruling. ② A fleet GPU node (Linux, R580+, CUDA 13, LLVM 21, sm_80+, 80 GB
device, ≥ 160 GB host) for the rVM CUDA backend's PTX build and the production N re-measurement
(M5.4's only open tasks, T3/T4).

### Block aggregation, Tasks 1–10 (2026-09-15, `aggregation-spec` branch): the full pipeline landed

(The fuller picture: `docs/superpowers/plans/2026-09-15-block-aggregation.md`, ten commits on
the branch. What a later session needs beyond the T1–T4 entry below, which stays as the
vendoring/workflow record.)

- **Load-bearing invariants this plan added**: a chain without `genesis.aggregation` is
  byte-for-byte chain 8 (the gate is absolute — `NOT_AGGREGATION` before any register check);
  the nine-step admission is cheap-before-expensive with the rVM verify last, and the covered
  bundles' records are always node-assembled (`Storage::covered_record`, one read for the Raw
  and Pruned forms); `total_supply == issued − slashed` holds with exactly the four new
  counters — `fees_paid` counts the proposer-kept floor at inclusion and an expired excess at
  its sweep, the bucket is not `register_total`, and the payout note's excess part touches no
  counter; a pruned bundle's ledger effect is bound to its aggregate-verified public values by
  the digest of its public fields (`check_bundle_proof`'s pruned branch) — never trust a
  marker form without it.
- **The proving share's bucket is `Ledger::unsealed_fees`, persisted beside `META_SUPPLY` and
  replay-audited** — a restarted node that lost it would mis-pay the next aggregate and fork
  at the state root. The aggregator register (`META_AGGREGATORS`) and the genesis section
  (`META_AGGREGATION`) are persisted the same way; `load_ledger` restores all three.
- **Sealed-form sync is batch-atomic**: a pruned bundle is accepted only when a covering
  aggregate is applied (a local mark) or in the same batch (whose commit is atomic); anything
  else is the raw-form fallback to another peer, never a ban (`node.rs`'s `RawFallback`).
- **Serving is coverage-closed** (`node.rs`'s `close_batch_coverage`). The acceptance above
  makes a batch that ends between a pruned block and its cover unservable — the fallback
  re-asks a peer that pruned the same record and serves the same split form, forever (the
  sealed-sync stall, shown by the capstone inside the full suite: the client's batch count
  halves on wire failures under load; the byte budget cuts where it cuts). So a `Blocks`
  response extends past the count asked and past the soft byte budget until every served
  pruned entry's seal mark resolves inside the batch, capped only by the reader's wire limit
  — beyond that is the genuine archive case the fallback exists for. Do not reintroduce a
  serve path that can cut coverage (regression tests:
  `a_batch_cut_short_of_its_cover_extends_until_the_coverage_closes`,
  `a_batch_cut_by_bytes_short_of_its_cover_extends_within_the_reader_limit`,
  `the_extension_stops_at_the_reader_limit_and_serves_what_it_can`).
- **The sync picker never silently gives up** (`node.rs`'s `pick_sync_peer`): the freshest
  connected-and-ahead peer wins, but with the chain known ahead and no such pair, any
  connected peer is worth one round trip; a send that cannot go out warns, counts, and tries
  the next candidate (regression test:
  `pick_sync_peer_prefers_fresh_and_falls_back_to_any_connected`).
- **Every replica construction re-registers the covered source.** `HotStuff::resume` builds a
  fresh replica, and `apply_synced` forgot to re-set it: a synced node then failed every
  aggregate block at the sidecar (peer-side `AggregateNeedsCovered`; a stable state-root
  mismatch on its own proposals). The resume re-sets `StoreCovered` exactly as startup does.
  And the source answers the **record-only** flavor — existence, bundle-ness, pv and shape —
  never the admission-policy one: before that fix, replaying an aggregate block whose window
  had passed was refused with `AggregateNeedsCovered`, a deterministic consensus break for any
  slow syncer. Coverability policy (window, seal) lives in the admission worker's
  `assemble_covered`, nowhere else.
- **A pruned bundle's identity is its *raw* transaction hash** (the marker form hashes
  differently — the proof bytes differ). The fee bucket keys on it (`0498a3b`), the sealed
  form's side table attests it, and `rand_getUnsealed` resolves marker forms through the
  proof-hash index. Get any of these wrong and the sealed replay diverges at the state root.
- **The proposer's root is computed in list order**: the §3.4 selection trial-applies the
  chosen aggregate *after* the ordinary transactions, where its place in the block is — the
  validators recompute in the same order (the ordering fix, also `0498a3b`).
- The capstone (`tests/cluster.rs`'s `a_fresh_node_syncs_pruned_history_with_one_rvm_verify_per_sealed_window`)
  is the end-to-end proof: register → prove (tier 19, ~26 min on the loaded box) → seal →
  prune → a fresh node resyncs with **one rVM verification per sealed window**. Its wall time
  (~31 min) and the measured numbers live in `docs/aggregation.md` §6.
- The chain-9 admitted shape is the fleet's own measured classes for a 2-in/2-out bundle
  (`program 12, input 10, keccak 0, sha256 0, public 2, mem 16`) — NOT the recursion
  fixtures' (they over-declare at 13/12/18). Cutting a genesis with the wrong shape means no
  aggregate can ever cover a fleet bundle; the cut script's `hc_bundle` keyword substitutes
  the build's pinned guest digest.
- **The measured numbers live in `docs/aggregation.md`** (the cluster capstone's walls, the
  startup key-build, the warm verify).

### Block aggregation, Tasks 1–4 (2026-09-15, `aggregation-spec` branch): the rVM vendored, admission live

The block-aggregation plan (`docs/superpowers/plans/2026-09-15-block-aggregation.md`, ten
tasks) is landing task-by-task on `aggregation-spec`. State and traps a later session needs:

- `crates/randprotocol-rvm/` is **vendored** from `circuits/recursion` (pin `271679d`) by
  `deploy/sync-zkvm.sh`'s recursion section (`RVM_SRC` env override) — never hand-edit it; the
  same two-step `rand_zkvm → randprotocol_zkvm` rename as the research section makes the two
  vendored crates' `Proof` types one type. Re-running the script re-vendors both sections.
- **The crate cycle decides where executor code lives**: `randprotocol-rvm → randprotocol-zkvm`, so
  `ZkExecutor` cannot touch the rVM. Its three aggregate arms return
  `ConfidentialError::AggregationUnsupported`; the real implementation is
  `randprotocol_node::agg_executor::AggExecutor`, which `node::executor_for_profile` always wraps.
  `AggregationUnsupported`/`BadDeclaredShape` are never permanent admission verdicts.
- `randprotocol_core::types::pv` **mirrors** the zkVM's `pv` layout (core cannot name zkvm types);
  `randprotocol-zkvm/src/executor.rs`'s test pins mirror == real.
- Interims by design until the later tasks land: `validate_inner`/`apply_tx` refuse
  `Action::Aggregate` with `TxError::AggregateNeedsCovered` (a proposer's trial-apply skips
  pooled aggregates; no block can carry one until T6's covered pre-pass); admission runs
  through `Ledger::validate_aggregate`/`apply_aggregate` with the covered records assembled
  node-side (`node::assemble_covered`, from CF_TXS); the payout amount is `subsidy(0)` (no
  excess buckets, `sealed_blocks` unincremented) until T5.
- **Gate gap this branch already fell into once**: `cargo test -p randprotocol-node --lib` compiles
  neither `src/main.rs` nor `tests/`, so T1's new `Genesis` field silently broke both. Fixed
  in T3/T4; run `cargo check --tests` (or the T10 full suite) before trusting a `--lib`-only
  gate after touching shared types.
- Recursion-heavy tests stay out of gates: `cargo test --release -p randprotocol-rvm -- --skip
  round_trips --skip two_test_profile` with `RECURSION_FIXTURES` pointing at a recursion
  fixture cache (the conformance vectors ride on the fixtures' random notes — the cache that
  produced `circuits/recursion/docs/02-aggregate.md`'s pins reproduces them byte-for-byte).

### Constraint set 6 re-vendor (2026-09-14, upstream 0200877): the public input segment, carrying M4.3 + M4.4

`crates/randprotocol-zkvm/` is re-vendored to `research`'s constraint-set-6 merge (the public input
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
  `randprotocol-zkvm` (`../../../circuits/guests-compiled/{evm-core,sbpf-core}`) and, unlike
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

### RAND rename and chain 10 (2026-09-16): the coin is RAND; every SHRUGG/SESH name is gone

Commits `a00c88c` (the rename: crates `randprotocol-core/-zkvm/-rvm/-client/-node` — a crate
cannot be `rand-core`, that is crates.io's `rand_core` — binaries `rand-node` and `rand`, RPC
`rand_*`, addresses `rand1…`, hash domains `rand-*`, p2p identity `rand-p2p-identity`, service
`rand-node`; the two root pins moved) and `a7b69d7` (the pin). **Chain 10** = genesis
`4d757f11…`, cut without the aggregation section like chain 9; `deploy/nodes.env` regenerated
(every peer id changed); rolled out with `deploy/cutover-droplet-rand.sh` C, D (the bootstraps)
first, then E, F, the twelve regional; hostnames are `rand-node-<name>`; old binaries and
retired chains' data dirs removed from every droplet. 16 droplets + A live; **B (MacBook Air)
still unreachable — it needs `bin-a00c88c/` and `.update-pin` = `a00c88c`.** The randscan
explorer got the same rename (randscan `286f399`) and was redeployed to E in the same minute.
Chain 9 (`dbb7498b…`, build `5f8c6f9`) lived for about an hour between the two.

### Pre-v0.1 security review (2026-09-16): two findings, both gated behind chain 9 — FIXED the same day

**Fixes merged to `main` (branch `security-fixes-v0.1`):** L1 `151af5b` (`Ledger::close_block`,
called by both `propose` and `apply_block_for_sync`); H1 `248a0f7` + `e03f8bd` (the fee bucket
records every bundle and is the ledger's coverable set — `CoverNotCoverable` at step 4, a
missing entry is a refusal not a zero share — and `BlockError::SecondAggregate` refuses a
second aggregate per block; spec §3.4/§4/§6.1 rewritten); M1 `32ec1b8` (`Transaction::hash`
takes the bundle proof by digest, domain `rand-txid-2`, so the marker form hashes to the
raw hash and the certified tx root binds a sealed block whole — **every transaction id
changes**, a hard fork like constraint set 6); dependencies `4a07d85` (libp2p 0.54 → 0.57,
all ten Dependabot alerts cleared). Each fix has a regression test that failed on `v0.1`.
The report's "Fixes" section records what was deliberately not done (binding the aggregate
proof to `(aggregator, nonce)` — a circuits change, defence in depth only now).


Tag `v0.1` sits on `0b98580`. A four-reviewer pass over `6f112e3..0b98580` (RPC hardening,
constraint set 6, M5 `randprotocol-rvm`, chain-side aggregation, S2/S3 follow-ups), each candidate
re-traced by an adversarial verifier. Findings:
`../security/fullnode-security-review-pre-v0.1-2026-09-16.md` (severity-ordered, "verified
OK" per crate — read it before re-reporting suspected issues). **Nothing found is reachable
on chains 5–8 (`aggregation: null`); all three items must be fixed before chain 9 is cut:**

- **H1** subsidy minting is bounded only by node policy: the replica applies every
  `Aggregate` in a block and `StoreCovered::covered` is seal-blind, so a leader holding an
  aggregator key re-signs a committed proof under fresh nonces and mints `subsidy(n)` per
  copy. Fix: one-per-block and unsealed-and-in-window as consensus rules, proof bound to
  `(aggregator, nonce)`.
- **M1** sealed-form sync binds a pruned bundle's digest fields and the state root, not its
  `envelopes` (nor a stateless `Call`); a sync peer can substitute them and the victim
  persists and re-serves them. Fix: a proof-less tx hash in the pruned record, bound by the
  aggregate interface or the tx-root leaf.
- **L1** (liveness, not security) `propose` never runs `sweep_expired_excesses`, which
  `apply_block_for_sync` runs before the root; the first expired fee bucket halts the chain.
  Fix: sweep in `propose` (factor the block-end steps into one function).

`randprotocol-zkvm` (constraint set 6) and `randprotocol-rvm` had no findings.

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
`crates/randprotocol-zkvm/` as vendored code and take a fix back to `research` first.

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
  `ZkExecutor::check_program` (`crates/randprotocol-zkvm/src/executor.rs`) rejects a
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
grew `rand_getCompactBlocks`, batch requests (cap 20, notifications refused
`-32600`) and a WebSocket `newHeads` subscription on the same port;
`docs/rpc.md`'s changelog is the client-facing list.

Same day, the key property narrowed: a node may hold **viewing keys** — never
spend keys; the RPC layer has no type for those — for explorer-side scanning
(`rand_importViewingKey` / `rand_getViewingNotes`, in memory, 64 keys, 10 000
leaves a call, cleared at restart) and answer one-call payment proofs
(`rand_checkTransaction`, stateless). An imported key can disclose notes but
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
  keeps a proof inside its window.** `crates/randprotocol-node/tests/proving_slot/`
  and `crates/randprotocol-client/tests/proving_slot/` (one module, two copies: both
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
- **Short-shielded-address feature, full release suite, 2026-09-17** (chain-11 cut, `short-address`
  branch, task 10): `RECURSION_FIXTURES=… cargo test --workspace --release -- --skip round_trips
  --skip two_test_profile` — **0 failed across every one of the ~50 test binaries**, run detached,
  **~87 min wall time**. The three long poles named in the task brief matched: **wallet flow**
  3 tests, **760.24 s** (12m40s); **cluster** 20 tests, **3467.25 s** (57m47s, the aggregation
  capstone included); **zkvm e2e** (`crates/randprotocol-zkvm/tests/e2e.rs`) 24 passed + 6 ignored,
  **412.20 s** (6m52s). Everything else in the workspace (`randprotocol-core`, `-node`, `-client`,
  `-rvm`, `-zkvm`'s ~40 other test files, `bridge-codec`, doctests) finished in seconds each. No
  code changes were needed — the branch's Tasks 1–9 were already green.
- The whitepaper is `../whitepapers/randprotocol.tex` (Draft 3) — its
  AGENTS.md has the parameter table (FRI 80/8/20, Poseidon2 width 8,
  384-bit soundness-bearing hashes) that this repo's docs should stay
  consistent with.
