# Block-level proof aggregation and the prover market

Status: **built (2026-09-15, the `aggregation-spec` branch): the chain-side spec
(`docs/superpowers/specs/2026-09-15-block-aggregation.md`) is implemented in full — the
register, the nine-step admission, the subsidy and fee split, sealing and pruning, sealed-form
sync, the RPC and CLI, and the chain-9 genesis tooling.** The measured numbers are collected
in §6; the text of §1–§4 below is the approved design as written, kept because the build
followed it almost word for word.

The original status line, for the record: *approved design as a starting point, not built*
(decided and approved 2026-09-12; the spec and plan build on §1–§4 and settle the open
questions in §5). This is the remedy chosen in `docs/block-space.md` §6 for the 80-query proof
size: a block carries one recursive proof for all of its bundles instead of one ~1.3 MB proof
per bundle. Proof pruning was rejected because it makes a syncing node trust finality
signatures for old history and so opens the long-range attack a proof-carrying chain does not
have.

## 1. Two roles, two kinds of hardware

| role | hardware | admitted by | does | paid by |
|---|---|---|---|---|
| **proposer** (HotStuff leader) | CPU | stake (`docs/staking.md`, the S2 register) | orders transactions, verifies one aggregate proof per sealed block (~0.8 s cold, ~16 ms warm) | the verification share of fees, as today |
| **aggregator** (prover) | GPU; measured: ≥ 512 GB host memory for one production proof (§ "Before enabling aggregation", item 3) | permissionless, a registered payout address | proves one recursive STARK that verifies N bundle proofs; submits it for a sealing block | the proving share of fees **plus a block subsidy in newly minted RAND** |

Validators stay CPU-cheap, so a home node can still validate. GPU capital competes in its own
market and is never a requirement for consensus. The two roles may be the same operator, but
nothing in the protocol couples them.

## 2. The pipeline

Nobody proves an aggregate inside a 2 s slot: a single bundle proof takes ~100 s today and a
recursive proof over a block is minutes of GPU. So aggregation is pipelined:

1. **Unaggregated blocks.** Senders submit bundles as today. A block at height `h` orders them
   and validators verify each bundle proof (three per block fit the 4 MiB cap). Consensus and
   finality run on these blocks unchanged.
2. **Sealing.** Aggregators watch the chain, take the bundles of a window of finalised blocks,
   and prove one aggregate. The aggregate is submitted to the network and included in a later
   block `h + k` as a *sealing* record: `Aggregate { covers: [bundle digests], proof, payout, r }`.
3. **Sealed history.** Once a block's bundles are covered by a finalised aggregate, every node
   may drop the individual bundle proofs and keep the aggregate; the ~3 KB of public fields per
   transfer stay. History remains proof-carrying end to end, which is the whole point.

The forward path (throughput above three per block) is the second step of the same design:
bundles travel sender → aggregator, the aggregator's proof enters the block, and the individual
proofs never do. That needs the aggregator to be on the critical path of inclusion, so it comes
after the sealing pipeline has run on the fleet.

## 3. Payment

### 3.1 Fees split

A bundle's fee (`docs/fees.md`) today prices one verification and goes to the proposer. With an
aggregator it prices proving too. The fee splits into a **verification share** (proposer) and a
**proving share** (the aggregator whose aggregate first covers the bundle). A sender who attaches
more than the floor is aggregated first; that is the fee-ordered mempool the block-space doc
asks for, with GPU operators doing the ordering.

Under the genesis `fees.burn_base` (`docs/fees.md` §1.3) the verification share is destroyed
instead of paid: the proposer keeps nothing at inclusion, `BUNDLE_BASE` joins `burned` and
`base_fees_burned`, and the proving share — `fee − BUNDLE_BASE`, bucketed exactly as without the
flag — reaches the covering aggregator, or the recorded proposer at the sweep, as it always has.

### 3.2 A block subsidy in new RAND

At launch fee volume is near zero and nobody runs a GPU for it. So the sealing block mints a
**subsidy** for the aggregate it includes, the way a Bitcoin coinbase pays a miner before fees
matter, on a decaying schedule (halving on a fixed block count) that hands over to fees as
volume grows. This is the chain's first issuance; today supply is genesis allocation plus
faucet mints only.

What the subsidy is **not**, and why the design differs from proof-of-work:

- **The work is useful and bounded by demand.** Hashing is wasted by design and scales with
  price; proving scales with the number of bundles waiting. There is no difficulty and nothing
  to adjust it against. So the subsidy rewards *coverage*, not *compute*: a fixed amount per
  sealed block, paid to one aggregate.
- **Per block, never per bundle.** A per-bundle subsidy would let a prover farm it by filling
  blocks with its own transfers. Per block, filling does not raise the reward; it only helps
  win the selection.
- **Most coverage wins, not first.** A first-valid race hands every block to the fastest GPU.
  Instead the sealing proposer picks, among the valid aggregates it received in the block's
  window, the one covering the most bundles; ties go to the lowest proof hash. A slower prover
  with a fuller aggregate stays competitive.
- **Security is not what the subsidy buys.** Consensus security comes from bonded stake; the
  subsidy buys throughput and bootstraps the prover set. It can be small and can decay to zero.

### 3.3 How the payment lands

The subsidy and the proving share are paid as **one deposit note** to the aggregator's shielded
payout address, exactly like a validator's Withdraw: the amount is public in that block, the
aggregate carries the note's blinding `r`, and the ledger derives the commitment itself, so an
aggregator cannot mint more than the schedule says. The note's later spend is unlinkable as any
other.

Under the genesis `fees.subsidy_net_of_fees` (`docs/fees.md` §1.3) the shares pay the schedule
first (spec §5.4's derivation, `Ledger::aggregate_payment`): the note carries
`max(subsidy(n), shares)`, and only `subsidy(n) − shares` — nothing once the shares reach the
schedule — is minted. `subsidised` and `rand_getAggregate`'s `subsidy` carry that minted part;
`sealed_blocks` advances by one either way. Admission and apply still derive one note from one
state: the rule lives in that one function.

**An aggregator must net the subsidy too.** The ledger never reads the envelope's amount: it
derives the commitment from its own `max(subsidy(n), shares)`, admits the aggregate and appends
that note whatever the envelope says. An envelope sealed at `subsidy(n) + shares` therefore opens
to a commitment matching no leaf, and the payout is lost to the wallet that holds it. The flag is
read off `rand_getLimits.fee_rules.subsidy_net_of_fees` (`null` — no rule on — a reply that
predates the section and a node with no `rand_getLimits` at all are the old sum).
`rand-node aggregate` reads it through its client's cached limits (`RpcClient::fee_rules`, the
same one `rand_getLimits` read the envelope format comes from: the section is fixed at genesis,
so one read per daemon, never one per pass that a transient RPC failure could abort — issue
#132), takes `rand_status.aggregation`'s schedule beside it, and seals at
`aggregation::minted_subsidy(subsidy(n), shares, &fees) + shares`, the ledger's own function
(pinned by `the_aggregate_pass_seals_the_ledgers_payout_under_subsidy_net_of_fees`). A third-party
aggregator must do the same.

### 3.4 Supply accounting

`docs/supply.md`'s value-balance invariant gains a term:

```
supply = genesis notes + faucet mints + Σ subsidies − burns
```

`rand_getSupply` reports issuance separately from faucet mints so an auditor can check the
schedule against the sealed-block count.

### 3.5 Who made the proof: the aggregate binding (audit v3, AGG-2)

The payout goes to the aggregator that signed the `Aggregate` transaction. The proof itself
must therefore say who made it; otherwise a registered aggregator could copy another's valid
aggregate from the pool, re-sign it under its own identity and nonce, and be paid for the work.
The rVM's aggregate program absorbs eight binding words into its interface digest:

```
interface = [inner_vk_digest(4) ‖ N ‖ B(8) ‖ 34·N public values]     -- pre-constraint-set-8
```

As of constraint set 8 (chain 18's `pv::NUM = 35`, `docs/confidential.md`'s "Constraint set 8",
built on `feat/gas-chain18`, not yet cut) the width is `35·N` — a chain built after chain 18
carries `[vk ‖ N ‖ B(8) ‖ 35·N]`, not the `34·N` this section was written against. No live chain
runs aggregation, and chain 18's genesis rejects `gas.dynamic` beside an `aggregation` section
(`docs/fees.md` §1.2), so the two have never yet had to coexist.

```
B = aggregate_binding(chain_id, aggregator, nonce)   // H("rand-aggregate-bind-1", …), 8 LE u32
```

The prover (`aggregate --watch`) reads its register nonce **before** proving and binds its
own `(chain, address, nonce)`. Admission step 8 recomputes `B` from the transaction, never
from the proof, and a copy of the proof under any other triple fails: re-signed by another
aggregator, or replayed at another nonce. `aggregate_binding` is in
`randprotocol-core/src/types/actions.rs`, and the program change is circuits `573ef2e`.
Because the program digest changed, a chain's `admitted_shapes[].aggregate_program_digest`
must be measured on a build that carries it, **and the production proof batch must use this
program**.

### 3.6 No slashing: a retry is not equivocation (INTERFACE-1)

`SlashAggregator` is refused on every aggregating chain (`AggregationError::SlashingRetired`,
permanent). The register nonce advances only when an aggregate commits, so every retry after a
lost race, a refusal or censorship re-signs the same nonce over new content — the `--watch`
daemon draws a fresh `r` and `time` each pass — and the spec's equivocation proof was exactly
two such headers, available to anyone. Exactly one aggregate can consume a nonce, so
equivocation harmed nothing; the bond is what prices spam. The action's wire variant stays (its
bincode index is part of every txid); `slashed` stays in the supply identity at 0.

## Before enabling aggregation

**Aggregation does not remove the auth proof (audit v6, AGG-7; recorded 2026-09-30).** On a
split-authorisation chain (`hc_auth` set: chains 17 and 18) a bundle carries two proofs: the
tier-14 bundle proof (~1.49 MB) and the tier-10 auth proof (~1.36 MB). The aggregate program
verifies bundle proofs only, and the pruned form replaces only `Bundle.proof`
(`Transaction::hash`'s doc comment: "The pruned form replaces only `proof`, never `auth_proof`").
So sealing a window shrinks a transfer from ~2.85 MB to ~1.36 MB, not to nothing, and a node
syncing sealed history still verifies every auth proof itself. Either the aggregate program is
extended to verify the auth proof too, so the pruned form can replace both — a program change,
with the digest re-measured and re-pinned — or storage is planned on 1.36 MB a transfer. Decide
before aggregation is switched on.

Aggregation is off on every live chain, and `rand-node` refuses to start on any genesis that
carries an `aggregation` section (`node::check_build_runs_genesis`). Two reasons hold it there;
both have to clear before a genesis may switch it on.

1. **The hidden-asset bundle's shape.** The admitted shapes and the recursion fixtures were
   measured for the retired 2-in-2-out guest; they are re-measured for the current bundle guest,
   and `admitted_shapes[].aggregate_program_digest` is taken on the build that will run.
2. **The rVM's own soundness (2026-09-27).** The recursion-VM security report's RVM-1 let a
   prover choose the high lane (column `D1`) of every extension value a STOREE writes to memory
   — no register read bound it — and the aggregate verifier stores 14 370 of them per inner
   proof (the REDUCE descriptors, the register allocator's spills). The same day's zk scan added
   the reduce chip's free per-row clock (OPCODES-1/TABLES-1), its padding rows that could write
   (V-OPCODES-1), runs that could stop before their write-back (ZKR-4), the public table's
   optional rows (OPCODES-4) and the unchecked base addresses and `r31` pairs (ZKQ-3). All are
   fixed in circuits `b786aae` and `cd4b788..971b96b` (on circuits main after the memo commit `c6cdef4`), vendored here at `971b96b`, each with a
   red-first cheating vector. The aggregate program's digest does not change with any of them
   (a pinned test says so); the rVM *verifier* does, so a proof from an unfixed prover no longer
   verifies. What has **not** been done, and has to be before a genesis enables aggregation:

   - **An end-to-end forged-aggregate exercise against the fixed verifier** — **run 2026-09-30
     (issue #45, closed; circuits `feat/issue-45` `d38d6cf`) on a 503 GB machine.** A malicious
     inner proof never reaches the prover, and a forged stored lane inside a real tier-19
     aggregate's trace is refused both ways it was built. With the RVM-1 fix reverted (scratch
     copy, never committed) the isolating vectors accept the forgery (`the forged run VERIFIED
     … publishing [12648430, 11, 11, 22]`), so they have teeth; the aggregate-scale test is
     stopped by RAM read-after-write instead, and a lane *chosen* to cancel a failing final
     check (the report's §6 path) was **not** built — issue #119.
   - The report's §11, what its review did not cover — rechecked on 2026-09-28 by the zk scan's
     "not covered" pass, which found no soundness break in any of them:
     - the generated constraint evaluation (`programs/constraints.rs`) against Plonky3 0.7.0's
       verifier folder, term by term (fold order, selectors, quotient recomposition, LogUp
       terminals, `X² = 7`): no mismatch. The Production-profile differential (all 9 instances)
       and a test that breaks a single AIR constraint on a non-first instance now exist and pass
       (#45);
     - the `rv32n` absorb schedule (`[vk ‖ N ‖ B ‖ 34·N]` at the time of this review, `35·N` since
       constraint set 8 — the same schedule, re-checked at the new width by circuits `18c2627`'s
       fix for the sponge's block-boundary bug, `docs/confidential.md`'s "Constraint set 8"), the
       length in capacity, the final
       permutation) and hostile cover sets (N = 0, a wrong N, duplicates, mixed shapes): no
       desynchronisation — read, not fuzzed. The `rv32r` self-verifier's binding is not tied to
       the inner aggregate's (ZKQ-5): decide before trees of aggregates ship;
     - the CUDA and reference backends: no verifier path differs under their features;
     - the witness tape and host-side replay: admission read every cover before checking the
       count and signature (ZKQ-1, fixed in this release);
     - timestamps: proven collision-free at every tier (`16·CLK + slot ≤ 2^27`, integral `CLK` on
       every real row once the reduce clock is carried).
   - Deferred from the zk scan (ZKQ-6): a DSL-side check that a loop body never reads a
     register before writing it.
3. **The hardware (measured 2026-09-30, #45).** A production aggregate of one bundle proof
   (tier 21) peaked at **376.9 GB** and took 8 131 s; N = 2 (tier 22, 2.4 % row headroom) is
   estimated at ~750 GB and N = 3 at over 1 TB — beyond any single CPU host, with or without the
   GPU backend (host-resident traces). An aggregator therefore needs ≥ 512 GB for N = 1, and
   N ≥ 2 needs a design change first (#119). Production N = 2 and N = 3 emulation (no proving)
   is within the memory and timestamp bounds (`2^27`), and register pressure does not grow with N.
   The full table is `docs/node-hardware.md` §4.
   **Phase 2 row cuts (circuits `75b7893`, 2026-10-04):** the production inner proof is 893 606
   cpu rows, so N = 1 lands at tier 20 (N = 2 at 21, N = 3/4 at 22) and projects to ≈ 240 GB — a
   ≥ 256 GB host, tight, and a projection until proved. On that tree
   `admitted_shapes[].aggregate_program_digest` is `c90b3f0a…74d8` and the node admits tiers
   {20, 21, 22} (`recursion/docs/04-phase2-row-cuts.md`, `docs/node-hardware.md` §4).

## 4. Fallback

A block whose bundles no aggregate ever covers stays valid: its raw bundle proofs are kept and
three per block is the rate. No subsidy is paid for it; fees go to the proposer as today. The
chain never depends on a GPU being online.

## 5. Open questions for the spec

- The subsidy amount, the halving interval, and whether issuance has a hard cap.
- The proving share: a fixed fraction of the bundle fee, or the whole fee above the floor.
- The sealing window `k`: how many blocks an aggregate may lag, and whether a bundle can be
  covered twice (it should not; the first finalised aggregate wins, later ones covering it are
  invalid).
- Submission spam: verifying an invalid aggregate costs ~0.8 s. Either aggregators register with
  a refundable bond and sign submissions, or nodes verify submissions off the consensus loop
  with a per-peer rate limit (the same machinery the RPC hardening task adds for bundles).
- The verifier guest: the STARK verifier (Poseidon2 Merkle paths, FRI folding) in RISC-V, its
  cycle count per inner 80-query proof, and the tier it lands in. This is the zkVM milestone
  the rest depends on.

## 6. Measured numbers (2026-09-15, this tree)

Every number below was measured on the implementation branch, not projected. The test-profile
rows are the cluster capstone's (`tests/cluster.rs`'s
`a_fresh_node_syncs_pruned_history_with_one_rvm_verify_per_sealed_window`); the production
rows are the activation checklist's placeholders (`docs/deploy.md`, "Chain 9 activation"),
filled at activation.

| measurement | value | source |
|---|---|---|
| bundle proof (register), test profile, tier 14 | 94.3–99.1 s across runs, 321 701–327 322 bytes (random notes vary the witness) | capstone register stage |
| aggregate prove, test profile, N=1 (tier 19) | **1568.2 s wall (~26 min) on a loaded shared box**, 327 035 bytes | capstone aggregate stage |
| startup key-build, test profile (2¹⁹) | **13.0–13.4 s** (the ops expectation at 2²¹ production: ~30–70 s) | `warm_aggregation` startup log, three nodes |
| warm aggregate verify, test profile | ~1–2 s (the first at a shape pays the 13 s key-build, once) | admission step 8 |
| seal → pruned | sealed at block 46; the pass at head 64 rewrote the record (every 16 blocks, gated at `sealed_at + window`) | capstone |
| sealed resync, a fresh joiner | **1 rVM verification per sealed window** (the covering aggregate's; a raw sync re-verifies each bundle); the 7-block sealed batch applied in under a second | capstone's verification counter |
| the capstone end to end | **1873.2 s** (register 97 s → prove 1568 s → seal → prune → resync) | `tests/cluster.rs` |
| rVM aggregate proof size, test profile | 325–327 KB measured here (the circuits M5.3 record is 328 121 bytes; production measured 2026-09-30 at **1 563 226 bytes** for N=1 under constraint set 8 — under the 2 MiB default cap, not the ~0.5–0.6 MB first estimated) | `circuits/recursion/docs/02-aggregate.md` |
| the interface conformance vectors | `inner_vk_digest` `33a94ec6…92a1c8`, the 115-word bound list (AGG-2; the stand-in binding of `circuits/recursion/docs/02-aggregate.md`), digest `9833ac5b…fdc868e` — reproduced byte-for-byte by the fullnode's recompute | the conformance suite (`agg_executor.rs`) |

### The one capstone walk-through

Register an aggregator (one bond-burning bundle, proving share 7 over the floor) → the chain
halts for the prove (the cover window cannot scroll) → one rVM aggregate over the bundle's
proof (the proving slot's single hold) → submitted, admitted (its own verification), pooled
per §3.4's selection, committed — the sealing block — the mark lands atomically with the
commit → the prune pass rewrites the record (34 public values + the 7 declared shape bytes,
~3.3 KB against ~1.3 MB raw) → a fresh node joins and syncs the pruned block in sealed form,
reaching the same blocks and state roots at every height with exactly one rVM verification —
and the supply audit holds end to end (`total_supply == issued − slashed`, with one subsidy
minted against `sealed_blocks == 1`).

### What the capstone exposed: the sealed-sync stall

The capstone passed alone, twice (1873.2 s, 1876.4 s), and stalled inside the full cluster
suite three times — the fresh joiner stuck part-way with nothing outstanding and nothing
counted as failed. The mechanism, once the warn-level keeper diagnostics named it, was two
give-ups compounding:

- **A batch cut between a pruned block and its cover is unservable, deterministically.** The
  sync client's batch count halves on wire failures (under suite load, toward 1) and the
  server's byte budget cuts where it cuts; either can end a batch after a sealed block (the
  window at 33) but before its covering aggregate (block 46). The joiner's coverage check
  refuses the batch — correctly, it is batch-atomic — and the raw-form fallback asked
  *another peer*, which pruned the same record and served the same split form. A give-up
  that can never succeed, retried forever.
- **The sync peer picker had no fallback.** When the fresh peer's connection flapped or its
  status had not landed, the picker returned nothing and the sync stopped silently until
  gossip happened to re-trigger it; a send that failed was not even counted.

The fixes, each with its node-lib regression test:

- **Coverage-closed serving** (`node.rs`'s `close_batch_coverage`): before a `Blocks`
  response goes out, every served pruned entry's seal mark is resolved and the batch extends
  — past the count asked, past the soft byte budget — until every cover it needs is in. The
  extension's only ceiling is the reader's own wire limit; a chain whose cover sits beyond
  that is the genuine archive case the raw-form fallback exists for. Pinned by
  `a_batch_cut_short_of_its_cover_extends_until_the_coverage_closes` (the count cut),
  `a_batch_cut_by_bytes_short_of_its_cover_extends_within_the_reader_limit` (the byte cut),
  and `the_extension_stops_at_the_reader_limit_and_serves_what_it_can` (the ceiling).
- **The robust picker** (`node.rs`'s `pick_sync_peer`): the freshest connected peer ahead
  wins, but when the chain is known ahead and no connected-and-fresh pair exists, any
  connected peer is worth one round trip — a possibly-stale answer costs a little, a silent
  stall costs the chain. A send that cannot go out warns, counts, and tries the next
  candidate. Pinned by `pick_sync_peer_prefers_fresh_and_falls_back_to_any_connected`.

### What pruning shrinks, and how much work a pass does (INTERFACE-9, issue #51)

A committed transaction is stored twice: inside its block's `CF_BLOCKS` row, and as its own
`CF_TXS` record. Until issue #51 the pruning pass rewrote only the record, so the block row kept
the raw ~1.3 MB proof and the disk §6.2 promises back never came back; and the pass found its
work by walking every seal mark the store had ever written, every 16 blocks, for ever. Both are
fixed node-side (no consensus, wire or genesis change; dormant while no chain carries an
`aggregation` section):

- **The block row shrinks with the record, in the same synced batch** (`Storage::stage_pruned`):
  the transaction at the record's index becomes the record's marker form. That is exactly the
  row a block synced in sealed form has always been stored as (`commit` stores a block "as
  served"), so no reader meets anything new, and both copies now hold one form:
  - *Serving* never used the raw row for a pruned bundle — `sealed_form_of` serves the record's
    marker form and side entry whichever row it finds — so a `Blocks` response is byte for byte
    what it was, and coverage-closed serving (`close_batch_coverage`, above) reads only the
    seal marks. What the raw row could have offered, a raw proof to a syncer whose fallback
    wants one, this node never served; that fallback was and is an archive's job
    (`--keep-raw-proofs`, which never runs the pass).
  - *The startup replay* meets the marker and applies the block through the pruned branch
    with the side table rebuilt from the records (INTERFACE-3, the sealed-synced path): each
    bundle's public fields are bound to its record's `OUT` and `H_PUB` words, and the covering
    aggregate's block, replayed after it, verifies the rVM proof over those same records. That
    is the soundness a sealed-synced node already rests on, and the one §6.2 prunes for: once a
    window has passed its seal, the aggregate — not the bundle's own STARK — is the proof.
  - *The block hash cannot move*: the marker form hashes to the raw hash (the proof enters the
    id by digest, `rand-txid-2`), and the write refuses unless the slot's hash, the record's
    hash and the block's tx root all still agree.
  - Visible changes: `rand_getBlockByHeight`/`ByHash` report a pruned bundle's `proof_len` as the
    marker's 44 bytes, as `rand_getTransaction` already did off the record; a by-hash block fetch
    of such a block returns the marker form, as a sealed-synced node's always has — by-hash
    fetches serve pending and recently committed blocks, never history a window past its seal.
- **A height index for the pass**: `CF_SEALS` rows `h ‖ sealed_at (BE) ‖ bundle`, written with
  every seal mark. The pass walks them from the lowest `sealed_at`, stops at the first still in
  its window, deletes each row it handles, and handles at most `PRUNE_SEALED_PASS_MAX` (64) a
  pass — steady state is 16 × `max_covers`, so the cap only paces a backlog. Its work is what came
  due since the last pass, never the sealed history. History pruning and truncation drop a
  mark's index row with the mark.
- **Upgrade**: a store sealed by an older build is indexed once at open (`seal_heights_built`);
  the next passes then also shrink the block rows an older pass left raw behind already-pruned
  records. An older build ignores `h` rows and replays marker rows (INTERFACE-3), so a rollback
  needs nothing.

Pinned by `the_sealed_pruning_pass_visits_only_the_marks_whose_window_passed_once`,
`the_sealed_pruning_pass_drains_a_backlog_a_bounded_step_at_a_time`,
`a_store_sealed_before_the_height_index_gets_it_at_open`,
`history_pruning_and_truncation_drop_the_height_index_rows`,
`a_pruned_bundle_shrinks_its_block_row_too_and_the_startup_replay_still_verifies`,
`a_block_row_left_raw_behind_a_pruned_record_shrinks_on_the_next_pass` (`storage.rs`) and
`a_block_row_this_node_pruned_serves_coverage_closed_like_a_sealed_synced_one` (`node.rs`) — all
stub-proved, so they run without a recursion fixture.

### The fleet bundle's declared shape

The admitted shape chain 9 registers is the fleet's own measured classes for a 2-in/2-out
bundle — `{tier, program 12, input 10, keccak 0, sha256 0, public 2, mem 16}` — and NOT the
recursion fixtures' shape (13/12/18): the same `guests::bundle()` underlies both, but the
chain executor pins the tight declared classes (`ZkExecutor::bundle_heights`) while the
fixtures' auto-derived ones land a rung or two looser, and a declared height is part of the
shape. The cluster capstone pins this distinction by asserting the committed bundle's header
equals the admitted shape; a genesis cut with the fixtures' classes would admit a shape no
fleet bundle can ever match.

**Re-measure before activating (2026-09-19).** That shape's `public 2` is the empty public
segment's height. Since the transaction binding (`docs/confidential.md`, "Transaction binding")
every bundle proof carries eight binding words and declares `public 4`, so no bundle proved after
that fork matches the chain-9 shape. Aggregation is inactive on every chain and chain 14 is cut
without it; re-measure the admitted shape (and the recursion fixtures) before any chain is cut
with an `aggregation` section.

**Enforced at genesis (2026-09-28, IFACE-9).** `Genesis::validate` now refuses an admitted shape
that is not the bundle header every accepted bundle carries — tier 14, no keccak or sha256 table,
public height 4 (`BUNDLE_PROOF_TIER`, `BUNDLE_PUBLIC_LOG_HEIGHT` in core, pinned to the zkVM's
own numbers by an `agg_executor` test) — and `rand-node genesis` refuses one the rVM cannot build
an inner verifier key for (`InnerShape::try_of`, via `agg_executor::check_admitted_shape`).
`deploy/cut-chain9-genesis.sh`'s default public height is 4 accordingly; the program, input and
mem heights are still the re-measurement above.

Related: `docs/block-space.md` (the numbers and the three remedies), `docs/fees.md`,
`docs/supply.md`, `docs/staking.md`, `docs/zkvm.md`.
