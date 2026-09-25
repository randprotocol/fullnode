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
| **aggregator** (prover) | GPU | permissionless, a registered payout address | proves one recursive STARK that verifies N bundle proofs; submits it for a sealing block | the proving share of fees **plus a block subsidy in newly minted RAND** |

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
interface = [inner_vk_digest(4) ‖ N ‖ B(8) ‖ 34·N public values]
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
| rVM aggregate proof size, test profile | 325–327 KB measured here (the circuits M5.3 record is 328 121 bytes; production est. ~0.5–0.6 MB, far under the 2 MiB cap) | `circuits/recursion/docs/02-aggregate.md` |
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

Related: `docs/block-space.md` (the numbers and the three remedies), `docs/fees.md`,
`docs/supply.md`, `docs/staking.md`, `docs/zkvm.md`.
