# Compute optimization: infrastructure, architecture and economics for high throughput

Status: **proposal, 2026-10-03.** Nothing below is implemented unless a row says *measured*
or cites a shipped release. The baseline numbers come from `docs/node-hardware.md`,
`docs/block-space.md`, `docs/aggregation.md` §6 and `docs/fees.md`; the token figures come from
`tokenomics/rand_tokenomics.tex` (Draft 2, 2026-09-29). Where this page proposes a parameter the
tokenomics draft also sets, the two agree; where it proposes a new one, §7 says so.

This page answers two questions for the four roles the chain has — **full nodes** (validators
and observers), **aggregators**, **delegated provers** and the **wallets** that submit work:

1. What has to change in the node, the aggregator and the proof system for the chain to carry
   on the order of a thousand shielded transactions a second, and in what order (§2–§5).
2. How the fee, the subsidy, the bonds and the pre-launch RAND rounds pay for the hardware that
   throughput needs, so that the operators exist before the fees do (§6–§8).

The one-line summary: **the validator's cost per transaction is already near zero, and the
chain is bounded by bytes per block and by the aggregator's recursion cost.** Everything below
moves proofs out of the block, makes recursion cheap enough to buy on the open market, and
prices block space and proving as two separate goods.

## 1. Where the chain is today

### 1.1 Measured baseline (chain 18, v0.6.7)

| quantity | value | source |
|---|---|---|
| block time | ~1.2 s (89 512 blocks in 29.28 h on chains 15–16) | `rand_supply_schedule.py` |
| transfer on the wire | ~2.85 MB: tier-14 bundle proof ~1.49 MB + tier-10 auth proof ~1.36 MB + four 1 860-byte envelopes | `docs/aggregation.md` "Before enabling aggregation"; `docs/node-hardware.md` |
| block caps | 20 MiB per block, 4 MiB per proof, 2 000 transactions | `docs/node-hardware.md` §0 |
| **transfers per block** | **7** (20 MiB / 2.85 MB); 3 on the 4 MiB chains | derived |
| **throughput** | **~6 tx/s** | derived |
| bundle verify, validator | 838 ms cold, ~16 ms warm; auth proof similar | `docs/node-hardware.md` §2.1 |
| validator work per block | 14 warm verifications ≈ 0.25 s of one core | derived |
| validator RAM | ~650 MiB resident | `docs/node-hardware.md` §2.1 |
| mempool admission | 4 blocking verification workers, queue 64 deep | `docs/architecture.md` §8 |
| wallet proof, tier 14 | 107.5 s on 1 thread, 13.9 s on 16 (M4 Max); 5.74 GB | `docs/node-hardware.md` §6 |
| recursion, N = 1, production | **376.9 GB host memory, 8 131 s**; N = 2 ≈ 750 GB (estimate) | `docs/aggregation.md` item 3 |
| aggregate proof | 1 563 226 bytes (N = 1, constraint set 8) | `docs/aggregation.md` §6 |
| aggregate verify, warm, test profile | ~1–2 s | `docs/aggregation.md` §6 |
| state root | nullifier root recomputed `O(n)` per block | `docs/architecture.md` §5 |
| speculative state | one full ledger clone per block in the 512-block tree | `docs/architecture.md` §6 |

### 1.2 What bounds throughput, in order

1. **Bytes, not compute.** A validator verifies a transaction in 16 ms but stores and gossips
   2.85 MB of it. The block cap is what limits the chain to seven transfers, and the cap cannot
   simply rise: at 100 transfers a block every validator would ingest 285 MB every 1.2 s.
2. **Recursion is not yet buyable.** Aggregation (`docs/aggregation.md`) is the designed remedy:
   the block carries one recursive proof over N bundles and ~3 KB of public fields per transfer.
   But one production aggregate of a *single* bundle needs 377 GB of host memory and 2¼ hours,
   and N = 2 does not fit on any single host. No market forms around that machine.
3. **Then the node's own hot path.** None of these binds at 7 tx/s; all of them bind before
   1 000: the `O(n)` nullifier root, the per-block ledger clone, one Dilithium2 vote (2 420 bytes)
   per validator per block, the leader pushing a whole block body to every peer, and the four
   admission workers.
4. **Then GPU supply.** Once recursion is cheap, every covered transaction still costs some GPU
   time somewhere. The chain's throughput becomes the aggregator market's capacity, and §6 is
   about making that capacity elastic.

## 2. Target architecture

### 2.1 Two lanes

Every transaction enters one of two lanes; the sender picks by fee (§6.2), the protocol
guarantees neither lane can starve the other.

```
                     RAW LANE (exists today)                 AGGREGATED LANE (the forward path)
                     ──────────────────────                  ──────────────────────────────────
  wallet ──bundle+proofs──▶ any node ──gossip──▶ leader      wallet ──bundle+proofs──▶ aggregator ingress
                                                 │                                        │
                                                 │           verify each proof (CPU, 16 ms); dedupe
                                                 │           nullifiers; batch B bundles → leaf proof;
                                                 │           2-to-1 tree → one aggregate (GPU)
                                                 │                                        │
                                                 │           Aggregate{covers[], proof, payout, r, B}
                                                 │                      ──gossip──▶ every validator
                                                 ▼                                        ▼
                                   ┌──────────────────────────────────────────────────────────┐
                                   │ LEADER builds a COMPACT BLOCK:                            │
                                   │   raw txs (≤ raw byte budget) + aggregate digests         │
                                   │   + the covered records (public fields + envelopes only)  │
                                   └──────────────────────────────────────────────────────────┘
                                                              ▼
                                   VALIDATORS: pull any body they lack by digest; verify ≤ k aggregate
                                   proofs (off the consensus loop, cached by digest); apply records;
                                   vote. Chained HotStuff unchanged.
```

- **The raw lane** is today's path. It stays forever (`docs/aggregation.md` §4: the chain never
  depends on a GPU being online) but is priced by the bytes it occupies, so under load it is the
  expensive lane and carries the latency-sensitive minority.
- **The aggregated lane** is the forward path `docs/aggregation.md` §2 defers. A bundle's proofs
  travel to an aggregator and never enter a block; the block carries the aggregate proof and the
  bundle's **record**: anchor, nullifiers, commitments, fee, burn, asset, time, the public
  values, and the envelopes the recipient needs to scan (~11 KB per transfer today, ~7 KB after
  §4.3).

### 2.2 Roles and what each one computes

| role | computes per block at 1 000 tx/s | hardware class | admitted by | paid by |
|---|---|---|---|---|
| **validator** | verify ≤ k aggregate proofs (target ≤ 150 ms each, off-loop, 4–8 workers); verify ≤ 100 Dilithium2 votes (~15 ms, batched); append ~4 800 commitments and ~4 800 nullifiers to incremental accumulators; one fsynced batch | 8 vCPU, 16 GB, NVMe, 1 Gbit/s | stake, `MIN_STAKE` (§7) | verification share of fees + validator issuance |
| **observer / RPC / archive** | the same verification; serves wallets scanning envelopes and witnesses; archives keep every envelope | as a validator, plus disk: ~600 GB/day of envelopes at 1 000 tx/s before slimming, ~380 GB/day after | none | none from the protocol; delegation programme criteria (§6.5) |
| **aggregator** | ingest bundles, verify every inner proof on CPU, prove leaf and tree steps on GPU, submit aggregates | ≥ 1× 80 GB-class GPU or 2× 24 GB consumer GPUs, 256 GB host, 32 cores, 1 Gbit/s | bond, quota per bond unit (§6.3) | proving share of fees + sealing subsidy |
| **delegated prover** | one tier-14 bundle proof for one sender (`docs/prover.md`); ~14 s on 16 cores, ~1–2 s target on a GPU | 8 GB+ CPU host, or a GPU | optional registry bond (§6.4) | the sender, privately; bootstrap grant |
| **wallet** | its own bundle and auth proofs, or seals a witness to a prover | laptop, phone + prover | — | pays the fee |

A validator stays CPU-only and cheap. That is the premise of `docs/aggregation.md` §1 and this
page keeps it: nothing in the validator's path grows with the program a sender ran, and nothing
requires a GPU.

### 2.3 Throughput ceilings by phase

Ceilings are what the caps admit; the sustained target is what the aggregator market is sized
for in §6.6.

| phase | per-transfer block bytes | block cap | `MAX_BLOCK_TXS` | aggregates per block | ceiling (1.2 s blocks) | sustained target |
|---|---|---|---|---|---|---|
| 0 — today | 2.85 MB (both proofs) | 20 MiB | 2 000 | 0 | ~6 tx/s | — |
| 1 — node hot path (§3) | 2.85 MB | 20 MiB | 2 000 | 0 | ~6 tx/s | — (no throughput change; prerequisite) |
| 2 — recursion redesign (§4) | 2.85 MB raw, sealing only | 20 MiB | 2 000 | 1 (sealing) | ~6 tx/s raw; history shrinks | — |
| 3 — forward path (§5) | ~11 KB, ~7 KB after envelope slimming | 40 MiB | 4 096 | ≤ 4 | ~3 200 records a block before slimming (~2 700 tx/s); 4 096 after → **~3 400 tx/s** | **1 000 tx/s** |
| 4 — propagation and caps (§5.4) | ~7 KB | 128 MiB, erasure-coded | 16 384 | ≤ 8 | ~13 000 tx/s | **5 000 tx/s** |

Bandwidth check: 5 000 tx/s × 7 KB = 35 MB/s ≈ 280 Mbit/s inbound per validator. That is why
phase 4 needs erasure-coded propagation and a 1 Gbit/s floor in the hardware spec; a leader
cannot push 128 MiB to 100 peers in a 1.2 s slot by itself.

## 3. Phase 1 — the validator hot path

None of these raises throughput on its own. All of them are required before a 4 096-transaction
block can be applied inside a slot, and all are testable now with the `StubExecutor` at
synthetic load. Each is a consensus-visible change only where marked; those ride the next
genesis-gated cut like `rand-state-5` did.

### 3.1 Incremental nullifier accumulator (state root; genesis-gated)

Today `nullifier_root` is a BLAKE3 Merkle root over the sorted nullifier set, recomputed every
block: `O(n)`, and `docs/architecture.md` §5 already flags 10⁶ entries as the limit. At 1 000 tx/s
the set grows by 4 000 a second and passes 10⁶ in four minutes.

Replace it with an **append-only Merkle Mountain Range in insertion order**: `O(log n)` per
insert, a root that commits to every nullifier ever published, and no sort. Membership (the
double-spend check) stays in the `BTreeSet` and RocksDB as now; the accumulator is only the
state-root commitment. The domain becomes `rand-state-6` with the MMR root in the nullifier
root's slot. The same construction serves `validators_root` and `programs_root` if they ever
grow, but they do not at this scale.

### 3.2 Copy-on-write speculative state

Every entry in the 512-block speculative tree clones the whole ledger. Replace the clone with an
**overlay per block**: a delta of the commitments, nullifiers, register rows and program rows
the block touched, resolved against the committed base on read. Memory per speculative block
becomes `O(block)`, and committing is applying a chain of deltas. No consensus change.

### 3.3 Verification off the loop, cached by digest

The admission workers already verify proofs on `spawn_blocking` threads and the proposal path
re-checks against a verified set. Generalise it: every proof the node will ever verify — bundle,
auth, call, aggregate — goes through one `VerifyCache` keyed by proof digest, filled by a worker
pool sized to the cores (default `cores − 2`, minimum 4), and the consensus loop only ever
looks up. A proposal whose aggregates are all cached applies in the time it takes to append
records. A proposal carrying an uncached aggregate waits on the worker, which is the ≤ 150 ms
budget of §4.4; if the budget is missed the view times out as it does for any slow proposal.

### 3.4 Compact blocks

Aggregators gossip their aggregate and its covered records before any leader includes them, so
by the time a block names them most validators hold the bodies. The block body on the wire
becomes **header + raw transactions + aggregate digests**; a validator that lacks a body pulls
it by digest from the leader or any peer (the same request-response channel block sync uses).
The leader's outbound cost per block falls from the block size to the header plus the raw
lane, and the gossip of a 1.5 MB aggregate happens once, not once per block that could carry
it. Wire change, no consensus change: the block hash still covers the full body.

### 3.5 Batched certificate verification

A QC at 100 validators is 100 Dilithium2 signatures, 242 KB, and ~15 ms to verify one at a time.
Verify them on the worker pool in parallel, and verify each validator's signature once per view
even when the same vote arrives on several paths. Dilithium2 has no aggregate signature, so the
certificate's size is a storage cost the chain accepts: ~17 GB a day at 1.2 s blocks and 100
validators (3.6 GB a day was measured at 18), pruned with history on validators
(`--prune-history`), kept on archives.

### 3.6 Acceptance

A one-validator local chain with the `StubExecutor`, 4 096 synthetic records a block for
10 000 blocks: block apply ≤ 300 ms at the 10 000th block, resident memory flat, nullifier set at
40 M entries. Measured and recorded in `docs/node-hardware.md` before phase 3 is cut.

## 4. Phase 2 — making recursion buyable

This is the critical path. Phase 3 is impossible without it, and §6's market cannot form around
a 377 GB machine. Three changes, each independently measurable, in the recursion crate
(`circuits/recursion`, vendored as `randprotocol-rvm`).

### 4.1 Precompile chips in the recursion VM

The inner verifier's work is Poseidon2 Merkle paths and FRI folding
(`docs/aggregation.md` §5). Today the rVM runs them as ordinary instructions, which is why one
inner proof is a tier-21 trace. Add two dedicated chips with their own AIRs, connected to the
CPU table by LogUp lookups as the existing reduce chip is:

- **Poseidon2 chip**: one permutation per row (today: hundreds of CPU rows). Verifying one
  80-query tier-14 proof is on the order of 10⁴ permutations; this chip puts that at 10⁴ rows.
- **FRI fold chip**: one fold step per row over the degree-k extension, with the
  challenge-derivation sponge on the Poseidon2 chip.

Target: one inner bundle proof verified in **≤ 2²⁰ total rows** across all tables (today:
tier 21 for the CPU table alone), so an aggregate of N = 16 lands around 2²⁴ rows — the size of
one ordinary GPU-proved shard in comparable systems.

### 4.2 Tree aggregation, bounded steps

Replace the single flat aggregate over N proofs with a tree:

```
 bundle proofs (B = 16 per leaf) ──▶ leaf aggregate ──┐
 bundle proofs (B = 16 per leaf) ──▶ leaf aggregate ──┼──▶ 2-to-1 ──┐
 ...                                                   ┘            ├──▶ 2-to-1 ──▶ root = Aggregate
 bundle proofs                   ──▶ leaf aggregate ──┬──▶ 2-to-1 ──┘
 bundle proofs                   ──▶ leaf aggregate ──┘
```

Every step verifies either 16 bundle proofs or 2 aggregate proofs, so **memory per step is a
constant** the hardware spec can name, and steps run in parallel across GPUs and across
operators. The root's interface is unchanged from `docs/aggregation.md` §3.5 — `[vk ‖ N ‖ B(8)
‖ 35·N public values]` with the aggregator's binding — so admission, selection, sealing and
pruning on the node side do not change; only `N` grows. The `rv32r` self-verifier's binding to
the inner aggregate (ZKQ-5, still open) is the one soundness item this design makes mandatory
rather than optional: a tree is exactly "trees of aggregates".

### 4.3 The auth proof is covered too

`docs/aggregation.md` records (AGG-7) that the aggregate program verifies bundle proofs only, so
a sealed transfer still carries its 1.36 MB auth proof. The forward path needs both proofs out
of the block, so the leaf step verifies the pair `(bundle proof, auth proof)` for each covered
transaction and the record replaces both. B = 16 bundles is then 32 inner verifications per
leaf, which is the number the §4.4 targets are set against.

### 4.4 Targets to measure before phase 3 is cut

| measurement | today | target | why this number |
|---|---|---|---|
| leaf step, B = 16 (32 inner proofs), one 80 GB GPU | not possible (377 GB for N = 1 on CPU) | ≤ 64 GB host, ≤ 60 s | fits one commodity GPU host; 16 bundles a minute a GPU |
| 2-to-1 step | — | ≤ 64 GB host, ≤ 30 s | same host; tree depth 4 adds ≤ 2 min |
| **GPU-seconds per covered transaction, amortised** | ~8 000 s CPU | **≤ 0.5 GPU-s** | §6.6 sizes the market on it |
| aggregate verify, warm, production | ~1–2 s (test profile) | ≤ 150 ms | ≤ 4 aggregates inside a 1.2 s slot with margin |
| aggregate proof size | 1.56 MB | ≤ 1.5 MB | 8 per block within 128 MiB leaves room for records |
| inner profile | 80 queries, rate ½ | decided by measurement (below) | — |

**The inner profile is a measured decision, not a given.** Fewer FRI queries make every Merkle
path in the recursion cheaper: a rate-¼ profile with 20 bits of grinding reaches the same
conjectured security near 40 queries, halving the recursion's hashing. The wallet pays for it in
a larger low-degree extension, roughly doubling its own Merkle hashing (80 % of a 14 s proof).
The right trade depends on how far §4.1 gets on its own; both profiles are measured and the
cheaper total (wallet + aggregator per transaction) is pinned at the phase-3 genesis.

**Post-quantum stays non-negotiable.** A Groth16 or Plonk wrapper (`docs/block-space.md` §6,
option 3) would make the per-block proof tiny and is ruled out: it is not post-quantum, and the
whole chain is. The root aggregate stays a hash-based STARK.

## 5. Phase 3 — the forward path

### 5.1 Aggregator ingress

An aggregator runs the bundle mempool the validators run today, with the same cheap-first
admission order (`docs/architecture.md` §8), the same nullifier and commitment conflict checks,
and CPU verification of every inner proof — 16 ms warm, so a 32-core host admits ~2 000 bundles a
second, more than any one operator will prove. A wallet submits with `rand_sendTransaction` to an
aggregator's RPC, or to any node, which forwards to the `rand-bundles` gossip topic that
aggregators subscribe to and validators do not. The wallet learns which lane it is in from
`rand_getLimits` (§6.2) and the receipt names the covering aggregate.

Aggregators may **share a bundle pool** across operators: the first aggregate to cover a bundle
is paid for it (`docs/aggregation.md` §5, the double-coverage rule), so two aggregators racing
on the same bundles waste one's work. The simple remedy is the one the subsidy rule already
uses: pick bundles by fee, and let the market size itself.

### 5.2 Block assembly and selection

A block carries up to `k` aggregates (4 in phase 3, 8 in phase 4) plus the raw lane within its
byte budget. The leader selects aggregates by **covered-fee total**, not by count, so an
aggregate full of floor-fee bundles does not crowd out one carrying tips; ties go to the lowest
proof hash, as today. The sealing subsidy (§6.3) splits pro rata by cover among the block's
aggregates, which is the one change to `docs/aggregation.md` §3.2's "most coverage wins": with
several aggregates a block there is no single winner.

A bundle appears in exactly one aggregate or in the raw lane, never both: the ledger's nullifier
set refuses the second, exactly as it refuses a double spend.

### 5.3 Envelope slimming (consensus change, privacy-reviewed)

Four 1 860-byte envelopes are ~70 % of a covered transfer's block bytes. Two of a hidden-asset
bundle's four outputs — slots 2–3, the RAND change — are the sender's own by construction. Sapling
solved the same cost with the outgoing viewing key: the sender encrypts its own change under a
key derived from `ovk`, with no KEM ciphertext. A **self-envelope** is ~120 bytes without a memo.
Every bundle carries exactly two full envelopes and two self-envelopes, so the shape is uniform
and reveals nothing an observer did not already know (slots 2–3 are always RAND change,
`docs/shielded.md`). A covered transfer drops from ~11 KB to ~7 KB; the raw lane benefits
equally. Requires the shielded-pool spec amendment, a bundle guest revision (`hc_bundle` moves),
and a wallet release; genesis-gated.

### 5.4 Phase 4: propagation and caps

With phase 3 measured on the fleet, the caps can follow the hardware:

- **Erasure-coded block propagation.** Reed–Solomon shards of the compact block body over the
  validator set (the Turbine/Rotor pattern), so a 128 MiB body reaches every validator at a
  fan-out the leader's uplink can carry. The hardware spec moves to a 1 Gbit/s floor and the
  deploy guide records the measured intake.
- **Delayed verification as a safety valve.** If aggregate verification ever exceeds the slot,
  the chain can adopt the rule that a block at `h` carries the state root of `h − 1`, giving
  verification a full extra slot without changing HotStuff. It is listed so the option is known;
  the ≤ 150 ms target in §4.4 is there so it is not needed.
- **Caps:** 128 MiB, 16 384 transactions, 8 aggregates. A genesis constant, as today.

### 5.5 Storage at scale, and the archive role

Privacy has a storage bill that transparent chains do not pay: every output's envelope must be
stored until its recipient has scanned it, and nobody knows who that is.

| rate | envelopes + records a day | validator at `--prune-history 6h` | archive a year |
|---|---|---|---|
| 1 000 tx/s, 7 KB | ~600 GB | ~150 GB | ~220 TB |
| 5 000 tx/s, 7 KB | ~3 TB | ~750 GB | ~1.1 PB |

So at scale validators prune aggressively and **archive nodes become a distinct, necessary role**:
wallets that were offline longer than the validators' window scan from an archive, and a fresh
node syncs sealed history from one (one rVM verification per sealed window, `docs/aggregation.md`
§6, so the sync is cheap even if the download is not). §6.5 pays for them. Commitments and
nullifiers themselves are small — ~250 KB/s at 1 000 tx/s, ~8 TB a year — and the frontier keeps
consensus state at `O(depth)` regardless.

## 6. Economics

### 6.1 Principles

1. **Two goods, two prices.** Block bytes are scarce for every validator; proving is scarce for
   aggregators. A fee that prices only one of them mis-sizes the other, which is how the chain
   got to three transfers a block (`docs/block-space.md` §4).
2. **Operators before fees.** At launch fee income is near zero (`rand_tokenomics.tex` §Issuance).
   Issuance pays validators, the sealing subsidy pays aggregators, and the pre-launch rounds put
   RAND and hardware in operators' hands before genesis. Every bootstrap payment decays or is
   gated on fee income.
3. **Bonds buy capacity, not permission.** An aggregator's bond is not a licence and is not
   slashed for losing a race (`docs/aggregation.md` §3.6); it meters how much of the validators'
   verification time one identity may claim. Sybil resistance comes from the quota, not a jury.
4. **Governance can only lower issuance.** Inherited from the tokenomics draft §Governance.

### 6.2 Fees: a two-lane market

`docs/fees.md` §1.1 already prices a call by `gas_price · gas_max + byte_price · ⌈bytes/1024⌉`
with chain 18's `gas.dynamic` adjusting both prices by up to `adjust_bps` a block. This page
extends that to every bundle and to two lanes:

```
fee_floor(raw)        = BUNDLE_BASE + byte_price_raw · ⌈bytes_on_chain / 1024⌉   -- ~2.85 MB today
fee_floor(aggregated) = BUNDLE_BASE + byte_price_agg · ⌈record_bytes / 1024⌉      -- ~7–11 KB
                        + prove_base
```

- **`byte_price_raw` and `byte_price_agg`** each adjust toward their own target fullness, raw
  lane at 25 % of the block and aggregated lane at 75 %, with the chain-18 rule (`±adjust_bps`
  a block, 12.5 % default). Under no load both sit at their genesis minimums and a covered
  transfer pays 0.0016 RAND (today's 0.001 plus `prove_base`); under load the raw lane prices itself
  at hundreds of times the aggregated lane because it occupies hundreds of times the bytes.
- **`prove_base`** is the aggregated lane's floor for the proving share, 0.0006 RAND at genesis,
  paid to the covering aggregator. It exists so an aggregator can model revenue without a tip
  market, and so the market clears at the GPU cost §6.6 derives.
- **The split.** Of every covered bundle's fee: `BUNDLE_BASE × 40 %` to the proposer
  (verification share), `BUNDLE_BASE × 60 % + prove_base + tip` to the covering aggregator
  (proving share). Of every raw bundle's fee: everything to the proposer, as today. The 40/60
  split of the base is this page's proposal (§7); `docs/aggregation.md` §3.1 names the two
  shares without fixing them.
- **No burn at launch**, per the tokenomics draft; governance may route part of the proposer's
  share to burn once annual fees exceed annual issuance.

A wallet asks `rand_estimateFee` for both lanes and shows the user two prices and two expected
latencies: raw, next block; aggregated, a few blocks (the tree depth of §4.2 at the measured
step times, which the aggregator advertises in its `rand_getLimits.aggregation`).

### 6.3 Aggregators: bond, quota, subsidy, share

| parameter | value | note |
|---|---|---|
| `aggregator_bond` | **25 000 RAND** per quota unit (≈ $3 750 at the public floor) | the cut-script default is 1 000 (`cut-chain9-genesis.sh`); raised so a quota unit costs a meaningful fraction of a GPU |
| quota | **1 aggregate submission per block per bond unit**, max 4 units per key | caps the verification time one key can claim from the validators at 4 × 150 ms a block; more capacity means more keys and more bond |
| bond return | unbond, 2 epochs, as a validator's | refundable; never slashed for a lost race or a retry |
| invalid submission | refused at admission, counted; a key over 8 refusals an epoch loses its quota for the epoch | the "submission spam" question of `docs/aggregation.md` §5, answered by quota not slashing |
| `subsidy_base` | **0.6 RAND per sealed block**, halving every 52 560 000 sealed blocks, 64 halvings, cap 63.1 M | the tokenomics draft's mainnet parameters, unchanged |
| subsidy split | pro rata by covered bundles among the block's aggregates | §5.2 |
| self-fill invariant | `subsidy_base / MAX_BLOCK_TXS < BUNDLE_BASE × 40 %` | 0.6 / 4 096 = 0.000146 < 0.0004 RAND: filling a block with one's own transfers to win more subsidy costs more in verification share than it earns; checked by `Genesis::validate` |
| proving share | `BUNDLE_BASE × 60 % + prove_base + tip` per covered bundle | §6.2 |

Why 20–40 operators is still the right number to plan for: §6.6 shows 1 000 tx/s needs about
500 GPU-equivalents at the §4.4 target. Forty operators with 12–16 cards each is a market, not a
cartel, and the quota (4 units, 100 000 RAND) is sized so that one operator cannot buy the whole
block's aggregate slots.

### 6.4 Delegated provers: registry, not bond

A prover is paid privately by its sender (`docs/prover.md` §3.5) and never touches consensus, so
the protocol has no reason to bond it. What wallets need is **discovery and reputation**:

- An optional on-chain **prover registry**: `RegisterProver { endpoint_hash, kem_fingerprint,
  payout }` with a 5 000 RAND bond that is only ever returned, listed by `rand_getProvers`. A
  wallet that pairs with a registered prover can check the KEM key against the chain, not only
  against the operator's web page.
- **A fee rebate from the aggregated lane**: a bundle proved by a registered prover may carry the
  prover's registry id in its binding words; the covering aggregator's proving share then pays
  10 % to that prover. It aligns provers with the aggregated lane, costs the aggregator a tenth
  of a share it would not have without the prover's work, and is the one protocol payment a
  prover ever receives. It is optional for the sender and reveals nothing beyond which prover
  was used, which the prover already knows.
- Bootstrap grant: §6.5.

### 6.5 The pre-launch rounds, mapped to the three operator roles

The tokenomics draft sells 30 % of a 10⁹ supply across five rounds for about $26.1 M and reserves
43 % for community programmes. This page does not move those buckets; it says which of them pay
for which hardware, and attaches the conditions.

| source (tokenomics draft) | RAND | who | what it funds | condition |
|---|---|---|---|---|
| **Validator and prover sale**, $0.12, at T₀ + 12 mo | 40 M | operators who completed a Tour de RAND stage; ≤ 2 M per buyer | validator stake: the 100 000 RAND `MIN_STAKE` and above (§7); aggregator bonds: 25 000–100 000 RAND; prover registry bonds | delivered as locked notes that must be bonded through the 6-month cliff; a buyer that stops operating has its cliff extended to 12 months (the draft's only enforced penalty) |
| **Prover hardware bootstrap**, community bucket | 30 M | the first 40 aggregators and the first 100 registered provers | matching grant: 150 000 RAND per 80 GB-class GPU, up to 4 per operator (24 M); 20 000 RAND per registered prover (2 M); 4 M reserve | vests over 24 months; an aggregator must cover ≥ 80 % of the blocks its quota admits in a month to vest that month; a prover must answer `prover_info` ≥ 95 % of the month |
| **Incentivised testnet**, community bucket | 40 M | validators (20 000 RAND per stage), aggregators (40 000 per stage), bounties | the operators themselves, before any token has a price | 6-month cliff after mainnet, as the draft sets |
| **Delegation programme**, community bucket | 40 M over 5 years | validators that also run a public archive + RPC node (§5.5) | the archive role, which the protocol itself does not pay | Foundation stake delegated only to validators whose archive serves the full envelope history and answers sync; re-evaluated each quarter |
| **Validator issuance** | 5 % of supply in year one, −15 %/yr to a 1.5 % floor | all bonded stake, pro rata; 5 % of each epoch's issuance by blocks proposed | validator capital return independent of fee volume | activates by vote once the set is above 60 and ≥ 20 aggregators are registered (draft timeline, T₀ + 24 mo) |
| **Sealing subsidy** | 15.8 M in year one at full sealing | aggregators, per sealed block | GPU operating cost before fees | minted only when a block seals, so an idle chain consumes none |

The sale gates in the draft stand, and this page adds one: **the validator and prover sale does
not open until the §4.4 leaf-step target is measured on an 80 GB GPU.** Selling aggregator seats
against a 377 GB machine would be selling hardware nobody can run.

### 6.6 Does it pay? Worked numbers

Assumptions, all stated so they can be changed: RAND at the $0.15 public floor; 1.2 s blocks
(26.28 M a year); every covered bundle pays the floor and no tip; 0.5 GPU-s per covered
transaction (the §4.4 target); a GPU-hour at $0.40 blended for owned consumer or prosumer cards
and $2.00 for rented 80 GB data-centre cards; every block sealed.

| | 100 tx/s | 1 000 tx/s | 5 000 tx/s |
|---|---|---|---|
| transactions a year | 3.15 B | 31.5 B | 158 B |
| fee revenue at the aggregated-lane floor (0.001 + 0.0006 `prove_base` = 0.0016 RAND) | 5.0 M RAND, $0.76 M | 50.4 M RAND, $7.6 M | 252 M RAND, $37.8 M |
| proposer share (40 % of `BUNDLE_BASE`) | 1.26 M RAND, $0.19 M | 12.6 M RAND, $1.9 M | 63 M RAND, $9.5 M |
| aggregator fee share (60 % of `BUNDLE_BASE` + `prove_base`) | 3.8 M RAND, $0.57 M | 37.8 M RAND, $5.7 M | 189 M RAND, $28 M |
| sealing subsidy, years 1–2 | $2.4 M | $2.4 M | $2.4 M |
| GPU-equivalents needed | 50 | 500 | 2 500 |
| GPU cost, owned cards | $0.18 M | $1.75 M | $8.8 M |
| GPU cost, rented data-centre cards | $0.9 M | $8.8 M | $44 M |
| **aggregator margin, owned cards** | **+$2.8 M (subsidy-carried)** | **+$6.4 M** | **+$21 M** |
| aggregator margin, rented cards | +$2.1 M | −$0.7 M | −$14 M |

Three things the table says:

- **At 100 tx/s the subsidy is the business.** That is its job, and it is why it is paid per
  sealed block and not per transaction: an operator is paid for being there when nobody is
  transacting.
- **At 1 000 tx/s fees carry owned hardware comfortably and rented hardware not at all.** The
  market will therefore be operators who own cards, which is who the hardware bootstrap grants
  are for. If the §4.4 target slips to 1 GPU-s per transaction the owned-card margin at 1 000
  tx/s is still positive (+$4.6 M); at 2 GPU-s it is roughly break-even, and `prove_base` would
  have to rise by governance. The target is where it is for that reason.
- **Validators are paid by issuance, not fees, at every scale below 5 000 tx/s.** 50 M RAND of
  year-one issuance is $7.5 M across at most 100 validators, against a hardware bill of a few
  hundred dollars a month each. The verification share is a rounding error until the chain is
  full, which is the correct incentive: a validator's job is to be cheap and present.

A sender's floor for a covered transfer is 0.0016 RAND, $0.00024 at the assumed price: the
0.001 RAND it pays today plus `prove_base`, against a few cents on the cheapest transparent
chains and a dollar or more on Ethereum. The sender's real cost is its own proving time, which §4.4's inner-profile decision
weighs explicitly.

## 7. Parameters this page proposes or changes

| parameter | today | proposed | where it lives | changeable by |
|---|---|---|---|---|
| `MIN_STAKE` | 1 000 RAND | **100 000 RAND** | genesis | governance (the draft's decision 5) |
| `aggregator_bond` | 1 000 (cut-script default) | **25 000 RAND per quota unit, ≤ 4 units** | genesis `aggregation` | governance |
| aggregates per block `k` | 1 (sealing) | **4**, then 8 | genesis | hard fork |
| `MAX_BLOCK_BYTES` / `MAX_BLOCK_TXS` | 20 MiB / 2 000 | **40 MiB / 4 096**, then 128 MiB / 16 384 | genesis | hard fork |
| fee split of `BUNDLE_BASE` | 100 % proposer | **40 % proposer / 60 % covering aggregator** | ledger rule, genesis-gated | governance |
| `prove_base` | — | **0.0006 RAND** | genesis `gas` | governance |
| `byte_price_raw` / `byte_price_agg` | one `byte_price` | **two prices, targets 25 % / 75 %** | genesis `gas.dynamic` | governance (targets), market (prices) |
| subsidy selection | most coverage wins | **pro rata by cover among the block's aggregates** | ledger rule | hard fork |
| self-fill invariant | — | `subsidy_base / MAX_BLOCK_TXS < 0.4 × BUNDLE_BASE` | `Genesis::validate` | — |
| prover registry + 10 % rebate | — | new | ledger rule, genesis-gated | governance (rate) |
| nullifier commitment | sorted BLAKE3 Merkle | **insertion-order MMR**, `rand-state-6` | state root | hard fork |
| envelopes | 4 × 1 860 B | **2 full + 2 self (~120 B)** | bundle guest, `hc_bundle` | hard fork |
| `subsidy_base`, `halving_blocks` | 100 / 210 000 (cut-script defaults) | **0.6 RAND / 52 560 000** | genesis `aggregation` | governance, downward only |

## 8. Plan

Phases are sequential where an arrow says so and parallel otherwise. Each ends with a number in
`docs/node-hardware.md`, not a claim.

| phase | work | depends on | done when |
|---|---|---|---|
| **1. Validator hot path** | §3.1 MMR, §3.2 overlays, §3.3 verify cache and pool, §3.4 compact blocks, §3.5 batched QC verify | — | §3.6: 4 096 stub records a block, ≤ 300 ms apply at block 10 000 |
| **2. Recursion** | §4.1 Poseidon2 and FRI chips, §4.2 tree steps, §4.3 auth proof covered, ZKQ-5 binding, inner-profile measurement | — | §4.4 targets measured on one 80 GB GPU; aggregate verify ≤ 150 ms warm |
| **3a. Forward path, node side** | aggregator ingress and `rand-bundles` topic, `k` aggregates a block, selection by covered fee, pro-rata subsidy, two-lane fees and `prove_base`, bond quota, prover registry and rebate, `MIN_STAKE` | 1 | cluster test: 64 validators (simulated), 4 aggregators, 1 000 tx/s sustained for an hour with the stub rVM; every fee and subsidy lands where §6 says, supply audit holds |
| **3b. Envelope slimming** | spec amendment, bundle guest, wallet | — (parallel) | ~7 KB covered record measured; privacy review signed off |
| **3. Cut** | genesis with the §7 parameters; Tour de RAND stage for aggregators on it | 2, 3a, 3b | 1 000 tx/s on the public testnet for a week, measured by `rand_getSupply` and the explorer; the validator and prover sale opens |
| **4. Propagation and caps** | erasure-coded bodies, 1 Gbit/s spec, 128 MiB / 16 384 / 8, delayed verification kept in reserve | 3 on the fleet | 5 000 tx/s sustained on the testnet; validator intake ≤ 300 Mbit/s |

What **not** to do, and why, so it is not re-litigated:

- **No SNARK wrapper.** Not post-quantum (§4.4).
- **No proof pruning without aggregation.** Trades the chain's proof-carrying history for
  finality-signature trust (`docs/aggregation.md`, status line).
- **No GPU requirement for validators.** The validator stays the role a home operator can run;
  the GPU market is separate and permissionless (§2.2).
- **No per-transaction subsidy.** It is farmable; per block it is not (§6.3).
- **No slashing for aggregators.** A lost race is not a fault; quota prices spam (§6.3).

## 9. Risks and open questions

- **The §4.4 targets may not be met.** The whole plan rests on recursion cost falling by three
  orders of magnitude from today's measurement. The precompile approach is what every production
  recursive zkVM does, so the direction is not in doubt; the constant is. If a leaf step lands at
  2 GPU-s a transaction, §6.6 says the aggregated lane still clears at a higher `prove_base` and
  a lower sustained throughput; it does not say the design fails.
- **Aggregated-lane latency.** A tree of depth 4 at the target step times is 2–3 minutes from
  submission to inclusion. Many payments are fine with that; some are not, and pay the raw lane.
  Whether users accept a two-speed chain is a product question the testnet stage answers.
- **Ordering.** Aggregators order bundles inside an aggregate and leaders order aggregates. All
  content is shielded, but the whitepaper's Part II is explicit that ordering is not protected
  on the running chain. This page does not change that; it does concentrate ordering power in
  fewer hands than a round-robin leader alone, and the VPA research direction becomes more
  relevant, not less.
- **Archive economics.** §5.5's 220 TB a year at 1 000 tx/s is funded by the delegation programme
  criteria, which is a Foundation policy, not a protocol rule. If the Foundation's stake becomes
  small relative to the set, archives need a protocol payment; the natural one is a share of the
  proposer's verification fee routed to archives that serve sealed-sync requests, and it is left
  for governance once the cost is real.
- **Envelope slimming and privacy.** The self-envelope reveals nothing beyond the slot structure
  the chain already publishes, but it is a change to what every transaction looks like, and the
  shielded-pool spec owner should review it before the guest moves.
- **Validator count.** A 100-validator set is 242 KB of Dilithium2 per block. Nothing here grows
  the set, and a post-quantum aggregate signature would be the first thing to adopt if it does.
- **Price assumptions.** Every dollar figure in §6.6 is at the $0.15 public floor from a draft that
  calls itself a proposal for decision. The RAND-denominated figures are the ones the protocol
  fixes.

Related: `docs/block-space.md` (the three remedies and why aggregation was chosen),
`docs/aggregation.md` (the sealing pipeline this page extends), `docs/fees.md` (the gas rule the
two-lane market extends), `docs/staking.md`, `docs/supply.md`, `docs/prover.md`,
`docs/node-hardware.md`, `tokenomics/rand_tokenomics.tex`.
