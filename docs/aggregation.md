# Block-level proof aggregation and the prover market

Status: **approved design as a starting point, not built** (decided and approved 2026-09-12; the spec and plan build on §1–§4 and settle the open questions in §5). This is the
remedy chosen in `docs/block-space.md` §6 for the 80-query proof size: a block carries one
recursive proof for all of its bundles instead of one ~1.3 MB proof per bundle. Proof pruning was
rejected because it makes a syncing node trust finality signatures for old history and so opens
the long-range attack a proof-carrying chain does not have.

## 1. Two roles, two kinds of hardware

| role | hardware | admitted by | does | paid by |
|---|---|---|---|---|
| **proposer** (HotStuff leader) | CPU | stake (`docs/staking.md`, the S2 register) | orders transactions, verifies one aggregate proof per sealed block (~0.8 s cold, ~16 ms warm) | the verification share of fees, as today |
| **aggregator** (prover) | GPU | permissionless, a registered payout address | proves one recursive STARK that verifies N bundle proofs; submits it for a sealing block | the proving share of fees **plus a block subsidy in newly minted SHRUGG** |

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

### 3.2 A block subsidy in new SHRUGG

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

`shrugg_getSupply` reports issuance separately from faucet mints so an auditor can check the
schedule against the sealed-block count.

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

Related: `docs/block-space.md` (the numbers and the three remedies), `docs/fees.md`,
`docs/supply.md`, `docs/staking.md`, `docs/zkvm.md`.
