# Fees, tiers and why there is no gas

This page explains what a transaction pays on SHRUGG, what the sender pays with its own machine
instead, and why the chain has no gas metering. `docs/confidential.md` has the on-chain call
model, `docs/zkvm.md` the machine, `docs/shielded.md` the pool.

## 1. What a transaction pays the chain

Fees are flat floors, in units of 10⁻⁹ SHRUGG (`crates/shrugg-core/src/gas.rs`):

| transaction | floor | today |
|---|---|---|
| any bundle: a transfer, a bond, the fee bundle of a bridge burn | `BUNDLE_BASE` = 1,000,000 | 0.001 SHRUGG |
| Deploy | `BUNDLE_BASE` + `DEPLOY_PER_WORD` (100,000) × program words | a 4,096-word program: 0.4106 SHRUGG |
| Call | `BUNDLE_BASE` + `call_fee(tier)`, `call_fee` = `CALL_BASE` (1,000,000) + 100,000 per two tiers above 10 | tier 10: 0.002; tier 14: 0.0022; tier 20: 0.0025 SHRUGG |
| Mint (testnet faucet) | 0 (no bundle; validator-signed) | — |

The fee is a public word of the bundle. The `bundle` guest binds it into its balance proof
(`Σ inputs = Σ outputs + fee + burn`), so it is paid out of hidden notes without revealing
which, and the ledger credits it to the block proposer's public `rewards`. A call's tier is only
known after its proof is decoded, so a call's floor is checked twice: `BUNDLE_BASE + CALL_BASE`
before any verification work, the tier-exact floor after. Paying more than the floor is allowed;
the mempool orders candidates by fee, so a higher fee only matters under congestion.

The wallet's defaults are exactly the floors: `deploy_fee_default = fee_floor(Deploy)`,
`call_fee_default(tier) = BUNDLE_BASE + call_fee(tier)`; `shrugg fee bundle|deploy <words>|call
<tier>` prints them.

Value also leaves the pool through `burn`: a `Bond` burns exactly its amount into the
validator's public stake, and a `BridgeBurn` burns the amount plus a relayer fee in the bridged
asset. Burns are not fees; `docs/supply.md` accounts for both.

## 2. What the sender pays with its own machine: proving

The one cost that varies is producing the STARK proof, and only the sender's machine pays it.
It depends, in order:

1. **The tier `t ∈ {10, 12, 14, 16, 18, 20}`.** Proving time is roughly linear in the trace's
   padded cells: the cpu table is padded to `2ᵗ` rows, the ALU table to `2ᵗ⁺¹`, the memory
   table to its own declared power of two. Each tier step roughly quadruples the padded trace.
   Measured on the development laptop: `private_payment` at tier 10 in about 7 s;
   the shielded `bundle` guest at tier 14 in about 100 s.
2. **Cycles executed**, because they decide the tier. Instructions *run*, not instructions
   *written*: a loop of 10,000 iterations costs 10,000 cycles from a handful of words. A
   `POSEIDON2` call adds about `1 + n/4 + 2` cpu rows; a `KECCAK` call (M4.2) adds one cpu row
   plus 32 rows in the keccak table and 100 memory rows.
3. **Program size**, weakly and twice: every program word is absorbed into the in-circuit digest
   `hc` at the start of the trace, one cpu row per four words (a 4,000-word program spends about
   1,000 cycles before executing anything), and the program table pads to the next power of two
   above the word count.
4. **Private-input size**, the same way: one digest row per four words for `H_IN`, plus the
   input table.
5. **Which tables are present.** The keccak table costs its columns' share of proving and about
   700 KB of proof only when a program used it (`keccak_log_height = 0` means absent).
6. **The FRI profile.** 80 queries instead of 27 triples proof size but barely changes proving
   time; queries are cheap for the prover and expensive only in bytes.
7. **The machine.** Proving is CPU-bound and parallel. The CUDA backend targets this cost and has
   not yet run on hardware.

Proving does *not* depend on the amounts, on how many notes the sender owns, or on the chain's
size: membership is proved against a fixed-depth tree, so a transfer costs the same at block ten
and block ten million.

The practical rule for a program author: keep the cycle count under the next tier boundary.
The fee floor barely notices a tier step; the wallet's proving time notices a 4× jump.

## 3. Why Ethereum needs gas and this chain does not

Ethereum's gas exists because **every node executes every transaction**, and execution is
open-ended: a contract can loop forever, allocate storage without bound, or recurse, and every
validator would have to run it to find out. Metering each opcode solves three problems at once:

1. **Termination.** Refusing to continue past the gas limit guarantees every execution ends, on
   every node, at the same point.
2. **Pricing the work of others.** The sender pays for the cycles, storage and bandwidth that
   thousands of other machines spend replaying its transaction, so the price has to track the
   per-opcode cost, hence the fee table and its revisions.
3. **Block sizing.** The block gas limit bounds the replay work a block can impose.

On SHRUGG the premise is gone: **no node executes anything.** The sender runs the program once,
off chain, and hands the chain a proof. A node's work per transaction is a fixed sequence: decode
the public fields, run the free checks, verify one STARK. That verification's cost depends on the
tier and the tables present, never on what the program did, and it is bounded by construction: a
proof only exists for a run that halted inside `2ᵗ` cycles.

So the three jobs of gas fall apart:

- **Termination** is enforced by the tier. A run that does not halt within the budget cannot be
  proved at all; the prover, not the network, absorbs the failure.
- **Pricing the work of others** is trivial because the work of others is nearly constant:
  about 16 ms of verification with a warm verifier key, plus bytes. A flat floor per bundle and a
  small tier step for calls cover it. The variable cost, proving, is borne by the sender's own
  machine and never by anyone else, so there is nothing to meter.
- **Block sizing** is a byte budget (`MAX_BLOCK_BYTES`) and a transaction count, because
  verification cost per transaction is flat.

Two caveats, stated plainly:

- **Bytes do vary.** With the 80-query profile a proof is around 900 KB, so block space, not
  compute, is the scarce resource. If the chain ever fills, the floor should become a fee market
  on bytes, not on opcodes.
- **State growth is under-priced today.** Ethereum's gas also prices storage writes (20,000 gas
  each) because they burden every node forever. Our equivalents — the commitment tree, the
  nullifier set, deployed program bytes — are priced only by the per-word deploy fee and the flat
  bundle fee. That is adequate for a testnet and worth revisiting when state size matters; it is
  a pricing question, not a termination one, and never requires per-opcode metering.

## 4. Where gas reappears: inside interpreters

The EVM interpreter guest (milestone M4.3) keeps a gas counter, for **semantic fidelity**: an
ERC-20 contract's behaviour on out-of-gas is part of the EVM specification, and a contract must
run the same under the interpreter as on Ethereum. That counter is private state inside the
guest, never seen by the chain. Its only chain-visible effect is the cycle count, which decides
the tier, which decides the floor. The same holds for the sBPF interpreter's compute-unit
accounting (M4.4).

## 5. Reference

| constant | value | where |
|---|---|---|
| `BUNDLE_BASE` | 1,000,000 units | `gas.rs` |
| `DEPLOY_PER_WORD` | 100,000 units | `gas.rs` |
| `CALL_BASE`, `CALL_PER_TIER_STEP` | 1,000,000; 100,000 | `gas.rs` |
| `MAX_PROGRAM_WORDS` | 4,096 | `gas.rs` |
| `MAX_PROOF_BYTES` | 2 MiB (constraint set 5's 80-query profile) | `gas.rs` |
| `MAX_BLOCK_BYTES`, `MAX_BLOCK_TXS` | 4 MiB, 2,000 | `gas.rs` |
| tiers | 10, 12, 14, 16, 18, 20 cycles = `2ᵗ − 1` | `shrugg-zkvm` `machine::TIERS` |
