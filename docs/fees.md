# Fees, tiers and why there is no gas

This page explains what a transaction pays on RAND, what the sender pays with its own machine
instead, and why the chain has no gas metering. `docs/confidential.md` has the on-chain call
model, `docs/zkvm.md` the machine, `docs/shielded.md` the pool.

## 1. What a transaction pays the chain

Fees are flat floors, in units of 10⁻⁹ RAND (`crates/randprotocol-core/src/gas.rs`):

| transaction | floor | today |
|---|---|---|
| any bundle: a transfer, a bond, a bridge deposit (`BridgeAttest`, paid by its relayer) | `BUNDLE_BASE` = 1,000,000 | 0.001 RAND |
| BridgeBurn | `BRIDGE_BURN_FEE` = 10 × `BUNDLE_BASE`: the base plus the bridge's own charge, on the one hidden-asset bundle every action carries since chain 14 | 0.01 RAND |
| Deploy | `BUNDLE_BASE` + `DEPLOY_PER_WORD` (100,000) × program words | a 4,096-word program: 0.4106 RAND |
| Call | `BUNDLE_BASE` + `call_fee(tier)`, `call_fee` = `CALL_BASE` (1,000,000) + 100,000 per two tiers above 10 | tier 10: 0.002; tier 14: 0.0022; tier 20: 0.0025 RAND |
| Mint (testnet faucet) | 0 (no bundle; validator-signed) | — |

The fee is a public word of the bundle. The `bundle` guest binds it into its balance proof
(`Σ inputs = Σ outputs + fee + burn`), so it is paid out of hidden notes without revealing
which, and the ledger credits it to the block proposer's public `rewards`. A call's tier is only
known after its proof is decoded, so a call's floor is checked twice: `BUNDLE_BASE + CALL_BASE`
before any verification work, the tier-exact floor after. Paying more than the floor is allowed;
the mempool orders candidates by fee, so a higher fee only matters under congestion.

The wallet's defaults are exactly the floors: `deploy_fee_default = fee_floor(Deploy)`,
`call_fee_default(tier) = BUNDLE_BASE + call_fee(tier)`; `rand fee bundle|deploy <words>|call
<tier>` prints them.

Value also leaves the pool through `burn`: a `Bond` burns exactly its amount into the
validator's public stake, and a `BridgeBurn` burns the amount plus a relayer fee in the bridged
asset. Burns are not fees; `docs/supply.md` accounts for both.

### 1.1 The gas rule (spec `2026-09-28-gas-model-design.md` §3.2, §4.1, §4.2)

Two rules apply, one live today on any chain, one riding chain 18's constraint set.

**Phase 0 (v0.6.4, node policy, live today).** A node prices a call by the work its proof header
*bounds*, without decoding anything the chain doesn't already read:

    gas_max = (2ᵗ − 1) + 2^(t−2) + 191·(2ᵏˡʰ / 32) + 63·(2ˢˡʰ / 64)     -- 0 for an absent table
    floor   = max( BUNDLE_BASE + call_fee(t, bytes),
                   BUNDLE_BASE + gas_price·gas_max + byte_price·⌈bytes / 1024⌉ )

`gas_price` and `byte_price` are the node's `--gas-price` / `--byte-price` (defaults 100 and
800 units: 10⁻⁷ RAND per gas, 8·10⁻⁷ RAND per KiB from byte 0); `rand_getLimits` announces
them and `rand_estimateFee` prices them; a wallet pays the floor by default. It is a policy above
the ledger's schedule, never a block rule: the pool refuses `FeeTooLow` (not permanent), a block
that carries a cheaper call is still valid. One gas is one cpu row; a `KECCAK` row is 192, a
`SHA256` row 64 (§3.1 of the spec). The `2^(t−2)` term is the Poseidon2 absorb surcharge: the
zkVM charges `+2` gas on every absorb row beyond its cycle, and a tier holds up to `2^(t−3)`
permutation slots, so a run can exceed the plain cycle budget by up to `2·2^(t−3)`. **Known
under-count (audit v6 ZKV-5, issue #95, constraint set 8):** the digest-prefix rows — one per
four program words for `hc`, the salt row plus one per four private-input words for `H_IN`, one
per four public words (at least one) for `H_PUB` — each pull a Poseidon2 permutation exactly as
an absorb row does, but the meter weighs them at 1, not 3. A Call's metered gas is therefore
`2 · (⌈words/4⌉ + 1 + ⌈n_in/4⌉ + max(1, ⌈n_pub/4⌉))` below its permutation-weighted figure
(the tier-14 bundle guest: 1 019 prefix rows, 2 038 gas of its 20 479 pin; the auth guest 46
rows, 92 gas — both pay a flat pinned limit, so only a Call's price is affected: ~0.0001 RAND on
a 2 854-word program at `gas_price` 100). The ceiling is unaffected — the `2^(t−2)` term already
counts every permutation slot a tier holds, prefix rows included. It is not priced chain-side:
the input-digest rows depend on the private input's length, which the salted `H_IN` keeps
private, and a chain-side surcharge would double-charge once the meter is fixed. The fix is in
the AIR and moves every verifier key — constraint set 9; `tests/executor.rs`'s
`zkv5_digest_row_gas_pin` pins the under-count so the re-vendor that fixes it is noticed. What
this changes, for a ~1.2–1.3 MB production proof: a tier-14 call — the highest tier a chain admits a
call at (`MAX_CALL_TIER`) — goes from ~0.0022 to ~0.0041 RAND (`20 479·100 +
800·⌈1 350 000/1024⌉ + 1 000 000`), and a tier-10 call pays ~0.0021 (was 0.0020). The schedule
would charge a tier-20 header ~0.133 RAND, but no such call is admitted today.

**Phase 1 (chain 18's constraint set, built on `feat/gas-chain18`, not yet cut).** The chain
learns the exact declared limit instead of the header's ceiling: a call proof carries one new
public value, `GAS_LIMIT` (`pv::GAS`), and the cpu AIR proves `GAS ≤ GAS_LIMIT` in-circuit
(`docs/confidential.md`'s "Constraint set 8", `docs/zkvm.md` §1, §4). The ledger rule replaces
`gas_max` in the floor above with the proof's own declared `outcome.gas_limit`:

    fee ≥ BUNDLE_BASE + gas_price·outcome.gas_limit + byte_price·⌈bytes / 1024⌉

and the pre-verify floor (before the proof is decoded) prices `outcome.gas_limit = 1`, so a verify
still isn't bought for nothing. A bundle proof's `GAS_LIMIT` must equal the genesis constant
`bundle_gas_limit` exactly — `20 479` (`gas_max(14, 0, 0)`) for today's tier-14 hidden-asset
guest — or the proof is refused (`TxError::BundleGasLimit`, permanent): every bundle then
publishes the same value, so a fixed price is still the right price for a fixed program. Chain 18
also runs split authorisation (genesis `hc_auth`, v0.6.3), so every bundle carries a second, auth
proof; its `GAS_LIMIT` must be `1 279` (`gas_max(10, 0, 0)`, the auth guest's tier-10 ceiling —
no genesis field, one honest value) or it is refused (`TxError::AuthGasLimit`, permanent). The
auth prover declares the ceiling by default, so wallets change nothing. On a
chain without a `gas` section (`rand_getLimits.gas_metering` absent) both rules are absent and
the ledger's flat tier schedule above applies unchanged.

### 1.2 Dynamic prices (Phase 2, chain 18's genesis `gas.dynamic`, built, not yet cut)

Optional inside the same `gas` section (spec §7.1): `gas_price`/`byte_price` become live ledger
state (`Ledger::gas_prices`, `GasPrices { gas_price, byte_price }`), moved once per block in
`close_block`, after the block's transactions and before the root, by fullness against a target:

    price' = max(min_price, price + ⌊price · adjust_bps · (used − target) / (10 000 · target)⌋)

applied to `byte_price` against `bytes_used`/`target_block_bytes` (Σ every transaction's
`encoded_len`) and to `gas_price` against `gas_used`/`target_block_gas` (Σ each call's declared
`GAS_LIMIT` plus `bundle_gas_limit` per bundle proof, built as `Ledger::block_usage`), with `used`
first capped at `2 · target` — so `adjust_bps` is the largest one-block move in either direction
(a block's gas can exceed twice its target; its bytes cannot, chain 18's `target_block_bytes` being
10 485 760, half the 20 MiB `max_block_bytes`). The division
floors toward zero fall (`div_euclid`, not truncating division — `next_price(1001, 800, 0, t,
1250) == 875`, not `876`); every price is clamped at its own `min_gas_price`/`min_byte_price`
floor, which genesis must set so `min_price · adjust_bps ≥ 10 000` (a price under that bound could
never rise again once floored). The live prices are folded into the state root, last, under
`rand-state-7`, **only** when `dynamic` is present (absent or a fixed-price-only section leaves
the root exactly as before — the vesting pattern), and persisted beside `META_SUPPLY`
(`META_GAS_PRICES`, restored by `reload_ledger` on every restart, written only when the chain has
a `gas` section at all). A `gas` section with `dynamic` set is refused beside an `aggregation`
section at genesis (`GenesisError::DynamicGasWithAggregation`): a pruned bundle's marker form
encodes shorter than its raw form, so sealed-sync's byte price would diverge from a live-synced
node's. The wallet reads `rand_getLimits` (which serves the tip's current prices under `dynamic`)
and pays two steps of headroom, `⌊floor · (10 000 + adjust_bps)² / 10 000²⌋` in u128: the served
prices are the committed head's, and a transaction lands two or three certified blocks later, so
two raises before it lands still admit it; `--fee` overrides. `rand_status` reports
`gas_prices`.

**Ceilings and the byte load (audit v6, POOL-2; genesis-gated, chain 18 unchanged).** Only a
Call pays the byte price, but under chain 18's rule every transaction's bytes move it: seven
transfers (~2.85 MB of proofs each, no byte price paid) fill a block to ~1.9× the 10 MiB target
and lift `byte_price` ~11 % a block, with no ceiling — about 65 such blocks take it to 1 000× its
start, and a 1.3 MB Call then costs ~1 RAND instead of ~0.004. Two optional `gas.dynamic` fields
bound that, each hashed only when set:

- `max_gas_price` / `max_byte_price` (decimal strings, each ≥ the section's starting price):
  ceilings the controller never lifts a price over. The step is the same
  (`gas::next_price_capped` = `next_price` clamped), so a price at its ceiling stays there through
  any run of full blocks and falls from it on the first block under target. Served by
  `rand_getLimits`. Without them a price has no ceiling — chain 18's rule.
- `byte_load: "paying"`: `bytes_used` counts only the bytes the byte price is charged on — each
  Call's proof plus input envelope (`gas::call_bytes`), nothing of a transfer, bond or burn — so a
  block of transfers moves no byte price. Absent, every transaction's encoded length, as on chain
  18. `Ledger::block_usage` is the one function the proposer and the replica both call, so the two
  cannot disagree on the figure.

Under `byte_load: "paying"` a block full of transfers gives a Call no price signal, so the
proposer reserves room for it (option 4 of the audit, node policy, not a rule): while a Call is
pooled and pays its current floor, flat-fee transactions take at most three quarters of the
block's bytes in `Mempool::candidates_within`, and what the Calls leave of the last quarter is
filled with the transfers held back — no block space is wasted, and with no Call pooled nothing
changes. A hostile proposer can ignore it; an honest one on chain 18 runs it today.

### 1.3 The `fees` section: a burned base and a fee-first subsidy (genesis-gated, on no chain yet)

Every fee above goes to the block's proposer today, in full (or, on an aggregating chain, the
floor to the proposer and the excess to the proof bucket, `docs/aggregation.md`), and an
aggregate's subsidy is minted on top of whatever fees it collected. The prices of §1.2 float, but
nothing is destroyed and nothing is netted: a busy chain pays its proposers more, mints its
provers as much as an idle one, and gives its holders nothing. The agent-driven fee study (plan
`superpowers/plans/2026-10-05-fee-feedback.md`) found two variants worth having — the EIP-1559
shape, burn the base and tip the rest, and the proving-auction shape, pay the prover from fees
first and mint only the shortfall — and a genesis `fees` section switches each on:

```json
"fees": { "burn_base": true, "subsidy_net_of_fees": true }
```

Both flags are optional booleans and **off by default**, following `tokens.burn_registration_fee`
(audit v5 TOK-2) exactly: absent, or present with no `true` flag, the chain is byte for byte what
it was — the genesis hash, the state root, every stored value and every RPC value. A `true` flag
is committed to the genesis hash right after the `tokens` section's bytes: `b"fees"`, then
`b"burn_base"` ‖ `1` if `burn_base`, then `b"subsidy_net_of_fees"` ‖ `1` if
`subsidy_net_of_fees`, in that order, and nothing at all when neither is `true` (pinned by
`the_fees_sections_hash_contribution_is_pinned`). An unknown key in the section is refused, so a
misspelt flag cannot read as "off". It is a genesis parameter, never state: on the ledger as
`Ledger::fees`, stored under `META_FEES` (JSON, written on every new database — `{}` without a
section) and set again from the genesis file by `reload_ledger` on every restart, the file being
the authority. `rand_getLimits` serves it as `fee_rules`, `null` on a chain without a `true` flag.
Dollar-indexed prover pay (the study's per-prover-day target) is out of scope: it needs a price
oracle the chain does not have.

**`burn_base`.** In the bundle fee split (`Ledger::apply_tx_with`) every bundle's
`gas::BUNDLE_BASE` is destroyed instead of paid: `supply.burned` and the supply counter
`base_fees_burned` move by it (`docs/supply.md`). With `fee` the bundle's fee after a TOK-2
registration burn:

| chain | proposer keeps at inclusion | bucketed for the aggregator | destroyed |
| --- | --- | --- | --- |
| no `aggregation` | `fee − BUNDLE_BASE` (the tip) | — | `BUNDLE_BASE` |
| `aggregation` | `0` | `fee − BUNDLE_BASE`, exactly as without the flag | `BUNDLE_BASE` |

`fees_paid` moves by what the proposer keeps. The bucketed excess resolves as it always has — in
a covering aggregate's payout note, or to the recorded proposer at the sweep. The floor already
holds every bundle's fee to at least `BUNDLE_BASE` (a fee under it is refused as `FeeTooLow`, never
wrapped), so nothing a sender pays changes: the wallet defaults and every floor are the same
numbers, only where the base goes differs.

A worked transfer: a sender pays 0.0012 RAND (1 200 000 units) on a chain without aggregation.
Without the flag the proposer keeps all of it. Under `burn_base` 0.001 RAND (`BUNDLE_BASE`) is
burned — `burned` and `base_fees_burned` each +1 000 000 — and the proposer keeps the 0.0002
RAND tip, `fees_paid` +200 000. On an aggregating chain the same transfer burns the same 0.001
and buckets the 0.0002 for the aggregator; the proposer keeps nothing at inclusion.

Only the base burns, not a Call's gas and byte terms (§1.1) nor a Deploy's per-word term. The
base is the one component every bundle pays and no proposer can steer; the priced terms stay the
proposer's, so including Calls stays worth its while. Burning the whole floor is a named
follow-up, not this rule. A `Withdraw`'s, a claim's and a revoke's base is untouched too: it is
paid register-side, out of the amount withdrawn, and never passes the bundle fee split.

Beside TOK-2 the two burns add: a registration under both flags destroys `registration_fee +
BUNDLE_BASE`, each counter moving by its own part.

**`subsidy_net_of_fees`.** The fee-first subsidy: an aggregate's prover pay is funded from the
fees it collected first and minted only for the shortfall. Without the flag a covering
aggregate's payout note carries `subsidy(n) + shares` — the schedule (`docs/aggregation.md` §3.2)
minted on top of the covered bundles' proving shares, however large those are. Under it, in
`Ledger::aggregate_payment` (spec §5.4, the one function admission and apply both derive the note
from, through `aggregation::minted_subsidy`):

```
schedule = subsidy(sealed_blocks)
minted   = schedule − shares, or 0 once shares ≥ schedule
note     = minted + shares = max(schedule, shares)
```

A worked aggregate: with a schedule of 0.6 RAND, an aggregate whose covers bucketed 0.4 RAND of
proving share mints 0.2 RAND and pays 0.6 (`subsidised` +0.2); one whose covers bucketed 0.9 RAND
mints nothing and pays 0.9. Without the flag the first would mint 0.6 and pay 1.0. The aggregator
is never paid less than the schedule, a busy chain mints less, and a chain whose fees cover the
schedule mints nothing. `supply.subsidised` — and `rand_getAggregate`'s `subsidy` — move by the
minted part alone; the shares were already in the pool, so the supply identity holds unchanged.
`rand_getEmission`'s `subsidy.current` is still the schedule, so under the flag it is a ceiling
on what an aggregate mints, not the mint. `sealed_blocks` still advances by one per aggregate,
minted or not: the schedule's index counts sealed blocks, not mints, so the halving clock does not
stop while fees carry the pay. The rule needs an `aggregation` section
(`GenesisError::SubsidyNetOfFeesWithoutAggregation`): on a chain without one there is no subsidy
to net.

The two compose without touching: under both flags the base is burned at inclusion, and the
bucketed excess `fee − BUNDLE_BASE` is the share this rule nets against. The 0.0012 RAND transfer
above burns 0.001 and contributes its 0.0002 to the shares a covering aggregate nets against the
schedule.

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

## 3. Why Ethereum needs gas as a bound, and this chain uses it only as a price

Ethereum's gas exists because **every node executes every transaction**, and execution is
open-ended: a contract can loop forever, allocate storage without bound, or recurse, and every
validator would have to run it to find out. Metering each opcode solves three problems at once:

1. **Termination.** Refusing to continue past the gas limit guarantees every execution ends, on
   every node, at the same point.
2. **Pricing the work of others.** The sender pays for the cycles, storage and bandwidth that
   thousands of other machines spend replaying its transaction, so the price has to track the
   per-opcode cost, hence the fee table and its revisions.
3. **Block sizing.** The block gas limit bounds the replay work a block can impose.

On RAND the premise is gone: **no node executes anything.** The sender runs the program once,
off chain, and hands the chain a proof. A node's work per transaction is a fixed sequence: decode
the public fields, run the free checks, verify one STARK. That verification's cost depends on the
tier and the tables present, never on what the program did, and it is bounded by construction: a
proof only exists for a run that halted inside `2ᵗ` cycles.

So the three jobs of gas fall apart:

- **Termination** is enforced by the tier. A run that does not halt within the budget cannot be
  proved at all; the prover, not the network, absorbs the failure.
- **Pricing the work** is what the gas floor above does: the network's marginal cost per
  instruction is near zero, but the sender's proving work is real, delegated provers and
  aggregators sell exactly it, and a flat floor priced a million-cycle call like a thousand-cycle
  one.
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
| `MAX_PROGRAM_WORDS` | 4,096 — the default; a genesis file's `max_program_words` replaces it, up to `MAX_PROGRAM_WORDS_LIMIT` = 65,535 | `gas.rs` |
| `MAX_PROOF_BYTES` | 2 MiB (constraint set 5's 80-query profile; re-measured and kept at constraint set 6) — the default; chains 13–15 set genesis `max_proof_bytes` to 8 MiB (note 2026-09-28) | `gas.rs` |
| `MAX_BLOCK_BYTES`, `MAX_BLOCK_TXS` | 4 MiB, 2,000 | `gas.rs` |
| tiers | 10, 12, 14, 16, 18, 20 cycles = `2ᵗ − 1` | `randprotocol-zkvm` `machine::TIERS` |
| `KECCAK_GAS`, `SHA256_GAS` | 192, 64 units of gas per row | `gas.rs` |
| `POSEIDON2_ABSORB_GAS` | 3 units of gas per absorb row (1 base + 2 surcharge) | `randprotocol-zkvm/src/gas.rs` |
| `GAS_PRICE_DEFAULT`, `BYTE_PRICE_DEFAULT` | 100, 800 units — a node's `--gas-price`/`--byte-price` default, and chain 18's testnet genesis starting prices | `gas.rs` |
| `bundle_gas_limit` | `20 479` = `gas_max(14, 0, 0)` — chain 18's genesis constant, the tier-14 hidden-asset guest's flat declared gas | `GasConfig` (genesis), `gas.rs` |
| `next_price`'s `adjust_bps` bound | `1..=5000` (genesis `gas.dynamic.adjust_bps`, chain 18's testnet default `1250` = 12.5% a block) | `GasConfig::check` |
| `min_gas_price · adjust_bps`, `min_byte_price · adjust_bps` | `≥ 10 000`, or that floor could never rise | `GasConfig::check` |
| `pv::GAS`, `pv::NUM` | 34, 35 (constraint set 8) — was 34 total before the gas meter | `randprotocol-zkvm/src/tables/cpu.rs` |
