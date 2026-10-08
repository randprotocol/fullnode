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

### 1.3 The `fees` section: the burns, a fee-first subsidy, the proposer/aggregator split and dollar-indexed prover pay (genesis-gated, on no chain yet)

Every fee above goes to the block's proposer today, in full (or, on an aggregating chain, the
floor to the proposer and the excess to the proof bucket, `docs/aggregation.md`), and an
aggregate's subsidy is minted on top of whatever fees it collected. The prices of §1.2 float, but
nothing is destroyed and nothing is netted: a busy chain pays its proposers more, mints its
provers as much as an idle one, and gives its holders nothing. The agent-driven fee study (plan
`superpowers/plans/2026-10-05-fee-feedback.md`) found two variants worth having — the EIP-1559
shape, burn the base and tip the rest, and the proving-auction shape, pay the prover from fees
first and mint only the shortfall — and a genesis `fees` section switches each on, with a third
flag, `burn_floor`, for the faithful EIP-1559 form (issue #135). Two numeric fields carry the
compute-optimization proposal's proposer/aggregator split (`docs/compute-optimization.md` §6.2–§6.3),
and a sub-section, `usd_subsidy`, the study's best prover-retention variant — prover pay indexed to
a dollar target at a price the validator set votes (below):

```json
"fees": { "burn_base": true, "subsidy_net_of_fees": true, "burn_floor": true,
          "proposer_share_bps": 4000, "prove_base": 600000,
          "usd_subsidy": { "usd_micros_per_sealed_block": 4791, "max_subsidy_per_block": 300000000,
                           "price_max_age_blocks": 72000, "initial_price_micros": 150000 } }
```

All three flags are optional booleans and **off by default**, following
`tokens.burn_registration_fee` (audit v5 TOK-2) exactly: absent, or present with no `true` flag, the
chain is byte for byte what it was — the genesis hash, the state root, every RPC value and every
stored value but two: a database created by a build that knows the section writes `META_FEES` (`{}`)
and `META_BASE_FEES_BURNED` (0) at genesis whether or not the file has one, and an older database
without them opens unchanged, reading both as their defaults. A `true` flag is committed to the
genesis hash right after the `tokens` section's bytes: `b"fees"`, then `b"burn_base"` ‖ `1` if
`burn_base`, then `b"subsidy_net_of_fees"` ‖ `1` if `subsidy_net_of_fees`, then `b"burn_floor"` ‖
`1` if `burn_floor`, then `b"proposer_share_bps"` ‖ be32 and `b"prove_base"` ‖ be64, each only when
set, in that order, then `b"usd_subsidy"` ‖ be64 ×4 (target, cap, age, initial price) when
`usd_subsidy` is, and nothing at all when no flag is `true` and no number is set (pinned by
`the_fees_sections_hash_contribution_is_pinned`, `the_fee_split_fields_hash_contributions_are_pinned`
and `the_usd_subsidy_hash_contribution_is_pinned`;
each newer field comes after the older ones so every hash pinned over them stays put). An unknown key in the section is refused, so a misspelt flag cannot
read as "off". It is a genesis parameter, never state: on the ledger as `Ledger::fees`, stored under
`META_FEES` (JSON, written on every new database — `{}` without a section) and set again from the
genesis file by `reload_ledger` on every restart, the file being the authority. `rand_getLimits`
serves it as `fee_rules`, `null` on a chain without a `true` flag or a set number. Dollar-indexed prover pay (the
study's per-prover-day target) needs a RAND/USD price; the chain takes it from the validator set's
vote, not from a market oracle (`usd_subsidy`, the end of this section).

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

Under `burn_base` alone only the base burns, not a Call's gas and byte terms (§1.1) nor a Deploy's
per-word term. The base is the one component every bundle pays and no proposer can steer; the priced
terms stay the proposer's, so including Calls stays worth its while. Burning the whole floor is the
next flag's rule. A `Withdraw`'s, a claim's and a revoke's base is untouched too: it is paid
register-side, out of the amount withdrawn, and never passes the bundle fee split.

**`burn_floor`** (issue #135; needs `burn_base: true`, else
`GenesisError::BurnFloorWithoutBurnBase` — there is no burned base to widen). The faithful
EIP-1559 form: the burned amount is the ledger's own floor for the bundle, not its base alone, so
a proposer gains nothing from a block that lifts a price (§1.2's controller moves exactly the terms
`burn_base` alone leaves it), which is what a burn is for. With `fee` the bundle's fee after a TOK-2
registration burn:

```
burned = min(fee, floor)                       -- base_fees_burned and supply.burned move by it
tip    = fee − burned                          -- the proposer's, or bucketed when aggregating
floor  = Ledger::settled_floor(tx, outcome):
           BUNDLE_BASE                         -- a transfer, a bond, a token action, an attestation
           BUNDLE_BASE + deploy_fee(words)     -- a Deploy (gas::fee_floor)
           BRIDGE_BURN_FEE                     -- a BridgeBurn (the base and the bridge's charge)
           circuit_call_floor(gas_price, byte_price, GAS_LIMIT, bytes)
                                               -- a Call under a `gas` section, at its GAS_LIMIT
           BUNDLE_BASE + call_fee(tier, bytes) -- a Call without one (the tier schedule)
           (+ cell_fee per created cell)       -- an Invoke
```

`settled_floor` is the one function `validate_inner` holds a call's fee to after its proof is
decoded and the fee split burns by, so the burned figure is always one the fee was checked against.
A Call's is the tier-exact floor — the pre-verify floor at `GAS_LIMIT = 1` only buys the verify and
is never the burned amount. The `min` restates the check (the fee is at least the floor after
validation); it never binds on a valid transaction. A registration's `registration_fee` is not part
of the floor (`fee_floor` is the plain base for it): burned under TOK-2, still the proposer's
without it. `base_fees_burned` counts the whole burn under either flag, so the supply identity is
unchanged. On an aggregating chain the bucketed excess becomes `fee − floor`, so the aggregator is
never paid a priced term the chain just burned. The figure lives in one place, the ledger's bucket
entry (`unsealed_fees`, served by `rand_getUnsealed`), which a covering aggregate's note and the
sweep both read; nothing recomputes it from the transaction, since a Call's floor needs its decoded
proof and the prices it was charged at. A `BridgeBurn`'s floor is `BRIDGE_BURN_FEE`, so under
`burn_floor` the bridge's own charge — the nine bases above `BUNDLE_BASE` that were the proposer's —
is destroyed with the base. `burn_floor` absent or `false` is `burn_base` alone, byte for byte.

| chain, both flags | proposer keeps at inclusion | bucketed for the aggregator | destroyed |
| --- | --- | --- | --- |
| no `aggregation` | `fee − floor` (the tip) | — | `floor` |
| `aggregation` | `0` | `fee − floor` | `floor` |

Worked, on a plain chain under both flags:

- **A transfer** paying 0.0012 RAND: its floor is `BUNDLE_BASE`, so exactly as under `burn_base`
  alone — 1 000 000 burned, 200 000 tipped.
- **A Deploy** of a 4 096-word program paying 0.411 RAND (411 000 000): its floor is
  `1 000 000 + 100 000 · 4 096 = 410 600 000`, all burned (`base_fees_burned` +410 600 000); the
  proposer keeps 400 000. Under `burn_base` alone it would burn 1 000 000 and keep 410 000 000.
- **A tier-14 Call under a `gas` section** at prices 100 / 800, declaring the tier's ceiling
  `GAS_LIMIT = 20 479` with 1 300 000 bytes of proof and no envelope, paying 0.0041 RAND
  (4 100 000): its floor is `1 000 000 + 100 · 20 479 + 800 · ⌈1 300 000 / 1024⌉ = 1 000 000 +
  2 047 900 + 1 016 000 = 4 063 900`, all burned; the proposer keeps 36 100. Under `burn_base`
  alone it would burn 1 000 000 and keep 3 100 000. The pre-verify floor (`GAS_LIMIT = 1`,
  2 016 100) is not the burned amount.

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
bucketed excess `fee − BUNDLE_BASE` is the share this rule nets against (`fee − floor` under
`burn_floor` too). The 0.0012 RAND transfer
above burns 0.001 and contributes its 0.0002 to the shares a covering aggregate nets against the
schedule.

**`proposer_share_bps` and `prove_base`** (`docs/compute-optimization.md` §6.2–§6.3). The
compute-optimization proposal splits every covered bundle's fee between the two kinds of work it
buys: verification, the proposer's, and proving, the covering aggregator's. Both fields need an
`aggregation` section (`GenesisError::ProposerShareWithoutAggregation`,
`GenesisError::ProveBaseWithoutAggregation`) — there is no aggregator and no bucket without one —
and `proposer_share_bps` is at most 10 000 (`GenesisError::ProposerShareOutOfRange`). Each is
absent by default, and absent is the chain without it, byte for byte. `prove_base: 0` is refused
(`GenesisError::ProveBaseZero`): it runs exactly as no `prove_base` but would hash as a second
chain, so leave the field out instead.

- **`proposer_share_bps`** (0..=10 000; the proposal's value is 4 000; 0 and 10 000 are real
  rules — the whole base to the aggregator, or to the proposer — and both hash). Of the base the proposer
  keeps at inclusion today — `BUNDLE_BASE`, or `0` under `burn_base` (and so under `burn_floor`),
  where the base is burned and there is no share to split — it keeps `proposer_share_bps / 10 000`.
  The rest is **bucketed beside the excess**, in the bundle's one bucket entry
  (`excess + aggregator part`): a covering aggregate is paid it as proving share, and an entry
  that expires uncovered is swept back to the recorded proposer exactly as an excess is — so an
  uncovered bundle pays the proposer the whole base in the end, nothing is lost, and `fees_paid`
  moves at inclusion by the proposer's part and at the sweep by the rest. The aggregator's part
  rounds down, so the proposer's is the remainder-free one:
  `aggregator part = ⌊kept_base · (10 000 − bps) / 10 000⌋`, `proposer part = kept_base − aggregator part`.
- **`prove_base`** (RAND units; the proposal's 0.0006 RAND is 600 000) — the aggregated lane's floor
  for the proving share. Every bundle's ledger floor rises by it: `Ledger::settled_floor`, the
  pre-verify floor, an invoke's and a registration's floor alike, so a bundle paying the old floor
  is `FeeTooLow` naming the new minimum. It is bucketed whole: proving share, never the proposer's
  at inclusion and **never burned** — under `burn_floor` the burned amount is the floor *without*
  `prove_base` (asserted in the fee split). `rand_estimateFee` includes it, and the wallet adds the
  served `fee_rules.prove_base` to every default it computes itself.

| chain, rules | proposer keeps at inclusion | bucketed for the aggregator | destroyed |
| --- | --- | --- | --- |
| `aggregation`, `proposer_share_bps` | `BUNDLE_BASE · bps / 10 000` (rounded up) | `fee − proposer part` (tip, `prove_base`, the rest of the base) | — |
| `aggregation`, `burn_base` + share | `0` | `fee − BUNDLE_BASE` | `BUNDLE_BASE` |
| `aggregation`, `burn_floor` + `prove_base` | `0` | `fee − (floor − prove_base)` | `floor − prove_base` |

Worked, on an aggregating chain under `proposer_share_bps: 4000`: a 0.0012 RAND transfer pays
0.0004 to the proposer at inclusion (`fees_paid` +400 000) and buckets 0.0008 — 0.0006 of base
and the 0.0002 tip; a covering aggregate's proving share is the 0.0008, and an uncovered one's
sweep pays the proposer the 0.0008. With `prove_base: 600000` as well, the floor is 0.0016 RAND,
so the same 0.0002 tip is a 0.0018 RAND fee: 0.0004 to the proposer and 0.0014 bucketed (0.0006
of base, 0.0006 `prove_base`, 0.0002 tip). Under `burn_base` the share has nothing to split: the
0.001 base burns and the bucket holds the tip (and `prove_base`). Under `subsidy_net_of_fees` the
shares the schedule is netted against carry `prove_base` and the aggregator's part of the base.

**`usd_subsidy`** (decision 2026-10-09; needs `aggregation`,
`GenesisError::UsdSubsidyWithoutAggregation`). The agent-driven fee study found prover retention
is what its agents react to, and its best variant paid provers a dollar-indexed amount "from fees
first, then minted". A RAND schedule cannot do that: at a falling price `subsidy(n)` buys less
GPU time and provers leave, at a rising one it overpays. The sub-section makes the sealing
subsidy's **schedule** a dollar target converted at a RAND/USD price, while that price is fresh:

```
usd_subsidy = { usd_micros_per_sealed_block, max_subsidy_per_block, price_max_age_blocks,
                initial_price_micros }                      -- all four required, all > 0
schedule(n) = min(⌊usd_micros_per_sealed_block · 10⁹ / price⌋, max_subsidy_per_block)
                                                            -- a fresh voted price, u128, floor
            = min(subsidy(n), max_subsidy_per_block)        -- a stale price (or none)
fresh       ⇔ height − set_at_height ≤ price_max_age_blocks -- height: the block sealing it
```

`aggregation::schedule_subsidy` is the one statement of it: `Ledger::aggregate_payment` (admission's
note and apply's), `rand_getEmission.subsidy.current` and the aggregate daemon all call it, and
`minted_subsidy` then nets it against the covered shares exactly as it nets `subsidy(n)` — so
under `subsidy_net_of_fees` this **is** the study's "from fees first, then minted": the aggregator
is paid `max(schedule, shares)` and only the shortfall is new RAND. The quotient rounds down; the
product is computed in u128 and the result saturates before the cap. The cap binds in **every**
branch (ruling 2026-10-09): the fallback is the RAND schedule clamped to `max_subsidy_per_block`,
so a quorum that lapses can never leave the chain minting above the cap either. `sealed_blocks`
still advances per aggregate, so the RAND schedule the chain falls back to keeps halving
underneath.

**The price is governance, not an oracle.** `price` is micro-dollars per RAND, held by the ledger
as `RandPrice { price_micros_per_rand, set_at_height, nonce }` — seeded from the required
`initial_price_micros` at height 0, nonce 0, so a chain with the section always has one — and
moved only by `SetRandPrice { price_micros_per_rand, nonce, votes }`, the validator set's vote in
`AdmitValidator`'s shape (`docs/staking.md` "The RAND price vote"): one action, bundle-less and
fee-less, each vote a Dilithium2 signature over `blake3("rand-set-price-1" ‖ genesis hash ‖
be64(price) ‖ be64(nonce))`, the voters strictly ascending, members of the voting set, and holding
strictly more than two thirds of its weight — the admission's own quorum. Each update carries the
ledger's nonce plus one and may move the price by **at most a factor of two** either way
(`2·new ≥ old` and `new ≤ 2·old`, exact). The price is consensus state under the section: folded
into the state root as `H("rand-state-price-1", root ‖ price_root)`, persisted (`META_RAND_PRICE`),
replay-audited. Without the section the root is byte for byte what it was and the action is
refused by name.

The trust trade, stated: a market oracle can be manipulated by whoever moves the market; a voted
price can be set by whoever holds two thirds of the stake — who can already halt or rewrite the
chain. The band bounds one vote's damage to a factor of two, and `max_subsidy_per_block` (genesis,
not votable) bounds the mint whatever the vote says, and whatever it fails to say: a quorum voting
the price to one micro-dollar mints at most the cap a block, and so does a stale price, whose
fallback is clamped to the same cap. `docs/compute-optimization.md` §6.1's "governance can only
lower issuance" holds against the cap, not against the RAND schedule — under a low price the dollar
schedule may exceed `subsidy(n)`, up to the cap the genesis fixed. There is **no minimum gap
between updates**: the per-update ×2 band and the quorum are the governance bound — a quorum can
step the price by two every block, but each step is a fresh two-thirds signature over the next
nonce, and no step moves the mint past the cap.

**Freshness, and the aggregator's payout.** A price older than `price_max_age_blocks` reverts the
schedule to the capped `subsidy(n)` — a set that stops voting cannot leave a stale price paying
forever. The age is judged at the height of the block that applies the aggregate, and the price can
move under an aggregate between its sealing and its inclusion (a `SetRandPrice` in any block before
it — and in its own block, since a proposer applies ordinary transactions before aggregates), as can
`sealed_blocks` across a halving. **That can no longer cost an aggregator its payout** (review
2026-10-09): an `Aggregate` carries the amount its envelope was sealed for, `payout_total`, signed
(`rand-aggregate-4`), and the ledger refuses one whose `payout_total` is not what it pays now —
`AggregationError::PayoutMismatch`, at admission and at apply — instead of paying its own amount
into a note the envelope cannot open. Nothing leaves the bucket; the pool evicts such an aggregate
at the next tip; `rand-node aggregate` re-seals the same proof at the current schedule (the proof
binds the aggregator, its nonce and the covers, never the payout) and resubmits. `rand_getRandPrice
.fresh` is judged for the next block, which is what the daemon seals at (`time = height + 1`), so
a re-seal is the exception at the staleness edge, not the rule.

Worked, with the study's $345 a day for the sealing prover at 1.2 s blocks (72 000 blocks a day):

- `usd_micros_per_sealed_block = ⌊345 000 000 / 72 000⌋ = 4 791` µ$ ($0.004791 a block,
  $344.95 a day).
- **At $0.15** (`price = 150 000`): `⌊4 791 · 10⁹ / 150 000⌋ = 31 940 000` units — 0.03194 RAND a
  block, 2 299.68 RAND a day — against today's RAND schedule of 0.6 RAND a block (43 200 RAND,
  $6 480 a day at that price). Under the cap, so the dollar target binds.
- **At $0.01** (`price = 10 000`): the target is `⌊4 791 · 10⁹ / 10 000⌋ = 479 100 000` units
  (0.4791 RAND), over a `max_subsidy_per_block` of 300 000 000 (0.3 RAND): **the cap binds**, the
  aggregate's schedule is 0.3 RAND ($0.003, $216 a day) and the prover is under-paid rather than
  the supply over-minted. The cap starts binding below `4 791 / 0.3 = 15 970` µ$ ($0.01597).
- With `subsidy_net_of_fees` beside it, an aggregate at $0.15 whose covers bucketed 0.01 RAND of
  shares mints 0.02194 RAND and pays 0.03194; one whose covers bucketed 0.05 RAND mints nothing
  and pays 0.05.
- If the set stops voting, 72 000 blocks after the last update the schedule is `subsidy(n)` again,
  clamped to the cap: with today's 0.6 RAND schedule and a 0.3 RAND cap, 0.3 RAND.

`rand_getLimits.fee_rules.usd_subsidy` serves the three numbers and `rand_getRandPrice` the live
price; the operator tooling is `rand-node price status|sign|submit` (`docs/cli.md`).

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
