# Gas: paying for the instructions a call executes, in RAND — design

Status: draft 2026-09-28, written on the user's request ("analyze the gas in terms of RAND to
execute ISA in the zkVM; build a model where the user pays for the ISA in RAND and not a fixed
cost"); **approved by the user 2026-09-28 ("ok amazing … implement it for v0.6.4"; "this should
be chain 18 cut")**. Read against `origin/main` at `aedf458` (v0.6).
Scope: fullnode (`randprotocol-core::gas`, the ledger's call rule, the wallet), one public value
and one column in the zkVM (circuits).
Ships in: **Phase 0 = v0.6.4** on any chain (node policy, no consensus change; plan
`docs/superpowers/plans/2026-09-28-gas-phase0-v0.6.4.md`). **Phase 0 built** (Tasks 1–6 on
`feat/gas`: `gas_max`/`GasPolicy` in `randprotocol-core::gas`, `--gas-price`/`--byte-price` on
`rand-node run`, `rand_getLimits`/`rand_estimateFee`, the mempool's `FeeTooLow` and surplus-per-KiB
order, and the wallet's `gas bound …` line and `rand fee call`'s hash-height flags) — not yet
tagged or rolled. **Phase 1 = the chain 18 cut**: a
hard fork that changes every verifier key, so it rides the constraint set chain 18 carries.
Constraint set 7 (#52) is chain 16's (v0.6.1, cut in flight) and chain 17 is delegated
proving's (v0.6.3); neither takes the meter.

Companion documents: `docs/fees.md` (the schedule this replaces and its "why there is no gas"
argument, which §2 revisits), `docs/zkvm.md` §§3–4, 8 (the ISA, the syscalls, the measured
costs), `docs/block-space.md` (bytes as the scarce resource),
`2026-09-19-call-limits-design.md` §7 (the byte term), `2026-09-28-delegated-proving-design.md`
§5 (a prover paid in RAND, which needs a unit to quote in).

## 1. Problem: the fee is flat, so the price of an instruction is whatever the tier makes it

A call pays `BUNDLE_BASE + CALL_BASE + CALL_PER_TIER_STEP · ⌊(t − 10)/2⌋` (`gas.rs`): 0.002 RAND at
tier 10, 0.0025 at tier 20. The tier is the only thing about the run the chain sees, and a tier
step quadruples the cycle budget while adding 5 % to the fee. Per cycle, at the top of each tier:

| tier | cycle budget `2ᵗ − 1` | call fee (units of 10⁻⁹ RAND, without the bundle base) | per cycle |
|---|---|---|---|
| 10 | 1 023 | 1 000 000 | 977 units |
| 12 | 4 095 | 1 100 000 | 269 |
| 14 | 16 383 | 1 200 000 | 73 |
| 16 | 65 535 | 1 300 000 | 20 |
| 18 | 262 143 | 1 400 000 | 5.3 |
| 20 | 1 048 575 | 1 500 000 | 1.4 |

A cycle at tier 20 costs 1/700 of a cycle at tier 10; inside a tier the marginal cycle costs
nothing; at a boundary the 1 024th cycle costs 100 000 units. Every chain-14 call was tier 10
and paid the same 2 000 000 units (`docs/confidential.md`); chain 13's ERC-20 `approve` was tier
16 and paid 15 % more for 64× the work. The fixed part is 95 % or more of the fee at every tier.
That is what the user wants replaced: the sender should pay for the instructions its program
ran, in RAND, and a fixed component should survive only where the network's cost is genuinely
fixed.

## 2. What an instruction actually costs

Three parties pay for a call, and only one of them pays per instruction.

### 2.1 The prover: per padded row, uniform across the ISA

Proving is linear in the trace's cells. Every executed instruction is one cpu row (275 columns
at constraint set 6), two ALU rows (64 columns; the ALU table pads to `2ᵗ⁺¹`) and four memory
rows (12 columns; two register reads, one memory read or syscall argument, one write):

| per cycle | main-trace cells |
|---|---|
| cpu row | 275 |
| 2 ALU rows | 128 |
| 4 memory rows | 48 |
| **total** | **≈ 451** |

`ADD`, `MUL`, `DIVU`, `LW`, `BEQ`, `JALR` — every RV32IM instruction costs exactly this. There
is no expensive opcode: multiplication and division are proved as identities on the same ALU
row, a load is a memory-bus lookup like a register read, a branch is a row like any other. The
non-uniform costs are the syscalls, which pull rows into other tables:

| syscall | cpu rows (cycles) | other rows | extra cells | in cycle-equivalents |
|---|---|---|---|---|
| `HALT`, `WRITE_OUTPUT`, `READ_INPUT`, `READ_PUBLIC` | 1 | — | 0 | 1 |
| `POSEIDON2 ptr n` | `3 + ⌈n/4⌉` | `32·⌈n/4⌉` poseidon2 rows × 34 columns | 1 088 per permutation | `3 + 3.4·⌈n/4⌉` |
| `KECCAK ptr` | 1 | 32 keccak rows × 2 612 columns + 100 memory rows | 84 784 | **≈ 189** |
| `SHA256 ptr` | 1 | 64 sha256 rows × 466 columns | 29 824 | **≈ 66** |

Two more things count as cycles and therefore as rows: the program digest (one digest row per
four program words, so a 4 000-word program spends ~1 000 cycles before its first instruction)
and the private-input digest (one row per four input words plus the salt row); the circuit
counts both as real rows (M3.4).
The tables' *padding* is paid by the prover too: the cpu table pads to `2ᵗ`, so a run of 1 100
cycles proves 4 096 rows. Measured (`docs/zkvm.md` §8): tier 10 in ~7 s over 1 024 rows, tier 14
in ~100 s over 16 384 rows — **6–7 ms per padded cycle** of laptop CPU either way.

### 2.2 The verifier: per proof, flat

Verifying costs ~16 ms with a warm verifier key and ~0.8 s cold, independent of what the
program did (`docs/block-space.md` §1, `executor.rs`). The cold cost is the key build, which
grows with the *declared table heights* — a tier-14 call with both hash tables at their caps
builds in 4.7 s at 312 MB (`MAX_CALL_KECCAK_LOG_HEIGHT`'s doc comment) — and is bounded by the
call-limit caps, never by a fee. Nothing here is per instruction.

### 2.3 Every node: per byte, mostly per table present

A proof is ~1.20 MB at tier 10 and ~1.25 MB at tier 12 (80-query profile): about **25 KB per
FRI layer**, i.e. per doubling of the trace. A keccak table adds ~1.91 MB whether it holds 32
rows or 32 768, a sha256 table ~400 KB: a proof pays for a table's *width*, not its rows. Bytes
are what a block is short of (three bundles per 4 MiB block) and what every validator relays and
stores, so they are the one shared cost that varies with a call — by table and by tier, in steps,
never per instruction.

### 2.4 So what is gas for?

`docs/fees.md` §3 is right that the chain does not need gas for termination or for pricing
replay: no node executes anything, and the tier bounds the run. What a flat floor gets wrong is
different: it prices the *shape* the sender chose and nothing about the *work*, so a program
that runs a million cycles pays what a program of a thousand pays. Charging per instruction
buys four things:

1. **A price proportional to work**, so the schedule stops being regressive (§1) and a
   program author gains from every cycle saved, not only at a tier boundary.
2. **A unit that provers and aggregators can quote in.** The delegated prover
   (`2026-09-28-delegated-proving-design.md` §5) and the aggregator (`docs/aggregation.md`)
   sell exactly the per-row work of §2.1; a chain-defined gas lets them price a job before
   proving it and lets a wallet compare quotes.
3. **A fee market with a denominator.** Ordering candidates by fee alone lets a small call
   outbid a large one for the same block bytes; gas plus bytes gives the mempool a price per
   unit of work to sort on (§7).
4. **A spam signal** — a full tier-20 trace costs 0.1 RAND, not 0.0025.

What gas does *not* do here: it never bounds anything. The caps (`MAX_CALL_TIER`, the hash-table
heights, `max_proof_bytes`) stay the security bounds; gas is a price.

## 3. The model

### 3.1 The unit

**1 gas = 1 cpu row**, weighted by the rows an instruction pulls into other tables (§2.1),
rounded to integers:

| ISA element | gas | why |
|---|---|---|
| every RV32I instruction (`LUI AUIPC JAL JALR`, branches, `LW SW LB LH LBU LHU SB SH`, all ALU-immediate and ALU-register ops) | 1 | one cpu row, uniform cells |
| every RV32M instruction (`MUL MULH MULHU MULHSU DIV DIVU REM REMU`) | 1 | same row, same ALU table |
| `ECALL HALT`, `WRITE_OUTPUT`, `READ_INPUT`, `READ_PUBLIC` | 1 | one row |
| `ECALL POSEIDON2 ptr n` | `3 + 3·⌈n/4⌉` | the `3 + ⌈n/4⌉` cpu rows at 1 each, plus 2 per permutation for the poseidon2 table (2.4 measured, rounded down: the chain's own primitive) |
| `ECALL KECCAK ptr` | **192** | 1 row + 189 cycle-equivalents, rounded up |
| `ECALL SHA256 ptr` | **64** | 1 row + 66 cycle-equivalents, rounded down to the block size |
| program digest | 1 per row = ¼ per program word | counted as cycles by the circuit already |
| input digest | 1 per row = ¼ per private-input word + 1 | likewise |

Reference points: a `private_payment`-sized call is under 1 000 gas; the 4-in/4-out bundle
guest is 6 920–9 160 gas depending on how many slots are real (`docs/zkvm.md` §8); a tier-16
EVM-interpreted ERC-20 `approve` is 16 384–65 535 gas; a full tier-20 run is 1 048 575 gas.
An EVM contract's *own* gas (the interpreter's private counter, `evm.rs`'s `gas_limit` word)
is unrelated: the chain meters the interpreter's RV32 cycles, and an EVM `SLOAD` at 2 100 EVM
gas costs whatever the interpreter spends implementing it.

### 3.2 The declared limit: pay for a bound you prove, not a count you reveal

The exact cycle count is witness (`docs/zkvm.md` §1) and must stay so: the bundle guest's count
differs by 2 240 cycles between a 1-in-1-out and a 2-in-2-out transfer, and a call's count is a
function of its private input. So the chain never learns the count. Instead:

- The proof carries one new public value, **`GAS_LIMIT`** (`pv::GAS`, `pv::NUM` 34 → 35),
  chosen by the prover.
- The circuit keeps a gas accumulator column in the cpu table (§4.2) and constrains
  **`gas_at_halt ≤ GAS_LIMIT`**.
- The ledger charges **`GAS_LIMIT`**, never the count — there is no refund, because a refund
  would publish the count.

This is Ethereum's gas limit with the refund removed, and the removal is the privacy design:
the sender chooses the granularity of its own leak. Every proof header already implies a
ceiling no run under it can exceed,

```
gas_max(header) = (2ᵗ − 1) + 2^(t−2) + 191 · (2ᵏˡʰ / 32) + 63 · (2ˢˡʰ / 64)      -- 0 for an absent table
```

(the cycle budget, plus the Poseidon2 absorb surcharge — the accumulator charges `+2` on every
absorb row beyond its cycle, and a tier holds up to `2^(t−3)` permutation slots (the Poseidon2
*table's* own capacity, `Tier::poseidon2_height(t) = 2^(t+2)` rows at `BLOCK = 32` rows per
permutation — `crates/randprotocol-zkvm/src/machine.rs`'s `Tier::for_workload`, ZH1 — not a
cpu-row count), so a run can exceed the plain cycle budget by up to `2·2^(t−3) = 2^(t−2)` — plus
the weight of every keccak permutation and sha256 compression the declared tables could hold).
Declaring `GAS_LIMIT = gas_max`
leaks exactly what the header leaks today and costs the most; declaring the count to the cycle
leaks the count and costs the least. The wallet's default (§9) rounds up to a quarter-tier, two
bits more than today. A
`GAS_LIMIT > gas_max` is refused before any verification work: it could only be a mispriced
header.

### 3.3 The fee

For a `Call`:

```
fee ≥ BUNDLE_BASE                                   -- the fee bundle's own verify, unchanged
    + GAS_PRICE · GAS_LIMIT                         -- the instructions, at the declared bound
    + BYTE_PRICE · ⌈(len(call proof) + len(input envelope)) / 1024⌉   -- from byte 0
```

with

| constant | value | in RAND | replaces |
|---|---|---|---|
| `GAS_PRICE` | 100 units per gas | 10⁻⁷ RAND | `CALL_PER_TIER_STEP` (removed) |
| `BYTE_PRICE` | 800 units per KiB | 8 · 10⁻⁷ RAND | `CALL_BASE` and `CALL_FREE_BYTES` (removed): a bare 1.25 MB proof is ~1 000 000 units, so a keccak-free call's byte term is today's `CALL_BASE` |
| `BUNDLE_BASE` | 1 000 000 units | 0.001 RAND | unchanged |

Both prices are genesis fields (`gas.gas_price`, `gas.byte_price`, defaults above), like the
call-limits caps; a chain without the section runs today's schedule byte for byte.

Calibration, all with the 0.001 RAND bundle base included:

| call | gas | bytes | today | this model: base + bytes + gas |
|---|---|---|---|---|
| tier-10 `fib`-sized, 1 000 gas, no hash table | 1 000 | 1.30 MB (1 270 KiB) | 0.0020 RAND | 0.0010 + 0.0010 + 0.0001 = **0.0021 RAND** |
| tier-14 program, 20 479 gas (`gas_max(14,0,0)`), no hash table | 20 479 | 1.35 MB | 0.0022 | 0.0010 + 0.0011 + 0.0020 = **0.0041** |
| tier-14 EVM ERC-20 transfer, 40 000 cycles + 40 keccak | 47 680 | 3.2 MB (needs `max_proof_bytes` raised) | 0.0022 + 0.0011 bytes = 0.0033 | 0.0010 + 0.0025 + 0.0048 = **0.0083** |
| tier-20, a full trace | 1 310 719 | 1.45 MB | 0.0025 | 0.0010 + 0.0011 + 0.1311 = **0.133** |
| tier-10, 200 gas, tightly declared | 200 | 1.30 MB | 0.0020 | 0.0010 + 0.0010 + 0.00002 = **0.0020** |

The small call pays what it pays today (the byte term is the old base under another name); the
big one pays forty times more; the tightly declared one saves nothing today because the bytes
dominate — which is the honest answer at tier 10, where the proof's 1.3 MB *is* the cost. The
gas term overtakes the byte term at about 10 000 gas.
The prices are testnet policy knobs, not security bounds (the call-limits spec's rule for
`CALL_PER_KIB`), and §7 says how they move.

### 3.4 Where the fee goes

Unchanged: the whole fee is credited to the proposer's `rewards`, as today. Burning the gas
term instead (the `registration_fee` precedent, TOK-2) is the alternative, on the argument that
the proposer did none of the per-instruction work; §13 leaves it open because it adds a supply
counter and an audit line for a policy question.

## 4. How the chain learns the gas

### 4.1 Phase 0 — from the header, no fork

Everything a proof declares is already a bound the prover chose: the tier bounds cycles at
`2ᵗ − 1`, `keccak_log_height` bounds permutations at `2ᵏˡʰ / 32`, `sha256_log_height` bounds
compressions at `2ˢˡʰ / 64`. So a node can charge today, on any chain, at `gas_max(header)`
(§3.2) with the same schedule:

```
fee ≥ max( BUNDLE_BASE + call_fee(t, bytes),                            -- the ledger's rule
           BUNDLE_BASE + GAS_PRICE · gas_max(header) + BYTE_PRICE · KiB )
```

(the `max` because the old schedule's byte term, 1 000 per KiB past 2 MiB, is the higher floor
for a proof of many MiB, and a policy may never demand less than the validity rule). The prices
are the node's `--gas-price` / `--byte-price` (defaults §3.3; both `0` = no policy), announced by
`rand_getLimits`. It is a smoother tier fee, not per-instruction — the bound is still a power of two — but it
already removes the regression of §1 (tier 20 pays 0.133 RAND, not 0.0025) and prices a keccak
table by its declared size. It is **admission policy above the ledger's rule**, the LEDGER-1
pattern: the ledger keeps today's `call_fee` floor as the validity rule (it is replayed, so it
cannot move without a cut), and the pool and the proposer demand the higher floor
(`TxError::FeeTooLow`, non-permanent → Ignore). It rolls one node at a time, and a fleet that
disagrees on it disagrees only about what to admit, never about what a block may contain.
Wallets read it from `rand_getLimits` (§9).

### 4.2 Phase 1 — the in-circuit meter, chain 18's constraint set

One column, one public value, two constraints in the cpu table:

- `GAS`: the accumulator. On every real row `GAS' = GAS + w(row)` with
  `w = 1 + 2·IS_HASH_BLOCK + 191·SYS_KECCAK + 63·SYS_SHA256`, where `IS_HASH_BLOCK` marks the
  first cpu row of each Poseidon2 permutation (the existing hash-row flags give it), and every
  weight is a constant, so the transition stays degree 1. `GAS = 0` on the entry row.
- On the `HALT` row, `GAS_LIMIT − GAS` is range-checked into `[0, 2ᵗ⁺⁸)` through the existing
  range table (the +8 bits admit the keccak weight: no run at tier `t` spends `192 · 2ᵗ` or
  more), which proves `GAS ≤ GAS_LIMIT`; the `GAS_LIMIT ≤ gas_max(header)` check outside the
  circuit keeps the difference inside that range.
- `GAS_LIMIT` is `pv::GAS`, the 35th public value.

The meter is exact per instruction — a `KECCAK` row adds 192 because that is what the circuit
sees on that row — and no new witness enters: everything it reads is already a column. Every
verifier key changes (the cpu AIR changes), which is why it rides chain 18's constraint set and
not a same-chain update. The rVM's aggregate interface grows
with it: `[vk ‖ N ‖ B(8) ‖ 35·N]` (was `34·N`), and the recursion verifier program takes the new
width — the aggregate program digest changes, as it did for AGG-2.

The ledger rule (`Ledger::validate_inner`'s call arm, where `call_fee` is charged today): after
`verify_call` returns the outcome, `fee ≥ BUNDLE_BASE + GAS_PRICE · outcome.gas_limit +
BYTE_PRICE · KiB`, with `outcome.gas_limit` read from the proof's public values. The pre-verify
floor stays `BUNDLE_BASE + GAS_PRICE · 1 + BYTE_PRICE · KiB` — the bytes are known before any
verification work, and they are what keeps a verify from being bought for nothing (the byte
term replaces `CALL_BASE` in that role too).

### 4.3 The bundle and every other action: flat, by construction

The bundle guest's `hc` is pinned in genesis and its shape is fixed; its gas is whatever that
guest spends, and the ledger must never let it vary on chain. Rule: **a bundle proof's
`GAS_LIMIT` must equal the genesis constant `bundle_gas_limit`** (`gas_max(14, 0, 0) = 20 479` for
today's tier-14 guest), exactly, or the proof is refused. Every bundle then publishes the same
value and the per-instruction schedule collapses to the flat `BUNDLE_BASE` it has today: a fixed
price is the right price for a fixed program. The same holds for the aggregate (rVM) proof and
for every bundle-less action; nothing outside `Call` changes.

## 5. Privacy

What a call proof leaks today: the tier, the six declared heights (`docs/03-privacy.md`'s
"What a proof leaks"). This adds `GAS_LIMIT`, an upper bound on the cycle count chosen by the
prover. Consequences, stated plainly:

- **The sender decides.** The wallet's default rounds the emulator's exact count up to the next
  multiple of `2ᵗ⁻²` (four buckets per tier): two bits beyond the tier. `--gas-limit` overrides
  in either direction; `--gas-limit max` declares `gas_max(header)` and leaks nothing new.
- **A data-dependent program leaks through its count.** A program whose cycle count depends on
  its private input (a loop over a secret length) reveals up to the bucket; a program that
  wants no leak pads its own loop or declares `max`. This is the same class of leak the tier
  already is, at a finer grain the sender controls.
- **The bundle leaks nothing new** (§4.3): its declared value is a chain constant.
- **LogUp totals (#52, INT-2)** are the larger leak on the same proof and are what constraint
  set 7 is for; `GAS` is one more column under the same blinding.

## 6. Deploy, calls to large programs, and the caps

- **Deploy** stays `BUNDLE_BASE + DEPLOY_PER_WORD · (words + public)`: it prices state growth,
  which gas does not.
- **Program size is metered per call anyway**, through the digest rows: a 4 000-word program
  costs ~1 000 gas per call (0.0001 RAND) before its first instruction. That is a real cost the
  prover pays and the schedule now shows it; an author who wants cheap calls keeps the program
  small.
- **Every cap is unchanged**: `MAX_CALL_TIER` 14, the hash-table height caps, `max_proof_bytes`,
  `max_call_envelope_bytes`. A call over a cap is refused before any key is built, as today;
  gas never admits what a cap refuses.

## 7. The fee market, and moving the prices

Today's mempool orders by total fee; the block cap is bytes. With gas in the floor, the sort
key becomes **the fee above the floor, per KiB** — bytes are the scarce thing
(`docs/block-space.md` §3), so a sender bidding for block space bids per byte, and the gas term
is not a bid but a cost. Governance stays first; ties fall to total fee, then hash. The floor is
the one the transaction was admitted against, recorded in the pool entry. Changing
`candidates_within`'s sort key is node policy (Phase 0).

Fixed prices first. When blocks fill, the standard second step is a per-block base price that
tracks fullness. That is **Phase 2**, cut with chain 18 beside Phase 1 (the user's ruling,
2026-09-28), and §7.1 is its rule.

### 7.1 Phase 2 — the dynamic prices (chain 18)

Genesis `gas.dynamic` (optional inside the `gas` section; absent = the fixed prices of §3.3):

```json
"gas": { "gas_price": "100", "byte_price": "800", "bundle_gas_limit": 16383, "metering": "circuit",
         "dynamic": { "target_block_bytes": 2097152, "target_block_gas": 262144,
                      "adjust_bps": 1250, "min_gas_price": "100", "min_byte_price": "800" } }
```

- **State.** The ledger holds `GasPrices { gas_price, byte_price }`, starting at the section's
  two prices, persisted beside `META_SUPPLY` (`META_GAS_PRICES`), replay-audited, and folded
  into the state root last under `rand-state-7` only when `dynamic` is present (the vesting
  pattern: absent = the root is unchanged).
- **The rule that prices a block** uses the prices in force at the block's start, i.e. the
  parent's closing state: a call's floor is `BUNDLE_BASE + gas_price·GAS_LIMIT + byte_price·KiB`
  at those prices; a bundle's floor stays `BUNDLE_BASE` (§4.3).
- **The update**, in `close_block`, after the block's transactions and before the root, from
  the block's `bytes_used` (Σ `tx.encoded_len()`) and `gas_used` (Σ `GAS_LIMIT` of every call
  proof plus `bundle_gas_limit` per bundle proof), in integer arithmetic (u128, floor division):

  ```
  price' = max(min_price, price + price · adjust_bps · (used − target) / (10 000 · target))
  ```

  applied to `byte_price` with `bytes_used`/`target_block_bytes` and to `gas_price` with
  `gas_used`/`target_block_gas`. An empty block lowers each price by `adjust_bps/10 000` (12.5 %
  at the default) down to its floor; a block at twice the target raises it by the same; a block
  at the target leaves it. `target_block_bytes` must be ≤ `max_block_bytes`; `adjust_bps` is
  `1..=5000`.
- **The wallet** reads `rand_getLimits` (which serves the tip's current prices under `dynamic`,
  the genesis prices otherwise) and pays the floor at the current prices times
  `(1 + adjust_bps/10 000)`, one step of headroom, so a block that raises the price before the
  transaction lands still admits it; `--fee` overrides. `rand_status` reports `gas_prices`.
- **What it is not:** no burn (the fee still goes to the proposer, §3.4), no per-transaction
  priority fee field (the bid is the fee above the floor, §7), no change to the bundle's flat
  base.

## 8. Interactions

- **Delegated proving** (§5 of that spec): `prover_info.fee` becomes a quote **per gas** plus
  a flat part, and the prover measures the job by running the emulator on the witness before
  proving — it learns the exact count (it holds the witness anyway) and charges its own price
  for the padded rows. Nothing on chain couples the two prices.
- **Aggregation**: the aggregate's proving share is collected from the covered bundles' excess
  (`docs/aggregation.md`), and bundles have a fixed gas, so nothing changes. If calls are ever
  covered, the aggregator's per-inner-proof cost (5.68 M rVM rows per inner proof at M5.1) is
  per proof, not per gas — a flat per-cover share stays right.
- **The EVM and sBPF interpreters**: the meter counts their RV32 cycles. An interpreted
  contract's price is the interpreter's efficiency; the translators (`docs/translators.md`)
  exist to bring that down. The interpreter's own gas/compute-unit counter stays private.
- **`rand_getLimits`** grows `gas_price`, `byte_price`, `bundle_gas_limit` and `gas_metering`
  (`"header"` for Phase 0, `"circuit"` for Phase 1, absent on a chain running the old
  schedule), so a wallet knows which floor to compute.

## 9. Wallet, CLI, RPC

- The wallet already runs `emulator::run` before proving (it has to pick the tier); the run's
  `CycleEvent`s give the exact gas by §3.1's table. `rand call` prints
  `gas: 38 412 (declaring 40 960, tier 16)` and the fee it implies before proving, and refuses
  to prove a call whose declared limit the emulator's run exceeds.
- `rand fee call --gas <n> --bytes <b>` replaces `rand fee call <tier>`; `rand fee call --tier
  <t>` keeps working as "gas = `gas_max` of a hash-free tier-`t` header".
- `rand call --gas-limit <n|max>`; `--fee` above the floor is the bid (§7).
- `rand_estimateGas` is deliberately absent: the node has no program input and no emulator
  role; estimation is the wallet's, with the witness.

## 10. Testing

Phase 0 (fullnode): `gas::call_fee_hdr` unit tests pinning the table in §4.1 at every tier and
both hash tables absent/present/at cap; a ledger test that a tier-20 header must pay the
tier-20 floor and a tier-10 one only its own; the schedule table of §3.3 as a known-answer
test; `rand fee call` output pinned.

Phase 1 (circuits, then vendored): the cheating suite gains a row-splice witness that declares
`GAS_LIMIT` below the run's gas (refused), one that skips the accumulator on a keccak row
(refused), and the honest boundary `GAS = GAS_LIMIT` (accepted); a measurement that the extra
column changes proof size by under 1 % and prove time within noise. Fullnode: the bundle
`GAS_LIMIT` pin (`a_bundle_declaring_any_other_gas_limit_is_refused`), the call floor read from
`pv::GAS`, the aggregate interface at 35 words reproduced against the circuits' conformance
vectors, and the wallet's rounding default (`the_wallet_declares_a_quarter_tier_bucket`).

## 11. Rollout

1. **Phase 0** ships as a node release on the running chain: the new floor is admission
   policy, `rand_getLimits` announces it, wallets that predate it pay the tier schedule and are
   refused by the pool with the new floor named (`TxError::FeeTooLow`, non-permanent). Roll the
   wallet release first, the node one a week later.
2. **Phase 1** is cut with chain 18's constraint set: the genesis carries `gas`
   (`gas_price`, `byte_price`, `bundle_gas_limit`, `metering: "circuit"`), the vendored zkVM at
   the set-7 pin, the re-measured aggregate program digest. Every wallet re-proves against the
   new keys, as at every constraint set.

Rollback for Phase 0 is a node re-pin; for Phase 1 it is the chain's, like every set.

## 12. Rejected

- **A per-opcode price table** (Ethereum's): the trace is uniform, so every RV32IM opcode costs
  the same row, and a table that says otherwise would price nothing real. The only non-uniform
  costs are the four syscalls, which §3.1 prices.
- **Publishing the exact cycle count** and refunding the difference: it reveals the count of
  every call and, for the bundle, the number of real slots. The limit-without-refund is the
  whole privacy design.
- **Charging the bundle per gas**: a wallet could declare a tight limit and leak its transfer
  shape for a discount of at most 0.0009 RAND. Pinned instead (§4.3).
- **A block gas limit**: the block is bounded by bytes and by the verify count, and gas bounds
  neither. It would become one only if nodes ever executed, which the design forbids.
- **Making the key-build cost a fee**: it is bounded by the caps and amortised by the cache;
  a fee cannot bound a memory spike, and DS-3 already does.
- **Waiting for Phase 1 before charging anything**: §4.1 costs a constant and a release and
  removes the 700× regression today.

## 13. Open questions

1. Proposer credit or burn for the gas term (§3.4)? Burn needs a `gas_burned` supply counter
   and an audit line; credit needs nothing.
2. The constants: `GAS_PRICE` at 10⁻⁷ RAND makes a full tier-20 call ~0.13 RAND. Is that the
   intended ceiling for an interpreted SPL call, or should the price be tiered by 10× above
   `2¹⁶` gas?
3. Should `bundle_gas_limit` be the guest's measured maximum (9 160 → 9 216) rather than the
   tier's `20 479`, to make a future smaller bundle guest cheaper? Either is a constant; the
   tier's is the one that never needs re-measuring.
4. Resolved by the user: Phase 1 is the chain 18 cut. Constraint set 7's LogUp blinding ships on
   chain 16 ahead of it.
