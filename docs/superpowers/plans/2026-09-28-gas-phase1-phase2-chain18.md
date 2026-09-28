# Gas Phase 1 + Phase 2 (chain 18) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A call pays for the instructions it executed, at a limit the sender declares and the circuit proves the run stayed under (Phase 1), at prices that track block fullness (Phase 2) — both switched on by the chain 18 genesis.

**Architecture:** Part A is constraint set 8 in `circuits`: one accumulator column `GAS` in the cpu AIR weighted per row kind, a 35th public value `GAS_LIMIT`, a halt-row range check `GAS ≤ GAS_LIMIT`, a native `GAS_LIMIT ≤ gas_max(header)` check, a `ProveOptions.gas_limit`, and the rVM interface at `35·N`. Part B is the fullnode: the re-vendor, a `CallOutcome.gas_limit`, a genesis `gas` section that makes the floor `BUNDLE_BASE + gas_price·GAS_LIMIT + byte_price·KiB` a validity rule, the bundle's pinned limit, the wallet's `--gas-limit`, and (Phase 2) `GasPrices` as ledger state updated in `close_block` by the spec §7.1 controller, persisted and folded into the state root. Part C cuts chain 18.

**Tech Stack:** Rust; `circuits/research` (Plonky3 AIRs, the symbolic-constraint harness in `tests/common`), `circuits/recursion` (the rVM), fullnode workspace (`randprotocol-core/-zkvm/-rvm/-node/-client`), `deploy/sync-zkvm.sh` for vendoring, clap, serde_json.

**Spec:** `docs/superpowers/specs/2026-09-28-gas-model-design.md` — §3.1 the schedule, §3.2 the declared limit, §4.2 the meter, §4.3 the bundle pin, §5 privacy, §7.1 Phase 2, §8 interactions, §9 wallet, §10 testing, §11 rollout. Phase 0 (v0.6.4, plan `2026-09-28-gas-phase0-v0.6.4.md`) is assumed merged: `gas::gas_max`, `GasPolicy`, `CallOutcome.{keccak,sha256}_log_height`, `admission::call_floor`, the client's `ChainLimits` prices.

## Global Constraints

- Circuit base: the `circuits` commit chain 16's build vendors (`b9ffc39` on `origin/feat/cs7`; `origin/main` once cs7 merges). Part A is **constraint set 8**: every verifier key changes, so it ships only with the chain 18 cut, never as a same-chain release. Branch `feat/cs8-gas` in `circuits`, `feat/gas-chain18` in fullnode (off the v0.6.4 tag).
- Weights, verbatim from the spec: every cpu row 1 gas; a `POSEIDON2` absorb row (`IS_HASH`) +2; a `KECCAK` row (`SYS_KECCAK`) +191; a `SHA256` row (`SYS_SHA256`) +63 (so `KECCAK_GAS = 192`, `SHA256_GAS = 64`, an absorb row 3). Digest rows (program, input, public) are real rows and count 1 each.
- `pv::GAS = 34`, `pv::NUM = 35`. `GAS_LIMIT` is canonical (`< Val::ORDER`), `≤ gas_max(tier, keccak_log_height, sha256_log_height)` (native, `check_public_values`), and `≥` the run's gas (in-circuit, halt row, four RANGE8 limbs: `GAS_LIMIT − GAS < 2^32`; the largest possible gas is `192·2^20 < 2^28`).
- `gas_max(t, klh, slh) = (2^t − 1) + 2^(t−2) + 191·(2^klh/32) + 63·(2^slh/64)` (corrected by a controller ruling from the constraint-set-8 final review, `randprotocol-core::gas::gas_max`): the `2^(t−2)` term is the Poseidon2 absorb surcharge — every absorb row beyond its cycle costs `+2` (this file's weight line above), bounded by the Poseidon2 *table's* own capacity of `2^(t−3)` permutation slots (`Tier::poseidon2_height(t) = 2^(t+2)` rows at `BLOCK = 32` rows per permutation, `research/src/machine.rs`'s `Tier::for_workload`, ZH1), not a cpu-row count. Hash-free ceilings this plan's literals use: tier 10 → 1 279, 14 → 20 479, 20 → 1 310 719.
- The library default `gas_limit` is `gas_max(header)` (leaks nothing new); the wallet's default is the exact gas rounded up to the next multiple of `2^(t−2)` (spec §5); `--gas-limit max` = `gas_max(header)`. **No refund, ever.**
- The bundle guest's `GAS_LIMIT` must equal genesis `gas.bundle_gas_limit` exactly (`20 479` = `gas_max(14, 0, 0)` for the v2 guest, which declares no hash table). The v2 guest's prover passes no limit, so the library default already yields exactly that.
- Under the genesis `gas` section a call's floor is `BUNDLE_BASE + gas_price·GAS_LIMIT + byte_price·⌈bytes/1024⌉` — a validity rule replacing `call_fee`'s tier floor on that chain; every other action keeps `fee_floor`. `FeeTooLow` stays non-permanent; `BundleGasLimit` is permanent.
- Phase 2 (`gas.dynamic`) uses the parent block's closing prices to price a block and updates them in `close_block` by `price' = max(min_price, price + price·adjust_bps·(used − target)/(10 000·target))` in u128 floor division; `adjust_bps ∈ 1..=5000`; `target_block_bytes ≤ max_block_bytes`. Prices are ledger state, persisted beside `META_SUPPLY`, replay-audited, and folded into the state root under `rand-state-7` **only when `dynamic` is present**.
- Amounts on the wire are decimal strings (`gas_price`, `byte_price`, `min_*`); heights and limits are numbers.
- Never `cargo fmt` either repo. Every fix red-first with the red quoted in the commit. No vendored fullnode file is hand-edited: circuits first, then `deploy/sync-zkvm.sh`. The `circuits` working tree at `/Users/dendisuhubdy/Github/randprotocol/circuits` is another session's: work in a fresh worktree (`git worktree add /private/tmp/circuits-cs8 -b feat/cs8-gas <base>`), and point the fullnode worktree's `../circuits` at it (`/tmp/circuits` symlink) for path deps.
- Recursion-heavy tests need `RECURSION_FIXTURES` and ≥ 64 GB; measure on the testbox (`206.189.41.202`, chain-16 memory) or a droplet, never assume the laptop.

## Review Focus

1. A proof whose `GAS_LIMIT` is below the run's gas by exactly 1 must fail verification (the halt-row range limbs cannot represent −1): Task A3's `a_limit_one_below_the_run_is_refused`.
2. A proof whose trace skips the `+191` on a keccak row (forged `GAS` column) must fail the transition constraint: A3's `a_keccak_row_that_pays_one_gas_is_refused`.
3. A `GAS_LIMIT` above `gas_max(header)` (a mispriced header) must be refused natively before any key is built: A1's `a_limit_above_the_header_ceiling_is_refused`.
4. A bundle proof under the `gas` section with `GAS_LIMIT ≠ bundle_gas_limit` — even by +1, even paying more — must be refused permanently: B3's `a_bundle_declaring_any_other_gas_limit_is_refused`.
5. Phase 2 replay: applying the same block from the same parent state on two nodes must yield identical `GasPrices` and state roots, including at the price floor and at saturation: B6's `the_controller_is_deterministic_and_floored`.

---

## Part A — circuits: constraint set 8

### Task A1: `pv::GAS`, `gas_max`, and the native ceiling check

**Files:**
- Create: `research/src/gas.rs` (weights, `gas_max`, `gas_of`)
- Modify: `research/src/lib.rs` (`pub mod gas;`), `research/src/tables/cpu.rs` (`pv`, `public_values`), `research/src/machine.rs` (`check_public_values`, `build_traces_salted`'s `public_values(...)` call)
- Test: `research/tests/gas.rs` (new)

**Interfaces:**
- Produces: `pub const KECCAK_GAS: u64 = 192; SHA256_GAS: u64 = 64; POSEIDON2_ABSORB_GAS: u64 = 3;` `pub fn gas_max(tier: Tier, keccak_log_height: u8, sha256_log_height: u8) -> u64`; `pv::GAS = PUB0 + 8` (34), `pv::NUM = GAS + 1` (35); `public_values(pc_entry, tier_log2, outputs, hc, hin, hpub, gas_limit: u64)`; `VerifyError::GasLimit`.

- [ ] **Step 1: Write the failing tests** (`research/tests/gas.rs`)

```rust
mod common;
use rand_zkvm::gas::{gas_max, KECCAK_GAS, POSEIDON2_ABSORB_GAS, SHA256_GAS};
use rand_zkvm::machine::{check_public_values, Tier, VerifyError};
use rand_zkvm::tables::cpu::pv;

#[test]
fn the_public_value_layout_gains_gas_limit_last() {
    assert_eq!(pv::GAS, 34);
    assert_eq!(pv::NUM, 35);
    assert_eq!((KECCAK_GAS, SHA256_GAS, POSEIDON2_ABSORB_GAS), (192, 64, 3));
}

#[test]
fn gas_max_is_the_headers_ceiling() {
    assert_eq!(gas_max(Tier(10), 0, 0), 1_279);
    assert_eq!(gas_max(Tier(10), 5, 0), 1_279 + 191);
    assert_eq!(gas_max(Tier(10), 0, 6), 1_279 + 63);
    assert_eq!(gas_max(Tier(14), 12, 13), 20_479 + 128 * 191 + 128 * 63);
    assert_eq!(gas_max(Tier(20), 20, 20), 1_310_719 + 32_768 * 191 + 16_384 * 63);
}

/// Review focus 3: a limit past the header's ceiling is refused natively, before any key.
#[test]
fn a_limit_above_the_header_ceiling_is_refused() {
    let (p, proof) = common::fib_proof_tier_10();   // the helper the executor tests use for a real tier-10 proof
    let hc = p.digest();
    assert_eq!(check_public_values(&hc, &proof), Ok(()));
    let mut over = proof.clone();
    over.public_values[pv::GAS] = gas_max(Tier(10), 0, 0) + 1;
    assert_eq!(check_public_values(&hc, &over), Err(VerifyError::GasLimit));
    let mut non_canonical = proof.clone();
    non_canonical.public_values[pv::GAS] = u64::MAX;
    assert_eq!(check_public_values(&hc, &non_canonical), Err(VerifyError::PublicValues));
}
```

If `tests/common` has no `fib_proof_tier_10`, add one there proving `guests::fib` at `Tier(10)` with `Machine::test_profile()` (the profile `tests/executor.rs` uses) and returning `(Program, Proof)`.

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --release --test gas` (in `research/`)
Expected: compile error, `no module gas` / `no field GAS`.

- [ ] **Step 3: Implement**

`research/src/gas.rs`:

```rust
//! Constraint set 8: what a run costs in gas (fullnode spec 2026-09-28 §3.1). One cpu row is one
//! gas; a `POSEIDON2` absorb row pulls one 32-row permutation into the poseidon2 table (+2); a
//! `KECCAK` row pulls 32 rows of 2 612 columns and 100 memory rows (+191); a `SHA256` row 64 rows
//! of 466 columns (+63). The cpu AIR accumulates exactly these weights in its `GAS` column.
use crate::machine::Tier;

pub const KECCAK_GAS: u64 = 192;
pub const SHA256_GAS: u64 = 64;
pub const POSEIDON2_ABSORB_GAS: u64 = 3;

/// The gas no run under this header can exceed: the tier's cycle budget plus the weight of
/// every permutation (`2^klh / 32`) and compression (`2^slh / 64`) the declared tables could
/// hold. `0` = no such table. The verifier refuses a `GAS_LIMIT` above it.
pub fn gas_max(tier: Tier, keccak_log_height: u8, sha256_log_height: u8) -> u64 {
    let cycles = (1u64 << tier.0) - 1;
    let blocks = |h: u8, block: u64| if h == 0 { 0 } else { (1u64 << h.min(40)) / block };
    cycles + blocks(keccak_log_height, 32) * (KECCAK_GAS - 1) + blocks(sha256_log_height, 64) * (SHA256_GAS - 1)
}
```

`tables/cpu.rs` `pv`: `pub const GAS: usize = PUB0 + 8; pub const NUM: usize = GAS + 1; // 35`. `public_values` gains a final `gas_limit: u64` and pushes `F::from_u64(gas_limit)`. `machine.rs` `build_traces_salted` passes `opts.gas_limit.unwrap_or_else(|| gas_max(tier, keccak_log_height, sha256_log_height))` — until Task A4 adds the option, pass `gas_max(...)` directly. `check_public_values`, after the tier echo:

```rust
    // Constraint set 8: the declared gas limit is canonical (checked above) and never past what
    // the header itself allows — a larger value could only be a mispriced header.
    if proof.public_values[pv::GAS] > crate::gas::gas_max(proof.tier, proof.keccak_log_height, proof.sha256_log_height) {
        return Err(VerifyError::GasLimit);
    }
```

Add `GasLimit` to `VerifyError`.

- [ ] **Step 4: Run**

Run: `cargo test --release --test gas && cargo test --release --test zk --test cheating -- --skip measure`
Expected: `gas` passes; the existing suites still pass (a public value was appended; no constraint reads it yet). Any test that pins `pv::NUM == 34` or a public-value vector length is updated in this task and named in the commit.

- [ ] **Step 5: Commit**

```bash
git add research/src/gas.rs research/src/lib.rs research/src/tables/cpu.rs research/src/machine.rs research/tests/gas.rs research/tests/common
git commit -m "cs8: pv::GAS — a 35th public value, the header's gas ceiling, the native check (spec 2026-09-28 §3.2)"
```

---

### Task A2: `gas_of` — the native meter over an execution

**Files:**
- Modify: `research/src/gas.rs`, `research/src/emulator.rs` (if `HashRow` does not expose its kind)
- Test: `research/tests/gas.rs`

**Interfaces:**
- Produces: `pub fn gas_of(program: &Program, inputs: &[u32], public: &[u32], events: &[CycleEvent]) -> u64` — the digest rows (`program.digest_rows()`, `hash::input_digest_row_count(inputs)`, `hash::public_digest_row_count(public)`) at 1 each, then per event `1 + 2·[absorb row] + 191·[Syscall::Keccak] + 63·[Syscall::Sha256]`.

- [ ] **Step 1: Write the failing tests**

```rust
use rand_zkvm::asm::{ops::*, Assembler};
use rand_zkvm::emulator::execute;
use rand_zkvm::gas::gas_of;

#[test]
fn gas_of_counts_rows_and_syscall_weights() {
    // A hash-free program: gas = digest rows + cycles.
    let mut a = Assembler::new(0);
    a.push(addi(5, 0, 7)); a.push(addi(6, 5, 1)); a.extend(halt());
    let p = a.assemble();
    let e = execute(&p, &[], &[], 1_000).unwrap();
    let digest_rows = p.digest_rows() + rand_zkvm::hash::input_digest_row_count(&[]) + rand_zkvm::hash::public_digest_row_count(&[]);
    assert_eq!(gas_of(&p, &[], &[], &e.events), (digest_rows + e.events.len()) as u64);
    // One KECCAK call adds 191 beyond its row.
    let k = rand_zkvm::guests::compiled::keccak256();
    let ek = execute(&k.program, &k.inputs_for_one_permutation(), &[], 100_000).unwrap();
    let perms = ek.events.iter().filter(|ev| matches!(ev.sys, Some(rand_zkvm::emulator::Syscall::Keccak { .. }))).count() as u64;
    assert!(perms >= 1);
    let rows = (k.program.digest_rows() + rand_zkvm::hash::input_digest_row_count(&k.inputs_for_one_permutation()) + rand_zkvm::hash::public_digest_row_count(&[]) + ek.events.len()) as u64;
    assert_eq!(gas_of(&k.program, &k.inputs_for_one_permutation(), &[], &ek.events), rows + perms * 191 + poseidon2_absorb_rows(&ek.events) * 2);
}
```

(`poseidon2_absorb_rows` counts events whose `hash_row` is an absorb row; use whatever the keccak guest fixture is actually named in `guests.rs` — the test's shape is what matters.)

- [ ] **Step 2: Run to see it fail**

Run: `cargo test --release --test gas gas_of`
Expected: compile error, `gas_of` not found.

- [ ] **Step 3: Implement** (`gas.rs`)

```rust
use crate::emulator::{CycleEvent, Syscall};
use crate::isa::Program;

/// The gas the cpu AIR's `GAS` column accumulates for this execution: the digest prefix rows
/// (program, input, public — real rows, one gas each), then every cycle at its row weight.
pub fn gas_of(program: &Program, inputs: &[u32], public: &[u32], events: &[CycleEvent]) -> u64 {
    let prefix = program.digest_rows() + crate::hash::input_digest_row_count(inputs) + crate::hash::public_digest_row_count(public);
    prefix as u64 + events.iter().map(row_gas).sum::<u64>()
}

/// One cycle's weight (spec §3.1): a row is 1; an absorb row of a `POSEIDON2` group adds 2
/// (its permutation); a `KECCAK` row adds `KECCAK_GAS − 1`; a `SHA256` row `SHA256_GAS − 1`.
pub fn row_gas(ev: &CycleEvent) -> u64 {
    1 + match ev.sys {
        Some(Syscall::Keccak { .. }) => KECCAK_GAS - 1,
        Some(Syscall::Sha256 { .. }) => SHA256_GAS - 1,
        _ => 0,
    } + if ev.hash_row.as_ref().is_some_and(|h| h.is_absorb()) { POSEIDON2_ABSORB_GAS - 1 } else { 0 }
}
```

If `HashRow` has no `is_absorb()`, add it in `emulator.rs` from the row kind it already records (absorb rows are the ones the cpu fill marks `IS_HASH`; write-back rows are `IS_HASH_OUT`).

- [ ] **Step 4: Run** — `cargo test --release --test gas` — Expected: pass.
- [ ] **Step 5: Commit** — `git commit -m "cs8: gas_of — the native meter, one weight per row kind"`

---

### Task A3: The `GAS` column and its constraints

**Files:**
- Modify: `research/src/tables/cpu.rs` (columns `GAS`, `GD0..GD3`; `eval`; `cpu_trace`), `research/src/machine.rs` (`build_traces_salted` passes `gas_limit` into `cpu_trace`; `ProveError::GasLimitBelowRun`, `GasLimitAboveHeader`)
- Test: `research/tests/gas.rs`, `research/tests/cheating.rs`

**Interfaces:**
- Produces: `col::GAS`, `col::GD0..GD3` (after the last existing column; `WIDTH += 5`); `cpu_trace(…, gas_limit: u64, …)`; the three constraints below.

- [ ] **Step 1: Write the failing tests**

In `tests/gas.rs`:

```rust
/// A real proof's GAS_LIMIT is the header ceiling by default, and verifies.
#[test]
fn a_default_proof_declares_the_ceiling_and_verifies() {
    let (p, proof) = common::fib_proof_tier_10();
    assert_eq!(proof.public_values[pv::GAS], gas_max(Tier(10), proof.keccak_log_height, proof.sha256_log_height));
    let m = rand_zkvm::machine::Machine::test_profile();
    assert!(m.verify(&p.digest(), &proof).is_ok());
}

/// Review focus 1: the honest boundary GAS == GAS_LIMIT verifies; one below does not.
#[test]
fn a_limit_one_below_the_run_is_refused() {
    let m = rand_zkvm::machine::Machine::test_profile();
    let p = rand_zkvm::guests::fib(20);
    let e = execute(&p, &[], &[], 10_000).unwrap();
    let gas = gas_of(&p, &[], &[], &e.events);
    let exact = m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions { gas_limit: Some(gas), ..Default::default() }).unwrap().0;
    assert_eq!(exact.public_values[pv::GAS], gas);
    assert!(m.verify(&p.digest(), &exact).is_ok(), "GAS == GAS_LIMIT is honest");
    let below = m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions { gas_limit: Some(gas - 1), ..Default::default() });
    assert!(matches!(below, Err(ProveError::GasLimitBelowRun { .. })), "the prover refuses before building traces");
    // A forged public value under an honest trace: the halt row's limbs cannot represent −1.
    let mut forged = exact.clone();
    forged.public_values[pv::GAS] = gas - 1;
    assert!(m.verify(&p.digest(), &forged).is_err());
}
```

(Task A4 adds `ProveOptions.gas_limit`; write this test now and let A3 land with the prove path taking a `gas_limit` through `build_traces_salted`'s existing options plumbing — if `ProveOptions` cannot carry it yet, the test compiles in A4 and A3's red is the cheating test below.)

In `tests/cheating.rs`, the row-forgery test in the file's existing style (`prove_traces` over a mutated `Traces`, then `verify` must fail):

```rust
/// Review focus 2 (cs8): a KECCAK row that pays one gas instead of 192 breaks the GAS chain.
#[test]
fn a_keccak_row_that_pays_one_gas_is_refused() {
    let m = Machine::test_profile();
    let (p, inputs) = keccak_one_permutation_fixture();          // the keccak fixture cheating.rs already uses
    let e = execute(&p, &inputs, &[], 100_000).unwrap();
    let mut t = build_traces_salted(&p, &inputs, &[], [0; 4], &e, Tier(12)).unwrap();
    let w = cpu::col::WIDTH;
    let rows = t.cpu.height();
    // Find the KECCAK row and lower every later GAS value by 191, keeping the chain consistent
    // everywhere but on that row's transition.
    let k = (0..rows).find(|r| t.cpu.values[r * w + cpu::col::SYS_KECCAK] == Val::ONE).expect("a keccak row");
    for r in k..rows { t.cpu.values[r * w + cpu::col::GAS] -= Val::from_u64(191); }
    // Re-derive the halt row's limbs so the only broken constraint is the transition at k−1→k.
    let halt = (0..rows).find(|r| t.cpu.values[r * w + cpu::col::SYS_HALT] == Val::ONE).unwrap();
    let diff = t.public_values[pv::GAS] - t.cpu.values[halt * w + cpu::col::GAS];
    for j in 0..4 { t.cpu.values[halt * w + cpu::col::GD0 + j] = Val::from_u64((diff.as_canonical_u64() >> (8 * j)) & 0xff); }
    let proof = m.prove_traces(&p, &t, Tier(12));
    assert!(m.verify(&p.digest(), &proof).is_err());
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --release --test gas --test cheating -- gas keccak_row`
Expected: compile errors (`col::GAS`), or the forged proof verifying.

- [ ] **Step 3: Implement**

`cpu.rs` columns, after the last existing column (`JALR_B0` at cs7; check the tree):

```rust
    /// Constraint set 8: the gas accumulated through this row (spec 2026-09-28 §4.2) —
    /// `GAS = 1` on row 0 (a digest row), then `+1 + 2·IS_HASH + 191·SYS_KECCAK + 63·SYS_SHA256`
    /// per real row. Read once, on the `HALT` row, against `pv::GAS`.
    pub const GAS: usize = JALR_B0 + 1;
    /// The four byte limbs of `pv::GAS − GAS` on the `HALT` row (RANGE8-checked, zero elsewhere):
    /// they prove `GAS ≤ GAS_LIMIT` without publishing `GAS`.
    pub const GD0: usize = GAS + 1;
    pub const WIDTH: usize = GD0 + 4;
```

`eval`, in the first-row block: `f.assert_eq(v(GAS), one.clone());`. In the transition block:

```rust
            // cs8: the gas chain. The next row's weight is a constant per row kind, so this is
            // degree 2 (n(IS_REAL) times a linear form in next-row selectors).
            let w_next = one.clone()
                + AB::Expr::from_u32(2) * n(IS_HASH)
                + AB::Expr::from_u32(191) * n(SYS_KECCAK)
                + AB::Expr::from_u32(63) * n(SYS_SHA256);
            t.assert_zero(n(IS_REAL) * (n(GAS) - v(GAS) - w_next));
```

After the selector block, the halt-row check and the limbs' gating:

```rust
        // cs8: on the HALT row, `pv::GAS − GAS` is the four RANGE8 limbs GD0..3 — so the limit is
        // at or above the run's gas, and the run's gas itself stays private. Off the HALT row the
        // limbs are zero (no lookup, no freedom).
        let gd = v(GD0) + c8(1) * v(GD0 + 1) + c8(2) * v(GD0 + 2) + c8(3) * v(GD0 + 3);
        b.assert_zero(v(SYS_HALT) * (pvs[pv::GAS].clone() - v(GAS) - gd));
        for k in 0..4 {
            b.assert_zero((one.clone() - v(SYS_HALT)) * v(GD0 + k));
            bus::RANGE8.lookup_key(b, [v(GD0 + k)], Count::bounded(v(SYS_HALT), 1));
        }
```

`cpu_trace(program, inputs, public, salt, events, height, gas_limit: u64, range, nibble)`: keep a running `gas` — set `r[GAS]` on every digest row (`gas += 1`) and every event row (`gas += row_gas(e)` from `crate::gas::row_gas`), and on the halt row fill `GD0..3` from `gas_limit − gas` (`range.range8` each limb). `build_traces_salted` takes `gas_limit`, and before any trace: `let gas = gas_of(program, inputs, public, &exec.events); if gas_limit < gas { return Err(ProveError::GasLimitBelowRun { gas, limit: gas_limit }); } if gas_limit > gas_max(tier, klh, slh) { return Err(ProveError::GasLimitAboveHeader { .. }); }`, and passes `gas_limit` to both `cpu_trace` and `public_values`.

- [ ] **Step 4: Run**

Run: `cargo test --release --test gas --test cheating --test zk --test e2e -- --skip measure` (e2e is ~7 min; the tier-16 EVM proof is the slow one) and `cargo test --release --test tables`.
Expected: everything passes; the two new refusals refuse. Record in the commit body the proof-size delta of `tests/e2e.rs::measure_production_profile_at_tier_10_and_12` run `--ignored` (expected: five columns ≈ +0.3 % of a 1.3 MB proof).

- [ ] **Step 5: Commit** — `git commit -m "cs8: the GAS column — a per-row-kind accumulator, GAS ≤ GAS_LIMIT on the halt row (spec §4.2)"`

---

### Task A4: `ProveOptions.gas_limit`

**Files:**
- Modify: `research/src/machine.rs` (`ProveOptions`, `prove_salted_with`, `build_traces_salted`)
- Test: `research/tests/gas.rs` (A3's `a_limit_one_below_the_run_is_refused` now compiles and passes)

- [ ] **Step 1: Failing test** — the A3 test above, plus:

```rust
#[test]
fn the_default_limit_is_the_ceiling_and_the_option_can_go_below() {
    let m = Machine::test_profile();
    let p = rand_zkvm::guests::fib(20);
    let e = execute(&p, &[], &[], 10_000).unwrap();
    let gas = gas_of(&p, &[], &[], &e.events);
    let dflt = m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions::default()).unwrap().0;
    assert_eq!(dflt.public_values[pv::GAS], gas_max(Tier(10), dflt.keccak_log_height, dflt.sha256_log_height));
    let tight = m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions { gas_limit: Some(gas + 5), ..Default::default() }).unwrap().0;
    assert_eq!(tight.public_values[pv::GAS], gas + 5);
    assert!(m.verify(&p.digest(), &tight).is_ok());
    assert!(matches!(
        m.prove_with_options(&p, &[], &[], Some(Tier(10)), ProveOptions { gas_limit: Some(u64::MAX), ..Default::default() }),
        Err(ProveError::GasLimitAboveHeader { .. })
    ));
}
```

- [ ] **Step 2: Run** — `cargo test --release --test gas` — Expected: compile error on `gas_limit`.
- [ ] **Step 3: Implement** — `ProveOptions` gains `/// cs8: the GAS_LIMIT to declare; None = gas_max(header) (spec §5: leaks nothing new). pub gas_limit: Option<u64>,` (keep `Default`). `prove_salted_with` resolves it after the tier and the declared heights are known and passes it to `build_traces_salted`. Note in the doc comment that HCS-3's floor-declared hash tables raise `gas_max` by `4·191 + 2·63` and therefore the *default* limit — a caller that wants the price of its actual work passes the exact gas.
- [ ] **Step 4: Run** — `cargo test --release --test gas` — Expected: pass.
- [ ] **Step 5: Commit** — `git commit -m "cs8: ProveOptions.gas_limit — declare less than the ceiling, never less than the run"`

---

### Task A5: Keys, measurements, docs

**Files:**
- Modify: `research/tests/verifier_key.rs` (re-pin the known answers), `research/docs/02-tables-and-buses.md` (the cpu row-kind table: `GAS`, `GD0..3`), `research/docs/03-privacy.md` ("What a proof leaks": `GAS_LIMIT`, the sender's bucket), `research/docs/05-roadmap.md` (a "Constraint set 8" entry: what it carries, the measured deltas), `research/docs/01-isa.md` (gas per syscall column in the syscall table)

- [ ] **Step 1:** Run `cargo test --release --test verifier_key` — Expected: FAIL (every key digest changed). Re-pin from the output; the commit body lists old → new per tier.
- [ ] **Step 2:** Run `--ignored` `measure_production_profile_at_tier_10_and_12` and the prove-time measurement the docs cite; write the numbers into 05-roadmap's cs8 entry (proof bytes before/after, prove time before/after).
- [ ] **Step 3:** Docs as listed. In 03-privacy: "`GAS_LIMIT` leaks an upper bound on the cycle count the prover chose; the default is the header's ceiling (nothing new); a bucket leaks `log2(bucket)` fewer bits than the count."
- [ ] **Step 4: Commit** — `git commit -m "cs8: re-pinned verifier keys, measured deltas, docs"`

---

### Task A6: Recursion — the 35-word interface and the aggregate program

**Files:**
- Modify: `recursion/src/programs/rv32.rs` (only if a public-value count is hard-coded — `grep -n "34" recursion/src/programs/*.rs recursion/src/*.rs`), `recursion/src/public_values.rs` (doc: `pv::NUM = 35`), `recursion/docs/02-aggregate.md` (the conformance vectors), `recursion/tests/aggregate.rs` (re-pinned digests)
- Test: `recursion/tests/aggregate.rs`, the `two_test_profile` round trip

- [ ] **Step 1:** `cargo test --release -p rand-rvm --test aggregate -- --skip round_trips --skip two_test_profile` with `RECURSION_FIXTURES` pointing at a cache **regenerated on cs8** (the old fixtures' inner proofs no longer verify: their keys changed). Expected first run: the interface digest pins fail (35 words per inner proof now).
- [ ] **Step 2:** Re-pin the conformance vectors and the aggregate program digest; the commit body carries old → new. The rv32 aggregate program itself reads `shape.num_public_values()`, so it needs no change unless Step 1's grep finds a literal.
- [ ] **Step 3:** On the ≥ 64 GB box, `two_test_profile` (the tier-19 round trip, ~30 min): the N-generic program's row count moves by the 35th word's absorb; record it.
- [ ] **Step 4: Commit** — `git commit -m "cs8: the aggregate interface carries 35 public values per inner proof; vectors re-pinned"`

Part A ends with `circuits` tagged for the fullnode to vendor (`cs8-<sha>`); nothing here is deployable on its own.

---

## Part B — fullnode: the genesis `gas` section, Phase 1 rules, Phase 2 prices

### Task B1: Re-vendor at constraint set 8; `CallOutcome.gas_limit`; the stub proofs carry a limit

**Files:**
- Run: `deploy/sync-zkvm.sh` (both sections at the cs8 pin; `RVM_SRC` too), then `cargo check --workspace --tests`
- Modify: `crates/randprotocol-core/src/types/mod.rs` (`pv::GAS`, `NUM = 35`), `crates/randprotocol-core/src/gas.rs` (`MAX_AGGREGATE_BYTES` in terms of `pv::NUM`), `crates/randprotocol-core/src/program.rs` (`CallOutcome.gas_limit: u64`), `crates/randprotocol-core/src/confidential.rs` (trait: `fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> { Ok(None) }`; the stub proof formats gain an 8-byte little-endian `gas_limit` at the end — `STUB_LEN += 8`, `STUB_BUNDLE_LEN += 8`; `make_proof*` default it to `gas::gas_max(tier, 0, 0)`, `make_bundle_proof` to `20_479`; new `make_proof_with_gas(program, tier, outputs, gas_limit)` and `with_bundle_gas(proof: &mut Vec<u8>, gas_limit: u64)`), `crates/randprotocol-zkvm/src/executor.rs` (`ZkExecutor::verify_call`/`decode_call*` fill `gas_limit` from `pv::GAS`; `bundle_gas_limit` decodes and returns `Some(pv[GAS])`), `crates/randprotocol-node/src/agg_executor.rs` (same two)
- Test: `crates/randprotocol-zkvm/src/executor.rs`'s mirror-pin test (`pv` mirror == real: extend to `GAS`/`NUM`), `crates/randprotocol-zkvm/tests/executor.rs` (a real proof's `gas_limit == gas_max`), `confidential.rs` tests (the stub's limit round-trips; `bundle_gas_limit` of a stub bundle is `Some(20_479)`)

- [ ] **Step 1: Failing tests**

```rust
// zkvm/src/executor.rs mirror test — extend:
assert_eq!(randprotocol_core::types::pv::GAS, pv::GAS);
assert_eq!(randprotocol_core::types::pv::NUM, pv::NUM);
// zkvm/tests/executor.rs, the fib call test:
assert_eq!(out.gas_limit, randprotocol_core::gas::gas_max(out.tier, out.keccak_log_height, out.sha256_log_height));
// core/confidential.rs tests:
let p = StubExecutor::make_proof_with_gas(&id, 12, [1; 8], 777);
assert_eq!(StubExecutor.verify_call(&rec, &p).unwrap().gas_limit, 777);
let mut b = StubExecutor::make_bundle_proof(&hc, &digest, &binding);
assert_eq!(StubExecutor.bundle_gas_limit(&b).unwrap(), Some(20_479));
StubExecutor::with_bundle_gas(&mut b, 16_384);
assert_eq!(StubExecutor.bundle_gas_limit(&b).unwrap(), Some(16_384));
```

- [ ] **Step 2:** `cargo test -p randprotocol-core --lib confidential` — Expected: compile errors.
- [ ] **Step 3: Implement** as listed. The sync script's header records the cs8 pin and that `executor.rs`/`hidden.rs`/`guests.rs` stay excluded. `StubExecutor::bound` (which re-binds a stub bundle proof to `tx.binding()`) must preserve the trailing gas bytes.
- [ ] **Step 4:** `cargo test -p randprotocol-core --release --lib && cargo test --release -p randprotocol-zkvm --test executor -- --skip measure && cargo check --workspace --tests --release` — Expected: green. **Every existing test that builds a stub proof by hand** (byte slicing) is updated in this task; list them in the commit.
- [ ] **Step 5: Commit** — `git commit -m "zkvm, rvm: re-vendor constraint set 8 (circuits <sha>); CallOutcome.gas_limit; the stub proofs carry a limit"`

---

### Task B2: The genesis `gas` section

**Files:**
- Modify: `crates/randprotocol-core/src/genesis.rs` (`Genesis.gas: Option<GasConfig>`, `validate`, `hash`, `to_json`/`from_json`, the ledger construction), `crates/randprotocol-core/src/gas.rs` (`GasConfig`, `GasMetering`, `DynamicGas`), `crates/randprotocol-core/src/ledger/mod.rs` (`gas: Option<GasConfig>`, `gas()`, `set_gas()`), `crates/randprotocol-node/src/main.rs` (`genesis --gas-price <UNITS> --byte-price <UNITS> --bundle-gas-limit <N> [--gas-dynamic <target_bytes>,<target_gas>,<adjust_bps>]`; `init` prints the section)
- Test: `genesis.rs` tests, `main.rs` tests

**Interfaces:**
- Produces:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasConfig {
    #[serde(with = "crate::genesis::decimal_u64")] pub gas_price: u64,
    #[serde(with = "crate::genesis::decimal_u64")] pub byte_price: u64,
    pub bundle_gas_limit: u64,
    pub metering: GasMetering,             // only `Circuit` is valid
    #[serde(default, skip_serializing_if = "Option::is_none")] pub dynamic: Option<DynamicGas>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")] pub enum GasMetering { Circuit }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicGas {
    pub target_block_bytes: u64, pub target_block_gas: u64, pub adjust_bps: u32,
    #[serde(with = "…decimal_u64")] pub min_gas_price: u64,
    #[serde(with = "…decimal_u64")] pub min_byte_price: u64,
}
```

(reuse the decimal-string serde helper `staking.faucet_budget_per_epoch` uses.)

- [ ] **Step 1: Failing tests** (`genesis.rs`, beside `hardening_v6_is_bound_into_the_hash_only_when_true`)

```rust
#[test]
fn the_gas_section_is_bound_into_the_hash_only_when_present() {
    let plain = fixtures::genesis_file();
    assert!(plain.gas.is_none() && !plain.to_json().contains("\"gas\""));
    let h0 = plain.hash();
    let mut g = plain.clone();
    g.gas = Some(GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: GasMetering::Circuit, dynamic: None });
    assert_ne!(g.hash(), h0);
    let s = g.clone().into_state().unwrap();
    assert_eq!(s.ledger.gas().unwrap().gas_price, 100);
    assert!(g.to_json().contains("\"gas_price\": \"100\""), "amounts are decimal strings");
    let mut d = g.clone();
    d.gas.as_mut().unwrap().dynamic = Some(DynamicGas { target_block_bytes: 2 << 20, target_block_gas: 1 << 18, adjust_bps: 1250, min_gas_price: 100, min_byte_price: 800 });
    assert_ne!(d.hash(), g.hash(), "dynamic is bound under its own tag");
    assert_eq!(Genesis::from_json(&d.to_json()).unwrap(), d, "round-trips");
}

#[test]
fn the_gas_section_is_validated() {
    let mut g = fixtures::genesis_file();
    let ok = GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: GasMetering::Circuit, dynamic: None };
    g.gas = Some(GasConfig { gas_price: 0, ..ok.clone() });
    assert!(g.validate().unwrap_err().contains("gas_price"));
    g.gas = Some(GasConfig { bundle_gas_limit: 0, ..ok.clone() });
    assert!(g.validate().unwrap_err().contains("bundle_gas_limit"));
    let bad_dyn = |d: DynamicGas| { let mut g = g.clone(); g.gas = Some(GasConfig { dynamic: Some(d), ..ok.clone() }); g.validate().unwrap_err() };
    let d = DynamicGas { target_block_bytes: 2 << 20, target_block_gas: 1 << 18, adjust_bps: 1250, min_gas_price: 100, min_byte_price: 800 };
    assert!(bad_dyn(DynamicGas { adjust_bps: 0, ..d.clone() }).contains("adjust_bps"));
    assert!(bad_dyn(DynamicGas { adjust_bps: 5001, ..d.clone() }).contains("adjust_bps"));
    assert!(bad_dyn(DynamicGas { target_block_bytes: (64 << 20) + 1, ..d.clone() }).contains("target_block_bytes"));
    assert!(bad_dyn(DynamicGas { target_block_gas: 0, ..d.clone() }).contains("target_block_gas"));
    assert!(bad_dyn(DynamicGas { min_gas_price: 101, ..d.clone() }).contains("min_gas_price"), "the floor cannot exceed the starting price");
}
```

- [ ] **Step 2:** `cargo test -p randprotocol-core --lib genesis::tests::the_gas_section` — Expected: compile errors.
- [ ] **Step 3: Implement.** Hash, after `hardening_v6`'s block, the same shape:

```rust
        if let Some(g) = &self.gas {
            commit.extend_from_slice(b"gas");
            commit.extend_from_slice(&g.gas_price.to_le_bytes());
            commit.extend_from_slice(&g.byte_price.to_le_bytes());
            commit.extend_from_slice(&g.bundle_gas_limit.to_le_bytes());
            commit.extend_from_slice(b"circuit");
            if let Some(d) = &g.dynamic {
                commit.extend_from_slice(b"gas_dynamic");
                for x in [d.target_block_bytes, d.target_block_gas, d.adjust_bps as u64, d.min_gas_price, d.min_byte_price] {
                    commit.extend_from_slice(&x.to_le_bytes());
                }
            }
        }
```

`validate`: prices `> 0`, `bundle_gas_limit ≥ 1`, `dynamic`: `1 ≤ adjust_bps ≤ 5000`, `target_block_bytes ≤ self.max_block_bytes.unwrap_or(gas::MAX_BLOCK_BYTES)` and `> 0`, `target_block_gas > 0`, `min_* ≤ the starting price`. The ledger gets `set_gas(Some(g.clone()))` at construction. `rand-node genesis`: the four flags, written only when `--gas-price` is given (the default file has no section — chain 16/17 shape). `init` prints `gas: price 100/gas, 800/KiB, bundle limit 20479, dynamic: …`.
- [ ] **Step 4:** `cargo test -p randprotocol-core --lib genesis && cargo test -p randprotocol-node --bin rand-node` — Expected: pass.
- [ ] **Step 5: Commit** — `git commit -m "genesis: the gas section — prices, the bundle's limit, circuit metering, the dynamic controller's parameters (spec §4.2, §7.1)"`

---

### Task B3: The validity rules — the call floor and the bundle pin

**Files:**
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (step 10's call arm; `check_bundle_proof`), `crates/randprotocol-core/src/gas.rs` (`pub fn circuit_call_floor(gas_price, byte_price, gas_limit, bytes) -> u64`), `crates/randprotocol-core/src/types/mod.rs` or wherever `TxError` lives (`BundleGasLimit { want: u64, got: Option<u64> }`), `crates/randprotocol-node/src/admission.rs` (`is_permanent`: `BundleGasLimit` is permanent; `call_floor` under `ledger.gas()` returns the ledger rule's floor)
- Test: `ledger/mod.rs` tests (the `ledger_with_program`/`call_tx` helpers), `admission.rs` tests

- [ ] **Step 1: Failing tests** (`ledger/mod.rs`)

```rust
    fn gas_ledger() -> (Ledger, ProgramId) {
        ledger_with_program(|l| l.set_gas(Some(gas::GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: gas::GasMetering::Circuit, dynamic: None })))
    }

    /// Spec §4.2: under the section a call pays gas_price·GAS_LIMIT + byte_price·KiB over the
    /// base — the declared limit, not the tier — and the old tier floor no longer applies.
    #[test]
    fn under_the_gas_section_a_call_pays_its_declared_limit() {
        let (l, id) = gas_ledger();
        let proof = StubExecutor::make_proof_with_gas(&id, 12, [7; 8], 3_000);
        let kib = proof.len().div_ceil(1024) as u64;
        let floor = gas::BUNDLE_BASE + 100 * 3_000 + 800 * kib;
        assert!(floor < gas::BUNDLE_BASE + gas::call_fee(12, proof.len()), "cheaper than the tier floor for a small declared limit");
        let short = call_tx(&l, 20, id, proof.clone(), floor - 1);
        assert_eq!(l.validate(&short, &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
        let paid = call_tx(&l, 30, id, proof, floor);
        assert!(l.validate(&paid, &StubExecutor).is_ok());
        // A limit of gas_max at tier 20 with the same bytes costs ~0.13 RAND more.
        let big = StubExecutor::make_proof_with_gas(&id, 14, [7; 8], 1_310_719);
        let kib = big.len().div_ceil(1024) as u64;
        let floor = gas::BUNDLE_BASE + 100 * 1_310_719 + 800 * kib;
        assert_eq!(l.validate(&call_tx(&l, 40, id, big, floor - 1), &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
    }

    /// Review focus 4 (spec §4.3): every bundle proof declares exactly `bundle_gas_limit`.
    #[test]
    fn a_bundle_declaring_any_other_gas_limit_is_refused() {
        let (l, _) = gas_ledger();
        let ok = bundle_tx_fixture(&l, 50);                          // whatever helper builds a plain transfer here
        assert!(l.validate(&ok, &StubExecutor).is_ok());
        for other in [20_478u64, 20_480, 1] {
            let mut tx = ok.clone();
            StubExecutor::with_bundle_gas(&mut tx.bundle.as_mut().unwrap().proof, other);
            let tx = StubExecutor::bound(tx);
            assert_eq!(l.validate(&tx, &StubExecutor), Err(TxError::BundleGasLimit { want: 20_479, got: Some(other) }), "{other}");
        }
        // Without the section any limit is accepted (chains 16/17).
        let (plain, _) = ledger_with_program(|_| {});
        let mut tx = bundle_tx_fixture(&plain, 60);
        StubExecutor::with_bundle_gas(&mut tx.bundle.as_mut().unwrap().proof, 1);
        assert!(plain.validate(&StubExecutor::bound(tx), &StubExecutor).is_ok());
    }
```

- [ ] **Step 2:** `cargo test -p randprotocol-core --lib ledger::tests -- gas_section bundle_declaring` — Expected: compile errors / the tier floor answering.
- [ ] **Step 3: Implement.** In step 10:

```rust
            let bytes = gas::call_bytes(proof, input_envelope.as_ref());
            let min = match self.gas() {
                // cs8 / spec §4.2: the declared limit at the chain's prices (Phase 2: the prices in
                // force at this block's start, `self.gas_prices()`), plus the bytes — the tier floor
                // is gone on such a chain.
                Some(g) => gas::circuit_call_floor(self.gas_prices().gas_price, self.gas_prices().byte_price, outcome.gas_limit, bytes),
                None => gas::BUNDLE_BASE + gas::call_fee(outcome.tier, bytes),
            };
```

(`gas_prices()` is Task B6's; until then return the section's two prices from `gas()` — write it as a method now so B6 only changes its body.) `circuit_call_floor` = `BUNDLE_BASE.saturating_add(gas_price.saturating_mul(gas_limit)).saturating_add(byte_price.saturating_mul(bytes.div_ceil(1024) as u64))`. In `check_bundle_proof`, under `self.gas()`: `let got = executor.bundle_gas_limit(&b.proof)?; if got != Some(g.bundle_gas_limit) { return Err(TxError::BundleGasLimit { want: g.bundle_gas_limit, got }); }` — before the verify (a decode is cheap; a wrong limit must not buy a verify), and on the B5 cache-hit path too. `is_permanent` adds `BundleGasLimit`. `admission::call_floor`: `if let Some(_) = ledger.gas() { return Ok(gas::circuit_call_floor(…)) }` from the decoded outcome — the policy floor IS the rule on such a chain.
- [ ] **Step 4:** `cargo test -p randprotocol-core --release --lib ledger && cargo test -p randprotocol-node --release --lib admission mempool` — Expected: pass.
- [ ] **Step 5: Commit** — `git commit -m "ledger: under the gas section a call pays its declared limit and every bundle declares the pinned one (spec §4.2, §4.3)"`

---

### Task B4: RPC — limits, estimate, status

**Files:**
- Modify: `crates/randprotocol-node/src/rpc.rs` (`ChainLimits`: `bundle_gas_limit: Option<u64>`, `gas_metering: "circuit"` and the chain's prices when the ledger has the section — `ChainLimits::of` reads `ledger.gas()`, and `with_gas_policy` never overrides a chain's own; `rand_estimateFee` call spec gains `gas` (the declared limit): under the section the answer is `circuit_call_floor`), `crates/randprotocol-node/src/node.rs` (a chain with the section ignores `--gas-price/--byte-price` with one warning)
- Test: `rpc.rs` tests (`get_limits_reports_the_chains_limits` on a `gas` genesis; `estimate_fee` with `gas`)

- [ ] **Step 1: Failing tests**

```rust
    #[tokio::test]
    async fn get_limits_serves_the_chains_gas_section() {
        let gs = fixtures::genesis_with(|g| g.gas = Some(gas::GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: gas::GasMetering::Circuit, dynamic: None }));
        let (_d, st) = state_for(&gs);
        let v = ok(&st, "rand_getLimits", json!([])).await;
        assert_eq!(v["gas_price"], "100"); assert_eq!(v["byte_price"], "800");
        assert_eq!(v["bundle_gas_limit"], 20_479); assert_eq!(v["gas_metering"], "circuit");
        let fee = ok(&st, "rand_estimateFee", json!([{"kind": "call", "tier": 12, "bytes": 1_300_000, "gas": 3_000}])).await;
        assert_eq!(fee, gas::circuit_call_floor(100, 800, 3_000, 1_300_000).to_string());
        let e = call(&st, "rand_estimateFee", json!([{"kind": "call", "tier": 12}])).await.unwrap_err();
        assert_eq!(e.code, -32602, "under the section a call estimate needs its gas");
    }
```

- [ ] **Step 2:** run, expect failures. **Step 3:** implement (the `gas` param is required under the section, ignored without it; `null` prices never appear on such a chain). **Step 4:** `cargo test -p randprotocol-node --release --lib rpc` — pass. **Step 5: Commit** — `git commit -m "rpc: rand_getLimits serves the gas section; rand_estimateFee prices a declared limit"`

---

### Task B5: The wallet declares its limit

**Files:**
- Modify: `crates/randprotocol-zkvm/src/executor.rs` (`prove`, `prove_call`, `prove_call_hardened` take `gas_limit: Option<u64>` and pass `ProveOptions { gas_limit, .. }`; `prove_bundle_for` passes `None` — the ceiling, `20_479` for the v2 guest — and asserts the resulting `pv[GAS] == 20_479` in its test), `crates/randprotocol-client/src/wallet.rs` (`pub fn default_gas_limit(exact: u64, tier: u8) -> u64` = round up to a multiple of `2^(t−2)`, capped at `gas_max`; `call_fee_default` under a section: `circuit_call_floor`), `crates/randprotocol-client/src/main.rs` (`rand call --gas-limit <N|max>`; before proving, run the emulator (`executor::dry_run` — the wallet already runs it for the tier), print `gas: <exact> (declaring <limit>, tier t)`; `rand fee call --gas <N>`)
- Test: `wallet.rs` tests, `zkvm/tests/hidden_bundle.rs` (the v2 guest's `GAS_LIMIT` is `20_479`)

- [ ] **Step 1: Failing tests**

```rust
    #[test]
    fn the_wallet_declares_a_quarter_tier_bucket() {
        assert_eq!(default_gas_limit(1, 10), 256);
        assert_eq!(default_gas_limit(256, 10), 256);
        assert_eq!(default_gas_limit(257, 10), 512);
        assert_eq!(default_gas_limit(1_025, 10), 1_279, "capped at the tier's own ceiling: rounding 1 025 up to the next 2^(t−2)=256 block gives 1 280, above gas_max(10,0,0)=1 279");
        assert_eq!(default_gas_limit(38_412, 16), 40_960);
    }
    // hidden_bundle.rs: after `prove_bundle_for(...)`:
    assert_eq!(proof.public_values[pv::GAS], 20_479, "the v2 guest declares exactly the pinned limit");
```

- [ ] **Step 2:** run, expect compile errors. **Step 3:** implement; `rand call` refuses `--gas-limit` below the emulator's exact gas with the exact number in the message, and above `gas_max` with the ceiling. **Step 4:** `cargo test -p randprotocol-client --release --lib && cargo test --release -p randprotocol-zkvm --test hidden_bundle` (proves a bundle: ~100 s). **Step 5: Commit** — `git commit -m "cli: rand call --gas-limit — the quarter-tier default, the exact count printed, the bundle's pinned limit (spec §9)"`

---

### Task B6: Phase 2 — `GasPrices` state and the controller

**Files:**
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (`gas_prices: GasPrices` field; `gas_prices()`/`set_gas_prices()`; `close_block(height, proposer, bytes_used: u64, gas_used: u64)`; `apply_block` sums `bytes_used` (Σ `tx.encoded_len()`) and `gas_used` (Σ call outcomes' `gas_limit` + `bundle_gas_limit` per bundle proof) and passes them; `state_root` folds `gas_prices` under `rand-state-7` when `gas.dynamic` is present), `crates/randprotocol-core/src/gas.rs` (`GasPrices`, `pub fn next_price(price, min, used, target, adjust_bps) -> u64`), `crates/randprotocol-core/src/consensus/hotstuff.rs:1178` and every `close_block` caller (the two args), `crates/randprotocol-node/src/storage.rs` (`META_GAS_PRICES`: written at genesis init, at every commit, restored in `load_ledger`, replay-audited beside `registration_fees_burned` — mirror its five sites)
- Test: `gas.rs` (the controller table), `ledger/mod.rs` (root and replay), `storage.rs` (persist/restore)

- [ ] **Step 1: Failing tests** (`gas.rs`)

```rust
    /// Spec §7.1: price' = max(min, price + price·adjust·(used − target)/(10 000·target)).
    #[test]
    fn the_controller_moves_prices_by_fullness() {
        let t = 2u64 << 20;
        assert_eq!(next_price(800, 800, t, t, 1250), 800, "at target: unchanged");
        assert_eq!(next_price(800, 800, 0, t, 1250), 800, "empty block at the floor stays at the floor");
        assert_eq!(next_price(1_000, 800, 0, t, 1250), 875, "empty block: −12.5 %");
        assert_eq!(next_price(1_000, 800, 2 * t, t, 1250), 1_125, "twice the target: +12.5 %");
        assert_eq!(next_price(1_000, 800, 3 * t, t, 1250), 1_250, "three times the target: +25 % (bytes cannot exceed 2× a half-cap target; gas can)");
        assert_eq!(next_price(u64::MAX, 800, 2 * t, t, 5000), u64::MAX, "saturates");
        assert_eq!(next_price(100, 100, 0, 1 << 18, 1250), 100, "gas: floor holds");
    }
```

(`ledger/mod.rs`)

```rust
    /// Review focus 5: the same block from the same parent gives the same prices and root.
    #[test]
    fn the_controller_is_deterministic_and_floored() {
        let dynamic = gas::DynamicGas { target_block_bytes: 4096, target_block_gas: 20_000, adjust_bps: 1250, min_gas_price: 100, min_byte_price: 800 };
        let (l, id) = ledger_with_program(|l| l.set_gas(Some(gas::GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: gas::GasMetering::Circuit, dynamic: Some(dynamic) })));
        assert_eq!(l.gas_prices(), gas::GasPrices { gas_price: 100, byte_price: 800 });
        let r0 = l.state_root();
        let (mut a, mut b) = (l.clone(), l.clone());
        let proof = StubExecutor::make_proof_with_gas(&id, 12, [7; 8], 40_000);
        let kib = proof.len().div_ceil(1024) as u64;
        let tx = call_tx(&l, 20, id, proof, gas::BUNDLE_BASE + 100 * 40_000 + 800 * kib);
        for l in [&mut a, &mut b] {
            l.apply_tx(&tx, &proposer(), &StubExecutor).unwrap();
            l.close_block(1, &proposer(), tx.encoded_len() as u64, 40_000 + 20_479);
        }
        assert_eq!(a.gas_prices(), b.gas_prices());
        assert_eq!(a.state_root(), b.state_root());
        assert_ne!(a.state_root(), r0, "the prices are in the root");
        assert!(a.gas_prices().gas_price > 100, "gas above target raised the gas price");
        // An empty block lowers each price toward its floor and never below.
        for h in 2..40 { a.close_block(h, &proposer(), 0, 0); }
        assert_eq!(a.gas_prices(), gas::GasPrices { gas_price: 100, byte_price: 800 });
        // A chain without `dynamic` never moves and keeps rand-state-6's root shape.
        let (fixed, _) = ledger_with_program(|l| l.set_gas(Some(gas::GasConfig { dynamic: None, ..l.gas().cloned().unwrap_or_default() })));
        let r = fixed.state_root();
        let mut f = fixed.clone();
        f.close_block(1, &proposer(), 1 << 30, 1 << 30);
        assert_eq!(f.gas_prices(), gas::GasPrices { gas_price: 100, byte_price: 800 });
        assert_eq!(f.state_root(), r, "without `dynamic` the prices are not in the root and never move");
    }
```

- [ ] **Step 2:** run, expect compile errors. **Step 3: Implement.**

```rust
/// Spec §7.1's controller, in u128 floor arithmetic, saturating, never below `min`.
pub fn next_price(price: u64, min: u64, used: u64, target: u64, adjust_bps: u32) -> u64 {
    let target = target.max(1) as i128;
    let delta = (price as i128) * (adjust_bps as i128) * (used as i128 - target) / (10_000 * target);
    let next = (price as i128).saturating_add(delta).clamp(0, u64::MAX as i128) as u64;
    next.max(min)
}
```

`close_block`: after `sweep_expired_excesses` and before `record_anchor`: `if let Some(d) = self.gas().and_then(|g| g.dynamic.as_ref()) { self.gas_prices = GasPrices { gas_price: next_price(p.gas_price, d.min_gas_price, gas_used, d.target_block_gas, d.adjust_bps), byte_price: next_price(p.byte_price, d.min_byte_price, bytes_used, d.target_block_bytes, d.adjust_bps) }; }`. `gas_prices()` returns the field (initialised from the section at `set_gas`). `state_root`: when `dynamic` is present, append `gas_price ‖ byte_price` (LE) to the vesting-domained buffer and re-domain `rand-state-7` — read `state_root`'s vesting branch and follow its shape exactly. Storage: `META_GAS_PRICES` at the five `registration_fees_burned` sites (`init_genesis`, the commit batch, `load_ledger`, the replay audit's comparison, the repair path).
- [ ] **Step 4:** `cargo test -p randprotocol-core --release --lib && cargo test -p randprotocol-node --release --lib storage` — Expected: pass; the consensus tests' `close_block` calls updated with `(0, 0)` where they build empty blocks.
- [ ] **Step 5: Commit** — `git commit -m "ledger: Phase 2 — GasPrices under the state root, moved per block by fullness (spec §7.1)"`

---

### Task B7: Phase 2 — the tip's prices on the RPC and the wallet's headroom

**Files:**
- Modify: `crates/randprotocol-node/src/rpc.rs` (`rand_getLimits` under `dynamic` reads the tip ledger's `gas_prices()` through the node command channel — the path `rand_status` uses — and `rand_status` gains `gas_prices: { gas_price, byte_price }` as strings), `crates/randprotocol-client/src/lib.rs` (`ChainLimits.adjust_bps: Option<u32>`, served alongside), `crates/randprotocol-client/src/wallet.rs` (`call_fee_default` under `dynamic`: `floor + floor·adjust_bps/10 000`, one step of headroom; `rand call` prints it as `fee … (incl. one price step of headroom)`)
- Test: `rpc.rs` (limits follow a moved tip), `wallet.rs` (headroom)

- [ ] **Step 1: Failing tests** — a `rpc.rs` test that commits one over-target block on a `dynamic` genesis and sees `rand_getLimits.byte_price` rise; a `wallet.rs` test `the_wallet_pays_one_price_step_of_headroom_under_dynamic_prices` (`adjust_bps: Some(1250)` → fee = floor·1.125, and none without it).
- [ ] **Step 2–4:** red, implement, `cargo test -p randprotocol-node --release --lib rpc && cargo test -p randprotocol-client --release --lib` green.
- [ ] **Step 5: Commit** — `git commit -m "rpc, cli: the tip's gas prices on rand_getLimits and rand_status; the wallet pays one step of headroom"`

---

### Task B8: Docs and the AGENTS entry

**Files:**
- Modify: `docs/fees.md` (§1.1 becomes "The gas rule" with the declared limit; §1.2 "Dynamic prices"; §5 constants), `docs/confidential.md` ("Constraint set 8": the column, the public value, the measured deltas from A5), `docs/zkvm.md` (§1 the relation gains "…and spent at most `GAS_LIMIT` gas"; §4 syscall table gains a gas column; §8), `docs/rpc.md` (`rand_getLimits` fields, `rand_estimateFee`'s `gas`, `rand_status.gas_prices`, changelog), `docs/cli.md` (`call --gas-limit`, `fee call --gas`, `genesis --gas-*`), `docs/deploy.md` ("The next cut: the gas section" — the JSON of spec §7.1 and what each field does; "chain 18 is all-stop/all-start: every verifier key changes"), `AGENTS.md` (the chain 18 entry, written at the cut with the measured numbers)

- [ ] Write, verify every name against the code, commit: `git commit -m "docs: constraint set 8, the gas section, dynamic prices"`

---

## Part C — the chain 18 cut

### Task C1: `deploy/cut-chain18-genesis.sh` and the cutover

**Files:**
- Create: `deploy/cut-chain18-genesis.sh` from `deploy/cut-chain17-genesis.sh` (delegated proving's; if chain 17 is not cut yet, from `cut-chain16-genesis.sh`): the same snapshot → carry-over of notes, validators, zUSD, bridge state; `rand-node genesis --hardening-v6 --bundle-guest v2 --gas-price 100 --byte-price 800 --bundle-gas-limit 20479 --gas-dynamic 2097152,262144,1250` (the testnet runs the controller; mins = the fixed prices) with the release binary; the `hc_bundle` the binary reports (unchanged by cs8 — the guest's words did not change — but assert it); `Σ notes == Σ locked` and the register checks as before.
- Modify: `deploy/cutover-fleet-chain18.sh` from chain 16's all-stop/all-start script (every proof format changes: no mixed fleet).
- Rollout order (spec §11, and the release-gating rule): tag the fullnode release that carries cs8 (`v0.6.5` unless the line has moved) only after the full suite on the testbox and a final review; **ship the clients (core re-vendored at cs8, `--gas-limit` in the apps) and randscan's `randscan-viewing`/pv decoding before the cut** — a wallet on cs7 can prove nothing chain 18 accepts; then the cut; obs1 first, then the validators, A/D/C bootstraps as in chain 16's runbook.

- [ ] **Step 1:** dry-run the cut script against a chain-17 (or 16) snapshot into a scratch dir; `rand-node init` on the file prints the gas section and hashes.
- [ ] **Step 2:** a three-node local cluster (`tests/cluster.rs`'s harness) on the cut file: a transfer, a call at a tight limit, a call at `max`, a bundle with a forged limit refused — the capstone `a_chain18_genesis_prices_calls_by_their_declared_limit`.
- [ ] **Step 3: Commit** — `git commit -m "deploy: the chain-18 cut — the gas section on, all-stop/all-start"`

Tagging, the roll and the cut itself are the operator's, per `feedback-release-gating` and `feedback-fleet-go-in-executing-session`.

## Open questions carried from the spec (decide before C1)

1. Proposer credit or burn for the gas term (spec §3.4) — this plan keeps credit (no new counter).
2. `bundle_gas_limit` = the tier ceiling (20 479) — chosen here: it never needs re-measuring and the v2 guest's default limit already equals it.
3. Whether chain 18 cuts with `dynamic` on (this plan: yes, on the testnet, with `min_* = the fixed prices`) or fixed first.
