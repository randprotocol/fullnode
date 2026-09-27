# Genesis Vesting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Timelocked RAND allocations at genesis (team / investors / partners): a public vesting register, `ClaimVested` (Action 24) and `RevokeVesting` (Action 25), supply-audited, genesis-gated.

**Architecture:** A new core module `ledger/vesting.rs` owns the register, the schedule function, the two actions' validate/apply and the leaf root; `Genesis` gains an optional `vesting` section seeded into `Ledger::vesting: Option<VestingRegister>`; the state root appends the vesting root under `rand-state-6` only when present. The node persists the register as JSON under `META_VESTING`, screens the two actions in the mempool, and serves them over RPC and the `rand-node vesting` CLI.

**Tech Stack:** Rust workspace (randprotocol-core, randprotocol-node), bincode + serde_json, Dilithium2 (`crypto::PublicKey`), BLAKE3 `merkle_root`.

**Spec:** `docs/superpowers/specs/2026-09-28-genesis-vesting-design.md` (user guide `docs/vesting.md`).

> **Revised during execution (2026-09-28, the SAFT check — spec §2):** the schedule fields are
> `cliff_ms`/`linear_ms`/`step_ms` (linear after the cliff), Task 3 also carries `BondVested` (26) and
> `UnbondVested` (27) for irrevocable entries, Task 4 adds `rand_getVestingSchedule`, and Task 5 has
> no `vesting keygen` (a `rand-node keygen` file is the key). The task list below is the original.

## Global Constraints

- A genesis without `vesting` builds, hashes and roots byte-for-byte as today: `chain_15s_genesis_file_still_builds_chain_15` and `the_genesis_hash_is_pinned` stay green untouched.
- `Supply` is a positional bincode blob: **never add a field to it**. The vesting counters live in `VestingRegister` (JSON on disk, `#[serde(default)]`).
- New `Action` variants are appended after `RotatePauseKey`: `ClaimVested` = 24, `RevokeVesting` = 25.
- Signing domains: `rand-vest-claim-1`, `rand-vest-revoke-1`; leaf domain `rand-vesting-leaf-1`; state domain `rand-state-6`; genesis commit tag `vesting`.
- Both actions pay `gas::BUNDLE_BASE` out of what they release to the proposer, exactly as `Withdraw`; their `time` is held to the bundle window (`check_time`).
- Schedule time = `Ledger::timestamp_ms()` (the applying block's, the head's at admission).
- Every fix/feature test is red first; quote the red in the commit. Never `cargo fmt` the repo.
- Run `cargo check --workspace --tests` after touching `Genesis` or `Action` (a `--lib` gate misses `main.rs` and `tests/`).

## Review Focus

1. A claim admitted against the head but applied after a `RevokeVesting` landed must be refused at apply (frozen total), never over-pay — test in Task 3.
2. A pooled claim whose entry nonce moved on must leave the pool, not fall through to the validator lookup (`UnknownValidator`) — test in Task 4.
3. A restarted node must restore the register (claimed, nonce, revoked) and compute `rand-state-6` — test in Task 4 (storage round trip).
4. A revoke's `unvested` above the true unvested (`u(t)`) is refused; below it, the difference stays with the beneficiary — test in Task 3.
5. `amount` near `u64::MAX` in the schedule must not overflow (u128) — test in Task 1.

---

### Task 1: Core register, schedule, messages

**Files:** Create `crates/randprotocol-core/src/ledger/vesting.rs`; modify `ledger/mod.rs` (declare `pub mod vesting;`), `types/actions.rs` (two message fns).

**Produces:**
- `pub enum Class { Team, Investor, Partner, Other }` (serde lowercase)
- `pub struct VestingEntryConfig { id: [u8;32] (hex), class, beneficiary: PublicKey, revoker: Option<PublicKey>, amount: u64, start_ms, cliff_ms, duration_ms: u64 }` — the genesis form
- `pub struct VestingConfig { entries: Vec<VestingEntryConfig> }`, `fn check(&self) -> Result<u64 /*Σ amount*/, String>`
- `pub struct Entry { class, beneficiary, revoker, amount, start_ms, cliff_ms, duration_ms, claimed, revoked_out, revoked_at: Option<u64>, nonce }`
- `pub struct VestingRegister { entries: BTreeMap<[u8;32], Entry>, released: u64 }` with `from_config`, `root() -> Hash`, `issued()`, `held()`
- `pub fn vested(e: &Entry, t_ms: u64) -> u64`, `pub fn claimable(e, t) -> u64`, `pub fn unvested(e, t) -> u64`
- `pub enum VestingError` (thiserror)
- `actions::claim_vested_message(genesis: &Hash, chain_id, entry: &[u8;32], amount, nonce, to: &ShieldedAddress, time, r, envelope) -> Hash` and `revoke_vesting_message(.., unvested, ..)`

Tests (red first): before cliff 0; at `start+cliff` exact; one ms before; midway; end and after; `amount = u64::MAX` midway (u128); frozen after revoke = `amount − revoked_out`; `check` refuses each bad input (empty, dup id, zero amount, zero duration, cliff > duration, overflow of `start+duration`, wrong key length, beneficiary == revoker, Σ overflow); messages bind every field under distinct domains.

### Task 2: Genesis section, Ledger field, state root, audit

**Files:** `genesis.rs` (field, `GenesisError::BadVesting(String)`, validate, commit tag, build seeding + `SupplyOverflow` on Σ), every `Genesis { .. }` literal (add `vesting: None`), `ledger/mod.rs` (`vesting: Option<VestingRegister>` in struct/new/from_parts/PartialEq, `vesting()`, `set_vesting()`, `vesting_mut()`, state root `rand-state-6`, `audit()` adds vesting), `ledger/supply.rs` (`Audit` gains `vesting_issued`, `vesting_released`, `vesting_held`; `total_supply`/`invariant_holds` include them; `with_vesting(issued, released, held)`).

Tests: a vesting genesis builds, `invariant_holds` at block 0, root domain differs only when section present; the genesis hash differs between files differing only in one entry field; every `BadVesting` reachable through `validate`.

### Task 3: The two actions in the ledger

**Files:** `types/transaction.rs` (variants, `bundle_less`, `blanked`, test tables `VARIANTS` 26/`variant_index`/`sample`/binding mutators), `gas.rs` (`fee_floor` → 0), `ledger/mod.rs` (`TxError::Vesting(#[from] VestingError)`, size cap on envelope, `check_time`, routing in `validate_inner`/`apply_tx_with`), `ledger/vesting.rs` (`validate`, `apply`, `claim_note`, `revoke_note`), `ledger/staking.rs::derived_commitment` (two arms).

Tests: claim exactly claimable accepted, +1 refused `NotYetVested`; wrong key; replayed nonce; `to` changed after signing (signature fails); amount ≤ base; duplicate commitment; no section → `UnsupportedAction("vesting")`; revoke: no revoker, double, fully vested, `unvested > u(t)` refused, `unvested < u(t)` leaves the rest claimable; claim after revoke bounded by frozen total; supply invariant through claim → revoke → claim; the note appended to deposits and base credited to proposer.

### Task 4: Node — storage, reload, mempool, admission, RPC

**Files:** `node/storage.rs` (`META_VESTING` JSON at the three write sites, restored in `load_ledger`, `vesting()` getter, `derived_note_count` → 1 for both, `verify_chain` comparison covers it through `Ledger` equality), `node/node.rs::reload_ledger` (refuse a genesis/storage gate mismatch), `node/mempool.rs` (`claimed_nonce` → `(Address(entry), nonce)`, `claim_key` role 5, `applies`: time window + entry nonce staleness), `node/admission.rs::is_permanent` (bad signature, not revocable, already revoked, unknown entry), `node/rpc.rs` (`tx_json` arms, `rand_getVesting`, `rand_getVestingSummary`, `rand_getSupply` vesting fields).

Tests: storage round trip restores claimed/nonce/revoked and the same state root; mempool drops a claim whose entry nonce moved; `tx_json` renders both kinds; RPC summary sums per class.

### Task 5: CLI

**Files:** `node/main.rs`: `genesis --vesting FILE.json`; `vesting keygen|status|claim|revoke` (claim: `--entry --key --to [--amount|--all]`; revoke: `--entry --key --to [--margin-secs 600]`), both through `submit_staking`.

Tests: the CLI's claim/revoke note is the note the ledger derives (the `the_cli_withdraw_note_is_…` pattern); `--vesting` round-trips a file into the section.

### Task 6: Docs

`docs/vesting.md` status → implemented, `docs/rpc.md` (two methods, supply fields, changelog), `docs/supply.md` (vesting rows), `docs/cli.md` (commands), AGENTS.md project-memory entry.
