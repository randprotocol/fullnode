# Fee feedback: the burned base and the fee-first subsidy

Branch `feat/fee-feedback` off `main` (2b5490d5). Worktree `~/rand-worktrees/fullnode-fee-feedback`.

## Why

The agent-driven fee study (four mechanisms, one seed, 24 months) found two things the node's
rules do not have and the scripted study already recommended:

1. **A feedback fee whose base is burned.** The node already floats `gas_price`/`byte_price`
   (`docs/fees.md` §1.2) but pays every unit of every fee to the proposer. The study's
   EIP-1559 variant burns the base and tips the rest.
2. **Prover pay funded from fees first, minted only for the shortfall.** Today an aggregate is
   paid `subsidy(sealed_blocks) + proving_shares` — the schedule is minted on top of the fees
   however large the fees are. The study's proving-auction variant pays the target from fees
   first and mints only what is missing.

Both are **genesis-gated consensus rules** that default off, following the exact pattern of
`tokens.burn_registration_fee` (audit v5 TOK-2): absent, the chain is byte-for-byte today's
(genesis hash, state root, storage, RPC values); present and true, the rule applies from block
1. Dollar indexing of prover pay (the study's `$345 per prover-day`) is **out of scope** — it
needs a price oracle the chain does not have.

## Global constraints

- **Off by default, byte-identical when off.** With no `fees` section — or a section with both
  flags absent/false — the genesis hash, the state root, every stored META value, every RPC
  response field that exists today, and every existing test are unchanged. New JSON fields may
  be *added* to `rand_getSupply` / `rand_getLimits` (they are additive today already, e.g.
  `registration_fees_burned`), but no existing value moves.
- **Genesis hash contribution, pinned:** when the section sets at least one flag true, append
  to the genesis commit, after the `tokens` contribution and before anything that follows it in
  `GenesisState::hash` today: `b"fees"`, then `b"burn_base"` ‖ `1u8` if `burn_base == Some(true)`,
  then `b"subsidy_net_of_fees"` ‖ `1u8` if `subsidy_net_of_fees == Some(true)`, in that order.
  A section with no true flag contributes **nothing** (a file may carry `"burn_base": false`
  and hash as if the section were absent). Pin it byte for byte in a test like
  `the_gas_sections_hash_contribution_is_pinned`.
- **The `fees` section** (`GenesisState.fees: Option<FeesConfig>`, serde `default` +
  `skip_serializing_if = "Option::is_none"`), `FeesConfig { burn_base: Option<bool>,
  subsidy_net_of_fees: Option<bool> }`, both fields `default` + `skip_serializing_if`.
  Lives in a new module `crates/randprotocol-core/src/ledger/fees.rs` with a `Default`,
  `burn_base()` / `subsidy_net_of_fees()` accessors returning `bool`. Validation:
  `subsidy_net_of_fees: true` without an `aggregation` section →
  `GenesisError::SubsidyNetOfFeesWithoutAggregation` (new variant, named like
  `DynamicGasWithAggregation`).
- **Ledger carries it** as `Ledger.fees: FeesConfig` (default), `fees()` / `set_fees()`, set by
  genesis exactly where `set_aggregation` / `set_tokens` are set, persisted by the node under a
  new META key `META_FEES = "fees"` as `bincode(FeesConfig)` written wherever `META_AGGREGATION`
  is written at genesis, restored in `reload_ledger` beside `set_aggregation` (absent key →
  `FeesConfig::default()`, so an existing database opens unchanged).
- **Rule 1 — `burn_base`** (in `Ledger::apply_tx_with`, the fee split): every bundle's
  `gas::BUNDLE_BASE` is destroyed instead of paid. Precisely, with `fee` = the bundle fee after
  the TOK-2 registration burn (exactly today's `fee` local):
  - `base = gas::BUNDLE_BASE` (the floor already guarantees `fee ≥ BUNDLE_BASE`; refuse by
    `TxError::FeeTooLow { min: BUNDLE_BASE, fee }` rather than wrap if it ever did not).
  - `supply.burned += base`; a new ledger counter `base_fees_burned += base` (sibling of
    `registration_fees_burned`: same `Ledger` field, getter, setter, `Audit::new` argument —
    extend `Audit::new`'s signature or add `with_base_fees_burned`; on the right of the identity
    beside `registration_fees_burned` in `invariant_holds`; persisted under
    `META_BASE_FEES_BURNED = "base_fees_burned"` wherever `META_REGISTRATION_FEES_BURNED` is
    written/read/compared, including the storage self-check that compares the two ledgers;
    served by `rand_getSupply` as `"base_fees_burned"` decimal string).
  - Non-aggregating chain: the proposer keeps `fee − base` (the tip); `fees_paid` moves by that.
  - Aggregating chain: the proposer keeps `0`; the excess `fee − base` is bucketed exactly as
    today (`bucketed_excess` unchanged) and reaches the aggregator or the sweep as today.
  - **Only `BUNDLE_BASE` is burned, not a Call's gas/byte term or a Deploy's per-word term.**
    Ruling: the base is the one component every bundle pays and the proposer cannot steer; the
    priced terms stay the proposer's so including Calls stays worth its while. Document the
    choice and name the full-floor burn as a follow-up.
  - Withdraws, claims and other register-side bases (`docs/supply.md` "a withdraw's base fee is
    not a crossing") are **not** touched: they never pass the bundle fee split.
- **Rule 2 — `subsidy_net_of_fees`** (in `Ledger::aggregate_payment`): `subsidy =
  gas::subsidy(sealed_blocks, cfg).saturating_sub(proving_shares)`; `total = subsidy +
  proving_shares` (so the aggregator receives `max(schedule, shares)`); `supply.subsidised`
  moves by `payment.subsidy` as today, which is now the minted part only. Admission
  (`validate_aggregate`) and apply derive one note from one state exactly as today — the
  derivation is in one function, change it there only.
- **`rand_getLimits`** gains `"fee_rules": {"burn_base": bool, "subsidy_net_of_fees": bool}`,
  present only when the chain's genesis has a `fees` section (`null`/absent otherwise, like
  `gas_metering`). Wallet defaults do not change: the floors are the same numbers.
- **Docs ride the task.** Every rule change updates `docs/fees.md` (a new §1.3 "The `fees`
  section: a burned base and a fee-first subsidy"), `docs/supply.md` (the `base_fees_burned`
  row and the identity), `docs/aggregation.md` (the payment under the flag), `docs/rpc.md`
  (the two methods' new fields, and its changelog), and `CHANGELOG.md` (an "Unreleased" entry
  at the top: hard fork when a genesis sets a flag, node-only otherwise). `genesis` docs
  (`docs/cli.md` or wherever genesis sections are listed — find it with `rg burn_registration_fee
  docs`) list the section.
- **Tests are TDD, in the existing test modules**, and every test names its rule. Run
  `cargo test -p randprotocol-core` and `cargo test -p randprotocol-node --lib` (the node's
  integration suite is slow; the lib tests cover storage and rpc) before committing. Clippy
  clean: `cargo clippy -p randprotocol-core -p randprotocol-node --all-targets`.
- **Style:** the repository's comment voice (full sentences, a *why* for every rule, audit-style
  cross-references to docs and spec sections). Commit messages like the log's:
  `core, node, docs: fees — <what>`. End commit messages with the attribution line
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- No new dependencies. No changes to the wallet/client crate.

## Task 1: the `fees` section and the burned base

Files: new `crates/randprotocol-core/src/ledger/fees.rs`; `ledger/mod.rs` (field, accessors,
the fee split, the audit); `ledger/supply.rs` (`Audit`); `genesis.rs` (section, validation,
hash, pinned test); `randprotocol-node/src/storage.rs` (two META keys, genesis write, reload,
the self-check); `randprotocol-node/src/rpc.rs` (`rand_getSupply.base_fees_burned`,
`rand_getLimits.fee_rules`); docs as in the constraints.

Tests to write first (names indicative):
1. `genesis`: `a_fees_section_with_no_true_flag_hashes_as_absent`,
   `the_fees_sections_hash_contribution_is_pinned` (exact bytes for `burn_base` alone, for both,
   and for `subsidy_net_of_fees` alone), `subsidy_net_of_fees_requires_an_aggregation_section`,
   round-trip through `to_json`/parse keeps the section and omits it when absent.
2. `ledger`: `burn_base_destroys_the_base_and_tips_the_proposer` — a transfer paying
   `BUNDLE_BASE + 5` under the flag: `burned` up by `BUNDLE_BASE`, `base_fees_burned` up by
   `BUNDLE_BASE`, proposer `rewards` and `fees_paid` up by 5, `audit().invariant_holds()`;
   the same transaction without the flag moves `rewards`/`fees_paid` by `BUNDLE_BASE + 5` and
   `burned` by 0 (the existing behaviour, asserted side by side).
3. `ledger` (aggregating chain, in `aggregation.rs`'s test module, reuse its fixtures):
   `burn_base_on_an_aggregating_chain_buckets_the_excess_and_pays_the_proposer_nothing` — the
   proposer's `rewards` unchanged at inclusion, the bucket holds `fee − BUNDLE_BASE`, the audit
   holds; the sweep and an aggregate still pay the excess as today.
4. `ledger`: TOK-2 and `burn_base` together: a registration under both flags burns
   `registration_fee + BUNDLE_BASE`, both counters move, the audit holds.
5. `storage`: `reload_ledger` restores `fees` and `base_fees_burned`; an old database with
   neither key opens with defaults (delete the keys and reload, like the `META_AGGREGATION`
   test at ~line 7448).
6. `rpc`: `rand_getSupply` reports `base_fees_burned` (`"0"` on a plain chain), `rand_getLimits`
   reports `fee_rules` only on a chain with the section.

## Task 2: the fee-first subsidy

Files: `ledger/aggregation.rs` (`aggregate_payment`), its tests, `docs/aggregation.md`,
`docs/fees.md` §1.3's second half, `CHANGELOG.md` line.

Tests to write first:
1. `subsidy_net_of_fees_mints_only_the_shortfall`: shares below the schedule → `subsidy =
   schedule − shares`, `total = schedule`, `subsidised` up by `schedule − shares`.
2. `subsidy_net_of_fees_mints_nothing_when_shares_cover_the_schedule`: shares ≥ schedule →
   `subsidy = 0`, `total = shares`, `subsidised` unchanged, `sealed_blocks` still up by 1.
3. Without the flag the existing payment tests pass unchanged (they are the control).
4. The admission/apply note identity still holds under the flag (the existing
   `debug_assert_eq!` path exercised by an apply test under the flag).
5. The supply audit holds after an aggregate under the flag (extend the Task 5 audit test).

## Task 3: whole-branch docs pass

Read the diff of the branch and the four docs touched; make `docs/fees.md` §1.3 read as one
section covering both rules with the worked arithmetic (a 0.0012 RAND transfer under
`burn_base`: 0.001 burned, 0.0002 to the proposer; an aggregate with 0.4 RAND of shares against
a 0.6 RAND schedule under `subsidy_net_of_fees`: 0.2 minted, 0.6 paid), the `AGENTS.md` project
memory gets a dated paragraph under "Project memory" naming the branch, the two flags, the
genesis-hash bytes and the META keys. No code changes in this task unless a doc exposes a
contradiction, in which case report it rather than fix it.
