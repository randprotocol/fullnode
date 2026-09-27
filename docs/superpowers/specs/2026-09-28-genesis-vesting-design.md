# Genesis vesting: timelocked RAND for the team, investors and founding partners

Status: design approved 2026-09-28 and **revised the same day** after the SAFT check (§2);
implemented on `feat/timelock-genesis` (plan `docs/superpowers/plans/2026-09-28-genesis-vesting.md`).
Targets the genesis cut that carries fundraising allocations (mainnet v1.0), rehearsed first on a
testnet cut. User-facing guide: `docs/vesting.md`.

## 1. Problem

Fundraising allocations — internal team, investors (VCs), founding partners — are issued at genesis
but must not be spendable until they unlock on a schedule. RAND lives as shielded notes: a spend
proof hides which note it consumes and what it is worth, so the ledger cannot enforce a lock on a
note it cannot see. The lock lives where amounts are already public — a register, like the
validator register — and value enters the pool only as it unlocks.

## 2. Decisions

| # | question | ruling |
|---|---|---|
| D1 | where the lock lives | **A public vesting register** seeded at genesis. Each entry's amount and schedule are public; the holder is a key, never a name. Rejected: a timelock inside the note (the SAFT draft's "Time-Locked Notes": a guest change, a tier-14 bundle re-measure, cheating tests, locked supply unauditable); off-chain/legal only. |
| D2 | revocation | **Per entry**: an entry with a `revoker` key is revocable, one without is not. A revoke takes only the *unvested* part. The user first ruled "all revocable"; the SAFT check (below) moved investor and partner allocations to irrevocable, team grants revocable — a genesis-file choice, no code difference. |
| D3 | where revoked RAND goes | A shielded note to the address the revoker names (the treasury), spendable at once. Rejected: burning it. |
| D4 | bonding locked RAND | **Yes, irrevocable entries only** (`BondVested`/`UnbondVested`). The user first ruled "no"; SAFT Schedule 2 §4 promises it and §8 forbids an amendment that "reduce[s] the Investor's ability to Bond locked Tokens". Revocable entries cannot bond, so a revoke never reaches into a validator's stake. |
| D5 | time basis | The applying block's `timestamp_ms`. B2 bounds it (`MAX_TIMESTAMP_STEP_MS` 60 s per block; honest replicas refuse to vote for a block more than 15 s ahead), so a proposer can move an unlock by seconds. The SAFT's height-based unlocks are, by its own text, an estimate of the calendar. |
| D6 | schedule shape | **The SAFT's**: nothing until `start + cliff`, then `linear` *after* the cliff, continuous or in whole `step`s released at the end of each step (a 12-month cliff and 18 monthly steps = tranches at months 13 … 30). The first draft accrued from `start` and would have released 12/30 at the cliff. |

**The SAFT check (2026-09-28).** The SAFT draft (`../termsheets/RAND_SAFT_Institutional_US.md`
§5.3, Schedule 2) and the tokenomics paper (`../tokenomics/rand_tokenomics.tex`, "Lockups as
time-locked shielded notes") specify bondable, non-revocable, in-circuit time-locked notes with an
aggregate, owner-free lockup table. The user chose to keep the register (D1) and meet the SAFT's
substance: D2, D4, D6 and the lockup-table RPC. The one remaining difference — per-entry amounts
public under a key — goes into the Schedule 2 §8 notice (`docs/vesting.md`, "The SAFT's
Schedule 2").

Out of scope (recorded): beneficiary key rotation (a lost key strands the entry); entries created
after genesis; a multi-party revoker (the planned custody hardening); delegation of bonded RAND's
rewards to the holder (rewards are the validator's, as on every bond on this chain).

## 3. Genesis section

`Genesis::vesting: Option<VestingConfig>`, omitted when absent — every chain to date keeps its file,
hash and state roots. Format (amounts as decimal strings, like the staking section's):

```json
"vesting": { "entries": [ {
  "id": "<64 hex>", "class": "team|investor|partner|other",
  "beneficiary": "<Dilithium2 public key, hex>", "revoker": "<optional, hex>",
  "amount": "<units>", "start_ms": 0, "cliff_ms": 0, "linear_ms": 0, "step_ms": 0 } ] }
```

`VestingConfig::check` (→ `GenesisError::BadVesting`): entries non-empty, ids distinct, amount > 0,
`step_ms` (when present) non-zero and dividing a non-zero `linear_ms`, `start + cliff + linear`
fits a u64, both keys `PUBLIC_KEY_LEN`, beneficiary ≠ revoker, Σ amount fits a u64. `build` also
refuses (`SupplyOverflow`) when notes + stakes + the register overflow. The genesis commit appends
tag `vesting`, the count, then every entry in **id order** with fixed-width fields and a presence
byte before each optional one — after every other section.

## 4. The schedule (`ledger::vesting::vested`)

```
vested(e, t) = 0                                    t < start + cliff
             = amount                               t − (start + cliff) ≥ linear
             = ⌊amount · k / linear⌋                otherwise, k = elapsed, or elapsed − elapsed mod step
frozen after a revoke:  vested(e, ·) = amount − revoked_out
claimable(e, t, epoch) = min(vested − claimed, free(epoch))
free(epoch)            = amount − claimed − revoked_out − bonded − Σ unbonding rows not yet released
unvested(e, t)         = amount − vested(e, t)   (0 once revoked)
```

u128 arithmetic; `vested` is monotonic in `t`.

## 5. Ledger state

`ledger/vesting.rs`: `VestingRegister { entries: Vec<Entry> (id order), released: u64 }`, each
`Entry` its genesis terms plus `claimed`, `revoked_out`, `revoked_at`, `bonded`, `bonded_to`,
`unbonding: Vec<(release_epoch, amount)>`, `nonce`. `Ledger::vesting: Option<VestingRegister>`,
inside `Ledger`'s equality. Root: leaves `rand-vesting-leaf-1` over every field, a Merkle root,
then count and `released` under `rand-vesting-root-1`; appended last to the state root, re-domained
**`rand-state-6`**, only under the section. Persisted as JSON under `META_VESTING` at the three
state-write sites; `reload_ledger` refuses a genesis file and database that disagree about having
one.

## 6. Actions (bundle-less, fee-less, `Action` 24–27, all signed over the genesis hash)

| action | signer, domain | rule | effect |
|---|---|---|---|
| `ClaimVested { entry, amount, nonce, to, time, r, envelope, signature }` | beneficiary, `rand-vest-claim-1` | `BUNDLE_BASE < amount ≤ claimable`, `to` a valid address, `time` in the bundle window, the note new | `claimed += amount`; a note of `amount − base` to `to`; the base to the proposer |
| `RevokeVesting { entry, unvested, nonce, to, time, r, envelope, signature }` | revoker, `rand-vest-revoke-1` | revocable, not revoked, `BUNDLE_BASE < unvested ≤ unvested(e, now)` | frozen: `revoked_at`, `revoked_out = unvested`; a note of `unvested − base` to `to`; the base to the proposer |
| `BondVested { entry, validator, amount, registration, nonce, signature }` | beneficiary, `rand-vest-bond-1` | irrevocable, `0 < amount ≤ free`, one validator per entry, the register's own `check_bond` | `ledger.bond(…)` (registration, minimum stake, bond queue); `bonded += amount` |
| `UnbondVested { entry, amount, nonce, signature }` | beneficiary, `rand-vest-unbond-1` | `amount ≤ bonded`, ≤ the validator's active stake | the validator's `stake −= amount`; a row `(epoch + UNBONDING_EPOCHS, amount)` back in the lock |

The revoke names its exact amount because its envelope is sealed for one: the CLI signs the amount
still unvested `--margin-secs` (600) past the head; what vests in the margin stays the holder's.
The validator's own `Unbond` may not touch stake an entry bonded to it
(`have = stake − queued − Σ bonded_to`). Every action bumps the entry's nonce; the mempool claims it
(role 5, keyed on the entry id). Cacheable verdicts: `BadSignature`, `UnknownEntry`,
`NotRevocable`, `BondNeedsIrrevocable`, `BadRecipient`, `BelowBundleBase`, `ZeroAmount`.

## 7. Supply

Off the positional `Supply` blob: `Audit::with_vesting(issued, released, in_register)` —
`vesting_issued` is issuance, `vesting_released` enters `pool_value`, `vesting_in_register`
(held, not bonded) is added to `total_supply`. `invariant_holds` is unchanged in form.

## 8. RPC and CLI

`rand_getVesting [id, at_ms?]`, `rand_getVestingSummary []` (per class, no owners),
`rand_getVestingSchedule [from, to, step]` (≤ 1 000 points: the aggregate lockup table),
`rand_getSupply`'s `vesting_*`. CLI: `rand-node genesis --vesting FILE`, `rand-node vesting
status|claim|revoke|bond|unbond`; keys are `rand-node keygen` files.

## 9. Custody

Holders generate their own keys and send only the public key. The revoker key is held offline or
hardware-backed, never in a shell profile or on a droplet (the BRG-14 lesson); a 2-of-3 revoker is
the planned hardening.

## 10. Rollout

Genesis-gated and wire-additive, but only a cut can carry it. Rehearse on a testnet cut with test
keys and minute-scale schedules (claim, revoke, bond, unbond, the lockup table), then the mainnet
v1.0 genesis built from the signed allocation table, with the Schedule 2 §8 notice sent first.
