# Genesis vesting: timelocked RAND for the team, investors and founding partners

Status: design approved 2026-09-28 (brainstorm with the user); not implemented. Targets the next
genesis cut that carries fundraising allocations (mainnet v1.0), rehearsed first on a testnet cut.
User-facing guide: `docs/vesting.md`.

## 1. Problem

Fundraising allocations — internal team, investors (VCs), founding partners — are issued at genesis
but must not be spendable until they unlock on a schedule (a cliff, then linear). RAND lives as
shielded notes: a spend proof hides which note it consumes and what it is worth, so the ledger
cannot enforce a lock on a note it cannot see. The lock therefore has to live where amounts are
already public — a register, like the validator register (`ledger/staking.rs`) — and value enters
the pool only as it unlocks.

## 2. Decisions (user, 2026-09-28)

| # | question | ruling |
|---|---|---|
| D1 | where the lock lives | **A public vesting register** seeded at genesis. Each entry's amount and schedule are public; the holder is a key, never a name. Rejected: a timelock inside the note (guest change, bundle re-measure, locked supply unauditable); off-chain/legal only (the chain enforces nothing). |
| D2 | revocation | **Every entry carries a revoker key** (the field is per-entry and optional, so a deal whose terms forbid clawback is simply listed without one — no code change). A revoke takes only the *unvested* part. |
| D3 | where revoked RAND goes | **A shielded note to the address the revoker names** (the treasury), spendable at once. Rejected: burning it. |
| D4 | bonding locked RAND | **No.** Locked RAND is inert until claimed: no stake, no rewards, no consensus weight. No interaction with slashing, unbonding or the 3333-bps weight cap. |
| D5 | time basis | The committing block's `timestamp_ms` — calendar-aligned with the legal agreements. B2 already bounds it (`MAX_TIMESTAMP_STEP_MS` 60 s per block; honest replicas refuse to vote for a block more than `MAX_CLOCK_DRIFT_MS` = 15 s ahead of their clock), so a proposer can shift an unlock by seconds, never by days. |

Out of scope (YAGNI, each recorded): beneficiary key rotation (a lost key strands the vested part —
custody, §9, is the mitigation); creating entries after genesis; bonding from the lock;
per-entry step schedules other than cliff + linear.

## 3. Genesis section

`Genesis::vesting: Option<VestingConfig>`, `#[serde(default, skip_serializing_if = "Option::is_none")]`.
Absent — every chain to date — changes nothing: genesis file, hash and state roots byte-for-byte.

```json
"vesting": {
  "entries": [
    {
      "id": "<64 hex>",
      "class": "investor",
      "beneficiary": "<Dilithium2 public key, hex>",
      "revoker": "<Dilithium2 public key, hex>",
      "amount": 50000000000000000,
      "start_ms": 1790000000000,
      "cliff_ms": 31536000000,
      "duration_ms": 126144000000
    }
  ]
}
```

- `amount` in units (1 RAND = 10⁹). The cut script checks `Σ amount` against the allocation table
  it was given, the same way the chain-15 cut checked `Σ notes == Σ locked` (the `alloc-note`
  10⁹-scaling trap is the reason).
- `class` ∈ `team | investor | partner | other`: reporting only (`rand_getVestingSummary`), no rule
  reads it.
- `id`: 32 bytes chosen by the cut tooling (random). Names and deal terms never go in the genesis
  file; the operator keeps an off-chain manifest `id → name`.
- `revoker` optional (D2). Both keys length-checked `== PUBLIC_KEY_LEN` (core review I-1's rule).

`Genesis::validate` refuses (`GenesisError::BadVesting(reason)`): an empty list; a duplicate `id`;
`amount == 0`; `duration_ms == 0`; `cliff_ms > duration_ms`; `start_ms + duration_ms` overflowing;
a wrong-length key; `Σ amount` (plus alloc, plus stakes) overflowing `u64`; and a `beneficiary`
equal to its own `revoker`.

## 4. The schedule

```
vested(e, t) = 0                                         if t < e.start + e.cliff
             = e.amount                                  if t ≥ e.start + e.duration
             = ⌊ e.amount · (t − e.start) / e.duration ⌋ otherwise   (u128, then u64)
```

After a revoke, `vested(e, t) = e.amount − e.revoked_out` for every later `t` — the entry is frozen
(§6.2). `vested` is monotonic in `t`, which makes admission sound: a claim valid against the
tip's timestamp is valid in any later block, the one exception being a revoke landing in between —
which apply re-checks.

One pure function, `ledger::vesting::vested(&Entry, t_ms) -> u64`, used by validate, apply, RPC and
CLI alike.

## 5. Ledger state

`ledger/vesting.rs`, alongside `staking.rs`:

```rust
pub struct Entry {
    pub class: Class,
    pub beneficiary: PublicKey,
    pub revoker: Option<PublicKey>,
    pub amount: u64,
    pub start_ms: u64,
    pub cliff_ms: u64,
    pub duration_ms: u64,
    pub claimed: u64,            // released to the beneficiary so far (gross, before the base)
    pub revoked_at: Option<u64>, // block timestamp of the revoke
    pub revoked_out: u64,        // the unvested part paid to the treasury
    pub nonce: u64,              // bumped by every accepted claim and revoke
}
pub struct VestingRegister(BTreeMap<[u8; 32], Entry>);
```

Invariant per entry: `claimed + revoked_out ≤ amount`, and `claimed ≤ vested(e, now)`.

Persisted as JSON through a storage-side mirror (the `RegistryExtDisk` pattern, so an appended
field reads as its default) under `META_VESTING`, restored by `load_ledger`, audited in replay.
Leaves `blake3("rand-vesting-leaf-1" ‖ id ‖ bincode(entry))`, a Merkle root over them in id order,
appended to the state root and re-domained **`rand-state-6`** — only when the section is present,
so a chain without it falls through to today's `rand-state-5` path unchanged. (The gate is restored
on restart exactly like aggregation's: a restarted node that lost it would compute the old domain
and fork at its first block.)

## 6. Actions

Both are bundle-less, fee-less on the wire, and pay `gas::BUNDLE_BASE` out of what they release,
to the proposer's `rewards` — exactly `Withdraw`'s shape (`ledger/staking.rs::apply`).

### 6.1 `ClaimVested` = `Action` 24

```rust
ClaimVested { entry: [u8; 32], amount: u64, nonce: u64, to: ShieldedAddress,
              time: u32, r: Word8, envelope: Envelope, signature: Signature }
```

Signed by `beneficiary` over
`H("rand-vest-claim-1", genesis_hash ‖ chain_id ‖ entry ‖ amount ‖ nonce ‖ to ‖ time ‖ r ‖ envelope)`.
Validate, cheap before expensive:
1. the chain has a `vesting` section, else `NOT_VESTING`;
2. `to`'s key lengths (`KEM_EK_BYTES`), permanent;
3. entry exists (`UnknownVesting`), `nonce == entry.nonce` (`BadNonce`);
4. `amount > BUNDLE_BASE` (`AmountTooSmall`) and `amount ≤ vested(e, block_ts) − claimed`
   (`NotYetVested { available }`) — **not permanent**: time cures it;
5. signature (`BadSignature`, permanent);
6. the derived note `cm = note(to.pk, amount − BUNDLE_BASE, asset 0, time, r)` is new
   (`CommitmentExists`); `time` held to the bundle window like a mint's.

Apply: `claimed += amount`, `nonce += 1`, append the deposit, credit the base,
`supply.vesting_released += amount − BUNDLE_BASE`. `derived_commitment` gains the arm (the note is
computable from the action alone), so the mempool's conflict index holds it.

`to` is in the signed message, so the beneficiary picks the receiving wallet per claim and nobody
relaying the transaction can redirect it.

### 6.2 `RevokeVesting` = `Action` 25

```rust
RevokeVesting { entry: [u8; 32], unvested: u64, nonce: u64, to: ShieldedAddress,
                time: u32, r: Word8, envelope: Envelope, signature: Signature }
```

Signed by `revoker` under
`H("rand-vest-revoke-1", genesis_hash ‖ chain_id ‖ entry ‖ unvested ‖ nonce ‖ to ‖ time ‖ r ‖ envelope)`.

The note's envelope is sealed for one exact amount, so the revoke names that amount itself:
`unvested` is what the treasury takes. The true unvested part `u(t) = amount − vested(e, t)` only
shrinks as blocks pass, so the CLI signs `unvested = u(tip_ts + margin)` (default margin 10 min);
whatever vests between that point and the committing block stays with the beneficiary.

Validate: a `vesting` section (`NOT_VESTING`); the entry exists; it has a revoker (`NotRevocable`,
permanent); not yet revoked (`AlreadyRevoked`, permanent); `nonce == entry.nonce`;
`BUNDLE_BASE < unvested ≤ u(block_ts)` (`RevokeExceedsUnvested { unvested_now }` — permanent in
effect, since `u` only falls: re-sign with a smaller amount); signature; the derived note
`note(to.pk, unvested − BUNDLE_BASE, asset 0, time, r)` is new.

Apply: `revoked_at = block_ts`, `revoked_out = unvested`, `nonce += 1`, the note to `to`, the base
to the proposer, `supply.vesting_released += unvested − BUNDLE_BASE`. From then on the entry is
**frozen**: the beneficiary may claim up to `amount − revoked_out` in total, at once (whatever had
vested plus the margin's worth), and not a unit more. A fully vested grant cannot be clawed back
(`u ≤ BUNDLE_BASE` refuses every revoke).

Both actions are added to `Action::blanked`, the `VARIANTS` table (24 → 26) and `tx_json`.
Governance-style mempool bypass: no — they are ordinary priority.

## 7. Supply audit

Two counters, both monotonic, both in `Supply` and served by `rand_getSupply`:

| counter | sums | moves |
|---|---|---|
| `genesis_vested` | `Σ entries.amount` | never after block 0 — **issuance**, like `genesis_staked` |
| `vesting_released` | every claim or revoke note (net of the base) | a claim/revoke commits — value **entering** the pool, like `withdraw_deposited` |

```
pool_value     = … + vesting_released
register_total = … + Σ_vesting (amount − claimed − revoked_out)
                 (a claim/revoke's base lands in a proposer's `rewards`, already in Σ rewards)
issued         = … + genesis_vested
invariant:       total_supply == issued − slashed − registration_fees_burned   (unchanged)
```

`rand_getSupply` additionally reports `vesting_locked = Σ (amount − revoked_out − vested(e, head_ts))`
(0 for a revoked entry) and `vesting_unclaimed = Σ (vested − claimed)`,
so **circulating = pool_value** and the locked figure are both first-class numbers. All amounts are
decimal strings (the v0.5 RPC rule).

## 8. RPC and CLI

- `rand_getVesting(id)` → the entry, `vested_now`, `claimable_now`, next unlock, `nonce`.
- `rand_getVestingSummary()` → per class: entries, total, vested, claimed, revoked, locked.
- `rand-node genesis --vesting <entries.json>` (the section is spliced before `init` prints the
  hash — the `bridge: None` trap: the hash that matters is `init`'s on the finished file).
- `rand-node vesting keygen --out <file>` (beneficiary/revoker Dilithium2 key; prints the public key).
- `rand-node vesting status <id>`, `rand-node vesting claim --entry <id> --key <file> --to <rand1…>
  [--amount <RAND>|--all]`, `rand-node vesting revoke --entry <id> --key <file> --to <rand1…>`.
  Both wait for the commit (like `submit_staking`), `--no-wait` to opt out. Amount parsing reuses
  the WAL-2 rule: the unit follows what was typed.

## 9. Custody (operational, part of the design)

- **Beneficiaries generate their own key** (`vesting keygen` on their machine) and send only the
  public key. The operator never holds an investor's or partner's key.
- **Revoker key**: one per class is enough; held offline / on a hardware-backed signer, never in a
  shell profile or on a droplet (the BRG-14 lesson). Its loss only removes the ability to revoke;
  its theft lets an attacker claw back unvested grants **to an address of its choosing** — so it is
  the highest-value key this feature creates. A 2-of-3 revoker (Dilithium multisig) is the natural
  hardening; deferred, recorded.
- A lost beneficiary key strands the entry's vested part forever (no rotation, D-out). The revoker
  can still recover the unvested part.

## 10. Tests (red-first; quote the red in each commit)

- `vested`: before the cliff (0), at `start+cliff` exactly, one ms before, midway, at and past
  `start+duration`, `amount` near `u64::MAX` (u128 path), frozen after revoke.
- Claim: over-claim refused `NotYetVested`, claim of exactly available accepted, replayed nonce
  refused, wrong key refused, `to` substituted after signing refused, amount ≤ base refused,
  duplicate commitment refused, claim on a chain without the section refused.
- Revoke: no revoker → `NotRevocable`; double revoke; fully vested → `NothingToRevoke`; beneficiary
  still claims the frozen part after a revoke and not a unit more; `unvested` above `u(block_ts)` refused;
  `unvested` below it leaves the difference to the beneficiary (frozen total = `amount − unvested`).
- Supply: `invariant_holds` through genesis → claim → revoke → claim, in replay too.
- Genesis: every `BadVesting` reason; **chain 15's genesis hash and state roots unchanged** without
  the section; a vesting genesis restarts with the `rand-state-6` gate restored.
- Cluster (one test): a vesting entry with a 0 cliff and a short duration claims through a live
  4-node cluster and the payout wallet scans the note.

## 11. Rollout

Genesis-gated and wire-additive (two enum variants appended), but only a cut can carry it: a new
chain whose genesis lists the entries. Rehearse on a testnet cut with test keys and minute-scale
schedules, then the mainnet v1.0 genesis. The mainnet entry file is built from the signed
allocation table; the cut script prints `Σ amount` per class for sign-off before `init`.
