# Vesting: timelocked genesis allocations

> **Status: designed, not yet implemented.** Design approved 2026-09-28; the full spec is
> `docs/superpowers/specs/2026-09-28-genesis-vesting-design.md`. It ships with the genesis cut that
> carries fundraising allocations (mainnet v1.0), after a testnet rehearsal. Commands below are the
> planned interface.

This page explains how RandProtocol gives RAND to the internal team, investors (VCs) and founding
partners at genesis **without letting it be spent before it unlocks**, and what each party does.

## Why this needs its own mechanism

RAND is held as shielded notes. A spend proves ownership without revealing which note it spends or
what that note is worth, so the chain cannot see a note well enough to refuse spending it "too
early". A lockup therefore cannot be a property of a note in the pool.

Instead, locked RAND sits **outside** the pool, in a public **vesting register** created at
genesis — the same idea as the validator register, whose stakes are public because consensus needs
them to be. As an allocation unlocks, its holder *claims* the unlocked part, and only then does it
become an ordinary private note.

```
genesis ──► vesting register (public, locked) ──claim──► shielded note (private, spendable)
                        │
                        └──revoke (unvested part only)──► treasury note
```

The chain enforces the schedule. No party — including the foundation — can release locked RAND
early, and anyone can audit how much RAND is still locked.

## What an allocation looks like

Each allocation is one entry in the genesis file's `vesting` section:

| field | meaning |
|---|---|
| `id` | 32 random bytes. The chain never learns a name; the foundation keeps the `id → holder` list off-chain. |
| `class` | `team`, `investor`, `partner` or `other` — used only for the per-class totals the RPC reports. |
| `beneficiary` | the holder's public key. Only this key can claim. |
| `revoker` | the foundation key that may claw back the **unvested** part. Optional per entry (see below). |
| `amount` | total RAND, in units (1 RAND = 10⁹ units). |
| `start_ms`, `cliff_ms`, `duration_ms` | the schedule. |

The schedule is a **cliff, then linear**:

- before `start + cliff`: nothing is available;
- at the cliff: everything accrued since `start` becomes available at once;
- after that: it unlocks continuously, block by block, until `start + duration`, when all of it is
  available.

Time is the block timestamp. Validators refuse to vote for a block stamped more than 15 seconds
ahead of their own clocks, so an unlock can move by seconds, never by days — the dates in the
legal agreements are the dates the chain uses.

### Worked example

An investor allocation of 1 000 000 RAND, `start` = genesis day, 12-month cliff, 48-month duration:

| time after start | available in total |
|---|---|
| 11 months | 0 |
| 12 months (cliff) | 250 000 |
| 24 months | 500 000 |
| 36 months | 750 000 |
| 48 months and after | 1 000 000 |

The holder can claim any amount up to "available − already claimed", as often as they like.

## Who does what

### The foundation (at the genesis cut)

1. Agree the allocation table and schedules with each party (the legal documents).
2. Collect each holder's **public** key. Never generate a holder's key for them.
3. Create the revoker key offline (see Custody).
4. Build the `vesting` section with random `id`s and pass it to `rand-node genesis --vesting`. The
   cut script prints the total per class; check it against the signed allocation table before
   `rand-node init` prints the final genesis hash. Amounts are in units: 1 RAND = 10⁹, and a missed
   factor of 10⁹ is the classic mistake.

### A holder (team member, investor, partner)

1. Generate a key on your own machine and send the foundation **only the public key**:
   `rand-node vesting keygen --out my-vesting.key.json`.
2. Keep a RAND wallet (`rand`) for receiving; its `rand1…` address is where claims are paid.
3. Check your allocation at any time: `rand-node vesting status <id>` (or `rand_getVesting`).
4. Claim what has unlocked:
   `rand-node vesting claim --entry <id> --key my-vesting.key.json --to <your rand1… address> --all`.
   The claim creates a private note in your wallet, minus a 0.001 RAND fee. The destination
   address is inside what your key signs, so nobody relaying the transaction can redirect it.

Locked RAND **cannot be staked** and earns nothing until it is claimed. Once claimed it is ordinary
RAND and can be bonded like any other.

### Revocation (for example, a team member who leaves)

The foundation's revoker key can revoke an entry once. A revoke:

- takes only the **unvested** part and pays it to a treasury address the foundation names;
- freezes the entry, and the holder can still claim everything that had already vested;
- cannot touch a fully vested allocation, or an entry listed without a revoker.

Every entry carries a revoker by default. If a deal's terms forbid clawback, and many investment
agreements do, list that entry without a `revoker` and the chain makes it irrevocable. No code
change is needed.

## What is public, and what is not

| public (on-chain, forever) | private |
|---|---|
| each allocation's amount, class and schedule | who the holder is (only a key is visible) |
| how much of each has been claimed or revoked | where claimed RAND goes after the claim note (claim notes are shielded) |
| total locked / unlocked / claimed per class | balances of the wallets claims were paid to |

A claim reveals that "entry X released N RAND" at that block. The receiving note is shielded,
though, and after that the RAND is indistinguishable from any other. Holders who want more distance
can claim to a fresh address.

## Supply reporting

`rand_getSupply` keeps its audit identity (`total_supply == issued`) and gains:

- `genesis_vested`: RAND issued into the vesting register at genesis;
- `vesting_released`: RAND that has left the register as claim or revoke notes;
- `vesting_locked`: RAND that has not unlocked yet;
- `vesting_unclaimed`: RAND that has unlocked but has not been claimed.

`rand_getVestingSummary` gives the same figures per class, so "how much team/investor/partner RAND
is still locked" is a single RPC call anyone can make.

## Custody

- **Holder keys:** generated and held by the holder. If the key is lost, the entry's vested RAND can
  never be claimed, because no key rotation exists. Back it up the way you would back up a wallet
  seed.
- **The revoker key:** the most valuable key this feature creates. Whoever holds it can send any
  entry's unvested RAND to an address of their choosing. Keep it offline or hardware-backed, and
  never put it in a shell profile, on a droplet or in this repository. A multi-party (2-of-3)
  revoker is the planned hardening.
- **The foundation never holds holders' keys.** If it did, the lockup would be a promise rather
  than a rule.
