# Vesting: timelocked genesis allocations

> **Status: implemented on `feat/timelock-genesis`, not yet on any chain.** It ships with the
> genesis cut that carries the fundraising allocations (mainnet v1.0), after a rehearsal on a
> testnet cut. Design: `docs/superpowers/specs/2026-09-28-genesis-vesting-design.md`; plan:
> `docs/superpowers/plans/2026-09-28-genesis-vesting.md`.

This page explains how RandProtocol gives RAND to the internal team, investors (VCs) and founding
partners at genesis **without letting it be spent before it unlocks**, and what each party does.
It covers what the SAFT (`../termsheets/RAND_SAFT_Institutional_US.md`) calls "Time-Locked Notes"
and "the Lockup Table"; see [The SAFT's Schedule 2](#the-safts-schedule-2) for where the two differ.

## Why this needs its own mechanism

RAND is held as shielded notes. A spend proves ownership without revealing which note it spends or
what that note is worth, so the chain cannot see a note well enough to refuse spending it "too
early". A lockup therefore cannot be a property of a note in the pool.

Instead, locked RAND sits **outside** the pool, in a public **vesting register** created at
genesis — the same idea as the validator register, whose stakes are public because consensus needs
them to be. As an allocation unlocks, its holder *claims* the unlocked part, and only then does it
become an ordinary private note.

```
                       ┌── bond (irrevocable entries) ──► validator stake ──unbond──┐
genesis ──► vesting register (public, locked) ◄───────────────────────────────────┘
                       ├── claim (what has vested) ──► shielded note (private, spendable)
                       └── revoke (unvested part, revocable entries) ──► the entry's treasury
```

The chain enforces the schedule: no party — the foundation included — can release locked RAND
early, and anyone can read how much is still locked.

## What an allocation looks like

Each allocation is one entry in the genesis file's `vesting` section:

```json
{
  "entries": [
    {
      "id": "3f9ad0c41b7e25a68c0d9e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d",
      "class": "investor",
      "beneficiary": "<the holder's Dilithium2 public key, hex>",
      "amount": "18000000000000000",
      "start_ms": 1790000000000,
      "cliff_ms": 31104000000,
      "linear_ms": 46656000000,
      "step_ms": 2592000000
    },
    {
      "id": "a41c77e0925b3d18f6e4c2a0b8d6f4e2c0a8b6d4f2e0c8a6b4d2f0e8c6a4b2d0",
      "class": "team",
      "beneficiary": "<the team member's Dilithium2 public key, hex>",
      "revokers": [
        "<revoker key 1, hex>",
        "<revoker key 2, hex>",
        "<revoker key 3, hex>"
      ],
      "threshold": 2,
      "treasury": "<the treasury's rand1… address>",
      "amount": "5000000000000000",
      "start_ms": 1790000000000,
      "cliff_ms": 31104000000,
      "linear_ms": 93312000000
    }
  ]
}
```

| field | meaning |
|---|---|
| `id` | 32 random bytes. The chain never learns a name; the foundation keeps the `id → holder` list off-chain. |
| `class` | `team`, `investor`, `partner` or `other` — only for the per-class totals the RPC reports. |
| `beneficiary` | the holder's public key. Only this key can claim, bond or unbond. |
| `revokers` | optional: the keys that may claw back the **unvested** part, `threshold` of them together. 1 to 5 distinct keys, none the beneficiary's. Absent or empty = irrevocable. The order matters: a revoke names its signers by position. |
| `threshold` | required with `revokers`: how many of them must sign a revoke, 1 ≤ `threshold` ≤ the number of keys. **Use 2 of 3**; a single key with `threshold` 1 is expressible and is the one-key revoker the audit objected to. |
| `treasury` | required with `revokers`: the `rand1…` address a revoke pays. A revoke to any other address is refused by every node, whoever signs it. |
| `amount` | total RAND in units (1 RAND = 10⁹ units), a decimal string. |
| `start_ms` | when the lockup starts (network launch for a sale round), Unix milliseconds. |
| `cliff_ms` | nothing unlocks before `start + cliff`. |
| `linear_ms` | the release period **after** the cliff. |
| `step_ms` | optional tranche length: unlock in whole steps (a month) instead of continuously; must divide `linear_ms`. |

The first entry is the SAFT's Founding Sale shape — a 12-month cliff, then 18 monthly tranches
(months are 30 days here: 2 592 000 000 ms). The second is a team grant: a 12-month cliff, then
36 months linear, revocable by two of three keys, to the treasury.

`rand-node genesis` refuses a file in which a revocable entry has no `treasury` or no `threshold`,
a threshold outside `1..=keys`, a key listed twice, more than five keys, the beneficiary among its
own revokers, a treasury that is not an address (or whose ML-KEM key does not decode), or an
irrevocable entry that names a treasury or a threshold. The old one-key `revoker` field is refused
as an unknown key rather than read as "irrevocable".

### The schedule

- before `start + cliff`: nothing;
- from the cliff, the linear period runs: continuously, or — with `step_ms` — one tranche at the
  **end** of each step;
- from `start + cliff + linear`: everything.

For the Founding Sale entry above (18 000 000 RAND):

| months after launch | unlocked in total |
|---|---|
| 0 – 12 | 0 |
| 13 | 1 000 000 |
| 14 | 2 000 000 |
| 21 | 9 000 000 |
| 30 and after | 18 000 000 |

Time is the block timestamp. Validators refuse to vote for a block stamped more than 15 seconds
ahead of their own clocks, so an unlock can move by seconds, never by days — the dates in the
agreements are the dates the chain uses (the SAFT's own Schedule 2 notes that height-based unlocks
are only an estimate of the calendar).

## Who does what

### The foundation, at the genesis cut

1. Agree the allocation table and schedules with each party (the legal documents).
2. Collect each holder's **public** key (below). Never generate a holder's key for them.
3. For revocable (team) grants: have each of the three revoker parties generate its own key
   offline and send the public key, and create the treasury wallet whose `rand1…` address the
   entries name — see Custody.
4. Write the `vesting` file with random `id`s and pass it to
   `rand-node genesis … --vesting vesting.json`. Check the totals per class against the signed
   allocation table before `rand-node init` prints the final genesis hash — amounts are in units,
   and a missed factor of 10⁹ is the classic mistake (it happened on the chain-15 cut).
5. Publish the lockup table (`rand_getVestingSchedule`, below) with the genesis file.

### A holder (team member, investor, partner)

1. Generate a key on your own machine and send the foundation **only the public key**:
   ```bash
   rand-node keygen --out my-vesting.key.json
   rand-node address --key my-vesting.key.json     # prints public_key: …
   ```
   Back the file up at once: it is the only copy of the key that claims your entry. `keygen`
   refuses a path that already exists (builds up to v0.6.7 overwrote it silently — never re-run
   the command on the same `--out` with one of those).
2. Keep a RAND wallet (`rand`) for receiving; its `rand1…` address is where claims pay.
3. Check your allocation at any time:
   ```bash
   rand-node vesting status <id> --rpc https://…
   ```
4. Claim what has unlocked:
   ```bash
   rand-node vesting claim --entry <id> --key my-vesting.key.json --to <your rand1…> --all
   ```
   The claim creates a private note in your wallet, minus a 0.001 RAND fee. The destination is
   inside what your key signs, so nobody relaying the transaction can redirect it.

### Bonding locked RAND (irrevocable entries)

Locked RAND can secure the chain before it unlocks, as the SAFT promises (Schedule 2 §4):

```bash
rand-node vesting bond --entry <id> --validator <address> --key my-vesting.key.json 50000
# a validator not yet in the register also needs --registration <what `rand-node register` printed>
rand-node vesting unbond --entry <id> --key my-vesting.key.json 50000
```

- The bonded RAND becomes that validator's stake (weight, under the usual bond queue and
  activation delay) and earns what that validator earns — rewards are paid to the validator's
  payout address as ordinary, unlocked notes.
- It stays **locked**: only your key can unbond it, and it returns to the lock, never to a note.
  The validator's own `unbond` cannot touch it. After unbonding it waits the usual two epochs
  before it can be claimed.
- An entry bonds to one validator at a time.
- Revocable entries cannot bond (a revoke never has to reach into a validator's stake).

### Revocation (for example, a team member who leaves)

A revocable entry is revoked once, by `threshold` of its revoker keys, in three steps — the keys
never have to be on one machine:

```bash
# 1. anyone (no key): write the revoke down
rand-node vesting revoke prepare --entry <id> --out revoke.json --rpc https://…
# 2. each revoker, on its own machine (offline is fine): read it, sign it
rand-node vesting revoke sign --proposal revoke.json --key revoker-1.key.json     # prints 0:<hex>
rand-node vesting revoke sign --proposal revoke.json --key revoker-3.key.json     # prints 2:<hex>
# 3. anyone: send it with the signatures
rand-node vesting revoke submit --proposal revoke.json --signature 0:<hex> --signature 2:<hex> --rpc https://…
```

- It takes only the **unvested** part, paid to the entry's `treasury` — the address fixed in
  genesis. There is no `--to`: the chain refuses a revoke that pays anywhere else, so a stolen
  quorum of revoker keys can move the unvested RAND to the treasury and nowhere else.
- Every revoker signs the same message (the entry, the amount, the nonce, the treasury note and
  its envelope), which is why the revoke is prepared once and the file passed around. `sign`
  prints what it is about to sign on stderr; **compare the treasury it shows with the genesis
  file** before signing — the prepared file is only as trustworthy as whoever wrote it, and the
  one thing a signer cannot check is that its envelope opens (run `prepare` yourself, or have a
  signer run it).
- Fewer than `threshold` signatures, a revoker listed twice, or one bad signature among good ones
  is refused.
- The amount is what will still be unvested 10 minutes after the head (`--margin-secs`), so the
  revoke still fits when it lands a few blocks later; whatever vests in that margin stays the
  holder's.
- The note's `time` is the head height at `prepare`, and a note older than 256 blocks is refused:
  gather the signatures and submit within that window (about 13 minutes at 3-second blocks), or
  prepare again.
- The entry is then frozen: the holder can claim everything that had vested, and nothing more.
- A fully vested grant cannot be revoked; an entry without `revokers` never can.

**Which entries are revocable is a choice made per entry in the genesis file.** The
recommendation, consistent with the SAFT: team grants revocable (2 of 3, to the treasury), investor
and founding-partner allocations irrevocable (no `revokers`).

## What is public, and what is not

| public (on chain, forever) | private |
|---|---|
| each allocation's amount, class and schedule | who the holder is (only a key is visible) |
| how much of each has been claimed, revoked, bonded | where claimed RAND goes after the claim note (shielded) |
| total locked / claimed per class, and the lockup table | balances of the wallets claims paid to |

A claim reveals "entry X released N RAND" at that block; the receiving note is shielded, and from
then on the RAND is indistinguishable from any other. Holders who want more distance claim to a
fresh address. Each entry's size is visible under its pseudonymous key — a holder with a known
allocation size can be linked to its entry; split an allocation across several entries if that
matters.

## Reading it

| method | answers |
|---|---|
| `rand_getVesting [id, at_ms?]` | one entry: terms (for a revocable one its `revokers`, `threshold` and `treasury`), `claimed`, `bonded`, `vested_now`, `claimable_now`, `unvested_now`, `nonce` (at the head, or at `at_ms`) |
| `rand_getVestingSummary []` | per class: entries, amount, vested, claimed, revoked, bonded, locked — no keys, no owners |
| `rand_getVestingSchedule [from_ms, to_ms, step_ms]` | the lockup table: the locked total at each point (≤ 1 000 points) |
| `rand_getSupply []` | adds `vesting_issued`, `vesting_released`, `vesting_in_register`, `vesting_locked`; the identity `total_supply == issued` covers the register |

Every amount is a decimal string. Circulating supply is `pool_value`; locked supply is
`vesting_locked`.

## The SAFT's Schedule 2

The SAFT draft and the tokenomics paper describe a different mechanism: notes whose spend circuit
carries an unlock height. This implementation keeps what the SAFT promises investors and changes how
it is enforced, which Schedule 2 §8 provides for ("the parties shall amend this Schedule to reflect
the implemented mechanics"):

| SAFT Schedule 2 | this implementation |
|---|---|
| §1 time-locked notes, unlock height in the spend circuit | a public register; unlocked RAND is claimed into an ordinary note. No circuit change. |
| §2 *L* notes, one per month, unlock heights at months *C*+1 … *C*+*L* | one entry with `cliff_ms` = *C* months, `linear_ms` = *L* months, `step_ms` = one month: the same tranches, dated by block timestamp rather than an estimated height |
| §3 lockup table: heights and amounts, no owners | `rand_getVestingSchedule` / `rand_getVestingSummary`: amounts over time, no owners. Per-entry amounts are also visible, under a key rather than a name |
| §4 bondable while locked; unbonding returns to the lock; rewards unlocked | the same (`vesting bond` / `vesting unbond`) |
| §5 company viewing key on the delivery address | unchanged: claims pay to the investor's delivery address, which the company's viewing key sees |
| no clawback of investor tokens | investor and partner entries are listed without `revokers` |

The notice to investors under §8 must state the one real difference: an entry's amount and schedule
are public under its key, where the SAFT's lockup table published only aggregates.

## Custody

- **Holder keys:** generated and held by the holder. A lost key strands the entry's vested RAND
  (there is no key rotation) and anything bonded from it. Back it up like a wallet seed.
- **The revoker keys:** three keys held by three parties, two of which revoke (`threshold` 2).
  One stolen key can do nothing; two can send a revocable entry's unvested RAND to the treasury
  and to no other address — a nuisance and a dispute, not a theft. Generate each on its holder's
  own machine, keep it offline or hardware-backed; never two of them in one place, in a shell
  profile, on a droplet or in this repository.
- **The treasury wallet:** an ordinary `rand` wallet whose address the revocable entries name.
  It cannot be changed after genesis, so back its key up before the cut: a lost treasury key
  strands whatever is revoked to it. It should not be held by the revoker parties alone — the
  point of pinning the destination is that revoking and spending are two different powers.
- **The foundation never holds holders' keys.** If it did, the lockup would be a promise rather
  than a rule.
