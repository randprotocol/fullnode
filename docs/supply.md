# The supply audit

A shielded chain cannot add up its own money. A note's value lives inside its commitment, so the
pool's contents are not summable by anyone — not by a node, not by the operator, not by a holder of
every viewing key but one.

What *is* public is every crossing of the pool's boundary, and on this chain there are only six
kinds. Count those, add the validator register — which holds its amounts in the clear because
consensus weight must be public (`docs/staking.md`) — and the total is exactly what the chain has
ever issued. That identity is the supply audit: `rand_getSupply` reports it, and every node checks
it against a full replay of its own chain.

## What is counted

Eight counters, all in units (1 RAND = 10⁹ units), all monotonic:

| counter | what it sums | when it moves |
|---|---|---|
| `genesis_deposited` | the `alloc` deposit notes in the genesis file | never after block 0 |
| `genesis_staked` | the stakes genesis seeded the register with | never after block 0 |
| `faucet_minted` | every accepted `Mint` (the testnet faucet) | a mint commits |
| `withdraw_deposited` | the notes accepted `Withdraw`s created | a withdraw commits |
| `fees_paid` | every bundle fee a proposer kept, i.e. value that left the pool into its `rewards` — under the genesis `fees.burn_base` only the tip, `fee − BUNDLE_BASE`, and under `fees.burn_floor` as well `fee − floor` | any bundle commits |
| `burned` | every bundle `burn` — a `Bond`, burning into `stake`; under the genesis gates below also a registration fee or a bundle's `BUNDLE_BASE` (its whole floor under `fees.burn_floor`), burning into nothing | a bond commits; under a gate, a registration or any bundle |
| `subsidised` | the aggregation subsidy every accepted `Aggregate` minted into its payout note — under the genesis `fees.subsidy_net_of_fees` only the schedule's shortfall over the covered proving shares (`docs/fees.md` §1.3) | an aggregate commits |
| `slashed` | what slashing destroyed: a slashed aggregator bond, and under `staking.slashing` an equivocating leader's slashed stake | a slash commits |

`rand_getSupply` serves two more fields of the same blob that are not value crossings:
`sealed_blocks`, the count of included aggregates (the subsidy schedule's index), and
`aggregator_bonds`, the bonds the aggregator register holds now (it falls as bonds are paid out
or slashed, and it is counted in `register_total` below).

Two more counters break part of `burned` down, because what they count enters no register entry
and so sits on the right of the identity below: `registration_fees_burned` (the registration fees
burned under `tokens.burn_registration_fee`, audit v5 TOK-2) and `base_fees_burned` (every
bundle's `BUNDLE_BASE` burned under `fees.burn_base`, `docs/fees.md` §1.3 — or, under
`fees.burn_floor` beside it, every bundle's whole burned floor, `min(fee, floor)`: the base plus a
Deploy's per-word term or a Call's tier-exact gas and byte terms; one counter holds the whole burn
under either flag, so the identity below reads the same). Both are kept beside
the supply blob rather than in it, so chain 14's stored layout never moved, and both read 0
without their gate.

Value **enters** the pool as a genesis deposit, a faucet mint, a validator's withdraw, or an
aggregate's payout note — of which only the minted subsidy (`subsidised`) is new: the note's
proving-share part is bucketed fee excess that never left the pool in this accounting. It
**leaves** as a bundle fee or a burn. There is no other movement across the boundary, which is what
makes the arithmetic below closed rather than approximate.

Two of those rows are easy to get subtly wrong, so they are worth stating twice:

- **`genesis_staked` is issuance.** A genesis validator's stake is real RAND — it can be unbonded
  and withdrawn into a note like any other — but it was never deposited into the pool. Without this
  counter every chain with validators would report more supply than it issued from its first block.
- **A withdraw's base fee is not a crossing.** A `Withdraw` takes the whole amount out of the
  register, creates a note worth `amount − 0.001 RAND`, and pays the 0.001 to the proposer's
  `rewards`. Only the note crossed, so `withdraw_deposited` counts the note; the base simply moved
  from one register entry to another and is not a `fees_paid`, because it was never in the pool to be
  paid out of it.

## The identity a node checks

```
pool_value     = genesis_deposited + faucet_minted + withdraw_deposited + subsidised
                 − fees_paid − burned
register_total = Σ over the validator register of (stake + pending + rewards)
                 + Σ over the aggregator register of bond
total_supply   = pool_value + register_total
issued         = genesis_deposited + genesis_staked + faucet_minted + subsidised

invariant:       total_supply == issued − slashed − registration_fees_burned
                                        − base_fees_burned
```

`pool_value` is value the pool holds; it is not the sum of the notes in it, which nobody can compute
— it is what entered minus what left, which comes to the same number. `invariant_holds` being false
is a consensus bug or a damaged database, never a legitimate chain state. Three things destroy
issuance and sit on the right of the identity as `issued − slashed − registration_fees_burned −
base_fees_burned`: a slashed aggregator bond (block aggregation); under the genesis
`tokens.burn_registration_fee` (v0.5.5, audit v5 TOK-2, `docs/tokens.md` §15), a registration's
fee; and under the genesis `fees.burn_base` (`docs/fees.md` §1.3), every bundle's `BUNDLE_BASE`
(its whole floor under `fees.burn_floor`) —
the last two leave the pool through `burned` and enter no register entry, which is why they are
the two counters beside the table above. All three read 0 on chain 14, and the last on every chain
cut so far.

Follow one bond and one withdraw of 1000 RAND through it, on a chain that deposited 2000 at genesis
and staked 4000:

| after | `burned` | `withdraw_deposited` | `fees_paid` | `pool_value` | `register_total` | `total_supply` |
|---|---|---|---|---|---|---|
| genesis | 0 | 0 | 0 | 2000 | 4000 | 6000 |
| a bond of 1000 (fee 0.001) | 1000 | 0 | 0.001 | 999.999 | 5000.001 | 6000 |
| its unbond | 1000 | 0 | 0.001 | 999.999 | 5000.001 | 6000 |
| its withdraw of 1000 | 1000 | 999.999 | 0.001 | 1999.998 | 4000.002 | 6000 |

`issued` is 6000 throughout: a bond, an unbond, a withdraw and a fee move value between the two
halves and never create or destroy any. Only a faucet mint (or, on an aggregating chain, an
aggregate's minted subsidy) moves `issued` at all.

## Genesis vesting: the third half

A chain whose genesis has a `vesting` section (`docs/vesting.md`) holds timelocked allocations in a
third public register beside the validator register. It adds one kind of issuance and one crossing,
kept off the positional `Supply` blob (so chain 14's and 15's stored counters keep their layout)
and served by `rand_getSupply` as `vesting_*`:

| number | what it is | on the identity |
|---|---|---|
| `vesting_issued` | Σ of the entries' amounts at genesis | issuance, beside `genesis_staked` |
| `vesting_released` | the notes claims and revokes created, net of their bases | value **entering** the pool, beside `withdraw_deposited` |
| `vesting_in_register` | Σ over entries of `amount − claimed − revoked_out − bonded` | the register's half of `total_supply` |

A claim of 100 takes 100 out of the vesting register, puts a 99.999 note into the pool and the
0.001 base into a proposer's `rewards` — the `Withdraw` shape. A bond from the lock moves value from
the vesting register into a validator's `stake` (so into `register_total`), and an unbond moves it
back; neither crosses the pool's boundary. `issued` moves only at genesis.

## Reading it

```bash
curl -s http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"rand_getSupply","params":[]}'
```

```json
{ "height": 1998,
  "genesis_deposited": "2000000000000", "genesis_staked": "4000000000000",
  "faucet_minted": "0", "withdraw_deposited": "999999000000",
  "fees_paid": "1000000", "burned": "1000000000000",
  "pool_value": "1999998000000", "register_total": "4000002000000",
  "total_supply": "6000000000000", "invariant_holds": true }
```

Every amount is a **decimal string of units**, because a JSON number is not an exact integer past
2⁵³ and a supply is 10⁹ units per RAND. `height` is the head the numbers are as of; the register's
own rows are in `rand_getValidators`.

Three things the reply does not say, by design: which notes make up `pool_value`, who holds them, and
what any one of them is worth.

## How exact it is

For everything the chain did itself, the counters are **exact, not estimated**. Each one is
incremented by the ledger in the same code path that applies the action, from the action's own public
fields — a mint's amount, a bundle's `fee` and `burn`, the amount a withdraw's note is worth — so a
counter can only disagree with the chain if the chain was replayed wrongly.

The genesis amounts are different in kind: they are **trusted from the genesis file**.
`genesis_deposited` is the sum of the `amount` fields in `alloc`, and `genesis_staked` the sum of the
seeded stakes. Both are part of the genesis hash, so every node on a chain agrees on them and a node
handed a different file refuses to join — but nothing *proves* that a genesis note's sealed value is
the amount its row declares, because the commitment hides it. A genesis that overstates an `alloc`
amount produces a chain whose stated supply is higher than what anyone can ever spend, and no rule
can catch it. Read a genesis file before joining its chain; that is the one place this chain's
accounting rests on a claim rather than a check.

The counters are also deliberately **not consensus state**: the state root does not hash them and no
rule reads them. They are derived from the chain the way the note tree is — a node persists them
beside the state, and `rand-node verify` recomputes every one of them by replaying every block and
reports `stored supply … does not match the replayed chain's …` if the snapshot disagrees. That
replay is what the RPC's numbers are worth:

```bash
rand-node verify --datadir ./data --mode quick     # structure, ledger replay, and the counters
```
