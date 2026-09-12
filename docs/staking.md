# Staking and the validator register

Phase S2 gives the shielded chain its stake. Consensus weight has to be public — every replica must
agree on who may propose a block and whose votes make a quorum — so the **register** is the one
table on this chain that holds amounts in the clear. Everything else stays in the pool: the stake a
validator bonds comes out of somebody's note, and the stake it withdraws goes back into a note, and
neither end says whose.

This page is the operator's guide to that: the register, the epochs, the four commands, what is
public, and how to read it back. The supply audit that ties the register and the pool together is
`docs/supply.md`; the design spec is
`docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §8; the wire-level reference is
`docs/rpc.md`.

## 1. The register

One row per validator that has ever bonded, keyed by its base58 address:

```rust
ValidatorEntry {
    public_key,                  // Dilithium2: signs blocks, and signs this validator's staking actions
    stake:    u64,               // bonded: the weight an epoch's set gives it
    pending:  Vec<(u64, u64)>,   // unbonding, as (release_epoch, amount), oldest first
    rewards:  u64,               // fees earned as a block proposer, unpaid
    payout:   ShieldedAddress,   // shrugg1… — where a withdraw pays
    nonce:    u64,               // the replay protection for its signed actions
}
```

Every field of every row is public, and the register is hashed into every block's state root
(leaf domain `shrugg-validator-leaf-2`), so a node that disagrees about one of them disagrees about
the chain. A row is created by genesis or by the bond that registers the validator, and is never
deleted: a validator that unbonds everything keeps a row with `stake = 0`, which is simply in no
epoch's set.

| constant | value | meaning |
|---|---|---|
| `MIN_STAKE` | 1000 SHRUGG | stake a row needs to be in an epoch's set at all |
| `MAX_VALIDATORS` | 100 | largest set an epoch can have |
| `UNBONDING_EPOCHS` | 2 | epochs an unbonded amount waits before it can be withdrawn |
| `epoch_blocks` | 1000 (genesis) | blocks per epoch; `shrugg-node genesis --epoch-blocks` |

## 2. Epochs

`epoch(h) = h / epoch_blocks`, so genesis (height 0) is in epoch 0 and the set for epoch 0 is the
genesis validators. The set for epoch `e ≥ 1` is derived from the register **as of the last block of
epoch `e − 1`**:

- every row with `stake ≥ MIN_STAKE`,
- the top `MAX_VALIDATORS` of those by `(stake descending, address ascending)`,
- sorted by address.

That rule is written once, in `staking::derive_set`, and it is a pure function of the register — which
is what lets every replica derive the same set from the same parent block without agreeing on
anything else first. Consensus then uses it in three places: the leader of a view comes from the set
of the epoch the next block belongs to, a block is voted by the set of its own epoch, and a quorum
certificate is verified against the set of the epoch of the block it certifies. Each epoch's set is
persisted when its first block commits, so replay and sync verify old certificates without holding
old registers.

Two consequences worth knowing:

- **A bond is not weight until the next epoch.** It is in the register the moment it commits, and
  `shrugg_getEpoch`'s `next_set` shows it immediately, but the set only changes at a boundary.
- **An unbond costs weight at the next boundary, not two epochs later.** The `UNBONDING_EPOCHS` wait
  is about the *amount* becoming withdrawable; the *set* is re-derived at the very next boundary, so
  a validator stops proposing long before it can withdraw.

If an epoch's derivation is empty — every validator below the minimum — the previous epoch's set is
carried forward, because an epoch with no leader is a halt nothing could end.

A node runs with `--validator` when it holds a validator key at all; being in the current set is a
separate thing, and `shrugg_status` reports the two separately as `is_validator` and
`active_validator`. A key in no current set neither proposes nor votes, but keeps following the
chain, so **a validator that bonds in after genesis does not need a restart**: start it with
`--validator` and it begins proposing when its epoch arrives.

## 3. The four commands

Which binary owns which action follows from which key signs it. A bond spends *notes*, so it is a
wallet command; an unbond and a withdraw are signed by the *validator's* Dilithium2 key, which only
the node holds.

| action | command | rides on | pays |
|---|---|---|---|
| register | `shrugg-node register` | nothing — it prints a blob | nothing (offline) |
| `Bond` | `shrugg bond` | a bundle, which burns the stake | the 0.001 SHRUGG bundle base, out of the wallet's notes |
| `Unbond` | `shrugg-node unbond` | nothing (`bundle: null`) | nothing |
| `Withdraw` | `shrugg-node withdraw` | nothing (`bundle: null`) | the 0.001 SHRUGG base, out of the amount withdrawn |

### Registration

```bash
shrugg-node register --key node.key.json --payout shrugg1<payout address> [--rpc http://127.0.0.1:8545]
```

Prints the validator's address and a hex `Registration` — its public key, the payout address, and a
signature over `(chain_id, payout)`. The RPC is only read for the chain id: a registration signed
for one chain is refused on another. The payout address comes from a **wallet** key
(`shrugg --key payout.key.json address`), not from a node key, and it is the one field a later
top-up cannot change.

Hand the hex to whoever holds the stake.

### Bond

```bash
shrugg bond <validator base58> <amount in SHRUGG> \
    [--registration <hex>] [--fee <SHRUGG>] [--no-wait] [--cuda]
```

A bond is an ordinary shielded transaction: the wallet proves a 2-in-2-out bundle whose `burn` is the
staked amount, so the stake leaves the pool instead of becoming anyone's note, and the ledger admits
a bond only when `burn == amount`. It takes about a minute and a half of local proving, like any
transfer.

- `--registration` is required exactly when the validator is not in the register yet, and refused
  when it is. The wallet asks the register first, so the wrong shape is an answer rather than a
  wasted proof.
- Registering bonds at least `MIN_STAKE` (1000 SHRUGG). A top-up afterwards can be any amount above
  zero — the wallet refuses zero, which would pay a fee and a proof to move nothing.
- What the chain learns is that this validator's stake grew by this much. Which notes paid for it,
  and who holds them, is hidden exactly as in a transfer — so anyone can stake onto a validator
  without revealing anything but the amount.

The wallet prints the new stake and the epoch the weight starts counting from:

```
submitted bond 8c3f…e1
  0 SHRUGG out, 1000 SHRUGG burned, 0.999 SHRUGG change, fee 0.001 SHRUGG, anchored at height 412
2nRdFC…: stake 1000 SHRUGG, counting as consensus weight from epoch 69
balance: 0.999 SHRUGG
```

### Unbond

```bash
shrugg-node unbond <amount in SHRUGG> --key node.key.json [--rpc …] [--no-wait]
```

Moves `amount` from `stake` into `pending` with `release_epoch = epoch + UNBONDING_EPOCHS`, and
increments the nonce. It is free and carries no bundle, exactly as a faucet mint does — there is
nothing to prove and a validator key owns no notes to pay from — so it commits in a block's time.
The command reads the register for its nonce, signs `(chain_id, validator, amount, nonce)` with the
node's key, and submits the action alone.

Unbonding more than the bonded stake is refused, and so is unbonding zero. Several unbonds in one
epoch merge into one `pending` row, because that row is hashed into the state root.

### Withdraw

```bash
shrugg-node withdraw <amount in SHRUGG> --key node.key.json [--rpc …] [--no-wait]
```

Pays released value into a deposit note at the register's `payout` address. Released means
`rewards` plus the `pending` rows whose `release_epoch` has arrived; the command takes the released
rows oldest first and then the rewards.

Like an unbond it is validator-signed and bundle-less, but it is not free: it pays the 0.001 SHRUGG
bundle base to the proposer of the block that applies it, **out of the amount withdrawn**. So a
withdrawal of 1000 SHRUGG leaves the register entirely and creates a note worth 999.999 SHRUGG, and
an amount that cannot cover the base is refused rather than buying a note worth nothing.

The note is the one the chain computes for itself, from the register's payout address, the amount
less the base, the blinding `r` the action publishes, and the action's own `time`:

```
cm = H_CM(payout.pk, from = 0, amount − 0.001 SHRUGG, asset 0, time, r)
```

`time` is the head height when the command ran, which it prints and which the signature binds — not
the height of the block that applies the transaction, because the envelope only the payout wallet
can open is sealed against this exact note before that block exists. Admission accepts any `time`
inside the 256-block window, so a withdraw that waits a few blocks for inclusion still pays a note
the payout wallet finds by scanning. Publishing `r` is what closes the "declare one amount, mint
another" gap: the chain never takes the note's commitment from the transaction.

```
withdrawing 1000 SHRUGG: a note worth 999.999 SHRUGG to shrugg1x7Qk…, the 0.001 SHRUGG base to the block's proposer
  note blinding r 3f9a…7c at time 4131
submitted withdraw of 1000 SHRUGG 1b7e…
  committed in block 4133
```

Afterwards the payout wallet finds the note like any other — by scanning, with nothing told to it:

```bash
shrugg --key payout.key.json balance      # balance: 999.999 SHRUGG
shrugg --key payout.key.json send shrugg1… 1
```

## 4. Joining and leaving a chain

Joining, from the two sides:

```bash
# on the joining validator's machine
shrugg-node register --key node.key.json --payout "$(shrugg --key payout.key.json address)"
shrugg-node run --datadir ./data --key node.key.json --validator --bootstrap /ip4/…/p2p/…
#   … it syncs and observes; shrugg_status says is_validator true, active_validator false

# on the machine holding the stake, with the hex from above
shrugg bond <validator base58> 1000 --registration <hex>
shrugg validators                       # the new row, active false until the boundary

# back on the validator's machine, from the next epoch on
shrugg-node status                      # active_validator: true — it is proposing now
```

Leaving:

```bash
shrugg-node unbond 1000 --key node.key.json     # out of the set at the next boundary
shrugg validators                                # stake 0, pending [{release_epoch, amount}]
#   … wait two epochs …
shrugg-node withdraw 1000 --key node.key.json    # a note worth 999.999 SHRUGG at the payout address
```

A set of `n` validators needs more than 2/3 of its stake online, so check the arithmetic before
unbonding: dropping one of four leaves three, which is a quorum only if all three are up.

Genesis seeds the register directly, one entry per `--validator`:

```bash
shrugg-node genesis --chain-id 6 \
    --validator node-a.key.json,1000,shrugg1<a's payout> \
    --validator <hex public key of b>,1000,shrugg1<b's payout> \
    --epoch-blocks 1000 --alloc shrugg1<address>=1000 --faucet --out genesis.json
```

The three fields of a `--validator` travel together because they are one register entry, and all
three are part of the genesis hash — the payout address included, because it is register state.
Genesis refuses a stake below `MIN_STAKE`: such a validator would be in the register but in no
epoch's set, and a chain seeded entirely from those would have nobody to pick a leader from.

## 5. What is public

| | public | hidden |
|---|---|---|
| the register | every row: address, stake, unbonding queue with its release epochs, unpaid rewards, payout address, nonce | nothing |
| `Bond` | the validator, the amount, whether a registration was attached, and the bundle's `burn` | which notes paid, who owns them, the bonder's change |
| `Unbond` | the validator, the amount, the nonce | nothing — there is nothing else in it |
| `Withdraw` | the validator, the amount, the nonce, the note's `time` | who can open the note, and every later spend of it |

So a watcher learns that 1000 SHRUGG was bonded to this validator and, later, that the validator
withdrew 1000 SHRUGG into a note at its published payout address. What the note is then worth to whom, and
where the value goes next, is a shielded transfer like any other. The payout address is public in the
register from the day the validator registers, so publishing the withdraw's blinding leaks nothing
the register did not already say.

Rewards are the fees of the blocks a validator proposed: every bundle's fee, and the base a withdraw
pays. They accrue in `rewards` and are paid out by `Withdraw` — there are no block rewards and no
inflation. There is also **no slashing and no jailing** in S2 (spec §13): a validator that misbehaves
costs its stake nothing, and the remedy is the operators'.

## 6. Reading it back

```bash
shrugg validators          # the whole register, one row per entry
shrugg status              # is_validator / active_validator for the node you asked
```

`shrugg_getValidators` (`docs/rpc.md`) returns one row per register entry, in address order, with
amounts as **decimal strings** — a stake is 10⁹ units per SHRUGG and a JSON number is not an exact
integer past 2⁵³:

```json
{ "address": "2nRdFC…", "stake": "1000000000000",
  "pending": [{ "release_epoch": 71, "amount": "1000000000000" }],
  "rewards": "4000000", "payout": "shrugg1…", "nonce": 3, "active": true }
```

`active` is whether this row is in the set running the current epoch — that, and not the presence of
a row, is what says who is producing blocks. `shrugg_getEpoch` answers where the chain is in its
schedule and what the next boundary would derive today:

```json
{ "epoch": 69, "epoch_blocks": 1000, "next_set": ["2nRdFC…", "ByDkxs…"] }
```

`next_set` is a projection, not a commitment: every bond and unbond before the boundary moves it.

For where the staked value came from and went to, read `shrugg_getSupply` and `docs/supply.md`: the
register's total and the pool's value have to add up to everything the chain ever issued, and a node
checks it.
