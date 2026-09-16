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
    payout:   ReceiverId,        // rand1… — the receiver id a withdraw pays; resolved through the registry
    nonce:    u64,               // the replay protection for its signed actions
}
```

Every field of every row is public, and the register is hashed into every block's state root
(leaf domain `rand-validator-leaf-3`), so a node that disagrees about one of them disagrees about
the chain. A row is created by genesis or by the bond that registers the validator, and is never
deleted: a validator that unbonds everything keeps a row with `stake = 0`, which is simply in no
epoch's set.

Since chain 11 (`docs/shielded.md` §2) `payout` is a **receiver id**, not the record itself: the
`pk` a withdraw's note is addressed to is resolved from the receiver registry
(`ledger.resolve_pk(payout)`) at validate and apply time, not stored in the register. A `Bond`
that registers a new validator (`check_bond`) therefore needs the `Registration`'s payout id to
already resolve in the registry — there is no way to carry the record on the same transaction, so
the payout wallet must run `rand register` before it is named as anyone's payout — else the bond
is refused as `StakingError::UnknownReceiver(payout)`, "receiver {id} is not in the registry". A
row's payout id can be rotated to a fresh KEM key without ever touching the register: `rand
register --rotate` republishes the same id's record, and the register entry needs no change.

| constant | value | meaning |
|---|---|---|
| `MIN_STAKE` | 1000 RAND | stake a row needs to be in an epoch's set at all |
| `MAX_VALIDATORS` | 100 | largest set an epoch can have |
| `UNBONDING_EPOCHS` | 2 | epochs an unbonded amount waits before it can be withdrawn |
| `epoch_blocks` | 1000 (genesis) | blocks per epoch; `rand-node genesis --epoch-blocks` |

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
  `rand_getEpoch`'s `next_set` shows it immediately, but the set only changes at a boundary.
- **An unbond costs weight at the next boundary, not two epochs later.** The `UNBONDING_EPOCHS` wait
  is about the *amount* becoming withdrawable; the *set* is re-derived at the very next boundary, so
  a validator stops proposing long before it can withdraw.

If an epoch's derivation is empty — every validator below the minimum — the previous epoch's set is
carried forward, because an epoch with no leader is a halt nothing could end.

A node runs with `--validator` when it holds a validator key at all; being in the current set is a
separate thing, and `rand_status` reports the two separately as `is_validator` and
`active_validator`. A key in no current set neither proposes nor votes, but keeps following the
chain, so **a validator that bonds in after genesis does not need a restart**: start it with
`--validator` and it begins proposing when its epoch arrives.

## 3. The four commands

Which binary owns which action follows from which key signs it. A bond spends *notes*, so it is a
wallet command; an unbond and a withdraw are signed by the *validator's* Dilithium2 key, which only
the node holds.

| action | command | rides on | pays |
|---|---|---|---|
| register | `rand-node register` | nothing — it prints a blob | nothing (offline) |
| `Bond` | `rand bond` | a bundle, which burns the stake | the 0.001 RAND bundle base, out of the wallet's notes |
| `Unbond` | `rand-node unbond` | nothing (`bundle: null`) | nothing |
| `Withdraw` | `rand-node withdraw` | nothing (`bundle: null`) | the 0.001 RAND base, out of the amount withdrawn |

### Registration

```bash
rand-node register --key node.key.json --payout rand1<payout address> [--rpc http://127.0.0.1:8545]
```

Prints the validator's address and a hex `Registration` — its public key, the payout receiver id,
and a signature over `(chain_id, payout)`. The RPC is only read for the chain id: a registration
signed for one chain is refused on another. The payout id comes from a **wallet** key
(`rand --key payout.key.json address`), not from a node key, and it is the one field a later
top-up cannot change. The id must already resolve in the registry — `rand --key payout.key.json
register` first, if it has never published a record — else the bond that carries this
registration is refused as `receiver {id} is not in the registry`.

Hand the hex to whoever holds the stake.

### Bond

```bash
rand bond <validator base58> <amount in RAND> \
    [--registration <hex>] [--fee <RAND>] [--no-wait] [--cuda]
```

A bond is an ordinary shielded transaction: the wallet proves a 2-in-2-out bundle whose `burn` is the
staked amount, so the stake leaves the pool instead of becoming anyone's note, and the ledger admits
a bond only when `burn == amount`. It takes about a minute and a half of local proving, like any
transfer.

- `--registration` is required exactly when the validator is not in the register yet, and refused
  when it is. The wallet asks the register first, so the wrong shape is an answer rather than a
  wasted proof.
- Registering bonds at least `MIN_STAKE` (1000 RAND). A top-up afterwards can be any amount above
  zero — the wallet refuses zero, which would pay a fee and a proof to move nothing.
- What the chain learns is that this validator's stake grew by this much. Which notes paid for it,
  and who holds them, is hidden exactly as in a transfer — so anyone can stake onto a validator
  without revealing anything but the amount.

The wallet prints the new stake and the epoch the weight starts counting from:

```
submitted bond 8c3f…e1
  0 RAND out, 1000 RAND burned, 0.999 RAND change, fee 0.001 RAND, anchored at height 412
2nRdFC…: stake 1000 RAND, counting as consensus weight from epoch 69
balance: 0.999 RAND
```

### Unbond

```bash
rand-node unbond <amount in RAND> --key node.key.json [--rpc …] [--no-wait]
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
rand-node withdraw <amount in RAND> --key node.key.json [--rpc …] [--no-wait]
```

Pays released value into a deposit note at the register's `payout` id. Released means
`rewards` plus the `pending` rows whose `release_epoch` has arrived; the command takes the released
rows oldest first and then the rewards.

Like an unbond it is validator-signed and bundle-less, but it is not free: it pays the 0.001 RAND
bundle base to the proposer of the block that applies it, **out of the amount withdrawn**. So a
withdrawal of 1000 RAND leaves the register entirely and creates a note worth 999.999 RAND, and
an amount that cannot cover the base is refused rather than buying a note worth nothing.

The note is the one the chain computes for itself, from the `pk` the registry resolves for the
entry's payout id, the amount less the base, the blinding `r` the action publishes, and the
action's own `time`:

```
pk = registry[payout].pk        // resolved at withdraw time — not stored in the register
cm = H_CM(pk, from = 0, amount − 0.001 RAND, asset 0, time, r)
```

A payout id the registry no longer holds a record for (it cannot happen through this chain's own
rules, since a receiver's record is never deleted, but a corrupted or hand-edited registry could
still lack one) refuses the withdraw as `receiver {id} is not in the registry` rather than
producing a note nobody can open.

`time` is the head height when the command ran, which it prints and which the signature binds — not
the height of the block that applies the transaction, because the envelope only the payout wallet
can open is sealed against this exact note before that block exists. Admission accepts any `time`
inside the 256-block window, so a withdraw that waits a few blocks for inclusion still pays a note
the payout wallet finds by scanning. Publishing `r` is what closes the "declare one amount, mint
another" gap: the chain never takes the note's commitment from the transaction.

```
withdrawing 1000 RAND: a note worth 999.999 RAND to rand1x7Qk…, the 0.001 RAND base to the block's proposer
  note blinding r 3f9a…7c at time 4131
submitted withdraw of 1000 RAND 1b7e…
  committed in block 4133
```

Afterwards the payout wallet finds the note like any other — by scanning, with nothing told to it:

```bash
rand --key payout.key.json balance      # balance: 999.999 RAND
rand --key payout.key.json send rand1… 1
```

## 4. Joining and leaving a chain

Joining, from the two sides:

```bash
# on the machine holding the stake, first, if it has never published a record (docs/shielded.md §2)
rand --key payout.key.json register

# on the joining validator's machine
rand-node register --key node.key.json --payout "$(rand --key payout.key.json address)"
rand-node run --datadir ./data --key node.key.json --validator --bootstrap /ip4/…/p2p/…
#   … it syncs and observes; rand_status says is_validator true, active_validator false

# on the machine holding the stake, with the hex from above
rand bond <validator base58> 1000 --registration <hex>
rand validators                       # the new row, active false until the boundary

# back on the validator's machine, from the next epoch on
rand-node status                      # active_validator: true — it is proposing now
```

Leaving:

```bash
rand-node unbond 1000 --key node.key.json     # out of the set at the next boundary
rand validators                                # stake 0, pending [{release_epoch, amount}]
#   … wait two epochs …
rand-node withdraw 1000 --key node.key.json    # a note worth 999.999 RAND at the payout address
```

A set of `n` validators needs more than 2/3 of its stake online, so check the arithmetic before
unbonding: dropping one of four leaves three, which is a quorum only if all three are up.

Genesis seeds the register directly, one entry per `--validator`:

```bash
rand-node genesis --chain-id 6 \
    --validator node-a.key.json,1000,rand1<a's payout> \
    --validator <hex public key of b>,1000,rand1<b's payout> \
    --epoch-blocks 1000 --alloc rand1<address>=1000 --faucet --out genesis.json
```

The three fields of a `--validator` travel together because they are one register entry, and all
three are part of the genesis hash — the payout id included, because it is register state. Each
payout id must resolve against the genesis file's own receiver registry, seeded by repeatable
`--receiver <RECORD.JSON>` entries (`docs/cli.md`) registered before any `--validator` or `--alloc`
is parsed — an id with no matching `--receiver` record is refused. Genesis refuses a stake below
`MIN_STAKE`: such a validator would be in the register but in no epoch's set, and a chain seeded
entirely from those would have nobody to pick a leader from.

## 5. What is public

| | public | hidden |
|---|---|---|
| the register | every row: address, stake, unbonding queue with its release epochs, unpaid rewards, payout address, nonce | nothing |
| `Bond` | the validator, the amount, whether a registration was attached, and the bundle's `burn` | which notes paid, who owns them, the bonder's change |
| `Unbond` | the validator, the amount, the nonce | nothing — there is nothing else in it |
| `Withdraw` | the validator, the amount, the nonce, the note's `time` | who can open the note, and every later spend of it |

So a watcher learns that 1000 RAND was bonded to this validator and, later, that the validator
withdrew 1000 RAND into a note at its published payout address. What the note is then worth to whom, and
where the value goes next, is a shielded transfer like any other. The payout address is public in the
register from the day the validator registers, so publishing the withdraw's blinding leaks nothing
the register did not already say.

Rewards are the fees of the blocks a validator proposed: every bundle's fee, and the base a withdraw
pays. They accrue in `rewards` and are paid out by `Withdraw` — there are no block rewards and no
inflation. There is also **no slashing and no jailing** in S2 (spec §13): a validator that misbehaves
costs its stake nothing, and the remedy is the operators'.

## 6. Reading it back

```bash
rand validators          # the whole register, one row per entry
rand status              # is_validator / active_validator for the node you asked
```

`rand_getValidators` (`docs/rpc.md`) returns one row per register entry, in address order, with
amounts as **decimal strings** — a stake is 10⁹ units per RAND and a JSON number is not an exact
integer past 2⁵³:

```json
{ "address": "2nRdFC…", "stake": "1000000000000",
  "pending": [{ "release_epoch": 71, "amount": "1000000000000" }],
  "rewards": "4000000", "payout": "rand1…", "nonce": 3, "active": true }
```

`active` is whether this row is in the set running the current epoch — that, and not the presence of
a row, is what says who is producing blocks. `rand_getEpoch` answers where the chain is in its
schedule and what the next boundary would derive today:

```json
{ "epoch": 69, "epoch_blocks": 1000, "next_set": ["2nRdFC…", "ByDkxs…"] }
```

`next_set` is a projection, not a commitment: every bond and unbond before the boundary moves it.

For where the staked value came from and went to, read `rand_getSupply` and `docs/supply.md`: the
register's total and the pool's value have to add up to everything the chain ever issued, and a node
checks it.
