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
    payout:   ShieldedAddress,   // rand1… — where a withdraw pays
    nonce:    u64,               // the replay protection for its signed actions
    activation_epoch: u64,       // v0.5.4: the first epoch this row may be in the set of (§2)
}
```

Every field of every row is public, and the register is hashed into every block's state root
(leaf domain `rand-validator-leaf-2`; `rand-validator-leaf-4`, with `activation_epoch` appended,
on a chain whose genesis has the `staking` section of §2), so a node that disagrees about one of
them disagrees about the chain. A row is created by genesis or by the bond that registers the validator, and is never
deleted: a validator that unbonds everything keeps a row with `stake = 0`, which is simply in no
epoch's set.

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

### The `staking` genesis section (v0.5.4, audit v4 STAKE-2)

Audit v4 pointed out that on a faucet chain the register was free to buy: `Mint` hands any
validator key 100 RAND per transaction with no counter, so ~91 mints and one `Bond` reached a
third of chain 14's genesis stake, active at the next boundary. Three rules close that. All three
are **switched on by one optional genesis section** and are off — behaviour and hashes
byte-for-byte unchanged — on any chain whose genesis lacks it, chain 14 included:

```json
"staking": { "faucet_budget_per_epoch": "100000000000", "bond_activation_epochs": 2 }
```

- **Activation delay.** A row created by a `Bond` in epoch `e` records
  `activation_epoch = e + 1 + bond_activation_epochs`, and `derive_set` skips a row whose
  activation epoch is past the epoch it is deriving *for*: the bond is in no set for epochs
  `e + 1 ..= e + N` and joins at `e + N + 1`. Genesis validators carry 0 and are in every set from
  epoch 0; a top-up of an existing row never moves its activation epoch — but since the bond
  queue below, the top-up's own amount waits exactly as long as a registration does. With
  `bond_activation_epochs: 0` the rule is exactly today's ("weight at the next boundary"). The
  field is hashed into the validator leaf (`rand-validator-leaf-4`) only under the section.
- **The bond queue** (the v4 re-review's "delay" gap). Under the section every `Bond` — a
  registration and a top-up of an active row alike — adds its amount to the row's `stake` at once
  (the supply audit, `rand_getValidators` and the overflow bound see bonded value where it is)
  *and* appends `(validator, amount, epoch = e + 1 + bond_activation_epochs)` to a ledger-wide
  queue, in the order the bonds are applied (a validator's consecutive rows for one epoch merge).
  A row's set weight is its `stake` less what of it is still queued for a later epoch, so before
  the queue an active validator could top up and be weight at the very next boundary while a fresh
  key served the whole delay; now neither can. Queued stake cannot be unbonded
  (`InsufficientStake` names the active part). The last block of every epoch admits the rows due
  at the next one (below), and admitted rows leave the queue. The queue is consensus state: its
  root (`rand-bond-queue-1`, length then every row in order) is appended to the `rand-state-5`
  root, it is persisted beside the supply counters (`META_BOND_QUEUE`) and `rand-node verify`
  replays it.
- **The faucet budget.** The ledger keeps `(faucet_epoch, faucet_minted_in_epoch)`; a `Mint` that
  would push the epoch's total over `faucet_budget_per_epoch` is refused
  (`FaucetBudgetExhausted`), and the counter starts from zero in the first block of the next
  epoch — the epoch is the ledger's own, `height / epoch_blocks`, never wall time. The refusal is
  state, not bytes: the node never caches it as permanent, and the same transaction is admitted
  again an epoch later. Both counters are consensus state under the section: the state root is
  re-domained `rand-state-5` with them appended, they are persisted beside the supply counters
  (`META_FAUCET_EPOCH`) and `rand-node verify` replays them. `rand_getSupply` reports them as
  `faucet_epoch` / `faucet_minted_in_epoch`.
- **A bridged chain has no faucet.** `faucet: true` beside a `bridge` section is refused at
  genesis (`GenesisError::FaucetWithBridge`) once the section is present: free RAND against a
  chain holding bridged custody is what the finding is about. Chain 14's genesis has both and no
  section, so it still loads — and a testnet that wants both names its testers instead
  (`faucet_recipients`, below).

Three further fields close what the v4 re-review still found open in the gated rules
("admission, weight cap, proof of possession"). Each is optional *inside* the section, omitted
from the file when absent, and committed to the genesis hash by name only when present, so a
section without them hashes exactly as v0.5.4's did:

```json
"staking": {
  "faucet_budget_per_epoch": "100000000000", "bond_activation_epochs": 2,
  "max_weight_bps": 3333, "max_stake_entry_per_epoch": "10000000000000", "registration_v2": true
}
```

- **`max_weight_bps` — the weight cap.** No validator's voting weight exceeds this fraction of its
  set's total, in basis points (3333 = a third; `1..=10000`, 10 000 = no cap). The cap is applied
  once, in `staking::cap_weights`, to every set `derive_set_with` derives and to the genesis set,
  so the quorum and third checks, QC verification and everything else that reads a
  `ValidatorSet` see the capped weights and nothing else; the register's `stake` is unchanged.
  Clamping lowers the total, so a one-pass cap at a third of the unclamped total would leave the
  clamped validator above a third of the new one. Instead one level `C` is computed: with the
  weights sorted descending `w_0 ≥ … ≥ w_{n−1}` and `R_k = w_k + … + w_{n−1}`, clamping exactly the
  top `k` needs `C ≤ b·(k·C + R_k)/10⁴`, whose largest integer solution is
  `C_k = ⌊b·R_k / (10⁴ − b·k)⌋`; the smallest `k` with `C_k ≥ w_k` is taken, every weight above
  `C_k` is lowered to it and nothing else moves. A set of fewer than ⌈10⁴ / b⌉ validators cannot
  meet the cap at all (three equal validators hold a third each) and is levelled to its smallest
  weight. A faucet-bought whale with 96 % of the stake ends with a third of the weight — no quorum
  alone, and not even a blocking third. The cap binds one key, not one operator: many keys are
  what the entry budget and the delay are for.
- **`max_stake_entry_per_epoch` — the admission (churn) limit.** The most stake, registrations and
  top-ups together, that may become weight at one epoch boundary, in RAND's base unit as a
  decimal string (`> 0`). The last block of epoch `e − 1` walks the bond queue front to back and
  admits the rows due by `e` while the budget lasts — a row in part when it runs out mid-row —
  and moves whatever of the due rows is left to epoch `e + 1`, keeping its place. The set for `e`
  is derived from that very ledger, so it counts exactly what was admitted. Absent, every due row
  is admitted (the delay rule alone). A large bond at the head of the queue holds everyone behind
  it for as many epochs as it needs — the price of an order nobody can jump.
- **`registration_v2` — proof of possession, bound to the chain.** The v1 registration a new row
  carries is the key's signature over `(chain_id, payout)` under `rand-register`: it proves the
  key, but binds neither the chain's genesis (any chain sharing the id accepts it) nor the address
  it registers. With `true` the registration is `rand-register-2` over
  `(genesis hash, chain_id, validator address, payout)` — the genesis-hash binding the consensus
  domain's v1 tags use — and a v1 registration is refused (`BadSignature`). `rand-node register
  --v2` signs it (the genesis hash is read from `--rpc`). Absent or `false` is the v1 rule and
  commits nothing.

One more optional field lets a testnet keep a faucet beside a bridge (chain 15):

```json
"staking": {
  "faucet_budget_per_epoch": "100000000000", "bond_activation_epochs": 2,
  "faucet_recipients": ["rand1…the operator's address…", "rand1…a second tester's…"]
}
```

- **`faucet_recipients` — the faucet allowlist.** A `Mint` publishes its note's opening, and the
  ledger recomputes `cm` from it (POOL-1), so the note's owner `pk` is on the wire; under this list
  a `Mint` whose `pk` is not on it is refused (`FaucetRecipientNotAllowed`) at admission and at
  apply, before any signature work. The faucet then feeds the named wallets and cannot buy the
  register for anyone else, which is why the list — and only the list — lets `faucet: true` sit
  beside a `bridge` section. The budget still applies on top. An entry is either a whole `rand1…`
  address, exactly what `rand --key <wallet.key.json> address` prints (its `pk` is taken, its
  ML-KEM key dropped), or that `pk`'s 64 hex characters; the file is written back as hex, and only
  the 32 `pk` bytes are committed to the genesis hash, key by key in file order, so both spellings
  are the same chain. An empty or duplicated list is refused at `init` (`BadStaking`). The refusal
  is about the transaction's own bytes against a genesis constant, so the node caches it as
  permanent. A tester outside the list is sent coins by a listed wallet, like anyone else.

Not in v0.5.4: slashing (audit decision D8 — "it means nothing while stake is free").

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

Prints the validator's address and a hex `Registration` — its public key, the payout address, and a
signature over `(chain_id, payout)`. The RPC is only read for the chain id: a registration signed
for one chain is refused on another. The payout address comes from a **wallet** key
(`rand --key payout.key.json address`), not from a node key, and it is the one field a later
top-up cannot change.

Hand the hex to whoever holds the stake.

### Bond

```bash
rand bond <validator base58> <amount in RAND> \
    [--registration <hex>] [--fee <RAND>] [--no-wait] [--cuda]
```

A bond is an ordinary shielded transaction: the wallet proves the one 4-in/4-out hidden-asset bundle
(since chain 14) whose RAND burn, `burn_r`, is the staked amount — `burn_a` and `burn_asset` stay
zero, so a bond can only ever burn RAND — and the ledger admits a bond only when `burn_r == amount`.
It takes about a minute and a half of local proving, like any transfer.

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

Pays released value into a deposit note at the register's `payout` address. Released means
`rewards` plus the `pending` rows whose `release_epoch` has arrived; the command takes the released
rows oldest first and then the rewards.

Like an unbond it is validator-signed and bundle-less, but it is not free: it pays the 0.001 RAND
bundle base to the proposer of the block that applies it, **out of the amount withdrawn**. So a
withdrawal of 1000 RAND leaves the register entirely and creates a note worth 999.999 RAND, and
an amount that cannot cover the base is refused rather than buying a note worth nothing.

The note is the one the chain computes for itself, from the register's payout address, the amount
less the base, the blinding `r` the action publishes, and the action's own `time`:

```
cm = H_CM(payout.pk, from = 0, amount − 0.001 RAND, asset 0, time, r)
```

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
three are part of the genesis hash — the payout address included, because it is register state.
Genesis refuses a stake below `MIN_STAKE`: such a validator would be in the register but in no
epoch's set, and a chain seeded entirely from those would have nobody to pick a leader from.

## 5. What is public

| | public | hidden |
|---|---|---|
| the register | every row: address, stake, unbonding queue with its release epochs, unpaid rewards, payout address, nonce | nothing |
| `Bond` | the validator, the amount, whether a registration was attached, and the bundle's `burn_r` | which notes paid, who owns them, the bonder's change |
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
