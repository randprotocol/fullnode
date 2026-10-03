# RPL-3: perpetual futures

RPL-3 lets a chain host a perpetual-futures exchange without running it. It is a genesis-gated
feature (the `perps` section); on a chain without it every perp action is refused and nothing else
changes. The design is `docs/superpowers/plans/2026-10-03-rpl3-perps.md`; this page is the
integrator's guide. The engine, its guest, the prover and the trading site are durian.market's
(`../durian.market`); the chain's half is here.

## The model

The chain never matches an order. It records, and a proof settles:

1. **Orders enter through consensus, unexecuted.** A trader signs an order, a cancel or a
   withdrawal request; a validator signs oracle prices; a deposit rides a bundle. The ledger checks
   what it can check by lookup (the key, the nonce window, the shape of the order) and appends the
   input to the block's word string. Whether the order is any good is not its business.
2. **Each block closes with a digest.** The block's inputs, then one `Close` input carrying the
   height, the block time and each market's oracle median, are hashed to `D_h` and recorded.
3. **The engine is proved.** The engine is a zkVM guest (`perp-engine.image.bin`, fixed by
   `engine_hc` in the genesis). One `PerpStateProof` runs it over a window of blocks and proves
   that the exchange's state moved from the root the chain holds to a new one, over exactly the
   digests the chain recorded, paying exactly the withdrawals it lists.
4. **Anyone may prove.** A state proof carries no signature and no bundle; the STARK is the
   authority. There is no prover register: whoever has the engine, the inputs and the time can
   advance the chain, and a second proof of the same window is simply refused (the window must
   start at the proved height).
5. **Settlement is final at proof.** Until a proof lands, an account's collateral and positions
   are the engine's state as of the proved height and nothing the chain holds as a note. When it
   lands, the root moves and each payout becomes a note.

Nothing about balances, positions or the book is in the ledger. The ledger holds only what it
needs to admit the next transaction: the trading keys and their nonce windows, the oracle, the
proved root and height, the digests not yet proved, and the withdrawals waiting to be paid.

## The genesis section

`rand-node genesis --perps perps.json` takes a `PerpsConfig`:

```json
{ "collateral_asset": 0,
  "max_tier": 18,
  "max_window_blocks": 64,
  "max_block_inputs": 8,
  "min_deposit": 1000000,
  "engine_hc": "<64 hex>",
  "genesis_root": "<64 hex>",
  "markets": [
    { "id": 0, "symbol": "BTC-PERP", "lot": 1000000, "tick": 1000000,
      "max_leverage": 20, "maintenance_bps": 500, "taker_fee_bps": 5, "maker_fee_bps": 2 } ] }
```

| field | meaning |
|---|---|
| `collateral_asset` | the asset deposits are made in and withdrawals paid in: `0` is RAND, otherwise a token the same genesis lists |
| `max_tier` | the highest zkVM tier (10, 12, 14, 16, 18 or 20) a state proof may be made at; it bounds what a proof costs to verify |
| `max_window_blocks` | the most blocks one state proof may cover, 1 to 64 |
| `max_block_inputs` | **required.** The most perp inputs (deposits, orders, cancels, withdrawals; not the `Close`) one block records, 1 to `MAX_BLOCK_INPUTS` = 1024. With `max_window_blocks` it bounds a window's engine work (below) |
| `min_deposit` | optional, default 0 (no floor): the smallest deposit, in collateral units; below 2^63 |
| `engine_hc` | the engine guest's program commitment; a state proof of any other program is refused. Hex byte order: each u32 word of `hc` as 8 little-endian hex characters (`word8_to_hex`); `rand perp image-hc --image <FILE>` prints an image's hc in that format, and `rand perp prove` refuses an image that does not match before proving |
| `genesis_root` | the engine's state root at height 0: `perp_digest(PERP_STATE, State::genesis(markets).encode())`. `perp-prover genesis-state` writes the words and `rand perp genesis-root --state` hashes them |
| `markets` | the `MarketSpec` list below |

`MarketSpec`: `id`, `symbol`, `lot` (the size increment in base atomic units), `tick` (the price
increment, in quote atomic units per `BASE_UNIT` = 10^9 of base), `max_leverage`,
`maintenance_bps`, `taker_fee_bps`, `maker_fee_bps`. The engine keeps its own copy of these in its
state, which `genesis_root` already commits to; the ledger keeps them to refuse an order for a
market that does not exist or is off the lot and tick grid.

**Requirements**, each refused by name at `genesis` (`Genesis::validate`, `PerpsConfig::check`):

- `max_tier` is one of the six tiers; `max_window_blocks` is in `1..=64`; `max_block_inputs` in
  `1..=1024`; `min_deposit` below 2^63;
- 1 to `MAX_MARKETS` = 2 markets — **the ledger pins 2**, the pinned engine's capacity (a new
  engine image may raise it) — ids `0, 1, …` in order, `lot` and `tick` positive,
  `max_leverage` in `1..=100`, `maintenance_bps` at least 1 (the engine requires a maintenance
  margin), each `*_bps` at most 10 000;
- the chain has `confidential`, `tokens`, `gas`, `hardening_v6` and `hc_auth` (the CLI says them
  as `--tokens`, `--gas-price`, `--hardening-v6`, `--auth-guest`);
- a non-zero `collateral_asset` is a token the file lists.

The section is bound into the genesis hash last, and into the state root under `rand-state-9`
(below). The genesis fixes it for the chain's life: there is no action that adds a market or
changes a bound.

**Sizing a window.** The engine's work per window grows with the inputs it reads, so
`max_block_inputs × max_window_blocks` must fit the engine's cycle budget at `max_tier`. At tier
16 the pinned engine has about 65 000 cycles, some 20 000 of them fixed per window; an operator
sizes the two bounds to fit what is left. The devnet runs `max_block_inputs = 8` with
`max_window_blocks = 4`.

### Per-block input caps

Every block records at most `max_block_inputs` perp inputs (`BlockFull`) and at most
`MAX_ACCOUNT_INPUTS_PER_BLOCK` = 8 from one account (`AccountBlockFull`) — **a deposit counts
towards the account it credits**. Both are refused by `validate` and by `apply` before any write,
against the inputs the block has recorded so far; neither is permanent (the next block has room).
A pool does not refuse on them: its ledger is the tip's, whose block inputs every close empties,
so `still_applies` never reads them and an input a full block left out stays pooled for the next.
A block carrying more is refused whole; the proposer's trial apply packs exactly the first
`max_block_inputs` that apply.

With at most 15 accounts, the per-account cap also bounds a block's words whatever
`max_block_inputs` says: 15 × 8 inputs × 21 words (a withdrawal's, the longest) + one `Close`
over 2 markets (12) = 2 532 words, inside the guest's 8 192-word block buffer.

## The six actions

Tags 34 to 39, appended after `Invoke` (33). The four signed ones are bundle-less and carry a
signature over `Transaction::perp_sign_message(binding_domain, chain_id, action)`.

**Signed messages.** Over the chain's binding domain (BIND-1), as every other signed action
message is:

- `binding_domain` 0 (absent): `blake3("rand-perp-sign-1", bincode(chain_id, tag, unsigned))`;
- `binding_domain` 1: `blake3("rand-perp-sign-2", bincode(genesis_hash, (chain_id, tag,
  unsigned)))` — the genesis hash leads, as in `BindingDomain::token_mint_message`.

`unsigned` is the action with an empty signature. The tag keeps one variant's signature from
verifying as another's, the chain id and (under domain 1) the genesis hash keep it off other
chains: a signature made for domain 0 is `BadSignature` on a domain-1 chain. The `rand perp`
commands learn the domain from the node (`RpcClient::binding_domain`, as a mint does).

An **account id** is `word8_from_bytes(Address::from_public_key(trading_key))`, the eight words of
the trading key's address; `rand perp keygen` prints it. A trading key is a Dilithium2 key, and it
is not the owner's spend key: it signs orders and nothing else.

| tag | action | signed by | fee floor |
|---|---|---|---|
| 34 | `PerpDeposit { trading_key }` | none: its bundle authorises it | 0.001 RAND (`BUNDLE_BASE`), paid from the bundle |
| 35 | `PerpOrder { account, body, signature }` | the account's trading key | 0 (bundle-less) |
| 36 | `PerpCancel { account, nonce, target, signature }` | the account's trading key | 0 |
| 37 | `PerpWithdraw { account, nonce, amount, recipient, r, time, envelope, signature }` | the account's trading key | 0 |
| 38 | `PerpOracle { validator, prices, nonce, signature }` | a validator's key | 0 |
| 39 | `PerpStateProof { from_height, to_height, new_root, payouts, fees, proof }` | none: the STARK is the authority | 0 |

Every rule below is checked by `validate`, in this order; the per-block caps come after the
action's own rules, and the signature last: it is the one expensive check. `apply` is only ever
reached through `apply_tx`, which runs `validate` on the same state first, and then re-checks,
before its first write, exactly the rules a write depends on: the section gate and the per-block
caps; for a deposit the collateral shape, the amount and floor and (for a new account) the
account cap and the reserved id; for an order and a cancel the account and the nonce; for a
withdrawal the account, the nonce, the request id, the pending cap, the opening and the
one-per-account rule; for a state proof every rule of `check_state_proof` (window, digests,
payouts) and the counters' overflow. It does not re-check an order's shape, a withdrawal's
envelope, recipient or time, an oracle's validator and prices, or any signature or STARK — those
`validate` decided on the same state a moment before. So a refusal leaves the ledger as it was.

### Deposit (34)

The bundle burns the collateral and nothing else: RAND through `burn_r` with `burn_a` and
`burn_asset` zero, or the collateral token through `burn_a` with `burn_r` zero. Anything else is
`CollateralAssetMismatch`; a zero amount is `ZeroAmount`. The account is the one the trading key
owns: a deposit by a new key opens it, a deposit by a key that already owns it tops it up.

- At least the genesis **`min_deposit`** (`DepositTooSmall`), when one is set.
- At most **15 trader accounts** (`TooManyAccounts`): the engine has 16 slots and keeps one for its
  insurance fund. The id `[0; 8]` is that fund's and no key may own it (`ReservedAccount`).
- An account id whose recorded key differs from the deposit's is `KeyMismatch`.
- A RAND deposit's `burn_r` is counted in `supply.burned` by the common path; the audit counts it
  back as the exchange's (below).

### Order (35) and cancel (36)

- The account must exist (`UnknownAccount`): deposit first.
- **Nonce window.** Per account: `nonce_high` and a 64-bit `used` bitmap over
  `nonce_high-63 ..= nonce_high`. A nonce `n` is accepted iff `n > nonce_high` (the bitmap shifts
  left by `n - nonce_high`, to 0 past 63, `nonce_high = n`, bit 0 set), or it is in the window
  with its bit clear (the bit is set). Anything else is `NonceUsed`. So orders need not arrive in
  order, a trader may have many in flight, and one more than 63 below the highest is refused
  because the window no longer remembers it. A cancel takes its own nonce from the same window.
- An order's body is checked for shape: a known market (`UnknownMarket`); `side` 0 buy or 1
  sell; `kind` 0 limit or 1 market; `tif` 0 GTC, 1 IOC or 2 post-only; `size` a positive multiple
  of the market's `lot`; a limit order's `price` a positive multiple of `tick`; a market order
  carries no price (all `BadOrder`). `reduce_only` is a boolean.
- A cancel's `target` is an order's nonce. The chain does not check that it names an order: the
  engine ignores a cancel of nothing.

### Withdraw (37)

A request to move collateral out of the engine to a note the chain will compute.

- The account exists; `amount` is positive (`ZeroAmount`) and **below 2^63** (`AmountTooLarge`):
  a note at or above 2^63 cannot be spent, so a request for one could only fail at payout while
  holding a slot.
- **At most 8 withdrawals pending** at once (`TooManyWithdrawals`), which is
  `MAX_PERP_PAYOUTS`: a state proof pays at most 8, so no more may wait. Without the cap one
  holder could queue requests no proof can ever pay.
- The envelope and the recipient pass the same checks as an RPL-2 payout's
  (`check_note_envelope`, `check_recipient`).
- **`time` is a block height** within the ledger's proof window (`time <= height` and
  `height - time <= proof_window_blocks`), the same check a bundle's `time` meets, not a wall-clock
  value.
- The nonce is taken from the window, and the request is held under its **request id**, the
  transaction hash as eight words.
- **One pending withdrawal per account** (`WithdrawalPending`, not permanent): the next request
  waits until a proof settles this one. With the cap of 8 it keeps one account from holding every
  slot.
- **No two pending withdrawals share `(recipient.pk, r)`** (`DuplicateOpening`). The payout note is
  `H(pk, PERP_FROM, amount, asset, time, r)` and `r` is public on the wire: a copy of a pending
  request's `(pk, r)` could commit to the same note, and the request whose id sorted first would
  mint it with its own envelope, leaving the owner's never recorded.

### Oracle (38)

A validator's prices, one per market named.

- The signer is **a validator** in the register and **not jailed** (`NotValidator`).
- At least one price, every price positive (`BadPrice`: the engine reads a median of 0 as "no
  price"); markets known (`UnknownMarket`) and **strictly ascending** (`UnorderedPrices`).
- The nonce is above the validator's last (`OracleNonce`). The CLI uses the wall clock in ms.
- Apply records `(price, height)` for each market under the validator's address, and the nonce.
  An oracle transaction is not an input of its own: its prices reach the engine through the block's
  `Close`.

### Block close and `D_h`

At the end of every block on a perps chain (`Ledger::close_block`, before the anchor):

1. Submissions of validators that have left the register are dropped, so a departed key does not
   sit in the root for ever. A jailed validator's submissions stay (it may serve again) and weigh 0.
2. Each market's **median** is the stake-weighted median of its fresh submissions: those given at
   `height - 30` or later (`ORACLE_STALE_BLOCKS`), each weighted by its validator's stake now,
   sorted by price; the median is the first price at which the running stake reaches half the
   total, rounded up. **Only with a quorum:** the fresh stake (non-stale, non-jailed, in the
   register) must be at least half of the active stake (every registered, non-jailed
   validator's). Without one — nothing fresh, or too little of the set behind it — the close
   carries **0**, the engine's "no price", and the old median is **not** kept. A chain of one
   validator is its own quorum.
3. The block's inputs, in block order, then exactly one `Close`, make the block's words;
   `D_h = perp_digest(PERP_BLOCK, words)` is recorded for every closed height above the proved
   height. The words are left for the node to store; the inputs are emptied.

Every step reads only consensus state, the block's height and its timestamp.

### State proof (39)

`from_height`, `to_height`, the engine's `new_root`, the withdrawals it pays and the fees it
collected, and the proof. The cheap rules come first and decide whether the STARK is looked at at
all:

- **Window.** `from_height` equals `proved_height`; `to_height > from_height`; and
  `to_height - from_height <= max_window_blocks` (`WindowMismatch`). **Every height in
  `from+1 ..= to` has a recorded digest** (`MissingDigest`), which is the whole bound on `to`: it
  must be a closed block.
- **Payouts.** At most 8 (`TooManyPayouts`). Each names a pending request (`UnknownRequest`), each
  request at most once (`DuplicatePayout`), each request **recorded inside the window**,
  `from < height <= to` (`RequestOutsideWindow`), and each amount is **the full request or
  nothing**: above it is `PayoutTooLarge`, a positive amount below it `PartialPayout`. They are
  listed **in the order the engine emits them**, which is the order the withdrawals were input,
  not sorted; the payouts digest binds that order.
- **The segment.** The ledger builds the public segment itself from its own proved root and
  recorded digests and the transaction's claims, so a prover cannot choose which block inputs the
  proof ran over:

  ```
  [PERP_VERSION = 1, from_lo, from_hi, to_lo, to_hi,
   R_from(8), R_to(8), payouts_digest(8), fees_lo, fees_hi, n_blocks,
   D_{from+1}(8), …, D_to(8)]
  payouts_digest = perp_digest(PERP_PAYOUTS, [n, (request(8), amount_lo, amount_hi)*])
  ```

  The ledger puts the proved root at `R_from`, the transaction's `new_root` at `R_to`.
- **The STARK.** Verified against `engine_hc` and the segment, like a call's proof and after every
  other check. A tier above `max_tier` is `TierTooHigh`; any other failure is `ProofRefused`. The
  engine's own two outputs must read: the version `1`, and a block count equal to
  `to_height - from_height`.
- **Payouts become notes the chain computes.** For each payout of a positive amount:
  `note_commitment(recipient.pk, PERP_FROM, amount, collateral_asset, time, r)`, with the
  request's recipient, `r` and `time`, and `PERP_FROM = "rpl3-pay"` as two little-endian words then
  zeros. The request's envelope is appended beside the commitment, so the owner's wallet finds the
  note by trial decryption as it finds any other. A payout of zero mints nothing. A payout whose
  note the tree already holds mints nothing and adds nothing to the audit. A payout is the full
  request or nothing — a consensus rule (`PartialPayout`), not only the engine's behaviour — so
  the amount sealed in the envelope is the amount paid.
- **Settlement.** The proved root and height advance, the digests the proof covered are dropped,
  and **every pending request recorded at or below `to` is settled**, paid or not: the engine saw
  it in this window, and a request it skipped can never be paid by a later one.

The proof is not a bundle's: `proof` is kept inside the transaction's binding, as a call's is, and
`proof_bytes` is capped by `max_proof_bytes`.

### The supply audit

A RAND deposit's `burn_r` is inside `burned`; a payout mints a note. The ledger keeps two counters
outside the state root, `rand_in` (Σ RAND deposited) and `rand_out` (Σ RAND paid by proofs), derived from the
chain like RPL-2's, and `Ledger::audit` folds them in as the identity's fifth
term, beside RPL-2's vaults. `rand_getSupply` serves `perps_rand_out` and `perps_rand_held`
(`rand_in - rand_out`). On a chain whose collateral is a token both are `"0"`: **a token's supply
is not audited by this term**, because a token's total supply does not move on the way in or out.

## What the guest sees

The guest is given the proof's public segment above, and a private witness:

```
[n_state, state_words…, n_blocks, (n_words, block_words…)*]
```

It hashes the state it was handed and the state it ends with (`R_from`, `R_to`), each block's
words (`D_h`) and the payouts the engine made, runs the engine over the blocks, and requires each
to equal what the public segment says, with the fees. It outputs
`[PERP_VERSION, n_blocks, n_orders, n_fills, n_liquidations, n_payouts, 0, 0]`: the ledger reads
the first two. A segment whose version word is `0xFFFF_FFFF` is the guest's echo mode and is never
admissible, because the version must equal 1.

## Hash domains

| name | what | where |
|---|---|---|
| `PERP_BLOCK` = 21 | a block's input digest `D_h` | Poseidon2 domain, ledger and guest |
| `PERP_STATE` = 22 | the engine's state root `R` | Poseidon2 domain |
| `PERP_PAYOUTS` = 23 | a state proof's payouts digest | Poseidon2 domain |
| `rand-perp-sign-1` | what a signed perp action signs, `binding_domain` 0 | blake3 |
| `rand-perp-sign-2` | what a signed perp action signs, `binding_domain` 1 (genesis hash first) | blake3 |
| `rand-perps-1` | the perps root, over proved root and height and five merkle roots | blake3 |
| `rand-perp-account-1`, `-oracle-1`, `-oracle-nonce-1`, `-digest-1`, `-withdrawal-1` | the leaves of those five roots | blake3 |
| `rand-state-9` | the chain's state root on a chain with the section | blake3 |

`rand-state-9` wraps exactly the bytes the chain without the section commits, then appends the
perps root. It sits beside RPL-2's: program state first, then perps. A node whose database and
genesis disagree on the section refuses to start.

The perps root commits every consensus field: the accounts' keys and nonce windows, **the
oracle's submissions and each validator's last nonce** (they decide whether the next oracle
transaction is valid, so two nodes that differ in them must differ in root), the proved root and
height, the recorded digests, and the pending withdrawals. The two audit counters and the two
per-block transient fields are outside it.

### `perp_digest(domain, words)`

```
acc = H(domain, [len(words) as u32])
for chunk in words.chunks(4000):
    acc = H(domain, acc(8) ‖ chunk)
return acc
```

The length word keeps `[a]` and `[a, 0]` apart; the chunk size keeps `1 + 8 + 4000` under the
`POSEIDON2` syscall's 4 096-word cap, so the guest computes the same digest in the same calls.

## The word encodings

`PerpInput::words`: every `u64` is two words, low first; every `Word8` is its eight words.

| input | tag | layout | words |
|---|---|---|---|
| Deposit | 1 | `[1, account(8), amount_lo, amount_hi]` | 11 |
| Order | 2 | `[2, account(8), nonce_lo, nonce_hi, market, side, kind, tif, reduce_only, price_lo, price_hi, size_lo, size_hi]` | 20 |
| Cancel | 3 | `[3, account(8), nonce_lo, nonce_hi, target_lo, target_hi]` | 13 |
| Withdraw | 4 | `[4, account(8), nonce_lo, nonce_hi, amount_lo, amount_hi, request(8)]` | 21 |
| Close | 5 | `[5, height_lo, height_hi, time_ms_lo, time_ms_hi, n_markets, (market, median_lo, median_hi)*]` | 6 + 3n |

`side`: 0 buy, 1 sell. `kind`: 0 limit, 1 market. `tif`: 0 GTC, 1 IOC, 2 post-only.
`reduce_only`: 0 or 1. A block's words are its inputs concatenated in block order, then exactly one
`Close`. `tests/vectors/perps-v1.json` pins the encodings, the digest and the segment so the
engine's crate, which cannot depend on this one, can check that it agrees. It also pins the
multi-chunk digest with the real Poseidon2: `digest_4000`, `digest_4001` and `digest_8001` are
`perp_digest(PERP_BLOCK, w)` over `w[i] = (i as u32).wrapping_mul(2654435761)` of 4 000, 4 001
and 8 001 words (one chunk, the chunk boundary, the three-chunk boundary), written by
`randprotocol-zkvm`'s `tests/perps_vectors.rs`.

The engine's state encoding (`State::encode`, hashed under `PERP_STATE` to give `R`):

```
[1 (version), next_order_seq(2), insurance(2), fees(2),
 n_markets, Market*, n_accounts, Account*, n_orders, Order*]
Market   = [id, lot(2), tick(2), max_leverage, maintenance_bps, taker_fee_bps, maker_fee_bps,
            funding_index(2, i64), last_oracle(2), last_funding_ms(2)]               15 words
Account  = [id(8), collateral(2), nonce_high(2), used(2), Position × MAX_MARKETS]
Position = [size(2, i64), entry_notional(2), funding_index(2, i64)]                   6 words
Order    = [seq(2), account_index, market, side, nonce(2), price(2), remaining(2), reduce_only]  12 words
```

The engine's constants (`perp-core`): `MAX_MARKETS = 2` (which the ledger pins, `perps::MAX_MARKETS`),
`MAX_ACCOUNTS = 16`, `MAX_ORDERS = 32`
(resting orders, all markets), `MAX_WITHDRAWS_PER_WINDOW = 8`, `BASE_UNIT = 10^9`,
`FUNDING_PERIOD_MS = 8 h`, `FUNDING_CLAMP_BPS = 50`. The genesis state is
`State::genesis(markets)`: counters 0, no accounts, no orders.

## Block time is bounded

A `Close` carries the block's timestamp and the engine's funding runs on it, so on a perps chain
block time is consensus input, as on a bridged chain (`Ledger::bounds_block_time`): a block may not
rewind past its parent, may not step more than 60 000 ms past it, and the proposer's clamp and the
drift vote rule apply. **NTP is a requirement for a perps chain's validators**, as it is for a
bridged one.

## The node

- **Persistence.** `META_PERPS` holds the `Perps` state as of the head, beside the other
  section states; it is written with the block's commit.
- **The `perp_inputs` column family.** Height (big-endian u64) to the block's input words. The
  words are written **in the same batch as the block**, so a crash cannot leave a perps block
  stored without the words a prover needs. A block whose words do not match the chain (absent on
  a perps chain, present on one without) is `Corrupt`. `rand_getPerpInputs` serves them.
  `rand-node verify` compares the stored words with the replayed chain's.
- **Pruning at proof.** The family holds only the heights above the proved height: the batch that
  commits a state proof deletes every row at or below `proved_height`. A height a proof has covered
  is `null` from `rand_getPerpInputs`.
- **Rollback.** The family is created on every database at first open, perps chain or not. A build
  from before RPL-3 (v0.7.1 and earlier) lists seventeen families and RocksDB refuses to open a
  database with an eighteenth, so before rolling back run
  `rand-node db drop-perp-inputs --datadir <dir>` with the node stopped. It is refused, touching
  nothing, on a database that holds perps state or any input row.
- **Genesis.** `rand-node genesis --perps perps.json` (`docs/cli.md`); the node refuses to start when its
  database and its genesis disagree on the section.
- **State-proof admission.** A state proof is bundle-less and fee-less, and its STARK is the most
  expensive check a node runs, so two node policies (never validity rules) protect it. A
  `ProofRefused` verdict is cached keyed by the transaction hash and the segment the tip builds
  for it (with the proved root it was made against), bounded, and emptied when the proved root
  moves: the same junk bytes re-sent are refused without verifying again. And the pool keeps
  **one reserved slot** for a state proof: it is admitted past the count and byte caps, never
  evicted to make room, and offered to a block after governance and ahead of fee order, so a pool
  full of free orders cannot keep out the proof that settles them. A second proof while the slot
  is held is pooled like anything else.
- **Transport.** `rand_getPerps`, `rand_getPerpAccount`, `rand_getPerpAccounts` and
  `rand_getPerpInputs` are on the public listener; `rand_getLimits` gains `perps`; `rand_getSupply`
  gains `perps_rand_out` and `perps_rand_held` (`docs/rpc.md`). Every perp action renders in
  `rand_getTransaction` under the kinds `perp_deposit`, `perp_order`, `perp_cancel`,
  `perp_withdraw`, `perp_oracle` and `perp_state_proof`.

## The CLI

`rand perp keygen | deposit | order | cancel | withdraw | oracle | prove | genesis-root | image-hc | state |
account | inputs`, in `docs/cli.md`. `rand perp prove` is the command `perp-prover` runs: it
submits and waits for inclusion, and exits non-zero on any refusal, including a `R_from` that is
not the chain's `proved_root`, which is how the prover learns to roll back.

## v0 limits

- **No prover bond (I1).** A state proof is not bound to a bonded prover register; the refusal
  cache and the reserved pool slot above are the minimum. A prover register with a bond, so junk
  proofs cost their sender, is a follow-up.
- **No withdrawal fee (I2).** The spec's bundled withdrawal is deferred: a request is bundle-less
  and fee-less, bounded only by one pending per account and 8 in all.
- **Provers versus 1 s blocks (I7).** `MAX_WINDOW_BLOCKS` is 64, and a tier-16 proof takes 76 to
  400 s, so on 1 s blocks a single prover falls behind the digests it must cover. A demo chain
  runs 2 s blocks; back-pressure on inputs while proofs lag, and eliding empty blocks from a
  window, are follow-ups.
- **The gate's error (M3).** `PerpError::Disabled` is the section gate's refusal. The five
  bundle-less actions are gated at the action step; a state proof is gated before the size caps
  (so a chain without the section answers `Disabled`, not `ProofTooLarge`).
- **Token collateral (M6).** A token's supply is not audited by the perps term: the audit cannot
  detect a token deposit and payout imbalance.
- **Engine capacities.** The ledger pins `MAX_MARKETS` = 2, the pinned engine's capacity, and
  nothing else of the engine's: `MAX_ACCOUNTS` (15) and `MAX_PERP_PAYOUTS` (8) are ledger rules
  chosen to fit it, not engine constants read from it.

## What v0 does not do

- **No prover register and no payment.** Proving is open and unpaid; the `fees` the engine
  collects stay in its state. A prover that stops is replaced by anyone who starts.
- **No forced exit.** A withdrawal is a request the engine must be proved over. If no one proves,
  collateral waits; there is no escape hatch that returns it without a proof.
- **No backstop vault.** The chain holds no reserve for losses the engine's insurance fund cannot
  cover; the fund is a balance inside the engine's state, not a note or a vault.
- **Markets are genesis-only.** No action lists, changes or delists one.
- **The mark price is the oracle median.** The chain supplies one number per market per block and
  nothing else: no separate index price, no premium.
- **No sealed orders.** Orders are public in the pool and in the block, before the engine
  sees them.
- **The supply of a token collateral is unaudited** by the perps term (above).
- **On no chain yet.** The section is inert on every chain whose genesis omits it.

## Where the rest is

The engine (`perp-core`), the guest (`perp-guest`), the prover (`perp-prover`) and the site are in
`../durian.market`; its README is the runbook. The wire shapes a prover reads are in
`docs/rpc.md`; the job file `rand perp prove` takes is in `docs/cli.md`.

## Recorded devnet run

`../durian.market/scripts/devnet-perps.sh` on 2026-10-04: fullnode `feat/rpl3` 8840fe51,
durian.market `feat/perps` ac0bd09, one validator, 2 s blocks, genesis `perps` with `max_tier`
16, `max_block_inputs` 8, `--binding-domain 1`, engine_hc `15e24915…580bb4`. Two traders deposit
500 RAND, cross 1 unit at 2000 RAND (fill at height 32), A withdraws 1 RAND (request at 36).

| fri | window | withdraw at | proved | windows (all tier 16) | cycles per window | prove s (total, max) | proof bytes (max, total) | peak RSS | deposit s A/B | engine (proved) | fills (view) | A's 1 RAND paid |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| test | 4 | 36 | 36 | 9 | 18 521–24 828 | 663.5, 78.9 | 357 286, 3 186 104 | — | 28 / 26 | 2 orders, 1 fill, 1 payout | 1 | yes, note at height 405 |
| production | 8 | 36 | 40 | 5 | 28 973–36 631 | 356.2, 71.8 | 1 556 425, 7 762 669 | 22.2 GB | 27 / 26 | 2 orders, 1 fill, 1 payout | 1 | yes, note at height 237 |
