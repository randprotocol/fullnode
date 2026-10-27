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
| `bound_payouts` | optional, default `false` (audit v10, PERP-6): a state proof whose payouts total more than the collateral the chain has counted the exchange holding — `initial_collateral + collateral_in − collateral_out` — is refused `PayoutExceedsCollateral`, at validate and at apply. Permanent: an engine that pays what it was never given is an engine fault. Off (chain 21), a payout is bounded by its request alone, and a request only by the note bound 2^63 |
| `initial_collateral` | optional, default 0: the collateral the genesis engine state already holds (accounts and insurance fund), in collateral units, below 2^63; what the count above starts from |
| `sparse_windows` | optional, default `false` (PERP-101): blocks without perp inputs record no digest, and a state proof spans up to `max_window_heights` heights over at most `max_window_blocks` recorded blocks ("Sparse windows" below). Off (chain 21), every block records a digest and a window is at most `max_window_blocks` consecutive heights |
| `engine_program_log_height` | optional, default 0 = unpinned (CON-60): the program-table height of the engine image (`rand perp image-hc` prints it on stderr as `engine_program_log_height N`). Set, a state proof declaring another program height, or any keccak or sha256 table (the engine calls neither), is refused `ProofRefused("declared shape: …")` from its header before any verifier key is built; a header that does not decode is refused the same way. Left free: the tier (at most `max_tier`) and the input height. 1 to 24 |
| `max_window_heights` | optional, default 0; required with `sparse_windows`, from `max_window_blocks` to `MAX_WINDOW_HEIGHTS` = 4096, and 0 without it: the most heights one sparse window spans, and the heartbeat interval |

The audit-v10 fields (and PERP-101's two) are bound into the genesis hash **only when set** (`PerpsConfig::commit_bytes`:
the pre-v10 shape's bincode, then each later field tagged by name), so a file that omits them —
chain 21's — hashes exactly as it did at its cut (`chain_21s_genesis_file_still_hashes_as_cut`).

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

The bound is the worst single block, and that is a mass liquidation: one counterparty against
the 14 other traders, whose close liquidates all 14. Measured on the pinned engine (durian.market
`scripts/check-perp-guest.sh`, case `block-14liq`; README "Perps" has the table): 153 845 cycles
with no inputs before the close, 212 018 with 24, 292 773 with 120. So `max_block_inputs` = 120
needs `max_tier` 20; tier 18 with 15 % headroom holds about 24 inputs. **The production sizing is
`max_tier` 18 with `max_block_inputs` ≤ 24**; the check's gate protects it (case
`block-24-14liq`, 212 018 cycles, must fit tier 18 with 15 % headroom), while `block-14liq`, the
120-input ceiling, is reported but not gated. A per-close liquidation cap that would let more
inputs fit is a later engine milestone. Tier 16 holds no close
that liquidates more than a few accounts at any input count (7 liquidations alone are 76 493
cycles), so the devnet's tier-16 genesis proves its fill blocks but not a mass liquidation.

### Per-block input caps

Every block records at most `max_block_inputs` perp inputs (`BlockFull`) and at most
`MAX_ACCOUNT_INPUTS_PER_BLOCK` = 8 from one account (`AccountBlockFull`) — **a deposit counts
towards the account it credits**. Both are refused by `validate` and by `apply` before any write,
against the inputs the block has recorded so far; neither is permanent (the next block has room).
A pool does not refuse on them: its ledger is the tip's, whose block inputs every close empties,
so `still_applies` never reads them and an input a full block left out stays pooled for the next.
A block carrying more is refused whole; the proposer's trial apply packs exactly the first
`max_block_inputs` that apply — and the pool offers the fee-less inputs account by account,
round-robin (audit v10, PERP-1 (d), "The node" below), so those slots go to distinct accounts
before any account's second input.

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

A `PerpDeposit`'s bundle is an ordinary bundle to the fee split (`Ledger::bundle_fee_split`): the
floor it pays is the schedule's, plus the genesis `fees.prove_base` where a chain sets it, and the
`fees` rules apply to it as to any bundle — under `burn_base` its base burns, under `burn_floor`
its whole floor, counted in `base_fees_burned`; the collateral burn beside it is the deposit, not a
fee. `rand perp deposit`'s default fee is that floor (`wallet::schedule_floor`).

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

### Sparse windows (PERP-101)

On 1 s blocks one prover cannot keep up with a digest per block (`max_window_blocks` is at most 64
and a tier-18 proof takes minutes), so withdrawals would wait without bound. Under the genesis flag
`sparse_windows` the engine is not run over blocks that carry nothing for it:

- **Close.** A block with no perp input records **no digest and no words**, unless
  `max_window_heights` heights have passed since the last recorded digest (or the proved height,
  when none waits) — then its `Close` is recorded as a **heartbeat**, so funding, marks and
  liquidations still run at least every `max_window_heights` heights and every window stays
  reachable. The oracle median is computed at every close either way (it is ledger state). The
  engine sees fewer closes: a liquidation or a funding step on a price that moved and moved back
  between two recorded closes is not run (funding accrues the elapsed time at the next recorded
  close, capped at one period, as before). That is the trade the flag makes.
- **Window.** `from_height` equals `proved_height`; `to_height > from_height`;
  `to_height - from_height <= max_window_heights` (`WindowMismatch`, its `max` that bound);
  `to_height` is a recorded height (`MissingDigest(to)`); and the span holds at most
  `max_window_blocks` recorded digests (`WindowTooManyBlocks`). The ledger builds the segment from
  **every** recorded digest in `from+1 ..= to`, in height order — the segment's shape is unchanged,
  `n_blocks` is their count — and the engine's block-count output must equal that count. The same
  engine image proves both kinds of window: it never reads a block's height for order.
- **Settlement** is unchanged: the proved root and height move to `to`, the covered digests go, and
  every pending request recorded at or below `to` is settled.
- **The node.** A block that recorded nothing stores no `perp_inputs` row, and
  `rand_getPerpInputs` answers `null` for it; `rand_getPerps.pending_heights` lists only the
  recorded heights. Back-pressure on new orders counts both recorded digests (four
  `max_window_blocks`) and heights (four `max_window_heights` between the head and the proved
  height).

**Building a sparse job (a prover).** From `rand_getPerps`: take `pending_heights` greater than
`proved_height`, ascending, while each is within `max_window_heights` of `proved_height` and at most
`max_window_blocks` (or the prover's own smaller cap) of them; `to_height` is the last one taken.
Fetch each one's words with `rand_getPerpInputs [h]` (never the heights between them), replay the
engine over exactly those blocks in that order, and write the job with `from_height =
proved_height`, `blocks` = those heights and words. `rand perp prove` checks the job against the
chain (`check_window`) and refuses one that skips or adds a height before proving. The client
library's `next_window_heights` is the reference for the selection.

### The supply audit

A RAND deposit's `burn_r` is inside `burned`; a payout mints a note. The ledger keeps two counters
outside the state root, `rand_in` (Σ RAND deposited) and `rand_out` (Σ RAND paid by proofs), derived from the
chain like RPL-2's, and `Ledger::audit` folds them in as the identity's fifth
term, beside RPL-2's vaults. `rand_getSupply` serves `perps_rand_out` and `perps_rand_held`
(`rand_in - rand_out`). On a chain whose collateral is a token both are `"0"`: **a token's supply
is not audited by this term**, because a token's total supply does not move on the way in or out.

**Collateral counters (audit v10, PERP-6).** Beside the RAND pair the ledger keeps `collateral_in`
(Σ every deposit's burn) and `collateral_out` (Σ every payout a state proof listed, minted or not —
the engine deducted it either way), in the collateral asset whatever it is, outside the root like
the RAND pair; `collateral_held = initial_collateral + collateral_in − collateral_out`. They are
what the genesis `bound_payouts` rule holds a proof to, and `rand_getSupply` serves them as
`perps_collateral_in`, `perps_collateral_out` and `perps_collateral_held` (token collateral
included; `rand_getPerps` carries the same four numbers). They move no term of the RAND identity.
Without `bound_payouts` they are reporting state, outside consensus equality: a node rolled onto
this build counts them from the roll (a v0.8.x row decodes with both at 0) and still compares equal
to a replay from genesis, so the first start's chain walk finds nothing to repair. The
`META_PERPS` row stays v0.8.x's bincode byte for byte, followed — only when a counter or a later
genesis field is not its default — by a trailer (`rand-perps-ext-1` ‖ the extension), which
v0.8.x's reader ignores (`Perps::encode_persisted`/`decode_persisted`). So a node can roll back
to v0.8.x on the same database.

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
- **A cancel names an order (I-4), on a `sparse_windows` chain.** The pool refuses a
  `PerpCancel` whose `target` is its own nonce, or a nonce inside the account's window that no
  order took and that is neither pooled here nor waiting in this node's verify queue: `the cancel
  names order nonce N, which no order of this account has taken` (retryable, never cached). A
  target above the account's highest nonce (an order still on its way) or older than the window
  remembers is let through. On a dense chain (chain 21) cancels are admitted as in v0.8.0. Either
  way cancels share the account's 16 fee-less slots with orders and withdrawals.
- **State-proof verifier keys (CON-60).** The executor builds the key a proof's header declares
  before it verifies anything, and a state proof is fee-less, so junk of ever new shapes would
  each cost a key build (a tier-18 key is over a minute in a debug build). Node policy, on every
  chain, never a validity rule — chain 21's verdicts are unchanged:
  - **the canonical shape.** The honest prover proves every window at the chain's canonical
    shape (below); a node reserves, caches and keeps exactly those keys;
  - a proof costs a cold-build token only if its shape has no key built **and** it passes every
    rule applied before a key is touched: the ledger's window and payout rules over the tip, the
    executor's header rules (canonical body, tier at most `max_tier`, declared caps, the public
    height of the tip's segment), the verifier's own pre-key prefix (`Machine::check_pre_key`,
    the function `Machine::verify` runs first: the public values against the genesis
    `engine_hc`, canonical values, `TIER`, `GAS`, the pc window, the commit PoW witnesses, the
    degree bits), the segment's public digest, and the genesis pin. The executor's verify path
    runs the same function (`perp_pre_key`) before it builds a key — the digest included, which
    `Machine::verify_public` alone would compare only after the key — so a proof refused for
    free never spends a token and never builds a key;
  - tokens come from two buckets of 2, each refilled one per 30 s: a **reserve** for the chain's
    canonical shapes, and a general bucket for every other shape. Canonical keys live in their
    own cache of 8 (a chain has at most four canonical shapes); other shapes share a cache of 2.
    Pins are per cache — 4 in the canonical cache, 1 in the general one, each below its cache's
    size — so neither cache ever holds more keys than its size: at most 10 state-proof keys in
    all, 6 on a chain with the genesis pin. A stored key keeps ~100 KB at every tier (its
    exported blob is 13 677 bytes), so the caches hold about 1 MB. With its bucket spent a
    proof is refused `this node is at its limit of verifier-key builds for new state-proof
    shapes; retry later` (`StateProofBusy`, retryable, never cached, no peer penalised, no
    timing). No refusal moves a bucket. An attacker can force at most one build per canonical
    shape before every honest shape is warm;
  - a shape whose proof verified here, or that a committed block carried, is pinned in its
    cache while that cache has a pin left (never evicted; non-canonical proofs can never take a
    canonical shape's pin) and recorded in the node's database; at startup, off the node loop and
    after the bundle key, the node walks the 8 newest recorded or recently committed shapes and
    builds and pins each whose cache still has a pin (reserving the pin before it builds);
  - **one state-proof key build at a time** per process, across both caches, every verify
    worker and the startup warm: a second cold shape waits for the first build, while proofs of
    warm shapes keep verifying. **The build is the memory cost**: its heap peaks at ~0.84 GB at
    tier 16 and ~3.3–4 GB at tier 18 (4× a tier step; measured with a counting allocator to tier
    16, msauth's tier-18 build at 4.0 GB). **A validator with less than 8 GB of memory should run
    a chain whose perps `max_tier` is at most 16**, or — a follow-up, not built yet — load a
    precomputed, hash-pinned state-proof key (13.7 KB, as the msauth key is loaded) instead of
    building it.

  **The canonical state-proof shape** (`ledger::perps::canonical_input_log_height`,
  `canonical_witness_words`, `segment_public_log_height`; `rand perp prove` proves at it by default
  only on a chain whose genesis sets `engine_program_log_height`, chain 22 on): for genesis `max_tier` = T and a window of n recorded blocks,

  | component | value |
  |---|---|
  | tier | T |
  | input height | h = clamp(T − 2, 7, 16): the witness is padded with zero words to 2^h − 1 words (65 535 at T = 18, 16 383 at T = 16); a longer witness is refused (prove a shorter window) |
  | public height | log2(next_pow2(max(32 + 8n + 1, 4))), at least 7: 7 for n = 1..=11, 8 for 12..=27, 9 for 28..=59, 10 for 60..=64 |
  | program height | the engine image's (genesis `engine_program_log_height` when set, else the shape a verified proof showed) |
  | keccak, sha256 | none |

  T − 2 keeps the input digest (one Poseidon2 row per four words, so 2^(T−4) rows) at half the
  tier's 2^(T−3) budget (16 384 of 32 768 rows at T = 18); 16 is the input height of the most words a proof may carry. The guest reads only
  the words its counts name, so the padding changes nothing it computes.

  **Which shape `rand perp prove` proves at.** On a chain whose genesis pins the engine's program
  height (`engine_program_log_height`, served as `rand_getPerps.engine_program_log_height`;
  chain 22 on), the canonical shape above by default. On a chain without the pin (chain 21) the
  smallest shape the window fits, unpadded, as before: chain 21's `max_tier` is 18, so canonical
  padding would put every proof at tier 18 (unmeasured, and likely past the prover host), and
  without a pin a node has no lineage for its reserve anyway. `--canonical` and `--smallest`
  force either; the pool's policy is the same whichever a prover picks.
- **Fee-less perp actions in the pool (audit v10, PERP-1).** An order, a cancel or a withdrawal
  request pays no fee, so the pool bounds them by count rather than by price — node policies,
  never validity rules, each a `mempool full`-class refusal (retryable, never cached, no peer
  penalised): **16 per account** (`MAX_PERP_ACCOUNT_POOLED`; two blocks' worth of one account's
  inputs in flight) and **1 024 in all** (`MAX_PERP_POOLED`, the backstop that keeps them off the
  fee-paying bundles' space; with 15 accounts the account cap binds first). Among candidates the
  pool ranks governance, then the state proof, then **withdrawal requests**, then everything else
  by fee; ties break by **arrival order** first and by hash last, so grinding a transaction's hash
  buys no place. The rank-0 orders and cancels are offered **round-robin by account** — every
  account's first pooled input, then every second — so a block's `max_block_inputs` go to distinct
  accounts before any account's second input: three accounts flooding chain 21's 24-input blocks
  hold three slots while the others wait. And **back-pressure**, only on a chain whose genesis sets `sparse_windows` (chain 22 on; a
  dense chain records a digest every block, so on chain 21 it would hold every order for good once
  proving fell behind): while
  `PERP_BACKPRESSURE_WINDOWS` (4) × `max_window_blocks` recorded digests wait for a proof, the node
  admits no new order or cancel (deposits, cancels, withdrawals, oracle prices and proofs are unaffected),
  so a lagging prover is not buried further. None of this returns collateral without a proof: the
  "no forced exit" limit below stands.
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
  and fee-less, bounded by one pending per account and 8 in all at the ledger, and by the pool's
  per-account and pool-wide counts of fee-less perp actions (PERP-1, "The node").
- **Provers versus 1 s blocks (I7, PERP-101).** `MAX_WINDOW_BLOCKS` is 64, and a tier-16 proof
  takes 76 to 400 s, so on 1 s blocks a single prover falls behind the digests it must cover on a
  dense chain (chain 21). Under genesis `sparse_windows` back-pressure holds new orders while proofs lag (PERP-1), and
  `sparse_windows` (from the next cut) elides input-less blocks so a window covers up to
  `max_window_heights` heights. A busy exchange (inputs in most blocks) still needs proving at the
  input rate: sparse windows bound the lag by activity, not by block count.
- **The gate's error (M3).** `PerpError::Disabled` is the section gate's refusal. The five
  bundle-less actions are gated at the action step; a state proof is gated before the size caps
  (so a chain without the section answers `Disabled`, not `ProofTooLarge`).
- **Token collateral (M6).** A token's supply is not audited by the perps term of the RAND
  identity. Since audit v10 (PERP-6) the collateral counters cover any asset and, under genesis
  `bound_payouts`, refuse a proof that pays more than was deposited; on a chain without the flag
  (chain 21) the counters are reported but bind nothing, and a payout is bounded by its request
  alone.
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

Re-run with test FRI after the liquidation-scoping fix re-pinned the engine: durian.market
27493ef, engine_hc `f286a611…1d1573`, fullnode binaries of 8840fe51 (c69a0b0f is docs only), the
same genesis shape (row "test, re-pin" below; fill at height 49, request at 53). The production
row is still the `15e24915…580bb4` engine's.

| fri | window | withdraw at | proved | windows (all tier 16) | cycles per window | prove s (total, max) | proof bytes (max, total) | peak RSS | deposit s A/B | engine (proved) | fills (view) | A's 1 RAND paid |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| test | 4 | 36 | 36 | 9 | 18 521–24 828 | 663.5, 78.9 | 357 286, 3 186 104 | — | 28 / 26 | 2 orders, 1 fill, 1 payout | 1 | yes, note at height 405 |
| test, re-pin | 4 | 53 | 56 | 14 | — | 1 042.4, 105.1 | 356 487, 4 937 279 | — | 52 / 36 | 2 orders, 1 fill, 1 payout | 1 | yes, A 9 499.999 → 9 500.999 RAND |
| production | 8 | 36 | 40 | 5 | 28 973–36 631 | 356.2, 71.8 | 1 556 425, 7 762 669 | 22.2 GB | 27 / 26 | 2 orders, 1 fill, 1 payout | 1 | yes, note at height 237 |
