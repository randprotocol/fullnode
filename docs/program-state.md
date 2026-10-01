# RPL-2: program state, program vaults and `Invoke`

RPL-2 lets a zkVM program keep state and hold value. It is a genesis-gated feature (the
`program_state` section); on a chain without it every `Invoke` is refused and nothing else
changes. The design is `docs/superpowers/specs/2026-09-30-rpl2-program-state-design.md`; this
page is the integrator's guide. The first program built on it is durian.market, a constant-product
exchange (`../durian.market`).

## What a program gets

| | |
|---|---|
| **Cells** | a map from an 8-word key to an 8-word value, per program. An absent cell reads as eight zeros; writing eight zeros removes it. Committed in the state root. |
| **A vault** | a public balance per asset (`0` is RAND). Value enters through an `Invoke`'s bundle and leaves as notes the chain computes. |
| **A token of its own** | a token registered with `MintAuthority::Program(<program id>)` and no initial supply is minted and burned only by that program's invokes. |

Nothing here is a note. Cells and vault balances are public, like a token's supply.

## `Invoke`

An `Invoke` is a `Call` that also declares a **transition** — and its call proof shows the
program accepts exactly that transition:

```
Invoke { program, proof, input_envelope, transition }

Transition {
  reads:  [{ key, value }]      // cells read, with the values read; keys strictly ascending
  writes: [{ key, value }]      // cells written; keys strictly ascending
  inflow: none | deposit | burn // what the bundle's burn_a of burn_asset is
  pays:   [{ asset, amount, recipient, r, envelope }]   // notes paid out of the vault
  mints:  [{ asset, amount, recipient, r, envelope }]   // new units of the program's token
}
```

**What comes in** is what the transaction's bundle burns, and is not repeated in the action:

| bundle field | under `Invoke` |
|---|---|
| `burn_r` | RAND deposited into the vault |
| `burn_a` of `burn_asset`, inflow `deposit` | the token deposited into the vault |
| `burn_a` of `burn_asset`, inflow `burn` | the token destroyed; it must be the program's own |

**What goes out** is one chain-computed note per payout, pays then mints:
`note_commitment(recipient.pk, PROGRAM_FROM, amount, asset, bundle.time, r)`, with
`PROGRAM_FROM = "rpl2-pay"` as two little-endian words. The amount and the recipient's `pk` are
public, as a mint's are. At most 4 payouts; at most 8 reads and 8 writes, and in practice fewer
(see the segment rule).

**The ledger applies the transition** if, and only if, the program exists, the shape is legal,
every cell in `reads` still holds the value declared, the vault (after this transaction's own
deposit) covers every pay, every mint is of the program's own token, and the two proofs verify.
A read that no longer matches is refused as `StaleRead`: the wallet re-reads and re-proves.

## What the program sees

The call proof is made over the public segment

```
public ‖ call_binding ‖ context
```

`public` is the program's deploy-time public input (usually empty), `call_binding` the eight
words of `Transaction::call_binding`, and `context` the transition as words. A program reads
context word `i` with `read_public(public_len + 8 + i)`:

| words | field |
|---|---|
| 0 | version, `1` |
| 1..=4 | `n_reads`, `n_writes`, `n_pays`, `n_mints` |
| 5, 6 | `burn_r` (low, high) |
| 7 | inflow: 0 none, 1 deposit, 2 burn |
| 8 | `burn_asset` |
| 9, 10 | `burn_a` (low, high) |
| then | each read: key (8 words), value (8) |
| then | each write: key (8), value (8) |
| then | each pay: asset, amount low, amount high |
| then | each mint: asset, amount low, amount high |

Recipients are not in the context: a program decides amounts, not who is paid; the binding fixes
who.

**The segment rule.** The whole segment must fit the public table a hardened call to the same
program is proved over: 127 words for a program with no public input, so 119 context words —
three reads, three writes and four payouts, for example. An invoke needs no verifier key a call
does not.

**The proof is state-independent.** The ledger builds the segment from the transaction, never
from its own cells, so a proof verifies or fails on the transaction's bytes alone; the read check
is a separate comparison that always runs. This is what keeps the node's verified-proofs cache
sound.

## Writing a program for it

Two rules, both without exception:

1. **Check everything you are shown.** A context word the program does not constrain is a word
   any caller may set. Pin the version, every count, the inflow kind, every key and every value
   word, for every method. durian.market's tests flip every word of every accepted context and
   demand a refusal.
2. **A refusal must leave no proof.** `guest-sdk`'s panic handler *halts*, and a halted run is a
   provable run whatever its outputs say. A program must therefore contain no panicking path
   (no indexing that can be out of bounds, no `unwrap`, no checked arithmetic that panics), and
   end a refused transition in something no run can satisfy — durian reads private input
   `u32::MAX`, an index no caller has committed. Check the linked image for the panic machinery
   before you deploy it (`durian.market/scripts/build-guest.sh` shows how).

Verify claimed amounts; do not compute them. A program that checks `out · denominator ≤
numerator` needs multiplications only, and the wallet can find the largest `out` by bisection
over the same inequality, so wallet and program never disagree about rounding.

The tier is decided by the program's size: the program is hashed into every proof, at four
words a Poseidon2 permutation, against the tier's budget (tier 12: 512 permutations, 4 095
cycles). durian's 1 635-word program proves every method at tier 12.

`guests::rpl2_counter` is the smallest example: one cell, incremented by one per invoke.

## Fees

An invoke pays a call's fee (`gas_price · gas_limit + byte_price · KiB` under a `gas` section)
plus `cell_fee` for every cell it creates — a cell written non-zero where none was stored.
Rewriting or deleting a cell is free. `rand_estimateFee {"kind":"invoke", …}` says.

## Genesis

```json
"program_state": { "cell_fee": 10000000 }
```

`rand-node genesis --program-state-cell-fee 10000000`. The section requires `tokens`, `gas`,
`hardening_v6`, `hc_auth` and `confidential`; `cell_fee` is at most 1 000 RAND. It is bound into
the genesis hash after `gas`, and adds the program-state root to the state root under
`rand-state-8`.

## RPC and CLI

- `rand_getProgramCell(program, key)`, `rand_getProgramCells(program, {after, limit})`,
  `rand_getProgramVault(program)`; `tx_json` renders `invoke`; `rand_getLimits` reports the
  section; `rand_getSupply` reports the vaults' RAND. See `docs/rpc.md`.
- `rand program invoke <id> --transition <file.json> [--inputs-file …]`, `rand program state`,
  `rand program vault`, `rand token create --program <id>`. See `docs/cli.md`.

## What is public

Amounts at both ends (reserves in cells, a deposit as a burn, a payout with its recipient's
`pk`); who paid in is not — the bundle names nobody, as ever. A program's own token, once
minted, is a shielded note like any other.
