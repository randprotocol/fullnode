# Multisig accounts: M-of-N controlled public balances

> **Status: on `main` (fullnode 3119a29a), not yet on any chain.** The section is genesis-gated: a
> chain without it refuses all four actions (`UnsupportedAction("multisig")`) and runs byte for
> byte as before, so the build changes no live chain. It reaches one with the genesis cut that
> carries the treasury. Design: `docs/superpowers/specs/2026-10-08-multisig-design.md`.

This page explains how RandProtocol holds RAND (and RPL tokens) under the control of **`threshold`
of `n` keys**, what the foundation does at the genesis cut to seed its treasury this way, and what
a signer does to spend from it or to replace a lost key.

## Why this needs a register

RAND is held as shielded notes, and a note is spent by one key: there is no threshold signature
inside the spend proof, and adding one would be a guest change and a tier re-measure. A treasury
that one key controls is a treasury one stolen laptop empties.

The chain already solves this three times with a public register instead of a note: the validator
register, the vesting register — whose revoke (`docs/vesting.md`) is authorised by a threshold of
positional Dilithium2 keys — and the program vaults. A **multisig account** is the fourth such
register: a public, per-asset balance whose spending authority is `threshold` of `n` Dilithium2
keys.

```
 genesis ──► multisig account (public balance, per asset) ◄── create / deposit (a bundle's burn)
                  ├── pay    (threshold signatures) ──► up to 4 shielded notes, base paid from the RAND row
                  └── rotate (threshold signatures) ──► a new signer set and threshold; same id, same balance
```

The chain enforces the rule: fewer than `threshold` valid signatures move nothing, and the
recipients are inside what the signers sign, so nobody relaying a transaction can redirect it.

## What an account looks like

Anyone can create accounts at any time (`rand multisig create`). A genesis file can also seed any
number of them with RAND, in its `multisig` section:

```json
{
  "create_fee": "1000000000",
  "accounts": [
    {
      "salt": "5e1f0c7a93d84b26a0c5e7819d3b4f62c8a1d07e5b9364f2a8c0e1d7b3569f48",
      "signers": [
        "<signer 1's Dilithium2 public key, hex>",
        "<signer 2's Dilithium2 public key, hex>",
        "<signer 3's Dilithium2 public key, hex>"
      ],
      "threshold": 2,
      "balance": "500000000000000000"
    }
  ]
}
```

| field | meaning |
|---|---|
| `create_fee` | units of RAND a later `CreateMultisig` must pay **above** the bundle's settled floor (the 0.001 RAND base, plus `fees.prove_base` on an aggregating chain) — not burned: it is part of the bundle's fee, which goes to the proposer, or, on a chain with the `aggregation` section, follows the fee split (the proposer keeps the 0.001 RAND `BUNDLE_BASE`, the rest is bucketed). `0` to 1 000 RAND. Spam on a permanent register is what it prices. |
| `accounts` | may be empty: a section with no accounts switches the module on with an empty register. |
| `salt` | 32 bytes (64 hex characters), the creator's randomness in the id. The chain never learns a name. |
| `signers` | 1 to 10 distinct Dilithium2 public keys. **The order matters**: a signature names its signer by position (`0:<hex>`). |
| `threshold` | `1 ≤ threshold ≤ signers`. **Use 2 of 3 or 3 of 5** for a treasury, so one lost key is survived by a rotation. |
| `balance` | RAND in units (1 RAND = 10⁹ units), a decimal string. `0` seeds an unfunded account. Only RAND can be seeded at genesis. |

The example is the foundation treasury: 500 000 000 RAND, 2 of 3. `rand-node genesis` refuses a file
with more than ten signers, a duplicate key, a threshold outside `1..=signers`, a `create_fee` over
1 000 RAND, two accounts with the same id, or balances that overflow a u64 (or, with the notes,
stakes and vesting entries, the supply).

### The id

An account's id is derived, never chosen:

```
id = blake3("rand-multisig-id-1", chain_id (u64 BE) ‖ salt ‖ threshold (u8) ‖ n (u8) ‖ pk_1 ‖ … ‖ pk_n)
```

The chain id is in it, so one creation file cannot name the same account on two chains; the signers'
order is in it, so a reordered set is another account. `rand-node genesis … --multisig multisig.json`
prints, after the genesis hash:

```
multisig: create fee 1 RAND, 1 account(s)
  multisig 9b2e…c41a 500000000 RAND, 2 of 3 signers
```

— the id to record in the cut record, and the balance to check against the allocation table. The id
can be derived offline, before the file is final:

```bash
rand-node multisig id --chain-id 20 --salt 5e1f…9f48 --threshold 2 --signer <pk1> --signer <pk2> --signer <pk3>
```

## Who does what

### The foundation, at the genesis cut

1. Agree who the signers are and the threshold (the legal documents; **2 of 3 or 3 of 5**).
2. Collect each signer's **public** key (below). Never generate a signer's key for them.
3. Write the `multisig` file with a random `salt` per account and pass it to
   `rand-node genesis … --multisig multisig.json --chain-id <N>`.
4. Record each printed id in the cut record, and check the balance against the signed allocation
   table **in units**: a missed factor of 10⁹ is the classic mistake (it happened on the chain-15
   cut).
5. After the cut, `rand-node multisig status <id>` must show the signers in the file's order, the
   threshold, nonce 0 and the balance.

### A signer

1. Generate a key on your own machine and send the foundation **only the public key**:
   ```bash
   rand-node keygen --out my-multisig.key.json
   rand-node address --key my-multisig.key.json     # prints public_key: …
   ```
   Back the file up at once: it is the only copy of that signer. `keygen` refuses a path that
   already exists.
2. Check the account at any time:
   ```bash
   rand-node multisig status <id> --rpc https://…
   ```
3. Take part in a payment or a rotation (below). Your index is your key's position in the
   account's `signers`; `sign` finds it from the prepared file, or takes `--index`.

### Creating and funding an account (the wallet)

Creating an account and putting value into it need a shielded spend, so they are the wallet's:

```bash
rand multisig create --signer <pk1> --signer <pk2> --signer <pk3> --threshold 2 \
    [--salt <64 hex>] [--fund <RAND>] [--fund-token <asset> <amount>] [--fee <RAND>]
rand multisig deposit <id> <amount> [--asset <index|id>] [--fee <RAND>]
```

- `create` prints the derived id before it proves anything. The fee floor is the bundle base plus
  the chain's `create_fee` (`rand_getLimits.multisig.create_fee`). `--fund` burns RAND from this
  wallet into the new account's RAND row; `--fund-token` does the same for one registered RPL
  token. Neither: an unfunded account.
- `deposit` is open to anyone — nothing is signed — and credits the account's row of that asset.
  The fee floor is the base.

**An account needs RAND even to pay tokens.** Every payment debits the 0.001 RAND bundle base from
the account's RAND row (below); an account holding only tokens cannot pay until someone deposits
RAND.

## Paying out of an account

A payment is three steps — the keys never have to be on one machine:

```bash
# 1. anyone (no key): write the payment down; each --to pairs with an --amount (and an --asset)
rand-node multisig pay prepare --account <id> --to rand1… --amount 250000 --out pay.json --rpc https://…
#    several payouts (at most 4): repeat the pair; --asset is all or nothing: omit it (every payout
#    is RAND) or give one --asset N per --to, in order (a count that differs is refused); an
#    --amount is in its asset's display units (RAND at 9 decimals, a token at its own decimals)
rand-node multisig pay prepare --account <id> --to rand1… --amount 10 --asset 0 \
                                                --to rand1… --amount 500 --asset 2 --out pay.json
# 2. each signer, on its own machine (offline is fine): read it, sign it
rand-node multisig pay sign --proposal pay.json --key signer-1.key.json     # prints 0:<hex>
rand-node multisig pay sign --proposal pay.json --key signer-3.key.json     # prints 2:<hex>
# 3. anyone: send it with the signatures
rand-node multisig pay submit --proposal pay.json --signature 0:<hex> --signature 2:<hex> --rpc https://…
```

- Each payout becomes a private note for its recipient, sealed in step 1. Every signer signs the
  same message (the genesis hash, the chain id, the account, the nonce, the `time` and every
  payout with its recipient, blinding and envelope), which is why the payment is prepared once and
  the file passed around. `sign` prints what it is about to sign on stderr; **check every
  recipient and amount before signing** — the prepared file is only as trustworthy as whoever
  wrote it.
- **The account pays the base.** `BUNDLE_BASE` (0.001 RAND) is debited from the account's RAND row
  to the proposer of the block that includes the payment, on top of the payouts: an account needs
  RAND for it even when it pays only tokens. The payouts' own amounts are the amounts the notes
  carry; nothing is netted.
- A payment from an account whose rows do not cover the payouts and the base is refused
  (`VaultShort`), and one with fewer valid signatures than the threshold, a signer listed twice, an
  index outside the set, or one bad signature among good ones is refused whole.
- The note's `time` is the head height at `prepare`, and a note older than the chain's proof window
  (256 blocks unless the genesis sets `proof_window_blocks`) is refused: gather the signatures and
  submit within that window (about 13 minutes at 3-second blocks), or prepare again.
- **One counter per account.** A payment and a rotation share the account's `nonce`, and applying
  either increments it. A payment prepared under the old signers dies with a rotation; a rotation
  signed against a stale set cannot land after a payment. The mempool holds one pooled payment or
  rotation per account, and re-checks a pooled payment against the account at selection, so two
  pooled payments cannot both drain one row.
- A payment carries 1 to 4 payouts. The one thing a signer cannot check is that a recipient's
  envelope opens: run `prepare` yourself, or have a signer run it.

## Rotating the signers

A lost or compromised key is replaced without moving the balance or changing the id. The *current*
signers sign their own replacement:

```bash
rand-node multisig rotate prepare --account <id> --signer <new pk1> --signer <new pk2> --signer <new pk3> --threshold 2 --out rotate.json
rand-node multisig rotate sign --proposal rotate.json --key signer-1.key.json      # prints 0:<hex>
rand-node multisig rotate sign --proposal rotate.json --key signer-3.key.json      # prints 2:<hex>
rand-node multisig rotate submit --proposal rotate.json --signature 0:<hex> --signature 2:<hex>
```

- The new set and threshold obey the creation bounds and replace the old ones atomically. The id,
  the balance and the nonce counter are kept (the nonce goes up by one).
- A rotation is **fee-less**: it pays no base, so an account with an empty RAND row can still
  replace a key.
- It needs the *old* threshold of valid signatures. With `threshold == n`, one lost key is the
  end of the account — which is why the recommendation is `threshold < n`.

## What is public, and what is not

| public (on chain, forever) | private |
|---|---|
| the account id, its signers, threshold and nonce | who the signers are (only keys are visible) |
| every asset balance in the vault | where a payout goes after its note (shielded) |
| each payment's payouts (amount, asset, note commitment) in the block's public notes, and which signer indices signed | the recipient's balance |
| each rotation's new signer count and which indices signed | the wallet that created or funded an account |

A payment reveals "account X paid N of asset A" at that block, exactly as a program invoke does; the
receiving note is shielded, and from then on the RAND is indistinguishable from any other.
Creating and depositing burn from a shielded wallet, so they reveal the amount, not the funder.

### So is a multisig account private?

**No — not the account itself.** A multisig account is a *public register*, like the validator and
vesting registers: its balance, its signer keys, its threshold and every payment out of it are on
chain for anyone to read. Only the edges are shielded: the wallet that created or funded it (a
burn from a shielded note) and where a payout goes once it is a note. It is the right shape for a
foundation treasury, whose balance is meant to be auditable; it is the wrong shape for anyone who
wants M-of-N control *and* RandProtocol's normal privacy.

The reason is where the threshold check runs. A shielded note is spent by a proof that its owner
knows one key (`sk`, or on split-authorisation chains the auth proof over `sk`, `docs/shielded.md`
§2); there is no threshold inside that proof. So the four multisig actions check their Dilithium2
signatures **natively, in the node, outside any proof** — and whatever the node checks, it must
see: the keys, the threshold, the indices that signed, the amounts.

Explicit multisig is also the post-quantum norm, not a RandProtocol shortcut. The compact
constructions classical chains use — MuSig2 and FROST (one Schnorr signature for M of N), BLS
aggregation — all rest on discrete logs or pairings that a quantum computer breaks, and lattice
threshold signatures are not yet standardised or deployed. What is left is N public keys and M
independent Dilithium2 signatures: 1 312 bytes per key and 2 420 per signature on the wire, with
the signer set visible.

## Planned: private multisig (the threshold inside the proof)

The way to get both is to move the M-of-N check **into a proof**, so the node verifies one proof
instead of M signatures and learns nothing about the policy. The design is
`docs/superpowers/specs/2026-10-11-private-multisig-design.md`; in short:

- A **multisig address** is an ordinary `rand1…` address. Its `nk` is derived from a hidden policy
  (the signers' Dilithium2 keys, the threshold, and a secret the signers share) instead of from one
  spend key, so its notes sit in the same shielded pool as everyone else's and look the same.
- Spending one uses the **existing** bundle guest unchanged. What changes is the *auth* proof:
  a second auth guest, `hc_auth_multisig`, verifies M Dilithium2 signatures over the transaction's
  binding inside the zkVM and publishes the same `auth_commit` the single-key auth guest does.
- The chain then sees one fixed-size proof. It does **not** see the account, the signer keys, N,
  M, the threshold, which signers signed, the amounts or the recipients. It does see that the
  spend was multisig-authorised (the auth proof's pinned shape differs from the single-key one).
- Rotation becomes an ordinary M-of-N spend of every note to a new policy's address; the public
  register's nonce and mempool slot are not needed, because nullifiers already prevent replay.
- A public account can move its balance into a private one with an ordinary `MultisigPay` to the
  private address: the payout is a note like any other.

How it is built, in order (each phase gated on the one before):

| phase | where | what | gate |
|---|---|---|---|
| 1 | `circuits` | a `no_std` Dilithium2 verifier compiled for the rVM (Keccak through the `KECCAK` syscall), byte-identical to `crystals-dilithium` 2.0.0's `dilithium2` | known-answer tests against the node's crate; **cycles per verification measured** |
| 2 | `circuits` | the multisig auth guest: policy check, up to `M_MAX` signatures over the binding read from the public segment, `c = H(AUTH, nk ‖ salt)` out | cheating suite; tier measured at `M_MAX` ∈ {2, 3, 5} |
| 3 | `circuits` (only if phase 2 misses tier 19) | a modular-arithmetic / NTT coprocessor chip for `q = 8 380 417`, so a verification costs rows, not hundreds of thousands of cycles | phase 2's tier re-measured under it |
| 4 | `fullnode` | genesis `hc_auth_multisig`, admission by the auth proof's declared shape, the prover's multisig witness, `rand multisig-private` (address, prepare, sign, prove, submit), wallet scanning by `nk` | a real-proof end-to-end on a test chain |
| 5 | cut | the genesis section on a chain; the treasury may then move privately | — |

Until phase 4 lands on a chain, the public account above is the only multisig there is.

## Reading it

| method | answers |
|---|---|
| `rand_getMultisig [id]` | `{ "enabled", "id", "signers", "threshold", "nonce", "vault": [{ "asset", "amount" }] }`; `null` for an unknown id; `{ "enabled": false }` without the section |
| `rand_getSupply []` | adds `multisig_issued`, `multisig_rand_in`, `multisig_rand_out`, `multisig_base_out`, `multisig_rand_held`; the identity `total_supply == issued` covers the register (`docs/supply.md`) |
| `rand_getLimits []` | `multisig`: `{ create_fee, max_signers, max_payouts }`, or `null` |

Every amount is a decimal string. The same account from a shell: `rand-node multisig status <id>`.

## Custody

- **Signer keys:** generated and held by each signer on its own machine, offline or
  hardware-backed. **Never two of them in one place**, in a shell profile, on a droplet or in this
  repository: two keys in one place is a one-key treasury for a 2-of-3 account. A key file is a
  `rand-node keygen` file (mode 600 enforced on load).
- **`threshold < n`.** Recommended: 2 of 3 or 3 of 5. A lost key is then survived by a rotation
  while `threshold` signers remain; a `threshold == n` account is stranded by one lost key.
- **The account needs 0.001 RAND per payment.** Keep a little RAND in the row; a payment whose
  rows cannot cover the payouts and the base is refused.
- **Rotation is the recovery path and the attack path.** Anyone holding `threshold` keys can
  rotate to keys of their own. Rehearse a rotation on a testnet cut before the real one.
- **The foundation never holds signers' keys.** If it did, the threshold would be a promise rather
  than a rule.
