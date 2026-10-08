# Multisig accounts: M-of-N controlled public balances, and the genesis treasury

Status: design approved in conversation 2026-10-08; this file is the written spec for the user's
review before the implementation plan. Branch `feat/multisig` from `origin/main` (d1fcfaa6).
Genesis-gated: a chain without the section runs byte for byte as today, so the build changes no
live chain and reaches one only by a cut. User-facing guide (to be written): `docs/multisig.md`.

## 1. Problem

The foundation's treasury — the RAND that is not allocated to validators, the sale or the team at
genesis — needs a home that no single key controls. RAND is held as shielded notes, and a note is
spent by one key: there is no threshold signature inside the spend proof, and adding one would be a
guest change and a tier re-measure. The chain already solves the same problem twice with a public
register instead of a note: the validator register (stake is public because consensus weighs it)
and the vesting register (a lock is public because the chain enforces it), whose revoke is already
authorised by a threshold of positional Dilithium2 keys. A program vault (RPL-2) shows how a public
balance per asset takes value in from a bundle's burn and pays it out as chain-computed notes.

A multisig account is the third such register: a public, per-asset balance whose spending authority
is `threshold` of `n` Dilithium2 keys. The treasury is its first account, seeded at genesis, and
`rand-node genesis` prints the account's derived id so the cut record names where the treasury is.

## 2. Decisions

| # | question | ruling |
|---|---|---|
| D1 | scope | **General accounts**, not a single genesis treasury: anyone creates one with a bundle-carried action; genesis seeds any number with RAND. |
| D2 | where balances live | **Their own register** (`ledger/multisig.rs`), vault-shaped like RPL-2's program vaults. Rejected: a synthetic program-vault row (`rand_getProgramVault`, the vault supply rows and the Invoke rules would see non-programs); a vesting entry without a schedule (RAND-only, revoke-shaped, bound to the SAFT). |
| D3 | assets | **RAND and RPL tokens**, one balance per asset; asset 0 is RAND. Only RAND can be seeded at genesis. |
| D4 | rotation | **Yes**: a threshold-signed action replaces the signer set and the threshold atomically. The id does not change. |
| D5 | how signatures are gathered | **Off chain, one transaction**: the vesting revoke's `prepare` / `sign` / `submit`. No pending proposals on chain. |
| D6 | who pays a payout's base | **The account**, from its RAND row, to the proposer's rewards — a Withdraw's shape. A rotation is fee-less (an Unbond's shape). |
| D7 | account id | **Derived**, never chosen, from the creation terms and a salt — the same rule for genesis and later accounts, so the genesis command can print the treasury's id before the cut. |
| D8 | state-root placement | A **wrapper** over the state root (`rand-state-multisig-1`, like `rand-state-tokens-1`), not the next positional domain: `feat/rpl3` (unmerged) takes `rand-state-9`, and a wrapper is independent of merge order. |
| D9 | action tags | **34–37**, appended after `Invoke` (33). A tag is the variant's bincode position, so nothing can be reserved: `feat/rpl3` (unmerged, on no chain) also appends at 34. Both are genesis-gated, so whichever branch merges second renumbers its variants before any cut carries them; this spec's numbers assume multisig merges first. |

Out of scope, recorded: on-chain proposals with approvals over several blocks; a vesting revoke
paying into a multisig id (a revoke's `treasury` stays a `rand1…` address); per-signer weights;
spending limits or timelocks; a multisig as a token's mint authority; a multisig-to-multisig
transfer (pay to a note, then deposit); seeding tokens at genesis.

## 3. Genesis section

`Genesis::multisig: Option<MultisigConfig>`, `skip_serializing_if = "Option::is_none"`: a file
without it hashes and builds byte for byte as before (chain 20 included).

```json
"multisig": {
  "create_fee": "1000000000",
  "accounts": [
    {
      "salt": "<64 hex>",
      "signers": ["<Dilithium2 public key, hex>", "<…>", "<…>"],
      "threshold": 2,
      "balance": "500000000000000000"
    }
  ]
}
```

| field | meaning |
|---|---|
| `create_fee` | units of RAND a `CreateMultisig` must pay above the bundle base, to the proposer with the rest of its fee. `0..=MAX_CREATE_FEE` (1 000 RAND). Spam on a permanent register is what it prices. |
| `accounts` | may be empty: a section with no accounts switches the module on with an empty register. |
| `salt` | 32 bytes, the creator's randomness in the id. The chain never learns a name. |
| `signers` | 1 to `MAX_SIGNERS` (10) distinct Dilithium2 public keys. **The order matters**: a signature names its signer by position. |
| `threshold` | `1..=signers.len()`. |
| `balance` | RAND in units, a decimal string; `0` seeds an unfunded account. |

`MultisigConfig::check` (→ `GenesisError::BadMultisig`): the bounds above, distinct derived ids,
Σ `balance` fits a u64; `Genesis::build` also refuses (`SupplyOverflow`) when notes, stakes, the
vesting register and the multisig balances together overflow. The genesis commit appends tag
`multisig`, `create_fee`, the count, then every account **in id order** with fixed-width fields:
salt, threshold, signer count, each key, balance — after every section before it, so a file with
the section and one without never hash alike.

### The id

```
id = blake3("rand-multisig-id-1", chain_id (u64 BE) ‖ salt ‖ threshold (u8) ‖ n (u8) ‖ pk_1 ‖ … ‖ pk_n)
```

`chain_id` is in it so one creation file cannot name the same account on two chains. `rand-node
genesis` prints, for every seeded account, its id, balance, threshold and signer count on stdout
after the genesis hash; `rand-node multisig id` derives one offline from the same inputs.

## 4. Ledger state

`ledger/multisig.rs`:

```rust
pub struct Account {
    pub signers: Vec<PublicKey>,   // list order = signature index
    pub threshold: u8,
    pub nonce: u64,                // one counter, shared by Pay and Rotate
    pub vault: BTreeMap<u32, u64>, // asset -> units; asset 0 is RAND; a zero row is removed
}
pub struct MultisigRegister {
    accounts: BTreeMap<[u8; 32], Account>,
    pub create_fee: u64,
    pub issued: u64,     // Σ genesis balances
    pub rand_in: u64,    // Σ burn_r deposited by creates and deposits
    pub rand_out: u64,   // Σ RAND paid out as notes
    pub base_out: u64,   // Σ bundle bases Pay debited into proposers' rewards
}
```

`Ledger::multisig: Option<MultisigRegister>`, inside `Ledger`'s equality. **Root**: one leaf per
account under `rand-multisig-leaf-1` over id, threshold, signer count, every key, nonce, row count
and every `(asset, amount)` row; a Merkle root over the leaves; then `blake3("rand-multisig-root-1",
leaves_root ‖ count ‖ create_fee ‖ issued ‖ rand_in ‖ rand_out ‖ base_out)`. **Fold**: in
`Ledger::state_root`, after the slashing wrapper and only under the section,
`root = blake3("rand-state-multisig-1", root ‖ multisig.root())`. `debug_state_root_components`
names it. **Persistence**: JSON under `META_MULTISIG` at the state-write sites that write
`META_VESTING`; `reload_ledger` refuses a genesis file and a database that disagree about having the
section, and the snapshot-is-the-head-state check covers it through the root.

## 5. Actions (`Action` 34–37)

All four are refused `UnsupportedAction("multisig")` on a chain without the section, at admission
and again at apply before any write. Signed messages carry the genesis hash and the chain id, like
every bundle-less signature on this chain.

### `CreateMultisig { salt: [u8; 32], signers: Vec<PublicKey>, threshold: u8 }` — tag 34, bundle-carried

- Fee floor `BUNDLE_BASE + create_fee` (`TxError::FeeTooLow` below it). `create_fee` goes to the
  proposer with the rest of the fee — it is not burned, so the supply identity does not move.
- The bundle may fund the account in the same transaction: `burn_r` lands in row 0; `burn_a` of
  `burn_asset` lands in that asset's row if the token is registered (any authority, as a program
  vault accepts a bridged token). The existing burn-shape rule still refuses RAND through `burn_a`.
  Both zero = an unfunded account.
- Rules: `MultisigConfig`'s signer and threshold bounds; the derived id must not exist
  (`AccountExists`).
- Mempool: a plain bundle transaction; its nullifiers are its claim.

### `MultisigDeposit { account: [u8; 32] }` — tag 35, bundle-carried

- Anyone, no signatures. `burn_r` and `burn_a` credit the rows as above; at least one of them
  non-zero (`EmptyDeposit`). Unknown account or unregistered token refused. Fee floor
  `BUNDLE_BASE`.

### `MultisigPay { account, nonce, time: u32, pays: Vec<Payout>, signatures: Vec<SignerSignature> }` — tag 36, bundle-less

- `Payout { asset, amount, recipient, r, envelope }` is RPL-2's type; `1..=MAX_PAYOUTS` (4) of
  them. Each is debited from its asset row (`VaultShort { asset, have, want }`) and becomes the
  note `payout_commitment(p, time)`, appended in order after the debit.
- The base: `BUNDLE_BASE` is debited from row 0 and paid to the proposer's `rewards`, so an account
  needs ≥ 0.001 RAND to pay anything, tokens included. `base_out` counts it. The payouts' own
  amounts are the amounts the notes carry — nothing is netted, which is what lets the recipient's
  wallet find the note by recomputing the commitment from the signed amount.
- `time` is held to the window a claim's is (`TimeOutOfWindow`: `proof_window_blocks` or
  `TIME_WINDOW` 256). Every envelope obeys the chain's envelope rule (`envelope_bytes`).
- Message, the same for every signer:
  `blake3("rand-multisig-pay-1", bincode(genesis, chain_id, account, nonce, time, pays))`.
  The recipients are inside it: a relayer cannot redirect a payout.
- `derived_note` (the admission hook a Withdraw and a claim use) returns the first payout's
  commitment so the pool's duplicate-commitment check sees it; every payout commitment is checked
  against the tree at apply through `Ledger::deposit` as a program payout is.

### `MultisigRotate { account, nonce, signers: Vec<PublicKey>, threshold: u8, signatures }` — tag 37, bundle-less, fee-less

- Replaces `signers` and `threshold` atomically under the creation bounds. The id, the nonce
  counter and the vault are untouched. Message:
  `blake3("rand-multisig-rotate-1", bincode(genesis, chain_id, account, nonce, signers, threshold))`.
- Fee-less like `Unbond`: the mempool's one-slot nonce claim bounds it to one pooled per account.

### Shared signature rules (Pay and Rotate)

`SignerSignature { index: u8, signature: Signature }` — `RevokerSignature`'s shape, a new type so
the two registers' wire docs stay separate. Checked cheap-first, the transaction's own bytes before
any state and any signature:

1. `signatures.len() <= signers.len()`, every `index < signers.len()`, no index twice (a u16
   bitmask), `signatures.len() >= threshold` (`BelowThreshold { have, need }`);
2. the account exists; `nonce == account.nonce` (`BadNonce { have, want }`);
3. for Pay: the rows cover the payouts and the base; for Rotate: the new set is within bounds;
4. every signature verifies against `signers[index]` over the message (`BadSignature(index)`); one
   bad signature among good ones refuses the whole action.

One nonce per account, shared: a rotation signed against a stale set cannot land after a payment,
and a payment prepared under the old signers dies with the rotation. Apply increments it.

**Mempool**: a new claim role (9) keyed by the account id and the nonce, so at most one pooled Pay
or Rotate per account; a pooled Pay is re-checked against the vault at selection
(`multisig::still_applies`, `program_state::still_applies`'s twin) so two pooled payments cannot
both drain one row. Role 0 (nullifiers) covers Create and Deposit.

## 6. Supply

Kept off the positional `Supply` blob, as the vesting and program-vault rows are, through
`Audit::with_multisig(issued, rand_in, rand_out, base_out)`:

| number | what it is | on the identity |
|---|---|---|
| `multisig_issued` | Σ genesis balances | issuance, beside `genesis_staked` and `vesting_issued` |
| `multisig_rand_in` | every `burn_r` a create or deposit put in | already in `burned` through the common bundle path: pool → register, not new value |
| `multisig_rand_out` | every RAND payout note | value entering the pool, beside `withdraw_deposited` |
| `multisig_base_out` | the bases Pay paid into proposers' `rewards` | register → register, not a crossing |
| `multisig_rand_held` | `issued + rand_in − rand_out − base_out` | the register's half of `total_supply` |

`pool_value` gains `rand_out`; `total_supply` gains `multisig_rand_held` as its own term; `issued` gains `multisig_issued`.
Tokens in a vault leave the token's `total_supply` untouched, as in a program vault. `rand-node
verify` replays the four counters and reports a snapshot that disagrees.

## 7. Surface

**RPC**: `rand_getMultisig [id]` → `{ enabled, id, signers, threshold, nonce, vault: [{asset,
amount}] }` or `null` for an unknown id, `{ enabled: false }` without the section; on
`PUBLIC_METHODS`. `rand_getSupply` adds the five `multisig_*` rows as decimal strings.
`rand_getLimits` adds `multisig: { create_fee, max_signers, max_payouts }`. `tx_json` renders the
four actions (payouts with their `cm`, as an invoke's).

**CLI** — the existing split: a bundle-carried action needs a shielded spend, so it is the
wallet's; a bundle-less signed action is `rand-node`'s.

| command | does |
|---|---|
| `rand-node genesis … --multisig multisig.json` | reads the section (`MultisigConfig::check`), prints each seeded account's id, balance, threshold, signers |
| `rand-node multisig id --salt <hex> --threshold N --signer <hex>…` | derives an id offline (`--chain-id`) |
| `rand-node multisig status <id> --rpc` | `rand_getMultisig` |
| `rand multisig create --signer <hex>… --threshold N [--fund <RAND>] [--fund-token <asset> <amount>] [--salt <hex>]` | the wallet builds the bundle (fee floor from `rand_getLimits`), prints the id |
| `rand multisig deposit <id> <amount> [--asset N]` | a bundle whose burn credits the account |
| `rand-node multisig pay prepare --account <id> --to <rand1…> <amount> [--asset N] (repeatable) --out pay.json` | seals the notes, reads the nonce and time from the node, writes the message |
| `rand-node multisig pay sign --proposal pay.json --key k.json` | prints `i:<hex>` after showing what it signs on stderr |
| `rand-node multisig pay submit --proposal pay.json --signature i:<hex>…` | one transaction, within the window of `prepare`'s `time` |
| `rand-node multisig rotate prepare/sign/submit` | the same flow for a new signer set |

Key files are the existing `rand-node keygen` files (mode 600 enforced on load).

**Docs**: `docs/multisig.md` (guide: the treasury at genesis, custody, the three-step spend),
`docs/supply.md` (the rows), `docs/rpc.md`, `docs/cli.md`, `docs/deploy.md` ("The next cut: a
`multisig` section"), `CHANGELOG.md`, and the `AGENTS.md` memory entry.

## 8. Errors

`MultisigError` behind `TxError::Multisig`: `Disabled`, `UnknownAccount`, `AccountExists`,
`BadSigners(String)` (count, duplicate, threshold out of range), `BadNonce { have, want }`,
`BelowThreshold { have, need }`, `UnknownSigner(u8)`, `DuplicateSigner(u8)`, `BadSignature(u8)`,
`VaultShort { asset, have, want }`, `NoPayouts`, `TooManyPayouts(usize)`, `EmptyDeposit`,
`UnknownToken(u32)` (reusing `TokenError`'s), `Overflow`. The genesis side is
`GenesisError::BadMultisig(String)`.

## 9. Testing

Red first, one rule per test, the file's existing style (a `StubExecutor` ledger, a genesis with
the section on and off).

- **Core** (`ledger/multisig.rs`): `check`'s every rule; id vectors (and that the chain id moves
  it); each action's `validate` and `apply`; the gate on a section-less ledger for all four; the
  shared nonce (a Pay then a Rotate at the same nonce fails; the reverse too); the base debit and
  an account with less than the base; a token deposit and a token payout; `VaultShort`; a zero row
  disappears; the root changes with every field and is absent without the section; `still_applies`
  prunes a stale Pay; the supply identity through create, deposit, pay, rotate.
- **Genesis**: the section is committed only when present; chain 20's file still builds chain
  20's hash (the existing `chain_20s_genesis_file_builds_chain_20` pin stays green); `the_consensus_encoding_and_txid_are_pinned` extended with the four tags; `SupplyOverflow`
  with a balance that overflows.
- **Node**: `genesis_cli` prints the derived ids; storage round-trips `META_MULTISIG`;
  `reload_ledger` refuses a mismatch; mempool one pooled Pay-or-Rotate per account and Create's
  nullifier claim; `rpc_contract` for `rand_getMultisig`, the supply rows, the limits; the CLI's
  sealed payout note equals the ledger's `payout_commitment` (the vesting pin's twin).
- **Wallet**: `rand multisig create` and `deposit` build a bundle with the right burn fields and
  fee floor (unit tests against the limits reply); the real-proof e2e (create, deposit, pay,
  rotate) written and `#[ignore]`d like RPL-2's, to run once on a c-16.
- **Suites to run before the PR**: core, node lib and bins, client lib, `genesis_cli`, `submit`,
  `rpc_contract`; the state-root and txid pins.

## 10. Rollout

Node-safe on chain 20: without the section the four actions are refused at admission, and nothing
else changes. The treasury reaches a chain at the next cut: the foundation collects the signers'
public keys (each generated on its holder's machine, never by the foundation), writes
`multisig.json`, runs `rand-node genesis … --multisig multisig.json`, records the printed id in
the cut record, and checks the balance against the allocation table in units — the missed factor
of 10⁹ is the classic mistake. Custody: no two signer keys in one place; a lost key is survived by
a rotation while `threshold` signers remain, which is why `threshold < n` is the recommendation
for the treasury (2 of 3, or 3 of 5).
