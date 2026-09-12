# Command-line reference

Two binaries are built by `cargo build --release`: `shrugg-node` (node and operator commands) and
`shrugg` (the shielded wallet client). Every command accepts `-h/--help`.

The two hold different kinds of key and must not be confused. A **node key** is a 32-byte seed and
a Dilithium2 key pair whose base58 address is public and signs blocks. A **wallet key** is a
256-bit shielded spend key whose `shrugg1…` address receives notes and which never signs anything
on chain (`docs/shielded.md` §1).

## `shrugg-node`

```
shrugg-node <COMMAND>
  keygen    Generate a new Dilithium2 key file
  address   Print the address, public key, and libp2p peer id of a key file
  genesis   Write a genesis.json: every validator key is staked, each --alloc becomes a deposit note
  init      Initialise a data directory from a genesis file
  run       Run the node
  verify    Verify the chain in a data directory without running the node
  status    Show node status
```

There is no `balance` and no `transfer` subcommand: this chain has no accounts to query and a
transfer needs a shielded spend key, which only the wallet holds. Use `shrugg` for both.

### `shrugg-node keygen`

| argument | default | meaning |
|---|---|---|
| `--out <OUT>` | `node.key.json` | where to write the key file |

Writes `{ "seed": <32-byte hex>, "address": <base58>, "public_key": <hex> }` with mode 0600. Only the
seed is secret; the Dilithium2 key pair is re-derived from it on every load.

### `shrugg-node address`

| argument | default | meaning |
|---|---|---|
| `--key <KEY>` | required | key file |

Prints `address`, `public_key` (hex, 1312 bytes) and `peer_id` (the libp2p identity derived from the
same seed). The peer id is what other nodes put after `/p2p/` in a bootstrap address.

### `shrugg-node genesis`

| argument | default | meaning |
|---|---|---|
| `--chain-id <CHAIN_ID>` | `1` | chain id; transactions and gossip topics are bound to it |
| `--validator <KEY,STAKE,PAYOUT>` | required, repeatable | one register entry: key file path **or** hex public key, the stake in SHRUGG (at least 1000, the staking minimum), and the `shrugg1…` address its rewards and unbonded stake are paid to |
| `--epoch-blocks <N>` | `1000` | blocks per epoch: how often the validator set is re-derived from the register (spec §8). Part of the genesis hash |
| `--alloc <ALLOCS>` | none, repeatable | a deposit note: `shrugg1<address>=<amount in SHRUGG>` |
| `--out <OUT>` | `genesis.json` | output path |
| `--faucet` | off | **testnet only**: enable `Mint` transactions (`shrugg_mint`, up to 100 SHRUGG per call). Part of the genesis hash |
| `--no-confidential` | off | disable Deploy/Call transactions on this chain. Part of the genesis hash |
| `--fri-profile <production\|test>` | `production` | zkVM FRI profile every node must use; `test` is insecure and for the test suite. Part of the genesis hash |

Prints the genesis hash, the validator and note counts, the epoch length and `hc_bundle`. Every
node of a chain must use a byte-identical genesis file.

### `shrugg-node register` / `unbond` / `withdraw`

The three staking commands a validator operator runs (spec §8). `register` is offline apart from
reading the chain id; the other two build a real transaction and take about a minute to prove it.

| command | arguments | meaning |
|---|---|---|
| `register` | `--key`, `--payout <shrugg1…>`, `--rpc` | print a `Registration` (hex) signed by this node's key, for a wallet to attach to the bond that registers it |
| `unbond <amount SHRUGG>` | `--key`, `--wallet`, `--rpc`, `--fee`, `--no-wait` | move bonded stake into unbonding; withdrawable two epochs later |
| `withdraw <amount SHRUGG>` | same | pay released stake and rewards into a note at the register's payout address |

The bond itself is a wallet command: it burns the stake out of shielded notes, and a validator key
owns none. For the same reason `unbond` and `withdraw` take a `--wallet` — the action is signed by
`--key`, but the bundle carrying it pays a fee out of the wallet's notes.

`withdraw` draws the note's blinding itself and seals the envelope to the payout address under a
throwaway sender key, so only the payout wallet can open it. The chain computes the note's
commitment from the height of the block that applies the transaction, which this command predicts
as the next block and prints; a transaction that lands at a different height still creates the note
and still pays it, but the payout wallet will not find it by scanning.

There is no `--alloc-each`: a shielded chain has no per-validator allocation, because value only
exists as a note someone holds the spend key for. Each `--alloc` builds one deposit note with
fresh commitment randomness, so writing the same allocation twice produces two different notes and
two different genesis hashes — a deterministic `r` would let anyone confirm a guess at a genesis
note's owner and amount by recomputing the commitment. Cut a genesis once and keep the file.

There is no `--bridge` either: `Genesis::build` rejects a bridge section outright until phase S3
puts the bridge back on the shielded chain (`docs/bridge.md`).

Genesis JSON shape:

```json
{
  "chain_id": 6,
  "timestamp_ms": 1788000000000,
  "validators": [ { "public_key": "<hex>", "stake": 100000 } ],
  "alloc": [
    { "cm": "<64 hex>",
      "envelope": { "kem_ct": "<hex>", "to_receiver": "<hex>", "to_sender": "<hex>", "body": "<hex>" },
      "amount": 1000000000000 }
  ],
  "faucet": true,
  "confidential": true,
  "fri_profile": "production",
  "hc_bundle": "<64 hex: the bundle guest's digest this build implements>"
}
```

`amount` is in smallest units and is public: it is what lets everyone add up the initial supply.
Who owns the note is not — only the address the envelope was sealed to can open it. `hc_bundle`
pins the one zkVM relation every bundle proof on this chain is checked against; a node whose
build assembles a different guest refuses to start and names both digests.

### `shrugg-node init`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | data directory to create |
| `--genesis <GENESIS>` | required | genesis file; copied to `<datadir>/genesis.json` |

Creates `<datadir>/db` (RocksDB) with block 0, the deposit notes as the tree's first leaves, and
the validator register. Re-running with the same genesis is a no-op; a different genesis is
refused.

### `shrugg-node run`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | initialised data directory |
| `--key <KEY>` | required | key file (validator identity, p2p identity, fee recipient) |
| `--listen <LISTEN>` | `/ip4/0.0.0.0/tcp/30303` | libp2p listen multiaddr, repeatable |
| `--bootstrap <BOOTSTRAP>` | none, repeatable | peer to dial at start and every 30 s while disconnected: `/ip4/<ip>/tcp/<port>/p2p/<peer-id>` |
| `--rpc <RPC>` | `127.0.0.1:8545` | JSON-RPC listen address; bind `0.0.0.0` only behind a firewall |
| `--validator` | off | this node holds a validator key and takes part in consensus. A key in no current epoch's set observes until an epoch admits it, so a validator that bonds in after genesis needs no restart; `shrugg_status` reports `is_validator` (the key is here) and `active_validator` (it is in the current set) separately |
| `--no-mdns` | off | disable LAN discovery (recommended on servers) |
| `--block-interval-ms <MS>` | `1000` | minimum spacing between proposals |
| `--view-timeout-ms <MS>` | `3000` | base view timeout; doubles per consecutive timeout up to 8x |
| `--verify-chain <MODE>` | `quick` | startup integrity check: `off`, `quick` (structure + ledger replay), `full` (also proposer signatures and every QC's votes) |

Environment: `RUST_LOG` (default `info,libp2p=warn,libp2p_mdns=off`). Ctrl-C shuts down cleanly.

Startup sequence: open storage, check that this build's bundle guest matches the genesis
`hc_bundle`, run the integrity check (truncating a damaged tail if any), resume consensus from the
persisted head and safety state, start networking and RPC, then sync from any peer that is ahead.

Block spacing matters more on a shielded chain than it did on an account chain: a bundle proof
takes about 100 seconds, and its anchor is only valid for 256 blocks. At the default 1000 ms that
is a little over four minutes of headroom; a chain paced much faster than that will reject honest
transfers whose anchor expired mid-proof.

### `shrugg-node verify`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | data directory (node must not be running) |
| `--mode <MODE>` | `full` | `quick` or `full`, as for `--verify-chain` |
| `--repair` | off | truncate the damaged tail and rewrite the note, nullifier, anchor and validator families from the replayed ledger; safety state is kept |

Exit code 0 if the chain is consistent, 2 if a problem was found and `--repair` was not given.
Replay re-verifies every bundle proof, so a build whose zkVM constraints differ from the one that
made the chain will stop at the first bundle (`docs/confidential.md`).

### `shrugg-node status`

| argument | default | meaning |
|---|---|---|
| `--rpc <URL>` | `http://127.0.0.1:8545` | node to ask |

Prints `shrugg_status` verbatim: height, view, peers, mempool, notes, nullifiers, tree root,
`hc_bundle`, sync state.

## `shrugg` (wallet)

Global options, accepted before or after the subcommand:

| option | env | default | meaning |
|---|---|---|---|
| `--rpc <RPC>` | `SHRUGG_RPC` | `http://127.0.0.1:8545` | node JSON-RPC endpoint |
| `--key <KEY>` | `SHRUGG_KEY` | `wallet.key.json` | spend-key file; the note store lives beside it at `<key>.notes.json` |

| command | arguments | behaviour |
|---|---|---|
| `keygen` | | write a new spend-key file at `--key`, mode 0600; refuses to overwrite |
| `address` | | print this wallet's `shrugg1…` shielded address |
| `balance` | | scan the tree, save the store, print spendable value and the unspent note count |
| `sync` | | scan without printing a balance; prints how far it got |
| `notes` | | every note this wallet has opened: index, amount, height, `spent`, `pending` |
| `history` | | every note this wallet created for someone else, opened through its own outgoing viewing key |
| `send <TO> <AMOUNT>` | `--fee <SHRUGG>` (default `0.001`), `--no-wait`, `--cuda` | scan, select at most two notes, prove a 2-in-2-out bundle locally, submit; waits for the commit unless `--no-wait` |
| `faucet [ADDRESS]` | `--amount <SHRUGG>` (default `100`, max `100`) | testnet only: ask a validator node to mint into a note for `ADDRESS` (default: this wallet), wait for the commit |
| `program build` | `--guest <fib\|memcpy\|bubble_sort\|balance_check\|private_payment>`, `--arg N` (repeatable), `--out <file>` (default `program.json`) | assemble a built-in guest to `{base_pc, words}` JSON; prints the program id |
| `program deploy <FILE>` | `.json` or `.bin` (raw LE words), `--cuda` | pay the deploy floor through a bundle, wait for the commit, print the program id |
| `program show <ID>` | | deployed program metadata |
| `call <PROGRAM-ID>` | `--input N` (repeatable, private), `--tier T`, `--fee <SHRUGG>`, `--cuda` | fetch the code from the node, prove the call locally with the chain's FRI profile, pay through a bundle, wait, print the receipt |
| `receipt <TX>` | | receipt of a committed call, or "no receipt" |
| `fee bundle` / `fee deploy <words>` / `fee call <tier>` | | minimum fee from the node's schedule |
| `tx <HASH>` | | committed transaction with its block height and index, or "not found" |
| `block <ID>` | | block by height (integer) or by hash (hex) |
| `head` | | `{height, hash, view}` |
| `status` | | node status object (see docs/rpc.md `shrugg_status`) |
| `peers` | | connected peers |
| `validators` | | validator register: address, stake, rewards |

Amounts are decimal SHRUGG strings with up to 9 decimal places (`1`, `1.5`, `.25`, `0.000000001`).

There is no `balance <ADDRESS>`, and no way to ask about anyone else's address: a balance is a
fact about this machine's key file, not about the chain. There are no `bridge-*` or
`asset-balance` commands either; they return with the bridge in phase S3.

`--cuda` proves on an attached NVIDIA GPU and requires a build with `--features cuda`. There is no
fallback: a missing driver is an error rather than a silent CPU run.

### A first shielded transfer

```bash
shrugg keygen                                   # wallet.key.json
shrugg address                                  # shrugg1… — give this to whoever pays you
shrugg faucet                                   # testnet: 100 SHRUGG into a note only you can open
shrugg balance                                  # balance: 100 SHRUGG
shrugg send shrugg1q9f… 1.5                     # ~100 s of local proving, then the commit
shrugg notes                                    # the spent note, and the change note
```

### Key file formats

Node key (both binaries' `keygen` used to share this; only `shrugg-node` writes it now):

```json
{
  "seed": "hex of 32 bytes",
  "address": "base58 of blake3(public key)",
  "public_key": "hex of 1312-byte Dilithium2 public key"
}
```

Wallet key, version 2 — the spend key and nothing else, because every other key (viewing key,
outgoing viewing key, ML-KEM decapsulation key, address) is a pure derivation of it:

```json
{ "version": 2, "spend_key": "hex of 8 little-endian u32 words (64 characters)" }
```

The libp2p peer id is derived as an ed25519 key from `blake3("shrugg-p2p-identity" || seed)`, so it
is stable across restarts. Losing a wallet key loses every note it could open; there is no
recovery phrase in this release.
