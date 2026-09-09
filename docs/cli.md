# Command-line reference

Two binaries are built by `cargo build --release`: `shrugg-node` (node and operator commands) and
`shrugg` (wallet client). Every command accepts `-h/--help`.

## `shrugg-node`

```
shrugg-node <COMMAND>
  keygen    Generate a new Dilithium2 key file
  address   Print the address, public key, and libp2p peer id of a key file
  genesis   Write a genesis.json: every validator key is staked and allocated SHRUGG
  init      Initialise a data directory from a genesis file
  run       Run the node
  verify    Verify the chain in a data directory without running the node
  balance   Query an account balance
  transfer  Sign and submit a transfer
  status    Show node status
```

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
| `--validator <VALIDATORS>` | required, repeatable | key file path **or** hex public key of each validator |
| `--stake <STAKE>` | `100000` | stake assigned to every validator (quorum is stake weighted) |
| `--alloc-each <ALLOC_EACH>` | `1000000` | SHRUGG credited to every validator address |
| `--alloc <ALLOCS>` | none, repeatable | extra allocation `address=amountSHRUGG` |
| `--out <OUT>` | `genesis.json` | output path |
| `--faucet` | off | **testnet only**: enable `Mint` transactions (`shrugg_mint`, up to 100 SHRUGG per call). Part of the genesis hash |
| `--no-confidential` | off | disable Deploy/Call transactions on this chain. Part of the genesis hash |
| `--fri-profile <production\|test>` | `production` | zkVM FRI profile every node must use; `test` is insecure and for the test suite. Part of the genesis hash |
| `--bridge <FILE>` | off | JSON file enabling the cross-chain bridge (see below). Part of the genesis hash |

Prints the genesis hash. Every node of a chain must use a byte-identical genesis file.

Genesis JSON shape:

```json
{
  "chain_id": 2,
  "timestamp_ms": 1788000000000,
  "validators": [ { "public_key": "<hex>", "stake": 100000 }, ... ],
  "alloc": { "<base58 address>": 100000000000, ... },  // smallest units (1 SHRUGG = 1e9)
  "faucet": true,                                        // omit or false outside testnets
  "confidential": true,                                  // default true
  "fri_profile": "production",                           // or "test"
  "bridge": {                                            // omit entirely for a chain without a bridge
    "emitter": "<64 hex>",                               // this chain's emitter address in outbound messages
    "guardians": ["<40 hex>", ...],                      // initial guardian set (secp256k1 addresses)
    "emitters": { "2": "<64 hex>", ... }                 // source chain id -> that chain's emitter address
  }
}
```

The `--bridge <FILE>` flag takes exactly the `bridge` object above. Chain id 1 is Rand itself and may not
appear in `emitters`; guardians must be non-empty, distinct and non-zero. A genesis without a `bridge`
section hashes exactly as it did before the bridge existed.

### `shrugg-node init`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | data directory to create |
| `--genesis <GENESIS>` | required | genesis file; copied to `<datadir>/genesis.json` |

Creates `<datadir>/db` (RocksDB) with block 0 and the genesis allocations. Re-running with the same
genesis is a no-op; a different genesis is refused.

### `shrugg-node run`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | initialised data directory |
| `--key <KEY>` | required | key file (validator identity, p2p identity, fee recipient) |
| `--listen <LISTEN>` | `/ip4/0.0.0.0/tcp/30303` | libp2p listen multiaddr, repeatable |
| `--bootstrap <BOOTSTRAP>` | none, repeatable | peer to dial at start and every 30 s while disconnected: `/ip4/<ip>/tcp/<port>/p2p/<peer-id>` |
| `--rpc <RPC>` | `127.0.0.1:8545` | JSON-RPC listen address; bind `0.0.0.0` only behind a firewall |
| `--validator` | off | vote and propose; the key must be in the genesis validator set, otherwise the node warns and runs as an observer |
| `--no-mdns` | off | disable LAN discovery (recommended on servers) |
| `--block-interval-ms <MS>` | `1000` | minimum spacing between proposals |
| `--view-timeout-ms <MS>` | `3000` | base view timeout; doubles per consecutive timeout up to 8x |
| `--verify-chain <MODE>` | `quick` | startup integrity check: `off`, `quick` (structure + ledger replay), `full` (also proposer signatures and every QC's votes) |

Environment: `RUST_LOG` (default `info,libp2p=warn,libp2p_mdns=off`). Ctrl-C shuts down cleanly.

Startup sequence: open storage, run the integrity check (truncating a damaged tail if any), resume
consensus from the persisted head and safety state, start networking and RPC, then sync from any
peer that is ahead.

### `shrugg-node verify`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | data directory (node must not be running) |
| `--mode <MODE>` | `full` | `quick` or `full`, as for `--verify-chain` |
| `--repair` | off | truncate the damaged tail and rewrite the account snapshot; safety state is kept |

Exit code 0 if the chain is consistent, 2 if a problem was found and `--repair` was not given.

### `shrugg-node balance`, `transfer`, `status`

Thin wrappers over the RPC, kept for operators who only have the node binary.

| command | arguments |
|---|---|
| `balance <ADDRESS>` | `--rpc <URL>` (default `http://127.0.0.1:8545`) |
| `transfer --key <KEY> --to <ADDRESS> --amount <SHRUGG>` | `--fee <SHRUGG>` (default `0.000001`), `--rpc <URL>` |
| `status` | `--rpc <URL>` |

`transfer` reads the sender's nonce from the node, checks the balance, signs, and submits; it does
not wait for the commit (use `shrugg send` for that).

## `shrugg` (wallet)

Global options, accepted before or after the subcommand:

| option | env | default | meaning |
|---|---|---|---|
| `--rpc <RPC>` | `SHRUGG_RPC` | `http://127.0.0.1:8545` | node JSON-RPC endpoint |
| `--key <KEY>` | `SHRUGG_KEY` | `wallet.key.json` | key file used for signing and as the default address |

| command | arguments | behaviour |
|---|---|---|
| `keygen` | | create the key file at `--key`; refuses to overwrite |
| `address` | | print this wallet's address |
| `balance [ADDRESS]` | | balance and nonce of `ADDRESS`, or of this wallet |
| `send <TO> <AMOUNT>` | `--fee <SHRUGG>` (default `0.000001`), `--no-wait` | fetch nonce, check balance, sign, submit; then poll until committed (up to 60 s) and print the block height and new balance |
| `faucet [ADDRESS]` | `--amount <SHRUGG>` (default `100`, max `100`) | testnet only: ask the node to mint to `ADDRESS` (default: this wallet), wait for the commit, print the balance. Fails with `faucet is disabled` on chains without the genesis flag |
| `program build` | `--guest <fib\|memcpy\|bubble_sort\|balance_check\|private_payment>`, `--arg N` (repeatable), `--out <file>` (default `program.json`) | assemble a built-in guest to `{base_pc, words}` JSON; prints the program id |
| `program deploy <FILE>` | `.json` or `.bin` (raw LE words) | sign a `Deploy` with the schedule fee, wait for the commit, print the program id |
| `program show <ID>` | | deployed program metadata |
| `call <PROGRAM-ID>` | `--input N` (repeatable, private), `--to <address>` (repeatable, public recipient list), `--tier T`, `--fee <SHRUGG>` | fetch the code from the node, prove locally with the chain's FRI profile, submit proof + recipients, wait, print the receipt |
| `receipt <TX>` | | receipt of a committed call, or "no receipt" |
| `fee deploy <words>` / `fee call <tier>` | | minimum fee from the node's schedule |
| `tx <HASH>` | | committed transaction with its block height and index, or "not found" |
| `block <ID>` | | block by height (integer) or by hash (hex) |
| `head` | | `{height, hash, view}` |
| `status` | | node status object (see docs/rpc.md `shrugg_status`) |
| `peers` | | connected peers |
| `validators` | | validator set with stakes |

Amounts are decimal SHRUGG strings with up to 9 decimal places (`1`, `1.5`, `.25`, `0.000000001`).

## Key file format

```json
{
  "seed": "hex of 32 bytes",
  "address": "base58 of blake3(public key)",
  "public_key": "hex of 1312-byte Dilithium2 public key"
}
```

Both binaries read the same format. The libp2p peer id is derived as an ed25519 key from
`blake3("shrugg-p2p-identity" || seed)`, so it is stable across restarts.
