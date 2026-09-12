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
| `--validator <VALIDATORS>` | required, repeatable | key file path **or** hex public key of each validator |
| `--stake <STAKE>` | `100000` | stake assigned to every validator (quorum is stake weighted) |
| `--alloc <ALLOCS>` | none, repeatable | a deposit note: `shrugg1<address>=<amount in SHRUGG>` |
| `--out <OUT>` | `genesis.json` | output path |
| `--faucet` | off | **testnet only**: enable `Mint` transactions (`shrugg_mint`, up to 100 SHRUGG per call). Part of the genesis hash |
| `--no-confidential` | off | disable Deploy/Call transactions on this chain. Part of the genesis hash |
| `--fri-profile <production\|test>` | `production` | zkVM FRI profile every node must use; `test` is insecure and for the test suite. Part of the genesis hash |

Prints the genesis hash, the note count, and `hc_bundle`. Every node of a chain must use a
byte-identical genesis file.

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
| `--validator` | off | vote and propose; the key must be in the genesis validator set, otherwise the node warns and runs as an observer |
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
| `notes` | | every note this wallet has opened: index, `asset`, amount, height, `spent`, `pending` |
| `asset-balance [INDEX]` | | scan, then print what this wallet holds in one bridged asset, or a row per asset held; amounts are in the asset's own smallest unit |
| `history` | | every note this wallet created for someone else, opened through its own outgoing viewing key |
| `send <TO> <AMOUNT>` | `--fee <SHRUGG>` (default `0.001`), `--no-wait`, `--cuda` | scan, select at most two notes, prove a 2-in-2-out bundle locally, submit; waits for the commit unless `--no-wait` |
| `faucet [ADDRESS]` | `--amount <SHRUGG>` (default `100`, max `100`) | testnet only: ask a validator node to mint into a note for `ADDRESS` (default: this wallet), wait for the commit |
| `program build` | `--guest <fib\|memcpy\|bubble_sort\|balance_check\|private_payment>`, `--arg N` (repeatable), `--out <file>` (default `program.json`) | assemble a built-in guest to `{base_pc, words}` JSON; prints the program id |
| `program deploy <FILE>` | `.json` or `.bin` (raw LE words), `--cuda` | pay the deploy floor through a bundle, wait for the commit, print the program id |
| `program show <ID>` | | deployed program metadata |
| `call <PROGRAM-ID>` | `--input N` (repeatable, private), `--tier T`, `--fee <SHRUGG>`, `--auditor <shrugg1…>`, `--no-envelope`, `--print-call-key`, `--cuda` | fetch the code from the node, prove the call locally with the chain's FRI profile, seal its input transcript, pay through a bundle, wait, print the receipt |
| `open-call <TXHASH>` | `--call-key <hex>`, `--as-auditor` | fetch the receipt and the sealed transcript, open it, check it against the receipt's `H_IN`, re-run the program on the recovered inputs and print both sets of outputs |
| `receipt <TX>` | | receipt of a committed call, or "no receipt" |
| `bridge-mint <ATTESTATION>` | hex or `@path`, `--to <shrugg1…>`, `--fee <SHRUGG>`, `--no-wait`, `--cuda` | deposit a guardian-signed attestation as a note: seal the deposit's envelope for its recipient and pay through a bundle from this wallet. Prints the note's `owner`, `time` and `r` every time, and on the waiting path checks the asset index the chain actually deposited under |
| `bridge-burn <ASSET> <AMOUNT> <TO_CHAIN> <TO>` | `--relayer-fee N`, `--fee <SHRUGG>` (default `0.002`), `--no-wait`, `--cuda` | burn a bridged asset to another chain: select that asset's notes for the asset bundle and SHRUGG for the fee bundle, prove **both**, submit one transaction |
| `bridge` | | the bridge's public state: guardians, emitters, the asset registry, `next_index`, the burn sequence |
| `bridge-message <SEQUENCE>` | | one outbound burn message, verbatim, for a guardian to sign |
| `fee bundle` / `fee deploy <words>` / `fee call <tier>` | | minimum fee from the node's schedule |
| `tx <HASH>` | | committed transaction with its block height and index, or "not found" |
| `block <ID>` | | block by height (integer) or by hash (hex) |
| `head` | | `{height, hash, view}` |
| `status` | | node status object (see docs/rpc.md `shrugg_status`) |
| `peers` | | connected peers |
| `validators` | | validator register: address, stake, rewards |

Amounts are decimal SHRUGG strings with up to 9 decimal places (`1`, `1.5`, `.25`, `0.000000001`).

There is no `balance <ADDRESS>`, and no way to ask about anyone else's address: a balance is a
fact about this machine's key file, not about the chain. That holds for a bridged asset too:
`asset-balance` reads this wallet's own notes, and the `bridge-*` commands read only the bridge's
*public* state (spec §10).

A `call`'s input transcript is sealed to three keys and no more (spec §6.1): this wallet's outgoing
viewing key, which opens every call it made; the per-call key `--print-call-key` shows, which opens
exactly one; and the `--auditor` address, if one was named. `--no-envelope` publishes nothing, and
then no key opens the call's inputs, ever — the transcript is the only record. `--cuda` cannot seal
one: every backend but the CPU draws the `H_IN` salt inside the prover and never returns it.

Amounts in a bridged asset are plain integers in that asset's own smallest unit, not decimal
SHRUGG: only index 0 has this chain's nine decimals, and what a bridged token's unit means belongs
to its source chain.

The one number `bridge-mint` cannot be certain of is the `asset` index of a token this chain has
never seen: the ledger assigns it from the registry's `next_index` when the transaction is
*applied*, and the wallet spends about 90 seconds proving the fee bundle in between. If another
first sighting registers in that window, the deposit note carries a different `asset` word than the
envelope was sealed against and the recipient's leaf opens under no key. So the command prints the
note's `owner`, `time` and `r` (all already public in that transaction) for every mint, and —
unless `--no-wait` — re-reads the committed transaction and warns with both indices if they differ,
naming the six words the note has to be rebuilt from. A token the registry already names cannot
move: an index is assigned once, forever.

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

### A confidential call you can open again later

```bash
shrugg program build --guest balance_check --arg 1000 --out bc.json
shrugg program deploy bc.json                   # prints the program id
shrugg call <id> --input 100 --input 200 --input 300 --input 400
shrugg open-call <txhash>                       # inputs: [100, 200, 300, 400] — H_IN: faithful
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
