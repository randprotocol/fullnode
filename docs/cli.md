# Command-line reference

Two binaries are built by `cargo build --release`: `rand-node` (node and operator commands) and
`rand` (the shielded wallet client). Every command accepts `-h/--help`.

The two hold different kinds of key and must not be confused. A **node key** is a 32-byte seed and
a Dilithium2 key pair whose base58 address is public and signs blocks. A **wallet key** is a
256-bit shielded spend key whose `rand1…` receiver id receives notes; the only thing it ever signs
on chain is its own receiver record (`rand register`, a Dilithium2 key derived from the spend key,
spec docs §1) — it never signs a transfer, which authorises itself by its bundle's proof instead
(`docs/shielded.md` §1–§2).

## `rand-node`

```
rand-node <COMMAND>
  keygen    Generate a new Dilithium2 key file
  address   Print the address, public key, and libp2p peer id of a key file
  genesis   Write a genesis.json: every validator key is staked, each --alloc becomes a deposit note
  init      Initialise a data directory from a genesis file
  run       Run the node
  verify    Verify the chain in a data directory without running the node
  status    Show node status
  register  Print this node's Registration, for the wallet that bonds it in
  unbond    Move bonded stake into unbonding
  withdraw  Pay released stake and rewards into a note at the payout address
```

There is no `balance` and no `transfer` subcommand: this chain has no accounts to query and a
transfer needs a shielded spend key, which only the wallet holds. Use `rand` for both.

### `rand-node keygen`

| argument | default | meaning |
|---|---|---|
| `--out <OUT>` | `node.key.json` | where to write the key file |

Writes `{ "seed": <32-byte hex>, "address": <base58>, "public_key": <hex> }` with mode 0600. Only the
seed is secret; the Dilithium2 key pair is re-derived from it on every load.

### `rand-node address`

| argument | default | meaning |
|---|---|---|
| `--key <KEY>` | required | key file |

Prints `address`, `public_key` (hex, 1312 bytes) and `peer_id` (the libp2p identity derived from the
same seed). The peer id is what other nodes put after `/p2p/` in a bootstrap address.

### `rand-node genesis`

| argument | default | meaning |
|---|---|---|
| `--chain-id <CHAIN_ID>` | `1` | chain id; transactions and gossip topics are bound to it |
| `--receiver <RECORD.JSON>` | none, repeatable | a signed receiver record — the file `rand address --record` writes, bare or under a top-level `"record"` key — registered into the genesis receiver registry before any `--validator` or `--alloc` below is parsed |
| `--validator <KEY,STAKE,PAYOUT>` | required, repeatable | one register entry: key file path **or** hex public key, the stake in RAND (at least 1000, the staking minimum), and the `rand1…` receiver id its rewards and unbonded stake are paid to — must name one of the `--receiver` records above |
| `--epoch-blocks <N>` | `1000` | blocks per epoch: how often the validator set is re-derived from the register (spec §8). Part of the genesis hash |
| `--alloc <ALLOCS>` | none, repeatable | a deposit note: `rand1<address>=<amount in RAND>`, where `<address>` is a receiver id one of the `--receiver` records resolves |
| `--out <OUT>` | `genesis.json` | output path |
| `--faucet` | off | **testnet only**: enable `Mint` transactions (`rand_mint`, up to 100 RAND per call). Part of the genesis hash |
| `--no-confidential` | off | disable Deploy/Call transactions on this chain. Part of the genesis hash |
| `--fri-profile <production\|test>` | `production` | zkVM FRI profile every node must use; `test` is insecure and for the test suite. Part of the genesis hash |

Prints the genesis hash, the validator and note counts, the epoch length and `hc_bundle`. Every
node of a chain must use a byte-identical genesis file.

There is no `--alloc-each`: a shielded chain has no per-validator allocation, because value only
exists as a note someone holds the spend key for. Each `--alloc` builds one deposit note with
fresh commitment randomness, so writing the same allocation twice produces two different notes and
two different genesis hashes — a deterministic `r` would let anyone confirm a guess at a genesis
note's owner and amount by recomputing the commitment. Cut a genesis once and keep the file.

There is no `--bridge` flag either, but a bridged chain is cut from this file by hand: add a
`bridge` section (`{"emitter": "<64 hex>", "guardians": ["<40 hex>"], "emitters": {"2": "<64 hex>"}}`)
and `Genesis::build` validates it, commits it to the genesis hash, and the node persists and reloads
it (`docs/bridge.md` §4). A guardian set and a per-chain emitter table belong with whoever holds the
guardian keys rather than with this command.

Genesis JSON shape:

```json
{
  "chain_id": 6,
  "timestamp_ms": 1788000000000,
  "validators": [ { "public_key": "<hex>", "stake": 1000000000000, "payout": "rand1…" } ],
  "alloc": [
    { "cm": "<64 hex>",
      "envelope": { "kem_ct": "<hex>", "to_receiver": "<hex>", "to_sender": "<hex>", "body": "<hex>" },
      "amount": 1000000000000 }
  ],
  "receivers": [
    { "version": 1, "pk": "<64 hex>", "kem_ek": "<2368 hex>",
      "signing_key": "<2624 hex>", "signature": "<4840 hex>" }
  ],
  "faucet": true,
  "confidential": true,
  "fri_profile": "production",
  "hc_bundle": "<64 hex: the bundle guest's digest this build implements>",
  "epoch_blocks": 1000
}
```

`bridge` is the one optional field this command never writes (add it by hand, as above); every
other field it writes, `epoch_blocks` included. `receivers` is absent (an empty registry, not an
error) on a genesis file with no `--receiver` at all.

Both `amount` and a validator's `stake` are in smallest units, and both are public: they are what
let everyone add up the initial supply (`docs/supply.md`). Who owns a note is not — only the address
the envelope was sealed to can open it. `receivers` is registered first, before any `validators`
payout or `alloc` owner is resolved against it (spec docs §6): each is a receiver id, and an id
with no matching record here is refused. A validator's `payout` is the receiver id its rewards
and unbonded stake are withdrawn to, and it is register state, so it is part of the genesis hash like
`epoch_blocks`, `faucet`, `confidential`, `fri_profile` and `hc_bundle`. `hc_bundle` pins the one
zkVM relation every bundle proof on this chain is checked against; a node whose build assembles a
different guest refuses to start and names both digests.

### `rand-node register` / `unbond` / `withdraw`

The three staking commands a validator operator runs (spec §8). `register` is offline apart from
reading the chain id; the other two submit a real transaction, which commits in a block's time —
there is no proof to build.

| command | arguments | meaning |
|---|---|---|
| `register` | `--key`, `--payout <rand1…>`, `--rpc` | print a `Registration` (hex) signed by this node's key, for a wallet to attach to the bond that registers it — `--payout` must already resolve in the receiver registry (`rand register` on that wallet first, if it never has) |
| `unbond <amount RAND>` | `--key`, `--rpc`, `--no-wait` | move bonded stake into unbonding; withdrawable two epochs later. Free |
| `withdraw <amount RAND>` | same | pay released stake and rewards into a note at the register's payout id, `pk` resolved from the receiver registry, less the bundle base |

The bond itself is a wallet command: it burns the stake out of shielded notes, and a validator key
owns none. `unbond` and `withdraw` need no wallet at all — they ride without a bundle, exactly as a
faucet mint does, and the register's nonce is their replay protection. `unbond` pays nothing;
`withdraw` pays the 0.001 RAND bundle base out of the amount it withdraws, to the proposer of
the block that applies it, so the note it creates is worth `amount − 0.001` and an amount that
cannot cover the base is refused.

`withdraw` draws the note's blinding itself and seals the envelope to the payout address under a
throwaway sender key, so only the payout wallet can open it. The chain computes the note's
commitment from the `time` the action carries — the head height when the command ran, which it
prints, and which the signature binds — not from the height of the block that applies the
transaction: the envelope is sealed before that block exists. Admission accepts any `time` within
the 256-block window, so a withdraw that waits a few blocks for inclusion still pays a note the
payout wallet finds by scanning.

`docs/staking.md` is the whole picture these three sit in: the register, the epochs, what each action
publishes, and a worked join-and-leave.

### `rand-node aggregator register` / `unbond` / `withdraw` (chain 9)

The validator trio's twins, one register over — the three actions an aggregator operator runs on
a chain whose genesis carries an `aggregation` section (block aggregation, spec §2.2):

| command | arguments | meaning |
|---|---|---|
| `aggregator register` | `--key`, `--bond <RAND>`, `--payout <rand1…>`, `--rpc` | print an `AggregatorRegistration` (hex) signed by this node's key; the bond itself burns through the wallet's `submit` as the register bundle's burn |
| `aggregator unbond` | `--key`, `--rpc`, `--no-wait` | stop this aggregator submitting; the bond releases after the chain's aggregation window |
| `aggregator withdraw` | same | pay the released bond into a note at the register's payout address, less the bundle base |

`unbond` and `withdraw` are bundle-less and free of proving, exactly the validator twins;
`withdraw`'s note is the bond less the base, sealed to the payout address the register holds.

### `rand-node aggregate` (chain 9)

The aggregate daemon (spec §8): a separate process from the validator, needing only an RPC
endpoint and the registered aggregator key.

| argument | default | meaning |
|---|---|---|
| `--key <KEY>` | required | the aggregator key the register knows; signs every aggregate |
| `--rpc <URL>` | `http://127.0.0.1:8545` | the node's RPC |
| `--watch` | off | keep polling instead of submitting once and exiting |
| `--interval-secs <N>` | 15 | poll interval in `--watch` mode |
| `--no-wait` | off | return once the node accepts the aggregate |

One pass polls `rand_getUnsealed`, fetches up to `max_covers` raw bundles with
`rand_getRawTransaction`, proves one rVM aggregate over them (CPU; the test profile lands at
tier 19, production at 21 — minutes and tens of GB on this tree, so run it on the proof batch
machine), seals the payment note (subsidy at the current schedule index plus the covered
bundles' proving shares) to the register's payout address, signs and submits. `rand_status`'s
`aggregation` section carries the chain parameters the payment is computed from.

`rand-node run` gains **`--keep-raw-proofs`**: an archive node keeps sealed bundles' raw
proofs; by default the pruning pass rewrites their records (34 public values + the 7 declared
shape bytes) once the sealing window passes.

### `rand-node init`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | data directory to create |
| `--genesis <GENESIS>` | required | genesis file; copied to `<datadir>/genesis.json` |

Creates `<datadir>/db` (RocksDB) with block 0, the deposit notes as the tree's first leaves, and
the validator register. Re-running with the same genesis is a no-op; a different genesis is
refused.

### `rand-node run`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | initialised data directory |
| `--key <KEY>` | required | key file (validator identity, p2p identity, fee recipient) |
| `--listen <LISTEN>` | `/ip4/0.0.0.0/tcp/30303` | libp2p listen multiaddr, repeatable |
| `--bootstrap <BOOTSTRAP>` | none, repeatable | peer to dial at start and every 30 s while disconnected: `/ip4/<ip>/tcp/<port>/p2p/<peer-id>` |
| `--rpc <RPC>` | `127.0.0.1:8545` | JSON-RPC listen address; bind `0.0.0.0` only behind a firewall |
| `--validator` | off | this node holds a validator key and takes part in consensus. A key in no current epoch's set observes until an epoch admits it, so a validator that bonds in after genesis needs no restart; `rand_status` reports `is_validator` (the key is here) and `active_validator` (it is in the current set) separately |
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

### `rand-node verify`

| argument | default | meaning |
|---|---|---|
| `--datadir <DATADIR>` | required | data directory (node must not be running) |
| `--mode <MODE>` | `full` | `quick` or `full`, as for `--verify-chain` |
| `--repair` | off | truncate the damaged tail and rewrite the note, nullifier, anchor and validator families from the replayed ledger; safety state is kept |

Exit code 0 if the chain is consistent, 2 if a problem was found and `--repair` was not given.
Replay re-verifies every bundle proof, so a build whose zkVM constraints differ from the one that
made the chain will stop at the first bundle (`docs/confidential.md`).

### `rand-node status`

| argument | default | meaning |
|---|---|---|
| `--rpc <URL>` | `http://127.0.0.1:8545` | node to ask |

Prints `rand_status` verbatim: height, view, peers, mempool, notes, nullifiers, tree root,
`hc_bundle`, sync state, and the two validator flags — `is_validator` (this node holds a key) and
`active_validator` (that key is in the current epoch's set).

## `rand` (wallet)

Global options, accepted before or after the subcommand:

| option | env | default | meaning |
|---|---|---|---|
| `--rpc <RPC>` | `RAND_RPC` | `http://127.0.0.1:8545` | node JSON-RPC endpoint |
| `--key <KEY>` | `RAND_KEY` | `wallet.key.json` | spend-key file; the note store lives beside it at `<key>.notes.json` |

| command | arguments | behaviour |
|---|---|---|
| `keygen` | | write a new spend-key file at `--key`, mode 0600; refuses to overwrite |
| `address` | `--record` | print this wallet's `rand1…` receiver id (54 characters); `--record` prints the current signed receiver record as JSON instead (the file `rand send --record` and `rand-node genesis --receiver` read) |
| `request` | `--amount <RAND>`, `--memo <TEXT>` | print a `rand:…` payment-request URI carrying this wallet's record inline — payable with no registry and no prior registration (`docs/shielded.md` §2) |
| `register` | `--rotate`, `--fee <RAND>`, `--cuda` | publish this wallet's receiver record on chain, paying with a self-transfer; `--rotate` first moves to a fresh ML-KEM key (every earlier key stays openable, forever) and publishes that instead |
| `balance` | | scan the tree, save the store, print spendable value and the unspent note count |
| `sync` | | scan without printing a balance; prints how far it got |
| `notes` | | every note this wallet has opened: index, `asset`, amount, height, `spent`, `pending` |
| `asset-balance [INDEX]` | | scan, then print what this wallet holds in one bridged asset, or a row per asset held; amounts are in the asset's own smallest unit |
| `history` | | every note this wallet created for someone else, opened through its own outgoing viewing key |
| `send <TO> <AMOUNT>` | `--fee <RAND>` (default `0.001`), `--record <FILE>`, `--registry <URL>` (default `https://randscan.org/api/v1`), `--register`, `--no-wait`, `--cuda` | resolve `TO`'s receiver record (a `rand:…` payment request carries its own; otherwise `--record` or, by default, the registry), verify it, then scan, select at most two notes, prove a 2-in-2-out bundle locally, submit; `--register` also publishes the resolved record, paying to register the receiver; waits for the commit unless `--no-wait` |
| `bond <VALIDATOR> <AMOUNT>` | `--registration <hex>`, `--fee <RAND>` (default `0.001`), `--no-wait`, `--cuda` | stake onto a validator: the bundle burns the amount out of this wallet's notes. `--registration` (from `rand-node register`) exactly when the validator is not in the register yet, and then at least 1000 RAND; prints the new stake and the epoch it counts from (`docs/staking.md`) |
| `faucet [ADDRESS]` | `--amount <RAND>` (default `100`, max `100`) | testnet only: ask a validator node to mint into a note for `ADDRESS` (default: this wallet), wait for the commit; a mint to this wallet's own id carries its record, so it need not already be registered |
| `program build` | `--guest <fib\|memcpy\|bubble_sort\|balance_check\|private_payment>`, `--arg N` (repeatable), `--out <file>` (default `program.json`) | assemble a built-in guest to `{base_pc, words}` JSON; prints the program id |
| `program deploy <FILE>` | `.json` or `.bin` (raw LE words), `--cuda` | pay the deploy floor through a bundle, wait for the commit, print the program id |
| `program show <ID>` | | deployed program metadata |
| `call <PROGRAM-ID>` | `--input N` (repeatable, private), `--tier T`, `--fee <RAND>`, `--auditor <rand1…>`, `--auditor-record <FILE>`, `--registry <URL>` (default `https://randscan.org/api/v1`), `--no-envelope`, `--print-call-key`, `--cuda` | fetch the code from the node, prove the call locally with the chain's FRI profile, seal its input transcript (also to `--auditor`, resolved via `--auditor-record` or the registry), pay through a bundle, wait, print the receipt |
| `open-call <TXHASH>` | `--call-key <hex>`, `--as-auditor` | fetch the receipt and the sealed transcript, open it, check it against the receipt's `H_IN`, re-run the program on the recovered inputs and compare the outputs with the receipt's. **Exits non-zero** if the transcript is not the preimage of that `H_IN`, or if the re-run disagrees with the receipt |
| `receipt <TX>` | | receipt of a committed call, or "no receipt" |
| `bridge-mint <ATTESTATION>` | hex or `@path`, `--to <rand1…>`, `--fee <RAND>`, `--no-wait`, `--cuda` | deposit a guardian-signed attestation as a note: seal the deposit's envelope for its recipient and pay through a bundle from this wallet. Prints the note's `owner`, `time` and `r` every time, and on the waiting path checks the asset index the chain actually deposited under |
| `bridge-burn <ASSET> <AMOUNT> <TO_CHAIN> <TO>` | `--relayer-fee N`, `--fee <RAND>` (default `0.002`), `--no-wait`, `--cuda` | burn a bridged asset to another chain: check the chain has a bridge and holds `ASSET` in its registry, select that asset's notes for the asset bundle and RAND for the fee bundle, prove **both**, submit one transaction. `--relayer-fee` is a *portion* of `AMOUNT` paid to the relayer on the destination chain, not an extra charge: the asset bundle burns exactly `AMOUNT` |
| `bridge` | | the bridge's public state: guardians, emitters, the asset registry, `next_index`, the burn sequence |
| `bridge-deposit-address` | | print this wallet's 32-byte `to` field (the receiver id, hex) for a source-chain depositor; refuses with "register first (rand register) before a bridge deposit can be claimed" until this wallet has published a receiver record |
| `bridge-message <SEQUENCE>` | | one outbound burn message, verbatim, for a guardian to sign |
| `fee bundle` / `fee deploy <words>` / `fee call <tier>` | | minimum fee from the node's schedule |
| `tx <HASH>` | | committed transaction with its block height and index, or "not found" |
| `block <ID>` | | block by height (integer) or by hash (hex) |
| `head` | | `{height, hash, view}` |
| `status` | | node status object (see docs/rpc.md `rand_status`) |
| `peers` | | connected peers |
| `validators` | | the validator register: one row per entry — address, stake, unbonding queue, rewards, payout address, nonce, and whether it is in the current epoch's set |

Amounts are decimal RAND strings with up to 9 decimal places (`1`, `1.5`, `.25`, `0.000000001`).

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
RAND: only index 0 has this chain's nine decimals, and what a bridged token's unit means belongs
to its source chain.

The one number `bridge-mint` cannot be certain of is the `asset` index of a token this chain has
never seen: the ledger assigns it from the registry's `next_index` when the transaction is
*applied*, and the wallet spends about 90 seconds proving the fee bundle in between. The
transaction names the index it sealed for, and the chain refuses it if that is not the index the
registry would give the deposit — so losing that race to another first sighting looks like
`the attestation deposits under asset 2, and the transaction names 1` from `rand_sendTransaction`
(or, if the race resolves after the transaction was pooled, a submission that never commits),
never a note the recipient cannot open. Re-run the command and it seals and proves against the
registry as it now stands. The command also prints the note's `owner`, `time` and `r` (all already
public in that transaction) for every mint, so the note can be rebuilt by hand, and — unless
`--no-wait` — re-reads the committed transaction as a check on the node that answered. A token the
registry already names cannot move: an index is assigned once, forever.

`--cuda` proves on an attached NVIDIA GPU and requires a build with `--features cuda`. There is no
fallback: a missing driver is an error rather than a silent CPU run.

### A first shielded transfer

```bash
rand keygen                                   # wallet.key.json
rand address                                  # rand1… (54 characters) — give this to whoever pays you
rand faucet                                   # testnet: 100 RAND into a note only you can open
rand balance                                  # balance: 100 RAND
rand send rand1q9f… 1.5                     # resolves the record from the registry, ~100 s of local proving, then the commit
rand notes                                    # the spent note, and the change note
```

### Getting paid before ever being on chain

```bash
rand keygen                                             # wallet.key.json, never submitted anywhere
rand request --amount 1.5 --memo "for the coffee"       # rand:rand1x7Qk…?rec=…&amount=1500000000&memo=for%20the%20coffee
#   … hand that URI to whoever is paying; their `rand send` resolves and verifies it inline …
rand register                                           # publish the record too, so `rand send rand1x7Qk… 1` also works later
rand register --rotate                                  # a fresh KEM key, published as record version 2; every earlier note still opens
```

### A confidential call you can open again later

```bash
rand program build --guest balance_check --arg 1000 --out bc.json
rand program deploy bc.json                   # prints the program id
rand call <id> --input 100 --input 200 --input 300 --input 400
rand open-call <txhash>                       # inputs: [100, 200, 300, 400] — verdict: faithful (exit 0)
```

### Key file formats

Node key (both binaries' `keygen` used to share this; only `rand-node` writes it now):

```json
{
  "seed": "hex of 32 bytes",
  "address": "base58 of blake3(public key)",
  "public_key": "hex of 1312-byte Dilithium2 public key"
}
```

Wallet key, version 3 — the spend key and the highest ML-KEM key version this wallet has rotated
to, and nothing else, because every other key (viewing key, outgoing viewing key, the ML-KEM
decapsulation keys, the receiver signing key, the address) is a pure derivation of the spend key:

```json
{ "version": 3, "spend_key": "hex of 8 little-endian u32 words (64 characters)", "kem_version": 0 }
```

A version 2 file (spend key alone, no `kem_version`) still loads, at `kem_version = 0` — it was
written before `rand register --rotate` existed, and 0 is the whole truth about it. No retired
ML-KEM secret is ever written to disk: each is re-derived from the spend key and the version
number, so keeping the highest version reached keeps every version below it (`docs/shielded.md`
§2).

The libp2p peer id is derived as an ed25519 key from `blake3("rand-p2p-identity" || seed)`, so it
is stable across restarts. Losing a wallet key loses every note it could open; there is no
recovery phrase in this release.
