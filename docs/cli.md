# Command-line reference

Two binaries are built by `cargo build --release`: `rand-node` (node and operator commands) and
`rand` (the shielded wallet client). Every command accepts `-h/--help`.

The two hold different kinds of key and must not be confused. A **node key** is a 32-byte seed and
a Dilithium2 key pair whose base58 address is public and signs blocks. A **wallet key** is a
256-bit shielded spend key whose `rand1…` address receives notes and which never signs anything
on chain (`docs/shielded.md` §1).

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
| `--validator <KEY,STAKE,PAYOUT>` | required, repeatable | one register entry: key file path **or** hex public key, the stake in RAND (at least 1000, the staking minimum), and the `rand1…` address its rewards and unbonded stake are paid to |
| `--epoch-blocks <N>` | `1000` | blocks per epoch: how often the validator set is re-derived from the register (spec §8). Part of the genesis hash |
| `--max-program-words <N>` | none (4096) | the largest program a `Deploy` may carry, in words, `1..=65535` (the zkVM's own limit). Omitted, the file has no `max_program_words` field and the chain runs the 4096-word cap with the genesis hash it always had. `--max-program-words 4096` (or `"max_program_words": 4096`) is a different chain from leaving the field out: the field is part of the genesis hash whenever it is present. Omit it to keep a chain's hash. Every node must run a build that knows the field (v0.4) before `init` on such a file — see `rand-node init` |
| `--alloc <ALLOCS>` | none, repeatable | a deposit note: `rand1<address>=<amount in RAND>` |
| `--max-proof-bytes <N>` | none (2 097 152) | the largest proof a transaction may carry, in bytes, `1048576..=33554432` (1–32 MiB). Every proof cap follows it: the call's, each bundle's, the bridge burn's, and the aggregate's |
| `--max-block-bytes <N>` | none (4 194 304) | the largest block, and so the largest transaction, in bytes, `4194304..=67108864`, and at least `2 × max_proof_bytes + 1 MiB` (the fee bundle's proof and the call's, plus room). When either this or `--max-proof-bytes` is given, the rule is checked with the default standing in for the other, so a proof cap above 1.5 MiB needs this flag too. The node's sync budget, sync reader limit and gossip transmit size follow it, and `rand_sendTransaction` refuses a transaction over it (the RPC body limit follows the proof and envelope caps) |
| `--max-call-envelope-bytes <N>` | none (18 432) | the largest call input envelope, in bytes, `18432..=1048576`. `rand call` derives its input-word cap from it: `(N − 1 252) / 4` |
| `--max-program-public-words <N>` | none (0) | the largest public input a `Deploy` may fix (`rand program deploy --public`), in words, `0..=65535`. 0, the default, admits no public input |
| `--out <OUT>` | `genesis.json` | output path |
| `--faucet` | off | **testnet only**: enable `Mint` transactions (`rand_mint`, up to 100 RAND per call). Part of the genesis hash |
| `--no-confidential` | off | disable Deploy/Call transactions on this chain. Part of the genesis hash |
| `--fri-profile <production\|test>` | `production` | zkVM FRI profile every node must use; `test` is insecure and for the test suite. Part of the genesis hash |

Prints one `alloc` line per `--alloc`, then the genesis hash, the validator and note counts, the
blocks per epoch, the program cap (`programs up to N words`: 4096 unless `--max-program-words` set
it), the four call limits (`proofs up to … bytes, blocks up to … bytes, call envelopes up to …
bytes, program public input up to … words`), the faucet and confidential switches, the FRI profile
and `hc_bundle`. Every node of a chain must use a byte-identical genesis file.

The five limit flags (`--max-program-words` and the four above) behave alike: omitted, the file has
no such field, the chain runs the default, and the genesis hash is what it would have been before
the field existed; given, the field is part of the genesis hash, even at its default value. A
running chain cannot change them. `rand_getLimits` reports all five. Chain 13's values, which
`deploy/cut-chain13-genesis.sh` writes:

```
--max-program-words 65535 --max-proof-bytes 8388608 --max-block-bytes 20971520 \
--max-call-envelope-bytes 65536 --max-program-public-words 32768
```

There is no `--alloc-each`: a shielded chain has no per-validator allocation, because value only
exists as a note someone holds the spend key for. Each `--alloc` builds one deposit note with
fresh commitment randomness, so writing the same allocation twice produces two different notes and
two different genesis hashes. This command always writes the note's opening (`pk`, `time`, `r`)
beside `cm` and `amount` (core I-2, required on any chain with a `tokens` section), so a genesis
note's owner and amount are public by design once the file is published — only when and into what
it is later spent stays private. Cut a genesis once and keep the file.

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
      "amount": 1000000000000,
      "opening": { "pk": "<64 hex>", "time": 0, "r": "<64 hex>" } }
  ],
  "faucet": true,
  "confidential": true,
  "fri_profile": "production",
  "hc_bundle": "<64 hex: the bundle guest's digest this build implements>",
  "epoch_blocks": 1000
}
```

`bridge` is the one optional field this command never writes (add it by hand, as above); every
other field it writes, `epoch_blocks` included. `max_program_words` (a number) is written only with
`--max-program-words`, each of `max_proof_bytes`, `max_block_bytes`, `max_call_envelope_bytes` and
`max_program_public_words` only with its flag, and `aggregation` only with `--aggregation`; a file
without them hashes as it did before those fields existed. `--max-program-words 4096` (or `"max_program_words": 4096`) is a
different chain from leaving the field out: the field is part of the genesis hash whenever it is
present. Omit it to keep a chain's hash.

Both `amount` and a validator's `stake` are in smallest units, and both are public: they are what
let everyone add up the initial supply (`docs/supply.md`). Who owns a note is not — only the address
the envelope was sealed to can open it. A validator's `payout` is the shielded address its rewards
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
| `register` | `--key`, `--payout <rand1…>`, `--rpc` | print a `Registration` (hex) signed by this node's key, for a wallet to attach to the bond that registers it |
| `unbond <amount RAND>` | `--key`, `--rpc`, `--no-wait` | move bonded stake into unbonding; withdrawable two epochs later. Free |
| `withdraw <amount RAND>` | same | pay released stake and rewards into a note at the register's payout address, less the bundle base |

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

**A v0.4 genesis needs a v0.4 binary on every node before `init`.** A build older than the
`max_program_words` field does not refuse a file that sets it: the genesis parser ignores fields
it does not know, so it silently drops the cap, builds the no-cap chain's genesis hash and ledger,
and then cannot join — its block 0 is not the fleet's. Check the hash `init` prints against the
one the cut announced; a mismatch on one node is almost always an old binary.

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
| `--min-free-disk-mb <MB>` | `1024` | refuse to start with less free on the data directory's filesystem; `rand_getHealth` says `disk_low` under four times it (audit v4 OPS-3). `0` disables the guard |

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
| `--rpc <RPC>` | `RAND_RPC` | `http://127.0.0.1:8545` | node JSON-RPC endpoint, `http` or `https` (the public one is `https://rpc.randprotocol.org`) |
| `--key <KEY>` | `RAND_KEY` | `wallet.key.json` | spend-key file; the note store lives beside it at `<key>.notes.json`. The store is bound to the chain it was scanned against (its `genesis` field, the node's `rand_getGenesisHash`): pointed at a node on another chain — a wallet file kept across a chain cut — it is emptied and rescanned from leaf 0 with a warning, never scanned from a cursor past the new chain's tree. A store written before the binding existed is rescanned once, the same way |

| command | arguments | behaviour |
|---|---|---|
| `keygen` | | write a new spend-key file at `--key`, mode 0600; refuses to overwrite |
| `address` | | print this wallet's `rand1…` shielded address |
| `viewing-key` | | print this wallet's viewing key `nk`, 64 hex — the parameter `rand_importViewingKey` takes. It reads every note the wallet has sent or received and spends none; derived from the spend key on each run, never stored |
| `balance` | | scan the tree, save the store, print spendable value and the unspent note count |
| `sync` | | scan without printing a balance; prints how far it got. A first sync reads every block header (1024 a call) before the leaves |
| `notes` | | every note this wallet has opened: index, `asset`, amount, height, `spent`, `pending` |
| `asset-balance [INDEX]` | | scan, then print what this wallet holds in one bridged asset, or a row per asset held; amounts are in the asset's own smallest unit |
| `history` | | every note this wallet created for someone else, opened through its own outgoing viewing key |
| `send <TO> <AMOUNT>` | `--asset <INDEX\|rpl1…\|hex>` (default `0`, RAND), `--fee <RAND>` (default `0.001`), `--no-wait`, `--cuda` | scan, select at most two notes of the asset and at most two RAND notes for the fee, prove one four-slot hidden-asset bundle locally, submit; waits for the commit unless `--no-wait`. `AMOUNT` is decimal RAND for RAND and whole units for a token. A token id (`rpl1…` or 64 hex) is resolved to its index from the node's **whole** registry listing (`rand_getTokens`, every page from index 0) — never by a per-token lookup, which would tell the node which token is about to move; a numeric index never reaches the node at all. On chain a token transfer is a plain bundle, indistinguishable from a RAND payment; its fee is RAND, and a wallet without spendable RAND is refused before proving |
| `bond <VALIDATOR> <AMOUNT>` | `--registration <hex>`, `--fee <RAND>` (default `0.001`), `--no-wait`, `--cuda` | stake onto a validator: the bundle burns the amount out of this wallet's notes. `--registration` (from `rand-node register`) exactly when the validator is not in the register yet, and then at least 1000 RAND; prints the new stake and the epoch it counts from (`docs/staking.md`) |
| `faucet [ADDRESS]` | `--amount <RAND>` (default `100`, max `100`) | testnet only: ask a validator node to mint into a note for `ADDRESS` (default: this wallet), wait for the commit |
| `program build` | `--guest <fib\|memcpy\|bubble_sort\|balance_check\|private_payment\|public_echo>`, `--arg N` (repeatable), `--out <file>` (default `program.json`) | assemble a built-in guest to `{base_pc, words}` JSON; prints the program id |
| `program deploy <FILE>` | `.json`, `.bin` (raw LE words), or `.bin` as the image container `rand-guest build` emits, `--public <FILE>`, `--cuda` | print the program id, `hc` and word count (and, with `--public`, the public input's word count and digest); check this chain's program cap with `rand_estimateFee`, and a public input's length against `max_program_public_words` from `rand_getLimits` (refuses either before any proving); pay the deploy floor, public words included, through a bundle, wait for the commit |
| `program show <ID>` | | deployed program metadata |
| `call <PROGRAM-ID>` | `--input N` (repeatable, private), `--expect-public <FILE>`, `--tier T`, `--fee <RAND>`, `--auditor <rand1…>`, `--no-envelope`, `--print-call-key`, `--cuda` | fetch the code and the program's public input from the node and check that they hash to `PROGRAM-ID`; read the chain's limits (`rand_getLimits`); prove the call locally with the chain's FRI profile over that public input; refuse a proof over `max_proof_bytes` before the paying bundle is proved; seal its input transcript; pay through a bundle, wait, print the receipt (with `h_pub`) |
| `open-call <TXHASH>` | `--call-key <hex>`, `--as-auditor` | fetch the receipt and the sealed transcript, open it, check it against the receipt's `H_IN`, re-run the program on the recovered inputs and compare the outputs with the receipt's. **Exits non-zero** if the transcript is not the preimage of that `H_IN`, or if the re-run disagrees with the receipt |
| `receipt <TX>` | | receipt of a committed call, or "no receipt" |
| `bridge-mint <ATTESTATION>` | hex or `@path`, `--pq <JSON or @path>` (required), `--to <rand1…>` (default: this wallet), `--fee <RAND>` (default: the action's floor), `--no-wait`, `--cuda` | deposit a guardian-signed attestation as a note. Before any proving: decode the attestation as a transfer; check `--pq` (the guardians' Dilithium2 co-signature quorum, `[{"index":0,"signature":"<4840 hex>"},…]`) against the node's `pq_guardians` and chain id under the chain's own rules; check the recipient hashes to the attested one; check the node's asset id; read the listed index (`rand_getAssets`). Then derive the deposit note's blinding from the attestation's own digest (F1: `r = blake3("rand-deposit-r-1" || mu)`, the only `r` the chain admits — `docs/bridge.md` §5), seal the deposit envelope for the recipient and submit the `BridgeAttest` on a fee bundle — the fee bundle is one four-slot hidden-asset bundle of RAND — the fee from slots 2–3, slots 0–1 dummies sealed to nobody, `burn_a`/`burn_r`/`burn_asset` zero — proved locally against the whole transaction, the `--pq` quorum included, so nobody can swap the co-signatures after the proof. The deposit note itself is rebuilt by its recipient from the action's public fields, so a garbage envelope still leaves it findable. Prints the note's `owner`, `time` and `r` every time, and on the waiting path checks the asset index the chain actually deposited under |
| `bridge-rotate <ROTATION>` | hex or `@path`, `--pq <JSON or @path>` (required), `--fee <RAND>` (default: the action's floor), `--no-wait`, `--cuda` | submit a guardian-set rotation (payload 2) with the current PQ set's co-signature quorum, as a `BridgeAttest` that deposits nothing. Before any proving: refuse anything but a rotation, a rotation that does not step Rand's set by one, and a quorum the chain would refuse; then the fee bundle — the fee bundle is one four-slot hidden-asset bundle of RAND — the fee from slots 2–3, slots 0–1 dummies sealed to nobody, `burn_a`/`burn_r`/`burn_asset` zero — proved locally against the whole transaction, the `--pq` quorum included, so nobody can swap the co-signatures after the proof. Prints the `guardian_set_index` Rand is on afterwards |
| `bridge-pause` | `--sig <HEX or @path>` (required), `--no-wait` | pause bridge minting (bridge hardening B1): a bundle-less, fee-less `PauseMints` — no key file and no RAND needed. The file is `rand-bridge-gov pause`'s output, the pause key's 2 420-byte signature as hex, made for the bridge's current `pause_nonce`; checked against the node's `pause_key` and chain id before it is sent, and a file signed for another nonce is refused naming that nonce. Burns and rotations stay open while paused |
| `bridge-unpause` | `--pq <JSON or @path>` (required), `--no-wait` | lift a pause with a PQ guardian quorum (`rand-bridge-gov pq-unpause`'s `[{"index","signature"}]`), made for the bridge's current `pause_nonce`, checked under the chain's five rules before it is sent. Bundle-less and fee-less; the pause key alone can never unpause |
| `token register-bridged` | `--name`, `--symbol`, `--salt <hex32>`, `--chain`, `--token <hex32>`, `--decimals` (the first backing's source decimals), `--pq <JSON or @path>` (required), `--fee <RAND>`, `--no-wait`, `--cuda` | register a bridged token after genesis (bridge hardening B4) with its first backing, authorised by a PQ guardian quorum (`rand-bridge-gov pq-register`'s file) and paid by this wallet's fee bundle (`--fee` default: the bundle base plus the node's `registration_fee`). Checked — name rules, backing chain and decimals, the quorum at the node's `list_nonce` — before a key file is opened or anything proved; a file signed for another nonce is refused naming it. Then the fee bundle is one four-slot hidden-asset bundle of RAND — the fee from slots 2–3, slots 0–1 dummies sealed to nobody, `burn_a`/`burn_r`/`burn_asset` zero — proved locally against the whole transaction, the `--pq` quorum included, so nobody can swap the co-signatures after the proof. List on Rand first, `setToken` on the endpoint second |
| `token list-backing` | `--asset <index>`, `--chain`, `--token <hex32>`, `--decimals`, `--pq <JSON or @path>` (required), `--fee <RAND>`, `--no-wait`, `--cuda` | add a backing to a bridged token (B4), authorised by a PQ guardian quorum (`rand-bridge-gov pq-list`'s file), paid by a fee bundle from this wallet (`--fee` default: the bundle base). The backing and the quorum at the node's `list_nonce` are checked before a key file is opened or anything proved; then the fee bundle is one four-slot hidden-asset bundle of RAND — the fee from slots 2–3, slots 0–1 dummies sealed to nobody, `burn_a`/`burn_r`/`burn_asset` zero — proved locally against the whole transaction, the `--pq` quorum included, so nobody can swap the co-signatures after the proof |
| `bridge-burn <ASSET> <AMOUNT> <TO_CHAIN> <TOKEN> <TO>` | `--relayer-fee N`, `--fee <RAND>` (default `0.01`), `--no-wait`, `--cuda` | burn a bridged asset to another chain: check the chain has a bridge, holds `ASSET` in its registry, that the coin `TOKEN` on `TO_CHAIN` backs it and has at least `AMOUNT` locked, and that `AMOUNT` and the relayer fee are whole release units; then prove **one** bundle that spends the asset in slots 0–1 and burns exactly `AMOUNT` of it (`burn_a`, `burn_asset`) and pays the RAND fee from slots 2–3. `--relayer-fee` is a *portion* of `AMOUNT` paid to the relayer on the destination chain, not an extra charge |
| `token burn <ASSET> <AMOUNT>` | `--fee <RAND>` (default `0.001`), `--no-wait`, `--cuda` | destroy `AMOUNT` of an RPL token this wallet holds (`ASSET`: index, or `rpl1…`/hex resolved from the whole registry listing, as for `send`); its public supply drops by exactly that. One bundle, shaped like a bridge burn's. A bridged token is refused before proving: it leaves through `bridge-burn` |
| `token create` | `--name`, `--symbol`, `--decimals <0..=9>`, `--salt <hex32>` (random if not given), then either `--fixed-supply <N> --to <rand1…>` or `--authority-key-out <FILE> [--initial <N> --to <rand1…>]` (exactly one of the two; `--initial`/`--to` must be given together), `--fee <RAND>` (default: the bundle base plus the registry's `registration_fee`), `--no-wait`, `--cuda` | register a token (RPL spec §4) at the registry's next index. Fixed supply (`--fixed-supply`, mints once, forever — authority `none`) or `Key`-authorised (`--authority-key-out`: a fresh Dilithium2 key file, `rand-node keygen`'s own shape, written 0600 and refusing to overwrite — mintable again with `token mint`), with or without an initial mint. Reads `next_index` and `registration_fee` off `rand_getTokens` before proving; the initial mint's note (recipient, `r`, `time`, envelope) is built first, since the asset id binds the whole initial mint. The `Key` branch's fresh authority key is written to `<FILE>.pending` right before the one call that can lose a race (`IndexMismatch`) is attempted — never before — then promoted to `FILE` once the chain accepts the registration, or discarded if the chain itself refuses it; a transport failure of unknown outcome leaves it at `.pending` rather than guessing. On `IndexMismatch` (another registration won the race) prints "another token took index N first — re-run to register at N+1"; on success prints the index and the id, hex and `rpl1…` |
| `token mint` | `--asset <INDEX\|rpl1…\|hex>`, `--to <rand1…>`, `--amount <N>` (the token's own smallest unit), `--authority-key <FILE>`, `--fee <RAND>` (default `0.001`), `--no-wait`, `--cuda` | mint more of a `Key`-authorised token. Reads the token's row off `rand_getTokens` for its `mint_nonce`; refused up front, before any note or proof, if `--asset` is not `Key`-authorised or `--authority-key` is not that key. Signs `token_mint_message` (the note's commitment and the envelope's digest included) with the authority key |
| `token set-authority` | `--asset <INDEX\|rpl1…\|hex>`, `--authority-key <FILE>`, then either `--new-key <FILE>` or `--renounce` (exactly one), `--fee <RAND>` (default `0.001`), `--no-wait`, `--cuda` | hand a `Key`-authorised token to another key, or renounce minting for good (`--renounce`: no key can ever mint it again). Same up-front refusals as `token mint`; signs `set_authority_message` |
| `token info <INDEX\|rpl1…\|hex>` | | one token's full `rand_getTokens` row: name, symbol, decimals, authority (kind, and for `key` the public key and address), `mint_nonce`, total supply, `registered_at`, id (hex and `id_text`) and, if bridged, each backing (chain, token, decimals, locked, `mint_cap_per_day`, `minted_today`, `mint_day`). Resolved from the **whole** listing — never `rand_getToken` — the same privacy reason as `send`'s asset resolution |
| `token list` | `--from <index>` (default `0`), `--limit <N>` (default `1000`) | one page of `rand_getTokens`: `enabled`, `registration_fee`, `next_index`, and `tokens` (every row `token info` prints) |
| `bridge` | | `rand_getBridgeState` verbatim: `enabled`, `guardians`, `pq_guardians`, `pause_key`, `emitters`, per-token `assets` rows (each backing's `locked`/`mint_cap_per_day`/`minted_today`), `mint_paused`, `pause_nonce`, `list_nonce`, `registration_fee`, `burn_sequence` — no `next_index` (that is the token registry's own field, `token list`/`rand_getTokens`) |
| `bridge-message <SEQUENCE>` | | one outbound burn message, verbatim, for a guardian to sign |
| `fee bundle` / `fee deploy <words>` / `fee call <tier>` | `--public-words M` (`deploy`), `--bytes B` (`call`) | minimum fee from the node's schedule. `--public-words` prices a public input like code words; `--bytes` is the call's proof plus input-envelope bytes, and only bytes past the free 2 MiB + 18 432 add to the fee (1 000 units per KiB) |
| `tx <HASH>` | | committed transaction with its block height and index, or "not found" |
| `tx-key <HASH>` | | one row per output of that transaction this wallet sent, received or kept as change: `output` (`bundle:0` … `bundle:3`, the one bundle's four slots, or `mint:0`), role, amount (in RAND, or `N (asset I)` for a token), and the per-transaction key it was sealed under. Recovered from the chain through the envelope's sender or receiver half, so it works for any past transaction; hand a `sent` row's key to a payee or auditor and `rand_checkTransaction <HASH> <KEY>` discloses that one output. A dummy slot (zero value, sealed to a throwaway key) opens to nobody and has no row. Errors if the wallet opens no output of the transaction |
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

The note store beside the key file also holds the wallet's own copy of the commitment tree and a
Merkle witness per owned note, built by the scan from the same `rand_getCommitments` pages it
already reads. Every bundle this wallet proves takes its witnesses from that copy — a send never
calls `rand_getWitness`, so the node cannot learn which leaves it spends; the only tree question
left is `rand_getAnchor`, which names no leaf. A store written before that copy existed (any
pre-v0.5.1 build) is detected on load and rescanned from leaf 0 once to build it.

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

**Public inputs.** `program deploy --public <FILE>` stores a public input with the program, on a
chain whose genesis sets `max_program_public_words` (0, none, by default). The file is one of two
forms:

- whitespace-separated u32 words, each decimal or `0x` hex;
- an ELF (`\x7fELF` magic; a `.so` name must be one), word-encoded as the sBPF guest reads its
  program: the byte length, then the bytes four per word, little-endian, the last word
  zero-padded. The committed SPL Token ELF (108 600 bytes) is 27 151 words.

The program id then binds the public input too (`program_id_with_public`), so the id `deploy`
prints differs from the one `program build` printed for the same code. A call carries no public
words of its own. `rand call` fetches the program's (`rand_getProgramPublic`), checks that code and
public input hash to the id, and proves over them. The chain checks the proof's `H_PUB` against
the digest it recorded at deploy, so a proof over any other public input is refused.
`--expect-public <FILE>` refuses before proving when the program's public input is not that
file's words.

**Call limits.** `rand call` reads the chain's limits from `rand_getLimits`:

- the most private input words a call with an input transcript may carry is
  `(max_call_envelope_bytes − 1 252) / 4`, where 1 252 bytes is the transcript's fixed overhead
  with an auditor named. That is 4 295 on a default chain, and 16 071 at 65 536 bytes. A node
  without `rand_getLimits` gets the old 4 096;
- a proof over `max_proof_bytes` (default 2 MiB) is refused before the paying bundle is proved.

The default fee is `BUNDLE_BASE + call_fee(tier, bytes)` (0.001 RAND plus the call fee, in
units), where `bytes` is the proof plus the sealed transcript.

### A first shielded transfer

```bash
rand keygen                                   # wallet.key.json
rand address                                  # rand1… — give this to whoever pays you
rand faucet                                   # testnet: 100 RAND into a note only you can open
rand balance                                  # balance: 100 RAND
rand send rand1q9f… 1.5                     # ~100 s of local proving, then the commit
rand notes                                    # the spent note, and the change note
```

### A confidential call you can open again later

```bash
rand program build --guest balance_check --arg 1000 --out bc.json
rand program deploy bc.json                   # prints the program id
rand call <id> --input 100 --input 200 --input 300 --input 400
rand open-call <txhash>                       # inputs: [100, 200, 300, 400] — verdict: faithful (exit 0)
```

### A program with a public input

```bash
rand program build --guest public_echo --out echo.json   # reads four public words
echo "1 2 3 4" > public.txt
rand program deploy echo.json --public public.txt    # program id binds the four words
rand call <id>                                       # proves over [1, 2, 3, 4]: out0 = 12, receipt has h_pub
rand call <id> --expect-public other.txt             # refused before proving if the words differ
rand program deploy sbpf.bin --public spl_token.so   # an ELF as 27 151 public words (needs max_program_public_words ≥ 27 151)
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

Wallet key, version 2 — the spend key and nothing else, because every other key (viewing key,
outgoing viewing key, ML-KEM decapsulation key, address) is a pure derivation of it:

```json
{ "version": 2, "spend_key": "hex of 8 little-endian u32 words (64 characters)" }
```

The libp2p peer id is derived as an ed25519 key from `blake3("rand-p2p-identity" || seed)`, so it
is stable across restarts. Losing a wallet key loses every note it could open; there is no
recovery phrase in this release.
