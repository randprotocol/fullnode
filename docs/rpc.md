# JSON-RPC reference

The node serves JSON-RPC 2.0 over HTTP on `--rpc` (default `127.0.0.1:8545`).

```bash
curl -s http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"rand_getHead","params":[]}'
```

The same port also serves a WebSocket on `/` and `/ws`, which pushes every committed head instead
of being polled for it — see [Subscriptions](#subscriptions-websocket).

Conventions:

- Validator addresses are base58 strings (32 bytes). Hashes are 64 hex characters, with or
  without `0x`. Shielded values (commitments, nullifiers, anchors, tree roots, witness levels) are
  `Word8` — eight little-endian `u32` words as 64 lowercase hex characters.
- Shielded addresses are `rand1` + base58, about 1668 characters. A parameter longer than 2000
  characters is refused on its length before it is parsed.
- **One rule, no exception: every `u64` amount — RAND units or token units, chain state or a
  decoded transaction's own field — is a decimal string** (`"1500000000"` = 1.5 RAND; 1 RAND =
  10^9 units), because a JSON number is not an exact integer past 2^53 and a 9-decimal token's
  supply already passes it at a few tens of millions of units. Indices, nonces, heights, leaf
  indices, views, lengths, decimals and day counters (`mint_day`) are never amounts and are plain
  JSON integers throughout. Concretely, every one of these is a string: `rand_getTokens`/
  `rand_getToken`/`rand_getTokenSupply`'s supplies and each backing's `locked`, `mint_cap_per_day`
  and `minted_today`; `rand_getAssets`'s and `rand_getBridgeState.assets[]`'s matching rows and
  both methods' `registration_fee`; a decoded transaction's `bundle.fee`, `burn_a` and `burn_r`;
  and `action.amount` for `mint`, `bond`, `unbond`, `withdraw`, `bridge_attest`, `bridge_burn`
  (plus its `relayer_fee`), `token_mint`, `token_burn` and `register_token` (`initial_amount`/
  `initial.amount`). **Breaking change, 2026-09-20 (v0.5 / chain 14):** the pre-chain-14 fields in
  that list — `bundle.fee`; `action.amount` for `mint`, `bond`, `unbond`, `withdraw`,
  `bridge_attest`; `action.amount` and `action.relayer_fee` for `bridge_burn`; and
  `rand_getAssets`'s / `rand_getBridgeState.assets[]`'s `locked` — used to be JSON integers; see
  the changelog below for the full list and why it changed.
- Heights, leaf indices and views are JSON integers.
- **Every request must carry an `id` member**, batched or not: an object without one is a JSON-RPC
  notification, and this node refuses it with `-32600` rather than running it silently. An explicit
  `"id": null` is a normal request. See [Batches](#batches) for why.
- `randprotocol_client::RpcClient` (Rust) wraps every method below.

**There is no balance method, and no account method.** This chain has no accounts; see
`docs/shielded.md`. A wallet computes its own balance by scanning the commitment tree with its
viewing key, which is what `rand_getCommitments` and `rand_getNullifiers` exist for. That
holds for bridged assets too: a bridged holding is a note whose `asset` word is the registry's
index for it (phase S3, `docs/bridge.md`), so the bridge methods below report the bridge's own
*public* state — guardians, emitters, the asset registry, the outbound burn log — and no
per-address balance. `rand_getAssetBalance` is gone for good.

**A node can now hold viewing keys — never spend keys.** `rand_importViewingKey` hands the node
a viewing key so it scans on the holder's behalf (the Zcash `z_importviewingkey` analogue, for
explorers). That is the one exception to "the node never holds a key", and it is deliberate: the
key arrives in memory only, is capped at 64 per node, dies with the process, and can disclose
notes but never move them. It also means the RPC port should be treated as key-bearing once an
import has happened: bind it where you would bind a wallet, not to the public internet.

## Two listeners: the operator's and the public one (audit v6)

`rand-node run --rpc <ADDR>` is the **operator's listener**: every method, batches, the
WebSocket. It identifies a caller by its socket address and trusts loopback — the viewing-key
methods answer loopback only, and loopback is not metered — so it belongs on `127.0.0.1` and
nothing that faces the Internet should forward to it. A reverse proxy or an SSH forward *arrives
on loopback*: behind one, every visitor is the operator.

`rand-node run --public-rpc <ADDR>` opens a second, **public listener** for exactly that hop:

- a fixed method set — the reads a wallet, an explorer or a page needs, and
  `rand_sendTransaction`. Not served, whatever else is configured: `rand_importViewingKey`,
  `rand_getViewingNotes`, `rand_removeViewingKey`, `rand_mint`, `rand_getPeers`, and any method
  added later until it is listed (`rpc::PUBLIC_METHODS`);
- no batch arrays (`-32600`), and no WebSocket (`GET /` and `GET /ws` have no route);
- **one meter for every caller together** (600 in a burst, 150 a second; HTTP 429 with a
  JSON-RPC body past it). Per-visitor limits belong to the proxy, which can see the visitors;
- at most half of the node's blocking-read slots, so the operator's listener is never starved.

Both listeners share the read limits: a range read is answered `-32000` "busy" after 30 s, and
`rand_getBlocks` ends its page once it has read 64 MiB of blocks, or before the header that would
take its reply past 16 MiB (a short page, as at the head).

`--rpc-viewing-token-file <PATH>` puts a bearer token on the viewing-key methods of the
operator's listener: the first line of the file (32+ characters), sent as
`Authorization: Bearer <token>`. With it loopback alone is not enough, and a caller anywhere
that presents it is served.

## Batches

The body of a POST to `/` is either one request object or an **array of at most 20** of them. A
batch answers with an array of the same length, in request order, one response per request —
errors included, so a client can correlate by position as well as by id. The requests run one after
another, not concurrently: a batch is a request amplifier, and `rand_getWitness` rebuilds the
whole commitment tree per call.

A request object with no `id` member is a JSON-RPC **notification**, and this node refuses it with
`-32600` and `"id": null` rather than running it silently — inside a batch and as a lone request
object alike, since both go through the same path. Every method here either reads, where
the answer is the point, or submits, where a silently dropped request is an invisible wallet bug —
and refusing keeps the reply array the same length as the request array. An explicit `"id": null`
is a normal request and is answered as always.

An empty array, an array over 20, and a body that is neither an object nor an array each come back
as a *single* `-32600` error object with a null id, because there is no per-request id to attach
them to. A batch that parses always answers `200`, whatever the errors inside it.

**The count cap is not the byte cap.** The whole body is still bounded by the node's request-body
limit, which is sized for a single proof-carrying transaction, and that limit is enforced
before the count is ever looked at: a batch of two *proof-carrying* `rand_sendTransaction` calls
is refused with a `413` and a `-32600` body naming the limit, whatever the count cap says. (The
bundle-less actions — a faucet mint, an `Unbond`, a `Withdraw` — are a few kilobytes each and
batch fine; it is the proofs that do not.) Batching proved submissions does not work, and is not
what this is for; batching the reads a wallet or explorer makes per page is.

```bash
curl -s http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '[{"jsonrpc":"2.0","id":1,"method":"rand_getHead","params":[]},
       {"jsonrpc":"2.0","id":2,"method":"rand_getTreeInfo","params":[]}]'
```

## Methods

### `rand_chainId`
Params: `[]`. Result: chain id (integer). Transactions must carry this id.

### `rand_tokenInfo`
Params: `[]`. Result: `{ "symbol": "RAND", "decimals": 9 }`.

### `rand_sendTransaction`
Params: `[hex]` where `hex` is `bincode(Transaction)` (as produced by `Transaction::encode()` in
`randprotocol-core`, or by the `rand` wallet). Result: the transaction hash.

The node validates against the state at the tip of the chain in the order of `docs/shielded.md`
§5 — size caps, chain id, shape and fee floor, anchor, time, nullifiers and commitments, action
checks, the bundle digest, the bundle proof, and for a call its own proof and tier fee — puts it
in the mempool, and gossips it. Errors come back as code `-32000` with the reason, for example
`nullifier already spent`, `anchor is not one of the last 256 roots`,
`time 12 is outside [244, 500]`, `fee 1000000 below minimum 2000000`,
`the bundle's digest is not what its proof published`, `invalid bundle proof: …`,
`unknown program …`, `already in mempool`, `conflicts with a pending transaction over <nullifier>`,
`faucet is disabled on this chain`, and for the bridge actions `bridge: attestation already
consumed`, `the attestation names a different recipient`, `the attestation deposits under asset 2,
and the transaction names 1`, `the bundle burns 399, not the 400 the action declares`, and for a
bundle carrying a burn its action may not carry, `the bundle burns asset 2 on an action that burns
no token` or `a burn of 5 is not allowed on this action`. A sealed (pruned) bundle's marker-form
proof submitted outside sealed-form sync — gossip, RPC, a proposer's trial-apply — is refused
`PrunedFormOutsideSync`, and, deliberately, **not** cached as a permanent verdict: the marker form
hashes to the raw transaction's own id (M1), so caching that refusal under the shared hash would
let a fast gossip peer censor the honest transaction network-wide (`docs/confidential.md`,
"Transaction binding").

Acceptance is not commitment: poll `rand_getTransaction` until it returns a block.

A transaction larger than the chain's block cap (`max_block_bytes` from `rand_getLimits`; 4 MiB by
default) is refused here with `-32000`, naming both sizes, before it reaches the mempool. The
request body itself is capped at `2 × (2 × max_proof_bytes + 4 × 2048 + max_call_envelope_bytes +
16 384 + 64 KiB) + 256 KiB` — 8 867 840 bytes on a default chain, 34 127 872 on a chain-13-sized
genesis (8 MiB proofs, 64 KiB call envelopes) — computed from the genesis at startup; a body over
it is `-32600` naming the limit. (`4 × 2048` is the bundle's four envelopes at the envelope cap.)

### `rand_mint` (testnet faucet)
Params: `[address]` or `[address, amount]`, where `address` is a `rand1…` shielded address and
`amount` is a string of units, at most `100000000000` (100 RAND; the default). Result: the mint
transaction hash.

Only available when the genesis file has `"faucet": true`; otherwise error `-32000`
`faucet is disabled on this chain`. The node builds the note, seals an envelope to `address`
under a throwaway sender key, signs the `Mint` with its own validator key and submits it through
the normal mempool, so the mint goes through consensus and every node applies it. An observer has
no validator key and answers `faucet mints are signed by validators; ask a validator node`. Poll
`rand_getTransaction` for the commit.

On a chain whose genesis sets `staking.faucet_recipients` (chain 15) only the listed wallets can be
paid: a mint to any other address is refused at admission with `the faucet may not mint to this
recipient (not in staking.faucet_recipients)` (`docs/staking.md` §2).

The faucet is rate limited per node process: eight mints back to back, refilling at one a
second. Past that the call answers `faucet is rate limited on this node (8 mints back to back,
refilling at 1/s); try again shortly`, so a faucet flood cannot fill the pool ahead of a bridge
`PauseMints`, which is also exempt from the pool's `mempool full` refusal and ordered first in a
block, like the other three governance actions.

### `rand_getCommitments`
Params: `[from_index]` or `[from_index, limit]`. Result: a page of commitment-tree leaves from
leaf `from_index`, oldest first, at most 1000 rows however large `limit` is (a missing or null
`limit` asks for the maximum). Page until the reply is short or empty.

```json
[ { "index": 40, "cm": "2a9f…07", "height": 37,
    "envelope": { "kem_ct": "b41c…", "to_receiver": "77e0…", "to_sender": "0c31…", "body": "9dd2…" } } ]
```

Every leaf and every envelope is served to everyone; only a viewing key tells one wallet's rows
from another's.

### `rand_getNullifiers`
Params: `[from_height]` or `[from_height, limit]`. Result: every nullifier published from that
block height onwards, same 1000-row cap.

```json
[ { "height": 37, "nullifier": "8c04…d1" }, { "height": 41, "nullifier": "12be…9a" } ]
```

A page can stop inside a height, so a caller pages back to the highest height it saw rather than
past it; re-reading rows is harmless.

### `rand_getCompactBlocks`
Params: `[from_height, to_height]`, both required. Result: one row per block in the range, oldest
first, carrying everything a light wallet needs to trial-decrypt and track spends — and nothing
else: no proofs, no actions, no receipts.

```json
[ { "height": 192, "hash": "63f6…08", "timestamp_ms": 1788000123456,
    "commitments": [],
    "transactions": [
      { "hash": "4f2c…e7",
        "commitments": [ { "index": 40, "cm": "2a9f…07",
          "envelope": { "kem_ct": "…", "to_receiver": "…", "to_sender": "…", "body": "…" } } ],
        "nullifiers": ["8c04…d1", "5e77…20", "03aa…6f", "e19b…42"] } ] } ]
```

Every bundle-carrying transaction owns four notes and four nullifiers here — its four slots, the
dummy slots included, which no reader can tell from real ones (only the example's first
commitment row is shown).

One call covers at most **128 blocks** (half the 256-block anchor window), counted from
`from_height`; a wider range is clamped, not refused. Past the first block the reply also stops
once it has emitted **1000 notes** — but the *first* block of a reply is always served whole,
however many notes it holds, so a caller is never stuck behind one fat block. Resume from the
last returned `height` plus one, and page until the reply is empty; a `from_height` past the head
comes back `[]` rather than an error.

The block-level `commitments` array holds the leaves of that block that belong to no transaction
— the genesis deposits at height 0 — and is empty at every other height. A `Withdraw`'s and a
`BridgeAttest`'s deposit notes do appear under their transaction even though the wire does not
carry their commitments (the ledger derives them, spec §7); they are appended immediately after
that transaction's own notes, which is the order served here.

Errors: `-32602` for a backwards range (`to_height` below `from_height`) or a missing bound.

On a node started with `--prune-history`, a range that reaches a height below the floor (genesis
excepted) answers error `-32010` naming the first such height —
`pruned: height h is below this node's retention floor f` with `data: {"floor": f}` — ask the
archive for it. `[0, to]` still serves genesis alone when `to` is 0.

### `rand_getAnchor`
Params: `[]` for the head, or `[height]`. Result: `{ "height": 192, "root": "6b1d…c4" }`, or error
`-32001` for a height with no recorded anchor.

Only *block-end* roots are anchors, and only the newest 256 are kept. A node that caught up in one
sync batch longer than that window holds rows only for the heights the batch covered, so ask for
the head — the only anchor a prover should build against anyway.

### `rand_getWitness`
Params: `[index]`. Result: `null` past the end of the tree, else the Merkle path of that leaf,
leaf-first, exactly 32 levels, with the tree's *current* root:

```json
{ "index": 40, "root": "6b1d…c4", "path": ["0000…00", "f2a1…3b", "…"] }
```

The root is the live root, not an anchor: a wallet checks it against the anchor it is proving
under and refetches if a leaf was appended in between. This is the most expensive read a node
serves (it rebuilds a full depth-32 tree from every stored leaf) and the one request that
discloses something about the caller — see `docs/shielded.md` §6.

### `rand_getTreeInfo`
Params: `[]`. Result: `{ "next_index": 41, "root": "6b1d…c4", "nullifiers": 12 }` — the leaf count
(the index the next note will get), the current root, and how many notes have been spent.

### `rand_importViewingKey`
Params: `[viewing_key]` or `[viewing_key, rescan_from_height]`, where `viewing_key` is a party
viewing key's `nk` as 64 hex characters and `rescan_from_height` is the block height to start
watching from (default 0, the whole chain). Result:

```json
{ "imported": true, "rescan_from_height": 0, "viewing_keys": 3 }
```

The Zcash `z_importviewingkey` analogue (`docs/rpc-comparison.md` §4), and the one deliberate
exception to this chain's "the node never holds a key" property: after this call the node holds
`viewing_key` **in memory** and trial-decrypts for it — which is what a block explorer runs a
node for. What it can never hold is a *spend* key (the RPC layer has no type for one), so an
imported key changes what compromising this process would disclose — the notes that key opens,
which its holder can already see — and never what it could spend. **Nothing is written to disk:**
a restart clears every import, and the operator's orchestration re-imports on boot.

Imports are bounded and idempotent:

- At most **64** keys per node (`viewing_keys` in the reply is the live count, also in
  `rand_status`). The 65th distinct key is `-32000`; a key already held is a no-op
  (`"imported": false`) — in particular it does **not** restart the scan, so a rescan from an
  earlier height is a restart plus re-import, not a second call.
- A `rescan_from_height` in the future is accepted and simply matches nothing until the chain
  reaches it.
- Import itself never scans: the scan is lazy, driven by `rand_getViewingNotes`.
- **Loopback only.** `rand_importViewingKey`, `rand_getViewingNotes` and `rand_removeViewingKey`
  answer a caller on the loopback interface and refuse anyone else with `-32000`. Nothing in this
  RPC authenticates anyone, and the facility is for the node operator's own explorer: without the
  rule a stranger could fill all 64 slots and lock the operator out until a restart. `rand-node run
  --rpc-viewing-open` lifts it, for an operator who has put something that *does* authenticate in
  front of the port.

Errors: `-32602` for a malformed key, `-32000` from a caller that is not on loopback.

### `rand_removeViewingKey`
Params: `[viewing_key]`. Reply: `{"removed": bool, "viewing_keys": n}` — `removed` is false when
the node was not holding that key. The import's scan state goes with it, its slot is freed, and
the key is zeroised in memory. Loopback only, like the other two.

The registry is keyed by a one-way id of the key (`blake3("rand-viewing-registry-id-1" ‖ nk)`),
never by `nk` itself, so the only long-lived copy of the key is the import that removal zeroises
(issue #65), and the three viewing methods parse the key into buffers wiped on drop. Not wiped:
the request's own JSON text, and transient copies the trial decryption makes.

### `rand_getViewingNotes`
Params: `[viewing_key]` or `[viewing_key, from_index, limit]` — `from_index` pages the matched
notes by leaf index (default 0), `limit` caps the page (default and maximum 1000, as everywhere).
Result:

```json
{ "scanned_index": 10041, "next_index": 10041, "complete": true,
  "notes": [
    { "index": 40, "cm": "2a9f…07", "height": 37, "role": "received",
      "note": { "pk": "…", "from": "…", "amount": "1500000000", "asset": 0, "time": 5, "memo": "coffee" },
      "nullifier": "8c04…d1", "spent": false },
    { "index": 43, "cm": "b310…88", "height": 39, "role": "sent",
      "note": { "pk": "…", "from": "…", "amount": "25000000", "asset": 0, "time": 9, "memo": null },
      "nullifier": null, "spent": null }
  ] }
```

Each call first advances the key's scan by up to **10 000** new leaves (one ML-KEM decapsulation
plus up to two AEAD opens each), then serves the page. `scanned_index` is how far the scan has
tried, `next_index` the tree's size, and `complete` is true when they meet — a long rescan
completes over several calls, so an explorer polls until `complete`. The cap bounds one request,
not the history: the cursor persists between calls.

A row is one matched leaf, in tree order. `role` is `"received"` for a note the key owns (the
envelope opened as receiver *and* the note names the key's `pk` — an envelope anyone can seal to
a public address is not proof of ownership) and `"sent"` for a note the key created for someone
else, opened through the outgoing viewing key. A `received` row carries the note's `nullifier`
(a function of the viewing key) and whether the chain has published it — refreshed on every call;
a `sent` row has neither, because the note is not the key's to nullify. Amounts are strings, as
everywhere chain state is served. The note's `memo` is the sender's encrypted memo (spec
2026-09-26 §2.3) if it opened one — `null` for no memo, or an envelope this key opened but whose
memo field was malformed (a malformed memo never costs the payee the note itself, just the text).
A memo can be present on any chain: where the genesis sets no `envelope_bytes` (chains 14 and 15) the ledger still accepts any note envelope up to 2 048 bytes, so a memo-carrying 1 860-byte envelope from another sender is valid and opens with its memo — wallets only *seal* one where the chain sets `envelope_bytes`. A memo is anyone's text: show it as untrusted (see `docs/cli.md`, "How a memo is shown").

Errors: `-32602` for a malformed key or page bound, `-32001` for a key this node has not
imported.

### `rand_getProgram`
Params: `[program_id]`. Result: `null` or
`{ "id", "base_pc", "words_len", "code_hash", "deployed_at", "public_words_len", "public_digest" }`.
There is no `deployer` field: a deploy is paid by a bundle, so the chain does not know who deployed
it.

`public_words_len` is the length of the program's deploy-time public input (0 without one), and
`public_digest` is its `Word8` hex digest — the value every call's proof is checked against — or
`null` for a program deployed without a public input. The words themselves are
`rand_getProgramPublic`'s.

### `rand_getProgramPublic`
Params: `[program_id]`. Result: the program's deploy-time public words as one hex string, each word
as its 4 little-endian bytes (8 hex digits a word, the same byte order as a `Word8` digest):
`[1, 2, 0xdeadbeef]` is `"0100000002000000efbeadde"`. `""` for a program deployed without a public
input, `null` for an id no program has. A wallet proving a call passes these words to the prover:
the proof commits to them and the ledger checks that commitment against `public_digest`.

### `rand_getProgramCell`
RPL-2 (program state; genesis-gated). Params: `[program_id, key]`, the key 64 hex characters
(a `Word8`, with or without `0x`). Result: `{ "key": "<64 hex>", "value": "<64 hex>" }`. A cell
the program never wrote — or wrote zeros to, which deletes it — reads as 64 zeros, the one
encoding of "absent"; so does any key of a program nobody deployed (the program's existence is
not checked). `{"enabled": false}` on a chain without a `program_state` section. A cell is
public by design (spec §2): what a wallet reads to build an `invoke`'s `reads`.

### `rand_getProgramCells`
Params: `[program_id, { "after": "<64 hex>" | null, "limit": n }]`, the object optional. Result:
`{ "cells": [{ "key", "value" }, …], "next": "<64 hex>" | null }` — the program's cells in key
order (an unsigned comparison of the eight words), starting after `after`, at most `limit` of
them (clamped to 1 000, at least 1). `next` is the last key served when more follow — pass it
back as `after` — and `null` on the last page. `{ "cells": [], "next": null }` for a program with
no cell; `{"enabled": false}` without the section.

### `rand_getProgramVault`
Params: `[program_id]`. Result: `[{ "asset": 0, "amount": "123" }, …]`, ascending by asset index
(0 is RAND, every other index the token registry's), amounts as decimal strings in the asset's
own units. A row at zero does not exist, so an empty vault — and a program nobody deployed — is
`[]`. `{"enabled": false}` without the section. Value enters a vault through an `invoke`'s bundle
(`burn_r`, and `burn_a` of `burn_asset` when the transition's `inflow` is `deposit`) and leaves
it as the notes the transition's `pays` name.

### `rand_getLimits`
Params: `[]`. Result: what a wallet needs from the chain's genesis to build a transaction — the
call limits (`max_program_words` through `max_program_public_words`), the envelope size, the v0.6
switch (`hardening_v6`) and the split-authorisation auth guest (`hc_auth`) — plus this node's own
gas policy:

```json
{ "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
  "max_call_envelope_bytes": 18432, "max_program_public_words": 0, "envelope_bytes": null,
  "hardening_v6": false, "hc_auth": null, "gas_price": "100", "byte_price": "800",
  "gas_metering": "header", "bundle_gas_limit": null, "adjust_bps": null,
  "max_gas_price": null, "max_byte_price": null, "byte_load": null,
  "admission_by_vote": false, "testnet": false, "slashing": null, "binding_domain": 0,
  "proof_window_blocks": null, "program_state": null, "fee_rules": null }
```

Those are the defaults, what a genesis without the fields gets (chain 12). A wallet derives its caps
from these instead of hard-coding them: the most words a program may have, the largest proof, the
largest transaction (a block's worth), the largest call-input envelope, and the most public words a
deploy may carry.

`envelope_bytes` is `null` on every genesis without the field (every existing chain), meaning no
uniform size is enforced and a wallet seals the legacy 1 348-byte note envelope with no memo. Set
to `1860` (spec 2026-09-26 §2.4), it means every note-creating envelope on this chain must be
exactly that long — a wallet seals the memo-carrying format instead, and a memo becomes readable
by the payee, the sender's own history, and anyone handed that output's per-transaction key.
There is no other value yet: `validate` accepts only `1860` once the field is present.

**A wallet does not take `envelope_bytes` on the node's word alone** (issue #64). Nothing in this
reply is authenticated, and a chain without the field still admits any note envelope up to 2 048
bytes — so a node answering `1860` there could make a wallet seal 1 860-byte envelopes among
everyone else's 1 348-byte ones, tagging every transaction it sends. The node keeps only the
genesis hash, not the file, so the claim cannot be checked against the genesis; instead the `rand`
wallet (and `rand-node`'s operator commands) seal the legacy form on every chain id pinned in
`randprotocol_client::LEGACY_ENVELOPE_CHAIN_IDS` (14–17 today) whatever this field says. The chain
id is the transaction's own, and a transaction carrying another is refused `WrongChain`, so a node
cannot move it. Every chain cut without `envelope_bytes` must be added to that list (a test over
`deploy/genesis-chain*.json` fails until it is). Other clients should do the same.

`hardening_v6` is `true` when the genesis sets the v0.6 switch (`docs/deploy.md`, "The next cut:
`hardening_v6`"). A wallet then proves a call over the program's public input (empty for most)
followed by the transaction's call binding (`Transaction::call_binding`, INT-4; issue #55 for a
program with a public input) instead of the public input alone —
the fee bundle's notes chosen first, the call proved second, the bundle last; a chain with the flag
refuses the old proof, a chain without it the new one. A node that predates the field answers
without it, which a wallet reads as `false`.

`hc_auth` is the auth guest the genesis pins (split authorisation, `docs/prover.md` §8), hex, or
`null`. Set, the chain's `hc_bundle` is bundle guest v3 and every bundle carries `auth_commit` and
an auth proof: a wallet gives the bundle guest `nk` and a fresh salt and proves the auth guest over
the spend key and the same binding itself. A node that predates the field answers without it — a
chain it runs has none.

`binding_domain` (audit v6, BIND-1) is the genesis `binding_domain`: `0` — chains 14 to 19, and
every genesis without the field — where a transaction's binding and every signed action message
bind the chain id alone, `1` where they carry the genesis hash under fresh tags
(`docs/deploy.md`, "The next cut: `binding_domain`"). **Informational, like every field here**: a
wallet decides which form to prove by the transaction's own chain id
(`randprotocol_client::CHAIN_ID_BINDING_CHAIN_IDS` — 14 to 19 get the chain-id form whatever a
node says; every other id gets the genesis-bound form over the genesis hash the wallet's store is
bound to), and reads this only to refuse early a chain whose ledger would refuse that form. A
node that predates the field answers without it, which a wallet reads as `0`.

`proof_window_blocks` (issue #118) is the genesis `proof_window_blocks`, 256 to 4 096, or `null`
on every genesis without the field (chains 14 to 19): how old, in blocks, a bundle's anchor may
be (one of the last N block-end roots) and how far behind the height its `time` may be — one
window for both, 256 for both when `null`. A chain's refusals name it: `anchor is not one of the
last N roots`, `time T is outside [H − N, H]`. A wallet with a slow or delegated prover reads it
for how long a proof may take; the `rand` wallet also uses it to decide when a `--no-wait` spend
that never appeared can no longer commit (clamped to 256..4 096, since this reply is
unauthenticated — it moves only the wallet's own bookkeeping, never what the chain admits). A
node that predates the field answers without it, which a wallet reads as `null`.

`fee_rules` is the genesis `fees` section (`docs/fees.md` §1.3), `{ "burn_base": bool,
"subsidy_net_of_fees": bool }`, or `null` on a chain without one — and on one whose section sets
no flag `true`, which hashes and runs as no section at all. Informational: under `burn_base` a
bundle's `BUNDLE_BASE` is destroyed rather than paid to the proposer, but what a sender pays is
unchanged — every floor is the same number — so a wallet changes nothing. A node that predates
the field answers without it, which a wallet reads as `null`.

`gas_price`, `byte_price` and `gas_metering` are this **node's** own gas policy (spec
`2026-09-28-gas-model-design.md` §4.1, Phase 0) *or* the chain's own `gas` section (§4.2, §7.1,
Phase 1) when its genesis carries one — a chain's section always wins, and a node's
`--gas-price`/`--byte-price` flags are silently ignored on such a chain (one `warn!` at startup).
Node policy is not a chain limit (two nodes on one chain may answer differently); a chain's own
section is consensus state and every node on the chain answers the same.

Without a `gas` section, `gas_price`/`byte_price` are the node's `--gas-price`/`--byte-price` in
units of 10⁻⁹ RAND (defaults 100, 800), decimal strings like every other amount on this API
(`null` with no policy); `gas_metering` is `"header"` while the policy prices a call's `gas_max`
off its proof's declared header, `null` with no policy (`--gas-price 0 --byte-price 0`). A node
that predates these fields answers without them, which a wallet reads as no policy.

With a `gas` section, `gas_metering` is `"circuit"` (the in-circuit meter, §4.2) and `gas_price`/
`byte_price` are the chain's current prices — under `gas.dynamic` (§7.1) these are the **tip's**
live prices, which move per block by fullness, not the genesis snapshot this node took at
startup; without `dynamic` they are the section's own fixed prices, which never move.
`bundle_gas_limit` is the bundle guest's flat declared gas (genesis `gas.bundle_gas_limit`;
`20479` on chain 18, the tier-14 hash-free ceiling `gas_max(14, 0, 0)`), `null` without a section. `adjust_bps` is the dynamic controller's per-block step size in basis
points (genesis `gas.dynamic.adjust_bps`), `null` on a chain without `dynamic` — including one
with a `gas` section whose prices never move. `max_gas_price`/`max_byte_price` (decimal strings)
are the ceilings the controller never lifts a price over and `byte_load` is `"paying"` when only
a call's proof and input envelope move `byte_price` (audit v6, POOL-2; `docs/fees.md` §1.2) —
all three `null` where the genesis sets none, chain 18 included. `admission_by_vote` (audit v6, STAKE-2) is whether
the genesis sets `staking.admission_by_vote`: there a bond that registers a new validator key is
refused (`NotAdmitted`) until the validator set has voted the key in — `rand_getAdmitted` lists
the keys that may register (`docs/staking.md` §2). `testnet` is the genesis `testnet` marker
(audit v6, STAKE-2): `true` only where the file says so — what lets a faucet sit beside a bridge
section — so a wallet or an explorer can label the chain; `false` on every chain through 18.

`program_state` (RPL-2, `docs/superpowers/specs/2026-09-30-rpl2-program-state-design.md`) is the
genesis `program_state` section and the `invoke` limits that come with it, or `null` on a chain
without the section — where every `invoke` is refused and no program token can be registered:

```json
"program_state": { "cell_fee": "10000000", "max_reads": 8, "max_writes": 8, "max_payouts": 4 }
```

`cell_fee` is the RAND units (a decimal string) an invoke's fee floor gains per cell it
*creates* — a write of a non-zero value to a cell that reads as zeros; rewriting, deleting or
writing zeros over nothing costs no cell fee. `max_reads`, `max_writes` and `max_payouts` (pays
and mints together) are the transition's hard caps; the binding bound in practice is the segment
rule — the transition's context words (11 + 16 per read or write + 3 per payout) must fit beside
the program's public input and the 8 binding words in a 128-row public table, so 119 context
words for a program without a public input. A node that predates the field answers without it,
which a wallet reads as `null`.

### `rand_getProgramCode`
Params: `[program_id]`. Result: `null` or `{ "base_pc": 0, "words": [u32, ...] }` (what the wallet
proves against).

### `rand_getReceipt`
Params: `[tx_hash]`. Result: `null` until the call is committed, then

```json
{ "tx": "…", "program": "…", "tier": 14, "outputs": [1, 0, 25, 0, 0, 0, 0, 0], "height": 17,
  "index": 0, "h_in": "9c0e…7f", "h_pub": null }
```

`h_in` is the proof's public commitment to the call's *private* inputs (`Word8` hex, zkVM M4.1).
It discloses nothing on its own — it is a salted digest — and it is what a call-input envelope is
sealed against, so a holder needs it to open one (`rand_getCallEnvelope`) and to check an
opened transcript with `hash::input_digest(salt, inputs)`.

`h_pub` is the digest of the program's deploy-time public input the call's proof was checked
against (`Word8` hex, the program's `public_digest`). `null` means the program was deployed without
a public input, and the proof was checked against the digest of the *empty* public input,
`public_digest([])`. The node does not repeat that constant digest in every receipt.

There is no `effect` field: effect kind 1 (the program-driven transfer to an account) was deleted
with the accounts. A call's outputs are recorded and nothing else moves; value moves only through
the bundle that paid for the call.

### `rand_getCallEnvelope`
Params: `[tx_hash]`. Result: `null`, or the call's input envelope (spec §6.1) in hex:

```json
{ "tx": "…", "h_in": "9c0e…7f", "kem_ct": "…", "to_sender": "…", "to_auditor": "…", "body": "…" }
```

`h_in` is the receipt's, repeated here so one request is enough to open the envelope. `body` is
the call's private input vector and its `H_IN` salt, sealed under a per-call key with that
`h_in` as associated data; `to_sender` wraps that key to the caller's outgoing
viewing key and `kem_ct`/`to_auditor` to the auditor the caller named, both empty strings when
there is none. The node holds no key that opens any of it and never looks inside — a viewing key
imported for note scanning (`rand_importViewingKey`) opens *note* envelopes only; call
envelopes are not part of its scan. It is served
so that a wallet with the caller's viewing key, a per-call key, or the auditor's key can open it
(`randprotocol_zkvm::call_envelope`) and check the transcript against `H_IN`. `null` means the call
published no envelope (`--no-envelope`), the transaction is not a call, or this node has no
receipt for that hash.

### `rand_estimateFee`
Params: `[spec]`, one of `{"kind":"bundle"}`, `{"kind":"deploy","words":n,"public_words":m}` or
`{"kind":"call","tier":t,"bytes":b,"keccak_log_height":k,"sha256_log_height":s}` (`t` one of 10,
12, 14, 16, 18, 20). Result: the minimum fee in units, as a string. `{"kind":"bundle"}` is the floor
for a plain transfer: `1000000`. A deploy of more words than the chain's program cap (4096, or the
genesis file's `max_program_words`) is an invalid-params error (`-32602`) naming the cap — the same
program admission would refuse, so a wallet can ask before it proves.

`public_words` (optional, default 0) is the deploy's public input length. Public words are paid for
per word like code, so the fee is the deploy fee of `n + m` words. More than the chain's
`max_program_public_words` (0 by default) is `-32602`, naming the cap, in the same shape.
Anything but a non-negative integer (or `null`) is `-32602` as well.

`bytes` (optional, default 0) is the call's proof length plus its input envelope's length. A call
at or under the free allowance (2 097 152 + 18 432 bytes) costs what it did before this field
existed; each KiB over it, a partial KiB counting as whole, adds 1000 units. Without `bytes` the
answer is the old one. Anything but a non-negative integer is `-32602`.

`keccak_log_height` and `sha256_log_height` (both optional, default 0, spec 2026-09-28 §8) are the
proof header's declared hash-table heights — `0` means the table is absent. Either out of `0..=40`
is `-32602`. On a node that announces a gas policy (`rand_getLimits.gas_metering == "header"`) the
answer is `GasPolicy::call_floor(tier, keccak_log_height, sha256_log_height, bytes)`: the greater of
the ledger's own tier floor and `BUNDLE_BASE + gas_price·gas_max + byte_price·⌈bytes/1024⌉`
(`docs/fees.md` §1.1). On a node with no policy the heights are accepted but change nothing — the
answer is the ledger floor alone, as before.

On a chain with its own `gas` section (`rand_getLimits.gas_metering == "circuit"`, spec §3.3,
§4.2), the call spec takes a fourth field, `gas` — the transaction's own declared limit, not the
proof header's `gas_max` ceiling — and it is **required**: without it the call arm answers
`-32602`, "under the gas section a call estimate needs its gas". With it, the answer is
`circuit_call_floor(gas_price, byte_price, gas, bytes)` = `BUNDLE_BASE + gas_price·gas +
byte_price·⌈bytes/1024⌉`, at `rand_getLimits`'s current prices — the tip's, under `gas.dynamic`
(§7.1). `keccak_log_height`/`sha256_log_height` are accepted but unused under a section: the
declared limit already bounds the header, hash tables included. On a chain with no `gas` section
this field does not exist and the estimate behaves exactly as above.

`{"kind":"invoke", …, "created_cells": c}` (RPL-2) takes every field a call spec takes — an
invoke carries a call proof and is priced as a call — plus `created_cells` (optional, default 0;
at most `max_writes`, else `-32602`): the cells the transition would create, each adding the
chain's `cell_fee` (`rand_getLimits.program_state`). The caller counts them: a write of a
non-zero value to a cell `rand_getProgramCell` reads as zeros. On a chain without the section
the kind is `-32602`.

### `rand_getTransaction`
Params: `[hash]`. Result: `null` until committed, then:

```json
{
  "height": 192, "index": 0, "block_hash": "63f6…08",
  "tx": {
    "hash": "4f2c…e7", "chain_id": 7,
    "bundle": {
      "anchor": "6b1d…c4",
      "nullifiers": ["8c04…d1", "5e77…20", "03aa…6f", "e19b…42"],
      "commitments": ["2a9f…07", "b310…88", "77c1…0e", "5d20…b3"],
      "fee": "1000000", "burn_a": "0", "burn_r": "0", "burn_asset": 0, "time": 5,
      "proof_len": 1431562, "envelope_len": [1380, 1380, 1380, 1380],
      "auth_commit": "0000…00", "auth_proof_bytes": 0
    },
    "action": { "kind": "none" }
  }
}
```

`bundle` is `null` on a mint (a mint carries no bundle). The proof and the envelopes are reported
by length only; anyone who wants the bytes can fetch the block.

`bundle` is the hidden-asset bundle (chain 14): four input slots and four output slots, so always
four `nullifiers`, four `commitments` and four `envelope_len`, dummies included. It has **no
`asset` field**: slots 0–1 carry a private asset and slots 2–3 RAND, and nothing public says which
asset slots 0–1 moved. A transfer of RAND and a transfer of any RPL token are both `"kind":
"none"` with `burn_a`, `burn_r` and `burn_asset` all 0 — the same shape, field for field. The
three burn fields are the bundle's only public statement about value leaving the pool:

- `burn_a` / `burn_asset` — an amount of the private asset burned, and which asset. Non-zero only
  on a `token_burn` or a `bridge_burn`, where they equal the action's `amount` and `asset`.
- `burn_r` — RAND burned. Non-zero only on a `bond` (equal to its `amount`) and a
  `register_aggregator` (the genesis bond).
- `fee` — the RAND fee, always from slots 2–3.

Other actions:

- `{ "kind": "mint", "cm": "…", "amount": "100000000000", "minter": "<validator base58>" }`
- `{ "kind": "deploy", "program": "<program id>", "words": 412, "public_words_len": 0 }`
- `{ "kind": "call", "program": "<program id>", "proof_len": 268123, "input_envelope_len": 1280 }`

`public_words_len` is the length of the deploy-time public input; the words are
`rand_getProgramPublic`'s once the deploy commits.

`input_envelope_len` is the size of the call's encrypted input transcript, or `null` when the call
carries none. Like every other envelope it is reported by length alone: the transcript opens for
the caller's viewing key and the auditor, not for whoever is reading the explorer.

The staking (phase S2) and bridge (phase S3) actions:

- `{ "kind": "bond", "validator": "<base58>", "amount": "500", "registered": false }` — `registered`
  is whether this bond carried a first-time registration.
- `{ "kind": "unbond", "validator": "<base58>", "amount": "7", "nonce": 2 }` — rendered with
  `"bundle": null`, as a withdraw is: both are signed by the validator's key, and the register's
  nonce, not a bundle, is what keeps them from being replayed.
- `{ "kind": "withdraw", "validator": "<base58>", "amount": "9", "nonce": 3, "time": 1994 }` — the
  deposit note's blinding and envelope are not rendered. `time` is the note's time word, which the
  withdrawing node chose; the note itself is worth `amount` less the bundle base.
- `{ "kind": "bridge_attest", "attestation_len": 520, "recipient": "<shielded address>",
  "asset": 1, "asset_index": 1, "amount": "1000", "time": 41, "r": "<64 hex>",
  "commitment": "<64 hex>", "pq_signers": [0, 2] }` — the amount and the asset are
  inside the attestation, so they are decoded out of it; `asset_index` is what the registry gave
  that asset, and is the `asset` word of the deposit note. Both are `null` for a guardian-set
  rotation (which deposits nothing) and on a chain whose registry does not name the asset.
  `asset` is the index the *action* names, and on a committed attest it always equals
  `asset_index` — admission refuses a transaction where they differ — but it is never `null`, so
  the two together say whether this node's registry can resolve the deposit at all. `time` is the
  deposit note's own `time` word, which the action publishes and admission holds to the window a
  bundle's `time` gets — the note is derived from it, not from the height the transaction landed
  at. `r` is the deposit note's blinding, a field of the action and public like the rest of it —
  derived since chain 14 from the attestation digest the guardians signed
  (`blake3("rand-deposit-r-1" || mu)`, `docs/bridge.md` §5), so a reader can recompute it from the
  same transaction's attestation bytes — and
  `commitment` is the leaf the chain computed from those five fields and appended — `null` for a
  rotation. Together they are the whole deposit note, which is what lets its recipient rebuild it
  without opening the submitter's envelope (`docs/bridge.md` §8); a transfer's or a withdrawal's
  blinding is *not* rendered, because those notes are not public. `pq_signers` (bridge hardening
  B3) is the co-signing guardians' indices into `rand_getBridgeState`'s `pq_guardians` — the
  signatures themselves are 2 420 bytes each and are not rendered, only which of them signed.
- `{ "kind": "bridge_burn", "asset": 2, "amount": "400", "relayer_fee": "100", "to_chain": 5,
  "token": "cdcd…", "to": "abab…" }` — `token` is the backing being redeemed and `to` the 32-byte
  destination address, hex. One bundle carries the whole burn: its `burn_asset` and `burn_a` are
  the action's `asset` and `amount`, and its `fee` pays the bridge fee.
- `{ "kind": "rotate_pq_guardians", "new_pq_guardians": ["<1312 bytes hex>", …], "nonce": 0,
  "pq_signers": [0, 1, 2, 3, 4] }` and `{ "kind": "rotate_pause_key", "new_pause_key": "<1312 bytes
  hex>", "nonce": 1, "pq_signers": [1, 2, 3, 4, 5] }` (v0.5.4, bridge rules v2 — `docs/bridge.md`
  §21): the two key rotations, rendered with `"bundle": null` like a pause. `nonce` is the
  bridge's `rotation_nonce` the rotation spent; `pq_signers` are indices into the PQ set *before*
  the rotation. Refused `RulesV2Disabled` on a chain without `bridge.rules_v2`.

The RPL token actions. **Every amount here is a decimal string** — a token's own units, not
RAND's — because a 9-decimal token's supply already passes 2^53 at a few tens of millions of
units:

- `{ "kind": "token_burn", "asset": 3, "amount": "400" }` — a holder burn. Its asset and amount are
  public by design (they audit the token's `total_supply`), and the bundle's `burn_asset`/`burn_a`
  repeat them (`burn_a` is a decimal string too, like every amount in this reply).
- `{ "kind": "token_mint", "asset": 3, "amount": "700", "recipient": "<shielded address>",
  "time": 41, "r": "<64 hex>", "nonce": 0 }`, `{ "kind": "register_token", "name": …, "symbol": …,
  "decimals": 6, "authority": "none" | "key" | "bridge" | "program", "index": 2,
  "initial_amount": "5000", "initial": { "amount": "5000", "recipient": "<shielded address>",
  "time": 40, "r": "<64 hex>" } | null }` and `{ "kind": "set_authority", "asset": 3, "nonce": 1,
  "new_authority": "<base58>" | null }` — a token's registration and mints are public, as a bridge
  deposit is. Every word of a minted note is here (its `from` is the chain's fixed `MINT_FROM`), so
  a recipient rebuilds the note from these fields with nothing decrypted, whatever envelope the
  minter published — the wallet's scan does exactly that. **The kind strings `bridge_attest`,
  `token_mint` and `register_token` are what that scan keys on and are pinned by a test.**

There is no `token_transfer`: a token transfer is `none`, indistinguishable from a RAND payment.

The RPL-2 `invoke` (program state, `docs/superpowers/specs/2026-09-30-rpl2-program-state-design.md`):

```json
{ "kind": "invoke", "program": "<program id>", "proof_len": 268123, "input_envelope_len": null,
  "transition": {
    "reads":  [{ "key": "<64 hex>", "value": "<64 hex>" }],
    "writes": [{ "key": "<64 hex>", "value": "<64 hex>" }],
    "inflow": "none" | "deposit" | "burn",
    "pays":  [{ "asset": 0, "amount": "300", "recipient": "<shielded address>", "time": 41,
                "r": "<64 hex>", "cm": "<64 hex>" }],
    "mints": [{ "asset": 2, "amount": "40", "recipient": "<shielded address>", "time": 41,
                "r": "<64 hex>", "cm": "<64 hex>" }] } }
```

A call's fields, then the state transition the proof vouched for and the ledger applied — all of
it public by design (spec §2, §9). `reads` are the cells the program read with the values it
read (the proof was made against them; the ledger refused the transaction unless they still
held), `writes` the cells it wrote; a cell key or value is a `Word8`, 64 hex of its eight words
little-endian, and a written value of 64 zeros deletes the cell. What came *in* is the bundle's
and is rendered with it: `burn_r` is RAND deposited into the program's vault, `burn_a` of
`burn_asset` is the token the transition's `inflow` names — `deposit` into the vault, `burn`
destroyed (the program's own token only), `none` when `burn_a` is 0. What went *out* is one
chain-computed note per payout, `pays` (out of the vault) then `mints` (new units of a token
whose mint authority is this program), in that order in the tree: every word of each note is
here under the field names a `token_mint` uses — `time` is the **bundle's** `time`, `cm` the leaf
the chain appended, and the `from` word is the chain's fixed `PROGRAM_FROM` — so a recipient
rebuilds it from these fields with nothing decrypted, as it rebuilds a mint. **The kind string
`invoke` is what the wallet's scan keys on and is pinned by a test.** The program's eight output
words are on the receipt (`rand_getReceipt`), as a call's are.

No reply from this method carries the sender, recipient, nonce or amount of a *transfer*: no such
field exists in a stored transfer. The staking and bridge actions above are the deliberate
exception — a validator address, an amount and a replay nonce are public in them by design, the
way a mint's amount is, because the validator register and the bridge's accounting are public
(spec §8). A shielded note's later spend stays private in every case.

On a node started with `--prune-history`, a transaction whose block was pruned normally
answers `null` (its location row went with the block); `-32010` `pruned: height h is below this
node's retention floor f` with `data: {"floor": f}` is answered only when a location row survived
and names a height below the floor.

### `rand_checkTransaction`
Params: `[hash, key]`, where `key` is a per-transaction `TxKey` as 64 hex characters. Result:
`null` for a hash this node has no committed transaction for, else what the key discloses about
it:

```json
{ "tx": "4f2c…e7", "height": 192,
  "disclosed": [
    { "output": "bundle:0", "cm": "2a9f…07", "index": 40,
      "note": { "pk": "…", "from": "…", "amount": "1500000000", "asset": 0, "time": 5, "memo": "invoice 7" } }
  ] }
```

Monero's `check_tx_proof` shape (`docs/rpc-comparison.md` §4): a sender who sealed an output with
a fresh `TxKey` can hand `(hash, key)` to anyone — a recipient proving they were paid, an auditor
checking a claim — and this call is the whole verification. Each entry of `disclosed` is one
envelope the key opened: `output` names the envelope set (`bundle:0` … `bundle:3` for the
transaction's bundle, one per output slot — slots 0–1 the private-asset outputs, slots 2–3 the
RAND outputs, dummies included — `deposit` for a `BridgeAttest`'s deposit envelope, `token_mint`
for a `TokenMint`'s note, `initial_mint` for a `RegisterToken`'s initial mint, `mint:0` for a
faucet mint's one envelope, `payout:0` … `payout:3` for the notes an RPL-2 `invoke` paid out —
one per payout, numbered by its place in the transition, `pays` then `mints`, each opened against
the commitment the chain computed for it), `cm` the on-chain commitment the note commits to, and
`index` its leaf. The disclosed `note` carries its `asset`: this call — with the key the sender sealed under —
is the one place the RPC reveals which asset a transfer moved. The binding is the proof: the AEAD
authenticates the note *and* checks it against `cm`, so a key lifted onto another transaction —
or a note that is not the commitment's preimage — yields an empty list, never a forged row. A
withdraw's and a genesis alloc's envelopes are not tried: they are sealed inside the node under
keys dropped at once, so no `TxKey` for them can exist. A mint's is sealed the same way, but its
recipient recovers the key through the envelope's KEM half (`rand tx-key`), so a mint is tried. A
token mint's and an initial mint's envelopes are sealed by the minter, and open against the
commitment the chain computed for that note.

The disclosed `note`'s `memo` is the sender's memo (spec 2026-09-26 §2.3) if this envelope
carried one — `null` for no memo or a memo field that opened malformed. A memo can be present on any chain: where the genesis sets no `envelope_bytes` (chains 14 and 15) the ledger still accepts any note envelope up to 2 048 bytes, so a memo-carrying 1 860-byte envelope from another sender is valid and opens with its memo — wallets only *seal* one where the chain sets `envelope_bytes`. A memo is anyone's text: show it as untrusted (see `docs/cli.md`, "How a memo is shown"). It is readable here for exactly the same reason the note itself is:
the key that opens one opens the other, from the same AEAD body.

The call is **stateless**: the key is used for this one request and dropped — it is not imported,
stored, or learnable from anything the node keeps (unlike `rand_importViewingKey`, which
retains). A key that opens nothing gets `{ "disclosed": [] }`, indistinguishable from a wrong key
by design. Amounts are strings, as everywhere chain state is served.

Errors: `-32602` for a malformed hash or key (both are parsed before any storage read).

On a node started with `--prune-history`, a transaction whose block was pruned normally
answers `null` (its location row went with the block); `-32010` `pruned: height h is below this
node's retention floor f` with `data: {"floor": f}` is answered only when a location row survived
and names a height below the floor.

### `rand_getBlockByHeight` / `rand_getBlockByHash`
Params: `[height]` (integer) or `[hash]`. Result: `null` if unknown, else:
```json
{
  "hash": "647b…", "height": 50, "view": 92, "parent": "2d41…",
  "proposer": "3v3VBJ…", "timestamp_ms": 1788000123456,
  "tx_root": "0000…", "state_root": "a1b2…", "justify_view": 91,
  "tx_count": 0, "transactions": [ ...same shape as rand_getTransaction.tx... ]
}
```
Only committed blocks are served. `justify_view` is the view of the quorum certificate for the
parent that this block carries.

On a node started with `--prune-history`, a height below `rand_status.prune_floor` (genesis
excepted) answers error `-32010` `pruned: height h is below this node's retention floor f`
with `data: {"floor": f}` — ask the archive for it. A pruned block asked for **by hash** still
answers `null`, as an unknown hash does: only an archive can say whether it was pruned or never
existed.

### `rand_getHead`
Params: `[]`. Result: `{ "height": 1998, "hash": "…", "view": 2251 }` (`view` is the node's current
consensus view, which runs ahead of height when views time out).

### `rand_status` (alias `rand_syncStatus`)
Params: `[]`. Result:
```json
{
  "height": 1998, "head_hash": "…", "view": 2251, "high_qc_view": 2250,
  "syncing": false, "sync_target": 1998,
  "sync_inflight_age_ms": null, "sync_failures": 0, "sync_late_batches": 0,
  "peer_count": 5, "connected_peers": 5, "reserved_peers": 5, "ws_clients": 3, "refused_cache": 0,
  "verify_queue": 0, "mempool_size": 0,
  "is_validator": true, "active_validator": true, "faucet": true, "confidential": true,
  "testnet": false, "fri_profile": "production", "programs": 2, "viewing_keys": 0,
  "notes": 41, "nullifiers": 12, "tree_root": "6b1d…c4", "hc_bundle": "f07a…19", "hc_auth": null, "binding_domain": 0,
  "address": "2nRdFC…", "peer_id": "12D3KooW...",
  "gas_prices": null
}
```
`syncing` is true while a batch request to a peer is in flight; `sync_target` is the highest height
any peer has advertised. `viewing_keys` is how many viewing keys this node is holding for
node-side scanning (see `rand_importViewingKey`) — in memory only, so it reads 0 after every
restart, and anything above it is worth an operator's attention precisely because it changes what
compromising the process would disclose.

The four fields beside them are for reading a node that is behind and not catching up, which
otherwise looks identical to a node that is behind and working:

- `sync_inflight_age_ms` — how long the outstanding batch request has been outstanding, or `null`
  when none is. An age that keeps climbing past a few seconds is the diagnosis: the request is not
  coming back. The node gives up at the wire's own timeout (30 s) and tries another peer.
- `sync_failures` — batch requests that failed since start: a wire or codec error, a give-up past
  that timeout, or a batch that arrived and could not be applied. Rising while `height` does not is
  a node that cannot catch up.
- `sync_late_batches` — batches applied *after* their request had been given up on. Progress, not
  failure, but a rising count means the give-up is firing on requests that were still alive, so the
  peers being asked are slower than the timeout.
- `connected_peers` — peers with an open connection, which are the only ones sync can ask for
  blocks. `peer_count` counts every entry in this node's peer map. Since 2026-09-24 a gossiped
  `Status` from an author this node holds no connection to no longer creates one (an entry
  nothing ever removed, and a peer id is free to mint), so the two numbers now differ only by
  peers that disconnected since the map was last pruned — `peer_count` far above
  `connected_peers` was hearsay before that date and is a bug after it.
- `reserved_peers` — peers admitted past the inbound connection cap (audit v6, NET-1): the
  bootstraps, the `--reserved-peer` list and every validator identity learned from a signed
  peer binding, each counted once. On a fleet node it should reach the validator count within a
  minute of start.
- `ws_clients` — WebSocket clients connected right now, against the 64 this node will carry (see
  [Subscriptions](#subscriptions-websocket)). At 64 the next upgrade is refused with a `503`, which
  otherwise shows up only as clients that cannot connect for no visible reason.
- `refused_cache` — transactions this node has already refused for a reason that is a function of
  the bytes alone (a bad proof or mint signature, an oversized part) and now refuses again by hash,
  for free. Bounded at 8192, oldest evicted first; a count pinned at the cap is a flood of distinct
  bad transactions, and the per-peer gossip rate limit is the bound that actually holds.
- `verify_queue` — transactions waiting for one of the four proof-verification workers that run
  off the consensus loop. 64 deep at most; a queue that stays full means verifications are arriving
  faster than ~20 ms apiece drains them, and what does not fit is shed — an honest peer re-gossips
  on its next heartbeat — rather than queued unboundedly.

`is_validator` says this node holds a validator key; `active_validator`
says that key is in the set running the current epoch (spec §8) — a validator that has bonded in
but whose epoch has not arrived is the first without the second. `notes` is every note the chain has ever created, `nullifiers` every note
it has ever spent, and `hc_bundle` the bundle guest this chain's proofs are against — a node whose
build disagrees with the genesis value refuses to start at all. `hc_auth` is the genesis auth guest
(split authorisation) or `null`, checked against the build the same way. `binding_domain` is the
genesis `binding_domain` (`0` or `1`, BIND-1), as `rand_getLimits` serves it.

`gas_prices` (spec 2026-09-28 §7.1, §8) is `{ "gas_price": "…", "byte_price": "…" }`, the tip
ledger's current gas prices, `null` on a chain without a `gas` section. Refreshed every commit,
the same as every other field here — it is what `rand_getLimits` reads to serve a `dynamic`
chain's current prices rather than the genesis snapshot it took at startup.

### `rand_getPeers`
Params: `[]`. Result: array of `{ "peer_id": "12D3KooW...", "addrs": ["/ip4/…/tcp/30303"], "connected_secs": 1241 }`.

### `rand_getBridgeState`
Params: `[]`. Result on a chain without a `bridge` section: `{ "enabled": false }`. Otherwise:
```json
{
  "enabled": true,
  "emitter": "01…",                      // this chain's outbound emitter address, 32 bytes hex
  "emitters": { "2": "02…" },            // source chain id -> the emitter address trusted there
  "guardian_set_index": 0,
  "guardians": ["aabb…"],                // the current set's 20-byte addresses, hex
  "pq_guardians": ["…"],                 // the genesis PQ set: Dilithium2 public keys (1 312 bytes), hex,
                                         // index-aligned with guardian set 0; every BridgeAttest carries a
                                         // quorum of co-signatures by it, and a rotation never moves it
  "mint_paused": false,                  // B1: while true every transfer attest is refused (burns and
                                         // rotations stay open)
  "pause_nonce": 0,                      // B1: what the next M_pause / M_unpause must carry
  "list_nonce": 0,                       // B4: what the next M_list / M_register must carry
  "pause_key": "…",                      // B1: the one Dilithium2 key that may pause minting, hex
  "registration_fee": "1000000000",      // B4: what a RegisterBridgedToken owes past the bundle base, RAND units
  "burn_sequence": 1,                    // outbound messages emitted so far
  "rotation_nonce": 0,                   // v0.5.4, bridge rules v2: what the next M_rotate_pq / M_rotate_pause
                                         // must carry (always 0 on a chain without rules_v2 — chain 14)
  "rules_v2": null,                      // v0.5.4: { "global_mint_cap_per_window": "<decimal string>",
                                         // "cap_window_secs": 86400 } on a chain whose genesis has the group
  "min_inbound_sequence": null,          // C15-1: { "2": 7, "4": 3 } — per source chain the lowest
                                         // sequence a transfer may carry, from the genesis replay floor;
                                         // null on a chain without one (chain 15 and earlier)
  "assets": [ …the rows of `rand_getAssets`… ],
  "fees": null                           // v0.6.8: { "mint_bps": 10, "burn_bps": 10, "recipient": "rand1…" }
                                         // — the genesis `bridge.fees`; null on a chain without it (14–19)
}
```
`fees` (v0.6.8, `docs/bridge.md` §25): the share of every deposit (`mint_bps`) and every burn
(`burn_bps`), in basis points, that the chain mints as a zUSD note to `recipient`, rounded down to
a whole release unit of the backing. A wallet reads it to value its own deposit (the gross less
the fee) and, when it is `recipient`, to rebuild its fee notes; a burner reads it to see what will
be released.
No balances: bridged value is notes, not accounts. **No `next_index` any more** (RPL, B4): a
bridged token is listed — under an index the registration already fixed — before it can ever be
deposited, so there is no index left to predict; a wallet reads a listed token's index off
`assets` (`rand_getAssets`) or `rand_getTokens`.

### `rand_getAssets`
Params: `[]`. Result: the bridge's asset registry, ascending by index (which is registration
order), or `[]` on a chain without a bridge:
```json
[{ "index": 1, "chain": 2, "token": "aaaa…", "asset_id": "…", "decimals": 6, "locked": "600",
   "mint_cap_per_day": "10000000000000", "minted_today": "1000", "mint_day": 20350 }]
```
`index` is the `asset` word a note of that asset carries — index 0 is RAND and is never in the
registry. One row per **backing** (source coin). `locked`, `mint_cap_per_day` and `minted_today`
are decimal strings in the token's own eight-decimal units, never RAND's; `mint_day` is a plain
integer, a UTC day number, not an amount. `mint_cap_per_day` (bridge hardening B1) is the
genesis `tokens.mint_cap_per_day`, the most one backing may mint per UTC day of the block time;
Under bridge rules v2 each row also carries `minted_in_window`, `mint_window_secs` and
`mint_headroom` (see the 2026-09-30 changelog entry), and `minted_today` is the rolling-window
count; the rest of this paragraph describes a day-counter chain (chain 14).
`minted_today` is what this backing has minted on `mint_day`, the
UTC day (`timestamp_ms / 86 400 000`) of the **head block** — the figure the cap would count the
next deposit against, so a counter left from an earlier day reads `"0"` once the head crosses
midnight, never the stale figure. A deposit past the cap is refused `MintCapExceeded` and becomes admissible the
next day. `chain` and `token` are the wire identity guardians sign about; `asset_id` is
`blake3` of the two, and is what `rand_bridgeAssetId` computes.

### `rand_bridgeAssetId`
Params: `[token_chain, token_address]` where `token_chain` is an integer and `token_address` is
32 bytes of hex. Result: the asset id (64 hex characters). Pure arithmetic on its arguments, so
it answers on any chain, bridged or not.

### `rand_getBridgeBurn`
Params: `[sequence]` (integer). Result: `null` if this chain has emitted no such message, else
```json
{ "sequence": 0, "body_hex": "…", "digest": "…", "tx": "…", "height": 2,
  "amount": "500000", "release_amount": "499500", "fee": "500" }
```
`body_hex` is the outbound message as guardians must hash and sign it; `digest` is its hash.
`tx` is the burn transaction that emitted it — a burn is funded by notes, so the transaction
hash stands in for the sender identity the message has no room for.

v0.6.8, every burn on every chain: **`release_amount`** is the amount the signed body carries —
what the source contract releases (out of which it pays the body's relayer `fee`) and what left
the backing's `locked`; it is read off `body_hex` itself, so it cannot disagree with what the
guardians sign. **`fee`** is the bridge fee the chain kept as a treasury note (`docs/bridge.md`
§25) and **`amount`** is what the bundle burned, `release_amount + fee`. On a chain with
`bridge.fees` every burn carries its split; on a chain without it (14–19) `fee` is `"0"` and
`amount == release_amount`. All three are decimal strings in the token's eight-decimal units.

### `rand_getTokens`
Params: `[from_index, limit]`, both optional (`0` and `1000`; `limit` is clamped to 1000). Result:
the RPL token registry — every token, bridged and native — ascending by index from `from_index`,
read by range from that index (never a scan of the rows below it, v0.5.4):
```json
{ "enabled": true, "registration_fee": "1000000000", "next_index": 3, "max_tokens": null,
  "tokens": [
    { "index": 2, "id": "<64 hex>", "id_text": "rpl1…", "name": "Test Coin", "symbol": "TST",
      "decimals": 6,
      "authority": { "kind": "key", "key": "<Dilithium2 key, hex>", "address": "<base58>" },
      "mint_nonce": 1, "total_supply": "5700", "registered_at": 3 }
  ] }
```
On a chain without a `tokens` section: `{ "enabled": false, "tokens": [] }`. `index` is the
`asset` word a note of the token carries (0 is RAND and is never listed). `id` is the token's
asset id and `id_text` its checksummed text form — bech32m, HRP `rpl`, over the 32 id bytes, 62
characters. `authority` is `{ "kind": "none" }` (fixed supply, or renounced), `{ "kind": "key",
"key", "address" }`, `{ "kind": "bridge", "backings": [{ "chain": 2, "token": "<32 bytes hex>",
"decimals": 6, "locked": "600", "mint_cap_per_day": "10000000000000", "minted_today": "1000",
"mint_day": 20350 }] }` (each backing's **source** decimals, the amount its contract holds for
this chain, and bridge hardening B1's mint-cap figures — `rand_getAssets`'s fields, one row per
backing) or `{ "kind": "program", "program": "<hex>" }`. Supplies, `locked`, `mint_cap_per_day`,
`minted_today` and `registration_fee` are decimal strings (RAND units for `registration_fee`,
token units for the rest); `next_index`, `mint_day` and `max_tokens` are numbers. `max_tokens`
(v0.5.4, audit v4 TOK-1) is the genesis cap on how many tokens the registry may hold —
registration is refused `RegistryFull` at it — or `null` on a chain whose genesis has none
(chain 14). `burn_registration_fee` (v0.5.5, audit v5 TOK-2) is a boolean: whether a
registration's `registration_fee` is burned rather than paid to the block's proposer
(`docs/tokens.md` §15) — `false` on chain 14. `bound_note_value` (v0.5.6, deep scan) is a
boolean: whether a mint or deposit is held below 2^63 as a validity rule (`docs/tokens.md` §16;
the admission screen refuses such an amount on every chain regardless) — `false` on chain 14.
`incremental_root` (audit v6 TOK-1, issue #86) is a boolean: whether the registry's root is the
incremental commitment of `docs/tokens.md` §17 (`rand-token-registry-4`, the state root under
`rand-state-tokens-1`, one stored row per token) — `false` on every chain through 20; it changes
no row of this listing and no validity rule. A page shorter than `limit` is the last.

A wallet resolves a token id **through this listing** (`wallet::resolve_asset`), never through
`rand_getToken`: a transfer's asset is private on chain, and reading the whole registry costs the
same whichever token is meant.

### `rand_getToken`
Params: `[token]` — a registry index (a number or a decimal string), the 64-hex id (with or
without `0x`, any case) or the `rpl1…` text form (all lower or all upper case). Result: that
token's `rand_getTokens` row, or `null` when there is none (and on a chain without tokens). A
malformed id — a bad checksum, another HRP, a wrong length, mixed case, not hex — is `-32602`, so
a typo is never some other token.

**Privacy:** a per-token lookup tells the node which token the caller cares about. It is for
explorers and one-off reads; a wallet about to send uses `rand_getTokens`.

### `rand_getTokenSupply`
Params: `[token]`, the same forms as `rand_getToken`. Result: `null`, or
```json
{ "total_supply": "600",
  "backings": [{ "chain": 2, "token": "<32 bytes hex>", "decimals": 6, "locked": "600",
                 "mint_cap_per_day": "10000000000000", "minted_today": "1000", "mint_day": 20350 }] }
```
`total_supply`, `locked`, `mint_cap_per_day` and `minted_today` are decimal strings; `mint_day` is
a plain integer. `backings` is empty for a native token; for a bridged one the `locked` amounts
sum to `total_supply`, and each is what `rand-bridge-audit` reconciles against that coin's custody
on its source chain. The same privacy note as `rand_getToken`.

### `rand_getValidators`
Params: `[]`. Result: array of

```json
{ "address": "…", "stake": "1000000000000", "pending": [{ "release_epoch": 41, "amount": "5000000000" }],
  "rewards": "4000000", "payout": "rand1…", "nonce": 3, "active": true, "jailed_until": null }
```

one row per entry of the **register** (spec §8), in address order. Since phase S2 that is every
validator that has ever bonded, not the genesis set: `active` is the ones in the set running the
current epoch, and those are what the leader rotation runs over. Amounts are **decimal strings**,
because a JSON number is not an exact integer past 2^53 and a stake is 10^9 units per RAND.
`pending` is the unbonding queue, oldest first; `rewards` is the bundle fees credited to that
validator as proposer; `payout` is where a `Withdraw` pays; `nonce` is what its next signed
`Unbond` or `Withdraw` must carry. The register is the only place this chain stores amounts in the
clear — `docs/staking.md` is the guide to it.

### `rand_getAdmitted`
Params: `[]`. Result:

```json
{ "admission_by_vote": true, "max": 256, "admitted": ["rand-node address …", "…"] }
```

Audit v6, STAKE-2 (`docs/staking.md` §2, "Admission by vote"): the keys the validator set has
voted in with an `AdmitValidator` that have not registered yet, by address, in address order —
what a `Bond` that registers a new key must be among on a chain whose genesis sets
`staking.admission_by_vote`. `max` is how many the ledger holds at once (`MAX_ADMITTED`). On a
chain without the flag `admission_by_vote` is `false`, the list is always empty and a
registration needs no vote. Served from storage, as of the committed head.

### `rand_getEpoch`
Params: `[]`. Result: `{ "epoch": 41, "epoch_blocks": 1000, "next_set": ["…", "…"] }`. `epoch` is
`height / epoch_blocks`. `next_set` is what the register would derive for the next epoch if this
one ended now — a projection, not a commitment: every bond and unbond before the boundary moves it.
The derivation rule is in `docs/staking.md` §2.

### `rand_getSupply`
Params: `[]`. Result:

```json
{ "height": 1998,
  "genesis_deposited": "…", "genesis_staked": "…", "faucet_minted": "…",
  "faucet_epoch": "…", "faucet_minted_in_epoch": "…",
  "withdraw_deposited": "…", "fees_paid": "…", "burned": "…",
  "subsidised": "…", "sealed_blocks": "…", "aggregator_bonds": "…", "slashed": "…",
  "registration_fees_burned": "…", "base_fees_burned": "…",
  "vesting_issued": "…", "vesting_released": "…", "vesting_in_register": "…", "vesting_locked": "…",
  "program_rand_out": "…", "program_rand_held": "…",
  "pool_value": "…", "register_total": "…", "total_supply": "…", "invariant_holds": true }
```

The four `vesting_*` fields (genesis vesting, `docs/vesting.md`; `"0"` without a `vesting`
section): what genesis issued into the vesting register, the notes claims and revokes released into
the pool (inside `pool_value`), what the register still holds (inside `total_supply`; RAND bonded
from it is a validator's `stake`, so in `register_total`), and what of it has not unlocked yet at the
head. `vesting_issued` is issuance, on the identity's right beside `genesis_staked`.

`registration_fees_burned` (v0.5.5, audit v5 TOK-2) is Σ of the registration fees burned under
the genesis `tokens.burn_registration_fee` (`docs/tokens.md` §15): inside `burned` on the pool
side and in no register entry, so the identity below subtracts it on its right beside `slashed`.
A decimal string; `"0"` on chain 14, which has no gate.

`base_fees_burned` (fee feedback, unreleased) is Σ of the bundle bases (`BUNDLE_BASE` each)
burned under the genesis `fees.burn_base` (`docs/fees.md` §1.3): inside `burned` on the pool side,
in no register entry, subtracted on the identity's right beside `registration_fees_burned`. Under
the flag `fees_paid` counts only what proposers kept — the tip. A decimal string; `"0"` on every
chain without the flag.

`faucet_epoch` and `faucet_minted_in_epoch` (v0.5.4, audit v4 STAKE-2) are the faucet's per-epoch
pair: the epoch the counter is for and what the faucet minted in it, against the genesis
`staking.faucet_budget_per_epoch`. Both are decimal strings like the rest of this object, and both
read `"0"` on a chain without a `staking` section (chain 14), where no budget applies. On a chain
with one they are consensus state — in the state root and replayed by `rand-node verify` — not a
derived count like the rest.

The supply audit. Note values are hidden, but every crossing of the pool's boundary is public, so
these are exact: value enters the pool as a genesis deposit, a faucet mint or a validator's
withdraw, and leaves it as a bundle fee (into a proposer's `rewards`) or a burn (a `Bond`, into
`stake`). A withdraw's own base fee is not a crossing: `withdraw_deposited` counts the note it
created (`amount` less the base), and the base moves from one register entry to another.
`pool_value = genesis_deposited + faucet_minted + withdraw_deposited − fees_paid −
burned`; `register_total` is Σ `stake + pending + rewards` over the register; `total_supply` is the
two together, and `invariant_holds` is whether it still equals everything the chain issued
(`genesis_deposited + genesis_staked + faucet_minted`) less what was destroyed (`slashed`,
`registration_fees_burned` and `base_fees_burned`). A false there is a bug, never a legitimate
chain state. The counters are not in the state root — `rand-node verify --mode quick` recomputes
every one of them by replaying the chain, which is what makes them auditable. `docs/supply.md`
works the identity through a bond and a withdraw and says where it rests on a claim (the genesis
file's own amounts) rather than on a check.

`program_rand_out` and `program_rand_held` (RPL-2, program state; `"0"` without a
`program_state` section): RAND that invokes have paid out of program vaults as notes (value
entering the pool, inside `pool_value` beside `withdraw_deposited`), and what the vaults still
hold — register-side value, inside `total_supply`. It entered through an invoke's bundle
`burn_r`, so it is inside `burned` on the pool side; this is its register-side twin, and a
token in a vault is still in that token's `total_supply`.

### `rand_getVesting`
Params: `[id, at_ms?]` — the entry's 64-hex id, and optionally the time to evaluate the schedule at
(default: the head block's timestamp). Result, genesis vesting (`docs/vesting.md`):

```json
{ "id": "3f9a…", "class": "investor", "beneficiary": "<address>", "revocable": false,
  "revokers": [], "threshold": 0, "treasury": null,
  "amount": "18000000000000000", "start_ms": 1790000000000, "cliff_ms": 31104000000,
  "linear_ms": 46656000000, "step_ms": 2592000000,
  "claimed": "0", "revoked_out": "0", "revoked_at": null,
  "bonded": "0", "bonded_to": null, "unbonding": [], "nonce": 0, "revoke_nonce": 0,
  "vested_now": "0", "claimable_now": "0", "unvested_now": "18000000000000000",
  "locked_now": "18000000000000000", "as_of_ms": 1790000000000 }
```

Keys are served as their addresses. A revocable entry lists its `revokers` in the order a revoke's
signer indices count them, the `threshold` of them a revoke needs, and the `treasury` (`rand1…`) a
revoke pays — the only address it may pay. `claimable_now` is what a `claim_vested` may take: vested,
unclaimed, and neither bonded nor still unbonding. `nonce` is what the holder's actions sign over
and `revoke_nonce` what a revoke does. `unvested_now` is what a `revoke_vesting`'s note may carry:
before a revoke the part not yet vested, after one what is still in the register for the treasury;
`locked_now` is the part still locked for the holder (`"0"` once revoked). `null` for an id the register does not hold;
`{"enabled": false}` on a chain without a `vesting` section.

### `rand_getVestingSummary`
Params: `[]`. Result: `{ "enabled": true, "height", "as_of_ms", "entries", "issued", "released",
"locked", "classes": [{ "class", "entries", "amount", "vested", "claimed", "revoked_out", "bonded",
"locked" }] }` — only the classes that have entries, in the order team, investor, partner, other.
No key or owner appears. `{"enabled": false}` without the section.

### `rand_getVestingSchedule`
Params: `[from_ms, to_ms, step_ms]`, at most 1 000 points (`-32602` otherwise). Result:
`{ "enabled": true, "issued": "…", "points": [{ "t_ms": …, "locked": "…" }] }` — the register's
locked total at `from_ms`, `from_ms + step_ms`, … `≤ to_ms`: the aggregate lockup table (SAFT
Schedule 2 §3). Revokes already applied are counted; future ones cannot be.

### `rand_getVersion`
Params: `[]`. Result:
```json
{ "version": "0.1.0", "git_sha": "c66e6b8…", "chain_id": 12, "hc_bundle": "f07a…19",
  "hc_auth": null, "fri_profile": "production" }
```
`version` is the workspace crate version. `git_sha` is the full commit hash captured at build time
by `randprotocol-node`'s `build.rs` — `git rev-parse HEAD` in a checkout, else the `.git-rev` file
`deploy/rebuild-vps.sh` writes into the tree it ships to the build host (which has no `.git`), else
`"unknown"` — with `-dirty` appended when tracked files differ from that commit (untracked files do
not count). This
is how a caller outside the fleet (an explorer, a survey script) confirms which build a node is
running without shelling in; the deploy's own sha-compare stays on the binary.

### `rand_getGenesisHash`
Params: `[]`. Result: the genesis hash as hex, e.g. `"605eb783…"`.

Chain id alone is not enough on a project that cuts chains as often as this one: chain 11 and
chain 12 could carry the same id on a misconfigured node, and this call catches that before a sync
is wasted on the wrong chain.

### `rand_getHealth`
Params: `[]`. Result, one of:
```json
{ "status": "disk_low", "free_bytes": "3221225472" }
{ "status": "ok" }
{ "status": "syncing", "behind": 412 }
{ "status": "behind", "behind": 30 }
```
`disk_low`, ahead of everything else, when free space on the data directory's filesystem is
under four times the node's startup minimum (`--min-free-disk-mb`, default 1024 → under 4 GB);
`free_bytes` is the measurement, as a decimal string, re-taken every status tick (audit v4 OPS-3).
`ok` when `sync_target - height` is at most 2 and no sync batch request is outstanding. `syncing`
while one is. `behind` when the node is not syncing and the lag is still above 2 — the chain-8
stall shape. A load balancer reads `status` alone; an operator reads `behind` too.

### `rand_getTransactionStatus`
Params: `[[hash, …]]`, 1 to 64 hashes. Result: one entry per hash, in order:
```json
[ { "hash": "…", "status": "committed", "height": 1998, "index": 0 },
  { "hash": "…", "status": "pending" },
  { "hash": "…", "status": "rejected", "reason": "bad mint signature" },
  { "hash": "…", "status": "unknown" } ]
```
Lookup order per hash: committed (storage), then pending (the mempool), then rejected (the refused
cache — the same cache `rand_status`'s `refused_cache` counts), else `unknown`. A hash this node
never saw and one a peer refused both read `unknown`; that is honest, since a wallet's submit goes
to one node, not to every node that might have an opinion. A rejection is not kept forever — the
cache evicts at 8192 entries — but a client polling sees it long before that.

**`rejected` covers refusals about the transaction's own bytes only** — the ones no later block can
change (`admission::is_permanent`): an invalid bundle, call or aggregate proof; a bundle digest that
is not what its proof published; a bad mint signature or a malformed program; the wrong chain id; a
bundle on an action that must not carry one, or none where one is required; an envelope, proof,
attestation, program, aggregate or whole transaction over its size cap; a nullifier or commitment
repeated inside the transaction itself; a burn or bridge attestation inconsistent with itself; and
an aggregate's own signature and cover-set verdicts (empty, too many, duplicated, an unregistered or
mismatched shape or guest, a cover that is not a bundle or is already sealed). A refusal that
depends on this node's state at that moment — a spent nullifier, a commitment already in the tree,
an anchor or `time` outside the window, a fee below the floor, an unknown program, the staking and
aggregator registers — is **not** remembered: a double-spend refused at submit reads `unknown`
straight away (the submitter got the reason as `rand_sendTransaction`'s error), and a pooled
transaction that a block makes unspendable reads `pending` and then `unknown` once it leaves the
pool.

`randprotocol_client::RpcClient::wait_for_transaction` calls this method and fails as soon as a
poll reads `rejected`, rather than waiting out its timeout on a transaction that is never coming
back; against a node too old for this method (`-32601`), it falls back to its previous polling
loop.

Errors: `-32602` for an empty list or more than 64 hashes.

On a pruned node (`rand_status.prune_floor > 0`), every `unknown` entry carries `floor` beside
`status`: `{ "hash": "…", "status": "unknown", "floor": 10 }` — whether or not that particular
hash's height is below it, since an archive is the only place that could say which. It is still
`unknown`, not an error — this method answers a page of hashes, not one lookup — and only an
archive can say whether that hash was ever committed.

### `rand_getReceipts`
Params: `[program_id, from_height, to_height, limit?]`. Result:
```json
{ "receipts": [ { "tx": "…", "program": "…", "tier": 14, "outputs": [1, 0, 25, 0, 0, 0, 0, 0],
    "height": 17, "index": 0, "h_in": "9c0e…7f", "h_pub": null }, … ],
  "next_height": 2051 }
```
Receipts for `program_id` with `from_height <= height <= to_height`, ordered by height then index;
the receipt object is exactly `rand_getReceipt`'s. `limit` defaults to and is capped at 256, and a
`limit` of 0 is clamped up to 1.

`limit` is a soft floor, not a hard page size: a page never splits a height. Once it holds `limit`
receipts it still serves the rest of that height's matching receipts before it stops, so a receipt
is never split across two pages and a caller never has to de-duplicate one across a page boundary.
`next_height` is the first height not served at all — resume from it — or `null` when the range's
own `to_height` ended the page rather than `limit`.

Errors: `-32602` for `to_height` below `from_height`.

On a node started with `--prune-history`, a range that reaches a height below the floor (genesis
excepted) answers error `-32010` naming the first such height —
`pruned: height h is below this node's retention floor f` with `data: {"floor": f}` — ask the
archive for it, rather than serving the range from the floor's receipts alone (the pruned heights'
receipt rows go with their blocks — see the retention pass). `[0, to]` still serves genesis alone
when `to` is 0.

### `rand_getWitnesses`
Params: `[[index, …]]`, 1 to 32 leaf indices. Result:
```json
{ "root": "…", "witnesses": [ { "index": 7, "path": ["…", …] }, { "index": 9, "path": null } ] }
```
`rand_getWitness` folded over many leaves in one tree build: a wallet proving several notes at once
pays for the rebuild once instead of once per note. An index past the end of the tree reads
`path: null` for that entry rather than failing the whole call. `rand_getWitness` is unchanged and
is not implemented through this call: it keeps its own arm and its own one-leaf tree build
(`Storage::witness`), and still answers `null` for an index past the tree.

Errors: `-32602` for an empty list or more than 32 indices.

### `rand_getBlocks`
Params: `[from_height, to_height]`. Result: a list of headers, oldest first, at most 1024
(`MAX_BLOCK_HEADERS`; 128 on a node before 2026-09-24) starting at `from_height`:
```json
[ { "hash": "647b…", "height": 50, "view": 92, "parent": "2d41…", "proposer": "3v3VBJ…",
    "timestamp_ms": 1788000123456, "tx_root": "0000…", "state_root": "a1b2…",
    "justify_view": 91, "sealed": true, "tx_count": 0 } ]
```
The same header fields as `rand_getBlockByHeight` / `rand_getBlockByHash`, minus `transactions` —
the block list a client pages through without paying for every transaction in it; those two serve
the transactions. A range wider than the cap, or past the head, is truncated, not refused — a
client advances from the last height it got back, which is also what makes a 1024-header ask
correct against an older node's 128.

A page is also bounded in bytes, and ends early — never before its first header, so a walk always
advances: after the block that takes what it has *read* past 64 MiB (`MAX_RANGE_READ_BYTES`), and
before the header that would take its serialised *reply* past 16 MiB (`MAX_HEADER_REPLY_BYTES`, a
quarter of the command-line wallet's 64 MiB reply cap; audit v7, RPC-5).

Each header carries `public_notes`: the block's transactions that append a note whose every word
is public — `bridge_attest`, `token_mint`, `register_token`, `invoke`, and `bridge_burn` on a chain
with `bridge.fees` — as `{ "hash", "raw", "proofs_stripped": true }`. `raw` is the transaction's
wire encoding in hex **with what a note's rebuild never reads emptied**: the bundle's `proof` and
`auth_proof`, an invoke's call proof, and a deposit's `pq_signatures`. The attestation (its body
and ECDSA signatures), every action field, the bundle's public fields and the envelopes are
kept. The copy hashes differently from the committed transaction; `hash` is the real id, which a
burn's fee note is blinded over. For the committed bytes, ask `rand_getRawTransaction` by that
hash. A client that meets a reply too large to read from an older node asks for a shorter range.

Errors: `-32602` for `to_height` below `from_height`.

On a node started with `--prune-history`, a range that reaches a height below the floor (genesis
excepted) answers error `-32010` naming the first such height —
`pruned: height h is below this node's retention floor f` with `data: {"floor": f}` — ask the
archive for it, rather than serving the range from the floor instead. `[0, to]` still serves
genesis alone when `to` is 0.

### `rand_getFinality`
Params: `[height]` or `[hash]`. Result, one of:
```json
{ "status": "committed", "height": 1998, "hash": "…" }
{ "status": "certified", "height": 1999, "hash": "…", "qc_view": 2251 }
{ "status": "proposed", "height": 2000, "hash": "…" }
{ "status": "unknown" }
```
`committed` is a block at or below the committed head — the only answer a height can give, since
two proposals can share an uncommitted height, so a height is only ever checked against the
committed chain. A hash can also read `certified` (in HotStuff's uncommitted tree with a quorum
certificate for it — `high_qc`, `locked_qc`, the committed head's `head_qc`, or a child's
`justify`) or `proposed` (in the tree without one yet); `unknown` is a hash this replica's tree has
never held.

Errors: `-32602` for a missing param 0, or one that is neither a height nor a block hash.

On a node started with `--prune-history`, a height below `rand_status.prune_floor` (genesis
excepted) answers error `-32010` `pruned: height h is below this node's retention floor f` with
`data: {"floor": f}` — ask the archive for it. A hash is unaffected: it still answers `committed`,
`certified`, `proposed` or `unknown` as above.

### `rand_getProposer`
Params: `[view]` or `[from_view, to_view]`, at most 64 views. Result:
```json
{ "epoch": 3, "proposers": [ { "view": 2251, "proposer": "2nRdFC…" }, … ] }
```
The leader of each view under the **current** validator set (`HotStuff::leader`), not the set that
actually ran at that view historically — views are not mapped to past epochs, so a view from an
earlier epoch answers with the current set's leader, and `epoch` says which epoch's set was used.

Errors: `-32602` for `to` below `from`, or a range of more than 64 views. The count is checked
before any allocation, so `[0, u64::MAX]` is refused on the count rather than an attempt to
collect the range first.

### `rand_getMempoolInfo`
Params: `[]`. Result:
```json
{ "count": 2, "bytes": 2611200, "oldest_ms": 1450, "max_count": 10000 }
```
`bytes` is the sum of every pooled transaction's encoded length. `oldest_ms` is how long the
longest-pooled transaction has waited, `null` when the pool is empty. Beside `max_count` the pool
is capped at eight times the genesis `max_block_bytes` in `bytes` (audit v6, CH-7): past it a
transaction paying more above its floor per KiB displaces the cheapest, and one paying less is
refused `mempool full`; governance actions pass both caps.

### `rand_getEmission`
Params: `[]`. Result:
```json
{ "inflation": "0",
  "subsidy": { "current": "250", "base": "1000", "halving_blocks": 210000,
               "sealed_blocks": 420001, "next_halving_at": 630000 },
  "faucet": true }
```
`inflation` is a fixed `"0"` — nothing on this chain mints outside a genesis allocation, the
testnet faucet, or the bounded aggregation subsidy, so a client expecting Solana's
`getInflationRate` gets a number instead of a missing method. `subsidy` is the block-aggregation
schedule (`gas::subsidy`, the 2026-09-15 changelog entry below); it is `null` on a chain whose
genesis carries no `aggregation` section, which chain 12 does not. `subsidy.current` is the
schedule's `subsidy(sealed_blocks)`: what the next aggregate mints, except under the genesis
`fees.subsidy_net_of_fees` (`docs/fees.md` §1.3), where it is a ceiling on the mint — the
aggregate mints only its shortfall over the covered proving shares, which `rand_getAggregate`'s
`subsidy` reports per aggregate. `faucet` mirrors `rand_status`'s field of the same name.

## Subscriptions (WebSocket)

The same port also speaks WebSocket: `ws://127.0.0.1:8545/` or `ws://127.0.0.1:8545/ws`, either
path. `POST /` is unchanged and is still where every method above is served — the socket serves
**only** `rand_subscribe` and `rand_unsubscribe`, and answers `-32601` to anything else,
including reads. There is nothing to configure and no second port to open.

One thing did change for non-WebSocket clients: `GET /` is now the upgrade handler, so a plain
`GET` with no upgrade headers answers **`400 Bad Request`** where a POST-only route used to answer
`405 Method Not Allowed`. Nothing reads that status — the RPC has always been `POST` — but a
health check that asserted on `405` needs to assert on `400`.

Three topics exist:

- **`newHeads`** — payload exactly `rand_getHead`'s three fields, in the same shape — one
  `HeadSummary` serves both, so they cannot drift apart. The one difference is what `view` means:
  a notification carries the *block's own* view, the one its quorum certificate is for, while
  `rand_getHead` reports the node's current consensus view. For the tip of a healthy chain they
  are the same number. A notification is sent **once per committed block, in order**, including
  during sync: a batch of 100 synced blocks is 100 notifications, not one for the tip, so a wallet
  tracking heads never silently skips a height. Nothing is sent before the block is committed to
  storage, so a head you are told about is a head this node will not lose.
- **`receipts`** or **`receipts <program_id>`** — one notification per committed block that
  carries at least one matching call receipt, in `rand_getReceipt`'s shape; a block with none
  sends nothing, so a quiet chain (for that filter) is a quiet socket. A filtered subscription
  accepts a program id this node has never seen, since the program may be deployed after the
  subscribe.
- **`transaction <hash>`** — one notification for that hash, then the node removes the
  subscription itself: `{ "status": "committed", "height", "index" }` on commit, or
  `{ "status": "rejected", "reason" }` when this node refuses it for good — the same reason
  `rand_getTransactionStatus` would report, from the same refused cache, so the same limit: only
  a refusal about the transaction's own bytes (a bad proof, digest or signature, the wrong chain,
  an oversize part) is announced. A state-dependent refusal — a spent nullifier, an expired
  anchor — is not, and neither is a transaction pruned from the pool; the subscription then waits
  until the socket closes, so pair it with your own timeout. A hash that had
  **already** committed or been refused when the subscribe request arrived is not answered
  synchronously in the subscribe reply; it is answered on the next committed block, exactly like a
  hash that settles afterwards, so a client has one code path whether it subscribes before or
  after submitting. A duplicate submission or a pool conflict is never announced here — only a
  permanent refusal that lands in the refused cache is.

The three topics are independent streams, not one feed kept in step: a connection subscribed to
more than one may see block N's `receipts` notification before its `newHeads` notification, or the
other way round. There is no ordering promise *between* topics, only *within* one.

```jsonc
// client -> node
{ "jsonrpc": "2.0", "id": 1, "method": "rand_subscribe",   "params": ["newHeads"] }
{ "jsonrpc": "2.0", "id": 2, "method": "rand_unsubscribe", "params": ["1"] }
{ "jsonrpc": "2.0", "id": 3, "method": "rand_subscribe", "params": ["receipts", "<program_id>"] }
{ "jsonrpc": "2.0", "id": 4, "method": "rand_subscribe", "params": ["transaction", "<hash>"] }
// node -> client
{ "jsonrpc": "2.0", "id": 1, "result": "1" }        // the subscription id, a decimal string
{ "jsonrpc": "2.0", "id": 2, "result": true }
{ "jsonrpc": "2.0", "id": 3, "result": "2" }
{ "jsonrpc": "2.0", "id": 4, "result": "3" }
{ "jsonrpc": "2.0", "method": "rand_subscription",
  "params": { "subscription": "1", "result": { "height": 1998, "hash": "…", "view": 2251 } } }
{ "jsonrpc": "2.0", "method": "rand_subscription",
  "params": { "subscription": "2", "result": { "height": 2051, "hash": "…",
    "receipts": [ { "tx": "…", "program": "…", "tier": 14, "outputs": [1,0,25,0,0,0,0,0],
      "height": 2051, "index": 0, "h_in": "9c0e…7f", "h_pub": null } ] } } }
{ "jsonrpc": "2.0", "method": "rand_subscription",
  "params": { "subscription": "3",
    "result": { "status": "committed", "height": 2051, "index": 3 } } }
```

`rand_unsubscribe` answers `true` when this connection held that id and `false` when it did not —
a `false` is not an error, because a client tearing down after a reconnect has no way to know which
ids survived. Ids are per connection, are never reused within one, and all of them go when the
socket does — a delivered `transaction` subscription also removes its own id, the moment its one
notification is sent. A frame with no `id` member is a notification and is refused with `-32600`,
as over HTTP. An unknown topic, or a malformed `receipts` program id or `transaction` hash, is
`-32602`.

This endpoint is unauthenticated, so it is bounded four ways:

- **64 connections per node.** The 65th is refused at the upgrade with HTTP `503` and a body
  naming the limit — not accepted and then dropped, which a client cannot tell from a network
  fault. `rand_status`'s `ws_clients` is the live count.
- **8 subscriptions per connection.** The ninth `rand_subscribe` is `-32000`; the eight it holds
  are untouched.
- **64 KiB per frame from the client.** A larger frame is refused and the socket ends. (This is a
  bound on what the node will *read*; what it writes is a request reply or a `newHeads`,
  `receipts` or `transaction` notification, none of which comes near it.) Proof-carrying bodies go
  to `POST /`, which has its own much larger limit.
- **5 seconds to take a frame, and a ping every 30 seconds.** A write that does not complete in
  5 s means a client that has stopped reading, and the socket is dropped rather than written to
  again. Without that deadline the node's task parks in the kernel's send buffer until the link is
  torn down — minutes — holding its connection slot, so 64 sockets from one host would close the
  endpoint to everyone while `ws_clients` still read 64 healthy clients. A connection with no
  subscription is never written to at all, so it is pinged every 30 s and must answer within the
  same 5 s. Any WebSocket library answers pings for you; a client that does not must send
  `Pong` itself.

**Backpressure closes, it does not buffer.** Three broadcast channels feed this endpoint, each
keeping 256 entries in flight per subscriber: heads (for `newHeads`), committed blocks (which
answers both `receipts` and a settled `transaction`), and refusals (which answers a `transaction`
still waiting). A client that falls further behind on one than its 256 entries — because it
stopped reading, or its link cannot carry what the chain produces — is closed with WebSocket code
`1008` (policy violation) and a reason naming the stream and how many entries it missed. Buffering
a slow subscriber is how a node runs out of memory.

A lag only closes a connection that actually holds a subscription the lagging channel feeds: a
`newHeads`-only client is untouched by a flood of receipts or refusals elsewhere on the chain, and
a `receipts`-only client is untouched by a lag on refusals. The recovery matches whichever stream
you fell behind on — reconnect, subscribe again, and fill the gap with
[`rand_getCompactBlocks`](#rand_getcompactblocks) (heads), [`rand_getReceipts`](#rand_getreceipts)
(committed blocks), or [`rand_getTransactionStatus`](#rand_gettransactionstatus) (refusals) from
the last point you did see. At 3 s blocks, 256 entries is about thirteen minutes, so a subscriber
that hits this was not going to catch up on the socket anyway.

## Errors

| code | meaning |
|---|---|
| `-32601` | unknown method — over HTTP, and on the WebSocket for anything but the two subscription methods |
| `-32602` | invalid or missing parameter (message says which) |
| `-32000` | rejected: a transaction the mempool refused, or a subscription over this connection's cap (message gives the reason) |
| `-32001` | referenced object not found |
| `-32603` | internal error (storage or node loop) |
| `-32600` | invalid request — the body is over the size limit, is not JSON, is a malformed batch, or is a notification |

Error responses look like `{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "…" } }`.

## The transaction on the wire

`rand_sendTransaction` takes `bincode(Transaction)`. There is no signature over the transaction
and no sender key: a bundle authorises itself by its proof, and an action that is signed carries
the signature inside itself — a faucet mint the minting validator's key and signature, an `Unbond`
or `Withdraw` the register's nonce and the validator's signature over it. Those three are also the
only actions with `bundle: null`; every other action must carry one.

```
Transaction { chain_id: u64, bundle: Option<Bundle>, action: Action }

Bundle {                                        // the hidden-asset bundle (chain 14)
  anchor: Word8, nullifiers: [Word8; 4], commitments: [Word8; 4],
  fee: u64, burn_a: u64, burn_r: u64, burn_asset: u32, time: u32,
  envelopes: [Envelope; 4], proof: Vec<u8>,     // postcard(rand_zkvm::Proof) of the hidden-asset guest
  auth_commit: Word8, auth_proof: Vec<u8>,      // v0.6.3, chain 17+: split authorisation's c and
}                                               //   auth proof; zeros and empty without hc_auth
Envelope { kem_ct: Vec<u8>, to_receiver: Vec<u8>, to_sender: Vec<u8>, body: Vec<u8> }

Action::None                                            // a plain shielded transfer
Action::Mint { cm: Word8, pk: Word8, time: u32, r: Word8,   // cm = commitment of (pk, no sender,
               envelope: Envelope, amount: u64,          //   amount, asset 0, time, r), checked
               minter: PublicKey, signature: Signature } //   by admission (audit v3, POOL-1)
Action::Deploy { base_pc: u32, words: Vec<u32>, public: Vec<u32> }
Action::Call { program: Hash, proof: Vec<u8>,           // postcard(rand_zkvm::Proof)
               input_envelope: Option<CallEnvelope> }
Action::Bond { validator: Address, amount: u64, registration: Option<Registration> }
Action::Unbond { validator: Address, amount: u64, nonce: u64, signature: Signature }
Action::Withdraw { validator: Address, amount: u64, nonce: u64, time: u32, r: Word8,
                   envelope: Envelope, signature: Signature }
Action::BridgeAttest { attestation: Vec<u8>, recipient: ShieldedAddress, r: Word8, time: u32,
                       asset: u32, envelope: Envelope,
                       pq_signatures: Vec<PqSignature> }   // bridge hardening B3, last field
Action::BridgeBurn { asset: u32, amount: u64, relayer_fee: u64, to_chain: u16,
                     token: [u8; 32], to: [u8; 32] }
Action::RegisterToken { name: String, symbol: String, decimals: u8, authority: MintAuthority,
                        initial: Option<InitialMint>, salt: [u8; 32], index: u32 }
Action::TokenMint { asset: u32, amount: u64, recipient: ShieldedAddress, r: Word8, time: u32,
                    envelope: Envelope, nonce: u64, signature: Signature }
Action::SetAuthority { asset: u32, new: Option<PublicKey>, nonce: u64, signature: Signature }
Action::TokenBurn { asset: u32, amount: u64 }
Action::PauseMints { nonce: u64, signature: Signature }               // B1, bundle-less, fee-less
Action::UnpauseMints { nonce: u64, pq_signatures: Vec<PqSignature> }  // B1, bundle-less
Action::RegisterBridgedToken { name: String, symbol: String, salt: [u8; 32], chain: u16,
                               token: [u8; 32], decimals: u8, nonce: u64,
                               pq_signatures: Vec<PqSignature> }      // B4
Action::ListBacking { token_index: u32, chain: u16, token: [u8; 32], decimals: u8, nonce: u64,
                      pq_signatures: Vec<PqSignature> }               // B4
Action::Invoke { program: Hash, proof: Vec<u8>, input_envelope: Option<CallEnvelope>,
                 transition: Transition }                             // RPL-2, tag 33 (after the vesting actions and audit v6's AdmitValidator … CancelRotation, 28–32)

MintAuthority = None | Key(PublicKey) | Bridge { backings: Vec<Backing> } | Program(Hash)
InitialMint { amount: u64, recipient: ShieldedAddress, r: Word8, time: u32, envelope: Envelope }
Transition { reads: Vec<Cell>, writes: Vec<Cell>, inflow: Inflow, pays: Vec<Payout>, mints: Vec<Payout> }
Cell { key: Word8, value: Word8 }              // keys strictly ascending in each list
Inflow = None | Deposit | Burn                  // what the bundle's burn_a of burn_asset is to the program
Payout { asset: u32, amount: u64, recipient: ShieldedAddress, r: Word8, envelope: Envelope }

Registration { public_key: PublicKey, payout: ShieldedAddress, signature: Signature }
PqSignature { index: u8, signature: Vec<u8> }   // one guardian's Dilithium2 co-signature, by set index
```

This block does not show the five block-aggregation actions (`RegisterAggregator`,
`UnbondAggregator`, `WithdrawAggregator`, `SlashAggregator`, `Aggregate`) that sit between
`BridgeBurn` and `RegisterToken` in the enum's declared order — see the 2026-09-15 changelog
entry below for their fields. They occupy real bincode tags on any chain whose genesis carries an
`aggregation` section; a chain without one (chain 12 onward, until it returns) never admits them,
but an encoder that hard-codes tag numbers rather than deriving them from the enum still needs to
count them.

A `Bond` must carry a bundle whose `burn_r` equals its `amount` (and whose `burn_a` and
`burn_asset` are 0) — that is how the stake leaves the pool — and `registration` is present exactly when the validator is not in the register yet
(`docs/staking.md`).

Every transaction carries at most one bundle. A `BridgeBurn` or a `TokenBurn` burns through it:
the bundle's `burn_asset` must be the action's `asset` (never 0), its `burn_a` the action's
`amount`, and its `burn_r` 0, while its `fee` pays in RAND from slots 2–3. Every other action burns
no token (`burn_asset` and `burn_a` 0), and RAND is only ever burned through `burn_r`: a bundle with
`burn_asset` 0 and `burn_a` non-zero is refused everywhere. A `BridgeAttest`'s deposit note is the one commitment the wire does not
carry — the chain computes it from the amount the guardians signed, the recipient the action
names, its blinding `r`, its `time` and the registry index it names in `asset`, so a submitter
cannot choose the amount or the owner. **`r` is derived, not chosen** (chain 14, F1): admission
requires it to equal `blake3("rand-deposit-r-1" ‖ mu)` over the digest the guardians signed
(`mu`), and refuses any other value with `BridgeError::WrongDepositBlinding` — a permanent
refusal, since it depends on the transaction's own bytes alone
(`docs/bridge.md` §5). A submitter can still choose `time`, within the window a bundle's `time`
gets, which is what lets the depositor seal an envelope for a note whose commitment it can compute
before knowing which block will take the transaction — and, with `r` derived too, two independent
submitters of the same attestation at the same `time` name the identical note. `asset` is the
index the envelope was sealed for: a bridged token is *listed* — at genesis or by a
`RegisterBridgedToken`/`ListBacking` governance message — before any attestation of it is
admissible, and a listing's index never moves once assigned, so there is no first-sighting
registration to race for a bridge deposit (that only ever applied to the RPL registry's own
`RegisterToken`, a different action). An attestation of a coin nobody has listed is refused
`BridgeError::UnlistedToken` before `asset` is even compared; once the coin is listed, a mismatch
between the index the attestation resolves to and the index the action names is
`TxError::AttestAssetMismatch` — `the attestation deposits under asset 2, and the transaction
names 1` — which only a stale registry view (a node behind the listing) or a hand-built
transaction can hit.

A `Withdraw` derives its note the same way and for the same reason: `time` is the head height when
the command ran, and the chain, not the wire, computes the commitment (`docs/staking.md`).

Encoded sizes (bincode's default configuration: fixed-width integers, 8-byte length prefixes,
`u32` enum tags):

| part | bytes |
|---|---|
| `Word8` | 32 |
| one `Envelope` | 1380 (1088-byte ML-KEM-768 ciphertext, two 60-byte wrapped transaction keys, a 140-byte sealed note, four length prefixes) |
| `Bundle` minus the proof | 5848 (four `Word8` nullifiers and commitments, four envelopes) |
| transfer transaction minus the proof | 5861 |
| deploy transaction minus both proofs, 100-word program | 6281 |
| call transaction minus both proofs | 5902 |
| mint transaction (no bundle) | 5181 (a 1312-byte Dilithium2 key and a 2420-byte signature) |
| bundle proof | 327,203 measured for the hidden-asset guest at tier 14 under the `test` FRI profile |

So a shielded transfer on the wire is about 1.43 MB at the 80-query production profile,
essentially all proof. The ledger caps a proof at 2 MiB by default (chains 13–15 set
`max_proof_bytes` to 8 MiB in their genesis; note 2026-09-28), an envelope
at 2048 bytes, a program at 4096 words (or the genesis file's `max_program_words`, at most 65 535),
and a block at 4 MiB of transaction bytes — two bundles
per block at that default (`docs/block-space.md`; a genesis may raise the caps).

A wallet builds all of this through `randprotocol_client::wallet::{send, submit}`, which selects the
inputs, fetches the anchor and the witnesses, proves the bundle, seals all four envelopes, and checks
the proof's published digest against the one it computed before it submits anything.

## Changelog

What changed for clients, in one place. Newest first.

### Unreleased — fee feedback: the genesis `fees` section and the burned base (genesis-gated; no chain carries it yet)

Additive. `rand_getSupply` gains `base_fees_burned` (a decimal string, `"0"` on every chain
without the flag): the bundle bases destroyed under the genesis `fees.burn_base`
(`docs/fees.md` §1.3), on the right of the supply identity beside `registration_fees_burned`.
`rand_getLimits` gains `fee_rules` (`{ "burn_base", "subsidy_net_of_fees" }`, booleans), `null`
on a chain whose genesis has no `fees` section with a `true` flag. Under `burn_base` a proposer's
`rewards` grow by the tip (`fee − BUNDLE_BASE`), or by nothing at inclusion on an aggregating
chain; no fee a wallet pays changes. Under `subsidy_net_of_fees` `rand_getAggregate`'s `subsidy`
(and `rand_getSupply`'s `subsidised`) carry only the minted part, the schedule's shortfall over
`proving_share`. Every existing field keeps its value on every chain without the section.
One fix applies on every chain: `rand_getAggregate`'s `subsidy`, `proving_share` and `n` are now
stored from the ledger's own payment, so a node that synced the covered bundle and its aggregate
in one commit no longer reports a `proving_share` of 0 (and, under the flag, the full schedule as
`subsidy`) where a live node reports the paid amounts. Records written before the fix keep their
stored values.

### 2026-10-01 — audit v6, TOK-1: `tokens.incremental_root` (genesis-gated; no chain carries it yet)

Additive. `rand_getTokens` gains `incremental_root` (boolean, `false` on every chain through 20):
whether the chain's genesis carries `tokens.incremental_root: true` (`docs/tokens.md` §17), under
which the registry's root is an incremental merkle commitment over `rand-token-leaf-2` leaves
(`rand-token-registry-4`; the state root re-domained `rand-state-tokens-1`) and the node stores one
row per token, rewriting only what a block changed. No validity rule, no listing row and no other
method changes; a client that recomputes the registry root from `rand_getTokens` must use the new
leaf domain and registry domain on such a chain. Node-only on every chain: the root is computed
once per change and reused, so a block that moves no token re-hashes none — the value is the same.

### 2026-10-01 — audit v7, RPC-5: `rand_getBlocks` pages bounded by their reply; every public note stripped (node-only)

A header page ends before the header that would take its serialised reply past 16 MiB
(`MAX_HEADER_REPLY_BYTES`), as well as after 64 MiB of blocks read; never before its first header.
And every entry in `public_notes` is now carried stripped and marked `"proofs_stripped": true` —
`bridge_attest`, `token_mint` and `register_token` included, which came whole before: the bundle's
`proof` and `auth_proof` emptied, and a deposit's `pq_signatures`; every field a note is rebuilt
from, the attestation and the envelopes stay. `hash` is the real id, as for burns and invokes. A
deposit carried whole was ~2.9 MB of proofs doubled by hex, so about a dozen in one page made a
reply past the command-line wallet's 64 MiB cap, which it refused — and asked for again, for ever:
a fresh wallet's first sync stopped for good. The wallet also halves its page when a node (one
without this change) answers one too large, down to a single height. Additive for a reader of
the JSON; a client that needs the committed bytes of a carried transaction reads
`rand_getRawTransaction` by its `hash`.

### 2026-10-01 — headers carry `invoke` transactions in `public_notes` (node-only, after v0.6.8)

Additive. A `rand_getBlocks` header's `public_notes` now also carries every `invoke` in its block,
with every proof stripped (the bundle's, the auth proof and the call proof; `"proofs_stripped":
true`) under its real `hash`. An invoke's payout and mint notes are public (recipient, amount,
asset, blinding, the bundle's `time`), and a wallet that reads header pages fetches no block — so on
v0.6.8 nodes it found a payout only through the envelope the invoker sealed. A wallet rebuilds the
notes from the stripped copy (the client's `rebuilt_notes_with` already does); nothing else changes.

### 2026-10-01 — v0.6.8: zUSD bridge fees, `bridge.fees` (genesis-gated; chain 20 at the earliest)

`docs/bridge.md` §25. Inert on every chain whose genesis bridge section has no `fees` group (chains
14 to 19): every field below then reads as the old rule.

- **`rand_getBridgeState` gains `fees`**: `{ "mint_bps", "burn_bps", "recipient" }` (bps numbers,
  the recipient a `rand1…` address) or `null`.
- **`rand_getBridgeBurn` gains `release_amount`, `fee` and `amount`** (decimal strings) on every
  chain. `release_amount` is the body's own amount — what guardians sign and the source contract
  releases. Under `bridge.fees` it is the burn less the chain's fee; without it `fee` is `"0"` and
  `release_amount == amount`. Relayers and guardians sign the body as before: under the group the
  body already carries `release_amount`.
- **`rand_getTransaction`'s `bridge_attest`** gains `deposit_amount` (the depositor's note value:
  `amount`, the gross the guardians signed, less the fee) and `fee_note` (`{ amount, asset, time,
  r, commitment }` — the treasury's note, every word but its owner — or `null`); `commitment` is
  now the net deposit's leaf. **`bridge_burn`** gains `release_amount` and `fee_note`.
- **`rand_getBlocks` headers carry `bridge_burn` transactions in `public_notes`** on a chain with
  the group, with their proofs emptied and `"proofs_stripped": true`; `hash` is the real
  transaction id (the stripped copy hashes differently, and the fee note's blinding is over the
  real one).
- **`rand_getCompactBlocks` / `rand_getCommitments`**: an attest owns its fee note after its
  deposit, a burn after its bundle's four; a fee note's envelope is empty (sealed to nobody —
  the treasury rebuilds it). `rand_checkTransaction` opens the net deposit.

### 2026-10-01 — RPL-2: program state, program vaults and the `invoke` (genesis-gated; on no chain yet)

`docs/superpowers/specs/2026-09-30-rpl2-program-state-design.md`. Inert on every chain whose
genesis has no `program_state` section; chain 20 is the first that can carry one.

- **A new action, `invoke`** (`Action` 33, appended after audit v6's 28–32): a call whose proof vouches for one declared state
  transition of a program, which the ledger applies. `rand_getTransaction` renders it as a call
  plus its transition — cells read and written, the inflow kind, and every payout note with all
  its words (`time` is the bundle's; `cm` the leaf appended). Its receipt is a call's:
  `rand_getReceipt`, `rand_getReceipts` and the `receipts` topic carry it unchanged.
- **`rand_getProgramCell`, `rand_getProgramCells`, `rand_getProgramVault`**: a program's cells
  (one, or paged in key order) and its vault. `{"enabled": false}` without the section. All
  three are on the public listener.
- **`rand_getLimits` gains `program_state`** (`{ cell_fee, max_reads, max_writes, max_payouts }`
  or `null`); **`rand_estimateFee` takes `{"kind":"invoke", …, "created_cells": c}`** — a call's
  estimate plus `cell_fee · c`.
- **`rand_getSupply` gains `program_rand_out` and `program_rand_held`** (both `"0"` without the
  section); `invariant_holds` covers the vaults.
- **`rand_getCompactBlocks` and `rand_getCommitments`** serve an invoke's payout notes at the
  leaves the ledger gave them (after the bundle's four, pays then mints), each with the payout's
  own envelope, so a wallet finds a note paid to it by trial decryption as it finds a mint.
  `rand_checkTransaction` names them `payout:<i>`.
- `register_token` may carry `"authority": "program"` under the section (a token the named
  program mints and burns through its invokes); `rand_getToken` renders such an authority as
  `{ "kind": "program", "program": "<id>" }`, as it always could.

### 2026-10-01 — issue #118: `proof_window_blocks` (genesis-gated; no chain carries it yet)

- **`rand_getLimits` gains `proof_window_blocks`** (a number, 256..4 096, or `null`): the genesis
  window that replaces both the 256-block anchor window and the 256-block `time` window. `null` on
  chains 14 to 19, where both stay 256; chain 20 is the first that can carry it (`docs/deploy.md`
  recommends 1024).
- **The two refusals name the window in force**: `anchor is not one of the last N roots` and
  `time T is outside [H − N, H]` (`-32000`), where `N` was always 256 before.
- Nothing on the wire changes; no existing chain's rules move.

### 2026-10-01 — audit v6, BRG-14: rotation possession, delay and cancel (genesis-gated; no chain carries it yet)

- **`rand_getBridgeState` gains `rotation_rules`** (`{ "delay_secs", "needs_possession" }`, `null`
  without the genesis `bridge.rotation` group) **and `pending_rotations`** (`null` without it; else
  a list of `{ "kind": "pq_guardians", "new_pq_guardians": [hex…], "effective_at_secs" }` /
  `{ "kind": "pause_key", "new_pause_key": hex, "effective_at_secs" }`).
- **Three new transaction kinds in `tx_json`**: `rotate_pq_guardians_v2` (the v1 fields plus
  `possession_signatures`, a count), `rotate_pause_key_v2`, and `cancel_rotation`
  (`rotation_kind` `"pq_guardians"`/`"pause_key"`, `nonce`). Wire variants 30, 31, 32 (after STAKE-2's `AdmitValidator` = 28 and STAKE-1's `SlashEquivocation` = 29).

### 2026-10-01 — audit v6, BIND-1: `binding_domain` (genesis-gated; no chain carries it yet)

- **`rand_getLimits` and `rand_status` gain `binding_domain`** (`0` or `1`): whether the chain's
  transaction bindings (`rand-tx-bind-2`, `rand-call-bind-2`) and its signed action messages — a
  faucet mint, unbond, withdraw, the RPL token mint and authority messages, the aggregator
  actions, the bridge governance messages — carry the genesis hash. Chains 14 to 19 answer `0`; chain 20 is the first that can carry `1`.
- **A wallet never takes the node's word for it.** The form it proves is decided by the
  transaction's chain id: 14 to 19 are pinned to the chain-id form (`CHAIN_ID_BINDING_CHAIN_IDS`),
  every other id gets the genesis-bound form over the store's genesis hash, and a node claiming
  `0` there only gets a refusal before any proof is made. A client of another kind (randscan, the
  apps) must follow the same rule before any chain is cut with the field.
- Nothing on the wire changes; no existing chain's messages move.

### 2026-10-01 — audit v6, STAKE-1: slashing leader equivocation (`staking.slashing`)

Genesis-gated; nothing changes on a chain without the section (every chain through 18).

- **`Action::SlashEquivocation { first, second }`** (variant 29, appended last): two
  `SignedHeader { header, signature }` of one key for one view. `tx_json` renders it as
  `{ "kind": "slash_equivocation", "offender": <address>, "view": n, "first": { "hash", "height" },
  "second": { "hash", "height" } }`.
- **`rand_getValidators`** rows gain `jailed_until` (the first epoch the key may be in a set again;
  `18446744073709551615` for good; `null` when not jailed).
- **`rand_getLimits.slashing`**: `{ "equivocation_bps", "jail_epochs" }` or `null`.

### 2026-10-01 — audit v6, STAKE-2: the `testnet` marker

- **`rand_status.testnet`** and **`rand_getLimits.testnet`** (bool): whether the genesis says
  `"testnet": true`. A genesis with `faucet: true` beside a `bridge` section is refused on any
  chain id past 18 without it, so a client can label a chain by this field alone; `false` on
  every chain through 18, whose files predate the marker.

### 2026-10-01 — audit v6, STAKE-2: admission by vote (`staking.admission_by_vote`)

Genesis-gated; nothing changes on a chain without the flag (every chain through 18).

- **`Action::AdmitValidator { candidate, signatures }`** (variant 28, appended last): the validator
  set's vote to admit a key to the register — bundle-less, fee-less, pooled like a bridge
  governance action. `tx_json` renders it as `{ "kind": "admit_validator", "candidate": <address>,
  "candidate_key": <hex>, "voters": [<address>, …] }`.
- **`rand_getAdmitted`** (public listener too): the admitted set with the flag and the bound.
- **`rand_getLimits.admission_by_vote`** (bool): whether a registration needs the vote.
- Under the flag `rand_sendTransaction` refuses a registering `Bond` whose key is not admitted
  with `staking: validator … has not been admitted by the validator set's vote` (not permanent —
  a vote one block later makes it valid).

### 2026-10-01 — a header row carries its block's public-note transactions (issue #117)

Additive. Every header `rand_getBlocks` returns gains `public_notes`: the block's `bridge_attest`,
`token_mint` and `register_token` transactions as `[{ "hash": hex, "raw": hex }]` (the same
encoding `rand_getRawTransaction` serves), empty for every other block. A wallet's first sync
reads the header pages and nothing else on such a node; on an older node it still fetches each
block with a transaction. The `rand` wallet also waits out a rate-limit refusal (`-32005`, or a
`-32000` that says rate limited / busy) with doubling waits before giving up, and saves the scan's
progress whether or not it finished, so an interrupted first sync resumes.

### 2026-09-30 — audit v6: a public listener, read limits, a viewing token (VK-2, RPC-2/3/4, VK-1)

Node-only. Nothing changes for a client of `--rpc` except the two read limits.

- **`--public-rpc <ADDR>`**: a second listener with a fixed method set, no batches, no WebSocket
  and one meter for all callers — see "Two listeners" above. A public endpoint must forward to
  this port, not to `--rpc`.
- **Read limits, both listeners**: a blocking read that has not returned within 30 s is answered
  `-32000` ("took longer than 30 s … retry with a smaller range"); `rand_getBlocks` ends its page
  after 64 MiB of block reads, so a page can be shorter than the range asked — advance from the
  last header returned, as at the head.
- **`--rpc-viewing-token-file`**: an optional bearer token on the three viewing-key methods.
- A removed viewing key's matched notes and memos are wiped with the key, and a viewing method's
  request parameters are wiped once it has run.

### 2026-09-30 — audit v6: the mint figures are the ones the ledger judges (BRG-19)

Node-only, additive. On a chain with bridge rules v2 (chains 15–18) a deposit is judged against a
rolling window per backing and one for all backings together; the UTC-day counter bounds nothing
there, and the RPC went on serving it.

- **Every backing row** (`rand_getAssets`, `rand_getBridgeState.assets[]`, the `backings` of
  `rand_getToken`/`rand_getTokens`/`rand_getTokenSupply`) gains `minted_in_window` (decimal
  string; `null` on a day-counter chain), `mint_window_secs` (number; `null` likewise) and
  **`mint_headroom`** (decimal string): the largest deposit to that backing the caps admit at
  the head's block time — the per-backing cap less what it has minted, and under rules v2 no
  more than the registry-wide window has left. **Read `mint_headroom`, not
  `mint_cap_per_day − minted_today`**: the second ignores the global cap.
- **`minted_today`** is, as its description always said, the figure the per-backing cap is
  checked against — under rules v2 that is now the rolling-window count, not the day counter
  (which read zero after midnight while the ledger still counted the deposit). `mint_day` is
  unchanged.
- **`rand_getBridgeState.rules_v2`** gains `global_minted_in_window` and `global_mint_headroom`
  (decimal strings).

### 2026-09-30 — audit v6: a vesting revoke pays a pinned treasury, signed by a threshold (STAKE-3; genesis-gated, on no chain)

No chain has carried a `vesting` section, so nothing a client reads today moves.

- **`rand_getVesting`**: `revoker` (one address or `null`) is replaced by `revokers` (addresses, in
  the order a revoke's signer indices count them; `[]` for an irrevocable entry), `threshold`
  (how many of them a revoke needs; `0` when irrevocable) and `treasury` (the `rand1…` address a
  revoke pays, the only one it may; `null` when irrevocable). `revocable` is unchanged.
- **`revoke_vesting`** in `rand_getTransaction` gains `signers`: the positions, in the entry's
  `revokers`, of the keys that signed it. The action's wire form changed (one `signature` became
  a list of `(index, signature)`), which no chain has ever admitted.
- **Refusals a submitter may hear** (all permanent — they are the transaction's bytes against the
  entry's genesis terms): `a revoke pays the entry's treasury, not the address it names`,
  `N revoker signatures, the entry needs M`, `revoker I signed twice`, `revoker index I is not in
  the entry's list`.

### 2026-09-30 — audit v6: price ceilings and the paying byte load (POOL-2; genesis-gated, chain 18 unchanged)

- **`rand_getLimits`** gains `max_gas_price`, `max_byte_price` (decimal strings; the ceilings the
  dynamic controller never lifts a price over) and `byte_load` (`"paying"` when only a call's
  proof and input envelope move `byte_price`). All three are `null` on chain 18 and on every chain
  without `gas.dynamic` — a wallet's two-step headroom (`docs/fees.md` §1.2) is unchanged, and
  under a ceiling it simply never needs more than the ceiling.
- Node policy, every chain: while a call is pooled and pays its floor, the proposer holds
  flat-fee transactions to three quarters of a block's bytes so the call is offered
  (`Mempool::candidates_within`); a submitter sees nothing of it but a call that lands.

### 2026-09-30 — audit v6: a revoke's own nonce, and no dust (STAKE-4; genesis-gated, on no chain)

- **`rand_getVesting`** gains `revoke_nonce` — the counter a `revoke_vesting` signs over, moved
  only by revokes; `nonce` stays the holder's (claims, bonds, unbonds) — and `locked_now` (what is
  still locked for the holder; `"0"` once revoked). `unvested_now` now reads, after a revoke, what
  is still in the register for the treasury (a later revoke sweeps it) rather than `"0"`.
- **A revoke takes the whole unvested part as of its block** (the schedule stops at `revoked_at`);
  its `unvested` field is the amount its note carries, at most what is unvested. A revoked entry
  admits further `revoke_vesting`s until that rest is paid out; `the entry is already revoked and
  its unvested part paid out` is the refusal after that.

### 2026-09-28 — gas (Phase 1 + Phase 2): the chain's own `gas` section, and the tip's moving prices

Task B4 + the RPC half of B7. Spec `docs/superpowers/specs/2026-09-28-gas-model-design.md` §3.3,
§7.1, §8. Genesis-gated (chain 18) — a chain without a `gas` section is unaffected, and its
`rand_getLimits`/`rand_estimateFee` behave exactly as Phase 0 above.

- **`rand_getLimits`** reports the chain's own `gas` section, not just a node's policy, when its
  genesis carries one: `gas_price`/`byte_price` are the chain's current prices (the tip's, under
  `gas.dynamic` — moving per block by fullness — else the section's fixed ones), `gas_metering`
  is `"circuit"`, and two new fields appear — `bundle_gas_limit` (the bundle guest's flat declared
  gas, `null` without a section) and `adjust_bps` (the dynamic controller's step size in basis
  points, `null` without `dynamic`). A chain's own section always wins over a node's
  `--gas-price`/`--byte-price` flags, which are silently ignored on such a chain (one `warn!` at
  node startup).
- **`rand_estimateFee`**'s call spec gains a fourth field, `gas` — the transaction's declared gas
  limit — **required** on a chain with a `gas` section (`-32602`, "under the gas section a call
  estimate needs its gas", without it); the answer is `circuit_call_floor(gas_price, byte_price,
  gas, bytes)` = `BUNDLE_BASE + gas_price·gas + byte_price·⌈bytes/1024⌉` at the current prices
  (`randprotocol_core::gas::circuit_call_floor`). `keccak_log_height`/`sha256_log_height` are
  accepted but unused under a section. A chain with no section is unaffected: `gas` does not
  exist and the answer is Phase 0's header-priced floor, as before.
- **`rand_status`** gains `gas_prices: { "gas_price": "…", "byte_price": "…" }`, the tip ledger's
  current prices (decimal strings), `null` on a chain without a `gas` section. Refreshed every
  commit by the node loop's `publish_status`, the same as every other status field — this is what
  `rand_getLimits` reads to serve a `dynamic` chain's *current* prices rather than the genesis
  snapshot taken at node startup.

### 2026-09-28 — gas (Phase 0): the header-priced call floor

Spec `docs/superpowers/specs/2026-09-28-gas-model-design.md` §4.1. Node policy, not a chain rule —
`rand-node run` carries the policy by default (`--gas-price 100 --byte-price 800`); only
`--gas-price 0 --byte-price 0` turns it off and answers as before.

- **`rand_getLimits`** gains three fields: `gas_price`, `byte_price` (this node's `--gas-price` /
  `--byte-price`, units of 10⁻⁹ RAND, defaults 100 and 800, as decimal strings — `"100"`,
  `"800"` — like every amount; `null` with no policy) and
  `gas_metering` (`"header"` under a policy, `null` without one; Phase 1's chain 18 answers
  `"circuit"`).
- **`rand_estimateFee`**'s call spec gains `keccak_log_height`, `sha256_log_height` (optional,
  `0..=40`, default 0, `-32602` outside the range): under a policy the answer is the gas floor of
  that header, `max(BUNDLE_BASE + call_fee(tier, bytes), BUNDLE_BASE + gas_price·gas_max +
  byte_price·⌈bytes/1024⌉)`; with no policy the heights are accepted but the answer is the ledger
  floor alone.
- **A pool refusal a submitter may now hear on a node running a policy**: `FeeTooLow` for a call
  under its gas floor — not a permanent verdict (`rand_getTransactionStatus` still reads
  `unknown` once it ages out of the pool), and never a block rule: a block carrying a cheaper call
  is still valid on every node.

### v0.6.3 — split authorisation: `hc_auth`, the bundle's auth fields, `rand-txid-3` (genesis-gated; chain 17+)

- **`rand_status`, `rand_getVersion` and `rand_getLimits` gain `hc_auth`**: the genesis auth guest,
  hex, or `null` on a chain without split authorisation. Set, `hc_bundle` is bundle guest v3 and a
  wallet builds v3 transactions (`nk` + salt to the bundle guest, its own auth proof over the spend
  key).
- **`rand_getTransaction`'s `bundle` gains `auth_commit`** (hex, the public `c = H(AUTH, nk, salt)`;
  zeros on a pre-v3 bundle) **and `auth_proof_bytes`** (the auth proof's length; `0` on a pre-v3
  bundle).
- **Every transaction id changes** (domain `rand-txid-3`, which binds `auth_commit` and the auth
  proof's digest), on every chain this build runs; the bundle wire gains the two fields too. This
  build therefore refuses chains 14–16 at startup and runs chain 17 on; a client that recomputes
  ids locally must move with it. New permanent refusals: `AuthUnexpected`, `AuthMissing`,
  `AuthMismatch`, `InvalidAuthProof`.
- **The `Bundle` wire changes** (a breaking change for every encoder): two fields appended after
  `proof`, `auth_commit: Word8` and `auth_proof: Vec<u8>` ("The transaction on the wire"). bincode
  is positional, so no chain-16 bundle decodes under v0.6.3, nor does a v0.6.2 node read a v0.6.3
  transaction as the one that was sent — the reason chains 14–16 are refused (`node::CHAINS_THIS_BUILD_CANNOT_RUN`).
  Without genesis `hc_auth` both fields must be zero and empty (`AuthUnexpected`); with it, every
  bundle carries an auth proof, self-proved or delegated alike (`docs/shielded.md` §2).
- **`tx_json`** — `rand_getTransaction`'s `tx` and each entry of a block's `transactions`
  (`rand_getBlockByHeight`, `rand_getBlockByHash`) — carries the bundle's `auth_commit` and `auth_proof_bytes`,
  so an explorer needs no core types to show them: randscan's `/transactions` reads bundles
  through `tx_json` (it does not vendor core) and gains `auth_commit` / `auth_proof_bytes` with no
  decoder change.
- **The delegated prover** (`docs/prover.md`, its own listener, never this RPC) gains
  `prover_info.fee` (`null`, or `{amount, address}` with the amount in RAND base units as a decimal
  string) and the error `-32006 the prover fee is not paid` on `prover_submit`; its `witness_kinds`
  always includes `viewing_key` (bundle guest v3).

### 2026-09-28 — the v0.6 switch: `hardening_v6` in `rand_getLimits` (genesis-gated; on no chain yet)

- **`rand_getLimits`** gains a seventh field, `hardening_v6`: `false` on every chain to date. `true`
  means the genesis runs the v0.6 validity rules (`docs/deploy.md`), of which one changes what a
  wallet proves: a call against a program without a public input carries the transaction's call
  binding as its public segment (INT-4), and the old, unbound proof is refused as `PublicValues`.
- **Pool refusals a submitter may now hear on every chain** (policy, never cached, never a ledger
  rule without the flag): `ProgramUncallable` for a deploy no call can hold (CPU-1), and
  `NonCanonicalProof` for a bundle or call proof whose header the honest prover would not write
  (INT-5, VERIFIER-1/-2).

### 2026-09-28 — genesis vesting (genesis-gated; on no chain yet)

- **Four bundle-less actions** — `claim_vested`, `revoke_vesting`, `bond_vested`, `unbond_vested`
  (`Action` 24–27, `docs/vesting.md`). `rand_getTransaction` renders each with its entry id (hex),
  amount as a decimal string, nonce and, for a claim or a revoke, the note's `time`; a bond adds
  the validator and whether it registers one.
- **`rand_getVesting`, `rand_getVestingSummary`, `rand_getVestingSchedule`**: an entry, the
  per-class totals, and the aggregate lockup table. `{"enabled": false}` without the section.
- **`rand_getSupply` gains `vesting_issued`, `vesting_released`, `vesting_in_register`,
  `vesting_locked`** (all `"0"` without the section); `invariant_holds` covers the register.

### 2026-09-27 — the bridge replay floor (C15-1, genesis-gated; not on chain 15)

- **`rand_getBridgeState` gains `min_inbound_sequence`**: the genesis `bridge.min_inbound_sequence`,
  an object of decimal chain ids to plain-number sequences, or `null` without one. A
  `bridge_attest` whose transfer carries a lower sequence from that chain is refused
  `BelowReplayFloor` — a permanent verdict (`rand_getTransactionStatus` reads `rejected`). Nothing
  changes on a chain whose genesis has no floor (`docs/bridge.md` §23).

### 2026-09-26 — address sharing and the encrypted memo: `envelope_bytes`, `memo` in disclosed notes

Spec `docs/superpowers/specs/2026-09-26-address-sharing-and-memo-design.md` §2.3–§2.4. Genesis-gated,
node-only otherwise; a chain without the field is unaffected.

- **`rand_getLimits`** gains a sixth field, `envelope_bytes`: `null` on every genesis without it
  (chains 14 and 15 and every earlier chain — wallets seal today's legacy 1 348-byte envelope and no memo), or `1860`
  when the genesis sets it, meaning every note-creating envelope (`Bundle.envelopes`, `Mint`,
  `Withdraw`, `BridgeAttest`, `Aggregate`, `TokenMint`, `RegisterToken`'s initial mint) must be
  exactly that long, memo field included whether or not it carries text.
- **`rand_checkTransaction`** and **`rand_getViewingNotes`**'s disclosed `note` objects gain
  `memo`: `null` for no memo or a memo field that opened malformed — a memo can be present on
  any chain, a chain without `envelope_bytes` included (its ledger accepts a 1 860-byte envelope
  up to the 2 048-byte cap; wallets only seal one where the chain sets the field), so treat it as
  untrusted text; otherwise the sender's UTF-8 text (at most 510 bytes), readable by whoever can
  already open that note — the payee, the sender's own history, or anyone handed the output's
  per-transaction key.
- A malformed envelope's memo field never costs the payee the note itself: only the memo is
  lost, not the payment.
- **The `rand` CLI (not an RPC change): one amount convention.** `rand send --asset <token>`,
  `rand token mint --amount` and `rand token burn <ASSET> <AMOUNT>` all read the amount in the
  asset's display units, at its `rand_getTokens` row's own `decimals` (RAND at nine) — the same
  units a `randpay:` link's `amount` carries. All three took whole smallest units before; a
  script passing `1000000` for one unit of a 6-decimal token now moves a million of them, so
  scale such amounts down. `send`'s confirmation prints both forms
  (`10.00000000 zUSD (1000000000 units)`).
- A non-conforming envelope size (present `envelope_bytes`, wrong length) is refused
  `TxError::EnvelopeSize { expected, got }`, a permanent verdict.

### 2026-09-25 — history pruning: `--prune-history`, `rand_status.prune_floor`, error `-32010`

A node started with `--prune-history 24h` keeps the ledger and only the last day of blocks.
`rand_status` carries `prune_floor` (0 on an archive) and `prune_history_secs` (`null` when the
node keeps everything). Height-addressed lookups below the floor answer `-32010` with the floor
in `data`; hash-addressed lookups still answer `null` for a hash the node does not hold, and only
an archive can say whether it was pruned or never existed. `rand_getTransactionStatus` adds
`floor` to an `unknown` entry on a pruned node. Wallet scanning (`rand_getCommitments`,
`rand_getNullifiers`, `rand_getWitness`) is unaffected: the notes and nullifiers families are
never pruned.

### 2026-09-25 — v0.5.6, the deep-scan release

Node-only; no wire or genesis change on chain 14 (`../security/fullnode-deep-scan-2026-09-24.md`).

- **A call proof's header is pinned before any verifier key is built** (DS-3). `Call` proofs
  above tier 14 (`MAX_CALL_TIER`), with a keccak table above 2^12 or a sha256 table above 2^13,
  with a `program_log_height` other than the deployed program's, or an `input_log_height` above
  the tier's bound are refused `invalid proof` with the reason in the message
  (`CallTierTooHigh { tier, max }` names the cap) — a permanent verdict, cached like any bad
  proof. Every call committed on chain 14 is tier 10; a tier-16 call (chain 13's ERC-20
  `approve`) is no longer admissible anywhere (`docs/confidential.md`, the call validity rules).
- **A mint or deposit at or above 2^63 is refused at admission on every chain** (DS-6):
  `TokenMint`, a `RegisterToken` initial mint and a `BridgeAttest` with such an `amount` answer
  `Token(AmountTooLarge)` / `Bridge(AmountTooLarge)` / `AmountTooLarge` before any proof is
  read, permanently. `rand_getTokens` serves `bound_note_value` (`false` on chain 14) beside
  `max_tokens` and `burn_registration_fee`.
- **Connection caps, and a `Status` from a stranger is not remembered** (DS-2, DS-5). The swarm now refuses inbound
connections past 256 established, 64 in handshake and 2 per remote peer (`docs/deploy.md`,
"Topology rules"). A gossiped `Status` is recorded only against a peer this node holds an entry
for — one it is, or was, connected to — and is metered per forwarding peer (16 back to back,
refilling at 4/s, `Ignore` over that, exactly the transaction bucket's shape), so
`rand_status.peer_count` no longer grows with the authors of relayed gossip.

### 2026-09-24 — v0.5.5

- **`tokens.burn_registration_fee` (genesis-gated, audit v5 TOK-2; not on chain 14).** Under it a
  `RegisterToken`'s or `RegisterBridgedToken`'s `registration_fee` is burned instead of paid to
  the block's proposer, who keeps `fee − registration_fee` (`docs/tokens.md` §15).
  `rand_getTokens` gains `burn_registration_fee` (a boolean, `false` on chain 14) and
  `rand_getSupply` gains `registration_fees_burned` (a decimal string, `"0"` on chain 14), which
  `invariant_holds` now subtracts on the right of the identity beside `slashed`. No wire change.
- **A committed block's certificate is stored once (node-only, audit v5 OPS-4).** No method, field or wire change. A committed block's QC now lives only in its child's `justify`
(`CF_QCS` keeps genesis' row and the head's; a v0.5.4 database is pruned once at open — audit v5
OPS-4). Every answer that carries a certificate (`rand_getBlockByHeight`/`ByHash`'s `justify_view`,
sync's `committed_block`) reads the same QC as before. What a client operator should know: **a
node rolled back below v0.5.5 needs a resync** (`docs/deploy.md`, "Roll note for v0.5.5").

### 2026-09-24 — v0.5.4

- **`rand_getSupply` gains `faucet_epoch` and `faucet_minted_in_epoch`** (decimal strings): the
  faucet's per-epoch counter under the genesis `staking` section (audit v4 STAKE-2,
  `docs/staking.md` §2). `"0"` and `"0"` on chain 14, which has no section. A `Mint` over the
  epoch's budget is refused `FaucetBudgetExhausted` — a state verdict, never cached as permanent,
  so `rand_getTransactionStatus` reads `unknown`, not `rejected`, once it leaves the pool.
- **Bridge rules v2 (genesis-gated, audit v4 BRG-14 / BR-4; not on chain 14).** Two new
  bundle-less, fee-less governance actions, `rotate_pq_guardians` and `rotate_pause_key`
  (`rand_getTransaction` kinds above; wire variants 22 and 23, appended, so every existing
  encoding is unchanged), under a PQ quorum of the current set over `M_rotate_pq` /
  `M_rotate_pause` (`docs/bridge.md` §21, byte for byte). `rand_getBridgeState` gains
  `rotation_nonce` (what the next rotation message must carry; 0 on chain 14) and `rules_v2`
  (the group's two parameters, `null` without it). Under the group the per-backing mint cap is a
  rolling window instead of a calendar day, a global cap bounds every backing together, and a
  listing is refused while minting is paused. The pool treats a rotation as governance (exempt
  from the capacity refusal, ordered first, one pooled per `rotation_nonce`).
- **`rand_getTokens` gains `max_tokens`** (audit v4 TOK-1): the genesis `tokens.max_tokens` cap
  on the registry, a number, or `null` without one (chain 14). At the cap `RegisterToken` and
  `RegisterBridgedToken` are refused `RegistryFull`. The listing now pages by range from
  `from_index` instead of scanning the registry from its first row; the reply's shape is
  otherwise unchanged.

### 2026-09-21 — wallets compute their own witnesses

Wallet-side only, no wire or node change (audit v3, PRIV-1). A wallet built from this tree no
longer calls `rand_getWitness` at all: it keeps its own copy of the commitment tree in the note
store, built during the scan from the same `rand_getCommitments` pages it already reads, and
computes every Merkle witness itself, so a node no longer learns which leaves a spend touches.
The only tree question a send still asks is `rand_getAnchor`, which names no leaf.
`rand_getWitness` / `rand_getWitnesses` stay on the node unchanged for wallets built before this
change. A note store written by an older wallet is detected on load and rescanned from leaf 0
once to build the tree.

### 2026-09-20 — witnesses are served from a cached tree

Node-side only, no client-visible change (audit v3, RPC-1). `rand_getWitness` and
`rand_getWitnesses` used to rebuild the whole commitment tree from every leaf on **every call**:
a wallet proving a two-input bundle paid for two full rebuilds, a hundred callers for a hundred.
The node now builds the tree once per change — a commit or a truncate — and serves every witness
in between from it. The concurrency cap of two rebuilds still applies, and answers are unchanged.

### 2026-09-20 — requests are metered per client address

Node-side only (audit v3, RPC-2 / decision D13). A client address gets **120 requests in a burst**,
refilling at **30 a second**; a batch spends one token per request object it carries, because a
batch is a request amplifier and the batch cap bounds one batch rather than the rate. Over the
allowance the node answers **HTTP 429** whose body is an ordinary JSON-RPC error object
(`-32000`, *"rate limited: …"*), so a client that speaks only JSON-RPC can read it. **Loopback is
exempt**, so a node's own explorer and the operator's tooling are unaffected.

This is a meter, not an authentication boundary: it bounds what one address can queue in front of
the node's other work. The expensive reads keep their own bound on top — at most two witness tree
rebuilds run at a time per node.

### 2026-09-24 — a disk guard: `rand_getHealth` says `disk_low`, `rand_status` carries the free bytes

Node-side only; no consensus, ledger or wire change (audit v4, OPS-3). Seven validators stalled
on a full disk on 2026-09-24 with nothing in their health to say so.

- **`rand_getHealth`** answers `{"status":"disk_low","free_bytes":"<bytes>"}` ahead of `ok` /
  `syncing` / `behind` while free space is under four times the startup minimum (4 GB at the
  default `--min-free-disk-mb 1024`).
- **`rand_status`** gains `disk_free_bytes` (a number, not an amount) and `disk_low`.
- The node refuses to start under the minimum itself, naming the directory and the flag.

### 2026-09-20 — the viewing-key methods are loopback-only, and a key can be removed

Node-side only; no consensus, ledger or wire change (audit v3, VK-1/2/3).

- **`rand_importViewingKey`, `rand_getViewingNotes`** now answer a loopback caller only, and
  refuse anyone else with `-32000` *"… answers loopback callers only on this node"*. Run the node
  with `--rpc-viewing-open` to restore the old behaviour, behind something that authenticates.
- **`rand_removeViewingKey(viewing_key)`**, new: gives a key back. Frees its slot at the 64-key
  cap and zeroises the key in memory.
- A scan no longer blocks the node's other work: each imported key has its own lock, so one key's
  scan does not hold up another's, an import, or the status the node publishes each round.

### 2026-09-20 — every amount is a decimal string, legacy fields included (breaking)

The one exception to the amount-is-a-string rule is gone. Every `u64` amount this RPC serves is
now a decimal string, chain state and a decoded transaction's own fields alike — see
[Conventions](#json-rpc-reference). **Breaking for a client built against the pre-chain-14 shape**:
these fields changed from JSON numbers to decimal strings, no other change to their meaning or
position:

- `bundle.fee` (`rand_getTransaction`'s `.tx`, and `rand_getBlockByHeight`/`rand_getBlockByHash`'s
  `.transactions[]`, same shape).
- `action.amount` for `kind` = `mint`, `bond`, `unbond`, `withdraw`, `bridge_attest` (same three
  methods).
- `action.amount` and `action.relayer_fee` for `kind` = `bridge_burn` (same three methods; never
  live on a bridged public chain before this change).
- `locked` in `rand_getAssets`'s rows and `rand_getBridgeState.assets[]`'s rows.

A client that reads any of these five with `.as_u64()`-style parsing must switch to parsing a
string. Every other amount this RPC serves was already a string before this change (`rand_getSupply`,
`rand_getEmission`, `rand_getValidators`, viewing notes, `unsealed.excess`, an aggregate's
`subsidy`/`proving_share`, and every RPL/bridge-hardening field). `rand_getStatus`'s
`aggregation.subsidy_base` is now a string too, for the same reason (it was the one amount this
RPC still served as a number).

### 2026-09-24 — `rand_getBlocks` pages 1024 headers; the wallet binds its store to `rand_getGenesisHash`

- **`rand_getBlocks`'s cap is 1024 headers** (`MAX_BLOCK_HEADERS`), up from the 128 it shared
  with `rand_getCompactBlocks`. A header carries no transaction, so the anchor-window reasoning
  behind the compact-block cap never applied to it; what did apply was the wallet's block walk,
  which pays a round trip per page — over a remote RPC a 240 000-block chain was ~1 900 round
  trips (about a quarter of an hour) before a first sync saw a leaf. Node-only, no wire or
  genesis change; a client asking for 1024 against an older node gets 128 and advances from the
  last height it got, as it always did.
- **The `rand` wallet now calls `rand_getGenesisHash` at the start of every scan** and binds its
  note store (`<key>.notes.json`, new `genesis` field) to the answer. A store scanned against
  another chain — a wallet file kept across a chain cut — is emptied and rescanned from leaf 0
  with a warning, instead of paging from a cursor past the new chain's tree and reporting
  `0 RAND, 0 notes`. A node without the method (before v0.3) can no longer be scanned against.
- **The `rand` wallet speaks TLS**: `--rpc https://rpc.randprotocol.org` works. It was built
  without a TLS backend and refused every https URL before connecting.

### 2026-09-20 — the token RPC and `rpl1…` token ids

- **New methods:** `rand_getTokens` (the whole registry, paged), `rand_getToken` (one token by
  index, hex or `rpl1…`) and `rand_getTokenSupply` (supply and each backing's locked amount).
  `rand_getAssets` is unchanged.
- **Token ids have a text form**, `rpl1…` (bech32m, HRP `rpl`, 62 characters): `id_text` on every
  token row, and accepted wherever a token is looked up. Hex stays accepted.
- **`rand_getTransaction`:** `token_mint` gains `r`; `register_token` gains `initial` (`{ amount,
  recipient, time, r }` or `null`). Existing fields are unchanged.
- **`rand_checkTransaction`:** also opens a `TokenMint`'s envelope (`output`: `token_mint`) and a
  registration's initial-mint envelope (`initial_mint`).
- **Pool:** two transactions at one token's `mint_nonce` (a `TokenMint` or a `SetAuthority`) or at
  one registration index conflict at submission, and one whose nonce or index the chain has
  already moved past is refused (`wrong mint nonce`, `wrong token index`) and pruned.

### 2026-09-19 — chain 14: the deposit blinding is derived, not chosen (F1)

A `BridgeAttest`'s `r` is no longer the submitter's to pick. Admission now requires
`r == blake3("rand-deposit-r-1" ‖ mu)`, where `mu` is the digest the guardians signed, and refuses
any other value with a new, **permanent** refusal, `BridgeError::WrongDepositBlinding` — cached
like every byte-level refusal, so a relayer built against the old free-`r` behaviour gets refused
once and then silently ignored on every retry rather than told again. `time` is unaffected and
stays the submitter's choice, inside the usual window. The upside: two independent submitters of
the same attestation at the same `time` now name the identical note, closing the substitution this
review round found (`docs/bridge.md` §5).

### 2026-09-19 — bridged tokens listed after genesis (bridge hardening B4, chain 14)

- Two actions, each on a RAND fee bundle its submitter pays and each authorised by a PQ guardian
  quorum: `register_bridged_token` (`name`, `symbol`, `salt`, the first backing's `chain`, `token`
  and source `decimals`, `nonce`, `asset_id`, `pq_signers`) — a new `Bridge`-authority token at the
  next index, eight decimals on Rand, under the genesis `mint_cap_per_day`; its fee owes the bundle
  base plus `registration_fee` — and `list_backing` (`token_index`, `chain`, `token`, `decimals`,
  `nonce`, `pq_signers`), owing the base. The quorum signs `M_register` / `M_list` (fixed
  big-endian layouts, `docs/superpowers/specs/2026-09-19-bridge-hardening-design.md` §9) at the
  bridge's `list_nonce`, which both bump.
- `rand_getBridgeState` gains `registration_fee` and **drops `next_index`**: a bridged token is
  listed (under an index its registration already fixed) before it can ever be deposited, so there
  is no index left to predict. A wallet or an explorer reads a listed token's index off `assets`
  (`rand_getAssets`) or `rand_getTokens` instead.
- New refusals, none cached: `wrong list nonce` (`BadListNonce`), `chain N has no registered
  emitter` (`NoEmitter`), and the registry's own (`BackingTaken`, `AlreadyRegistered`,
  `TooManyBackings`, `BadBackingDecimals`, `RegistrationFeeTooLow`, …) under `bridge: `.

### 2026-09-19 — the mint cap and the mint pause (bridge hardening B1, chain 14)

- `rand_getBridgeState` gains `mint_paused`, `pause_nonce`, `list_nonce` and `pause_key` (hex).
- `rand_getAssets` rows (and `rand_getBridgeState.assets`) gain `mint_cap_per_day`,
  `minted_today` and `mint_day`.
- Two bundle-less, fee-less actions: `pause_mints` (`{ "kind": "pause_mints", "nonce" }`, the
  genesis pause key's signature over `b"rand-bridge-pause-1" ‖ chain_id u64 BE ‖ nonce u64 BE`) and
  `unpause_mints` (`{ "kind": "unpause_mints", "nonce", "pq_signers" }`, a PQ guardian quorum over
  `b"rand-bridge-pq-unpause-1" ‖ chain_id ‖ nonce`). Both carry the bridge's `pause_nonce` and bump
  it; the pause key can never unpause.
- New refusals, not cached (state, not bytes): `bridge minting is paused` (`MintsPaused`) on a
  transfer attest while paused; `mint cap … per backing per day` (`MintCapExceeded`); and the
  pause's own `already paused`, `not paused`, `wrong pause nonce`. `the pause signature does not
  verify` **is** cached as a permanent refusal: it is judged after the nonce, over the
  transaction's own nonce and chain id under the genesis pause key, so it depends on the bytes
  alone — and a bundle-less, fee-less pause should not buy a free Dilithium2 verification per
  replay.

### 2026-09-19 — the hidden-asset bundle (chain 14): a hard fork

One bundle moves any asset and nobody without a key can tell which
(`docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md`). The bundle's wire format, the
bundle guest (`hc_bundle`) and every transaction id change; chain 14 only.

- **Four slots.** A bundle carries four nullifiers, four commitments and four envelopes, dummies
  included. `rand_getTransaction`/`rand_getBlockByHeight`'s `bundle.nullifiers`, `commitments`
  and `envelope_len` have four elements; `rand_getCompactBlocks` lists four notes and four
  nullifiers per bundle; the tree and the nullifier set grow by four per bundle.
- **No `asset`, three burn fields.** `bundle.burn` and `bundle.asset` are gone; `bundle.burn_a`,
  `burn_r` and `burn_asset` replace them (see `rand_getTransaction`). A transfer of any asset is
  `"kind": "none"`: the `token_transfer` kind and `Action::TokenTransfer` no longer exist.
- **One bundle per transaction.** `bridge_burn` has no `asset_bundle`; `token_burn` burns through
  the bundle's `burn_a`/`burn_asset`. New refusals: `the bundle burns asset {n} on an action that
  burns no token`, `a burn of {n} is not allowed on this action`, `RAND burned through burn_a
  ({n}); a RAND burn goes through burn_r`.
- **`rand_checkTransaction`**: `output` is `bundle:0` … `bundle:3`; `asset_bundle:*` is gone.
- **`rand_sendTransaction`'s body cap** counts four envelopes: 8 867 840 bytes on a default chain.

### 2026-09-19 — audit v3: the faucet mint's opening, a witness-build cap

A hard fork (the `Mint` wire format), for the next chain cut; nothing else in this list changes a
format.

- **`Action::Mint`** gains the note's opening, `pk`, `time` and `r`. Admission refuses a `cm` that is
  not the commitment of `(pk, no sender, amount, native asset, time, r)` with *"the mint's
  commitment does not open to its published note and amount"*, and holds `time` to the bundle
  window. The minter signs under the domain `rand-mint-2` over all seven fields. A faucet note's
  owner is therefore public, as a withdraw's payout is. `rand_mint`'s parameters are unchanged.
- **`rand_getWitness` / `rand_getWitnesses`** run at most two tree rebuilds at a time per node. A
  request that waits more than 10 s for a slot is refused with `-32000` *"witness builds are busy
  on this node; retry shortly"*.

### 2026-09-19 — call limits: two methods, new fields, limits from the genesis

For the chain cut that sets the call-limit genesis fields (`max_proof_bytes`, `max_block_bytes`,
`max_call_envelope_bytes`, `max_program_public_words`). A default chain's answers are unchanged,
apart from the new fields. Changes:

- **`rand_getLimits`**, new: the chain's five limits at the time, so wallets stop hard-coding them
  (a sixth, `envelope_bytes`, follows in the 2026-09-26 entry below).
- **`rand_getProgramPublic(program_id)`**, new: a program's deploy-time public words, as hex of
  their little-endian bytes. It returns `""` for a program without a public input.
- **`rand_getProgram`** adds `public_words_len` and `public_digest`, which is `null` without a public
  input.
- **Receipts** (`rand_getReceipt`, `rand_getReceipts`, the `receipts` topic) add `h_pub`. It is
  `null` when the proof was checked against the empty public input.
- **`rand_getTransaction`** and the blocks: a deploy action adds `public_words_len`.
- **`rand_estimateFee`** takes `public_words` for a deploy and `bytes` for a call. Both are
  optional and default to 0, so old callers get the old answers.
- **Limits from the genesis.** The request-body limit and `rand_sendTransaction`'s block-size
  pre-check now come from the genesis. So do the node's sync budget (`max_block_bytes + 2 MiB`)
  and its gossip transmit size (`max(16 MiB, max_block_bytes + 1 MiB)`). On a default chain they
  are the old constants.

### 2026-09-18 — for the v0.4 chain: the program cap is a genesis parameter

A genesis file may set `max_program_words` (`1..=65535`); absent, the cap stays 4096 words and the
genesis hash is unchanged, so running chains (chain 12) see no difference. `rand_estimateFee` for a
deploy now refuses past the chain's cap rather than the constant, with the cap in the message.
No method, parameter or result shape changed. (The v0.3 entry below is the RPC release; this one
lands after it and takes effect on the chain cut that sets the field.)

### 2026-09-18 — v0.3: eleven methods and two WebSocket topics

No wire, consensus or genesis change: old and new nodes interoperate on the wire, and the fleet
takes this as a same-chain update (`deploy/update-droplet.sh`), not a chain cut. The database is
forward-only, though, unless `rand-node db drop-receipts-index` is run before downgrading (see
**Storage** below). What a client can see:

- **Node identity and health** — `rand_getVersion` (crate version, full git sha, chain id,
  `hc_bundle`, FRI profile), `rand_getGenesisHash`, `rand_getHealth` (`ok` / `syncing` / `behind`).
- **`rand_getTransactionStatus(hashes)`** — up to 64 hashes at once, each `committed` / `pending`
  / `rejected` (with the refusal reason) / `unknown`. `randprotocol_client::wait_for_transaction`
  now uses it and fails fast on `rejected`, falling back to its old polling loop against a node
  older than this release.
- **`rand_getReceipts(program_id, from_height, to_height, limit?)`** — a program's receipts over a
  height range, paged with a soft-floor `limit` (default and cap 256) that never splits a height.
- **`rand_getWitnesses(indices)`** — `rand_getWitness` folded over up to 32 leaves in one tree
  build.
- **`rand_getBlocks(from_height, to_height)`** — up to 128 headers (1024 since 2026-09-24),
  `rand_getBlockByHeight`'s fields minus `transactions`.
- **`rand_getFinality(height_or_hash)`** — `committed` / `certified` / `proposed` / `unknown`
  from the replica's own HotStuff tree and quorum certificates.
- **`rand_getProposer(view)` or `(from_view, to_view)`** — the leader per view under the
  *current* validator set, at most 64 views per call.
- **`rand_getMempoolInfo`** — pool count, byte total, and the oldest pooled transaction's age.
- **`rand_getEmission`** — a fixed `"0"` inflation, the block-aggregation subsidy schedule
  (`null` without an `aggregation` genesis section, which chain 12 lacks), and the faucet flag.
- **Two new WebSocket topics**, `receipts [program_id]` and `transaction <hash>`, beside
  `newHeads`: see [Subscriptions](#subscriptions-websocket) for their shapes, the once-then-gone
  behaviour of `transaction`, and why a lag on one topic's channel no longer closes a connection
  that does not listen to it.

**Storage.** First start of a node running this release builds a new `receipts_by_program` index
from the existing `receipts` family, once — the fleet's 22 000-odd receipts take under a second;
an empty node is a no-op. `rand_getReceipts` and the `receipts` topic read this index; nothing
else about how receipts are stored changed. The new column family is also what makes the database
forward-only: a pre-v0.3 binary refuses to open it until `rand-node db drop-receipts-index
--datadir <dir>` (run with this release, node stopped) drops the family and its built marker —
the rollback procedure is in `deploy/README.md`, "Rolling back v0.3".

### 2026-09-15 — block aggregation (chain 9): a hard fork

**The wire format, block rules and consensus change: this is a hard fork, not an
interop-compatible hardening.** A chain whose genesis carries an `aggregation` section admits
five new transaction actions — `RegisterAggregator`, `UnbondAggregator`, `WithdrawAggregator`,
`SlashAggregator` and the `Aggregate` itself — prunes sealed bundle proofs, and serves a second
block form on sync. Chains without the section behave byte-for-byte as before. What a client can
see:

- **`rand_submitAggregate`** is `rand_sendTransaction`: an `Aggregate` is an ordinary
  bundle-less transaction, admitted on the same queue (its rVM verification occupies a worker
  slot far longer than a bundle's ~20 ms, which the queue and the per-peer token bucket already
  bound).
- **`rand_getBlockByHeight` / `rand_getBlockByHash`** gain `sealed` (every bundle in the
  block covered) and a per-transaction `sealed_by` (the covering aggregate's hash, `null` while
  the bundle is coverable or the transaction is bundle-less).
- **`rand_getAggregate(hash)`** returns the sealing aggregate's public fields: `covers`
  (hashes, in proof order), `aggregator`, `subsidy`, `proving_share`, and `n` — the subsidy
  schedule's index the block minted at — plus its `height`. `null` for any other transaction.
  `subsidy` is what the aggregate minted: `subsidy(n)`, or under the genesis
  `fees.subsidy_net_of_fees` its shortfall over `proving_share` (`docs/fees.md` §1.3), so
  `subsidy + proving_share` is always the payout note's amount. All three numbers are the
  payment the ledger made while applying the aggregate, stored as it committed — not recomputed
  from the database, which on a node syncing several blocks in one commit missed a cover
  committed in the same batch (fee feedback, 2026-10-05).
- **`rand_getAggregators`** lists the register (public by design): `address`, `bond`,
  `payout`, `nonce`, `unbonding` per row.
- **`rand_getUnsealed(from, limit)`** pages the bundles an aggregator may still cover —
  finalised, inside the window, unsealed — as `{ bundles: [{ hash, height, excess }], next_from }`,
  `excess` in units over the floor: the daemon's work list. Since 2026-09-28 (IFACE-7) `excess`
  is the ledger's own bucket entry — under `tokens.burn_registration_fee` a token registration's
  is `fee − registration_fee − BUNDLE_BASE`, not `fee − BUNDLE_BASE` — and a bundle with no
  bucket entry is not listed; `rand_getAggregate`'s `proving_share` is summed the same way.
- **`rand_getRawTransaction(hash)`** returns the full transaction, bincode as hex — the proof
  bytes an aggregator needs and `tx_json` deliberately never renders.
- **`rand_getSupply`** gains the four counters `subsidised`, `sealed_blocks`,
  `aggregator_bonds`, `slashed` (reported separately from `faucet_minted`, so the schedule is
  auditable against `sealed_blocks` directly).
- **`rand_status` gains `aggregation`**: `registered`, `unsealed`, `verify_queue`, and the
  chain parameters an aggregate daemon computes the payment from (`max_covers`, `window`,
  `subsidy_base`, `halving_blocks`, `sealed_blocks`). `subsidy_base` is a decimal string, like
  every other amount this RPC serves (2026-09-20); the rest of this object is plain integers.
- **`tx_json`** renders the five new actions (`register_aggregator`, `unbond_aggregator`,
  `withdraw_aggregator`, `slash_aggregator`, `aggregate`) with their public fields.
- The node CLI gains the role's commands: **`rand-node aggregator register|unbond|withdraw`**
  (the validator commands' twins, one register over) and **`rand-node aggregate [--watch]`**,
  the aggregate daemon: poll `rand_getUnsealed`, fetch the raw bundles, prove one aggregate,
  submit — a separate process from the validator, needing only an RPC endpoint and the
  registered key. `--keep-raw-proofs` keeps sealed bundles' raw proofs for archives; by default
  the pruning pass rewrites their records once the window passes.

### 2026-09-14 — viewing keys in the node

A node may now hold **viewing keys** (never spend keys — the RPC layer has no type for those) and
scan on the holder's behalf, the Zcash `z_importviewingkey` shape for explorers. Keys are held in
memory only: at most 64 per node, cleared at restart, re-imported by the operator. No wire format,
block or consensus rule changed.

- **`rand_importViewingKey(viewing_key, [rescan_from_height])`** registers the party viewing
  key's `nk` (64 hex); re-import of a held key is a no-op. `rand_status` gains `viewing_keys`.
- **`rand_getViewingNotes(viewing_key, [from_index, limit])`** lazily scans from the rescan
  floor (at most 10 000 leaves per call, with `scanned_index`/`next_index`/`complete` for
  progress) and pages matched notes — received rows with their nullifier and spent state, sent
  rows (opened through `ovk`) without.
- **`rand_checkTransaction(hash, key)`** is the Monero `check_tx_proof` shape: stateless, one
  call, no key retention — what the given per-transaction `TxKey` discloses about the committed
  transaction, each opened note bound to its on-chain commitment by the AEAD. A wrong key returns
  an empty `disclosed` list, indistinguishable from a transaction that discloses nothing.

### 2026-09-14 — RPC hardening

No wire format, block or consensus rule changed: old and new nodes interoperate, and a fleet
upgrades by ordinary restart. What a client can see:

- **`rand_getCompactBlocks(from_height, to_height)`** is new: per block its height, hash and
  timestamp, and per transaction the note commitments it created (leaf index, commitment, envelope)
  and the nullifiers it spent. At most 128 blocks per call and, past the first block — which is
  always served whole — 1000 notes; resume from the last returned height plus one. This is the
  one-round-trip note stream a light wallet syncs with.
- **Batch requests** are new: a POST body may be an array of at most 20 request objects, answered
  as an array of the same length in request order. A request object with no `id` member — a
  JSON-RPC notification — is refused with `-32600`, batched or not; an explicit `"id": null` is
  still a normal request.
- **A WebSocket endpoint on the same port** (`/` and `/ws`) is new, serving one subscription,
  `newHeads`, through `rand_subscribe` / `rand_unsubscribe`: one notification per committed
  block, in order, in `rand_getHead`'s shape. Bounded — 64 connections per node, 8 subscriptions
  per connection, 64 KiB per client frame, 256 heads of backlog — and a subscriber that falls
  further behind than that is closed (code `1008`), not buffered; the recovery is to reconnect and
  fill the gap with `rand_getCompactBlocks`.
- **`rand_status` gains three fields**: `ws_clients`, `refused_cache` and `verify_queue`, beside
  the four sync fields (`sync_inflight_age_ms`, `sync_failures`, `sync_late_batches`,
  `connected_peers`), which are unchanged.
- **`-32600` is newly documented, not new**: it already answered an oversized or unparseable body,
  and now also covers the malformed-batch shapes and notifications.
- **The one behaviour change an existing client can notice**: a transaction submitted over RPC is
  answered after its proof has verified on a worker rather than on the consensus loop, so the reply
  can take a few hundred milliseconds longer under load. The error messages are unchanged.

