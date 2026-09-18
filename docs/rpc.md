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
- Amounts are strings of smallest units (`"1500000000"` = 1.5 RAND); 1 RAND = 10^9 units.
  Amounts *inside a decoded transaction* are JSON integers instead — a bundle's `fee` and `burn`, a
  mint's amount, a staking action's amount — because they are being reported as the transaction's own
  fields rather than as chain state.
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
and the transaction names 1`, `the burn's asset bundle burns 399, not the 400 the action sends`.

Acceptance is not commitment: poll `rand_getTransaction` until it returns a block.

A transaction larger than the chain's block cap (`max_block_bytes` from `rand_getLimits`; 4 MiB by
default) is refused here with `-32000`, naming both sizes, before it reaches the mempool. The
request body itself is capped at `2 × (2 × max_proof_bytes + 2 × 2048 + max_call_envelope_bytes +
16 384 + 64 KiB) + 256 KiB` — 8 859 648 bytes on a default chain — computed from the genesis at
startup; a body over it is `-32600` naming the limit.

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
        "nullifiers": ["8c04…d1", "5e77…20"] } ] } ]
```

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

Errors: `-32602` for a malformed key.

### `rand_getViewingNotes`
Params: `[viewing_key]` or `[viewing_key, from_index, limit]` — `from_index` pages the matched
notes by leaf index (default 0), `limit` caps the page (default and maximum 1000, as everywhere).
Result:

```json
{ "scanned_index": 10041, "next_index": 10041, "complete": true,
  "notes": [
    { "index": 40, "cm": "2a9f…07", "height": 37, "role": "received",
      "note": { "pk": "…", "from": "…", "amount": "1500000000", "asset": 0, "time": 5 },
      "nullifier": "8c04…d1", "spent": false },
    { "index": 43, "cm": "b310…88", "height": 39, "role": "sent",
      "note": { "pk": "…", "from": "…", "amount": "25000000", "asset": 0, "time": 9 },
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
everywhere chain state is served.

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

### `rand_getLimits`
Params: `[]`. Result: the chain's five call limits, from its genesis:

```json
{ "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
  "max_call_envelope_bytes": 18432, "max_program_public_words": 0 }
```

Those are the defaults, what a genesis without the fields gets (chain 12). A wallet derives its caps
from these instead of hard-coding them: the most words a program may have, the largest proof, the
largest transaction (a block's worth), the largest call-input envelope, and the most public words a
deploy may carry.

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
`{"kind":"call","tier":t,"bytes":b}` (`t` one of 10, 12, 14, 16, 18, 20). Result: the minimum fee
in units, as a string. `{"kind":"bundle"}` is the floor for a plain transfer: `1000000`. A deploy of
more words than the chain's program cap (4096, or the genesis file's `max_program_words`) is an
invalid-params error (`-32602`) naming the cap — the same program admission would refuse, so a
wallet can ask before it proves.

`public_words` (optional, default 0) is the deploy's public input length. Public words are paid for
per word like code, so the fee is the deploy fee of `n + m` words. More than the chain's
`max_program_public_words` (0 by default) is `-32602`, naming the cap, in the same shape.
Anything but a non-negative integer (or `null`) is `-32602` as well.

`bytes` (optional, default 0) is the call's proof length plus its input envelope's length. A call
at or under the free allowance (2 097 152 + 18 432 bytes) costs what it did before this field
existed; each KiB over it, a partial KiB counting as whole, adds 1000 units. Without `bytes` the
answer is the old one. Anything but a non-negative integer is `-32602`.

### `rand_getTransaction`
Params: `[hash]`. Result: `null` until committed, then:

```json
{
  "height": 192, "index": 0, "block_hash": "63f6…08",
  "tx": {
    "hash": "4f2c…e7", "chain_id": 7,
    "bundle": {
      "anchor": "6b1d…c4",
      "nullifiers": ["8c04…d1", "5e77…20"],
      "commitments": ["2a9f…07", "b310…88"],
      "fee": 1000000, "burn": 0, "asset": 0, "time": 5,
      "proof_len": 302857, "envelope_len": [1348, 1348]
    },
    "action": { "kind": "none" }
  }
}
```

`bundle` is `null` on a mint (a mint carries no bundle). The proof and the envelopes are reported
by length only; anyone who wants the bytes can fetch the block. Other actions:

- `{ "kind": "mint", "cm": "…", "amount": 100000000000, "minter": "<validator base58>" }`
- `{ "kind": "deploy", "program": "<program id>", "words": 412, "public_words_len": 0 }`
- `{ "kind": "call", "program": "<program id>", "proof_len": 268123, "input_envelope_len": 1280 }`

`public_words_len` is the length of the deploy-time public input; the words are
`rand_getProgramPublic`'s once the deploy commits.

`input_envelope_len` is the size of the call's encrypted input transcript, or `null` when the call
carries none. Like every other envelope it is reported by length alone: the transcript opens for
the caller's viewing key and the auditor, not for whoever is reading the explorer.

The staking (phase S2) and bridge (phase S3) actions:

- `{ "kind": "bond", "validator": "<base58>", "amount": 500, "registered": false }` — `registered`
  is whether this bond carried a first-time registration.
- `{ "kind": "unbond", "validator": "<base58>", "amount": 7, "nonce": 2 }` — rendered with
  `"bundle": null`, as a withdraw is: both are signed by the validator's key, and the register's
  nonce, not a bundle, is what keeps them from being replayed.
- `{ "kind": "withdraw", "validator": "<base58>", "amount": 9, "nonce": 3, "time": 1994 }` — the
  deposit note's blinding and envelope are not rendered. `time` is the note's time word, which the
  withdrawing node chose; the note itself is worth `amount` less the bundle base.
- `{ "kind": "bridge_attest", "attestation_len": 520, "recipient": "<shielded address>",
  "asset": 1, "asset_index": 1, "amount": 1000, "time": 41, "r": "<64 hex>",
  "commitment": "<64 hex>" }` — the amount and the asset are
  inside the attestation, so they are decoded out of it; `asset_index` is what the registry gave
  that asset, and is the `asset` word of the deposit note. Both are `null` for a guardian-set
  rotation (which deposits nothing) and on a chain whose registry does not name the asset.
  `asset` is the index the *action* names, and on a committed attest it always equals
  `asset_index` — admission refuses a transaction where they differ — but it is never `null`, so
  the two together say whether this node's registry can resolve the deposit at all. `time` is the
  deposit note's own `time` word, which the action publishes and admission holds to the window a
  bundle's `time` gets — the note is derived from it, not from the height the transaction landed
  at. `r` is the deposit note's blinding, a field of the action and public like the rest of it, and
  `commitment` is the leaf the chain computed from those five fields and appended — `null` for a
  rotation. Together they are the whole deposit note, which is what lets its recipient rebuild it
  without opening the submitter's envelope (`docs/bridge.md` §8); a transfer's or a withdrawal's
  blinding is *not* rendered, because those notes are not public.
- `{ "kind": "bridge_burn", "asset": 2, "amount": 400, "relayer_fee": 100, "to_chain": 5, "to":
  "abab…", "asset_bundle": { …same shape as `bundle`… } }` — `to` is the 32-byte destination
  address, hex. The asset bundle renders exactly like the fee bundle: same public fields, no more.

No reply from this method carries the sender, recipient, nonce or amount of a *transfer*: no such
field exists in a stored transfer. The staking and bridge actions above are the deliberate
exception — a validator address, an amount and a replay nonce are public in them by design, the
way a mint's amount is, because the validator register and the bridge's accounting are public
(spec §8). A shielded note's later spend stays private in every case.

### `rand_checkTransaction`
Params: `[hash, key]`, where `key` is a per-transaction `TxKey` as 64 hex characters. Result:
`null` for a hash this node has no committed transaction for, else what the key discloses about
it:

```json
{ "tx": "4f2c…e7", "height": 192,
  "disclosed": [
    { "output": "bundle:0", "cm": "2a9f…07", "index": 40,
      "note": { "pk": "…", "from": "…", "amount": "1500000000", "asset": 0, "time": 5 } }
  ] }
```

Monero's `check_tx_proof` shape (`docs/rpc-comparison.md` §4): a sender who sealed an output with
a fresh `TxKey` can hand `(hash, key)` to anyone — a recipient proving they were paid, an auditor
checking a claim — and this call is the whole verification. Each entry of `disclosed` is one
envelope the key opened: `output` names the envelope set (`bundle:0` / `bundle:1` for the
transaction's own bundle — the fee bundle of a `BridgeBurn` — `asset_bundle:0` / `asset_bundle:1`
for a burn's second bundle, `deposit` for a `BridgeAttest`'s deposit envelope, `mint:0` for a
faucet mint's one envelope), `cm` the on-chain
commitment the note commits to, and `index` its leaf. The binding is the proof: the AEAD
authenticates the note *and* checks it against `cm`, so a key lifted onto another transaction —
or a note that is not the commitment's preimage — yields an empty list, never a forged row. A
withdraw's and a genesis alloc's envelopes are not tried: they are sealed inside the node under
keys dropped at once, so no `TxKey` for them can exist. A mint's is sealed the same way, but its
recipient recovers the key through the envelope's KEM half (`rand tx-key`), so a mint is tried.

The call is **stateless**: the key is used for this one request and dropped — it is not imported,
stored, or learnable from anything the node keeps (unlike `rand_importViewingKey`, which
retains). A key that opens nothing gets `{ "disclosed": [] }`, indistinguishable from a wrong key
by design. Amounts are strings, as everywhere chain state is served.

Errors: `-32602` for a malformed hash or key (both are parsed before any storage read).

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
  "peer_count": 5, "connected_peers": 5, "ws_clients": 3, "refused_cache": 0,
  "verify_queue": 0, "mempool_size": 0,
  "is_validator": true, "active_validator": true, "faucet": true, "confidential": true,
  "fri_profile": "production", "programs": 2, "viewing_keys": 0,
  "notes": 41, "nullifiers": 12, "tree_root": "6b1d…c4", "hc_bundle": "f07a…19",
  "address": "2nRdFC…", "peer_id": "12D3KooW..."
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
  blocks. `peer_count` counts every peer this node knows of, including those seen only as the author
  of relayed gossip, so `peer_count` far above `connected_peers` means most of what this node knows
  about the network is hearsay.
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
build disagrees with the genesis value refuses to start at all.

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
  "burn_sequence": 1,                    // outbound messages emitted so far
  "next_index": 2,                       // the note index the next newly registered asset gets
  "assets": [ …the rows of `rand_getAssets`… ]
}
```
No balances: bridged value is notes, not accounts.

### `rand_getAssets`
Params: `[]`. Result: the bridge's asset registry, ascending by index (which is registration
order), or `[]` on a chain without a bridge:
```json
[{ "index": 1, "chain": 2, "token": "aaaa…", "asset_id": "…" }]
```
`index` is the `asset` word a note of that asset carries — index 0 is RAND and is never in the
registry. `chain` and `token` are the wire identity guardians sign about; `asset_id` is
`blake3` of the two, and is what `rand_bridgeAssetId` computes.

### `rand_bridgeAssetId`
Params: `[token_chain, token_address]` where `token_chain` is an integer and `token_address` is
32 bytes of hex. Result: the asset id (64 hex characters). Pure arithmetic on its arguments, so
it answers on any chain, bridged or not.

### `rand_getBridgeBurn`
Params: `[sequence]` (integer). Result: `null` if this chain has emitted no such message, else
```json
{ "sequence": 0, "body_hex": "…", "digest": "…", "tx": "…", "height": 2 }
```
`body_hex` is the outbound message as guardians must hash and sign it; `digest` is its hash.
`tx` is the burn transaction that emitted it — a burn is funded by notes, so the transaction
hash stands in for the sender identity the message has no room for.

### `rand_getValidators`
Params: `[]`. Result: array of

```json
{ "address": "…", "stake": "1000000000000", "pending": [{ "release_epoch": 41, "amount": "5000000000" }],
  "rewards": "4000000", "payout": "rand1…", "nonce": 3, "active": true }
```

one row per entry of the **register** (spec §8), in address order. Since phase S2 that is every
validator that has ever bonded, not the genesis set: `active` is the ones in the set running the
current epoch, and those are what the leader rotation runs over. Amounts are **decimal strings**,
because a JSON number is not an exact integer past 2^53 and a stake is 10^9 units per RAND.
`pending` is the unbonding queue, oldest first; `rewards` is the bundle fees credited to that
validator as proposer; `payout` is where a `Withdraw` pays; `nonce` is what its next signed
`Unbond` or `Withdraw` must carry. The register is the only place this chain stores amounts in the
clear — `docs/staking.md` is the guide to it.

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
  "withdraw_deposited": "…", "fees_paid": "…", "burned": "…",
  "pool_value": "…", "register_total": "…", "total_supply": "…", "invariant_holds": true }
```

The supply audit. Note values are hidden, but every crossing of the pool's boundary is public, so
these are exact: value enters the pool as a genesis deposit, a faucet mint or a validator's
withdraw, and leaves it as a bundle fee (into a proposer's `rewards`) or a burn (a `Bond`, into
`stake`). A withdraw's own base fee is not a crossing: `withdraw_deposited` counts the note it
created (`amount` less the base), and the base moves from one register entry to another.
`pool_value = genesis_deposited + faucet_minted + withdraw_deposited − fees_paid −
burned`; `register_total` is Σ `stake + pending + rewards` over the register; `total_supply` is the
two together, and `invariant_holds` is whether it still equals everything the chain issued
(`genesis_deposited + genesis_staked + faucet_minted`). A false there is a bug, never a legitimate
chain state. The counters are not in the state root — `rand-node verify --mode quick` recomputes
every one of them by replaying the chain, which is what makes them auditable. `docs/supply.md`
works the identity through a bond and a withdraw and says where it rests on a claim (the genesis
file's own amounts) rather than on a check.

### `rand_getVersion`
Params: `[]`. Result:
```json
{ "version": "0.1.0", "git_sha": "c66e6b8…", "chain_id": 12, "hc_bundle": "f07a…19",
  "fri_profile": "production" }
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
{ "status": "ok" }
{ "status": "syncing", "behind": 412 }
{ "status": "behind", "behind": 30 }
```
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
Params: `[from_height, to_height]`. Result: a list of headers, oldest first, at most 128 (the
compact-block cap) starting at `from_height`:
```json
[ { "hash": "647b…", "height": 50, "view": 92, "parent": "2d41…", "proposer": "3v3VBJ…",
    "timestamp_ms": 1788000123456, "tx_root": "0000…", "state_root": "a1b2…",
    "justify_view": 91, "sealed": true, "tx_count": 0 } ]
```
The same header fields as `rand_getBlockByHeight` / `rand_getBlockByHash`, minus `transactions` —
the block list a client pages through without paying for every transaction in it; those two serve
the transactions. A range wider than 128, or past the head, is truncated, not refused.

Errors: `-32602` for `to_height` below `from_height`.

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
longest-pooled transaction has waited, `null` when the pool is empty.

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
genesis carries no `aggregation` section, which chain 12 does not. `faucet` mirrors `rand_status`'s
field of the same name.

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

Bundle {
  anchor: Word8, nullifiers: [Word8; 2], commitments: [Word8; 2],
  fee: u64, burn: u64, asset: u32, time: u32,
  envelopes: [Envelope; 2], proof: Vec<u8>,     // postcard(rand_zkvm::Proof) of the bundle guest
}
Envelope { kem_ct: Vec<u8>, to_receiver: Vec<u8>, to_sender: Vec<u8>, body: Vec<u8> }

Action::None                                            // a plain shielded transfer
Action::Mint { cm: Word8, envelope: Envelope, amount: u64, minter: PublicKey, signature: Signature }
Action::Deploy { base_pc: u32, words: Vec<u32> }
Action::Call { program: Hash, proof: Vec<u8>,           // postcard(rand_zkvm::Proof)
               input_envelope: Option<CallEnvelope> }
Action::Bond { validator: Address, amount: u64, registration: Option<Registration> }
Action::Unbond { validator: Address, amount: u64, nonce: u64, signature: Signature }
Action::Withdraw { validator: Address, amount: u64, nonce: u64, time: u32, r: Word8,
                   envelope: Envelope, signature: Signature }
Action::BridgeAttest { attestation: Vec<u8>, recipient: ShieldedAddress, r: Word8, time: u32,
                       asset: u32, envelope: Envelope }
Action::BridgeBurn { asset_bundle: Bundle, asset: u32, amount: u64, relayer_fee: u64,
                     to_chain: u16, to: [u8; 32] }

Registration { public_key: PublicKey, payout: ShieldedAddress, signature: Signature }
```

A `Bond` must carry a bundle whose `burn` equals its `amount` — that is how the stake leaves the
pool — and `registration` is present exactly when the validator is not in the register yet
(`docs/staking.md`).

A `BridgeBurn` is the chain's one two-bundle transaction: the outer `bundle` pays the RAND fee
(the bundle base twice, once per verified bundle) and `asset_bundle` burns exactly `amount`
of the bridged asset. A `BridgeAttest`'s deposit note is the one commitment the wire does not
carry — the chain computes it from the amount the guardians signed, the recipient the action
names, its blinding `r`, its `time` and the registry index it names in `asset`, so a submitter
cannot choose the amount or the owner. It *can* choose `time`, within the window a bundle's `time`
gets, which is what lets the depositor seal an envelope for a note whose commitment it can compute
before knowing which block will take the transaction. `asset` is the other half of that: the index
the envelope was sealed for, which admission compares against the index the registry resolves (an
existing asset's, or the one this transaction's own registration would assign) and refuses on a
mismatch — `the attestation deposits under asset 2, and the transaction names 1`. Only a *first*
sighting can hit that, and only by losing a race to another first sighting, which costs the
submitter a fee bundle and a re-proof instead of depositing a note its recipient cannot open.

A `Withdraw` derives its note the same way and for the same reason: `time` is the head height when
the command ran, and the chain, not the wire, computes the commitment (`docs/staking.md`).

Encoded sizes (bincode's default configuration: fixed-width integers, 8-byte length prefixes,
`u32` enum tags):

| part | bytes |
|---|---|
| `Word8` | 32 |
| one `Envelope` | 1380 (1088-byte ML-KEM-768 ciphertext, two 60-byte wrapped transaction keys, a 140-byte sealed note, four length prefixes) |
| `Bundle` minus the proof | 2952 |
| transfer transaction minus the proof | 2965 |
| deploy transaction minus both proofs, 100-word program | 3377 |
| call transaction minus both proofs | 3005 |
| mint transaction (no bundle) | 5181 (a 1312-byte Dilithium2 key and a 2420-byte signature) |
| bundle proof | 302,857 measured at tier 14 under the `test` FRI profile |

So a shielded transfer on the wire is about 1.3 MB at constraint set 5's 80-query profile,
essentially all proof (it was ~300 KB at 27 queries). The ledger caps a proof at 2 MiB, an envelope
at 2048 bytes, a program at 4096 words (or the genesis file's `max_program_words`, at most 65 535),
and a block at 4 MiB of transaction bytes — three bundles
per block (`docs/block-space.md`).

A wallet builds all of this through `randprotocol_client::wallet::{send, submit}`, which selects the
inputs, fetches the anchor and the witnesses, proves the bundle, seals both envelopes, and checks
the proof's published digest against the one it computed before it submits anything.

## Changelog

What changed for clients, in one place. Newest first.

### 2026-09-19 — call limits: two methods, new fields, limits from the genesis

For the chain cut that sets the call-limit genesis fields (`max_proof_bytes`, `max_block_bytes`,
`max_call_envelope_bytes`, `max_program_public_words`). A default chain's answers are unchanged,
apart from the new fields. Changes:

- **`rand_getLimits`**, new: the chain's five limits, so wallets stop hard-coding them.
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
- **`rand_getBlocks(from_height, to_height)`** — up to 128 headers, `rand_getBlockByHeight`'s
  fields minus `transactions`.
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
- **`rand_getAggregators`** lists the register (public by design): `address`, `bond`,
  `payout`, `nonce`, `unbonding` per row.
- **`rand_getUnsealed(from, limit)`** pages the bundles an aggregator may still cover —
  finalised, inside the window, unsealed — as `{ bundles: [{ hash, height, excess }], next_from }`,
  `excess` in units over the floor: the daemon's work list.
- **`rand_getRawTransaction(hash)`** returns the full transaction, bincode as hex — the proof
  bytes an aggregator needs and `tx_json` deliberately never renders.
- **`rand_getSupply`** gains the four counters `subsidised`, `sealed_blocks`,
  `aggregator_bonds`, `slashed` (reported separately from `faucet_minted`, so the schedule is
  auditable against `sealed_blocks` directly).
- **`rand_status` gains `aggregation`**: `registered`, `unsealed`, `verify_queue`, and the
  chain parameters an aggregate daemon computes the payment from (`max_covers`, `window`,
  `subsidy_base`, `halving_blocks`, `sealed_blocks`).
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
