# JSON-RPC reference

The node serves JSON-RPC 2.0 over HTTP on `--rpc` (default `127.0.0.1:8545`). One request per HTTP
POST to `/`; batches are not supported.

```bash
curl -s http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"shrugg_getHead","params":[]}'
```

Conventions:

- Validator addresses are base58 strings (32 bytes). Hashes are 64 hex characters, with or
  without `0x`. Shielded values (commitments, nullifiers, anchors, tree roots, witness levels) are
  `Word8` — eight little-endian `u32` words as 64 lowercase hex characters.
- Shielded addresses are `shrugg1` + base58, about 1668 characters. A parameter longer than 2000
  characters is refused on its length before it is parsed.
- Amounts are strings of smallest units (`"1500000000"` = 1.5 SHRUGG); 1 SHRUGG = 10^9 units.
  Amounts *inside a decoded transaction* are JSON integers instead — a bundle's `fee` and `burn`, a
  mint's amount, a staking action's amount — because they are being reported as the transaction's own
  fields rather than as chain state.
- Heights, leaf indices and views are JSON integers.
- `shrugg_client::RpcClient` (Rust) wraps every method below.

**There is no balance method, and no account method.** This chain has no accounts; see
`docs/shielded.md`. A wallet computes its own balance by scanning the commitment tree with its
viewing key, which is what `shrugg_getCommitments` and `shrugg_getNullifiers` exist for. That
holds for bridged assets too: a bridged holding is a note whose `asset` word is the registry's
index for it (phase S3, `docs/bridge.md`), so the bridge methods below report the bridge's own
*public* state — guardians, emitters, the asset registry, the outbound burn log — and no
per-address balance. `shrugg_getAssetBalance` is gone for good.

## Methods

### `shrugg_chainId`
Params: `[]`. Result: chain id (integer). Transactions must carry this id.

### `shrugg_tokenInfo`
Params: `[]`. Result: `{ "symbol": "SHRUGG", "decimals": 9 }`.

### `shrugg_sendTransaction`
Params: `[hex]` where `hex` is `bincode(Transaction)` (as produced by `Transaction::encode()` in
`shrugg-core`, or by the `shrugg` wallet). Result: the transaction hash.

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

Acceptance is not commitment: poll `shrugg_getTransaction` until it returns a block.

### `shrugg_mint` (testnet faucet)
Params: `[address]` or `[address, amount]`, where `address` is a `shrugg1…` shielded address and
`amount` is a string of units, at most `100000000000` (100 SHRUGG; the default). Result: the mint
transaction hash.

Only available when the genesis file has `"faucet": true`; otherwise error `-32000`
`faucet is disabled on this chain`. The node builds the note, seals an envelope to `address`
under a throwaway sender key, signs the `Mint` with its own validator key and submits it through
the normal mempool, so the mint goes through consensus and every node applies it. An observer has
no validator key and answers `faucet mints are signed by validators; ask a validator node`. Poll
`shrugg_getTransaction` for the commit.

### `shrugg_getCommitments`
Params: `[from_index]` or `[from_index, limit]`. Result: a page of commitment-tree leaves from
leaf `from_index`, oldest first, at most 1000 rows however large `limit` is (a missing or null
`limit` asks for the maximum). Page until the reply is short or empty.

```json
[ { "index": 40, "cm": "2a9f…07", "height": 37,
    "envelope": { "kem_ct": "b41c…", "to_receiver": "77e0…", "to_sender": "0c31…", "body": "9dd2…" } } ]
```

Every leaf and every envelope is served to everyone; only a viewing key tells one wallet's rows
from another's.

### `shrugg_getNullifiers`
Params: `[from_height]` or `[from_height, limit]`. Result: every nullifier published from that
block height onwards, same 1000-row cap.

```json
[ { "height": 37, "nullifier": "8c04…d1" }, { "height": 41, "nullifier": "12be…9a" } ]
```

A page can stop inside a height, so a caller pages back to the highest height it saw rather than
past it; re-reading rows is harmless.

### `shrugg_getAnchor`
Params: `[]` for the head, or `[height]`. Result: `{ "height": 192, "root": "6b1d…c4" }`, or error
`-32001` for a height with no recorded anchor.

Only *block-end* roots are anchors, and only the newest 256 are kept. A node that caught up in one
sync batch longer than that window holds rows only for the heights the batch covered, so ask for
the head — the only anchor a prover should build against anyway.

### `shrugg_getWitness`
Params: `[index]`. Result: `null` past the end of the tree, else the Merkle path of that leaf,
leaf-first, exactly 32 levels, with the tree's *current* root:

```json
{ "index": 40, "root": "6b1d…c4", "path": ["0000…00", "f2a1…3b", "…"] }
```

The root is the live root, not an anchor: a wallet checks it against the anchor it is proving
under and refetches if a leaf was appended in between. This is the most expensive read a node
serves (it rebuilds a full depth-32 tree from every stored leaf) and the one request that
discloses something about the caller — see `docs/shielded.md` §6.

### `shrugg_getTreeInfo`
Params: `[]`. Result: `{ "next_index": 41, "root": "6b1d…c4", "nullifiers": 12 }` — the leaf count
(the index the next note will get), the current root, and how many notes have been spent.

### `shrugg_getProgram`
Params: `[program_id]`. Result: `null` or
`{ "id", "base_pc", "words_len", "code_hash", "deployed_at" }`. There is no `deployer` field: a
deploy is paid by a bundle, so the chain does not know who deployed it.

### `shrugg_getProgramCode`
Params: `[program_id]`. Result: `null` or `{ "base_pc": 0, "words": [u32, ...] }` (what the wallet
proves against).

### `shrugg_getReceipt`
Params: `[tx_hash]`. Result: `null` until the call is committed, then

```json
{ "tx": "…", "program": "…", "tier": 14, "outputs": [1, 0, 25, 0, 0, 0, 0, 0], "height": 17,
  "index": 0, "h_in": "9c0e…7f" }
```

`h_in` is the proof's public commitment to the call's *private* inputs (`Word8` hex, zkVM M4.1).
It discloses nothing on its own — it is a salted digest — and it is what a call-input envelope is
sealed against, so a holder needs it to open one (`shrugg_getCallEnvelope`) and to check an
opened transcript with `hash::input_digest(salt, inputs)`.

There is no `effect` field: effect kind 1 (the program-driven transfer to an account) was deleted
with the accounts. A call's outputs are recorded and nothing else moves; value moves only through
the bundle that paid for the call.

### `shrugg_getCallEnvelope`
Params: `[tx_hash]`. Result: `null`, or the call's input envelope (spec §6.1) in hex:

```json
{ "tx": "…", "h_in": "9c0e…7f", "kem_ct": "…", "to_sender": "…", "to_auditor": "…", "body": "…" }
```

`h_in` is the receipt's, repeated here so one request is enough to open the envelope. `body` is
the call's private input vector and its `H_IN` salt, sealed under a per-call key with that
`h_in` as associated data; `to_sender` wraps that key to the caller's outgoing
viewing key and `kem_ct`/`to_auditor` to the auditor the caller named, both empty strings when
there is none. The node holds no key that opens any of it and never looks inside — it is served
so that a wallet with the caller's viewing key, a per-call key, or the auditor's key can open it
(`shrugg_zkvm::call_envelope`) and check the transcript against `H_IN`. `null` means the call
published no envelope (`--no-envelope`), the transaction is not a call, or this node has no
receipt for that hash.

### `shrugg_estimateFee`
Params: `[spec]`, one of `{"kind":"bundle"}`, `{"kind":"deploy","words":n}` or
`{"kind":"call","tier":t}` (`t` one of 10, 12, 14, 16, 18, 20). Result: the minimum fee in units,
as a string. `{"kind":"bundle"}` is the floor for a plain transfer: `1000000`.

### `shrugg_getTransaction`
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
- `{ "kind": "deploy", "program": "<program id>", "words": 412 }`
- `{ "kind": "call", "program": "<program id>", "proof_len": 268123, "input_envelope_len": 1280 }`

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

### `shrugg_getBlockByHeight` / `shrugg_getBlockByHash`
Params: `[height]` (integer) or `[hash]`. Result: `null` if unknown, else:
```json
{
  "hash": "647b…", "height": 50, "view": 92, "parent": "2d41…",
  "proposer": "3v3VBJ…", "timestamp_ms": 1788000123456,
  "tx_root": "0000…", "state_root": "a1b2…", "justify_view": 91,
  "tx_count": 0, "transactions": [ ...same shape as shrugg_getTransaction.tx... ]
}
```
Only committed blocks are served. `justify_view` is the view of the quorum certificate for the
parent that this block carries.

### `shrugg_getHead`
Params: `[]`. Result: `{ "height": 1998, "hash": "…", "view": 2251 }` (`view` is the node's current
consensus view, which runs ahead of height when views time out).

### `shrugg_status` (alias `shrugg_syncStatus`)
Params: `[]`. Result:
```json
{
  "height": 1998, "head_hash": "…", "view": 2251, "high_qc_view": 2250,
  "syncing": false, "sync_target": 1998,
  "peer_count": 5, "mempool_size": 0,
  "is_validator": true, "active_validator": true, "faucet": true, "confidential": true,
  "fri_profile": "production", "programs": 2,
  "notes": 41, "nullifiers": 12, "tree_root": "6b1d…c4", "hc_bundle": "f07a…19",
  "address": "2nRdFC…", "peer_id": "12D3KooW..."
}
```
`syncing` is true while a batch request to a peer is in flight; `sync_target` is the highest height
any peer has advertised. `is_validator` says this node holds a validator key; `active_validator`
says that key is in the set running the current epoch (spec §8) — a validator that has bonded in
but whose epoch has not arrived is the first without the second. `notes` is every note the chain has ever created, `nullifiers` every note
it has ever spent, and `hc_bundle` the bundle guest this chain's proofs are against — a node whose
build disagrees with the genesis value refuses to start at all.

### `shrugg_getPeers`
Params: `[]`. Result: array of `{ "peer_id": "12D3KooW...", "addrs": ["/ip4/…/tcp/30303"], "connected_secs": 1241 }`.

### `shrugg_getBridgeState`
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
  "assets": [ …the rows of `shrugg_getAssets`… ]
}
```
No balances: bridged value is notes, not accounts.

### `shrugg_getAssets`
Params: `[]`. Result: the bridge's asset registry, ascending by index (which is registration
order), or `[]` on a chain without a bridge:
```json
[{ "index": 1, "chain": 2, "token": "aaaa…", "asset_id": "…" }]
```
`index` is the `asset` word a note of that asset carries — index 0 is SHRUGG and is never in the
registry. `chain` and `token` are the wire identity guardians sign about; `asset_id` is
`blake3` of the two, and is what `shrugg_bridgeAssetId` computes.

### `shrugg_bridgeAssetId`
Params: `[token_chain, token_address]` where `token_chain` is an integer and `token_address` is
32 bytes of hex. Result: the asset id (64 hex characters). Pure arithmetic on its arguments, so
it answers on any chain, bridged or not.

### `shrugg_getBridgeBurn`
Params: `[sequence]` (integer). Result: `null` if this chain has emitted no such message, else
```json
{ "sequence": 0, "body_hex": "…", "digest": "…", "tx": "…", "height": 2 }
```
`body_hex` is the outbound message as guardians must hash and sign it; `digest` is its hash.
`tx` is the burn transaction that emitted it — a burn is funded by notes, so the transaction
hash stands in for the sender identity the message has no room for.

### `shrugg_getValidators`
Params: `[]`. Result: array of

```json
{ "address": "…", "stake": "1000000000000", "pending": [{ "release_epoch": 41, "amount": "5000000000" }],
  "rewards": "4000000", "payout": "shrugg1…", "nonce": 3, "active": true }
```

one row per entry of the **register** (spec §8), in address order. Since phase S2 that is every
validator that has ever bonded, not the genesis set: `active` is the ones in the set running the
current epoch, and those are what the leader rotation runs over. Amounts are **decimal strings**,
because a JSON number is not an exact integer past 2^53 and a stake is 10^9 units per SHRUGG.
`pending` is the unbonding queue, oldest first; `rewards` is the bundle fees credited to that
validator as proposer; `payout` is where a `Withdraw` pays; `nonce` is what its next signed
`Unbond` or `Withdraw` must carry. The register is the only place this chain stores amounts in the
clear — `docs/staking.md` is the guide to it.

### `shrugg_getEpoch`
Params: `[]`. Result: `{ "epoch": 41, "epoch_blocks": 1000, "next_set": ["…", "…"] }`. `epoch` is
`height / epoch_blocks`. `next_set` is what the register would derive for the next epoch if this
one ended now — a projection, not a commitment: every bond and unbond before the boundary moves it.
The derivation rule is in `docs/staking.md` §2.

### `shrugg_getSupply`
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
chain state. The counters are not in the state root — `shrugg-node verify --mode quick` recomputes
every one of them by replaying the chain, which is what makes them auditable. `docs/supply.md`
works the identity through a bond and a withdraw and says where it rests on a claim (the genesis
file's own amounts) rather than on a check.

## Errors

| code | meaning |
|---|---|
| `-32601` | unknown method |
| `-32602` | invalid or missing parameter (message says which) |
| `-32000` | transaction rejected by the mempool (message gives the reason) |
| `-32001` | referenced object not found |
| `-32603` | internal error (storage or node loop) |

Error responses look like `{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "…" } }`.

## The transaction on the wire

`shrugg_sendTransaction` takes `bincode(Transaction)`. There is no signature over the transaction
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

A `BridgeBurn` is the chain's one two-bundle transaction: the outer `bundle` pays the SHRUGG fee
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
at 2048 bytes, a program at 4096 words, and a block at 4 MiB of transaction bytes — three bundles
per block (`docs/block-space.md`).

A wallet builds all of this through `shrugg_client::wallet::{send, submit}`, which selects the
inputs, fetches the anchor and the witnesses, proves the bundle, seals both envelopes, and checks
the proof's published digest against the one it computed before it submits anything.
