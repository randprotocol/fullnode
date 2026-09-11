# JSON-RPC reference

The node serves JSON-RPC 2.0 over HTTP on `--rpc` (default `127.0.0.1:8545`). One request per HTTP
POST to `/`; batches are not supported.

```bash
curl -s http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"shrugg_getHead","params":[]}'
```

Conventions:

- Addresses are base58 strings (32 bytes). Hashes are 64 hex characters, with or without `0x`.
- Bridge hex fields (asset ids, emitters, guardian keys, token addresses, message bodies) are
  lowercase hex without a `0x` prefix in results; parameters accept either form.
- Amounts are strings of smallest units (`"1500000000"` = 1.5 SHRUGG); 1 SHRUGG = 10^9 units.
- Heights, nonces and views are JSON integers.
- `shrugg_client::RpcClient` (Rust) wraps every method below.

## Methods

### `shrugg_chainId`
Params: `[]`. Result: chain id (integer). Transactions must carry this id.

### `shrugg_tokenInfo`
Params: `[]`. Result: `{ "symbol": "SHRUGG", "decimals": 9 }`.

### `shrugg_getBalance`
Params: `[address]`. Result: balance as a string of units. Unknown addresses return `"0"`.

### `shrugg_getAccount`
Params: `[address]`. Result:
```json
{ "address": "7th5YW...", "nonce": 4, "balance": "113085010000" }
```

### `shrugg_sendTransaction`
Params: `[hex]` where `hex` is the bincode encoding of a signed `Transaction` (as produced by
`Transaction::encode()` in `shrugg-core`, or by the `shrugg` wallet). Result: the transaction hash.

The node validates against the state at the tip of the chain (chain id, signature, nonce not below
the account nonce and at most 64 ahead, balance covering amount plus fee, confidential proof), puts it
in the mempool, and gossips it. Errors come back as code `-32000` with the reason, for example
`bad nonce: expected 4, got 3`, `insufficient balance: have 100, need 150`, `already in mempool`,
`replacement fee too low`, `nonce 80 too far ahead of account nonce 4`, `unknown program ...`,
`invalid proof: ...`, `fee 1 below minimum 1000000`, `bad effect: recipient index 2 out of range`,
`insufficient balance for emitted transfer`.

Acceptance is not commitment: poll `shrugg_getTransaction` until it returns a block.

### `shrugg_mint` (testnet faucet)
Params: `[address]` or `[address, amount]` (amount as a string of units, at most `100000000000` =
100 SHRUGG; default 100 SHRUGG). Result: the mint transaction hash.

Only available when the genesis file has `"faucet": true`; otherwise error `-32000`
`faucet is disabled on this chain`. The node signs a `Mint` transaction with its own key (fee 0) and
submits it through the normal mempool, so the mint goes through consensus and every node applies it.
Poll `shrugg_getTransaction` for the commit. A `Mint` appears in blocks as
`"kind": { "type": "mint", "to": "...", "amount": "..." }`.

### `shrugg_getProgram`
Params: `[program_id]`. Result: `null` or
`{ "id", "base_pc", "words_len", "code_hash", "deployer", "deployed_at" }`.

### `shrugg_getProgramCode`
Params: `[program_id]`. Result: `null` or `{ "base_pc": 0, "words": [u32, ...] }` (what the wallet
proves against).

### `shrugg_getReceipt`
Params: `[tx_hash]`. Result: `null` until the call is committed, then
```json
{ "tx": "...", "program": "...", "tier": 10, "outputs": [1, 0, 25, 0, 0, 0, 0, 0],
  "effect": { "to": "...", "amount": "25" }, "height": 17, "index": 0 }
```
`effect` is `null` for kind-0 outputs.

### `shrugg_estimateFee`
Params: `["deploy", words]` or `["call", tier]`. Result: minimum fee in units (string).

### `shrugg_getTransaction`
Params: `[hash]`. Result: `null` until committed, then:
```json
{
  "height": 1372, "index": 0, "block_hash": "8bf2...",
  "tx": {
    "hash": "e7a7...", "from": "7th5YW...", "nonce": 0, "fee": "1000", "chain_id": 2,
    "kind": { "type": "transfer", "to": "9W7dsb...", "amount": "3500000000" }
  }
}
```
Other kinds: `{ "type": "mint", "to", "amount" }`,
`{ "type": "deploy", "base_pc", "words_len", "program" }`,
`{ "type": "call", "program", "proof_len", "recipients": [...] }`,
`{ "type": "bridge_attest", "attestation": "<hex>" }`,
`{ "type": "bridge_burn", "asset", "amount", "to_chain", "to", "fee" }`.

### `shrugg_getBlockByHeight` / `shrugg_getBlockByHash`
Params: `[height]` (integer) or `[hash]`. Result: `null` if unknown, else:
```json
{
  "hash": "647b...", "height": 50, "view": 92, "parent": "2d41...",
  "proposer": "3v3VBJ...", "timestamp_ms": 1788000123456,
  "tx_root": "0000...", "state_root": "a1b2...", "justify_view": 91,
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
  "is_validator": true, "faucet": true, "confidential": true, "fri_profile": "production", "programs": 2,
  "address": "2nRdFC...", "peer_id": "12D3KooW..."
}
```
`syncing` is true while a batch request to a peer is in flight; `sync_target` is the highest height
any peer has advertised.

### `shrugg_getPeers`
Params: `[]`. Result: array of `{ "peer_id": "12D3KooW...", "addrs": ["/ip4/…/tcp/30303"], "connected_secs": 1241 }`.

### `shrugg_getAssetBalance`
Params: `[address, asset]` where `asset` is the 64-hex asset id. Result: balance as a string of
bridged units (8 decimals, not SHRUGG's 9). `"0"` for an unknown asset, an address that never held
it, or a chain without a bridge.

### `shrugg_getAssets`
Params: `[address]`. Result: every bridged asset the address holds a non-zero balance of:
```json
[ { "asset": "8f1c...", "token_chain": 2,
    "token_address": "000000000000000000000000f10befe1e0794722d3baf8bfd5bdac47b2a33148",
    "balance": "99999000" } ]
```
Empty on a chain without a bridge.

### `shrugg_getBridgeState`
Params: `[]`. Result on a bridged chain:
```json
{
  "enabled": true,
  "emitter": "65dc6def...",
  "emitters": { "2": "0000...7be73b64", "3": "0000...869f41c8" },
  "guardian_set_index": 0,
  "guardians": ["7e5f4552091a69125d5dfcb7b8c2659029395bdf", "..."],
  "burn_sequence": 3,
  "assets": [ { "asset": "8f1c...", "token_chain": 2, "token_address": "0000...33148" } ]
}
```
`emitter` is the Rand emitter address stamped into outbound burn messages; `emitters` maps each
source chain id to the contract address allowed to emit transfers into this chain; `guardians` are
the 20-byte keys of the current set, in index order; `assets` is the registry, which grows the first
time each token is bridged in. On a chain without a bridge the result is exactly
`{ "enabled": false }`.

### `shrugg_getBridgeBurn`
Params: `[sequence]` (integer). Result: `null` until that sequence exists, then
```json
{ "sequence": 0, "body_hex": "…", "digest": "…", "tx": "…", "height": 42 }
```
`body_hex` is the encoded Section 3.2 body of the outbound message and `digest` is
`keccak256(keccak256(body))` — what guardians sign so a source-chain contract will release. The
sequence of the newest message is `burn_sequence - 1` from `shrugg_getBridgeState`.

### `shrugg_bridgeAssetId`
Params: `[token_chain, token_address]` where `token_address` is 32 bytes of hex (20-byte EVM and
Tron addresses left-padded with zeros). Result: the asset id hex,
`blake3("shrugg-bridge-asset" || token_chain BE u16 || token_address)`. A pure function of its
arguments, so it answers on any chain, bridge or not.

### `shrugg_getValidators`
Params: `[]`. Result: array of `{ "address": "…", "stake": "100000" }` in leader-rotation order
(sorted by address). The leader of view `v` is entry `v mod n`.

## Errors

| code | meaning |
|---|---|
| `-32601` | unknown method |
| `-32602` | invalid or missing parameter (message says which) |
| `-32000` | transaction rejected by the mempool (message gives the reason) |
| `-32001` | referenced object not found |
| `-32603` | internal error (storage or node loop) |

Error responses look like `{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "…" } }`.

## Building a transaction without the wallet

The signed payload is `bincode(Transaction)` where

```
Transaction { body: TxBody, signature: Dilithium2 signature over blake3("shrugg-tx" || bincode(body)) }
TxBody { chain_id: u64, from: PublicKey(1312 bytes), nonce: u64, fee: u128, kind: TxKind }
TxKind::Transfer { to: Address(32 bytes), amount: u128 }
TxKind::Mint { to: Address, amount: u128 }                                      // testnet faucet only
TxKind::Deploy { base_pc: u32, words: Vec<u32> }
TxKind::Call { program: Hash, proof: Vec<u8>, recipients: Vec<Address> }        // proof = postcard(rand_zkvm::Proof)
TxKind::BridgeAttest { attestation: Vec<u8> }                                   // bridged chains only
TxKind::BridgeBurn { asset: Hash, amount: u128, to_chain: u16, to: [u8; 32], fee: u128 }
```

Use `shrugg_core::Transaction::transfer(&keypair, chain_id, nonce, to, amount, fee)` from Rust; the
`shrugg` wallet and `shrugg_client::RpcClient::transfer` do this for you.
