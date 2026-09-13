# The SHRUGG RPC next to Ethereum's and Solana's

A method-family comparison of this node's JSON-RPC (`docs/rpc.md`) with Ethereum's execution
JSON-RPC and Solana's JSON-RPC, written 2026-09-12 after phase S1 (the shielded pool). Items
marked *S2* arrive with the staking phase.

## 1. Method families

| concern | Ethereum JSON-RPC | Solana JSON-RPC | SHRUGG |
|---|---|---|---|
| chain identity | `eth_chainId`, `net_version` | `getGenesisHash`, `getVersion` | `shrugg_chainId`, `shrugg_status` (also `hc_bundle`, `tree_root`, the FRI profile) |
| balances / accounts | `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt` | `getBalance`, `getAccountInfo`, `getProgramAccounts`, `getTokenAccountBalance` | none, by design: balances exist only in wallets. The node serves `shrugg_getCommitments`, `shrugg_getNullifiers`, `shrugg_getWitness`, `shrugg_getTreeInfo` and the wallet does the rest |
| submit | `eth_sendRawTransaction` | `sendTransaction` | `shrugg_sendTransaction` (bincode, hex) |
| dry-run | `eth_call`, `eth_estimateGas` | `simulateTransaction` | none on the node. A confidential call is dry-run in the wallet's emulator before proving; fees come from `shrugg_estimateFee` (flat floors, no gas model) |
| fees | `eth_gasPrice`, `eth_feeHistory`, EIP-1559 fields | `getFeeForMessage`, `getRecentPrioritizationFees` | `shrugg_estimateFee` only: fixed floors, no market |
| blocks and transactions | `eth_blockNumber`, `eth_getBlockBy*`, `eth_getTransactionByHash` | `getSlot`, `getBlock`, `getTransaction`, `getLatestBlockhash` | `shrugg_getHead`, `shrugg_getBlockByHeight`, `shrugg_getBlockByHash`, `shrugg_getTransaction`, `shrugg_getAnchor` |
| receipts and events | `eth_getTransactionReceipt`, `eth_getLogs` (topics, bloom filters) | `getSignatureStatuses`, program logs inside `getTransaction` | `shrugg_getReceipt` (tier, 8 output words, `H_IN`), `shrugg_getCallEnvelope`; no event log, no filters |
| history by address | `eth_getLogs` by address; external indexers | `getSignaturesForAddress` | impossible by design; a viewing-key holder reconstructs it client-side |
| validators and epochs | none (the consensus client's beacon API) | `getVoteAccounts`, `getEpochInfo`, `getLeaderSchedule` | `shrugg_getValidators`, `shrugg_getPeers`; `shrugg_getEpoch` (*S2*) |
| supply | none | `getSupply`, `getInflationRate` | `shrugg_getSupply` (*S2*, `docs/supply.md`); no inflation |
| subscriptions | WebSocket `newHeads`, `logs`, `pendingTransactions` | WebSocket `accountSubscribe`, `logsSubscribe`, `slotSubscribe` | none; polling only |
| batching and paging | JSON-RPC batch requests | batch, plus cursors on `getSignaturesForAddress` | no batch; limit-based paging on commitments and nullifiers |
| state proofs | `eth_getProof` (Merkle-Patricia) | none | `shrugg_getWitness` (a Poseidon2 Merkle path the zkVM consumes) |

## 2. What the differences mean

**The closest relative is neither.** This node speaks something much nearer to Zcash's
`lightwalletd`: stream commitments, nullifiers and ciphertexts; let the client trial-decrypt.
`shrugg_getCommitments` with the envelope inline is a compact block by another name. Ethereum
and Solana expose state because their state is public; ours cannot, so the "missing" account
methods are the privacy property, not a gap.

**Where this node is behind, and why it matters for explorers and wallets.** No subscriptions (a
wallet or explorer polls `shrugg_getHead`), no batch requests, and scanning is chatty (one page
of commitments plus one page of nullifiers per sync). Two cheap, non-consensus additions close
most of that and are scheduled as an RPC hardening task after phase S3:

- `shrugg_getCompactBlocks(from_height, to_height)`: per block, its commitments (with
  envelopes) and nullifiers, so a sync is one round-trip per few hundred blocks.
- a WebSocket `newHeads` subscription, so nothing has to poll.

**Where the shape differs deliberately and should stay that way.** No gas market (fees are flat
floors because verification cost is nearly constant per proof); no event logs (a call publishes
eight words, and its inputs are disclosed only through an envelope, `docs/confidential.md`); no
address-indexed history. Solana's `getSupply` is the one method worth copying outright, and
`shrugg_getSupply` does.

## 3. Method-for-method notes

- `eth_getTransactionReceipt` / `getSignatureStatuses` → `shrugg_getReceipt`: a receipt exists
  only for a `Call`; a plain transfer has no receipt because it has no observable effect beyond
  the commitments and nullifiers already in the block.
- `eth_getProof` → `shrugg_getWitness`: both return a Merkle path, but ours is an input to a
  proof the client builds, not a proof the client checks; the root it is against is the head's
  anchor, and the node learns which leaf the client asked about (`docs/shielded.md`, privacy
  notes).
- `getEpochInfo` / `getLeaderSchedule` → `shrugg_getEpoch` (*S2*): the set for the next epoch is
  derived from the public register, so a client can predict it exactly as on Solana.
- `simulateTransaction` → the wallet's emulator: the zkVM's reference emulator runs the program
  on the private inputs locally; the node never sees them, so a node-side simulation would be
  meaningless.

## 4. Next to the privacy chains: Monero and Zcash

The comparison that matters more than Ethereum's or Solana's. Both privacy chains split their
interface into a *node* API that serves what the chain can see and a *wallet* API that holds
keys; SHRUGG follows the same split, with the wallet API living in the `shrugg` CLI rather than
behind a socket.

| concern | Monero (`monerod` + `monero-wallet-rpc`) | Zcash (`zcashd` + `lightwalletd`) | SHRUGG |
|---|---|---|---|
| chain info | `get_info`, `get_block_count`, `get_last_block_header` | `getblockchaininfo` (incl. `valuePools`), `getinfo`; lightwalletd `GetLatestBlock`, `GetLightdInfo` | `shrugg_status`, `shrugg_getHead`, `shrugg_chainId` |
| blocks / txs | `get_block`, `get_transactions`, `get_transaction_pool` | `getblock`, `getrawtransaction`; lightwalletd `GetBlock`, `GetTransaction` | `shrugg_getBlockBy*`, `shrugg_getTransaction` |
| submit | `send_raw_transaction` | `sendrawtransaction`; lightwalletd `SendTransaction` | `shrugg_sendTransaction` |
| fee | `get_fee_estimate` (per-byte, dynamic) | `estimatefee`, ZIP-317 conventional fee | `shrugg_estimateFee` (flat floors) |
| the spent-set | key images, checked via `is_key_image_spent` | nullifiers inside compact blocks (`CompactTx.spends`) | `shrugg_getNullifiers` |
| the note stream a wallet scans | `get_blocks.bin` (full blocks; wallet trial-decrypts every output with the private view key) | lightwalletd `GetBlockRange` → `CompactBlock` (per output: `cmu`, ephemeral key, 52-byte ciphertext prefix) | `shrugg_getCommitments` (index, `cm`, full envelope, height) |
| membership witness | `get_outs`, `get_output_distribution` (ring-signature decoys, no Merkle tree) | `z_gettreestate`; lightwalletd `GetTreeState`, `GetSubtreeRoots` (clients keep their own tree) | `shrugg_getWitness`, `shrugg_getAnchor`, `shrugg_getTreeInfo` |
| wallet balance | `get_balance` (wallet RPC) | `z_getbalance`, `z_gettotalbalance` (zcashd holds keys) | `shrugg balance` (CLI, local key file) |
| send | `transfer`, `transfer_split` | `z_sendmany` | `shrugg send` |
| viewing keys | private view key; "view-only wallets"; `query_key` | `z_exportviewingkey` / `z_importviewingkey` (node scans on the holder's behalf), full and incoming viewing keys, unified keys | party viewing key `nk` (full history) and per-transaction `TxKey`; no node-side import yet |
| per-tx disclosure | `get_tx_key`, `get_tx_proof` / `check_tx_proof` (prove a payment to a third party) | `z_getpaymentdisclosure` (experimental), viewing keys | `TxKey` opens one transaction; a call's `CallEnvelope` opens one call's inputs |
| supply audit | `get_reserve_proof` (prove a wallet holds ≥ X); no chain-wide value balance (RingCT hides amounts; inflation undetectable except via range proofs) | `getblockchaininfo.valuePools[].chainValue` — the per-pool value balance, exactly the invariant | `shrugg_getSupply` (*S2*, `docs/supply.md`) |
| subscriptions | ZMQ `json-minimal-chain_main`, `json-minimal-txpool_add` | lightwalletd `GetMempoolStream`; zcashd ZMQ | none yet (planned: WebSocket `newHeads`) |
| history by address | none (by design); wallet keeps `get_transfers` | none by address; `z_listreceivedbyaddress` from the wallet's own scan | none (by design) |

**What is the same.** All three make the wallet, not the node, the place where balances exist:
the node hands out the public residue (outputs or commitments, spent markers, ciphertexts) and
the wallet trial-decrypts with a viewing key. SHRUGG's `getCommitments` is Zcash's
`CompactBlock` with the whole envelope instead of a 52-byte prefix, and `getNullifiers` is the
`spends` list. Monero's key image and SHRUGG's nullifier play the same role (a one-way
per-note spend tag); Zcash's nullifier is the direct ancestor of ours.

**Where SHRUGG is structurally different.**

- *Membership.* Monero hides the spent output among decoys with a ring signature, so its node
  serves decoy candidates (`get_outs`) and the anonymity set is the ring (16 today). Zcash and
  SHRUGG prove membership in a Merkle tree, so the anonymity set is every note ever created, and
  the node serves tree witnesses instead. SHRUGG's witness is consumed by a STARK rather than a
  Groth16/Halo 2 circuit, and the wallet asks the node for it (a privacy leak Zcash avoids by
  keeping the tree client-side; scheduled follow-up).
- *Auditability.* Zcash's `valuePools` and SHRUGG's `getSupply` expose the chain-wide value
  balance; Monero cannot, because RingCT hides amounts and only per-wallet reserve proofs exist.
- *Programs.* Neither Monero nor Zcash has confidential programs; SHRUGG's `getReceipt`,
  `getProgram*` and `getCallEnvelope` have no counterpart.
- *Keys in the node.* zcashd and monero-wallet-rpc can hold keys and scan on the holder's
  behalf; SHRUGG's node never holds a key. A node-side "import a viewing key" for explorers
  (RandScan) would be the Zcash `z_importviewingkey` equivalent and is a candidate for the RPC
  hardening task.

**What SHRUGG should borrow.** Zcash's compact-block range stream (planned as
`shrugg_getCompactBlocks`), lightwalletd's mempool stream (the `newHeads`/mempool subscription),
Monero's `check_tx_proof` shape for third-party payment proofs (a `TxKey` already gives the
capability; a `shrugg_checkTransaction(tx, key)` RPC would make it a one-call verification for
an explorer), and Zcash's viewing-key import for explorer-side views.
