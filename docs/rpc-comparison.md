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
