# SHRUGG Full Node — Design

Date: 2026-09-09
Status: approved for implementation (autonomous session; assumptions listed at the end)

## Goal

A standalone full node for the Rand Protocol chain that:

1. Runs BFT consensus (chained HotStuff) among a fixed validator set.
2. Discovers other full nodes (LAN via mDNS, WAN via Kademlia + bootstrap list).
3. Maintains an account-based ledger of the native token **SHRUGG** and applies signed transfers.

Confidential arbitrary computation is deliberately out of scope until the
`circuits/research` results land. The execution layer is a single trait
boundary so a proven VM can slot in later.

## Non-goals (v1)

- Programs / smart contracts, EVM or SVM execution.
- STARK/SNARK verification, shielded transfers.
- Dynamic validator set, staking transactions, slashing.
- Hash-sortition leader beacon (round-robin now; `LeaderSchedule` is the hook).
- Programs beyond native transfers; the confidential-computation path is a stub (see below).

## Workspace layout

```
fullnode/
  Cargo.toml                 workspace
  crates/
    shrugg-core/               pure, no async, no I/O
      src/crypto.rs          Keypair, PublicKey, Signature, Hash (blake3), Address
      src/types/             Transaction, Block, Vote, QuorumCertificate, ValidatorSet
      src/ledger.rs          Account state, transfer rules, state root
      src/genesis.rs         Genesis file format + genesis state/block derivation
      src/consensus/         HotStuff state machine (safety + commit rule), pacemaker timers
    shrugg-node/               async runtime, I/O
      src/storage.rs         redb: blocks, state snapshot, consensus safety data
      src/mempool.rs         pending txs ordered by (fee, nonce), per-sender nonce gaps
      src/network/           libp2p swarm: mdns, kad, identify, gossipsub, request-response
      src/sync.rs            catch-up: request blocks [from, to] from peers, verify QCs, apply
      src/rpc/               JSON-RPC 2.0 over HTTP (axum)
      src/node.rs            wires everything; single event loop owning consensus
      src/main.rs            CLI: keygen, init, run, balance, transfer
  docs/
```

## Data model

### Identifiers

- `Hash`: 32 bytes, BLAKE3.
- `PublicKey`: **Dilithium2** (CRYSTALS-Dilithium level 2, `crystals-dilithium` crate), 1312 bytes.
- `Address`: 32 bytes = blake3(public key), rendered as base58 (Solana-style length,
  hashed because a Dilithium key is too large to be the address itself).
- `Signature`: Dilithium2, 2420 bytes. Signed objects carry the signer's public key so
  verifiers can check `blake3(pk) == address`.
- Keys are derived from a 32-byte seed; the key file stores only the seed.
- libp2p peer identity: ed25519 key derived as `blake3("shrugg-p2p-identity" || seed)`;
  libp2p has no Dilithium transport identity. Validator identity on the wire is
  established by Dilithium-signed consensus messages, not by peer id.

### Account

```
Account { nonce: u64, balance: u128 }
```
Balances are in the smallest unit; 1 SHRUGG = 10^9 units (`SHRUGG_DECIMALS = 9`).

### Transaction

```
Transaction {
  chain_id: u64,
  from: PublicKey,        // address = blake3(from)
  nonce: u64,
  fee: u128,
  kind: TxKind,
  signature: Signature    // over blake3(bincode(unsigned fields))
}
TxKind = Transfer { to: Address, amount: u128 }
       | Confidential { program: Hash, public_inputs: Vec<u8>, proof: Vec<u8> }   // stub
```
Validity: signature verifies for `from`; `nonce == account.nonce`;
`balance >= amount + fee`; `chain_id` matches. Fee credited to the block proposer.
`hash()` = blake3 of the signed encoding.

### Block

```
BlockHeader {
  height: u64,
  view: u64,
  parent: Hash,
  proposer: Address,
  timestamp_ms: u64,
  tx_root: Hash,          // blake3 merkle of tx hashes
  state_root: Hash,       // ledger root AFTER applying this block
  justify: QuorumCertificate   // QC for parent
}
Block { header, transactions: Vec<Transaction>, signature }   // proposer signs header hash
```

### Consensus messages

```
Vote { view, block_hash, voter: Address, signature }
QuorumCertificate { view, block_hash, signers: Vec<(Address, Signature)> }
   valid iff sum(stake of signers) * 3 > total_stake * 2 and each sig verifies
NewView { view, high_qc, sender, signature }
ConsensusMessage = Proposal(Block) | Vote(Vote) | NewView(NewView)
```

### Validator set

`ValidatorSet { validators: Vec<Validator { address, stake }> }` from genesis.
Leader for view `v` = `validators[v % n]` (round-robin), behind `LeaderSchedule` trait.

## Consensus: chained HotStuff

Pure state machine `HotStuff` in `shrugg-core::consensus`, driven by the node
loop. Inputs: `on_proposal`, `on_vote`, `on_new_view`, `on_timeout`,
`on_local_txs_available`. Outputs: `Vec<Action>` where

```
Action = Broadcast(ConsensusMessage)
       | SendTo(Address, ConsensusMessage)
       | Commit(Vec<Block>)      // in order, finalized
       | ScheduleTimeout(view, Duration)
```

Rules (standard chained HotStuff, 3-chain commit):

- Node tracks `view`, `high_qc`, `locked_qc`, `last_voted_view`.
- **Proposal**: leader of `view` proposes `Block{ parent = high_qc.block, justify = high_qc }`
  once it enters the view (via QC for view-1 or 2f+1 NewView for this view).
  Non-leaders only accept proposals from the correct leader for the block's view.
- **Vote safety**: vote for block `b` iff `b.view > last_voted_view` and
  (`b.justify.view > locked_qc.view` OR `b` extends `locked_qc.block`).
- Votes go to the leader of `view + 1`; that leader assembles a QC when quorum stake reached.
- **Lock/commit** on receiving a block `b` with justify chain `b -> b' -> b'' -> b'''`:
  `locked_qc = b'.justify` (2-chain), and if `b'`, `b''`, `b'''` have consecutive views,
  commit `b'''` and all its uncommitted ancestors (3-chain).
- **Pacemaker**: on entering a view start a timer (base 1s, x2 per consecutive
  timeout up to 8s). On timeout: `view += 1`, broadcast `NewView(high_qc)`.
  Leader of a view starts proposing after collecting NewViews from quorum stake
  or on receiving a QC for `view - 1`.
- Empty blocks are allowed so the chain keeps advancing (keeps liveness and
  makes commit deterministic in tests). Blocks are produced at most once per view.

Persistence for safety: `last_voted_view`, `locked_qc`, `high_qc` are written to
storage before the corresponding vote is sent.

## Ledger / execution

`Ledger` is an in-memory `BTreeMap<Address, Account>` plus a `apply_block(&Block, proposer)`
that validates and applies every tx in order, rejecting the block if any tx is invalid
(proposers only include valid txs, so an invalid one is a Byzantine proposal).
`state_root()` = blake3 Merkle over `(address, nonce, balance)` leaves in address order.

### Confidential computation stub

`shrugg_core::confidential` defines
`trait ConfidentialExecutor { fn verify(&self, program: &Hash, public_inputs: &[u8], proof: &[u8]) -> Result<(), ConfidentialError>; }`
and `StubExecutor`, which accepts a proof iff it is the 4-byte marker `b"STUB"` followed
by `blake3(program || public_inputs)`. A `TxKind::Confidential` tx pays its fee, is
recorded on chain, and changes no balances. Replacing `StubExecutor` with a STARK
verifier from `circuits/research` is the only intended change to enable real
confidential computation. `shrugg_sendTransaction` accepts both kinds.

## Storage (RocksDB, one DB, column families)

`datadir/db/` is a single RocksDB with column families:
- `blocks: height(be u64) -> bincode(Block)` (committed only)
- `block_index: Hash -> height`
- `txs: Hash -> (height, index)`
- `accounts: Address -> bincode(Account)` (snapshot updated with each commit)
- `meta: key -> bytes` (`head_height`, `high_qc`, `locked_qc`, `last_voted_view`, `chain_id`, `genesis_hash`)

Each commit is one `WriteBatch` covering blocks, index, txs, accounts, and meta.
`datadir/genesis.json` is copied in by `init`; `datadir/node.key.json` holds the seed.

## Networking (libp2p 0.54)

Behaviour: `gossipsub + mdns + kad + identify + request_response<SyncRequest, SyncResponse>`.
Transport: TCP + noise + yamux.

- Topics: `shrugg/consensus/1`, `shrugg/tx/1`.
- Discovery: mDNS auto-dials LAN peers; `--bootstrap <multiaddr>` seeds Kademlia,
  then `kad.bootstrap()` periodically. Identify feeds Kademlia's routing table.
- Node identity key = the validator/account keypair (same ed25519 key), so
  peer IDs map to validator addresses.
- Sync protocol: `SyncRequest::Blocks{ from_height, max }` → `SyncResponse::Blocks(Vec<Block>)`.
  Peers advertise head height via periodic `Status` gossip on the consensus topic.

`Network` exposes `NetworkHandle { broadcast(msg), request_blocks(peer, from, max), peers() }`
and an `mpsc::Receiver<NetworkEvent>` for the node loop.

## Sync

On start and whenever a peer's advertised head exceeds local head by >1, request
blocks in batches of 100, verify each block's `justify` QC against the validator set
and that it chains from local head, apply via ledger, persist. While syncing,
consensus messages for views far ahead are buffered but not voted on.

## RPC (JSON-RPC 2.0, HTTP)

| method | params | result |
|---|---|---|
| `shrugg_chainId` | | `u64` |
| `shrugg_getBalance` | `[address]` | `u128` string |
| `shrugg_getAccount` | `[address]` | `{nonce, balance}` |
| `shrugg_sendTransaction` | `[hex(bincode(tx))]` | tx hash |
| `shrugg_getTransaction` | `[hash]` | `{tx, height, index}` or null |
| `shrugg_getBlockByHeight` | `[height]` | block or null |
| `shrugg_getBlockByHash` | `[hash]` | block or null |
| `shrugg_getHead` | | `{height, hash, view}` |
| `shrugg_getPeers` | | `[{peer_id, addrs}]` |
| `shrugg_getValidators` | | `[{address, stake}]` |
| `shrugg_syncStatus` | | `{syncing, head, target}` |

## CLI

```
shrugg-node keygen --out key.json
shrugg-node init --genesis genesis.json --datadir ./data
shrugg-node run --datadir ./data --key key.json --listen /ip4/0.0.0.0/tcp/30303 \
              --rpc 127.0.0.1:8545 [--bootstrap <multiaddr>]... [--validator]
shrugg-node balance --rpc http://127.0.0.1:8545 <address>
shrugg-node transfer --rpc http://127.0.0.1:8545 --key key.json --to <address> --amount 1.5
shrugg-node genesis-template --validators key1.json,key2.json > genesis.json
```

Genesis JSON: `{ chain_id, timestamp_ms, validators: [{address, stake}], alloc: {address: balance} }`.

## Error handling

- Invalid messages from peers are logged and dropped, never panic.
- Storage errors are fatal (node exits non-zero).
- RPC returns JSON-RPC error objects with codes: -32602 invalid params,
  -32000 tx rejected (reason string), -32001 not found.

## Testing

- Unit tests: crypto round-trips; tx validity matrix; ledger apply/rollback; state
  root determinism; QC quorum math; HotStuff safety (no two conflicting commits in
  a simulated 4-node network with message reordering); pacemaker timeout math; storage round-trips.
- Integration test (`crates/shrugg-node/tests/cluster.rs`): 4 validators in-process on
  localhost with mDNS off and explicit bootstrap addresses; submit a transfer via RPC;
  assert every node commits the same block containing it and balances match.
- Manual: `scripts/local-testnet.sh` launches 4 processes.

## Decisions confirmed with the user (2026-09-09)

- RocksDB, one DB with column families.
- 32-byte Solana-style addresses (hash of the Dilithium2 public key, base58).
- Dilithium2 signatures from the start.
- Rust for everything; first deployment target is two computers, each a validator.
  With n=2 the quorum is both signatures, so the chain halts if either node is down.
- Confidential arbitrary computation is a stub until `circuits/research` delivers.

## Assumptions made without user input

1. Token symbol `SHRUGG` per the request, even though whitepaper Draft 3 renamed it SHRUGG. One constant.
2. Standalone workspace; does not link the existing `randprotocol/node` or SVM crates.
3. Round-robin leaders now; hash sortition later behind `LeaderSchedule`.
4. Fixed validator set from genesis; fees to proposer; no block rewards.
