# Architecture

The original design spec is in `docs/superpowers/specs/2026-09-09-shrugg-fullnode-design.md`; this
page describes what is implemented.

## Crates

- `shrugg-core` has no I/O, no async, and no Plonky3. It holds cryptography (Dilithium2 via
  `crystals-dilithium`, BLAKE3), the data types, the ledger and its transaction rules, gas and
  effect decoding, genesis derivation, the executor trait, and the HotStuff state machine.
- `shrugg-zkvm` is the Rand zkVM (vendored from `circuits/research`, resynced with
  `deploy/sync-zkvm.sh`) plus `executor.rs`, the chain's proof verifier with its key cache, and
  `codec.rs` for program files. Everything here is tested deterministically,
  including a simulated multi-replica network with message loss, partitions and restarts.
- `shrugg-node` wraps the core in I/O: RocksDB storage, libp2p networking, mempool, block sync, the
  JSON-RPC server, the node event loop, and the `shrugg-node` CLI.
- `shrugg-client` is the RPC client library and the `shrugg` wallet.

## Identity and addresses

A node or wallet key is a 32-byte seed. From it: a Dilithium2 key pair (1312-byte public key,
2420-byte signatures), the address `blake3("shrugg-address" || public_key)` shown in base58, and an
ed25519 libp2p identity `blake3("shrugg-p2p-identity" || seed)`. Signed objects carry the full public key
so verifiers can check `blake3(pk) == address`.

## Ledger

`Account { nonce, balance }` per address, kept in a `BTreeMap`. A transfer is valid when the chain id
matches, the signature verifies, the nonce equals the account nonce, and balance covers
amount + fee. Fees go to the block proposer. Applying a block is atomic: any invalid transaction
rejects the whole block, and the resulting state root must equal the header's. The state root is a
BLAKE3 Merkle root over `(address, nonce, balance)` leaves in address order; empty accounts are pruned
so absent and never-touched accounts hash identically.

`Mint { to, amount }` transactions exist for testnets: the genesis `faucet` flag (part of the genesis
hash) enables them, each is capped at 100 SHRUGG, the signer pays only the fee (usually 0) and its
nonce advances, so mints are ordinary consensus-ordered transactions and cannot be replayed.

`Deploy` and `Call` implement confidential computation (see `docs/confidential.md`). The ledger holds
a map of deployed programs (in the state root) and applies calls through a `ConfidentialExecutor`:
`ZkExecutor` (in `shrugg-zkvm`) verifies STARK proofs with per-program cached verifier keys that are
warmed in a background task when a deploy commits; `StubExecutor` is a crypto-free stand-in for
tests; `DisabledExecutor` serves chains with `confidential: false`. Deploy validation only decodes
instructions, so it is cheap inside block application.

## Consensus

Chained HotStuff. Each block carries a quorum certificate (QC) for its parent; a QC is a set of
Dilithium2 votes from validators holding strictly more than 2/3 of stake. Rules:

- Leader of view `v` is validator `v mod n` (validators sorted by address).
- The leader proposes when it holds a QC for `v-1` or `NewView` messages for `v` from quorum stake.
- A validator votes for a block once per view, only if the block's justify QC is newer than its lock or
  the block extends its locked block. Safety state (`last_voted_view`, locked QC, high QC) is fsynced
  before the vote leaves the node.
- Lock on the block certified two QCs back; commit the block certified three QCs back together with its
  uncommitted ancestors.
- Timeouts double per consecutive timeout (base 3 s, cap 8x) and reset on progress. A `NewView` from a
  validator in a higher view pulls a lagging node into that view.

Empty blocks are proposed so the chain keeps advancing; the node paces proposals by
`--block-interval-ms` measured from the last block seen from any proposer.

## Storage

One RocksDB per data directory with column families `blocks` (height → block), `qcs` (height → QC
certifying that block), `block_index` (hash → height), `txs` (tx hash → height, index), `accounts`
(address → account) and `meta` (head height, genesis hash, chain id, safety state). A commit of one
or more blocks is a single fsynced `WriteBatch` covering blocks, QCs, indexes, transaction locations,
touched accounts and the head.

On startup the node verifies the chain (`--verify-chain`): block 0 must equal the genesis derivation;
each later block must link to the previous hash, have the right height, a matching index entry, a QC
that certifies it, the correct leader as proposer, a valid transaction root, indexed transactions, and
must re-execute to the state root in its header; the account snapshot must equal the replayed ledger.
`full` mode also checks proposer signatures and every QC's votes. On the first inconsistency the node
truncates to the last good height (rewriting the account snapshot from the replayed ledger, keeping
the safety state) and lets sync refetch the rest from peers. Quick mode over a few thousand blocks
takes well under a second.

## Networking and sync

libp2p 0.54 over TCP with Noise and Yamux. Behaviours: gossipsub (topics
`shrugg/<chain-id>/consensus`, `/tx`, `/status`), Kademlia (protocol `/shrugg/<chain-id>/kad/1`) seeded from
`--bootstrap`, identify, optional mDNS, request-response (`/shrugg/sync/1`, CBOR) for block sync, and
ping every 15 s. The node remembers every address it dialled or learnt through identify and redials
disconnected known peers every 30 s, in addition to the bootstrap list.

Every node gossips a status (height, head hash, view) every 3 s. A node that sees a peer more than one
block ahead requests up to 100 committed blocks with their QCs, verifies each QC against the validator
set, checks linkage and leader, re-executes, persists, and then rebuilds its consensus replica on the
new head. A proposal whose parent is unknown triggers a fetch of that block by hash, or a batch sync
if the node is more than two blocks behind.

## Mempool

Transactions are validated against the ledger at the tip of the consensus tree. Per sender, nonces may
run up to 64 ahead of the account nonce; a replacement for the same nonce must pay a higher fee. The
proposer takes each sender's contiguous nonce run from the account nonce, ordered by the first
transaction's fee, with a cumulative balance check, up to 2000 transactions per block. Committed and
stale transactions are pruned after every commit.

## Tests

- `shrugg-core`: unit tests for every module and a deterministic simulation of 4 (or 2, or 5 with an
  observer) HotStuff replicas: lockstep commits, transfers, timeouts, partitions, wrong-leader and
  forged proposals, view sync, and restarts (no double vote after restart, repeated restarts, offline
  catch-up, two-of-four halt and recovery).
- `shrugg-node`: storage round trips and corruption cases, mempool rules, a two-node libp2p test, and a
  cluster suite of real nodes over TCP on localhost: two validators with a transfer, four validators
  plus a late observer, restart from disk, restart cycles with transfers, two-of-four down then
  recovery without a fork, catch-up across more than one sync batch, and a corrupted RocksDB detected,
  truncated and resynced.
