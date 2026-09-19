# Architecture

The original design spec is in `docs/superpowers/specs/2026-09-09-rand-fullnode-design.md` and
the shielded pool's is `docs/superpowers/specs/2026-09-11-shielded-pool-design.md`; this page
describes what is implemented, and walks one confidential transaction end to end. Where the code
and an older doc disagreed, this page follows the code.

Phase S1 replaced the account ledger with a shielded note pool. There are no accounts, no
balances, no nonces and no signed transfers anywhere below; `docs/shielded.md` is the user-facing
guide to what took their place.

## 1. Overview

```
 WALLET (randprotocol-client)                           EVERY NODE (rand-node)
 ───────────────────────                          ─────────────────────────────────────
  scan the tree with the viewing key                 JSON-RPC (rand_sendTransaction, ...)
  select ≤ 2 notes, fetch anchor + witnesses                │
       │                                                     ▼
       │  every value-moving tx:                     ┌───────────────┐
       │  ┌─────────────────────────┐                │    Mempool     │  cheap checks first:
       │  │ Rand zkVM PROVER         │                │  (nullifier /  │  duplicate hash, a
       │  │  notes, paths, amounts   │                │   commitment   │  conflicting nullifier
       │  │  → bundle guest, tier 14 │                │   conflicts)   │  or commitment, pool
       │  │  → postcard(Proof)       │                └───────┬────────┘  full, then a full
       │  └─────────────────────────┘                        │           ledger.validate() probe
       │  Call also: prove the program                       ▼           (anchor, spends, digest,
       ▼                                             ┌───────────────┐    proof verification)
  bincode(Transaction) ───── rand_sendTransaction ─▶│   HotStuff     │◀─── gossipsub / libp2p ──▶
  { chain_id, bundle, action }                       │  (chained BFT) │
                                                     │  leader proposes a block of candidates │
                                                     │  votes → QC → lock → 3-chain commit    │
                                                     └───────┬────────────────────────────────┘
                                                             │ Action::Commit(CommittedBlock)
                                                             ▼
                                                     ┌───────────────┐
                                                     │     Ledger     │  apply_block:
                                                     │  (randprotocol-core) │  bundle → digest + verify_bundle
                                                     │                │  Deploy → check_program (cheap)
                                                     │                │  Call   → verify_call ──────┐
                                                     └───────┬────────┘                             │
                                                             │ state_root must match header          │
                                                             ▼                                       ▼
                                                     ┌───────────────┐                     ┌──────────────────┐
                                                     │    RocksDB     │  one fsynced        │ ZkExecutor::      │
                                                     │  (rand-node) │  WriteBatch per      │ verify_bundle /   │
                                                     │  blocks/qcs/   │  commit              │ verify_call       │
                                                     │  notes/nulli-  │                      │ (randprotocol-zkvm):    │
                                                     │  fiers/anchors/│                      │ Machine::verify   │
                                                     │  validators/   │                      │ (STARK verifier,  │
                                                     │  programs/     │                      │ cached key)       │
                                                     │  receipts/meta │                      └──────────────────┘
                                                     └────────────────┘

 A late or lagging node: gossiped status (height/hash/view) every 3 s → SyncRequest over
 request-response → verify each fetched QC and re-execute every block (proof verification
 included) before accepting it, exactly like a block arriving live.
```

The prover only ever runs on the wallet's machine, on private inputs — the notes it is spending
included — that never leave it. The verifier only ever runs inside `Ledger::apply_block`/`apply_tx`,
on every node, on public bytes (a proof, a digest, eight output words) that anyone can see.

## 2. Crates and their boundaries

- **`randprotocol-core`** has no I/O, no async runtime, and no Plonky3 dependency. It holds cryptography
  (Dilithium2 via `crystals-dilithium`, BLAKE3), the transaction/block/validator types, the ledger
  and its transaction rules, the note/commitment-tree/address types, gas, genesis derivation, the
  `ConfidentialExecutor` trait (an interface, not an implementation), and the HotStuff state
  machine. Keeping it free of
  I/O and of the zkVM means the entire ledger and consensus logic — the part that must be
  deterministic across every validator — can be unit-tested and simulated (a whole multi-replica
  network) in-process, in milliseconds, without RocksDB, sockets, or a STARK prover in the loop.
  `StubExecutor` (a crypto-free fake proof format) stands in for the real verifier in that world.
- **`randprotocol-zkvm`** is the Rand zkVM itself (vendored from `circuits/research`, resynced with
  `deploy/sync-zkvm.sh`): an RV32I-subset emulator, a Plonky3 batch STARK prover/verifier, and
  `executor.rs`, which is the only place `ConfidentialExecutor` gets a real implementation
  (`ZkExecutor`). `codec.rs` reads/writes program files. This is the one crate allowed to depend on
  Plonky3, and the boundary means a chain can run with `confidential: false` (`DisabledExecutor`,
  in `randprotocol-core`) without linking any of it in.
- **`rand-node`** wraps `randprotocol-core` in I/O: RocksDB storage, libp2p networking, the mempool,
  block sync, the JSON-RPC server, the node event loop, and the `rand-node` CLI. It picks which
  executor to construct (`ZkExecutor`, or `DisabledExecutor` per genesis) and hands it to the
  ledger and consensus layers underneath.
- **`randprotocol-client`** is the RPC client library and the `rand` wallet binary: no RocksDB or
  libp2p dependency. It is where proving happens — `executor::prove` calls straight into
  `randprotocol-zkvm`'s `Machine`, so the wallet links the zkVM prover but never a node's storage or
  networking stack.

## 3. Identity, addresses, keys

A node or wallet key is a 32-byte seed. From it:

- A Dilithium2 (post-quantum lattice signature) key pair: 1312-byte public key, 2420-byte
  signatures.
- The address: `blake3("rand-address" || public_key)`, shown base58.
- A libp2p identity: an ed25519 key derived as `blake3("rand-p2p-identity" || seed)`, stable
  across restarts.

Signed objects (votes, blocks, faucet mints) carry the full public key, not just the address, so a
verifier checks `blake3(public_key) == address` rather than trusting a bare address. The node key
file format (`{ "seed", "address", "public_key" }`, mode 0600) is written by `rand-node keygen`;
only the seed is secret, everything else is re-derived on load (`docs/cli.md`).

A **wallet** key is a different object entirely, and this is where the spending/viewing split
lives: a 256-bit `SpendKey` from which the viewing key `nk = H(NK, sk)` is derived, and from that
the note-owner field `pk`, the nullifier function `H_NF(nk, cm)`, the outgoing viewing key, the
ML-KEM-768 decapsulation key, and the `rand1…` address (32-byte `pk` plus the 1184-byte
encapsulation key, base58, ~1668 characters). A wallet key never signs a transaction: a bundle
authorises itself by its proof. See `docs/shielded.md` §1.

## 4. Transactions

A transaction is a shielded bundle, an action, or — for a faucet mint — an action alone:

```
Transaction { chain_id: u64, bundle: Option<Bundle>, action: Action }
Bundle { anchor, nullifiers[2], commitments[2], fee: u64, burn: u64, asset: u32, time: u32,
         envelopes[2], proof }
```

`Action` has four variants (bincode tags 0–3, in declaration order):

| action | fields | bundle | what it does |
|---|---|---|---|
| `None` | — | required | a plain shielded transfer: the bundle is the whole transaction |
| `Mint` | `cm, envelope, amount: u64, minter: PublicKey, signature` | **must be absent** | testnet faucet: creates one note of public `amount` |
| `Deploy` | `base_pc: u32, words: Vec<u32>` | required | puts a zkVM program on chain |
| `Call` | `program: ProgramId, proof: Vec<u8>` | required | verifies a proof and records its eight outputs |

Everything that moves value moves it through the bundle, including the fee. A deploy and a call
are ordinary shielded transactions whose bundle happens to be a self-transfer of zero: it exists to
pay the action's fee floor out of the caller's notes, and the chain never learns whose notes they
were. There is no `Action` that pays an address, because there are no addresses to pay.

**Identity and replay.** There is no signature over the transaction and no sender field. The
transaction id used everywhere (mempool keys, receipts, RPC) is
`blake3("rand-txid" || bincode(Transaction))`. Replay protection is the nullifier set: a bundle
publishes `H_NF(nk, cm)` for each input, and a second transaction spending the same note is
rejected with `nullifier already spent` — no nonces, and nothing per-sender to order.

**Cheap checks before expensive checks.** Verifying a bundle proof costs roughly 16–20 ms once its
verifier key is warm (`docs/confidential.md` (and `docs/zkvm.md` for the machine itself)) and materially longer the first time. Left
unguarded, an attacker could flood a node with syntactically-valid, cryptographically-bogus
transactions and burn CPU on proof verification for each one. `Ledger::validate_inner` therefore
runs the spec §7 order — size caps, chain id, shape and fee floor, anchor, time, nullifier and
commitment membership, the action's own cheap checks — and only then recomputes the bundle digest
and verifies the STARK; a call's own proof, and the tier-dependent fee floor that only a decoded
proof reveals, come last of all. `Mempool::insert` is cheaper still in front of it: a duplicate
hash, a nullifier or commitment already claimed by a pending transaction, or a full pool are all
answered before the ledger probe runs at all (§8).

**Fees.** The fee is a public field of the bundle, and all of it — tip above the minimum included
— is credited to the block proposer's `rewards` in the validator register. There is no burn and no
split. Minimums come from `randprotocol_core::gas`: every bundle pays `BUNDLE_BASE = 1,000,000` units
(0.001 RAND); a `Deploy` adds `100,000` units per program word; a `Call` adds `1,000,000` units
at the lowest tier (10) plus `100,000` per two tiers above it, to `1,500,000` at tier 20
(`call_fee`). A `BridgeBurn` pays `BUNDLE_BASE` twice, because it is the one transaction that
carries two bundles and a node verifies both. A mint carries no bundle and pays nothing. Blocks
are capped at 2,000 transactions and 4 MiB of encoded bytes (`gas::MAX_BLOCK_TXS`,
`gas::MAX_BLOCK_BYTES`) — enforced both where the proposer selects candidates and inside
`Ledger::apply_block`, so a Byzantine leader cannot stuff an
over-limit block and force every replica to execute it. At constraint set 5's 80-query profile a
bundle proof is ~1.3 MB (it was ~300 KB at 27 queries), so a 4 MiB block holds **three** shielded
transactions — see `docs/block-space.md` for why the cap stays at 4 MiB and block-level aggregation
is the queued remedy.

## 5. Ledger and state root

The ledger is the shielded pool plus the two public registers:

```
tree          CommitmentTree — depth 32, Poseidon2, append-only, stored as a frontier
commitments   BTreeSet<Word8> — every leaf ever appended (the frontier cannot answer membership)
nullifiers    BTreeSet<Word8> — every note ever spent
anchors       VecDeque<(height, root)> — the last ANCHOR_WINDOW = 256 block-end roots
validators    BTreeMap<Address, ValidatorEntry { public_key, stake, rewards }>
programs      BTreeMap<ProgramId, ProgramRecord>
```

The tree is a *frontier*: `O(DEPTH)` state and `O(DEPTH)` per append, so consensus state never
materializes the leaf set. The leaves live in RocksDB (§7), and a Merkle witness is folded by
rebuilding a full tree from them on demand.

Applying a block is atomic: `Ledger::apply_block` clones itself into a scratch copy, applies every
transaction of the block to it (any single invalid transaction fails the whole block), records the
block-end anchor, and only commits the scratch copy back if the resulting `state_root` equals the
header's. `apply_tx` is atomic in the same way one level down: everything that can fail — the
proposer's register entry, the reward addition — is resolved before the first mutation, so a
rejected transaction leaves the ledger byte-identical.

`Ledger::state_root()`:

1. `nullifier_root` = a BLAKE3 pairwise Merkle root over
   `blake3("rand-nullifier-leaf" || nf(32))` for every nullifier, in sorted (BTreeSet) order.
   It is recomputed per block: `O(n)`, which is fine until the set passes about 10^6 entries and
   wants an incremental accumulator.
2. `validators_root` = the same construction over
   `blake3("rand-validator-leaf-2" || address(32) || stake_be(8) || rewards_be(8) ||
   nonce_be(8) || pending_len_be(8) || (release_epoch_be(8) || amount_be(8))* ||
   payout_pk(32) || payout_kem_ek(1184))`, in address-sorted order. That is the whole v2
   register entry (phase S2): the bonded stake, the proposer rewards, the replay nonce, the
   unbonding queue and the shielded address a withdraw pays. The queue is length-prefixed so
   the leaf is injective; every other field is fixed width.
3. `programs_root` = the same over `blake3("rand-program-leaf" || program_id)`, in id order.
4. `state_root = blake3("rand-state-2" || tree_root(32) || nullifier_root(32) ||
   validators_root(32) || programs_root(32))`.

`tree_root` is the commitment tree's own Poseidon2 root — the same value a wallet anchors a proof
to — so the pool's contents are committed by the state root without any of them being readable
from it. The `-2` in the domain is the S1 break from the account-era `"rand-state"`.

The order transactions were applied in is not separately hashed into the state root; the block's
`tx_root` (a Merkle root over `tx.hash()` in block order, checked before any transaction is
applied) fixes it instead.

**What is public.** Commitments, nullifiers, anchors, fees, program code, call receipts, validator
stakes and validator rewards. **What is not**: who sent a transaction, who received it, what any
note is worth, which leaf a nullifier corresponds to, and which of a bundle's two inputs was a
dummy. The one place an amount is stored in the clear is a faucet mint (and the equivalent genesis
`alloc` note), where value enters the pool — the same one-hop visibility a transparent-to-shielded
deposit has anywhere — and the `rewards` counter in the validator register. `docs/shielded.md` §2
has the per-action table.

`Deploy`/`Call` implement confidential computation; see §9 for the full path. Briefly: `Deploy`
validation only decodes instructions (cheap, so it can run inline in block application) and the
executor computes a code commitment stored as `ProgramRecord.code_hash`; `Call` validation verifies
a STARK proof against that commitment and records the eight public output words in a receipt.
There is no longer an `Effect`: output kind 1, the program-driven transfer to an account, was
deleted with the accounts, and a call moves value only through the bundle that pays for it.
`Mint` exists only for testnets: gated by the genesis `faucet` flag (itself part of the genesis
hash), capped at 100 RAND per call, signed by a validator's own key, and admitted through the
mempool and consensus like anything else — its commitment can be created only once, so it cannot
be replayed.

## 6. Consensus: chained HotStuff

Each block carries a quorum certificate (QC) for its parent — a set of Dilithium2 votes from
validators holding strictly more than 2/3 of total stake (`ValidatorSet::has_quorum`). Rules
currently implemented in `crates/randprotocol-core/src/consensus/hotstuff.rs`:

- **Leader schedule.** Pure round robin: the leader of view `v` is `validators[v mod n]`, validators
  sorted and deduplicated by address at genesis. No stake weighting in leader selection — stake
  only counts votes.
- **Proposing.** The leader of view `v` proposes once it holds a QC for `v-1`, or a quorum of
  `NewView` messages for `v` (view synchronisation, so a node that starts late or resumes from a
  partition does not have to time out through every intermediate view). A proposal that would apply
  an invalid transaction simply drops that transaction rather than failing the whole block.
- **Voting and safety.** A validator votes for a block once per view (`last_voted_view` strictly
  increases), and only if the block is *safe*: its justify QC is newer than the validator's locked
  QC, or the block extends the locked block. The vote is only sent (or, if this node is itself the
  next leader, only processed locally) after `SafetyState { view, high_qc, locked_qc,
  last_voted_view }` is written to RocksDB with an fsynced `put` — the vote must never leave the
  node, or count for anything locally, before that write lands.
- **QC assembly.** Every validator assembles QCs locally from gossiped votes (`on_vote` no longer
  drops votes at non-collectors), so the chain keeps committing even if the leader of the next view
  is offline (shipped in the consensus-hardening merge, commits 1d24bf9, d5143a6, a44d3f4; before
  it, one down collector stalled finality). The wire cost is unchanged: votes already flooded the
  gossip topic, they were just being discarded by the application gate.
- **Lock and commit.** Chained three-QC rule, evaluated on each newly-processed block `b*`: `b''` is
  the block `b*.justify` certifies, `b'` is the block `b''.justify` certifies, `b` is the block
  `b'.justify` certifies. The lock advances to `b''.justify` when it is newer than the current lock;
  `b` (and every uncommitted ancestor back to the current committed head) commits once this
  three-link chain is found and actually threads back to the committed head — and only if the three
  certifying QCs are in *consecutive views* `v, v+1, v+2` (the three-consecutive-view commit rule,
  shipped in the same hardening merge; without it, two forks could ratchet past each other's locks
  and both finalize).
- **Timeouts.** Base view timeout `--view-timeout-ms` (default 3,000 ms), doubling per consecutive
  timeout up to 8x, reset to zero on any progress (a QC formed or a new view entered from a peer). A
  `NewView` from a validator already in a higher view pulls a lagging node forward without it having
  to wait out every intermediate timeout itself. Views are bounded (`MAX_VIEW_AHEAD` = 10⁶) and all
  view arithmetic is saturating.
- **Empty blocks and pacing.** The leader still proposes (an empty block, if no transactions are
  pending) so the chain keeps advancing during idle periods; proposals are paced to at least
  `--block-interval-ms` (default 1,000 ms) after the last block seen from *any* proposer, not just
  this node's own last proposal.
- **Block limits.** See §4 — the 4 MiB / 2,000-transaction cap is a consensus rule: the proposer
  respects it when building its candidate list (`Mempool::candidates_within`) *and*
  `Ledger::apply_block` rejects an over-limit block outright (`gas::MAX_BLOCK_BYTES` /
  `gas::MAX_BLOCK_TXS`), so a Byzantine leader cannot stuff one and force every honest replica to
  execute it.
- **Speculative state.** Every entry in the in-memory block tree clones the full ledger. The tree,
  the pending-vote map, the NewView map, and the view counter are all bounded against a misbehaving
  or diverging peer (`max_tree_blocks` = 512, 4096 pending-vote keys, 2048 NewView views,
  `MAX_VIEW_AHEAD`); the per-entry ledger clone is a known design cost to revisit as state grows.

## 7. Storage, startup verification, hard forks

One RocksDB per data directory, eleven column families:

| family | key → value |
|---|---|
| `blocks` | height (BE u64) → block |
| `qcs` | height → the QC certifying that block |
| `block_index` | block hash → height |
| `txs` | tx hash → (height, index) |
| `notes` | leaf index (BE u64) → `NoteRow { cm, envelope, height }` |
| `nullifiers` | nullifier (32 bytes) → the height of the block that spent it |
| `anchors` | height (BE u64) → the commitment-tree root at the end of that block |
| `validators` | validator address (32 bytes) → `ValidatorEntry { public_key, stake, rewards }` |
| `programs` | program id → `ProgramRecord` |
| `receipts` | tx hash → `CallReceipt` |
| `meta` | small blobs: head height, genesis hash, chain id, the consensus `SafetyState`, the commitment-tree frontier (`tree`), and `hc_bundle` |

`accounts` is gone, and so are the three bridge families. `notes` is dense from zero and keyed in
tree order, which is what makes `rand_getCommitments` a straight range scan and
`notes_count()` the next leaf index; it is also the only copy of the leaf set, since consensus
state keeps the frontier alone (§5). `anchors` is pruned to the newest `ANCHOR_WINDOW` heights.

A commit of one or more blocks is a single, fsynced `WriteBatch`: the blocks, QCs and indexes, one
`notes` row per commitment the block created (a bundle's two outputs, or a mint's single note),
one `nullifiers` row per spend, the block-end `anchors` row, the proposer's rewritten
`ValidatorEntry`, any new programs and receipts, the new `meta/tree` frontier, and the new head.

**Startup verification (`--verify-chain off|quick|full`).** Block 0 must equal the genesis file's
own derivation, and this build's bundle guest must equal the genesis `hc_bundle` — a mismatch
refuses to start at all, naming both digests. `quick` then replays every later block's transactions
against a ledger rebuilt from genesis, checking each block's parent link, height, index entry,
transaction root, and that re-execution (through the real executor — including every bundle proof
and every `Call` proof) reproduces the header's state root. `full` additionally checks every
proposer signature and every QC's votes. On the first inconsistency the node truncates its chain to
the last good height — deleting the `notes` rows above the replayed ledger's next index, the
`nullifiers` and `anchors` rows above that height, and rewriting every validator row and the tree
frontier from the replayed ledger, while keeping its consensus safety state so it never
double-votes — and lets sync refetch the rest from peers. `rand-node verify --repair` does the
same thing offline, without running the node.

**Why a constraint-set change is a hard fork.** `--verify-chain quick`/`full` re-verify every
historical `Call`'s proof through whatever zkVM constraints the running binary implements. A STARK
proof is a proof *about a specific constraint system* — different FRI parameters, a different table
set, or a different program-digest construction all change what "a valid proof" even means. A node
built from a newer `randprotocol-zkvm` therefore fails startup replay at the first historical block that
contains a confidential call proved under the old constraints, and truncates its own chain at that
point (`docs/confidential.md` documents two such transitions already, "constraint set 2" and
"constraint set 3"). The only ways forward on a chain whose constraints changed are to start a new
chain id, or to run the old-constraint nodes (or the new ones, on old history) with
`--verify-chain off` so they stop re-checking proofs they can no longer verify.

## 8. Networking and sync; mempool

libp2p 0.54 over TCP with Noise and Yamux. Behaviours: **gossipsub** (topics
`rand/<chain-id>/consensus`, `/tx`, `/status`), **Kademlia** (protocol `/rand/<chain-id>/kad/1`)
seeded from `--bootstrap`, **identify**, optional **mDNS** for LAN discovery, **request-response**
(`/rand/sync/1`, CBOR) for block sync, and **ping** every 15 s. A node remembers every address it
dialled or learnt through identify and redials disconnected known peers every 30 s, in addition to
the bootstrap list.

Every node gossips its status (height, head hash, view) every 3 s. A node that sees a peer more than
one block ahead sends a sync request for up to 100 committed blocks with their QCs; on the reply it
verifies each QC against the validator set, checks linkage and leader, re-executes every block
(proof verification included, exactly as if it had arrived live), persists, and rebuilds its
consensus replica on the new head. A proposal whose parent is unknown triggers a targeted fetch of
that one block by hash, or a full batch sync if the node has fallen more than two blocks behind.

**Mempool.** Transactions are validated against the ledger at the tip of the consensus tree (not
necessarily the last committed block — the tip a proposer would actually build on). A redacted
chain has no senders and no nonces, so there is no per-sender ordering left to do: a bundle is
admissible or it is not, and two bundles are related only when they touch the same note. What
replaces the nonce bookkeeping is *conflict* tracking. The pool indexes every pending
transaction's nullifiers and commitments, and admission runs in this order:

1. a duplicate transaction hash;
2. a nullifier or a commitment already claimed by a pending transaction (`conflicts with a pending
   transaction over <value>`) — at most one of the two could ever be included, and carrying the
   other would cost the proposer block space and a proof verification per gossip round;
3. a full pool;
4. the state-dependent half of `Ledger::validate` — anchor in the window, `time` in it, nullifiers
   unspent, commitments absent, attestation digests unclaimed, the register nonce — everything that
   can go stale between admission and inclusion, and nothing that costs a proof;
5. the transaction queues (64 deep at most) for one of four verification workers, and
   `Ledger::validate`'s expensive half — the bundle digest, the bundle proof, then the call's own —
   runs on a blocking task **off the consensus loop**, against a snapshot of the tip that is
   cloned lazily, at most once per tip change and only while a transaction is waiting;
6. `insert_verified` re-runs step 4 against the tip the transaction is actually pooled on — it may
   have moved while the proof ran — and admits it.

Steps 1–4 are `Mempool::precheck`, and step 5 is the only one that verifies a STARK, so everything
cheaper has refused what it can before that cost is paid — and because the cost is paid on a
worker, a flood of bad proofs occupies four threads, never the loop that votes. The proposer orders
candidates by fee (highest first, ties broken by hash so every honest proposer
building on the same pool picks the same block) and fills up to the 2,000-transaction / 4 MiB
budget, re-checking the cheap half of admission — anchor still in the window, `time` still in it,
nullifiers not yet spent, commitments not yet present — against the ledger it is building on. After
every commit, `prune` drops exactly the same way: transactions whose note was spent by someone
else, whose commitment now exists, or whose anchor or `time` has scrolled out of the 256-block
window. A bundle that loses a double-spend race therefore disappears on its own. See §4 for the
ledger's own admission order, which steps 4 and 5 between them run.

Two guards sit in front of that order for gossiped traffic, and a verdict cache behind it. A
gossiped transaction is metered against the peer that *forwarded* it — a token bucket, burst 16
refilling at 4/s; RPC submissions are not metered, because that port is the operator's own and is
already bounded by the request-body limit — and a transaction this node has already refused for a
reason that is a function of its bytes alone (a bad proof, a bad signature, an oversized part) is
refused again from an 8192-entry FIFO cache instead of being verified a second time. A verdict
that says something about *this node's state* — an unknown anchor, a spent nullifier — is never
cached: a node one block behind would poison itself against transactions that are about to be
valid.

Gossipsub runs with application-level validation (`validate_messages()`), so a transaction is
forwarded to other peers only once it has verified here; consensus and status messages are
accepted immediately, exactly as before. The invariant the switch imposes is that every delivered
message is reported back to gossipsub **exactly once** — accept, reject or ignore — or this node
silently stops forwarding it, so every admission path, error paths included, ends in exactly one
report. `ValidationMode` stays `Permissive` on purpose: a Strict/Permissive mix across a fleet
drops messages, and application-level validation is local to one node, so the change rolls out by
ordinary restart. A *proposal's* proof verification stays on the consensus loop: a proposal is
signed by a scheduled leader and paced by the block interval, so it is not the DoS vector, and
moving it would change when a vote is emitted.

## 9. End-to-end confidential transaction

This section follows one `private_payment` call — `rand call <program-id> --input 400 --input 250
--input 300 --input 75` — from the wallet to a settled receipt. `private_payment`
(`randprotocol-zkvm::guests::private_payment`) reads four private balances and, if their sum is at least a
threshold baked into the program, publishes the surplus in its output words; on this chain those
words are recorded and nothing else follows from them, because the effect that used to pay an
account was deleted with the accounts (§5).

Two proofs are involved and it is worth keeping them apart: the **call proof**, about the program's
execution, and the **bundle proof**, about the notes that pay for it. The call rides on the bundle
the way a transfer's action rides on one; the chain verifies both.

### a. Deploy

Before anyone can call a program, someone deploys it:

```
rand program build --guest private_payment --arg 1000 --out pp.json
rand program deploy pp.json
```

The wallet assembles (or loads, for a hand-written `.json`/`.bin` file) `{ base_pc, words }` and
computes the content address `program_id = blake3("rand-program" || base_pc(LE32) ||
words(LE32 each))` — this is a plain content hash, purely for addressing, distinct from the zkVM's
own in-circuit digest below. It then builds a transaction whose action is `Deploy { base_pc, words }` and whose bundle pays at
least `BUNDLE_BASE + deploy_fee(words.len()) = 1,000,000 + 100,000 * words.len()` units — a
self-transfer of zero out of the wallet's own notes, proved locally like any other bundle — and
submits it. Nothing in that transaction says who deployed the program.

Every node that applies the block runs `ZkExecutor::check_program(base_pc, words)`: `base_pc` must
be word-aligned, the program must be non-empty, and *every word must decode as an instruction* — a
program that doesn't parse is rejected right there, before anything expensive happens, exactly
because deploy validation runs inline inside block application and so must stay cheap. Having
decoded every word, `check_program` computes `hc = Program { base_pc, words }.digest()` — the zkVM's
in-circuit Poseidon2 program digest (`isa::Program::digest`, absorbed through the same Poseidon2
sponge the guest's own hashing uses, so it is provable in-circuit) — and stores its 8 little-endian
`u32` words (32 bytes) as `ProgramRecord.code_hash`. This is no longer a merely informational label:
`hc` is exactly the value `Machine::verify` checks a call's proof against, so `code_hash` *is* the
verification key material from this point on. `ProgramRecord` (id, base_pc, words, code_hash,
deployed_at — there is no `deployer` field any more) goes into the ledger's programs map and so into `programs_root` — deployed
programs are public, content-addressed, immutable data.

Once the block commits, the node warms the verifier for the tiers real guests land on today (10,
12 and 14) at this program's declared table height in a background `spawn_blocking` task
(`ZkExecutor::warm`), so the first call against it doesn't pay the full uncached-verify cost. The
key is keyed on `(tier, program_log_height, input_log_height, keccak_log_height,
sha256_log_height, public_log_height)` — constraint set 6's six components — not on the program's
content, so this warms shared keys that every program of the same shape reuses, not a per-program
cache. `warm` covers two input-height classes (the smallest table and the 4-word-call class the
current guests use) at `keccak_log_height = 0` and `sha256_log_height = 0`, since no guest this
chain deploys calls either hash syscall, and at the program's own public segment height
(`public_log_height(ProgramRecord.public_len)`: the empty segment's for a program deployed without
a public input, `verify_call` below): twelve keys total, one of which a first call
typically finds already built by an earlier verify.

### b. Prove (wallet, off-chain)

`rand call` fetches the deployed code back from the chain (`rand_getProgramCode`) rather than
trusting a local copy, reads the chain's declared FRI profile from `rand_status`, and warns if it
is the insecure `test` profile. It then runs the program once in the plain emulator to find how many
cycles it takes, and picks the smallest tier `t` with `2^t - 1 >= cycles` — a tier is a proof-of-work
sized padding bucket (10, 12, 14, 16, 18, or 20), and the proof reveals only which tier was used,
never the real cycle count.

`Machine::prove` (or, behind `--cuda`, `prove_with(Backend::Cuda)` — the batch STARK's NTTs and
Poseidon2 Merkle commitments run on an attached NVIDIA GPU instead of the CPU; there is no fallback,
so a missing driver, missing PTX, or a tier too large for device memory is a hard error rather than
a silent CPU run) builds nine interconstrained trace tables for this execution (`docs/zkvm.md` describes them): `program` (now a
witness, decoded in-circuit — no longer the verifier's own preprocessed copy), `cpu` (whose first
rows are three *digest prefixes* that absorb the whole program, the committed private
inputs, and the public segment through Poseidon2, one permutation per up to four words, computing
`hc`, the salted `H_IN` and the unsalted `H_PUB`
as part of the trace itself), `memory`, `alu`, `range`, `nibble` (the
old combined byte-range table split in two for a much smaller preprocessed commitment),
`poseidon2` (the syscall's own chip), `input` (one row per committed private-input word,
feeding the `H_IN` digest and `READ_INPUT` over two split buses), and `public` (one row per
public-segment word, feeding `H_PUB` and `READ_PUBLIC` the same way — mandatory since constraint
set 6, four rows even when the segment is empty). Two further tables are
*optional* per proof: `keccak` (constraint set 5) and `sha256` (arrived with constraint set 6),
each carried only when the guest called the matching syscall — a proof that declares
`keccak_log_height = 0` and `sha256_log_height = 0` carries neither, and the batch has nine
instances, which is every proof on this chain, since no guest here calls either
syscall. LogUp/permutation buses tie them together (e.g. the
`POSEIDON2` bus between `cpu`'s hash rows and the `poseidon2` chip). The private inputs — the four
balances here — never appear in any public column; they only steer which trace rows get produced.
FRI is run in hiding mode, so two proofs of the identical execution are different bytes — proofs
don't fingerprint the specific inputs that produced them.

The proof publishes exactly 34 public values (`tables::cpu::pv`): `PC_ENTRY` (1 word), `TIER` (1
word), `OUT0..OUT0+7` (the eight output words), `HC0..HC0+7` (the 8-word program digest),
`IN0..IN0+7` (the salted private-input commitment `H_IN`, milestone 4.1), and `PUB0..PUB0+7` (the
unsalted public-segment commitment `H_PUB`, constraint set 6). It is serialized as
`Proof { tier, program_log_height, input_log_height, public_values, batch }`, postcard-encoded — the
same shape `Action::Call.proof` carries — with `keccak_log_height` and `mem_log_height` added to it
by constraint set 5 and `sha256_log_height` and `public_log_height` by constraint set 6. Measured upstream on a different guest (`fib`) at tier 10 under constraint
set 3 (`docs/confidential.md`): proof size 268 KB, prove time 3.1 s, first (uncached) verify 16 ms;
at constraint set 5's 80 queries the same proof is ~1.20 MB and first verify ~233 ms, and at
constraint set 6 it is 1 298 729 bytes (see `docs/confidential.md`, "Constraint set 6"). The README's own measurement of `private_payment` specifically (an
earlier constraint set): proving ~21 s, proof ~0.9 MB, on-chain verification ~19 ms once its
verifier key is cached (the key itself costs ~2 s to build on a laptop, ~7 s on a 2-vCPU server, and
is what deploy-time warming amortizes away).

### c. Submit

The wallet builds `Call { program: program_id, proof }` and a bundle paying at least
`BUNDLE_BASE + call_fee(tier)` — 2,000,000 units at tier 10, rising by 100,000 per two tiers to
2,500,000 at tier 20 — then proves that bundle (about 100 s at tier 14) and submits the pair over
`rand_sendTransaction`. The RPC handler hands it to the admission path, which runs the order
from §8: the pre-screen first — duplicate hash, nullifier/commitment conflicts, pool space, the
state-dependent half of validation — then the full `ledger.validate` probe (chain id, fee floor,
anchor, time, spends, the bundle digest, the bundle proof, and finally the call's own proof) on a
verification worker off the consensus loop, and only then is it pooled against the tip and
gossiped.

### d. Block

The leader includes the transaction in its next proposal (subject to the block's size/count budget,
§4/§6). Every validator, on receiving the block — proposer and non-proposer alike — applies it
through `Ledger::apply_block` → `apply_tx` → `validate_inner`. The bundle half runs first (spec §7
steps 1–9: caps, chain id, fee floor, anchor, time, nullifiers and commitments, the recomputed
digest, `verify_bundle` against the genesis-pinned `hc_bundle`). Then the call half:

1. Proof size (≤ 2 MiB, `gas::MAX_PROOF_BYTES`) — a cheap bounds check, run back at step 1
   with the other caps.
2. The program must exist (`programs.get(program)`).
3. `ZkExecutor::verify_call`: decode the `postcard`-encoded `Proof`; reject an out-of-range tier or
   declared height — `program_log_height`, `input_log_height`, `keccak_log_height`,
   `sha256_log_height`, `public_log_height`, `mem_log_height`
   — before any of them is used to size anything (guarding against a panic on an attacker-chosen
   huge shift), through `machine::check_declared_heights`, the very function the verifier itself
   calls; check the proof's declared degree bits match what those heights imply, which also pins the
   batch's instance count (nine mandatory tables, plus one per optional hash table declared);
   decode `record.code_hash` back
   into `hc`; call `Machine::verify_public(&hc, &[], &proof)` — the actual batch-STARK check,
   against a verifier
   key cached by `(tier, program_log_height, input_log_height, keccak_log_height,
   sha256_log_height, public_log_height)` (shared across
   every program of that shape, not recomputed per call). The `&[]` is this chain's public
   segment: no transaction publishes public words, so the only admissible `H_PUB` is the empty
   segment's digest (`docs/confidential.md`, "Constraint set 6").
4. `Machine::verify` itself checks, in order: the public value count is exactly 34; every public
   value is a canonical field element (rejecting `x` and `x + p` as two encodings of one proof);
   `HC0..HC7` match the caller-supplied `hc`; `TIER` matches the proof's declared tier and that tier
   is one of the six defined; every declared height is in range; the declared degree bits match;
   then the batch STARK verification equation itself — and `verify_public` adds the one check
   `verify` cannot do on its own: `PUB0..PUB7` equal `hash::public_digest(&[])`, recomputed
   natively from the (empty) public segment.
5. Back in the ledger: the fee must now cover `BUNDLE_BASE + call_fee(tier)`, which is only
   knowable once a verified proof has revealed the tier. This is the last check of the whole
   admission order.
6. The eight raw `u32` outputs and the tier go into a `CallReceiptData` verbatim. Nothing is
   decoded and nothing else moves: the bundle already spent its two notes, created its two, and
   credited its fee to the proposer's register entry.

If any step fails, the whole transaction is invalid and the whole block is rejected — there is no
partial application. After every transaction in the block applies, the resulting `state_root` must
equal the header's, or the block is rejected outright (§5).

### e. Consensus

The block's votes, its QC, and the lock/commit rules of §6 apply to this block exactly like any
other — a confidential call does not get special consensus treatment. Once the block commits (with
its uncommitted ancestors, per the three-QC rule), it and its `CallReceipt`s are written together in
one fsynced `WriteBatch`.

### f. Afterwards

`rand_getReceipt` (or `rand receipt <tx>`) now returns
`{ tx, program, tier, outputs, height, index }` — no `effect` field. An explorer, or anyone else
watching the chain, sees: the program id and its `hc` (via `rand_getProgram`), the tier the call
was proven at, the eight output words, and the bundle's public fields (two nullifiers, two
commitments, a fee). It never sees: the four private input balances, any register or memory value,
which branch the program took, the real cycle count (only which padded tier bucket it fit in), who
called it, or what the notes that paid for it were worth. Caveats worth stating plainly: `hc` is
*binding*, not *hiding* — it has no per-deployment salt, so anyone who can enumerate candidate
programs can test a guess against a published `hc` and confirm which was deployed; the output words
are published verbatim, so a program that writes a number to an output slot publishes that number;
and the public fee tells a watcher which *kind* of transaction this was, since the floors differ by
action.

### g. Sync and replay

A node joining later, or catching up after a partition, does not take any committed receipt on
faith. Batch sync re-executes every fetched block through the real executor — every `Call`'s proof
is re-verified, not merely trusted because a quorum signed the block — before the node accepts it
and advances its head. `--verify-chain quick|full` does the same thing over the whole chain at
startup (§7): quick mode re-derives every state root (proof verification included, since it goes
through the real executor); full mode additionally re-checks every proposer signature and QC.

## 10. Failure modes

| situation | rejected by | what the caller sees |
|---|---|---|
| Bad or forged proof | `ZkExecutor::verify_call` → `Machine::verify` (ledger, both mempool probe and block application) | RPC: `invalid proof: ...`; block: the transaction is dropped from a proposal, or a block containing it is rejected by every other validator |
| Tier not one of 10/12/14/16/18/20 | `verify_call`'s pre-check, and again inside `Machine::verify` | `invalid proof: unknown tier` |
| Declared `program_log_height` out of `[4, 22]` | same two layers | `invalid proof: program height out of range` |
| Declared `input_log_height` out of range | same two layers | `invalid proof: input height out of range` |
| Declared `keccak_log_height` neither 0 nor in `[5, 20]`, or above `tier + 5` | same two layers | `invalid proof: keccak height out of range` |
| Declared `sha256_log_height` neither 0 nor in `[6, 20]`, or above `tier + 6` | same two layers | `invalid proof: sha256 height out of range` |
| Declared `public_log_height` outside `[2, 20]` (mandatory — no `0` escape) | same two layers | `invalid proof: public height out of range` |
| Declared `mem_log_height` out of `[tier + 2, 24]` | same two layers | `invalid proof: memory height out of range` |
| Call proof's `H_PUB` ≠ the program's recorded public digest (`public_digest(&[])` for a program deployed without a public input) | `verify_call`, after `Machine::verify`; bundles `verify_public(hc, &tx.binding(), proof)` since the transaction binding (`docs/confidential.md`) | `invalid proof: …` naming `PublicValues` |
| Proof's degree bits don't match the declared heights | `verify_call`'s pre-check | `invalid proof: degree bits` |
| Stale/wrong program (proof's `hc` doesn't match `record.code_hash`) | `Machine::verify`'s public-value check | `invalid proof: ...` (opaque `VerifyError`, no separate error code) |
| Unknown program id | `Ledger::check_call` | `unknown program <id>` |
| Oversized proof (> `max_proof_bytes`, 2 MiB unless the genesis sets it) | `Ledger::validate_inner` step 1, before any decoding | `proof too large` |
| Fee below the action's floor | `Ledger::validate_inner` step 3 | `fee N below minimum M` |
| Fee below `BUNDLE_BASE + call_fee(tier)` | `Ledger::validate_inner` step 10, after the tier is known from a successful verify | `fee N below minimum M` |
| Bundle anchored to a root outside the window | step 4 | `anchor is not one of the last 256 roots` |
| A bundle's `time`, or a bundle-less `Withdraw`'s, outside `[height - 256, height]` | step 5 | `time T is outside [lo, hi]` |
| Note already spent (a replay, or a lost double-spend race) | step 6 | `nullifier already spent` |
| Bundle plaintext does not match what its proof published | step 8 | `the bundle's digest is not what its proof published` |
| Bundle proof for another guest, or invalid | step 9 (`verify_bundle` against the genesis `hc_bundle`) | `invalid bundle proof: …` |
| Two pending transactions spending one note | `Mempool::insert` | `conflicts with a pending transaction over <nullifier>` |

## 11. Pointers

- `docs/zkvm.md` — the zkVM's ISA, tables, syscalls and execution model.
- `docs/fees.md` — fees, tiers, proving cost, and why there is no gas metering.
- `docs/block-space.md` — proof size against the block cap, throughput, chain growth, and how the number comes down.
- `docs/confidential.md` — the on-chain call model, gas schedule, constraint-set history (why a
  zkVM upgrade is a hard fork), and the `--cuda` GPU proving path in full.
- `docs/zkvm-milestones.md` — being written alongside this page; tracks the zkVM's milestone history
  in more detail than the constraint-set notes here.
- `docs/shielded.md` — the user's guide to the pool: keys, what is published and what is not, the
  wallet commands, the RPC surface, the admission order, and what still leaks.
- `docs/bridge.md` — the cross-chain bridge, wired up on the shielded chain since phase S3: a
  bridged holding is a note whose `asset` word is the registry's index for it, an attestation
  deposits one note the chain computes itself, and a burn is the chain's one two-bundle transaction.
  A chain turns it on with a `bridge` section in its genesis.
- `docs/rpc.md` — every JSON-RPC method, including the ones this page names (`rand_getReceipt`,
  `rand_getProgram`, `rand_sendTransaction`, `rand_status`) with full parameter and result
  shapes.
- `docs/cli.md` — every `rand-node` and `rand` command this page references
  (`genesis`, `verify`, `program deploy`, `call`), with arguments and defaults.
