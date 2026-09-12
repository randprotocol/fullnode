# Architecture

The original design spec is in `docs/superpowers/specs/2026-09-09-shrugg-fullnode-design.md` and
the shielded pool's is `docs/superpowers/specs/2026-09-11-shielded-pool-design.md`; this page
describes what is implemented, and walks one confidential transaction end to end. Where the code
and an older doc disagreed, this page follows the code.

Phase S1 replaced the account ledger with a shielded note pool. There are no accounts, no
balances, no nonces and no signed transfers anywhere below; `docs/shielded.md` is the user-facing
guide to what took their place.

## 1. Overview

```
 WALLET (shrugg-client)                           EVERY NODE (shrugg-node)
 ───────────────────────                          ─────────────────────────────────────
  scan the tree with the viewing key                 JSON-RPC (shrugg_sendTransaction, ...)
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
  bincode(Transaction) ───── shrugg_sendTransaction ─▶│   HotStuff     │◀─── gossipsub / libp2p ──▶
  { chain_id, bundle, action }                       │  (chained BFT) │
                                                     │  leader proposes a block of candidates │
                                                     │  votes → QC → lock → 3-chain commit    │
                                                     └───────┬────────────────────────────────┘
                                                             │ Action::Commit(CommittedBlock)
                                                             ▼
                                                     ┌───────────────┐
                                                     │     Ledger     │  apply_block:
                                                     │  (shrugg-core) │  bundle → digest + verify_bundle
                                                     │                │  Deploy → check_program (cheap)
                                                     │                │  Call   → verify_call ──────┐
                                                     └───────┬────────┘                             │
                                                             │ state_root must match header          │
                                                             ▼                                       ▼
                                                     ┌───────────────┐                     ┌──────────────────┐
                                                     │    RocksDB     │  one fsynced        │ ZkExecutor::      │
                                                     │  (shrugg-node) │  WriteBatch per      │ verify_bundle /   │
                                                     │  blocks/qcs/   │  commit              │ verify_call       │
                                                     │  notes/nulli-  │                      │ (shrugg-zkvm):    │
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

- **`shrugg-core`** has no I/O, no async runtime, and no Plonky3 dependency. It holds cryptography
  (Dilithium2 via `crystals-dilithium`, BLAKE3), the transaction/block/validator types, the ledger
  and its transaction rules, the note/commitment-tree/address types, gas, genesis derivation, the
  `ConfidentialExecutor` trait (an interface, not an implementation), and the HotStuff state
  machine. Keeping it free of
  I/O and of the zkVM means the entire ledger and consensus logic — the part that must be
  deterministic across every validator — can be unit-tested and simulated (a whole multi-replica
  network) in-process, in milliseconds, without RocksDB, sockets, or a STARK prover in the loop.
  `StubExecutor` (a crypto-free fake proof format) stands in for the real verifier in that world.
- **`shrugg-zkvm`** is the Rand zkVM itself (vendored from `circuits/research`, resynced with
  `deploy/sync-zkvm.sh`): an RV32I-subset emulator, a Plonky3 batch STARK prover/verifier, and
  `executor.rs`, which is the only place `ConfidentialExecutor` gets a real implementation
  (`ZkExecutor`). `codec.rs` reads/writes program files. This is the one crate allowed to depend on
  Plonky3, and the boundary means a chain can run with `confidential: false` (`DisabledExecutor`,
  in `shrugg-core`) without linking any of it in.
- **`shrugg-node`** wraps `shrugg-core` in I/O: RocksDB storage, libp2p networking, the mempool,
  block sync, the JSON-RPC server, the node event loop, and the `shrugg-node` CLI. It picks which
  executor to construct (`ZkExecutor`, or `DisabledExecutor` per genesis) and hands it to the
  ledger and consensus layers underneath.
- **`shrugg-client`** is the RPC client library and the `shrugg` wallet binary: no RocksDB or
  libp2p dependency. It is where proving happens — `executor::prove` calls straight into
  `shrugg-zkvm`'s `Machine`, so the wallet links the zkVM prover but never a node's storage or
  networking stack.

## 3. Identity, addresses, keys

A node or wallet key is a 32-byte seed. From it:

- A Dilithium2 (post-quantum lattice signature) key pair: 1312-byte public key, 2420-byte
  signatures.
- The address: `blake3("shrugg-address" || public_key)`, shown base58.
- A libp2p identity: an ed25519 key derived as `blake3("shrugg-p2p-identity" || seed)`, stable
  across restarts.

Signed objects (votes, blocks, faucet mints) carry the full public key, not just the address, so a
verifier checks `blake3(public_key) == address` rather than trusting a bare address. The node key
file format (`{ "seed", "address", "public_key" }`, mode 0600) is written by `shrugg-node keygen`;
only the seed is secret, everything else is re-derived on load (`docs/cli.md`).

A **wallet** key is a different object entirely, and this is where the spending/viewing split
lives: a 256-bit `SpendKey` from which the viewing key `nk = H(NK, sk)` is derived, and from that
the note-owner field `pk`, the nullifier function `H_NF(nk, cm)`, the outgoing viewing key, the
ML-KEM-768 decapsulation key, and the `shrugg1…` address (32-byte `pk` plus the 1184-byte
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
`blake3("shrugg-txid" || bincode(Transaction))`. Replay protection is the nullifier set: a bundle
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
split. Minimums come from `shrugg_core::gas`: every bundle pays `BUNDLE_BASE = 1,000,000` units
(0.001 SHRUGG); a `Deploy` adds `100,000` units per program word; a `Call` adds `1,000,000` units
at the lowest tier (10) plus `100,000` per two tiers above it, to `1,500,000` at tier 20
(`call_fee`). A `BridgeBurn` pays `BUNDLE_BASE` twice, because it is the one transaction that
carries two bundles and a node verifies both. A mint carries no bundle and pays nothing. Blocks
are capped at 2,000 transactions and 4 MiB of encoded bytes (`gas::MAX_BLOCK_TXS`,
`gas::MAX_BLOCK_BYTES`) — enforced both where the proposer selects candidates and inside
`Ledger::apply_block`, so a Byzantine leader cannot stuff an
over-limit block and force every replica to execute it. At ~300 KB per bundle proof that is about a
dozen shielded transactions per block.

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
   `blake3("shrugg-nullifier-leaf" || nf(32))` for every nullifier, in sorted (BTreeSet) order.
   It is recomputed per block: `O(n)`, which is fine until the set passes about 10^6 entries and
   wants an incremental accumulator.
2. `validators_root` = the same construction over
   `blake3("shrugg-validator-leaf" || address(32) || stake_be(16) || rewards_be(8))`, in
   address-sorted order.
3. `programs_root` = the same over `blake3("shrugg-program-leaf" || program_id)`, in id order.
4. `state_root = blake3("shrugg-state-2" || tree_root(32) || nullifier_root(32) ||
   validators_root(32) || programs_root(32))`.

`tree_root` is the commitment tree's own Poseidon2 root — the same value a wallet anchors a proof
to — so the pool's contents are committed by the state root without any of them being readable
from it. The `-2` in the domain is the S1 break from the account-era `"shrugg-state"`.

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
hash), capped at 100 SHRUGG per call, signed by a validator's own key, and admitted through the
mempool and consensus like anything else — its commitment can be created only once, so it cannot
be replayed.

## 6. Consensus: chained HotStuff

Each block carries a quorum certificate (QC) for its parent — a set of Dilithium2 votes from
validators holding strictly more than 2/3 of total stake (`ValidatorSet::has_quorum`). Rules
currently implemented in `crates/shrugg-core/src/consensus/hotstuff.rs`:

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
- **QC assembly.** In this tree, a vote is handled by `on_vote` only on the node that is the leader
  of the *next* view — that leader alone collects votes into a QC once quorum stake is reached
  (`on_vote` rejects a vote outright if `!self.is_leader(vote.view + 1)`). Having *every* validator
  assemble QCs locally from gossiped votes, so the chain keeps committing even if the next leader is
  offline, lands with the consensus-hardening merge (commits 1d24bf9, d5143a6, a44d3f4, 543d72b).
- **Lock and commit.** Chained three-QC rule, evaluated on each newly-processed block `b*`: `b''` is
  the block `b*.justify` certifies, `b'` is the block `b''.justify` certifies, `b` is the block
  `b'.justify` certifies. The lock advances to `b''.justify` when it is newer than the current lock;
  `b` (and every uncommitted ancestor back to the current committed head) commits once this
  three-link chain is found and actually threads back to the committed head. This tree's rule links
  three *QCs*, not three strictly *consecutive view numbers* — tightening it to require the three
  certifying QCs' views to be exactly `v, v+1, v+2` (closing a conflicting-finality edge case around
  gaps left by timed-out views) is the "three-consecutive-view commit rule" that lands with the
  hardening merge above.
- **Timeouts.** Base view timeout `--view-timeout-ms` (default 3,000 ms), doubling per consecutive
  timeout up to 8x, reset to zero on any progress (a QC formed or a new view entered from a peer). A
  `NewView` from a validator already in a higher view pulls a lagging node forward without it having
  to wait out every intermediate timeout itself.
- **Empty blocks and pacing.** The leader still proposes (an empty block, if no transactions are
  pending) so the chain keeps advancing during idle periods; proposals are paced to at least
  `--block-interval-ms` (default 1,000 ms) after the last block seen from *any* proposer, not just
  this node's own last proposal.
- **Block limits.** See §4 — the 4 MiB / 2,000-transaction cap is a consensus rule: the proposer
  respects it when building its candidate list (`Mempool::candidates_within`) *and*
  `Ledger::apply_block` rejects an over-limit block outright, so a Byzantine leader cannot stuff
  one and force every honest replica to execute it.
- **Speculative state.** Every entry in the in-memory block tree clones the full ledger, and (in
  this tree) the tree, the pending-vote map, and the view counter are not yet bounded against a
  misbehaving or diverging peer; adding those bounds (a maximum tree size, capped vote/NewView maps,
  a maximum view-ahead distance) is part of the same hardening work.

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
tree order, which is what makes `shrugg_getCommitments` a straight range scan and
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
double-votes — and lets sync refetch the rest from peers. `shrugg-node verify --repair` does the
same thing offline, without running the node.

**Why a constraint-set change is a hard fork.** `--verify-chain quick`/`full` re-verify every
historical `Call`'s proof through whatever zkVM constraints the running binary implements. A STARK
proof is a proof *about a specific constraint system* — different FRI parameters, a different table
set, or a different program-digest construction all change what "a valid proof" even means. A node
built from a newer `shrugg-zkvm` therefore fails startup replay at the first historical block that
contains a confidential call proved under the old constraints, and truncates its own chain at that
point (`docs/confidential.md` documents two such transitions already, "constraint set 2" and
"constraint set 3"). The only ways forward on a chain whose constraints changed are to start a new
chain id, or to run the old-constraint nodes (or the new ones, on old history) with
`--verify-chain off` so they stop re-checking proofs they can no longer verify.

## 8. Networking and sync; mempool

libp2p 0.54 over TCP with Noise and Yamux. Behaviours: **gossipsub** (topics
`shrugg/<chain-id>/consensus`, `/tx`, `/status`), **Kademlia** (protocol `/shrugg/<chain-id>/kad/1`)
seeded from `--bootstrap`, **identify**, optional **mDNS** for LAN discovery, **request-response**
(`/shrugg/sync/1`, CBOR) for block sync, and **ping** every 15 s. A node remembers every address it
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
transaction's nullifiers and commitments and refuses, in this order:

1. a duplicate transaction hash;
2. a nullifier or a commitment already claimed by a pending transaction (`conflicts with a pending
   transaction over <value>`) — at most one of the two could ever be included, and carrying the
   other would cost the proposer block space and a proof verification per gossip round;
3. a full pool;
4. only then the full `Ledger::validate` probe, which is where the STARK verification happens.

The proposer orders candidates by fee (highest first, ties broken by hash so every honest proposer
building on the same pool picks the same block) and fills up to the 2,000-transaction / 4 MiB
budget, re-checking the cheap half of admission — anchor still in the window, `time` still in it,
nullifiers not yet spent, commitments not yet present — against the ledger it is building on. After
every commit, `prune` drops exactly the same way: transactions whose note was spent by someone
else, whose commitment now exists, or whose anchor or `time` has scrolled out of the 256-block
window. A bundle that loses a double-spend race therefore disappears on its own. See §4 for how
the ledger's own admission order continues from step 4.

## 9. End-to-end confidential transaction

This section follows one `private_payment` call — `shrugg call <program-id> --input 400 --input 250
--input 300 --input 75` — from the wallet to a settled receipt. `private_payment`
(`shrugg-zkvm::guests::private_payment`) reads four private balances and, if their sum is at least a
threshold baked into the program, publishes the surplus in its output words; on this chain those
words are recorded and nothing else follows from them, because the effect that used to pay an
account was deleted with the accounts (§5).

Two proofs are involved and it is worth keeping them apart: the **call proof**, about the program's
execution, and the **bundle proof**, about the notes that pay for it. The call rides on the bundle
the way a transfer's action rides on one; the chain verifies both.

### a. Deploy

Before anyone can call a program, someone deploys it:

```
shrugg program build --guest private_payment --arg 1000 --out pp.json
shrugg program deploy pp.json
```

The wallet assembles (or loads, for a hand-written `.json`/`.bin` file) `{ base_pc, words }` and
computes the content address `program_id = blake3("shrugg-program" || base_pc(LE32) ||
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

Once the block commits, the node warms the verifier for the smallest tier (`TIERS[0]` = 10) at this
program's declared table height in a background `spawn_blocking` task (`ZkExecutor::warm`), so the
first call against it doesn't pay the full uncached-verify cost. The key is keyed on
`(tier, program_log_height)`, not on the program's content, so this warms one shared key that every
program of the same size and tier reuses — not a per-program cache.

### b. Prove (wallet, off-chain)

`shrugg call` fetches the deployed code back from the chain (`shrugg_getProgramCode`) rather than
trusting a local copy, reads the chain's declared FRI profile from `shrugg_status`, and warns if it
is the insecure `test` profile. It then runs the program once in the plain emulator to find how many
cycles it takes, and picks the smallest tier `t` with `2^t - 1 >= cycles` — a tier is a proof-of-work
sized padding bucket (10, 12, 14, 16, 18, or 20), and the proof reveals only which tier was used,
never the real cycle count.

`Machine::prove` (or, behind `--cuda`, `prove_with(Backend::Cuda)` — the batch STARK's NTTs and
Poseidon2 Merkle commitments run on an attached NVIDIA GPU instead of the CPU; there is no fallback,
so a missing driver, missing PTX, or a tier too large for device memory is a hard error rather than
a silent CPU run) builds eight interconstrained trace tables for this execution (`docs/zkvm.md` describes them): `program` (now a
witness, decoded in-circuit — no longer the verifier's own preprocessed copy), `cpu` (whose first
rows are a *digest prefix* that absorbs the whole program through Poseidon2, one permutation per up
to four words, computing `hc` as part of the trace itself), `memory`, `alu`, `range`, `nibble` (the
old combined byte-range table split in two for a much smaller preprocessed commitment), and
`poseidon2` (the syscall's own chip). LogUp/permutation buses tie them together (e.g. the
`POSEIDON2` bus between `cpu`'s hash rows and the `poseidon2` chip). The private inputs — the four
balances here — never appear in any public column; they only steer which trace rows get produced.
FRI is run in hiding mode, so two proofs of the identical execution are different bytes — proofs
don't fingerprint the specific inputs that produced them.

The proof publishes exactly 26 public values (`tables::cpu::pv`): `PC_ENTRY` (1 word), `TIER` (1
word), `OUT0..OUT0+7` (the eight output words), `HC0..HC0+7` (the 8-word program digest), and
`IN0..IN0+7` (the salted private-input commitment `H_IN`, milestone 4.1). It is serialized as
`Proof { tier, program_log_height, input_log_height, public_values, batch }`, postcard-encoded — the
same shape `Action::Call.proof` carries. Measured upstream on a different guest (`fib`) at tier 10
under the current constraint set (`docs/confidential.md`): proof size 268 KB, prove time 3.1 s,
first (uncached) verify 16 ms. The README's own measurement of `private_payment` specifically (an
earlier constraint set): proving ~21 s, proof ~0.9 MB, on-chain verification ~19 ms once its
verifier key is cached (the key itself costs ~2 s to build on a laptop, ~7 s on a 2-vCPU server, and
is what deploy-time warming amortizes away).

### c. Submit

The wallet builds `Call { program: program_id, proof }` and a bundle paying at least
`BUNDLE_BASE + call_fee(tier)` — 2,000,000 units at tier 10, rising by 100,000 per two tiers to
2,500,000 at tier 20 — then proves that bundle (about 100 s at tier 14) and submits the pair over
`shrugg_sendTransaction`. The RPC handler hands it to the mempool, which runs the admission order
from §8: duplicate hash, nullifier/commitment conflicts and pool space first, then the full
`ledger.validate` probe — chain id, fee floor, anchor, time, spends, the bundle digest, the bundle
proof, and finally the call's own proof — before it is gossiped.

### d. Block

The leader includes the transaction in its next proposal (subject to the block's size/count budget,
§4/§6). Every validator, on receiving the block — proposer and non-proposer alike — applies it
through `Ledger::apply_block` → `apply_tx` → `validate_inner`. The bundle half runs first (spec §7
steps 1–9: caps, chain id, fee floor, anchor, time, nullifiers and commitments, the recomputed
digest, `verify_bundle` against the genesis-pinned `hc_bundle`). Then the call half:

1. Proof size (≤ 1 MiB) — a cheap bounds check, run back at step 1 with the other caps.
2. The program must exist (`programs.get(program)`).
3. `ZkExecutor::verify_call`: decode the `postcard`-encoded `Proof`; reject an out-of-range tier or
   `program_log_height` before either is used to size anything (guarding against a panic on an
   attacker-chosen huge shift); check the proof's declared degree bits match what `(tier,
   program_log_height)` implies; decode `record.code_hash` back into `hc`; call
   `Machine::verify(&hc, &proof)` — the actual batch-STARK check, against a verifier key cached by
   `(tier, program_log_height)` (shared across every program of that shape, not recomputed per
   call).
4. `Machine::verify` itself checks, in order: the public value count is exactly 18; every public
   value is a canonical field element (rejecting `x` and `x + p` as two encodings of one proof);
   `HC0..HC7` match the caller-supplied `hc`; `TIER` matches the proof's declared tier and that tier
   is one of the six defined; `program_log_height` is in range; the declared degree bits match; then
   the batch STARK verification equation itself.
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

`shrugg_getReceipt` (or `shrugg receipt <tx>`) now returns
`{ tx, program, tier, outputs, height, index }` — no `effect` field. An explorer, or anyone else
watching the chain, sees: the program id and its `hc` (via `shrugg_getProgram`), the tier the call
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
| Proof's degree bits don't match `(tier, program_log_height)` | `verify_call`'s pre-check | `invalid proof: degree bits` |
| Stale/wrong program (proof's `hc` doesn't match `record.code_hash`) | `Machine::verify`'s public-value check | `invalid proof: ...` (opaque `VerifyError`, no separate error code) |
| Unknown program id | `Ledger::check_call` | `unknown program <id>` |
| Oversized proof (> 1 MiB) | `Ledger::validate_inner` step 1, before any decoding | `proof too large` |
| Fee below the action's floor | `Ledger::validate_inner` step 3 | `fee N below minimum M` |
| Fee below `BUNDLE_BASE + call_fee(tier)` | `Ledger::validate_inner` step 10, after the tier is known from a successful verify | `fee N below minimum M` |
| Bundle anchored to a root outside the window | step 4 | `anchor is not one of the last 256 roots` |
| Bundle `time` outside `[height - 256, height]` | step 5 | `bundle time T is outside [lo, hi]` |
| Note already spent (a replay, or a lost double-spend race) | step 6 | `nullifier already spent` |
| Bundle plaintext does not match what its proof published | step 8 | `the bundle's digest is not what its proof published` |
| Bundle proof for another guest, or invalid | step 9 (`verify_bundle` against the genesis `hc_bundle`) | `invalid bundle proof: …` |
| Two pending transactions spending one note | `Mempool::insert` | `conflicts with a pending transaction over <nullifier>` |

## 11. Pointers

- `docs/zkvm.md` — the zkVM's ISA, tables, syscalls and execution model.
- `docs/confidential.md` — the on-chain call model, gas schedule, constraint-set history (why a
  zkVM upgrade is a hard fork), and the `--cuda` GPU proving path in full.
- `docs/zkvm-milestones.md` — being written alongside this page; tracks the zkVM's milestone history
  in more detail than the constraint-set notes here.
- `docs/shielded.md` — the user's guide to the pool: keys, what is published and what is not, the
  wallet commands, the RPC surface, the admission order, and what still leaks.
- `docs/bridge.md` — the cross-chain bridge as it stood on the account chain. It is **not wired up
  on the shielded chain**: `Genesis::build` rejects a bridge section, the bridge transaction kinds
  and RPC methods are gone, and bridged balances come back as notes in phase S3.
- `docs/rpc.md` — every JSON-RPC method, including the ones this page names (`shrugg_getReceipt`,
  `shrugg_getProgram`, `shrugg_sendTransaction`, `shrugg_status`) with full parameter and result
  shapes.
- `docs/cli.md` — every `shrugg-node` and `shrugg` command this page references
  (`genesis`, `verify`, `program deploy`, `call`), with arguments and defaults.
