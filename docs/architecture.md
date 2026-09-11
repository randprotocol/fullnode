# Architecture

The original design spec is in `docs/superpowers/specs/2026-09-09-shrugg-fullnode-design.md`; this
page describes what is implemented, and walks one confidential transaction end to end. Where the
code and an older doc disagreed, this page follows the code.

## 1. Overview

```
 WALLET (shrugg-client)                           EVERY NODE (shrugg-node)
 ───────────────────────                          ─────────────────────────────────────
                                                    JSON-RPC (shrugg_sendTransaction, ...)
  build Transaction                                        │
  (Transfer/Mint/Deploy/Call)                               ▼
       │                                            ┌───────────────┐
       │  Call only:                                │    Mempool     │  cheap checks first:
       │  ┌─────────────────────────┐               │  (per-sender   │  duplicate hash, nonce
       │  │ Rand zkVM PROVER         │               │   nonce order) │  range, replacement fee,
       │  │  private inputs          │               └───────┬────────┘  pool full, then a full
       │  │  → Machine::prove(_with) │                       │           ledger.validate() probe
       │  │  → postcard(Proof)       │                       ▼           (signature, balance,
       │  └─────────────────────────┘               ┌───────────────┐    proof verification)
       │                                             │   HotStuff     │
       ▼                                             │  (chained BFT) │◀──── gossipsub / libp2p ────▶
  bincode(Transaction) ───── shrugg_sendTransaction ─▶  leader proposes a block of candidates
                                                     │  votes → QC → lock → 3-chain commit  │
                                                     └───────┬────────────────────────────────┘
                                                             │ Action::Commit(CommittedBlock)
                                                             ▼
                                                     ┌───────────────┐
                                                     │     Ledger     │  apply_block:
                                                     │  (shrugg-core) │  Deploy → check_program (cheap)
                                                     │                │  Call   → verify_call ──────┐
                                                     └───────┬────────┘                             │
                                                             │ state_root must match header          │
                                                             ▼                                       ▼
                                                     ┌───────────────┐                     ┌──────────────────┐
                                                     │    RocksDB     │  one fsynced        │ ZkExecutor::      │
                                                     │  (shrugg-node) │  WriteBatch per      │ verify_call       │
                                                     │  blocks/qcs/   │  commit              │ (shrugg-zkvm):    │
                                                     │  accounts/     │                      │ Machine::verify   │
                                                     │  programs/     │                      │ (STARK verifier,  │
                                                     │  receipts/meta │                      │ cached key)       │
                                                     └────────────────┘                      └──────────────────┘

 A late or lagging node: gossiped status (height/hash/view) every 3 s → SyncRequest over
 request-response → verify each fetched QC and re-execute every block (proof verification
 included) before accepting it, exactly like a block arriving live.
```

The prover only ever runs on the wallet's machine, on private inputs that never leave it. The
verifier only ever runs inside `Ledger::apply_block`/`apply_tx_with_receipt`, on every node, on
public bytes (a proof and eight output words) that anyone can see.

## 2. Crates and their boundaries

- **`shrugg-core`** has no I/O, no async runtime, and no Plonky3 dependency. It holds cryptography
  (Dilithium2 via `crystals-dilithium`, BLAKE3), the transaction/block/validator types, the ledger
  and its transaction rules, gas and effect decoding, genesis derivation, the `ConfidentialExecutor`
  trait (an interface, not an implementation), and the HotStuff state machine. Keeping it free of
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

There is no separate spending/viewing key split — one seed produces one signing key and one
address. Signed objects (transactions, votes, blocks) carry the full public key, not just the
address, so a verifier checks `blake3(public_key) == address` rather than trusting a bare address.
The key file format (`{ "seed", "address", "public_key" }`, mode 0600) is shared by
`shrugg-node keygen` and `shrugg keygen`; only the seed is secret, everything else is re-derived on
load (`docs/cli.md`).

## 4. Transactions

`TxKind` has four variants in this tree (bincode tags 0–3, in declaration order):

| kind | fields | who pays | what it does |
|---|---|---|---|
| `Transfer` | `to: Address, amount: u128` | `amount + fee` | moves `amount` to `to` |
| `Mint` | `to: Address, amount: u128` | `fee` only | testnet faucet: creates `amount` for `to` |
| `Deploy` | `base_pc: u32, words: Vec<u32>` | `fee` only | puts a zkVM program on chain |
| `Call` | `program: ProgramId, proof: Vec<u8>, recipients: Vec<Address>` | `fee` only (the effect's own transfer is a separate debit inside `apply_tx_with_receipt`) | verifies a proof and applies its effect |

`Transaction::total_cost()` reflects that split directly: only `Transfer` bundles `amount` into the
debited cost; the other three kinds debit only the declared `fee`, because whatever value a `Mint`
or a `Call`'s effect moves happens as a separate step inside block application, not through the
generic cost check.

**Envelope.** `TxBody { chain_id: u64, from: PublicKey, nonce: u64, fee: u128, kind: TxKind }`.
Signing hash = `blake3("shrugg-tx" || bincode(body))`; `Transaction { body, signature }`; the
transaction id used everywhere (mempool keys, receipts, RPC) is
`blake3("shrugg-txid" || bincode(Transaction))` — it commits to the signature too, not just the
body. Replay protection is a plain per-account monotonic nonce, checked ledger-side
(`tx.body.nonce != account.nonce` fails); there is no separate nullifier set for ordinary
transactions.

**Cheap checks before expensive checks.** A confidential call's proof takes roughly 16–20 ms to
verify once its verifier key is warm (`docs/confidential.md`), and materially longer the first time
a given `(tier, program_log_height)` pair is seen. Left unguarded, an attacker could flood a node
with syntactically-valid, cryptographically-bogus `Call` transactions and burn CPU on proof
verification for each one — a denial-of-service vector that costs the attacker nothing but network
bandwidth. Both the mempool and the ledger order their checks so the cheapest possible rejection
happens first:

- `Ledger::check_call` (inside `validate_inner`, run by both mempool probing and block application):
  `proof.len() <= MAX_PROOF_BYTES` (1 MiB) and `recipients.len() <= MAX_RECIPIENTS` (8) — pure size
  checks — then a `BTreeMap` lookup for the program, all before `executor.verify_call` (the STARK
  check) ever runs. Only once the proof verifies does the ledger know the call's tier and check the
  tier-scaled fee floor, then decode the effect and check the balance it implies.
- `Mempool::insert` rejects a duplicate transaction hash and an out-of-range nonce (below the
  account nonce, or more than `max_per_sender` — 64 — ahead) before cloning the ledger and running
  the full `validate` probe (signature check, balance, and for a `Call`, the proof verify). The
  pool-full and replacement-fee-too-low checks in this tree run *after* that full probe, not before
  it; reordering every mempool gate to be strictly cheapest-first is one of the things landing with
  the consensus-hardening merge (commits 1d24bf9, d5143a6, a44d3f4, 543d72b) — see §6 and §11.

**Fees.** All of it — tip above the minimum included — goes to the block proposer; there is no burn
and no split. Minimums come from `shrugg_core::gas`: `Deploy` is `100,000` units per word;
`Transfer`/`Mint` have no minimum (the fee is a pure tip); `Call`'s minimum is `1,000,000` units at
the lowest tier (10) plus `100,000` units per two tiers above that, up to `1,500,000` units at tier
20 (`call_fee`). A block's *proposer* additionally limits how many candidates it selects — up to
2,000 transactions and 4 MiB of encoded bytes (`gas::MAX_BLOCK_BYTES`) — but in this tree that limit
is enforced only where the proposer picks candidates (`Mempool::candidates_within`), not inside
`Ledger::apply_block` itself; making the size cap a rule every validator enforces on every block it
applies, not just proposer etiquette, is one of the consensus-hardening changes (§6).

## 5. Ledger and state root

`Account { nonce: u64, balance: u128 }`, kept in a `BTreeMap<Address, Account>` — the entire
balance model is this map plus a `BTreeMap<ProgramId, ProgramRecord>` of deployed programs.
Applying a block is atomic: `Ledger::apply_block` clones itself into a scratch copy, applies every
transaction of the block to the scratch copy (any single invalid transaction fails the whole
block), and only commits the scratch copy back if the resulting `state_root` equals the header's.

`Ledger::state_root()`:

1. For every account with non-zero balance or non-zero nonce (zero accounts pruned, so an untouched
   and an absent account hash identically), build a leaf
   `blake3("shrugg-account" || address(32) || nonce_be(8) || balance_be(16))`.
2. `accounts_root` = a BLAKE3 pairwise Merkle root over those leaves in address-sorted (BTreeMap
   iteration) order.
3. `programs_root` = the same construction over `blake3("shrugg-program-leaf" || program_id)` for
   every deployed program, in id-sorted order.
4. `state_root = blake3("shrugg-state" || accounts_root(32) || programs_root(32))`.

The order transactions were applied in is not separately hashed into the state root — only the
resulting map is committed. Ordering is instead enforced by nonce sequencing and by the block's
`tx_root` (a Merkle root over `tx.hash()` in block order, checked against `block.header.tx_root`
before any transaction is applied).

**What is public.** Every field of every stored `Account`, `ProgramRecord`, `Transaction`, and
`CallReceipt` sits in RocksDB and behind RPC in the clear: balances, nonces, the full bytes of every
transaction body (including a `Call`'s proof and recipient list), and every call's outputs and
resulting transfer. **The ledger is transparent except for the private inputs to a zkVM call** — a
confidential call hides *why* a transfer happens (the private computation that produced it), never
that it happened, who sent it, or how much moved. A fully shielded balance model (hidden amounts and
senders/recipients, note commitments and nullifiers in place of `Account`) is planned but not
implemented here; see the note in §11 pointing at the future shielded-chain spec.

`Deploy`/`Call` implement confidential computation; see §9 for the full path. Briefly: `Deploy`
validation only decodes instructions (cheap, so it can run inline in block application) and the
executor computes a code commitment stored as `ProgramRecord.code_hash`; `Call` validation verifies
a STARK proof against that commitment and decodes eight public output words into an `Effect`
(`None` or `Transfer { to, amount }`) applied inside the same transaction. `Mint` exists only for
testnets: gated by the genesis `faucet` flag (itself part of the genesis hash), capped at 100 SHRUGG
per call, and otherwise an ordinary consensus-ordered, nonce-sequenced transaction — the RPC method
signs it with the *node's own* key, so it goes through the mempool and consensus like anything else
and cannot be replayed outside that sequencing.

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
- **Block limits.** See §4 — the 4 MiB / 2,000-transaction cap is a consensus rule: it is enforced
  in `Ledger::apply_block` (`gas::MAX_BLOCK_BYTES` / `gas::MAX_BLOCK_TXS`), which every validator
  runs on a received block before voting, as well as where the proposer builds a candidate list.
- **Speculative state.** Every entry in the in-memory block tree clones the full ledger. The tree,
  the pending-vote map, the NewView map, and the view counter are all bounded against a misbehaving
  or diverging peer (`max_tree_blocks` = 512, 4096 pending-vote keys, 2048 NewView views,
  `MAX_VIEW_AHEAD`); the per-entry ledger clone is a known design cost to revisit as state grows.

## 7. Storage, startup verification, hard forks

One RocksDB per data directory, column families: `blocks` (height → block), `qcs` (height → the QC
certifying that block), `block_index` (block hash → height), `txs` (tx hash → (height, index)),
`accounts` (address → account), `programs` (program id → `ProgramRecord`), `receipts` (tx hash →
`CallReceipt`), and `meta` (small blobs: head height, genesis hash, chain id, the consensus
`SafetyState`). A commit of one or more blocks is a single, fsynced `WriteBatch` touching only the
blocks/QCs/indexes/accounts/programs/receipts the commit actually changed, plus the new head.

**Startup verification (`--verify-chain off|quick|full`).** Block 0 must equal the genesis file's
own derivation. `quick` then replays every later block's transactions against a ledger rebuilt from
genesis, checking each block's parent link, height, index entry, transaction root, and that
re-execution (through the real executor — including every `Call`'s proof) reproduces the header's
state root. `full` additionally checks every proposer signature and every QC's votes. On the first
inconsistency the node truncates its chain to the last good height (rewriting the account/program
snapshot from the replayed ledger, but keeping its consensus safety state so it never double-votes),
and lets sync refetch the rest from peers. `shrugg-node verify --repair` does the same thing offline,
without running the node.

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
necessarily the last committed block — the tip a proposer would actually build on). Per sender,
nonces may run up to 64 ahead of the account nonce so several future transactions can queue; a
replacement transaction for an already-pending nonce must pay a strictly higher fee. The proposer
takes each sender's contiguous nonce run starting at the account nonce, orders senders by their
first transaction's fee (highest first), and fills up to the 2,000-transaction / 4 MiB budget with a
running balance check so it never selects a transaction it already knows will fail. Committed and
now-stale transactions are pruned after every commit. See §4 for the ordering of mempool admission
checks.

## 9. End-to-end confidential transaction

This section follows one `private_payment` call — `shrugg call <program-id> --input 400 --input 250
--input 300 --input 75 --to <address>` — from the wallet to a settled receipt. `private_payment`
(`shrugg-zkvm::guests::private_payment`) reads four private balances; if their sum is at least a
threshold baked into the program, it pays recipient 0 the surplus and otherwise emits nothing.

### a. Deploy

Before anyone can call a program, someone deploys it:

```
shrugg program build --guest private_payment --arg 1000 --out pp.json
shrugg program deploy pp.json
```

The wallet assembles (or loads, for a hand-written `.json`/`.bin` file) `{ base_pc, words }` and
computes the content address `program_id = blake3("shrugg-program" || base_pc(LE32) ||
words(LE32 each))` — this is a plain content hash, purely for addressing, distinct from the zkVM's
own in-circuit digest below. It signs a `Deploy { base_pc, words }` transaction with fee at least
`deploy_fee(words.len()) = 100,000 * words.len()` units and submits it.

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
deployer, deployed_at) goes into the ledger's programs map and so into `programs_root` — deployed
programs are public, content-addressed, immutable data.

Once the block commits, the node warms the verifier for the tiers real guests land on today (10,
12, and 14) at this program's declared table height in a background `spawn_blocking` task
(`ZkExecutor::warm`), so the first call against it doesn't pay the full uncached-verify cost. The
key is keyed on `(tier, program_log_height, input_log_height)`, not on the program's content, so
this warms shared keys that every program of the same shape reuses — not a per-program cache.
`warm` covers two input-height classes (the smallest table and the 4-word-call class the current
guests use): six keys total, one of which a first call typically finds already built by an earlier
verify.

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
a silent CPU run) builds eight interconstrained trace tables for this execution: `program` (now a
witness, decoded in-circuit — no longer the verifier's own preprocessed copy), `cpu` (whose first
rows are two *digest prefixes* that absorb the whole program and, separately, the committed private
inputs through Poseidon2, one permutation per up to four words, computing `hc` and the salted
`H_IN` as part of the trace itself), `memory`, `alu`, `range`, `nibble` (the
old combined byte-range table split in two for a much smaller preprocessed commitment),
`poseidon2` (the syscall's own chip), and `input` (one row per committed private-input word,
feeding the `H_IN` digest and `READ_INPUT` over two split buses). LogUp/permutation buses tie
them together (e.g. the
`POSEIDON2` bus between `cpu`'s hash rows and the `poseidon2` chip). The private inputs — the four
balances here — never appear in any public column; they only steer which trace rows get produced.
FRI is run in hiding mode, so two proofs of the identical execution are different bytes — proofs
don't fingerprint the specific inputs that produced them.

The proof publishes exactly 26 public values (`tables::cpu::pv`): `PC_ENTRY` (1 word), `TIER` (1
word), `OUT0..OUT0+7` (the eight output words), `HC0..HC0+7` (the 8-word program digest),
`IN0..IN0+7` (the 8-word salted private-input commitment `H_IN`). It is
serialized as `Proof { tier, program_log_height, input_log_height, public_values, batch }`, postcard-encoded — the
same shape `TxKind::Call.proof` carries. Measured upstream on a different guest (`fib`) at tier 10
under constraint set 3 (`docs/confidential.md`): proof size 268 KB, prove time 3.1 s,
first (uncached) verify 16 ms. The README's own measurement of `private_payment` specifically (an
earlier constraint set): proving ~21 s, proof ~0.9 MB, on-chain verification ~19 ms once its
verifier key is cached (the key itself costs ~2 s to build on a laptop, ~7 s on a 2-vCPU server, and
is what deploy-time warming amortizes away).

### c. Submit

The wallet signs `Call { program: program_id, proof, recipients }` with fee at least
`call_fee(tier)` (1,000,000 units at tier 10, rising by 100,000 units per two tiers, to 1,500,000 at
tier 20) and submits it over `shrugg_sendTransaction`. The RPC handler hands it to the mempool, which
runs the admission order from §4: duplicate-hash and nonce-range checks first, then the full
`ledger.validate` probe — signature, chain id, balance, and (because this is a `Call`) proof
verification — before it is gossiped and queued by nonce.

### d. Block

The leader includes the transaction in its next proposal (subject to the block's size/count budget,
§4/§6). Every validator, on receiving the block — proposer and non-proposer alike — applies it
through `Ledger::apply_block`, whose `Call` path is `Ledger::check_call` followed by
`apply_tx_with_receipt`'s `Call` arm:

1. Proof size (≤ 1 MiB) and recipient-list size (≤ 8) — cheap bounds checks.
2. The program must exist (`programs.get(program)`).
3. `ZkExecutor::verify_call`: decode the `postcard`-encoded `Proof`; reject an out-of-range tier,
   `program_log_height`, or `input_log_height` before any of them is used to size anything
   (guarding against a panic on an attacker-chosen huge shift); check the proof's declared degree
   bits match what `(tier, program_log_height, input_log_height)` implies; decode
   `record.code_hash` back into `hc`; call
   `Machine::verify(&hc, &proof)` — the actual batch-STARK check, against a verifier key cached by
   `(tier, program_log_height, input_log_height)` (shared across every program of that shape, not
   recomputed per call).
4. `Machine::verify` itself checks, in order: the public value count is exactly 26; every public
   value is a canonical field element (rejecting `x` and `x + p` as two encodings of one proof);
   `HC0..HC7` match the caller-supplied `hc`; `TIER` matches the proof's declared tier and that tier
   is one of the six defined; `program_log_height` and `input_log_height` are in range; the declared
   degree bits match; then the batch STARK verification equation itself.
5. Back in the ledger: the call's minimum fee (`call_fee(tier)`) must be met; the eight raw `u32`
   outputs are decoded through `effect::decode` against the transaction's own `recipients` list —
   `out0` is the effect kind (0 none, 1 transfer), `out1` an index into `recipients`, `out2|out3` a
   little-endian `u64` amount, `out4..7` free data recorded verbatim in the receipt.
6. For a transfer effect, the caller's balance must cover `amount + fee`; the ledger then debits the
   caller, credits the recipient, and always credits the block proposer the fee. The applied effect
   (`Option<(Address, u128)>`), tier, and outputs go into a `CallReceiptData`.

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
`{ tx, program, tier, outputs, effect: { to, amount } | null, height, index }`. An explorer, or
anyone else watching the chain, sees: the program id and its `hc` (via `shrugg_getProgram`), the
tier the call was proven at, the eight output words, the caller (`TxBody.from`, public on every
transaction), the full recipient list carried on the transaction, and — for a transfer effect —
exactly who was paid and how much. It never sees: the four private input balances, any register or
memory value, which branch the program took, or the real cycle count (only which padded tier bucket
it fit in). Caveats worth stating plainly: `hc` is *binding*, not *hiding* — it has no per-deployment
salt, so anyone who can enumerate candidate programs can test a guess against a published `hc` and
confirm which was deployed; the effect words are the *entire* payment in the clear (recipient and
amount), so a confidential call hides only the reasoning behind a payment, never the payment itself;
and the caller is always public, on every transaction kind, with no exception for `Call`.

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
| Declared `input_log_height` out of `[2, 20]` | same two layers | `invalid proof: input height out of range` |
| Proof's degree bits don't match `(tier, program_log_height, input_log_height)` | `verify_call`'s pre-check | `invalid proof: degree bits` |
| Stale/wrong program (proof's `hc` doesn't match `record.code_hash`) | `Machine::verify`'s public-value check | `invalid proof: ...` (opaque `VerifyError`, no separate error code) |
| Unknown program id | `Ledger::check_call` | `unknown program <id>` |
| Insufficient balance for the call's own fee | `Ledger::validate_inner`'s generic `total_cost` check | `insufficient balance: have X, need Y` |
| Insufficient balance for the effect's transfer | `Ledger::check_call` | `insufficient balance for emitted transfer: have X, need Y` |
| Oversized proof (> 1 MiB) | `Ledger::check_call`, before any decoding | `proof too large`-shaped `TxError` (checked before program lookup or verification) |
| Too many recipients (> 8) | `Ledger::check_call` | `too many recipients` |
| Unknown effect kind (`out0` not 0 or 1) | `effect::decode` | `bad effect: unknown effect kind N` |
| Recipient index out of range | `effect::decode` | `bad effect: recipient index N out of range (list has M)` |
| Fee below `call_fee(tier)` | `Ledger::check_call`, after the tier is known from a successful verify | `fee too low: below minimum M` |

## 11. Pointers

- `docs/confidential.md` — the zkVM's tables, syscalls, gas schedule, constraint-set history (why a
  zkVM upgrade is a hard fork), and the `--cuda` GPU proving path in full.
- `docs/zkvm-milestones.md` — being written alongside this page; tracks the zkVM's milestone history
  in more detail than the constraint-set notes here.
- `docs/bridge.md` — being written; the cross-chain bridge (guardian-attested deposits from other
  chains) is additive to everything in this document — its own transaction kinds, its own RocksDB
  column families, and its own root folded into `state_root` only when a chain's genesis configures
  it, so a chain without a bridge section hashes and behaves exactly as described above.
- `docs/rpc.md` — every JSON-RPC method, including the ones this page names (`shrugg_getReceipt`,
  `shrugg_getProgram`, `shrugg_sendTransaction`, `shrugg_status`) with full parameter and result
  shapes.
- `docs/cli.md` — every `shrugg-node` and `shrugg` command this page references
  (`genesis`, `verify`, `program deploy`, `call`), with arguments and defaults.
