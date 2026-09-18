# Changelog

Every tagged release of the RAND full node, newest first. The client-facing RPC changes are also
logged, method by method, in [`docs/rpc.md`](docs/rpc.md#changelog).

## v0.4 (unreleased)

**Draft. The controller finalises this section at tagging.** Release date: `TODO-CONTROLLER`
(estimate 2026-09-25). Chain: 13, genesis `TODO-CONTROLLER`, pinned build `TODO-CONTROLLER`.

v0.4 is the RISC-V developer release: the `rand-guest` toolchain and the two bytecode
translators, `sbpf2rv` (Solana) and `evm2rv` (Ethereum). They live in the circuits repo (main
`7ef3220`). Fullnode's side is the program cap as a genesis parameter and the deploy of a
`rand-guest` image. Those commits are already listed under v0.3's
[Also included: the program cap as a genesis parameter](#-also-included-the-program-cap-as-a-genesis-parameter)
and are not repeated here. They take effect on the first chain whose genesis sets
`max_program_words`.

### Claims, measurements and methods

| claim | measurement | method |
|---|---|---|
| `rand-guest` builds a Rust or C guest into an image the chain accepts | a Rust and a C guest built, checked, run and deployed; the call's receipt outputs equal `rand-guest run`'s | a local one-validator chain, test FRI profile, 2026-09-19 (`docs/guests.md`) |
| the build is reproducible | the Rust `fib` guest rebuilt at a different checkout path gives the committed `hc ed475c16…b99e` | rebuild and compare; `rand-guest/tests/build.rs` gates the four committed guests |
| the raised cap admits large images | the 11 686-word ERC-20 image deployed on a chain cut with `--max-program-words 65535` (fee 1.1696 RAND); the same deploy on a 4096-word chain is refused before any proving | the same local chain setup |
| `evm2rv` output equals the interpreter's | identical eight words for `transfer`, `approve` and `transferFrom`; 66 235 / 48 119 / 88 824 cycles against 121 638 / 85 645 / 161 434 on `evm.bin` (54.5–56.2 %) | `rand-guest run` on both images and `diff`, re-run 2026-09-19; `evm2rv/tests/parity.rs` (8 vectors, both stages) and `tests/fuzz.rs` (10 000 random programs) |
| `sbpf2rv` output equals the interpreter's | identical eight words for SPL Token `Transfer` 250; 765 851 cycles against 694 498 on `sbpf.bin`; all 8 vectors in tier 20; image 65 096 words | `sbpf2rv/tests/parity.rs`, 2026-09-18 |
| SPL Token translation does not pay off today | about 98 % of each run is the fixed sBPF ABI harness; the translated image is 69–75 k cycles dearer per vector | per-stage cycle attribution (`sbpf2rv/README.md`) |
| ERC-20 is proven; SPL Token is not | tier 18 (ERC-20 `transfer`): OOM-killed at 24.7 GB on a 48 GB laptop, above 47 GB at 25 min on a 64 GB droplet; proved on a 128 GB droplet (m-16vcpu-128gb) at 85.0 GB (translated) / 85.5 GB (interpreted) peak RSS, 3 230.5 s / 3 143.3 s, 811 600 / 805 108-byte proofs. Tier 16 (ERC-20 `approve`, translated): 21.7 GB, 786.7 s (13.1 min), 798 930-byte proof. Tier 20 (SPL Token): OOM-killed at 65.1 GB on a 64 GB droplet after 10 m 41 s; not yet proven — extrapolated at about 330 GB and about 3.6 h, more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) | `/usr/bin/time`, watchdogs; the prover is single-threaded (99 % of one core on 16 vCPUs) |

### Docs

- `docs/guests.md`: the Rand ISA, the syscall ABI, the image container, step-by-step Rust, C and
  hand-built deploys, `hc` versus program id (and `hc`'s two spellings), the hermetic build, the
  cap.
- `docs/translators.md`: the trust model, the parity guarantee and its accepted divergences, the
  ERC-20 and SPL Token walkthroughs, measured tables, limits.
- `docs/node-hardware.md`: what each role proves or verifies, measured RAM and disk, DigitalOcean
  sizes, prover memory per tier, setup.

### Known limits

- A translated SPL Token can be deployed on a raised-cap chain but not called. Its call needs
  27 151 public words (the chain accepts only an empty public segment) and 10 458 private words
  (the wallet caps call input at 4 096, `MAX_CALL_INPUT_WORDS`).
- The ERC-20 call's input fits (921 words for `transfer`). Its proof size may not: the EVM harness
  uses the `KECCAK` syscall, and a keccak-carrying production proof measured 3 198 430 bytes at
  tier 10, above `MAX_PROOF_BYTES` (2 MiB). Tier-18 size (test profile): 811 600 bytes translated,
  805 108 bytes interpreted.
- EVM: the nine block-context opcodes trap; a `CALL` with nonzero value traps; ecrecover,
  bn256 mul and pairing, large modexp and long blake2f exceed the 2^20-cycle tier cap.
- sBPF: CPI and unknown syscalls trap at run time; Ed25519 and secp256k1 exist in software but are
  unlinked.
- Fixed: `deploy/vps-setup.sh` deleted the `rand-node` unit it had just written (a leftover of the
  rename). It still inits from chain 5's `deploy/genesis.json`; `docs/node-hardware.md` gives the
  manual steps.

---

## 🚀 RAND fullnode v0.3 — the RPC catches up with Ethereum and Solana

**Released 2026-09-18 · chain 12 (genesis `605eb783…`) · same-chain update, no fork**

The fleet runs `4504a03`. The tag also carries two later groups of commits, neither deployed yet:

- `3ee3913`, `c36d690`: the `rand viewing-key` and `rand tx-key` wallet commands and one node-side fix. See [Keys you can hand out](#-keys-you-can-hand-out).
- `3cfc0a2..10422b6`: the program cap as an optional genesis parameter, and deploys of `rand-guest` images. See [Also included](#-also-included-the-program-cap-as-a-genesis-parameter).

v0.3 is an RPC release. We lined the node's JSON-RPC up against Ethereum's execution API and
Solana's RPC, method by method. Then we added the methods a wallet or explorer author reaches for
first and could not find here:

- post-submit status that tells *pending* apart from *dropped*
- per-program receipt queries
- multi-gets
- finality
- health and build identity
- two new WebSocket push topics

Everything is node-side. Blocks, transactions, gossip, sync and genesis are byte-for-byte
unchanged, so v0.3 nodes and chain-12 nodes run side by side. The whole fleet was upgraded in
place with no chain cut.

---

### ✨ Eleven new JSON-RPC methods

| Method | What it answers | Ethereum twin | Solana twin |
|---|---|---|---|
| `rand_getVersion` | crate version, full git sha, chain id, `hc_bundle`, FRI profile | `web3_clientVersion` | `getVersion` |
| `rand_getGenesisHash` | the genesis hash this node was initialised with | — | `getGenesisHash` |
| `rand_getHealth` | `ok` / `syncing` / `behind` + the lag in blocks | `eth_syncing` | `getHealth` |
| `rand_getTransactionStatus` | up to 64 hashes → `committed` / `pending` / `rejected` (with reason) / `unknown` | `eth_getTransactionReceipt` | `getSignatureStatuses` |
| `rand_getReceipts` | a program's receipts over a height range, paged | `eth_getLogs` | `getSignaturesForAddress` |
| `rand_getWitnesses` | up to 32 Merkle witnesses from **one** tree build | `eth_getProof` × N | `getMultipleAccounts` |
| `rand_getBlocks` | up to 128 block headers in one call | batch only | `getBlocks` |
| `rand_getFinality` | `committed` / `certified` / `proposed` / `unknown` from the replica's own QCs | `eth_getBlockByNumber("finalized")` | `getBlockCommitment` |
| `rand_getProposer` | the leader per view (≤ 64) under the current validator set | — | `getLeaderSchedule` |
| `rand_getMempoolInfo` | pooled count, bytes, oldest age, cap | `txpool_status` | — |
| `rand_getEmission` | inflation (a fixed `"0"`), the aggregation subsidy schedule, faucet flag | — | `getInflationRate` |

Full parameters, result shapes, caps and error codes are in [`docs/rpc.md`](docs/rpc.md). The
method-by-method comparison is in [`docs/rpc-comparison.md`](docs/rpc-comparison.md).

#### A closer look

- **Know when a transaction is dead.**
  - What it covers: `rand_getTransactionStatus` checks the chain first, then the mempool, then the
    node's refused-transaction cache. A transaction refused for its own bytes reads `rejected`,
    with the exact reason the node gave. Those reasons include:
    - a bad proof, digest or mint signature
    - the wrong chain
    - an oversize part
  - What it does not cover: a refusal about *state* is not remembered. Examples are a spent
    nullifier or an expired anchor. Such a transaction reads `unknown` once it leaves the pool.
- **Receipts by program**, paged with a *soft-floor* limit (default and cap 256).
  - A page never splits a block, so `next_height` is always the first height not yet served.
  - A client never sees a receipt twice and never loops.
- **Witnesses in bulk.**
  - `rand_getWitness` rebuilds the whole commitment tree for every call.
  - `rand_getWitnesses` pays that cost once for up to 32 leaves.
  - A wallet spending several notes needs one round trip.
- **Finality you can show a user.**
  - `certified` means a quorum certificate exists but the block has not committed yet.
  - `committed` is final.
  - A block that commits while you are asking still reads `committed`, never `unknown`.
- **Emission.** There is no inflation on RAND, and the method says so explicitly. Clients
  porting from Solana's `getInflationRate` get a number instead of a missing method.

---

### 📡 Two new WebSocket topics

Same port and path as before (`ws://host:8545/`). `newHeads` is unchanged.

| Topic | Subscribe with | You get |
|---|---|---|
| `receipts` | `["receipts"]` or `["receipts", "<program_id>"]` | one message per block that carries matching receipts |
| `transaction` | `["transaction", "<hash>"]` | **exactly one** message when the hash commits or is refused, then the subscription removes itself |

- **No race on submit-then-subscribe.** If the transaction already committed or was refused
  before you subscribed, the answer arrives on the next block. Clients have one code path.
- **A slow topic can't disconnect you from another one.** A lag closes a connection only when
  it is subscribed to a stream that fell behind. A `newHeads`-only client is never dropped
  because of receipt or refusal traffic.
- The three streams are independent. A client subscribed to several may see block N's
  receipts before block N's head.

---

### 🔑 Keys you can hand out

Two new wallet commands export the keys a holder may choose to share. Neither can spend.

- **`rand viewing-key`** prints the wallet's viewing key: 64 hex, the exact parameter
  `rand_importViewingKey` takes. It reveals every note the wallet has sent or received.
- **`rand tx-key <hash>`** prints one row per output of that transaction the wallet sent, received
  or kept as change, with the per-transaction key the output was sealed under.
  - A `sent` row's key is a payment proof. `rand_checkTransaction <hash> <key>` discloses that one
    output to whoever holds the pair, and nothing else.
  - Nothing is stored at send time. Every envelope carries its key twice, under the sender's
    outgoing viewing key and under the recipient's KEM secret. So the sender and the recipient
    both recover the same key, for any past transaction.

```
$ rand tx-key bee116bf…
output          role                      amount  tx key
bundle:0        sent                   1000 RAND  5f60738f…ae46
bundle:1        change               99.979 RAND  b5624451…9654
```

**Node change:** `rand_checkTransaction` now also discloses a faucet mint's note (`mint:0`).
Its recipient recovers the key through the envelope's KEM half. The chain-12 fleet runs
`4504a03`, so this check applies once nodes are rebuilt at or after `c36d690`.

---

### 🧩 Also included: the program cap as a genesis parameter

These ten commits were written for the v0.4 chain and change nothing on chain 12.

- A genesis file may set `max_program_words` (`1..=65535`). Absent, the cap stays 4096 words and
  the genesis hash is unchanged, so running chains see no difference. The ledger, admission,
  reload and `rand_estimateFee` all read it.
- `rand_estimateFee` for a deploy refuses past the chain's cap, with the cap in the message. No
  method, parameter or result shape changed.
- `rand program deploy` accepts the image container `rand-guest build` emits, prints `hc` in
  `rand_getProgram`'s spelling, and refuses an over-cap program before any proving.
- It takes effect on the chain cut that sets the field. Details are in `docs/rpc.md`, entry
  "for the v0.4 chain".

---

### 🗄️ Storage

- **New `receipts_by_program` index**, a RocksDB column family written in the same atomic
  batch as each receipt and dropped with it on a truncate.
- **One-time backfill on first start.** Chain 12's explorer node indexed its 117 receipts
  instantly. A later restart finds the marker and skips the backfill. A node killed mid-backfill
  finishes on its next start.
- **The database is forward-only.** A pre-v0.3 binary refuses to open a database that has the
  new column family. To roll back, run the new subcommand with the v0.3 binary while the node is
  stopped:

  ```bash
  rand-node db drop-receipts-index --datadir <dir>
  ```

  Then re-pin the old build. The full procedure is in `deploy/README.md`, section "Rolling back
  v0.3". Tests cover both directions: a pre-v0.3 database migrates, and a dropped database opens
  with the old column-family list.

---

### 👛 Client library (`randprotocol-client`)

- `wait_for_transaction` now fails fast on `rejected`, with the node's reason in the error,
  instead of waiting out the full timeout.
- **Old nodes still work.** Against a node older than v0.3, the client detects the missing
  method once and falls back to its old polling loop.
- New `transaction_status(&[Hash])`.

---

### 🔒 Bounds and hardening

The RPC is unauthenticated, so every new surface is bounded. Code review during the release found
and fixed the following before release.

- `rand_getProposer` refuses a range wider than 64 views **before** allocating anything. It
  used to build the whole range first, so one call with `[0, u64::MAX]` could exhaust a node's
  memory.
- `rand_getTransactionStatus` reads only a transaction's *location* (height and index). It
  no longer decodes the full record, which on chain 12 includes a ~1.2 MB proof. That was up to
  64 decodes per call on the threads consensus shares. The lookup now also runs off the async
  runtime.
- `rand_getMempoolInfo` keeps a running byte total. It no longer re-serializes every pooled
  transaction on the consensus loop for each call. Block building reuses the stored lengths too.
- `rand_getEmission` reads two metadata keys. It no longer rebuilds the whole ledger and
  commitment tree for each call.
- `rand_getReceipts` cursors always advance. The earlier design could loop forever on a
  height with more receipts than the page size.
- `rand_getFinality` by hash no longer reads `unknown` for a block that commits while you ask.
- Every new method checks its caps on the input before doing any work: 64 hashes, 32
  indices, 128 headers, 64 views, 256 receipts, 8 subscriptions per socket.

---

### 🧰 Operators

- **`rand_getVersion` reports the exact commit a node was built from.**
  - `deploy/rebuild-vps.sh` writes it into the tree before the rsync and passes it to the build
    as `RAND_BUILD_SHA`, so a stale `.git` on the build host can't mislead it.
  - `build.rs` now notices new commits on a branch.
  - It marks a build `-dirty` only for modified tracked files.
- **`rand-node db drop-receipts-index`** is the rollback step described above.
- **Startup takes minutes, not seconds.** A node's RPC opens after its quick chain
  verification, about 4 minutes at chain 12's ~59 000 blocks. This is unchanged behaviour, but
  worth knowing when you watch a rolling update.

---

### 📚 Docs

- [`docs/rpc.md`](docs/rpc.md): a section per new method and topic, plus the v0.3 changelog
  entry.
- [`docs/rpc-comparison.md`](docs/rpc-comparison.md): the Ethereum / Solana / RAND table,
  refreshed, and a new section "What v0.3 closed".
- [`docs/superpowers/specs/2026-09-18-rpc-v0.3-design.md`](docs/superpowers/specs/2026-09-18-rpc-v0.3-design.md):
  the design and a record of every decision changed during implementation.
- `deploy/README.md`: "Rolling back v0.3".

---

### ⚠️ Known issues

- `rand_getVersion`'s `version` field reports the workspace crate version, which still reads
  `0.1.0`. Use `git_sha` to identify a build. The crate version will be bumped with the next
  binary change.
- `main.rs`'s `the_genesis_hash_is_pinned` test fails on this commit and on the commit before
  it. The failure predates this release and does not touch chain 12's genesis.

---

### 🙅 Deliberately not in v0.3

These gaps are by design, because RAND's state is shielded. They are not planned.

- `eth_call` / `simulateTransaction`: execution and proving happen in the wallet.
- `eth_getBalance` / `getAccountInfo` / `getProgramAccounts`: there are no readable accounts.
- `debug_traceTransaction`: the node never sees a call's private inputs.
- `rand_feeHistory`: it arrives with the fee-ordered mempool.

---

### 🛫 Upgrading

It is a drop-in binary swap on chain 12. There is no genesis change and no resync.

```bash
deploy/rebuild-vps.sh <build-host>        # build once
deploy/update-droplet.sh <ip>             # per node, one at a time; idempotent
```

The testnet fleet (16 DigitalOcean droplets plus the laptop validator) was rolled one node at a
time with the chain producing blocks throughout.

---

### 📊 By the numbers

| | |
|---|---|
| Commits | 28 |
| Files changed | 20 (+3 904 / −178 lines) |
| New tests | 30 |
| New RPC methods | 11 |
| New WebSocket topics | 2 |
| Review fix rounds before release | 6 (5 per-task + 1 whole-branch) |

**What's next:** v0.4 is the guest toolchain (`rand-guest`, Rust and C to RV32IM) and the
sBPF → RV32 and EVM → RV32 transpilers.
---

## v0.2 — 2026-09-17 (chain 11, reverted the same day)

Short shielded addresses: a receiver id plus a verifiable receiver record. Reverted at
`17db41d` because a sender cannot seal a note to a hash and an empty wallet cannot register;
chain 12 returned to the long ML-KEM address. See `AGENTS.md`.

## v0.1 — 2026-09-16

The first tagged full node: HotStuff BFT, the shielded pool, staking, the bridge, confidential
programs on the zkVM, block aggregation, and the pre-v0.1 security review's fixes.

