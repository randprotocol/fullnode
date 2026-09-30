# Randprotocol Full Node and RPC Client

The reference full node for the Rand Protocol chain and its command-line wallet, written in Rust.
The chain's native token is **RAND**, and it lives in a **fully shielded pool**: there are no
accounts and no balances, only note commitments and nullifiers, and a transfer is a zero-knowledge
proof that some two notes became some other two. The same token pays for **confidential arbitrary
computation** — programs that run off-chain inside a zero-knowledge virtual machine and settle on
chain with a proof instead of their inputs.

| | |
|---|---|
| Consensus | chained HotStuff BFT, stake-weighted quorums (more than 2/3), round-robin leaders, three-chain commit, view synchronisation, exponential timeouts |
| Signatures / hashes | Dilithium2 (post-quantum) / BLAKE3 for validators and blocks; Poseidon2 for notes, the tree and nullifiers; ML-KEM-768 + ChaCha20-Poly1305 for note envelopes |
| Networking | libp2p 0.57: TCP + Noise + Yamux, gossipsub, Kademlia + bootstrap list, mDNS on LANs, request-response block sync, ping keepalive, automatic redial |
| Ledger | shielded note pool: a depth-32 Poseidon2 commitment tree, a nullifier set, 4-in-4-out hidden-asset proved bundles (one bundle moves any asset — RAND, a bridged coin or an RPL token — and nobody without a key can tell which), split authorisation (since chain 17 a bundle carries a second, small auth proof, so the bundle proof itself no longer takes the spend key), 1,860-byte note envelopes with an encrypted memo (chain 18), public fees to the proposer's register entry, BLAKE3 Merkle state root over tree, nullifiers, validators and programs, plus the bridge and the RPL token registry on a chain that carries them |
| Staking | a public validator register — bond out of a bundle's burn (v2 registrations, a two-epoch activation delay), unbond over two epochs, withdraw into a shielded note — epochs that re-derive the validator set from it, timelocked genesis vesting (`docs/vesting.md`), and a supply audit that adds the register and the pool back up to what the chain issued |
| Wallet keys | a 256-bit spend key; viewing key, note-owner field, nullifier key, outgoing viewing key, ML-KEM-768 decapsulation key and `rand1…` address all derived from it |
| Bridged assets | the guardian bridge as notes: a bridged holding is a note whose `asset` word is the registry's index, an attestation deposits one note the chain computes itself, and a burn is a single hidden-asset bundle — the same bundle spends the bridged asset from slots 0–1 and pays the RAND fee from slots 2–3 (`docs/bridge.md`) |
| Confidential computation | Rand zkVM: RV32I under a Plonky3 batch STARK (Goldilocks, Poseidon2, ZK-hiding FRI, constraint set 8); programs deployed on chain, calls carry a proof + 8 public outputs and a declared gas limit the circuit enforces, priced per gas and per KiB with dynamic prices (chain 18), and pay through a bundle like everything else |
| Storage | one RocksDB per node with column families for blocks, certificates, indexes, notes, nullifiers, anchors, validators, programs and receipts; fsynced commits; startup integrity check with truncate-and-resync; optional history pruning (`--prune-history 24h`) with archive nodes keeping everything |
| Interfaces | JSON-RPC 2.0 over HTTP with batch requests, a WebSocket `newHeads` / `receipts` / `transaction` subscription on the same port (`rand-node`), `rand` wallet CLI with a local prover, `rand-prover` delegated prover (`docs/prover.md`), Rust client library |

Status: an experimental testnet runs **chain 18** (live since 2026-09-29 04:56 UTC; genesis
`a7cb020c…4da76`, build **v0.6.7** `86941a1`) on 26 DigitalOcean validators — quorum 18 of 26 —
including two archive nodes that keep full history; the others keep one day. Chain 18 is the first
gas-metered chain (constraint set 8), runs split authorisation, carries the encrypted memo, and
keeps the zUSD-backed guardian bridge (10 zUSD, audited `supply == locked == custody`). Public RPC:
`https://rpc.randprotocol.org`. Not audited as a whole; not for real value — mainnet is v1.0.

## Contents

- [Repository layout](#repository-layout)
- [Build and test](#build-and-test)
- [Run a node](#run-a-node)
- [Use the wallet](#use-the-wallet)
- [The shielded pool](#the-shielded-pool)
- [Confidential computation](#confidential-computation)
- [Operating a node](#operating-a-node)
- [How it works](#how-it-works)
- [Release history](#release-history)
- [v0.5: RPL, zUSD and bridge hardening](#v05-rpl-zusd-and-bridge-hardening)
- [Documentation](#documentation)
- [Roadmap](#roadmap)

## Repository layout

```
crates/randprotocol-core     pure logic, no I/O: crypto, types, notes and the commitment tree, ledger
                       rules, gas, genesis, the HotStuff state machine (tested with a simulated network)
crates/randprotocol-zkvm     the Rand zkVM (vendored from circuits/research; resync with deploy/sync-zkvm.sh)
                       plus the chain-side proof verifier with its verifier-key cache
crates/randprotocol-node     RocksDB storage, libp2p networking, mempool, block sync, JSON-RPC server,
                       the node event loop, and the rand-node binary
crates/randprotocol-client   the rand wallet binary and the RpcClient library (no RocksDB/libp2p dependency)
crates/randprotocol-prover   the rand-prover binary: a delegated prover that proves bundles for paired wallets
deploy/                testnet genesis, test keys, run scripts, cloud provisioning and rebuild scripts
docs/                  reference documentation and the design spec / plan
scripts/               local two-validator testnet
```

## Build and test

Requirements: Rust 1.98.1 (pinned in `rust-toolchain.toml`; rustup installs it), a C++ compiler
and `cmake` (RocksDB). First build: 10 to 20 minutes (RocksDB and Plonky3 from source).

**The build needs the circuits repository checked out beside this one, as `circuits/`.**
`randprotocol-zkvm` has path dependencies on `../circuits/guests-compiled/evm-core` and
`sbpf-core`, and it and `randprotocol-rvm` an optional one on `../circuits/rand-zkvm-cuda`; cargo
reads all three manifests for every command, so a clone of this repository alone fails at
`cargo metadata` (audit v6, PROC-2 — open; CI's `clean-clone` job is the test for it). The commit
to check out is the one this tree's vendored crates were synced from: the `circuits:` line of
`crates/randprotocol-zkvm/guests-compiled/PROVENANCE.md`, the same value as `CIRCUITS_PIN` in
`.github/workflows/ci.yml` (`aeacf31…` for v0.6.7). It is on a branch of zkp-circuits, not yet on
a tag.

```bash
git clone https://github.com/randprotocol/fullnode.git
git clone https://github.com/randprotocol/zkp-circuits.git circuits   # the sibling directory must be named `circuits`
git -C circuits checkout "$(sed -n 's/^circuits: //p' fullnode/crates/randprotocol-zkvm/guests-compiled/PROVENANCE.md)"
cd fullnode
cargo build --release        # target/release/rand-node, target/release/rand, target/release/rand-prover
cargo test --release         # all crates; release because STARK proving is slow in debug
```

Test coverage spans the core crate (crypto, notes and the tree, ledger admission rules, staking,
gas, genesis, and a deterministic multi-replica HotStuff simulation with partitions, restarts and
epoch rollovers), node unit tests (storage, pruning, sync, the mempool, the RPC), wallet tests,
the vendored zkVM and rVM suites (upstream's tests wholesale, including cheating-prover suites and
real proofs), a wallet-flow test against a real one-node chain, and cluster tests that start real
nodes over TCP (transfers, a double-spend race, deploy-and-call, a bridge deposit and burn,
validators bonding in and unbonding out, restarts, quorum loss and recovery, database recovery).

The full suite takes one to two hours because the proofs dominate. At v0.6.1, on a 16-vCPU
machine: core lib 521, node lib 373, client lib 117, cheating 116, hidden_cheating 21 (75 min),
wallet_flow 6 (53 min), cluster 26 (44 min), zusd_e2e 2 (51 min). Each release's measured
numbers are in `AGENTS.md`. The recursion-VM aggregation tests need a fixture cache
(`RECURSION_FIXTURES`), and the production rVM exit and aggregate proofs need a large machine:
N=2 took 133 GB, N=3 221 GB, and the production exit proof more than 256 GB under constraint set 7.

## Run a node

### One machine, two validators

```bash
scripts/local-testnet.sh
target/release/rand --rpc http://127.0.0.1:8545 status
```

### Several machines

Each machine creates a key:

```bash
rand-node keygen --out node.key.json      # prints the address
rand-node address --key node.key.json     # address, public key, libp2p peer id
```

One machine writes the genesis with every validator's key file or hex public key, then the file is
copied to all machines unchanged (the genesis hash must match everywhere):

```bash
rand-node genesis --chain-id 6 \
    --validator a.key.json,1000,rand1<a's payout address> \
    --validator <hex public key of b>,1000,rand1<b's payout address> \
    --alloc rand1<address>=1000 \
    [--epoch-blocks 1000] \
    [--faucet] [--no-confidential] [--fri-profile production] \
    --out genesis.json
```

A `--validator` is one register entry, so it carries all three of its fields at once: the key, the
stake in RAND, and the payout address its block rewards and unbonded stake are paid to (phase S2).
All three are part of the genesis hash. 1000 RAND is the minimum a validator needs to be in an
epoch's validator set at all; genesis refuses less. `--epoch-blocks` is how often the set is
re-derived from the register (spec §8) — the default is 1000 blocks.

Each `--alloc` creates one shielded deposit note: there is no per-validator allocation, because
value exists only as a note someone holds the spend key for. The addresses come from
`rand keygen` + `rand address` on whichever machines will hold the funds. `deploy/README.md`
has a worked example, and `deploy/genesis-shielded.example.json` is one such file.

A validator that joins an existing chain registers instead of appearing in genesis:

```bash
rand-node register --key node.key.json --payout rand1<payout address>   # prints a Registration (hex)
rand-node unbond   1000 --key node.key.json                               # two epochs to release
rand-node withdraw 1000 --key node.key.json                               # into a note at the payout address
```

The bond itself is a wallet transaction — it burns the stake out of shielded notes, which a node
holds none of — and takes the hex `register` printed. `unbond` and `withdraw` need no wallet: they
are signed by the node's key and carry no bundle at all, exactly as a faucet mint does, and the
register's nonce is what keeps them from being replayed. So there is nothing to prove and each
commits in a block's time.

Their fee model is its own, for the same reason: `unbond` moves stake inside the public register
and pays nothing at all, while `withdraw` pays the 0.001 RAND bundle base out of the amount it
withdraws, to the proposer of the block that applies it. A withdrawal of 1000 RAND therefore
creates a note worth 999.999, and an amount that cannot cover the base is refused. `docs/staking.md`
walks the whole join-and-leave through, including when bonded stake starts counting as weight.

Each machine initialises and runs:

```bash
rand-node init --datadir ./data --genesis genesis.json
rand-node run  --datadir ./data --key node.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    [--bootstrap /ip4/<ip>/tcp/30303/p2p/<peer id>]...
```

Nodes on one LAN discover each other over mDNS; across networks, machines behind NAT dial out to a
node with a public address. `--validator` means "this node holds a validator key": a key that is in
no current epoch's set observes until an epoch admits it, which is how a validator that bonds in
after genesis joins without a restart (`rand_status` reports `is_validator` for the key and
`active_validator` for being in the current set). Omit `--validator` to run an observer on purpose. Restarting from the same `--datadir` resumes from
the persisted head. A validator set of `n` needs more than 2/3 of stake online: 2 of 2, 3 of 4, 5 of 6.

## Use the wallet

```bash
export RAND_RPC=http://127.0.0.1:8545     # or --rpc on each call
rand keygen                                # wallet.key.json (or --key <file>, RAND_KEY)
rand address                               # rand1… — about 1.6 KB of base58
rand balance                               # scans the tree with this key; nobody else can
rand send <rand1 address> 1.5            # confirms, proves a bundle locally (~100 s), submits, waits
rand bond <validator address> 1000         # stake: the bundle burns it out of this wallet's notes
rand faucet [address]                      # testnet chains only: mint up to 100 RAND
rand notes | rand history
rand tx <hash> | rand block <height|hash> | rand head | rand status | rand peers | rand validators
```

Amounts are decimal RAND (1 RAND = 10^9 units). The fee floor is 0.001 RAND per bundle and
goes to the proposer of the block that includes the transaction. There is no
`rand balance <address>`: a balance is a fact about your key file, not about the chain.

The ~1,667-character address is made shareable rather than shorter: `rand address` prints a
16-character fingerprint (`1WCV-YC8F-47BY-5RZY`) on stderr, and a `randpay:` link or QR code
carries the address, an optional amount and asset, and a memo of up to 510 bytes. On a chain
whose genesis sets `envelope_bytes: 1860` (chain 18) every note carries that memo, sealed to the
recipient. A memo is sender-chosen text: every client shows it sanitised, on one line. A wallet
that cannot hold a tier-14 proof in memory can pair a prover its owner runs (`rand prover pair`,
then `--prover` on any proving command; `docs/prover.md`).

## The shielded pool

Value on this chain is a set of **notes**. A note's plaintext — owner, amount, asset, randomness —
never appears on chain; what appears is its Poseidon2 **commitment**, appended as a leaf of a
depth-32 tree, and an **envelope** carrying the plaintext sealed to the owner's address (ML-KEM-768
+ ChaCha20-Poly1305). Spending a note publishes its **nullifier** `H_NF(nk, cm)`, which nobody can
link back to the commitment without the owner's viewing key.

Every transfer is one fixed 4-in-4-out **bundle** — the hidden-asset bundle, since chain 14 —
proved by a pinned zkVM guest. One bundle moves any asset (RAND, a bridged coin, an RPL token) and
nobody without a key can tell which:

```
Bundle { anchor, nullifiers[4], commitments[4], fee, burn_a, burn_r, burn_asset, time, envelopes[4], proof,
         auth_commit, auth_proof }
```

Slots 0–1 carry the private asset moved (dummies on a RAND-only transfer); a token or bridge burn
accounts for it there, in `burn_a`/`burn_asset`. Slots 2–3 always carry RAND — the `fee`, and, on
a bond or an aggregator registration, the stake burned in `burn_r`. The proof says: all four
inputs are leaves under `anchor`, their nullifiers are the published ones, each pair's inputs
balance its outputs plus whatever it burns or pays as fee, and the spender holds the keys —
without revealing which leaves, which amounts, which asset, or who. Since chain 17 the spend key
never enters the bundle proof: a small separate auth proof shows the spender holds it, bound to
the bundle by `auth_commit`, so the bundle can be proved by a delegated prover without handing
over custody. A wallet finds its own notes
by trial-decrypting every envelope on
the chain with its viewing key, so a node answers "here is the whole tree" and never "here is your
balance". `docs/howto.md` (five questions, end to end) and `docs/shielded.md` is the full guide, including the public/hidden table per action and
what still leaks (a witness request names the leaf you are about to spend).

```bash
rand faucet                  # testnet: a validator mints 100 RAND into a note only you can open
rand sync && rand notes    # scan the tree; list what this key can open
rand send rand1q9f… 1.5    # ~100 s of local proving, then the commit
```

Value enters the pool through a faucet mint, a genesis `alloc` note, or a validator's withdraw,
and every one of those amounts is **public** — the same one-hop visibility a transparent-to-shielded
deposit has anywhere. It leaves as a bundle's fee or a bond's burn, both public too, which is what
lets `rand_getSupply` account for a chain nobody can add up (`docs/supply.md`). Staking is where
those public amounts live: `docs/staking.md`. Bridged assets arrive as notes too
(`docs/bridge.md`).

## Confidential computation

A program is RV32I code for the Rand zkVM. You deploy it once (its content hash is its id), then
call it with private inputs: the wallet runs the program and proves it locally, and only the proof
and eight public output words reach the chain. Every node verifies the proof, charges gas by tier,
and stores a receipt. The gas is paid by a shielded bundle like any other transaction, so the
chain does not learn who called the program either.

```bash
rand program build --guest private_payment --arg 1000 --out pp.json   # assemble a built-in guest
rand program deploy pp.json                                            # prints the program id
rand call <program id> --input 400 --input 250 --input 300 --input 75
rand receipt <tx>
```

`private_payment` reads four private balances and, if they sum to at least the threshold,
publishes the surplus in its outputs — `[1, 0, 25, 0, ...]`. The chain sees the proof, the tier and
those eight words; it never sees the balances. What it does **not** do any more is move money on
its own: effect kind 1, the program-driven transfer to an account, was deleted with the accounts,
so the outputs are data and any payment is made by the caller in a bundle. Measured on Apple
Silicon: proving 21 s, proof 0.9 MB, on-chain verification 19 ms with a cached verifier key (the
key costs 2 s per program on a laptop, 7 s on a 2-vCPU server, computed once in the background
when the program is deployed).

Gas: every bundle 0.001 RAND and 100,000 units per code word to deploy. On chain 18 a call pays
per gas: its proof declares a gas limit the circuit enforces (`GAS ≤ GAS_LIMIT`), and the fee
floor is `BUNDLE_BASE + gas_price · gas_limit + byte_price · ⌈bytes / 1024⌉`. The prices start at
100 units per gas and 800 per KiB and adjust per block toward a target. A tier-14 call costs
about 0.004 RAND. See `docs/fees.md` and `docs/confidential.md`.

## Operating a node

```bash
rand-node status                                  # height, view, peers, mempool, programs, sync state
rand-node verify --datadir ./data                 # full integrity check: hashes, QCs, signatures, proofs, replay
rand-node verify --datadir ./data --repair        # truncate a damaged tail; peers resync the rest
RUST_LOG=debug rand-node run ...                  # verbose logs
```

At startup a node checks its chain (`--verify-chain quick|full|off`), truncates anything
inconsistent while keeping its vote-safety state, and refetches the missing blocks from peers.
`--prune-history 24h` keeps one day of blocks and certificates (the ledger itself is never
pruned); a node without the flag is an archive. A pruned node answers a lookup below its floor
with `-32010`, so point wallets and explorers at an archive for old history.
`deploy/` has scripts to provision a Linux server as a systemd service and to rebuild it on new
commits; `docs/deploy.md` describes the rollout and the fault tests that have been run.

## How it works

1. A wallet scans the commitment tree, picks at most two of its own notes per asset it is moving,
   proves a 4-in-4-out hidden-asset bundle locally, and submits `{ chain_id, bundle, action }` over
   RPC. There is no signature and no sender: the proof is the authorisation. A faucet mint is the
   one exception — a validator signs it with its own key.
2. The node validates against the tip state — cheap checks first, the bundle's STARK last — refuses
   anything conflicting with a pending transaction over a nullifier or a commitment, and gossips
   the rest.
3. The leader of the current view proposes a block extending the highest quorum certificate it
   knows, choosing transactions by fee within a 4 MiB budget. Validators vote if the block is safe
   with respect to their lock; votes from more than 2/3 of stake form the next certificate.
4. A block is committed once three consecutive certificates chain on top of it. Commits are one
   fsynced RocksDB batch: blocks, certificates, indexes, the new notes and nullifiers, the
   block-end anchor, the proposer's rewards, programs and receipts.
5. A node that falls behind requests committed blocks with their certificates from a peer, verifies
   every certificate, re-executes every block (including every bundle and call proof), and compares
   receipts before accepting.

Full detail in `docs/architecture.md`.

## Release history

Every release is a git tag, and `CHANGELOG.md` has one entry per tag; `AGENTS.md` has the full
record of each, with the measured suite and the roll. Not every tag has binaries on GitHub (as
read on 2026-09-30): v0.5.8 to v0.6.7 carry Linux binaries and `SHA256SUMS`, except v0.5.11 (no
assets) and v0.6.6 (a tag with no release); v0.5, v0.5.1, v0.5.4 and v0.5.5 have no assets, v0.5.6
has two differently named binaries and no `SHA256SUMS`, v0.5.7 has the binaries and no
`SHA256SUMS`. Those binaries were built by hand on one host and are unsigned; from the next tag
the release is built by `.github/workflows/release.yml` (`docs/deploy.md`, "Release trust"). A release that changes consensus, the wire
format or a verifier key ships with a new chain; the others roll onto the live chain one node at
a time.

| release | what it brought | chain |
|---|---|---|
| v0.5 – v0.5.8 | RPL tokens, zUSD and the hardened bridge (below); the audit fixes; history pruning; consensus and sync hardening | 14, 15 |
| v0.5.9 | rescan fixes: faucet mints only from genesis validators, sync back-off, gossip prechecks | 15 |
| v0.5.10 | address sharing: fingerprints, `randpay:` links and QR codes, the encrypted memo | 15 |
| v0.5.11 | timelocked genesis vesting for team, investor and partner allocations | — |
| v0.6 | the zkVM, rVM and aggregation fixes from the September reviews | 15 |
| v0.6.1 | constraint set 7: LogUp blinding, a 2^7 table floor, 32-bit range checks, `POSEIDON2_LEN`, JALR fix | 16 |
| v0.6.2 | delegated proving, phase 1: `rand-prover` and `--prover` | 16 |
| v0.6.3 / v0.6.4 | delegated proving, phase 2: split authorisation (the auth proof, `rand-txid-3`) | 17 |
| v0.6.6 / v0.6.7-rc1 | gas: constraint set 8, a declared gas limit per proof, dynamic gas and byte prices; the memo turned on | 18 |
| v0.6.7 | fixes on chain 18: sealed-proof pruning, the envelope-format pin, viewing-key hygiene, the rVM allocator, GPU-kernel aliasing, ALU test coverage | 18 |

## v0.5: RPL, zUSD and bridge hardening

v0.5 adds **RPL**, RandProtocol's own token standard, and hardens the bridge for its first real
asset, **zUSD** (backed by USDT and USDC bridged from Ethereum, BSC, Tron and Solana). Merged to
`main` and **live on chain 14** since 2026-09-20, pinned build `b3c594c` (see `AGENTS.md` for the
full launch record, the mainnet round-trip evidence table, and what is still pending). Highlights,
all hard forks together as chain 14:

- **A token is a registry entry, not a contract** — a shielded native asset with an id, an index,
  and a checksummed `rpl1…` text form; creation is permissionless, under a mint authority fixed at
  registration (none, a key, or the bridge); symbols are not unique, as with ERC-20 and SPL
  (`docs/tokens.md`).
- **Every transfer, of RAND or any RPL token, is one hidden-asset bundle** — a fixed 4-in/4-out
  proof that hides not only the amount and the parties but *which asset moved at all*
  (`docs/confidential.md`, "The hidden-asset bundle guest"). A token transfer publishes exactly
  what a RAND payment does.
- **A transaction is bound to its whole self.** Every bundle proof is now made over, and verified
  against, a hash of the entire transaction — closing a redirect attack that let a copied,
  unmodified proof be resubmitted under a changed destination, validator or memo
  (`docs/confidential.md`, "Transaction binding"; `docs/bridge.md` §1).
- **One bridged token can have many backings.** zUSD is one token backed by seven source coins
  across four chains, with `total_supply == Σ backings.locked` held by construction and a burn
  refused unless the named backing has enough locked and the amount is a whole release unit
  (`docs/bridge.md` §13).
- **Bridge hardening**: a per-backing daily mint cap and an operator pause key (B1); a forward
  bound on block timestamps, which makes NTP a requirement for a bridged chain's validators (B2); a
  second, post-quantum (Dilithium2) co-signature quorum on every mint (B3); and listing a new
  bridged token or backing after genesis under a PQ guardian quorum, with no chain cut and no wire
  change (B4) — `docs/bridge.md` §§14–20.

## Documentation

| document | contents |
|---|---|
| [docs/cli.md](docs/cli.md) | every `rand-node` and `rand` command, argument, and default |
| [docs/rpc.md](docs/rpc.md) | JSON-RPC methods, parameters, result shapes, error codes |
| [docs/shielded.md](docs/shielded.md) | the shielded pool: keys, what is public, the wallet, the RPC, admission, what still leaks |
| [docs/staking.md](docs/staking.md) | the validator register, epochs, and the four staking commands: register, bond, unbond, withdraw |
| [docs/supply.md](docs/supply.md) | the supply audit: the counters, the invariant a node checks, and how exact it is |
| [docs/confidential.md](docs/confidential.md) | programs, calls, outputs, gas, privacy, and each constraint set |
| [docs/fees.md](docs/fees.md) | what a transaction pays: the floors, the gas rule, dynamic prices |
| [docs/zkvm.md](docs/zkvm.md) | the Rand zkVM: ISA and execution model, memory and syscalls, trace to STARK, what is public, costs |
| [docs/aggregation.md](docs/aggregation.md) | block aggregation with the recursion VM: sealing, pruning, sealed-form sync (off on every chain today) |
| [docs/vesting.md](docs/vesting.md) | timelocked genesis allocations: claims, revocation, bonding locked RAND |
| [docs/consensus.md](docs/consensus.md) | the consensus rules added since the architecture write-up (the not-held quorum, durable pending blocks, recovery rules) |
| [docs/tokens.md](docs/tokens.md) | RPL, the token standard (v0.5): a token as a registry entry, asset ids and `rpl1…`, mint authorities, creation, hidden-asset transfers, burning, the CLI and RPC, ERC-20/SPL comparison |
| [docs/guests.md](docs/guests.md) | writing and deploying a RISC-V program: the Rand ISA, the syscall ABI, the image container, `rand-guest` build/check/run/pack, `hc` versus program id, the program-size cap |
| [docs/translators.md](docs/translators.md) | the Solana (`sbpf2rv`) and Ethereum (`evm2rv`) translators: trust model, parity, the ERC-20 and SPL Token walkthroughs, measured cycles, limits |
| [docs/architecture.md](docs/architecture.md) | how the node works end to end: consensus, ledger, storage, networking, sync, and one confidential transaction followed from wallet to receipt |
| [docs/zkvm-milestones.md](docs/zkvm-milestones.md) | the Rand zkVM milestone by milestone (M1–M4, CUDA backend): what was built and why |
| [docs/zkvm-m4-m5-progress.md](docs/zkvm-m4-m5-progress.md) | M4 and M5 as delivered: constraint sets 4–6, the recursion VM (M5.1–M5.4) with all measured numbers, what is deferred to which hardware |
| [docs/bridge.md](docs/bridge.md) | the guardian bridge: trust model, wire format, guardian sets, state, the two bridge actions, what stays public, and (v0.5) one token with many backings, the mint cap and pause, bounded timestamps, the post-quantum co-signature, and listing a token after genesis |
| [docs/prover.md](docs/prover.md) | the delegated prover (`rand-prover`, `rand-node run --prover`): the trust model (a Phase 1 prover receives the spend key), pairing, running one, what the wallet checks, the wire |
| [docs/deploy.md](docs/deploy.md) | multi-machine and cloud deployment, rebuilds, fault tests |
| [docs/node-hardware.md](docs/node-hardware.md) | what validators, wallets and aggregators compute; measured RAM, disk and prover memory per tier; DigitalOcean sizes; setup |
| [deploy/README.md](deploy/README.md) | the live testnet: nodes, addresses, peer ids |
| [docs/superpowers/specs](docs/superpowers/specs) | design specs (node, confidential computation, fully shielded pool) |

## Roadmap

Done: the shielded pool, staking and the bridge as notes (phases S1–S3), RPL tokens, history
pruning, address sharing and the memo, genesis vesting, delegated proving with split
authorisation, and gas.

Next:
- **Mainnet (v1.0)**, with a fresh genesis and a network marker that makes archive rules into
  consensus rules.
- **The bridge endpoint redeploy** (the reentrancy guard and the separate pauser). New Ethereum,
  BNB and Tron contracts only become usable in a genesis that names them.
- **Block aggregation**, off on every chain today. It still needs the end-to-end
  forged-aggregate exercise (#45), and the production rVM proofs need more than 256 GB of memory
  under constraint sets 7–8, which the aggregator machine class has to account for.
- **The timeout-certificate pacemaker** (B3); slashing and jailing; persistent per-program state
  and cross-program calls; a nullifier accumulator; the hash-sortition leader beacon.

## Open ops tasks

- **An aggregator machine.** The production rVM exit proof exceeds 256 GB under constraint set 7
  (N=2 aggregate 133 GB, N=3 221 GB, measured on a 256 GB DigitalOcean droplet, 2026-09-28/29);
  re-measure under constraint set 8 before sizing one.
- **The GPU backend.** It was first run on an NVIDIA H100 on 2026-09-28: the kernels build to PTX
  for sm_80 and sm_90 and match the CPU and Plonky3 reference (#49). The production
  N re-measurement on a fleet GPU node is still to do.
- **Wallets and the explorer on constraint set 8.** Every proof format changed with chain 18, so
  the clients repository (desktop, web, iOS, Android) and randscan need builds against circuits
  `aeacf31` before users can prove for chain 18.

## License

GNU General Public License v3.0 (`GPL-3.0-only`) — see [LICENSE](LICENSE).
