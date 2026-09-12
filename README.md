# Randprotocol Full Node and RPC Client

The reference full node for the Rand Protocol chain and its command-line wallet, written in Rust.
The chain's native token is **SHRUGG**, and it lives in a **fully shielded pool**: there are no
accounts and no balances, only note commitments and nullifiers, and a transfer is a zero-knowledge
proof that some two notes became some other two. The same token pays for **confidential arbitrary
computation** — programs that run off-chain inside a zero-knowledge virtual machine and settle on
chain with a proof instead of their inputs.

| | |
|---|---|
| Consensus | chained HotStuff BFT, stake-weighted quorums (more than 2/3), round-robin leaders, three-chain commit, view synchronisation, exponential timeouts |
| Signatures / hashes | Dilithium2 (post-quantum) / BLAKE3 for validators and blocks; Poseidon2 for notes, the tree and nullifiers; ML-KEM-768 + ChaCha20-Poly1305 for note envelopes |
| Networking | libp2p 0.54: TCP + Noise + Yamux, gossipsub, Kademlia + bootstrap list, mDNS on LANs, request-response block sync, ping keepalive, automatic redial |
| Ledger | shielded note pool: a depth-32 Poseidon2 commitment tree, a nullifier set, 2-in-2-out proved bundles, public fees to the proposer's register entry, BLAKE3 Merkle state root over tree, nullifiers, validators and programs |
| Staking | a public validator register — bond out of a bundle's burn, unbond over two epochs, withdraw into a shielded note — epochs that re-derive the validator set from it, and a supply audit that adds the register and the pool back up to what the chain issued |
| Wallet keys | a 256-bit spend key; viewing key, note-owner field, nullifier key, outgoing viewing key, ML-KEM-768 decapsulation key and `shrugg1…` address all derived from it |
| Bridged assets | parked: the guardian bridge returns in phase S3, with bridged assets as notes (`docs/bridge.md`) |
| Confidential computation | Rand zkVM: RV32I under a Plonky3 batch STARK (Goldilocks, Poseidon2, ZK-hiding FRI); programs deployed on chain, calls carry a proof + 8 public outputs, gas by tier, and pay through a bundle like everything else |
| Storage | one RocksDB per node with column families for blocks, certificates, indexes, notes, nullifiers, anchors, validators, programs and receipts; fsynced commits; startup integrity check with truncate-and-resync |
| Interfaces | JSON-RPC 2.0 over HTTP (`shrugg-node`), `shrugg` wallet CLI with a local prover, Rust client library |

Status: an experimental testnet (see `deploy/README.md`) runs across two laptops and four cloud
servers. That fleet is still on **chain 5, an account chain**: the shielded pool is a hard fork and
the operator cuts it as a new chain id when they choose to. Not audited; not for real value.

## Contents

- [Repository layout](#repository-layout)
- [Build and test](#build-and-test)
- [Run a node](#run-a-node)
- [Use the wallet](#use-the-wallet)
- [The shielded pool](#the-shielded-pool)
- [Confidential computation](#confidential-computation)
- [Operating a node](#operating-a-node)
- [How it works](#how-it-works)
- [Documentation](#documentation)
- [Roadmap](#roadmap)

## Repository layout

```
crates/shrugg-core     pure logic, no I/O: crypto, types, notes and the commitment tree, ledger
                       rules, gas, genesis, the HotStuff state machine (tested with a simulated network)
crates/shrugg-zkvm     the Rand zkVM (vendored from circuits/research; resync with deploy/sync-zkvm.sh)
                       plus the chain-side proof verifier with its verifier-key cache
crates/shrugg-node     RocksDB storage, libp2p networking, mempool, block sync, JSON-RPC server,
                       the node event loop, and the shrugg-node binary
crates/shrugg-client   the shrugg wallet binary and the RpcClient library (no RocksDB/libp2p dependency)
deploy/                testnet genesis, test keys, run scripts, cloud provisioning and rebuild scripts
docs/                  reference documentation and the design spec / plan
scripts/               local two-validator testnet
```

## Build and test

Requirements: Rust 1.98.1 (pinned in `rust-toolchain.toml`; rustup installs it), a C++ compiler
and `cmake` (RocksDB). First build: 10 to 20 minutes (RocksDB and Plonky3 from source).

```bash
cargo build --release        # target/release/shrugg-node, target/release/shrugg
cargo test --release         # all crates; release because STARK proving is slow in debug
```

Test coverage: 133 core tests (crypto, notes and the tree, ledger admission rules, the staking
register and its epochs, the supply audit, gas, genesis, a deterministic multi-replica HotStuff
simulation with partitions, restarts and epoch rollovers), node unit tests (storage, corruption
cases, the conflict mempool, the redacted RPC), wallet tests (key file, scanning, coin selection),
the zkVM suite (upstream tests plus executor tests with real proofs), one wallet-flow test against a
real one-node chain (mint, scan, send, spend the change, bond), and 14 cluster tests that start real
nodes over TCP: a shielded transfer between wallets, a double-spend race between two validators, a
deploy-and-call paid by bundles, a fifth validator that registers and bonds itself into the next
epoch, a validator that unbonds out of the set and withdraws into a note its payout wallet spends,
late joiners, restart cycles, quorum loss and recovery, corrupted database recovery, and the faucet.
The cluster suite proves real bundles and takes about twenty minutes.

## Run a node

### One machine, two validators

```bash
scripts/local-testnet.sh
target/release/shrugg --rpc http://127.0.0.1:8545 status
```

### Several machines

Each machine creates a key:

```bash
shrugg-node keygen --out node.key.json      # prints the address
shrugg-node address --key node.key.json     # address, public key, libp2p peer id
```

One machine writes the genesis with every validator's key file or hex public key, then the file is
copied to all machines unchanged (the genesis hash must match everywhere):

```bash
shrugg-node genesis --chain-id 6 \
    --validator a.key.json,1000,shrugg1<a's payout address> \
    --validator <hex public key of b>,1000,shrugg1<b's payout address> \
    --alloc shrugg1<address>=1000 \
    [--epoch-blocks 1000] \
    [--faucet] [--no-confidential] [--fri-profile production] \
    --out genesis.json
```

A `--validator` is one register entry, so it carries all three of its fields at once: the key, the
stake in SHRUGG, and the payout address its block rewards and unbonded stake are paid to (phase S2).
All three are part of the genesis hash. 1000 SHRUGG is the minimum a validator needs to be in an
epoch's validator set at all; genesis refuses less. `--epoch-blocks` is how often the set is
re-derived from the register (spec §8) — the default is 1000 blocks.

Each `--alloc` creates one shielded deposit note: there is no per-validator allocation, because
value exists only as a note someone holds the spend key for. The addresses come from
`shrugg keygen` + `shrugg address` on whichever machines will hold the funds. `deploy/README.md`
has a worked example, and `deploy/genesis-shielded.example.json` is one such file.

A validator that joins an existing chain registers instead of appearing in genesis:

```bash
shrugg-node register --key node.key.json --payout shrugg1<payout address>   # prints a Registration (hex)
shrugg-node unbond   1000 --key node.key.json                               # two epochs to release
shrugg-node withdraw 1000 --key node.key.json                               # into a note at the payout address
```

The bond itself is a wallet transaction — it burns the stake out of shielded notes, which a node
holds none of — and takes the hex `register` printed. `unbond` and `withdraw` need no wallet: they
are signed by the node's key and carry no bundle at all, exactly as a faucet mint does, and the
register's nonce is what keeps them from being replayed. So there is nothing to prove and each
commits in a block's time.

Their fee model is its own, for the same reason: `unbond` moves stake inside the public register
and pays nothing at all, while `withdraw` pays the 0.001 SHRUGG bundle base out of the amount it
withdraws, to the proposer of the block that applies it. A withdrawal of 1000 SHRUGG therefore
creates a note worth 999.999, and an amount that cannot cover the base is refused. `docs/staking.md`
walks the whole join-and-leave through, including when bonded stake starts counting as weight.

Each machine initialises and runs:

```bash
shrugg-node init --datadir ./data --genesis genesis.json
shrugg-node run  --datadir ./data --key node.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    [--bootstrap /ip4/<ip>/tcp/30303/p2p/<peer id>]...
```

Nodes on one LAN discover each other over mDNS; across networks, machines behind NAT dial out to a
node with a public address. `--validator` means "this node holds a validator key": a key that is in
no current epoch's set observes until an epoch admits it, which is how a validator that bonds in
after genesis joins without a restart (`shrugg_status` reports `is_validator` for the key and
`active_validator` for being in the current set). Omit `--validator` to run an observer on purpose. Restarting from the same `--datadir` resumes from
the persisted head. A validator set of `n` needs more than 2/3 of stake online: 2 of 2, 3 of 4, 5 of 6.

## Use the wallet

```bash
export SHRUGG_RPC=http://127.0.0.1:8545     # or --rpc on each call
shrugg keygen                                # wallet.key.json (or --key <file>, SHRUGG_KEY)
shrugg address                               # shrugg1… — about 1.6 KB of base58
shrugg balance                               # scans the tree with this key; nobody else can
shrugg send <shrugg1 address> 1.5            # proves a bundle locally (~100 s), submits, waits
shrugg bond <validator address> 1000         # stake: the bundle burns it out of this wallet's notes
shrugg faucet [address]                      # testnet chains only: mint up to 100 SHRUGG
shrugg notes | shrugg history
shrugg tx <hash> | shrugg block <height|hash> | shrugg head | shrugg status | shrugg peers | shrugg validators
```

Amounts are decimal SHRUGG (1 SHRUGG = 10^9 units). The fee floor is 0.001 SHRUGG per bundle and
goes to the proposer of the block that includes the transaction. There is no
`shrugg balance <address>`: a balance is a fact about your key file, not about the chain.

## The shielded pool

Value on this chain is a set of **notes**. A note's plaintext — owner, amount, asset, randomness —
never appears on chain; what appears is its Poseidon2 **commitment**, appended as a leaf of a
depth-32 tree, and an **envelope** carrying the plaintext sealed to the owner's address (ML-KEM-768
+ ChaCha20-Poly1305). Spending a note publishes its **nullifier** `H_NF(nk, cm)`, which nobody can
link back to the commitment without the owner's viewing key.

Every transfer is one fixed 2-in-2-out **bundle**, proved by a pinned zkVM guest:

```
Bundle { anchor, nullifiers[2], commitments[2], fee, burn, asset, time, envelopes[2], proof }
```

The proof says: both inputs are leaves under `anchor`, their nullifiers are the published ones,
inputs balance outputs plus the fee, and the spender holds the keys — without revealing which
leaves, which amounts, or who. A wallet finds its own notes by trial-decrypting every envelope on
the chain with its viewing key, so a node answers "here is the whole tree" and never "here is your
balance". `docs/shielded.md` is the full guide, including the public/hidden table per action and
what still leaks (a witness request names the leaf you are about to spend).

```bash
shrugg faucet                  # testnet: a validator mints 100 SHRUGG into a note only you can open
shrugg sync && shrugg notes    # scan the tree; list what this key can open
shrugg send shrugg1q9f… 1.5    # ~100 s of local proving, then the commit
```

Value enters the pool through a faucet mint, a genesis `alloc` note, or a validator's withdraw,
and every one of those amounts is **public** — the same one-hop visibility a transparent-to-shielded
deposit has anywhere. It leaves as a bundle's fee or a bond's burn, both public too, which is what
lets `shrugg_getSupply` account for a chain nobody can add up (`docs/supply.md`). Staking is where
those public amounts live: `docs/staking.md`. Bridged assets are phase S3.

## Confidential computation

A program is RV32I code for the Rand zkVM. You deploy it once (its content hash is its id), then
call it with private inputs: the wallet runs the program and proves it locally, and only the proof
and eight public output words reach the chain. Every node verifies the proof, charges gas by tier,
and stores a receipt. The gas is paid by a shielded bundle like any other transaction, so the
chain does not learn who called the program either.

```bash
shrugg program build --guest private_payment --arg 1000 --out pp.json   # assemble a built-in guest
shrugg program deploy pp.json                                            # prints the program id
shrugg call <program id> --input 400 --input 250 --input 300 --input 75
shrugg receipt <tx>
```

`private_payment` reads four private balances and, if they sum to at least the threshold,
publishes the surplus in its outputs — `[1, 0, 25, 0, ...]`. The chain sees the proof, the tier and
those eight words; it never sees the balances. What it does **not** do any more is move money on
its own: effect kind 1, the program-driven transfer to an account, was deleted with the accounts,
so the outputs are data and any payment is made by the caller in a bundle. Measured on Apple
Silicon: proving 21 s, proof 0.9 MB, on-chain verification 19 ms with a cached verifier key (the
key costs 2 s per program on a laptop, 7 s on a 2-vCPU server, computed once in the background
when the program is deployed).

Gas: every bundle 0.001 SHRUGG, plus 100,000 units per code word to deploy, plus 0.001 SHRUGG at
tier 10 rising 0.0001 per two tiers to call. See `docs/confidential.md`.

## Operating a node

```bash
shrugg-node status                                  # height, view, peers, mempool, programs, sync state
shrugg-node verify --datadir ./data                 # full integrity check: hashes, QCs, signatures, proofs, replay
shrugg-node verify --datadir ./data --repair        # truncate a damaged tail; peers resync the rest
RUST_LOG=debug shrugg-node run ...                  # verbose logs
```

At startup a node checks its chain (`--verify-chain quick|full|off`), truncates anything
inconsistent while keeping its vote-safety state, and refetches the missing blocks from peers.
`deploy/` has scripts to provision a Linux server as a systemd service and to rebuild it on new
commits; `docs/deploy.md` describes the rollout and the fault tests that have been run.

## How it works

1. A wallet scans the commitment tree, picks at most two of its own notes, proves a 2-in-2-out
   bundle locally, and submits `{ chain_id, bundle, action }` over RPC. There is no signature and
   no sender: the proof is the authorisation. A faucet mint is the one exception — a validator
   signs it with its own key.
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

## Documentation

| document | contents |
|---|---|
| [docs/cli.md](docs/cli.md) | every `shrugg-node` and `shrugg` command, argument, and default |
| [docs/rpc.md](docs/rpc.md) | JSON-RPC methods, parameters, result shapes, error codes |
| [docs/shielded.md](docs/shielded.md) | the shielded pool: keys, what is public, the wallet, the RPC, admission, what still leaks |
| [docs/staking.md](docs/staking.md) | the validator register, epochs, and the four staking commands: register, bond, unbond, withdraw |
| [docs/supply.md](docs/supply.md) | the supply audit: the counters, the invariant a node checks, and how exact it is |
| [docs/confidential.md](docs/confidential.md) | programs, calls, outputs, gas, privacy |
| [docs/architecture.md](docs/architecture.md) | how the node works end to end: consensus, ledger, storage, networking, sync, and one confidential transaction followed from wallet to receipt |
| [docs/zkvm-milestones.md](docs/zkvm-milestones.md) | the Rand zkVM milestone by milestone (M1–M4, CUDA backend): what was built and why |
| [docs/bridge.md](docs/bridge.md) | the guardian bridge: trust model, wire format, guardian sets, state, transactions — **parked until phase S3** |
| [docs/deploy.md](docs/deploy.md) | multi-machine and cloud deployment, rebuilds, fault tests |
| [deploy/README.md](deploy/README.md) | the live testnet: nodes, addresses, peer ids |
| [docs/superpowers/specs](docs/superpowers/specs) | design specs (node, confidential computation, fully shielded pool) |

## Roadmap

The shielded pool lands in three phases, each a hard fork (`docs/shielded.md` §7). **S1** is the
pool itself: notes, bundles, the wallet, the redacted RPC. **S2**, here, adds staking on top of it —
Bond, Unbond and Withdraw, epochs that re-derive the validator set from the register, and the
validator rewards S1 accrued but could not pay out (`docs/staking.md`). **S3** brings the bridge back
as notes and gives call inputs their own envelopes. Still outstanding from S2's own plan: the local
wallet commitment tree, so a wallet stops telling its node which leaf it is about to spend.

Not yet implemented beyond that: persistent per-program state and cross-program calls; a RISC-V
compiler flow for programs (today: the built-in assembler or raw word files); slashing and jailing;
a nullifier accumulator in place of the per-block recomputation; block rewards; the hash-sortition
leader beacon; proof pruning after finality; fee markets.

## License

Apache-2.0.
