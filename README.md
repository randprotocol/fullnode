# Randprotocol Full Node and RPC Client

The reference full node for the Rand Protocol chain and its command-line wallet, written in Rust.
The chain's native token is **SHRUGG**: it is transferred between accounts like ETH or SOL, and it
pays for **confidential arbitrary computation**, programs that run off-chain inside a zero-knowledge
virtual machine and settle on chain with a proof instead of their inputs.

| | |
|---|---|
| Consensus | chained HotStuff BFT, stake-weighted quorums (more than 2/3), round-robin leaders, three-chain commit, view synchronisation, exponential timeouts |
| Signatures / hashes | Dilithium2 (post-quantum) / BLAKE3; addresses are base58 of the hashed public key |
| Networking | libp2p 0.54: TCP + Noise + Yamux, gossipsub, Kademlia + bootstrap list, mDNS on LANs, request-response block sync, ping keepalive, automatic redial |
| Ledger | account based (nonce + balance), signed transfers with fees to the proposer, BLAKE3 Merkle state root over accounts and deployed programs |
| Confidential computation | Rand zkVM: RV32I under a Plonky3 batch STARK (Goldilocks, Poseidon2, ZK-hiding FRI); programs deployed on chain, calls carry a proof + 8 public outputs, gas by tier, program-driven transfers |
| Storage | one RocksDB per node with column families for blocks, certificates, indexes, accounts, programs, receipts; fsynced commits; startup integrity check with truncate-and-resync |
| Interfaces | JSON-RPC 2.0 over HTTP (`shrugg-node`), `shrugg` wallet CLI with a local prover, Rust client library |

Status: an experimental testnet (see `deploy/README.md`) runs across two laptops and four cloud
servers. Not audited; not for real value.

## Contents

- [Repository layout](#repository-layout)
- [Build and test](#build-and-test)
- [Run a node](#run-a-node)
- [Use the wallet](#use-the-wallet)
- [Confidential computation](#confidential-computation)
- [Operating a node](#operating-a-node)
- [How it works](#how-it-works)
- [Documentation](#documentation)
- [Roadmap](#roadmap)

## Repository layout

```
crates/shrugg-core     pure logic, no I/O: crypto, types, ledger rules, gas, output effects, genesis,
                       the HotStuff state machine (tested with a simulated network)
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

Test coverage: 58 core tests (crypto, ledger rules, gas, effects, genesis, a deterministic
multi-replica HotStuff simulation with partitions and restarts), 18 node unit tests (storage,
corruption cases, mempool), 40 zkVM tests (upstream suite plus executor tests with real proofs),
and 10 cluster tests that start real nodes over TCP: transfers, late joiners, restart cycles,
quorum loss and recovery, corrupted database recovery, the faucet, and a full confidential
deploy-and-call with receipts on every node.

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
shrugg-node genesis --chain-id 1 \
    --validator a.key.json --validator <hex public key of b> \
    --alloc-each 100 [--faucet] [--no-confidential] [--fri-profile production] \
    --out genesis.json
```

Each machine initialises and runs:

```bash
shrugg-node init --datadir ./data --genesis genesis.json
shrugg-node run  --datadir ./data --key node.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    [--bootstrap /ip4/<ip>/tcp/30303/p2p/<peer id>]...
```

Nodes on one LAN discover each other over mDNS; across networks, machines behind NAT dial out to a
node with a public address. A key that is not in the genesis validator set runs as an observer;
omit `--validator` to run an observer on purpose. Restarting from the same `--datadir` resumes from
the persisted head. A validator set of `n` needs more than 2/3 of stake online: 2 of 2, 3 of 4, 5 of 6.

## Use the wallet

```bash
export SHRUGG_RPC=http://127.0.0.1:8545     # or --rpc on each call
shrugg keygen                                # wallet.key.json (or --key <file>, SHRUGG_KEY)
shrugg address
shrugg balance [address]
shrugg send <address> 1.5                    # signs, submits, waits for the commit
shrugg faucet [address]                      # testnet chains only: mint up to 100 SHRUGG
shrugg tx <hash> | shrugg block <height|hash> | shrugg head | shrugg status | shrugg peers | shrugg validators
```

Amounts are decimal SHRUGG (1 SHRUGG = 10^9 units). Fees default to 0.000001 SHRUGG and go to the
proposer of the block that includes the transaction.

## Confidential computation

A program is RV32I code for the Rand zkVM. You deploy it once (its content hash is its id), then
call it with private inputs: the wallet runs the program and proves it locally, and only the proof
and eight public output words reach the chain. Every node verifies the proof, charges gas by tier,
stores a receipt, and applies the transfer the outputs request.

```bash
shrugg program build --guest private_payment --arg 1000 --out pp.json   # assemble a built-in guest
shrugg program deploy pp.json                                            # prints the program id
shrugg call <program id> --input 400 --input 250 --input 300 --input 75 --to <address>
shrugg receipt <tx>
```

`private_payment` reads four private balances and, if they sum to at least the threshold, pays
recipient 0 the surplus. The chain sees the proof, the tier, and the outputs `[1, 0, 25, 0, ...]`
("transfer 25 units to recipient 0"); it never sees the balances. Measured on Apple Silicon:
proving 21 s, proof 0.9 MB, on-chain verification 19 ms with a cached verifier key (the key costs
2 s per program on a laptop, 7 s on a 2-vCPU server, computed once in the background when the
program is deployed).

Outputs are the program's instruction to the chain: `out0` kind (0 none, 1 transfer), `out1`
recipient index into the public list passed with `--to`, `out2|out3` amount as a 64-bit little-endian
integer, `out4..7` free data. Gas: deploy 100,000 units per code word; call 0.001 SHRUGG plus
0.0001 per two tiers above tier 10. See `docs/confidential.md`.

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

1. A transaction (transfer, mint, deploy, or call) is signed with Dilithium2, submitted over RPC,
   validated against the tip state, gossiped, and queued per sender by nonce.
2. The leader of the current view proposes a block extending the highest quorum certificate it
   knows, choosing transactions by fee within a 4 MiB budget. Validators vote if the block is safe
   with respect to their lock; votes from more than 2/3 of stake form the next certificate.
3. A block is committed once three consecutive certificates chain on top of it. Commits are one
   fsynced RocksDB batch: blocks, certificates, indexes, touched accounts, programs, receipts.
4. A node that falls behind requests committed blocks with their certificates from a peer, verifies
   every certificate, re-executes every block (including proof verification), and compares receipts
   before accepting.

Full detail in `docs/architecture.md`.

## Documentation

| document | contents |
|---|---|
| [docs/cli.md](docs/cli.md) | every `shrugg-node` and `shrugg` command, argument, and default |
| [docs/rpc.md](docs/rpc.md) | JSON-RPC methods, parameters, result shapes, error codes |
| [docs/confidential.md](docs/confidential.md) | programs, calls, effects, gas, privacy |
| [docs/architecture.md](docs/architecture.md) | how the node works end to end: consensus, ledger, storage, networking, sync, and one confidential transaction followed from wallet to receipt |
| [docs/zkvm-milestones.md](docs/zkvm-milestones.md) | the Rand zkVM milestone by milestone (M1–M4, CUDA backend): what was built and why |
| [docs/bridge.md](docs/bridge.md) | the guardian bridge: trust model, wire format, guardian sets, state, transactions |
| [docs/deploy.md](docs/deploy.md) | multi-machine and cloud deployment, rebuilds, fault tests |
| [deploy/README.md](deploy/README.md) | the live testnet: nodes, addresses, peer ids |
| [docs/superpowers/specs](docs/superpowers/specs) | design specs (node, confidential computation, fully shielded pool) |

## Roadmap

Not yet implemented: persistent per-program state and cross-program calls; a RISC-V compiler flow
for programs (today: the built-in assembler or raw word files); the whitepaper's shielded balance
model (hidden amounts and recipients); staking transactions, validator-set changes, and slashing;
block rewards; the hash-sortition leader beacon; proof pruning after finality; fee markets.

## License

Apache-2.0.
