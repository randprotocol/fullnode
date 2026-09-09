# SHRUGG full node

A Rust full node for the Rand Protocol chain.

- **Consensus:** chained HotStuff BFT with stake-weighted quorums (more than 2/3), round-robin
  leaders, three-chain commit, exponential view timeouts, and view synchronisation.
- **Peer discovery:** libp2p with mDNS on a LAN, Kademlia plus a bootstrap list elsewhere, gossipsub
  for consensus and transactions, request-response for block sync, ping keepalive and automatic
  redial of known peers.
- **Ledger:** account based, like Ethereum and Solana. Each address has a nonce and a SHRUGG balance;
  transfers are signed, fee paying, and applied in order. State root is a BLAKE3 Merkle root.
- **Cryptography:** post-quantum Dilithium2 signatures, BLAKE3 hashes, 32-byte addresses in base58.
- **Storage:** one RocksDB with column families, atomic fsynced commits, and a startup integrity check
  that truncates a damaged tail and resyncs it from peers.
- **Confidential computation:** programs for the Rand zkVM (RV32I under a Plonky3 batch STARK,
  Goldilocks, Poseidon2, ZK-hiding FRI) are deployed on chain; a call carries a STARK proof plus eight
  public output words. Every node verifies the proof (about 20 ms with a cached verifier key),
  charges SHRUGG gas by tier, records a receipt, and applies the transfer the outputs request. Inputs,
  memory, and the real cycle count never leave the prover.

Two binaries: `shrugg-node` (the node and operator tools) and `shrugg` (a wallet client that talks to
any node over JSON-RPC and runs the zkVM prover locally for confidential calls).

## Layout

```
crates/shrugg-core     pure logic: crypto, types, ledger, gas, effects, genesis, HotStuff state machine (no I/O)
crates/shrugg-zkvm     the Rand zkVM (vendored from circuits/research) + the chain executor (proof verification)
crates/shrugg-node     storage (RocksDB), network (libp2p), mempool, sync, JSON-RPC server, node loop, CLI
crates/shrugg-client   RpcClient library + `shrugg` wallet CLI (prover for calls; no RocksDB or libp2p)
deploy/              genesis, test keys, run scripts, and droplet provisioning for the live testnet
docs/                reference documentation (see below)
scripts/             local two-validator testnet
```

## Documentation

| document | contents |
|---|---|
| [docs/cli.md](docs/cli.md) | every `shrugg-node` and `shrugg` command with all arguments and defaults |
| [docs/rpc.md](docs/rpc.md) | JSON-RPC methods, parameters, result shapes, error codes, examples |
| [docs/architecture.md](docs/architecture.md) | consensus, ledger, storage layout, networking, sync, integrity check |
| [docs/deploy.md](docs/deploy.md) | multi-machine and DigitalOcean deployment, rebuilds, fault tests |
| [docs/confidential.md](docs/confidential.md) | confidential computation: programs, calls, effects, gas, privacy |
| [deploy/README.md](deploy/README.md) | the live testnet: node addresses, peer ids, IPs |
| [docs/superpowers/specs](docs/superpowers/specs) | the original design spec |

## Build and test

Requires Rust 1.98.1 (pinned in `rust-toolchain.toml`; rustup installs it), a C++ compiler and
`cmake` for RocksDB.

```bash
cargo build --release            # target/release/shrugg-node and target/release/shrugg
cargo test --release             # core 58, node 18, zkVM 40, cluster (real TCP) 10; release because proving is slow in debug
```

The first build compiles RocksDB and Plonky3 from source and takes 10 to 20 minutes.

## Quick start: one machine, two validators

```bash
scripts/local-testnet.sh         # keys, genesis, init, two nodes on 30301/30302, RPC 8545/8546
target/release/shrugg --rpc http://127.0.0.1:8545 status
```

## Quick start: several machines

On every machine:

```bash
shrugg-node keygen --out node.key.json          # prints the address
shrugg-node address --key node.key.json         # address, public key, libp2p peer id
```

On one machine, with every validator's key file or hex public key:

```bash
shrugg-node genesis --chain-id 1 --validator a.key.json --validator <hex-pubkey-of-b> \
    --alloc-each 100 [--faucet] --out genesis.json          # --faucet: testnet mint RPC
```

Copy `genesis.json` to every machine unchanged (the genesis hash must match), then on each:

```bash
shrugg-node init --datadir ./data --genesis genesis.json
shrugg-node run  --datadir ./data --key node.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    [--bootstrap /ip4/<other-ip>/tcp/30303/p2p/<other-peer-id>]...
```

Nodes on the same LAN find each other through mDNS without `--bootstrap`. Behind NAT, dial out to a
node with a public address. Restarting from the same `--datadir` resumes from the persisted head.
Any validator whose key is not in the genesis set runs as an observer; omit `--validator` to run an
observer deliberately.

## Using the wallet

```bash
export SHRUGG_RPC=http://127.0.0.1:8545
shrugg keygen                                # wallet.key.json
shrugg balance [address]                     # defaults to this wallet
shrugg send <address> 1.5                    # signs, submits, waits for the commit
shrugg tx <hash> | shrugg block <height|hash> | shrugg head | shrugg status | shrugg peers | shrugg validators
```

On a testnet whose genesis has `"faucet": true`, `shrugg faucet [address]` mints up to 100 SHRUGG per call
through a real `Mint` transaction that goes through consensus (`shrugg_mint` over RPC).

## Confidential calls

```bash
shrugg program build --guest private_payment --arg 1000 --out pp.json   # assemble a built-in guest
shrugg program deploy pp.json                                            # pays deploy gas, prints the program id
shrugg call <program-id> --input 400 --input 250 --input 300 --input 75 --to <address>
#   proves on this machine (~20 s), submits proof + outputs, waits, prints the receipt
shrugg receipt <tx>
```

The program above reads four private balances and, if they sum to at least 1000, pays recipient 0
the surplus. The chain sees the proof, the tier, and the eight output words; not the balances.
See `docs/confidential.md`.

Amounts are decimal SHRUGG; 1 SHRUGG = 10^9 units. Fees default to 0.000001 SHRUGG and go to the proposer
of the block that includes the transaction.

## Operating

```bash
shrugg-node status                              # height, view, peers, mempool, sync state
shrugg-node verify --datadir ./data             # full integrity check of the local chain
shrugg-node verify --datadir ./data --repair    # truncate a damaged tail; peers resync the rest
RUST_LOG=debug shrugg-node run ...              # verbose logs
```

A validator set of `n` needs more than 2/3 of stake online to commit: with 2 validators both must be
up, with 4 one may be down, with 3 none may be down.

## Not yet implemented

Staking transactions and validator-set changes, slashing, block rewards, the hash-sortition leader
beacon from the whitepaper, persistent per-program storage and cross-program calls, a RISC-V
compiler flow for programs (the built-in assembler and raw word files are supported), the whitepaper's
shielded balance model, proof pruning after finality, and mempool back-pressure.
