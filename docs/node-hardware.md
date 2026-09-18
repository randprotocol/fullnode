# Node hardware: validators, observers, wallets and aggregators

This page says what each role computes, what hardware it has been measured to need, and how to
set one up. Every number has a source: this repo's docs and `deploy/`, the circuits READMEs, or a
command run for this page on 2026-09-19 (local date). Numbers that are not final yet are marked
`TODO-CONTROLLER`, with the current measured bound beside them.

## 1. What each role does

| role | binary and command | proves? | verifies? | notes |
|---|---|---|---|---|
| **validator** | `rand-node run --validator` | no | every bundle proof and call proof in every block | orders transactions, votes (HotStuff), stores blocks, serves RPC |
| **observer** | `rand-node run` (no `--validator`) | no | the same as a validator | syncs, verifies, serves RPC; takes no part in consensus |
| **wallet** | `rand send`, `rand call`, `rand program deploy` | yes: the tier-14 bundle proof, and the call proof | no | runs on the user's machine; the spend key never leaves it |
| **aggregator** | `rand-node aggregate --watch` | yes: one rVM aggregate proof over N bundle proofs | its own inputs | only on a chain whose genesis has an `aggregation` section |

How this was confirmed in the code at `0cfd1e3`:

- In `crates/randprotocol-node/src`, the only non-test call into a prover is
  `randprotocol_rvm::aggregate::aggregate` in `main.rs`, inside the `aggregate` command. The
  `run` path calls the executor's `verify_call`, `verify_bundle` and `verify_aggregate` only.
- The wallet proves in `crates/randprotocol-client` (`executor::prove`, `executor::prove_call`).
- Chains 9 to 12 were cut **without** the `aggregation` section (`deploy/README.md`;
  `deploy/cut-chain12-genesis.sh` defaults to `AGGREGATION=off`). So no aggregator runs on the
  testnet today. A local chain-12-style node reports `"max_covers": 0` in `rand status`.

A validator stays CPU-cheap by design (`docs/aggregation.md` §1). Proving happens in wallets and,
on an aggregation chain, in aggregators.

## 2. Validator and observer

### 2.1 Measured needs

| resource | measurement | source |
|---|---|---|
| RAM, resident | 650.5 MiB: node A, chain 12, production profile, height about 86 425, macOS | `ps -o rss`, 2026-09-19 |
| RAM, resident, fresh test chain | 65.9 MiB idle; 312.8 MiB after verifying one deploy | `ps -o rss` on a local one-validator chain, test profile |
| disk | 10 GB at height 62 276; 14 GB at height about 86 425 (node A, chain 12) | `deploy/README.md` (v0.3 update, step 4); `du -sh`, 2026-09-19 |
| disk, full blocks | about 170 GB per day if every block were full (4 MiB per block) | `docs/block-space.md` |
| startup | about 4 minutes: the quick chain verification took 239 s at 59 183 blocks before the RPC opened | `deploy/README.md` (v0.3 update, step 2) |
| bundle verify | 838 ms cold, about 16 ms warm | `docs/superpowers/specs/2026-09-15-block-aggregation.md` §1 |
| call verify | about 233 ms first (uncached) verify at tier 10, production profile (constraint set 5) | `docs/confidential.md` |
| network | TCP 30303 inbound on public nodes | `docs/deploy.md` |

Between those two disk readings the chain added about 24 000 blocks, most of them empty, and the
data dir grew by about 4 GB. Plan disk from the chain's age and load, not from the genesis size.

### 2.2 DigitalOcean sizes in use

| size | nodes | status |
|---|---|---|
| `s-1vcpu-2gb` | ams3, nyc1, nyc2, sfo2 (validators) | running chain 12 |
| `s-2vcpu-2gb` | part of the rest of the fleet (the per-node sizes are not recorded in `deploy/`) | running chain 12 |
| `s5-1vcpu-2gb-30gb` | mkc1, mem1 (validators) | running, but the 30 GB disk filled with three chains' data dirs; resize before the chain grows past about 20 GB |
| 4 vCPU, 8 GB | E (validator, explorer, build host) | builds the Linux binaries: 4 min 17 s for `4504a03` |

Sources: `deploy/nodes.env`, `deploy/README.md`.

Rules that follow from these numbers:

- **2 GB of RAM runs a validator** on this chain today. The fleet's `s-1vcpu-2gb` droplets do it.
- **Disk, not RAM, is the limit.** Keep at least 20 GB free for builds (`docs/block-space.md` §5)
  and delete a retired chain's data dir after a cut-over.
- **Do not build on a 2 GB droplet.** Build once on the 8 GB build host and copy the binaries
  (`deploy/update-droplet.sh`, `deploy/cutover-droplet.sh`). Copying 36 MB per node from a laptop
  uplink takes minutes each; droplet-to-droplet takes under a minute for all 15.
- **An aggregation chain adds a start-up cost.** Each node builds the rVM verifier key once:
  13.0–13.4 s at the test profile (2^19). The production figure at 2^21 is an estimate of about
  30–70 s. `TODO-CONTROLLER`: measure the production key build and its memory.

### 2.3 Set up a validator on a droplet

The fleet's droplets were provisioned by `deploy/push-to-vps.sh`, which runs `deploy/vps-setup.sh`
on the server. The server needs `build-essential clang cmake pkg-config libssl-dev` and a Rust
toolchain, and ports 22 and 30303 open (`docs/deploy.md`).

> **Two caveats about `deploy/vps-setup.sh`.**
>
> - Up to `0cfd1e3` it wrote `/etc/systemd/system/rand-node.service` and then deleted it: the
>   rename (`ed96c39`) had turned its "retire the pre-rename service" line into `rand-node`
>   itself. The `docs-v04` branch fixes this (`deploy: vps-setup.sh keeps the rand-node unit it
>   just wrote`). Use a checkout that has the fix.
> - It still initialises from `deploy/genesis.json`, which is chain 5, not the live chain.
>
> The manual steps below are the script's own commands with the live chain's genesis file.

On the build host (E), build the pinned commit from your machine:

```bash
deploy/rebuild-vps.sh 188.166.235.187      # rsync this checkout, cargo build --release, restart E
```

On the new droplet, as root, with the binaries copied from E to `/usr/local/bin/` and the repo
(or at least `deploy/`) at `/root/fullnode`:

```bash
rand-node keygen --out /root/fullnode/deploy/node-<name>.key.json
rand-node address --key /root/fullnode/deploy/node-<name>.key.json   # address, public key, peer id
rand-node init --datadir /root/data-<name>-<genesis8> --genesis /root/fullnode/deploy/genesis-chain<N>.json
```

`init` prints the genesis hash. It must equal the one the chain announced. On a chain whose
genesis sets `max_program_words`, the binary must be a v0.4 build before `init`, or the hash
differs (`docs/cli.md`, `rand-node init`).

The unit `deploy/vps-setup.sh` writes, with the placeholders filled:

```ini
[Unit]
Description=RAND full node (<name>)
After=network-online.target
[Service]
Environment=RUST_LOG=info,libp2p=warn,libp2p_mdns=off
ExecStart=/usr/local/bin/rand-node run --datadir /root/data-<name>-<genesis8> --key /root/fullnode/deploy/node-<name>.key.json --validator --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 --no-mdns --bootstrap <multiaddr> --bootstrap <multiaddr>
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
```

Drop `--validator` for an observer. Take bootstrap multiaddrs from `deploy/nodes.env`. Then:

```bash
systemctl daemon-reload
systemctl enable rand-node
systemctl restart rand-node
systemctl status rand-node
journalctl -u rand-node -f
rand status          # height climbing, peer_count, chain_id, active_validator
```

A key in the genesis register validates from block 0. A new key joins a running chain by staking
(`rand-node register`, then `rand bond … --registration <hex>`; `docs/staking.md`) and starts
proposing at the next epoch boundary without a restart.

### 2.4 Keep it running

| task | command | source |
|---|---|---|
| same-chain binary update | `deploy/update-droplet.sh <ip>`, one droplet at a time; wait for `rand_getHealth` = `ok` before the next | `deploy/README.md` |
| cut over to a new chain | `deploy/cutover-droplet.sh <ip> <old-prefix> <new-prefix> <genesis-file>` | `deploy/README.md` |
| verify the stored chain | `rand-node verify --datadir <dir> --mode full` (stop the service first) | `docs/deploy.md` |
| laptop validator behind NAT | `deploy/run-a.sh` | `deploy/run-a.sh` |

Keep `--block-interval-ms` at 1000 or slower. A bundle proof takes about 100 s and its anchor is
valid for 256 blocks (`docs/cli.md`).

## 3. Wallet

A wallet proves locally. Its hardware sets how fast a user can send or call.

| proof | tier | time | peak memory |
|---|---|---|---|
| bundle (every transfer, deploy and call) | 14 | about 100 s (production); 97.0 s measured (test profile) | 5.74 GB for one `rand call` (tier-10 call plus tier-14 bundle), test profile. Production: `TODO-CONTROLLER` |
| a call at tier 10 | 10 | 6.0 s measured (test profile); 6.05 s for `fib` (production, constraint set 5) | included above |
| a call at tier 18 or 20 | 18, 20 | see §5 | see §5 |

The test-profile row is `/usr/bin/time -l rand call …` on this laptop, 2026-09-19
([`guests.md`](guests.md#46-call-it)).

## 4. Aggregator

An aggregator proves one rVM STARK over N bundle proofs and submits it for a sealing window. It
needs only an RPC endpoint and a registered aggregator key. It runs only on a chain whose genesis
carries an `aggregation` section; none does today.

| aggregate | tier | measured | machine class |
|---|---|---|---|
| test profile, N=1 | 19 | proven: 1568.2 s wall on a loaded shared box, 327 035 bytes; about 30 GB peak | — |
| production, N=1 | 21 | 1 968 758 rows; 48.6 GB oracle, not yet proven | ≥ 64 GB host. Final: `TODO-CONTROLLER` |
| production, N=2 | 22 | about 95.3 GB estimate | ≥ 128 GB host. Final: `TODO-CONTROLLER` |
| production, N=3 | 23 | about 127 GB estimate | ≥ 160 GB host plus an 80 GB GPU. Final: `TODO-CONTROLLER` |

Sources: `docs/aggregation.md` §6, `docs/zkvm-m4-m5-progress.md`,
`docs/superpowers/specs/2026-09-15-block-aggregation.md`.

Setup, on a chain with an `aggregation` section (`docs/cli.md`, `docs/deploy.md`):

```bash
rand-node aggregator register --key agg.key.json --bond <RAND> --payout <rand1…> --rpc <URL>
# the printed registration is burned in through a wallet's bundle; then:
rand-node aggregate --key agg.key.json --rpc <URL> --watch
```

## 5. Prover memory per tier

**The prover is single-threaded.** A 16-vCPU box ran it at 99 % of one core. More cores do not
shorten a proof today; more RAM decides whether it finishes.

| tier | cycles (up to) | workload measured | memory measured | time measured | final |
|---|---:|---|---|---|---|
| 10 | 1 023 | `fib` (production, constraint set 5) | not recorded | 6.05 s | — |
| 14 | 16 383 | the bundle (wallet, test profile) | 5.74 GB whole `rand call` | 97.0 s | production: `TODO-CONTROLLER` |
| 18 | 262 143 | ERC-20, about 66 k–162 k cycles | OOM-killed on a 48 GB laptop at 24.7 GB. On a 64 GB droplet: above 47 GB at 25 min, still running | killed after 1 016 s on the laptop | translated `transfer`: 85.0 GB, 3 230.5 s (53.8 min), 811 600 B proof. Interpreter `evm.bin`: 85.5 GB, 3 143.3 s (52.4 min), 805 108 B proof. Verify: 101.4 s (droplet), 50.2 s at 3.66 GB RSS (laptop). Measured on m-16vcpu-128gb, 2026-09-19 |
| 19 (rVM) | — | rVM aggregate, N=1, test profile | about 30 GB peak | 1568.2 s | — |
| 20 | 1 048 575 | SPL Token, about 700 k–770 k cycles | stopped on a 48 GB laptop at about 31 GB (30.77 GB peak footprint); OOM-killed on a 64 GB droplet at 65.1 GB | 10 m 41 s on the droplet before the kill | not yet proven. Extrapolated from the measured tier-16/18 scaling (memory about ×3.9, time about ×4.1 per +2 tiers): about 330 GB and about 3.6 h, more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) |
| 21 (rVM) | — | rVM aggregate, N=1, production | 48.6 GB oracle | not run | `TODO-CONTROLLER` |

The cycle column is `2^t − 1` for the RV32 zkVM (`docs/confidential.md`). The rVM (the
recursion machine) has its own tiers, sized in rows (`docs/zkvm-m4-m5-progress.md`). The tier-18 and tier-20 laptop runs used
`FriProfile::Test` (circuits `evm2rv/README.md`, `sbpf2rv/README.md`).

### DigitalOcean sizes for proving

| workload | size | status |
|---|---|---|
| a tier-14 bundle (any wallet) | any machine with more than 5.74 GB free (test profile) | measured |
| tier 18 | a 128 GB droplet (size slug `m-16vcpu-128gb`, Memory-Optimized, 16 vCPU). OOM-killed on a 64 GB droplet (`g-16vcpu-64gb`) at 65.1 GB after 32 min | measured: 85.0 GB (translated) / 85.5 GB (interpreted) peak RSS, 3 230.5 s / 3 143.3 s |
| tier 20 | more than 64 GB. OOM-killed on a 64 GB droplet (`g-16vcpu-64gb`) at 65.1 GB after 10 m 41 s | not yet proven; extrapolated at about 330 GB and about 3.6 h (see §5), more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) |
| aggregate N=1, production | ≥ 64 GB | not run |

No proof above tier 14 is part of normal chain operation today. Tier 18 and 20 matter for calls to
the translated ERC-20 and SPL Token programs ([`translators.md`](translators.md#7-what-works-on-chain-today)).
