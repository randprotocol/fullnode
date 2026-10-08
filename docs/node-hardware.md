# Node hardware: validators, observers, wallets and aggregators

This page says what each role computes, what hardware it has been measured to need, and how to
set one up. Every number has a source: this repo's docs and `deploy/`, the circuits READMEs, or a
command run for this page on 2026-09-19 (local date). Numbers nobody has measured yet are marked
"not measured yet", with the current bound beside them.

The testnet runs **chain 18** (genesis `a7cb020c…4da76`, build v0.6.7 `86941a1`, live since
2026-09-29 04:56 UTC) on 26 DigitalOcean validators; a quorum is 18 of 26. Twenty-four run
`--prune-history 24h`; two (obs1 and rand-archive-2) keep every block. Its caps: 4 MiB per proof,
20 MiB per block; every note envelope is 1 860 bytes; calls and bundles declare a gas limit
(`docs/deploy.md`, "The network today"; `docs/fees.md`).

**Most measurements below were taken on chains 12 and 13 (2026-09-18/19) and are kept with their
dates; they have not been re-measured on chain 18** (updated 2026-09-30, audit v6 DOC-6). What
changed since, where a row depends on it: a transfer now carries two proofs (the tier-14 bundle
proof and a tier-10 auth proof, since chain 17); a call above tier 14 is refused by every node
since v0.5.6 (`MAX_CALL_TIER`), so the tier-16 call measured on chain 13 is not admissible on
chain 18; validators prune, so the disk rows describe an archive.

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
- Chains 9 to 13 were cut **without** the `aggregation` section (`deploy/README.md`;
  `deploy/cut-chain12-genesis.sh` and `deploy/cut-chain13-genesis.sh` default to
  `AGGREGATION=off`). So no aggregator runs on the testnet today. A local chain-12-style node
  reports `"max_covers": 0` in `rand status`.

A validator stays CPU-cheap by design (`docs/aggregation.md` §1). Proving happens in wallets and,
on an aggregation chain, in aggregators.

## 2. Validator and observer

### 2.1 Measured needs

| resource | measurement | source |
|---|---|---|
| RAM, resident | 650.5 MiB: node A, chain 12, production profile, height about 86 425, macOS | `ps -o rss`, 2026-09-19 |
| RAM, resident, fresh test chain | 65.9 MiB idle; 312.8 MiB after verifying one deploy | `ps -o rss` on a local one-validator chain, test profile |
| disk | 10 GB at height 62 276; 14 GB at height about 86 425 (node A, chain 12) | `deploy/README.md` (v0.3 update, step 4); `du -sh`, 2026-09-19 |
| disk, full blocks | about 170 GB per day if every block were full (4 MiB per block, chains ≤ 12; chain 18's block cap is 20 MiB) | `docs/block-space.md` |
| disk, pruning validator | block tables 3.3–4.4 GB with one day kept (≤ 65.5k blocks), where they were 19 GB unpruned: chain 14, 18 validators, 2026-09-25. Not re-measured with chain 18's 26-signature certificates | `AGENTS.md`, "v0.5.7" |
| disk, idle growth, archive | about 60 KB a block (the certificate inside the header), ≈ 3.6 GB/day at 1.4 s blocks: chain 14, 18 validators. Not re-measured on chain 18 | `AGENTS.md`, "v0.5.5" |
| startup | about 4 minutes: the quick chain verification took 239 s at 59 183 blocks before the RPC opened (chain 12, unpruned). A pruned node's startup check is structural, not a replay | `deploy/README.md` (v0.3 update, step 2); `AGENTS.md`, "v0.5.7" |
| bundle verify | 838 ms cold, about 16 ms warm | `docs/superpowers/specs/2026-09-15-block-aggregation.md` §1 |
| call verify | about 233 ms first (uncached) verify at tier 10, production profile (constraint set 5) | `docs/confidential.md` |
| network | TCP 30303 inbound on public nodes | `docs/deploy.md` |
| block apply, 2 000 bundles, 80 M nullifiers | 56.1 ms at block 10 000 (incremental nullifier root on; the replica's apply on a clone of the tip) | this page §7 |

Between those two disk readings the chain added about 24 000 blocks, most of them empty, and the
data dir grew by about 4 GB. Plan disk from the chain's age and load, not from the genesis size.

### 2.2 DigitalOcean sizes in use

The size table was read on 2026-09-19, when the fleet was 16 droplets and a laptop on chain 13. The
fleet on chain 18 is 26 validators: the 18 nodes of `deploy/nodes.env` (`NODE_A` … `NODE_MEM1`; A
moved from the laptop to a droplet on 2026-09-27), the two archives (obs1 and rand-archive-2) and
the six guardian hosts. The sizes of the nodes added since 2026-09-19 are not recorded in this
repository, and whether mkc1 and mem1 were resized is not recorded here either.

| size | nodes | status (as read 2026-09-19, chain 13) |
|---|---|---|
| `s-1vcpu-2gb` | ams3, nyc1, nyc2, sfo2 (validators) | running |
| `s-2vcpu-2gb` | part of the rest of the fleet (the per-node sizes are not recorded in `deploy/`) | running |
| `s5-1vcpu-2gb-30gb` | mkc1, mem1 (validators) | running. Their 29 GB disks were full at the chain-13 cut-over; the dead chain-11 data dirs (7 GB) were deleted, leaving 7 GB free. **They need a resize.** |
| 4 vCPU, 8 GB | E (validator, explorer, build host) | builds the Linux binaries: 4 min 17 s for `4504a03` |

Sources: `deploy/nodes.env`, `deploy/README.md`.

Rules that follow from these numbers:

- **2 GB of RAM runs a validator** on this chain today. The fleet's `s-1vcpu-2gb` droplets do it.
- **Disk, not RAM, is the limit.** Keep at least 20 GB free for builds (`docs/block-space.md` §5)
  and delete a retired chain's data dir after a cut-over (`deploy/retire-chain-dirs.sh`). A
  validator runs `--prune-history 24h`; a node refuses to start under 1 GB free and
  `rand_getHealth` answers `disk_low` under 4 GB (`docs/deploy.md`, "Disk guard"). Chain 14
  stalled on full 48 GB disks on 2026-09-24.
- **Do not build on a 2 GB droplet.** Build once on the 8 GB build host and copy the binaries
  (`deploy/update-droplet.sh`, `deploy/cutover-droplet.sh`). Copying 36 MB per node from a laptop
  uplink takes minutes each; droplet-to-droplet takes under a minute for all 15.
- **An aggregation chain adds a start-up cost.** Each node builds the rVM verifier key once:
  13.0–13.4 s at the test profile (2^19). The production figure at 2^21 is an estimate of about
  30–70 s. The production key build and its memory are not measured yet; the bound stays the
  30–70 s estimate.

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
install -d -m 700 /root/keys
test -e /root/keys/node-<name>.key.json || rand-node keygen --out /root/keys/node-<name>.key.json
rand-node address --key /root/keys/node-<name>.key.json   # address, public key, peer id
rand-node init --datadir /root/data-<name>-<genesis8> --genesis /root/fullnode/deploy/genesis-chain<N>.json
```

**The key goes in `/root/keys`, never under `/root/fullnode`.** `deploy/rebuild-vps.sh` and
`deploy/push-to-vps.sh` rsync `/root/fullnode` with `--delete` from a `git archive` of the commit,
which holds no key file: a key kept in that tree is deleted by the next rebuild and the unit then
fails to restart (audit v6, OPS-8; until 2026-09-30 this page and `deploy/vps-setup.sh` said
`/root/fullnode/deploy/`). The fleet has kept its keys in `/root/keys/node-<name>.key.json` since
the chain-14 cut. `keygen` overwrites an existing file, hence the `test -e`. Back the key up off
the host before bonding it.

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
ExecStart=/usr/local/bin/rand-node run --datadir /root/data-<name>-<genesis8> --key /root/keys/node-<name>.key.json --validator --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 --no-mdns --bootstrap <multiaddr> --bootstrap <multiaddr>
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
| cut over to a new chain | a per-chain fleet script (chain 18: `deploy/cutover-fleet-chain18.sh`, all-stop/all-start), under the rules of `docs/deploy.md`, "Cut policy" | `docs/deploy.md` |
| verify the stored chain | `rand-node verify --datadir <dir> --mode full` (stop the service first) | `docs/deploy.md` |
| laptop validator behind NAT | `deploy/run-a.sh` — retired 2026-09-27: validator A runs on a droplet and the script refuses to start a second copy of its key | `deploy/run-a.sh` |

Keep `--block-interval-ms` at 1000 or slower. A bundle proof takes about 100 s and its anchor is
valid for 256 blocks (`docs/cli.md`).

## 3. Wallet

A wallet proves locally. Its hardware sets how fast a user can send or call. On chain 17 and 18 a
send makes two proofs: the bundle proof (guest v3, tier 14; 102 s locally on the laptop, test
profile) and the auth proof (tier 10; 6.4–7.4 s), about 1.49 MB + 1.36 MB at the production
profile (`AGENTS.md`, "v0.6.3", measured 2026-09-29). The table below predates that.

| proof | tier | time | peak memory |
|---|---|---|---|
| bundle (every transfer, deploy and call) | 14 | 92.2 s, 94.3 s and 96.0 s measured (production, chain 13, laptop); 97.0 s measured (test profile) | 5.74 GB for one `rand call` (tier-10 call plus tier-14 bundle), test profile. Production: the bundle alone is not measured yet; one whole production `rand call` (tier-16 call plus tier-14 bundle) peaked at 22.9 GB RSS |
| a call at tier 16 (ERC-20 `approve`, production) | 16 | 388.7 s for the call proof; 622.8 s for the whole `rand call` (chain 13, 48 GB M-series laptop) | 22.9 GB peak RSS, whole `rand call` |
| a call at tier 10 | 10 | 6.0 s measured (test profile); 6.05 s for `fib` (production, constraint set 5) | included above |
| a call at tier 18 or 20 | 18, 20 | see §5 | see §5 |

The test-profile row is `/usr/bin/time -l rand call …` on this laptop, 2026-09-19
([`guests.md`](guests.md#46-call-it)). The production rows are the deploys and the call made on
the live chain 13 on 2026-09-19 ([`translators.md`](translators.md) §4.6, §4.6.1, §5.4).

A wallet that cannot hold that peak can hand the bundle proof to a delegated prover it owns
([`docs/prover.md`](prover.md)). The prover needs the same 5.74 GB per proof it runs at once, plus
1 GiB of headroom: `rand-prover run` (and `rand-node run --prover`) refuses to start unless
`5.74 GB × --max-parallel + 1 GiB` of memory is available.

## 4. Aggregator

An aggregator proves one rVM STARK over N bundle proofs and submits it for a sealing window. It
needs only an RPC endpoint and a registered aggregator key. It runs only on a chain whose genesis
carries an `aggregation` section; none does today.

Measured 2026-09-30/10-01 on a 64-vCPU, 503 GB droplet (constraint set 8, circuits `feat/issue-45`
`d38d6cf`, peak RSS from `/usr/bin/time -v`; issue #45). Every peak is 4–8× what earlier docs
derived from the trace sizes.

| aggregate | tier | cpu rows | prove | verify | proof | peak RSS |
|---|---|---|---|---|---|---|
| test profile, N=1 | 19 | 462 262 | 2 034.6 s (the whole aggregate test binary) | — | 334 778 B | **94.5 GB** |
| test profile, N=2 | 20 | 924 115 | 3 983.5 s | — | 355 577 B | **183.7 GB** |
| test profile, N=3 | 21 | 1 385 968 | 4 807.8 s | 24.75 s | 347 800 B | **221.0 GB** |
| production, N=1 | 21 | 2 047 542 | 8 131.3 s | 99.36 s | 1 563 226 B | **376.9 GB** |
| production, N=2 | 22 | 4 094 675 (2.4 % under 2²²) | not attempted | | | ~750 GB estimated |
| production, N=3 | 23 | 6 141 808 | not attempted | | | over 1 TB estimated |

What it means for hardware:

- **A production aggregator needed a ≥ 512 GB host** for N = 1 at constraint set 8, the smallest
  useful aggregate (measured); ≈ 240 GB projected after the phase-2 row cuts and ≈ 170–175 GB
  after the quotient layout, so a ≥ 256 GB host (below), a projection until the tier-20 proof runs.
  The earlier "≥ 64 GB" class came from a 48.6 GB oracle that the measurement disproved.
- **N ≥ 2 at production does not fit any single CPU host** on offer, and the GPU backend does not
  change that: the traces live in host memory. Aggregating more than one proof needs a design
  change (smaller inner proofs, a different recursion layout, or trace streaming), tracked in
  issue #119 with the remaining soundness item.
- These runs proved single-threaded (the recursion crate had no `parallel` feature before circuits `75b7893`), so the 64 vCPUs ran several proofs side by side; the walls above are single-core walls.

Sources: `circuits/recursion/docs/02-aggregate.md` ("Constraint set 8, proved"), the #45 closing
comment, `~/rand-agg-512-results/` on the operator's laptop (all 24 step logs).

**Phase 2 row cuts (circuits `75b7893`, 2026-10-04; `recursion/docs/04-phase2-row-cuts.md`).**
Three cuts to the inner verifier (hint rows into the sponge buffers, `HINTN`, `COMPRESS`) take the
production inner proof from 2 047 268 to 893 606 cpu rows, so every rung above lands one tier
lower. Nothing in this table is a measured proof yet: the memory column weights the
constraint-set-8 peaks by committed cells, calibrated on a tier-19 live-heap trace
(`tests/memprofile.rs`, 78.7 GB live when the 48 GB laptop killed it), and the tier-20 production
proof has not run on a big host.

| aggregate | tier (was) | cpu rows | projected peak | after the quotient layout (below) | measured anchor (constraint set 8) |
|---|---|---|---|---|---|
| test profile, N=1 | 18 (19) | 231 224 | ≈ 50 GB | **33.27 GB peak live, measured** (the tier-18 twin, 230 950 rows) | 94.5 GB at tier 19 |
| test profile, N=2 | 19 (20) | 462 039 | — | — | 183.7 GB at tier 20 |
| test profile, N=3 | 20 (21) | 692 854 | — | — | 221.0 GB at tier 21 |
| production, N=1 | **20** (21) | 893 880 | ≈ 240 GB | **≈ 170–175 GB**, projected | 376.9 GB at tier 21 |
| production, N=2 | 21 (22) | 1 787 351 | ≈ 475 GB | — | — |
| production, N=4 | 22 (23) | 3 574 293 | ≈ 950 GB | — | — |

So the production N = 1 aggregator is a **≥ 256 GB host** (`m-32vcpu-256gb` is DigitalOcean's
largest memory droplet), down from ≥ 512 GB — tight after the phase-2 cuts, with room after the
quotient layout (below); N ≥ 2 still fits no single host. The rest is structural — the register
table, the blowup — and is listed in
`docs/compute-optimization.md` §4.1. The rVM also has Plonky3's `parallel` feature now (the same
two patched crates the prover uses): 4.7× on 16 threads at tier 16 with the peak heap unchanged,
so threads are a wall-time lever only. The macOS RSS figures the September docs quoted (15–30 GB)
measured compressed memory, not the working set; only Linux peaks count here. The node admits
tiers {20, 21, 22} production and {18, 19, 20} test (`agg_executor.rs`).

**Quotient layout (circuits `5ff7676`, 2026-10-05; `recursion/docs/05-quotient-layout.md`).** The
rVM commits each instance's quotient chunks as one matrix (a vendored `p3-batch-stark` fork,
`vendor/p3-batch-stark`; the RV32 wallet machine keeps upstream's per-chunk layout). Measured on
the 48 GB laptop (peak live heap, the allocator's count, not RSS): the tier-16 synthetic's peak
9.09 → 6.41 GB (−29 %), prove 40.7 → 32.9 s, proof −19 %; the tier-18 exit twin — the test-profile
N=1 aggregate's shape, 230 950 rows — proved at **33.27 GB peak live** in 185 s on 16 threads, so a
**64 GB host runs the test-profile N=1 aggregate with margin** (measured; it replaces the ≈ 50 GB
projection above). The production N=1 projection moves ≈ 240 → **≈ 170–175 GB** (the tier-16
ratio ×0.705 and the derived tier-18 quotient-phase ratio ×0.73 applied to 240 GB): a projection
until the tier-20 production proof runs on a ≥ 256 GB host. The aggregate program digest and the
admission vectors did not move.

Setup, on a chain with an `aggregation` section (`docs/cli.md`, `docs/deploy.md`):

```bash
rand-node aggregator register --key agg.key.json --bond <RAND> --payout <rand1…> --rpc <URL>
# the printed registration is burned in through a wallet's bundle; then:
rand-node aggregate --key agg.key.json --rpc <URL> --watch
```

## 5. Prover memory per tier

**The prover uses every core since the `parallel` build** (2026-10-01: `p3-maybe-rayon`'s
`parallel` feature, on with the prover crate's `service` and in the CLI). Before it the prover
was single-threaded — a 16-vCPU box ran it at 99 % of one core — and a production tier-14 bundle
took 217–237 s on an 8-vCPU DigitalOcean c-8; with it, 68.6–72.9 s on the same class of droplet
at 5.88 GB peak (`deploy/prover/README.md`). Memory per proof is unchanged in kind, and the
figures below were measured on the single-core build.

| tier | cycles (up to) | workload measured | memory measured | time measured | final |
|---|---:|---|---|---|---|
| 10 | 1 023 | `fib` (production, constraint set 5) | not recorded | 6.05 s | — |
| 14 | 16 383 | the bundle (wallet, test profile) | 5.74 GB whole `rand call` | 97.0 s | production: 92.2–96.0 s and 1 418 406–1 420 423-byte proofs (chain 13, laptop); memory of the bundle alone not measured yet |
| 16 | 65 535 | ERC-20 `approve`, translated | test profile, DigitalOcean: 21.7 GB. Production, laptop: 22.9 GB peak RSS for the whole `rand call` | test profile: 786.7 s (13.1 min). Production: 388.7 s | production: proved and committed on chain 13, 3 412 405-byte proof |
| 18 | 262 143 | ERC-20, about 66 k–162 k cycles | OOM-killed on a 48 GB laptop at 24.7 GB. On a 64 GB droplet: above 47 GB at 25 min, still running | killed after 1 016 s on the laptop | translated `transfer`: 85.0 GB, 3 230.5 s (53.8 min), 811 600 B proof. Interpreter `evm.bin`: 85.5 GB, 3 143.3 s (52.4 min), 805 108 B proof. Verify: 101.4 s (droplet), 50.2 s at 3.66 GB RSS (laptop). Measured on m-16vcpu-128gb, 2026-09-19 |
| 19 (rVM) | — | rVM aggregate, N=1, test profile (constraint set 8) | **94.5 GB peak RSS** (Linux, 503 GB droplet). The "about 30 GB" quoted before was macOS RSS, which excludes compressed pages | 1568.2 s (loaded shared box); 2 034.6 s (droplet, whole test binary) | after the phase-2 row cuts the same proof is tier 18; after the quotient layout it proved at 33.27 GB peak live heap on the 48 GB laptop (§4) |
| 20 | 1 048 575 | SPL Token, about 700 k–770 k cycles | stopped on a 48 GB laptop at about 31 GB (30.77 GB peak footprint); OOM-killed on a 64 GB droplet at 65.1 GB | 10 m 41 s on the droplet before the kill | not yet proven. Extrapolated from the measured tier-16/18 scaling (memory about ×3.9, time about ×4.1 per +2 tiers): about 330 GB and about 3.6 h, more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) |
| 21 (rVM) | — | rVM aggregate, N=1, production (constraint set 8) | **376.9 GB peak RSS** (the 48.6 GB oracle counted one of four memory terms) | 8 131.3 s | §4; after the phase-2 row cuts the same proof is tier 20, projected ≈ 240 GB (≈ 170–175 GB after the quotient layout), not yet run |

The cycle column is `2^t − 1` for the RV32 zkVM (`docs/confidential.md`). The rVM (the
recursion machine) has its own tiers, sized in rows (`docs/zkvm-m4-m5-progress.md`). The tier-18 and tier-20 laptop runs used
`FriProfile::Test` (circuits `evm2rv/README.md`, `sbpf2rv/README.md`).

### DigitalOcean sizes for proving

| workload | size | status |
|---|---|---|
| a tier-14 bundle (any wallet) | any machine with more than 5.74 GB free (test profile) | measured |
| tier 18 | a 128 GB droplet (size slug `m-16vcpu-128gb`, Memory-Optimized, 16 vCPU). OOM-killed on a 64 GB droplet (`g-16vcpu-64gb`) at 65.1 GB after 32 min | measured: 85.0 GB (translated) / 85.5 GB (interpreted) peak RSS, 3 230.5 s / 3 143.3 s |
| tier 20 | more than 64 GB. OOM-killed on a 64 GB droplet (`g-16vcpu-64gb`) at 65.1 GB after 10 m 41 s | not yet proven; extrapolated at about 330 GB and about 3.6 h (see §5), more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) |
| aggregate N=1, production | a 503 GB droplet at constraint set 8 (376.9 GB peak); ≥ 256 GB projected after the phase-2 row cuts (`m-32vcpu-256gb`; ≈ 170–175 GB projected after the quotient layout, so with room) | measured at constraint set 8 (§4); the tier-20 proof not yet run |

No proof above tier 14 is part of normal chain operation today. Tier 18 and 20 matter for calls to
the translated ERC-20 and SPL Token programs ([`translators.md`](translators.md#7-what-works-on-chain-today)).

## 6. Threads and the GPU

Measured 2026-10-01 (the audit v7 addendum's proving slide): one production tier-14 bundle proof
on an Apple M4 Max, the `parallel` build, threads set with `RAYON_NUM_THREADS`.

| threads | wall time | speed-up | parallel efficiency |
|---:|---:|---:|---:|
| 1 | 107.5 s | 1.0× | 100 % |
| 4 | 30.7 s | 3.5× | 87 % |
| 8 | 17.1 s | 6.3× | 78 % |
| 16 | 13.9 s | 7.7× | about 48 % |

About 80 % of the time is Poseidon2 Merkle hashing (170 million permutations a proof); the FFTs
are most of the rest. The CUDA backend (`rand-zkvm-cuda`) moves the Merkle hashing and the FFTs,
87.4 % of the CPU time, to the device. The rVM (the aggregate prover) has the same `parallel`
feature since circuits `75b7893`: 4.7× on 16 threads at tier 16 (171 s → 36 s), peak heap
unchanged (§4).

**What the binaries do with it** (`randprotocol_prover::proving`, the one place all three
decide):

- `rand` proves one bundle with a person waiting, so it takes **every core** by default; the
  eighth-to-sixteenth threads still cut the wall time by a fifth.
- `rand-prover run` and `rand-node run --prover` share their host (the pool's members run
  beside a validator) and prove jobs back to back, so they take **the cores minus one, at most
  8** — the eighth thread returns 78 % of itself, the sixteenth about half — and a bigger host
  serves more jobs at once (`--max-parallel`) rather than one job on more threads. A c-8 member
  gets 7, which is what `deploy/prover/install-host.sh` has always set.
- `--threads N` (`--prover-threads` on the node) overrides either; so does `RAYON_NUM_THREADS`
  when no flag is given. `0`, or an env value that is not a count, is refused, never defaulted.
- **The GPU is used by default when it can be.** A build with the CUDA backend (`--features
  cuda`) proves on a visible NVIDIA GPU (a `/dev/nvidia*` node, `/proc/driver/nvidia`, or
  `nvidia-smi` on the `PATH`) without being asked, and says so once; `--cpu` (`--prover-cpu`)
  keeps it on the CPU. `--cuda` still means the GPU and nothing else — no CPU fallback, a device
  that will not open is an error. A build without the backend proves on the CPU and, when a GPU
  is visible, prints once that it is going unused and how to rebuild. The release binaries are
  built without the backend (a CUDA 13 toolkit is not on the release runner), so a GPU host
  builds its own `rand`/`rand-prover` with `--features cuda`.

## 7. The hot path at synthetic load (2026-10-05)

Measured on the `feat/hot-path` branch with `rand-node bench apply`: one validator on the
`StubExecutor`, 2 000 bundles a block (the block cap), each bundle four nullifier and four
commitment slots (two real, two dummy), and a bundle inserts all four, so 8 000 nullifiers and
16 000 commitments a block, through the real HotStuff propose, apply and commit path. Ten thousand
blocks therefore hold 80 M nullifiers, twice the 40 M that `docs/compute-optimization.md` §3.6
counted from two a bundle, so the acceptance is stricter than the page it answers. `apply_ms` is
the replica's `apply_block_for_sync` of the proposed block on a clone of the pre-block tip, which
is what §3.6 bounds; `propose_ms` is the leader's whole `propose` call, which itself contains an
apply and a state root; `root_ms` is one `state_root`; `clone_ms` is one ledger clone. The host is
an Apple M4 Max, 16 cores, 48 GB (`sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize`).

Baseline, unmodified code, 100 blocks (`/tmp/bench-baseline-100.txt`). The 300-block baseline run
was killed after 20 minutes without a usable row, so the 100-block table is the baseline.

```
 height  propose_ms  apply_ms  root_ms  clone_ms  nullifiers   rss_mb  peak_rss_mb
     20      4276.2      81.2    27.78      1.21      160000      234          234
     40      9886.1     117.7    56.73      2.45      320000      439          484
     60     16008.4     152.3    84.84      3.73      480000      646          646
     80     29776.8     227.4   172.00      5.02      640000      818          818
    100     27077.2     221.4   143.26      6.37      800000     1002         1002
verdict: apply 221.4 ms at block 100 (800000 nullifiers) — within the 100000 ms budget
```

After the shared set, the proposer without a clone per candidate and replay on failure, 300 blocks
(`/tmp/bench-sharedset-300.txt`):

```
 height  propose_ms  apply_ms  root_ms  clone_ms  nullifiers   rss_mb  peak_rss_mb
     50       275.4     129.5    73.90      0.39      400000      619          626
    100       448.3     207.1   146.01      0.39      800000     1026         1217
    150       572.6     286.1   225.90      0.42     1200000      928         1707
    200       730.0     346.2   293.99      0.48     1600000     1954         2004
    250      1327.8     445.1   375.99      0.44     2000000     1546         2321
    300      1026.4     495.0   441.53      0.48     2400000     1682         2655
verdict: apply 495.0 ms at block 300 (2400000 nullifiers) — within the 100000 ms budget
```

After the incremental nullifier root, `--incremental-nullifier-root`, 300 blocks
(`/tmp/bench-mmr-300.txt`):

```
 height  propose_ms  apply_ms  root_ms  clone_ms  nullifiers   rss_mb  peak_rss_mb
     50       123.0      54.4     0.00      0.25      400000      116          116
    100       126.2      54.3     0.00      0.26      800000      160          160
    150       128.8      54.9     0.00      0.25     1200000      205          205
    200       137.7      56.1     0.00      0.27     1600000      250          250
    250       132.7      55.5     0.00      0.28     2000000      294          294
    300       134.8      55.5     0.00      0.29     2400000      339          339
verdict: apply 55.5 ms at block 300 (2400000 nullifiers) — within the 100000 ms budget
```

The acceptance run, `rand-node bench apply --blocks 10000 --report-every 500
--incremental-nullifier-root` (`/tmp/bench-final-10000.txt`):

```
 height  propose_ms  apply_ms  root_ms  clone_ms  nullifiers   rss_mb  peak_rss_mb
    500       132.7      54.8     0.00      0.27     4000000      516          516
   1000       138.8      55.3     0.00      0.27     8000000      961          961
   1500       144.8      55.4     0.00      0.28    12000000     1405         1405
   2000       146.9      55.2     0.00      0.25    16000000     1849         1849
   2500       147.6      55.3     0.00      0.27    20000000     2293         2293
   3000       151.2      55.9     0.00      0.27    24000000     2737         2737
   3500       151.4      55.5     0.00      0.27    28000000     3182         3182
   4000       150.9      55.9     0.00      0.28    32000000     3626         3626
   4500       154.4      56.3     0.00      0.29    36000000     4071         4071
   5000       155.1      55.4     0.00      0.27    40000000     4514         4514
   5500       157.2      56.5     0.00      0.29    44000000     4958         4958
   6000       156.5      55.5     0.00      0.27    48000000     5403         5403
   6500       157.6      56.9     0.00      0.29    52000000     5847         5847
   7000       159.9      56.0     0.00      0.29    56000000     6291         6291
   7500       160.2      56.0     0.00      0.28    60000000     6736         6736
   8000       166.3      56.7     0.00      0.27    64000000     7180         7180
   8500       161.2      56.6     0.00      0.28    68000000     7624         7624
   9000       161.9      56.8     0.00      0.27    72000000     8067         8067
   9500       160.8      56.0     0.00      0.28    76000000     8510         8510
  10000       162.4      56.1     0.00      0.28    80000000     8954         8954
verdict: apply 56.1 ms at block 10000 (80000000 nullifiers) — within the 300 ms budget
exit 0
```

The flag-off comparison, same code, `rand-node bench apply --blocks 600 --report-every 100
--fail-over-ms 100000` (`/tmp/bench-final-flagoff-600.txt`). It stops at 600 blocks because the
sorted nullifier root is `O(n)` and runs three times a block, so the run is quadratic in blocks
and 2 000 blocks would take over two hours; the 300-block shared-set table above is the same code
and also stands.

```
 height  propose_ms  apply_ms  root_ms  clone_ms  nullifiers   rss_mb  peak_rss_mb
    100       404.1     189.5   139.54      0.30      800000     1375         1383
    200       686.4     330.4   284.87      0.34     1600000     1334         2275
    300       968.4     469.0   416.30      0.39     2400000     1993         2600
    400      1251.4     606.7   553.61      0.40     3200000     2670         3188
    500      1578.3     769.6   722.73      0.36     4000000     1954         3569
    600      1878.9     915.1   861.71      0.33     4800000     2837         3722
verdict: apply 915.1 ms at block 600 (4800000 nullifiers) — within the 100000 ms budget
exit 0
```

Which change moved which column. The shared set took `clone_ms` from 1.21 ms at 160 000
nullifiers and 6.37 ms at 800 000, growing with the set, to a flat 0.39 to 0.48 ms (0.25 to 0.29 ms
with the incremental root on), and with the
proposer change took `propose_ms` from 4 276 ms at height 20 and 27 077 ms at height 100 to
275.4 ms at height 50 and 1 026.4 ms at height 300. What it left was the sorted-order nullifier
root: `root_ms` 73.90 ms at height 50 and 441.53 ms at height 300, and `apply_ms` 129.5 to 495.0 ms
with it, linear in the set (915.1 ms at 600 blocks in the flag-off table). The incremental root took `root_ms` to 0.00 at every row
and `apply_ms` to 54.4 ms at height 50 and 55.5 ms at height 300, flat, and held it at 56.1 ms at
block 10 000 with 80 M nullifiers; `propose_ms` rises slowly, 132.7 ms at block 500 to 162.4 ms at
block 10 000, which is the leader's own apply, root and the replay bookkeeping, not a root term.

Memory does not meet the spec's original criterion, and cannot while the sets live in memory.
That criterion (the last 1 000 blocks within 5 % of the first 1 000 after block 1 000) asks for
a flat resident size, and the run went from 961 MB at block 1 000 to 8 954 MB at block 10 000,
because every block adds 8 000 nullifiers and 16 000 commitments that the validator keeps. The
criterion met is the amended one (spec 2026-10-05 §1, amendment 6 in §0): resident memory linear
in the entries, at a constant 117 to 121 bytes per nullifier, with no term in the speculative
tree or in height. From the `rss_mb` and `nullifiers` columns,
taking `rss_mb` as MiB, the resident size per nullifier is 121.2 bytes at row 2 000 (1 849 MB,
16 000 000), 118.3 bytes at row 5 000 (4 514 MB, 40 000 000) and 117.4 bytes at row 10 000
(8 954 MB, 80 000 000). That figure carries both sets (each block also adds twice as many
commitments as nullifiers), the tree's leaf set and the range peaks, and it falls slightly with
height as fixed costs amortise; there is no term in height beyond the entries themselves. The
sets are in memory by design: 80 M nullifiers cost about 9 GB here, which a validator must budget.

Acceptance (`docs/compute-optimization.md` §3.6): passed on apply time and set size, and on
memory under the amended criterion above. Exit 0, `apply_ms` 56.1 against the 300 ms bound at
block 10 000, 80 000 000 nullifiers.

## 8. Compact proposals on the wire (2026-10-08)

Since the compact-blocks change (spec `docs/superpowers/specs/2026-10-08-compact-blocks-design.md`
§1) a leader publishes a proposal as its header, its signature and its transaction hashes
(`GossipMessage::CompactProposal`, bincode tag 4); the bodies cross the network once, on the
transaction topic, and a replica rebuilds the block from its pool and recent cache, fetching by
hash only what it never saw. Measured on the `feat/compact-blocks` branch, debug build, on an
Apple M4 Max; every number below is printed by the test named beside it.

| quantity | value | source |
|---|---|---|
| largest compact frame, four validators | 15 708 bytes carrying 13 transactions (a second run: 15 804 bytes carrying 16) | `tests/cluster.rs` `a_proposal_frame_carries_hashes_not_bodies`, raw gossipsub frames read by an observer swarm |
| what those bodies cost on the tx topic | 32 mints, 32 frames, 168 096 bytes (5 253 bytes a mint) — so the 13 the largest frame named were about 68 KB of bodies the frame did not carry | the same test |
| fixed part of a compact frame, four justify votes, no hashes | 19 080 bytes | `network::wire::tests::a_compact_proposal_at_26_validators_and_2000_hashes_is_its_header_plus_32_bytes_a_hash` |
| compact frame at 26 justify votes, no hashes | 102 416 bytes | the same unit test |
| compact frame at 26 justify votes and 2 000 hashes (the block cap) | **166 416 bytes** — exactly 2 000 × 32 more than with none | the same unit test (`bincode::serialized_size`) |
| today's full proposal on chain 20 | up to the 20 MiB block cap: seven transfers at ~2.85 MB each (tier-14 bundle proof ~1.49 MB, tier-10 auth proof ~1.36 MB, envelopes) | `docs/compute-optimization.md` §1.1 |
| bodies a late validator fetched by hash | 8 of 8 (`compact_fetched` = 8 on its `rand_status`; 0 on the two validators that had them) in each of three runs | `tests/cluster.rs` `a_late_validator_fetches_bodies_it_never_saw` |

Reading the table. In the four-validator cluster the justify carried three votes (a quorum), so
the observed fixed part (15 708 − 13 × 32 = 15 292 bytes) is exactly one vote (3 788 bytes) under the unit test’s
four-vote 19 080; the two unit-test rows put one vote at (102 416 − 19 080) / 22 = 3 788 bytes.
At 26 validators a quorum is 18, so a QC that carries exactly a quorum makes the cap-size frame
about 166 416 − 8 × 3 788 = 136 112 bytes; the 166 416 in the table is the bound with every vote
in. Either way a proposal on chain 20 falls from up to 20 MiB to under 170 KB on the consensus
topic.

The late-validator test is the fetch path end to end: two of a four-validator genesis run (no
quorum, so nothing commits), eight faucet mints are pooled and gossiped between them, and a third
validator joins only after gossipsub's 2.5 s history window has passed, so it never sees the
bodies. Its arrival makes the quorum; the first proposal that names the mints parks on it, the
eight bodies are fetched from the leader's peer by hash (`SyncRequest::Transactions`), and it
votes and commits the same chain (`assert_chains_equal`). Fetch latency was not separately
timed: the whole test, three node starts included, runs in 11 to 14 s.
