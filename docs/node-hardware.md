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
| startup | a restart of the same build: seconds (one ledger load and the head's state root; the startup checkpoint). The first start of a new build: the full check, which took 239 s at 59 183 blocks (chain 12, unpruned) and up to 30 min at 259 k blocks on 48 GB droplets. A pruned node's check is structural, not a replay | `deploy/README.md` (v0.3 update, step 2); `AGENTS.md`, "v0.5.7" |
| transfer verify (bundle + auth proof, admission) | v0.8.3: **62 ms warm, 1.56 s cold** (p50; the cold one builds both verifier keys). v0.8.0–v0.8.2: 73 ms warm, 1.6 s cold. Warm stages: bundle STARK ~31 ms, auth STARK ~27 ms, header/digest/canonical checks ~4 ms (~10 ms before v0.8.3, when each check re-decoded the 1.4–1.5 MB proofs). Plus the `rand_sendTransaction` body decode: 1.2 ms (18.5 ms before v0.8.3). Apple M4 Max, n = 38 chain-21 transactions (2.87–2.90 MB), 2026-10-28. The earlier "838 ms cold, about 16 ms warm" was a tier-12 research proof | fullnode issue #152; `nettest/data/verify_bench.jsonl` |
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

- **4 GB of RAM is the validator minimum** (issue #157). A 2 GB droplet runs a validator at rest
  (~1.4 GB resident), but the 2026-10-27 overnight run OOM-killed the 2 GB validators 24 times in
  8 h, each after a burst of eight ~2.9 MB transactions; the one 4 GB node in a burst survived
  it. v0.8.3 bounds admission memory (`--admission-budget-mb`, 1/16 of RAM by default and never
  under one largest submission: ~129 MiB on a 2 GB host on chain 21; a request body counts three
  times its length, the heap it is measured to hold — OPS-602, `tests/burst_memory.rs`), and every setup and roll (`deploy/vps-setup.sh`, `deploy/update-droplet.sh`,
  `deploy/roll-all.sh`) writes the drop-in `rand-node.service.d/50-limits.conf` from
  `deploy/lib/unit-limits.sh` (PROC-601) with `MemoryHigh=85%`, so the kernel reclaims and
  throttles before it kills. A 2 GB host that has
  to stay on needs both, plus swap (the fleet's have 1 GB). `deploy/probe-memory.sh` records each
  host's RAM, swap, `MemoryHigh`, resident memory and budget, and names the hosts under the
  minimum, without swap, or without `MemoryHigh`.
- **A perps state-proof key build is the largest single allocation a node makes** (CON-601):
  ~1 GiB at tier 16, ~4 GiB at tier 18 (3.56 GB resident measured), ~16 GiB at tier 20. Chain 21
  allows tier 18, which neither a 2 GB nor a 4 GB host can build. The node caps the tier it
  builds keys for outside a block at the highest one fitting three quarters of the memory left
  (the host's RAM or its cgroup's `memory.high`/`memory.max` if lower, less the node's resident
  size, re-measured every minute and held at 16 or lower for the first minute after a start:
  CON-701; 16 needs ~1.43 GB left and 18 ~5.73 GB, so an 8 GB host whose node sits at 5 GB
  under `MemoryHigh=85%` is 16, a 4 GB host is 16 while its node stays under ~1.9 GB, and **a
  2 GB host under `MemoryHigh=85%` is 14 or 12 at rest, not 16** — CON-751;
  `--max-state-proof-tier` overrides it), so a proof above the cap is not pooled, relayed or
  proposed there. On the default a 2 GB validator does not pool or relay a cold tier-16 proof
  either; pass `--max-state-proof-tier 16` to have it do so, on swap. A block that carries one still makes every validator build the key;
  until chain 22 pins the engine shape, a validator that must survive that needs 8 GB
  (`docs/perps.md`, "the node's tier cap").
- **Disk, not RAM, is the limit.** Keep at least 20 GB free for builds (`docs/block-space.md` §5)
  and delete a retired chain's data dir after a cut-over (`deploy/retire-chain-dirs.sh`). A
  validator runs `--prune-history 24h`; a node refuses to start under 1 GB free and
  `rand_getHealth` answers `disk_low` under 4 GB (`docs/deploy.md`, "Disk guard"). Chain 14
  stalled on full 48 GB disks on 2026-09-24. Under 16 GB (16 × the minimum) the node logs a
  `disk_warn` once an hour and `rand_getHealth` carries `"disk_warn": true` beside its status word,
  with the measured `disk_bytes_per_day` and `disk_days_left` to `disk_low` (audit v12, OPS-601).
- **Size an archive for its growth (OPS-601).** Every header carries its parent's QC: at least 18
  Dilithium2 votes of 3 788 bytes, ~68 KB of certificate, ~72 KB on disk per empty block. At
  chain 21's ~1.15 s blocks that is ~75 000 blocks and **5.1–5.4 GB a day unpruned** (5.8 GB/day
  measured on the public RPC's upstream archive after the 1 Nov roll), ~160 GB a month. An
  unpruned archive therefore needs: today's data dir + 20 GB build headroom + at least 30 days
  of growth (~160 GB) before its next resize, and a monitor on `disk_warn` / `disk_days_left`
  that pages at 3 days. The arithmetic for a disk of `D` GB with `U` GB used is
  `(D - U - 4) / 5.4` days to `disk_low`. A node that does not have to serve history runs
  `--prune-history` (validators 24h, observers 7d) and stays flat. The three archive roles are the
  only unpruned hosts; losing one costs no quorum, but the public RPC's upstream archive going
  full takes the public RPC off the chain.
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
deploy/rebuild-vps.sh 203.0.113.33      # rsync this checkout, cargo build --release, restart E
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
([`docs/prover.md`](prover.md)). The prover needs the same 6.2 GB per proof it runs at once, plus
1 GiB of headroom: `rand-prover run` (and `rand-node run --prover`) refuses to start unless
`6.2 GB × --max-parallel + 1 GiB` of memory is available.

## 4. Aggregator

An aggregator proves one rVM STARK over N bundle proofs (or a tree of them) and submits it for a
sealing window. It needs only an RPC endpoint and a registered aggregator key. It runs only on a
chain whose genesis carries an `aggregation` section; none does, and `rand-node` refuses to start
on one (`node::check_build_runs_genesis`; [`aggregation.md`](aggregation.md#before-enabling-aggregation)).

**The state on 2026-11-18 (issue #119).** No production-profile aggregate has been proved since
constraint set 8 (2026-09-30). For the build this repository vendors, every production row count
is emulated or counted and every production memory figure is a projection. The constraint-set-8
runs (§4.3) are the only production-scale measurements that exist. The "≥ 512 GB host" they led
to is outdated, since the same aggregate is three rVM tiers lower now, but it is not disproven:
nothing has been run to replace it.

An "rVM tier" in this section is the recursion machine's, sized in rows. It is not the RV32
zkVM's tier of §5, sized in cycles: the 92.9 GiB tier-18 msauth proof of §9 is an RV32 proof and
says nothing about an rVM tier-18 aggregate.

### 4.1 The vendored build: rows, tiers and projected memory

The build is circuits `b3e21d9` (`CIRCUITS_PIN` in `.github/workflows/ci.yml`): constraint set 9,
rVM phase 5, the rVM's own proofs at rate ¼ (92 queries, 24 grinding bits). Its production
aggregate program digest is `792a66d4…a982`, and the node admits rVM tiers {18, 19, 20, 21} at
production and {18, 19, 20} at the test profile (`agg_executor::admitted_tiers`). Circuits `main`
is constraint set 10, which adds 7 rows an inner proof, moves no tier and moves the production
digest to `a3d5c38b…83d3` (circuits `recursion/docs/10-phase5-n2-tier19.md`, "Constraint set
10"). That re-vendor is a chain cut and is not done (issue #166); the numbers here are the
vendored build's.

| production aggregate | cpu rows | rVM tier | the rows are | peak memory |
|---|---:|---:|---|---|
| flat, N = 1 | 235 744 | 18 | emulated | **not measured**; projected ≈ 32–75 GB (below) |
| flat, N = 2 | 471 105 | 19 | emulated | not measured; no projection at this tier |
| flat, N = 3 | 706 466 | 20 | emulated | not measured; no projection at this tier |
| flat, N = 4 | ≈ 941 827 | 20 | arithmetic (235 361 rows a further proof) | not measured; no projection at this tier |
| flat, N = 5, the rVM's ceiling | ≈ 1 177 188 | 21 | arithmetic | not measured; no projection at this tier |
| tree leaf, `rv32n`, L = 2 | 471 105 | 19 | emulated | not measured |
| tree step, `rv32t_leaf` | 508 735 (band 432 420 … 585 040) | 19 (the band's top is tier 20) | emulated | not measured (below) |
| tree root and any deeper level | not known | not known | the fixed-point level needs a proved production depth-2 tree | not measured |

Source: circuits `recursion/docs/10-phase5-n2-tier19.md` §4 and §6. The test profile on the same
build: N = 1 / 2 / 3 at 88 486 / 176 589 / 264 692 rows, tiers 18 / 18 / 19; the test tree's
`rv32t_leaf` step 149 586 rows, tier 18.

**The projection for production N = 1, and the host it asks for.** Three circuits records, oldest
first; none is a measurement:

- `docs/07` §4 (rate ¼, 2026-10-08, N = 1 then at tier 20): ≈ 64–75 GB, "a ≥ 96 GB host".
- `docs/09` §5 (phase 4, 2026-10-11, N = 1 then at tier 19): the cpu-sized terms halve and the
  RAM table does not, so ≈ 32–38 GB is a floor and `docs/07`'s range a ceiling: ≈ 32–75 GB. It
  names no host class ("a measurement for a larger host, not this record's claim").
- `docs/10` §6 (phase 5, 2026-10-12, N = 1 now at tier 18; the newest): no number. "At tier 18
  the cpu table and every term sized by it halve again, while the RAM table does not.
  Production memory stays a projection until a proof runs on a larger host."

So the current projection is **≈ 32–75 GB**, a range computed one tier higher than the proof now
sits, and the host that follows from it is **≥ 96 GB**: the only class a circuits record names,
for the range's top. Both are projections. Of the DigitalOcean sizes this page names, the 128 GB
`m-16vcpu-128gb` is the smallest above it.

**N = 2 to 5.** `docs/07` §4 projected N = 2 at ≈ 122–142 GB (≥ 192 GB), N = 3 at ≈ 168–197 GB
(≥ 256 GB) and N = 4 at ≈ 238–284 GB (≥ 384 GB), at the tiers of that day (21, 21, 22). Those
aggregates are tiers 19, 20 and 20 on the vendored build and no record re-projects them, so this
page gives no host class for N ≥ 2. Production N ≤ 5 is the rVM's ceiling (the reduce chip,
`docs/aggregation.md`): the node refuses a larger aggregate by name.

**The tree.** Two circuits records disagree on the step's tier, and the newer one is right for
this build. `docs/08` §3 and §8 (2026-10-09) put the production leaf and step at tier 21
(1 171 511 and 1 294 577 rows), project a tier-21 proof at ≈ 122–197 GB and name the **256 GB
droplet**, one proving process at a time. `docs/10` §4 (2026-10-12, newer) puts the leaf at
471 105 rows and the step at 508 735, both tier 19, gives no memory figure for them, and still
names "the 256 GB host" for the production tree (§5). So 256 GB is the host class on record for
the tree's production leaf and step; what a tier-19 step needs has not been projected or
measured.

The GPU backend changes none of this: the traces live in host memory. Threads change wall time
only (4.7× on 16 threads at tier 16 with the peak heap unchanged).

### 4.2 The latest measurements (test profile only)

All on the 48 GB laptop, 16 threads. "Peak live heap" is the heap profiler's count
(`tests/memprofile.rs`), which is lower than the process's maximum RSS: the tier-18 test leaf
that read 15.64 GB live read 21.39 GB maximum RSS (circuits `docs/08` §5). macOS RSS alone is
never a memory number here; it excludes compressed pages.

| what was proved | circuits | rows, rVM tier | measured |
|---|---|---|---|
| the exit twin, the test N = 1 aggregate's shape | `d155616` (phase 4, before the MODQ chip of constraint set 9), 2026-10-11 | 104 150, tier 18 | **17.19 GB peak live heap** (16.75 GB at the base `c83b1c7`, 169 366 rows; the +0.44 GB not traced, one run a side) |
| the same twin, at rate ¼ | `2fbd45b`, 2026-10-08 | 169 366, tier 18 | 15.64 GB peak live heap |
| the test N = 2 aggregate | phase 4, 2026-10-11 | 208 571, tier 18 | proved and verified; no heap figure printed |
| the test tree's step and root | the tree branch (`92b750e`), 2026-10-09, before phase 4 | 287 107 and 306 985, tier 19 | **34.35 GB** and **33.21 GB** process maximum RSS |

Not measured on the vendored build (phase 5, `b3e21d9`): the twin, the tier-16 synthetic and the
test N = 2 aggregate are "pending operator run" in circuits `docs/10` §8, and the test tree's
fixtures (steps at tier 18 since phase 4) wait on a regeneration that `docs/10` §5 sizes at
≈ 34 GB. The phase-4 re-proof of the test tree (2026-10-11) recorded no memory figure. What the
measurements do show: a 48 GB machine has run every test-profile aggregate tried on it since
rate ¼, flat and tree.

Sources: circuits `recursion/docs/07-rvm-rate-quarter.md` §3, `08-tree-aggregation.md` §5,
`09-phase4-spans.md` §4.

### 4.3 History: constraint set 8, measured, and the projections since

**Measured at constraint set 8, circuits `feat/issue-45` `d38d6cf`; superseded.** 2026-09-30 and
10-01, a 64-vCPU, 503 GB droplet, peak RSS from `/usr/bin/time -v` (issue #45). These are the
only production-scale proofs ever run. Every peak was 4–8× what earlier docs derived from the
trace sizes, and the runs proved single-threaded (the recursion crate had no `parallel` feature
before circuits `75b7893`), so the walls are single-core walls.

| aggregate | tier | cpu rows | prove | verify | proof | peak RSS |
|---|---|---|---|---|---|---|
| test profile, N=1 | 19 | 462 262 | 2 034.6 s (the whole aggregate test binary) | — | 334 778 B | **94.5 GB** |
| test profile, N=2 | 20 | 924 115 | 3 983.5 s | — | 355 577 B | **183.7 GB** |
| test profile, N=3 | 21 | 1 385 968 | 4 807.8 s | 24.75 s | 347 800 B | **221.0 GB** |
| production, N=1 | 21 | 2 047 542 | 8 131.3 s | 99.36 s | 1 563 226 B | **376.9 GB** |
| production, N=2 | 22 | 4 094 675 (2.4 % under 2²²) | not attempted | | | ~750 GB estimated |
| production, N=3 | 23 | 6 141 808 | not attempted | | | over 1 TB estimated |

At that constraint set a production aggregator was a ≥ 512 GB host for N = 1, and N ≥ 2 fitted
no single host. Issue #119 recorded both. Neither describes the vendored build: production N = 1
is 235 744 rows where it was 2 047 542, and N = 2 is a tier-19 proof where it was tier 22. The
earlier "≥ 64 GB" class came from a 48.6 GB oracle that these runs disproved.

Sources: `circuits/recursion/docs/02-aggregate.md` ("Constraint set 8, proved"), the #45 closing
comment, `~/rand-agg-512-results/` on the operator's laptop (all 24 step logs).

**What changed since, in order.** Each row's production figure was a projection when written and
none was ever run; the test-twin column is measured (peak live heap, 48 GB laptop).

| change (circuits) | production N = 1 | projected for production N = 1 | the test twin, measured |
|---|---|---|---|
| constraint set 8 (`d38d6cf`) | 2 047 542 rows, tier 21 | 376.9 GB peak RSS, **measured** | 94.5 GB peak RSS (the test N = 1 aggregate, tier 19, the droplet) |
| phase 2 row cuts (`75b7893`, 2026-10-04) | 893 880 rows, tier 20 | ≈ 240 GB, a ≥ 256 GB host | — (a tier-19 trace held 78.7 GB live when the laptop killed it) |
| quotient layout (`5ff7676`, 2026-10-05) | unchanged | ≈ 170–175 GB | 33.27 GB (230 950 rows, tier 18) |
| phase 3 (in `71e1a04`, 2026-10-08) | one inner verification 585 686 rows, tier 20 | ≈ 110–130 GB | 26.88 GB (169 366 rows) |
| rate ¼ (`71e1a04`, 2026-10-08) | unchanged | ≈ 64–75 GB, a ≥ 96 GB host | 15.64 GB |
| phase 4, Merkle spans (`d155616`; vendored with the MODQ chip at `d217252`, 2026-10-11) | 316 279 rows (315 718 with the MODQ chip), tier 19 | ≈ 32–75 GB | 16.75 → 17.19 GB (104 150 rows) |
| phase 5 (`b3e21d9`, vendored 2026-10-15; the build today) | 235 744 rows, tier 18 | no new figure | pending operator run |

The details of each step are in `docs/compute-optimization.md` §4.1 and circuits
`recursion/docs/04` to `10`; the pins each one moved are in
[`aggregation.md`](aggregation.md#before-enabling-aggregation), item 3.

### 4.4 Setup

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
| 14 | 16 383 | the bundle (wallet, test profile) | 5.74 GB whole `rand call` (live provers: 6.2 GB per bundle, 2026-10-27) | 97.0 s | production: 92.2–96.0 s and 1 418 406–1 420 423-byte proofs (chain 13, laptop); memory of the bundle alone not measured yet |
| 16 | 65 535 | ERC-20 `approve`, translated | test profile, DigitalOcean: 21.7 GB. Production, laptop: 22.9 GB peak RSS for the whole `rand call` | test profile: 786.7 s (13.1 min). Production: 388.7 s | production: proved and committed on chain 13, 3 412 405-byte proof |
| 18 | 262 143 | ERC-20, about 66 k–162 k cycles | OOM-killed on a 48 GB laptop at 24.7 GB. On a 64 GB droplet: above 47 GB at 25 min, still running | killed after 1 016 s on the laptop | translated `transfer`: 85.0 GB, 3 230.5 s (53.8 min), 811 600 B proof. Interpreter `evm.bin`: 85.5 GB, 3 143.3 s (52.4 min), 805 108 B proof. Verify: 101.4 s (droplet), 50.2 s at 3.66 GB RSS (laptop). Measured on m-16vcpu-128gb, 2026-09-19 |
| 19 (rVM) | — | rVM aggregate, N=1, test profile (constraint set 8) | **94.5 GB peak RSS** (Linux, 503 GB droplet). The "about 30 GB" quoted before was macOS RSS, which excludes compressed pages | 1568.2 s (loaded shared box); 2 034.6 s (droplet, whole test binary) | superseded: on the vendored build (rVM phase 5) the same aggregate is 88 486 rows at rVM tier 18. The newest measurement of its shape is the phase-4 exit twin, 17.19 GB peak live heap on the 48 GB laptop (§4.2); not re-measured at phase 5 |
| 20 | 1 048 575 | SPL Token, about 700 k–770 k cycles | stopped on a 48 GB laptop at about 31 GB (30.77 GB peak footprint); OOM-killed on a 64 GB droplet at 65.1 GB | 10 m 41 s on the droplet before the kill | not yet proven. Extrapolated from the measured tier-16/18 scaling (memory about ×3.9, time about ×4.1 per +2 tiers): about 330 GB and about 3.6 h, more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) |
| 21 (rVM) | — | rVM aggregate, N=1, production (constraint set 8) | **376.9 GB peak RSS** (the 48.6 GB oracle counted one of four memory terms) | 8 131.3 s | the only production aggregate ever proved; superseded, not re-measured. On the vendored build the same aggregate is 235 744 rows at rVM tier 18, projected ≈ 32–75 GB, not yet run (§4.1) |

The cycle column is `2^t − 1` for the RV32 zkVM (`docs/confidential.md`). The rVM (the
recursion machine) has its own tiers, sized in rows (`docs/zkvm-m4-m5-progress.md`); the two
rVM rows are constraint set 8's measurements, kept as history, and §4 has the current state. The tier-18 and tier-20 laptop runs used
`FriProfile::Test` (circuits `evm2rv/README.md`, `sbpf2rv/README.md`).

### DigitalOcean sizes for proving

| workload | size | status |
|---|---|---|
| a tier-14 bundle (any wallet) | any machine with more than 6.2 GB free (test profile) | measured |
| tier 18 | a 128 GB droplet (size slug `m-16vcpu-128gb`, Memory-Optimized, 16 vCPU). OOM-killed on a 64 GB droplet (`g-16vcpu-64gb`) at 65.1 GB after 32 min | measured: 85.0 GB (translated) / 85.5 GB (interpreted) peak RSS, 3 230.5 s / 3 143.3 s |
| tier 20 | more than 64 GB. OOM-killed on a 64 GB droplet (`g-16vcpu-64gb`) at 65.1 GB after 10 m 41 s | not yet proven; extrapolated at about 330 GB and about 3.6 h (see §5), more than DigitalOcean's largest memory droplet (m-32vcpu-256gb, 256 GB) |
| aggregate N=1, production | ≥ 96 GB, projected (≈ 32–75 GB projected peak, §4.1); of the sizes in this table the 128 GB `m-16vcpu-128gb` is the smallest above it | not measured on the vendored build (rVM tier 18, 235 744 rows). The one measurement is constraint set 8's: 376.9 GB peak on a 503 GB droplet, the proof then at rVM tier 21 (§4.3); superseded, not re-measured |
| aggregation tree, production leaf and step | the 256 GB droplet (`m-32vcpu-256gb`), projected when the steps were rVM tier 21; they are tier 19 on the vendored build and not re-projected (§4.1) | not measured |

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
hash only what it never saw. Measured on the `feat/compact-blocks` branch, debug build. The
source column says where each number comes from: most are printed by the test named beside them,
two are derived from printed sizes and one is quoted from another page.

Memory the compact path keeps beside the pool (spec §0 and its 2026-10-09 follow-ups): the
recent cache, `4 × max_block_bytes`; the overflow cache of bodies relayed past a forwarder's
transaction limit, `max_block_bytes`; and the first-header record, 64 signed headers of ~100 KB
each at 26 validators — about 6 MB at worst (it was 1 024 entries, ~100 MB). The table below
was measured before the overflow cache; the unpaced run's 24 fetches were bodies dropped by that
limit, which a rebuild would now find in the overflow cache (not re-measured).

| quantity | value | source |
|---|---|---|
| largest compact frame, four validators | 15 420 bytes carrying 4 transactions, mints paced one per node every 500 ms (before the pacing, a burst of all 32: 15 708 bytes carrying 13, and 15 804 carrying 16) | `tests/cluster.rs` `a_proposal_frame_carries_hashes_not_bodies`, raw gossipsub frames read by an observer swarm |
| bodies fetched in that test | 0 on all four validators, paced (four runs); unpaced, 8 on each of three (24), the bodies n0 relayed past each receiver's per-forwarder limit (`PEER_TX_BURST` 16) | the same test, `compact_fetched` |
| what those bodies cost on the tx topic | 32 mints, 32 frames, 168 096 bytes (5 253 bytes a mint) — so the 13 the unpaced run's largest frame named were about 68 KB of bodies (13 × 5 253, derived) the frame did not carry | the same test |
| fixed part of a compact frame, four justify votes, no hashes | 19 080 bytes | `network::wire::tests::a_compact_proposal_at_26_validators_and_2000_hashes_is_its_header_plus_32_bytes_a_hash` |
| compact frame at 26 justify votes, no hashes | 102 416 bytes | the same unit test |
| compact frame at 26 justify votes and 2 000 hashes (the block cap) | **166 416 bytes** (printed) — exactly 2 000 × 32 more than with none | the same unit test (`bincode::serialized_size`) |
| today's full proposal on chain 20 | up to the 20 MiB block cap: seven transfers at ~2.85 MB each (tier-14 bundle proof ~1.49 MB, tier-10 auth proof ~1.36 MB, envelopes) | quoted, not measured here: `docs/compute-optimization.md` §1.1 |
| bodies a late validator fetched by hash | 8 of 8 (`compact_fetched` = 8 on its `rand_status`; 0 on the two validators that had them) in each of three runs | `tests/cluster.rs` `a_late_validator_fetches_bodies_it_never_saw` |

Reading the table. The figures below are derived from the printed sizes, not printed
themselves. One vote is (102 416 − 19 080) / 22 = 3 788 bytes, the difference between the
26-vote and four-vote frames over their 22 extra votes. In the four-validator cluster the
observed fixed part is 15 420 − 4 × 32 = 15 292 bytes (and 15 708 − 13 × 32 before the
pacing), which is 19 080 − 3 788: consistent
with three votes in the justify (a quorum) against the unit test's four. At 26 validators a
quorum is 18, so a QC that carries exactly a quorum makes the cap-size frame about
166 416 − 8 × 3 788 = 136 112 bytes (derived); the 166 416 in the table is the bound with every
vote in. Either way a proposal on chain 20 falls from up to 20 MiB to under 170 KB on the
consensus topic.

The late-validator test is the fetch path end to end: two of a four-validator genesis run (no
quorum, so nothing commits), eight faucet mints are pooled and gossiped between them, and a third
validator joins only after gossipsub's 2.5 s history window has passed, so it never sees the
bodies. Its arrival makes the quorum; the first proposal that names the mints parks on it, the
eight bodies are fetched by hash (`SyncRequest::Transactions`), and it votes and commits the
same chain (`assert_chains_equal`). Fetch latency was not timed.

## 9. The msauth verifier key: built once, loaded everywhere (2026-10-12)

A chain naming `hc_auth_multisig` needs the tier-18 msauth verifier key on every validator.
Building it is too big for an `s-2vcpu-4gb` droplet, so validators load a pinned blob instead
(`docs/deploy.md`, "The msauth verifier key"). Measured on the M-series laptop, circuits d217252:

| | wall | memory | file |
|---|---|---|---|
| build (Task 2, `verifier_key_with_modq`) | 78.6 s | ~4.0 GB peak and resident after | — |
| `keygen-msauth-vk --profile production` | 25.0 s (91 s CPU) | 4.00 GB peak RSS | 23 754 bytes |
| load (`install_verifier_key_pinned`, Production) | 6.6 ms (6.3 ms on a re-run) | +8 MiB resident (2 → 10 MiB) | — |
| load (Test) | 14.6 ms | +7 MiB resident (3 → 10 MiB) | 23 754 bytes |

The load checks the SHA-256 pin, decodes the `CommonData` and recomputes the packed lookups; it
does no LDE and no Merkle commit, which is the build's 4 GB.

**To measure on an `s-2vcpu-4gb` droplet (Task 8 / cut rehearsal): RSS after load, and after the
first tier-18 verify.** glibc may return freed memory where macOS did not.

**The proof itself: one Production measurement (audit v14, MSC-751).** On 6 November 2026 one Production-profile proof completed: M = 3 signatures, tier 18, a proof of 3.7 MB, 69 minutes, peak RSS 92.9 GiB (≈ 99.7 GB). Plan for a machine with **at least 128 GB**; the earlier "at least 96 GB" was a guess made before any proof had finished and is too small. The logs are held privately in the operator's configuration records, not in this repository; the machine it ran on is not recorded here. It has not been submitted on chain 21 by a wallet flow. Before it, one Test-profile attempt existed (M = 2 shares, tier 18, 52 GB M-series Mac, `/usr/bin/time -l`): max RSS 22.5 GB but a peak memory footprint of 76.4 GB (compressed pages included; RSS understates it), killed by macOS after 273 s. The guest runs 85 830 / 169 068 / 251 946 cycles at
M = 1 / 2 / 3 signatures, inside tier 18's 262 143 (a Dilithium2 verify is 80 572 cycles with the
MODQ chip, 880 102 in software). The plan's Task 2 `MSAUTH-PROD:`/`MSAUTH-TEST:` lines (the
Production prove's time and peak RSS, the proof's size, and a warm tier-18 verify on a validator)
are not recorded in this repository: the 6 November figures above come from the operator's private
logs, and no warm tier-18 verify on a validator is on record here. The auth proof was estimated at
≥ 3.4 MB (≈ 4.8 MB with the bundle proof) and measured at 3.7 MB; the node's floor
beside `hc_auth_multisig` is a 4 MiB `max_proof_bytes`, and chain 21 is cut at 6 MiB (6 291 456) with
19 MiB blocks (19 922 944) — the decided chain-21 values; asserted by the cut script on `feat/chain21-msauth` (`a7379a6c`), which merges after this branch.
