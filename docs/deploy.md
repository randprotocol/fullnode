# Deployment

## Topology rules

- A chain is defined by its genesis file. Every node needs the identical file; validators are the keys
  listed in it. Changing the validator set means a new genesis and a fresh chain.
- **Set `genesis.timestamp_ms` close to the actual launch time, never ahead of it.** Too far in
  the past and block time visibly lags wall clock until the timestamp step bound (60 s per block on
  a bridged chain, `docs/bridge.md` §16) lets it catch up. **More than 15 seconds in the future and
  block 1 does not commit at all**: every vote, the leader's own included, is withheld until wall
  time reaches the genesis timestamp (`MAX_CLOCK_DRIFT_MS`). Check the cut script's timestamp
  against the clock on the machine that will actually launch the fleet, not the one that cut the
  file.
- More than 2/3 of stake must be online to commit. With equal stakes: 2 validators tolerate none down,
  4 tolerate one, 7 tolerate two.
- Nodes behind NAT dial out to nodes with public addresses (`--bootstrap`). On one LAN, mDNS finds
  peers without configuration. Open TCP 30303 inbound on public nodes.
- Bind RPC to `127.0.0.1` unless it is firewalled; it accepts transactions from anyone who can reach it.
- Observers run the same binary without `--validator`; they sync, verify and serve RPC.
- **The one public RPC endpoint is `https://rpc.randprotocol.org`** — Cloudflare, proxied to Caddy
  on droplet F, forwarding to that node's own `127.0.0.1:8545`; every other droplet keeps RPC
  loopback-only. It is not on E on purpose: E's node holds randscan's 64 `rand_importViewingKey`
  slots, and a public RPC there would let anyone else's import calls evict them.

## Provisioning a Linux server (DigitalOcean example)

The repository ships scripts used for the live testnet (`deploy/`):

| script | runs on | purpose |
|---|---|---|
| `deploy/push-to-vps.sh <ip> <letter> "<bootstraps>" [validator\|observer]` | your machine | rsync the source to `/root/fullnode`, build, install `/usr/local/bin/{rand-node,rand}`, init a datadir keyed on the genesis hash, install and start a `rand-node` systemd service |
| `deploy/rebuild-vps.sh <ip>` | your machine | rsync new source, incremental build, reinstall binaries, restart the service (data kept) |
| `deploy/vps-setup.sh` | the server | what `push-to-vps.sh` executes remotely |
| `deploy/run-a.sh`, `deploy/run-b.sh` | laptops behind NAT | run a validator bootstrapping to the public nodes. On A the script is run by launchd (`deploy/launchd/org.randprotocol.node-a.plist`, installed under `~/Library/LaunchAgents`): it starts at login and restarts on exit, so a reboot no longer takes A down until someone notices — restart it with `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a`, never by running the script in a shell beside it |

The server needs `build-essential clang cmake pkg-config libssl-dev` and a Rust toolchain; the
cloud-init used for the droplets installs them and opens ports 22 and 30303 with `ufw`. Set `SSH_KEY`
to the private key to use (default `~/.ssh/id_ed25519`; passphrase-protected keys do not work in
scripts).

Service management on the server:

```bash
systemctl status rand-node
journalctl -u rand-node -f
rand status
rand-node verify --datadir /root/data-<letter>-<genesis8> --mode full   # stop the service first
```

## Rolling out a new commit

1. `cargo test` locally, commit, push.
2. Restart local validators from the new binary (`cargo build --release`, point `run-a.sh`'s `BINDIR` at it, then `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a` — launchd restarts A from the script).
3. `deploy/rebuild-vps.sh <ip>` per server, staggered so that more than 2/3 of stake stays up. A
   restart costs a node a few seconds; it resumes from its persisted head, verifies the chain, and
   batch-syncs what it missed. Do not leave nodes on different builds for long: a node still on the
   previous build cannot answer block fetches for the new one.

## Fault tests that have been run on the live testnet

- Stop one of four validators: the chain keeps committing, with a timeout on the absent leader's
  views; the node resumes from disk and catches up in seconds.
- Stop two of four: the chain halts (no quorum) and resumes without a fork when they return.
- Corrupt a node's RocksDB (garbage block, wrong account balance): detected at startup, truncated,
  resynced from peers, ending byte-identical to the others.
- Random transfers submitted through different nodes: all committed; balances identical on every
  node; total supply unchanged.
- A dropped peer link is re-established by the redial logic within about 30 s.

## Deferred proof runs and hardware tasks (user-owned; accepted 2026-09-15, scheduled 2026-09-16)

Two hardware tasks gate the next milestones. **For any future session:** this is the checklist;
the runbook with exact per-run commands and estimates is `circuits/recursion/docs/03-gpu-and-self-recursion.md`
Appendix A (11 rows). The deferred proofs are all written and `#[ignore]`d with run-alone command
lines in their test files.

1. **The ≥ 64 GB batch** (runbook rows 1–6; one machine, one session, sequential with an RSS
   watchdog — the 48 GB laptop jetsams these at ~33 GB): the ERC-20 transfer proof, the SPL token
   proof (`research/tests/e2e.rs`, both `#[ignore]`d), the rVM tier-21 exit (`recursion/tests/exit.rs`),
   the M5.3 N=2/N=3 test-profile aggregates (`recursion/tests/aggregate.rs`), the production N=1
   aggregate. Record per run: wall time, peak RSS, proof size. **Then fill chain-9's
   `genesis.aggregation.admitted_shapes[0]`** (the production bundle guest's declared heights +
   `hc`, `aggregate_program_digest(shape, key)`, the startup key-build wall at 2^21, the warm
   verify wall) — the zero-digest placeholder refuses to init, so this measurement is what
   activates chain 9. Per the 2026-09-15 ruling the batch runs *after* chain-side aggregation
   lands on main.
2. **The fleet GPU node** (runbook rows 8–10): Linux, R580+ driver, CUDA 13, LLVM 21, sm_80+,
   80 GB device (H100/A100-80G), ≥ 160 GB host RAM — none exists today. Unlocks the first PTX
   build + hardware bring-up (`circuits` `PTX_BUILD.md`'s checklist, param-ABI audit first), then
   the production N re-measurement (runbook rows 7–8, production N=2/N=3, the ≥ 160 GB host
   classes), and later the self-verifier's end-to-end (row 11, est. tier 22 / ≥ 128 GB).

## The chain-14 cut (v0.5, 2026-09-20)

Full step-by-step order of operations: `docs/superpowers/handoffs/2026-09-20-chain14-cut-runbook.md`.
Outcome and the launch record: `AGENTS.md`'s v0.5 entry; the live facts table: `deploy/README.md`.
This section is the reusable checklist for a hard fork that changes genesis format, wire format and
key custody all at once — worth re-reading before chain 15.

1. **Merge first, linearly, no merge commits** — a rollback story depends on it (user: "so rollback
   is easier").
2. **NTP on every validator before the cut, not after.** Chain 14 is the first bridged chain with a
   forward timestamp bound (B2, `docs/bridge.md` §16): a validator whose clock is more than 15 s off
   silently stops voting.
3. **Fleet disk survey before touching anything.** Chain 13 stalled at `ENOSPC` on seven droplets
   because chain-11 and chain-12's retired data dirs were never deleted, and chain 13 itself grew
   ~16 GB/day — delete every retired chain's data dir (guarded to the unit's own current datadir
   only) and re-check free space on the 48 GB droplets specifically before rolling the next cut.
4. **Generate fresh keys off-repo, back them up, and never commit them.** A public repository that
   tracks validator seeds on a chain with a live bridge lets anyone finalize conflicting blocks
   (OPS-1). `deploy/gen-chain14-keys.sh` → `$KEYDIR` (default `~/.rand-chain14`); back the whole
   directory up somewhere off the laptop before going further — there is no second copy.
5. **Cut the genesis close to the actual launch time**, not the evening before: the chain's clock
   zero is the genesis `timestamp_ms`, and on a bridged chain that also starts the guardian-set
   grace window and the mint-cap day. `rand-node init` on the *finished*, bridge-spliced file is the
   real hash — not what `rand-node genesis` printed on the unbridged one.
6. **Roll bootstraps first (C, D), then the rest one at a time waited to `rand_getHealth: ok`, node A
   last.** Nothing commits until 13 of 18 are up; that is quorum, not a fault.
7. **Redeploy the explorer in the same window**, not after — a node's RPC amount encoding is a
   breaking change too (every `u64` amount became a decimal string in this cut) and an explorer
   built for the old shape renders nothing on the new chain. Check its migration numbering against
   what the database has already *tried*: a version number consumed by a reverted feature (chain 14
   hit this — receivers migration 8, reverted, silently skipped the next migration numbered 008)
   stalls the indexer at whatever height that skip happened.
8. **List a bridged token on Rand before enabling it on the source endpoint**, never the other way:
   a deposit into an endpoint with nothing to credit it against on Rand is refused but safe in
   custody; the reverse has no symmetric failure.
9. **A guardian-set rotation is independent of the chain cut and can follow it at any time** — Rand's
   genesis starts at the guardian set already in use and takes the rotation attestation later, so
   there is no reason to gate the cut on it.

## Chain 9 activation (block aggregation)

Cutting and bringing up the chain-9 fleet, in order. Everything here is the hard fork it is:
the wire format, block rules and consensus all change, so every node runs the same build, cut
from the same commit.

1. **Measure the activation values** on the production build the fleet will run (never from a
   note, never from another build): the admitted shape is the fleet's 2-in/2-out bundle at its
   production landing — tier, the six declared log-heights, and the aggregate program digest,
   computed from the shape alone by the startup key-build (spec §2.3; the ~30–70 s 2²¹ key-build
   every node then pays once at startup). The fleet's own measured classes for the bundle are
   `program 12, input 10, keccak 0, sha256 0, public 2, mem 16`; the tier and the digest are the
   two numbers activation must measure — the digest through the executor's
   `aggregate_program_digest`, the tier from a production bundle proof's header.
2. **Cut the genesis**: `deploy/cut-chain9-genesis.sh`, mirroring chain-8's validator and alloc
   mechanics with `--chain-id 9` and the section. The admitted shape's `hc` is the keyword
   `hc_bundle` (the genesis command substitutes the build's pinned guest digest — the cut
   cannot carry a stale one); the digest and tier come from step 1. The script ships with the
   test-profile values marked FILL-AT-ACTIVATION; genesis validation refuses a zero digest, so
   an unedited placeholder can never reach a fleet.
3. **Distribute the file byte-identically** (re-cutting re-randomises the deposit notes, so the
   hash differs every run — cut once, copy everywhere).
4. **Bring the fleet up as usual**; each node logs the startup key-build's wall time once
   (`aggregation: aggregate program built and the tier-21 verifier key warmed`).
5. **Aggregators register** (`rand-node aggregator register --bond --payout` prints the
   signed registration; the bond burns through the wallet's `submit` as the register bundle's
   burn) and run **`rand-node aggregate --watch`** on a proof machine (≥ 64 GB at N=1, the
   GPU node for N≥2 — see `docs/aggregation.md`'s machine classes), pointed at any fleet RPC.
6. **Ops checks**: `rand_status`'s `aggregation` section (registered, unsealed, the schedule
   index), `rand_getUnsealed` for the work list, `rand_getSupply` for the four counters
   (`subsidised` against `sealed_blocks` is the schedule audit). Archive nodes run with
   `--keep-raw-proofs`; everyone else lets the pruning pass reclaim sealed bundles after the
   256-block window.

## Recovery cheatsheet

| symptom | action |
|---|---|
| height not advancing, `peer_count` low | check bootstrap addresses and port 30303; `rand peers` |
| height not advancing, peers fine | fewer than 2/3 of stake online: start the missing validators |
| `CORRUPT CHAIN` in the log at startup | nothing; the node truncated and is resyncing. To inspect first, run `rand-node verify` before starting |
| node refuses to start: `already initialized with a different genesis` | the datadir belongs to another chain; use a fresh `--datadir` |
| a validator warns it is not in the validator set | the key is not in genesis; it runs as an observer |
| views advance but nothing commits after nodes restarted | validators are waiting for uncommitted blocks behind the newest certificate that no reachable peer holds; since `f5b8dfd` they fall back to the committed head after failed fetches (log: `falling back to the committed head QC`). Make sure every node runs the same build: the sync protocol is chain-scoped and builds cannot fetch across versions |
| a peer keeps connecting but never helps | it may run another chain or an older build; gossip topics and the sync protocol are per chain id, so it is harmless but useless |
