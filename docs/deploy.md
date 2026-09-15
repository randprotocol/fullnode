# Deployment

## Topology rules

- A chain is defined by its genesis file. Every node needs the identical file; validators are the keys
  listed in it. Changing the validator set means a new genesis and a fresh chain.
- More than 2/3 of stake must be online to commit. With equal stakes: 2 validators tolerate none down,
  4 tolerate one, 7 tolerate two.
- Nodes behind NAT dial out to nodes with public addresses (`--bootstrap`). On one LAN, mDNS finds
  peers without configuration. Open TCP 30303 inbound on public nodes.
- Bind RPC to `127.0.0.1` unless it is firewalled; it accepts transactions from anyone who can reach it.
- Observers run the same binary without `--validator`; they sync, verify and serve RPC.

## Provisioning a Linux server (DigitalOcean example)

The repository ships scripts used for the live testnet (`deploy/`):

| script | runs on | purpose |
|---|---|---|
| `deploy/push-to-vps.sh <ip> <letter> "<bootstraps>" [validator\|observer]` | your machine | rsync the source to `/root/fullnode`, build, install `/usr/local/bin/{shrugg-node,shrugg}`, init a datadir keyed on the genesis hash, install and start a `shrugg-node` systemd service |
| `deploy/rebuild-vps.sh <ip>` | your machine | rsync new source, incremental build, reinstall binaries, restart the service (data kept) |
| `deploy/vps-setup.sh` | the server | what `push-to-vps.sh` executes remotely |
| `deploy/run-a.sh`, `deploy/run-b.sh` | laptops behind NAT | run a validator bootstrapping to the public nodes |

The server needs `build-essential clang cmake pkg-config libssl-dev` and a Rust toolchain; the
cloud-init used for the droplets installs them and opens ports 22 and 30303 with `ufw`. Set `SSH_KEY`
to the private key to use (default `~/.ssh/id_ed25519`; passphrase-protected keys do not work in
scripts).

Service management on the server:

```bash
systemctl status shrugg-node
journalctl -u shrugg-node -f
shrugg status
shrugg-node verify --datadir /root/data-<letter>-<genesis8> --mode full   # stop the service first
```

## Rolling out a new commit

1. `cargo test` locally, commit, push.
2. Restart local validators from the new binary (`deploy/run-a.sh` after `cargo build --release`).
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

## Recovery cheatsheet

| symptom | action |
|---|---|
| height not advancing, `peer_count` low | check bootstrap addresses and port 30303; `shrugg peers` |
| height not advancing, peers fine | fewer than 2/3 of stake online: start the missing validators |
| `CORRUPT CHAIN` in the log at startup | nothing; the node truncated and is resyncing. To inspect first, run `shrugg-node verify` before starting |
| node refuses to start: `already initialized with a different genesis` | the datadir belongs to another chain; use a fresh `--datadir` |
| a validator warns it is not in the validator set | the key is not in genesis; it runs as an observer |
| views advance but nothing commits after nodes restarted | validators are waiting for uncommitted blocks behind the newest certificate that no reachable peer holds; since `f5b8dfd` they fall back to the committed head after failed fetches (log: `falling back to the committed head QC`). Make sure every node runs the same build: the sync protocol is chain-scoped and builds cannot fetch across versions |
| a peer keeps connecting but never helps | it may run another chain or an older build; gossip topics and the sync protocol are per chain id, so it is harmless but useless |
