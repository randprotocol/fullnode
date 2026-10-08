# Deployment

## The network today: chain 18 (read 2026-09-30)

This page is a log as well as a manual: the roll notes and "the next cut" sections below are dated
and describe the chain they were written for (14 to 17). What runs now, from
`deploy/genesis-chain18.json` and `AGENTS.md`'s "Chain 18" and "v0.6.7" entries:

| | |
|---|---|
| chain | id **18**, genesis `a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76`, live since 2026-09-29 04:56 UTC |
| build | v0.6.7 `86941a1` (cut on v0.6.7-rc1 `0017de7`; v0.6.7 rolled node by node) |
| validators | 26 at genesis, 1 000 RAND each; a quorum is strictly more than two thirds of the stake, so **18 of 26**, and the chain commits with up to 8 down |
| history | 24 validators run `--prune-history 24h`; two keep every block: obs1 (`ARCHIVE` in `deploy/nodes.env`) and rand-archive-2 (`ARCHIVE2`) |
| caps | `max_proof_bytes` 4 194 304 (4 MiB), `max_block_bytes` 20 971 520 (20 MiB), `max_program_words` 65 535, `max_call_envelope_bytes` 65 536 |
| guests | `hc_bundle` = bundle guest v3, `hc_auth` = the auth guest (split authorisation, since chain 17); `hardening_v6`; `consensus_domain` 1 |
| gas | `gas_price` 100, `byte_price` 800, `bundle_gas_limit` 20 479, `metering: "circuit"`, `dynamic` {`target_block_bytes` 10 485 760, `target_block_gas` 262 144, `adjust_bps` 1 250, floors 100 / 800} |
| note envelopes | `envelope_bytes: 1860` — every note envelope is exactly 1 860 bytes and carries the encrypted memo field |
| faucet | on, for an allow-list: 16 `faucet_recipients`, 18 `faucet_minters`, 10 000 RAND per 1 000-block epoch |
| bridge | guardian set 1, rules v2: 100 000 zUSD per backing and 4 000 zUSD across all backings per rolling 24 h |
| aggregation | off: no genesis carries the section and the node refuses one |

All 26 validator keys are one operator's ("Key separation", below). The release rule and how far
it has been followed are under "Rolling out a new commit"; the rules for the next cut are under
"Cut policy".

Since this table was written: **chain 19** (v0.6.7, genesis `a3defc93…228a`, 2026-10-01,
`deploy/cut-chain19-genesis.sh`) and **chain 20** (v0.6.8, genesis `6210cf07…5135`, live since
2026-10-01 06:17 UTC, `deploy/cut-chain20-genesis.sh`, `deploy/cut-records/chain20.record`; now on
v0.7.1) — chain 20 is the chain that runs. **Chain 21** is prepared, not cut:
`deploy/cut-chain21-genesis.sh` carries chain 20's shape and value plus the `fees` section
(`burn_base`, `burn_floor`; "The next cut: the `fees` section (chain 21)", below) and needs a
build at d6cc16f5 or later on every node (signers read the genesis hash from the node or take
`--genesis-hash`, so they need it only to know `fee_rules`).

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
  4 tolerate one, 7 tolerate two, 26 tolerate eight (chain 18's quorum is 18).
- Nodes behind NAT dial out to nodes with public addresses (`--bootstrap`). On one LAN, mDNS finds
  peers without configuration. Open TCP 30303 inbound on public nodes.
- Bind RPC to `127.0.0.1` unless it is firewalled; it accepts transactions from anyone who can reach it.
- **The swarm caps what it will hold** (deep scan 2026-09-24): at most 256 established *inbound*
  connections, 64 inbound handshakes in flight and 2 connections per remote peer
  (`network::WireLimits`); the next inbound connection is refused at the handshake and the dialer
  sees a `ConnectionDenied`. A node's own dials — its bootstraps and redials — are never counted
  against its own caps, so a validator always reaches the peers it dials, and 26 validators plus
  every explorer and observer sit far under 256; the cap is a bound on what one host can be made
  to hold, since a fresh libp2p identity costs nothing to mint. The node's peer map is held to
  the same bound: a new connection evicts the entries that are not connected before it is
  recorded, and a gossiped `Status` from an author this node holds no connection to no longer
  creates an entry at all.
- Observers run the same binary without `--validator`; they sync, verify and serve RPC.
- **History pruning (testnet only).** `--prune-history <n>m|<n>h|<n>d`, at least `1h` (`24h`
  keeps the ledger and one day of blocks); the rest is deleted every 16 blocks
  (`docs/superpowers/specs/2026-09-24-history-pruning-design.md`).
  Two nodes keep everything — the archives, `ARCHIVE` in `deploy/nodes.env` (obs1 on
  randbridge-web, data dir on a volume) and, since 2026-09-27, `ARCHIVE2` (rand-archive-2, fra1,
  a 250 GiB volume) — and a node that falls more than a day behind must sync from one of them. **Mainnet units never pass the flag.** A pruned node that fails its startup check does
  not repair itself: re-sync it from the archive. **Rollback:** a pruned data directory opened by
  a build ≤ v0.5.6 with the default `--verify-chain quick` replays from genesis, finds block 1
  missing and truncates the whole ledger to genesis; run an older build on a pruned data
  directory only with `--verify-chain off`, or re-sync from the archive.
- **The one public RPC endpoint is `https://rpc.randprotocol.org`** — Cloudflare → the web
  droplet's nginx → the sale service's filtered, per-IP-metered proxy → an SSH tunnel to obs1 →
  obs1's `127.0.0.1:8545`, the archive (since 2026-09-27; before that randscan's `/rpc` route on E.
  `deploy/caddy/README.md` has the chain; F's Caddy is not in it and does not run). Every droplet
  keeps its node's RPC loopback-only. The proxy's allowlist never forwards
  `rand_importViewingKey`.
- **A delegated prover is never on the public RPC path.** An operator node started with
  `rand-node run --prover <ADDR>` (or a separate `rand-prover run`) listens on its own address,
  and holds the sending wallet's viewing key — its whole history — while it proves (never a spend
  key: that witness is retired, and `--prover-accept-spend-key` is refused at startup).
  Keep that listener on loopback (`127.0.0.1:8600` is `rand-prover run`'s default; the node's
  `--prover` has none and must be given) unless a TLS-terminating proxy fronts it for a LAN or a
  phone, and never run it on E, the web droplet or any other host in the `rpc.randprotocol.org` chain, nor route it through that chain. Both stop gracefully on
  SIGTERM, systemd's default; set `TimeoutStopSec=180` so a stop lets the proof in flight (about
  100 s) finish before systemd escalates. Runbook and trust model: `docs/prover.md`.

## Provisioning a Linux server (DigitalOcean example)

The repository ships scripts used for the live testnet (`deploy/`):

| script | runs on | purpose |
|---|---|---|
| `deploy/push-to-vps.sh <ip> <letter> "<bootstraps>" [validator\|observer]` | your machine | rsync the source to `/root/fullnode`, build, install `/usr/local/bin/{rand-node,rand}`, init a datadir keyed on the genesis hash, install and start a `rand-node` systemd service |
| `deploy/rebuild-vps.sh <ip>` | your machine | rsync new source, incremental build, reinstall binaries, restart the service (data kept) |
| `deploy/vps-setup.sh` | the server | what `push-to-vps.sh` executes remotely |
| `deploy/run-a.sh`, `deploy/run-b.sh` | laptops behind NAT | run a validator bootstrapping to the public nodes. On A the script is run by launchd (`deploy/launchd/org.randprotocol.node-a.plist`, installed under `~/Library/LaunchAgents` by `deploy/install-launchd.sh`, which copies `run-a.sh` — and `fleet-watch.sh` with `nodes.env` — to `~/rand-node-a/deploy/` so launchd never runs the shared checkout; re-run it after either script changes): it starts at login and restarts on exit, so a reboot no longer takes A down until someone notices — restart it with `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a`, never by running the script in a shell beside it |

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

### Reserved peers (audit v6, NET-1)

A node accepts at most 256 established and 64 half-open inbound connections, and a libp2p
identity costs nothing to mint, so strangers can hold every slot. Three kinds of peer are
**reserved** — admitted past the established-inbound cap however many strangers hold it, and
served from the validators' share of the sync budget (SYNC-3):

- every `--bootstrap` address's peer id;
- every `--reserved-peer <PEER_ID>` (repeatable; `rand-node address --key <file>` prints a key's
  id — the same id the fleet's `nodes.env` bootstrap lines end in);
- every validator identity learned from a signed peer binding. Each `--validator` node signs
  "my libp2p identity is …" with its validator key and gossips it on `rand/<chain>/peers` when a
  peer connects (at most every 10 s) and every minute; a node that knows the key from a
  validator set records it, reserves the peer and persists the record (`peer_bindings` in the
  meta column, a cache — not fsynced), so a restart or a node-by-node roll comes back with its
  validators reserved before gossip says anything.

A freshly cut chain has an empty store, so until the first announcements arrive only the first
two kinds are reserved: pass the fleet's validator peer ids with `--reserved-peer` in the unit
(or keep them in the bootstrap list) for a cut. Reserved peers still count toward the 256, so
they take slots from strangers, never the other way round; each is held to four connections of
its own (two for anyone else). Independently, one source address may hold at most four
half-open connections, and a connection that has not finished its handshake in 5 s is dropped
(libp2p's default was 10 s). The binding topic is new: an older build does not subscribe to it,
so this rolls node by node.

Serving sync batches (audit v6, SYNC-3): a node serves at most 32 batch requests back to back and
8 a second to all strangers together, and the same again to validator peers (the reserved ones)
from a share of their own. Over the node-wide budget — or with every serving slot busy — it
answers `Busy`, and a new asker takes the request to another peer without backing this one off.
A build older than this one cannot decode `Busy`: it counts the request as failed, backs the
peer off and halves its next batch, a little more than the empty answer it used to get. That
lasts only while such a node syncs from an upgraded one whose budget is spent, and ends with
the roll.

### The pool's byte cap and `--strict-gossip` (audit v6, CH-7)

The pool holds at most eight blocks' worth of transaction bytes (8 × the genesis
`max_block_bytes`: 160 MiB on a 20 MiB-block chain) beside its 10 000-entry count cap. At the
cap a transaction that pays more above its floor per KiB displaces the cheapest pooled ones;
one that pays less, or the same, is refused `mempool full`. Governance actions (pause, unpause,
listings, rotations) pass both caps and are never displaced.

`rand-node run --strict-gossip` switches gossipsub to strict validation: a delivered message must
carry a valid author signature, sequence number and source, so an unsigned message claiming
someone else's authorship is dropped by gossipsub itself (without it the node's own rules
already refuse such a `Status`, SYNC-1). Off by default. The mode governs only what a node
*accepts*, and every node signs what it publishes, so — tested, not assumed — a strict node and a
permissive one exchange every honest message in both directions: the flag **can roll node by
node**, and the older advice here (a strict/permissive mix drops messages; only at an
all-stop/all-start) does not hold for this fleet. Turn it on everywhere once it has run on a
canary.

## Rolling out a new commit

1. `cargo test` locally, commit, push.
2. Restart local validators from the new binary (`cargo build --release`, point `run-a.sh`'s `BINDIR` at it, then `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a` — launchd restarts A from the script).
**Release rule (audit v4 PROC-3).** The rule: a version tag is made only from a commit whose CI
run (`.github/workflows/ci.yml`) is green and whose full `cargo test --workspace --release` passed
on the release machine, `the_genesis_hash_is_pinned` included; the tag annotation names the run. A
known-failing test is a reason not to tag, never a note to tag over.

**The record (audit v6, 2026-09-30): the rule was written and not followed.** By the audit's count
CI was red at the tagged commit for 10 of the 12 tags since v0.5.8 — eight died at the checkout of
the pinned circuits commit, v0.6.3 on the write-ahead-log test, v0.6.4 on a guest-provenance test
that lagged chain 17's genesis — no tag annotation names a run, no nightly run has been green, and
v0.6.7 was tagged before its full suite finished, on instruction (`AGENTS.md`, "v0.6.7"). Until
2026-09-30 this paragraph stated the rule as if it were the practice.

**The mechanism (from 2026-09-30).** `.github/workflows/release.yml` runs on a pushed `v*` tag. It
refuses to build unless the `ci` workflow's latest run for the tagged commit concluded `success`,
or the tag's annotation carries a line `ci-override: <who> <why>` — an exception that is copied
into the release notes, not a default. It then builds the three binaries on a clean runner and
publishes them with `SHA256SUMS` and a build attestation; the release notes name the CI run. Fleet
binaries come from that release, not from a hand build ("Release trust", below). The workflow has
not yet produced a release: the first tag after 2026-09-30 is its first run.

3. `deploy/rebuild-vps.sh <ip>` per server, staggered so that more than 2/3 of stake stays up. A
   restart costs a node a few seconds; it resumes from its persisted head, verifies the chain, and
   batch-syncs what it missed. Do not leave nodes on different builds for long: a node still on the
   previous build cannot answer block fetches for the new one.

**Roll note for v0.5.4's lock rule (audit v4 CON-4).** A validator's lock is now released only on
signed `NotHeld` answers from validators holding a quorum of the stake — strictly more than two
thirds since v0.5.5 (audit v5; v0.5.4 released on a third) — (`docs/consensus.md`, "The lock"), and
a node on an older build never sends one: in a mixed fleet a lock on a block no peer holds simply
holds, and that validator withholds its vote until a newer QC forms without it. Roll all
validators, one at a time waited to `rand_getHealth: ok`, before relying on the rule; the v0.5.4
database stays forward-compatible (no new column family — `META_LOCKED_BLOCK` is a CF_META key an
old build never reads), so the rollback from v0.5.4 is the re-pin of the previous binary. Since
v0.5.5 every certified block above the head is persisted too (`META_PENDING_BLOCKS`, another
CF_META key an old build never reads) and restored at startup, so a whole-fleet restart no longer
leaves every validator's high QC naming a block nobody holds — the 2026-09-24 stall.

**Roll note for the not-held freshness fix (scan 2026-09-27, CN-3): one at a time, not
all-stop.** A `NotHeld` now signs `rand-not-held-2 ‖ genesis ‖ hash ‖ view` and carries the
signer's view as a field appended last; the asker counts it only when its view is above the
locked QC's and within 256 views of its own (`docs/consensus.md`, "The lock"). The sync wire is
CBOR with named fields, so nothing fails to decode in a mixed fleet (pinned by
`network::wire`'s `a_not_held_decodes_across_the_roll_and_counts_on_neither_side`): an old node
skips the unknown `view` field and its `rand-not-held-1` check refuses the signature — counted
nothing, next peer asked, exactly as for `Block(None)`, no penalty; a new node reads an old
answer with `view` 0, which the new tag refuses and every lock is above — counted nothing too.
Votes, proposals, NewViews, blocks and every validity rule are unchanged, so the chain keeps
committing through any mix and there is no fork window — which is why the roll is the usual
one node at a time waited to `rand_getHealth: ok` rather than v0.5.6's all-stop. The cost is
the v0.5.4 D15 corner only: while the fleet is mixed, a lock on a block nobody holds can be
released only by the new build's words from more than two thirds of the stake (13 of the 18
equal stakes), so keep the roll short and do not leave the fleet mixed. Rollback is the re-pin of
the previous binary (no storage change).

**Roll note for v0.5.5's storage layout (audit v5 OPS-4).** A committed block's certificate is
stored once: it lives in its child's `justify`, and `CF_QCS` keeps only genesis' row and the
head's. The first open on v0.5.5 deletes the row v0.5.4 wrote for every other height (~250 000
rows, ~12 GB on a chain-14 validator) in one batch, sets `META_QCS_PRUNED`, and compacts the
family; a node killed mid-pass finishes it on its next open. Startup verification reads each
block once (the child is carried into the next height), so it is no slower than before. **Rollback
below v0.5.5 needs a resync**: a v0.5.4 binary reading a pruned database finds no row for a
non-head height and fails `committed_block` with `Corrupt` — it cannot serve sync and its own
startup verify refuses the chain — so the old binary must start from an empty data directory.
No wire, consensus or genesis change: v0.5.5 and v0.5.4 nodes interoperate, and the roll is one
node at a time waited to `rand_getHealth: ok` as usual. The slope this halves: an idle chain-14
block is ~60 KB of `blocks` (the 18-signature Dilithium2 QC inside the header) and ~0 of `qcs`
where it was ~49 KB more — about 3.6 GB/day at the fleet's measured 1.4 s blocks, 1.7 GB/day at
3 s (the D19 numbers; the release notes carry the figure measured after the roll).

**Roll note for v0.5.6 (the deep scan, 2026-09-25): all-stop, all-start, like v0.5.5.**
Node-only, same chain, rollback = re-pin `0154fe2`. One of its rules is a block-validity rule as
well as an admission one: a `Call` proof above tier 14 (or with an oversized hash table —
`docs/confidential.md`) is refused by v0.5.6 and accepted by v0.5.5. No such call has ever been
committed on chain 14 (all 340 are tier 10), but the public RPC admits submissions from anyone,
so a one-at-a-time roll has a window in which an old-build leader could commit such a call and
split the fleet (the independent review's one finding). The roll therefore installs the binary
everywhere first, then stops all eighteen and starts all eighteen (`deploy/roll-all.sh`, ~15 min
of no commits, the v0.5.5 procedure) — no mixed fleet ever runs. A sealed-form side table of the
wrong length is refused instead of crashing the node (no aggregation section on chain 14, so
unreachable). The swarm now refuses inbound connections past 256
established, 64 in handshake and 2 per remote peer ("Topology rules"); a validator's own dials
are never refused. `deploy/fleet-watch.sh` (every five minutes from the laptop via
`deploy/launchd/org.randprotocol.fleet-watch.plist`) alerts on a stall, a node behind, `disk_low`,
mixed builds or an unreachable droplet; `update-droplet.sh` takes `WANT_SHA=<release sha>` and
verifies the binary against that rather than the build host's own.

**Both binaries are checked (ops review OPS-2).** The `rand` wallet binary is installed beside
`rand-node` and run as root by the roll scripts, so it is verified exactly like the node:
`update-droplet.sh` and `cutover-droplet-chain14.sh` take `WANT_SHA_WALLET=<release sha of rand>`
beside `WANT_SHA`, check the build host's copy and the droplet's copy of each before anything is
installed, and refuse `WANT_SHA` without `WANT_SHA_WALLET`; `roll-all.sh` takes the wallet's sha
as its fourth argument (or `WANT_SHA_WALLET`) and refuses a roll without it. A release's
annotation therefore names two sha256s: `rand-node` and `rand`.

**Disk guard (audit v4 OPS-3).** A node refuses to start under 1 GB free on its data directory's
filesystem (`--min-free-disk-mb`, default 1024, names the directory and the flag), and
`rand_getHealth` answers `disk_low` with the free byte count under 4 GB, re-measured every status
tick with a warning in the log — the 2026-09-24 stall was seven full disks and a health check that
said `ok` right up to the crash loop. A roll waits on `ok`, so a droplet near full now stops the
roll at that node instead of at the next one that fills.

## The compact-blocks flag day

The compact-blocks release changes the consensus-topic wire format and is not backward
compatible: an old node cannot decode `GossipMessage::CompactProposal` or the new
`SyncRequest::Transactions` / `SyncResponse::Transactions` variants, and a new leader publishes
only the compact form. A new node still accepts an old leader's full proposal.

**What an old node does with a compact proposal.** It reports the undecodable message to
gossipsub as `Reject` (`network/mod.rs` ~884-891, "this peer's fault"), so it neither votes on it
nor relays it. This node configures no gossipsub peer scoring: the gossipsub construction at
`network/mod.rs:539-555` sets none and nothing in `network/` mentions `with_peer_score`, peer
score parameters, thresholds or a graylist. So a Reject only drops the message at that node and
does not forward it; it does not penalise the forwarding peer or prune a mesh. The effect is
that old nodes between new nodes are relay holes for compact proposals, while the new-to-new
mesh is unaffected. Restarting a node onto the new build is the whole cure.

**Roll order and why.** Observers and archives first: they relay consensus gossip and serve
fetches, and while old they would drop (and Reject) compact proposals; rolling them early costs
nothing, because a new node still accepts full proposals from old leaders. Then every validator
at once, with `deploy/roll-all.sh` — not staggered as in step 3 above, and not in batches.

**A mixed validator set is a stopped chain, not a slow one.** A commit needs three consecutive
certified views: chained HotStuff finalises a block only when it, its child and its grandchild are
certified in views `v`, `v + 1`, `v + 2` (`consensus/commit_rule.rs:28-40`, and the live path's
`consecutive_views` check at `consensus/hotstuff.rs:51-53, :1564-1573`). Leaders rotate by view
over the validator list, `validators[view % n]` (`types/validator.rs:87-93`). An old-build
validator cannot decode a compact proposal, so while more than a third of the stake is on the old
build, every view led by a new-build validator gets no quorum and times out. Views led by
old-build validators still certify (a new node accepts a full proposal), but a block commits only
when three consecutive views are all led by old-build validators — with the two builds' leaders
interleaved in the rotation that need never happen. **Commits can stop entirely**: blocks certify
on the old leaders' views, none commit, and the uncommitted tree grows toward `max_tree_blocks`
(512, `consensus/mod.rs:389`). Once more than two thirds of the stake runs the new build, both
builds' leaders' views certify again. There is no genesis field and no chain cut.

**Procedure.** Observers and archives with `deploy/update-droplet.sh` (one at a time). For the
validators, `deploy/roll-all.sh <rand-node> <rand> <sha256 of rand-node> [<sha256 of rand>]`
(with `RELEASE_SUMS` and `RELEASE_SIG`, or `ALLOW_UNSIGNED=1`): it installs the signed binaries
on every host in `deploy/nodes.env` with no restart, then stops every node together and starts
every node together, node A last, each stop and start run in parallel over ssh. It is an
all-stop all-start, not a sequential roll: the chain commits nothing for the startup verify (its
header comment says about 15 minutes) whatever the fleet size, and no mixed validator set ever
runs. It is the only validator procedure for this release: any staggered or batched restart is
the mixed window above. It has no observers-first mode; run `update-droplet.sh` on those
beforehand.

**Rollback.** All together as well, by the same script: `deploy/roll-all.sh` with the previous
release's `rand-node` and `rand` and their shas — the bytes `roll-all.sh` kept on each host as
`/root/rand-node.prev`. A partial rollback is the same mixed window: while more than a third of
the stake is on the old build, the new leaders' views time out and commits can stop. Nothing is
written to disk that the old build cannot read, so the rollback needs no resync.

## Release trust

Written 2026-09-30 (audit v6, PROC-4 and PROC-5). Until now every fleet binary was built by hand
on one host — which is also the explorer's host and a validator — uploaded with a `SHA256SUMS`
copied from that build by the person who made it, and installed as root on 26 nodes. That
checksum catches a corrupt download. It does not catch a compromised build host: the build host
was the trust root of the fleet, and on the 20 non-guardian hosts a bad `rand-node` reads the
validator key beside it — 20 keys, more than the quorum of 18. No commit and no tag is signed,
and `main` is not a protected branch.

What a release is from the next tag on, and who is trusted for what:

1. **The build: CI, from the tag.** `.github/workflows/release.yml` runs on a pushed `v*` tag.
   Its first job refuses unless the `ci` workflow's latest push run for the tagged commit
   concluded `success`, or the tag's annotation carries `ci-override: <who> <why>` (copied into
   the release notes; a lightweight tag cannot carry one). Its second job builds `rand-node`,
   `rand` and `rand-prover` on a clean `ubuntu-24.04` runner — fullnode at the tag, zkp-circuits
   at the tag's own `CIRCUITS_PIN` beside it, the compiler `rust-toolchain.toml` pins,
   `cargo build --release --locked`, `RAND_BUILD_SHA` = the commit — writes `SHA256SUMS`, attests
   build provenance over the three binaries, and creates the GitHub release with the CI run's id
   in its notes. Check a downloaded binary's provenance with
   `gh attestation verify <binary> -R randprotocol/fullnode`. No `gh release create` by hand for
   a fleet binary. The binaries need the glibc of Ubuntu 24.04 or newer.
2. **The signature: a person, off the build host.** The workflow does not sign. The release key
   holder downloads `SHA256SUMS`, checks the attestation, and signs the file on a machine that is
   not a build host and not CI:

   ```bash
   ssh-keygen -Y sign -n rand-release -f <key> SHA256SUMS      # writes SHA256SUMS.sig
   gh release upload <tag> SHA256SUMS.sig -R randprotocol/fullnode
   ```

   **The key is held off the build host**, preferably hardware-backed (`ed25519-sk`); its public
   half is one line of `deploy/release-signers`, and a change to that file is a reviewed change —
   whoever is listed there can authorise a binary that runs as root on the fleet. SSH signatures
   because `ssh-keygen` is on every host already.
3. **The check: every roll script, before it installs.** `deploy/lib/verify-release.sh`:
   `verify_release_sums <SHA256SUMS> <SHA256SUMS.sig>` refuses a missing signature, one that does
   not verify, one made for another namespace, a signer not in `deploy/release-signers`, and an
   allowed-signers file with no key in it; `verify_binary <file> <SHA256SUMS>` refuses a binary
   the signed file does not list at that sha256. `deploy/update-droplet.sh` and
   `deploy/roll-all.sh` take `RELEASE_SUMS` and `RELEASE_SIG`, verify first, and read the expected
   sha256s from the signed file. Without them they print that the install is unsigned and refuse,
   unless `ALLOW_UNSIGNED=1` says so on purpose. `SELFTEST=1 bash deploy/lib/verify-release.sh`
   runs the cases on a throwaway key (13 checks).

   ```bash
   gh release download <tag> -R randprotocol/fullnode -D rel     # rand-node, rand, rand-prover, SHA256SUMS, SHA256SUMS.sig
   RELEASE_SUMS=rel/SHA256SUMS RELEASE_SIG=rel/SHA256SUMS.sig \
     deploy/roll-all.sh rel/rand-node rel/rand "$(awk '$2=="rand-node"{print $1}' rel/SHA256SUMS)" "$(awk '$2=="rand"{print $1}' rel/SHA256SUMS)"
   ```

**What is not in place yet (2026-09-30), stated so nobody reads the above as done:**

- **`deploy/release-signers` lists no key.** Until the operator adds the public key,
  `verify_release_sums` refuses every release and the scripts install only with
  `ALLOW_UNSIGNED=1` — which is exactly the old trust model, now said out loud on every run.
- **`release.yml` has not produced a release.** Its first run is the first tag after this date.
  The releases up to v0.6.7 were hand-built and are unsigned.
- **`main` is not a protected branch and no review is required.** Both are repository settings
  the operator applies: protect `main` and the `v*` tags, require a pull request with one review
  and a green `ci` run before merge. Until they are applied, anyone with write access can change
  `deploy/release-signers` or the workflows without a second person seeing it.
- **The per-chain cutover scripts** (`deploy/cutover-fleet-chain18.sh` and earlier) still fetch
  and check a bare sha256; the next cut script sources `verify-release.sh` the same way it
  sources `cut-policy.sh`.
- **The guardian hosts.** A `rand` binary installed as root there can read the guardian keys. The
  audit asks that each guardian operator installs on the hosts they run, with a second person
  checking the hash; that is a process, not a script, and is not in place.
- **Reproducible builds** — two builders reaching the same hash from the tag — are the step that
  takes the build host out of the trust root altogether. Not attempted; it needs the clean-clone
  build first (PROC-2).

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
   proof (`research/tests/e2e.rs`, both `#[ignore]`d), the rVM tier-20 exit (tier 21 before the phase-2 row cuts; `recursion/tests/exit.rs`),
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

## Cut policy

Written 2026-09-30 (audit v6, OPS-7). Chains 15, 16, 17 and 18 went live on 2026-09-26 13:05,
2026-09-28 16:39, 2026-09-29 03:03 and 2026-09-29 04:56 UTC: four hard forks in 2.7 days, chain 17
replaced after 1 hour 53 minutes. Each was an all-stop of the fleet from one laptop on one
operator's go, with a genesis nobody else rebuilt; only chain 17's record says what it dropped
(130 RAND faucet-minted to a wallet the operator does not hold), and wallets, the explorer and the
site were not rebuilt for constraint set 8 before chain 18. None of that loses anyone's money
while every balance is the operator's to re-issue. Once anyone else holds a balance, a cut that
does not say what it carries can lose it. So, from the next cut on, **a chain cut needs all six**:

1. **A reason a rolling update cannot meet.** A changed validity rule, wire format or verifier
   key. A node-only change rolls onto the live chain (`deploy/update-droplet.sh`, or
   `deploy/roll-all.sh` when the fleet must never run mixed). A feature that is merely ready is
   not a reason; several fork-requiring changes wait and ship in one cut.
2. **A published list of what the cut carries and what it drops, written before the cut.** Every
   balance re-issued at genesis, by holder; every balance not re-issued, with its amount —
   **every non-operator balance in particular** — and unwithdrawn validator rewards. "Nothing" is
   written out, from a scan, not left blank.
3. **A client rebuild checklist, done before the cut**: the wallet CLI (`rand`), the clients
   repository's apps (desktop, web, extension, iOS, Android), randscan, the website's WASM, and
   the bridge relayer's `rand`. Each named with the version or commit built against the new
   chain. A chain no shipped wallet can send on is not live for anyone but the operator.
4. **Two people.** One authors the genesis. A second rebuilds it from the tag on another machine,
   and the two genesis hashes must match before anything is published or stopped. Neither is a
   session acting on the other's go.
5. **A rollback plan**: what stays on every host (the old chain's data dirs, the old binaries),
   for how long, and the steps back.
6. **A chain id never used before.** Signatures, the PQ co-signature and the bridge governance
   messages bind the chain id; ids 14 to 18 have not repeated, and that is what protects them.

**The mechanism.** `deploy/lib/cut-policy.sh` is sourced by a cut script and refuses, non-zero and
with the reason on stderr:

| function | refuses when |
|---|---|
| `require_cut_record <file>` | the record is missing, or has no non-empty `reason:`, `carries:`, `drops:`, `clients:`, `second-operator:` or `rollback:` line (an unfilled `<placeholder>` counts as empty) |
| `refuse_reused_chain_id <id>` | any `deploy/genesis*.json` in the repository already has that `chain_id`, the id is not a positive integer, or no genesis file can be read |
| `require_second_rebuild <file> <hash>` | the record's `second-hash:` line is absent or differs from the author's genesis hash |
| `require_key_separation_or_testnet <genesis.json> [status]` | `deploy/key-separation` (or `status`) says `met: no` and the genesis does not set `"testnet": true`; the status file is missing or has no `met:` line (audit v6, OPS-6: no mainnet genesis by one key holder) |

`deploy/cut-record.template` is the form; a filled record is committed and published before the
cut. `SELFTEST=1 bash deploy/lib/cut-policy.sh` exercises all four on temp files (44 checks). The
scripts that cut chains 15 to 18 do not source it — they predate it and are history; **the next
cut script must**, calling `require_cut_record`, `refuse_reused_chain_id` and (on the finished
file) `require_key_separation_or_testnet` before its first
step and `require_second_rebuild` before it pushes a genesis. The library checks that a record
exists and is complete. It cannot check that the record is true, that it was published
beforehand, or that the second operator is a second person: the record is the evidence for
those, and they are the operators' to keep.

### Key separation (a dated exception, 2026-09-30)

The audit's target (its option 1 under OPS-6, from the 29 September key-management policy it
cites; that policy is not in this repository): **at most 8 of the 26 validator keys, and at most
2 of the 8 guardian keys of each set, per person and per hosting account.** A holder of nine
validator keys can stop a quorum of 18 of 26; a holder of eight cannot. Meeting both caps needs
at least four independent operators.

**Not met, as of 2026-09-30.** All 26 validator keys are one operator's, and so are the guardian
keys (`AGENTS.md`, "Chain 15": the eight validators added on 2026-09-27 include the six guardian
hosts). One compromise of that operator's control plane is a quorum. Where the validator keys
generated on the laptop for chain 14 are backed up, and whether a live copy remains there, is not
recorded in this repository. This is carried as a dated exception, recorded here so that it is a
decision and not an oversight. **Schedule, set 2026-10-01 by the operator: by 2026-11-01, and
before any mainnet genesis**, 18 of the 26 validator keys and 6 of the 8 guardian keys of each set
go to three other operators, each on their own hosting account (names recorded here when they take
delivery), so no person or account holds more than 8 validator keys or 2 guardian keys. The
status is `deploy/key-separation` (`met: no`, `deadline: 2026-11-01`) and the mechanism is
`require_key_separation_or_testnet` in `deploy/lib/cut-policy.sh`: **while `met: no`, a cut
refuses any genesis that does not set `"testnet": true`** — a mainnet genesis cannot be cut by one
key holder by mistake; a passed deadline is warned about on every cut until a new date is set.
Until it is met, the network is a testnet run by its authors, and the bridge caps stay where they
are. When the keys are handed over: flip `met:` to `yes`, record the holders here, and only then
can a genesis without the testnet marker be cut.

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

## The chain-17 cut (v0.6.3, split authorisation)

Scripts: `deploy/cut-chain17-genesis.sh` (the genesis), `deploy/cutover-fleet-chain17.sh` (the
fleet), `deploy/chain17-bridge-steps.md` (the bridge session's half). **What changes:** the genesis
is cut with `rand-node genesis --hardening-v6 --bundle-guest v3 --auth-guest` — `hc_bundle` is the
v3 hidden-asset guest (`60af094a…`, `EXPECT_HC_BUNDLE`) and the new `hc_auth` (the auth guest's
digest, hashed after `hardening_v6`) is pinned by the operator from the v0.6.3 release binary
(`EXPECT_HC_AUTH`, defaulting to `guest_provenance.rs`'s pin `1e4e347f…39c1` and cross-checked
against what the built binary reports). A v3 transaction carries up to three proofs (bundle,
auth, call), so `Genesis::validate` requires `max_block_bytes ≥ 3·max_proof_bytes + 1 MiB` with
`hc_auth`: the cut halves the proof cap to 4 MiB (`MAX_PROOF_BYTES`, every admissible proof is
≤ 2 MiB by the zkVM cap; chain 16's 8 MiB would need 25 MiB blocks) and keeps 20 MiB blocks. Every
bundle then carries an auth proof, **every txid changes** (`rand-txid-3`), and **the wire changes**:
a v0.6.3 node refuses chains 14/15/16 at startup and a v0.6.1/v0.6.2 node cannot decode a chain-17
bundle, so the roll is all-stop/all-start onto a new genesis, chain 16's shape (26 validators, the
same keys, `faucet_minters` the 18 operator keys, the bridge's live set and a re-derived replay
floor). Wallets, the relayer's `rand`, randscan and the website move to v0.6.3 with it.

**The carry-over rule.** Chain 17 starts from chain 16's value, but only value whose opening the
operator can re-issue: zUSD as chain 16's per-backing `locked` with fresh genesis notes to the
holders in `ZUSD_CARRY` (Σ notes == Σ locked == source custody); RAND as one genesis alloc note per
wallet the operator holds, at its chain-16 balance; the vesting register re-emitted with each
entry's claimed amount subtracted; validator stakes as chain 16's register holds them (asserted,
not assumed). **Shielded notes of wallets the operator does not hold cannot be carried** — a
genesis note needs an opening — and the launch notes must say so. Two more things are refused
rather than silently dropped, each with an explicit opt-out: a validator with unwithdrawn
`rewards` on chain 16 (`REWARDS_DROPPED_OK=1` — rewards are never carried either way, withdraw
them first if that is not the intent) and a wallet reporting pending notes (`PENDING_OK=1`, a
note submitted but not yet confirmed is not in `balance` and would otherwise vanish with no
trace). **The vesting carry is an approximation, not the correct one**: the right carry is
`A·f(t) − C` (`A` = amount, `C` = claimed, `f` = the vesting curve), which the genesis format
cannot express without a `claimed` field; carrying `(A − C)` on the same schedule instead
front-loads `C·(1 − f(t))` — that much unlocks early — so an entry with `claimed > 0` is refused
unless `VESTING_CLAIMED_OK=1` accepts the approximation. **The `balances` step**
(`cut-chain17-genesis.sh balances <snapshot dir>`, read-only toward the chain, after `snapshot`,
while chain 16 is up) runs `rand sync` + `balance` + `notes` for every `*.key.json` under
`WALLETS_DIRS` (default: chain 14's and chain 15's `wallets/` and `payout/`, plus chain 16's
`wallets/` (since chain 16 has no `payout/` of its own yet) and `$FULLNODE_DIR/wallets` — this
repo's own gitignored `wallets/`, where the chain-16 genesis allocs `shielded-1..5` (the chain-15
cut's `ALLOC_WALLETS` default) actually live) against chain 16 and writes `ALLOC_ADDRESSES` from
the non-zero balances plus `balances.json` beside the snapshot; it refuses against a pruned
`CHAIN16_RPC` (a scan needs an archive). It also decodes chain 16's own genesis alloc notes' `pk`
and lists any that match no scanned wallet ("uncovered genesis allocs" — `UNCOVERED_ALLOCS_OK=1`
to drop them knowingly if a wallet's key file genuinely cannot be found). The cut asserts the
alloc list is those wallets one-for-one and Σ alloc ==
Σ scanned (`NO_BALANCES=1` is the explicit opt-out); it warns, but does not refuse, when an
operator wallet's Σ zUSD differs from `ZUSD_CARRY`'s (a non-operator holder like Anish's wallet
legitimately differs). A changed `FAUCET_RECIPIENTS` list needs `FAUCET_RECIPIENTS_CHANGED=1`,
the same rule chain 16 enforces. `EXPECT_HC_AUTH` has no compiled-in default — as of this build,
`crates/randprotocol-zkvm/tests/guest_provenance.rs` pins the bundle guest's v1/v2/v3 digests but
not the auth guest's — so read it from a Linux host after `stage`: `/root/rand-node.c17 genesis
--bundle-guest v3 --auth-guest --hardening-v6 …` and its printed `hc_auth`. `SELFTEST=1` runs the
assembly twice (once plain, once accepting the `VESTING_CLAIMED_OK=1` front-load) and sixteen
refusal cases on fixtures derived from `deploy/genesis-chain16.json` (eighteen checks total),
with no network and no binary; each refusal is checked against its expected reason phrase, not
just its exit code.

**Order and the gate.** `stage` → bridge stop → `snapshot` → `balances` → **the user's go, typed in
the executing session** → `stop` → cut → `push` → `switch` → `start` → `wait` → bridge restart →
`retire-chain-dirs.sh` for chain 16 after a day. `stage`, `snapshot`, `balances` and the cut are
reversible and need no go; `stop` does. Run every phase alone and read its `$?` (chain 16's trap: a
piped `push … | tail && … start` started the fleet after a failed push). `push`, `switch` and `wait`
refuse without `LOCAL_NODE` (a v0.6.3 `rand-node`); `start` refuses unless a successful `switch`
left `/tmp/chain17-switched-<genesis prefix>`.

## The next cut: genesis fields v0.5.4 introduces

The audit-v4 release (v0.5.4) added consensus rules that are switched on by genesis fields chain
14 does not carry, so that chain 14 runs byte-for-byte as before. The next cut's genesis sets:

- **`"consensus_domain": 1`** — every vote, new-view and proposal then carries the genesis hash
  (`docs/consensus.md`, "Signing domains"), so a validator signature for this chain verifies on no
  other. Absent or `0` is chain 14's behaviour; `2` and up are refused by `rand-node init`. The
  field is a top-level genesis key beside `epoch_blocks`; the cut script splices it in the way it
  splices the `bridge` section, since `rand-node genesis` writes today's shape.
## The next cut: genesis fields v0.5.5 introduces

- **`"tokens": { …, "burn_registration_fee": true }`** — a `RegisterToken`'s or
  `RegisterBridgedToken`'s `registration_fee` is burned instead of paid to the block's proposer
  (audit v5 TOK-2, `docs/tokens.md` §15): the proposer keeps `fee − registration_fee`, the fee
  joins `rand_getSupply`'s `burned` and `registration_fees_burned`. Absent or `false` is chain
  14's rule and commits nothing; `true` is committed to the genesis hash under its own tag and
  folded into the token root, so it ships with a chain cut, never as a same-chain update. Optional
  inside the `tokens` section the cut script already splices in.

## The next cut: genesis fields v0.5.6 introduces

- **`"tokens": { …, "bound_note_value": true }`** — no mint, initial mint or bridge deposit may
  create a note worth 2^63 or more, nor push an asset's `total_supply` to 2^63 (the hidden-asset
  guest's u63 range check makes such a note unspendable for ever; `docs/tokens.md` §16). Absent or
  `false` is chain 14's rule and commits nothing; `true` is committed under its own tag and folded
  into the token root. The admission screen refuses such an amount on every chain regardless.

## The next cut: the STAKE-2 re-review's `staking` fields

The v4 re-review found the gated `staking` section still lacked admission, a weight cap, proof of
possession and a delay for top-ups (`docs/staking.md` §2). Three optional fields inside the section
close them, each omitted from the file and from the genesis hash when absent; the bond queue that
delays top-ups is on whenever the section is:

```json
"staking": {
  "faucet_budget_per_epoch": "100000000000", "bond_activation_epochs": 2,
  "max_weight_bps": 3333, "max_stake_entry_per_epoch": "10000000000000", "registration_v2": true
}
```

- **`max_weight_bps`** (`1..=10000`) caps every validator's weight at that fraction of its set's
  total, genesis set included. 3333 keeps any one key below a blocking third on a set of four or
  more; a set smaller than ⌈10⁴ / bps⌉ is levelled to equal weights.
- **`max_stake_entry_per_epoch`** (decimal string, `> 0`) is the most stake that may become weight
  at one boundary; the rest waits in bond order. 10 000 RAND above is ten minimum bonds an epoch.
- **`registration_v2: true`** makes a `Bond`'s registration sign `rand-register-2` over the genesis
  hash and the validator's address: every validator that registers after the cut uses
  `rand-node register --v2`, and a v1 registration is refused.

A testnet cut that keeps its faucet beside the bridge (chain 15) adds the faucet allowlist to the
same section, and sets `"faucet": true` at the top level:

```json
"staking": {
  "faucet_budget_per_epoch": "100000000000", "bond_activation_epochs": 2,
  "max_weight_bps": 3333, "max_stake_entry_per_epoch": "10000000000000", "registration_v2": true,
  "faucet_recipients": [
    "rand1…the output of `rand --key ~/.rand-chain15/wallets/dendi.key.json address`…",
    "rand1…anish's address, as he sends it…"
  ],
  "faucet_minters": [
    "…the address `rand-node` prints for each operator validator key that may run the faucet…"
  ]
}
```

- **`faucet_recipients`** (non-empty, no key twice): a `Mint` pays only these wallets
  (`FaucetRecipientNotAllowed` otherwise, cached as permanent). Without it `faucet: true` beside a
  `bridge` section is refused (`FaucetWithBridge`). Each entry is a full `rand1…` address — what
  `rand address` prints — or its `pk` as 64 hex characters; only the `pk` is committed, so an
  address can be pasted as it is. `rand_mint` to any other
  address is refused at admission. **Mainnet never carries a faucet**, allowlisted or not — and
  since audit v6 (STAKE-2) that is a check, not a sentence: a genesis with `faucet: true` and a
  `bridge` section is refused at `init` (`FaucetWithBridgeNeedsTestnet`) unless its top level
  says `"testnet": true` (`rand-node genesis --testnet`), whatever its `staking` section and
  allowlist say; chains 14–18, cut before the marker, are grandfathered by chain id in
  `genesis::FAUCET_BESIDE_BRIDGE_CHAIN_IDS`. A mainnet genesis carries neither the faucet nor the
  marker, and `rand_status.testnet` / `rand_getLimits.testnet` tell every client which it is.
- **`faucet_minters`** (RESCAN-LEDGER-1; the next cut that keeps a faucet sets it, to the operator's
  own validator keys): a `Mint` may be signed only by these keys (`MinterNotAllowed` otherwise).
  Without it the ledger accepts any key with a register row — which a permissionless `Bond` writes,
  and which is in the active set two epochs later — and only every node's admission policy (the
  genesis validators) keeps a bonder from draining the budget. Each entry is a validator's base58
  address, its 64 hex characters, or its `public_key` hex; non-empty, no key twice, committed only
  when present.

Like the rest of the section: `rand-node genesis` never writes them, the cut script splices them
in, and `rand-node init` on the finished file prints the hash that matters. Chain 14 has no
section, and `rand-node`'s `chain_14s_genesis_file_still_builds_chain_14` pins its hash
(`1cff3b7d…`) against all of it; `chain_15s_genesis_file_still_builds_chain_15` pins chain 15's
(`cc30e085…`) against `faucet_minters`.

## The next cut: the bridge replay floor (C15-1)

A chain cut from another one's bridge keeps the source endpoints, their sequence counters and —
at a carried-over guardian set — their signers, so an old chain's already-minted lock is an
ECDSA-valid attestation on its successor (`docs/bridge.md` §23). The next bridged cut sets, inside
the `bridge` section the cut script splices in, beside `guardian_set_index` and `burn_sequence`:

```json
"bridge": { …, "min_inbound_sequence": { "2": <n2>, "3": <n3>, "4": <n4>, "5": <n5> } }
```

- **Each source chain's floor is one past the last lock the previous chain observed from it**:
  the highest `sequence` of any committed `BridgeAttest` transfer from that emitter chain, plus
  one — read off the old chain (or the guardians' signed-message stores) after its last mint and
  before it stops, the way the burn sequence and the residue custody are read. Drain in-flight
  locks first: a lock the old chain never minted but that sits below a minted one would be
  stranded under the floor (carry its custody at genesis instead).
- A source chain that never locked anything toward the old chain is left out (every lock on it is
  new). Keys must be chains in `emitters`, values above 0, and a present map non-empty
  (`rand-node init` refuses otherwise). The script should refuse to run with any floor unset, the
  way `cut-chain15-genesis.sh` refuses to guess the residue custody.
- Absent is chain 15's behaviour and commits nothing; present, it is committed to the genesis
  hash under its own tag and wraps the bridge root, so it ships with a cut, never as a same-chain
  update. `rand-node`'s `chain_15s_genesis_file_still_builds_chain_15` pins chain 15's hash
  (`cc30e085…`) against it.

**Until then — chain 15 runs without a floor — the rule is the guardians' (bridge.md §23):** a
guardian brought up with an empty store sets its source cursors past chain 14's last observed lock
(`start_block` for EVM/Tron sources, `start_sequence` for Solana) before it starts, never the
configuration's deployment block.

## The next cut: genesis fields address sharing and the encrypted memo introduces

Spec `docs/superpowers/specs/2026-09-26-address-sharing-and-memo-design.md` §2.3–§2.4.

- **`"envelope_bytes": 1860`** — every note-creating envelope (`Bundle.envelopes[..]`, `Mint`,
  `Withdraw`, `BridgeAttest`, `Aggregate`, `TokenMint`, `RegisterToken`'s initial mint, and a
  genesis alloc note) must be exactly 1860 bytes, which is what lets every one of them carry the
  fixed 512-byte encrypted memo field. Absent (chains 14 and 15 and every earlier chain) is today's
  rule byte-for-byte: an envelope at most `MAX_ENVELOPE_BYTES` (2048), no uniform size, and a memo
  refused by the wallet before proving rather than silently dropped. The ledger there still admits
  a memo-carrying 1860-byte envelope (it is under the 2048 cap) and a new wallet opens its memo, so
  **memos are live on chains 14 and 15 as soon as the new wallets ship**: anyone can pay a dust
  note with any memo to a public address. Every surface shows a memo through one display rule
  (`docs/cli.md`, "How a memo is shown"). `1860` is the only value `validate` accepts
  today — a future layout is a new value. Set with `rand-node genesis --envelope-bytes 1860`; the
  field is hash-bound last, and a genesis alloc note whose own envelope is not exactly 1860 bytes
  fails `Genesis::build` (`GenesisError::AllocEnvelopeSize`) rather than silently mismatching it.
- **Ship the apps and the website first, the genesis after.** A wallet built before this change
  cannot open a 652-byte sealed body (its `Note::from_bytes` sees 624 bytes and fails); a wallet
  built after opens both the legacy 112-byte body and the memo-carrying 624-byte one. So the cut
  order (spec §5) is: `randprotocol.org` and the wallet apps release the new core first, and only
  then does a genesis with `envelope_bytes: 1860` go live — never the other way, or a deployed
  wallet meets a form it cannot open at all.

## Address sharing release checklist

Task 17 (plan `2026-09-26-address-sharing-and-memo`) closed out the branch with a cross-repo
verification pass and this checklist. Per the user: **address sharing itself ships as v0.5.10**
(same-chain — nothing here changes the rules of chains 14 and 15, neither of which sets
`envelope_bytes`), right after this task and its review. The
`envelope_bytes: 1860` memo *rule* above is a separate, later event: it is not part of v0.5.10 and
does not go live until the v1.0 genesis (~chain 20, `rand-node genesis --envelope-bytes 1860`).
Everything that ships as v0.5.10 works against a chain without `envelope_bytes` exactly as it does
today (address sharing, the fingerprint, `randpay:` links, contacts) — only *sealing* a memo is
gated on a chain that carries the section. Opening one is not: a third-party sender can already
put a memo in a 1860-byte envelope on chains 14 and 15 (see above), and the new wallets show it.

### Step 1: final verification, one run per repo at the branch's final commits

| repo | commit | command | result |
|---|---|---|---|
| fullnode | the release commit (recorded at the release step) | (not re-run — see below) | 61/63 binaries clean, 1478 passed / 13 failed / 15 ignored; the 13 failures are the documented `RECURSION_FIXTURES` gap (`node::tests`/`rpc::tests`, all panicking at `agg_executor.rs:295`) and the `randprotocol-rvm --test aggregate` binary is the documented laptop OOM (SIGKILL) — both pre-existing laptop limits, not this branch |
| circuits (`research`) | `95c9072` | `cargo test --release --test viewing` | 19 passed, 0 failed |
| randscan-viewing | `b889519` | `cargo test` | 8 passed, 0 failed (lib 0 + `memo.rs` 3 + `rpl_disclosure.rs` 1 + `vectors.rs` 4) |
| website | `4b8e276` | `node --test tests/` | 28 total, 27 passed, 1 skipped (`LIVE_KEY`, needs a live node — expected), 0 failed |
| website `server/address-wasm` | `4b8e276` | `cargo test --release` | 9 passed, 0 failed |
| clients (`ui`/`web`/`extension`) | `96b9999` | `node --test ui/test web/wallet/test extension/test` | 772 passed, 0 failed, 0 skipped — includes `web/wallet/test/core.integration.test.mjs` run for real (not skipped): the wasm core was already built (`core/target/wasm32-unknown-unknown/wasm/wallet_wasm.wasm`, from Task 13) |
| clients `core/` | `96b9999` | `cargo test --release` | 78 passed, 0 failed |
| clients `android/` | `96b9999` | `./gradlew testDebugUnitTest --rerun` | 28 tests (Amounts 2, Contacts 7, NoteStore 6, SendLink 13), 0 failed, 0 skipped |
| clients `ios/` | `96b9999` | `xcodebuild test` on iPhone 18 Pro simulator | 31 tests, 0 failures |

fullnode's full suite was not re-run here per the controller's ruling: it ran in full at the end
of Task 9 (log: `.superpowers/sdd/2026-09-26-address-sharing-and-memo/memo-suite.log`), and the
release step records the commit it ships and the suite run against it. Every other repo's commit
matched the plan's final list exactly; every suite is green (the one `LIVE_KEY` skip is a
pre-existing, expected skip — it needs a reachable live node).

### Step 2: the bridge relayer

`grep -rn "seal_note\|Envelope::seal\|envelope\|BridgeAttest" ../bridge --include='*.rs'` finds no
envelope-sealing code in the bridge repo (`/Users/dendisuhubdy/Github/randprotocol/bridge`) at all,
and no Cargo dependency on `randprotocol-client` or `randprotocol-core` from the `daemons` crate
(only `tools/vectors`, an unrelated test-vector helper, depends on `randprotocol-core`).
`daemons/src/submit/process.rs`'s `RandSubmitter::mint` reaches Rand by shelling out to the `rand`
CLI's `bridge-mint` subcommand (`daemons/src/submit/process.rs:5-6`: *"Rand, through the wallet's
`rand bridge-mint`, because minting a deposit means sealing a note and proving a fee bundle, which
is the wallet's job"*) — it writes the attestation (and, for a PQ quorum, the co-signature list) to
a scratch file and runs `rand bridge-mint @<file> --to <address>` as a child process.

**Verdict: nothing to change in the bridge repo, and no blocker.** The relayer never builds a
`BridgeAttest` envelope itself; sealing is entirely the `rand` binary's job, and Task 7 already
made every one of the wallet's sealing sites (including the `bridge-mint` deposit path in
`randprotocol-client/src/main.rs`, which seals through `wallet::deposit_note_for`) fetch `rpc.envelope_format()` and seal through
`seal_note_as`. The only operational requirement is that the `rand` binary the relayer's host
invokes be rebuilt from a fullnode commit at or after Task 7 before the launch genesis is cut —
an ordinary binary update, not a bridge-repo code change.

### Step 3: the release order

1. **Apps and website released with the new core.** `randprotocol.org` (worktree `/tmp/site-memo`,
   `4b8e276`) and every wallet app (`clients`, `/tmp/clients-memo`, `96b9999`: web wallet, desktop,
   browser extensions, iOS, Android) ship the code that reads both the legacy 112-byte note body
   and the 624-byte memo-carrying one, and that speaks `randpay:` links, fingerprints and contacts
   — all of which work unchanged against today's chains (no `envelope_bytes`). This is what makes
   the later genesis cut safe: every deployed client can already open the longer form before any
   chain produces one.
2. **randscan deployed with Task 10.** `randscan-viewing` (`/tmp/randscan-memo`, `b889519`) opens
   both note-body layouts and reports `"memo": string | null` from `open_note`; deploy it to the
   explorer (E) alongside or before the genesis cut, so `/account`'s viewing-key disclosure and the
   sale service's balance reads keep working once a memo chain exists.
3. **The launch genesis cut with `rand-node genesis --envelope-bytes 1860`.** Per the spec and the
   "next cut" section above, this is a *future* chain (~chain 20, v1.0) — not part of v0.5.10. When
   it happens: cut with the flag, confirm `Genesis::build` accepts every alloc note at exactly 1860
   bytes (`GenesisError::AllocEnvelopeSize` on a mismatch), and roll the fleet as any other chain
   cut (`docs/deploy.md`'s topology rules; validators first via the bootstraps, then the rest, node
   A last).
4. **After the cut, verify:**
   - `rand_getLimits.envelope_bytes == 1860` on every node (validators and observers alike — a
     stale or misbuilt node would still answer `null` or an older value).
   - A faucet mint's envelope is exactly 1860 bytes (`rand_mint`, then read the committed
     transaction's envelope length back — the same check `under_envelope_bytes_every_alloc_envelope
     _is_exactly_that_long` and `on_a_memo_chain_every_output_is_1860_bytes_and_the_payee_reads_the
     _memo` make in the test suite, now against the live chain).
   - A payment with a memo round-trips end to end on the live chain: the payee's scan and the
     sender's `history` both show it, and `rand_checkTransaction` with the output's tx key discloses
     it — the same shape as the wallet-flow test (Task 9), now manual and against mainnet.

### Known untested items (carried forward, not blockers for v0.5.10)

- **iOS: pre-filled Send not observed on the simulator.** Task 15's simulator smoke got the OS
  "Open in Rand Wallet?" prompt (confirming the `randpay` scheme is registered) but nothing on that
  machine could tap through the unlock prompt to see Send actually pre-filled — Simulator.app was
  not at the expected Xcode path and neither `cliclick` nor `idb` was available. Logic is covered by
  `SendLinkTests`/`LinkHandoffTests` (unit tests), not by an observed run.
- **Android: camera scan of a real QR, and the review/prove screens, not exercised on device.**
  Task 16's emulator has a synthetic virtual camera (no way to show it an actual QR — scan and
  paste share the same resolution code path, which *was* exercised), and the emulator wallet held
  0 RAND with the public faucet returning HTTP 429, so the Review screen, its confirmation line and
  a real proof were never driven end to end on device — only by unit tests.
- **macOS: OS-level `randpay:` routing needs a built `.app`.** Task 14's desktop deep-link wiring
  (`tauri-plugin-deep-link`) is verified against the plugin's own vendored source and by unit tests
  only; the scheme is read from the Info.plist a real `cargo tauri build` generates, so a manual
  pass (`cargo tauri build`, then `open "randpay:rand1...?amount=1"` against the installed app) is
  still owed at release time.
- **Website: the saved-account share block awaits the account save flow.** Task 11's `[data-acct-
  share]`/`[data-acct-address]` wiring on `/address` activates automatically (via a
  `MutationObserver`) once a sign-in/save flow exists, but `randprotocol.org` has no such flow yet
  in this worktree (no `src/scripts/account.js` or equivalent) — this predates address sharing and
  is out of this branch's scope, so it is untested against a real save, not broken.

### Every push waits for the user's go

Nothing in this checklist authorizes acting on it. Every `git push` of every branch above, the
website deploy, every app-store upload, and the genesis cut itself each wait for the user's
explicit go, typed in the session that will do it — per the standing rule that a relayed go is not
authorization for a fleet-wide or public-facing action (see "Repo workflow traps" and the memory
note on fleet gos).

## The next cut: `hardening_v6` (the v0.6 switch)

The 2026-09-27 zkVM/ISA review's R4: every stricter validity rule on a live path (its class H)
ships behind **one** top-level genesis field, so one cut turns them all on together. The next cut
sets:

```json
"hardening_v6": true
```

Absent or `false` commits nothing and is chain 15's rules; `true` is committed to the genesis hash
under its own tag. Until a genesis carries it, each rule below is every node's **pool policy** (a
node on this build never pools or forwards what the rule refuses), and a block from an older
proposer that carries such a transaction still applies. `chain_15s_genesis_file_still_builds_chain_15`
pins `cc30e085…` against the field. The rules, one subsection each:

### The program pc window (ZKV-11)

A `Deploy` whose *padded* program table — `max(len + 1, 16)` rounded up to a power of two rows,
and never fewer than 128 (the table a hardened call declares, `2^MIN_PRIVATE_TABLE_LOG_HEIGHT`;
PCW-FLOOR, the v0.6 rescan: measured unfloored, the window admitted fib at `0xffffffc0`, whose
floored proof is refused), four bytes a row — runs past the u32 pc wrap can never be proven (the circuit does PC arithmetic
in the field, the emulator wraps), yet ZH4's `check_program` bounds only `base_pc + 4·len`: fib's
15 words at `0xffffffc4` deploy and are uncallable for ever. (It first shipped on `feat/v0.6` as
its own `program_pc_window` flag; no genesis ever carried that, and it is folded in here.)

- Under `hardening_v6`, `base_pc + 4 · rows > 2^32` is `BadProgram` at admission and at apply
  (`program::pc_window_fits`).
- **Every node already refuses such a deploy at its pool, on every chain** (node policy, cached as
  a byte verdict like the note-value screen); a block from an older proposer that carries one still
  applies until the flag is set. Nothing live is affected: every chain-15 program sits at
  `base_pc` 0.
- The verifier- and prover-side fixes (bound the table in the circuit, refuse to prove) are the
  zkVM's, upstream.

### The callable program size (CPU-1)

Every proof pays one Poseidon2 permutation per four program words before it executes anything,
plus one for the empty input's salt row and one for the (empty) public segment's header. A call is
capped at tier 14 (`MAX_CALL_TIER`), whose Poseidon2 table holds `2^(14-3)` = 2 048 permutations,
so a program has at most 2 046 digest rows: **8 184 words**, fewer beside a public input
(`max(1, ⌈n/4⌉)` slots for `n` public words). Chain 15's genesis admits 65 535-word programs, so a
larger one deploys, is charged `deploy_fee`, and can never be called — the shipped EVM interpreter
(18 009 words) and sBPF interpreter (8 317) among them.

- Under `hardening_v6` such a deploy is `ProgramUncallable` at admission and at apply
  (`ConfidentialExecutor::max_callable_program_words`, the prover's own terms —
  `randprotocol_zkvm::executor::max_callable_program_words`, pinned one word either side against
  `build_traces_salted`).
- Every node already refuses it at its pool (`admission::deploy_uncallable`), as a non-permanent
  Ignore: the bound follows the build's call tier cap, which a later build may raise.

### The call binding (INT-4)

A call proof is not bound to its transaction today, so a copy of someone's call proof attached
under another fee bundle yields a second receipt. Under `hardening_v6` every call must carry
`Transaction::call_binding` — the transaction with its bundle proof and call proof blanked, under
`rand-call-bind-1`, which covers the fee bundle's nullifiers — in its public segment
(`ConfidentialExecutor::verify_call_hardened`): the whole segment for a program deployed without a
public input, and after the program's deploy-time public words for one deployed with them
(`program::hardened_call_segment`, `public ‖ call_binding`; issue #55). The same proof
under another fee bundle is refused, and the nullifiers spend once, so one proof yields one receipt.

- **Flag-only, no pool policy**: every wallet in the field proves the empty segment, so screening
  for the binding at the pool would refuse every call on chain 15. A wallet learns the flag from
  `rand_getLimits.hardening_v6` and then proves the call inside the submission
  (`wallet::submit_bound_call`): notes chosen and the fee fixed from the call's tier first
  (`executor::call_tier`), the input envelope sealed, the call proved over the call binding, the
  bundle proved last.
- **Programs with a public input (issue #55, v0.6.1)**: the ledger now keeps each program's
  deploy-time public words (`Ledger::program_public`, outside the state root — the program id
  already binds them — restored from the node's `program_public` column at open and checked against
  the record's digest there), so such a call is bound too. The guest reads its public words at the
  same indices; only `H_PUB` moves. Before, such calls kept the recorded digest and stayed unbound.
- Under the flag the CPU-1 bound is taken with the segment a call carries, `public.len() + 8`
  words: 8 180 for a program without a public input.

### The program-table floor (PROGRAM-TABLE-LEAK)

The program table carries each instruction's fetch count — a call's control flow — and a committed
table is hiding only while it has more random rows than the proof opens (80 FRI queries plus two
out-of-domain points). The prover already floors the input, keccak and sha256 tables at 2^7 rows
(COV-2 / INT-6), but the chain pins a call's program-table height to the deployed record's, so every
program under 64 words proves at 16–64 rows and publishes its fetch counts: all 105 programs on
chain 15 are 43 words.

- Under `hardening_v6` a call declares `max(record height, 7)` (`executor::
  hardened_program_log_height`): the wallet's hardened prover emits it (`prove_call_hardened`, a
  taller table is padding the AIR allows, the same `hc`) and `verify_call_hardened` pins exactly
  it; `warm_hardened` builds those keys. Without the flag nothing changes, and the old rule refuses
  a floored proof. No pool policy: every wallet in the field declares the record's height.
- Calls already committed on chain 15 stay exposed; only a cut stops new ones leaking.

### Canonical proofs (INT-5, VERIFIER-2, VERIFIER-1)

A proof header or transcript field the verifier accepts at more than one value lets whoever relays
a transaction re-encode its proof into a second transaction id (`Transaction::hash` takes a proof
by digest) — the sender's wallet then reports its own payment as not committed — and lets a bundle
take a shape no aggregate can cover. `randprotocol_zkvm::executor::non_canonical` pins each such
field to the honest prover's value, for bundle and call proofs alike:

- **The memory table's height** (INT-5 / HB-2): exactly `t + 2` for a proof without a keccak or
  sha256 table — 16 for every bundle. A bundle declaring 17 verified. With a hash table the honest
  height depends on the run's access count, not on the header, so it is capped rather than pinned
  (issue #56): at most `executor::hash_bearing_mem_log_height_ceiling` of the declared tier and
  hash-table heights, which leaves one or two encodings where the verifier's range left up to a
  dozen. A pin needs the prover to declare the ceiling itself — a circuits change, next
  constraint set (#52).
- **The FRI folding schedule** (VERIFIER-2 / V-VERIFIER-1): the per-round `log_arity` the verifier
  accepts at any value that folds onto every input height; pinned to the prover's greedy schedule,
  re-derived from the declared shape (`executor::honest_fri_arities`, checked against calls at
  tiers 10/12/14 and a bundle).
- **The random-codeword openings** (V-VERIFIER-1): four random values at every opened point of a
  randomised round, none in the preprocessed round — a count the hiding PCS's verifier does not
  check.
- **The commit-phase proof-of-work words** (VERIFIER-1): zero. At 0 grinding bits the verifier
  never reads them, so a relayer could rewrite one and commit a second encoding of someone's bundle
  under another transaction id.

Under `hardening_v6` a transaction carrying such a proof is `NonCanonicalProof` at admission and at
apply (`ConfidentialExecutor::non_canonical_proof`, before either proof is verified). Every node
already refuses it at its pool (`admission::non_canonical_proofs`), as a non-permanent Ignore.

## The chain-17 cut: split authorisation (`--bundle-guest v3 --auth-guest`, v0.6.3; live 2026-09-29)

Delegated proving Phase 2 (`docs/prover.md` §8, `docs/shielded.md` §2) is genesis-gated and a hard
fork: `rand-node genesis --bundle-guest v3 --auth-guest` pins `hc_bundle`
`60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce` and `hc_auth`
`1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1` (the pins in
`crates/randprotocol-zkvm/tests/guest_provenance.rs`; the build that cuts must print the same). The
two flags come as a pair, both ways. The v0.6.3 build refuses chains 14–16 at `run` and `verify`,
so it rolls only onto a new genesis, all-stop/all-start; wallets, the prover and the bridge
relayer's `rand` move with it. The cut procedure is "The chain-17 cut" (it arrives with the
chain-17 scripts).

## The next cut: the gas section (chain 18)

Spec `docs/superpowers/specs/2026-09-28-gas-model-design.md` §3.2–§4.3, §7.1. **Built on
`feat/gas-chain18`, not yet cut** — see the AGENTS.md v0.6.6 entry for the review traps and
gate counts. Chain 18 follows chain 17 (live since 2026-09-29, v0.6.3): it carries chain 17's
split authorisation (bundle guest v3 + `hc_auth`), its caps (4 MiB proofs, 20 MiB blocks — room for
three proofs), its validators, bridge state and value, and adds the genesis `gas` section
(optional, absent from every chain up to and including 17 and hashed in only when present, after
`hc_auth`). **Chain 18 also turns the encrypted memo on** (the user's ruling): the cut passes
`--envelope-bytes 1860` (the v0.5.10 field — every note-creating envelope exactly 1 860 B,
`rand_getLimits.envelope_bytes == 1860`, wallets seal the memo form). `rand-node genesis
--envelope-bytes` seals its own `--alloc` notes in that form; the zUSD carry notes come from
`rand-node alloc-note --envelope-bytes 1860` (without the flag it writes the legacy 1 348-B form,
which the genesis refuses), and the cut asserts the field and every alloc note's 1 860 B. The gas
section:

```json
"gas": { "gas_price": "100", "byte_price": "800", "bundle_gas_limit": 20479, "metering": "circuit",
         "dynamic": { "target_block_bytes": 10485760, "target_block_gas": 262144,
                      "adjust_bps": 1250, "min_gas_price": "100", "min_byte_price": "800" } }
```

- **`gas_price`, `byte_price`** (decimal strings, `> 0`): the starting units of RAND per gas and
  per KiB of call proof plus input envelope. A call's floor is `BUNDLE_BASE + gas_price·GAS_LIMIT
  + byte_price·⌈bytes/1024⌉`, priced at the proof's own declared `GAS_LIMIT`, not the header's
  ceiling (`docs/fees.md` §1.1).
- **`bundle_gas_limit`** (exactly `20479`): every bundle proof's declared `GAS_LIMIT` must equal
  this exactly, or the proof is refused (`TxError::BundleGasLimit`, permanent). It must be
  `gas_max(14, 0, 0) = 20479` for today's tier-14 hidden-asset guests (v1, v2 and chain 18's v3),
  and genesis refuses any other value (`GasConfig::check`, `gas::bundle_gas_limit_pin`) — any
  other value would mean no real bundle could ever be admitted. On a split-authorisation chain the
  auth proof is pinned the same way with no field of its own: `gas_max(10, 0, 0) = 1279`
  (`gas::auth_gas_limit_pin`, `TxError::AuthGasLimit`, permanent).
- **`metering`**: only `"circuit"` parses; the field exists so a later metering scheme has a name.
- **`dynamic`** (optional, Phase 2 — absent means the two starting prices never move):
  `target_block_bytes` (`1..=max_block_bytes`, the ledger's effective cap; half `max_block_bytes`
  by convention — 10 485 760 for chain 18, whose cap is 20 MiB) and `target_block_gas` (`> 0`)
  are what the controller measures fullness against; `adjust_bps` (`1..=5000`) is the largest
  one-block price move, in basis points, in either direction (`gas::next_price` caps `used` at
  `2·target` before the formula); `min_gas_price`/`min_byte_price` (decimal
  strings, each `<=` the section's own starting price) are the floors the controller never crosses,
  and each must satisfy `min_price · adjust_bps >= 10000` — a floor under that bound could never
  rise again once reached (`docs/fees.md` §1.2).
- **Refused beside an `aggregation` section** (`GenesisError::DynamicGasWithAggregation`) whenever
  `dynamic` is set: a pruned bundle's marker form encodes shorter than its raw form, so a node
  syncing sealed history would compute a different `bytes_used` than a live-synced one and diverge
  on the byte price. A fixed-price `gas` section (no `dynamic`) is not affected — its prices never
  move, so nothing about sealed-form sync depends on them.

**Constraint set 8 changes every verifier key** (the cpu AIR itself changes, `docs/confidential.md`
"Constraint set 8"), so — like every prior constraint-set cut — this is **all-stop, all-start**, no
mixed-fleet path: a v0.6.3 node cannot verify a cs8 proof and vice versa, and a v0.6.6 node refuses
chains 14–17 by genesis hash (`node::CHAINS_THIS_BUILD_CANNOT_RUN`). **Clients and randscan
rebuild against cs8 first**, same rule as constraint sets 5–7: a wallet or explorer built before
the cut cannot prove or verify anything the new chain admits.

`rand-node genesis --gas-price <UNITS> --byte-price <UNITS> --bundle-gas-limit <N> [--gas-dynamic
<target_bytes>,<target_gas>,<adjust_bps>]` writes the section (`--gas-price` is what turns it on
at all; the other three flags are meaningless without it, and default to `800`, `gas_max(14, 0,
0)` and "off"). `rand-node genesis`/`init` print `gas: price P/gas, B/KiB, bundle limit N,
dynamic: …` (or `gas: none`) on the finished file — the hash that matters, as with every gated
section. `deploy/cut-chain18-genesis.sh` is derived from `deploy/cut-chain17-genesis.sh` (the
same snapshot → `balances` → cut, with chain 17 as the source: its live register, bridge, zUSD
custody and the operator's RAND, scanned from the curated `~/.rand-chain17/alloc-wallets` through
an SSH tunnel to obs1 with the v0.6.3 `rand`; the bridge emitters stay chain 17's — the endpoint
redeploy waits); it writes chain 18's testnet defaults (the JSON above) and asserts the section is
present, `dynamic` is set with the right target/adjust/floor values (the byte target half of
`max_block_bytes`), `envelope_bytes` is 1860 with every genesis note in that form, the guests and
`hc_auth` are chain 17's, and no `aggregation` section rides
beside it. `SELFTEST=1` runs its assembly on fixtures; `DRY_RUN=1 NODE=… WALLET=…` runs the real
cut path — `rand-node genesis` with the gas flags, `alloc-note`, both `init`s, which print the gas
section — on inputs synthesised from `deploy/genesis-chain17.json`, into a temp dir.
`deploy/cutover-fleet-chain18.sh` (from chain 17's) is the all-stop/all-start roll;
`deploy/chain18-bridge-steps.md` has the bridge relayer's own rebuild step.

## The next cut: gas price ceilings and the paying byte load (audit v6, POOL-2)

Audit v6 (§8.22): chain 18's byte price follows every transaction's bytes while only a Call pays
it, and has no ceiling — a stream of transfers lifts it without bound. Three optional fields
inside `gas.dynamic`, each hashed only when set, so chain 18's genesis (which sets none) hashes
and behaves byte for byte as before:

```json
"dynamic": { …chain 18's five fields…,
             "max_gas_price": "10000", "max_byte_price": "80000", "byte_load": "paying" }
```

- **`max_gas_price`, `max_byte_price`** (decimal strings, each ≥ the section's starting price;
  `GasConfig::check` refuses less): the ceilings. Pick them as the multiple of the start the
  chain is willing to charge a call at its busiest — 100× is a bound at ~0.4 RAND for a 1.3 MB
  call against chain 18's unbounded 1 000×-and-rising. `rand-node genesis --max-gas-price
  --max-byte-price`.
- **`byte_load: "paying"`** (`rand-node genesis --gas-byte-load paying`): `byte_price` moves by
  the bytes that pay it — each Call's proof and input envelope — not by every transaction's
  length. Under it a block of transfers gives no byte-price signal; the proposer's reservation
  of a quarter of the block for pooled Calls (node policy, live on every build from this one) is
  what keeps a Call in the block then.

Check on the finished file: `rand-node init` prints `ceiling …/…, byte load paying` in its gas
line, and `rand_getLimits` on the first node serves `max_gas_price`, `max_byte_price` and
`byte_load: "paying"`. Wallets need no rebuild: the headroom they pay is unchanged and
`rand_getLimits` keeps every field it had.

## The next cut: a `vesting` section is fit to carry (audit v6, STAKE-3, STAKE-4)

Audit v6 (§8.13) said: put no `vesting` section in any genesis until a revoke's destination is
pinned. It is now — and a revoke has its own nonce and takes the whole unvested part (STAKE-4) —
so the section may ride the next cut that needs it (the v1.0 genesis, after a testnet rehearsal). No chain has carried one; a genesis without it hashes and behaves exactly as
before. What the cut passes, per **revocable** entry of the `--vesting` file (`docs/vesting.md`):

- **`revokers`**: 1–5 distinct Dilithium2 public keys, none the beneficiary's. Use three, held
  by three parties; each party generates its own (`rand-node keygen`) and sends only the public
  key. The list's order is a term: a revoke names its signers by position.
- **`threshold`**: how many of them sign a revoke — required, no default. Use `2`.
- **`treasury`**: the `rand1…` address a revoke pays, the only one it may. Create the treasury
  wallet and back up its key **before** the cut: the address cannot be changed afterwards, and
  `rand-node genesis` refuses one whose ML-KEM key does not decode.

An irrevocable entry (investors, partners) names none of the three. The old one-key `revoker`
field is refused. Check before `rand-node init`'s hash is published: every team entry shows
`"revocable": true`, three `revokers`, `"threshold": 2` and the treasury's address in
`rand_getVesting`; every investor and partner entry shows `"revocable": false`. Rehearse one
revoke on the testnet cut with two of the three keys on separate machines (`vesting revoke
prepare` → `sign` ×2 → `submit`, inside 256 blocks) and open the note with the treasury wallet.
The chain-18 cut script's vesting carry reads `rand_getVesting`'s `amount`/`claimed`/`revoked_*`
fields, which are unchanged; a cut that carries a register forward must also carry each entry's
`revokers`, `threshold` and `treasury`, which the genesis file holds, and must not re-list a
revoked entry on its old schedule (its `vested` is frozen at `revoked_at`, and what is left after
`claimed` and `revoked_out` is the treasury's, not the holder's).

## The next cut: `binding_domain` (audit v6, BIND-1, issue #79)

**What it is.** Votes, new-views and proposals have signed the genesis hash since
`consensus_domain: 1`; v2 registrations and the vesting messages bind it too. Everything else a
user or an operator proves or signs bound the **chain id alone**: the eight-word binding every
bundle, auth and call proof is made over (`Transaction::binding`, `call_binding`) and the signed
messages of a faucet `Mint`, `Unbond`, `Withdraw`, an RPL `TokenMint`/`SetAuthority`, the
aggregator register actions and the bridge governance actions (pause, unpause, register, list,
the two rotations). Two chains sharing a chain id — a re-cut, a private copy — would accept each
other's proofs and signatures; that chain ids 14–19 never repeated was the only protection
(`deploy/lib/cut-policy.sh` now refuses a reused id, OPS-7). The top-level genesis field
`binding_domain: 1` puts the genesis hash first in every one of those preimages under a fresh tag
(`rand-tx-bind-2`, `rand-call-bind-2`, `rand-mint-3`, `rand-unbond-2`, `rand-withdraw-2`,
`rand-rpl-mint-2`, `rand-rpl-authority-2`, `rand-aggregator-{register,unbond,withdraw}-2`,
`rand-aggregate-3`, `rand-aggregate-bind-2`, and the bridge's `…-2` fixed layouts with the 32-byte
hash between the tag and the chain id — `crates/randprotocol-core/src/types/binding.rs`,
`bridge/gov.rs`). The binding is a *public input* of the proofs — the wallet, a prover service
and the ledger compute it and hand it to the circuit — so nothing in any guest or verifier key
moves (`guest_provenance` stays green). A genesis-bound registration is exactly the v2 message,
whether or not `staking.registration_v2` is also set. Absent or `0`: chains 14–19's messages,
byte for byte, pinned by `the_chain_id_domain_is_the_messages_chain_18_signs_byte_for_byte`.

**What the cut passes.** `rand-node genesis … --binding-domain 1` — from **chain 20**, the first
chain that can carry the field: chain 19 is the v0.6.7 re-genesis, cut without it, and is pinned
with 14–18 in `CHAIN_ID_BINDING_CHAIN_IDS`. The field is tagged and
appended to the genesis hash after `gas`, only when present; `rand-node genesis` warns when a
chain id outside 14–19 is cut without it, because **no wallet can transact on such a chain**:
`randprotocol_client::CHAIN_ID_BINDING_CHAIN_IDS` (= 14–19) pins which chain ids get the
chain-id form, and a wallet uses the genesis-bound form on every other id, over the genesis hash
its note store is bound to — never the node's `rand_getLimits.binding_domain` claim, which it
reads only to refuse early (the `envelope_bytes` trap, issue #64). A node lying about the hash
can only make that wallet's own transactions invalid (a genesis-bound binding verifies on exactly
the chain whose genesis hash it carries); it cannot make them valid on a second chain, which is
what BIND-1 is about. **A cut without the field must add its chain id to that list first**
(`every_committed_genesis_without_binding_domain_is_pinned` fails until it does) — do not: cut
with the field.

**Every signer of an action message must be on a build with the field before the cut**, as with
every prior message change: the wallet (`rand` — `wallet::binding_domain`), the operator commands
(`rand-node register/unbond/withdraw/aggregator …` — `RpcClient::binding_domain`), the aggregate
daemon, and **the bridge repository's `rand-bridge-gov`**, whose pause, unpause, register and
list signatures must be made over the `…-2` layouts (`docs/bridge.md` §21, "BIND-1") — a pause
file signed in the chain-id form is refused `BadPauseSignature` on a `binding_domain: 1` chain.
The clients repository (wasm core, the apps) and randscan must carry the same chain-id rule.

**Already genesis-bound, so not re-domained:** `AdmitValidator`'s votes (`rand-admit-validator-1
‖ genesis ‖ candidate`, on every chain) and `SlashEquivocation`'s evidence (two block signatures
under the consensus signing domain; genesis validation refuses `staking.slashing` without
`consensus_domain: 1`, so that evidence always carries the genesis hash).

**Not re-domained (deliberately, out of this repository's hands):** the mint co-signature
`rand-bridge-pq-cosign-1 ‖ chain_id ‖ mu` the guardian daemons sign. It still binds the chain id
only, so a same-id copy of a chain that also copies the guardian set would accept a deposit's
co-signatures; binding it needs the guardian daemon (another repository) to sign
`rand-bridge-pq-cosign-2 ‖ genesis ‖ chain_id ‖ mu` and the ledger to verify it under the flag.
Recorded in `docs/bridge.md` §21 as the open half; the attest transaction's own fee bundle is
genesis-bound, the attestation body inside it is not.

**Tests that pin it:** core `ledger::bind_tests` (a transfer, an auth proof, a hardened call, a
mint, unbond/withdraw, a registration, each made for genesis A refused on B with the same chain
id, and the chain-id form refused under the flag), `tokens::action_tests::under_binding_domain_…`,
`aggregation::admission_tests::under_binding_domain_…`, `bridge_gov::tests::under_binding_domain_…`,
`genesis::tests::a_genesis_with_binding_domain_1_…`; node `a_restart_restores_the_binding_domain`;
client `the_binding_domain_is_the_chain_ids_never_the_nodes_claim`; `split_auth` (chain 20, real
proofs under the flag) and `wallet_flow` (chain 7 under the flag); `cluster` and `zusd_e2e` moved
to chain id 18 so their hand-signed chain-id messages stay today's.

### CH-8 re-verified (audit v6: 8a–8d, "chain-id binding, faucet key, quick-verify, guest wrap")

The audit's registry names the four halves of CH-8 without their text; what each is in the tree
today, as re-read on 2026-10-01:

- **8a, chain-id binding** — BIND-1 above: closed by `binding_domain: 1` at the next cut; until
  then chains 14–19 bind the chain id only, as before.
- **8b, the faucet key** — a faucet mint is signed by the node's *validator* key
  (`Node::mint`, `crates/randprotocol-node/src/node.rs`: `Keypair::from_seed(self.cfg.seed)`),
  the one key that also signs its votes. What bounds it: the message is domain-separated from
  every consensus message (`rand-mint-2`, `rand-mint-3` under the flag — a mint signature can
  never be read as a vote or a new-view, and vice versa); the ledger admits a mint only from a
  register row and, under `staking.faucet_minters`, only from the genesis list (`ledger/mod.rs`,
  `MinterNotValidator` / `MinterNotAllowed`); `rand_mint` is refused on the public listener
  (`rpc.rs`, `PUBLIC_METHODS`) and metered on the operator's; the faucet is off on mainnet by the
  cut policy. Not changed: a separate faucet key would be a genesis change (a `faucet_minters`
  entry that is not a validator) and the faucet is a testnet-only feature — recorded, not fixed.
- **8c, quick-verify mode** — `rand-node run --verify-chain quick` is the default
  (`main.rs`, `verify_chain`; `storage.rs`, `VerifyMode`): at startup every block's hash links,
  indexes, QC/block match and tx roots are checked and the ledger replayed against every
  header's state root, with bundle proofs re-verified; **QC votes are not verified** — `full`
  does that too. It is a check of the node's *own* disk, not of anything a peer sends (synced
  blocks are fully verified on arrival, `apply_synced`); a QC on disk that no quorum signed can
  only have been written by whoever writes the data directory. On a pruned node the check is
  structural over the retained range (v0.5.7). Not changed: `full` costs a Dilithium2 verify per
  vote per block (26 validators × 18 signatures × ~250 000 blocks on chain 18's archive) and the
  default stays `quick`; run `full` after any restore from a foreign copy of a data directory.
- **8d, the demo guest's wrapping add** — `circuits/guests-compiled/fib/src/main.rs` computes
  `fib(n)` with `u32::wrapping_add`, so `fib(48)` and up wrap silently. It is the zkVM's demo
  and test guest (`randprotocol-zkvm-demo`, `tests/executor.rs`), vendored from the circuits
  repository (`deploy/sync-zkvm.sh`), deployed on no chain, and its wrapping is the RV32 `add`
  it compiles to — the guest is a fixture, not a program anyone is paid by. Not changed here
  (vendored); a guest that must not wrap uses `checked_add` and halts on `None`.

## The next cut: `bridge.rotation` (audit v6, BRG-14, issue #89)

A group inside the genesis `bridge` section, beside `rules_v2`: `"rotation": { "delay_secs":
86400, "needs_possession": true }` (`docs/bridge.md` §21.5). `needs_possession` makes every PQ-set
and pause-key rotation carry each new key's own signature over the rotation message (the V2
actions, variants 30/31); `delay_secs` (1 s to 30 days) makes an accepted rotation pend until a
block's time reaches `effective_at_secs`, while the current pause key can cancel it
(`CancelRotation`, variant 32). Hashed after `binding_domain`, in the bridge root under
`rand-bridge-rotation-1` and stored under `bridge_rotation`, all only when present — chain 18 is
byte for byte unchanged. **What the cut passes:** the group in the bridge JSON the cut script
splices in (`rand-node genesis` writes no bridge section, so there is no flag); recommended
`delay_secs: 86400, needs_possession: true`. **Before the first real rotation**, run the
rehearsal checklist in `docs/bridge.md` §21.5 on a private chain; the signer is
`rand-node bridge-gov` (this repository). A rotation's activation spends a `rotation_nonce`, so
relayers holding attestations co-signed by the old set must re-collect co-signatures from the new
set after `effective_at_secs`.

## The next cut: `bridge.fees` (zUSD bridge fees, v0.6.8; chain 20)

The user's decision (2026-10-01): take the bridge fee in zUSD on Rand, both ways, not in USDT on the
host chain — the fee income is then shielded. `docs/bridge.md` §25 is the rule. The cut splices into
the genesis `bridge` section (there is no `rand-node genesis` flag — the cut script writes the bridge
section):

```json
"fees": { "mint_bps": 10, "burn_bps": 10, "recipient": "rand1…" }
```

- **Recommended: `mint_bps: 10, burn_bps: 10`** (0.1 % each way, the endpoints' old skim moved on
  chain). At most 100 each.
- **`recipient`: a dedicated treasury key**, generated off the laptop for this purpose
  (`rand keygen`), never a validator's, guardian's or relayer's wallet — every fee note is visible
  to whoever holds its viewing key, and the address is fixed for the chain's life. Back it up
  before the cut; `rand-node init` refuses an address whose ML-KEM key is not one.
- **Before or with the cut:** the guardians and relayer sign the burn body as before — under the
  group it already carries `release_amount` (`rand_getBridgeBurn.release_amount`); a relayer
  that recomputes the release from the burn transaction's `amount` must switch to the body's.
  Decide whether the endpoints keep their own 10 bps skim on top (the chain's fee does not
  replace it by itself). Rebuild the wallet apps against v0.6.8, or deposits on the new chain show
  the gross until their envelope opens (the relayer's `rand bridge-mint` seals for the net).
- After launch: `rand_getBridgeState.fees` reads the group; a 1 USDT deposit leaves 0.999 zUSD with
  the depositor and the treasury's `rand balance` shows 0.001 after a sync.

## The next cut: `program_state` (RPL-2, v0.6.8; chain 20 at the earliest)

RPL-2's program cells, program vaults and `Invoke` (variant 33) switch on with a top-level
`"program_state": { "cell_fee": <units> }` (a JSON number) (`docs/program-state.md`). Chain 19 is cut on v0.6.7
without it; **chain 20 is the first chain that can carry it**. Hashed last (after
`proof_window_blocks`), folded into the state root as `rand-state-8` and persisted under
`META_PROGRAM_STATE`, all only when present — chain 18 is byte for byte unchanged. **What the cut
passes:** `rand-node genesis --program-state-cell-fee <UNITS>` (at most 1 000 RAND), which needs
`--tokens`, `--gas-price`, `--hardening-v6` and `--auth-guest` (with `--bundle-guest v3`), each
refused by name; `Genesis::validate` also requires `confidential`. Check `rand_getLimits.program_state`
after the cut. randscan and the clients render the `invoke` kind and its payout notes before or
with it (`docs/rpc.md`, changelog).

## The `staking` genesis section (v0.5.4)

Audit v4's STAKE-2 (`docs/staking.md` §2): a per-epoch faucet budget, a bond activation delay and
the rule that a faucet and a bridge exclude each other. Genesis-gated — `rand-node genesis` never
writes it, so a file without it (chain 14's) hashes byte-for-byte as before; the cut script splices
it in beside the `bridge` section, and `rand-node init` on the finished file prints the hash that
matters:

```json
"staking": { "faucet_budget_per_epoch": "100000000000", "bond_activation_epochs": 2 }
```

`faucet_budget_per_epoch` is in RAND's base unit as a decimal string (100 RAND above — one `Mint`'s
worth per 1000-block epoch); `bond_activation_epochs` is how many whole epochs a new bond waits
past the boundary it would have joined at (0 = today's rule). On a bridged chain set
`faucet: false` — a faucet beside a bridge is refused at `init` once the section is present —
unless `faucet_recipients` limits the faucet to named wallets (the STAKE-2 fields above). The
section moves the state root domain to `rand-state-5` and the validator leaf to
`rand-validator-leaf-4` and appends the bond queue's root to the state root, so it ships with a
chain cut, never as a same-chain update; a node restores it from the genesis file on every restart
(`reload_ledger`), never from the database. The bond queue itself is state, persisted as
`META_BOND_QUEUE` beside the supply counters.

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
   (`aggregation: aggregate program built and the verifier keys for tiers [20, 21, 22] warmed`).
5. **Aggregators register** (`rand-node aggregator register --bond --payout` prints the
   signed registration; the bond burns through the wallet's `submit` as the register bundle's
   burn) and run **`rand-node aggregate --watch`** on a proof machine (≥ 256 GB at N=1 after the
   phase-2 row cuts, a projection until the tier-20 proof runs — `docs/node-hardware.md` §4; the GPU
   node for N≥2 — see `docs/aggregation.md`'s machine classes), pointed at any fleet RPC.
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

## Chain 20's faucet, and where testnet RAND comes from

Chain 20 (like 15–19) runs the faucet **for an allow-list only**: genesis
`staking.faucet_recipients` names 16 wallets, and the ledger refuses a `Mint` to any other address
(`rand_status.faucet: true` says the faucet exists, not that anyone may mint). `rand_mint` is also
not on the public listener (`rpc::PUBLIC_METHODS`) nor through `https://rpc.randprotocol.org` (the
website's sale proxy allow-list). A session or a developer that needs testnet RAND asks the operator,
who sends it from an operator wallet with `rand send` (a v0.6.8 `rand`; on 2026-10-01, 300 RAND each
to durian.market's treasury and to example-programs). The RPL-2 reads (`rand_getProgramCell`,
`rand_getProgramCells`, `rand_getProgramVault`) are on the node's public listener but were **not**
on the website proxy's allow-list at chain 20's launch; randprotocol.org `e77ec7a` (2026-10-01,
`server/sale/src/rpc.rs` `RPC_ALLOWED`) added them, and `rand program invoke/state/vault` work
through the public URL since. A new public method needs that list too.

## The next cut: `proof_window_blocks` (issue #118)

**What it is.** A bundle's anchor must be one of the last 256 block-end roots
(`ledger::ANCHOR_WINDOW`) and its `time` at most 256 blocks behind the height
(`ledger::TIME_WINDOW`). At chain 18's 1.17 s blocks that is ~300 s for the whole trip — the auth
proof, the bundle proof, the wallet's verify, submission and inclusion — and a delegated bundle
proof on a loaded single-core prover took 294 s and was refused (`time 102225 is outside [102230,
102486]`). The top-level genesis field `proof_window_blocks` replaces **both** windows (they exist
for the same reason) with one value in `[256, 4096]`. Hashed under the tag `proof_window_blocks`,
after `bridge_rotation`, only when present; never in the state root (the anchor deque it sizes
never was); `reload_ledger` restores it and re-reads the deeper anchor rows on every restart;
served as `rand_getLimits.proof_window_blocks`.

**Recommended: `--proof-window-blocks 1024` for chain 20** (`rand-node genesis
--proof-window-blocks 1024`, or `"proof_window_blocks": 1024` spliced in): ~20 minutes at
1.17 s blocks, room for any prover the pool or a user runs, while a stale anchor still dies within
the hour. Chain 19 (v0.6.7, being cut now) carries no field and stays 256/256. The chain-20 cut
script (`deploy/cut-chain20-genesis.sh`) asserts the field, and its `check-limits` step reads `rand_getLimits.proof_window_blocks == 1024` back after launch. Every validator
must run a build that knows the field before a genesis carries it — a v0.6.7 node does not parse
it (and would compute a different genesis hash).

## The next cut: `tokens.incremental_root` (audit v6, TOK-1, issue #86)

**What it is.** The token registry's root was a merkle root over every token's leaf, recomputed
from every leaf at every state root, and the node rewrote the whole registry blob (`META_TOKENS`)
at every commit, whatever the block changed — bounded by `tokens.max_tokens` (4 096) and the
burned registration fee, so a Low. The tokens-section field `incremental_root: true` makes the
root an incremental merkle commitment over `rand-token-leaf-2` leaves (one leaf and `log n` nodes
re-hashed per changed token; `rand-token-registry-4`; the state root re-domained
`rand-state-tokens-1`, innermost of the audit-v6 wrappers) and the store one row per token under
a `tokens_header` key, rewriting only the rows a block changed (`docs/tokens.md` §17). Hashed under
the tag `tokens_incremental_root`, after `bridge_fees`, only when `true`; `reload_ledger` restores
the flag from the file on every restart; `verify --mode full` rebuilds the registry from its rows
and compares it with the replay; served as `rand_getTokens.incremental_root`. No validity rule
changes. Node-only on every chain, already: the legacy root is computed once per change and reused.

**Recommended: on, for the next cut** (`rand-node genesis --tokens tokens.json
--tokens-incremental-root`, or `"incremental_root": true` in the tokens file the cut script
splices). Chains 18, 19 and 20 carry no field and hash, root and store exactly as before. Every
validator must run a build that knows the field before a genesis carries it — a v0.6.9 node does
not parse it (`deny_unknown_fields` on the section) and would compute a different genesis hash.
After launch: `rand_getTokens.incremental_root == true`, and a validator's `meta` family holds
`tokens_header` and one `token/…` row per listed token and no `tokens` blob. Rolling back a node
to a build before this one on such a chain is not possible (it cannot parse the genesis) — the
same rule as every genesis field before it.

## The next cut: the `fees` section (chain 21)

**What it is.** A top-level genesis section, `"fees": { "burn_base": true }`, with three optional
booleans (`docs/fees.md` §1.3). `burn_base` destroys every bundle's `BUNDLE_BASE` instead of paying
it to the proposer: the proposer keeps the tip (`fee − BUNDLE_BASE`), or nothing at inclusion on an
aggregating chain, whose excess is bucketed as before; the base joins `rand_getSupply`'s `burned`
and `base_fees_burned`. `subsidy_net_of_fees` pays an aggregate's subsidy from its proving shares
first and mints only the shortfall (the note is `max(schedule, shares)`); it needs an `aggregation`
section, or `rand-node init` refuses the file (`SubsidyNetOfFeesWithoutAggregation`). `burn_floor`
(issue #135) widens `burn_base`'s burn to the bundle's whole settled floor — the base plus a
Deploy's per-word term, or a Call's tier-exact gas and byte terms — so the proposer keeps only
`fee − floor`; it needs `burn_base: true`, or `rand-node init` refuses the file
(`BurnFloorWithoutBurnBase`). Absent, or present with no `true` flag, is every chain's rule so far
and commits nothing; a `true` flag is hashed after the `tokens` section's bytes under `fees` and its
own tag, so it ships with a chain cut, never as a same-chain update. Never in the state root: stored
at genesis under `META_FEES` (JSON; written on every new database, the default `{}` without a
section), and `reload_ledger` sets it again from the file on every restart; served as
`rand_getLimits.fee_rules`.

**Recommended for chain 21: `{"burn_base": true, "burn_floor": true}`** (the user's decision,
2026-10-08), the faithful EIP-1559 form of `docs/fees.md` §1.3. Under it the whole floor a bundle
was checked against is destroyed — `BUNDLE_BASE` (0.001 RAND) for a transfer, a bond, a token action
or an attestation; the base plus 100 000 units a word for a Deploy; the tier-exact
`1 000 000 + gas_price · GAS_LIMIT + byte_price · ⌈bytes / 1024⌉` for a Call under chain 20's gas
section; `BRIDGE_BURN_FEE` for a BridgeBurn; an Invoke's cell fee with it — and the proposer keeps
only the tip above it, `fee − floor` (a 0.0012 RAND transfer burns 0.001 and tips 0.0002; a 0.0041
RAND tier-14 Call burns 0.0040639 and tips 0.0000361). With chain 20's floating prices (§1.2) that
is the point: a proposer gains nothing from a block that lifts a price, and a busy chain shrinks the
supply instead of paying its proposers more. Nothing a sender pays changes — the floors and the
wallet defaults are the same numbers; only where the floor goes differs. What every client sees:
`rand_getLimits.fee_rules` = `{"burn_base": true, "subsidy_net_of_fees": false, "burn_floor":
true}` (`null` on chains 14–20), and `rand_getSupply.base_fees_burned`, a decimal string inside
`burned` and on the right of the supply identity, `"0"` at launch and growing by each included
bundle's floor with `invariant_holds` still `true`. The wallets, randscan and the bridge site should
read both: a wallet's fee preview should say the floor is burned, the explorer and the bridge
site's supply panel should show `base_fees_burned` beside `registration_fees_burned`; a client that
does not know either field still decodes the reply (each is an added key).

**Not `subsidy_net_of_fees`.** It needs an `aggregation` section, and this build refuses any
genesis with one at startup (`check_build_runs_genesis`): the admitted shapes and the recursion
fixtures were measured for the retired 2-in-2-out guest and must be re-measured against the
hidden-asset bundle (b053a76) before aggregation is activated. Until then the flag can only be
refused (`rand-node genesis --fees` errors without `--aggregation`), so chain 21 does not carry it,
and the cut script refuses a genesis that sets it, naming that reason. It rides with the cut that
re-activates aggregation.

**Rolling it out.** `rand-node genesis --fees FEES.JSON` writes the section (`docs/cli.md`).
`deploy/cut-chain21-genesis.sh` — derived from chain 20's script, chain 20's shape and value cut
from a snapshot of chain 20 — writes `fees.json` itself (`{"burn_base": true, "burn_floor":
true}`), passes it as `--fees`, asserts the section on the finished file, refuses
`subsidy_net_of_fees`, and proves the section is part of the genesis hash by re-deriving the hash
with the section removed, and with `burn_floor` removed, and refusing if either does not move. The
real cut refuses a `rand-node` without `--fees` (any build before d6cc16f5, v0.7.1 included);
`DRY_RUN=1` skips the section, loudly, on such a binary. Every validator must run a build that knows
the section before a genesis carries it — an older node does not refuse the file: `Genesis` has no
`deny_unknown_fields`, so it silently ignores the section, derives a different genesis hash and so
cannot join the chain. So **every node** — the 26 validators, both archives, and any RPC node the
website, randscan or the bridge relayer reads — runs the d6cc16f5+ build from chain 21's first
block. A signer binds chain 21's genesis hash without re-deriving it from the file: the `rand`
wallet (and the relayer, which is a `rand`) reads it from the node (`rand_getGenesisHash`, under
`binding_domain: 1`), and the offline operator commands (`rand-node admit sign`) take it as
`--genesis-hash`, so a v0.6.8+ `rand` still signs for chain 21 (check any other signer, e.g. the
bridge repo's `rand-bridge-gov`, for where it takes the hash before the cut).
Ship them the same build anyway, in the cut's `clients:` line: only it knows `fee_rules`
(`RpcClient::fee_rules`; no wallet fee preview says yet that the floor is burned — a follow-up),
and the clients repo apps, randscan and the website WASM vendor their fullnode version as before
(the chain-20 record's lesson).

**After launch:** `NODE=… deploy/cut-chain21-genesis.sh check-limits <first node's RPC> <genesis
file>` reads `rand_getLimits.fee_rules.burn_base == true` and `.burn_floor == true` (with
`subsidy_net_of_fees == false`), `rand_getSupply.base_fees_burned == "0"` and `invariant_holds ==
true`, beside every value carried from chain 20. Run it before the first bundle lands, or with
`BASE_FEES_BURNED_ANY=1` once one has.

## The next cut: the proposer/aggregator split (`fees.proposer_share_bps`, `fees.prove_base`; unreleased)

**What it is.** Two optional numbers in the same `fees` section (`docs/fees.md` §1.3,
`docs/compute-optimization.md` §6.2–§6.3), each only on a chain with an `aggregation` section
(`rand-node init` refuses either without one: `ProposerShareWithoutAggregation`,
`ProveBaseWithoutAggregation`; a share over 10000 is `ProposerShareOutOfRange`; `prove_base: 0` is
`ProveBaseZero` — leave the field out).
`proposer_share_bps` keeps that share of the base to the proposer at inclusion and buckets the rest
beside the excess as proving share (swept back to the proposer if no aggregate covers it);
`prove_base` raises every bundle's floor by a proving share bucketed whole and never burned. Each is
hashed only when set, after `burn_floor`'s bytes (`proposer_share_bps` ‖ be32, `prove_base` ‖ be64),
so it ships with a chain cut. Served as `rand_getLimits.fee_rules.proposer_share_bps` and
`.prove_base`; `rand_estimateFee` includes `prove_base`.

**Recommended values, deferred.** `"proposer_share_bps": 4000, "prove_base": 600000` (40 % of the
base to the proposer, 0.0006 RAND proving floor) — the proposal's numbers — once aggregation is
admitted on the chain being cut. Until then no cut should carry either: both need the `aggregation`
section, which waits on the production-proof measurement (`docs/aggregation.md`, "Before enabling
aggregation"). After launch: `fee_rules` serves both, `rand_estimateFee {"kind":"bundle"}` answers
`1600000`, a proposer's `rewards` grow by 400 000 per included transfer, and `invariant_holds`
stays `true` through covers and sweeps.

## The next cut: audit v6's staking fields (STAKE-2)

Audit v6 (2026-09-30) §8.5. Each is optional, absent from every genesis through chain 18, and
committed to the genesis hash under its own tag — after every tag that existed before it — only
when set; a file without them hashes and runs byte-for-byte as before.

- **`staking.max_stake_entry_bps_per_epoch`** (`docs/staking.md` §2): the entry budget as basis
  points of the active weight at the boundary, in place of the fixed
  `max_stake_entry_per_epoch` (the two are refused together). Chain 18's 10 000 RAND holds an
  entrant to a third for two epochs of a 26 000-RAND set and for 1 301 of a 26 000 000-RAND one;
  `2500` holds it for two at either scale. Size it with the genesis stake (audit decision D24):
  a mainnet cut that changes the stake sizes must not carry chain 18's fixed figure.
- **`staking.slashing: { equivocation_bps, jail_epochs }`** (audit v6, STAKE-1; `docs/staking.md`
  §2, "Slashing leader equivocation"). A leader that signs two headers for one view loses
  `equivocation_bps` of its bonded and unbonding stake and is jailed for `jail_epochs` (0 = for
  good, otherwise ≥ 2). Needs `consensus_domain: 1`; refused beside `vesting`. Vote equivocation
  is not slashed. **The build that carries it persists `last_proposed_view` before every
  proposal** (a node-only change that rolls with this build): a leader that restarted mid-view
  could otherwise sign a second header and slash itself, so every validator must run this build
  before any chain with the section starts. Recommended once stake is held by more than one
  operator (D8) — with one operator's keys it changes nothing but the risk of a bug.
- **`testnet: true`** (top level; `rand-node genesis --testnet`). Required on any chain whose
  genesis keeps `faucet: true` beside a `bridge` section — free RAND beside real custody — on a
  chain id past 18 (`GenesisError::FaucetWithBridgeNeedsTestnet`; chains 14–18 are grandfathered
  by id, `genesis::FAUCET_BESIDE_BRIDGE_CHAIN_IDS`). Hashed under the tag `testnet` only when
  `true`; a mainnet genesis never carries it. `rand_status.testnet` and
  `rand_getLimits.testnet` serve it. The next testnet cut passes it; a mainnet cut passes
  neither it nor `--faucet`.
- **`staking.admission_by_vote: true`** (`docs/staking.md` §2, "Admission by vote"). A `Bond`
  that registers a new validator key is refused `NotAdmitted` until validators holding strictly
  more than two thirds of the voting set's weight have signed it in (`AdmitValidator`, the
  `rand-node admit sign` / `admit submit` commands); a top-up needs no vote. The admitted set is
  consensus state (`rand-state-admitted-1` around the root, `META_ADMITTED`, `rand_getAdmitted`).
  Recommended for any chain that will hold value: until slashing exists it turns the price of two
  thirds of the stake into a vote. The cut passes it inside the `staking` section it splices in
  (or writes with `rand-node genesis --staking STAKING.JSON`), and every validator that will vote
  needs its key file at hand — `admit sign` is offline. Every wallet that bonds should read
  `rand_getLimits.admission_by_vote` and say so before it proves a registering bond.
