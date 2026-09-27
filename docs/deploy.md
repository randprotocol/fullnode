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
- **The swarm caps what it will hold** (deep scan 2026-09-24): at most 256 established *inbound*
  connections, 64 inbound handshakes in flight and 2 connections per remote peer
  (`network::WireLimits`); the next inbound connection is refused at the handshake and the dialer
  sees a `ConnectionDenied`. A node's own dials — its bootstraps and redials — are never counted
  against its own caps, so a validator always reaches the peers it dials, and 18 validators plus
  every explorer and observer sit far under 256; the cap is a bound on what one host can be made
  to hold, since a fresh libp2p identity costs nothing to mint. The node's peer map is held to
  the same bound: a new connection evicts the entries that are not connected before it is
  recorded, and a gossiped `Status` from an author this node holds no connection to no longer
  creates an entry at all.
- Observers run the same binary without `--validator`; they sync, verify and serve RPC.
- **History pruning (testnet only).** `--prune-history <n>m|<n>h|<n>d`, at least `1h` (`24h`
  keeps the ledger and one day of blocks); the rest is deleted every 16 blocks
  (`docs/superpowers/specs/2026-09-24-history-pruning-design.md`).
  Exactly one node keeps everything — the archive, `ARCHIVE` in `deploy/nodes.env` (obs1 on
  randbridge-web, data dir on a volume) — and a node that falls more than a day behind must sync
  from it. **Mainnet units never pass the flag.** A pruned node that fails its startup check does
  not repair itself: re-sync it from the archive. **Rollback:** a pruned data directory opened by
  a build ≤ v0.5.6 with the default `--verify-chain quick` replays from genesis, finds block 1
  missing and truncates the whole ledger to genesis; run an older build on a pruned data
  directory only with `--verify-chain off`, or re-sync from the archive.
- **The one public RPC endpoint is `https://rpc.randprotocol.org`** — Cloudflare → the web
  droplet's nginx → the sale service's filtered, per-IP-metered proxy → randscan's `/rpc` route on
  E → E's `127.0.0.1:8545` (`deploy/caddy/README.md` has the chain; F's Caddy is not in it and does
  not run). Every droplet keeps its node's RPC loopback-only. E's viewing-key slots are safe because
  the proxy's allowlist never forwards `rand_importViewingKey`.

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

## Rolling out a new commit

1. `cargo test` locally, commit, push.
2. Restart local validators from the new binary (`cargo build --release`, point `run-a.sh`'s `BINDIR` at it, then `launchctl kill TERM gui/$(id -u)/org.randprotocol.node-a` — launchd restarts A from the script).
**Release rule (audit v4 PROC-3).** A version tag is made only from a commit whose CI run
(`.github/workflows/ci.yml`) is green and whose full `cargo test --workspace --release` passed on
the release machine, `the_genesis_hash_is_pinned` included; the tag annotation names the run. A
known-failing test is a reason not to tag, never a note to tag over.

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
  address is refused at admission. **Mainnet never carries a faucet**, allowlisted or not.
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
four bytes a row — runs past the u32 pc wrap can never be proven (the circuit does PC arithmetic
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

### Canonical proofs (INT-5, VERIFIER-2, VERIFIER-1)

A proof header or transcript field the verifier accepts at more than one value lets whoever relays
a transaction re-encode its proof into a second transaction id (`Transaction::hash` takes a proof
by digest) — the sender's wallet then reports its own payment as not committed — and lets a bundle
take a shape no aggregate can cover. `randprotocol_zkvm::executor::non_canonical` pins each such
field to the honest prover's value, for bundle and call proofs alike:

- **The memory table's height** (INT-5 / HB-2): exactly `t + 2` for a proof without a keccak or
  sha256 table — 16 for every bundle. A bundle declaring 17 verified.
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
