# Testnet: chain id 11 (short shielded addresses, staking, bridge, zkVM constraint set 6)

Test keys only; all seeds are committed on purpose so any machine can pull and run.

> **Chain 11 (cut 2026-09-17) is the short-shielded-address chain.** An address is now a 53–55-char
> receiver id (`rand1…`), not the long shielded address chain 10 used: what a sender needs to pay
> it — the note key and the 1,184-byte ML-KEM encapsulation key — lives in a signed **receiver
> record** the id resolves to, either delivered inline with a payment request or filed in the
> on-chain registry (`rand_getReceiver`, `rand register`). Every payout and every genesis deposit
> note is now a receiver id backed by a record filed at genesis with `--receiver`; genesis's
> `receivers` array carries all 23 of them (`deploy/payout/*.record.json`, committed, and
> `wallets/shielded-*.record.json`, gitignored like the keys). No hash-domain or peer-id change —
> same RAND naming, same `rand_*` RPC methods, same libp2p identities as chain 10 — so `nodes.env`
> is untouched, but the genesis format itself changed (a chain-10 node cannot parse a receiver-id
> payout), which is why this is a fresh chain like every format change before it. Same code
> otherwise as chain 10 (constraint set 6, the pre-v0.1 security fixes, libp2p 0.57), and like
> chain 10 **cut without the `aggregation` section** (`deploy/cut-chain11-genesis.sh` defaults to
> `AGGREGATION=off`; the activation values are the user-owned ≥ 64 GB measurements). The chain-10
> and chain-9 records are under "History".

| | |
|---|---|
| chain id | **11** |
| genesis hash | **`79123fa75a2b946e21248e4b77e86444f134d0dc879035af9d4996c55eadeec2`** |
| genesis file | `deploy/genesis-chain11.json` (cut 2026-09-17; chain 10's stays at `deploy/genesis-chain10.json`) |
| pinned build | **`CHAIN11BUILD`** — binaries `rand-node` and `rand` in `bin-CHAIN11BUILD/` (macOS) and E's `/root/fullnode/target/release` (Linux), `.update-pin` content is `CHAIN11BUILD` (filled in by the controller after merge, from the merge commit) |
| zkVM | **constraint set 6** (the public input segment; M4.3 EVM and M4.4 sBPF/sha256 guests ride along) — unchanged, this feature touches no proof |
| `hc_bundle` | `4a27356f379571036025a4a8661c294b0edec2b7cf7fbfd60b472b186cbd4afb` |
| receivers | **23** filed at genesis: 18 validator payouts + 5 alloc-note owners, each a signed record verified for chain id 11 |
| validators | **18, every one staked at exactly 1000 RAND** (the staking minimum) |
| quorum | **13 of 18** (strictly more than two thirds of 18 000 RAND of stake) |
| epochs | `--epoch-blocks 1000`; `UNBONDING_EPOCHS = 2`, so unbonded stake releases ~2000 blocks later |
| genesis value | 18 000 RAND staked in the register + 5 × 1000 RAND as deposit notes = 23 000 RAND |
| faucet | **on** (`rand faucet [address]`, up to 100 RAND per call on any node) |
| confidential computation | **on**, production FRI profile (80 queries; `MAX_PROOF_BYTES` 2 MiB) |
| bridge | **no bridge section** — and one cannot be added to this chain later, see below |

Chain 8 is a fresh genesis because **constraint set 5 cannot replay chain 7**: a chain-7 proof and a
constraint-set-5 verifier do not round-trip in either direction, so a `03c9fb9` node can neither join
the chain-7 fleet nor replay its blocks. Same reason chain 5 → 6 and 6 → 7 were new chains. The
build also merges phases S2 (staking: a register, bonding, epochs, per-validator payouts) and S3
(the bridge as notes, and call envelopes), neither of which the chain-7 fleet's build (`01dc23d`,
S3-only) understands.

> **`hc_bundle` is not a constraint-set marker.** It is the digest of the vendored *bundle guest*,
> and that guest is byte-identical between `01dc23d` and `03c9fb9` — chain 6, chain 7 and chain 8 all
> pin `4a27356f…`. So a chain-7-era binary pointed at this genesis file will accept the `hc_bundle`
> and only diverge later, on proof verification. The chain id is what actually keeps the two fleets
> apart. Check the build, not the bundle digest: `bin-03c9fb9/`, `.update-pin` = `03c9fb9`.

## The 18 validators

Every validator holds exactly **1000 RAND**, which is `MIN_STAKE` — one unit less and genesis
refuses the file outright (a validator below the minimum would sit in the register but in no epoch's
set). That is deliberate: this fleet is here to exercise the minimum-stake rule, the epoch
boundary and the withdraw path on a real network, so every node sits exactly on the line. Chain 7
gave each of the same 18 nodes 100 000 RAND; chain 8 gives them 1/100th of that.

Consequence to plan around: **13 of the 18 must be online to commit anything.** With 12 up, views
advance and nothing finalises. Stake is uniform, so quorum is a headcount here.

`payout` is where this validator's rewards and released stake are paid, as a note. It is register
state and therefore part of the genesis hash. Each validator has its own wallet in
`deploy/payout/<name>.key.json` — read `deploy/payout/README.md` before trusting the regional names
in this table: `a`…`f` are verified against the key files in `deploy/`, `lon1`…`mem1` are inferred
from chain 7's validator order and can only be confirmed on the droplet itself.

| name | where (chain-7 fleet) | validator address | pubkey | payout (`deploy/payout/…`) |
|---|---|---|---|---|
| a | laptop, LAN 192.168.100.123 (NAT) | `2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v` | `15321b04570d7095…` | `rand12wXbbPp9S…7RdsHX` |
| b | 192.168.100.79 (NAT), MacBook Air, auto-updater | `ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z` | `4d491d8a5540f005…` | `rand123m1qRsJC…spYBt2` |
| c | DigitalOcean fra1 164.90.239.200 | `F6rYLexPhyMmwPNqbEmyyp5FiTmtQqDgZyqScUqYY4F6` | `f3557730c8a76b43…` | `rand12JKxhEJdK…bbBC9D` |
| d | DigitalOcean ric1 165.245.173.74 | `5tMgLSzXL8keU1vg2wtGEXRJkmfBK6GzhjNjxrCFgCaj` | `e95ecd68c5621147…` | `rand1K6CKerkU7…epmHvS` |
| e | DigitalOcean sgp1 188.166.235.187 (RandScan explorer) | `CxeG7vJaxUoKBZZe8U8LGXohH2FvcCbE47AufK6Mp2jf` | `9ffac1e8ff6b687d…` | `rand12LtowjJ4a…DvagmG` |
| f | DigitalOcean nyc3 159.89.185.254 | `DcuuZrzDSJedhFnynLFchNfYmW4UKiZT2nEKbcs2ojmJ` | `b277b8eb8863fca2…` | `rand12NKo9Vzad…JZ67ce` |
| lon1 | DigitalOcean lon1 139.59.160.76 | `8UcsaXDSSWcC6fT3CWT89fgUvG4ubaYd61FUQHKiUDLv` | `7edc60fc6e6e35f6…` | `rand1psgNofkXu…b9ELgs` |
| sfo3 | DigitalOcean sfo3 24.144.89.22 | `9rex7stS6d9QxaAh5nghjaUEratKJFUAmLAoxRFmP7LM` | `5394ea2fc122a869…` | `rand1c4QGogGoQ…9JWq6o` |
| tor1 | DigitalOcean tor1 146.190.243.29 | `CRW3fQsuFa7YSdU5ZDrRMxQjJ4ET9kzf6hg1D8CAhoWH` | `71528cc5c8b11715…` | `rand12Nqq4qRnA…z8eRU8` |
| blr1 | DigitalOcean blr1 167.71.235.108 | `ASzbnFwqVnwsrN81iytkuhNbs8f93Q3h4rQjXPDUNMjU` | `ca6b8bdc43f95a4f…` | `rand1EgAGA6jvA…PovHe2` |
| syd1 | DigitalOcean syd1 170.64.226.65 | `8cHAjP3wgGDv55Ym2qZrYyu2Mvc7b86jsrN6vWcwZoJV` | `574d78491644c873…` | `rand127uhVMLgw…fZc1iT` |
| atl1 | DigitalOcean atl1 165.245.142.90 | `BV2BfMZJo2Lpo3pR7RfAjytnFxmMhzCWxoUHhXhjT2qL` | `c82e55fd7ff180e0…` | `rand12DXh5myrS…zza1UL` |
| ams3 | DigitalOcean ams3 146.190.233.230 | `6orzEKd3Ds3ZFmp21pidbF19kAe6AczzPCtnMVrKRLeA` | `76bcc53c2370404b…` | `rand12KMhq8TQf…V4sthx` |
| nyc1 | DigitalOcean nyc1 192.81.214.91 | `F5RVdAe3Wo2AWHsjKZjFKmGcnTHvJrDpdSHL8gnF4wN1` | `59bd8ed1017f2743…` | `rand1PzJWMbbmr…R8tBxd` |
| nyc2 | DigitalOcean nyc2 107.170.49.234 | `9hU2qrPFxbcZjSse6MJnapYRs4RchALWtJH4RRrbwDGo` | `2c111e425d2fa4d3…` | `rand1299VKZVdp…t47CTv` |
| sfo2 | DigitalOcean sfo2 143.110.135.126 | `6NGLfkZcTs3i5LTTbqoYKM9aQCs7ZXygHirTg2AtWhsA` | `c18d93c46e9f8cc5…` | `rand1j9HvRGKyh…rRDbgB` |
| mkc1 | DigitalOcean mkc1 201.79.35.212 | `8m5BoX2RA4xTVNfDwKMbWQ3JSChrj69hvJzdSEKMsZDM` | `38c1921b1738182a…` | `rand12sQ9J2wkd…D8jXFH` |
| mem1 | DigitalOcean mem1 168.144.61.10 | `6T5WyBUrYN1noLi3tDKC1Uw5Vf3xabExnWCDdik7VTPV` | `ce48ef3e62463c08…` | `rand12ZnGtMMx6…TS36wS` |

The rows are in genesis order (which is chain 7's validator order). C, D, E and the rest of the
droplets have public IPs and act as bootstrap nodes; A and B are behind NAT and dial out
(`deploy/run-a.sh`, `deploy/run-b.sh`). Full multiaddrs and peer ids are in `deploy/nodes.env`.

## The five genesis notes

A shielded chain has no per-validator allocation: value exists only as a note someone holds the
spend key for, so `--alloc` takes a receiver id and creates one deposit note owned by whatever
record that id resolves to (`--receiver`). As on chain 7, 1000 RAND goes to each of the five
wallets in `wallets/` (gitignored — those keys and their `.record.json` files live on the machine
that cut this genesis and nowhere else):

| wallet | address | amount |
|---|---|---|
| `wallets/shielded-1.key.json` | `rand12re6vUGb3MM…rQk1Ck` | 1000 RAND |
| `wallets/shielded-2.key.json` | `rand1boQSaTUEzfr…BVPiKx` | 1000 RAND |
| `wallets/shielded-3.key.json` | `rand1W7pknfb5F2K…ypKKV3` | 1000 RAND |
| `wallets/shielded-4.key.json` | `rand1uKceMv12dvy…UPdhGV` | 1000 RAND |
| `wallets/shielded-5.key.json` | `rand1DxMwWQrZjap…w3vBUe` | 1000 RAND |

## No bridge section, and why it stays that way

Chain 8 has no `bridge` section, exactly like chain 7. The bridge's guardian set, emitters and asset
registry are genesis state and go into the genesis hash, so **a bridge cannot be added to a running
chain**: switching it on means cutting chain 9. The S3 code is in this build and its bridge RPCs
answer, but with no guardian set there is nothing to attest a deposit, so `rand bridge-mint` and
`rand bridge-burn` have nothing to do here. If the fleet wants to exercise the bridge, that is a
new genesis with a `bridge` section and a decision about who the guardians are — worth doing
deliberately rather than bolting onto this cut.

What chain 8 *does* add over chain 7 is the staking half: bonding, unbonding, withdraw, epoch sets
and per-validator payouts (phase S2), and call envelopes (S3).

## The exact command that cut this genesis

`deploy/cut-chain8-genesis.sh`, run from the repo root against the `03c9fb9` release binaries:

```bash
./deploy/cut-chain8-genesis.sh          # ALLOC_WALLETS=wallets by default
```

It expands to one `rand-node genesis` call — 18 `--validator <key or hex pubkey>,1000,<payout>`
and 5 `--alloc <rand1…>=1000`:

```bash
rand-node genesis --chain-id 8 \
  --validator "deploy/node-a.key.json,1000,$(payout a)" \
  ... (b, c, d, e, f the same way) ... \
  --validator "<chain-7 pubkey #6>,1000,$(payout lon1)" \
  ... (sfo3 … mem1, chain-7 pubkeys #7..#17) ... \
  --alloc "$(addr 1)=1000" ... --alloc "$(addr 5)=1000" \
  --epoch-blocks 1000 --faucet --fri-profile production \
  --out deploy/genesis-chain8.json
```

where `payout n` is `rand --key deploy/payout/$n.key.json address` and `addr i` is
`rand --key wallets/shielded-$i.key.json address`. The twelve regional public keys are read out of
`deploy/genesis-chain7.json` (committed here as history for exactly this reason), because those
nodes' key files were generated on the droplets and exist nowhere in this repo.

Re-running the script does **not** reproduce this genesis hash: every deposit note carries fresh
commitment randomness, so the same `--alloc` list yields a different hash every time. A
deterministic `r` would let anyone confirm a guess at a genesis note's owner and amount by
recomputing the commitment. Cut once, distribute `deploy/genesis-chain8.json` byte-identically,
keep it.

## The receiver records (new in chain 11)

Every payout and every alloc-note owner is now a receiver id, and an id alone proves nothing —
genesis needs the *record* that id resolves to: the note key `pk` and the 1,184-byte ML-KEM
encapsulation key, signed by the wallet over `(chain id, version, pk, kem_ek)`
(`ReceiverRecord::sign`/`verify`). `rand-node genesis --receiver <RECORD.JSON>` files each one
into `Genesis::receivers` before any `--validator` payout or `--alloc` owner is resolved against
it, and `Genesis::build` refuses the file outright if a record's signature does not verify for
*this* genesis's chain id — a record signed for chain 10 (or any other chain) cannot be replayed
into chain 11's genesis.

Each record was produced once, on this machine, with `rand address --record --key <wallet>` —
the `--rpc` node it asked answered chain id 11 — and the JSON that command prints is exactly the
file `--receiver` reads (`ReceiverRecordHex`, either bare or wrapped under a `"record"` key):

- **The 18 payout records are committed**, at `deploy/payout/<name>.record.json` — public data (a
  public signing key, a public KEM key, a signature), the same convention as the payout key files
  themselves.
- **The 5 alloc records are gitignored**, at `wallets/shielded-<i>.record.json`, next to the key
  files they were derived from — `wallets/` is already excluded.

## Cut-over checklist, per node

Nothing about chain 10 is reusable — different chain id, a genesis format a chain-10 node cannot
parse — so this is a clean start on every machine. Keep chain 10's data directory around if you
want to keep serving it; the new `DATA` name is keyed on the genesis hash, so the two never
collide.

1. **Binary**: `bin-CHAIN11BUILD/rand-node` and `bin-CHAIN11BUILD/rand` (or `cargo build --release`
   at the chain-11 merge commit; the Linux ones are built once on E and fanned out by
   `deploy/cutover-droplet-rand.sh`). Every node on the fleet must run this one build — a genesis
   format change is a fork, and a mixed fleet stalls.
2. **Genesis**: `deploy/genesis-chain11.json`, byte-identical everywhere. `rand-node init` prints
   the hash; it must read `79123fa75a2b946e21248e4b77e86444f134d0dc879035af9d4996c55eadeec2`, and
   the file's `receivers` array must have 23 entries.
3. **Fresh data dir**: `data-<letter>-79123fa7` (never reuse a chain-10 directory).
4. **`.update-pin`** on the MacBook Air (node B, auto-updater): set its content to
   **`CHAIN11BUILD`**, or the updater drags B back onto the chain-10 build and B drops out of the
   set.
5. **Start**, and check `rand-node status`: `height` climbing, `chain id 11`,
   `hc_bundle 4a27356f…`, `active_validator: true`, `notes: 5` at genesis,
   `tree_root f5b40b3ad78200448937c306e0a55edd37a56602428f79a1ce66f948c1c9f80b` at height 0.
6. **Quorum**: nothing commits until 13 of the 18 are up. Bring the droplets up before declaring a
   stall.
7. **Explorer** on E re-indexes itself on a chain id change; RandScan's chain 10 index can be
   dropped once nobody is asking for it.
8. **Per droplet**, same service and peer ids as chain 10 —
   `deploy/cutover-droplet.sh <ip> 4d757f11 79123fa7 deploy/genesis-chain11.json` (old prefix,
   new prefix, then the genesis file; peer ids do not change, so this is the whole cut-over).

```bash
rand-node init --datadir data-c-8c742fc9 --genesis deploy/genesis-chain8.json
rand-node run --datadir data-c-8c742fc9 --key deploy/node-c.key.json --validator \
    --block-interval-ms 1000 --bootstrap /ip4/<ip>/tcp/30303/p2p/<peer id>
```

### The droplet unit change, exactly as applied (2026-09-13 rollout)

Every droplet already had a `rand-node` systemd unit pointing at its chain-7 data dir. The only
edit the unit needed was the data-dir name — the key path, listen address, `--rpc 127.0.0.1:8545`,
`--no-mdns` and both `--bootstrap` multiaddrs stay exactly as they were, because the peer ids did
not change with the genesis:

```bash
# 1. new data dir, from the chain-8 genesis (must print 8c742fc9…, chain id 8)
systemctl stop rand-node
rand-node init --datadir /root/data-$(hostname)-8c742fc9 \
    --genesis /root/fullnode/deploy/genesis-chain8.json

# 2. repoint the unit: the datadir suffix, and nothing else
cp -a /etc/systemd/system/rand-node.service /root/rand-node.service.chain7.bak
sed -i 's/-55668ebf/-8c742fc9/g' /etc/systemd/system/rand-node.service

# 3. restart
systemctl daemon-reload && systemctl restart rand-node
rand status          # chain id 8 via rand_chainId, height climbing, peer_count → 15–16
```

`-55668ebf` occurs exactly once per unit (in `--datadir`), so the `sed` is safe as written; the
chain-7 backup of each unit is left at `/root/rand-node.service.chain7.bak`. Data dirs are keyed
on the genesis hash, so `/root/data-<hostname>-55668ebf` survives untouched next to the new one.

Two things worth knowing before the next cut-over:

- **Swap the binary and chain 7 stops there and then.** Build `03c9fb9` cannot open a chain-7 data
  dir at all: it needs a `payout` on every validator in the stored genesis, and chain 7's genesis has
  none, so the node exits with ``json: missing field `payout` `` and `Restart=always` turns that into
  a crash loop. Distributing the binaries *is* the cut-over — do it immediately before the init, not
  as a separate earlier step, and expect no graceful overlap between the two chains.
- **Distribute through E, not from the laptop.** 36 MB per node over a home uplink is minutes each;
  copying to E once and fanning out droplet-to-droplet (`ssh -A` from the laptop, so E uses the
  forwarded agent and never holds a private key) moves all 15 in well under a minute.

#### What the rollout actually did

The 16 droplets went to chain 8 in this order — the 12 regional validators in batches of four, then
F, C, D, and E last because it also serves the explorer. **The 13th node (F) came up at
07:10:55Z and block 1 committed at 07:10:58.438Z**, 3.4 s later: quorum is 13 of 18 and the 16
droplets alone carry it, so the chain started without waiting for A or B. Nothing on E's explorer
(`/root/randscan`, `/etc/randscan`, `/etc/caddy`, `randscan-*`) was touched, and E's RPC stayed on
`127.0.0.1:8545`.

Keep `--block-interval-ms` at 1000 (the default) or slower. A bundle proof takes ~100 s and its
anchor is valid for 256 blocks, so a faster chain rejects honest transfers whose anchor expired
mid-proof (`docs/shielded.md` §5); at 1000 ms the anchor window is ~256 s, which holds. The
integrated S2+S3 branch's own cluster tests run at 3000 ms because proving on a contended laptop is
much slower than on the fleet — if a node is also proving locally, slow its chain down, not the
fleet's.

On A and B: `./deploy/run-a.sh` / `./deploy/run-b.sh` (they init `data-{a,b}-8c742fc9` from
`deploy/genesis-chain8.json` themselves). Droplets:
`deploy/push-to-vps.sh <ip> <letter> "<bootstrap multiaddrs>" [validator|observer]` provisions from
scratch, `deploy/rebuild-vps.sh <ip>` rebuilds on a new commit and restarts. Service name:
`rand-node`.

### What the chain-10 rollout actually did (2026-09-16, ~50 minutes after chain 9)

`deploy/cutover-droplet-rand.sh`, one droplet at a time: a peer-id pass first (the new binary on
every droplet, `rand-node address --key`, nothing else touched) to regenerate `deploy/nodes.env`
and the bootstraps, then **C and D first** — every peer id changed with the rename, so the nodes
that bootstrap the fleet had to be on their new identities before anyone dialled them — then E,
F, and the twelve regional validators. The script writes a fresh `rand-node` unit (bootstraps
included), renames the hostname to `rand-node-<name>`, and retires the `shrugg-node` unit. All
16 were over in about 12 minutes; heights were climbing at ~1 block/s with 16 peers each by the
time the last one finished, and A followed from `deploy/run-a.sh`. The explorer on E was
redeployed with the `rand_*` RPC names (randscan `286f399`) right after E's cut-over: healthy,
lag 0. Old binaries and every retired chain's data dir were then removed from all droplets.

### What the chain-9 rollout actually did (2026-09-16)

Order: lon1 alone first (to prove `deploy/cutover-droplet.sh`), then sfo3/tor1/blr1, ams3,
nyc1/nyc2/sfo2, mkc1/mem1, syd1/atl1, then F, C, D, E. Binaries built once on E (4 cores, 8 GB)
from `5f8c6f9` and fanned out droplet-to-droplet over the forwarded agent — the deploy key
(`~/.ssh/id_ed25519`) has to be *in* the agent (`ssh-add`) for the hop to E to authenticate.
**Quorum (13 of 18) landed during the last batch; D reported height 23 while E was still cutting
over**, and ten minutes later all 16 droplets plus A sat at 16 peers each, ~1 block/s. B (the
MacBook Air) was unreachable and stays on chain 8 until its `.update-pin` is set to `5f8c6f9`.

Three things went wrong and are fixed in the scripts:

- `deploy/cutover-fleet.sh` under macOS bash 3.2 re-ran droplets that were already over, and the
  per-droplet script stopped the service *before* its unit check — nyc1, nyc2 and sfo2 were left
  stopped for a few minutes. The unit check now comes first, and the fleet script says to use
  bash ≥ 4 or go one droplet at a time.
- mkc1 and mem1 (30 GB disks) had filled up with three chains' data dirs and crash-looped for days
  before the rollout (RocksDB `No space left on device` on every restart, 10k and 29k restarts);
  the chain-8 resync after clearing the stale dirs filled them again. Their chain-8 data dirs
  were deleted at cut-over (a set-6 binary cannot serve chain 8 anyway); 25 GB free each now.
  Resize those two before chain 9 grows past ~20 GB.
- Chain 9 is cut **without the aggregation section** — see the note at the top.

## Using the chain

```bash
rand --key wallets/shielded-1.key.json balance      # scans the tree; 1000 RAND at genesis
rand --key wallets/shielded-1.key.json send "$(rand --key wallets/shielded-2.key.json address)" 1.5
rand faucet "$(rand --key wallets/shielded-3.key.json address)"
rand --key wallets/shielded-1.key.json program build --guest private_payment --arg 1000 --out pp.json
rand --key wallets/shielded-1.key.json program deploy pp.json
rand --key wallets/shielded-1.key.json call <program-id> --input 400 --input 250 --input 300 --input 75
```

`rand-node status` reports `notes`, `nullifiers`, `tree_root` and `hc_bundle` next to the usual
height and peer counts — the quickest check that a fresh fleet agrees. `is_validator` (this node
holds a key in the register) and `active_validator` (that key is in the current epoch's set) are
different things from phase S2 on, and the second is the one that says whether a node is producing.

### Staking, on a running chain

No new genesis is needed to add or remove a validator (`docs/staking.md`): the operator runs
`rand-node register --key node-x.key.json --payout <rand1…>`, a wallet with 1000 RAND runs
`rand bond <its address> 1000 --registration <hex>`, and the node — started with `--validator`
all along — begins proposing at the next epoch boundary (1000 blocks). Leaving is
`rand-node unbond`, then `rand-node withdraw` two epochs (~2000 blocks) later, which pays the
stake into a note at the payout address. Check the quorum arithmetic first: at 18 validators of
equal stake, 13 must stay online, and every validator added or removed moves that number.

Because every validator here sits exactly at `MIN_STAKE`, any unbond at all drops that node out of
the next epoch's set. That is the rule this fleet exists to exercise — just do it to one node at a
time.

## Smoke test done at cut time (2026-09-13, laptop)

- `rand-node init` from `deploy/genesis-chain8.json` into two separate data dirs: both print
  genesis `8c742fc9…`, chain id 8.
- Nodes A and B started from it and gossiped (`peer_count: 1` each), agreeing on
  `head_hash 8c742fc9…`, `tree_root 1ff29374…`, `hc_bundle 4a27356f…`, `notes: 5`,
  `active_validator: true`.
- `rand_getValidators`: 18 rows, each `stake 1000000000000` (1000 RAND), `active: true`,
  `nonce: 0`, `rewards: 0`, each with its own payout address. `rand_getEpoch`: epoch 0,
  `epoch_blocks 1000`, an 18-address `next_set`. `rand_getSupply`: `genesis_staked 18 000`,
  `genesis_deposited 5000`, `total_supply 23 000` RAND, `invariant_holds: true`.
- **Height stayed 0 and the view advanced — correct, not a bug.** Two of eighteen validators are
  not a quorum, so no QC forms. Block production on this genesis cannot be tested with fewer than
  13 of the 18 keys, and 12 of them are on droplets.
- Control run, same binary, a throwaway 2-validator genesis (chain id 88, same flags): 31 blocks in
  ~40 s at `--block-interval-ms 1000`, both nodes on the same head, 2 register rows with payouts,
  `invariant_holds: true`. So the build commits; chain 8 waits on its fleet.

## History

Chain 1 (2 validators, RAND) and chain 2 (4 validators + 2 observers) ran 2026-09-09; chain 3
followed the RAND → RAND rename and added the faucet; chain 4 (2026-09-10) added confidential
computation on constraint set 2 and ended at 31 952 blocks; chain 5 (2026-09-11) moved to constraint
set 4; chain 6 was the first shielded genesis (phase S1: the note ledger, bundles, the shielded
wallet — an account balance stopped existing); chain 7 (build `01dc23d`) added S3's bridge-as-notes
and call envelopes with 18 validators at 100 000 RAND each, genesis
`55668ebfe1cb842c48bf67fe58bb9e97d344be1e07f8f36b35eb8b405aef8c1f`, and ran to height ~12 620,
where it stopped when the fleet moved to chain 8 on 2026-09-13. Its genesis file is kept here as
`deploy/genesis-chain7.json` and every node still has its `data-*-55668ebf` directory, but build
`03c9fb9` cannot open one — replaying chain 7 needs a `01dc23d` binary.

**Chain 10** (cut and rolled out 2026-09-16, build `a00c88c`) was the RAND rename: every crate,
binary, RPC method (`rand_*`), address prefix (`rand1…`), hash domain, transaction id and p2p
identity carried the new name over chain 9's constraint-set-6, cut-without-aggregation genesis,
18 validators at 1000 RAND each, genesis
`4d757f11cbbf48daaf2040fbd091d70ca66d5ff6fcb228e8319c9014a99bb7ed`. All 16 droplets plus A were
over in about 12 minutes ("What the chain-10 rollout actually did", above), and it ran until the
fleet moved to chain 11 for the short-shielded-address feature. Its genesis file is kept here as
`deploy/genesis-chain10.json`; a chain-11 node cannot open a chain-10 data dir (the genesis format
changed: payouts and alloc owners are receiver ids now, not bare addresses).
