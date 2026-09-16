# Testnet: chain id 9 (SHRUGG shielded pool, staking, bridge, zkVM constraint set 6, the pre-v0.1 security fixes)

Test keys only; all seeds are committed on purpose so any machine can pull and run.

> **Chain 9 (cut 2026-09-16) is the constraint-set-6 chain, on build `5f8c6f9`**: the M4.3/M4.4
> re-vendor (the public input segment, `pv::NUM` 34, the six-keyed verifier key), the RPC
> hardening, the vendored recursion VM and the chain-side aggregation code, the pre-v0.1
> security review's three fixes (H1, M1, L1 — `../security/fullnode-security-review-pre-v0.1-2026-09-16.md`),
> and libp2p 0.57. **Cut without the `aggregation` section** (`AGGREGATION=off
> deploy/cut-chain9-genesis.sh`): the section's activation values are the user-owned ≥ 64 GB
> measurements (`docs/deploy.md`, "Chain 9 activation") and a section cannot be added to a
> running chain, so aggregation activates on a later chain. Chain 8 (build `03c9fb9`,
> constraint set 5) is retired: a set-6 build cannot join the chain-8 fleet and a set-5 build
> cannot verify a set-6 chain, in either direction. The chain-8 record is under "History".

| | |
|---|---|
| chain id | **9** |
| genesis hash | **`dbb7498b83723ccf4de66f3497a50237bff3306e71d9598eb462120c5ae28904`** |
| genesis file | `deploy/genesis-chain9.json` (cut 2026-09-16; chain 8's stays at `deploy/genesis-chain8.json`) |
| pinned build | **`5f8c6f9`** — binaries in `bin-5f8c6f9/` (macOS) and E's `/root/fullnode/target/release` (Linux), `.update-pin` content is `5f8c6f9` |
| zkVM | **constraint set 6** (the public input segment; M4.3 EVM and M4.4 sBPF/sha256 guests ride along) |
| `hc_bundle` | `4a27356f379571036025a4a8661c294b0edec2b7cf7fbfd60b472b186cbd4afb` |
| validators | **18, every one staked at exactly 1000 SHRUGG** (the staking minimum) |
| quorum | **13 of 18** (strictly more than two thirds of 18 000 SHRUGG of stake) |
| epochs | `--epoch-blocks 1000`; `UNBONDING_EPOCHS = 2`, so unbonded stake releases ~2000 blocks later |
| genesis value | 18 000 SHRUGG staked in the register + 5 × 1000 SHRUGG as deposit notes = 23 000 SHRUGG |
| faucet | **on** (`shrugg faucet [address]`, up to 100 SHRUGG per call on any node) |
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

Every validator holds exactly **1000 SHRUGG**, which is `MIN_STAKE` — one unit less and genesis
refuses the file outright (a validator below the minimum would sit in the register but in no epoch's
set). That is deliberate: this fleet is here to exercise the minimum-stake rule, the epoch
boundary and the withdraw path on a real network, so every node sits exactly on the line. Chain 7
gave each of the same 18 nodes 100 000 SHRUGG; chain 8 gives them 1/100th of that.

Consequence to plan around: **13 of the 18 must be online to commit anything.** With 12 up, views
advance and nothing finalises. Stake is uniform, so quorum is a headcount here.

`payout` is where this validator's rewards and released stake are paid, as a note. It is register
state and therefore part of the genesis hash. Each validator has its own wallet in
`deploy/payout/<name>.key.json` — read `deploy/payout/README.md` before trusting the regional names
in this table: `a`…`f` are verified against the key files in `deploy/`, `lon1`…`mem1` are inferred
from chain 7's validator order and can only be confirmed on the droplet itself.

| name | where (chain-7 fleet) | validator address | pubkey | payout (`deploy/payout/…`) |
|---|---|---|---|---|
| a | laptop, LAN 192.168.100.123 (NAT) | `2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v` | `15321b04570d7095…` | `shrugg11qgA3ETvT…uLm4n9` |
| b | 192.168.100.79 (NAT), MacBook Air, auto-updater | `ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z` | `4d491d8a5540f005…` | `shrugg188sGyCRpX…hY5T8k` |
| c | DigitalOcean fra1 164.90.239.200 | `F6rYLexPhyMmwPNqbEmyyp5FiTmtQqDgZyqScUqYY4F6` | `f3557730c8a76b43…` | `shrugg14wXebNPJc…rxb3sy` |
| d | DigitalOcean ric1 165.245.173.74 | `5tMgLSzXL8keU1vg2wtGEXRJkmfBK6GzhjNjxrCFgCaj` | `e95ecd68c5621147…` | `shrugg13SKXv49EH…thJHN4` |
| e | DigitalOcean sgp1 188.166.235.187 (RandScan explorer) | `CxeG7vJaxUoKBZZe8U8LGXohH2FvcCbE47AufK6Mp2jf` | `9ffac1e8ff6b687d…` | `shrugg12nJ3vSqUc…E3YbGt` |
| f | DigitalOcean nyc3 159.89.185.254 | `DcuuZrzDSJedhFnynLFchNfYmW4UKiZT2nEKbcs2ojmJ` | `b277b8eb8863fca2…` | `shrugg1CE5oAjb8S…VFDQs2` |
| lon1 | DigitalOcean lon1 139.59.160.76 | `8UcsaXDSSWcC6fT3CWT89fgUvG4ubaYd61FUQHKiUDLv` | `7edc60fc6e6e35f6…` | `shrugg12kmqp9BMq…2h77jF` |
| sfo3 | DigitalOcean sfo3 24.144.89.22 | `9rex7stS6d9QxaAh5nghjaUEratKJFUAmLAoxRFmP7LM` | `5394ea2fc122a869…` | `shrugg1cjU3K9faj…x2sB7S` |
| tor1 | DigitalOcean tor1 146.190.243.29 | `CRW3fQsuFa7YSdU5ZDrRMxQjJ4ET9kzf6hg1D8CAhoWH` | `71528cc5c8b11715…` | `shrugg191phQ9Ffb…YCHDJc` |
| blr1 | DigitalOcean blr1 167.71.235.108 | `ASzbnFwqVnwsrN81iytkuhNbs8f93Q3h4rQjXPDUNMjU` | `ca6b8bdc43f95a4f…` | `shrugg1aD55SbVMS…HJjUTs` |
| syd1 | DigitalOcean syd1 170.64.226.65 | `8cHAjP3wgGDv55Ym2qZrYyu2Mvc7b86jsrN6vWcwZoJV` | `574d78491644c873…` | `shrugg1CdUmb2fXv…v2YX2p` |
| atl1 | DigitalOcean atl1 165.245.142.90 | `BV2BfMZJo2Lpo3pR7RfAjytnFxmMhzCWxoUHhXhjT2qL` | `c82e55fd7ff180e0…` | `shrugg13iwyU6yJM…cJcDx3` |
| ams3 | DigitalOcean ams3 146.190.233.230 | `6orzEKd3Ds3ZFmp21pidbF19kAe6AczzPCtnMVrKRLeA` | `76bcc53c2370404b…` | `shrugg16ct7YSQsS…DsRzq9` |
| nyc1 | DigitalOcean nyc1 192.81.214.91 | `F5RVdAe3Wo2AWHsjKZjFKmGcnTHvJrDpdSHL8gnF4wN1` | `59bd8ed1017f2743…` | `shrugg15eMjSnZxL…GqYsZj` |
| nyc2 | DigitalOcean nyc2 107.170.49.234 | `9hU2qrPFxbcZjSse6MJnapYRs4RchALWtJH4RRrbwDGo` | `2c111e425d2fa4d3…` | `shrugg1AY2hQjQ3X…MHYjq9` |
| sfo2 | DigitalOcean sfo2 143.110.135.126 | `6NGLfkZcTs3i5LTTbqoYKM9aQCs7ZXygHirTg2AtWhsA` | `c18d93c46e9f8cc5…` | `shrugg18BY14Pv39…EwrVu6` |
| mkc1 | DigitalOcean mkc1 201.79.35.212 | `8m5BoX2RA4xTVNfDwKMbWQ3JSChrj69hvJzdSEKMsZDM` | `38c1921b1738182a…` | `shrugg1qtwxvqK9M…7obifJ` |
| mem1 | DigitalOcean mem1 168.144.61.10 | `6T5WyBUrYN1noLi3tDKC1Uw5Vf3xabExnWCDdik7VTPV` | `ce48ef3e62463c08…` | `shrugg15ijmGYjDG…N7co5n` |

The rows are in genesis order (which is chain 7's validator order). C, D, E and the rest of the
droplets have public IPs and act as bootstrap nodes; A and B are behind NAT and dial out
(`deploy/run-a.sh`, `deploy/run-b.sh`). Full multiaddrs and peer ids are in `deploy/nodes.env`.

## The five genesis notes

A shielded chain has no per-validator allocation: value exists only as a note someone holds the
spend key for, so `--alloc` takes a shielded address and creates one deposit note. As on chain 7,
1000 SHRUGG goes to each of the five wallets in `wallets/` (gitignored — those keys live on the
machine that cut this genesis and nowhere else):

| wallet | address | amount |
|---|---|---|
| `wallets/shielded-1.key.json` | `shrugg14mvBw1njfEY…BcuX6X` | 1000 SHRUGG |
| `wallets/shielded-2.key.json` | `shrugg17twtYjPKv2J…6nQRjq` | 1000 SHRUGG |
| `wallets/shielded-3.key.json` | `shrugg18NRCt4GE9qu…AxGBHY` | 1000 SHRUGG |
| `wallets/shielded-4.key.json` | `shrugg1BFkPNgb7vZq…xS8jqF` | 1000 SHRUGG |
| `wallets/shielded-5.key.json` | `shrugg1DoRgCizWrqB…DhyMfb` | 1000 SHRUGG |

## No bridge section, and why it stays that way

Chain 8 has no `bridge` section, exactly like chain 7. The bridge's guardian set, emitters and asset
registry are genesis state and go into the genesis hash, so **a bridge cannot be added to a running
chain**: switching it on means cutting chain 9. The S3 code is in this build and its bridge RPCs
answer, but with no guardian set there is nothing to attest a deposit, so `shrugg bridge-mint` and
`shrugg bridge-burn` have nothing to do here. If the fleet wants to exercise the bridge, that is a
new genesis with a `bridge` section and a decision about who the guardians are — worth doing
deliberately rather than bolting onto this cut.

What chain 8 *does* add over chain 7 is the staking half: bonding, unbonding, withdraw, epoch sets
and per-validator payouts (phase S2), and call envelopes (S3).

## The exact command that cut this genesis

`deploy/cut-chain8-genesis.sh`, run from the repo root against the `03c9fb9` release binaries:

```bash
./deploy/cut-chain8-genesis.sh          # ALLOC_WALLETS=wallets by default
```

It expands to one `shrugg-node genesis` call — 18 `--validator <key or hex pubkey>,1000,<payout>`
and 5 `--alloc <shrugg1…>=1000`:

```bash
shrugg-node genesis --chain-id 8 \
  --validator "deploy/node-a.key.json,1000,$(payout a)" \
  ... (b, c, d, e, f the same way) ... \
  --validator "<chain-7 pubkey #6>,1000,$(payout lon1)" \
  ... (sfo3 … mem1, chain-7 pubkeys #7..#17) ... \
  --alloc "$(addr 1)=1000" ... --alloc "$(addr 5)=1000" \
  --epoch-blocks 1000 --faucet --fri-profile production \
  --out deploy/genesis-chain8.json
```

where `payout n` is `shrugg --key deploy/payout/$n.key.json address` and `addr i` is
`shrugg --key wallets/shielded-$i.key.json address`. The twelve regional public keys are read out of
`deploy/genesis-chain7.json` (committed here as history for exactly this reason), because those
nodes' key files were generated on the droplets and exist nowhere in this repo.

Re-running the script does **not** reproduce this genesis hash: every deposit note carries fresh
commitment randomness, so the same `--alloc` list yields a different hash every time. A
deterministic `r` would let anyone confirm a guess at a genesis note's owner and amount by
recomputing the commitment. Cut once, distribute `deploy/genesis-chain8.json` byte-identically,
keep it.

## Cut-over checklist, per node

Nothing about chain 7 is reusable — different chain id, incompatible proofs — so this is a clean
start on every machine. Keep chain 7's data directory around if you want to keep serving it; the
new `DATA` name is keyed on the genesis hash, so the two never collide.

1. **Binary**: `bin-5f8c6f9/shrugg-node` and `bin-5f8c6f9/shrugg` (or `cargo build --release` at
   commit `5f8c6f9`; the Linux ones are built once on E and fanned out by `deploy/cutover-droplet.sh`). Every node on the fleet must run this one build — a constraint-set change is a
   fork, and a mixed fleet stalls.
2. **Genesis**: `deploy/genesis-chain9.json`, byte-identical everywhere. `shrugg-node init` prints
   the hash; it must read `dbb7498b83723ccf4de66f3497a50237bff3306e71d9598eb462120c5ae28904`.
3. **Fresh data dir**: `data-<letter>-dbb7498b` (never reuse a chain-8 directory).
4. **`.update-pin`** on the MacBook Air (node B, auto-updater): set its content to **`5f8c6f9`**, or
   the updater drags B back onto the chain-8 build and B drops out of the set.
5. **Start**, and check `shrugg-node status`: `height` climbing, `chain id 9`,
   `hc_bundle 4a27356f…`, `active_validator: true`, `notes: 5` at genesis,
   `tree_root 1ff293744074aa828b7a63cc26e5591d6f04173606a3b5048981649bbe2b35da` at height 0.
6. **Quorum**: nothing commits until 13 of the 18 are up. Bring the droplets up before declaring a
   stall.
7. **Explorer** on E re-indexes itself on a chain id change; RandScan's chain 7 index can be dropped
   once nobody is asking for it.

```bash
shrugg-node init --datadir data-c-8c742fc9 --genesis deploy/genesis-chain8.json
shrugg-node run --datadir data-c-8c742fc9 --key deploy/node-c.key.json --validator \
    --block-interval-ms 1000 --bootstrap /ip4/<ip>/tcp/30303/p2p/<peer id>
```

### The droplet unit change, exactly as applied (2026-09-13 rollout)

Every droplet already had a `shrugg-node` systemd unit pointing at its chain-7 data dir. The only
edit the unit needed was the data-dir name — the key path, listen address, `--rpc 127.0.0.1:8545`,
`--no-mdns` and both `--bootstrap` multiaddrs stay exactly as they were, because the peer ids did
not change with the genesis:

```bash
# 1. new data dir, from the chain-8 genesis (must print 8c742fc9…, chain id 8)
systemctl stop shrugg-node
shrugg-node init --datadir /root/data-$(hostname)-8c742fc9 \
    --genesis /root/fullnode/deploy/genesis-chain8.json

# 2. repoint the unit: the datadir suffix, and nothing else
cp -a /etc/systemd/system/shrugg-node.service /root/shrugg-node.service.chain7.bak
sed -i 's/-55668ebf/-8c742fc9/g' /etc/systemd/system/shrugg-node.service

# 3. restart
systemctl daemon-reload && systemctl restart shrugg-node
shrugg status          # chain id 8 via shrugg_chainId, height climbing, peer_count → 15–16
```

`-55668ebf` occurs exactly once per unit (in `--datadir`), so the `sed` is safe as written; the
chain-7 backup of each unit is left at `/root/shrugg-node.service.chain7.bak`. Data dirs are keyed
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
`shrugg-node`.

## Using the chain

```bash
shrugg --key wallets/shielded-1.key.json balance      # scans the tree; 1000 SHRUGG at genesis
shrugg --key wallets/shielded-1.key.json send "$(shrugg --key wallets/shielded-2.key.json address)" 1.5
shrugg faucet "$(shrugg --key wallets/shielded-3.key.json address)"
shrugg --key wallets/shielded-1.key.json program build --guest private_payment --arg 1000 --out pp.json
shrugg --key wallets/shielded-1.key.json program deploy pp.json
shrugg --key wallets/shielded-1.key.json call <program-id> --input 400 --input 250 --input 300 --input 75
```

`shrugg-node status` reports `notes`, `nullifiers`, `tree_root` and `hc_bundle` next to the usual
height and peer counts — the quickest check that a fresh fleet agrees. `is_validator` (this node
holds a key in the register) and `active_validator` (that key is in the current epoch's set) are
different things from phase S2 on, and the second is the one that says whether a node is producing.

### Staking, on a running chain

No new genesis is needed to add or remove a validator (`docs/staking.md`): the operator runs
`shrugg-node register --key node-x.key.json --payout <shrugg1…>`, a wallet with 1000 SHRUGG runs
`shrugg bond <its address> 1000 --registration <hex>`, and the node — started with `--validator`
all along — begins proposing at the next epoch boundary (1000 blocks). Leaving is
`shrugg-node unbond`, then `shrugg-node withdraw` two epochs (~2000 blocks) later, which pays the
stake into a note at the payout address. Check the quorum arithmetic first: at 18 validators of
equal stake, 13 must stay online, and every validator added or removed moves that number.

Because every validator here sits exactly at `MIN_STAKE`, any unbond at all drops that node out of
the next epoch's set. That is the rule this fleet exists to exercise — just do it to one node at a
time.

## Smoke test done at cut time (2026-09-13, laptop)

- `shrugg-node init` from `deploy/genesis-chain8.json` into two separate data dirs: both print
  genesis `8c742fc9…`, chain id 8.
- Nodes A and B started from it and gossiped (`peer_count: 1` each), agreeing on
  `head_hash 8c742fc9…`, `tree_root 1ff29374…`, `hc_bundle 4a27356f…`, `notes: 5`,
  `active_validator: true`.
- `shrugg_getValidators`: 18 rows, each `stake 1000000000000` (1000 SHRUGG), `active: true`,
  `nonce: 0`, `rewards: 0`, each with its own payout address. `shrugg_getEpoch`: epoch 0,
  `epoch_blocks 1000`, an 18-address `next_set`. `shrugg_getSupply`: `genesis_staked 18 000`,
  `genesis_deposited 5000`, `total_supply 23 000` SHRUGG, `invariant_holds: true`.
- **Height stayed 0 and the view advanced — correct, not a bug.** Two of eighteen validators are
  not a quorum, so no QC forms. Block production on this genesis cannot be tested with fewer than
  13 of the 18 keys, and 12 of them are on droplets.
- Control run, same binary, a throwaway 2-validator genesis (chain id 88, same flags): 31 blocks in
  ~40 s at `--block-interval-ms 1000`, both nodes on the same head, 2 register rows with payouts,
  `invariant_holds: true`. So the build commits; chain 8 waits on its fleet.

## History

Chain 1 (2 validators, SESH) and chain 2 (4 validators + 2 observers) ran 2026-09-09; chain 3
followed the SESH → SHRUGG rename and added the faucet; chain 4 (2026-09-10) added confidential
computation on constraint set 2 and ended at 31 952 blocks; chain 5 (2026-09-11) moved to constraint
set 4; chain 6 was the first shielded genesis (phase S1: the note ledger, bundles, the shielded
wallet — an account balance stopped existing); chain 7 (build `01dc23d`) added S3's bridge-as-notes
and call envelopes with 18 validators at 100 000 SHRUGG each, genesis
`55668ebfe1cb842c48bf67fe58bb9e97d344be1e07f8f36b35eb8b405aef8c1f`, and ran to height ~12 620,
where it stopped when the fleet moved to chain 8 on 2026-09-13. Its genesis file is kept here as
`deploy/genesis-chain7.json` and every node still has its `data-*-55668ebf` directory, but build
`03c9fb9` cannot open one — replaying chain 7 needs a `01dc23d` binary.
