# Testnet: chain id 6 (SHRUGG, shielded pool S1+S3, zkVM constraint set 4)

Test keys only; all seeds are committed on purpose so any machine can pull and run.
Genesis hash `7913586b10f2f5539469c6cb4817b81e0edba6c86950fb00cedff6ad7288cbbb`, cut 2026-09-12 from
build `01dc23d` (branch `shielded-s3`: notes ledger, bundles, faucet mints, deploy/call on bundles
with call-input envelopes, bridge as notes; no staking register yet, no bridge section). Four
validators A–D with stake 100000 each (quorum 3 of 4), five 1000-SHRUGG genesis deposit notes
owned by `wallets/shielded-{1..5}.key.json` on the laptop (gitignored), **faucet enabled**,
**confidential computation enabled** (production FRI profile), `hc_bundle`
`4a27356f379571036025a4a8661c294b0edec2b7cf7fbfd60b472b186cbd4afb`. There are no accounts on this
chain: `shrugg faucet` mints into a note for a `shrugg1…` address and `shrugg send` proves a bundle
(about 100 s on a laptop). Datadirs are `data-<letter>-7913586b`.

Chain 5 (genesis 3a82b0c7, account chain, build dbea18c) halted at height 29,854 and was replaced
by this cut. The next fork (S2 staking + constraint set 5) is a new chain id again.

| node | role | where | address | peer id |
|---|---|---|---|---|
| A | validator | laptop, LAN 192.168.100.123 (NAT) | 2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v | 12D3KooWRbvv6T8iQz1jT5ijvPoo6CEGy3yRdiuxkUMJGUkTNq6P |
| B | validator | 192.168.100.79 (NAT) | ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z | 12D3KooWMUjpbd6U7c6KTjVXy3121aV6JLka47dh4ZPwGjyMV8Bf |
| C | validator | DigitalOcean fra1 164.90.239.200 (moved from sgp1 2026-09-12) | F6rYLexPhyMmwPNqbEmyyp5FiTmtQqDgZyqScUqYY4F6 | 12D3KooWBKYD5bBRczEhzYQrN4jgfgaoGXb6PzbfdjtTjiy1SA5g |
| D | validator | DigitalOcean sgp1 178.128.91.236 | 5tMgLSzXL8keU1vg2wtGEXRJkmfBK6GzhjNjxrCFgCaj | 12D3KooWPrdUXsVXsD3RqaV4otq35awpJgMonSfdu3u8gtq5iUYq |
| E | observer | DigitalOcean sgp1 188.166.235.187 (explorer) | CxeG7vJaxUoKBZZe8U8LGXohH2FvcCbE47AufK6Mp2jf | 12D3KooWR1nihpYk6vvdRYuq2WMGUtzDiwygytTXZJszdSnaVmDM |
| F | observer | DigitalOcean nyc3 138.197.19.86 (moved from sgp1 2026-09-12) | DcuuZrzDSJedhFnynLFchNfYmW4UKiZT2nEKbcs2ojmJ | 12D3KooWJwsFwi9CawJrPyA7ZBT5Q6mYWmctNvLRt3SuS7SdyU6j |
| lon1 | observer | DigitalOcean lon1 139.59.160.76 | 8UcsaXDSSWcC6fT3CWT89fgUvG4ubaYd61FUQHKiUDLv | 12D3KooWJFWHiHNHnBPhjVctvLQFZQo7ecfkqbVpjuArysC88ETc |
| sfo3 | observer | DigitalOcean sfo3 24.144.89.22 | 9rex7stS6d9QxaAh5nghjaUEratKJFUAmLAoxRFmP7LM | 12D3KooWQuPiWbAy4Pk6v4phQQauKc3iUAAFyuRnG5ahZVgLSMvQ |
| tor1 | observer | DigitalOcean tor1 146.190.243.29 | CRW3fQsuFa7YSdU5ZDrRMxQjJ4ET9kzf6hg1D8CAhoWH | 12D3KooW9qxfAEdazt4yRB2pzWbmhFPTafy1ojJ1cdJArgHrp8Z5 |
| blr1 | observer | DigitalOcean blr1 167.71.235.108 | ASzbnFwqVnwsrN81iytkuhNbs8f93Q3h4rQjXPDUNMjU | 12D3KooWHBtRvSeR3c4FkkQRtEJ6huEeFhG9Uj46NGs8N29ZaCsP |
| syd1 | observer | DigitalOcean syd1 170.64.226.65 | 8cHAjP3wgGDv55Ym2qZrYyu2Mvc7b86jsrN6vWcwZoJV | 12D3KooWFmqkbLxNQb1wiTHzvRj8Xh5PkVDzPXJGzQrVZJBTv9Ms |
| atl1 | observer | DigitalOcean atl1 165.245.142.90 | BV2BfMZJo2Lpo3pR7RfAjytnFxmMhzCWxoUHhXhjT2qL | 12D3KooWSDCzHY7aTDyJxBMEGex4G4tWhfwt5ijFzCzsHP11npDw |

D and E (sgp1) and C (fra1) have public IPs and act as bootstrap nodes; the regional observers were provisioned with `deploy/provision-observer.sh` (a small droplet, prebuilt binaries, no compiler) and dial D and E; A and B are behind NAT and dial out to C and D
(`deploy/run-a.sh`, `deploy/run-b.sh`). Full multiaddrs are in `deploy/nodes.env`.

Droplets: `deploy/push-to-vps.sh <ip> <letter> "<bootstrap multiaddrs>" [validator|observer]` provisions from scratch;
`deploy/rebuild-vps.sh <ip>` rebuilds on new commits and restarts (data kept). Service name: `shrugg-node`.

On 192.168.100.79:
```bash
git pull && ./deploy/run-b.sh
shrugg --key deploy/node-b.key.json balance
shrugg faucet ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z        # 100 SHRUGG from the testnet faucet
shrugg --key deploy/node-b.key.json send 2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v 1.5
```

Live on chain 4 (2026-09-10): program `private_payment(1000)` deployed by A in block 10, id
`675adeea7e4242d8dc48bf56faedb7bea14a4f832d7c8a973f942fa7dd850065`; first confidential call in block 19
(tx `d4c75efbe141567eae72d5f639a1d444eb074d8b58a6592d95e01cd39a2364e3`), outputs `[1, 0, 25, 0, 0, 0, 0, 0]`,
25 units paid to B. Laptop proving 21 s; droplet verifier-key warm 7 s (one-time, background); receipt and
balance identical on A, C, D, E, F. Further calls the same evening: a below-threshold run (block 78, outputs all
zero, no effect, B unchanged) and a call proved and submitted entirely on observer E (79 s to prove on 2 vCPUs;
block 105, 200 units to B). `shrugg-node verify --mode full` on F re-verified all 109 blocks including the three
proofs in 6.9 s. B ends at 100.000000225 SHRUGG on every node.

Confidential call from the laptop (private inputs never leave it):
```bash
shrugg --key deploy/node-a.key.json program build --guest private_payment --arg 1000 --out pp.json
shrugg --key deploy/node-a.key.json program deploy pp.json
shrugg --key deploy/node-a.key.json call <program-id> --input 400 --input 250 --input 300 --input 75 --to <B address>
```

Chain 5 (2026-09-11, cut by the Air's session, fleet joined 09:04 UTC): first confidential call on the
constraint-set-4 zkVM committed in block 37 (prove 7.4 s on the laptop, proof 435 KB, down from 21 s / 878 KB).
Rule for this fleet: every node runs the pinned build commit (`dbea18c`); a zkVM constraint change is a fork,
announced by the zkVM session first, and moves the whole fleet at once with a fresh genesis. Observer E also
hosts the RandScan explorer, which re-indexes itself on a chain id change.

History: chain 1 (2 validators, SESH) and chain 2 (4 validators + 2 observers, SESH) ran on 2026-09-09;
chain 3 followed the SESH -> SHRUGG rename and added the faucet; chain 4 (2026-09-10) added confidential
computation on constraint set 2 and ended at 31,952 blocks when the fleet moved to constraint set 4.

## Cutting a shielded genesis

A shielded chain has no per-validator allocation: value exists only as a note someone holds the
spend key for, so `--alloc` takes a **shielded address** and creates one deposit note. The
addresses come from wallet keys, which are not node keys.

```bash
# one spend key per wallet that should start with funds (wallets/ is gitignored — never commit these)
for i in 1 2 3 4 5; do shrugg --key wallets/shielded-$i.key.json keygen; done

# the genesis: four validators, five 1000-SHRUGG deposit notes, faucet on, production FRI
args=()
for i in 1 2 3 4 5; do
  args+=(--alloc "$(shrugg --key wallets/shielded-$i.key.json address)=1000")
done
shrugg-node genesis --chain-id 6 \
  --validator deploy/node-a.key.json --validator deploy/node-b.key.json \
  --validator deploy/node-c.key.json --validator deploy/node-d.key.json \
  --stake 100000 "${args[@]}" --faucet --fri-profile production \
  --out deploy/genesis-shielded.example.json
```

`deploy/genesis-shielded.example.json` in this repo is exactly that file, produced by that command
(chain id 6, genesis hash `6457243776e7c152b946a3a245f6748d9934ffc6f08ac22f868fb4014b38ddf3`; the live fleet genesis is `deploy/genesis.json`, hash 7913586b…,
`hc_bundle 4a27356f379571036025a4a8661c294b0edec2b7cf7fbfd60b472b186cbd4afb`). It is an **example**:
its five deposit notes belong to spend keys that live only on the machine that cut it, so re-cut
your own rather than adopting it. Two properties make that unavoidable:

- Every deposit note carries fresh commitment randomness, so the same `--alloc` list produces a
  different genesis hash every time. A deterministic `r` would let anyone confirm a guess at a
  genesis note's owner and amount by recomputing the commitment. Cut it once, distribute the file
  byte-identically, and keep it.
- `hc_bundle` pins the bundle guest every proof on the chain is checked against. A node whose build
  assembles a different guest refuses to start and names both digests, so a zkVM constraint change
  is a fork here exactly as it is for confidential calls.

Then, on each machine, as for any chain:

```bash
shrugg-node init --datadir ./data-6 --genesis genesis-shielded.json
shrugg-node run --datadir ./data-6 --key deploy/node-a.key.json --validator \
  --block-interval-ms 1000 --bootstrap /ip4/<ip>/tcp/30303/p2p/<peer id>
```

Keep `--block-interval-ms` at 1000 or slower: a bundle proof takes about 100 seconds and its
anchor is valid for 256 blocks, so a much faster chain rejects honest transfers whose anchor
expired mid-proof (`docs/shielded.md` §5).

The wallet side, on any machine with a key file:

```bash
shrugg --key wallets/shielded-1.key.json balance      # scans the tree; ~1000 SHRUGG at genesis
shrugg --key wallets/shielded-1.key.json send "$(shrugg --key wallets/shielded-2.key.json address)" 1.5
shrugg faucet "$(shrugg --key wallets/shielded-3.key.json address)"   # if --faucet was set
```

`shrugg-node status` on any node reports `notes`, `nullifiers`, `tree_root` and `hc_bundle`
alongside the usual height and peer counts, which is the quickest check that a fresh fleet agrees.
