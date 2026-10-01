# prover.randprotocol.org — the validators' prover pool

Five validator hosts also run a delegated prover (`docs/prover.md`), and one name,
`https://prover.randprotocol.org`, reaches whichever of them has a free slot. A wallet that cannot
make a bundle proof itself (a browser, a phone) pairs with the pool once and sends it viewing-key
jobs; the spend key never leaves the wallet (split authorisation, `docs/prover.md` §8).

```
wallet ──https──> nginx (web droplet, TLS, per-address limit, no access log)
                    └─> router.py 127.0.0.1:8650   least-loaded prover with a free slot
                          ├─ ssh tunnel 127.0.0.1:8601 ──> prover host 1  127.0.0.1:8600  rand-prover
                          ├─ ssh tunnel 127.0.0.1:8602 ──> prover host 2  …
                          └─ …
```

**Status, 2026-10-01 11:20 UTC — per-member keys (audit v7, VK-9).** Four members, each with
its OWN key generated on its host and never copied (no backup): `a` (rand-node-a, ZEXQ-1JHV-ZT60-KFB5),
`archive2` (rand-archive-2, D2XV-WXVT-PZRC-D7G8), `nyc3` (SR28-MYT0-GR6A-03DE) and `sfo3`
(GMNX-Q1QD-FEXG-JHJM), at `https://prover.randprotocol.org/m/<member>`, listed in the pool descriptor
`/.well-known/rand-prover-pool.json` that wallet 0.6.9 pins (`rand-prover-member.service`, port
8610). **The shared key RGTF-7HKJ-XZFV-GQ1J is retiring:** wallet 0.6.8 pins it, so it still serves
the root URL from the two dedicated droplets only (`rand-prover.service`, port 8600) until 0.6.9 is
out and the owner decides the cut-over; then `retire-shared.sh` on nyc3/sfo3 and shred
`~/rand-prover-trusted/home`. Every instance runs the hardened unit (loopback only, a syscall filter;
`systemd-analyze security` 1.5, VK-13), installed only from a release whose SHA256SUMS verified against
the release key (OPS-9), with a 600 s proving timeout coming in the next release (VK-12) and the
watchdog meanwhile. The router meters submits per address across the pool (VK-10). Window: #118.

## What the pool is

- **One key, one pairing.** Every member runs with the same `prover.key.json` and `pairings.json`,
  so a job sealed to the pool's key opens on any of them and a wallet pins one fingerprint. The
  pairing token is public — it is in every client and in
  `https://prover.randprotocol.org/.well-known/rand-prover.json` — so the token authorises nothing;
  capacity is protected by nginx's per-address limit and by each prover's slots.
- **Viewing-key jobs only.** No member runs with `--accept-spend-key`; the pairing has no `own=1`,
  so no wallet will send it a spend key either. What a member learns from a job is the sending
  wallet's viewing key: that wallet's whole history, past and future. The operators of the pool are
  trusted with that and with nothing else. Someone who wants that kept private runs their own
  prover.
- **A short line.** A bundle is valid for `ledger::TIME_WINDOW` = 256 blocks after the height it
  names (about five minutes on chain 18). Each member proves one bundle at a time on all its cores
  but one — 68.6–72.9 s on an 8-vCPU `c-8` with the `v0.6.7-prover.1` build (Plonky3's `parallel`
  feature; v0.6.7's own single-core binary took 217–237 s on the same class of droplet, and a
  294 s proof on a shared-CPU droplet was refused for its height) — and lets one job wait
  (`--max-queue 1`). Past that it answers `busy`, the router tries the next member, and when the
  whole pool is full the wallet is told `busy` at once instead of being handed a proof it can no
  longer use.
- **A sibling service.** `rand-prover.service` runs beside `rand-node.service`, as its own
  unprivileged user, sandboxed, at a lower CPU weight and under a memory ceiling — not as
  `rand-node run --prover`, where a prover killed for memory stops the validator. It listens on
  loopback only; the web droplet reaches it through an SSH tunnel whose key may open that one port.
  A chain cut does not touch it unless the cut changes the bundle guest, the constraint set or the
  prover wire — then every member needs that build's `rand-prover` (`TAG=… WANT_SHA_PROVER=…
  install-host.sh`), all five before the pool is used on the new chain.

## Files

| file | where it runs | what it is |
|---|---|---|
| `install-host.sh` | operator's machine → a prover host | the release's `rand-prover` (sha-checked), the pool's key and pairing, the unit, the tunnel user |
| `resize-host.sh` | operator's machine → DigitalOcean | a CPU/RAM-only resize of one validator host (default `c-8`), node stopped cleanly, waits for health |
| `rand-prover.service` | prover host | the sandboxed unit (`@THREADS@`, `@MEMORY_MAX@` filled in by the script) |
| `install-web.sh` | operator's machine → the web droplet | tunnels, router, nginx vhost, certificate, the pairing document |
| `prover-tunnel@.service` | web droplet | one tunnel; the instance name is the local port |
| `rand-prover-router.service`, `router.py` | web droplet | the router; `test_router.py` tests it against fake provers |
| `nginx-prover.conf` | web droplet | the vhost |

The pool's secret (`prover.key.json`, `pairings.json`) and its public link live outside the
repository, on the operator's machine: `~/rand-prover-trusted/home/` (mode 0700) and
`~/rand-prover-trusted/public/` (`link.txt`, `trusted-prover.json`). Losing the key means a new
fingerprint and a new release of every client, so it is backed up with the validator keys.

## Standing it up

```sh
# 0. DNS: prover.randprotocol.org A <web droplet>, DNS-only like rpc.randprotocol.org.
# 1. the pool's key and pairing, made once on any Linux host with the release binary:
rand-prover --home ./home keygen
rand-prover --home ./home pair --name public --url https://prover.randprotocol.org   # the link
# 2. the tunnel key
WEB=root@<web> deploy/prover/install-web.sh --key > ~/rand-prover-trusted/public/web-tunnel.pub
# 3. each host (resize it first if it cannot hold a slot: 5.74 GB and one core per slot)
POOL_HOME=~/rand-prover-trusted/home TUNNEL_PUBKEY=~/rand-prover-trusted/public/web-tunnel.pub \
  deploy/prover/install-host.sh root@<ip>
# 4. the web droplet
WEB=root@<web> PUBLIC_DIR=~/rand-prover-trusted/public \
  deploy/prover/install-web.sh 8601=<ip1> 8602=<ip2> 8603=<ip3> 8604=<ip4> 8605=<ip5>
# 5. check
curl -s -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"prover_info","params":[]}' https://prover.randprotocol.org/
rand prover pair "$(cat ~/rand-prover-trusted/public/link.txt)" --name randprotocol
rand --prover send <address> 1
```

Adding or removing a member is steps 3 and 4 again with the new list. Rotating the pairing token
(`unpair`, `pair` again, copy `pairings.json` to every member, restart them) invalidates every
wallet's pairing and needs a client release; rotating the key does too.
