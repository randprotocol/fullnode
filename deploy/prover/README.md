# prover.randprotocol.org — the validators' prover pool

Two hosts, `a` and `b`, run a delegated prover (`docs/prover.md`), and one name,
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

**Status, 2026-10-22 — two members.** The pool is `a` (4SK4-P64N-XWEN-ZSZZ) and `b`
(0XZX-NZ1J-SPMB-GWZN), each with a key made on its own host, both running the signed `v0.8.0`
rand-prover (`TAG=v0.8.0 MEMBER=… install-host.sh`, then `install-web.sh a:8611=… b:8612=…`). One
real chain-21 transfer proved through each. Clients pin them from wallet 0.8.1 and
`rand prover pair --trusted` from fullnode v0.8.2; older wallets and CLIs refuse both. The
history below is kept for the retired members.

**Status, 2026-10-01 13:00 UTC — per-member keys only.** Four members, each with its own key made
on its host and never copied: `a` (rand-node-a, ZEXQ-1JHV-ZT60-KFB5), `archive2` (rand-archive-2,
D2XV-WXVT-PZRC-D7G8), `nyc3` (SR28-MYT0-GR6A-03DE), `sfo3` (GMNX-Q1QD-FEXG-JHJM), at
`https://prover.randprotocol.org/m/<member>`, listed in `/.well-known/rand-prover-pool.json` and
pinned by wallet 0.6.9 and `rand prover pair --trusted`. **The shared key RGTF-7HKJ-XZFV-GQ1J is
retired** (2026-10-01, on the owner's go once wallet 0.6.9 was public): removed from every host by
`retire-shared.sh`, the operator's copy deleted, and the root URL no longer proves (503). All
members run the signed `v0.6.9` rand-prover under the hardened unit (loopback only, a syscall
filter; `systemd-analyze security` 1.5), installed through `verify_release_sums`; the router
meters submits per address. Verified: one real chain-20 transfer through each member's URL via the
router (a `e89e2cc4…`, archive2 `7c404236…`, nyc3 `bdc88a53…`, sfo3 `f925b4cd…`), and `--trusted`
`9042a402…`. Window: #118.

**Submit limit (VK-10).** The router meters `prover_submit` per client address: a burst of
`SUBMIT_BURST` (default 2), refilled at `SUBMIT_SHARE` (default 0.3) of the pool's **measured**
capacity — the members the router's two-second poll finds up, times `MEMBER_JOBS_PER_MIN`
(default 0.6, one bundle in ~70 s on a c-8). With two members up that is 0.36 a minute: one
address is admitted at most ~23 submits an hour against the ~72 the pool clears, under a third,
and the refill rises and falls with the members that answer. `SUBMIT_PER_MIN`, if set, is only a
ceiling on that refill. **What this does not do:** it bounds one address, not the pool — three
addresses at their full share still take ~95% of it, and an attacker with many addresses (the
meter keys on nginx's `X-Real-IP`) can hold the pool; each member's own slots (`--max-queue 1`) and
nginx's per-address limit are what remain. The figures before audit v12 (fixed 2 + 1 a minute)
let one address take ~61 of the 72 (~85%), which this README then called "cannot hold the pool".
Set the variables in `/etc/rand-prover-pool/router.env` (an old `SUBMIT_PER_MIN=1` there is now a
harmless ceiling) and restart `rand-prover-router`.

## What the pool is

- **One key per member (current: `a` and `b`; the shared-key model below is the retired one).** A
  wallet pins each member's fingerprint and URL (`/m/<member>`). In the retired shared-key model every member
  ran the same `prover.key.json` and `pairings.json`, so a job opened on any of them. The
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
  install-host.sh`), both `a` and `b` before the pool is used on the new chain.

## Retired keys (VK-9)

| key | what it was | pinned by | retired |
|---|---|---|---|
| `RGTF-7HKJ-XZFV-GQ1J` | the key every machine shared | wallet 0.6.8 | 2026-10-01 |
| `ZEXQ-1JHV-ZT60-KFB5` | member `a` | wallets 0.6.9–0.8.0 | 2026-10-22 |
| `D2XV-WXVT-PZRC-D7G8` | member `archive2` | wallets 0.6.9–0.8.0 | 2026-10-22 |
| `SR28-MYT0-GR6A-03DE` | member `nyc3` | wallets 0.6.9–0.8.0 | 2026-10-22 |
| `GMNX-Q1QD-FEXG-JHJM` | member `sfo3` | wallets 0.6.9–0.8.0 | 2026-10-22 |

**What cannot be done.** A released wallet's pins are compiled in. Nothing the pool serves, and
nothing a later release does, removes a pin from a wallet 0.6.9–0.8.0 that someone still runs: it
goes on trusting those four keys at `https://prover.randprotocol.org/m/<name>` until it is
updated. What that trust is worth to an attacker is bounded by two things, both the operator's:
whoever holds a retired key's private half, and whoever can answer at that name over TLS. Such a
wallet would then seal its viewing key (never its spend key) to them.

**What is done.**

- *The current releases refuse the keys.* `rand` carries the table above
  (`crates/randprotocol-client/src/retired-provers.txt`) and neither stores a pairing with one of
  those keys nor sends one anything, so a pairing file from before the retirement is refused at
  the update; a CI test holds the list and the pinned pool apart. Add a line there (and the
  matching entry in the wallets' list, randprotocol/clients) in the same change that retires a key.
- *The pool says so.* The router answers `/m/archive2`, `/m/nyc3` and `/m/sfo3` with HTTP 410 and
  the JSON-RPC error `-32010` "the RandProtocol prover '<name>' was retired … update Rand Wallet
  (or rand) to the current release" (`PROVER_RETIRED`, default those three; `install-web.sh`
  writes the nginx locations that pass them to the router). It refuses to start with a retired
  name among `PROVER_MEMBERS`, so a retired name is never routed to a prover again. `a` kept its
  name under a new key, so an old wallet asking `/m/a` gets the current `a`, sees another key
  than its pin and uses nothing. **Wallets 0.6.9–0.8.0 do not show the pool's message**: they
  report any failed member as "did not answer" and tell the user to try again later. The message
  reaches `curl`, `rand`, and anyone reading the network tab — not those wallets' users.
- *Wallets 0.8.2 and later* tell the user to update when a pinned member answers with another
  key, so the next rotation is announced by the wallet itself.

**What is the owner's** (not in any repository):

1. Destroy the retired keys' private halves wherever a copy remains — the four members' hosts
   (`/var/lib/rand-prover` on each, including any powered-off or snapshotted droplet) and any
   operator copy — and record the date here.
2. Keep `prover.randprotocol.org` (DNS and certificate) under the operator's control for as long
   as a 0.6.9–0.8.0 wallet may be in use; never point `/m/archive2`, `/m/nyc3` or `/m/sfo3` at
   anything.
3. Publish the update notice (below) where wallet users are: the release page of the current
   wallet, the site, and the stores' "what's new".
4. Re-run `install-web.sh` so the web droplet carries the retired locations and `PROVER_RETIRED`.

**The notice.**

> Rand Wallet 0.6.9 to 0.8.0 pin four RandProtocol prover keys that were retired on 22 October
> 2026. Those versions can no longer use the RandProtocol provers — a send that needs them says
> the provers "cannot be reached" — and they still trust the retired keys. Update to the current
> Rand Wallet (0.8.1 or later pins the current provers; from 0.8.2 the wallet tells you itself when
> its pins are out of date). If you use the `rand` command line, update to 0.8.2 or later and run
> `rand prover pair --trusted` again. Your funds are not at risk: a prover is only ever sent a
> viewing key, never the key that spends.

## Files

| file | where it runs | what it is |
|---|---|---|
| `install-host.sh` | operator's machine → a prover host | the release's `rand-prover` (sha-checked), the pool's key and pairing, the unit, the tunnel user |
| `resize-host.sh` | operator's machine → DigitalOcean | a CPU/RAM-only resize of one validator host (default `c-8`), node stopped cleanly, waits for health |
| `rand-prover.service` | prover host | the sandboxed unit (`@THREADS@`, `@MEMORY_MAX@`, `@MAX_PARALLEL@` filled in by the script (`MEMORY_MAX` = 7 GB × `MAX_PARALLEL` + 1 GB); `@THREADS@` = the cores minus one, at most 8 — the same figure `rand-prover run` now defaults to, kept explicit in the unit so a host reads it) |
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
# 3. each host (resize it first if it cannot hold a slot: 6.2 GB and one core per slot).
#    TAG defaults to the current fleet release (v0.8.0); MEMBER names the member (a, b).
#    The unit's MemoryMax is derived from --max-parallel: 7 GB per slot + 1 GB = 8G for one slot, 15G for two.
MEMBER=a TUNNEL_PUBKEY=~/rand-prover-trusted/public/web-tunnel.pub \
  deploy/prover/install-host.sh root@<ip>
# 4. the web droplet
WEB=root@<web> PUBLIC_DIR=~/rand-prover-trusted/public \
  deploy/prover/install-web.sh a:8611=<ip-a> b:8612=<ip-b>
# 5. check
curl -s -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"prover_info","params":[]}' https://prover.randprotocol.org/
rand prover pair "$(cat ~/rand-prover-trusted/public/link.txt)" --name randprotocol
rand --prover send <address> 1
```

Adding or removing a member is steps 3 and 4 again with the new list. Rotating the pairing token
(`unpair`, `pair` again, copy `pairings.json` to every member, restart them) invalidates every
wallet's pairing and needs a client release; rotating the key does too.
