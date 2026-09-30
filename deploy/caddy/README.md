# The public RPC: `rpc.randprotocol.org`

**F's Caddy is not in the path.** `Caddyfile.rpc-randprotocol-org` is droplet F's
`/etc/caddy/Caddyfile`, copied verbatim from F's disk (unchanged since 2026-09-20 03:02 UTC) — but
on F `caddy.service` is `disabled` and `inactive (dead)` with no start since the host booted,
nothing listens on 80 or 443, and F's ufw admits only 22 and 30303 (read 2026-09-27). The file is
kept as a record of a hop that was written and never carried traffic after 2026-09-20; it must not
be started (see "RS-2" below for why that would be a regression).

## What actually serves a public request

```
client → Cloudflare (proxied DNS) → web droplet 159.65.138.161, nginx vhost rpc.randprotocol.org
         (randprotocol.org repo, server/nginx-rpc.conf = /etc/nginx/sites-enabled/rpc-randprotocol;
          its own Let's Encrypt certificate, DNS-01 via Cloudflare, valid to 2026-12-19;
          set_real_ip_from <Cloudflare ranges> + real_ip_header CF-Connecting-IP;
          limit_req zone=rpc 180 r/min burst 60 per client address)
       → proxy_pass http://127.0.0.1:8788/api/rpc, X-Real-IP $remote_addr, CF-Connecting-IP stripped
       → the sale service's RPC proxy (randprotocol.org repo, server/sale/src/rpc.rs)
       → SALE_RPC_UPSTREAM = http://127.0.0.1:18545 (since 2026-09-27; was https://randscan.org/rpc)
       → rpc-tunnel-obs1.service on the web droplet: ssh -N -L 127.0.0.1:18545:127.0.0.1:8545
         rpctunnel@168.144.46.203 (key /root/.ssh/obs1_rpc_tunnel, host key pinned in
         /root/.ssh/obs1_rpc_known_hosts)
       → obs1's node on 127.0.0.1:8545 — the archive, no --prune-history, datadir on the
         250 GiB volume
```

**Why obs1, not E.** Until 2026-09-27 the upstream was randscan's Caddy route on E
(`https://randscan.org/rpc`, `remote_ip` the web droplet only) to E's node. E prunes like every
validator, and a pruned node answers a fresh wallet's first `rand_getBlocks(0, …)` with `-32010`
(the rescan's RS-1), so the public RPC must end at a node that keeps every block. E was unpruned
as a stopgap (it grows ~4.3 GB/day on a 77 GB disk); obs1 keeps full history on a volume.
obs1's own nginx serves randbridge.org behind Cloudflare and trusts `CF-Connecting-IP` from
anywhere, so an IP allowlist there would be spoofable — hence an SSH tunnel: `rpctunnel` on obs1
has no shell (`/usr/sbin/nologin`) and its `authorized_keys` entry is
`restrict,port-forwarding,permitopen="127.0.0.1:8545",command="/usr/sbin/nologin"`, so the key
can forward to the node's RPC port and nothing else (checked: a shell and a forward to port 22
are both refused). The node sees the proxy as loopback, as E's did through Caddy — the proxy's
`RPC_ALLOWED` stays the only method gate. randscan's `/rpc` route on E is now unused.

**Rollback:** `SALE_RPC_UPSTREAM=https://randscan.org/rpc` in `/etc/randprotocol/sale.env`
(backup `/root/sale.env.bak-20260927`), `systemctl restart sale` — and turn E's pruning off again
first if it was turned back on.

The web droplet's vhost was installed at 2026-09-20 03:04 UTC, two minutes after F's Caddyfile was
written (website commit `66a6be9`); the DNS record went to the web droplet and F's hop was never
brought back. F's own node binds `127.0.0.1:8545` and nothing forwards to it. The older passthrough
is on F as `/etc/caddy/Caddyfile.bak-20260920-passthrough` (not copied here — it must not come
back).

## RS-2 — "every caller shares F's rate-limit bucket" — refuted (2026-09-27)

The suspicion (also the 2026-09-24 deep scan's, which added `set_real_ip_from 159.89.185.254` and
`real_ip_recursive on` to the main randprotocol.org vhost for it): F's Caddy re-enters Cloudflare,
so Cloudflare would set `CF-Connecting-IP` to F and every public caller would share one bucket.
It would be true if F were in the path — Caddy's `X-Forwarded-For` is not the header nginx reads,
and with `real_ip_recursive` a single trusted value in `CF-Connecting-IP` resolves to F itself, so
the 09-24 trust line never helped. But F is not in the path (above), and the web droplet's access
log shows the rpc vhost (`POST /`) metering real clients separately — 2026-09-26, addresses cut to
two octets:

```
 85 180.248.x.x 07h 200 | 125 180.248.x.x 07h 429   (curl, one client hitting its own limit)
 19 2400:9800:x 07h 200                              (same hour, a different client, never 429'd)
277 5.31.x.x    08h 200 |  13 5.31.x.x    08h 429
 37 83.110.x.x  10–11h 200                           (a browser)
```

No request in the two uncompressed logs comes from `159.89.185.254`. The limits are per client, as
designed. What remains for the operator is housekeeping, listed at the end.

## The node's own public listener (audit v6, VK-2 / RPC-4) — point the tunnel at it

From v0.6.8 the node has a listener made for this hop: `rand-node run --public-rpc 127.0.0.1:8546`.
It serves a fixed method set (no viewing-key methods, no `rand_mint`, no `rand_getPeers`), takes
no batch and no WebSocket, meters every caller together, and never counts a caller as loopback —
so the method gate and the meter are the node's, not only the sale proxy's `RPC_ALLOWED` in
another repository. **To do on the roll, by the operator** (not yet done; this file records the
target, not the state):

1. obs1's unit: add `--public-rpc 127.0.0.1:8546` to `ExecStart`.
2. obs1's `rpctunnel` key: `permitopen="127.0.0.1:8546"` in place of `:8545`.
3. The web droplet's `rpc-tunnel-obs1.service`: `-L 127.0.0.1:18545:127.0.0.1:8546`.
4. Check from the web droplet: `rand_chainId` answers through `127.0.0.1:18545`;
   `rand_getPeers` answers "not served on this node's public listener".
5. E, if randscan's `/rpc` route is ever used again: the same flag, and the route's upstream to
   `127.0.0.1:8546`. randscan's own explorer keeps `127.0.0.1:8545` — it needs the viewing methods.

Until then the section below describes the running chain.

## Why the proxy is security-critical

E's node sees every proxied request from loopback (randscan's Caddy), and it decides two protections
by the TCP peer address, treating loopback as the operator:

- **RPC-2 metering** (`RpcLimiter::allow_at`, `crates/randprotocol-node/src/rpc.rs`): loopback is
  exempt, so every public caller is one unmetered client at the node.
- **VK-3's loopback gate** (`require_loopback`): the viewing-key methods answer loopback callers,
  so every public caller would pass it.

The node's own per-caller defences are therefore off for public traffic, and the sale service's
proxy stands where they would. It does, verified 2026-09-26 against the live endpoint:

1. **A method allowlist** (`RPC_ALLOWED`) — `rand_mint`, `rand_importViewingKey`,
   `rand_getViewingNotes`, `rand_removeViewingKey`, `rand_getUnsealed` and `rand_getPeers` are not
   on it and answer `-32601 method not allowed here`. An allowlist, so a method added to the node
   later stays closed until someone opens it there.
2. **No batches** — a top-level array is refused, so a refused method cannot ride inside one.
3. **Per-IP limits** — 120 reads and 6 `rand_sendTransaction` a minute, keyed on the real client IP
   (`client_ip` reads `X-Real-IP`, set by the web droplet's nginx from `CF-Connecting-IP` for
   Cloudflare's ranges only — a direct connection to the origin is metered as its own TCP peer and
   cannot name an address), and a 12 MiB body cap.

Change the allowlist in the randprotocol.org repo, never by pointing Caddy at a node directly.

## The faucet (decided 2026-09-27)

`rand_mint` stays as the genesis sets it — there is no per-node switch — and stays off the public
path:

- Chain 15's faucet is `staking.faucet_recipients`-limited: it pays only the 16 spend keys the
  genesis names, within `faucet_budget_per_epoch`. It cannot pay anyone else.
- F's node answers `rand_mint` only on its own loopback, which nothing forwards to; E's is reached
  publicly only through the proxy, which refuses it.
- So nothing changes on F (whose Caddy does not run). Mint to an allowlisted key from the host itself (`rand faucet <address>` against
  `127.0.0.1:8545`), never by opening the method on the proxy.

## Checks after any change here or to the proxy

- Every refused method above returns an error through `https://rpc.randprotocol.org`, alone and
  inside a batch.
- `rand_status`, `rand_getBlockByHeight` and the methods wallets and randscan use still answer.
- A burst from one IP is throttled; two IPs are metered separately.
- F's and E's nodes still bind `127.0.0.1:8545` only (the topology rule in `docs/deploy.md`).

## Housekeeping left for the operator (not done; read-only investigation 2026-09-27)

- **Do not start `caddy` on F.** If it ran and DNS moved back to F, the double Cloudflare hop would
  make RS-2 real: every caller would share F's bucket. Either leave it disabled or remove the
  package and this file together.
- The main randprotocol.org vhost's `set_real_ip_from 159.89.185.254;` and `real_ip_recursive on;`
  (added 2026-09-24 for the non-existent F hop) are dead config; drop them with the next edit of
  that file (`nginx -t && systemctl reload nginx`).
- `/etc/nginx/sites-enabled/` on the web droplet holds `randprotocol.bak-20260924` and
  `rpc-randprotocol.bak-20260924` as regular files, so nginx loads them and prints "conflicting
  server name … ignored" for every name on `nginx -t`. The live files win only because they sort
  first; move the backups out of `sites-enabled/`.
- The public RPC ends at E, a validator that prunes to one day: heights older than a day answer
  `-32010` through `rpc.randprotocol.org`.
- IPv6 callers are bucketed per /128 at both nginx and the sale service; one host with a /64 can
  rotate addresses. Keying IPv6 on its /64 is a sale-service change, if it ever matters.
