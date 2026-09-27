# The public RPC: `rpc.randprotocol.org`

`Caddyfile.rpc-randprotocol-org` is droplet F's `/etc/caddy/Caddyfile`, copied verbatim as it runs
(2026-09-27, unchanged since 2026-09-20). Keep it that way: a change on F that is not also a commit
here is drift.

## What actually serves a public request

The public RPC is **not** a passthrough to F's node. The chain is:

```
client → Cloudflare → Caddy on F (this file) → https://randprotocol.org/api/rpc
       → the sale service's RPC proxy (randprotocol.org repo, server/sale/src/rpc.rs)
       → SALE_RPC_UPSTREAM = https://randscan.org/rpc
       → randscan's Caddy route on E (randscan repo, deploy/Caddyfile; admits only the web
         droplet 159.65.138.161, 403s everyone else)
       → E's node on 127.0.0.1:8545
```

F's own node binds `127.0.0.1:8545` and nothing forwards to it. The previous passthrough is on F
as `/etc/caddy/Caddyfile.bak-20260920-passthrough` (not copied here — it must not come back).

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
   (`client_ip` reads `X-Real-IP`, set by nginx on the web droplet), and a 12 MiB body cap.

Change the allowlist in the randprotocol.org repo, never by pointing Caddy at a node directly.

## The faucet (decided 2026-09-27)

`rand_mint` stays as the genesis sets it — there is no per-node switch — and stays off the public
path:

- Chain 15's faucet is `staking.faucet_recipients`-limited: it pays only the 18 allowlisted spend
  keys (all the operator's), within `faucet_budget_per_epoch`. It cannot pay anyone else.
- F's node answers `rand_mint` only on its own loopback, which nothing forwards to; E's is reached
  publicly only through the proxy, which refuses it.
- So nothing changes on F. Mint to an allowlisted key from the host itself (`rand faucet <address>` against
  `127.0.0.1:8545`), never by opening the method on the proxy.

## Checks after any change here or to the proxy

- Every refused method above returns an error through `https://rpc.randprotocol.org`, alone and
  inside a batch.
- `rand_status`, `rand_getBlockByHeight` and the methods wallets and randscan use still answer.
- A burst from one IP is throttled; two IPs are metered separately.
- F's and E's nodes still bind `127.0.0.1:8545` only (the topology rule in `docs/deploy.md`).
