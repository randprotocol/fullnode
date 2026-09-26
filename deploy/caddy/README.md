# Caddy in front of the public RPC (droplet F)

`https://rpc.randprotocol.org` is Cloudflare → Caddy on droplet F → that node's own
`127.0.0.1:8545` (`docs/deploy.md`, `deploy/README.md` "Public RPC"). **The live Caddy
configuration is not in this repository yet.** Operator: copy F's `/etc/caddy/Caddyfile` (and any
file it imports) into this directory as it is running, commit it, and keep it here from then on —
a change on F that is not also a commit here is drift. Nothing below is that config; it is what
the config must do and why.

## Why the front filter is security-critical

Behind the reverse proxy, **every caller reaches the node from loopback.** The node decides two
protections by the TCP peer address, and both treat loopback as the operator itself:

- **RPC-2 metering** (`RpcLimiter::allow_at`, `crates/randprotocol-node/src/rpc.rs`): per-client
  token buckets, one token per request object — loopback is exempt. Behind Caddy every public
  caller is one unmetered client.
- **VK-3's loopback gate** (`require_loopback`): `rand_importViewingKey`, `rand_getViewingNotes`
  and `rand_removeViewingKey` answer loopback callers only unless the node runs with
  `--rpc-viewing-open`. Behind Caddy every public caller passes it.

So on F the node's own per-caller defences are off for public traffic, and Caddy is the only
thing standing where they would. The filter F runs must:

1. **Allowlist methods, refusing at least** `rand_mint` (the faucet), `rand_importViewingKey`,
   `rand_getViewingNotes`, `rand_removeViewingKey`, `rand_getUnsealed` and `rand_getPeers`. An
   allowlist, not a denylist: a method added to the node later must stay closed on F until
   someone decides to open it.
2. **Refuse JSON-RPC batches** (a top-level array body). A method filter that reads only a single
   object's `method` is bypassed by putting the refused method inside a batch, and a batch of 20
   costs the node twenty requests for one proxied one.
3. **Rate-limit per client IP** — the real client's, from the header Cloudflare sets and only when
   the request came from Cloudflare's ranges, never a header the client can set itself.

## Checks once the config is committed

- Every refused method above returns an error through `https://rpc.randprotocol.org`, alone and
  inside a batch.
- `rand_status`, `rand_getBlockByHeight` and the methods wallets and randscan use still answer.
- A burst from one IP is throttled; two IPs are metered separately.
- F's node itself still binds `127.0.0.1:8545` only (the topology rule in `docs/deploy.md`).
