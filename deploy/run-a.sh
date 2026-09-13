#!/usr/bin/env bash
# Run validator A (behind NAT). Bootstraps to the public DigitalOcean nodes C and D; LAN peers are found via mDNS.
set -euo pipefail
cd "$(dirname "$0")/.."
# Prebuilt binaries at commit 03c9fb9 — the whole fleet must run this one build, because a
# constraint-set change is a fork and a mixed fleet stalls. Override with BINDIR= to test a build.
BINDIR=${BINDIR:-bin-03c9fb9}
BIN=$BINDIR/shrugg-node
[ -x $BIN ] || { echo "$BIN missing — build it at 03c9fb9 or set BINDIR" >&2; exit 1; }
DATA=data-a-8c742fc9   # keyed on the genesis hash so a regenerated genesis gets a fresh db
[ -d $DATA/db ] || $BIN init --datadir $DATA --genesis deploy/genesis-chain8.json
exec $BIN run --datadir $DATA --key deploy/node-a.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    --bootstrap /ip4/164.90.239.200/tcp/30303/p2p/12D3KooWBKYD5bBRczEhzYQrN4jgfgaoGXb6PzbfdjtTjiy1SA5g \
    --bootstrap /ip4/165.245.173.74/tcp/30303/p2p/12D3KooWPrdUXsVXsD3RqaV4otq35awpJgMonSfdu3u8gtq5iUYq
