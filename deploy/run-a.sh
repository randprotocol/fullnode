#!/usr/bin/env bash
# Run validator A (behind NAT). Bootstraps to the public DigitalOcean nodes C and D; LAN peers are found via mDNS.
set -euo pipefail
cd "$(dirname "$0")/.."
# Prebuilt binaries at the chain-11 build (the short-shielded-address feature: receiver ids,
# the registry, the record files — no hash-domain or peer-id change, so this is the same p2p
# identity as chain 10) — the whole fleet must run this one build, because a genesis-format
# change is a fork and a mixed fleet stalls. Override with BINDIR= to test a build.
BINDIR=${BINDIR:-bin-ee716d7}
BIN=$BINDIR/rand-node
[ -x $BIN ] || { echo "$BIN missing — build it at the chain-11 commit or set BINDIR" >&2; exit 1; }
DATA=data-a-79123fa7   # keyed on the genesis hash so a regenerated genesis gets a fresh db
[ -d $DATA/db ] || $BIN init --datadir $DATA --genesis deploy/genesis-chain11.json
exec $BIN run --datadir $DATA --key deploy/node-a.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    --bootstrap /ip4/164.90.239.200/tcp/30303/p2p/12D3KooWSsBY2RbzwoFtRTJjVDghUqJ1zTwM5dMNra5JyVjpHxDK \
    --bootstrap /ip4/165.245.173.74/tcp/30303/p2p/12D3KooWCWS38w4DwVt4vnfBnK7i4VFz3BrMziQpfoczSD7bdFg1
