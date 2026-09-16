#!/usr/bin/env bash
# Run validator A (behind NAT). Bootstraps to the public DigitalOcean nodes C and D; LAN peers are found via mDNS.
set -euo pipefail
cd "$(dirname "$0")/.."
# Prebuilt binaries at the chain-10 build (RAND: every hash domain, id and peer id changed with
# the rename) — the whole fleet must run this one build, because a hash-domain change is a fork
# and a mixed fleet stalls. Override with BINDIR= to test a build.
BINDIR=${BINDIR:-bin-a00c88c}
BIN=$BINDIR/rand-node
[ -x $BIN ] || { echo "$BIN missing — build it at the chain-10 commit or set BINDIR" >&2; exit 1; }
DATA=data-a-4d757f11   # keyed on the genesis hash so a regenerated genesis gets a fresh db
[ -d $DATA/db ] || $BIN init --datadir $DATA --genesis deploy/genesis-chain10.json
exec $BIN run --datadir $DATA --key deploy/node-a.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    --bootstrap /ip4/164.90.239.200/tcp/30303/p2p/12D3KooWSsBY2RbzwoFtRTJjVDghUqJ1zTwM5dMNra5JyVjpHxDK \
    --bootstrap /ip4/165.245.173.74/tcp/30303/p2p/12D3KooWCWS38w4DwVt4vnfBnK7i4VFz3BrMziQpfoczSD7bdFg1
