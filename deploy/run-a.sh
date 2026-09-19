#!/usr/bin/env bash
# Run validator A (behind NAT). Bootstraps to the public DigitalOcean nodes C and D; LAN peers are found via mDNS.
set -euo pipefail
cd "$(dirname "$0")/.."
# Prebuilt binaries at the fleet's pinned build, 4504a03 (tag v0.3, a same-chain update on chain 12;
# chain 12 itself was cut from 17db41d, the short-shielded-address revert, and c66e6b8 was a
# byte-identical re-pin). The whole fleet runs one build: a genesis-format change is a fork and a
# mixed fleet stalls. Override with BINDIR= to test a build.
BINDIR=${BINDIR:-bin-86af6eb}
BIN=$BINDIR/rand-node
[ -x $BIN ] || { echo "$BIN missing — build it at the chain-13 commit or set BINDIR" >&2; exit 1; }
DATA=data-a-8123ccac   # keyed on the genesis hash so a regenerated genesis gets a fresh db
[ -d $DATA/db ] || $BIN init --datadir $DATA --genesis deploy/genesis-chain13.json
exec $BIN run --datadir $DATA --key deploy/node-a.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    --bootstrap /ip4/164.90.239.200/tcp/30303/p2p/12D3KooWSsBY2RbzwoFtRTJjVDghUqJ1zTwM5dMNra5JyVjpHxDK \
    --bootstrap /ip4/165.245.173.74/tcp/30303/p2p/12D3KooWCWS38w4DwVt4vnfBnK7i4VFz3BrMziQpfoczSD7bdFg1
