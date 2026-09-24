#!/usr/bin/env bash
# Run validator A (the laptop, behind NAT) on chain 14. Bootstraps to the public nodes C and D.
# Chain 14 runs from NODE_A_HOME (default ~/rand-node-a), not from a checkout: the validator key
# lives off-repo in ~/.rand-chain14 (audit v3 OPS-1) and the checkout is shared between sessions.
# The whole fleet runs one build (0154fe2, v0.5.5): a genesis-format change is a fork and a mixed
# fleet stalls. NEVER run node B here too — B is the sgp1 droplet.
set -euo pipefail
HOME_A=${NODE_A_HOME:-$HOME/rand-node-a}
KEYDIR=${KEYDIR:-$HOME/.rand-chain14}
cd "$HOME_A"
BINDIR=${BINDIR:-bin-0154fe2}
BIN=$BINDIR/rand-node
[ -x $BIN ] || { echo "$HOME_A/$BIN missing — build it at the chain-14 commit or set BINDIR" >&2; exit 1; }
DATA=data-a-1cff3b7d   # keyed on the genesis hash so a regenerated genesis gets a fresh db
[ -d $DATA/db ] || $BIN init --datadir $DATA --genesis genesis-chain14.json
exec $BIN run --datadir $DATA --key "$KEYDIR/node-a.key.json" --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    --bootstrap /ip4/164.90.239.200/tcp/30303/p2p/12D3KooWEQEbUwZRgqhDPXhW7vNBmcRcnhUDGUADe81VFdv3ALYe \
    --bootstrap /ip4/165.245.173.74/tcp/30303/p2p/12D3KooWJyc5oDHggAr89e9QrRFBy9Tg8TxXh18yzrb1SM6KKLYw
