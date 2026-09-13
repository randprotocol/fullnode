#!/usr/bin/env bash
# Run validator A from a prebuilt binary directory (no cargo build): run-a-pinned.sh <bindir>
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${1:-bin-03c9fb9}/shrugg-node
DATA=data-a-8c742fc9
[ -d $DATA/db ] || $BIN init --datadir $DATA --genesis deploy/genesis-chain8.json
exec $BIN run --datadir $DATA --key deploy/node-a.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    --bootstrap /ip4/164.90.239.200/tcp/30303/p2p/12D3KooWBKYD5bBRczEhzYQrN4jgfgaoGXb6PzbfdjtTjiy1SA5g \
    --bootstrap /ip4/165.245.173.74/tcp/30303/p2p/12D3KooWPrdUXsVXsD3RqaV4otq35awpJgMonSfdu3u8gtq5iUYq
