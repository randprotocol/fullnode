#!/usr/bin/env bash
# Run validator A from a prebuilt binary directory (no cargo build): run-a-pinned.sh <bindir>
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${1:-bin-b00bc72}/shrugg-node
DATA=data-a-7e6271a3
[ -d $DATA/db ] || $BIN init --datadir $DATA --genesis deploy/genesis.json
exec $BIN run --datadir $DATA --key deploy/node-a.key.json --validator \
    --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 \
    --bootstrap /ip4/167.172.65.63/tcp/30303/p2p/12D3KooWBKYD5bBRczEhzYQrN4jgfgaoGXb6PzbfdjtTjiy1SA5g \
    --bootstrap /ip4/178.128.91.236/tcp/30303/p2p/12D3KooWPrdUXsVXsD3RqaV4otq35awpJgMonSfdu3u8gtq5iUYq
