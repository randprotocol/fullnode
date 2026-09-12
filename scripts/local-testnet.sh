#!/usr/bin/env bash
# Launch a 2-validator SHRUGG testnet on this machine (ports 30301/30302, RPC 8545/8546).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release
BIN=target/release/shrugg-node
mkdir -p testnet
[ -f testnet/node1.key.json ] || $BIN keygen --out testnet/node1.key.json
[ -f testnet/node2.key.json ] || $BIN keygen --out testnet/node2.key.json
# Phase S2: every validator needs a payout address in genesis (rewards and unbonded stake are
# paid there as notes), so the wallet makes one key both validators are paid at.
WALLET=target/release/shrugg
[ -f testnet/payout.key.json ] || $WALLET --key testnet/payout.key.json keygen
PAYOUT=$($WALLET --key testnet/payout.key.json address | tail -1)
[ -f testnet/genesis.json ] || $BIN genesis --chain-id 1 \
    --validator testnet/node1.key.json --payout "$PAYOUT" \
    --validator testnet/node2.key.json --payout "$PAYOUT" --out testnet/genesis.json
[ -d testnet/data1/db ] || $BIN init --datadir testnet/data1 --genesis testnet/genesis.json
[ -d testnet/data2/db ] || $BIN init --datadir testnet/data2 --genesis testnet/genesis.json
$BIN run --datadir testnet/data1 --key testnet/node1.key.json --validator \
    --listen /ip4/127.0.0.1/tcp/30301 --rpc 127.0.0.1:8545 --no-mdns > testnet/node1.log 2>&1 &
P1=$!
sleep 1
PEER1=$(grep -o '/ip4/127.0.0.1/tcp/30301/p2p/[A-Za-z0-9]*' testnet/node1.log | head -1)
$BIN run --datadir testnet/data2 --key testnet/node2.key.json --validator \
    --listen /ip4/127.0.0.1/tcp/30302 --rpc 127.0.0.1:8546 --no-mdns --bootstrap "$PEER1" > testnet/node2.log 2>&1 &
P2=$!
echo "node1 pid $P1 rpc http://127.0.0.1:8545  peer $PEER1"
echo "node2 pid $P2 rpc http://127.0.0.1:8546"
echo "logs: testnet/node1.log testnet/node2.log   stop: kill $P1 $P2"
trap 'kill $P1 $P2 2>/dev/null' EXIT
wait
