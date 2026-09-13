#!/usr/bin/env bash
# Cut the chain-8 genesis: 18 validators, each staked at exactly the 1000 SHRUGG staking minimum,
# each with its own payout wallet, five 1000 SHRUGG deposit notes, faucet on, production FRI,
# 1000-block epochs, no bridge section. Constraint set 5 (build 03c9fb9).
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash: every deposit note carries
# fresh commitment randomness (see deploy/README.md). Cut once, distribute the file byte-identically.
#
# The six local nodes are named by their key files. The twelve regional DigitalOcean validators have
# no key files here, so their Dilithium2 public keys are taken from chain 7's validator list, in
# chain-7 order, and paired with the payout wallet of the same name — see deploy/payout/README.md
# for how solid that name mapping is.
set -euo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:-target/release/shrugg-node}
WALLET=${WALLET:-target/release/shrugg}
CHAIN7=${CHAIN7:-deploy/genesis-chain7.json}
ALLOC_WALLETS=${ALLOC_WALLETS:-wallets}          # shielded-{1..5}.key.json (gitignored)
OUT=${OUT:-deploy/genesis-chain8.json}

payout() { "$WALLET" --key "deploy/payout/$1.key.json" address | tail -1; }

args=()
# node a..f: our own key files, positions 0..5 of the chain-7 list.
for n in a b c d e f; do
  args+=(--validator "deploy/node-$n.key.json,1000,$(payout "$n")")
done
# The twelve regional validators: hex public keys, chain-7 positions 6..17.
regions=(lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1)
for i in "${!regions[@]}"; do
  pk=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['validators'][6+int(sys.argv[2])]['public_key'])" "$CHAIN7" "$i")
  args+=(--validator "$pk,1000,$(payout "${regions[$i]}")")
done
# Five 1000 SHRUGG deposit notes, one per shielded wallet.
for i in 1 2 3 4 5; do
  args+=(--alloc "$("$WALLET" --key "$ALLOC_WALLETS/shielded-$i.key.json" address | tail -1)=1000")
done

"$NODE" genesis --chain-id 8 "${args[@]}" \
  --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT"
