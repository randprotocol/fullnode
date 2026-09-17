#!/usr/bin/env bash
# Cut the chain-12 genesis: chain 10's form again. The short shielded address (chain 11, v0.2)
# is reverted at 17db41d — a receiver id is a hash and a sender cannot seal a note to a hash, so
# the first payment to a wallet that never registered needed a payment request or a hand-carried
# record. Until a short form keeps both unconditional sendability and privacy, the address is
# `rand1` + base58(pk ‖ kem_ek) as on chain 10, payouts and deposit notes are bare addresses
# again, and the registry is gone: a chain-11 node cannot parse this genesis, so chain 12 is a
# fresh chain like every format change before it. Same 18 validators, same five alloc wallets.
# Cut WITHOUT the aggregation section by default (AGGREGATION=on restores the section; the
# activation values are still the user-owned ≥ 64 GB measurements).
#
# The regional validators' public keys come from the chain-10 genesis (positions 6..17); the six
# local nodes from their key files; every payout from deploy/payout/<name>.key.json (the same
# keys — `rand address` prints the long form again).
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness).
# Cut once, distribute the file byte-identically.
set -euo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN10=${CHAIN10:-deploy/genesis-chain10.json}
ALLOC_WALLETS=${ALLOC_WALLETS:-wallets}          # shielded-{1..5}.key.json (gitignored)
OUT=${OUT:-deploy/genesis-chain12.json}
# AGGREGATION=off cuts the chain without the section (a genesis like chain 8's, on this build):
# the security-fixed constraint-set-6 tree goes to the fleet while the section's activation
# values are still the user-owned hardware measurements (docs/deploy.md, "Chain 9 activation").
# A later chain activates aggregation; a section cannot be added to a running chain.
AGGREGATION=${AGGREGATION:-off}

# ── the aggregation section ────────────────────────────────────────────────────────────────
# The bond, cap, schedule and window (spec §2.3, §3.3): the activation values.
BOND=${BOND:-1000}
MAX_COVERS=${MAX_COVERS:-3}
SUBSIDY_BASE=${SUBSIDY_BASE:-100}
HALVING_BLOCKS=${HALVING_BLOCKS:-210000}
AGGREGATION_WINDOW=${AGGREGATION_WINDOW:-256}

# The admitted shape (spec §2.3, R2): profile, tier, the six declared log-heights, the bundle
# guest's digest (hc), and the aggregate program's digest. FILL-AT-ACTIVATION: these are the
# *test-profile* measurements (the fleet's 2-in/2-out bundle at tier 14, the recursion
# conformance vectors' digest) — replace ALL THREE of TIER, MEM, and the digests at activation
# with the production measurements. `hc` is ZkExecutor::hc_bundle() as 64 hex chars; the
# digest is the four canonical words as 16 lowercase hex chars each, concatenated.
SHAPE_PROFILE=${SHAPE_PROFILE:-test}
SHAPE_TIER=${SHAPE_TIER:-14}
SHAPE_PROGRAM=${SHAPE_PROGRAM:-12}
SHAPE_INPUT=${SHAPE_INPUT:-10}
SHAPE_KECCAK=${SHAPE_KECCAK:-0}
SHAPE_SHA256=${SHAPE_SHA256:-0}
SHAPE_PUBLIC=${SHAPE_PUBLIC:-2}
SHAPE_MEM=${SHAPE_MEM:-16}
# The keyword `hc_bundle` means "this build's pinned bundle guest digest": the genesis command
# substitutes it, so the cut cannot carry a stale hc from a stale note. It is the only value a
# chain-9 genesis may take here.
SHAPE_HC=${SHAPE_HC:-hc_bundle}
SHAPE_DIGEST=${SHAPE_DIGEST:-33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8}

payout() { "$WALLET" --key "deploy/payout/$1.key.json" address | tail -1; }

args=()
# node a..f: our own key files, positions 0..5 of the chain-8 list.
for n in a b c d e f; do
  args+=(--validator "deploy/node-$n.key.json,1000,$(payout "$n")")
done
# The twelve regional validators: hex public keys, chain-8 positions 6..17.
regions=(lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1)
for i in "${!regions[@]}"; do
  pk=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['validators'][6+int(sys.argv[2])]['public_key'])" "$CHAIN10" "$i")
  args+=(--validator "$pk,1000,$(payout "${regions[$i]}")")
done
# Five 1000 RAND deposit notes, one per shielded wallet.
for i in 1 2 3 4 5; do
  args+=(--alloc "$("$WALLET" --key "$ALLOC_WALLETS/shielded-$i.key.json" address | tail -1)=1000")
done

if [ "$AGGREGATION" = off ]; then
  "$NODE" genesis --chain-id "${CHAIN_ID:-12}" "${args[@]}" \
    --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT"
else
  "$NODE" genesis --chain-id "${CHAIN_ID:-12}" "${args[@]}" \
    --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT" \
    --aggregation "$BOND,$MAX_COVERS,$SUBSIDY_BASE,$HALVING_BLOCKS,$AGGREGATION_WINDOW" \
    --admitted-shape "$SHAPE_PROFILE,$SHAPE_TIER,$SHAPE_PROGRAM,$SHAPE_INPUT,$SHAPE_KECCAK,$SHAPE_SHA256,$SHAPE_PUBLIC,$SHAPE_MEM,$SHAPE_HC,$SHAPE_DIGEST"
fi
