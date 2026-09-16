#!/usr/bin/env bash
# Cut the chain-9 genesis: 18 validators, each staked at exactly the 1000 RAND staking
# minimum, each with its own payout wallet, five 1000 RAND deposit notes, faucet on,
# production FRI, 1000-block epochs — and, new in chain 9, the `aggregation` section (block
# aggregation, spec §2.3): the bond, the subsidy schedule, the window, and the one admitted
# bundle shape with its aggregate program digest. A hard fork, like every chain before it.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash: every deposit note
# carries fresh commitment randomness (see deploy/README.md). Cut once, distribute the file
# byte-identically.
#
# ⚠ FILL-AT-ACTIVATION: `ADMITTED_SHAPE` below ships with the test-profile values measured on
# this tree (so the script is reviewable end to end), NOT the production activation values.
# What activation must replace before cutting for real — see docs/deploy.md, "Chain 9
# activation": the shape's tier and the `aggregate_program_digest`, measured on the production
# bundle (the startup key-build measures the digest: `rand-node` builds it from the shape
# alone). Genesis validation refuses a zero digest, so the placeholder can never reach a
# fleet; cutting with the test-profile values below is just as wrong for a production fleet —
# the same refusal class, one level up: no fleet bundle would match the shape.
#
# The six local nodes are named by their key files. The twelve regional DigitalOcean validators
# are chain-8's, keyed as in deploy/cut-chain8-genesis.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN8=${CHAIN8:-deploy/genesis-chain8.json}
ALLOC_WALLETS=${ALLOC_WALLETS:-wallets}          # shielded-{1..5}.key.json (gitignored)
OUT=${OUT:-deploy/genesis-chain9.json}
# AGGREGATION=off cuts the chain without the section (a genesis like chain 8's, on this build):
# the security-fixed constraint-set-6 tree goes to the fleet while the section's activation
# values are still the user-owned hardware measurements (docs/deploy.md, "Chain 9 activation").
# A later chain activates aggregation; a section cannot be added to a running chain.
AGGREGATION=${AGGREGATION:-on}

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
  pk=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['validators'][6+int(sys.argv[2])]['public_key'])" "$CHAIN8" "$i")
  args+=(--validator "$pk,1000,$(payout "${regions[$i]}")")
done
# Five 1000 RAND deposit notes, one per shielded wallet.
for i in 1 2 3 4 5; do
  args+=(--alloc "$("$WALLET" --key "$ALLOC_WALLETS/shielded-$i.key.json" address | tail -1)=1000")
done

if [ "$AGGREGATION" = off ]; then
  "$NODE" genesis --chain-id "${CHAIN_ID:-9}" "${args[@]}" \
    --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT"
else
  "$NODE" genesis --chain-id "${CHAIN_ID:-9}" "${args[@]}" \
    --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT" \
    --aggregation "$BOND,$MAX_COVERS,$SUBSIDY_BASE,$HALVING_BLOCKS,$AGGREGATION_WINDOW" \
    --admitted-shape "$SHAPE_PROFILE,$SHAPE_TIER,$SHAPE_PROGRAM,$SHAPE_INPUT,$SHAPE_KECCAK,$SHAPE_SHA256,$SHAPE_PUBLIC,$SHAPE_MEM,$SHAPE_HC,$SHAPE_DIGEST"
fi
