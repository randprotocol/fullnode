#!/usr/bin/env bash
# Cut the chain-13 genesis: chain 12's validators, payouts and alloc notes, plus the five call
# limits (spec docs/superpowers/specs/2026-09-19-call-limits-design.md §3, §11). Each limit is a
# genesis field bound into the hash, so a chain-12 build cannot run this genesis and a chain-12
# node never sees it: chain 13 is a fresh chain like every format change before it. The program
# id with a public input (`rand-program-2`), ProgramRecord.public_len/public_digest and the
# receipt's h_pub are chain-13 formats as well.
#
# The chain-13 values (each overridable by env):
#   max_program_words        65 535     the zkVM's limit; the translated ERC-20 and SPL images fit
#   max_proof_bytes          8 388 608  8 MiB: the ERC-20 call (~3.5 MB with the keccak table)
#                                       with room for a tier-20 SPL call proof
#   max_block_bytes          20 971 520 20 MiB ≥ 2 · 8 MiB + 1 MiB (the rule genesis enforces):
#                                       the fee bundle's and the call's worst-case proofs
#   max_call_envelope_bytes  65 536     64 KiB: (65 536 − 1 252) / 4 = 16 071 sealed input
#                                       words, enough for SPL's 10 458
#   max_program_public_words 32 768     SPL Token's ELF is 27 151 words
# Cut WITHOUT the aggregation section by default (AGGREGATION=on restores the section; the
# activation values are still the user-owned ≥ 64 GB measurements).
#
# The regional validators' public keys come from the chain-12 genesis (positions 6..17, the same
# keys as chain 10); the six local nodes from their key files; every payout from
# deploy/payout/<name>.key.json.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness).
# Cut once, distribute the file byte-identically.
set -euo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
CHAIN12=${CHAIN12:-deploy/genesis-chain12.json}
ALLOC_WALLETS=${ALLOC_WALLETS:-wallets}          # shielded-{1..5}.key.json (gitignored)
CHAIN_ID=${CHAIN_ID:-13}
OUT=${OUT:-deploy/genesis-chain13.json}
AGGREGATION=${AGGREGATION:-off}

# ── the call limits (spec §3) ──────────────────────────────────────────────────────────────
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-8388608}
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-20971520}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}

# ── the aggregation section (unchanged from chain 12; used only with AGGREGATION=on) ───────
BOND=${BOND:-1000}
MAX_COVERS=${MAX_COVERS:-3}
SUBSIDY_BASE=${SUBSIDY_BASE:-100}
HALVING_BLOCKS=${HALVING_BLOCKS:-210000}
AGGREGATION_WINDOW=${AGGREGATION_WINDOW:-256}
# FILL-AT-ACTIVATION: test-profile measurements; see cut-chain12-genesis.sh.
SHAPE_PROFILE=${SHAPE_PROFILE:-test}
SHAPE_TIER=${SHAPE_TIER:-14}
SHAPE_PROGRAM=${SHAPE_PROGRAM:-12}
SHAPE_INPUT=${SHAPE_INPUT:-10}
SHAPE_KECCAK=${SHAPE_KECCAK:-0}
SHAPE_SHA256=${SHAPE_SHA256:-0}
SHAPE_PUBLIC=${SHAPE_PUBLIC:-2}
SHAPE_MEM=${SHAPE_MEM:-16}
SHAPE_HC=${SHAPE_HC:-hc_bundle}
SHAPE_DIGEST=${SHAPE_DIGEST:-33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8}

payout() { "$WALLET" --key "deploy/payout/$1.key.json" address | tail -1; }

args=()
# node a..f: our own key files, positions 0..5.
for n in a b c d e f; do
  args+=(--validator "deploy/node-$n.key.json,1000,$(payout "$n")")
done
# The twelve regional validators: hex public keys, chain-12 positions 6..17.
regions=(lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1)
for i in "${!regions[@]}"; do
  pk=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['validators'][6+int(sys.argv[2])]['public_key'])" "$CHAIN12" "$i")
  args+=(--validator "$pk,1000,$(payout "${regions[$i]}")")
done
# Five 1000 RAND deposit notes, one per shielded wallet.
for i in 1 2 3 4 5; do
  args+=(--alloc "$("$WALLET" --key "$ALLOC_WALLETS/shielded-$i.key.json" address | tail -1)=1000")
done

limits=(
  --max-program-words "$MAX_PROGRAM_WORDS"
  --max-proof-bytes "$MAX_PROOF_BYTES"
  --max-block-bytes "$MAX_BLOCK_BYTES"
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES"
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS"
)

if [ "$AGGREGATION" = off ]; then
  "$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" "${limits[@]}" \
    --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT"
else
  "$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" "${limits[@]}" \
    --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT" \
    --aggregation "$BOND,$MAX_COVERS,$SUBSIDY_BASE,$HALVING_BLOCKS,$AGGREGATION_WINDOW" \
    --admitted-shape "$SHAPE_PROFILE,$SHAPE_TIER,$SHAPE_PROGRAM,$SHAPE_INPUT,$SHAPE_KECCAK,$SHAPE_SHA256,$SHAPE_PUBLIC,$SHAPE_MEM,$SHAPE_HC,$SHAPE_DIGEST"
fi
