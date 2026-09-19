#!/usr/bin/env bash
# Cut the chain-14 genesis: the v0.5 bridge + RPL chain.
#
#   deploy/gen-chain14-keys.sh                      # once, off-repo — see that script
#   NODE=target/release/rand-node WALLET=target/release/rand deploy/cut-chain14-genesis.sh
#
# Chain 14 is chain 13's five call limits, plus three things chain 13 cannot take as an update:
#
#   * the `bridge` section — bridge-06's FIXED mainnet inputs (handoff §6), now also carrying
#     B3's `pq_guardians` and B1's `pause_key`, read from a PUBLIC key file (PQ_PUBLIC);
#   * the RPL `tokens` section — `registration_fee` and `mint_cap_per_day`, listing NO token:
#     zUSD is registered after the cut by `RegisterBridgedToken` + six `ListBacking` under the PQ
#     guardian quorum (docs/bridge.md §20, spec 2026-09-19-bridge-hardening-design.md §6);
#   * eighteen FRESH validator keys and payout wallets from $KEYDIR (audit v3 OPS-1) — chains
#     8–13 ran on keys this public repository tracks.
#
# It is also the first genesis whose alloc notes carry their opening (`pk`, `time`, `r`): core
# I-2 makes that mandatory on any chain with a `tokens` section, and `rand-node genesis` writes
# it for every `--alloc` on this build, so nothing here has to ask for it.
#
# **No aggregation section, and not optional.** `node::check_build_runs_genesis` refuses to start
# on any genesis that carries one: the transaction-bound hidden-asset bundle declares `public 4`
# where the admitted shape assumes 2, so no bundle proved on this build could ever be covered.
# There is no AGGREGATION=on path here, unlike chains 9–13.
#
# The `bridge` section cannot come from a flag — `rand-node genesis` writes `bridge: None` on
# purpose ("a guardian set plus a per-chain emitter table … belongs with whoever holds the
# guardian keys, not with this command") — so this script writes the file, splices the section in,
# and then makes the NEW binary re-read the whole thing with `rand-node init`. The hash that
# `rand-node genesis` prints is the hash of the unbridged file and is NOT chain 14's; the hash
# this script prints at the end, from `init`, is.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh note randomness and
# a fresh timestamp). Cut once, distribute the file byte-identically.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/lib/key-guard.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
KEYDIR=${KEYDIR:-$HOME/.rand-chain14}                 # deploy/gen-chain14-keys.sh wrote this
ALLOC_WALLETS=${ALLOC_WALLETS:-wallets}               # shielded-{1..5}.key.json (gitignored)
PQ_PUBLIC=${PQ_PUBLIC:-$HOME/.rand-bridge/mainnet-pq-set1/public.json}
CHAIN_ID=${CHAIN_ID:-14}
OUT=${OUT:-deploy/genesis-chain14.json}

# ── chain 13's five call limits, unchanged (spec 2026-09-19-call-limits-design.md §3) ─────────
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-8388608}
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-20971520}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}

# ── the RPL `tokens` section ───────────────────────────────────────────────────────────────────
# registration_fee: 1 RAND = genesis::MIN_REGISTRATION_FEE, the value the nine-phase E2E gate runs
# (`crates/randprotocol-node/tests/zusd_e2e.rs`'s REGISTRATION_FEE = UNITS_PER_RAND).
# mint_cap_per_day: 100 000 × 10^8 — B1's per-backing, per-UTC-day cap in the token's own
# eight-decimal units (bridge-hardening spec §6, verbatim).
REGISTRATION_FEE=${REGISTRATION_FEE:-1000000000}
MINT_CAP_PER_DAY=${MINT_CAP_PER_DAY:-10000000000000}

# ── the `bridge` section: bridge-06's fixed mainnet inputs, handoff §6, VERBATIM ───────────────
# The guardian set is **set 0**, the one live on the four source endpoints today — not the freshly
# generated set 1. docs/bridge.md §20 step 6: "Only after that: the guardian-set rotation (set 0 →
# set 1, payload 2, signed 5-of-6 by the *current* set) on the four source endpoints, then the
# same attestation submitted to Rand, whose genesis starts at set 0". A genesis naming set 1 would
# refuse every attestation the live endpoints' guardians produce.
BRIDGE_EMITTER=${BRIDGE_EMITTER:-c02df6ba70c2457a7406780da97492a6acb57dc40751e6279f003a570559d15f}
GUARDIANS=(
  5b5c007b5638b643a1f6b3c18afb2a7784a9a2aa
  3facdaf6ea59bc75cd18b4ca1844344005e66453
  8cd7478eca7235e8a5265d4b7f638086f25cc9f5
  76845347679b878c0016491b19defc59c83e20fb
  62fa3e39f56636955df228917edd2e9e68f3a957
  b3f1409ae0d5b2467229fa74a92c51b15f980445
)
# chain id → emitter address, 32 bytes. 2 Ethereum, 3 BNB Chain, 4 Tron, 5 Solana.
EMITTER_2=${EMITTER_2:-000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892}
EMITTER_3=${EMITTER_3:-000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892}
EMITTER_4=${EMITTER_4:-0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700}
EMITTER_5=${EMITTER_5:-d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a}

for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "cut-chain14: $bin is not executable — cargo build --release -p randprotocol-node -p randprotocol-client" >&2; exit 1; }
done
[ -f "$PQ_PUBLIC" ] || { echo "cut-chain14: no PQ public key file at $PQ_PUBLIC (set PQ_PUBLIC)" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "cut-chain14: $OUT already exists — a genesis is cut once; move it aside deliberately" >&2; exit 1; }

NAMES=(a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1)

# OPS-1: every key this cut touches is refused if it resolves inside the repository.
for n in "${NAMES[@]}"; do
  refuse_in_tree_key "$KEYDIR/node-$n.key.json"
  refuse_in_tree_key "$KEYDIR/payout/$n.key.json"
done

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# ── the tokens config file `--tokens` reads ────────────────────────────────────────────────────
cat > "$TMP/tokens.json" <<JSON
{ "registration_fee": $REGISTRATION_FEE, "mint_cap_per_day": $MINT_CAP_PER_DAY, "tokens": [] }
JSON

payout() { "$WALLET" --key "$KEYDIR/payout/$1.key.json" address | tail -1; }

args=()
for n in "${NAMES[@]}"; do
  args+=(--validator "$KEYDIR/node-$n.key.json,1000,$(payout "$n")")
done
# Five 1000 RAND deposit notes, one per shielded wallet — chain 13's shape, now with openings.
for i in 1 2 3 4 5; do
  args+=(--alloc "$("$WALLET" --key "$ALLOC_WALLETS/shielded-$i.key.json" address | tail -1)=1000")
done

echo "cut-chain14: writing the unbridged file (its printed hash is NOT chain 14's)"
"$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" \
  --max-program-words "$MAX_PROGRAM_WORDS" \
  --max-proof-bytes "$MAX_PROOF_BYTES" \
  --max-block-bytes "$MAX_BLOCK_BYTES" \
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES" \
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS" \
  --tokens "$TMP/tokens.json" \
  --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT" | tee "$TMP/genesis.out"

# What this build reports its bundle guest to be. `rand-node genesis` closes its summary line with
# `hc_bundle <64 hex>)`, which is `word8_to_hex(&ZkExecutor::hc_bundle())` of the binary that just
# ran — the same value `node::check_build_runs_genesis` will hold the fleet's binaries to.
HC_REPORTED=$(sed -n 's/.*hc_bundle \([0-9a-f]\{64\}\))$/\1/p' "$TMP/genesis.out")
[ -n "$HC_REPORTED" ] || { echo "cut-chain14: could not read hc_bundle out of the genesis command's output" >&2; exit 1; }

# ── splice in the `bridge` section, then assert the whole file ─────────────────────────────────
GUARDIANS_JOINED=$(IFS=,; echo "${GUARDIANS[*]}")
BRIDGE_EMITTER="$BRIDGE_EMITTER" GUARDIANS_JOINED="$GUARDIANS_JOINED" \
EMITTER_2="$EMITTER_2" EMITTER_3="$EMITTER_3" EMITTER_4="$EMITTER_4" EMITTER_5="$EMITTER_5" \
PQ_PUBLIC="$PQ_PUBLIC" OUT="$OUT" CHAIN_ID="$CHAIN_ID" HC_REPORTED="$HC_REPORTED" \
REGISTRATION_FEE="$REGISTRATION_FEE" MINT_CAP_PER_DAY="$MINT_CAP_PER_DAY" \
MAX_PROGRAM_WORDS="$MAX_PROGRAM_WORDS" MAX_PROOF_BYTES="$MAX_PROOF_BYTES" \
MAX_BLOCK_BYTES="$MAX_BLOCK_BYTES" MAX_CALL_ENVELOPE_BYTES="$MAX_CALL_ENVELOPE_BYTES" \
MAX_PROGRAM_PUBLIC_WORDS="$MAX_PROGRAM_PUBLIC_WORDS" \
python3 - <<'PY'
import json, os, re, sys, time

out = os.environ["OUT"]
g = json.load(open(out))

pq = json.load(open(os.environ["PQ_PUBLIC"]))
# The public file carries public keys only: six Dilithium2 guardian keys and the pause key, each
# 1312 bytes = 2624 lowercase hex characters. Its own `note` states the indexing.
for field in ("pq_guardians", "pause_key"):
    if field not in pq:
        sys.exit(f"cut-chain14: {os.environ['PQ_PUBLIC']} has no {field}")
pq_guardians, pause_key = pq["pq_guardians"], pq["pause_key"]
guardians = os.environ["GUARDIANS_JOINED"].split(",")
if len(pq_guardians) != len(guardians):
    sys.exit(f"cut-chain14: {len(pq_guardians)} pq_guardians against {len(guardians)} guardians — the two lists are index-aligned")
for i, k in enumerate(list(pq_guardians) + [pause_key]):
    if not re.fullmatch(r"[0-9a-f]{2624}", k):
        sys.exit(f"cut-chain14: PQ key {i} is not 2624 lowercase hex characters (a Dilithium2 public key is 1312 bytes)")
if pause_key in pq_guardians:
    sys.exit("cut-chain14: pause_key is one of the pq_guardians — it must be held apart from them")
if len(set(pq_guardians)) != len(pq_guardians):
    sys.exit("cut-chain14: duplicate pq_guardians key")

bridge = {
    "emitter": os.environ["BRIDGE_EMITTER"],
    "guardians": guardians,
    "emitters": {c: os.environ[f"EMITTER_{c}"] for c in ("2", "3", "4", "5")},
    "pq_guardians": pq_guardians,
    "pause_key": pause_key,
}

# Rebuild the object in `Genesis`'s own field order so the file reads the way serde writes one.
order = ["chain_id", "timestamp_ms", "validators", "alloc", "faucet", "confidential", "fri_profile",
         "hc_bundle", "bridge", "tokens", "aggregation", "epoch_blocks", "max_program_words",
         "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes", "max_program_public_words"]
g["bridge"] = bridge
unknown = [k for k in g if k not in order]
if unknown:
    sys.exit(f"cut-chain14: the genesis command wrote fields this script does not know: {unknown}")
g = {k: g[k] for k in order if k in g}

# ── assertions: everything this cut promises, checked in the bytes that will ship ─────────────
def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain14: {msg}")

need(g["chain_id"] == int(os.environ["CHAIN_ID"]), f"chain_id is {g['chain_id']}")
need(g["faucet"] is True, "faucet is not true — a deployer with no balance could not register zUSD (bridge-hardening spec §6)")
need(g["confidential"] is True, "confidential is not true")
need(g["fri_profile"] == "production", f"fri_profile is {g['fri_profile']!r}, not production")
need(g["hc_bundle"] == os.environ["HC_REPORTED"],
     f"hc_bundle {g['hc_bundle']} is not what this rand-node reports ({os.environ['HC_REPORTED']})")
need("aggregation" not in g, "an aggregation section is present — node::check_build_runs_genesis refuses to start on one")
need(len(g["validators"]) == 18, f"{len(g['validators'])} validators, expected 18")
need(all(v["stake"] == 1000 * 10**9 for v in g["validators"]), "a validator is not staked at exactly 1000 RAND")
need(len({v["public_key"] for v in g["validators"]}) == 18, "two validators share a public key")
need(len({v["payout"] for v in g["validators"]}) == 18, "two validators share a payout address")
need(len(g["alloc"]) == 5, f"{len(g['alloc'])} alloc notes, expected 5")
# Core I-2: on a chain with a `tokens` section every alloc note must open.
for i, n in enumerate(g["alloc"]):
    o = n.get("opening")
    need(o is not None, f"alloc note {i} has no opening — core I-2 requires one on a tokens chain")
    need(re.fullmatch(r"[0-9a-f]{64}", o["pk"]) and re.fullmatch(r"[0-9a-f]{64}", o["r"]),
         f"alloc note {i}'s opening is malformed")
    need(n["amount"] == 1000 * 10**9, f"alloc note {i} is not 1000 RAND")

t = g["tokens"]
need(t["registration_fee"] == int(os.environ["REGISTRATION_FEE"]), "registration_fee does not match")
need(t["mint_cap_per_day"] == int(os.environ["MINT_CAP_PER_DAY"]), "mint_cap_per_day does not match")
need(t["mint_cap_per_day"] == 100_000 * 10**8, "mint_cap_per_day is not 100 000 × 10^8 (bridge-hardening spec §6)")
need(t["tokens"] == [], "the tokens section lists a token — zUSD is registered after the cut (docs/bridge.md §20)")

b = g["bridge"]
need(len(b["guardians"]) == 6 and all(re.fullmatch(r"[0-9a-f]{40}", x) for x in b["guardians"]),
     "guardians is not six 40-hex addresses")
need(b["guardians"][0] == "5b5c007b5638b643a1f6b3c18afb2a7784a9a2aa",
     "the guardian set is not bridge-06's set 0 — a genesis naming set 1 refuses every live attestation")
need(sorted(b["emitters"]) == ["2", "3", "4", "5"], "the emitter table is not chains 2, 3, 4, 5")
need(all(re.fullmatch(r"[0-9a-f]{64}", v) for v in b["emitters"].values()), "an emitter is not 64 hex")
need(len(b["pq_guardians"]) == len(b["guardians"]), "pq_guardians and guardians are not index-aligned")
need(b.get("pause_key"), "no pause_key")

for k, want in (("max_program_words", "MAX_PROGRAM_WORDS"), ("max_proof_bytes", "MAX_PROOF_BYTES"),
                ("max_block_bytes", "MAX_BLOCK_BYTES"), ("max_call_envelope_bytes", "MAX_CALL_ENVELOPE_BYTES"),
                ("max_program_public_words", "MAX_PROGRAM_PUBLIC_WORDS")):
    need(g[k] == int(os.environ[want]), f"{k} is {g[k]}")

# B2: the chain's clock starts here. A leader may not step a block's timestamp more than
# MAX_TIMESTAMP_STEP_MS (60 s) past its parent, and a validator will not VOTE for a block more
# than MAX_CLOCK_DRIFT_MS (15 s) ahead of its own clock. A genesis stamped in the future is
# therefore a chain nobody votes on until wall-clock time catches up.
now_ms = int(time.time() * 1000)
need(g["timestamp_ms"] <= now_ms + 15_000,
     f"timestamp_ms is {(g['timestamp_ms'] - now_ms) / 1000:.1f} s in the future — more than the 15 s "
     "vote drift bound; fix this machine's clock and re-cut")
json.dump(g, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(f"cut-chain14: bridge section spliced in; {len(b['pq_guardians'])} pq_guardians, pause_key present")
PY

# ── the real chain-14 hash: the NEW binary re-reads the finished file ──────────────────────────
INIT=$("$NODE" init --datadir "$TMP/probe" --genesis "$OUT")
echo "$INIT"
HASH=$(printf '%s\n' "$INIT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ -n "$HASH" ] || { echo "cut-chain14: rand-node init printed no genesis hash" >&2; exit 1; }

# Age at the moment the file became final. Everything above is fast, but a cut left sitting for an
# hour starts a chain whose clock is an hour behind: block N's timestamp may only step 60 s past
# block N-1, so the chain crawls forward in time one minute per block, and B1's per-UTC-day mint
# cap and §3's guardian-set grace window run on that lagging clock until it catches up.
TS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['timestamp_ms'])" "$OUT")
AGE=$(( ( $(date +%s) * 1000 - TS ) / 1000 ))

cat <<EOF

cut-chain14: wrote $OUT
cut-chain14: genesis hash $HASH
cut-chain14: chain id $CHAIN_ID, hc_bundle $HC_REPORTED, faucet on, fri production, no aggregation
cut-chain14: 18 validators at 1000 RAND (keys under $KEYDIR, never in this repo), 5 alloc notes with openings
cut-chain14: bridge = guardian SET 0 + PQ set from $PQ_PUBLIC; tokens = fee $REGISTRATION_FEE, cap $MINT_CAP_PER_DAY, no listed token

⚠  This genesis is stamped $AGE s ago and the chain's clock starts there. Launch within MINUTES:
   a block's timestamp may step at most 60 s past its parent (B2), so every hour of delay is
   another 60 blocks the chain spends catching its clock up — with B1's mint-cap day and the
   guardian-set grace window running on the lagging clock the whole time. If the fleet cannot be
   started now, delete $OUT and cut again when it can.
EOF
