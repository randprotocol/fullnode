#!/usr/bin/env bash
# Cut the chain-15 genesis: chain 14's shape with every genesis-gated audit fix switched on.
#
#   NODE=target/release/rand-node WALLET=target/release/rand deploy/cut-chain15-genesis.sh
#
# What chain 15 is, against chain 14 (cut-chain14-genesis.sh; read it first):
#
#   * the SAME eighteen validator keys (`$KEYDIR`, default ~/.rand-chain14, off-repo) — peer ids and
#     deploy/nodes.env are unchanged; `consensus_domain: 1` puts the genesis hash into every vote,
#     new-view and proposal, so a chain-14 signature verifies on no other chain;
#   * the `staking` section (STAKE-2): per-epoch faucet budget, bond activation delay, a 1/3 weight
#     cap, a per-epoch stake entry budget, genesis-bound registrations, and a faucet that pays only
#     the wallets in `faucet_recipients` — which is what lets a bridged testnet keep a faucet;
#   * the `bridge` section at guardian SET 1 (`guardian_set_index: 1`, the set all four source
#     endpoints hold since the rotation), the successor Dilithium2 PQ set (eight keys, positions =
#     set-1 indices, from the bridge session's PUBLIC file), chain 14's pause key, chain 14's burn
#     sequence carried on (`burn_sequence`), and `rules_v2` (PQ/pause rotation, a global rolling cap);
#   * the `tokens` section lists zUSD AT GENESIS with chain 14's name/symbol/salt — the same asset id
#     `32e5ab28…` — holding the custody the chain-14 burns left behind as per-backing `locked`, and
#     the matching genesis notes (`ALLOC_TOKEN_NOTES`, from `rand-node alloc-note --asset 1`), so
#     `total_supply == Σ locked == custody` from block 0; plus TOK-1/2 and DS-6's switches.
#
# Chain-14 residue (bridge session, 2026-09-26): after burns seq 4–6 the endpoints hold 9 USDT on Tron
# and 1 USDT on Solana, all of it Anish's 10 zUSD. LOCKED_TRON_USDT / LOCKED_SOL_USDT default to that
# and MUST equal the bridge session's audited custody figures — the script refuses to guess.
#
# Run from the repo root. Re-running produces a DIFFERENT genesis hash (fresh randomness and a fresh
# timestamp). Cut once, distribute the file byte-identically, launch within minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/lib/key-guard.sh

NODE=${NODE:-target/release/rand-node}
WALLET=${WALLET:-target/release/rand}
KEYDIR=${KEYDIR:-$HOME/.rand-chain14}                     # chain 14's validator keys, reused
ALLOC_WALLETS=${ALLOC_WALLETS:-wallets}                   # shielded-{1..5}.key.json (gitignored)
PQ_GUARDIANS=${PQ_GUARDIANS:-$HOME/.rand-bridge/mainnet-set1/pq-guardians-chain15.json}
PQ_GUARDIANS_SHA256=${PQ_GUARDIANS_SHA256:-b1f6e8781784fa6e88e295ff27626a9a42d1c1d4348826e49ef751ab06dd7fb1}
PAUSE_KEY=${PAUSE_KEY:-$HOME/.rand-bridge/mainnet-set1/pause-key-chain15.pub}
FAUCET_RECIPIENTS=${FAUCET_RECIPIENTS:-$HOME/.rand-chain15/faucet-recipients.txt}   # one rand1… per line
ALLOC_TOKEN_NOTES=${ALLOC_TOKEN_NOTES:-$HOME/.rand-chain15/alloc-token-notes.json}  # JSON list of alloc-note outputs
CHAIN_ID=${CHAIN_ID:-15}
OUT=${OUT:-deploy/genesis-chain15.json}

# ── chain 14's call limits and token economics, unchanged ─────────────────────────────────────
MAX_PROGRAM_WORDS=${MAX_PROGRAM_WORDS:-65535}
MAX_PROOF_BYTES=${MAX_PROOF_BYTES:-8388608}
MAX_BLOCK_BYTES=${MAX_BLOCK_BYTES:-20971520}
MAX_CALL_ENVELOPE_BYTES=${MAX_CALL_ENVELOPE_BYTES:-65536}
MAX_PROGRAM_PUBLIC_WORDS=${MAX_PROGRAM_PUBLIC_WORDS:-32768}
REGISTRATION_FEE=${REGISTRATION_FEE:-1000000000}
MINT_CAP_PER_DAY=${MINT_CAP_PER_DAY:-10000000000000}

# ── the gated switches ────────────────────────────────────────────────────────────────────────
# Faucet budget: 10 000 RAND a 1000-block epoch — a hundred 100-RAND mints, all of them to the
# allowlist. STAKE-2's exposure is the allowlist (our own wallets), not the budget.
FAUCET_BUDGET_PER_EPOCH=${FAUCET_BUDGET_PER_EPOCH:-10000000000000}
BOND_ACTIVATION_EPOCHS=${BOND_ACTIVATION_EPOCHS:-2}
MAX_WEIGHT_BPS=${MAX_WEIGHT_BPS:-3333}
MAX_STAKE_ENTRY_PER_EPOCH=${MAX_STAKE_ENTRY_PER_EPOCH:-10000000000000}
MAX_TOKENS=${MAX_TOKENS:-4096}
# Global rolling mint cap across every backing: 4 000 zUSD a day — the four source endpoints' own
# daily caps (1 000 each) summed, so Rand never admits more than the sources could have locked.
GLOBAL_MINT_CAP_PER_WINDOW=${GLOBAL_MINT_CAP_PER_WINDOW:-400000000000}
CAP_WINDOW_SECS=${CAP_WINDOW_SECS:-86400}
GUARDIAN_SET_INDEX=${GUARDIAN_SET_INDEX:-1}
BURN_SEQUENCE=${BURN_SEQUENCE:-7}
LOCKED_TRON_USDT=${LOCKED_TRON_USDT:-900000000}
LOCKED_SOL_USDT=${LOCKED_SOL_USDT:-100000000}

# ── the bridge: set 1, index order = ~/.rand-bridge/mainnet-set1/set1.txt ─────────────────────
BRIDGE_EMITTER=${BRIDGE_EMITTER:-c02df6ba70c2457a7406780da97492a6acb57dc40751e6279f003a570559d15f}
GUARDIANS=(
  29851d77b4b5b095cd10f85ad76ee917dcf0f0ac
  ba56d1cec76b461b7aeb04a559350962070b5f7f
  c0a9fc250cfe2ae8ebfb6704777e6be4fbe3e374
  6f7196e8448415f667b32cf162e8689f98e6a987
  4dc932582668dbfeb24c03b22701f7e93ad53320
  6d63947627cac07bb863d36e015a714099a57359
  849f4e9e2420e115fa6e6715f53279af0a679c39
  98fffdec75284d77433404c1c0fc9f90abb58a9c
)
EMITTER_2=${EMITTER_2:-000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892}
EMITTER_3=${EMITTER_3:-000000000000000000000000d6ebd21c3df90c9175ebdc8d6b377a9361604892}
EMITTER_4=${EMITTER_4:-0000000000000000000000000992df85dcce77ded2c0387f1fa9cf98ac859700}
EMITTER_5=${EMITTER_5:-d3e58f1e9317bbc3c69b63fadff558ea82ba5d00765f1f1e483d705d209b413a}

for bin in "$NODE" "$WALLET"; do
  [ -x "$bin" ] || { echo "cut-chain15: $bin is not executable — cargo build --release -p randprotocol-node -p randprotocol-client" >&2; exit 1; }
done
for f in "$PQ_GUARDIANS" "$PAUSE_KEY" "$FAUCET_RECIPIENTS" "$ALLOC_TOKEN_NOTES"; do
  [ -f "$f" ] || { echo "cut-chain15: missing $f" >&2; exit 1; }
done
[ "$(shasum -a 256 "$PQ_GUARDIANS" | cut -c1-64)" = "$PQ_GUARDIANS_SHA256" ] \
  || { echo "cut-chain15: $PQ_GUARDIANS is not the file the bridge session published (sha256)" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "cut-chain15: $OUT already exists — a genesis is cut once; move it aside deliberately" >&2; exit 1; }

NAMES=(a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1)
for n in "${NAMES[@]}"; do
  refuse_in_tree_key "$KEYDIR/node-$n.key.json"
  refuse_in_tree_key "$KEYDIR/payout/$n.key.json"
done

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/tokens.json" <<JSON
{ "registration_fee": $REGISTRATION_FEE, "mint_cap_per_day": $MINT_CAP_PER_DAY, "tokens": [] }
JSON

payout() { "$WALLET" --key "$KEYDIR/payout/$1.key.json" address | tail -1; }
args=()
for n in "${NAMES[@]}"; do
  args+=(--validator "$KEYDIR/node-$n.key.json,1000,$(payout "$n")")
done
for i in 1 2 3 4 5; do
  args+=(--alloc "$("$WALLET" --key "$ALLOC_WALLETS/shielded-$i.key.json" address | tail -1)=1000")
done

echo "cut-chain15: writing the base file (its printed hash is NOT chain 15's)"
"$NODE" genesis --chain-id "$CHAIN_ID" "${args[@]}" \
  --max-program-words "$MAX_PROGRAM_WORDS" \
  --max-proof-bytes "$MAX_PROOF_BYTES" \
  --max-block-bytes "$MAX_BLOCK_BYTES" \
  --max-call-envelope-bytes "$MAX_CALL_ENVELOPE_BYTES" \
  --max-program-public-words "$MAX_PROGRAM_PUBLIC_WORDS" \
  --tokens "$TMP/tokens.json" \
  --epoch-blocks 1000 --faucet --fri-profile production --out "$OUT" | tee "$TMP/genesis.out"

HC_REPORTED=$(sed -n 's/.*hc_bundle \([0-9a-f]\{64\}\))$/\1/p' "$TMP/genesis.out")
[ -n "$HC_REPORTED" ] || { echo "cut-chain15: could not read hc_bundle out of the genesis command's output" >&2; exit 1; }

GUARDIANS_JOINED=$(IFS=,; echo "${GUARDIANS[*]}")
export BRIDGE_EMITTER GUARDIANS_JOINED EMITTER_2 EMITTER_3 EMITTER_4 EMITTER_5 PQ_GUARDIANS PAUSE_KEY \
  FAUCET_RECIPIENTS ALLOC_TOKEN_NOTES OUT CHAIN_ID HC_REPORTED REGISTRATION_FEE MINT_CAP_PER_DAY \
  MAX_PROGRAM_WORDS MAX_PROOF_BYTES MAX_BLOCK_BYTES MAX_CALL_ENVELOPE_BYTES MAX_PROGRAM_PUBLIC_WORDS \
  FAUCET_BUDGET_PER_EPOCH BOND_ACTIVATION_EPOCHS MAX_WEIGHT_BPS MAX_STAKE_ENTRY_PER_EPOCH MAX_TOKENS \
  GLOBAL_MINT_CAP_PER_WINDOW CAP_WINDOW_SECS GUARDIAN_SET_INDEX BURN_SEQUENCE LOCKED_TRON_USDT LOCKED_SOL_USDT
python3 - <<'PY'
import json, os, re, sys, time

E = os.environ
out = E["OUT"]
g = json.load(open(out))

def need(cond, msg):
    if not cond:
        sys.exit(f"cut-chain15: {msg}")

# ── bridge ─────────────────────────────────────────────────────────────────────────────────────
pq_guardians = json.load(open(E["PQ_GUARDIANS"]))["pq_guardians"]
pause_key = open(E["PAUSE_KEY"]).read().strip()
guardians = E["GUARDIANS_JOINED"].split(",")
need(len(pq_guardians) == len(guardians) == 8, f"{len(pq_guardians)} pq_guardians against {len(guardians)} guardians, expected 8 and 8")
for i, k in enumerate(pq_guardians + [pause_key]):
    need(re.fullmatch(r"[0-9a-f]{2624}", k), f"PQ key {i} is not 2624 lowercase hex characters")
need(pause_key not in pq_guardians, "pause_key is one of the pq_guardians")
need(len(set(pq_guardians)) == 8 and len(set(guardians)) == 8, "duplicate guardian key")
g["bridge"] = {
    "emitter": E["BRIDGE_EMITTER"],
    "guardians": guardians,
    "emitters": {c: E[f"EMITTER_{c}"] for c in ("2", "3", "4", "5")},
    "pq_guardians": pq_guardians,
    "pause_key": pause_key,
    "rules_v2": {"global_mint_cap_per_window": int(E["GLOBAL_MINT_CAP_PER_WINDOW"]),
                 "cap_window_secs": int(E["CAP_WINDOW_SECS"])},
    "guardian_set_index": int(E["GUARDIAN_SET_INDEX"]),
    "burn_sequence": int(E["BURN_SEQUENCE"]),
}

# ── tokens: zUSD at genesis, chain 14's registration fields (asset id 32e5ab28…) ──────────────────
USDT_TRON = "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c"
USDT_SOL = "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264"
backings = [
    {"chain": 2, "token": "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", "decimals": 6},
    {"chain": 2, "token": "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "decimals": 6},
    {"chain": 3, "token": "00000000000000000000000055d398326f99059ff775485246999027b3197955", "decimals": 18},
    {"chain": 3, "token": "0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d", "decimals": 18},
    {"chain": 4, "token": USDT_TRON, "decimals": 6, "locked": int(E["LOCKED_TRON_USDT"])},
    {"chain": 5, "token": USDT_SOL, "decimals": 6, "locked": int(E["LOCKED_SOL_USDT"])},
    {"chain": 5, "token": "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61", "decimals": 6},
]
backings = [{k: v for k, v in b.items() if k != "locked" or v > 0} for b in backings]
t = g["tokens"]
t["tokens"] = [{"name": "Shielded USD", "symbol": "zUSD",
                "salt": "27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60",
                "backings": backings}]
t["max_tokens"] = int(E["MAX_TOKENS"])
t["burn_registration_fee"] = True
t["bound_note_value"] = True

token_notes = json.load(open(E["ALLOC_TOKEN_NOTES"]))
need(isinstance(token_notes, list) and token_notes, f"{E['ALLOC_TOKEN_NOTES']} is not a non-empty JSON list")
locked_total = sum(b.get("locked", 0) for b in backings)
notes_total = 0
for i, n in enumerate(token_notes):
    need(n.get("opening", {}).get("asset") == 1, f"token note {i} is not an asset-1 (zUSD) note with an opening")
    notes_total += n["amount"]
need(notes_total == locked_total, f"zUSD genesis notes sum to {notes_total}, backings lock {locked_total} — they must be equal")
g["alloc"] = g["alloc"] + token_notes

# ── staking: STAKE-2 with an allowlisted faucet ──────────────────────────────────────────────────
recipients = [l.split()[-1] for l in open(E["FAUCET_RECIPIENTS"]) if l.strip() and not l.startswith("#")]
need(recipients and all(r.startswith("rand1") for r in recipients), "faucet_recipients must be rand1… addresses")
need(len(set(recipients)) == len(recipients), "a faucet recipient is listed twice")
g["staking"] = {
    "faucet_budget_per_epoch": E["FAUCET_BUDGET_PER_EPOCH"],
    "bond_activation_epochs": int(E["BOND_ACTIVATION_EPOCHS"]),
    "max_weight_bps": int(E["MAX_WEIGHT_BPS"]),
    "max_stake_entry_per_epoch": E["MAX_STAKE_ENTRY_PER_EPOCH"],
    "registration_v2": True,
    "faucet_recipients": recipients,
}
g["consensus_domain"] = 1

order = ["chain_id", "timestamp_ms", "validators", "alloc", "faucet", "confidential", "fri_profile",
         "hc_bundle", "bridge", "tokens", "aggregation", "consensus_domain", "staking", "epoch_blocks",
         "max_program_words", "max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes",
         "max_program_public_words"]
unknown = [k for k in g if k not in order]
need(not unknown, f"the genesis command wrote fields this script does not know: {unknown}")
g = {k: g[k] for k in order if k in g}

# ── assertions over the bytes that ship ───────────────────────────────────────────────────────
need(g["chain_id"] == int(E["CHAIN_ID"]) == 15, f"chain_id is {g['chain_id']}")
need(g["faucet"] is True, "faucet is not true — the allowlist needs it on")
need(g["confidential"] is True and g["fri_profile"] == "production", "confidential/fri_profile wrong")
need(g["hc_bundle"] == E["HC_REPORTED"], "hc_bundle is not what this rand-node reports")
need("aggregation" not in g, "an aggregation section is present")
need(len(g["validators"]) == 18 and all(v["stake"] == 1000 * 10**9 for v in g["validators"]), "validators wrong")
need(len({v["public_key"] for v in g["validators"]}) == 18, "two validators share a key")
for i, n in enumerate(g["alloc"]):
    need(n.get("opening") is not None, f"alloc note {i} has no opening (core I-2)")
need(g["bridge"]["guardian_set_index"] == 1, "guardian_set_index is not 1 — the endpoints are at set 1")
need(g["bridge"]["guardians"][0] == "29851d77b4b5b095cd10f85ad76ee917dcf0f0ac", "the guardian set is not set 1")
need(sorted(g["bridge"]["emitters"]) == ["2", "3", "4", "5"], "the emitter table is not chains 2–5")
for k, want in (("max_program_words", "MAX_PROGRAM_WORDS"), ("max_proof_bytes", "MAX_PROOF_BYTES"),
                ("max_block_bytes", "MAX_BLOCK_BYTES"), ("max_call_envelope_bytes", "MAX_CALL_ENVELOPE_BYTES"),
                ("max_program_public_words", "MAX_PROGRAM_PUBLIC_WORDS")):
    need(g[k] == int(E[want]), f"{k} is {g[k]}")
now_ms = int(time.time() * 1000)
need(g["timestamp_ms"] <= now_ms + 15_000, "timestamp_ms is in the future beyond the 15 s vote drift bound")

json.dump(g, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(f"cut-chain15: spliced bridge (set 1, 8 PQ keys, burn seq {g['bridge']['burn_sequence']}), zUSD at genesis "
      f"(locked {locked_total}, {len(token_notes)} note(s)), staking ({len(recipients)} faucet recipients), consensus_domain 1")
PY

INIT=$("$NODE" init --datadir "$TMP/probe" --genesis "$OUT")
echo "$INIT"
HASH=$(printf '%s\n' "$INIT" | sed -n 's/.*genesis \([0-9a-f]\{64\}\).*/\1/p')
[ -n "$HASH" ] || { echo "cut-chain15: rand-node init printed no genesis hash" >&2; exit 1; }
TS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['timestamp_ms'])" "$OUT")
AGE=$(( ( $(date +%s) * 1000 - TS ) / 1000 ))

cat <<EOF

cut-chain15: wrote $OUT
cut-chain15: genesis hash $HASH
cut-chain15: chain id $CHAIN_ID, hc_bundle $HC_REPORTED, consensus_domain 1, faucet allowlisted, no aggregation
cut-chain15: 18 validators (chain 14's keys, $KEYDIR); bridge set 1 at index 1, burn sequence $BURN_SEQUENCE
cut-chain15: zUSD listed at genesis — locked Tron-USDT $LOCKED_TRON_USDT, Sol-USDT $LOCKED_SOL_USDT

⚠  Stamped $AGE s ago; the chain's clock starts there. Launch within MINUTES, or delete $OUT and re-cut.
EOF
