#!/usr/bin/env bash
# Does THIS validator host's beacon seed open its genesis commitment? (The randomness beacon,
# genesis `beacon`, PR #189; docs/evm-block-context.md §11.5.) Run ON EACH VALIDATOR HOST, as
# root, before its node first starts on a beacon chain — the chain-22 cutover's `start` gate,
# beside the msauth key check — and again after the start with --rpc. A host whose seed does not
# open its commitment starts and votes, but can never propose (every one of its slots costs the
# chain a view timeout): this catches it before launch.
#
#   deploy/check-beacon-seed.sh --genesis <genesis.json> --datadir <datadir> --key <node key>
#                               [--rpc <url>] [--node <rand-node>]
#
# Offline (always):
#   1. the node key's address (`rand-node address --key`) has a commitment C in the genesis
#      `beacon` section;
#   2. `rand-node beacon commitment --datadir` succeeds — it re-derives every chain in
#      <datadir>/beacon.seed.json from its seed, so a file that is not this validator's, or that
#      was edited, is refused there — and names THIS key's address and the genesis chain id (a
#      seed file copied from another host names that host's validator: refused);
#   3. some chain in the file has commitment C (the newest, normally; an older one is accepted
#      with a warning — the node walks every chain in the file);
#   4. the file is mode 0600 or stricter (it is secret).
# With --rpc (the node running on this genesis): `rand-node beacon status` exits 0 — the
# commitment the chain holds in force for this validator is opened by the file — and at height 0
# that commitment is C.
#
# Reads the commitments of the seed file, never prints a seed. Needs rand-node and python3.
# Exit 0 and one line `beacon seed OK: …` on success; non-zero and the reason otherwise.
set -euo pipefail

NODE=${NODE:-rand-node}
GENESIS='' DATADIR='' KEY='' RPC=''
while [ $# -gt 0 ]; do
  case "$1" in
    --genesis) GENESIS=${2:?}; shift 2;;
    --datadir) DATADIR=${2:?}; shift 2;;
    --key) KEY=${2:?}; shift 2;;
    --rpc) RPC=${2:?}; shift 2;;
    --node) NODE=${2:?}; shift 2;;
    *) echo "check-beacon-seed: unknown argument $1 (--genesis --datadir --key [--rpc] [--node])" >&2; exit 2;;
  esac
done
fail() { echo "check-beacon-seed: $(hostname 2>/dev/null || echo host): $*" >&2; exit 1; }
[ -n "$GENESIS" ] && [ -n "$DATADIR" ] && [ -n "$KEY" ] || { echo "check-beacon-seed: --genesis, --datadir and --key are required" >&2; exit 2; }
[ -f "$GENESIS" ] || fail "no genesis file $GENESIS"
[ -f "$KEY" ] || fail "no node key $KEY"
SEED=$DATADIR/beacon.seed.json
[ -f "$SEED" ] || fail "no $SEED — run \`rand-node beacon init --datadir $DATADIR --key $KEY --chain-id <chain id>\` on this host (or restore THIS validator's own offline backup) and send only the commitment"

# 1. this key's address and its genesis commitment
ADDR=$("$NODE" address --key "$KEY" | sed -n 's/^address: \(.*\)$/\1/p' | head -1)
[ -n "$ADDR" ] || fail "\`$NODE address --key $KEY\` printed no address"
read -r CHAIN_ID WANT < <(python3 - "$GENESIS" "$ADDR" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
b = g.get("beacon")
if not b:
    sys.exit(f"check-beacon-seed: {sys.argv[1]} has no beacon section — nothing to check")
c = [x["commitment"] for x in b["commitments"] if x["validator"] == sys.argv[2]]
if len(c) != 1:
    sys.exit(f"check-beacon-seed: the genesis beacon lists no commitment for this key's address {sys.argv[2]} — not a genesis validator's key?")
print(g["chain_id"], c[0])
PY
) || exit 1
[ -n "${WANT:-}" ] || fail "could not read the genesis commitment"

# 2. the file is this validator's, on this chain, and every chain in it re-derives
ERR=$(mktemp); trap 'rm -f "$ERR"' EXIT
NEWEST=$("$NODE" beacon commitment --datadir "$DATADIR" 2>"$ERR") || fail "\`rand-node beacon commitment\` refused $SEED: $(tail -1 "$ERR")"
read -r FCHAIN FVAL < <(sed -n 's/^chain \([0-9][0-9]*\), validator \([^,]*\), .*/\1 \2/p' "$ERR" | head -1) || true
[ -n "${FVAL:-}" ] || fail "\`rand-node beacon commitment\` did not name the file's chain and validator ($(tail -1 "$ERR"))"
[ "$FVAL" = "$ADDR" ] || fail "$SEED is validator $FVAL's, and this host's key is $ADDR's — a seed file copied from another host (never copy beacon.seed.json); run \`rand-node beacon init\` here"
[ "$FCHAIN" = "$CHAIN_ID" ] || fail "$SEED is for chain $FCHAIN, the genesis is chain $CHAIN_ID's"

# 3. a chain in the file is the genesis commitment; 4. the mode
read -r HAS MODE < <(python3 - "$SEED" "$WANT" <<'PY'
import json, os, stat, sys
f = json.load(open(sys.argv[1]))
cs = [s.get("commitment", "").lower() for s in f.get("seeds", [])]   # commitments only — never a seed
print("newest" if cs and cs[-1] == sys.argv[2] else ("older" if sys.argv[2] in cs else "none"), oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))
PY
) || fail "could not read the commitments of $SEED"
case "$HAS" in
  newest) ;;
  older) echo "check-beacon-seed: ⚠ the genesis commitment is an OLDER chain in $SEED, not its newest ($NEWEST) — a recommit since? the node still opens it" >&2;;
  *) fail "no seed in $SEED opens this validator's genesis commitment $WANT (its newest is $NEWEST) — the commitment sent for the genesis is not this file's; this validator would miss every slot";;
esac
case "$MODE" in 0o600|0o400) ;; *) fail "$SEED is mode $MODE, not 0600 — it is secret (chmod 600 it)";; esac
OK="validator $ADDR, chain $CHAIN_ID, genesis commitment ${WANT:0:12}… opened by $SEED (offline)"

# With --rpc: what the running node holds in force for this validator, opened by the file.
if [ -n "$RPC" ]; then
  OUT=$("$NODE" beacon status --datadir "$DATADIR" --rpc "$RPC" 2>&1) || fail "\`rand-node beacon status\` failed: $(printf '%s\n' "$OUT" | tail -1)"
  H=$(printf '%s\n' "$OUT" | sed -n 's/^validator .* at height \([0-9][0-9]*\);.*/\1/p' | head -1)
  INFORCE=$(printf '%s\n' "$OUT" | sed -n 's/^commitment in force \([0-9a-f]\{64\}\): the seed file opens it; remaining reveals: \([0-9]*\)$/\1 \2/p' | head -1)
  [ -n "$INFORCE" ] || fail "\`rand-node beacon status\` exited 0 but printed no opened commitment in force: $(printf '%s\n' "$OUT" | tail -1)"
  if [ "${H:-}" = 0 ] && [ "${INFORCE%% *}" != "$WANT" ]; then
    fail "at height 0 the node holds ${INFORCE%% *} in force for $ADDR, not the genesis commitment $WANT — the node runs another genesis?"
  fi
  OK="$OK; the node at height ${H:-?} holds ${INFORCE%% *} in force, opened, ${INFORCE#* } reveals left"
fi
echo "beacon seed OK: $OK"
