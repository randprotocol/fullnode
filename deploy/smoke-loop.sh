#!/usr/bin/env bash
# Health loop for the shielded testnet (chain 6): every INTERVAL seconds run one round of
#   1. mint (faucet, validator-signed, no bundle)
#   2. SHRUGG transfer (a proved 2-in-2-out bundle, ~100 s on a laptop)
#   3. program deployment (a fresh private_payment guest each round, paid by a bundle)
#   4. program call (proved locally, input transcript published, paid by a bundle)
#   5. burn: NOT AVAILABLE on this chain — a burn is either a bridge burn (needs a bridge
#      section and guardian-attested deposits; chain 6 has neither) or a stake bond (phase S2,
#      not in build 01dc23d). Logged as "n/a" so the gap is visible.
# then compare every node's height and the explorer's view of each transaction.
#
# Usage: deploy/smoke-loop.sh   (env: BIN, WALLETS, RPC, EXPLORER, INTERVAL, NODES, SSH_KEY)
# Log: one line per step, "round N step ... ok|FAIL ..." — grep FAIL.
set -uo pipefail
BIN=${BIN:-$HOME/Github/randprotocol/fullnode/bin-01dc23d}
WALLETS=${WALLETS:-$HOME/Github/randprotocol/fullnode/wallets}
RPC=${RPC:-http://127.0.0.1:8545}
EXPLORER=${EXPLORER:-https://randscan.org/api/v1}
INTERVAL=${INTERVAL:-600}
NODES=${NODES:-"c=167.172.65.63 d=178.128.91.236 e=188.166.235.187 f=157.245.156.41"}
KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}
W1=$WALLETS/shielded-1.key.json
W2=$WALLETS/shielded-2.key.json
TMP=${TMPDIR:-/tmp}/smoke-loop; mkdir -p "$TMP"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
rpc() { curl -s --max-time 10 "$RPC" -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"; }
# Poll the explorer until it serves the transaction (indexing lags the commit by a second or two).
explorer_tx() {
  local hash=$1 want=$2 i
  for i in $(seq 1 30); do
    local body; body=$(curl -s --max-time 10 "$EXPLORER/transactions/$hash")
    if echo "$body" | grep -q "\"kind\":\"$want\""; then echo "$body"; return 0; fi
    sleep 3
  done
  echo "$body"; return 1
}
submitted() { grep "submitted $2 " <<<"$1" | awk '{print $3}' | head -1; }

round=0
while true; do
  round=$((round+1)); start=$(date +%s)
  log "round $round start (chain $(rpc shrugg_chainId '[]' | grep -o '"result":[0-9]*' | cut -d: -f2), head $(rpc shrugg_getHead '[]' | grep -o '"height":[0-9]*' | cut -d: -f2))"

  # 1. mint
  out=$("$BIN/shrugg" faucet --key "$W1" --rpc "$RPC" --amount 10 2>&1); h=$(submitted "$out" mint)
  if [ -n "$h" ] && explorer_tx "$h" mint >/dev/null; then log "round $round mint ok $h"; else log "round $round mint FAIL ${h:-nohash}: $(tail -1 <<<"$out")"; fi

  # 2. transfer (proved bundle)
  to=$("$BIN/shrugg" --key "$W2" address)
  t0=$(date +%s); out=$("$BIN/shrugg" send "$to" 1.5 --key "$W1" --rpc "$RPC" 2>&1); h=$(submitted "$out" transfer)
  if [ -n "$h" ] && body=$(explorer_tx "$h" transfer); then
    nf=$(grep -o '"nullifiers":\[[^]]*\]' <<<"$body" | head -1 | cut -c15-30)
    log "round $round transfer ok $h (proved+committed in $(( $(date +%s) - t0 )) s, bundle nullifiers ${nf}...)"
  else log "round $round transfer FAIL ${h:-nohash}: $(tail -1 <<<"$out")"; fi

  # 3. deploy (a different threshold each round gives a different program id)
  pj="$TMP/pp-$round.json"
  "$BIN/shrugg" program build --guest private_payment --arg $((100 + round)) --out "$pj" >/dev/null 2>&1
  t0=$(date +%s); out=$("$BIN/shrugg" program deploy "$pj" --key "$W1" --rpc "$RPC" 2>&1); h=$(submitted "$out" deploy)
  pid=$(grep -o 'program id: [0-9a-f]*' <<<"$out" | awk '{print $3}')
  if [ -n "$h" ] && explorer_tx "$h" deploy >/dev/null; then log "round $round deploy ok $h program $pid ($(( $(date +%s) - t0 )) s)"; else log "round $round deploy FAIL ${h:-nohash}: $(tail -1 <<<"$out")"; fi

  # 4. call (400 + 250 above the threshold: outputs [1, 0, 550-threshold, …])
  if [ -n "$pid" ]; then
    t0=$(date +%s); out=$("$BIN/shrugg" call "$pid" --input 400 --input 250 --input 0 --input 0 --key "$W1" --rpc "$RPC" 2>&1); h=$(submitted "$out" call)
    if [ -n "$h" ] && body=$(explorer_tx "$h" call) && grep -q '"h_in":"[0-9a-f]' <<<"$body"; then
      log "round $round call ok $h outputs $(grep -o '"outputs":\[[^]]*\]' <<<"$body" | head -1) envelope $(grep -o '"input_envelope_len":[0-9]*' <<<"$body") ($(( $(date +%s) - t0 )) s)"
    else log "round $round call FAIL ${h:-nohash}: $(tail -1 <<<"$out")"; fi
  else log "round $round call skipped (no program)"; fi

  # 5. burn
  log "round $round burn n/a (no bridge section on chain 6, no staking in build 01dc23d)"

  # health: every node at the same height (within a few blocks) and the explorer caught up
  local_h=$(rpc shrugg_getHead '[]' | grep -o '"height":[0-9]*' | cut -d: -f2)
  heights="a=$local_h"
  for n in $NODES; do
    ip=${n#*=}; hh=$(ssh -i "$KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "root@$ip" 'shrugg status 2>/dev/null | grep -o "\"height\": *[0-9]*" | grep -o "[0-9]*$"' 2>/dev/null)
    heights="$heights ${n%%=*}=${hh:-down}"
  done
  ex=$(curl -s --max-time 10 "$EXPLORER/health")
  log "round $round health heights [$heights] explorer $(grep -o '"status":"[a-z]*"' <<<"$ex") lag $(grep -o '"lag":[0-9-]*' <<<"$ex" | cut -d: -f2) balance $("$BIN/shrugg" balance --key "$W1" --rpc "$RPC" 2>/dev/null | grep -o 'balance: .*')"
  spent=$(( $(date +%s) - start )); log "round $round done in $spent s"
  [ $spent -lt $INTERVAL ] && sleep $((INTERVAL - spent))
done
