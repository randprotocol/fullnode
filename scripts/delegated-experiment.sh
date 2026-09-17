#!/usr/bin/env bash
# The spec §11 loop: N sends, each timed from submission to the commit the wallet waits for,
# under whatever RAND_PROVER* is (or is not) set in the environment. Prints one line per run and
# a summary. Usage: scripts/delegated-experiment.sh <to rand1…> [amount RAND=0.5] [runs=20]
#
# Two clocks per run, because they answer different questions. The wall clock is what the user
# feels: proving plus submission plus the wait for the commit, and it is the only number
# delegation can move. The committing block's own timestamp is what the *chain* did, and it is
# there to show that it did not move — delegation shifts where a proof is made, not how fast
# blocks close, and a run whose block timestamps drift would mean something else changed too.
set -euo pipefail
TO=${1:?destination address}
AMOUNT=${2:-0.5}
RUNS=${3:-20}
RAND=${RAND_BIN:-target/release/rand}
RPC=${RAND_RPC:-http://127.0.0.1:8545}
label="local"; [ -n "${RAND_PROVER:-}" ] && label="delegated ${RAND_PROVER}"
echo "mode: $label; runs: $RUNS; amount: $AMOUNT; rpc: $RPC"

# One JSON-RPC call; prints the raw body. Never fatal — a node that is not answering costs the
# finality line, not the run.
rpc_call() {
  curl -s --max-time 10 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC" 2>/dev/null || true
}

# First `"<key>": <number>` in a JSON body. Good enough for these two flat fields and keeps the
# script free of a jq dependency on a droplet that may not have one.
json_num() { grep -o "\"$2\"[[:space:]]*:[[:space:]]*[0-9]\+" <<<"$1" | head -1 | grep -o '[0-9]\+$' || true; }

total=0
for i in $(seq 1 "$RUNS"); do
  start=$(date +%s.%N)
  out=$("$RAND" send "$TO" "$AMOUNT" 2>&1)
  end=$(date +%s.%N)
  secs=$(echo "$end - $start" | bc)
  total=$(echo "$total + $secs" | bc)
  printf 'run %2d: %7.1f s wall' "$i" "$secs"

  # `rand send` prints the transaction hash but not the height it committed at ("anchored at
  # height N" is the anchor the bundle was planned against, which is not the committing block).
  # So the committing height comes from the node: hash -> rand_getTransaction -> height ->
  # rand_getBlockByHeight -> timestamp_ms. If `rand send` ever prints the committed height
  # itself, this can read it straight out of "$out" and skip the first call.
  hash=$(grep -oE '\b[0-9a-f]{64}\b' <<<"$out" | head -1 || true)
  height=""
  [ -n "$hash" ] && height=$(json_num "$(rpc_call rand_getTransaction "[\"$hash\"]")" height)
  if [ -n "$height" ]; then
    ts=$(json_num "$(rpc_call rand_getBlockByHeight "[$height]")" timestamp_ms)
    if [ -n "$ts" ]; then
      printf ', committed in block %s at %s (%s ms)\n' \
        "$height" "$(date -u -r "$((ts / 1000))" +%H:%M:%SZ 2>/dev/null || date -u -d "@$((ts / 1000))" +%H:%M:%SZ)" "$ts"
    else
      printf ', committed in block %s; finality: n/a (block %s has no timestamp)\n' "$height" "$height"
    fi
  else
    # Either the send printed no hash (it failed, or its output changed) or the node does not
    # know that transaction yet. Resolving it would need `rand send` to print the committed
    # height, or a retry loop here against rand_getTransaction.
    printf ', finality: n/a (send output has no height)\n'
  fi
done
printf 'mean: %.1f s over %d runs (%s)\n' "$(echo "$total / $RUNS" | bc -l)" "$RUNS" "$label"
