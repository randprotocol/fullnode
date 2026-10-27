#!/usr/bin/env bash
# Cut the droplet fleet over to a new chain, in the order the chain-8 rollout used: the twelve
# regional validators in batches of four, then F, C, D, and E last (it serves the explorer).
#
# ⚠ Run it with bash ≥ 4 (`brew install bash`; macOS's /bin/bash is 3.2). Under 3.2 the array
# slicing re-ran droplets that were already over during the chain-9 rollout; the per-droplet
# script now refuses those before stopping anything, but the labels in this script's output
# were wrong too. One droplet at a time with deploy/cutover-droplet.sh is the safe fallback.
#
#   deploy/cutover-fleet.sh <old-genesis-prefix> <new-genesis-prefix> <genesis-file> [batch]
#
# One log per droplet under $LOGDIR (default /tmp/cutover-<new>). Each droplet runs
# deploy/cutover-droplet.sh; a failure there stops that droplet before any change and is
# reported at the end, never retried silently. Environment passes through (SERVICE, BIN_NODE,
# BIN_WALLET for the RAND-named chain-10 cut-over).
set -uo pipefail
OLD=$1; NEW=$2; GENESIS=$3; BATCH=${4:-4}
cd "$(dirname "$0")/.."
LOGDIR=${LOGDIR:-/tmp/cutover-$NEW}; mkdir -p "$LOGDIR"
regional=(203.0.113.14 203.0.113.10 203.0.113.18 203.0.113.27 203.0.113.32 203.0.113.24 203.0.113.17 203.0.113.34 203.0.113.12 203.0.113.16 203.0.113.37 203.0.113.30)
tail_order=(203.0.113.21 203.0.113.23 203.0.113.25 203.0.113.33)   # F, C, D, E
failed=()
# SKIP="ip ip": droplets already cut over (a re-run refuses them at the unit edit anyway).
run_batch() {
  # `local -a`, and reset explicitly: bash 3.2 (macOS) otherwise leaks the arrays across calls.
  local -a pids ips
  pids=(); ips=()
  for ip in "$@"; do
    case " ${SKIP:-} " in *" $ip "*) echo "skip ${ip}"; continue;; esac
    ips+=("$ip")
  done
  [ ${#ips[@]} -gt 0 ] || return 0
  for ip in "${ips[@]}"; do
    deploy/cutover-droplet.sh "$ip" "$OLD" "$NEW" "$GENESIS" > "$LOGDIR/$ip.log" 2>&1 &
    pids+=($!)
  done
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then echo "ok   ${ips[$i]}"; else echo "FAIL ${ips[$i]} (see $LOGDIR/${ips[$i]}.log)"; failed+=("${ips[$i]}"); fi
  done
}
for ((i = 0; i < ${#regional[@]}; i += BATCH)); do
  run_batch "${regional[@]:i:BATCH}"
done
for ip in "${tail_order[@]}"; do
  run_batch "$ip"
done
if [ ${#failed[@]} -gt 0 ]; then echo "failed: ${failed[*]}" >&2; exit 1; fi
echo "fleet on $NEW"
