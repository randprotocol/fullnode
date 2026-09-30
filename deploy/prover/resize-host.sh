#!/usr/bin/env bash
# Give one validator host the cores and memory a prover needs, without touching its disk: stop the
# node cleanly, shut the droplet down, CPU/RAM-only resize (reversible — the disk is not grown),
# power on, wait until the validator is healthy again. One host at a time; the rest of the fleet
# keeps quorum.
#
#   deploy/prover/resize-host.sh <droplet id> root@<ip> [ssh options]      # SIZE=c-8 by default
set -euo pipefail
ID=${1:?droplet id}; TARGET=${2:?root@ip}; shift 2
SIZE=${SIZE:-c-8}
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15 "$@" "$TARGET")
health() { "${SSH[@]}" 'curl -s -m 5 -X POST -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}" http://127.0.0.1:8545' 2>/dev/null || true; }

now=$(doctl compute droplet get "$ID" --format SizeSlug --no-header)
if [ "$now" = "$SIZE" ]; then echo "$TARGET is already $SIZE"; exit 0; fi
[ "$("${SSH[@]}" 'systemctl is-enabled rand-node')" = enabled ] || { echo "$TARGET: rand-node is not enabled at boot; fix that first" >&2; exit 1; }
echo "$(date -u +%T) $TARGET ($now -> $SIZE): health before: $(health)"
"${SSH[@]}" 'systemctl stop rand-guardian 2>/dev/null || true; systemctl stop rand-prover 2>/dev/null || true; systemctl stop rand-node' || true
echo "$(date -u +%T) node stopped; shutting down"
doctl compute droplet-action shutdown "$ID" --wait --format Status --no-header || doctl compute droplet-action power-off "$ID" --wait --format Status --no-header
echo "$(date -u +%T) resizing"
doctl compute droplet-action resize "$ID" --size "$SIZE" --wait --format Status --no-header
echo "$(date -u +%T) powering on"
doctl compute droplet-action power-on "$ID" --wait --format Status --no-header
for i in $(seq 1 120); do
    h=$(health)
    case "$h" in *'"ok"'*|*'"status":"ok"'*) echo "$(date -u +%T) healthy: $h"; break ;; esac
    sleep 10
    [ "$i" = 120 ] && { echo "$TARGET did not become healthy in 20 minutes: $h" >&2; exit 1; }
done
"${SSH[@]}" 'echo "$(nproc) cpus, $(free -m | awk "/Mem:/{print \$2}") MB; rand-node $(systemctl is-active rand-node); guardian $(systemctl is-active rand-guardian 2>/dev/null || echo none)"'
