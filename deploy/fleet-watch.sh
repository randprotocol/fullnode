#!/usr/bin/env bash
# Poll every validator's health, height, view, build and free disk, and alert on what the
# 2026-09-24 stall would have shown hours earlier: a height that has not moved, a node behind,
# disk_low, a build that differs from the rest, or a node that does not answer. Runs from the
# laptop (deploy/launchd/org.randprotocol.fleet-watch.plist, every 5 minutes) or by hand.
#
#   deploy/fleet-watch.sh            # one pass; prints a table, alerts on stderr and via
#                                    # a macOS notification; exit 1 when anything is wrong
#   FLEET_WATCH_WEBHOOK=https://…    # optional: POST the alert text as JSON {"text": …}
#
# State between runs lives in ~/.rand-fleet-watch (the last height seen), so a stall is
# "the highest height across the fleet did not change since the previous pass".
set -uo pipefail
cd "$(dirname "$0")/.."
STATE=${FLEET_WATCH_STATE:-$HOME/.rand-fleet-watch}
mkdir -p "$STATE"
IPS=$(grep -oE '/ip4/[0-9.]+' deploy/nodes.env | cut -d/ -f3 | sort -u)
rpc() { curl -s -m 5 -X POST -H content-type:application/json --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}" "http://$1:8545"; }
alerts=()
rows=()
max_height=0
builds=()
# One snapshot per node, all in parallel: a sequential sweep took 84 s and made the first nodes
# look 60 blocks behind the last.
TMP=$(mktemp -d)
for ip in $IPS; do
  ( ssh -o ConnectTimeout=8 -o BatchMode=yes root@$ip 'h=$(hostname); s=$(curl -s -m 4 -X POST -H content-type:application/json --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_status\",\"params\":[]}" 127.0.0.1:8545); v=$(curl -s -m 4 -X POST -H content-type:application/json --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getVersion\",\"params\":[]}" 127.0.0.1:8545 | grep -oE "\"git_sha\":\"[0-9a-f]{7}" | cut -d\" -f4); hl=$(curl -s -m 4 -X POST -H content-type:application/json --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}" 127.0.0.1:8545 | grep -oE "\"status\":\"[a-z_]+\"" | cut -d\" -f4); echo "$h|$(echo "$s" | grep -oE "\"height\":[0-9]+" | cut -d: -f2)|$(echo "$s" | grep -oE "\"view\":[0-9]+" | cut -d: -f2)|$(echo "$s" | grep -oE "\"high_qc_view\":[0-9]+" | cut -d: -f2)|$v|$hl|$(df -h / | awk "NR==2{print \$4}")"' > "$TMP/$ip" 2>/dev/null ) &
done
wait
for ip in $IPS; do
  out=$(cat "$TMP/$ip" 2>/dev/null)
  if [ -z "$out" ]; then alerts+=("$ip: unreachable"); rows+=("$ip|?|?|?|?|unreachable|?"); continue; fi
  IFS='|' read -r host height view hqc build health free <<<"$out"
  rows+=("$out")
  if [ -z "$height" ]; then alerts+=("$host: rpc closed"); continue; fi
  [ "$height" -gt "$max_height" ] && max_height=$height
  builds+=("$build")
  [ "$health" = ok ] || alerts+=("$host: health $health")
done
rm -rf "$TMP"
# Node A, local.
a=$(rpc 127.0.0.1 rand_status); ah=$(echo "$a" | grep -oE '"height":[0-9]+' | cut -d: -f2)
if [ -n "$ah" ]; then
  rows+=("A|$ah|$(echo "$a" | grep -oE '"view":[0-9]+' | cut -d: -f2)|$(echo "$a" | grep -oE '"high_qc_view":[0-9]+' | cut -d: -f2)|$(rpc 127.0.0.1 rand_getVersion | grep -oE '"git_sha":"[0-9a-f]{7}' | cut -d'"' -f4)|$(rpc 127.0.0.1 rand_getHealth | grep -oE '"status":"[a-z_]+"' | cut -d'"' -f4)|$(df -h / | awk 'NR==2{print $4}')")
  [ "$ah" -gt "$max_height" ] && max_height=$ah
else
  alerts+=("A: rpc closed")
fi
# Behind, builds, stall.
for r in "${rows[@]}"; do IFS='|' read -r host height _ _ build _ _ <<<"$r"; [ -n "$height" ] && [ "$height" != "?" ] && [ $((max_height - height)) -gt 60 ] && alerts+=("$host: behind by $((max_height - height))"); done
distinct=$(printf '%s\n' "${builds[@]}" | sort -u | grep -c .)
[ "$distinct" -gt 1 ] && alerts+=("mixed builds: $(printf '%s\n' "${builds[@]}" | sort | uniq -c | tr '\n' ' ')")
last=$(cat "$STATE/height" 2>/dev/null || echo 0)
[ "$max_height" -le "$last" ] && [ "$last" -gt 0 ] && alerts+=("STALL: highest height $max_height unchanged since the last pass")
echo "$max_height" > "$STATE/height"
printf '%-8s %-8s %-8s %-8s %-8s %-9s %s\n' node height view high_qc build health free
for r in "${rows[@]}"; do IFS='|' read -r host height view hqc build health free <<<"$r"; printf '%-8s %-8s %-8s %-8s %-8s %-9s %s\n' "${host#rand-node-}" "$height" "$view" "$hqc" "$build" "$health" "$free"; done
if [ ${#alerts[@]} -gt 0 ]; then
  text="rand fleet $(date -u +%H:%M): $(printf '%s; ' "${alerts[@]}")"
  echo "ALERT $text" >&2
  command -v osascript >/dev/null && osascript -e "display notification \"${text//\"/}\" with title \"RAND fleet\"" 2>/dev/null
  [ -n "${FLEET_WATCH_WEBHOOK:-}" ] && curl -s -m 10 -X POST -H content-type:application/json --data "{\"text\": \"${text//\"/}\"}" "$FLEET_WATCH_WEBHOOK" >/dev/null
  exit 1
fi
echo "ok: fleet at $max_height, one build, every node healthy"
