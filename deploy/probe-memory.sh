#!/usr/bin/env bash
# Record what each fleet host has to absorb a burst with (audit v12, OPS-602): RAM, swap, the
# unit's MemoryHigh, rand-node's resident memory and the admission budget the node says it runs
# (rand_status.admission_budget_bytes). No earlier probe recorded RAM or swap, so "the 2 GB
# validators" was a class read off the budget, not a reading.
#
#   NODES_ENV=<fleet list> deploy/probe-memory.sh            # every host in NODES_ENV, over ssh
#   deploy/probe-memory.sh --local [unit]                    # this host only (run on the node)
#   SELFTEST=1 bash deploy/probe-memory.sh                   # the classifier's self-test, no hosts
#
# Read-only: it runs cat, systemctl show, ps and one loopback RPC call. One TSV line per host:
#   host  ram_mb  swap_mb  swap_free_mb  memory_high  rss_mb  budget_mib  build  verdict
# and exit 1 when any verdict is not "ok". Verdicts (docs/node-hardware.md):
#   under-minimum   RAM under 4 GB: below the validator minimum
#   no-swap         RAM under 4 GB and no swap: MemoryHigh has nothing to reclaim into
#   no-memory-high  the unit has no MemoryHigh (infinity): roll it (deploy/lib/unit-limits.sh)
#   no-headroom     RAM minus resident minus the admission budget is under 128 MB
#   unreachable     no answer over ssh, or the RPC is closed
set -uo pipefail

# The line a host prints about itself. `unit` is the systemd unit (rand-node).
probe_cmd() {
  local unit=${1:-rand-node}
  cat <<EOF
h=\$(hostname)
ram=\$(awk '/^MemTotal:/{print int(\$2/1024)}' /proc/meminfo)
swap=\$(awk '/^SwapTotal:/{print int(\$2/1024)}' /proc/meminfo)
swapfree=\$(awk '/^SwapFree:/{print int(\$2/1024)}' /proc/meminfo)
high=\$(systemctl show $unit -p MemoryHigh --value 2>/dev/null)
pid=\$(systemctl show $unit -p MainPID --value 2>/dev/null)
rss=\$(awk '/^VmRSS:/{print int(\$2/1024)}' /proc/\${pid:-0}/status 2>/dev/null)
st=\$(curl -s -m 4 -X POST -H content-type:application/json --data '{"jsonrpc":"2.0","id":1,"method":"rand_status","params":[]}' http://127.0.0.1:8545)
budget=\$(printf '%s' "\$st" | sed -n 's/.*"admission_budget_bytes":\([0-9]*\).*/\1/p')
build=\$(printf '%s' "\$st" | sed -n 's/.*"git_sha":"\([0-9a-f]*\)".*/\1/p' | cut -c1-8)
echo "\$h|\${ram:-}|\${swap:-}|\${swapfree:-}|\${high:-}|\${rss:-}|\${budget:-}|\${build:-}"
EOF
}

# classify RAM_MB SWAP_MB MEMORY_HIGH RSS_MB BUDGET_BYTES -> a verdict on stdout.
classify() {
  local ram=$1 swap=$2 high=$3 rss=$4 budget=$5 v=()
  if [ -z "$ram" ] || [ -z "$budget" ]; then echo unreachable; return; fi
  [ "$ram" -lt 3800 ] && v+=(under-minimum)
  if [ "$ram" -lt 3800 ] && [ "${swap:-0}" -eq 0 ]; then v+=(no-swap); fi
  case "$high" in ""|infinity) v+=(no-memory-high) ;; esac
  if [ -n "$rss" ] && [ $((ram - rss - budget / 1048576)) -lt 128 ]; then v+=(no-headroom); fi
  if [ ${#v[@]} -eq 0 ]; then echo ok; else (IFS=,; echo "${v[*]}"); fi
}

# One host's line, from what probe_cmd printed.
row() {
  local h ram swap swapfree high rss budget build
  IFS='|' read -r h ram swap swapfree high rss budget build <<<"$1"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${h:-?}" "${ram:-?}" "${swap:-?}" "${swapfree:-?}" "${high:-?}" "${rss:-?}" \
    "$([ -n "$budget" ] && echo $((budget / 1048576)) || echo '?')" "${build:-?}" "$(classify "$ram" "$swap" "$high" "$rss" "$budget")"
}

if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${SELFTEST:-}" = 1 ]; then
  export SELFTEST=0; PASS=0; FAIL=0
  t() { local what=$1 want=$2 got; shift 2; got=$("$@"); if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $what"; else FAIL=$((FAIL+1)); echo "  FAIL $what: got '$got', want '$want'"; fi; }
  # 134889472: chain 21's default budget on a 1 967 MB host (its floor); 268435456: the 256 MiB ceiling.
  t "a 4 GB validator with MemoryHigh is ok"                ok                              classify 3915 0 3327000000 460 268435456
  t "a 2 GB validator with swap is under the minimum"       under-minimum                   classify 1967 1023 1672000000 460 134889472
  t "a 2 GB validator without swap says so"                 under-minimum,no-swap           classify 1967 0 1672000000 460 134889472
  t "a unit without MemoryHigh says so"                     no-memory-high                  classify 3915 0 infinity 460 268435456
  t "an empty MemoryHigh is no MemoryHigh"                  no-memory-high                  classify 3915 0 "" 460 268435456
  t "resident memory plus the budget past RAM is no headroom" under-minimum,no-headroom     classify 1967 1023 1672000000 1750 134889472
  t "a host that answered nothing is unreachable"           unreachable                     classify "" "" "" "" ""
  t "a host whose RPC is closed is unreachable"             unreachable                     classify 3915 0 3327000000 460 ""
  t "a row is nine tab-separated fields" 9 bash -c 'source "$1"; row "e|1967|1023|1000|1672000000|460|134889472|4a1b2c3d" | awk -F"\t" "{print NF}"' selftest "$0"
  t "a row carries the budget in MiB and the verdict" "128 under-minimum" bash -c 'source "$1"; row "e|1967|1023|1000|1672000000|460|134889472|4a1b2c3d" | awk -F"\t" "{print \$7, \$9}"' selftest "$0"
  t "the probe runs nothing that writes, restarts or stops" 0 bash -c 'source "$1"; probe_cmd rand-node | grep -cE "(^|[ ;|(])(rm|mv|tee|dd|kill|systemctl (restart|stop|start|daemon-reload)|sed -i)( |$)"' selftest "$0"
  echo "probe-memory self-test: $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]; exit
fi

# Sourced (the self-test sources this file for `row` and `probe_cmd`): define, do not run.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then return 0; fi

echo -e "host\tram_mb\tswap_mb\tswap_free_mb\tmemory_high\trss_mb\tbudget_mib\tbuild\tverdict"
bad=0
if [ "${1:-}" = --local ]; then
  line=$(row "$(bash -c "$(probe_cmd "${2:-rand-node}")")")
  echo "$line"; case "$line" in *$'\t'ok) ;; *) bad=1 ;; esac
  exit $bad
fi
cd "$(dirname "$0")/.."
. "$(dirname "$0")/lib/fleet-env.sh"
require_fleet_env
IPS=$(grep -oE '/ip4/[0-9.]+' "$NODES_ENV" | cut -d/ -f3 | sort -u)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
for ip in $IPS; do
  ( ssh -o ConnectTimeout=8 -o BatchMode=yes "root@$ip" "$(probe_cmd rand-node)" > "$TMP/$ip" 2>/dev/null ) &
done
wait
for ip in $IPS; do
  out=$(cat "$TMP/$ip" 2>/dev/null)
  [ -n "$out" ] || out="$ip|||||||"
  line=$(row "$out")
  echo "$line"; case "$line" in *$'\t'ok) ;; *) bad=1 ;; esac
done
exit $bad
