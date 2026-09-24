#!/usr/bin/env bash
# Delete a droplet's retired chain data directories — every /root/data-* whose genesis suffix is
# not the one the running unit's ExecStart names — and only while the node answers
# rand_getHealth: ok. The 2026-09-21 fleet-wide cleanup as a script (audit v5, OPS-3's second
# half): chains 11–13 left on disk after each cut are what filled the 48 GB droplets, twice.
#
#   deploy/retire-chain-dirs.sh <ip> [--dry-run]
#
# Refuses when the unit's datadir cannot be read, when health is not ok, or when a candidate
# directory is the current one. Prints what it deletes and the disk before and after.
set -euo pipefail
IP=$1; DRY=${2:-}
ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$IP "set -euo pipefail
  unit=/etc/systemd/system/rand-node.service
  cur=\$(grep -oE -- '--datadir [^ ]+' \$unit | awk '{print \$2}')
  [ -n \"\$cur\" ] || { echo 'no --datadir in the unit; refusing' >&2; exit 1; }
  suffix=\${cur##*-}
  health=\$(curl -s -m 5 -X POST -H content-type:application/json --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}' 127.0.0.1:8545 | grep -o '\"status\":\"ok\"' || true)
  [ -n \"\$health\" ] || { echo \"\$(hostname): health is not ok; refusing\" >&2; exit 1; }
  echo \"\$(hostname): current datadir \$cur (genesis \$suffix); before: \$(df -h / | awk 'NR==2{print \$3\" used, \"\$4\" free\"}')\"
  for d in /root/data-*; do
    [ -d \"\$d\" ] || continue
    [ \"\$d\" = \"\$cur\" ] && continue
    case \"\$d\" in *-\$suffix) echo \"  keeping \$d (current genesis)\"; continue;; esac
    if [ \"$DRY\" = --dry-run ]; then echo \"  would delete \$d (\$(du -sh \$d | cut -f1))\"; else echo \"  deleting \$d (\$(du -sh \$d | cut -f1))\"; rm -rf -- \"\$d\"; fi
  done
  echo \"  after: \$(df -h / | awk 'NR==2{print \$3\" used, \"\$4\" free\"}')\""
