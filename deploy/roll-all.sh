#!/usr/bin/env bash
# All-stop, all-start roll of a same-chain node-only build (v0.5.5's procedure, kept for v0.5.6):
#
#   deploy/roll-all.sh <rand-node binary> <rand binary> <expected sha256 of rand-node>
#
# 1. copies both binaries to every droplet in deploy/nodes.env and installs them only when the
#    copy's sha256 equals the expected one (the release tag's), keeping the previous rand-node
#    beside it as /root/rand-node.prev; nothing restarts yet;
# 2. stops node A (launchd) and every droplet's rand-node together;
# 3. starts them all together, A last.
#
# Use it when a release must never run mixed (a validity rule changed — v0.5.6's call-proof caps)
# or when a certificate lost fleet-wide must not be re-announced by any running peer (v0.5.5).
# The chain commits nothing for the ~15 min of startup verify. A one-at-a-time roll is
# deploy/update-droplet.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE_BIN=$1; WALLET_BIN=$2; WANT=$3
[ "$(shasum -a 256 "$NODE_BIN" | cut -d' ' -f1)" = "$WANT" ] || { echo "local $NODE_BIN does not match $WANT"; exit 1; }
IPS=$(grep -oE '/ip4/[0-9.]+' deploy/nodes.env | cut -d/ -f3 | sort -u)
echo "== install (no restart) $(date -u +%H:%M:%S)"
for ip in $IPS; do
  scp -q -o ConnectTimeout=15 -o BatchMode=yes "$NODE_BIN" root@$ip:/root/rand-node.new && scp -q -o ConnectTimeout=15 -o BatchMode=yes "$WALLET_BIN" root@$ip:/root/rand.new || { echo "   $ip: copy failed"; continue; }
  ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip "set -e; [ \"\$(sha256sum /root/rand-node.new | cut -d' ' -f1)\" = \"$WANT\" ] || { echo '   sha mismatch, skipping'; rm -f /root/rand-node.new /root/rand.new; exit 1; }; cp -f /usr/local/bin/rand-node /root/rand-node.prev; install -m 755 /root/rand-node.new /usr/local/bin/rand-node; install -m 755 /root/rand.new /usr/local/bin/rand; rm -f /root/rand-node.new /root/rand.new; echo \"   \$(hostname): installed \$(/usr/local/bin/rand-node --version)\"" 2>&1 | tail -1
done
echo "== stop all $(date -u +%H:%M:%S)"
launchctl bootout gui/$(id -u)/org.randprotocol.node-a 2>/dev/null && echo "   A stopped"
for ip in $IPS; do ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'systemctl stop rand-node; echo "   $(hostname): $(systemctl is-active rand-node)"' 2>&1 | tail -1 & done; wait
echo "== start all $(date -u +%H:%M:%S)"
for ip in $IPS; do ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'systemctl start rand-node; sleep 2; echo "   $(hostname): $(systemctl is-active rand-node)"' 2>&1 | tail -1 & done; wait
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.randprotocol.node-a.plist && echo "   A started"
echo "ROLL-DONE $(date -u +%H:%M:%S) — wait for rand_getHealth: ok on every node (deploy/fleet-watch.sh)"
