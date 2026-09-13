#!/usr/bin/env bash
# Run locally: switch-chain.sh <ip> [validator|observer]  — ship deploy/genesis.json to a droplet that
# already runs shrugg-node, init a fresh datadir keyed on the genesis hash, rewrite the unit's
# --datadir (and --validator flag) keeping its key and bootstraps, restart. Used at a chain cut.
set -euo pipefail
IP=$1; ROLE=${2:-validator}
cd "$(dirname "$0")/.."
KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}
SSH="ssh -n -i $KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=25 -o BatchMode=yes"
scp -q -i "$KEY" -o StrictHostKeyChecking=accept-new deploy/genesis.json root@$IP:/root/fullnode/deploy/genesis.json
$SSH root@$IP "set -e
NAME=\$(hostname)
HASH=\$(shrugg-node init --datadir /root/probe-\$\$ --genesis /root/fullnode/deploy/genesis.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-\$\$
DATA=/root/data-\$NAME-\${HASH:0:8}
[ -d \$DATA/db ] || shrugg-node init --datadir \$DATA --genesis /root/fullnode/deploy/genesis.json >/dev/null
U=/etc/systemd/system/shrugg-node.service
sed -i \"s|--datadir /root/data-[^ ]*|--datadir \$DATA|\" \$U
sed -i 's| --validator||' \$U
if [ '$ROLE' = validator ]; then sed -i 's| --listen| --validator --listen|' \$U; fi
systemctl daemon-reload; systemctl restart shrugg-node
for i in \$(seq 1 25); do sleep 3; s=\$(shrugg status 2>/dev/null | grep -E '\"(height|peer_count|is_validator)\"' | tr -d '\n '); [ -n \"\$s\" ] && break; done
echo \"$IP \$NAME \${HASH:0:8} \$s\""
