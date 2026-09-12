#!/usr/bin/env bash
# Run locally: provision-observer.sh <droplet-name> <region> <node-key-file> [validator|observer] [size]
# Creates a small DigitalOcean droplet (doctl; token from DIGITALOCEAN_ACCESS_TOKEN), ships the
# prebuilt Linux binaries (LINUX_BIN dir: shrugg-node, shrugg), deploy/genesis.json and the node
# key, and starts a `shrugg-node` systemd service bootstrapping to BOOTSTRAPS (default: D and E).
# No compiler on the droplet: the binaries come from a node that built the fleet commit.
set -euo pipefail
# The saved doctl context wins over the environment, so the token goes on every call explicitly.
doctl() { command doctl --config /dev/null -t "${DIGITALOCEAN_ACCESS_TOKEN:?set DIGITALOCEAN_ACCESS_TOKEN}" "$@"; }
NAME=$1; REGION=$2; KEYFILE=$3; ROLE=${4:-observer}; SIZE=${5:-s-1vcpu-2gb}
cd "$(dirname "$0")/.."
. deploy/nodes.env
BOOTSTRAPS=${BOOTSTRAPS:-"$NODE_D $NODE_E"}
LINUX_BIN=${LINUX_BIN:?set LINUX_BIN to a dir holding Linux x86_64 shrugg-node and shrugg}
SSH_KEY_ID=${SSH_KEY_ID:-53473251}
KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o BatchMode=yes"
VALIDATOR_FLAG=""; [ "$ROLE" = validator ] && VALIDATOR_FLAG="--validator"

# 1 GB of swap keeps a 2 GB box alive while verifier keys warm; ufw opens ssh and p2p only.
USER_DATA='#cloud-config
runcmd:
  - [ sh, -c, "fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo /swapfile none swap sw 0 0 >> /etc/fstab" ]
  - [ sh, -c, "ufw allow 22/tcp && ufw allow 30303/tcp && ufw --force enable" ]
  - [ sh, -c, "touch /root/.cloud-init-done" ]'

if ! doctl compute droplet get "$NAME" >/dev/null 2>&1; then
  doctl compute droplet create "$NAME" --region "$REGION" --size "$SIZE" --image ubuntu-24-04-x64 \
    --ssh-keys "$SSH_KEY_ID" --tag-names shrugg-node --user-data "$USER_DATA" --wait >/dev/null
fi
IP=""; for i in $(seq 1 30); do IP=$(doctl compute droplet get "$NAME" --format PublicIPv4 --no-header); [ -n "$IP" ] && break; sleep 5; done
[ -n "$IP" ] || { echo "$NAME: no public IP"; exit 1; }
for i in $(seq 1 60); do $SSH root@$IP 'test -f /root/.cloud-init-done' 2>/dev/null && break; sleep 5; done
$SSH root@$IP 'test -f /root/.cloud-init-done' || { echo "$NAME ($IP): cloud-init did not finish"; exit 1; }

$SSH root@$IP 'mkdir -p /root/fullnode/deploy'
scp -q -i "$KEY" -o StrictHostKeyChecking=accept-new "$LINUX_BIN/shrugg-node" "$LINUX_BIN/shrugg" root@$IP:/usr/local/bin/
scp -q -i "$KEY" -o StrictHostKeyChecking=accept-new deploy/genesis.json "$KEYFILE" root@$IP:/root/fullnode/deploy/
KEYBASE=$(basename "$KEYFILE")
BOOT_ARGS=""; for b in $BOOTSTRAPS; do BOOT_ARGS="$BOOT_ARGS --bootstrap $b"; done
$SSH root@$IP "set -e; chmod 755 /usr/local/bin/shrugg-node /usr/local/bin/shrugg; chmod 600 /root/fullnode/deploy/$KEYBASE
HASH=\$(shrugg-node init --datadir /root/probe-\$\$ --genesis /root/fullnode/deploy/genesis.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-\$\$
DATA=/root/data-$NAME-\${HASH:0:8}
[ -d \$DATA/db ] || shrugg-node init --datadir \$DATA --genesis /root/fullnode/deploy/genesis.json >/dev/null
cat > /etc/systemd/system/shrugg-node.service <<UNIT
[Unit]
Description=SHRUGG full node ($NAME, $REGION)
After=network-online.target
[Service]
Environment=RUST_LOG=info,libp2p=warn,libp2p_mdns=off
ExecStart=/usr/local/bin/shrugg-node run --datadir \$DATA --key /root/fullnode/deploy/$KEYBASE $VALIDATOR_FLAG --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 --no-mdns $BOOT_ARGS
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable shrugg-node >/dev/null 2>&1; systemctl restart shrugg-node; sleep 8
echo \"$NAME $REGION $IP \$(shrugg status | grep -E '\"(height|peer_count|peer_id)\"' | tr -d '\n ')\""
