#!/usr/bin/env bash
# Runs ON a droplet as root. Usage: vps-setup.sh <node-letter> "<bootstrap multiaddrs>" [validator|observer]
# Expects the repo rsync'd to /root/fullnode (see deploy/push-to-vps.sh).
set -euo pipefail
NODE=$1; BOOTSTRAPS=${2:-}; ROLE=${3:-validator}
VALIDATOR_FLAG=""; if [ "$ROLE" = validator ]; then VALIDATOR_FLAG="--validator"; fi
while [ ! -f /root/.cloud-init-done ]; do echo "waiting for cloud-init (build deps)..."; sleep 10; done
source /root/.cargo/env
cd /root/fullnode
cargo build --release -p shrugg-node -p shrugg-client
install -m 755 target/release/shrugg-node target/release/shrugg /usr/local/bin/
HASH=$(/usr/local/bin/shrugg-node init --datadir /root/probe-$$ --genesis deploy/genesis.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-$$
DATA=/root/data-$NODE-${HASH:0:8}
[ -d $DATA/db ] || /usr/local/bin/shrugg-node init --datadir $DATA --genesis deploy/genesis.json
BOOT_ARGS=""; for b in $BOOTSTRAPS; do BOOT_ARGS="$BOOT_ARGS --bootstrap $b"; done
cat > /etc/systemd/system/shrugg-node.service <<UNIT
[Unit]
Description=SHRUGG full node ($NODE)
After=network-online.target
[Service]
Environment=RUST_LOG=info,libp2p=warn,libp2p_mdns=off
ExecStart=/usr/local/bin/shrugg-node run --datadir $DATA --key /root/fullnode/deploy/node-$NODE.key.json $VALIDATOR_FLAG --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 --no-mdns $BOOT_ARGS
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
# Retire the pre-rename service if this box ran one.
systemctl disable --now sesh-node 2>/dev/null || true; rm -f /etc/systemd/system/sesh-node.service
systemctl daemon-reload
systemctl enable shrugg-node
systemctl restart shrugg-node
sleep 3
systemctl --no-pager status shrugg-node | head -5
/usr/local/bin/shrugg status
