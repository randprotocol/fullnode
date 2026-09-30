#!/usr/bin/env bash
# Runs ON a droplet as root. Usage: vps-setup.sh <node-letter> "<bootstrap multiaddrs>" [validator|observer]
# Expects the repo rsync'd to /root/fullnode (see deploy/push-to-vps.sh).
#
# The node key lives in $KEYDIR (default /root/keys), never under /root/fullnode: rebuild-vps.sh
# and push-to-vps.sh rsync that tree with --delete from a `git archive`, which holds no key file,
# so a key kept there is deleted by the next rebuild and the unit then fails to start (audit v6,
# OPS-8). A key already at $KEYDIR/node-<name>.key.json is used as it is and never overwritten; a
# missing one is generated here, on the host, and only its public half is printed.
set -euo pipefail
NODE=$1; BOOTSTRAPS=${2:-}; ROLE=${3:-validator}
KEYDIR=${KEYDIR:-/root/keys}
KEYFILE=$KEYDIR/node-$NODE.key.json
case "$KEYDIR/" in /root/fullnode/*) echo "refusing KEYDIR=$KEYDIR: it is inside /root/fullnode, which rebuild-vps.sh rsyncs with --delete" >&2; exit 1;; esac
VALIDATOR_FLAG=""; if [ "$ROLE" = validator ]; then VALIDATOR_FLAG="--validator"; fi
while [ ! -f /root/.cloud-init-done ]; do echo "waiting for cloud-init (build deps)..."; sleep 10; done
source /root/.cargo/env
cd /root/fullnode
cargo build --release -p randprotocol-node -p randprotocol-client
install -m 755 target/release/rand-node target/release/rand /usr/local/bin/
HASH=$(/usr/local/bin/rand-node init --datadir /root/probe-$$ --genesis deploy/genesis.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-$$
DATA=/root/data-$NODE-${HASH:0:8}
[ -d $DATA/db ] || /usr/local/bin/rand-node init --datadir $DATA --genesis deploy/genesis.json
install -d -m 700 "$KEYDIR"
if [ -e "$KEYFILE" ]; then
    echo "using the existing key $KEYFILE"
else
    # `rand-node keygen` truncates an existing file, hence the test above; the umask covers the
    # moment before it sets 0600 itself.
    (umask 077; /usr/local/bin/rand-node keygen --out "$KEYFILE" >/dev/null)
    echo "generated $KEYFILE — back it up off this host before the validator is bonded"
fi
chmod 600 "$KEYFILE"
/usr/local/bin/rand-node address --key "$KEYFILE"
BOOT_ARGS=""; for b in $BOOTSTRAPS; do BOOT_ARGS="$BOOT_ARGS --bootstrap $b"; done
# Retire the pre-rename service if this box ran one (shrugg-node, the name before RAND). This runs
# before the rand-node unit is written: the rename once turned this line into `rand-node` itself,
# which deleted the unit just written below.
systemctl disable --now shrugg-node 2>/dev/null || true; rm -f /etc/systemd/system/shrugg-node.service
cat > /etc/systemd/system/rand-node.service <<UNIT
[Unit]
Description=RAND full node ($NODE)
After=network-online.target
[Service]
Environment=RUST_LOG=info,libp2p=warn,libp2p_mdns=off
ExecStart=/usr/local/bin/rand-node run --datadir $DATA --key $KEYFILE $VALIDATOR_FLAG --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 --no-mdns $BOOT_ARGS
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable rand-node
systemctl restart rand-node
sleep 3
systemctl --no-pager status rand-node | head -5
/usr/local/bin/rand status
