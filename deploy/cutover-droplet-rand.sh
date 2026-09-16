#!/usr/bin/env bash
# The chain-10 hop for one droplet: from the `shrugg-node` service on chain 9 to the `rand-node`
# service on chain 10. Unlike deploy/cutover-droplet.sh (same service, one datadir edit), the
# rename changes the binaries' names, the service, the data-dir prefix, the hostname, AND every
# peer id (the p2p identity derives under a renamed domain), so the unit is rewritten from
# scratch with the bootstraps given here.
#
#   deploy/cutover-droplet-rand.sh <ip> <node-name> <new-genesis-prefix> <genesis-file> [build-host]
#
# with BOOTSTRAPS="<multiaddr> <multiaddr>" (the NEW peer ids of C and D, or whichever public
# nodes bootstrap the fleet) in the environment. Two passes are expected: `PEER_ID_ONLY=1` puts
# the new binary on the droplet and prints its new peer id without changing anything else — run
# that on every droplet first, build nodes.env and BOOTSTRAPS from the answers, then the real
# pass. Binaries fan out from BUILD_HOST (E) over the forwarded agent, as before.
set -euo pipefail
IP=$1; NAME=$2; NEW=$3; GENESIS=$4; BUILD_HOST=${5:-188.166.235.187}
OLD_SERVICE=${OLD_SERVICE:-shrugg-node}
BUILD_DIR=${BUILD_DIR:-/root/fullnode/target/release}
SSH="ssh -A -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$IP"

$SSH "scp -o StrictHostKeyChecking=accept-new root@$BUILD_HOST:$BUILD_DIR/rand-node root@$BUILD_HOST:$BUILD_DIR/rand /root/ && chmod 755 /root/rand-node /root/rand"
PEER=$($SSH "/root/rand-node address --key /root/fullnode/deploy/node-$NAME.key.json | grep -o 'peer_id: .*' | cut -d' ' -f2")
echo "$IP $NAME peer_id $PEER"
if [ "${PEER_ID_ONLY:-}" = 1 ]; then exit 0; fi
[ -n "${BOOTSTRAPS:-}" ] || { echo "BOOTSTRAPS is empty — run the peer-id pass first" >&2; exit 1; }

scp -o StrictHostKeyChecking=accept-new "$GENESIS" "root@$IP:/root/fullnode/deploy/$(basename "$GENESIS")"
HASH=$($SSH "/root/rand-node init --datadir /root/probe-\$\$ --genesis /root/fullnode/deploy/$(basename "$GENESIS") | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2; rm -rf /root/probe-\$\$")
case "$HASH" in
  "$NEW"*) ;;
  *) echo "genesis hash on $IP is $HASH, expected prefix $NEW — stopping before any change" >&2; exit 1 ;;
esac

BOOT_ARGS=""; for b in $BOOTSTRAPS; do BOOT_ARGS="$BOOT_ARGS --bootstrap $b"; done
$SSH "set -e
  [ -f /etc/systemd/system/$OLD_SERVICE.service ] || { echo 'no $OLD_SERVICE unit here — already over?' >&2; exit 1; }
  systemctl disable --now $OLD_SERVICE
  install -m 755 /root/rand-node /root/rand /usr/local/bin/
  hostnamectl set-hostname rand-node-$NAME
  DATA=/root/data-rand-node-$NAME-$NEW
  [ -d \$DATA/db ] || /usr/local/bin/rand-node init --datadir \$DATA --genesis /root/fullnode/deploy/$(basename "$GENESIS")
  cat > /etc/systemd/system/rand-node.service <<UNIT
[Unit]
Description=RAND full node ($NAME)
After=network-online.target
[Service]
Environment=RUST_LOG=info,libp2p=warn,libp2p_mdns=off
ExecStart=/usr/local/bin/rand-node run --datadir \$DATA --key /root/fullnode/deploy/node-$NAME.key.json --validator --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:8545 --no-mdns$BOOT_ARGS
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
  mv /etc/systemd/system/$OLD_SERVICE.service /root/$OLD_SERVICE.service.chain9.bak
  systemctl daemon-reload
  systemctl enable --now rand-node
  sleep 4
  systemctl is-active rand-node
  /usr/local/bin/rand status | grep -E '\"(height|peer_count|peer_id)\"' || true"
echo "$IP: on chain 10 as rand-node ($NAME, peer $PEER)"
