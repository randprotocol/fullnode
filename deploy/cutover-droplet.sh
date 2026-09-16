#!/usr/bin/env bash
# Cut one droplet over to a new chain, the way the 2026-09-13 chain-8 rollout did it by hand
# (deploy/README.md, "The droplet unit change, exactly as applied"), plus the binary swap:
#
#   deploy/cutover-droplet.sh <ip> <old-genesis-prefix> <new-genesis-prefix> <genesis-file> [build-host]
#
# - the binaries come from BUILD_HOST (default: node E, 188.166.235.187), fanned out
#   droplet-to-droplet over the forwarded agent (`ssh -A`), never from the laptop's uplink;
# - the genesis file is copied from this checkout and its hash is checked against
#   <new-genesis-prefix> before anything is stopped;
# - the unit's `--datadir` suffix is the only line edited (peer ids and bootstraps stay), and the
#   previous unit is kept at /root/<service>.service.<old>.bak;
# - the old data dir is left in place (keyed on its genesis hash, it never collides).
#
# SERVICE and BIN_NODE/BIN_WALLET default to the pre-rename names; the chain-10 cut-over passes
# the RAND ones. Run from the repo root with an agent that can reach both hosts.
set -euo pipefail
IP=$1; OLD=$2; NEW=$3; GENESIS=$4; BUILD_HOST=${5:-188.166.235.187}
SERVICE=${SERVICE:-rand-node}
BIN_NODE=${BIN_NODE:-rand-node}
BIN_WALLET=${BIN_WALLET:-rand}
BUILD_DIR=${BUILD_DIR:-/root/fullnode/target/release}
SSH="ssh -A -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$IP"

# 1. the genesis file, and its hash checked on the droplet with the NEW binary before any stop
scp -o StrictHostKeyChecking=accept-new "$GENESIS" "root@$IP:/root/fullnode/deploy/$(basename "$GENESIS")"
$SSH "scp -o StrictHostKeyChecking=accept-new root@$BUILD_HOST:$BUILD_DIR/$BIN_NODE root@$BUILD_HOST:$BUILD_DIR/$BIN_WALLET /root/ && chmod 755 /root/$BIN_NODE /root/$BIN_WALLET"
HASH=$($SSH "/root/$BIN_NODE init --datadir /root/probe-\$\$ --genesis /root/fullnode/deploy/$(basename "$GENESIS") | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2; rm -rf /root/probe-\$\$")
case "$HASH" in
  "$NEW"*) ;;
  *) echo "genesis hash on $IP is $HASH, expected prefix $NEW — stopping before any change" >&2; exit 1 ;;
esac

# 2. the unit check FIRST (a droplet already cut over, or one with a hand-edited unit, is refused
#    before anything is stopped — the chain-9 rollout learned this by leaving three nodes
#    stopped), then stop, swap the binaries, init the new data dir, repoint the unit, restart
$SSH "set -e
  UNIT=/etc/systemd/system/$SERVICE.service
  n=\$(grep -c -- '-$OLD' \$UNIT || true)
  [ \"\$n\" = 1 ] || { echo \"expected exactly one -$OLD in \$UNIT, found \$n — not touching this node\" >&2; exit 1; }
  systemctl stop $SERVICE
  install -m 755 /root/$BIN_NODE /root/$BIN_WALLET /usr/local/bin/
  DATA=/root/data-\$(hostname)-$NEW
  [ -d \$DATA/db ] || /usr/local/bin/$BIN_NODE init --datadir \$DATA --genesis /root/fullnode/deploy/$(basename "$GENESIS")
  cp -a \$UNIT /root/$SERVICE.service.$OLD.bak
  sed -i 's/-$OLD/-$NEW/' \$UNIT
  systemctl daemon-reload
  systemctl restart $SERVICE
  sleep 4
  systemctl is-active $SERVICE
  /usr/local/bin/$BIN_WALLET status | grep -E '\"(height|peer_count|chain_id)\"' || true"
echo "$IP: cut over to $NEW"
