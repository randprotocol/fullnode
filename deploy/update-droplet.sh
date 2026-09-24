#!/usr/bin/env bash
# Same-chain binary update of one droplet — no genesis change, no unit edit, data dir kept:
#
#   deploy/update-droplet.sh <ip> [build-host]
#
# - the binaries come from BUILD_HOST (default: node E, 188.166.235.187), fanned out
#   droplet-to-droplet over the forwarded agent (`ssh -A`), never from the laptop's uplink
#   (build there first with `deploy/rebuild-vps.sh <build-host>` from a clean checkout);
# - the copies are checked against the build host's sha256 before the service is stopped;
# - a droplet already on that binary is left alone (idempotent, safe to re-run over the fleet).
#
# Run one droplet at a time and let it rejoin (16 peers, height moving) before the next, so the
# validator quorum is never short by more than one node.
set -euo pipefail
IP=$1; BUILD_HOST=${2:-188.166.235.187}
SERVICE=${SERVICE:-rand-node}
BIN_NODE=${BIN_NODE:-rand-node}
BIN_WALLET=${BIN_WALLET:-rand}
BUILD_DIR=${BUILD_DIR:-/root/fullnode/target/release}
SSH="ssh -A -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$IP"

# The sha the copy must match. Pass WANT_SHA (the sha256 the release tag's annotation names) so the
# check is against the release, not against whatever the build host currently holds: a compromised
# build host would otherwise pass its own binary through "sha matches the build host" every time
# (deep scan 2026-09-24). Without WANT_SHA the old behaviour stands, with a warning.
if [ -n "${WANT_SHA:-}" ]; then
  WANT=$WANT_SHA
  HOST_HAS=$(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$BUILD_HOST "sha256sum $BUILD_DIR/$BIN_NODE | cut -d' ' -f1")
  [ "$HOST_HAS" = "$WANT" ] || { echo "$BUILD_HOST holds ${HOST_HAS:0:12}, not the release's ${WANT:0:12} — not rolling" >&2; exit 1; }
else
  echo "warning: no WANT_SHA — trusting $BUILD_HOST's own sha; pass the tag's sha256 for a release roll" >&2
  WANT=$(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$BUILD_HOST "sha256sum $BUILD_DIR/$BIN_NODE | cut -d' ' -f1")
fi
HAVE=$($SSH "sha256sum /usr/local/bin/$BIN_NODE | cut -d' ' -f1")
if [ "$WANT" = "$HAVE" ]; then echo "$IP: already on ${WANT:0:8}"; exit 0; fi

$SSH "set -e
  scp -o StrictHostKeyChecking=accept-new root@$BUILD_HOST:$BUILD_DIR/$BIN_NODE root@$BUILD_HOST:$BUILD_DIR/$BIN_WALLET /root/
  chmod 755 /root/$BIN_NODE /root/$BIN_WALLET
  [ \"\$(sha256sum /root/$BIN_NODE | cut -d' ' -f1)\" = \"$WANT\" ] || { echo 'copied $BIN_NODE does not match the build host — not touching this node' >&2; exit 1; }
  systemctl stop $SERVICE
  install -m 755 /root/$BIN_NODE /root/$BIN_WALLET /usr/local/bin/
  systemctl restart $SERVICE
  sleep 4
  systemctl is-active $SERVICE
  /usr/local/bin/$BIN_WALLET status | grep -E '\"(height|peer_count|chain_id)\"' || true"
echo "$IP: updated to ${WANT:0:8}"
