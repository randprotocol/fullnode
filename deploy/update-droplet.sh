#!/usr/bin/env bash
# Same-chain binary update of one droplet — no genesis change, no unit edit, data dir kept:
#
#   deploy/update-droplet.sh <ip> [build-host]
#
# - the binaries come from BUILD_HOST (default: node E, 188.166.235.187), fanned out
#   droplet-to-droplet over the forwarded agent (`ssh -A`), never from the laptop's uplink
#   (build there first with `deploy/rebuild-vps.sh <build-host>` from a clean checkout);
# - both copies (rand-node and rand) are checked against WANT_SHA / WANT_SHA_WALLET (or, without
#   them, the build host's sha256) before anything is installed or the service is stopped;
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

# The shas the copies must match — BOTH binaries: rand-node runs as the service, and `rand` (the
# wallet) is installed beside it and run as root below, so an unchecked wallet binary is root code
# execution on every droplet (ops review OPS-2). Pass WANT_SHA and WANT_SHA_WALLET (the sha256s the
# release tag's annotation names) so the check is against the release, not against whatever the
# build host currently holds: a compromised build host would otherwise pass its own binaries
# through "sha matches the build host" every time (deep scan 2026-09-24). WANT_SHA without
# WANT_SHA_WALLET is refused. Without either the old behaviour stands, with a warning.
host_sha() { ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$BUILD_HOST "sha256sum $BUILD_DIR/$1 | cut -d' ' -f1"; }
if [ -n "${WANT_SHA:-}" ]; then
  [ -n "${WANT_SHA_WALLET:-}" ] || { echo "WANT_SHA is set but WANT_SHA_WALLET is not — the $BIN_WALLET binary runs as root too; pass the release's sha256 of it" >&2; exit 1; }
  WANT=$WANT_SHA
  WANT_WALLET=$WANT_SHA_WALLET
  HOST_HAS=$(host_sha "$BIN_NODE")
  [ "$HOST_HAS" = "$WANT" ] || { echo "$BUILD_HOST holds $BIN_NODE ${HOST_HAS:0:12}, not the release's ${WANT:0:12} — not rolling" >&2; exit 1; }
  HOST_HAS=$(host_sha "$BIN_WALLET")
  [ "$HOST_HAS" = "$WANT_WALLET" ] || { echo "$BUILD_HOST holds $BIN_WALLET ${HOST_HAS:0:12}, not the release's ${WANT_WALLET:0:12} — not rolling" >&2; exit 1; }
else
  [ -z "${WANT_SHA_WALLET:-}" ] || { echo "WANT_SHA_WALLET is set but WANT_SHA is not — pass both" >&2; exit 1; }
  echo "warning: no WANT_SHA/WANT_SHA_WALLET — trusting $BUILD_HOST's own shas; pass the tag's sha256s for a release roll" >&2
  WANT=$(host_sha "$BIN_NODE")
  WANT_WALLET=$(host_sha "$BIN_WALLET")
fi
HAVE=$($SSH "sha256sum /usr/local/bin/$BIN_NODE | cut -d' ' -f1")
HAVE_WALLET=$($SSH "sha256sum /usr/local/bin/$BIN_WALLET 2>/dev/null | cut -d' ' -f1")
if [ "$WANT" = "$HAVE" ] && [ "$WANT_WALLET" = "$HAVE_WALLET" ]; then echo "$IP: already on ${WANT:0:8}"; exit 0; fi

$SSH "set -e
  scp -o StrictHostKeyChecking=accept-new root@$BUILD_HOST:$BUILD_DIR/$BIN_NODE root@$BUILD_HOST:$BUILD_DIR/$BIN_WALLET /root/
  chmod 755 /root/$BIN_NODE /root/$BIN_WALLET
  [ \"\$(sha256sum /root/$BIN_NODE | cut -d' ' -f1)\" = \"$WANT\" ] || { echo 'copied $BIN_NODE does not match the expected sha — not touching this node' >&2; exit 1; }
  [ \"\$(sha256sum /root/$BIN_WALLET | cut -d' ' -f1)\" = \"$WANT_WALLET\" ] || { echo 'copied $BIN_WALLET does not match the expected sha — not touching this node' >&2; exit 1; }
  systemctl stop $SERVICE
  install -m 755 /root/$BIN_NODE /root/$BIN_WALLET /usr/local/bin/
  if [ -n \"${PRUNE_ARGS:-}\" ] && ! grep -q -- '--prune-history' /etc/systemd/system/$SERVICE.service; then
    sed -i \"s|^ExecStart=\(.*\)\$|ExecStart=\1 ${PRUNE_ARGS}|\" /etc/systemd/system/$SERVICE.service
    systemctl daemon-reload
  fi
  systemctl restart $SERVICE
  sleep 4
  systemctl is-active $SERVICE
  /usr/local/bin/$BIN_WALLET status | grep -E '\"(height|peer_count|chain_id)\"' || true"
echo "$IP: updated to ${WANT:0:8}"
