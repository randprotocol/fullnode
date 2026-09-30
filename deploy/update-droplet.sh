#!/usr/bin/env bash
# Same-chain binary update of one droplet — no genesis change, no unit edit, data dir kept:
#
#   deploy/update-droplet.sh <ip> [build-host]
#
# - the binaries come from BUILD_HOST (default: node E, 188.166.235.187), relayed through a
#   scratch directory on this machine with the sha256 checked at every hop (deploy/lib/
#   relay-binaries.sh) — no agent is forwarded to any droplet (ops review OPS-3: `ssh -A` handed
#   the laptop's agent to every droplet it touched); build there first with
#   `deploy/rebuild-vps.sh <build-host>` from a clean checkout;
# - both copies (rand-node and rand) are checked against WANT_SHA / WANT_SHA_WALLET (or, without
#   them, the build host's sha256) before anything is installed or the service is stopped;
# - a droplet already on that binary is left alone (idempotent, safe to re-run over the fleet).
# - the release's signature is checked first (audit v6, PROC-5; deploy/lib/verify-release.sh):
#   pass RELEASE_SUMS=<SHA256SUMS> and RELEASE_SIG=<SHA256SUMS.sig>, the release's checksum file
#   and the release key holder's SSH signature over it. The signature must verify against a key
#   in deploy/release-signers, and the two shas the rest of this script checks at every hop are
#   then READ FROM the signed file (a WANT_SHA/WANT_SHA_WALLET passed as well must agree with
#   it). Without RELEASE_SUMS/RELEASE_SIG the install is unsigned — the sha is only as good as
#   whoever typed it — and the script refuses unless ALLOW_UNSIGNED=1 says so on purpose.
#
# Run one droplet at a time and let it rejoin (16 peers, height moving) before the next, so the
# validator quorum is never short by more than one node.
set -euo pipefail
IP=$1; BUILD_HOST=${2:-188.166.235.187}
SERVICE=${SERVICE:-rand-node}
BIN_NODE=${BIN_NODE:-rand-node}
BIN_WALLET=${BIN_WALLET:-rand}
BUILD_DIR=${BUILD_DIR:-/root/fullnode/target/release}
. "$(dirname "$0")/lib/relay-binaries.sh"
. "$(dirname "$0")/lib/verify-release.sh"
SSH="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$IP"

# The signature, before anything else is asked of any host (PROC-5). The allowed signers are
# deploy/release-signers in this checkout and nothing else: no environment variable points it
# elsewhere.
if [ -n "${RELEASE_SUMS:-}" ] || [ -n "${RELEASE_SIG:-}" ]; then
  { [ -n "${RELEASE_SUMS:-}" ] && [ -n "${RELEASE_SIG:-}" ]; } || { echo "RELEASE_SUMS and RELEASE_SIG go together: the release's SHA256SUMS and its SHA256SUMS.sig" >&2; exit 1; }
  verify_release_sums "$RELEASE_SUMS" "$RELEASE_SIG" || exit 1
  SIGNED_NODE=$(release_sha "$RELEASE_SUMS" "$BIN_NODE") || exit 1
  SIGNED_WALLET=$(release_sha "$RELEASE_SUMS" "$BIN_WALLET") || exit 1
  [ -z "${WANT_SHA:-}" ] || [ "$WANT_SHA" = "$SIGNED_NODE" ] || { echo "WANT_SHA ${WANT_SHA:0:12} is not what the signed SHA256SUMS lists for $BIN_NODE (${SIGNED_NODE:0:12}) — not rolling" >&2; exit 1; }
  [ -z "${WANT_SHA_WALLET:-}" ] || [ "$WANT_SHA_WALLET" = "$SIGNED_WALLET" ] || { echo "WANT_SHA_WALLET ${WANT_SHA_WALLET:0:12} is not what the signed SHA256SUMS lists for $BIN_WALLET (${SIGNED_WALLET:0:12}) — not rolling" >&2; exit 1; }
  WANT_SHA=$SIGNED_NODE
  WANT_SHA_WALLET=$SIGNED_WALLET
else
  {
    echo "################################################################################"
    echo "# UNSIGNED INSTALL: no RELEASE_SUMS/RELEASE_SIG. Nothing ties these binaries to a"
    echo "# release the key holder signed; a sha256 typed by hand or read off the build host"
    echo "# proves only that the copy is intact. They will run as root on $IP."
    echo "################################################################################"
  } >&2
  [ "${ALLOW_UNSIGNED:-}" = 1 ] || { echo "refusing an unsigned install — pass RELEASE_SUMS and RELEASE_SIG, or ALLOW_UNSIGNED=1 to go ahead anyway" >&2; exit 1; }
fi

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

relay_binaries "$IP"
$SSH "set -e
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
