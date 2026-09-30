#!/usr/bin/env bash
# All-stop, all-start roll of a same-chain node-only build (v0.5.5's procedure, kept for v0.5.6):
#
#   deploy/roll-all.sh <rand-node binary> <rand binary> <expected sha256 of rand-node> [<expected sha256 of rand>]
#
#   The wallet's sha is the fourth argument or WANT_SHA_WALLET; without one the roll is refused —
#   `rand` is installed as root and run as root, so it is checked exactly like rand-node (OPS-2).
#
# 1. copies both binaries to every droplet in deploy/nodes.env and installs them only when each
#    copy's sha256 equals the expected one (the release tag's), keeping the previous rand-node
#    beside it as /root/rand-node.prev; nothing restarts yet;
# 2. stops node A (launchd) and every droplet's rand-node together;
# 3. starts them all together, A last.
#
# The release's signature is checked before anything is copied (audit v6, PROC-5;
# deploy/lib/verify-release.sh): with RELEASE_SUMS=<SHA256SUMS> and RELEASE_SIG=<SHA256SUMS.sig>
# the signature must verify against a key in deploy/release-signers, both local binaries must be
# the ones the signed file lists (as `rand-node` and `rand`), and the expected shas given as
# arguments must agree with it. Without them the roll is unsigned and is refused unless
# ALLOW_UNSIGNED=1 says so on purpose.
#
# Use it when a release must never run mixed (a validity rule changed — v0.5.6's call-proof caps)
# or when a certificate lost fleet-wide must not be re-announced by any running peer (v0.5.5).
# The chain commits nothing for the ~15 min of startup verify. A one-at-a-time roll is
# deploy/update-droplet.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE_BIN=$1; WALLET_BIN=$2; WANT=$3; WANT_WALLET=${4:-${WANT_SHA_WALLET:-}}
[ -n "$WANT_WALLET" ] || { echo "no expected sha256 for $WALLET_BIN (fourth argument or WANT_SHA_WALLET) — the wallet binary is installed as root too"; exit 1; }
. deploy/lib/verify-release.sh
if [ -n "${RELEASE_SUMS:-}" ] || [ -n "${RELEASE_SIG:-}" ]; then
  { [ -n "${RELEASE_SUMS:-}" ] && [ -n "${RELEASE_SIG:-}" ]; } || { echo "RELEASE_SUMS and RELEASE_SIG go together: the release's SHA256SUMS and its SHA256SUMS.sig"; exit 1; }
  verify_release_sums "$RELEASE_SUMS" "$RELEASE_SIG" || exit 1
  verify_binary "$NODE_BIN" "$RELEASE_SUMS" rand-node || exit 1
  verify_binary "$WALLET_BIN" "$RELEASE_SUMS" rand || exit 1
  [ "$WANT" = "$(release_sha "$RELEASE_SUMS" rand-node)" ] || { echo "the expected rand-node sha256 given here is not the one the signed SHA256SUMS lists — not rolling"; exit 1; }
  [ "$WANT_WALLET" = "$(release_sha "$RELEASE_SUMS" rand)" ] || { echo "the expected rand sha256 given here is not the one the signed SHA256SUMS lists — not rolling"; exit 1; }
else
  echo "################################################################################"
  echo "# UNSIGNED ROLL: no RELEASE_SUMS/RELEASE_SIG. Nothing ties these binaries to a"
  echo "# release the key holder signed; the sha256s on the command line prove only that"
  echo "# the copies are intact. They will run as root on every node in deploy/nodes.env."
  echo "################################################################################"
  [ "${ALLOW_UNSIGNED:-}" = 1 ] || { echo "refusing an unsigned roll — pass RELEASE_SUMS and RELEASE_SIG, or ALLOW_UNSIGNED=1 to go ahead anyway"; exit 1; }
fi
[ "$(shasum -a 256 "$NODE_BIN" | cut -d' ' -f1)" = "$WANT" ] || { echo "local $NODE_BIN does not match $WANT"; exit 1; }
[ "$(shasum -a 256 "$WALLET_BIN" | cut -d' ' -f1)" = "$WANT_WALLET" ] || { echo "local $WALLET_BIN does not match $WANT_WALLET"; exit 1; }
IPS=$(grep -oE '/ip4/[0-9.]+' deploy/nodes.env | cut -d/ -f3 | sort -u)
echo "== install (no restart) $(date -u +%H:%M:%S)"
for ip in $IPS; do
  scp -q -o ConnectTimeout=15 -o BatchMode=yes "$NODE_BIN" root@$ip:/root/rand-node.new && scp -q -o ConnectTimeout=15 -o BatchMode=yes "$WALLET_BIN" root@$ip:/root/rand.new || { echo "   $ip: copy failed"; continue; }
  ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip "set -e; [ \"\$(sha256sum /root/rand-node.new | cut -d' ' -f1)\" = \"$WANT\" ] && [ \"\$(sha256sum /root/rand.new | cut -d' ' -f1)\" = \"$WANT_WALLET\" ] || { echo '   sha mismatch, skipping'; rm -f /root/rand-node.new /root/rand.new; exit 1; }; cp -f /usr/local/bin/rand-node /root/rand-node.prev; install -m 755 /root/rand-node.new /usr/local/bin/rand-node; install -m 755 /root/rand.new /usr/local/bin/rand; rm -f /root/rand-node.new /root/rand.new; echo \"   \$(hostname): installed \$(/usr/local/bin/rand-node --version)\"" 2>&1 | tail -1
done
echo "== stop all $(date -u +%H:%M:%S)"
launchctl bootout gui/$(id -u)/org.randprotocol.node-a 2>/dev/null && echo "   A stopped"
for ip in $IPS; do ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'systemctl stop rand-node; echo "   $(hostname): $(systemctl is-active rand-node)"' 2>&1 | tail -1 & done; wait
echo "== start all $(date -u +%H:%M:%S)"
for ip in $IPS; do ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'systemctl start rand-node; sleep 2; echo "   $(hostname): $(systemctl is-active rand-node)"' 2>&1 | tail -1 & done; wait
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.randprotocol.node-a.plist && echo "   A started"
echo "ROLL-DONE $(date -u +%H:%M:%S) — wait for rand_getHealth: ok on every node (deploy/fleet-watch.sh)"
