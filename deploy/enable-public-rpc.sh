#!/usr/bin/env bash
# Open the node's own public RPC listener (--public-rpc 127.0.0.1:8546) on a host that serves
# public RPC traffic (VK-2): a fixed read-method set plus rand_sendTransaction; no viewing-key
# methods, no rand_mint, no rand_getPeers; no batches, no WebSocket; one meter for all callers.
# Point the reverse proxy or SSH tunnel at 8546, never at --rpc (8545).
#
#   deploy/enable-public-rpc.sh root@<host> [unit]        # edits the unit, does NOT restart
#   RESTART=1 deploy/enable-public-rpc.sh root@<host>     # ... and restarts it (one host at a time)
#
# Idempotent. The unit defaults to rand-node. Needs a build with --public-rpc (v0.6.8 or later);
# on an older binary the node refuses to start, so roll the binary first (update-droplet.sh).
set -euo pipefail
TARGET=${1:?usage: enable-public-rpc.sh root@<host> [unit]}
UNIT=${2:-rand-node}
ADDR=127.0.0.1:8546
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20 "$TARGET")
"${SSH[@]}" "set -e
  f=/etc/systemd/system/$UNIT.service
  [ -f \$f ] || { echo \"\$f: no such unit\" >&2; exit 1; }
  /usr/local/bin/rand-node run --help 2>&1 | grep -q -- --public-rpc || { echo 'rand-node here has no --public-rpc: roll a newer binary first' >&2; exit 1; }
  if grep -q -- '--public-rpc' \$f; then echo \"$TARGET: \$f already has --public-rpc\"; else
    sed -i 's|^ExecStart=\(.*\)\$|ExecStart=\1 --public-rpc $ADDR|' \$f
    systemctl daemon-reload
    echo \"$TARGET: --public-rpc $ADDR added to \$f\"
  fi"
if [ "${RESTART:-0}" = 1 ]; then
    "${SSH[@]}" "systemctl restart $UNIT && sleep 4 && systemctl is-active $UNIT"
    "${SSH[@]}" "curl -s -m 5 -X POST -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getPeers\",\"params\":[]}' http://$ADDR/" | grep -q 'not served' \
        && echo "$TARGET: public listener is up and refuses rand_getPeers" \
        || { echo "$TARGET: the public listener did not answer as expected" >&2; exit 1; }
else
    echo "restart to apply: ssh $TARGET systemctl restart $UNIT   (one host at a time; check rand_chainId on $ADDR after)"
fi
