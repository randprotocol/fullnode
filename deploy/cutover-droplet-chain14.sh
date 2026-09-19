#!/usr/bin/env bash
# Cut one droplet over to chain 14. This is NOT deploy/cutover-droplet.sh with a new hash in it:
# chain 14 rotates every validator key (audit v3 OPS-1), so
#
#   * each droplet gets a NEW key file, generated on the operator's machine by
#     deploy/gen-chain14-keys.sh and scp'd here — never generated on the droplet, never in the
#     repository, and never under /root/fullnode (deploy/rebuild-vps.sh rsyncs that path with
#     --delete);
#   * every peer id changes with its key, so every `--bootstrap` multiaddr changes, so the unit
#     is REWRITTEN rather than sed-ed — deploy/cutover-droplet.sh's one-line `-<old>` → `-<new>`
#     datadir edit is exactly what cannot work here;
#   * the node then has to be waited for on `rand_getHealth` = ok, not on a sleep: a node's
#     startup chain verification ran 239 s at 59k blocks on chain 12 (deploy/README.md, "The v0.3
#     same-chain update"). A fresh chain-14 datadir starts in seconds, but the wait is the same
#     loop either way and it is what keeps a rolling cut from stopping two validators at once.
#
#   deploy/cutover-droplet-chain14.sh <ip> <node-name> <new-genesis-prefix> <genesis-file> [build-host]
#
#     <node-name>   a|b|…|f|lon1|…|mem1 — picks $KEYDIR/node-<name>.key.json
#     BOOTSTRAPS    space-separated multiaddrs for this node's unit (the chain-14 peer ids, from
#                   $KEYDIR/public/nodes-chain14.env). Required: with stale bootstraps a droplet
#                   dials peer ids that no longer exist.
#     PIN           the build sha written to /root/.update-pin (node B's auto-updater reads it)
#
# The old chain-13 data dir is left in place — it is keyed on its own genesis hash, so it never
# collides — and the previous unit is kept at /root/<service>.service.chain13.bak. That pair is
# the rollback: restore the unit, re-pin, restart.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/lib/key-guard.sh

IP=$1; NAME=$2; NEW=$3; GENESIS=$4; BUILD_HOST=${5:-188.166.235.187}
SERVICE=${SERVICE:-rand-node}
BIN_NODE=${BIN_NODE:-rand-node}
BIN_WALLET=${BIN_WALLET:-rand}
BUILD_DIR=${BUILD_DIR:-/root/fullnode/target/release}
KEYDIR=${KEYDIR:-$HOME/.rand-chain14}
REMOTE_KEYDIR=${REMOTE_KEYDIR:-/root/keys}
RPC=${RPC:-127.0.0.1:8545}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-900}
BOOTSTRAPS=${BOOTSTRAPS:-}
PIN=${PIN:-}
SSH="ssh -A -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$IP"

KEY="$KEYDIR/node-$NAME.key.json"
[ -f "$KEY" ] || { echo "cutover14: no $KEY — run deploy/gen-chain14-keys.sh first" >&2; exit 1; }
refuse_in_tree_key "$KEY"
[ -f "$GENESIS" ] || { echo "cutover14: no genesis file at $GENESIS" >&2; exit 1; }
[ -n "$BOOTSTRAPS" ] || { echo "cutover14: BOOTSTRAPS is empty — a node with no bootstrap on a brand-new peer-id set never finds the fleet" >&2; exit 1; }
[ -n "$PIN" ] || { echo "cutover14: PIN is empty — set it to the chain-14 build sha (/root/.update-pin)" >&2; exit 1; }
GFILE=/root/$(basename "$GENESIS")

# ── 1. everything that can fail before the node is stopped, fails here ─────────────────────────
scp -o StrictHostKeyChecking=accept-new "$GENESIS" "root@$IP:$GFILE"
# The key goes to a 0700 directory outside /root/fullnode, at 0600, over scp only (never printed,
# never echoed into a remote shell).
$SSH "install -d -m 700 $REMOTE_KEYDIR"
scp -o StrictHostKeyChecking=accept-new "$KEY" "root@$IP:$REMOTE_KEYDIR/node-$NAME.key.json"
$SSH "chmod 600 $REMOTE_KEYDIR/node-$NAME.key.json"

# The chain-14 binaries, fanned out droplet-to-droplet over the forwarded agent, and checked
# against the build host's sha256 before anything is installed.
WANT=$(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 root@$BUILD_HOST "sha256sum $BUILD_DIR/$BIN_NODE | cut -d' ' -f1")
$SSH "set -e
  scp -o StrictHostKeyChecking=accept-new root@$BUILD_HOST:$BUILD_DIR/$BIN_NODE root@$BUILD_HOST:$BUILD_DIR/$BIN_WALLET /root/
  chmod 755 /root/$BIN_NODE /root/$BIN_WALLET
  [ \"\$(sha256sum /root/$BIN_NODE | cut -d' ' -f1)\" = \"$WANT\" ] || { echo 'copied $BIN_NODE does not match the build host — not touching this node' >&2; exit 1; }"

# The genesis hash, computed on the droplet by the NEW binary, before any stop. A mismatch here
# is a wrong file or a wrong build and costs nothing.
HASH=$($SSH "/root/$BIN_NODE init --datadir /root/probe-\$\$ --genesis $GFILE | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2; rm -rf /root/probe-\$\$")
case "$HASH" in
  "$NEW"*) ;;
  *) echo "cutover14: genesis hash on $IP is $HASH, expected prefix $NEW — stopping before any change" >&2; exit 1 ;;
esac

# The key on the droplet must be the key this cut put there: its public key has to be one the
# genesis file stakes, or this node joins as a spectator and the quorum is short by one.
PUB=$($SSH "/root/$BIN_NODE address --key $REMOTE_KEYDIR/node-$NAME.key.json" | sed -n 's/^public_key: //p')
python3 - "$GENESIS" "$PUB" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
if sys.argv[2] not in {v["public_key"] for v in g["validators"]}:
    sys.exit(f"cutover14: the key on this droplet ({sys.argv[2][:16]}…) is not a validator in {sys.argv[1]}")
PY

BOOT_ARGS=""; for b in $BOOTSTRAPS; do BOOT_ARGS="$BOOT_ARGS --bootstrap $b"; done

# ── 2. stop, swap, init, rewrite the unit, restart ────────────────────────────────────────────
$SSH "set -e
  UNIT=/etc/systemd/system/$SERVICE.service
  [ -f \$UNIT ] || { echo \"no \$UNIT on this droplet — this script cuts an existing node over\" >&2; exit 1; }
  systemctl stop $SERVICE || true
  install -m 755 /root/$BIN_NODE /root/$BIN_WALLET /usr/local/bin/
  DATA=/root/data-\$(hostname)-$NEW
  [ -d \$DATA/db ] || /usr/local/bin/$BIN_NODE init --datadir \$DATA --genesis $GFILE
  cp -a \$UNIT /root/$SERVICE.service.chain13.bak
  cat > \$UNIT <<UNITEOF
[Unit]
Description=RAND full node ($NAME, chain 14)
After=network-online.target
[Service]
Environment=RUST_LOG=info,libp2p=warn,libp2p_mdns=off
ExecStart=/usr/local/bin/$BIN_NODE run --datadir \$DATA --key $REMOTE_KEYDIR/node-$NAME.key.json --validator --listen /ip4/0.0.0.0/tcp/30303 --rpc $RPC --no-mdns$BOOT_ARGS
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNITEOF
  printf '%s\n' '$PIN' > /root/.update-pin
  systemctl daemon-reload
  systemctl enable $SERVICE >/dev/null
  systemctl restart $SERVICE"

# ── 3. wait on rand_getHealth = ok, never on a sleep ──────────────────────────────────────────
$SSH "set -e
  for i in \$(seq 1 $HEALTH_TIMEOUT); do
    systemctl is-active --quiet $SERVICE || { echo 'service died during startup' >&2; journalctl -u $SERVICE -n 30 --no-pager >&2; exit 1; }
    s=\$(curl -s --max-time 5 -X POST -H 'content-type: application/json' \
          --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}' http://$RPC || true)
    case \"\$s\" in *'\"status\":\"ok\"'*) echo \"healthy after \${i}s\"; exit 0;; esac
    sleep 1
  done
  echo 'rand_getHealth never reached ok' >&2; exit 1"

$SSH "/usr/local/bin/$BIN_WALLET status | grep -E '\"(height|peer_count|chain_id)\"' || true"
echo "$IP ($NAME): on chain 14, genesis $NEW, key $REMOTE_KEYDIR/node-$NAME.key.json, pin $PIN"
