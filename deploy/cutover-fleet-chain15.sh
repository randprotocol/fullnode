#!/usr/bin/env bash
# Cut the fleet over from chain 14 to chain 15 — all-stop, all-start, in phases.
#
# Chain 15 keeps chain 14's validator keys (so every peer id, every `--bootstrap` multiaddr and
# deploy/nodes.env stay as they are): each unit changes in exactly one place, its datadir suffix
# `-<old prefix>` → `-<new prefix>`. Keys stay where they are (/root/keys), untouched.
#
#   deploy/cutover-fleet-chain15.sh stage              # chain 14 still running: relay + install-aside
#   deploy/cutover-fleet-chain15.sh stop               # stop every chain-14 node (droplets + obs1 + A)
#   (cut the genesis now: deploy/cut-chain15-genesis.sh — minutes before `switch`, never earlier)
#   deploy/cutover-fleet-chain15.sh switch <genesis>   # install, init, rewrite unit datadir — no start
#   deploy/cutover-fleet-chain15.sh start              # bootstraps C, D first, then the rest, A last
#
# Env: BUILD_HOST (E), BUILD_DIR (where E built the release), WANT_SHA / WANT_SHA_WALLET (the sha256
# of the Linux rand-node / rand; both required), OLD (chain-14 datadir suffix, 1cff3b7d), NODE_A_BINDIR
# (node A's macOS build dir under ~/rand-node-a, for `switch`/`start`).
#
# The guardians' six observer droplets are NOT here: the bridge session cuts them over with their
# guardians. The chain-14 data dirs are kept (rollback = restore the unit's old suffix and binary,
# `/root/rand-node.c14`), retire them later with deploy/retire-chain-dirs.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

PHASE=${1:?stage|stop|switch|start}
BUILD_HOST=${BUILD_HOST:-188.166.235.187}
BUILD_DIR=${BUILD_DIR:-/root/build15/target/release}
BIN_NODE=rand-node; BIN_WALLET=rand
OLD=${OLD:-1cff3b7d}
OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -o BatchMode=yes"
BOOTS="164.90.239.200 165.245.173.74"          # C, D — started first, as in every cut
IPS=$(grep -oE '/ip4/[0-9.]+' deploy/nodes.env | cut -d/ -f3 | sort -u)   # 17 droplets + obs1
NODE_A_HOME=${NODE_A_HOME:-$HOME/rand-node-a}

each() {  # run a remote script on every droplet in parallel, one line of output each
  local ip
  for ip in $IPS; do ( out=$(ssh $OPTS root@$ip "$1" 2>&1 | tail -1); echo "   $ip: $out" ) & done; wait
}

case "$PHASE" in
stage)
  : "${WANT_SHA:?}" "${WANT_SHA_WALLET:?}"
  WANT=$WANT_SHA; WANT_WALLET=$WANT_SHA_WALLET
  STAGE=$(mktemp -d "${TMPDIR:-/tmp}/c15-stage.XXXXXX"); trap 'rm -rf "$STAGE"' EXIT
  scp -q $OPTS "root@$BUILD_HOST:$BUILD_DIR/$BIN_NODE" "root@$BUILD_HOST:$BUILD_DIR/$BIN_WALLET" "$STAGE/"
  [ "$(shasum -a 256 "$STAGE/$BIN_NODE" | cut -d' ' -f1)" = "$WANT" ] || { echo "stage: $BIN_NODE from $BUILD_HOST is not $WANT" >&2; exit 1; }
  [ "$(shasum -a 256 "$STAGE/$BIN_WALLET" | cut -d' ' -f1)" = "$WANT_WALLET" ] || { echo "stage: $BIN_WALLET is not $WANT_WALLET" >&2; exit 1; }
  for ip in $IPS; do
    ( scp -q $OPTS "$STAGE/$BIN_NODE" "root@$ip:/root/rand-node.c15" && scp -q $OPTS "$STAGE/$BIN_WALLET" "root@$ip:/root/rand.c15" \
      && ssh $OPTS root@$ip "[ \"\$(sha256sum /root/rand-node.c15 | cut -d' ' -f1)\" = '$WANT' ] && [ \"\$(sha256sum /root/rand.c15 | cut -d' ' -f1)\" = '$WANT_WALLET' ] && chmod 755 /root/rand-node.c15 /root/rand.c15 && echo \"\$(hostname) staged, \$(df -h / | tail -1 | awk '{print \$4}') free\" || { rm -f /root/rand-node.c15 /root/rand.c15; echo 'SHA MISMATCH — removed'; }" \
      | sed "s/^/   $ip: /" ) &
  done; wait
  ;;
stop)
  echo "== stop all $(date -u +%T)"
  launchctl bootout "gui/$(id -u)/org.randprotocol.node-a" 2>/dev/null && echo "   A stopped" || echo "   A was not loaded"
  each 'systemctl stop rand-node; echo "$(hostname) $(systemctl is-active rand-node)"'
  ;;
switch)
  GENESIS=${2:?switch <genesis file>}
  NEW=$("$NODE_A_HOME/${NODE_A_BINDIR:?}/rand-node" init --datadir "$(mktemp -d)/p" --genesis "$GENESIS" | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2)
  P=${NEW:0:8}; echo "== switch to chain 15, genesis $NEW (datadir suffix -$P) $(date -u +%T)"
  for ip in $IPS; do ( scp -q $OPTS "$GENESIS" "root@$ip:/root/genesis-chain15.json" && echo "   $ip: genesis copied" ) & done; wait
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    [ -x /root/rand-node.c15 ] || { echo 'not staged'; exit 1; }
    H=\$(/root/rand-node.c15 init --datadir /root/probe-c15 --genesis /root/genesis-chain15.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-c15
    [ \"\$H\" = '$NEW' ] || { echo \"genesis hash \$H, expected $NEW\"; exit 1; }
    U=/etc/systemd/system/rand-node.service
    grep -q -- '-$OLD' \$U || { echo 'unit has no -$OLD datadir'; exit 1; }
    OLDDIR=\$(grep -o -- '--datadir [^ ]*' \$U | cut -d' ' -f2); NEWDIR=\${OLDDIR%-$OLD}-$P
    if [ -L \$OLDDIR ]; then T=\$(dirname \$(readlink \$OLDDIR))/\$(basename \$NEWDIR); mkdir -p \$T; ln -sfn \$T \$NEWDIR; fi
    cp -f /usr/local/bin/rand-node /root/rand-node.c14; cp -f /usr/local/bin/rand /root/rand.c14
    install -m 755 /root/rand-node.c15 /usr/local/bin/rand-node; install -m 755 /root/rand.c15 /usr/local/bin/rand
    [ -d \$NEWDIR/db ] || /usr/local/bin/rand-node init --datadir \$NEWDIR --genesis /root/genesis-chain15.json >/dev/null
    cp -a \$U /root/rand-node.service.$OLD.bak
    sed -i 's/-$OLD /-$P /' \$U
    systemctl daemon-reload
    echo \"\$(hostname) ready: \$(grep -o -- '--datadir [^ ]*' \$U)\""
  # node A: a fresh datadir keyed on the new prefix, the genesis beside it, the new binaries.
  cp "$GENESIS" "$NODE_A_HOME/genesis-chain15.json"
  "$NODE_A_HOME/$NODE_A_BINDIR/rand-node" init --datadir "$NODE_A_HOME/data-a-$P" --genesis "$NODE_A_HOME/genesis-chain15.json" >/dev/null
  echo "   A: $NODE_A_HOME/data-a-$P initialised — run-a.sh must name BINDIR=$NODE_A_BINDIR, DATA=data-a-$P, genesis-chain15.json"
  ;;
start)
  echo "== start bootstraps $(date -u +%T)"
  for ip in $BOOTS; do ssh $OPTS root@$ip 'systemctl start rand-node; sleep 2; echo "   $(hostname): $(systemctl is-active rand-node)"'; done
  echo "== start the rest $(date -u +%T)"
  for ip in $IPS; do case " $BOOTS " in *" $ip "*) continue;; esac
    ( ssh $OPTS root@$ip 'systemctl start rand-node; sleep 2; echo "   $(hostname): $(systemctl is-active rand-node)"' ) & done; wait
  launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/org.randprotocol.node-a.plist" && echo "   A started"
  echo "START-DONE $(date -u +%T) — nothing commits until 13 of 18 validators are up"
  ;;
*) echo "unknown phase $PHASE" >&2; exit 1 ;;
esac
