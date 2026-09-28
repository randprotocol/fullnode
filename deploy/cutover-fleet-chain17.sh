#!/usr/bin/env bash
# Cut the fleet over from chain 16 to chain 17 — all-stop, all-start, in phases, over all 26 hosts:
# the 20 hosts of deploy/nodes.env (A–F, the twelve regional validators, obs1, rand-archive-2) and
# the six guardian hosts (their own ssh key; their unit takes its ExecStart from a drop-in).
#
# Why all-stop/all-start: v0.6.3 (split authorisation — bundle guest v3, `hc_auth`, `rand-txid-3`)
# refuses chains 14/15/16 at startup, and a v0.6.1/v0.6.2 node cannot decode a chain-17 bundle.
# There is no mixed-version window to roll through; chain 17 is a new genesis, as chain 16 was.
#
# Chain 17 keeps every key chain 16 runs (so every peer id, every `--bootstrap` multiaddr and
# deploy/nodes.env stay as they are). Each nodes.env unit changes in exactly one place, its datadir
# suffix `-<chain-16 prefix>` → `-<chain-17 prefix>`; each guardian host gets a `chain17.conf`
# drop-in, chain 16's `chain16.conf` with `data-16` → `data-17`, and chain16.conf is moved aside.
#
#   deploy/cutover-fleet-chain17.sh stage              # chain 16 running: every host downloads the
#                                                      # v0.6.3 release binaries, sha-checked, aside
#   (bridge: deploy/chain17-bridge-steps.md "stop" — relayer + guardians down, BEFORE the snapshot)
#   deploy/cut-chain17-genesis.sh snapshot <dir>       # chain 16 still up
#   deploy/cut-chain17-genesis.sh balances <dir>       # chain 16 still up: the RAND carry list
#   ── the user's go, typed in the executing session, before anything below ──
#   deploy/cutover-fleet-chain17.sh stop               # stop every chain-16 node (26)
#   (cut: CHAIN16_SNAPSHOT=<dir> NODE=<v0.6.3 rand-node> WALLET=<v0.6.3 rand> EXPECT_HC_AUTH=<pin>
#         deploy/cut-chain17-genesis.sh)
#   LOCAL_NODE=<v0.6.3 rand-node> deploy/cutover-fleet-chain17.sh push <genesis>
#                                                      # the genesis to every host, sha-checked, and
#                                                      # its hash re-derived there by the staged binary
#   LOCAL_NODE=… deploy/cutover-fleet-chain17.sh switch <genesis>   # install, init, rewrite unit /
#                                                      # drop-in — no start; writes the start marker
#   deploy/cutover-fleet-chain17.sh start              # bootstraps C, D first, then the other 24
#   LOCAL_NODE=… deploy/cutover-fleet-chain17.sh wait <genesis>     # until all 26 serve chain 17
#   deploy/cutover-fleet-chain17.sh status             # read-only: version, genesis, height per host
#
# THE TRAP FROM CHAIN 16 (2026-09-28): `push … | tail && switch … | tail && start` ran `start` after
# `push` had FAILED (LOCAL_NODE unset) — a pipeline's exit status is its last command's, `tail`'s —
# and the fleet came back up on chain 16's build for a minute. So:
#   * run each phase ALONE, never piped, never chained; read `echo $?` before the next one;
#   * `push`, `switch` and `wait` refuse to run without LOCAL_NODE (an executable v0.6.3 rand-node:
#     it re-derives the genesis hash on the laptop);
#   * `start` refuses unless a successful `switch` left /tmp/chain17-switched-<genesis prefix>
#     (and exactly one such marker); `stop` and `push` delete any marker, so a stale switch never
#     licenses a start.
#
# Env: TAG (v0.6.3), WANT_SHA / WANT_SHA_WALLET (sha256 of the release's Linux rand-node / rand; both
# required for `stage` and re-checked by `push`/`switch`), RELEASE_URL (default the GitHub release of
# $TAG — each host downloads it itself: the laptop's upload is too slow to relay 47 MB × 26), OLD
# (chain-16 datadir suffix, 20925ae6), GUARDIAN_HOSTS (`<index> <ip>` per line; the bridge
# session's file), LOCAL_NODE (above).
#
# The laptop only relays the genesis (~150 KB). Nothing here touches keys (/root/keys,
# /var/lib/randnode/node.key.json) or the guardian daemons (the bridge steps own those; `switch`
# refuses a guardian host whose rand-guardian is still active).
#
# Rollback (chain 16 again, all-stop/all-start): on a nodes.env host restore
# /root/rand-node.service.$OLD.bak over the unit and /root/rand-node.pre-c17, /root/rand.pre-c17 over
# /usr/local/bin; on a guardian host move /root/chain16.conf.c16 back into
# /etc/systemd/system/rand-node.service.d/, delete chain17.conf, restore the same two binaries;
# daemon-reload; start. The chain-16 data dirs are never touched here — retire them with
# deploy/retire-chain-dirs.sh once chain 17 has run a day.
set -euo pipefail
cd "$(dirname "$0")/.."

PHASE=${1:?stage|stop|push|switch|start|wait|status}
TAG=${TAG:-v0.6.3}
RELEASE_URL=${RELEASE_URL:-https://github.com/randprotocol/fullnode/releases/download/$TAG}
OLD=${OLD:-20925ae6}
GUARDIAN_HOSTS=${GUARDIAN_HOSTS:-$HOME/.rand-bridge/mainnet-set1/hosts.txt}
MARKER_GLOB=/tmp/chain17-switched-
OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -o BatchMode=yes"
GOPTS="-i $HOME/.ssh/rand_guardian_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=$HOME/.ssh/rand_guardian_known_hosts -o StrictHostKeyChecking=yes -o ConnectTimeout=20 -o BatchMode=yes"
BOOTS="164.90.239.200 165.245.173.74"          # C, D — started first, as in every cut
IPS=$(echo $(grep -oE '/ip4/[0-9.]+' deploy/nodes.env | cut -d/ -f3 | sort -u))   # 20: A–F, 12 regional, obs1, archive-2
[ "$(echo $IPS | wc -w)" -eq 20 ] || { echo "deploy/nodes.env names $(echo $IPS | wc -w) hosts, expected 20" >&2; exit 1; }
[ -f "$GUARDIAN_HOSTS" ] || { echo "missing $GUARDIAN_HOSTS" >&2; exit 1; }
GUARDS=$(echo $(awk '$1 ~ /^[1-6]$/ {print $2}' "$GUARDIAN_HOSTS"))
[ "$(echo $GUARDS | wc -w)" -eq 6 ] || { echo "$GUARDIAN_HOSTS names $(echo $GUARDS | wc -w) guardian hosts, expected 6" >&2; exit 1; }
ALL="$IPS $GUARDS"

is_guard() { case " $GUARDS " in *" $1 "*) return 0;; esac; return 1; }
on() { local ip=$1; shift; if is_guard "$ip"; then ssh -n $GOPTS root@$ip "$@"; else ssh -n $OPTS root@$ip "$@"; fi; }
cp_to() { local ip=$1 src=$2 dst=$3; if is_guard "$ip"; then scp -q $GOPTS "$src" "root@$ip:$dst"; else scp -q $OPTS "$src" "root@$ip:$dst"; fi; }
each() {  # run a remote script on every host in parallel, the last line of output each; fail if any failed
  local ip dir; dir=$(mktemp -d)
  for ip in $ALL; do ( on "$ip" "$1" > "$dir/$ip" 2>&1 && echo ok >> "$dir/$ip.rc" || echo FAIL >> "$dir/$ip.rc" ) & done; wait
  local bad=0
  for ip in $ALL; do printf '   %-16s %s %s\n' "$ip" "$(cat "$dir/$ip.rc")" "$(tail -1 "$dir/$ip")"; [ "$(cat "$dir/$ip.rc")" = ok ] || bad=1; done
  rm -rf "$dir"; return $bad
}
rpc() { on "$1" "curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}'" 2>/dev/null || true; }
need_local_node() {
  [ -n "${LOCAL_NODE:-}" ] || { echo "$PHASE: LOCAL_NODE is unset — point it at a v0.6.3 rand-node on this machine; nothing done (the chain-16 trap)" >&2; exit 1; }
  [ -x "$LOCAL_NODE" ] || { echo "$PHASE: LOCAL_NODE=$LOCAL_NODE is not executable — nothing done" >&2; exit 1; }
  "$LOCAL_NODE" genesis --help | grep -q -- --auth-guest || { echo "$PHASE: $LOCAL_NODE is not v0.6.3 (no --auth-guest) — nothing done" >&2; exit 1; }
}
genesis_hash() { local d h; d=$(mktemp -d); h=$("$LOCAL_NODE" init --datadir "$d/p" --genesis "$1" | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2 || true); rm -rf "$d"; echo "$h"; }
clear_markers() { rm -f "$MARKER_GLOB"*; }

case "$PHASE" in
stage)
  : "${WANT_SHA:?the release rand-node sha256}" "${WANT_SHA_WALLET:?the release rand sha256}"
  echo "== stage $TAG on $(echo $ALL | wc -w) hosts from $RELEASE_URL $(date -u +%T)"
  # Each host fetches the release itself and checks both pins; a mismatch deletes what it fetched.
  each "set -e; cd /root
    curl -fsSL --retry 3 -o rand-node.c17 '$RELEASE_URL/rand-node'
    curl -fsSL --retry 3 -o rand.c17 '$RELEASE_URL/rand'
    if ! echo '$WANT_SHA  rand-node.c17' | sha256sum -c --quiet || ! echo '$WANT_SHA_WALLET  rand.c17' | sha256sum -c --quiet; then
      rm -f rand-node.c17 rand.c17; echo 'SHA MISMATCH — removed'; exit 1; fi
    chmod 755 rand-node.c17 rand.c17
    ./rand-node.c17 genesis --help | grep -q -- --auth-guest
    echo \"\$(hostname) staged \$(./rand-node.c17 --version), \$(df -h / | tail -1 | awk '{print \$4}') free\"" \
    || { echo "stage: not every host staged — fix those before stopping anything" >&2; exit 1; }
  ;;
stop)
  clear_markers
  echo "== stop all 26 $(date -u +%T)"
  H0=$(rpc 164.90.239.200 rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
  echo "   chain 16 head at C: ${H0:-?}"
  each 'systemctl stop rand-node; echo "$(hostname) $(systemctl is-active rand-node || true)"' || true
  echo "STOPPED $(date -u +%T) — cut the genesis now (deploy/cut-chain17-genesis.sh), then push (run it alone, check \$?)"
  ;;
push)
  GENESIS=${2:?push <genesis file>}
  clear_markers
  need_local_node
  : "${WANT_SHA:?}"
  SHA=$(shasum -a 256 "$GENESIS" | cut -d' ' -f1)
  NEW=$(genesis_hash "$GENESIS"); [ -n "$NEW" ] || { echo "push: $LOCAL_NODE derived no genesis hash from $GENESIS — nothing pushed" >&2; exit 1; }
  echo "== push $GENESIS (sha256 $SHA, genesis $NEW) $(date -u +%T)"
  for ip in $ALL; do ( cp_to "$ip" "$GENESIS" /root/genesis-chain17.json ) & done; wait
  each "set -e
    [ \"\$(sha256sum /root/genesis-chain17.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis sha mismatch'; exit 1; }
    [ \"\$(sha256sum /root/rand-node.c17 | cut -d' ' -f1)\" = '$WANT_SHA' ] || { echo 'not staged'; exit 1; }
    H=\$(/root/rand-node.c17 init --datadir /root/probe-c17 --genesis /root/genesis-chain17.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-c17
    [ \"\$H\" = '$NEW' ] || { echo \"genesis hash \$H, expected $NEW\"; exit 1; }
    echo \"\$(hostname) genesis $NEW verified\"" \
    || { echo "push: not every host holds the genesis — do NOT switch or start" >&2; exit 1; }
  echo "PUSHED — next: switch (alone; check \$?)"
  ;;
switch)
  GENESIS=${2:?switch <genesis file>}
  clear_markers
  need_local_node
  : "${WANT_SHA:?}" "${WANT_SHA_WALLET:?}"
  SHA=$(shasum -a 256 "$GENESIS" | cut -d' ' -f1)
  NEW=$(genesis_hash "$GENESIS"); [ ${#NEW} -eq 64 ] || { echo "switch: could not derive the genesis hash — nothing switched" >&2; exit 1; }
  P=${NEW:0:8}
  echo "== switch to chain 17, genesis $NEW (datadir suffix -$P) $(date -u +%T)"
  # One script for both kinds of host; the guardian branch is chosen by the drop-in's presence.
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    [ \"\$(sha256sum /root/genesis-chain17.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis not pushed'; exit 1; }
    [ \"\$(sha256sum /root/rand-node.c17 | cut -d' ' -f1)\" = '$WANT_SHA' ] && [ \"\$(sha256sum /root/rand.c17 | cut -d' ' -f1)\" = '$WANT_SHA_WALLET' ] || { echo 'not staged'; exit 1; }
    [ -e /root/rand-node.pre-c17 ] || cp -a /usr/local/bin/rand-node /root/rand-node.pre-c17
    [ -e /root/rand.pre-c17 ] || cp -a /usr/local/bin/rand /root/rand.pre-c17
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain16.conf ] || [ -f \$D/chain17.conf ]; then
      # A guardian host: the node runs as randnode from /var/lib/randnode, ExecStart in a drop-in.
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it first'; exit 1; }
      install -m 755 /root/rand-node.c17 /usr/local/bin/rand-node; install -m 755 /root/rand.c17 /usr/local/bin/rand
      install -d -o randnode -g randnode /var/lib/randnode/data-17
      install -m 644 -o randnode -g randnode /root/genesis-chain17.json /var/lib/randnode/genesis-chain17.json
      [ -d /var/lib/randnode/data-17/db ] || runuser -u randnode -- /usr/local/bin/rand-node init --datadir /var/lib/randnode/data-17 --genesis /var/lib/randnode/genesis-chain17.json >/dev/null
      if [ -f \$D/chain16.conf ]; then
        grep -q -- '--datadir /var/lib/randnode/data-16 ' \$D/chain16.conf || { echo 'chain16.conf has no data-16 datadir'; exit 1; }
        sed 's#--datadir /var/lib/randnode/data-16 #--datadir /var/lib/randnode/data-17 #' \$D/chain16.conf > \$D/chain17.conf
        mv \$D/chain16.conf /root/chain16.conf.c16
      fi
      grep -q -- '--datadir /var/lib/randnode/data-17 ' \$D/chain17.conf
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"
    else
      U=/etc/systemd/system/rand-node.service
      if grep -q -- '-$P ' \$U; then echo \"\$(hostname) already switched\"; exit 0; fi
      grep -q -- '-$OLD ' \$U || { echo 'unit has no -$OLD datadir'; exit 1; }
      OLDDIR=\$(grep -o -- '--datadir [^ ]*' \$U | cut -d' ' -f2); NEWDIR=\${OLDDIR%-$OLD}-$P
      # obs1 and rand-archive-2 keep their data on a volume behind a symlink: so does chain 17.
      if [ -L \$OLDDIR ]; then T=\$(dirname \$(readlink \$OLDDIR))/\$(basename \$NEWDIR); mkdir -p \$T; ln -sfn \$T \$NEWDIR; fi
      install -m 755 /root/rand-node.c17 /usr/local/bin/rand-node; install -m 755 /root/rand.c17 /usr/local/bin/rand
      [ -d \$NEWDIR/db ] || /usr/local/bin/rand-node init --datadir \$NEWDIR --genesis /root/genesis-chain17.json >/dev/null
      [ -e /root/rand-node.service.$OLD.bak ] || cp -a \$U /root/rand-node.service.$OLD.bak
      sed -i 's/-$OLD /-$P /' \$U
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(grep -o -- '--datadir [^ ]*' \$U)\"
    fi" || { echo "switch: some hosts are not ready — fix them and re-run switch; do NOT start" >&2; exit 1; }
  # Only a switch that reached every host licenses `start`.
  echo "$NEW $(date -u +%FT%TZ)" > "$MARKER_GLOB$P"
  echo "SWITCHED — marker $MARKER_GLOB$P written; next: start (alone; check \$?)"
  ;;
start)
  set -- "$MARKER_GLOB"*
  [ -e "$1" ] || { echo "start: no $MARKER_GLOB<prefix> marker — a successful switch writes it; refusing (a failed push/switch never starts the fleet)" >&2; exit 1; }
  [ $# -eq 1 ] || { echo "start: $# markers ($*) — ambiguous; remove the stale ones by hand after checking which genesis was switched" >&2; exit 1; }
  echo "== start on the switch recorded in $1: $(cat "$1")"
  echo "== start bootstraps $(date -u +%T)"
  for ip in $BOOTS; do on "$ip" 'systemctl start rand-node; sleep 2; echo "   $(hostname): $(systemctl is-active rand-node)"'; done
  echo "== start the other 24 $(date -u +%T)"
  for ip in $ALL; do case " $BOOTS " in *" $ip "*) continue;; esac
    ( on "$ip" 'systemctl start rand-node; sleep 2; echo "   $(hostname): $(systemctl is-active rand-node)"' ) & done; wait
  # A start that ran is a start that happened; keep the marker from licensing a second one later.
  rm -f "$1"
  echo "START-DONE $(date -u +%T) — nothing commits until 18 of the 26 validators are up"
  ;;
wait)
  GENESIS=${2:?wait <genesis file>}
  need_local_node
  NEW=$(genesis_hash "$GENESIS"); [ ${#NEW} -eq 64 ] || { echo "wait: could not derive the genesis hash" >&2; exit 1; }
  for i in $(seq 1 90); do
    sleep 20; ok=0
    for ip in $ALL; do
      g=$(rpc "$ip" rand_getGenesisHash | grep -oE '"result":"[0-9a-f]+"' | cut -d'"' -f4)
      s=$(rpc "$ip" rand_getHealth | grep -oE '"status":"[a-z_]+"' | cut -d'"' -f4)
      [ "$g" = "$NEW" ] && [ "$s" = ok ] && ok=$((ok+1))
    done
    H=$(rpc 164.90.239.200 rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)
    echo "  $(date -u +%T) $ok/26 on chain 17 and healthy; C height ${H:-?}"
    if [ "$ok" = 26 ] && [ -n "$H" ] && [ "$H" -gt 2 ]; then echo "=== $(date -u +%T) CUTOVER DONE: all 26 on $NEW, committing at $H"; exit 0; fi
  done
  echo "=== not all 26 healthy after 30 min — check the laggards"; exit 1
  ;;
status)
  for ip in $ALL; do (
    v=$(rpc "$ip" rand_getVersion | grep -oE '"git_sha":"[a-z0-9]+"|"chain_id":[0-9]+' | tr '\n' ' ')
    h=$(rpc "$ip" rand_status | grep -oE '"height":[0-9]+' | head -1)
    printf '   %-16s %s %s\n' "$ip" "$v" "$h" ) & done; wait
  ;;
*) echo "unknown phase $PHASE" >&2; exit 1 ;;
esac
