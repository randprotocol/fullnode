#!/usr/bin/env bash
# Cut the fleet over from chain 18 to chain 19 — all-stop, all-start, in phases, over all 26 hosts:
# the 20 hosts of deploy/nodes.env (A–F, the twelve regional validators, obs1, rand-archive-2) and
# the six guardian hosts (their own ssh key; their unit takes its ExecStart from a drop-in).
#
# DERIVED from deploy/cutover-fleet-chain18.sh (chain 18 = v0.6.7, the gas model, is chain 19's
# predecessor): the same phases, markers and traps with the chain ids moved up one — MINUS
# everything that assumed a new build. Chain 19 is a pure re-genesis of chain 18 (only the bridge
# section's emitter table, floors and burn sequence differ; deploy/cut-chain19-genesis.sh), and the
# fleet already runs the build that runs it: v0.6.7 (`86941a1`). So, against chain 18's script:
#
#   * NO `stage`, NO binary install, NO `*.pre-c19` copies. Nothing is downloaded and nothing under
#     /usr/local/bin is written by any phase. `preflight` (read-only) replaces `stage`: it proves
#     every host's INSTALLED rand-node and rand are the v0.6.7 release binaries (sha256 = WANT_SHA /
#     WANT_SHA_WALLET, defaults below from the GitHub release's SHA256SUMS), that the host is on
#     chain 18 (its unit / drop-in names the chain-18 datadir) and healthy, and that no chain-19
#     datadir is lying around from an earlier attempt. `push` and `switch` re-check the same
#     sha256s and use the installed binary to re-derive the genesis hash and to `init`.
#     A host still on v0.6.7-rc1 (or anything else) fails `preflight`: roll it to v0.6.7 on chain 18
#     first (deploy/update-droplet.sh), or pass that build's sha256s knowingly — every host must
#     then hold that same build.
#   * No build refuses the other chain here: a v0.6.7 node runs chain 18 AND chain 19 (its refuse
#     list, `node::CHAINS_THIS_BUILD_CANNOT_RUN`, names 14–17). What keeps the two apart is the
#     datadir alone — each is initialised from its own genesis — so `switch` is the whole cut, and
#     `wait` checks the genesis HASH each node serves, not its version.
#   * OLD has a default now: chain 18's datadir suffix on the nodes.env hosts is its genesis hash
#     prefix, `a7cb020c` (chain 18 is live and its genesis committed).
#   * A guardian host's datadir carries no genesis prefix (`data-19`), so a RE-CUT after a failed
#     first attempt would find `data-19/db` initialised from the first genesis and keep it. `switch`
#     therefore stamps the genesis hash beside it (`/var/lib/randnode/data-19.genesis`), and a
#     `data-19` that holds a db but not this genesis's stamp is moved aside (never deleted) to
#     `data-19.stale-<its prefix>` before the fresh init. A RE-CUT after a `switch` goes through
#     `rollback` first: the nodes.env units must name chain 18's datadir again before `switch`
#     rewrites them.
#   * A `rollback` phase (chain 18's script left it to hand edits): restore every host's unit /
#     drop-in to chain 18. No binaries to restore. It starts nothing; it leaves a marker that
#     licenses one `start`.
#
# Why still all-stop/all-start: chain 19 is a new genesis on the same 26 keys. There is no block
# both chains share, so nothing rolls node by node; chain 18 stops committing the moment a third of
# the stake is down, and chain 19 commits once 18 of the 26 are up.
#
# Chain 19 keeps every key chain 18 runs (so every peer id, every `--bootstrap` multiaddr and
# deploy/nodes.env stay as they are). Each nodes.env unit changes in exactly one place, its datadir
# suffix `-<chain-18 prefix>` → `-<chain-19 prefix>`; each guardian host gets a `chain19.conf`
# drop-in, chain 18's `chain18.conf` with `data-18` → `data-19`, and chain18.conf is moved aside.
#
#   deploy/cutover-fleet-chain19.sh preflight          # chain 18 running, READ-ONLY: every host on the
#                                                      # v0.6.7 binaries, on chain 18, healthy, disk free
#   (bridge: deploy/chain19-bridge-steps.md "stop" — relayer + guardians down, BEFORE the snapshot)
#   deploy/cut-chain19-genesis.sh snapshot <dir>       # chain 18 still up
#   deploy/cut-chain19-genesis.sh balances <dir>       # chain 18 still up: the RAND carry list
#   ── the user's go, typed in the executing session, before anything below ──
#   deploy/cutover-fleet-chain19.sh stop               # stop every chain-18 node (26)
#   (cut: CHAIN18_SNAPSHOT=<dir> NODE=<v0.6.7 rand-node> WALLET=<v0.6.7 rand>
#         MIN_INBOUND_2=1 MIN_INBOUND_3=1 MIN_INBOUND_4=1 deploy/cut-chain19-genesis.sh)
#   LOCAL_NODE=<v0.6.7 rand-node> deploy/cutover-fleet-chain19.sh push <genesis>
#                                                      # the genesis to every host, sha-checked, and
#                                                      # its hash re-derived there by the installed binary
#   LOCAL_NODE=… deploy/cutover-fleet-chain19.sh switch <genesis>   # init the chain-19 datadir, rewrite
#                                                      # unit / drop-in — no start; writes the start marker
#   deploy/cutover-fleet-chain19.sh start              # bootstraps C, D first, then the other 24
#   LOCAL_NODE=… deploy/cutover-fleet-chain19.sh wait <genesis>     # until all 26 serve chain 19
#   deploy/cutover-fleet-chain19.sh status             # read-only: version, chain id, height per host
#   deploy/cutover-fleet-chain19.sh rollback           # ONLY after `stop`: every host back on its
#                                                      # chain-18 unit / drop-in; then `start`
#
# THE TRAP FROM CHAIN 16 (2026-09-28, kept by every script since): `push … | tail && switch … | tail
# && start` ran `start` after `push` had FAILED (LOCAL_NODE unset) — a pipeline's exit status is its
# last command's, `tail`'s — and the fleet came back up on the old chain for a minute. So:
#   * run each phase ALONE, never piped, never chained; read `echo $?` before the next one;
#   * `push`, `switch` and `wait` refuse to run without LOCAL_NODE (an executable v0.6.7 rand-node —
#     the macOS build of the same line, e.g. ~/rand-node-a/bin-v067rc1/rand-node: it re-derives the
#     genesis hash on the laptop, which every host must then re-derive identically);
#   * `start` refuses unless a successful `switch` (or `rollback`) left /tmp/chain19-switched-<tag>
#     (and exactly one such marker); `stop` and `push` delete any marker, so a stale switch never
#     licenses a start.
#
# Env: WANT_SHA / WANT_SHA_WALLET (sha256 of the Linux rand-node / rand every host must already
# have installed; default: the v0.6.7 GitHub release), OLD (chain-18 datadir suffix, default
# a7cb020c), GUARDIAN_HOSTS (`<index> <ip>` per line; the bridge session's file), LOCAL_NODE (above).
#
# The laptop only relays the genesis (~150 KB). Nothing here touches keys (/root/keys,
# /var/lib/randnode/node.key.json), binaries, or the guardian daemons (the bridge steps own those;
# `switch` and `rollback` refuse a guardian host whose rand-guardian is still active).
#
# Rollback (chain 18 again, all-stop/all-start) — `rollback`, or by hand: on a nodes.env host
# restore /root/rand-node.service.$OLD.bak over the unit; on a guardian host move
# /root/chain18.conf.c18 back into /etc/systemd/system/rand-node.service.d/ and delete chain19.conf;
# daemon-reload; start. Chain 18 resumes from the height it stopped at: its data dirs are never
# touched here — retire them with deploy/retire-chain-dirs.sh once chain 19 has run a day. A chain
# 18 that comes back does NOT trust the redeployed bridge endpoints (deploy/chain19-bridge-steps.md
# "Rollback").
set -euo pipefail
cd "$(dirname "$0")/.."

PHASE=${1:?preflight|stop|push|switch|start|wait|status|rollback}
# The v0.6.7 GitHub release's Linux binaries (tag v0.6.7 = 86941a1; its SHA256SUMS).
WANT_SHA=${WANT_SHA:-f365317eb2ae3340e50a9dcdbfc2d3d2f3beba819ccf5f5ef21b61a5efbe08f9}
WANT_SHA_WALLET=${WANT_SHA_WALLET:-480bd838bf64b151c1406da3a44f4b440b4b2b1c31f88e11139448f276720fc4}
# Chain 18's datadir suffix on the nodes.env hosts: its genesis hash prefix (a7cb020c…4da76).
OLD=${OLD:-a7cb020c}
GUARDIAN_HOSTS=${GUARDIAN_HOSTS:-$HOME/.rand-bridge/mainnet-set1/hosts.txt}
MARKER_GLOB=${MARKER_GLOB:-/tmp/chain19-switched-}
OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -o BatchMode=yes"
GOPTS="-i $HOME/.ssh/rand_guardian_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=$HOME/.ssh/rand_guardian_known_hosts -o StrictHostKeyChecking=yes -o ConnectTimeout=20 -o BatchMode=yes"
BOOTS=${BOOTS:-164.90.239.200 165.245.173.74}   # C, D — started first, as in every cut
IPS=$(echo $(grep -oE '/ip4/[0-9.]+' deploy/nodes.env | cut -d/ -f3 | sort -u))   # 20: A–F, 12 regional, obs1, archive-2
[ "$(echo $IPS | wc -w)" -eq 20 ] || { echo "deploy/nodes.env names $(echo $IPS | wc -w) hosts, expected 20" >&2; exit 1; }
[ -f "$GUARDIAN_HOSTS" ] || { echo "missing $GUARDIAN_HOSTS" >&2; exit 1; }
GUARDS=$(echo $(awk '$1 ~ /^[1-6]$/ {print $2}' "$GUARDIAN_HOSTS"))
[ "$(echo $GUARDS | wc -w)" -eq 6 ] || { echo "$GUARDIAN_HOSTS names $(echo $GUARDS | wc -w) guardian hosts, expected 6" >&2; exit 1; }
ALL="$IPS $GUARDS"
for ip in $BOOTS; do case " $IPS " in *" $ip "*) ;; *) echo "bootstrap $ip is not in deploy/nodes.env" >&2; exit 1;; esac; done
BOOT1=${BOOTS%% *}
[[ "$WANT_SHA" =~ ^[0-9a-f]{64}$ && "$WANT_SHA_WALLET" =~ ^[0-9a-f]{64}$ ]] || { echo "WANT_SHA / WANT_SHA_WALLET are not sha256 hex" >&2; exit 1; }
[[ "$OLD" =~ ^[0-9a-f]{8}$ ]] || { echo "OLD=$OLD is not an 8-hex genesis prefix" >&2; exit 1; }

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
  [ -n "${LOCAL_NODE:-}" ] || { echo "$PHASE: LOCAL_NODE is unset — point it at a v0.6.7 rand-node on this machine; nothing done (the chain-16 trap)" >&2; exit 1; }
  [ -x "$LOCAL_NODE" ] || { echo "$PHASE: LOCAL_NODE=$LOCAL_NODE is not executable — nothing done" >&2; exit 1; }
  "$LOCAL_NODE" genesis --help | grep -q -- --auth-guest || { echo "$PHASE: $LOCAL_NODE has no --auth-guest (not v0.6.3+) — nothing done" >&2; exit 1; }
  "$LOCAL_NODE" genesis --help | grep -q -- --gas-dynamic || { echo "$PHASE: $LOCAL_NODE has no --gas-dynamic (not the v0.6.7 cs8/gas line) — nothing done" >&2; exit 1; }
  case "$("$LOCAL_NODE" --version)" in "rand-node 0.6.7"*) ;; *) echo "$PHASE: $LOCAL_NODE is $("$LOCAL_NODE" --version), not rand-node 0.6.7 — nothing done" >&2; exit 1;; esac
}
genesis_hash() { local d h; d=$(mktemp -d); h=$("$LOCAL_NODE" init --datadir "$d/p" --genesis "$1" | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2 || true); rm -rf "$d"; echo "$h"; }
# The file must BE a chain-19 genesis: a chain-18 (or any other) file pushed by mistake would
# "switch" the fleet onto a fresh copy of the wrong chain.
need_chain19_genesis() {
  [ -f "$1" ] || { echo "$PHASE: $1 is not a file — nothing done" >&2; exit 1; }
  local id; id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("chain_id"))' "$1" 2>/dev/null || true)
  [ "$id" = 19 ] || { echo "$PHASE: $1 has chain_id ${id:-?}, not 19 — nothing done" >&2; exit 1; }
}
clear_markers() { rm -f "$MARKER_GLOB"*; }
# The remote checks `preflight`, `push` and `switch` share: the INSTALLED binaries are the pinned ones.
INSTALLED_OK="[ \"\$(sha256sum /usr/local/bin/rand-node | cut -d' ' -f1)\" = '$WANT_SHA' ] || { echo \"installed rand-node is \$(/usr/local/bin/rand-node --version 2>&1 | head -1) sha256 \$(sha256sum /usr/local/bin/rand-node | cut -c1-12)…, not the pinned $(echo "$WANT_SHA" | cut -c1-12)…\"; exit 1; }
    [ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$WANT_SHA_WALLET' ] || { echo \"installed rand is sha256 \$(sha256sum /usr/local/bin/rand | cut -c1-12)…, not the pinned $(echo "$WANT_SHA_WALLET" | cut -c1-12)…\"; exit 1; }"

case "$PHASE" in
preflight)
  echo "== preflight (read-only) on $(echo $ALL | wc -w) hosts: installed rand-node $WANT_SHA, rand $WANT_SHA_WALLET, chain-18 datadir -$OLD / data-18 $(date -u +%T)"
  each "set -e
    $INSTALLED_OK
    /usr/local/bin/rand-node genesis --help | grep -q -- --gas-dynamic
    /usr/local/bin/rand-node genesis --help | grep -q -- --envelope-bytes
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain18.conf ] || [ -f \$D/chain19.conf ]; then
      [ -f \$D/chain18.conf ] && [ ! -f \$D/chain19.conf ] || { echo 'a chain19.conf drop-in is already present'; exit 1; }
      grep -q -- '--datadir /var/lib/randnode/data-18 ' \$D/chain18.conf || { echo 'chain18.conf has no data-18 datadir'; exit 1; }
      [ ! -e /var/lib/randnode/data-19 ] || { echo '/var/lib/randnode/data-19 already exists — move it aside'; exit 1; }
      [ ! -e /root/chain18.conf.c18 ] || { echo '/root/chain18.conf.c18 already exists (an earlier switch?)'; exit 1; }
      KIND=guardian-host
    else
      grep -q -- '-$OLD ' /etc/systemd/system/rand-node.service || { echo 'unit has no -$OLD datadir'; exit 1; }
      KIND=node
    fi
    G=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getGenesisHash\",\"params\":[]}' | grep -oE '\"result\":\"[0-9a-f]+\"' | cut -d'\"' -f4)
    case \"\$G\" in $OLD*) ;; *) echo \"serves genesis \${G:-nothing}, not chain 18 ($OLD…)\"; exit 1;; esac
    curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}' | grep -q '\"status\":\"ok\"' || { echo 'rand_getHealth is not ok'; exit 1; }
    echo \"\$(hostname) \$KIND ready: \$(/usr/local/bin/rand-node --version), on chain 18, healthy, \$(df -h / | tail -1 | awk '{print \$4}') free\"" \
    || { echo "preflight: not every host is ready — fix those before stopping anything" >&2; exit 1; }
  echo "PREFLIGHT OK — nothing was changed"
  ;;
stop)
  clear_markers
  echo "== stop all 26 $(date -u +%T)"
  H0=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
  echo "   chain 18 head at C: ${H0:-?}"
  each 'systemctl stop rand-node; echo "$(hostname) $(systemctl is-active rand-node || true)"' || true
  echo "STOPPED $(date -u +%T) — cut the genesis now (deploy/cut-chain19-genesis.sh), then push (run it alone, check \$?)"
  ;;
push)
  GENESIS=${2:?push <genesis file>}
  clear_markers
  need_local_node
  need_chain19_genesis "$GENESIS"
  SHA=$(shasum -a 256 "$GENESIS" | cut -d' ' -f1)
  NEW=$(genesis_hash "$GENESIS"); [ ${#NEW} -eq 64 ] || { echo "push: $LOCAL_NODE derived no genesis hash from $GENESIS — nothing pushed" >&2; exit 1; }
  [ "${NEW:0:8}" != "$OLD" ] || { echo "push: $GENESIS is chain 18's genesis ($NEW) — nothing pushed" >&2; exit 1; }
  echo "== push $GENESIS (sha256 $SHA, genesis $NEW) $(date -u +%T)"
  for ip in $ALL; do ( cp_to "$ip" "$GENESIS" /root/genesis-chain19.json ) & done; wait
  each "set -e
    [ \"\$(sha256sum /root/genesis-chain19.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis sha mismatch'; exit 1; }
    $INSTALLED_OK
    rm -rf /root/probe-c19
    H=\$(/usr/local/bin/rand-node init --datadir /root/probe-c19 --genesis /root/genesis-chain19.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-c19
    [ \"\$H\" = '$NEW' ] || { echo \"genesis hash \$H, expected $NEW\"; exit 1; }
    echo \"\$(hostname) genesis $NEW verified\"" \
    || { echo "push: not every host holds the genesis — do NOT switch or start" >&2; exit 1; }
  echo "PUSHED — next: switch (alone; check \$?)"
  ;;
switch)
  GENESIS=${2:?switch <genesis file>}
  clear_markers
  need_local_node
  need_chain19_genesis "$GENESIS"
  SHA=$(shasum -a 256 "$GENESIS" | cut -d' ' -f1)
  NEW=$(genesis_hash "$GENESIS"); [ ${#NEW} -eq 64 ] || { echo "switch: could not derive the genesis hash — nothing switched" >&2; exit 1; }
  P=${NEW:0:8}
  [ "$P" != "$OLD" ] || { echo "switch: $GENESIS is chain 18's genesis — nothing switched" >&2; exit 1; }
  echo "== switch to chain 19, genesis $NEW (datadir suffix -$P) $(date -u +%T)"
  # One script for both kinds of host; the guardian branch is chosen by the drop-in's presence.
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    [ \"\$(sha256sum /root/genesis-chain19.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis not pushed'; exit 1; }
    $INSTALLED_OK
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain18.conf ] || [ -f \$D/chain19.conf ]; then
      # A guardian host: the node runs as randnode from /var/lib/randnode, ExecStart in a drop-in.
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it first'; exit 1; }
      V=/var/lib/randnode
      # data-19 carries no genesis prefix: a db there must be THIS genesis's. A re-cut leaves a stale
      # one — moved aside, never deleted, and never reused.
      if [ -d \$V/data-19/db ] && [ \"\$(cat \$V/data-19.genesis 2>/dev/null)\" != '$NEW' ]; then
        STALE=\$V/data-19.stale-\$(cut -c1-8 \$V/data-19.genesis 2>/dev/null || echo unknown)
        [ ! -e \$STALE ] || { echo \"\$V/data-19 is stale and \$STALE already exists — sort them out by hand\"; exit 1; }
        mv \$V/data-19 \$STALE; rm -f \$V/data-19.genesis
      fi
      install -d -o randnode -g randnode \$V/data-19
      install -m 644 -o randnode -g randnode /root/genesis-chain19.json \$V/genesis-chain19.json
      [ -d \$V/data-19/db ] || runuser -u randnode -- /usr/local/bin/rand-node init --datadir \$V/data-19 --genesis \$V/genesis-chain19.json >/dev/null
      echo '$NEW' > \$V/data-19.genesis
      if [ -f \$D/chain18.conf ]; then
        grep -q -- '--datadir /var/lib/randnode/data-18 ' \$D/chain18.conf || { echo 'chain18.conf has no data-18 datadir'; exit 1; }
        sed 's#--datadir /var/lib/randnode/data-18 #--datadir /var/lib/randnode/data-19 #' \$D/chain18.conf > \$D/chain19.conf
        mv \$D/chain18.conf /root/chain18.conf.c18
      fi
      grep -q -- '--datadir /var/lib/randnode/data-19 ' \$D/chain19.conf
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"
    else
      U=/etc/systemd/system/rand-node.service
      if grep -q -- '-$P ' \$U; then echo \"\$(hostname) already switched\"; exit 0; fi
      grep -q -- '-$OLD ' \$U || { echo 'unit has no -$OLD datadir'; exit 1; }
      OLDDIR=\$(grep -o -- '--datadir [^ ]*' \$U | cut -d' ' -f2); NEWDIR=\${OLDDIR%-$OLD}-$P
      # obs1 and rand-archive-2 keep their data on a volume behind a symlink: so does chain 19.
      if [ -L \$OLDDIR ]; then T=\$(dirname \$(readlink \$OLDDIR))/\$(basename \$NEWDIR); mkdir -p \$T; ln -sfn \$T \$NEWDIR; fi
      [ -d \$NEWDIR/db ] || /usr/local/bin/rand-node init --datadir \$NEWDIR --genesis /root/genesis-chain19.json >/dev/null
      [ -e /root/rand-node.service.$OLD.bak ] || cp -a \$U /root/rand-node.service.$OLD.bak
      sed -i 's/-$OLD /-$P /' \$U
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(grep -o -- '--datadir [^ ]*' \$U)\"
    fi" || { echo "switch: some hosts are not ready — fix them and re-run switch; do NOT start" >&2; exit 1; }
  # Only a switch that reached every host licenses `start`.
  echo "$NEW $(date -u +%FT%TZ)" > "$MARKER_GLOB$P"
  echo "SWITCHED — marker $MARKER_GLOB$P written; next: start (alone; check \$?)"
  ;;
rollback)
  # Back to chain 18's unit / drop-in on every host. Only after `stop`: a running node is refused.
  # Idempotent per host (a host never switched, or already rolled back, answers "on chain 18").
  clear_markers
  echo "== rollback to chain 18 (datadir suffix -$OLD / data-18) $(date -u +%T)"
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain18.conf ] || [ -f \$D/chain19.conf ]; then
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it first'; exit 1; }
      if [ -f \$D/chain19.conf ]; then
        [ -f /root/chain18.conf.c18 ] || { echo 'no /root/chain18.conf.c18 to restore'; exit 1; }
        mv /root/chain18.conf.c18 \$D/chain18.conf
        rm -f \$D/chain19.conf
      fi
      grep -q -- '--datadir /var/lib/randnode/data-18 ' \$D/chain18.conf
      [ -d /var/lib/randnode/data-18/db ] || { echo 'data-18 has no db'; exit 1; }
      systemctl daemon-reload
      echo \"\$(hostname) on chain 18: \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"
    else
      U=/etc/systemd/system/rand-node.service
      if ! grep -q -- '-$OLD ' \$U; then
        [ -f /root/rand-node.service.$OLD.bak ] || { echo 'no /root/rand-node.service.$OLD.bak to restore'; exit 1; }
        grep -q -- '-$OLD ' /root/rand-node.service.$OLD.bak || { echo 'the backup unit has no -$OLD datadir'; exit 1; }
        cp -a /root/rand-node.service.$OLD.bak \$U
      fi
      OLDDIR=\$(grep -o -- '--datadir [^ ]*' \$U | cut -d' ' -f2)
      [ -d \$OLDDIR/db ] || { echo \"\$OLDDIR has no db\"; exit 1; }
      systemctl daemon-reload
      echo \"\$(hostname) on chain 18: \$(grep -o -- '--datadir [^ ]*' \$U)\"
    fi" || { echo "rollback: some hosts are not back on chain 18 — fix them and re-run rollback; do NOT start" >&2; exit 1; }
  echo "ROLLBACK to chain 18 ($OLD) $(date -u +%FT%TZ)" > "${MARKER_GLOB}rollback-$OLD"
  echo "ROLLED BACK — marker ${MARKER_GLOB}rollback-$OLD written; next: start (alone; check \$?), then the bridge rollback"
  ;;
start)
  set -- "$MARKER_GLOB"*
  [ -e "$1" ] || { echo "start: no $MARKER_GLOB<prefix> marker — a successful switch (or rollback) writes it; refusing (a failed push/switch never starts the fleet)" >&2; exit 1; }
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
    sleep "${WAIT_SLEEP:-20}"; ok=0
    for ip in $ALL; do
      g=$(rpc "$ip" rand_getGenesisHash | grep -oE '"result":"[0-9a-f]+"' | cut -d'"' -f4)
      s=$(rpc "$ip" rand_getHealth | grep -oE '"status":"[a-z_]+"' | cut -d'"' -f4)
      [ "$g" = "$NEW" ] && [ "$s" = ok ] && ok=$((ok+1))
    done
    H=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)
    echo "  $(date -u +%T) $ok/26 on chain 19 and healthy; C height ${H:-?}"
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
