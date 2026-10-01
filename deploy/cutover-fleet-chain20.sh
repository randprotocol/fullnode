#!/usr/bin/env bash
# Cut the fleet over from chain 19 to chain 20 — all-stop, all-start, in phases, over all 26 hosts:
# the 20 hosts of deploy/nodes.env (A–F, the twelve regional validators, obs1, rand-archive-2) and
# the six guardian hosts (their own ssh key; their unit takes its ExecStart from a drop-in).
#
# DERIVED from deploy/cutover-fleet-chain19.sh (chain 19 = v0.6.7, a pure re-genesis, is chain 20's
# predecessor; read it first) PLUS the new-build half of deploy/cutover-fleet-chain18.sh, because
# chain 20 runs a new build: v0.6.8 (main + RPL-2). Against chain 19's script:
#
#   * `stage` is back (chain 18's), with THREE sources for the v0.6.8 Linux binaries, each landing
#     as /root/rand-node.c20 and /root/rand.c20 on every host, sha256-checked there against
#     WANT_SHA / WANT_SHA_WALLET (both required — there is no default: the build does not exist yet)
#     before anything is kept:
#       STAGE_FROM=release (default)  each host downloads $RELEASE_URL/{rand-node,rand} itself
#                                     (default: the GitHub release of $TAG) — the laptop's upload is
#                                     too slow to relay 47 MB × 26.
#       STAGE_FROM=url                the same from STAGE_URL, a PRIVATE base URL (a bucket's
#                                     presigned prefix, an operator host behind TLS) — for binaries
#                                     built privately before the release is published. The URL is
#                                     never printed whole (it may carry a token).
#       STAGE_FROM=path               the laptop pushes STAGE_DIR/{rand-node,rand} to every host by
#                                     scp, after checking both sha256s locally (and that each is a
#                                     Linux ELF). Slow (~170 KB/s laptop upload): use it when the
#                                     binaries exist nowhere else.
#     With RELEASE_SUMS (+ RELEASE_SUMS_SIG), the SHA256SUMS signature is verified first
#     (deploy/lib/verify-release.sh, PROC-5) and WANT_SHA / WANT_SHA_WALLET must be what it lists;
#     without them the pins are the operator's word (printed as a warning).
#     A staged binary must report `rand-node $WANT_VERSION` and know every flag in NEED_FLAGS.
#   * `switch` installs the staged binaries (keeping the v0.6.7 ones as /root/rand-node.pre-c20 and
#     /root/rand.pre-c20, each checked to BE the v0.6.7 release binary — OLD_SHA / OLD_SHA_WALLET —
#     before it is kept), then initialises the chain-20 datadir and rewrites the unit / drop-in.
#   * `rollback` restores the unit / drop-in AND the two binaries (sha-checked against OLD_SHA /
#     OLD_SHA_WALLET), then leaves the marker that licenses one `start`.
#   * `push` refuses unless the cut record (CUT_RECORD) carries `second-hash: <this genesis hash>`
#     — the second operator's rebuild, deploy/lib/cut-policy.sh `require_second_rebuild` (OPS-7).
#     SECOND_REBUILD_WAIVED=1 skips it, loudly: it prints what the waiver leaves unchecked and
#     appends `second-rebuild-waived: <UTC> genesis <hash> by <user@host>: <why>` to the (filled)
#     cut record before anything is pushed (SECOND_REBUILD_WAIVED_REASON overrides the default why:
#     one operator holds every key). The policy says not to.
#   * `preflight` (read-only) proves every host runs the v0.6.7 release binaries on chain 19 and is
#     healthy, that no chain-20 datadir / drop-in / binary backup is lying around, and prints disk.
#
# Why all-stop/all-start, and never node by node: v0.6.8 carries audit v6's CON-4 and CH-1 consensus
# changes (the vote's hash persisted, no automatic lock release, the timeout-certificate pacemaker)
# — "all-stop/all-start, never node by node" (AGENTS.md) — and chain 20 is a new genesis besides:
# there is no block both chains share. Chain 19 stops committing once a third of the stake is down;
# chain 20 commits once 18 of the 26 are up.
#
# Chain 20 keeps every key chain 19 runs (so every peer id, every `--bootstrap` multiaddr and
# deploy/nodes.env stay as they are). Each nodes.env unit changes in exactly one place, its datadir
# suffix `-<chain-19 prefix>` → `-<chain-20 prefix>`; each guardian host gets a `chain20.conf`
# drop-in, chain 19's `chain19.conf` with `data-19` → `data-20`, and chain19.conf is moved aside.
#
#   STAGE_FROM=… WANT_SHA=… WANT_SHA_WALLET=… deploy/cutover-fleet-chain20.sh preflight
#                                                      # chain 19 running, READ-ONLY
#   STAGE_FROM=… WANT_SHA=… WANT_SHA_WALLET=… deploy/cutover-fleet-chain20.sh stage
#                                                      # chain 19 running: v0.6.8 to /root/*.c20, checked
#   (bridge: deploy/chain20-bridge-steps.md "stop" — relayer + guardians down, BEFORE the snapshot)
#   deploy/cut-chain20-genesis.sh snapshot <dir>       # chain 19 still up
#   deploy/cut-chain20-genesis.sh balances <dir>       # chain 19 still up: the RAND carry list
#   ── the user's go, typed in the executing session, before anything below ──
#   deploy/cutover-fleet-chain20.sh stop               # stop every chain-19 node (26)
#   (cut: CUT_RECORD=… CHAIN19_SNAPSHOT=<dir> NODE=<v0.6.8 rand-node> WALLET=<v0.6.8 rand>
#         deploy/cut-chain20-genesis.sh; the second operator writes second-hash into the record)
#   LOCAL_NODE=<v0.6.8 rand-node> CUT_RECORD=… WANT_SHA=… deploy/cutover-fleet-chain20.sh push <genesis>
#   LOCAL_NODE=… WANT_SHA=… WANT_SHA_WALLET=… deploy/cutover-fleet-chain20.sh switch <genesis>
#                                                      # install, init, rewrite — no start; writes the marker
#   deploy/cutover-fleet-chain20.sh start              # bootstraps C, D first, then the other 24
#   LOCAL_NODE=… deploy/cutover-fleet-chain20.sh wait <genesis>     # until all 26 serve chain 20
#   (then: NODE=<v0.6.8 rand-node> deploy/cut-chain20-genesis.sh check-limits <a node's RPC> <genesis>)
#   deploy/cutover-fleet-chain20.sh status             # read-only: version, chain id, height per host
#   deploy/cutover-fleet-chain20.sh rollback           # ONLY after `stop`: every host back on chain 19's
#                                                      # unit / drop-in and v0.6.7 binaries; then `start`
#
# THE TRAP FROM CHAIN 16 (2026-09-28, kept by every script since): `push … | tail && switch … | tail
# && start` ran `start` after `push` had FAILED (LOCAL_NODE unset) — a pipeline's exit status is its
# last command's, `tail`'s — and the fleet came back up on the old chain for a minute. So:
#   * run each phase ALONE, never piped, never chained; read `echo $?` before the next one;
#   * `push`, `switch` and `wait` refuse to run without LOCAL_NODE (an executable v0.6.8 rand-node on
#     this machine — the macOS build of the same commit: it re-derives the genesis hash, which every
#     host's staged binary must then re-derive identically);
#   * `start` refuses unless a successful `switch` (or `rollback`) left /tmp/chain20-switched-<tag>
#     (and exactly one such marker); `stop`, `push` and `stage` delete any marker, so a stale switch
#     never licenses a start.
#
# Env: TAG (v0.6.8), STAGE_FROM / RELEASE_URL / STAGE_URL / STAGE_DIR (above), WANT_SHA /
# WANT_SHA_WALLET (the v0.6.8 Linux rand-node / rand; required by stage, push, switch),
# RELEASE_SUMS / RELEASE_SUMS_SIG (optional, PROC-5), WANT_VERSION (0.6.8), NEED_FLAGS (the
# genesis flags a v0.6.8 rand-node must know), OLD_SHA / OLD_SHA_WALLET (the v0.6.7 release binaries
# chain 19 runs; defaults from its SHA256SUMS), OLD (chain-19 datadir suffix, default a3defc93),
# CUT_RECORD (push), GUARDIAN_HOSTS (`<index> <ip>` per line; the bridge session's file),
# LOCAL_NODE (above).
#
# Nothing here touches keys (/root/keys, /var/lib/randnode/node.key.json) or the guardian daemons
# (the bridge steps own those; `switch` and `rollback` refuse a guardian host whose rand-guardian
# is still active).
#
# Rollback by hand (if `rollback` itself cannot run): on a nodes.env host restore
# /root/rand-node.service.$OLD.bak over the unit and /root/rand-node.pre-c20, /root/rand.pre-c20 over
# /usr/local/bin; on a guardian host move /root/chain19.conf.c19 back into
# /etc/systemd/system/rand-node.service.d/, delete chain20.conf, restore the same two binaries;
# daemon-reload; start. Chain 19 resumes from the height it stopped at: its data dirs are never
# touched here — retire them with deploy/retire-chain-dirs.sh once chain 20 has run a day.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/lib/cut-policy.sh

PHASE=${1:?preflight|stage|stop|push|switch|start|wait|status|rollback}
TAG=${TAG:-v0.6.8}
STAGE_FROM=${STAGE_FROM:-release}
RELEASE_URL=${RELEASE_URL:-https://github.com/randprotocol/fullnode/releases/download/$TAG}
STAGE_URL=${STAGE_URL:-}
STAGE_DIR=${STAGE_DIR:-}
WANT_SHA=${WANT_SHA:-}                 # the v0.6.8 Linux rand-node — no default: it is not built yet
WANT_SHA_WALLET=${WANT_SHA_WALLET:-}   # the v0.6.8 Linux rand
WANT_VERSION=${WANT_VERSION:-0.6.8}
NEED_FLAGS=${NEED_FLAGS:---testnet --binding-domain --proof-window-blocks --max-gas-price --gas-byte-load --program-state-cell-fee}
# The v0.6.7 GitHub release's Linux binaries (tag v0.6.7 = 86941a1), which chain 19 runs.
OLD_SHA=${OLD_SHA:-f365317eb2ae3340e50a9dcdbfc2d3d2f3beba819ccf5f5ef21b61a5efbe08f9}
OLD_SHA_WALLET=${OLD_SHA_WALLET:-480bd838bf64b151c1406da3a44f4b440b4b2b1c31f88e11139448f276720fc4}
# Chain 19's datadir suffix on the nodes.env hosts: its genesis hash prefix (a3defc93…228a).
OLD=${OLD:-a3defc93}
CUT_RECORD=${CUT_RECORD:-$HOME/.rand-chain20/cut-record.txt}
GUARDIAN_HOSTS=${GUARDIAN_HOSTS:-$HOME/.rand-bridge/mainnet-set1/hosts.txt}
MARKER_GLOB=${MARKER_GLOB:-/tmp/chain20-switched-}
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
[[ "$OLD_SHA" =~ ^[0-9a-f]{64}$ && "$OLD_SHA_WALLET" =~ ^[0-9a-f]{64}$ ]] || { echo "OLD_SHA / OLD_SHA_WALLET are not sha256 hex" >&2; exit 1; }
[[ "$OLD" =~ ^[0-9a-f]{8}$ ]] || { echo "OLD=$OLD is not an 8-hex genesis prefix" >&2; exit 1; }

is_guard() { case " $GUARDS " in *" $1 "*) return 0;; esac; return 1; }
on() { local ip=$1; shift; if is_guard "$ip"; then ssh -n $GOPTS root@$ip "$@"; else ssh -n $OPTS root@$ip "$@"; fi; }
cp_to() { local ip=$1 dst=$2; shift 2; if is_guard "$ip"; then scp -q $GOPTS "$@" "root@$ip:$dst"; else scp -q $OPTS "$@" "root@$ip:$dst"; fi; }
each() {  # run a remote script on every host in parallel, the last line of output each; fail if any failed
  local ip dir; dir=$(mktemp -d)
  for ip in $ALL; do ( on "$ip" "$1" > "$dir/$ip" 2>&1 && echo ok >> "$dir/$ip.rc" || echo FAIL >> "$dir/$ip.rc" ) & done; wait
  local bad=0
  for ip in $ALL; do printf '   %-16s %s %s\n' "$ip" "$(cat "$dir/$ip.rc")" "$(tail -1 "$dir/$ip")"; [ "$(cat "$dir/$ip.rc")" = ok ] || bad=1; done
  rm -rf "$dir"; return $bad
}
rpc() { on "$1" "curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}'" 2>/dev/null || true; }
need_new_shas() {
  [[ "$WANT_SHA" =~ ^[0-9a-f]{64}$ && "$WANT_SHA_WALLET" =~ ^[0-9a-f]{64}$ ]] \
    || { echo "$PHASE: WANT_SHA / WANT_SHA_WALLET must be the sha256 of the v0.6.8 Linux rand-node / rand — nothing done" >&2; exit 1; }
  [ "$WANT_SHA" != "$OLD_SHA" ] || { echo "$PHASE: WANT_SHA is chain 19's v0.6.7 rand-node — chain 20 needs v0.6.8; nothing done" >&2; exit 1; }
}
need_local_node() {
  local f help
  [ -n "${LOCAL_NODE:-}" ] || { echo "$PHASE: LOCAL_NODE is unset — point it at a v0.6.8 rand-node on this machine; nothing done (the chain-16 trap)" >&2; exit 1; }
  [ -x "$LOCAL_NODE" ] || { echo "$PHASE: LOCAL_NODE=$LOCAL_NODE is not executable — nothing done" >&2; exit 1; }
  help=$("$LOCAL_NODE" genesis --help)
  for f in $NEED_FLAGS; do grep -q -- "$f" <<<"$help" || { echo "$PHASE: $LOCAL_NODE has no $f (not the v0.6.8 build) — nothing done" >&2; exit 1; }; done
  case "$("$LOCAL_NODE" --version)" in "rand-node $WANT_VERSION"*) ;; *) echo "$PHASE: $LOCAL_NODE is $("$LOCAL_NODE" --version), not rand-node $WANT_VERSION — nothing done" >&2; exit 1;; esac
}
genesis_hash() { local d h; d=$(mktemp -d); h=$("$LOCAL_NODE" init --datadir "$d/p" --genesis "$1" | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2 || true); rm -rf "$d"; echo "$h"; }
# The file must BE a chain-20 genesis: a chain-19 (or any other) file pushed by mistake would
# "switch" the fleet onto a fresh copy of the wrong chain.
need_chain20_genesis() {
  [ -f "$1" ] || { echo "$PHASE: $1 is not a file — nothing done" >&2; exit 1; }
  local id; id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("chain_id"))' "$1" 2>/dev/null || true)
  [ "$id" = 20 ] || { echo "$PHASE: $1 has chain_id ${id:-?}, not 20 — nothing done" >&2; exit 1; }
}
clear_markers() { rm -f "$MARKER_GLOB"*; }
# The remote check every phase after `stage` shares: the staged binaries are the pinned v0.6.8 ones.
STAGED_OK="[ \"\$(sha256sum /root/rand-node.c20 2>/dev/null | cut -d' ' -f1)\" = '$WANT_SHA' ] && [ \"\$(sha256sum /root/rand.c20 2>/dev/null | cut -d' ' -f1)\" = '$WANT_SHA_WALLET' ] || { echo 'the v0.6.8 binaries are not staged (/root/rand-node.c20, /root/rand.c20 with the pinned sha256s)'; exit 1; }"
# What a staged rand-node must say about itself.
STAGED_SELF="./rand-node.c20 --version | grep -q 'rand-node $WANT_VERSION' || { echo \"staged rand-node is \$(./rand-node.c20 --version 2>&1 | head -1), not $WANT_VERSION\"; exit 1; }
    H=\$(./rand-node.c20 genesis --help); for f in $NEED_FLAGS; do printf '%s' \"\$H\" | grep -q -- \"\$f\" || { echo \"staged rand-node has no \$f\"; exit 1; }; done"

case "$PHASE" in
preflight)
  echo "== preflight (read-only) on $(echo $ALL | wc -w) hosts: installed v0.6.7 rand-node ${OLD_SHA:0:12}…, rand ${OLD_SHA_WALLET:0:12}…, chain-19 datadir -$OLD / data-19 $(date -u +%T)"
  each "set -e
    [ \"\$(sha256sum /usr/local/bin/rand-node | cut -d' ' -f1)\" = '$OLD_SHA' ] || { echo \"installed rand-node is \$(/usr/local/bin/rand-node --version 2>&1 | head -1) sha256 \$(sha256sum /usr/local/bin/rand-node | cut -c1-12)…, not chain 19's v0.6.7 ${OLD_SHA:0:12}…\"; exit 1; }
    [ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$OLD_SHA_WALLET' ] || { echo \"installed rand is sha256 \$(sha256sum /usr/local/bin/rand | cut -c1-12)…, not chain 19's v0.6.7\"; exit 1; }
    [ ! -e /root/rand-node.pre-c20 ] && [ ! -e /root/rand.pre-c20 ] || { echo 'a *.pre-c20 binary backup already exists (an earlier switch?)'; exit 1; }
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain19.conf ] || [ -f \$D/chain20.conf ]; then
      [ -f \$D/chain19.conf ] && [ ! -f \$D/chain20.conf ] || { echo 'a chain20.conf drop-in is already present'; exit 1; }
      grep -q -- '--datadir /var/lib/randnode/data-19 ' \$D/chain19.conf || { echo 'chain19.conf has no data-19 datadir'; exit 1; }
      [ ! -e /var/lib/randnode/data-20 ] || { echo '/var/lib/randnode/data-20 already exists — move it aside'; exit 1; }
      [ ! -e /root/chain19.conf.c19 ] || { echo '/root/chain19.conf.c19 already exists (an earlier switch?)'; exit 1; }
      KIND=guardian-host
    else
      grep -q -- '-$OLD ' /etc/systemd/system/rand-node.service || { echo 'unit has no -$OLD datadir'; exit 1; }
      KIND=node
    fi
    G=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getGenesisHash\",\"params\":[]}' | grep -oE '\"result\":\"[0-9a-f]+\"' | cut -d'\"' -f4)
    case \"\$G\" in $OLD*) ;; *) echo \"serves genesis \${G:-nothing}, not chain 19 ($OLD…)\"; exit 1;; esac
    curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}' | grep -q '\"status\":\"ok\"' || { echo 'rand_getHealth is not ok'; exit 1; }
    S=\$( [ -e /root/rand-node.c20 ] && echo ', a staged rand-node.c20 present' || echo ', nothing staged yet')
    echo \"\$(hostname) \$KIND ready: \$(/usr/local/bin/rand-node --version), on chain 19, healthy, \$(df -h / | tail -1 | awk '{print \$4}') free\$S\"" \
    || { echo "preflight: not every host is ready — fix those before staging or stopping anything" >&2; exit 1; }
  echo "PREFLIGHT OK — nothing was changed"
  ;;
stage)
  clear_markers
  need_new_shas
  if [ -n "${RELEASE_SUMS:-}" ]; then
    . deploy/lib/verify-release.sh
    verify_release_sums "$RELEASE_SUMS" "${RELEASE_SUMS_SIG:-$RELEASE_SUMS.sig}" || { echo "stage: the release SHA256SUMS signature does not verify — nothing staged" >&2; exit 1; }
    [ "$(release_sha "$RELEASE_SUMS" rand-node)" = "$WANT_SHA" ] && [ "$(release_sha "$RELEASE_SUMS" rand)" = "$WANT_SHA_WALLET" ] \
      || { echo "stage: WANT_SHA / WANT_SHA_WALLET are not what the signed SHA256SUMS lists — nothing staged" >&2; exit 1; }
    echo "== the signed SHA256SUMS lists both pins"
  else
    echo "== ⚠ no RELEASE_SUMS: the pins ${WANT_SHA:0:12}… / ${WANT_SHA_WALLET:0:12}… are the operator's word (PROC-5's signature is not checked)"
  fi
  case "$STAGE_FROM" in
    release|url)
      if [ "$STAGE_FROM" = url ]; then
        [ -n "$STAGE_URL" ] || { echo "stage: STAGE_FROM=url needs STAGE_URL (a private base URL holding rand-node and rand) — nothing staged" >&2; exit 1; }
        BASE=$STAGE_URL; SHOWN="${STAGE_URL%%\?*}"; SHOWN="${SHOWN%/*}/…"
      else BASE=$RELEASE_URL; SHOWN=$RELEASE_URL; fi
      case "$BASE" in
        https://*) ;;
        http://*)
          # A private build served from an operator host for the length of `stage` (chain 20's
          # v0.6.8 was served from E). Integrity rests on the sha256 pins every host checks before
          # it keeps a byte, not on TLS; what plain HTTP gives up is that anyone on the path sees
          # the binaries. Allowed for STAGE_FROM=url only, and only when asked for by name.
          if [ "$STAGE_FROM" = url ] && [ "${STAGE_ALLOW_HTTP:-0}" = 1 ]; then
            echo "== ⚠ STAGE_ALLOW_HTTP=1: staging from plain http:// ($SHOWN) — the sha256 pins are the only integrity check" >&2
          else
            echo "stage: $SHOWN is not https:// — nothing staged (STAGE_ALLOW_HTTP=1 allows a private STAGE_FROM=url over http; the sha256 pins still decide)" >&2; exit 1
          fi ;;
        *) echo "stage: $SHOWN is not https:// — nothing staged" >&2; exit 1;;
      esac
      Q=""; case "$BASE" in *\?*) Q="?${BASE#*\?}"; BASE=${BASE%%\?*};; esac
      echo "== stage $TAG on $(echo $ALL | wc -w) hosts from $SHOWN $(date -u +%T)"
      # Each host fetches the binaries itself and checks both pins; a mismatch deletes what it fetched.
      each "set -e; cd /root
        rm -f rand-node.c20.part rand.c20.part
        curl -fsSL --retry 10 --retry-all-errors --retry-delay 5 -o rand-node.c20.part '$BASE/rand-node$Q'
        curl -fsSL --retry 10 --retry-all-errors --retry-delay 5 -o rand.c20.part '$BASE/rand$Q'
        if [ \"\$(sha256sum rand-node.c20.part | cut -d' ' -f1)\" != '$WANT_SHA' ] || [ \"\$(sha256sum rand.c20.part | cut -d' ' -f1)\" != '$WANT_SHA_WALLET' ]; then
          rm -f rand-node.c20.part rand.c20.part; echo 'SHA MISMATCH — removed'; exit 1; fi
        chmod 755 rand-node.c20.part rand.c20.part; mv rand-node.c20.part rand-node.c20; mv rand.c20.part rand.c20
        $STAGED_SELF
        echo \"\$(hostname) staged \$(./rand-node.c20 --version), \$(df -h / | tail -1 | awk '{print \$4}') free\"" \
        || { echo "stage: not every host staged — fix those before stopping anything" >&2; exit 1; }
      ;;
    path)
      [ -n "$STAGE_DIR" ] && [ -f "$STAGE_DIR/rand-node" ] && [ -f "$STAGE_DIR/rand" ] \
        || { echo "stage: STAGE_FROM=path needs STAGE_DIR holding rand-node and rand (the v0.6.8 Linux builds) — nothing staged" >&2; exit 1; }
      [ "$(shasum -a 256 "$STAGE_DIR/rand-node" | cut -d' ' -f1)" = "$WANT_SHA" ] \
        || { echo "stage: $STAGE_DIR/rand-node is not WANT_SHA ${WANT_SHA:0:12}… — nothing staged" >&2; exit 1; }
      [ "$(shasum -a 256 "$STAGE_DIR/rand" | cut -d' ' -f1)" = "$WANT_SHA_WALLET" ] \
        || { echo "stage: $STAGE_DIR/rand is not WANT_SHA_WALLET ${WANT_SHA_WALLET:0:12}… — nothing staged" >&2; exit 1; }
      if [ "${STAGE_ALLOW_NON_ELF:-}" != 1 ]; then
        for b in rand-node rand; do
          [ "$(head -c 4 "$STAGE_DIR/$b" | od -An -c | tr -d ' ')" = '177ELF' ] \
            || { echo "stage: $STAGE_DIR/$b is not a Linux ELF binary (a macOS build?) — nothing staged" >&2; exit 1; }
        done
      fi
      echo "== stage $TAG on $(echo $ALL | wc -w) hosts from $STAGE_DIR (laptop scp — slow; sha256s checked here first) $(date -u +%T)"
      for ip in $ALL; do ( on "$ip" 'rm -f /root/rand-node.c20.part /root/rand.c20.part' \
        && cp_to "$ip" /root/rand-node.c20.part "$STAGE_DIR/rand-node" && cp_to "$ip" /root/rand.c20.part "$STAGE_DIR/rand" ) & done; wait
      each "set -e; cd /root
        [ -f rand-node.c20.part ] && [ -f rand.c20.part ] || { echo 'the copy did not arrive'; exit 1; }
        if [ \"\$(sha256sum rand-node.c20.part | cut -d' ' -f1)\" != '$WANT_SHA' ] || [ \"\$(sha256sum rand.c20.part | cut -d' ' -f1)\" != '$WANT_SHA_WALLET' ]; then
          rm -f rand-node.c20.part rand.c20.part; echo 'SHA MISMATCH after copy — removed'; exit 1; fi
        chmod 755 rand-node.c20.part rand.c20.part; mv rand-node.c20.part rand-node.c20; mv rand.c20.part rand.c20
        $STAGED_SELF
        echo \"\$(hostname) staged \$(./rand-node.c20 --version), \$(df -h / | tail -1 | awk '{print \$4}') free\"" \
        || { echo "stage: not every host staged — fix those before stopping anything" >&2; exit 1; }
      ;;
    *) echo "stage: STAGE_FROM=$STAGE_FROM — release, url or path" >&2; exit 1;;
  esac
  echo "STAGED $(date -u +%T) — nothing was installed; the fleet still runs chain 19 on v0.6.7"
  ;;
stop)
  clear_markers
  echo "== stop all 26 $(date -u +%T)"
  H0=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
  echo "   chain 19 head at C: ${H0:-?}"
  each 'systemctl stop rand-node; echo "$(hostname) $(systemctl is-active rand-node || true)"' || true
  echo "STOPPED $(date -u +%T) — cut the genesis now (deploy/cut-chain20-genesis.sh), then push (run it alone, check \$?)"
  ;;
push)
  GENESIS=${2:?push <genesis file>}
  clear_markers
  need_local_node
  need_new_shas
  need_chain20_genesis "$GENESIS"
  SHA=$(shasum -a 256 "$GENESIS" | cut -d' ' -f1)
  NEW=$(genesis_hash "$GENESIS"); [ ${#NEW} -eq 64 ] || { echo "push: $LOCAL_NODE derived no genesis hash from $GENESIS — nothing pushed" >&2; exit 1; }
  [ "${NEW:0:8}" != "$OLD" ] || { echo "push: $GENESIS is chain 19's genesis ($NEW) — nothing pushed" >&2; exit 1; }
  # OPS-7: the second operator rebuilt this hash on another machine before anything is published.
  if [ "${SECOND_REBUILD_WAIVED:-}" = 1 ]; then
    # The waiver is a decision, so it is written down: the record must exist and be filled in
    # (require_cut_record), and the waiver — why, who, when, for which hash — is appended to it
    # before anything is pushed. Re-running push for the same hash does not append twice.
    require_cut_record "$CUT_RECORD" || { echo "push: a waiver is recorded in the cut record, and $CUT_RECORD is not a filled one — nothing pushed" >&2; exit 1; }
    WHY=${SECOND_REBUILD_WAIVED_REASON:-one operator holds every validator key and every host; no second operator exists to rebuild the genesis for this cut}
    cat <<EOF
== ⚠⚠ SECOND_REBUILD_WAIVED=1 — pushing genesis $NEW WITHOUT a second operator's rebuild.
==    docs/deploy.md "Cut policy" item 4 (two people: a second operator rebuilds the genesis from
==    the tag on another machine and the hashes match before anything is published) is NOT met.
==    What that leaves unchecked: that this genesis file is the one the scripts at this commit cut
==    from the snapshot — a wrong or tampered file would be caught by no one but its author.
==    Why waived: $WHY
==    Recorded in $CUT_RECORD.
EOF
    if ! grep -q "^second-rebuild-waived: .*genesis $NEW" "$CUT_RECORD"; then
      printf 'second-rebuild-waived: %s genesis %s by %s@%s: %s\n' "$(date -u +%FT%TZ)" "$NEW" "$(id -un)" "$(hostname -s)" "$WHY" >> "$CUT_RECORD"
    fi
  else
    require_second_rebuild "$CUT_RECORD" "$NEW" || { echo "push: nothing pushed" >&2; exit 1; }
  fi
  echo "== push $GENESIS (sha256 $SHA, genesis $NEW) $(date -u +%T)"
  for ip in $ALL; do ( cp_to "$ip" /root/genesis-chain20.json "$GENESIS" ) & done; wait
  each "set -e
    [ \"\$(sha256sum /root/genesis-chain20.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis sha mismatch'; exit 1; }
    $STAGED_OK
    rm -rf /root/probe-c20
    H=\$(/root/rand-node.c20 init --datadir /root/probe-c20 --genesis /root/genesis-chain20.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-c20
    [ \"\$H\" = '$NEW' ] || { echo \"genesis hash \$H, expected $NEW\"; exit 1; }
    echo \"\$(hostname) genesis $NEW verified by the staged v0.6.8 binary\"" \
    || { echo "push: not every host holds the genesis — do NOT switch or start" >&2; exit 1; }
  echo "PUSHED — next: switch (alone; check \$?)"
  ;;
switch)
  GENESIS=${2:?switch <genesis file>}
  clear_markers
  need_local_node
  need_new_shas
  need_chain20_genesis "$GENESIS"
  SHA=$(shasum -a 256 "$GENESIS" | cut -d' ' -f1)
  NEW=$(genesis_hash "$GENESIS"); [ ${#NEW} -eq 64 ] || { echo "switch: could not derive the genesis hash — nothing switched" >&2; exit 1; }
  P=${NEW:0:8}
  [ "$P" != "$OLD" ] || { echo "switch: $GENESIS is chain 19's genesis — nothing switched" >&2; exit 1; }
  echo "== switch to chain 20, genesis $NEW (datadir suffix -$P), installing v0.6.8 $(date -u +%T)"
  # One script for both kinds of host; the guardian branch is chosen by the drop-in's presence.
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    [ \"\$(sha256sum /root/genesis-chain20.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis not pushed'; exit 1; }
    $STAGED_OK
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain19.conf ] || [ -f \$D/chain20.conf ]; then
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it first'; exit 1; }
    fi
    # Keep the v0.6.7 binaries once, and only if they ARE the v0.6.7 release binaries.
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET; do n=\${b%%:*}; s=\${b#*:}
      if [ ! -e /root/\$n.pre-c20 ]; then
        [ \"\$(sha256sum /usr/local/bin/\$n | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"installed \$n is not chain 19's v0.6.7 binary — no backup made, nothing switched\"; exit 1; }
        cp -a /usr/local/bin/\$n /root/\$n.pre-c20
      fi
    done
    install -m 755 /root/rand-node.c20 /usr/local/bin/rand-node; install -m 755 /root/rand.c20 /usr/local/bin/rand
    if [ -f \$D/chain19.conf ] || [ -f \$D/chain20.conf ]; then
      # A guardian host: the node runs as randnode from /var/lib/randnode, ExecStart in a drop-in.
      V=/var/lib/randnode
      # data-20 carries no genesis prefix: a db there must be THIS genesis's. A re-cut leaves a stale
      # one — moved aside, never deleted, and never reused.
      if [ -d \$V/data-20/db ] && [ \"\$(cat \$V/data-20.genesis 2>/dev/null)\" != '$NEW' ]; then
        STALE=\$V/data-20.stale-\$(cut -c1-8 \$V/data-20.genesis 2>/dev/null || echo unknown)
        [ ! -e \$STALE ] || { echo \"\$V/data-20 is stale and \$STALE already exists — sort them out by hand\"; exit 1; }
        mv \$V/data-20 \$STALE; rm -f \$V/data-20.genesis
      fi
      install -d -o randnode -g randnode \$V/data-20
      install -m 644 -o randnode -g randnode /root/genesis-chain20.json \$V/genesis-chain20.json
      [ -d \$V/data-20/db ] || runuser -u randnode -- /usr/local/bin/rand-node init --datadir \$V/data-20 --genesis \$V/genesis-chain20.json >/dev/null
      echo '$NEW' > \$V/data-20.genesis
      if [ -f \$D/chain19.conf ]; then
        grep -q -- '--datadir /var/lib/randnode/data-19 ' \$D/chain19.conf || { echo 'chain19.conf has no data-19 datadir'; exit 1; }
        sed 's#--datadir /var/lib/randnode/data-19 #--datadir /var/lib/randnode/data-20 #' \$D/chain19.conf > \$D/chain20.conf
        mv \$D/chain19.conf /root/chain19.conf.c19
      fi
      grep -q -- '--datadir /var/lib/randnode/data-20 ' \$D/chain20.conf
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(/usr/local/bin/rand-node --version), \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"
    else
      U=/etc/systemd/system/rand-node.service
      if grep -q -- '-$P ' \$U; then echo \"\$(hostname) already switched (\$(/usr/local/bin/rand-node --version))\"; exit 0; fi
      grep -q -- '-$OLD ' \$U || { echo 'unit has no -$OLD datadir'; exit 1; }
      OLDDIR=\$(grep -o -- '--datadir [^ ]*' \$U | cut -d' ' -f2); NEWDIR=\${OLDDIR%-$OLD}-$P
      # obs1 and rand-archive-2 keep their data on a volume behind a symlink: so does chain 20.
      if [ -L \$OLDDIR ]; then T=\$(dirname \$(readlink \$OLDDIR))/\$(basename \$NEWDIR); mkdir -p \$T; ln -sfn \$T \$NEWDIR; fi
      [ -d \$NEWDIR/db ] || /usr/local/bin/rand-node init --datadir \$NEWDIR --genesis /root/genesis-chain20.json >/dev/null
      [ -e /root/rand-node.service.$OLD.bak ] || cp -a \$U /root/rand-node.service.$OLD.bak
      sed -i 's/-$OLD /-$P /' \$U
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(/usr/local/bin/rand-node --version), \$(grep -o -- '--datadir [^ ]*' \$U)\"
    fi" || { echo "switch: some hosts are not ready — fix them and re-run switch; do NOT start" >&2; exit 1; }
  # Only a switch that reached every host licenses `start`.
  echo "$NEW $(date -u +%FT%TZ)" > "$MARKER_GLOB$P"
  echo "SWITCHED — marker $MARKER_GLOB$P written; next: start (alone; check \$?)"
  ;;
rollback)
  # Back to chain 19's unit / drop-in and v0.6.7 binaries on every host. Only after `stop`.
  # Idempotent per host (a host never switched, or already rolled back, answers "on chain 19").
  clear_markers
  echo "== rollback to chain 19 (datadir suffix -$OLD / data-19, v0.6.7 binaries) $(date -u +%T)"
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain19.conf ] || [ -f \$D/chain20.conf ]; then
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it first'; exit 1; }
    fi
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET; do n=\${b%%:*}; s=\${b#*:}
      if [ \"\$(sha256sum /usr/local/bin/\$n | cut -d' ' -f1)\" != \"\$s\" ]; then
        [ -f /root/\$n.pre-c20 ] || { echo \"no /root/\$n.pre-c20 to restore\"; exit 1; }
        [ \"\$(sha256sum /root/\$n.pre-c20 | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"/root/\$n.pre-c20 is not chain 19's v0.6.7 binary\"; exit 1; }
        install -m 755 /root/\$n.pre-c20 /usr/local/bin/\$n
      fi
    done
    if [ -f \$D/chain19.conf ] || [ -f \$D/chain20.conf ]; then
      if [ -f \$D/chain20.conf ]; then
        [ -f /root/chain19.conf.c19 ] || { echo 'no /root/chain19.conf.c19 to restore'; exit 1; }
        mv /root/chain19.conf.c19 \$D/chain19.conf
        rm -f \$D/chain20.conf
      fi
      grep -q -- '--datadir /var/lib/randnode/data-19 ' \$D/chain19.conf
      [ -d /var/lib/randnode/data-19/db ] || { echo 'data-19 has no db'; exit 1; }
      systemctl daemon-reload
      echo \"\$(hostname) on chain 19: \$(/usr/local/bin/rand-node --version), \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"
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
      echo \"\$(hostname) on chain 19: \$(/usr/local/bin/rand-node --version), \$(grep -o -- '--datadir [^ ]*' \$U)\"
    fi" || { echo "rollback: some hosts are not back on chain 19 — fix them and re-run rollback; do NOT start" >&2; exit 1; }
  echo "ROLLBACK to chain 19 ($OLD) $(date -u +%FT%TZ)" > "${MARKER_GLOB}rollback-$OLD"
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
    echo "  $(date -u +%T) $ok/26 on chain 20 and healthy; C height ${H:-?}"
    if [ "$ok" = 26 ] && [ -n "$H" ] && [ "$H" -gt 2 ]; then echo "=== $(date -u +%T) CUTOVER DONE: all 26 on $NEW, committing at $H — next: check-limits (deploy/cut-chain20-genesis.sh)"; exit 0; fi
  done
  echo "=== not all 26 healthy after 30 min — check the laggards"; exit 1
  ;;
status)
  for ip in $ALL; do (
    v=$(rpc "$ip" rand_getVersion | grep -oE '"version":"[^"]+"|"git_sha":"[a-z0-9]+"|"chain_id":[0-9]+' | tr '\n' ' ')
    h=$(rpc "$ip" rand_status | grep -oE '"height":[0-9]+' | head -1)
    printf '   %-16s %s %s\n' "$ip" "$v" "$h" ) & done; wait
  ;;
*) echo "unknown phase $PHASE" >&2; exit 1 ;;
esac
