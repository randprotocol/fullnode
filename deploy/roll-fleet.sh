#!/usr/bin/env bash
# One-host-at-a-time roll of a same-chain, node-only release over the fleet, with a rejoin gate
# between hosts and a roll record written by the tool (audit v14, PROC-751).
#
#   deploy/roll-fleet.sh --release LABEL [--dry-run] [--skip NAME[,NAME…]] [--last NAME[,NAME…]]
#                        [--ref NAME[,NAME…]] [--within N] [--min-peers M] [--timeout SECS]
#                        [--poll SECS] [--record FILE]
#
#   environment: NODES_ENV (the operator's fleet list), RELEASE_SUMS + RELEASE_SIG (the release's
#   SHA256SUMS and its signature), BUILD_HOST (default: NODE_E) and BUILD_DIR (where the release's
#   rand-node and rand lie on it); SERVICE, BIN_NODE, BIN_WALLET, PRUNE_ARGS as update-droplet.sh.
#
#   The v0.8.6 roll, as this script would have been run for it (operator's notes: BUILD_HOST=e,
#   BUILD_DIR=/root/rel-v0.8.6, archive2 unreachable, archives obs1 and e last):
#
#     NODES_ENV=…/configuration/fleet/nodes.env RELEASE_SUMS=rel/SHA256SUMS RELEASE_SIG=rel/SHA256SUMS.sig \
#       BUILD_DIR=/root/rel-v0.8.6 deploy/roll-fleet.sh --release v0.8.6 --skip ARCHIVE2 --last ARCHIVE,E
#
# Why this file exists. The v0.8.5 and v0.8.6 roll records describe a procedure — one host at a
# time, each back within 5 blocks of a reference node with at least 10 peers before the next —
# that was in no committed script: update-droplet.sh rolls ONE host and waits for nothing,
# roll-all.sh is the all-stop roll and is not what ran. What ran was a throwaway loop round
# update-droplet.sh that waited for each host by hand-written polling. This is that loop, kept.
#
# What it does, in order:
#  1. reads the inventory (NODES_ENV: NODE_<NAME>=, ARCHIVE=, ARCHIVE2= lines; names are the keys
#     without NODE_). Order: the NODE_ hosts as listed, then the archives; --last moves hosts to
#     the end, in the order given. --skip leaves hosts out (an unreachable host must be skipped
#     by name: nothing is skipped silently). A name that is not in the inventory is refused.
#  2. verifies the release's signed SHA256SUMS (deploy/lib/verify-release.sh, PROC-5) BEFORE any
#     host is contacted, and reads both binaries' sha256 from it. Unsigned is refused unless
#     ALLOW_UNSIGNED=1, the same explicit override update-droplet.sh has; an unsigned roll must
#     then name both shas itself (WANT_SHA, WANT_SHA_WALLET).
#  3. for each host, one at a time:
#       a. the reference node must answer rand_status (else the roll stops before the host is
#          touched). The reference is the first --ref name (default E) that is not the host being
#          rolled and is not skipped, else the first such host of the inventory;
#       b. deploy/update-droplet.sh <host> <build host> — the signature again, the relay with a
#          sha256 check at every hop, the limits drop-in, the restart. A failure stops the roll;
#       c. THE REJOIN GATE: polls the host and the reference every --poll seconds (default 10)
#          until ALL of: the service is active; /usr/local/bin/rand-node on the host is the
#          release's sha256; the host's height is within --within (default 5) blocks of the
#          reference's; the host has at least --min-peers (default 10) peers; and the reference
#          has moved past the height it had before this host was stopped (a halted chain keeps
#          every node "in step" and must not pass). After --timeout seconds (default 900) without
#          that, THE ROLL STOPS: the script never goes on past a host that did not rejoin.
#  4. writes the roll record as it goes (default deploy/roll-records/<LABEL>-<UTC time>.record;
#     never over an existing file): the release, both sha256s and how they were authenticated,
#     the gate's numbers, the hosts skipped, and one line per host with its timestamps and the
#     probe values the gate actually read. A stopped roll's record says where and why, and names
#     the hosts not rolled. Names only — no addresses (the record is committed).
#
# --dry-run does 1 and 2 and prints the plan; it contacts no host and writes no record.
#
# Not covered: a host outside the inventory (the third-party site node rolled by hand at v0.8.5
# and v0.8.6), the all-stop roll (deploy/roll-all.sh), and anything a release needs beyond the two
# binaries (roll-all.sh carries the msauth key blob; update-droplet.sh does not).
#
# ssh reads its stdin: inside a loop that reads the host list that eats the rest of the list, which
# is how a driver loop rolls one host and "finishes". Every ssh here is `ssh -n`, update-droplet.sh
# runs with stdin from /dev/null, and the hosts are in an array, not read from a pipe.
#
# Exit: 0 every host rolled and rejoined · 1 refused before any host was touched · 2 stopped
# part-way (the record says where).
#
#   SELFTEST=1 bash deploy/roll-fleet.sh    # deploy/lib/roll-fleet-selftest.sh: the sandbox of
#                                           # deploy/lib/host-sandbox.sh, no host touched
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd -P)
if [ "${SELFTEST:-}" = 1 ]; then exec env SELFTEST= bash "$HERE/lib/roll-fleet-selftest.sh"; fi
. "$HERE/lib/fleet-env.sh"
. "$HERE/lib/verify-release.sh"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2; }
die() { echo "roll-fleet: $*" >&2; exit 1; }

RELEASE=; DRY=; SKIP=; LAST=; REFS=E; WITHIN=5; MIN_PEERS=10; TIMEOUT=900; POLL=10; RECORD=
while [ $# -gt 0 ]; do
  case "$1" in
    --release) RELEASE=${2:-}; shift ;;
    --dry-run) DRY=1 ;;
    --skip) SKIP=${2:-}; shift ;;
    --last) LAST=${2:-}; shift ;;
    --ref) REFS=${2:-}; shift ;;
    --within) WITHIN=${2:-}; shift ;;
    --min-peers) MIN_PEERS=${2:-}; shift ;;
    --timeout) TIMEOUT=${2:-}; shift ;;
    --poll) POLL=${2:-}; shift ;;
    --record) RECORD=${2:-}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument '$1'" ;;
  esac
  shift
done
[ -n "$RELEASE" ] || { usage; die "--release LABEL is required (it names the record)"; }
case "$RELEASE" in *[!A-Za-z0-9._-]*) die "--release '$RELEASE': letters, digits, dot, dash and underscore only" ;; esac
for v in WITHIN MIN_PEERS TIMEOUT POLL; do
  case "${!v}" in ''|*[!0-9]*) die "--$(echo "$v" | tr 'A-Z_' 'a-z-') wants a whole number, got '${!v}'" ;; esac
done

# ── 1. the inventory ────────────────────────────────────────────────────────────────────────
require_fleet_env
upper() { echo "$1" | tr 'a-z' 'A-Z'; }
NAMES=(); IPS=(); ARCH_NAMES=(); ARCH_IPS=()
while IFS= read -r line; do
  case "$line" in
    NODE_*=/ip4/*) key=${line%%=*}; name=${key#NODE_} ;;
    ARCHIVE*=/ip4/*) key=${line%%=*}; name=$key ;;
    *) continue ;;
  esac
  ip=$(echo "$line" | sed -n 's#^[A-Z0-9_]*=/ip4/\([0-9.]*\)/.*#\1#p')
  [ -n "$ip" ] || die "$NODES_ENV: no address in the line for $key"
  case "$key" in ARCHIVE*) ARCH_NAMES+=("$name"); ARCH_IPS+=("$ip") ;; *) NAMES+=("$name"); IPS+=("$ip") ;; esac
done < "$NODES_ENV"
NAMES+=(${ARCH_NAMES[@]+"${ARCH_NAMES[@]}"}); IPS+=(${ARCH_IPS[@]+"${ARCH_IPS[@]}"})
[ "${#NAMES[@]}" -gt 0 ] || die "$NODES_ENV lists no NODE_<NAME>= or ARCHIVE= host"
ip_of() { local i=0; while [ "$i" -lt "${#NAMES[@]}" ]; do [ "${NAMES[$i]}" = "$1" ] && { echo "${IPS[$i]}"; return 0; }; i=$((i+1)); done; return 1; }
# A comma list of names → upper case, each checked against the inventory, one per line.
names_of() {
  local what=$1 list=$2 n
  for n in $(echo "$list" | tr ',' ' '); do
    n=$(upper "$n"); n=${n#NODE_}
    ip_of "$n" >/dev/null || die "$what names '$n', which is not in $NODES_ENV (hosts: ${NAMES[*]})"
    echo "$n"
  done
}
SKIPPED=$(names_of --skip "$SKIP") || exit 1
LASTS=$(names_of --last "$LAST") || exit 1
REFLIST=$(names_of --ref "$REFS") || exit 1
in_list() { case "
$2
" in *"
$1
"*) return 0 ;; esac; return 1; }
ORDER=()
for n in "${NAMES[@]}"; do in_list "$n" "$SKIPPED" || in_list "$n" "$LASTS" || ORDER+=("$n"); done
for n in $LASTS; do in_list "$n" "$SKIPPED" || ORDER+=("$n"); done
[ "${#ORDER[@]}" -gt 0 ] || die "every host is skipped: nothing to roll"
# The reference for a host: the first --ref name that is neither that host nor skipped, else the
# first such host of the inventory.
ref_for() {
  local n
  for n in $REFLIST "${NAMES[@]}"; do
    [ "$n" = "$1" ] && continue
    in_list "$n" "$SKIPPED" && continue
    echo "$n"; return 0
  done
  return 1
}
[ "${#ORDER[@]}" -gt 1 ] || ref_for "${ORDER[0]}" >/dev/null || die "one host and no other to compare it with: there is no reference node"

# ── 2. the release: signature first, before any host ────────────────────────────────────────
BIN_NODE=${BIN_NODE:-rand-node}; BIN_WALLET=${BIN_WALLET:-rand}; SERVICE=${SERVICE:-rand-node}
RPC_ADDR=${RPC_ADDR:-127.0.0.1:8545}
sha_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
if [ -n "${RELEASE_SUMS:-}" ] || [ -n "${RELEASE_SIG:-}" ]; then
  { [ -n "${RELEASE_SUMS:-}" ] && [ -n "${RELEASE_SIG:-}" ]; } || die "RELEASE_SUMS and RELEASE_SIG go together: the release's SHA256SUMS and its SHA256SUMS.sig"
  SIGNED_BY=$(verify_release_sums "$RELEASE_SUMS" "$RELEASE_SIG" 2>&1) || { echo "$SIGNED_BY" >&2; die "the release's signature does not verify — not rolling"; }
  echo "$SIGNED_BY"
  WANT=$(release_sha "$RELEASE_SUMS" "$BIN_NODE") || exit 1
  WANT_WALLET=$(release_sha "$RELEASE_SUMS" "$BIN_WALLET") || exit 1
  [ -z "${WANT_SHA:-}" ] || [ "$WANT_SHA" = "$WANT" ] || die "WANT_SHA is not what the signed SHA256SUMS lists for $BIN_NODE — not rolling"
  [ -z "${WANT_SHA_WALLET:-}" ] || [ "$WANT_SHA_WALLET" = "$WANT_WALLET" ] || die "WANT_SHA_WALLET is not what the signed SHA256SUMS lists for $BIN_WALLET — not rolling"
  AUTH="signed: SHA256SUMS sha256 $(sha_of "$RELEASE_SUMS"), ${SIGNED_BY#verify-release: }"
  export RELEASE_SUMS RELEASE_SIG
else
  [ "${ALLOW_UNSIGNED:-}" = 1 ] || die "refusing an unsigned roll — pass RELEASE_SUMS and RELEASE_SIG (the release's SHA256SUMS and its signature), or ALLOW_UNSIGNED=1 with WANT_SHA and WANT_SHA_WALLET to go ahead anyway"
  { [ -n "${WANT_SHA:-}" ] && [ -n "${WANT_SHA_WALLET:-}" ]; } || die "ALLOW_UNSIGNED=1 needs WANT_SHA and WANT_SHA_WALLET: the record names the binaries rolled, and the gate checks each host against them"
  WANT=$WANT_SHA; WANT_WALLET=$WANT_SHA_WALLET
  AUTH="UNSIGNED (ALLOW_UNSIGNED=1): no signature ties these sha256s to a release"
  echo "roll-fleet: UNSIGNED ROLL (ALLOW_UNSIGNED=1)" >&2
  export ALLOW_UNSIGNED
fi
export WANT_SHA=$WANT WANT_SHA_WALLET=$WANT_WALLET BIN_NODE BIN_WALLET SERVICE
BUILD_HOST=${BUILD_HOST:-$(fleet_ip E)} || exit 1
[ -n "$BUILD_HOST" ] || die "BUILD_HOST is empty (give it, or list NODE_E in NODES_ENV)"
refuse_placeholder BUILD_HOST "$BUILD_HOST"

GATE="height within $WITHIN of the reference, at least $MIN_PEERS peers, service active, installed $BIN_NODE is the release's, reference past its height before the host was stopped; timeout $TIMEOUT s, poll $POLL s"
echo "roll-fleet: release $RELEASE — $BIN_NODE ${WANT:0:12}… $BIN_WALLET ${WANT_WALLET:0:12}…"
echo "roll-fleet: order (${#ORDER[@]}): ${ORDER[*]}"
echo "roll-fleet: skipped: $(echo $SKIPPED | tr '\n' ' ')"
echo "roll-fleet: gate: $GATE"
if [ -n "$DRY" ]; then
  for n in "${ORDER[@]}"; do echo "  would roll $n (reference $(ref_for "$n"))"; done
  echo "roll-fleet: dry run — no host contacted, no record written"
  exit 0
fi

# ── 4 (opened here). the record ─────────────────────────────────────────────────────────────
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
RECORD=${RECORD:-$HERE/roll-records/$RELEASE-$(date -u +%Y%m%dT%H%M%SZ).record}
[ ! -e "$RECORD" ] || die "$RECORD exists — a roll record is never written over (pass --record)"
mkdir -p "$(dirname "$RECORD")" || exit 1
TOOL_AT=$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo "not a git checkout")
[ -z "$(git -C "$HERE" status --porcelain -- . 2>/dev/null)" ] || TOOL_AT="$TOOL_AT, deploy/ modified"
rec() { echo "$*" >> "$RECORD"; }
{
  echo "# Roll record — $RELEASE, one host at a time (a node-only, same-chain roll; no genesis, no cut)."
  echo "#"
  echo "# Written by deploy/roll-fleet.sh as the roll ran (audit v14, PROC-751); not written by hand."
  echo "# Every value on a host: line was read from that host by the gate at the time given. Names"
  echo "# only: the fleet's addresses are the operator's (the private configuration repository)."
  echo
  echo "release: $RELEASE"
  echo "tool: deploy/roll-fleet.sh ($TOOL_AT) calling deploy/update-droplet.sh per host"
  echo "binary: $BIN_NODE sha256 $WANT; $BIN_WALLET sha256 $WANT_WALLET"
  echo "authenticated: $AUTH"
  echo "gate: $GATE"
  echo "order: ${ORDER[*]}"
  echo "skipped: $(if [ -n "$SKIPPED" ]; then echo $SKIPPED; else echo none; fi) (--skip; not contacted)"
  echo "started: $(now)"
} > "$RECORD" || die "cannot write $RECORD"
echo "roll-fleet: record $RECORD"

# One probe of a host: prints "active=<state> sha=<sha256> height=<n> peers=<n>" (a value is empty
# when the host did not give it). `ssh -n`: see the header.
probe() {
  local out status
  # shellcheck disable=SC2029  # expanded here on purpose
  out=$(ssh -n -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o BatchMode=yes "root@$1" \
    "echo \"active=\$(systemctl is-active $SERVICE 2>/dev/null)\"; echo \"sha=\$(sha256sum /usr/local/bin/$BIN_NODE 2>/dev/null | cut -d' ' -f1)\"; echo \"status=\$(curl -s -m 4 -X POST -H content-type:application/json --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_status\",\"params\":[]}' $RPC_ADDR)\"" 2>/dev/null) || out=
  status=$(echo "$out" | sed -n 's/^status=//p')
  echo "active=$(echo "$out" | sed -n 's/^active=//p') sha=$(echo "$out" | sed -n 's/^sha=//p') height=$(echo "$status" | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2) peers=$(echo "$status" | grep -oE '"peer_count":[0-9]+' | head -1 | cut -d: -f2)"
}
field() { echo "$2" | tr ' ' '\n' | sed -n "s/^$1=//p"; }

ROLLED=0
stop_roll() {   # stop_roll <index of the host it stopped at> <why>
  local i=$1 rest=()
  shift
  i=$((i+1)); while [ "$i" -lt "${#ORDER[@]}" ]; do rest+=("${ORDER[$i]}"); i=$((i+1)); done
  rec "result: STOPPED — $*"
  rec "rolled: $ROLLED of ${#ORDER[@]}"
  rec "not-rolled: ${rest[*]:-none}"
  rec "finished: $(now)"
  echo "roll-fleet: STOPPED — $*" >&2
  echo "roll-fleet: not rolled: ${rest[*]:-none}; record $RECORD" >&2
  exit 2
}

# ── 3. one host at a time ───────────────────────────────────────────────────────────────────
idx=0
while [ "$idx" -lt "${#ORDER[@]}" ]; do
  name=${ORDER[$idx]}; ip=$(ip_of "$name"); ref=$(ref_for "$name"); ref_ip=$(ip_of "$ref")
  # a. the reference answers, before this host is touched.
  ref0=; tries=0
  while [ -z "$ref0" ] && [ "$tries" -lt 3 ]; do
    [ "$tries" -eq 0 ] || sleep "$POLL"
    ref0=$(field height "$(probe "$ref_ip")"); tries=$((tries+1))
  done
  [ -n "$ref0" ] || stop_roll $((idx-1)) "before $name: the reference $ref did not answer rand_status ($name not touched)"
  started=$(now)
  echo "== $name ($((idx+1))/${#ORDER[@]}) $started — reference $ref at $ref0"
  # b. the update. stdin from /dev/null: see the header.
  if bash "$HERE/update-droplet.sh" "$ip" "$BUILD_HOST" </dev/null; then :; else
    rc=$?
    rec "host: $name started=$started update=FAILED exit=$rc"
    stop_roll "$idx" "at $name: update-droplet.sh failed (exit $rc); the host's state is whatever that script left — read its output"
  fi
  updated=$(now)
  # c. the rejoin gate.
  SECONDS=0; polls=0; last=
  while :; do
    p=$(probe "$ip"); r=$(probe "$ref_ip"); polls=$((polls+1))
    act=$(field active "$p"); got=$(field sha "$p"); h=$(field height "$p"); peers=$(field peers "$p"); rh=$(field height "$r")
    last="active=${act:-?} $BIN_NODE-sha256=${got:-?} height=${h:-?} peers=${peers:-?} ref=$ref ref-height=${rh:-?} ref-height-before=$ref0"
    if [ "$act" = active ] && [ "$got" = "$WANT" ] && [ -n "$h" ] && [ -n "$peers" ] && [ -n "$rh" ] \
       && [ $((rh - h)) -le "$WITHIN" ] && [ "$peers" -ge "$MIN_PEERS" ] && [ "$rh" -gt "$ref0" ]; then
      break
    fi
    if [ "$SECONDS" -ge "$TIMEOUT" ]; then
      rec "host: $name started=$started updated=$updated rejoined=NO polls=$polls waited=${SECONDS}s last: $last"
      stop_roll "$idx" "at $name: not back in step after ${SECONDS} s ($last)"
    fi
    echo "   $name: waiting ($last)"
    sleep "$POLL"
  done
  rec "host: $name started=$started updated=$updated rejoined=$(now) polls=$polls $last"
  echo "   $name: rejoined ($last)"
  ROLLED=$((ROLLED+1)); idx=$((idx+1))
done
rec "result: complete — every host in the order rolled and rejoined"
rec "rolled: $ROLLED of ${#ORDER[@]}"
rec "not-rolled: none"
rec "finished: $(now)"
echo "ROLL-DONE $(now): $ROLLED hosts; record $RECORD"
