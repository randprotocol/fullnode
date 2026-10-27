#!/usr/bin/env bash
# shellcheck disable=SC2016  # single-quoted remote / bash -c scripts expand on the far side, on purpose
# Cut the fleet over from chain 20 to chain 21 — all-stop, all-start, in phases, over all 26 hosts
# of the CURRENT droplets (the DigitalOcean account is locked: nothing here creates a host): the 20
# hosts of deploy/nodes.env (A–F, the twelve regional validators, obs1, rand-archive-2) and the six
# guardian hosts (their own ssh key; their unit takes its ExecStart from a drop-in).
#
# DERIVED from deploy/cutover-fleet-chain20.sh (chain 20 = v0.6.8, then v0.7.0 from 2026-10-02;
# v0.7.1 was tagged but never rolled — a read-only `status` on 2026-10-12 showed all 26 hosts on
# 0.7.0, git_sha 806ed349; chain 21's predecessor; read it first). The phases, the stop order
# (C and D started first, every phase run alone), the datadir handling (nodes.env units: suffix -<chain-20 prefix> → -<chain-21 prefix>,
# volumes behind symlinks kept; guardian hosts: chain20.conf/data-20 → chain21.conf/data-21, a
# stale data-21 moved aside, never reused), the sha-checked binary backups, the marker that
# licenses `start`, and the rollback are chain 20's. Against chain 20's script:
#
#   * THE BUILD IS v0.8.0 (TAG v0.8.0, WANT_VERSION 0.8.0): fullnode main a1785c95 plus the pre-tag
#     commit, built by .github/workflows/release.yml on the tag. NEED_FLAGS adds --fees, --multisig
#     and --auth-multisig-guest (chain 21's three sections and its one new field).
#   * THE SIGNED SHA256SUMS IS REQUIRED. Chain 20's script took RELEASE_SUMS optionally and fell
#     back to the operator's word; this one refuses `stage`, `push` and `switch` without
#     RELEASE_SUMS and RELEASE_SUMS_SIG (default $RELEASE_SUMS.sig), verifies the signature first
#     (deploy/lib/verify-release.sh, a key in deploy/release-signers), and reads every pin from the
#     signed file: rand-node → WANT_SHA, rand → WANT_SHA_WALLET, msauth-vk-production.bin →
#     WANT_SHA_VK. Any of the three given in the environment must equal the signed value. Each host
#     then checks the sha256 of each file it holds against those pins before keeping a byte.
#   * THE MSAUTH VERIFIER KEY (docs/deploy.md, "The msauth verifier key"): a chain-21 node refuses to
#     start without /usr/local/bin/msauth-vk-production.bin beside its binary. So:
#       - `stage` fetches msauth-vk-production.bin with the binaries (→ /root/msauth-vk-production.bin.c21),
#         checks its sha256 against WANT_SHA_VK, and asks the STAGED rand-node: its
#         `keygen-msauth-vk --check <blob>` must equal its own `--print-pinned production`, and both
#         must be MSAUTH_VK_SHA (68facb06…cd30, the decided blob, 23 754 bytes);
#       - `switch` repeats that check with the staged binary BEFORE it installs anything (the docs
#         snippet, against the build being installed, never a pin read on the laptop), installs the
#         blob 0644 to /usr/local/bin/msauth-vk-production.bin, and re-checks the installed blob with
#         the installed binary;
#       - `start` (after a switch) re-checks every host with its INSTALLED binary before starting
#         any node, refuses the whole start if one host fails, and checks each host once more in the
#         same ssh call as its `systemctl start`: a node whose key is not verified is never started;
#       - `wait` counts a host only when `rand_status.msauth_key` is `loaded`.
#     A start after `rollback` (chain 20, v0.7.0, which has no msauth key) skips the key check.
#   * THE GENESIS MUST BE CHAIN 21'S: chain_id 21, hc_auth_multisig = 9705f8e2…8247 (the decided
#     private-multisig guest), max_proof_bytes 6291456 and max_block_bytes 19922944 (the cut
#     script's decided limits). `push` and `switch` refuse any other file.
#   * `push` refuses unless the cut record (CUT_RECORD, default deploy/cut-records/chain21.record)
#     carries `second-hash: <this genesis hash>` — the second operator's rebuild, deploy/lib/cut-
#     policy.sh `require_second_rebuild`, as deploy/cut-chain21-genesis.sh prints it ("push refuses
#     without it"). SECOND_REBUILD_WAIVED=1 is kept from chain 20 (it printed what the waiver leaves
#     unchecked and appended `second-rebuild-waived: …` to the record); the policy says not to, and
#     the chain-21 record is drafted for a real second operator.
#   * THE OLD BUILD IS OLD_VERSION (default 0.7.0, tag 806ed349 = OLD_GIT_SHA: what chain 20 runs
#     since 2026-10-02), one variable for every old-side check. OLD_SHA / OLD_SHA_WALLET have NO
#     default here (this tree holds no v0.7.0 SHA256SUMS). Give them, or OLD_RELEASE_SUMS (+
#     OLD_RELEASE_SUMS_SIG) — v0.7.0's signed SHA256SUMS, verified with its .sig by
#     verify_release_sums, read for rand-node and rand. preflight (which also reads each node's
#     rand_getVersion: version OLD_VERSION, git_sha OLD_GIT_SHA), the stop gate, switch's *.pre-c21
#     backups and rollback need them. OLD (chain 20's datadir suffix) is 6210cf07.
#   * DRY_RUN=1: every phase prints every remote command (per host list) and every local write,
#     runs no ssh/scp/curl, writes no marker and no record line — touches nothing. Missing inputs
#     (the signed sums, LOCAL_NODE, the genesis) become placeholders, loudly.
#   * SELFTEST=1: exec deploy/rehearse-cutover-fleet-chain21.sh — the whole cutover against 26 FAKE
#     hosts (TEST-NET-1 addresses behind a fake ssh/scp/curl; needs NODE / WALLET, a rand-node and
#     rand built from this tree). Chain 20's script had no SELFTEST of its own; its rehearsal script
#     is the model.
#
# Why all-stop/all-start: v0.8.0 refuses chains 18–20 at startup (constraint set 9), carries the
# compact-blocks wire change (a flag day on any one chain), and chain 21 is a new genesis besides:
# there is no block both chains share. Chain 20 stops committing once a third of the stake is down;
# chain 21 commits once 18 of the 26 are up. All 26 hosts are validators (obs1 and rand-archive-2
# are validator+archive; there is no observer-only node in the fleet), so the compact-blocks
# "observers and archives first" order does not apply to a cut: nothing runs mixed.
#
# Chain 21 keeps every key chain 20 runs (every peer id, every `--bootstrap` and deploy/nodes.env
# stay as they are).
#
#   RELEASE_SUMS=rel/SHA256SUMS OLD_RELEASE_SUMS=old/SHA256SUMS deploy/cutover-fleet-chain21.sh preflight
#                                                      # chain 20 running, READ-ONLY
#   RELEASE_SUMS=rel/SHA256SUMS deploy/cutover-fleet-chain21.sh stage
#                                                      # chain 20 running: v0.8.0 + the msauth blob to /root/*.c21, checked
#   (bridge: deploy/chain21-bridge-steps.md "stop" — relayer + guardians down, BEFORE the snapshot)
#   deploy/cut-chain21-genesis.sh snapshot <dir>       # chain 20 still up
#   WALLET=<v0.7.0 rand> deploy/cut-chain21-genesis.sh balances <dir>
#   (cut: CUT_RECORD=… CHAIN20_SNAPSHOT=<dir> NODE=<v0.8.0 rand-node> WALLET=<v0.8.0 rand> …
#         deploy/cut-chain21-genesis.sh — reads only the snapshot; chain 20 still up)
#   (the second operator re-derives the hash and writes second-hash into the record)
#   LOCAL_NODE=<v0.8.0 rand-node> RELEASE_SUMS=… deploy/cutover-fleet-chain21.sh push <genesis>
#                                                      # chain 20 STILL RUNNING: genesis beside the staged build, checked
#   ── the user's go, typed in the executing session, before anything below ──
#   LOCAL_NODE=… RELEASE_SUMS=… deploy/cutover-fleet-chain21.sh stop <genesis>
#                                                      # GATED: refuses unless all 26 hold the staged files, the
#                                                      # verified key and the pushed genesis; then stops all 26
#   LOCAL_NODE=… RELEASE_SUMS=… OLD_RELEASE_SUMS=… deploy/cutover-fleet-chain21.sh switch <genesis>
#                                                      # key checked, install, init, rewrite — no start; writes the marker
#   deploy/cutover-fleet-chain21.sh start              # every key re-checked; C, D first, then the other 24; a
#                                                      # host that fails is named, rc 1, the marker kept
#   LOCAL_NODE=… deploy/cutover-fleet-chain21.sh wait <genesis>     # until all 26 serve chain 21, key loaded
#   (then: NODE=<v0.8.0 rand-node> deploy/cut-chain21-genesis.sh check-limits <a node's RPC> <genesis>)
#   deploy/cutover-fleet-chain21.sh status             # read-only: version, chain id, height per host
# Rollback (bridge stopped first — deploy/chain21-bridge-steps.md):
#   deploy/cutover-fleet-chain21.sh quiet <genesis>    # read-only: nothing burned or minted on chain 21?
#   deploy/cutover-fleet-chain21.sh halt               # stop a fleet that does not run chain 20 (refuses one that does)
#   OLD_RELEASE_SUMS=… deploy/cutover-fleet-chain21.sh rollback     # chain 20's units / drop-ins and v0.7.0 binaries
#   deploy/cutover-fleet-chain21.sh start              # the rollback marker licenses it (no key check)
#   deploy/cutover-fleet-chain21.sh wait20             # until all 26 serve chain 20 and C's height moves
# A re-cut after a switch: halt, rollback, start, wait20, then push / stop / switch the new genesis.
#
# THE TRAP FROM CHAIN 16 (kept by every script since): `push … | tail && switch … | tail && start`
# ran `start` after `push` had FAILED — a pipeline's exit status is its last command's. So:
#   * run each phase ALONE, never piped, never chained; read `echo $?` before the next one;
#   * `push`, `switch` and `wait` refuse to run without LOCAL_NODE (an executable v0.8.0 rand-node on
#     this machine — the macOS build of the same tag: it re-derives the genesis hash, which every
#     host's staged binary must then re-derive identically);
#   * `start` refuses unless a successful `switch` (or `rollback`) left /tmp/chain21-switched-<tag>
#     (exactly one such marker); `stop`, `halt`, `push`, `stage` and `switch` delete any marker first.
#   * THE ORDER IS NOT CHAIN 20'S: chain 20 stopped before the cut, and the second operator's hash and
#     push came during the downtime. Here chain 20 keeps running through the cut, the second hash
#     and push; `stop <genesis>` is gated on push having reached every host, so a refused cut or an
#     absent second operator never leaves the fleet down.
#
# Env: TAG (v0.8.0), STAGE_FROM (release|url|path) / RELEASE_URL / STAGE_URL / STAGE_DIR (as chain
# 20's: a path holds rand-node, rand and msauth-vk-production.bin), RELEASE_SUMS / RELEASE_SUMS_SIG
# (required: stage, push, switch), WANT_SHA / WANT_SHA_WALLET / WANT_SHA_VK (optional, must agree
# with the signed file), WANT_VERSION (0.8.0), NEED_FLAGS, OLD_SHA / OLD_SHA_WALLET or
# OLD_RELEASE_SUMS / OLD_RELEASE_SUMS_SIG (v0.7.0), OLD (6210cf07), CUT_RECORD (push),
# GUARDIAN_HOSTS (`<index> <ip>` per line; the bridge session's file), LOCAL_NODE, DRY_RUN, SELFTEST.
#
# Nothing here touches keys (/root/keys, /var/lib/randnode/node.key.json) or the guardian daemons
# (the bridge steps own those; `switch` and `rollback` refuse a guardian host whose rand-guardian
# is still active).
#
# Rollback by hand (if `rollback` itself cannot run): on a nodes.env host restore
# /root/rand-node.service.$OLD.bak over the unit and /root/rand-node.pre-c21, /root/rand.pre-c21 over
# /usr/local/bin; on a guardian host move /root/chain20.conf.c20 back into
# /etc/systemd/system/rand-node.service.d/, delete chain21.conf, restore the same two binaries;
# daemon-reload; start. /usr/local/bin/msauth-vk-production.bin may stay: v0.7.0 never reads it.
# Chain 20 resumes from the height it stopped at: its data dirs are never touched here — retire
# them with deploy/retire-chain-dirs.sh only once chain 21 has run a day (it deletes the rollback
# target too).
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${SELFTEST:-}" = 1 ]; then exec bash deploy/rehearse-cutover-fleet-chain21.sh "$@"; fi
# shellcheck disable=SC1091  # sourced from the repo root (the cd above)
. deploy/lib/cut-policy.sh
# shellcheck disable=SC1091
. deploy/lib/verify-release.sh

PHASE=${1:?preflight|stage|push|stop|switch|start|wait|status|halt|quiet|rollback|wait20}
DRY=${DRY_RUN:-0}
TAG=${TAG:-v0.8.0}
STAGE_FROM=${STAGE_FROM:-release}
RELEASE_URL=${RELEASE_URL:-https://github.com/randprotocol/fullnode/releases/download/$TAG}
STAGE_URL=${STAGE_URL:-}
STAGE_DIR=${STAGE_DIR:-}
RELEASE_SUMS=${RELEASE_SUMS:-}
RELEASE_SUMS_SIG=${RELEASE_SUMS_SIG:-${RELEASE_SUMS:+$RELEASE_SUMS.sig}}
WANT_SHA=${WANT_SHA:-}                 # v0.8.0 Linux rand-node — read from the signed SHA256SUMS
WANT_SHA_WALLET=${WANT_SHA_WALLET:-}   # v0.8.0 Linux rand
WANT_SHA_VK=${WANT_SHA_VK:-}           # msauth-vk-production.bin
WANT_VERSION=${WANT_VERSION:-0.8.0}
NEED_FLAGS=${NEED_FLAGS:---testnet --binding-domain --proof-window-blocks --max-gas-price --gas-byte-load --program-state-cell-fee --fees --multisig --auth-multisig-guest}
# The decided msauth verifier key (docs/deploy.md; circuits d217252, constraint set 9) and the
# decided private-multisig guest and limits (deploy/cut-chain21-genesis.sh). Not overridable: another
# blob or guest edits this script, the cut script and docs/deploy.md together.
MSAUTH_VK_SHA=68facb06c7f321aaf1d4d541acf6b5c0e9d7f17788ed1c9add6c5a8a8f7acd30
MSAUTH_VK_BYTES=23754
HC_AUTH_MULTISIG=9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247
MAX_PROOF_BYTES=6291456
MAX_BLOCK_BYTES=19922944
VK=msauth-vk-production.bin
# The build chain 20 runs (one variable; see the header). Its binary pins have no default.
OLD_SHA=${OLD_SHA:-}
OLD_SHA_WALLET=${OLD_SHA_WALLET:-}
OLD_RELEASE_SUMS=${OLD_RELEASE_SUMS:-}
OLD_RELEASE_SUMS_SIG=${OLD_RELEASE_SUMS_SIG:-${OLD_RELEASE_SUMS:+$OLD_RELEASE_SUMS.sig}}
OLD_VERSION=${OLD_VERSION:-0.7.0}
OLD_GIT_SHA=${OLD_GIT_SHA:-806ed349e52a25045455f3e4a84bdb941daddc60}   # tag v0.7.0, what rand_getVersion reports
[[ "$OLD_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$OLD_GIT_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "OLD_VERSION / OLD_GIT_SHA are not a version and a 40-hex commit" >&2; exit 1; }
# Chain 20's datadir suffix on the nodes.env hosts: its genesis hash prefix (6210cf07…5135).
OLD=${OLD:-6210cf07}
CUT_RECORD=${CUT_RECORD:-deploy/cut-records/chain21.record}
GUARDIAN_HOSTS=${GUARDIAN_HOSTS:-$HOME/.rand-bridge/mainnet-set1/hosts.txt}
MARKER_GLOB=${MARKER_GLOB:-/tmp/chain21-switched-}
OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -o BatchMode=yes)
GOPTS=(-i "$HOME/.ssh/rand_guardian_ed25519" -o IdentitiesOnly=yes -o "UserKnownHostsFile=$HOME/.ssh/rand_guardian_known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=20 -o BatchMode=yes)
# What goes into a single-quoted remote string must not be able to leave it (M4): no quote,
# semicolon, space or shell metacharacter in the URLs and the version; NEED_FLAGS is a
# space-separated list of --flags and nothing else.
for v in RELEASE_URL STAGE_URL WANT_VERSION; do
  case "${!v}" in *[\'\;\ \"\`\$\\\|\<\>\(\)\{\}]*) echo "$v contains a quote, ';', a space or a shell metacharacter — refused" >&2; exit 1;; esac
done
for f in $NEED_FLAGS; do [[ "$f" =~ ^--[a-z0-9-]+$ ]] || { echo "NEED_FLAGS: '$f' is not a --flag — refused" >&2; exit 1; }; done
BOOTS=${BOOTS:-203.0.113.23 203.0.113.25}   # C, D — started first, as in every cut
# shellcheck disable=SC2046,SC2005  # word-split on purpose: one space-separated list
IPS=$(echo $(grep -oE '/ip4/[0-9.]+' deploy/nodes.env | cut -d/ -f3 | sort -u))   # 20: A–F, 12 regional, obs1, archive-2
NIPS=$(wc -w <<<"$IPS" | tr -d ' ')
[ "$NIPS" -eq 20 ] || { echo "deploy/nodes.env names $NIPS hosts, expected 20" >&2; exit 1; }
[ -f "$GUARDIAN_HOSTS" ] || { echo "missing $GUARDIAN_HOSTS" >&2; exit 1; }
# shellcheck disable=SC2046,SC2005
GUARDS=$(echo $(awk '$1 ~ /^[1-6]$/ {print $2}' "$GUARDIAN_HOSTS"))
NG=$(wc -w <<<"$GUARDS" | tr -d ' ')
for ip in $GUARDS; do [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "$GUARDIAN_HOSTS: '$ip' is not an IPv4 address" >&2; exit 1; }; done
[ "$NG" -eq 6 ] || { echo "$GUARDIAN_HOSTS names $NG guardian hosts, expected 6" >&2; exit 1; }
ALL="$IPS $GUARDS"
for ip in $BOOTS; do case " $IPS " in *" $ip "*) ;; *) echo "bootstrap $ip is not in deploy/nodes.env" >&2; exit 1;; esac; done
BOOT1=${BOOTS%% *}
[[ "$OLD" =~ ^[0-9a-f]{8}$ ]] || { echo "OLD=$OLD is not an 8-hex genesis prefix" >&2; exit 1; }

dry() { [ "$DRY" = 1 ]; }
# A missing input: refused on a real run; a placeholder (printed) in a dry run.
missing() { # <message> <placeholder variable> <placeholder>
  if dry; then echo "== DRY RUN: $1 — using placeholder $3" >&2; printf -v "$2" '%s' "$3"
  else echo "$PHASE: $1 — nothing done" >&2; exit 1; fi
}
is_guard() { case " $GUARDS " in *" $1 "*) return 0;; esac; return 1; }
on() {
  local ip=$1; shift
  if dry; then echo "[dry-run] ssh root@$ip $*"; return 0; fi
  if is_guard "$ip"; then ssh -n "${GOPTS[@]}" "root@$ip" "$@"; else ssh -n "${OPTS[@]}" "root@$ip" "$@"; fi
}
cp_to() {
  local ip=$1 dst=$2; shift 2
  if dry; then echo "[dry-run] scp $* root@$ip:$dst"; return 0; fi
  if is_guard "$ip"; then scp -q "${GOPTS[@]}" "$@" "root@$ip:$dst"; else scp -q "${OPTS[@]}" "$@" "root@$ip:$dst"; fi
}
each() {  # run a remote script on every host in parallel, the last line of output each; fail if any failed
  if dry; then
    printf '[dry-run] on each of %s hosts (%s) in parallel, over ssh as root (guardian hosts with %s):\n' \
      "$(wc -w <<<"$ALL" | tr -d ' ')" "$ALL" "$HOME/.ssh/rand_guardian_ed25519"
    printf '%s\n' "$1" | sed 's/^/[dry-run] | /'
    return 0
  fi
  local ip dir; dir=$(mktemp -d)
  for ip in $ALL; do ( on "$ip" "$1" > "$dir/$ip" 2>&1 && echo ok >> "$dir/$ip.rc" || echo FAIL >> "$dir/$ip.rc" ) & done; wait
  local bad=0
  for ip in $ALL; do printf '   %-16s %s %s\n' "$ip" "$(cat "$dir/$ip.rc")" "$(tail -1 "$dir/$ip")"; [ "$(cat "$dir/$ip.rc")" = ok ] || bad=1; done
  rm -rf "$dir"; return $bad
}
rpc() { dry && { on "$1" "curl -s -m5 -X POST 127.0.0.1:8545 … $2" >&2; return 0; }
  on "$1" "curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}'" 2>/dev/null || true; }
local_write() { # <description> <command…>: a write on this machine; printed only in a dry run
  local what=$1; shift
  if dry; then echo "[dry-run] local: $what"; else "$@"; fi
}
clear_markers() { local_write "rm -f $MARKER_GLOB*" bash -c 'rm -f "$1"*' _ "$MARKER_GLOB"; }

# The v0.8.0 pins, from the signed SHA256SUMS only (PROC-5; the coordinator's rule for this cut).
need_new_shas() {
  local got name var
  if [ -z "$RELEASE_SUMS" ]; then
    missing "RELEASE_SUMS is unset — the v0.8.0 release's SHA256SUMS (signed: SHA256SUMS.sig beside it) is required" \
      WANT_SHA "<rand-node sha256 from the signed SHA256SUMS>"
    WANT_SHA_WALLET="<rand sha256 from the signed SHA256SUMS>"; WANT_SHA_VK="<$VK sha256 from the signed SHA256SUMS>"
    return 0
  fi
  verify_release_sums "$RELEASE_SUMS" "$RELEASE_SUMS_SIG" || { echo "$PHASE: the v0.8.0 SHA256SUMS signature does not verify — nothing done" >&2; exit 1; }
  for name in rand-node:WANT_SHA rand:WANT_SHA_WALLET "$VK:WANT_SHA_VK"; do
    var=${name#*:}; name=${name%%:*}
    got=$(release_sha "$RELEASE_SUMS" "$name") || { echo "$PHASE: the signed SHA256SUMS lists no $name — nothing done" >&2; exit 1; }
    [ -z "${!var}" ] || [ "${!var}" = "$got" ] || { echo "$PHASE: $var=${!var} is not what the signed SHA256SUMS lists for $name ($got) — nothing done" >&2; exit 1; }
    printf -v "$var" '%s' "$got"
  done
  [ "$WANT_SHA_VK" = "$MSAUTH_VK_SHA" ] || { echo "$PHASE: the signed SHA256SUMS lists $VK at $WANT_SHA_VK, not the decided blob $MSAUTH_VK_SHA — nothing done" >&2; exit 1; }
  [ -z "$OLD_SHA" ] || [ "$WANT_SHA" != "$OLD_SHA" ] || { echo "$PHASE: the signed rand-node is chain 20's v$OLD_VERSION — chain 21 needs v$WANT_VERSION; nothing done" >&2; exit 1; }
  echo "== the signed SHA256SUMS ($RELEASE_SUMS) pins rand-node ${WANT_SHA:0:12}…, rand ${WANT_SHA_WALLET:0:12}…, $VK ${WANT_SHA_VK:0:12}…"
}
need_old_shas() {
  local got
  if [ -z "$OLD_SHA" ] && [ -n "$OLD_RELEASE_SUMS" ]; then
    verify_release_sums "$OLD_RELEASE_SUMS" "$OLD_RELEASE_SUMS_SIG" || { echo "$PHASE: the v$OLD_VERSION SHA256SUMS signature does not verify — nothing done" >&2; exit 1; }
    OLD_SHA=$(release_sha "$OLD_RELEASE_SUMS" rand-node) || exit 1
    got=$(release_sha "$OLD_RELEASE_SUMS" rand) || exit 1
    [ -z "$OLD_SHA_WALLET" ] || [ "$OLD_SHA_WALLET" = "$got" ] || { echo "$PHASE: OLD_SHA_WALLET is not what v$OLD_VERSION's signed SHA256SUMS lists" >&2; exit 1; }
    OLD_SHA_WALLET=$got
  fi
  if [[ ! "$OLD_SHA" =~ ^[0-9a-f]{64}$ || ! "$OLD_SHA_WALLET" =~ ^[0-9a-f]{64}$ ]]; then
    missing "OLD_SHA / OLD_SHA_WALLET (or OLD_RELEASE_SUMS) must give the sha256 of chain 20's v$OLD_VERSION Linux rand-node / rand" \
      OLD_SHA "<v$OLD_VERSION rand-node sha256>"
    OLD_SHA_WALLET="<v$OLD_VERSION rand sha256>"
  fi
}
need_local_node() {
  local f help
  if [ -z "${LOCAL_NODE:-}" ]; then
    dry && { echo "== DRY RUN: LOCAL_NODE is unset — the real run refuses (the chain-16 trap); hash checks become placeholders" >&2; LOCAL_NODE=; return 0; }
    echo "$PHASE: LOCAL_NODE is unset — point it at a v$WANT_VERSION rand-node on this machine; nothing done (the chain-16 trap)" >&2; exit 1
  fi
  [ -x "$LOCAL_NODE" ] || { echo "$PHASE: LOCAL_NODE=$LOCAL_NODE is not executable — nothing done" >&2; exit 1; }
  help=$("$LOCAL_NODE" genesis --help)
  for f in $NEED_FLAGS; do grep -q -- "$f" <<<"$help" || { echo "$PHASE: $LOCAL_NODE has no $f (not the v$WANT_VERSION build) — nothing done" >&2; exit 1; }; done
  case "$("$LOCAL_NODE" --version)" in "rand-node $WANT_VERSION"*) ;; *) echo "$PHASE: $LOCAL_NODE is $("$LOCAL_NODE" --version), not rand-node $WANT_VERSION — nothing done" >&2; exit 1;; esac
}
genesis_hash() {
  local d h
  if [ -z "${LOCAL_NODE:-}" ]; then echo "<genesis hash: LOCAL_NODE unset>"; return 0; fi
  d=$(mktemp -d); h=$("$LOCAL_NODE" init --datadir "$d/p" --genesis "$1" | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2 || true); rm -rf "$d"; echo "$h"
}
# The file must BE chain 21's genesis, with private multisig at the decided guest and limits: a
# chain-20 file pushed by mistake would "switch" the fleet onto a fresh copy of the wrong chain,
# and one without hc_auth_multisig would not be the chain the user decided to cut.
need_chain21_genesis() {
  if [ ! -f "$1" ]; then
    dry && { echo "== DRY RUN: $1 is not a file (the cut has not run) — genesis checks skipped" >&2; return 0; }
    echo "$PHASE: $1 is not a file — nothing done" >&2; exit 1
  fi
  local why
  why=$(python3 - "$1" "$HC_AUTH_MULTISIG" "$MAX_PROOF_BYTES" "$MAX_BLOCK_BYTES" <<'PY'
import json, sys
try:
    g = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"is not JSON ({e})"); sys.exit(0)
if g.get("chain_id") != 21: print(f"has chain_id {g.get('chain_id')}, not 21"); sys.exit(0)
if g.get("hc_auth_multisig") != sys.argv[2]: print(f"has hc_auth_multisig {g.get('hc_auth_multisig')}, not the decided {sys.argv[2]}"); sys.exit(0)
if g.get("max_proof_bytes") != int(sys.argv[3]): print(f"has max_proof_bytes {g.get('max_proof_bytes')}, not {sys.argv[3]}"); sys.exit(0)
if g.get("max_block_bytes") != int(sys.argv[4]): print(f"has max_block_bytes {g.get('max_block_bytes')}, not {sys.argv[4]}"); sys.exit(0)
PY
)
  [ -z "$why" ] || { echo "$PHASE: $1 $why — nothing done" >&2; exit 1; }
}
file_sha() { if [ -f "$1" ]; then shasum -a 256 "$1" | cut -d' ' -f1; else echo "<sha256 of $1>"; fi; }

# The remote check every phase after `stage` shares: the staged files are the pinned v0.8.0 ones.
# A function, not a string: the pins exist only once need_new_shas has read the signed sums.
staged_ok() {
  echo "[ \"\$(sha256sum /root/rand-node.c21 2>/dev/null | cut -d' ' -f1)\" = '$WANT_SHA' ] && [ \"\$(sha256sum /root/rand.c21 2>/dev/null | cut -d' ' -f1)\" = '$WANT_SHA_WALLET' ] && [ \"\$(sha256sum /root/$VK.c21 2>/dev/null | cut -d' ' -f1)\" = '$WANT_SHA_VK' ] || { echo 'the v$WANT_VERSION files are not staged (/root/rand-node.c21, /root/rand.c21, /root/$VK.c21 with the pinned sha256s)'; exit 1; }"
}
# The msauth key check of docs/deploy.md, with the binary named: <rand-node> <blob>. Its own
# --check must equal its own --print-pinned production, and that must be the decided blob.
vk_check() {
  echo "vk_got=\$($1 keygen-msauth-vk --check $2) && vk_pin=\$($1 keygen-msauth-vk --print-pinned production) && [ \"\$vk_got\" = \"\$vk_pin\" ] && [ \"\$vk_pin\" = '$MSAUTH_VK_SHA' ] && [ \"\$(wc -c < $2 | tr -d ' ')\" = '$MSAUTH_VK_BYTES' ] || { echo \"msauth key NOT verified: $2 is \${vk_got:-unreadable}, $1 pins \${vk_pin:-nothing}, decided $MSAUTH_VK_SHA\"; exit 1; }"
}
# What a staged rand-node must say about itself, and about the staged blob.
staged_self() {
  echo "./rand-node.c21 --version | grep -q 'rand-node $WANT_VERSION' || { echo \"staged rand-node is \$(./rand-node.c21 --version 2>&1 | head -1), not $WANT_VERSION\"; exit 1; }
    H=\$(./rand-node.c21 genesis --help); for f in $NEED_FLAGS; do printf '%s' \"\$H\" | grep -q -- \"\$f\" || { echo \"staged rand-node has no \$f\"; exit 1; }; done
    $(vk_check ./rand-node.c21 ./$VK.c21)"
}

# The genesis a phase was given, checked once: chain 21's, the hash this machine's v0.8.0 derives
# (NEW, prefix P), its sha256 (SHA). Every phase that acts on a genesis calls it.
need_genesis() {
  GENESIS=$1
  need_chain21_genesis "$GENESIS"
  SHA=$(file_sha "$GENESIS")
  NEW=$(genesis_hash "$GENESIS")
  if [ ${#NEW} -eq 64 ]; then P=${NEW:0:8}
  elif dry; then P="<8-hex genesis prefix>"
  else echo "$PHASE: $LOCAL_NODE derived no genesis hash from $GENESIS — nothing done" >&2; exit 1; fi
  [ "$P" != "$OLD" ] || { echo "$PHASE: $GENESIS is chain 20's genesis ($NEW) — nothing done" >&2; exit 1; }
}
# OPS-7: the second operator rebuilt this hash (`second-hash:`), or push recorded a waiver for it.
# push writes the waiver; stop and switch only read it (defence in depth: each re-checks).
second_rebuild_ok() {
  if dry && [ ${#NEW} -ne 64 ]; then
    echo "[dry-run] local: require_second_rebuild $CUT_RECORD <genesis hash> — the record's second-hash: must equal it"; return 0; fi
  if grep -q "^second-rebuild-waived: .*genesis $NEW" "$CUT_RECORD" 2>/dev/null; then
    echo "== ⚠ the cut record carries a second-rebuild WAIVER for genesis $NEW (no second operator's hash)"; return 0; fi
  if require_second_rebuild "$CUT_RECORD" "$NEW"; then return 0; fi
  if dry; then echo "== DRY RUN: the real $PHASE REFUSES here (above); the dry run goes on to show the rest"; return 0; fi
  echo "$PHASE: nothing done" >&2; exit 1
}
# The remote check that a host holds the pushed genesis and the staged build re-derives its hash
# (run from /root).
pushed_ok() {
  echo "[ \"\$(sha256sum /root/genesis-chain21.json 2>/dev/null | cut -d' ' -f1)\" = '$SHA' ] || { echo 'the chain-21 genesis is not pushed here (sha256 differs or no file)'; exit 1; }
    rm -rf /root/probe-c21
    H=\$(/root/rand-node.c21 init --datadir /root/probe-c21 --genesis /root/genesis-chain21.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf /root/probe-c21
    [ \"\$H\" = '$NEW' ] || { echo \"genesis hash \$H, expected $NEW\"; exit 1; }"
}
# Stop every host's rand-node and fail (non-zero) when one is still active.
stop_all() {
  each 'systemctl stop rand-node; if systemctl is-active --quiet rand-node; then echo "$(hostname) STILL ACTIVE"; exit 1; fi; echo "$(hostname) stopped"' \
    || { echo "$PHASE: some hosts did not stop (above) — stop them by hand; switch and rollback refuse a running node" >&2; exit 1; }
}

case "$PHASE" in
preflight)
  need_old_shas
  echo "== preflight (read-only) on $(wc -w <<<"$ALL" | tr -d ' ') hosts: installed v$OLD_VERSION rand-node ${OLD_SHA:0:12}…, rand ${OLD_SHA_WALLET:0:12}…, chain-20 datadir -$OLD / data-20 $(date -u +%T)"
  each "set -e
    [ \"\$(sha256sum /usr/local/bin/rand-node | cut -d' ' -f1)\" = '$OLD_SHA' ] || { echo \"installed rand-node is \$(/usr/local/bin/rand-node --version 2>&1 | head -1) sha256 \$(sha256sum /usr/local/bin/rand-node | cut -c1-12)…, not chain 20's v$OLD_VERSION ${OLD_SHA:0:12}…\"; exit 1; }
    [ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$OLD_SHA_WALLET' ] || { echo \"installed rand is sha256 \$(sha256sum /usr/local/bin/rand | cut -c1-12)…, not chain 20's v$OLD_VERSION\"; exit 1; }
    [ ! -e /root/rand-node.pre-c21 ] && [ ! -e /root/rand.pre-c21 ] || { echo 'a *.pre-c21 binary backup already exists (an earlier switch?)'; exit 1; }
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain20.conf ] || [ -f \$D/chain21.conf ]; then
      [ -f \$D/chain20.conf ] && [ ! -f \$D/chain21.conf ] || { echo 'a chain21.conf drop-in is already present'; exit 1; }
      grep -q -- '--datadir /var/lib/randnode/data-20 ' \$D/chain20.conf || { echo 'chain20.conf has no data-20 datadir'; exit 1; }
      [ ! -e /var/lib/randnode/data-21 ] || { echo '/var/lib/randnode/data-21 already exists — move it aside'; exit 1; }
      [ ! -e /root/chain20.conf.c20 ] || { echo '/root/chain20.conf.c20 already exists (an earlier switch?)'; exit 1; }
      KIND=guardian-host
    else
      grep -q -- '-$OLD ' /etc/systemd/system/rand-node.service || { echo 'unit has no -$OLD datadir'; exit 1; }
      KIND=node
    fi
    G=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getGenesisHash\",\"params\":[]}' | grep -oE '\"result\":\"[0-9a-f]+\"' | cut -d'\"' -f4)
    case \"\$G\" in $OLD*) ;; *) echo \"serves genesis \${G:-nothing}, not chain 20 ($OLD…)\"; exit 1;; esac
    curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}' | grep -q '\"status\":\"ok\"' || { echo 'rand_getHealth is not ok'; exit 1; }
    VER=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getVersion\",\"params\":[]}')
    printf '%s' \"\$VER\" | grep -q '\"version\":\"$OLD_VERSION\"' && printf '%s' \"\$VER\" | grep -q '\"git_sha\":\"$OLD_GIT_SHA\"' \\
      || { echo \"rand_getVersion answers \$(printf '%s' \"\$VER\" | grep -oE '\"(version|git_sha)\":\"[^\"]*\"' | tr '\\n' ' '), not $OLD_VERSION / ${OLD_GIT_SHA:0:8}\"; exit 1; }
    S=\$( [ -e /root/rand-node.c21 ] && echo ', a staged rand-node.c21 present' || echo ', nothing staged yet')
    K=\$( [ -e /usr/local/bin/$VK ] && echo \", an msauth blob already installed (sha256 \$(sha256sum /usr/local/bin/$VK | cut -c1-12)…; switch replaces it)\" || echo '')
    echo \"\$(hostname) \$KIND ready: \$(/usr/local/bin/rand-node --version), on chain 20, healthy, \$(df -h / | tail -1 | awk '{print \$4}') free\$S\$K\"" \
    || { echo "preflight: not every host is ready — fix those before staging or stopping anything" >&2; exit 1; }
  echo "PREFLIGHT OK — nothing was changed"
  ;;
stage)
  clear_markers
  need_new_shas
  case "$STAGE_FROM" in
    release|url)
      if [ "$STAGE_FROM" = url ]; then
        [ -n "$STAGE_URL" ] || { echo "stage: STAGE_FROM=url needs STAGE_URL (a private base URL holding rand-node, rand and $VK) — nothing staged" >&2; exit 1; }
        BASE=$STAGE_URL; SHOWN="${STAGE_URL%%\?*}"; SHOWN="${SHOWN%/*}/…"
      else BASE=$RELEASE_URL; SHOWN=$RELEASE_URL; fi
      case "$BASE" in
        https://*) ;;
        http://*)
          if [ "$STAGE_FROM" = url ] && [ "${STAGE_ALLOW_HTTP:-0}" = 1 ]; then
            echo "== ⚠ STAGE_ALLOW_HTTP=1: staging from plain http:// ($SHOWN) — the sha256 pins are the only integrity check" >&2
          else
            echo "stage: $SHOWN is not https:// — nothing staged (STAGE_ALLOW_HTTP=1 allows a private STAGE_FROM=url over http; the sha256 pins still decide)" >&2; exit 1
          fi ;;
        *) echo "stage: $SHOWN is not https:// — nothing staged" >&2; exit 1;;
      esac
      Q=""; case "$BASE" in *\?*) Q="?${BASE#*\?}"; BASE=${BASE%%\?*};; esac
      echo "== stage $TAG + $VK on $(wc -w <<<"$ALL" | tr -d ' ') hosts from $SHOWN $(date -u +%T)"
      # Each host fetches the three files itself and checks every pin; a mismatch deletes what it fetched.
      each "set -e; cd /root
        rm -f rand-node.c21.part rand.c21.part $VK.c21.part
        curl -fsSL --retry 10 --retry-all-errors --retry-delay 5 -o rand-node.c21.part '$BASE/rand-node$Q'
        curl -fsSL --retry 10 --retry-all-errors --retry-delay 5 -o rand.c21.part '$BASE/rand$Q'
        curl -fsSL --retry 10 --retry-all-errors --retry-delay 5 -o $VK.c21.part '$BASE/$VK$Q'
        if [ \"\$(sha256sum rand-node.c21.part | cut -d' ' -f1)\" != '$WANT_SHA' ] || [ \"\$(sha256sum rand.c21.part | cut -d' ' -f1)\" != '$WANT_SHA_WALLET' ] || [ \"\$(sha256sum $VK.c21.part | cut -d' ' -f1)\" != '$WANT_SHA_VK' ]; then
          rm -f rand-node.c21.part rand.c21.part $VK.c21.part; echo 'SHA MISMATCH — removed'; exit 1; fi
        chmod 755 rand-node.c21.part rand.c21.part; chmod 644 $VK.c21.part
        mv rand-node.c21.part rand-node.c21; mv rand.c21.part rand.c21; mv $VK.c21.part $VK.c21
        $(staged_self)
        echo \"\$(hostname) staged \$(./rand-node.c21 --version), msauth key \${vk_pin:0:12}… verified, \$(df -h / | tail -1 | awk '{print \$4}') free\"" \
        || { echo "stage: not every host staged — fix those before stopping anything" >&2; exit 1; }
      ;;
    path)
      [ -n "$STAGE_DIR" ] && [ -f "$STAGE_DIR/rand-node" ] && [ -f "$STAGE_DIR/rand" ] && [ -f "$STAGE_DIR/$VK" ] \
        || { echo "stage: STAGE_FROM=path needs STAGE_DIR holding rand-node, rand and $VK (the v$WANT_VERSION release assets) — nothing staged" >&2; exit 1; }
      verify_binary "$STAGE_DIR/rand-node" "$RELEASE_SUMS" rand-node || { echo "stage: $STAGE_DIR/rand-node is not the signed rand-node — nothing staged" >&2; exit 1; }
      verify_binary "$STAGE_DIR/rand" "$RELEASE_SUMS" rand || { echo "stage: $STAGE_DIR/rand is not the signed rand — nothing staged" >&2; exit 1; }
      verify_binary "$STAGE_DIR/$VK" "$RELEASE_SUMS" "$VK" || { echo "stage: $STAGE_DIR/$VK is not the signed blob — nothing staged" >&2; exit 1; }
      if [ "${STAGE_ALLOW_NON_ELF:-}" != 1 ]; then
        for b in rand-node rand; do
          [ "$(head -c 4 "$STAGE_DIR/$b" | od -An -c | tr -d ' ')" = '177ELF' ] \
            || { echo "stage: $STAGE_DIR/$b is not a Linux ELF binary (a macOS build?) — nothing staged" >&2; exit 1; }
        done
      fi
      echo "== stage $TAG + $VK on $(wc -w <<<"$ALL" | tr -d ' ') hosts from $STAGE_DIR (laptop scp — slow; signed sha256s checked here first) $(date -u +%T)"
      for ip in $ALL; do ( on "$ip" "rm -f /root/rand-node.c21.part /root/rand.c21.part /root/$VK.c21.part" \
        && cp_to "$ip" /root/rand-node.c21.part "$STAGE_DIR/rand-node" && cp_to "$ip" /root/rand.c21.part "$STAGE_DIR/rand" \
        && cp_to "$ip" "/root/$VK.c21.part" "$STAGE_DIR/$VK" ) & done; wait
      each "set -e; cd /root
        [ -f rand-node.c21.part ] && [ -f rand.c21.part ] && [ -f $VK.c21.part ] || { echo 'the copy did not arrive'; exit 1; }
        if [ \"\$(sha256sum rand-node.c21.part | cut -d' ' -f1)\" != '$WANT_SHA' ] || [ \"\$(sha256sum rand.c21.part | cut -d' ' -f1)\" != '$WANT_SHA_WALLET' ] || [ \"\$(sha256sum $VK.c21.part | cut -d' ' -f1)\" != '$WANT_SHA_VK' ]; then
          rm -f rand-node.c21.part rand.c21.part $VK.c21.part; echo 'SHA MISMATCH after copy — removed'; exit 1; fi
        chmod 755 rand-node.c21.part rand.c21.part; chmod 644 $VK.c21.part
        mv rand-node.c21.part rand-node.c21; mv rand.c21.part rand.c21; mv $VK.c21.part $VK.c21
        $(staged_self)
        echo \"\$(hostname) staged \$(./rand-node.c21 --version), msauth key \${vk_pin:0:12}… verified, \$(df -h / | tail -1 | awk '{print \$4}') free\"" \
        || { echo "stage: not every host staged — fix those before stopping anything" >&2; exit 1; }
      ;;
    *) echo "stage: STAGE_FROM=$STAGE_FROM — release, url or path" >&2; exit 1;;
  esac
  echo "STAGED $(date -u +%T) — nothing was installed; the fleet still runs chain 20 on v$OLD_VERSION"
  ;;
stop)
  # Chain 20 keeps running through stage, the cut, the second operator's hash and push; stop is the
  # first phase that takes it down, and it refuses unless every host is ready to switch at once.
  GENESIS=${2:?stop <genesis file> — stop is gated on push: every host must hold the staged v0.8.0 files and the pushed genesis (halt stops a fleet that does not run chain 20)}
  clear_markers
  need_local_node
  need_new_shas
  need_old_shas
  need_genesis "$GENESIS"
  second_rebuild_ok
  echo "== stop gate on $(wc -w <<<"$ALL" | tr -d ' ') hosts: the staged v$WANT_VERSION files at their pins, the staged key verified, the pushed genesis $NEW $(date -u +%T)"
  each "set -e; cd /root
    $(staged_ok)
    $(staged_self)
    $(pushed_ok)
    # What switch will need of the installed build, checked while chain 20 can still run: v$OLD_VERSION
    # installed (or already backed up), and on a guardian host no rand-guardian running.
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET; do n=\${b%%:*}; s=\${b#*:}
      [ -e /root/\$n.pre-c21 ] || [ \"\$(sha256sum /usr/local/bin/\$n | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"installed \$n is not chain 20's v$OLD_VERSION binary (switch would refuse it)\"; exit 1; }
    done
    if [ -f /etc/systemd/system/rand-node.service.d/chain20.conf ] || [ -f /etc/systemd/system/rand-node.service.d/chain21.conf ]; then
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it before the stop'; exit 1; }
    fi
    echo \"\$(hostname) ready: staged v$WANT_VERSION, msauth key \${vk_pin:0:12}… verified, genesis $NEW pushed\"" \
    || { echo "stop: not every host is ready (above) — NOTHING STOPPED; chain 20 keeps running. Re-run stage / push for those hosts" >&2; exit 1; }
  echo "== stop all 26 $(date -u +%T)"
  H0=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
  echo "   chain 20 head at C: ${H0:-?}"
  stop_all
  echo "STOPPED $(date -u +%T) — next: switch $GENESIS (alone; check \$?)"
  ;;
halt)
  # Stop a fleet that does NOT run chain 20: chain 21 before a rollback, or before a re-cut's push.
  # A host still running chain 20 is refused here — taking chain 20 down is `stop <genesis>`'s, gated.
  clear_markers
  echo "== halt: no host may be running chain 20 (its datadir -$OLD / data-20) $(date -u +%T)"
  each "D=\$(systemctl cat rand-node 2>/dev/null | grep -o -- '--datadir [^ ]*' | tail -1 | cut -d' ' -f2)
    if systemctl is-active --quiet rand-node; then
      [ -n \"\$D\" ] || { echo \"\$(hostname) is active and its unit names no --datadir — cannot tell its chain; refusing\"; exit 1; }
      case \"\$D\" in *-$OLD|*/data-20) echo \"\$(hostname) RUNS CHAIN 20 (\$D) — use stop <genesis>\"; exit 1;; esac
      G=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getGenesisHash\",\"params\":[]}' | grep -oE '\"result\":\"[0-9a-f]+\"' | cut -d'\"' -f4 || true)
      case \"\$G\" in $OLD*) echo \"\$(hostname) SERVES CHAIN 20's genesis \$G — use stop <genesis>\"; exit 1;; esac
    fi
    echo \"\$(hostname) may halt (\$(systemctl is-active rand-node || true), \$D)\"" \
    || { echo "halt: a host runs chain 20 — nothing halted; chain 20 is stopped only by \`stop <genesis>\`" >&2; exit 1; }
  stop_all
  echo "HALTED $(date -u +%T) — next: rollback (or push + switch for a re-cut)"
  ;;
push)
  # Chain 20 is still RUNNING here: push only copies the genesis beside the staged build and checks it.
  need_local_node
  need_new_shas
  need_genesis "${2:?push <genesis file>}"
  clear_markers
  # OPS-7: the second operator rebuilt this hash on another machine before anything is published.
  if [ "${SECOND_REBUILD_WAIVED:-}" = 1 ]; then
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
      LINE=$(printf 'second-rebuild-waived: %s genesis %s by %s@%s: %s' "$(date -u +%FT%TZ)" "$NEW" "$(id -un)" "$(hostname -s)" "$WHY")
      local_write "append to $CUT_RECORD: $LINE" bash -c 'printf "%s\n" "$1" >> "$2"' _ "$LINE" "$CUT_RECORD"
    fi
  else
    second_rebuild_ok
  fi
  echo "== push $GENESIS (sha256 $SHA, genesis $NEW) $(date -u +%T)"
  for ip in $ALL; do ( cp_to "$ip" /root/genesis-chain21.json "$GENESIS" ) & done; wait
  each "set -e
    $(staged_ok)
    $(pushed_ok)
    echo \"\$(hostname) genesis $NEW verified by the staged v$WANT_VERSION binary\"" \
    || { echo "push: not every host holds the genesis — do NOT stop chain 20; re-run push" >&2; exit 1; }
  echo "PUSHED — chain 20 still runs; next: the user's go, then stop $GENESIS (alone; check \$?)"
  ;;
switch)
  need_local_node
  need_new_shas
  need_old_shas
  need_genesis "${2:?switch <genesis file>}"
  clear_markers
  second_rebuild_ok
  echo "== switch to chain 21, genesis $NEW (datadir suffix -$P), checking the msauth key, installing v$WANT_VERSION $(date -u +%T)"
  # One script for both kinds of host; the guardian branch is chosen by the drop-in's presence.
  # Order on each host: refuse while running; genesis and staged files at their pins; the msauth
  # key verified by the STAGED binary (docs/deploy.md's snippet) — all before any change; then the
  # v$OLD_VERSION backups, the install (binaries + key), the installed key re-verified by the installed
  # binary, the datadir init and the unit / drop-in rewrite.
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    [ \"\$(sha256sum /root/genesis-chain21.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis not pushed'; exit 1; }
    $(staged_ok)
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain20.conf ] || [ -f \$D/chain21.conf ]; then
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it first'; exit 1; }
      if [ -f \$D/chain21.conf ]; then
        [ \"\$(cat /var/lib/randnode/data-21.genesis 2>/dev/null)\" = '$NEW' ] || { echo 'chain21.conf already runs another chain-21 genesis — a re-cut over a switched fleet needs rollback first; nothing switched'; exit 1; }
      else
        grep -q -- '--datadir /var/lib/randnode/data-20 ' \$D/chain20.conf || { echo 'chain20.conf has no data-20 datadir — nothing switched'; exit 1; }
      fi
    else
      # The unit must name chain 20's datadir (or already this genesis's) BEFORE anything is installed.
      grep -q -- '-$P ' /etc/systemd/system/rand-node.service || grep -q -- '-$OLD ' /etc/systemd/system/rand-node.service \
        || { echo 'unit names neither -$OLD (chain 20) nor -$P (this genesis) — a re-cut over a switched fleet needs rollback first; nothing switched'; exit 1; }
    fi
    chmod 755 /root/rand-node.c21
    $(vk_check /root/rand-node.c21 /root/$VK.c21)
    # Keep the v$OLD_VERSION binaries once, and only if they ARE the v$OLD_VERSION release binaries.
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET; do n=\${b%%:*}; s=\${b#*:}
      if [ ! -e /root/\$n.pre-c21 ]; then
        [ \"\$(sha256sum /usr/local/bin/\$n | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"installed \$n is not chain 20's v$OLD_VERSION binary — no backup made, nothing switched\"; exit 1; }
        cp -a /usr/local/bin/\$n /root/\$n.pre-c21
      fi
    done
    install -m 755 /root/rand-node.c21 /usr/local/bin/rand-node; install -m 755 /root/rand.c21 /usr/local/bin/rand
    install -m 644 /root/$VK.c21 /usr/local/bin/$VK
    $(vk_check /usr/local/bin/rand-node /usr/local/bin/$VK)
    if [ -f \$D/chain20.conf ] || [ -f \$D/chain21.conf ]; then
      # A guardian host: the node runs as randnode from /var/lib/randnode, ExecStart in a drop-in.
      V=/var/lib/randnode
      # data-21 carries no genesis prefix: a db there must be THIS genesis's. A re-cut leaves a stale
      # one — moved aside, never deleted, and never reused.
      if [ -d \$V/data-21/db ] && [ \"\$(cat \$V/data-21.genesis 2>/dev/null)\" != '$NEW' ]; then
        STALE=\$V/data-21.stale-\$(cut -c1-8 \$V/data-21.genesis 2>/dev/null || echo unknown)
        [ ! -e \$STALE ] || { echo \"\$V/data-21 is stale and \$STALE already exists — sort them out by hand\"; exit 1; }
        mv \$V/data-21 \$STALE; rm -f \$V/data-21.genesis
      fi
      install -d -o randnode -g randnode \$V/data-21
      install -m 644 -o randnode -g randnode /root/genesis-chain21.json \$V/genesis-chain21.json
      [ -d \$V/data-21/db ] || runuser -u randnode -- /usr/local/bin/rand-node init --datadir \$V/data-21 --genesis \$V/genesis-chain21.json >/dev/null
      echo '$NEW' > \$V/data-21.genesis
      if [ -f \$D/chain20.conf ]; then
        grep -q -- '--datadir /var/lib/randnode/data-20 ' \$D/chain20.conf || { echo 'chain20.conf has no data-20 datadir'; exit 1; }
        sed 's#--datadir /var/lib/randnode/data-20 #--datadir /var/lib/randnode/data-21 #' \$D/chain20.conf > \$D/chain21.conf
        mv \$D/chain20.conf /root/chain20.conf.c20
      fi
      grep -q -- '--datadir /var/lib/randnode/data-21 ' \$D/chain21.conf
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(/usr/local/bin/rand-node --version), msauth key \${vk_pin:0:12}… verified, \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"
    else
      U=/etc/systemd/system/rand-node.service
      if grep -q -- '-$P ' \$U; then echo \"\$(hostname) already switched (\$(/usr/local/bin/rand-node --version))\"; exit 0; fi
      grep -q -- '-$OLD ' \$U || { echo 'unit has no -$OLD datadir'; exit 1; }
      OLDDIR=\$(grep -o -- '--datadir [^ ]*' \$U | cut -d' ' -f2); NEWDIR=\${OLDDIR%-$OLD}-$P
      # A datadir on a volume behind a symlink keeps chain 21's on the same volume.
      if [ -L \$OLDDIR ]; then T=\$(dirname \$(readlink \$OLDDIR))/\$(basename \$NEWDIR); mkdir -p \$T; ln -sfn \$T \$NEWDIR; fi
      [ -d \$NEWDIR/db ] || /usr/local/bin/rand-node init --datadir \$NEWDIR --genesis /root/genesis-chain21.json >/dev/null
      [ -e /root/rand-node.service.$OLD.bak ] || cp -a \$U /root/rand-node.service.$OLD.bak
      sed -i 's/-$OLD /-$P /' \$U
      systemctl daemon-reload
      echo \"\$(hostname) ready: \$(/usr/local/bin/rand-node --version), msauth key \${vk_pin:0:12}… verified, \$(grep -o -- '--datadir [^ ]*' \$U)\"
    fi" || { echo "switch: some hosts are not ready — fix them and re-run switch; do NOT start. Or roll the fleet back (the fleet is already stopped; \`halt\` if any node runs): rollback → start → wait20, then restart the bridge on chain 20 — rollback restores the hosts that switched and leaves the rest alone" >&2; exit 1; }
  # Only a switch that reached every host licenses `start`.
  local_write "echo '$NEW <UTC>' > $MARKER_GLOB$P" bash -c 'echo "$1 $(date -u +%FT%TZ)" > "$2"' _ "$NEW" "$MARKER_GLOB$P"
  echo "SWITCHED — marker $MARKER_GLOB$P written; next: start (alone; check \$?)"
  ;;
rollback)
  # Back to chain 20's unit / drop-in and v$OLD_VERSION binaries on every host. Only after `stop`.
  # Idempotent per host (a host never switched, or already rolled back, answers "on chain 20").
  # The msauth blob stays in /usr/local/bin: v$OLD_VERSION never reads it.
  clear_markers
  need_old_shas
  echo "== rollback to chain 20 (datadir suffix -$OLD / data-20, v$OLD_VERSION binaries) $(date -u +%T)"
  each "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    D=/etc/systemd/system/rand-node.service.d
    if [ -f \$D/chain20.conf ] || [ -f \$D/chain21.conf ]; then
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — the bridge steps stop it first'; exit 1; }
    fi
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET; do n=\${b%%:*}; s=\${b#*:}
      if [ \"\$(sha256sum /usr/local/bin/\$n | cut -d' ' -f1)\" != \"\$s\" ]; then
        [ -f /root/\$n.pre-c21 ] || { echo \"no /root/\$n.pre-c21 to restore\"; exit 1; }
        [ \"\$(sha256sum /root/\$n.pre-c21 | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"/root/\$n.pre-c21 is not chain 20's v$OLD_VERSION binary\"; exit 1; }
        install -m 755 /root/\$n.pre-c21 /usr/local/bin/\$n
      fi
    done
    if [ -f \$D/chain20.conf ] || [ -f \$D/chain21.conf ]; then
      if [ -f \$D/chain21.conf ]; then
        [ -f /root/chain20.conf.c20 ] || { echo 'no /root/chain20.conf.c20 to restore'; exit 1; }
        mv /root/chain20.conf.c20 \$D/chain20.conf
        rm -f \$D/chain21.conf
      fi
      grep -q -- '--datadir /var/lib/randnode/data-20 ' \$D/chain20.conf
      [ -d /var/lib/randnode/data-20/db ] || { echo 'data-20 has no db'; exit 1; }
      systemctl daemon-reload
      echo \"\$(hostname) on chain 20: \$(/usr/local/bin/rand-node --version), \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"
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
      echo \"\$(hostname) on chain 20: \$(/usr/local/bin/rand-node --version), \$(grep -o -- '--datadir [^ ]*' \$U)\"
    fi" || { echo "rollback: some hosts are not back on chain 20 — fix them and re-run rollback; do NOT start" >&2; exit 1; }
  local_write "echo 'ROLLBACK to chain 20 ($OLD) <UTC>' > ${MARKER_GLOB}rollback-$OLD" bash -c 'echo "ROLLBACK to chain 20 ($1) $(date -u +%FT%TZ)" > "$2"' _ "$OLD" "${MARKER_GLOB}rollback-$OLD"
  echo "ROLLED BACK — marker ${MARKER_GLOB}rollback-$OLD written; next: start (alone; check \$?), then the bridge rollback"
  ;;
start)
  if dry; then
    MARK="$MARKER_GLOB<prefix>"; echo "[dry-run] local: refuse unless exactly one $MARKER_GLOB* marker exists (written by a successful switch or rollback)"
    KIND=switch
  else
    set -- "$MARKER_GLOB"*
    [ -e "$1" ] || { echo "start: no $MARKER_GLOB<prefix> marker — a successful switch (or rollback) writes it; refusing (a failed push/switch never starts the fleet)" >&2; exit 1; }
    [ $# -eq 1 ] || { echo "start: $# markers ($*) — ambiguous; remove the stale ones by hand after checking which genesis was switched" >&2; exit 1; }
    MARK=$1
    case "$MARK" in "${MARKER_GLOB}rollback-"*) KIND=rollback;; *) KIND=switch;; esac
    echo "== start on the $KIND recorded in $MARK: $(cat "$MARK")"
  fi
  GATE=""
  if [ "$KIND" = switch ]; then
    # A chain-21 node never starts on an unverified key: every host first, before any start …
    echo "== the msauth key on every host, checked by its installed rand-node $(date -u +%T)"
    each "set -e
      $(vk_check /usr/local/bin/rand-node /usr/local/bin/$VK)
      echo \"\$(hostname) msauth key \${vk_pin:0:12}… verified\"" \
      || { echo "start: the msauth key is not verified on every host — nothing started (re-run switch on those hosts)" >&2; exit 1; }
    # … and again in the same call as each host's own start.
    GATE="$(vk_check /usr/local/bin/rand-node /usr/local/bin/$VK);"
  fi
  # Each host's start is one ssh call: the key gate (after a switch), the start, and a check that
  # the unit is active. Every result is collected; a host that failed is named, the phase exits
  # non-zero and the marker is KEPT, so `start` can be re-run once those hosts are fixed (a host
  # already active just starts again as a no-op).
  ONE="$GATE systemctl start rand-node; sleep 2; systemctl is-active --quiet rand-node || { echo \"\$(hostname) NOT ACTIVE after start\"; exit 1; }; echo \"\$(hostname) active\""
  RES=$(mktemp -d)
  start_one() { if on "$1" "$ONE" > "$RES/$1" 2>&1; then echo ok > "$RES/$1.rc"; else echo FAIL > "$RES/$1.rc"; fi; }
  echo "== start bootstraps $(date -u +%T)"
  for ip in $BOOTS; do start_one "$ip"; printf '   %-16s %s %s\n' "$ip" "$(cat "$RES/$ip.rc")" "$(tail -1 "$RES/$ip")"; done
  echo "== start the other 24 $(date -u +%T)"
  for ip in $ALL; do case " $BOOTS " in *" $ip "*) continue;; esac; start_one "$ip" & done; wait
  FAILED=""
  for ip in $ALL; do
    case " $BOOTS " in *" $ip "*) ;; *) printf '   %-16s %s %s\n' "$ip" "$(cat "$RES/$ip.rc")" "$(tail -1 "$RES/$ip")";; esac
    [ "$(cat "$RES/$ip.rc")" = ok ] || FAILED="$FAILED $ip"
  done
  rm -rf "$RES"
  if [ -n "$FAILED" ]; then
    echo "start: NOT STARTED on:$FAILED — the marker $MARK is kept; fix those hosts and re-run start (or stop + rollback)" >&2; exit 1
  fi
  local_write "rm -f $MARK" rm -f "$MARK"
  echo "START-DONE $(date -u +%T) — all 26 active; nothing commits until 18 of the 26 validators are up"
  ;;
wait)
  GENESIS=${2:?wait <genesis file>}
  need_local_node
  NEW=$(genesis_hash "$GENESIS")
  if dry; then
    echo "[dry-run] every ${WAIT_SLEEP:-20} s, up to 90 times: on each of the 26 hosts rand_getGenesisHash == $NEW, rand_getHealth ok, rand_status.msauth_key loaded; C's rand_status height > 2"
    rpc "$BOOT1" rand_status; exit 0
  fi
  [ ${#NEW} -eq 64 ] || { echo "wait: could not derive the genesis hash" >&2; exit 1; }
  for _ in $(seq 1 90); do
    sleep "${WAIT_SLEEP:-20}"; ok=0; late=""
    for ip in $ALL; do
      # `|| true` in each: a node that does not answer yet is a laggard, not a failed wait (I1).
      g=$(rpc "$ip" rand_getGenesisHash | grep -oE '"result":"[0-9a-f]+"' | cut -d'"' -f4 || true)
      s=$(rpc "$ip" rand_getHealth | grep -oE '"status":"[a-z_]+"' | cut -d'"' -f4 || true)
      k=$(rpc "$ip" rand_status | grep -oE '"msauth_key":"[a-z]+"' | cut -d'"' -f4 || true)
      if [ "$g" = "$NEW" ] && [ "$s" = ok ] && [ "$k" = loaded ]; then ok=$((ok+1)); else late="$late $ip"; fi
    done
    H=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
    echo "  $(date -u +%T) $ok/26 on chain 21, healthy, msauth key loaded; C height ${H:-?}${late:+; not yet:$late}"
    if [ "$ok" = 26 ] && [ -n "$H" ] && [ "$H" -gt 2 ]; then echo "=== $(date -u +%T) CUTOVER DONE: all 26 on $NEW, committing at $H — next: check-limits (deploy/cut-chain21-genesis.sh)"; exit 0; fi
  done
  echo "=== not all 26 healthy after 30 min — check the laggards"; exit 1
  ;;
wait20)
  # After a rollback + start: every host serves chain 20 again, healthy, and C's height MOVES.
  if dry; then
    echo "[dry-run] every ${WAIT_SLEEP:-20} s, up to 90 times: each of the 26 hosts serves genesis $OLD…, rand_getHealth ok; C's height strictly above the previous poll's"
    rpc "$BOOT1" rand_status; exit 0
  fi
  PREV=""
  for _ in $(seq 1 90); do
    sleep "${WAIT_SLEEP:-20}"; ok=0; late=""
    for ip in $ALL; do
      g=$(rpc "$ip" rand_getGenesisHash | grep -oE '"result":"[0-9a-f]+"' | cut -d'"' -f4 || true)
      s=$(rpc "$ip" rand_getHealth | grep -oE '"status":"[a-z_]+"' | cut -d'"' -f4 || true)
      case "$g" in "$OLD"*) [ "$s" = ok ] && { ok=$((ok+1)); continue; };; esac
      late="$late $ip"
    done
    H=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
    echo "  $(date -u +%T) $ok/26 on chain 20 and healthy; C height ${H:-?} (previous ${PREV:-?})${late:+; not yet:$late}"
    if [ "$ok" = 26 ] && [ -n "$H" ] && [ -n "$PREV" ] && [ "$H" -gt "$PREV" ]; then echo "=== $(date -u +%T) CHAIN 20 COMMITTING AGAIN: all 26 on $OLD…, C at $H (was $PREV)"; exit 0; fi
    PREV=$H
  done
  echo "=== chain 20 is not committing on all 26 after 30 min"; exit 1
  ;;
quiet)
  # Before a rollback: has anything bridge-side happened on chain 21? burn_sequence and every
  # backing's `locked` must still be the genesis values (no burn emitted, no deposit minted). A
  # rollback after either loses it.
  GENESIS=${2:?quiet <genesis file>}
  if [ ! -f "$GENESIS" ]; then
    dry && { echo "== DRY RUN: $GENESIS is not a file — quiet would compare C and D's rand_getBridgeState with its burn_sequence and Σ locked"; rpc "$BOOT1" rand_getBridgeState; exit 0; }
    echo "quiet: $GENESIS is not a file — the chain-21 genesis the fleet runs" >&2; exit 1
  fi
  WANT=$(python3 -c 'import json,sys
g=json.load(open(sys.argv[1])); b=g["bridge"]
locked=sum(int(k.get("locked",0)) for t in g["tokens"]["tokens"] for k in t["backings"])
print(b["burn_sequence"], locked)' "$GENESIS")
  echo "== genesis: burn_sequence ${WANT% *}, Σ locked ${WANT#* }"
  if dry; then rpc "$BOOT1" rand_getBridgeState; exit 0; fi
  bad=0
  for ip in $BOOTS; do
    GOT=$(rpc "$ip" rand_getBridgeState | python3 -c 'import json,sys
try:
    r=json.load(sys.stdin)["result"]
    print(r["burn_sequence"], sum(int(a.get("locked") or 0) for a in r.get("assets",[])))
except Exception as e:
    print("unreadable", e)' || true)
    if [ "$GOT" = "$WANT" ]; then echo "   $ip: burn_sequence ${GOT% *}, Σ locked ${GOT#* } — as at genesis"
    else echo "   $ip: $GOT — NOT the genesis values: something was burned or minted on chain 21"; bad=1; fi
  done
  [ $bad = 0 ] || { echo "quiet: chain 21 has bridge activity — a rollback loses it; the user decides" >&2; exit 1; }
  echo "QUIET — nothing burned or minted on chain 21 (as C and D report)"
  ;;
status)
  for ip in $ALL; do (
    v=$(rpc "$ip" rand_getVersion | grep -oE '"version":"[^"]+"|"git_sha":"[a-z0-9]+"|"chain_id":[0-9]+' | tr '\n' ' ' || true)
    h=$(rpc "$ip" rand_status | grep -oE '"height":[0-9]+|"msauth_key":"[a-z]+"' | head -2 | tr '\n' ' ' || true)
    printf '   %-16s %s %s\n' "$ip" "$v" "${h:-no answer}" ) & done; wait
  ;;
*) echo "unknown phase $PHASE" >&2; exit 1 ;;
esac
