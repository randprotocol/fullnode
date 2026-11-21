#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2028  # single-quoted remote / bash -c scripts expand on the far side, and the
#   remote text's backslashes are for the far shell — both on purpose
# Cut the fleet over from chain 21 to chain 22 — all-stop, then a quorum of validators started
# together, then the archives — over the 25 hosts of the inventory that chain 22 keeps (nothing here
# creates a host). archive2 is DROPPED (owner, 2026-11-19): it is not a chain-22 validator, it is
# unreachable on a locked account, and this script never contacts it (it is filtered out of the
# inventory as it is read, and `on`/`cp_to` refuse its name and address besides).
#
# DERIVED from deploy/cutover-fleet-chain21.sh (chain 21 = v0.8.0, live 2026-10-12, on v0.8.6 since
# 2026-11-09; read it first). Its phases, its stop gate (chain 21 keeps running through stage, the
# cut, the second operator's hash and push; `stop` is gated on every host being ready), its datadir
# handling (nodes.env-style units: suffix -<chain-21 prefix> → -<chain-22 prefix>, volumes behind
# symlinks kept; guardian hosts: chain21.conf/data-21 → chain22.conf/data-22, a stale data-22 moved
# aside), the sha-checked backups, the marker that licenses `start`, the chain-16 trap rules and the
# rollback are chain 21's. Against chain 21's script:
#
#   * THE BUILD IS v0.8.7, CONSTRAINT SET 11. A set-11 rand-node REFUSES every chain-14–21 genesis
#     (constraint_set::build_genesis): there is no running both chains on one binary. So `switch`
#     keeps v0.8.6 as /root/rand-node.pre-c22 and /root/rand.pre-c22 AND chain 21's msauth blob as
#     /root/msauth-vk-production.bin.pre-c22 (v0.8.6 on chain 21 READS it — chain 21 names
#     hc_auth_multisig — and the set-11 blob is another file), and `rollback` restores all three.
#   * SEVEN SIGNED FILES, NOT THREE: rand-node, rand, msauth-vk-production.bin (set 11: 168d79a8…71b3,
#     23 851 bytes) and the four perps state-proof keys perp-vk-production-t18-*.bin (CON-601; the
#     pins of docs/deploy.md "The perps state-proof verifier keys"). A chain-22 node refuses to start
#     without every one beside its binary. Every pin is read from the SIGNED SHA256SUMS and must equal
#     the decided value; each host checks every staged and every installed file by sha256 and by the
#     binary's own `keygen-msauth-vk` / `keygen-perp-vk` pins, before and after the install, and again
#     in the same ssh call as its `systemctl start` (chain 21's msauth gate, widened).
#   * THE BEACON (#189). Each validator host needs its own beacon.seed.json, made ON THAT HOST:
#       - `beacon-init` runs `rand-node beacon init --chain-id 22` (the STAGED v0.8.7 binary: v0.8.6
#         has no `beacon`) on each of the 25 validators into a staging dir that survives a re-cut
#         (/root/beacon-c22, or /var/lib/randnode/beacon-c22 owned by randnode on a guardian host),
#         and prints each public commitment. A host that already has a seed keeps it (never
#         overwritten). THE SEED NEVER LEAVES ITS HOST: no phase reads, prints or copies it off.
#       - `beacon-collect` (read-only toward the fleet) reads each host's commitment back with
#         `rand-node beacon commitment`, checks the file names chain 22 and that host's own key
#         address, and writes BEACON_TSV — "<name> <64 hex>", the format cut-chain22-genesis.sh reads.
#       - `stop` refuses unless deploy/check-beacon-seed.sh passes on every validator against the
#         PUSHED genesis with the staging dir (so a bad seed is caught while chain 21 still runs);
#         `switch` copies the seed into the new datadir on the same host (0600; never between hosts)
#         and runs the check there; `start` runs it on every validator before any start and again
#         in the same ssh call as each start; `wait` runs it with --rpc.
#     The script ships deploy/check-beacon-seed.sh to each host (`stage`, sha-checked) — the hosts
#     have no checkout.
#   * THE CONSTRAINT SET (issue #166). `push` and `switch` run deploy/check-constraint-set.sh
#     --print-row with LOCAL_NODE's `constraint-set` marker (the binary, this tree and the vendored
#     zkVM must all be set 11), every host's probe and new datadir must carry the marker `11`, and
#     `verify` runs the full row check (CHAIN_CONSTRAINT_SETS must hold `(22, "<hash>", 11),`), as
#     docs/deploy.md asks of this script's verify. `check-limits` (the cut script's) makes the same
#     call; neither passes until the row is committed — commit it while chain 21 still runs.
#   * 25 VALIDATORS, NOT 26: the validator set is the cut script's GENESIS_NAMES plus BONDED (read
#     from deploy/cut-chain22-genesis.sh, not restated here); the inventory's validator rows minus
#     DROPPED_VALIDATORS must be exactly that set. Quorum 2·25/3+1 = 17. Archives (role "archive":
#     e, obs1) and observers (no "validator" in the role) start AFTER the first group and after
#     check-limits; the first group is every other validator (23 ≥ 17), bootstraps C and D first.
#   * THE HALT GUARD: `stop` refuses — before any host is contacted — unless
#     CONFIRM_HALT_CHAIN21=halt-chain-21-for-<P>, P the first 8 hex of the chain-22 genesis hash
#     being pushed. A typed phrase bound to this genesis: a confirmation left in the environment
#     from an earlier attempt does not stop the fleet for another genesis.
#   * THE INVENTORY is configuration/fleet/inventory.tsv in the private configuration repository
#     (INVENTORY; columns by header name: name ip role ssh_key key_path datadir address …), not
#     deploy/nodes.env + GUARDIAN_HOSTS; each host's ssh key, node key and datadir are read from it.
#     No address is written here, and the roll record names hosts by name only.
#   * PRUNED_SCAN_OK=1 is part of the cut: e and obs1 report prune_floor 187556 and no unpruned
#     chain-21 node exists. `snapshot`, `balances` and `cut` wrap deploy/cut-chain22-genesis.sh with
#     it set (and `cut` with the collected BEACON_TSV); the cut record must carry
#     `scan-floor: 187556` (the cut script checks).
#   * THE BRIDGE: `bridge-stop` stops rand-guardian on the six guardian hosts (and rand-relayer on
#     RELAYER_HOST) before the snapshot; `bridge-start` starts them again once chain 22 serves —
#     only with BRIDGE_ON_CHAIN22=yes: the daemons' configs (chain id, cursor) are the bridge
#     session's to switch first.
#   * A ROLL RECORD (ROLL_RECORD, default deploy/roll-records/v0.8.7-chain22-cutover.record) is
#     appended by every phase that changes something: names, hashes and times, never addresses.
#
#   INVENTORY=…/configuration/fleet/inventory.tsv is needed by every phase. In order:
#
#   RELEASE_SUMS=rel/SHA256SUMS OLD_RELEASE_SUMS=old/SHA256SUMS deploy/cutover-fleet-chain22.sh preflight
#                                                      # READ-ONLY: 25 hosts reachable, v0.8.6, chain 21,
#                                                      # disk, keys; the signed v0.8.7 sums and files
#   RELEASE_SUMS=… deploy/cutover-fleet-chain22.sh stage # v0.8.7 + 5 key files + the seed checker → /root/stage-c22
#   deploy/cutover-fleet-chain22.sh beacon-init        # each validator makes ITS seed; prints the 25 commitments
#   (each validator operator: an offline, encrypted backup of its beacon-c22/beacon.seed.json)
#   deploy/cutover-fleet-chain22.sh beacon-collect     # read-only: the 25 commitments → BEACON_TSV
#   [RELAYER_HOST=…] deploy/cutover-fleet-chain22.sh bridge-stop   # guardians (+ relayer) down
#   CHAIN21_RPC=<tunnel to e or obs1> deploy/cutover-fleet-chain22.sh snapshot <dir>
#   CHAIN21_RPC=… WALLET=<v0.8.6 rand> WALLET22=<v0.8.7 rand> deploy/cutover-fleet-chain22.sh balances <dir>
#   CUT_RECORD=… CHAIN21_SNAPSHOT=<dir> NODE=… WALLET=… WALLET22=… FEE_RECIPIENT_FILE=… \
#     FEE_RECIPIENT_FINGERPRINT=<the owner's SET-11 fingerprint> … deploy/cutover-fleet-chain22.sh cut
#   (constraint set 11 moves every rand1 address for the same key: WALLET, chain 21's rand, reads
#    chain 21; WALLET22, the signed v0.8.7 rand, derives every chain-22 address — cut-chain22-genesis.sh,
#    "EVERY SHIELDED ADDRESS IS RE-DERIVED UNDER CONSTRAINT SET 11")
#   (the second operator re-derives the hash and writes second-hash into the record; the
#    CHAIN_CONSTRAINT_SETS row the cut printed is committed)
#   LOCAL_NODE=<v0.8.7 rand-node> RELEASE_SUMS=… deploy/cutover-fleet-chain22.sh push <genesis>
#                                                      # chain 21 STILL RUNNING
#   ── the owner's go, typed in the executing session, before anything below ──
#   CONFIRM_HALT_CHAIN21=halt-chain-21-for-<P> LOCAL_NODE=… RELEASE_SUMS=… OLD_RELEASE_SUMS=… \
#     deploy/cutover-fleet-chain22.sh stop <genesis>   # GATED; stops all 25
#   LOCAL_NODE=… RELEASE_SUMS=… OLD_RELEASE_SUMS=… deploy/cutover-fleet-chain22.sh switch <genesis>
#   deploy/cutover-fleet-chain22.sh start              # every gate on all 25; C, D, then the first group (23)
#   LOCAL_NODE=… deploy/cutover-fleet-chain22.sh check-limits <genesis>   # cut script's, against C
#   deploy/cutover-fleet-chain22.sh start-archives     # e, obs1 (and any observer)
#   LOCAL_NODE=… deploy/cutover-fleet-chain22.sh wait <genesis>           # all 25 on chain 22, keys loaded, beacon --rpc
#   BRIDGE_ON_CHAIN22=yes [RELAYER_HOST=…] deploy/cutover-fleet-chain22.sh bridge-start
#   LOCAL_NODE=… deploy/cutover-fleet-chain22.sh verify <genesis>         # the CHAIN_CONSTRAINT_SETS row; the record
#   deploy/cutover-fleet-chain22.sh status             # read-only
# Rollback (bridge stopped first):
#   deploy/cutover-fleet-chain22.sh quiet <genesis>    # read-only: nothing burned or minted on chain 22?
#   deploy/cutover-fleet-chain22.sh halt               # stop a fleet that does not run chain 21 (refuses one that does)
#   OLD_RELEASE_SUMS=… deploy/cutover-fleet-chain22.sh rollback   # chain 21's units, v0.8.6 binaries, chain 21's msauth blob
#   deploy/cutover-fleet-chain22.sh start              # the rollback marker licenses it: all 25, C and D first
#   deploy/cutover-fleet-chain22.sh wait21             # until all 25 serve chain 21 and C's height moves
# A re-cut after a switch: halt, rollback, start, wait21, then push / stop / switch the new genesis.
# The beacon seeds stay in each host's staging dir and are reused (they are bound to chain 22 and
# the validator, not to a genesis hash); a re-cut keeps the same BEACON_TSV.
#
# THE TRAP FROM CHAIN 16: run each phase ALONE, never piped or chained; read `echo $?` first.
# `push`, `stop`, `switch`, `check-limits`, `wait` and `verify` refuse without LOCAL_NODE; `start`
# refuses without exactly one marker from a successful `switch` (or `rollback`).
#
# Env: INVENTORY (required), DROPPED_VALIDATORS (from the cut script), TAG (v0.8.7), STAGE_FROM
# (release|url|path) / RELEASE_URL / STAGE_URL / STAGE_DIR, RELEASE_SUMS / RELEASE_SUMS_SIG,
# WANT_SHA / WANT_SHA_WALLET (optional, must agree with the signed file), OLD_SHA / OLD_SHA_WALLET or
# OLD_RELEASE_SUMS / OLD_RELEASE_SUMS_SIG (v0.8.6), CUT_RECORD, BEACON_TSV, LOCAL_NODE, BOOT_NAMES
# ("c d"), MIN_FREE_GB (5), CHECK_LIMITS_RPC (else a tunnel to the first bootstrap), RELAYER_HOST /
# RELAYER_SSH_KEY, GUARDIAN_KNOWN_HOSTS, MARKER_DIR, ROLL_RECORD, CONFIRM_HALT_CHAIN21, DRY_RUN, SELFTEST.
#
#   DRY_RUN=1   every phase prints every remote command and local write; no ssh/scp, no marker, no
#               record line, no halt. Missing inputs become placeholders, loudly.
#   SELFTEST=1  exec deploy/rehearse-cutover-fleet-chain22.sh: the whole cutover against 26 FAKE hosts
#               (archive2 among them, never reachable) behind a fake ssh/scp/curl and fake rand-node
#               stubs. No binary needed, no network.
#
# Nothing here touches node keys or reads a beacon seed's contents. Rollback by hand (if `rollback`
# itself cannot run): restore /root/rand-node.pre-c22, /root/rand.pre-c22 and
# /root/msauth-vk-production.bin.pre-c22 into /usr/local/bin; on a node host restore
# /root/rand-node.service.$OLD.bak over the unit; on a guardian host move /root/chain21.conf.c21
# back into /etc/systemd/system/rand-node.service.d/ and delete chain22.conf; daemon-reload; start.
# The four perp-vk files may stay (chain 21's genesis pins no state-proof key). Chain 21 resumes
# from the height it stopped at: its datadirs are never touched here.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${SELFTEST:-}" = 1 ]; then exec bash deploy/rehearse-cutover-fleet-chain22.sh "$@"; fi
# shellcheck disable=SC1091  # sourced from the repo root (the cd above)
. deploy/lib/cut-policy.sh
# shellcheck disable=SC1091
. deploy/lib/verify-release.sh

PHASE=${1:?preflight|stage|beacon-init|beacon-collect|bridge-stop|snapshot|balances|cut|push|stop|switch|start|check-limits|start-archives|wait|bridge-start|verify|status|quiet|halt|rollback|wait21}
DRY=${DRY_RUN:-0}
TAG=${TAG:-v0.8.7}
WANT_VERSION=${WANT_VERSION:-0.8.7}
STAGE_FROM=${STAGE_FROM:-release}
RELEASE_URL=${RELEASE_URL:-https://github.com/randprotocol/fullnode/releases/download/$TAG}
STAGE_URL=${STAGE_URL:-}
STAGE_DIR=${STAGE_DIR:-}
RELEASE_SUMS=${RELEASE_SUMS:-}
RELEASE_SUMS_SIG=${RELEASE_SUMS_SIG:-${RELEASE_SUMS:+$RELEASE_SUMS.sig}}
WANT_SHA=${WANT_SHA:-}
WANT_SHA_WALLET=${WANT_SHA_WALLET:-}
WANT_SHA_VK=
NEED_FLAGS=${NEED_FLAGS:---testnet --binding-domain --proof-window-blocks --max-gas-price --gas-byte-load --program-state-cell-fee --fees --multisig --auth-multisig-guest --program-state-refuse-panics --tokens-incremental-root --program-state-reference-block-window --beacon-commitment}
CHAIN_ID=22
# ── the decided values (docs/deploy.md; deploy/cut-chain22-genesis.sh). Not overridable: another
# blob, key, guest or limit edits this script, the cut script and docs/deploy.md together.
VK=msauth-vk-production.bin
MSAUTH_VK_SHA=168d79a880b13b6d3e5b1f2a0f50561590712179c63189b52038cb2172a971b3   # constraint set 11
MSAUTH_VK_BYTES=23851
OLD_VK_SHA=68facb06c7f321aaf1d4d541acf6b5c0e9d7f17788ed1c9add6c5a8a8f7acd30      # chain 21's (set 9), what v0.8.6 reads
PVK_PINS="perp-vk-production-t18-pg14-in16-pub10-p2h20.bin:ae3d0dc276061fd2a87b2e91b239f6dcccb746b49dedeecfdb2aab977c95c370
perp-vk-production-t18-pg14-in16-pub7-p2h20.bin:4dc1f18bdd6d9104ba1622710cf2c146f71759676dbdcb70dad036152242e8b4
perp-vk-production-t18-pg14-in16-pub8-p2h20.bin:6392e5e9b7348f3729ba2031e0e3ec9788d6ed62a14521526482c92615f55106
perp-vk-production-t18-pg14-in16-pub9-p2h20.bin:c31636aa281004163e6fe0debd81854f11d7bca6c8062a91b1501c7e593e5bf0"
PVK_PINS=$(printf '%s\n' "$PVK_PINS" | LC_ALL=C sort | tr '\n' ' ')   # one sorted line: "<file>:<sha256> …"
PVK_FILES=$(for fp in $PVK_PINS; do printf '%s ' "${fp%%:*}"; done)
REL_FILES="rand-node rand $VK $PVK_FILES"
HC_AUTH_MULTISIG=41db73c507ab1f24ebe76d9c425b42a08ed9a02b4b1284d410502729ce6b9cd1   # MSAUTH_HC, set 11
MAX_PROOF_BYTES=6291456
MAX_BLOCK_BYTES=19922944
WANT_CONSTRAINT_SET=11
NODE_RS=${NODE_RS:-crates/randprotocol-node/src/node.rs}
TREE_SET=$(sed -n 's/^pub const BUILD_CONSTRAINT_SET: u32 = \([0-9][0-9]*\);.*$/\1/p' "$NODE_RS")
[ "$TREE_SET" = "$WANT_CONSTRAINT_SET" ] || { echo "this tree's BUILD_CONSTRAINT_SET ($NODE_RS) is '${TREE_SET:-?}', not $WANT_CONSTRAINT_SET — chain 22 is cut and launched from a set-11 tree" >&2; exit 1; }
# ── the build chain 21 runs: v0.8.6 (tag 6591c884). Its binary pins have no default.
OLD_SHA=${OLD_SHA:-}
OLD_SHA_WALLET=${OLD_SHA_WALLET:-}
OLD_RELEASE_SUMS=${OLD_RELEASE_SUMS:-}
OLD_RELEASE_SUMS_SIG=${OLD_RELEASE_SUMS_SIG:-${OLD_RELEASE_SUMS:+$OLD_RELEASE_SUMS.sig}}
OLD_VERSION=${OLD_VERSION:-0.8.6}
OLD_GIT_SHA=${OLD_GIT_SHA:-6591c884187126f118460c940d15715032bd124f}
[[ "$OLD_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$OLD_GIT_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "OLD_VERSION / OLD_GIT_SHA are not a version and a 40-hex commit" >&2; exit 1; }
OLD=ca76c276                                                                 # chain 21's genesis prefix: the datadir suffix
OLD_HASH=ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a
CUT_SCRIPT=deploy/cut-chain22-genesis.sh
CUT_RECORD=${CUT_RECORD:-$HOME/.rand-chain22/cut-record.txt}
BEACON_TSV=${BEACON_TSV:-$HOME/.rand-chain22/beacon-commitments.tsv}
MARKER_DIR=${MARKER_DIR:-/tmp/chain22-cutover}
ROLL_RECORD=${ROLL_RECORD:-deploy/roll-records/v0.8.7-chain22-cutover.record}
MIN_FREE_GB=${MIN_FREE_GB:-5}
WAIT_TRIES=${WAIT_TRIES:-90}
GUARDIAN_KNOWN_HOSTS=${GUARDIAN_KNOWN_HOSTS:-$HOME/.ssh/rand_guardian_known_hosts}
RELAYER_HOST=${RELAYER_HOST:-}
RELAYER_SSH_KEY=${RELAYER_SSH_KEY:-$HOME/.ssh/rand_guardian_ed25519}
S=/root/stage-c22                                                            # the staging dir on every host
for v in RELEASE_URL STAGE_URL WANT_VERSION; do
  case "${!v}" in *[\'\;\ \"\`\$\\\|\<\>\(\)\{\}]*) echo "$v contains a quote, ';', a space or a shell metacharacter — refused" >&2; exit 1;; esac
done
for f in $NEED_FLAGS; do [[ "$f" =~ ^--[a-z0-9-]+$ ]] || { echo "NEED_FLAGS: '$f' is not a --flag — refused" >&2; exit 1; }; done
[[ "$MIN_FREE_GB" =~ ^[0-9]{1,4}$ ]] || { echo "MIN_FREE_GB=$MIN_FREE_GB is not a number of GB" >&2; exit 1; }
[[ "$WAIT_TRIES" =~ ^[1-9][0-9]{0,3}$ ]] || { echo "WAIT_TRIES=$WAIT_TRIES is not a count" >&2; exit 1; }
[ -z "$RELAYER_HOST" ] || [[ "$RELAYER_HOST" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "RELAYER_HOST=$RELAYER_HOST is not an IPv4 address" >&2; exit 1; }

# ── the validator set, from the cut script (one source) ────────────────────────────────────────
cut_default() { sed -n "s/^$1=\${$1:-\(.*\)}\$/\1/p" "$CUT_SCRIPT" | head -1; }
GENESIS_NAMES=$(cut_default GENESIS_NAMES)
BONDED=$(cut_default BONDED)
DROPPED_VALIDATORS=$(sed -n 's/^DROPPED_VALIDATORS=\([a-z0-9 ]*\)$/\1/p' "$CUT_SCRIPT" | head -1)
[ -n "$GENESIS_NAMES" ] && [ -n "$BONDED" ] && [ -n "$DROPPED_VALIDATORS" ] \
  || { echo "could not read GENESIS_NAMES / BONDED / DROPPED_VALIDATORS from $CUT_SCRIPT — an anchor moved; update this script" >&2; exit 1; }
# shellcheck disable=SC2086  # word-split on purpose: name lists
VALSET=$(printf '%s\n' $GENESIS_NAMES $BONDED | sort | tr '\n' ' ')
NVALSET=$(wc -w <<<"$VALSET" | tr -d ' ')
QUORUM=$(( 2 * NVALSET / 3 + 1 ))
[ "$NVALSET" = 25 ] || { echo "$CUT_SCRIPT names $NVALSET chain-22 validators, not 25" >&2; exit 1; }

# ── the inventory ──────────────────────────────────────────────────────────────────────────────
INVENTORY=${INVENTORY:-}
[ -n "$INVENTORY" ] || { echo "INVENTORY is unset — point it at configuration/fleet/inventory.tsv (the private configuration repository)" >&2; exit 1; }
[ -f "$INVENTORY" ] || { echo "INVENTORY=$INVENTORY is not a file" >&2; exit 1; }
if grep -qE '(^|[[:space:]])203\.0\.113\.' "$INVENTORY"; then echo "$INVENTORY holds placeholder hosts (203.0.113.x) — point INVENTORY at the operator's file" >&2; exit 1; fi
INV_ROWS=$(awk -F'\t' '
  NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i
            n = split("name ip role ssh_key key_path datadir address", w, " ")
            for (i = 1; i <= n; i++) if (!(w[i] in col)) { print "MISSING " w[i]; exit }
            next }
  /^[[:space:]]*(#|$)/ { next }
  { a = $col["address"]; if (a == "") a = "-"
    print $col["name"], $col["ip"], $col["role"], $col["ssh_key"], $col["key_path"], $col["datadir"], a }' "$INVENTORY")
case "$INV_ROWS" in MISSING*) echo "$INVENTORY has no '${INV_ROWS#MISSING }' column" >&2; exit 1;; esac
ALL_N=""; VAL_N=""; FIRST_N=""; LATE_N=""; GUARD_N=""; DROPPED_IPS=""; SEEN=""
while read -r n ip role key kp dd addr; do
  [ -n "$n" ] || continue
  [[ "$n" =~ ^[a-z][a-z0-9]{0,15}$ ]] || { echo "$INVENTORY: name '$n' is not [a-z][a-z0-9]*" >&2; exit 1; }
  case " $SEEN " in *" $n "*) echo "$INVENTORY: $n is listed twice" >&2; exit 1;; esac; SEEN="$SEEN $n"
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "$INVENTORY: $n's ip '$ip' is not an IPv4 address" >&2; exit 1; }
  case " $DROPPED_VALIDATORS " in *" $n "*) DROPPED_IPS="$DROPPED_IPS $ip"; continue;; esac   # never contacted
  for v in "$kp" "$dd"; do [[ "$v" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "$INVENTORY: $n: '$v' is not a plain absolute path" >&2; exit 1; }; done
  [[ "$role" =~ ^[a-z+-]+$ ]] || { echo "$INVENTORY: $n's role '$role' is not a role" >&2; exit 1; }
  key=${key/#\~/$HOME}
  [[ "$key" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo "$INVENTORY: $n's ssh_key '$key' is not a plain path" >&2; exit 1; }
  printf -v "INV_ip_$n" '%s' "$ip"; printf -v "INV_key_$n" '%s' "$kp"; printf -v "INV_dd_$n" '%s' "$dd"
  printf -v "INV_ssh_$n" '%s' "$key"; printf -v "INV_addr_$n" '%s' "$addr"
  case "$role" in *guardian-host*) printf -v "INV_kind_$n" guardian; GUARD_N="$GUARD_N $n";; *) printf -v "INV_kind_$n" node;; esac
  case "$role" in *validator*) printf -v "INV_val_$n" 1; VAL_N="$VAL_N $n";; *) printf -v "INV_val_$n" 0;; esac
  case "$role" in *archive*|observer*) LATE_N="$LATE_N $n";; *validator*) FIRST_N="$FIRST_N $n";; *) LATE_N="$LATE_N $n";; esac
  ALL_N="$ALL_N $n"
done <<<"$INV_ROWS"
ALL_N=${ALL_N# }; VAL_N=${VAL_N# }; FIRST_N=${FIRST_N# }; LATE_N=${LATE_N# }; GUARD_N=${GUARD_N# }
for d in $DROPPED_VALIDATORS; do case " $SEEN " in *" $d "*) ;; *) echo "$INVENTORY has no row for the dropped $d — is this the fleet's inventory?" >&2; exit 1;; esac; done
# shellcheck disable=SC2086
HAVE=$(printf '%s\n' $VAL_N | sort | tr '\n' ' ')
[ "$HAVE" = "$VALSET" ] || { echo "the inventory's validators without $DROPPED_VALIDATORS ($HAVE) are not chain 22's 25 (GENESIS_NAMES + BONDED: $VALSET)" >&2; exit 1; }
NALL=$(wc -w <<<"$ALL_N" | tr -d ' '); NFIRST=$(wc -w <<<"$FIRST_N" | tr -d ' ')
[ "$NFIRST" -ge "$QUORUM" ] || { echo "the first group ($FIRST_N) has $NFIRST validators, below the quorum $QUORUM — chain 22 would not commit before the archives" >&2; exit 1; }
[ "$(wc -w <<<"$GUARD_N" | tr -d ' ')" = 6 ] || { echo "the inventory has $(wc -w <<<"$GUARD_N" | tr -d ' ') guardian hosts, expected 6" >&2; exit 1; }
BOOT_NAMES=${BOOT_NAMES:-c d}
for b in $BOOT_NAMES; do case " $FIRST_N " in *" $b "*) ;; *) echo "bootstrap $b is not a first-group validator of the inventory" >&2; exit 1;; esac; done
BOOT1=${BOOT_NAMES%% *}
iget() { local v="INV_${2}_$1"; printf '%s' "${!v:-}"; }

dry() { [ "$DRY" = 1 ]; }
missing() { # <message> <placeholder variable> <placeholder>
  if dry; then echo "== DRY RUN: $1 — using placeholder $3" >&2; printf -v "$2" '%s' "$3"
  else echo "$PHASE: $1 — nothing done" >&2; exit 1; fi
}
refuse_dropped() { # <name> <ip>: archive2 (any dropped validator) is never contacted
  local d
  for d in $DROPPED_VALIDATORS; do [ "$1" != "$d" ] || { echo "REFUSED: $d is dropped from chain 22 and is never contacted" >&2; return 1; }; done
  case " $DROPPED_IPS " in *" $2 "*) echo "REFUSED: $2 is a dropped validator's address and is never contacted" >&2; return 1;; esac
  [ -n "$2" ] || { echo "REFUSED: $1 is not an inventory host" >&2; return 1; }
}
sshopts() { # <name> → the ssh options for that host (its inventory key; the guardians' pinned known_hosts)
  if [ "$(iget "$1" kind)" = guardian ]; then
    printf '%s\n' -i "$(iget "$1" ssh)" -o IdentitiesOnly=yes -o "UserKnownHostsFile=$GUARDIAN_KNOWN_HOSTS" -o StrictHostKeyChecking=yes -o ConnectTimeout=20 -o BatchMode=yes
  else
    printf '%s\n' -i "$(iget "$1" ssh)" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -o BatchMode=yes
  fi
}
on() { # <name> <remote command>
  local n=$1 ip; ip=$(iget "$1" ip); shift
  refuse_dropped "$n" "$ip" || return 1
  if dry; then echo "[dry-run] ssh root@$n($ip) $*"; return 0; fi
  local o=(); while IFS= read -r l; do o+=("$l"); done < <(sshopts "$n")
  ssh -n "${o[@]}" "root@$ip" "$@"
}
cp_to() { # <name> <remote path> <local file…>
  local n=$1 ip dst=$2; ip=$(iget "$1" ip); shift 2
  refuse_dropped "$n" "$ip" || return 1
  if dry; then echo "[dry-run] scp $* root@$n($ip):$dst"; return 0; fi
  local o=(); while IFS= read -r l; do o+=("$l"); done < <(sshopts "$n")
  scp -q "${o[@]}" "$@" "root@$ip:$dst"
}
# Per-host values for a remote script: its name, node key, chain-21 datadir, validator flag, kind.
hvars() { printf "H_NAME='%s'; H_KEY='%s'; H_DD='%s'; H_VAL=%s; H_KIND=%s; " "$1" "$(iget "$1" key)" "$(iget "$1" dd)" "$(iget "$1" val)" "$(iget "$1" kind)"; }
EACH_OUT=""
each() {  # <host names> <remote script>: in parallel, the last line of each; fail if any failed.
          # EACH_OUT, when set, names a directory that keeps each host's full output as <name>.
  local hosts=$1 script=$2
  if dry; then
    printf '[dry-run] on each of %s hosts (%s) in parallel, over ssh as root, H_NAME/H_KEY/H_DD/H_VAL/H_KIND from the inventory:\n' "$(wc -w <<<"$hosts" | tr -d ' ')" "$hosts"
    printf '%s\n' "$script" | sed 's/^/[dry-run] | /'
    return 0
  fi
  local n dir; dir=$(mktemp -d)
  for n in $hosts; do ( if on "$n" "$(hvars "$n")$script" > "$dir/$n" 2>&1; then echo ok > "$dir/$n.rc"; else echo FAIL > "$dir/$n.rc"; fi ) & done; wait
  local bad=0
  for n in $hosts; do printf '   %-8s %s %s\n' "$n" "$(cat "$dir/$n.rc")" "$(tail -1 "$dir/$n")"; [ "$(cat "$dir/$n.rc")" = ok ] || bad=1; done
  if [ -n "$EACH_OUT" ]; then for n in $hosts; do cp "$dir/$n" "$EACH_OUT/$n"; done; fi
  rm -rf "$dir"; return $bad
}
rpc() { dry && { on "$1" "curl -s -m5 -X POST 127.0.0.1:8545 … $2" >&2; return 0; }
  on "$1" "curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}'" 2>/dev/null || true; }
local_write() { local what=$1; shift; if dry; then echo "[dry-run] local: $what"; else "$@"; fi; }
mark() { local_write "write $MARKER_DIR/$1" bash -c 'mkdir -p "$1" && echo "$2 $(date -u +%FT%TZ)" > "$1/$3"' _ "$MARKER_DIR" "${2:-}" "$1"; }
unmark() { local_write "rm -f $MARKER_DIR/$1" bash -c 'rm -f "$1"/$2' _ "$MARKER_DIR" "$1"; }
clear_markers() { local_write "rm -f $MARKER_DIR/{switched,first,limits,rollback}-*" bash -c 'rm -f "$1"/switched-* "$1"/first-* "$1"/limits-* "$1"/rollback-*' _ "$MARKER_DIR"; }
# shellcheck disable=SC2086  # $1 is a glob on purpose
markers() { ls "$MARKER_DIR"/$1 2>/dev/null || true; }
# The roll record: appended, never written over; names and hashes, no addresses.
rec() {
  dry && { echo "[dry-run] local: append to $ROLL_RECORD: $PHASE: $*"; return 0; }
  if [ ! -f "$ROLL_RECORD" ]; then
    mkdir -p "$(dirname "$ROLL_RECORD")"
    { echo "# Roll record — chain 21 → chain 22 on $TAG (a chain cut: all-stop, then a quorum, then the archives)."
      echo "#"
      echo "# Written by deploy/cutover-fleet-chain22.sh as the phases ran; one line per phase, appended, never"
      echo "# written over. Names only: the fleet's addresses are the operator's (configuration/fleet)."
      echo
      echo "release: $TAG (v$WANT_VERSION, constraint set $WANT_CONSTRAINT_SET); chain 21 ran v$OLD_VERSION ($OLD_GIT_SHA)"
      echo "hosts: $NALL — validators $NVALSET ($VAL_N), first group $NFIRST ($FIRST_N), late ${LATE_N:-none}; quorum $QUORUM"
      echo "skipped: $DROPPED_VALIDATORS (dropped from chain 22; never contacted)"
      echo "tool: deploy/cutover-fleet-chain22.sh ($(git rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout'))"
    } > "$ROLL_RECORD"
  fi
  printf '%s: %s %s\n' "$PHASE" "$(date -u +%FT%TZ)" "$*" >> "$ROLL_RECORD"
}

# ── the v0.8.7 pins, from the signed SHA256SUMS only ─────────────────────────────────────────────
PINS=""   # "<file>:<sha256> …" for the seven release files, set by need_new_shas
need_new_shas() {
  local got name var fp
  if [ -z "$RELEASE_SUMS" ]; then
    missing "RELEASE_SUMS is unset — the $TAG release's SHA256SUMS (signed: SHA256SUMS.sig beside it) is required" \
      WANT_SHA "<rand-node sha256 from the signed SHA256SUMS>"
    WANT_SHA_WALLET="<rand sha256>"; WANT_SHA_VK=$MSAUTH_VK_SHA
    PINS="rand-node:$WANT_SHA rand:$WANT_SHA_WALLET $VK:$WANT_SHA_VK $PVK_PINS"; return 0
  fi
  verify_release_sums "$RELEASE_SUMS" "$RELEASE_SUMS_SIG" || { echo "$PHASE: the $TAG SHA256SUMS signature does not verify — nothing done" >&2; exit 1; }
  for name in rand-node:WANT_SHA rand:WANT_SHA_WALLET "$VK:WANT_SHA_VK"; do
    var=${name#*:}; name=${name%%:*}
    got=$(release_sha "$RELEASE_SUMS" "$name") || { echo "$PHASE: the signed SHA256SUMS lists no $name — nothing done" >&2; exit 1; }
    [ -z "${!var}" ] || [ "${!var}" = "$got" ] || { echo "$PHASE: $var=${!var} is not what the signed SHA256SUMS lists for $name ($got) — nothing done" >&2; exit 1; }
    printf -v "$var" '%s' "$got"
  done
  [ "$WANT_SHA_VK" = "$MSAUTH_VK_SHA" ] || { echo "$PHASE: the signed SHA256SUMS lists $VK at $WANT_SHA_VK, not constraint set 11's decided blob $MSAUTH_VK_SHA — nothing done" >&2; exit 1; }
  for fp in $PVK_PINS; do
    got=$(release_sha "$RELEASE_SUMS" "${fp%%:*}") || { echo "$PHASE: the signed SHA256SUMS lists no ${fp%%:*} (CON-601: a chain-22 node does not start without it) — nothing done" >&2; exit 1; }
    [ "$got" = "${fp#*:}" ] || { echo "$PHASE: the signed SHA256SUMS lists ${fp%%:*} at $got, not the decided ${fp#*:} — nothing done" >&2; exit 1; }
  done
  [ -z "$OLD_SHA" ] || [ "$WANT_SHA" != "$OLD_SHA" ] || { echo "$PHASE: the signed rand-node is chain 21's v$OLD_VERSION — chain 22 needs v$WANT_VERSION; nothing done" >&2; exit 1; }
  PINS="rand-node:$WANT_SHA rand:$WANT_SHA_WALLET $VK:$WANT_SHA_VK $PVK_PINS"
  echo "== the signed SHA256SUMS ($RELEASE_SUMS) pins rand-node ${WANT_SHA:0:12}…, rand ${WANT_SHA_WALLET:0:12}…, $VK ${WANT_SHA_VK:0:12}… and the four perps keys"
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
    missing "OLD_SHA / OLD_SHA_WALLET (or OLD_RELEASE_SUMS) must give the sha256 of chain 21's v$OLD_VERSION Linux rand-node / rand" \
      OLD_SHA "<v$OLD_VERSION rand-node sha256>"
    OLD_SHA_WALLET="<v$OLD_VERSION rand sha256>"
  fi
}
LOCAL_SET=""
need_local_node() {
  local f help d
  if [ -z "${LOCAL_NODE:-}" ]; then
    dry && { echo "== DRY RUN: LOCAL_NODE is unset — the real run refuses (the chain-16 trap); hash checks become placeholders" >&2; LOCAL_NODE=; return 0; }
    echo "$PHASE: LOCAL_NODE is unset — point it at a v$WANT_VERSION rand-node on this machine; nothing done (the chain-16 trap)" >&2; exit 1
  fi
  [ -x "$LOCAL_NODE" ] || { echo "$PHASE: LOCAL_NODE=$LOCAL_NODE is not executable — nothing done" >&2; exit 1; }
  help=$("$LOCAL_NODE" genesis --help)
  for f in $NEED_FLAGS; do grep -q -- "$f" <<<"$help" || { echo "$PHASE: $LOCAL_NODE has no $f (not the v$WANT_VERSION build) — nothing done" >&2; exit 1; }; done
  case "$("$LOCAL_NODE" --version)" in "rand-node $WANT_VERSION"*) ;; *) echo "$PHASE: $LOCAL_NODE is $("$LOCAL_NODE" --version), not rand-node $WANT_VERSION — nothing done" >&2; exit 1;; esac
}
genesis_hash() { # <genesis> → "<hash LOCAL_NODE's init derives> <the constraint-set marker it wrote, or ->"
  local d h c=-
  if [ -z "${LOCAL_NODE:-}" ]; then echo "<hash:LOCAL_NODE-unset> -"; return 0; fi
  d=$(mktemp -d)
  h=$("$LOCAL_NODE" init --datadir "$d/p" --genesis "$1" 2>/dev/null | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2 || true)
  [ ! -f "$d/p/constraint-set" ] || c=$(tr -d '[:space:]' < "$d/p/constraint-set")
  rm -rf "$d"; echo "${h:--} ${c:--}"
}
# The file must BE chain 22's genesis: chain id, the set-11 msauth guest, the decided limits, the four
# pinned state-proof keys, a beacon with one commitment per validator — and, when BEACON_TSV exists,
# exactly the commitments the fleet's hosts gave (beacon-collect).
need_chain22_genesis() {
  if [ ! -f "$1" ]; then
    dry && { echo "== DRY RUN: $1 is not a file (the cut has not run) — genesis checks skipped" >&2; return 0; }
    echo "$PHASE: $1 is not a file — nothing done" >&2; exit 1
  fi
  local why
  why=$(python3 - "$1" "$HC_AUTH_MULTISIG" "$MAX_PROOF_BYTES" "$MAX_BLOCK_BYTES" "$PVK_PINS" "$NVALSET" "$BEACON_TSV" <<'PY'
import json, os, sys
gf, hc, mpb, mbb, pins, nval, tsv = sys.argv[1:8]
try:
    g = json.load(open(gf))
except Exception as e:
    print(f"is not JSON ({e})"); sys.exit(0)
def no(m): print(m); sys.exit(0)
if g.get("chain_id") != 22: no(f"has chain_id {g.get('chain_id')}, not 22")
if g.get("hc_auth_multisig") != hc: no(f"has hc_auth_multisig {g.get('hc_auth_multisig')}, not constraint set 11's {hc}")
if g.get("max_proof_bytes") != int(mpb): no(f"has max_proof_bytes {g.get('max_proof_bytes')}, not {mpb}")
if g.get("max_block_bytes") != int(mbb): no(f"has max_block_bytes {g.get('max_block_bytes')}, not {mbb}")
if len(g.get("validators", [])) != int(nval): no(f"names {len(g.get('validators', []))} validators, not {nval}")
want = sorted(p.split(":", 1)[1] for p in pins.split())
got = sorted(k.get("sha256", "") for k in (g.get("perps") or {}).get("state_proof_keys", []))
if got != want: no(f"pins perps.state_proof_keys {[x[:12] for x in got]}, not the four decided keys {[x[:12] for x in want]} (CON-601)")
b = g.get("beacon")
if not b: no("has no beacon section (#189)")
cs = [c.get("commitment") for c in b.get("commitments", [])]
if len(cs) != int(nval) or len(set(cs)) != len(cs): no(f"has {len(cs)} beacon commitments ({len(set(cs))} distinct), not {nval}")
if os.path.isfile(tsv):
    t = [l.split() for l in open(tsv) if l.strip() and not l.lstrip().startswith("#")]
    if sorted(x[1] for x in t if len(x) == 2) != sorted(cs):
        no(f"has beacon commitments that are not the {len(t)} in {tsv} (beacon-collect) — a genesis cut from other commitments; its validators would miss their slots")
PY
)
  [ -z "$why" ] || { echo "$PHASE: $1 $why — nothing done" >&2; exit 1; }
}
file_sha() { if [ -f "$1" ]; then shasum -a 256 "$1" | cut -d' ' -f1; else echo "<sha256 of $1>"; fi; }
NEW=""; P=""; SHA=""; GENESIS=""
need_genesis() {
  GENESIS=$1
  need_chain22_genesis "$GENESIS"
  SHA=$(file_sha "$GENESIS")
  read -r NEW LOCAL_SET <<<"$(genesis_hash "$GENESIS")"
  [ "$LOCAL_SET" != - ] || LOCAL_SET=""
  if [ ${#NEW} -eq 64 ]; then P=${NEW:0:8}
  elif dry; then P="<P>"
  else echo "$PHASE: $LOCAL_NODE derived no genesis hash from $GENESIS — nothing done" >&2; exit 1; fi
  [ "$P" != "$OLD" ] || { echo "$PHASE: $GENESIS is chain 21's genesis ($NEW) — nothing done" >&2; exit 1; }
}
# deploy/check-constraint-set.sh for this genesis: the binary (LOCAL_NODE's init marker), this tree
# and the vendored zkVM are one constraint set (--print-row: the table is not consulted — the row
# cannot predate the cut). With "row", the full CHAIN_CONSTRAINT_SETS row check (verify).
constraint_set_ok() {
  if dry && [ ${#NEW} -ne 64 ]; then echo "[dry-run] local: deploy/check-constraint-set.sh --chain $CHAIN_ID --genesis-hash <hash> --binary-set <LOCAL_NODE's marker> ${1:+(the row) }"; return 0; fi
  [ -n "$LOCAL_SET" ] || { echo "$PHASE: LOCAL_NODE's init wrote no constraint-set marker — not a v$WANT_VERSION build with the guard; nothing done" >&2; exit 1; }
  if [ "${1:-}" = row ]; then
    deploy/check-constraint-set.sh --chain "$CHAIN_ID" --genesis-hash "$NEW" --binary-set "$LOCAL_SET"; return
  fi
  local row
  row=$(deploy/check-constraint-set.sh --chain "$CHAIN_ID" --genesis-hash "$NEW" --binary-set "$LOCAL_SET" --print-row) \
    || { echo "$PHASE: the constraint-set check refused (above) — nothing done" >&2; exit 1; }
  echo "== constraint set: LOCAL_NODE $LOCAL_SET = this tree = the vendored zkVM; chain 22's row is $row"
  if deploy/check-constraint-set.sh --chain "$CHAIN_ID" --genesis-hash "$NEW" --binary-set "$LOCAL_SET" >/dev/null 2>&1; then
    echo "== CHAIN_CONSTRAINT_SETS already holds it"
  else
    echo "== ⚠ CHAIN_CONSTRAINT_SETS ($NODE_RS's crate) does not hold $row yet: check-limits and verify refuse until it is committed — add it now, while chain 21 still runs"
  fi
}
second_rebuild_ok() {
  if dry && [ ${#NEW} -ne 64 ]; then
    echo "[dry-run] local: require_second_rebuild $CUT_RECORD <genesis hash> — the record's second-hash: must equal it"; return 0; fi
  if grep -q "^second-rebuild-waived: .*genesis $NEW" "$CUT_RECORD" 2>/dev/null; then
    echo "== ⚠ the cut record carries a second-rebuild WAIVER for genesis $NEW (no second operator's hash)"; return 0; fi
  if require_second_rebuild "$CUT_RECORD" "$NEW"; then return 0; fi
  if dry; then echo "== DRY RUN: the real $PHASE REFUSES here (above); the dry run goes on to show the rest"; return 0; fi
  echo "$PHASE: nothing done" >&2; exit 1
}

# ── remote snippets ─────────────────────────────────────────────────────────────────────────────
# Per host: BDIR (its beacon staging dir), and — once P is known — NEWDIR (its chain-22 datadir) and
# HG (the genesis its node reads). Literal paths on purpose (the rehearsal maps them per fake host).
r_paths() {
  echo "if [ \"\$H_KIND\" = guardian ]; then BDIR=/var/lib/randnode/beacon-c22; NEWDIR=/var/lib/randnode/data-22; HG=/var/lib/randnode/genesis-chain22.json; OWN=randnode
    else BDIR=/root/beacon-c22; NEWDIR=\${H_DD%-$OLD}-$P; HG=$S/genesis-chain22.json; OWN=root; fi"
}
staged_ok() {
  local fp out=""
  for fp in $PINS; do out="${out}[ \"\$(sha256sum $S/${fp%%:*} 2>/dev/null | cut -d' ' -f1)\" = '${fp#*:}' ] || { echo 'staged ${fp%%:*} is not the pinned $TAG file ($S)'; exit 1; }
    "; done
  echo "${out}[ \"\$(sha256sum $S/check-beacon-seed.sh 2>/dev/null | cut -d' ' -f1)\" = '$CHECKER_SHA' ] || { echo 'staged check-beacon-seed.sh is not this tree'\''s'; exit 1; }"
}
vk_check() { # <rand-node> <blob>: docs/deploy.md's msauth check
  echo "vk_got=\$($1 keygen-msauth-vk --check $2) && vk_pin=\$($1 keygen-msauth-vk --print-pinned production) && [ \"\$vk_got\" = \"\$vk_pin\" ] && [ \"\$vk_pin\" = '$MSAUTH_VK_SHA' ] && [ \"\$(wc -c < $2 | tr -d ' ')\" = '$MSAUTH_VK_BYTES' ] || { echo \"msauth key NOT verified: $2 is \${vk_got:-unreadable}, $1 pins \${vk_pin:-nothing}, decided $MSAUTH_VK_SHA\"; exit 1; }"
}
pvk_check() { # <rand-node> <dir>: the four perps keys (CON-601) — the binary's pins are the decided four, each file holds to its pin
  echo "pv=\$($1 keygen-perp-vk --print-pinned production | awk '{print \$1\":\"\$2}' | LC_ALL=C sort | tr '\\n' ' ') && [ \"\$pv\" = '$PVK_PINS' ] || { echo \"perps keys NOT verified: $1 pins \${pv:-nothing}, not the decided four\"; exit 1; }
    for fp in $PVK_PINS; do f=\${fp%%:*}; p=\${fp#*:}
      [ \"\$(sha256sum $2/\$f 2>/dev/null | cut -d' ' -f1)\" = \"\$p\" ] && [ \"\$($1 keygen-perp-vk --check $2/\$f 2>/dev/null)\" = \"\$p\" ] || { echo \"perps key NOT verified: $2/\$f is not \${p:0:12}…\"; exit 1; }
    done"
}
beacon_check() { # <rand-node> <genesis> <datadir> [<rpc>]: validators only; deploy/check-beacon-seed.sh on the host
  echo "BS=skipped; if [ \"\$H_VAL\" = 1 ]; then BS=\$(bash $S/check-beacon-seed.sh --node $1 --genesis $2 --datadir $3 --key \$H_KEY${4:+ --rpc $4} 2>&1) || { echo \"\$H_NAME: beacon seed NOT verified — \$(printf '%s\\n' \"\$BS\" | tail -1)\"; exit 1; }; BS=ok; fi"
}
cs_check() { # <datadir>: the constraint-set marker init wrote
  echo "[ \"\$(tr -d '[:space:]' < $1/constraint-set 2>/dev/null)\" = '$WANT_CONSTRAINT_SET' ] || { echo \"$1/constraint-set says '\$(cat $1/constraint-set 2>/dev/null)', not constraint set $WANT_CONSTRAINT_SET\"; exit 1; }"
}
staged_self() {
  echo "$S/rand-node --version | grep -q 'rand-node $WANT_VERSION' || { echo \"staged rand-node is \$($S/rand-node --version 2>&1 | head -1), not $WANT_VERSION\"; exit 1; }
    GH=\$($S/rand-node genesis --help); for f in $NEED_FLAGS; do printf '%s' \"\$GH\" | grep -q -- \"\$f\" || { echo \"staged rand-node has no \$f\"; exit 1; }; done
    $(vk_check $S/rand-node $S/$VK)
    $(pvk_check $S/rand-node $S)"
}
pushed_ok() {
  echo "[ \"\$(sha256sum $S/genesis-chain22.json 2>/dev/null | cut -d' ' -f1)\" = '$SHA' ] || { echo 'the chain-22 genesis is not pushed here (sha256 differs or no file)'; exit 1; }
    rm -rf $S/probe; GH=\$($S/rand-node init --datadir $S/probe --genesis $S/genesis-chain22.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2)
    [ \"\$GH\" = '$NEW' ] || { rm -rf $S/probe; echo \"genesis hash \$GH, expected $NEW\"; exit 1; }
    $(cs_check $S/probe)
    rm -rf $S/probe"
}
installed_gate() { # what every chain-22 host must hold before its node starts
  echo "$(r_paths)
      $(vk_check /usr/local/bin/rand-node /usr/local/bin/$VK)
      $(pvk_check /usr/local/bin/rand-node /usr/local/bin)
      $(cs_check \$NEWDIR)
      $(beacon_check /usr/local/bin/rand-node \$HG \$NEWDIR)"
}
stop_all() {
  each "$ALL_N" 'systemctl stop rand-node; if systemctl is-active --quiet rand-node; then echo "$(hostname) STILL ACTIVE"; exit 1; fi; echo "$(hostname) stopped"' \
    || { echo "$PHASE: some hosts did not stop (above) — stop them by hand; switch and rollback refuse a running node" >&2; exit 1; }
}
CHECKER_SHA=$(file_sha deploy/check-beacon-seed.sh)

case "$PHASE" in
preflight)
  need_old_shas
  need_new_shas
  if [ "$STAGE_FROM" = path ] && [ -n "$STAGE_DIR" ] && ! dry; then
    for f in $REL_FILES; do verify_binary "$STAGE_DIR/$f" "$RELEASE_SUMS" "$f" || { echo "preflight: $STAGE_DIR/$f is not the signed $f" >&2; exit 1; }; done
    echo "== the seven $TAG files in $STAGE_DIR are the signed ones"
  else
    echo "== the $TAG files at the release URL, as $BOOT1 fetches them (HEAD only):"
    BASE=$RELEASE_URL; [ "$STAGE_FROM" != url ] || BASE=${STAGE_URL%%\?*}
    on "$BOOT1" "for f in $REL_FILES; do curl -fsSIL -o /dev/null --retry 3 '$BASE/'\$f || { echo \"\$f is not at the release\"; exit 1; }; done; echo 'all seven present'" \
      || { echo "preflight: the release does not hold every file (above)" >&2; exit 1; }
  fi
  echo "== preflight (read-only) on $NALL hosts ($DROPPED_VALIDATORS never contacted): v$OLD_VERSION rand-node ${OLD_SHA:0:12}…, rand ${OLD_SHA_WALLET:0:12}…, chain 21's msauth blob, chain-21 datadir -$OLD / data-21, ≥ $MIN_FREE_GB GB free $(date -u +%T)"
  each "$ALL_N" "set -e
    [ \"\$(sha256sum /usr/local/bin/rand-node | cut -d' ' -f1)\" = '$OLD_SHA' ] || { echo \"installed rand-node is \$(/usr/local/bin/rand-node --version 2>&1 | head -1) sha256 \$(sha256sum /usr/local/bin/rand-node | cut -c1-12)…, not chain 21's v$OLD_VERSION ${OLD_SHA:0:12}…\"; exit 1; }
    [ \"\$(sha256sum /usr/local/bin/rand | cut -d' ' -f1)\" = '$OLD_SHA_WALLET' ] || { echo \"installed rand is not chain 21's v$OLD_VERSION\"; exit 1; }
    [ \"\$(sha256sum /usr/local/bin/$VK 2>/dev/null | cut -d' ' -f1)\" = '$OLD_VK_SHA' ] || { echo 'installed $VK is not chain 21'\''s blob (${OLD_VK_SHA:0:12}…) — the rollback needs it'; exit 1; }
    for b in rand-node rand $VK; do [ ! -e /root/\$b.pre-c22 ] || { echo \"a /root/\$b.pre-c22 backup already exists (an earlier switch?)\"; exit 1; }; done
    [ -f \"\$H_KEY\" ] || { echo \"no node key at \$H_KEY\"; exit 1; }
    command -v python3 >/dev/null || { echo 'no python3 (check-beacon-seed.sh needs it)'; exit 1; }
    D=/etc/systemd/system/rand-node.service.d
    if [ \"\$H_KIND\" = guardian ]; then
      [ -f \$D/chain21.conf ] && [ ! -f \$D/chain22.conf ] || { echo 'a guardian host without chain21.conf, or with a chain22.conf already'; exit 1; }
      [ \"\$H_DD\" = /var/lib/randnode/data-21 ] && grep -q -- '--datadir /var/lib/randnode/data-21 ' \$D/chain21.conf || { echo 'chain21.conf has no data-21 datadir, or the inventory names another'; exit 1; }
      [ ! -e /var/lib/randnode/data-22 ] || { echo '/var/lib/randnode/data-22 already exists — move it aside'; exit 1; }
      [ ! -e /root/chain21.conf.c21 ] || { echo '/root/chain21.conf.c21 already exists (an earlier switch?)'; exit 1; }
    else
      [ ! -f \$D/chain21.conf ] || { echo 'the inventory says node, the host has a guardian drop-in'; exit 1; }
      case \"\$H_DD\" in *-$OLD) ;; *) echo \"the inventory's datadir \$H_DD has no -$OLD suffix\"; exit 1;; esac
      grep -q -- \"--datadir \$H_DD \" /etc/systemd/system/rand-node.service || { echo \"the unit does not run the inventory's datadir \$H_DD\"; exit 1; }
    fi
    [ -d \"\$H_DD/db\" ] || { echo \"\$H_DD has no db\"; exit 1; }
    FREE=\$(df -Pk \"\$H_DD/\" | awk 'NR==2 {print \$4}'); [ \"\$FREE\" -ge $((MIN_FREE_GB * 1048576)) ] || { echo \"only \$((FREE / 1048576)) GB free under \$H_DD (want $MIN_FREE_GB)\"; exit 1; }
    G=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getGenesisHash\",\"params\":[]}' | grep -oE '\"result\":\"[0-9a-f]+\"' | cut -d'\"' -f4)
    [ \"\$G\" = '$OLD_HASH' ] || { echo \"serves genesis \${G:-nothing}, not chain 21 ($OLD…)\"; exit 1; }
    curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getHealth\",\"params\":[]}' | grep -q '\"status\":\"ok\"' || { echo 'rand_getHealth is not ok'; exit 1; }
    VER=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getVersion\",\"params\":[]}')
    printf '%s' \"\$VER\" | grep -q '\"version\":\"$OLD_VERSION\"' && printf '%s' \"\$VER\" | grep -q '\"git_sha\":\"$OLD_GIT_SHA\"' \\
      || { echo \"rand_getVersion answers \$(printf '%s' \"\$VER\" | grep -oE '\"(version|git_sha)\":\"[^\"]*\"' | tr '\\n' ' '), not $OLD_VERSION / ${OLD_GIT_SHA:0:8}\"; exit 1; }
    $(r_paths)
    ST=\$( [ -e $S/rand-node ] && echo ', staged' || echo ', nothing staged')
    BC=\$( [ \"\$H_VAL\" = 1 ] && { [ -f \$BDIR/beacon.seed.json ] && echo ', beacon seed made' || echo ', no beacon seed yet'; } || echo ', not a validator')
    echo \"\$H_NAME \$H_KIND ready: v$OLD_VERSION, chain 21, healthy, \$((FREE / 1048576)) GB free\$ST\$BC\"" \
    || { echo "preflight: not every host is ready — fix those before staging or stopping anything" >&2; exit 1; }
  echo "PREFLIGHT OK — nothing was changed ($NALL hosts; $NVALSET validators; first group $NFIRST ≥ quorum $QUORUM; late: ${LATE_N:-none})"
  ;;
stage)
  clear_markers
  need_new_shas
  [ -f deploy/check-beacon-seed.sh ] || { echo "stage: no deploy/check-beacon-seed.sh in this tree" >&2; exit 1; }
  FETCH=""
  case "$STAGE_FROM" in
    release|url)
      if [ "$STAGE_FROM" = url ]; then
        [ -n "$STAGE_URL" ] || { echo "stage: STAGE_FROM=url needs STAGE_URL (a private base URL holding the seven files) — nothing staged" >&2; exit 1; }
        BASE=$STAGE_URL; SHOWN="${STAGE_URL%%\?*}"; SHOWN="${SHOWN%/*}/…"
      else BASE=$RELEASE_URL; SHOWN=$RELEASE_URL; fi
      case "$BASE" in https://*) ;; *) echo "stage: $SHOWN is not https:// — nothing staged" >&2; exit 1;; esac
      Q=""; case "$BASE" in *\?*) Q="?${BASE#*\?}"; BASE=${BASE%%\?*};; esac
      echo "== stage $TAG (seven files) + check-beacon-seed.sh on $NALL hosts from $SHOWN $(date -u +%T)"
      FETCH="for f in $REL_FILES; do curl -fsSL --retry 10 --retry-all-errors --retry-delay 5 -o $S/\$f.part '$BASE/'\$f'$Q'; done"
      ;;
    path)
      [ -n "$STAGE_DIR" ] || { echo "stage: STAGE_FROM=path needs STAGE_DIR holding the seven $TAG files — nothing staged" >&2; exit 1; }
      for f in $REL_FILES; do
        [ -f "$STAGE_DIR/$f" ] || { echo "stage: STAGE_DIR has no $f — nothing staged" >&2; exit 1; }
        dry || verify_binary "$STAGE_DIR/$f" "$RELEASE_SUMS" "$f" || { echo "stage: $STAGE_DIR/$f is not the signed $f — nothing staged" >&2; exit 1; }
      done
      if [ "${STAGE_ALLOW_NON_ELF:-}" != 1 ]; then
        for b in rand-node rand; do [ "$(head -c 4 "$STAGE_DIR/$b" | od -An -c | tr -d ' ')" = '177ELF' ] || { echo "stage: $STAGE_DIR/$b is not a Linux ELF binary (a macOS build?) — nothing staged" >&2; exit 1; }; done
      fi
      echo "== stage $TAG from $STAGE_DIR (laptop scp; signed sha256s checked here first) $(date -u +%T)"
      ;;
    *) echo "stage: STAGE_FROM=$STAGE_FROM — release, url or path" >&2; exit 1;;
  esac
  # The checker comes from this tree (the hosts have no checkout); path mode copies the seven too.
  for n in $ALL_N; do ( on "$n" "mkdir -p $S && rm -f $S/*.part" && cp_to "$n" "$S/check-beacon-seed.sh.part" deploy/check-beacon-seed.sh \
      && if [ "$STAGE_FROM" = path ]; then for f in $REL_FILES; do cp_to "$n" "$S/$f.part" "$STAGE_DIR/$f" || exit 1; done; fi ) & done; wait
  CHECKS=""; for fp in $PINS; do CHECKS="$CHECKS [ \"\$(sha256sum $S/${fp%%:*}.part 2>/dev/null | cut -d' ' -f1)\" = '${fp#*:}' ] || BAD=\"\$BAD ${fp%%:*}\";"; done
  each "$ALL_N" "set -e; cd $S
    $FETCH
    BAD=''; $CHECKS [ \"\$(sha256sum $S/check-beacon-seed.sh.part 2>/dev/null | cut -d' ' -f1)\" = '$CHECKER_SHA' ] || BAD=\"\$BAD check-beacon-seed.sh\"
    if [ -n \"\$BAD\" ]; then rm -f $S/*.part; echo \"SHA MISMATCH (\$BAD) — removed\"; exit 1; fi
    for f in $REL_FILES check-beacon-seed.sh; do mv $S/\$f.part $S/\$f; done
    chmod 755 $S/rand-node $S/rand; chmod 644 $S/$VK $S/perp-vk-production-*.bin $S/check-beacon-seed.sh
    $(staged_self)
    echo \"\$H_NAME staged \$($S/rand-node --version), msauth key \${vk_pin:0:12}… and the four perps keys verified\"" \
    || { echo "stage: not every host staged — fix those before going on" >&2; exit 1; }
  rec "staged $TAG on $NALL hosts: rand-node ${WANT_SHA:0:16}, rand ${WANT_SHA_WALLET:0:16}, $VK ${WANT_SHA_VK:0:16}, four perps keys, check-beacon-seed.sh ${CHECKER_SHA:0:16}"
  echo "STAGED $(date -u +%T) — nothing was installed; the fleet still runs chain 21 on v$OLD_VERSION. Next: beacon-init"
  ;;
beacon-init)
  need_new_shas
  echo "== beacon-init on the $NVALSET validators: each makes ITS OWN seed with the staged v$WANT_VERSION (chain id $CHAIN_ID); a seed already there is kept $(date -u +%T)"
  each "$VAL_N" "set -e
    $(staged_ok)
    $(r_paths)
    A=\$($S/rand-node address --key \$H_KEY | sed -n 's/^address: \\(.*\\)\$/\\1/p' | head -1); [ -n \"\$A\" ] || { echo 'no address from the node key'; exit 1; }
    if [ -f \$BDIR/beacon.seed.json ]; then WHAT=kept
    else
      mkdir -p \$BDIR; chmod 700 \$BDIR
      $S/rand-node beacon init --datadir \$BDIR --key \$H_KEY --chain-id $CHAIN_ID > \$BDIR/.init.out 2>/dev/null || { rm -f \$BDIR/.init.out; echo 'rand-node beacon init failed'; exit 1; }
      rm -f \$BDIR/.init.out; chmod 600 \$BDIR/beacon.seed.json; chown -R \$OWN:\$OWN \$BDIR; WHAT=made
    fi
    C=\$($S/rand-node beacon commitment --datadir \$BDIR 2>\$BDIR/.c.err) || { tail -1 \$BDIR/.c.err; rm -f \$BDIR/.c.err; echo 'the seed file does not re-derive'; exit 1; }
    W=\$(sed -n 's/^chain \\([0-9][0-9]*\\), validator \\([^,]*\\), .*/\\1 \\2/p' \$BDIR/.c.err | head -1); rm -f \$BDIR/.c.err
    [ \"\$W\" = \"$CHAIN_ID \$A\" ] || { echo \"the seed file names '\$W', not chain $CHAIN_ID and this key's address \$A\"; exit 1; }
    echo \"beacon \$H_NAME \$C (\$WHAT; validator \$A)\"" \
    || { echo "beacon-init: not every validator has a seed (above) — fix those and re-run (a seed already made is kept)" >&2; exit 1; }
  rec "beacon seeds present on the $NVALSET validators (made on each host, never copied; commitments only leave the hosts)"
  echo "BEACON-INIT DONE — each operator now keeps an OFFLINE, ENCRYPTED backup of its host's beacon-c22/beacon.seed.json; next: beacon-collect"
  ;;
beacon-collect)
  need_new_shas
  OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT
  echo "== beacon-collect (read-only toward the fleet): the $NVALSET public commitments → $BEACON_TSV $(date -u +%T)"
  EACH_OUT=$OUT each "$VAL_N" "set -e
    $(staged_ok)
    $(r_paths)
    [ -f \$BDIR/beacon.seed.json ] || { echo 'no beacon seed here — run beacon-init'; exit 1; }
    A=\$($S/rand-node address --key \$H_KEY | sed -n 's/^address: \\(.*\\)\$/\\1/p' | head -1)
    E=\$(mktemp); C=\$($S/rand-node beacon commitment --datadir \$BDIR 2>\$E) || { tail -1 \$E; rm -f \$E; echo 'the seed file does not re-derive'; exit 1; }
    W=\$(sed -n 's/^chain \\([0-9][0-9]*\\), validator \\([^,]*\\), .*/\\1 \\2/p' \$E | head -1); rm -f \$E
    [ \"\$W\" = \"$CHAIN_ID \$A\" ] || { echo \"the seed file names '\$W', not chain $CHAIN_ID and this key's address \$A\"; exit 1; }
    M=\$(stat -c %a \$BDIR/beacon.seed.json 2>/dev/null || stat -f %Lp \$BDIR/beacon.seed.json); [ \"\$M\" = 600 ] || [ \"\$M\" = 400 ] || { echo \"the seed file is mode \$M, not 0600\"; exit 1; }
    echo \"beacon \$H_NAME \$C \$A\"" \
    || { echo "beacon-collect: not every validator answered (above) — nothing written" >&2; exit 1; }
  if dry; then echo "[dry-run] local: write $BEACON_TSV — \"<name> <64 hex>\" for the $NVALSET validators, in GENESIS_NAMES + BONDED order"; exit 0; fi
  TMPTSV=$(mktemp)
  # shellcheck disable=SC2094  # the rm in the refusal is of the file being written, then exit
  { echo "# chain-22 beacon commitments, one per validator: what each host's own \`rand-node beacon init --chain-id 22\` made."
    echo "# Collected by deploy/cutover-fleet-chain22.sh beacon-collect $(date -u +%FT%TZ). Public: commitments only, never a seed."
    for n in $GENESIS_NAMES $BONDED; do
      l=$(grep '^beacon ' "$OUT/$n" | tail -1)
      # shellcheck disable=SC2086  # "beacon <name> <hex> <address>": split on purpose
      set -- $l
      [ "${2:-}" = "$n" ] && [[ "${3:-}" =~ ^[0-9a-f]{64}$ ]] && [[ ! "$3" =~ ^0+$ ]] || { echo "beacon-collect: $n answered '$l', not a commitment — nothing written" >&2; rm -f "$TMPTSV"; exit 1; }
      a=$(iget "$n" addr); [ "$a" = - ] || [ "$a" = "$4" ] || echo "beacon-collect: ⚠ $n's key derives $4 and the inventory says $a — the inventory's address column is stale; the cut and check-beacon-seed.sh use the key's" >&2
      echo "$n $3"
    done
  } > "$TMPTSV"
  [ "$(grep -v '^#' "$TMPTSV" | awk '{print $2}' | sort -u | wc -l | tr -d ' ')" = "$NVALSET" ] || { echo "beacon-collect: two validators gave the same commitment — nothing written" >&2; rm -f "$TMPTSV"; exit 1; }
  if [ -f "$BEACON_TSV" ]; then
    if diff -q <(grep -v '^#' "$BEACON_TSV") <(grep -v '^#' "$TMPTSV") >/dev/null; then echo "== $BEACON_TSV already holds these $NVALSET commitments — unchanged"; rm -f "$TMPTSV"
    else
      [ "${BEACON_TSV_REPLACE:-}" = 1 ] || { echo "beacon-collect: $BEACON_TSV exists with OTHER commitments — a genesis cut from it would not match these seeds; BEACON_TSV_REPLACE=1 moves it aside" >&2; rm -f "$TMPTSV"; exit 1; }
      mv "$BEACON_TSV" "$BEACON_TSV.replaced-$(date -u +%Y%m%dT%H%M%SZ)"; mv "$TMPTSV" "$BEACON_TSV"; echo "== the old $BEACON_TSV moved aside"
    fi
  else mkdir -p "$(dirname "$BEACON_TSV")"; mv "$TMPTSV" "$BEACON_TSV"; fi
  rec "collected $NVALSET beacon commitments into BEACON_TSV (sha256 $(file_sha "$BEACON_TSV" | cut -c1-16))"
  echo "COLLECTED — $BEACON_TSV holds $NVALSET commitments; next: bridge-stop, then snapshot"
  ;;
bridge-stop|bridge-start)
  if [ "$PHASE" = bridge-start ]; then
    [ "${BRIDGE_ON_CHAIN22:-}" = yes ] || dry || { echo "bridge-start: BRIDGE_ON_CHAIN22=yes is required — the guardian and relayer configs (chain id 22, the Rand cursor) are the bridge session's to switch first; nothing started" >&2; exit 1; }
    VERB=start; WANT=active
  else VERB=stop; WANT=inactive; fi
  if [ -z "$RELAYER_HOST" ] && [ "${RELAYER_HANDLED:-}" != yes ] && ! dry; then
    echo "$PHASE: RELAYER_HOST is unset — give the relayer's address (rand-relayer-1; not in the inventory), or RELAYER_HANDLED=yes if the bridge session ${VERB}s it by hand; nothing done" >&2; exit 1; fi
  # Before any host is contacted: the relayer address must not be a dropped validator's (archive2).
  if [ -n "$RELAYER_HOST" ]; then
    [[ "$RELAYER_HOST" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "$PHASE: RELAYER_HOST=$RELAYER_HOST is not an IPv4 address — refused" >&2; exit 1; }
    case " $DROPPED_IPS " in *" $RELAYER_HOST "*) echo "$PHASE: RELAYER_HOST is a dropped validator's address — refused; nothing done" >&2; exit 1;; esac
  fi
  echo "== $PHASE: rand-guardian on the six guardian hosts${RELAYER_HOST:+, rand-relayer on the relayer} $(date -u +%T)"
  each "$GUARD_N" "systemctl $VERB rand-guardian; sleep 1; s=\$(systemctl is-active rand-guardian || true); [ \"\$s\" = $WANT ] || { echo \"\$H_NAME rand-guardian is \$s\"; exit 1; }; echo \"\$H_NAME rand-guardian \$s\"" \
    || { echo "$PHASE: not every guardian is $WANT (above)" >&2; exit 1; }
  if [ -n "$RELAYER_HOST" ]; then
    if dry; then echo "[dry-run] ssh root@relayer($RELAYER_HOST) systemctl $VERB rand-relayer"
    else
      ssh -n -i "$RELAYER_SSH_KEY" -o IdentitiesOnly=yes -o "UserKnownHostsFile=$GUARDIAN_KNOWN_HOSTS" -o StrictHostKeyChecking=yes -o ConnectTimeout=20 -o BatchMode=yes "root@$RELAYER_HOST" \
        "systemctl $VERB rand-relayer; sleep 1; s=\$(systemctl is-active rand-relayer || true); echo \"relayer \$s\"; [ \"\$s\" = $WANT ]" || { echo "$PHASE: the relayer is not $WANT" >&2; exit 1; }
    fi
  fi
  rec "rand-guardian $WANT on the six guardian hosts; relayer: $(if [ -n "$RELAYER_HOST" ]; then echo "$WANT"; else echo "by hand (RELAYER_HANDLED)"; fi)"
  echo "$(tr '[:lower:]' '[:upper:]' <<<"$PHASE") DONE — guardians 7/8 on the laptop are the bridge session's (deploy/chain21-bridge-steps.md's lineage)"
  ;;
snapshot|balances|cut)
  # deploy/cut-chain22-genesis.sh, with PRUNED_SCAN_OK=1 (owner, 2026-11-19: e and obs1 prune below
  # 187556 and no unpruned chain-21 node exists) and, for the cut, the collected BEACON_TSV.
  ARGS=()
  # balances and the cut derive chain 22's addresses: both wallets, by path, and their sha256 on the
  # roll record (the cut script then tells set 9 from set 11 by the probe key's fingerprint).
  WALLETS_NOTE=
  if [ "$PHASE" != snapshot ]; then
    [ -x "${WALLET:-}" ] || dry || { echo "$PHASE: WALLET=${WALLET:-<unset>} is not executable — chain 21's v$OLD_VERSION rand (constraint set 9), which reads chain 21" >&2; exit 1; }
    [ -x "${WALLET22:-}" ] || dry || { echo "$PHASE: WALLET22=${WALLET22:-<unset>} is not executable — the v0.8.7 rand from the signed release (constraint set 11), which derives every chain-22 address; chain 21's rand would carry set-9 addresses no set-11 wallet can spend" >&2; exit 1; }
    if [ -x "${WALLET:-}" ] && [ -x "${WALLET22:-}" ]; then
      [ "$(file_sha "$WALLET")" != "$(file_sha "$WALLET22")" ] || { echo "$PHASE: WALLET and WALLET22 are the same binary — WALLET22 must be the v0.8.7 (set-11) rand" >&2; exit 1; }
      WALLETS_NOTE=", WALLET22 sha256 $(file_sha "$WALLET22" | cut -c1-16) (set 11), WALLET sha256 $(file_sha "$WALLET" | cut -c1-16) (chain 21)"
    fi
  fi
  case "$PHASE" in
    snapshot|balances)
      DIR=${2:?$PHASE <dir>}; ARGS=("$PHASE" "$DIR")
      [ -n "${CHAIN21_RPC:-}" ] || dry || { echo "$PHASE: CHAIN21_RPC is unset — open a tunnel to an archive (e or obs1): ssh -N -L 8545:127.0.0.1:8545 root@<e's address from the inventory>, then CHAIN21_RPC=http://127.0.0.1:8545" >&2; exit 1; }
      # The bridge must be down before the state the cut carries is read.
      echo "== the bridge daemons must be stopped before the $PHASE (read-only check on the guardian hosts)"
      each "$GUARD_N" "if systemctl is-active --quiet rand-guardian; then echo \"\$H_NAME rand-guardian STILL ACTIVE\"; exit 1; fi; echo \"\$H_NAME rand-guardian inactive\"" \
        || { echo "$PHASE: a guardian runs — bridge-stop first; nothing read" >&2; exit 1; }
      ;;
    cut)
      [ -f "$BEACON_TSV" ] || dry || { echo "cut: $BEACON_TSV is missing — beacon-collect first" >&2; exit 1; }
      if [ -f "$BEACON_TSV" ]; then
        [ "$(grep -v '^#' "$BEACON_TSV" | awk 'NF {print $1}' | sort | tr '\n' ' ')" = "$VALSET" ] \
          || { echo "cut: $BEACON_TSV does not name exactly chain 22's $NVALSET validators — re-run beacon-collect" >&2; exit 1; }
      fi
      ;;
  esac
  if dry; then echo "[dry-run] local: PRUNED_SCAN_OK=1 BEACON_TSV=$BEACON_TSV WALLET=${WALLET:-<unset>} WALLET22=${WALLET22:-<unset>} $CUT_SCRIPT ${ARGS[*]}"; exit 0; fi
  env -u DRY_RUN -u SELFTEST PRUNED_SCAN_OK=1 BEACON_TSV="$BEACON_TSV" CUT_RECORD="$CUT_RECORD" bash "$CUT_SCRIPT" ${ARGS[@]+"${ARGS[@]}"} \
    || { echo "$PHASE: $CUT_SCRIPT refused (above)" >&2; exit 1; }
  if [ "$PHASE" = cut ]; then rec "the cut ($CUT_SCRIPT) with PRUNED_SCAN_OK=1 and BEACON_TSV sha256 $(file_sha "$BEACON_TSV" | cut -c1-16)$WALLETS_NOTE"
  else rec "$CUT_SCRIPT $PHASE with PRUNED_SCAN_OK=1$WALLETS_NOTE"; fi
  ;;
push)
  need_local_node
  need_new_shas
  need_genesis "${2:?push <genesis file>}"
  clear_markers
  constraint_set_ok
  if [ "${SECOND_REBUILD_WAIVED:-}" = 1 ]; then
    require_cut_record "$CUT_RECORD" || { echo "push: a waiver is recorded in the cut record, and $CUT_RECORD is not a filled one — nothing pushed" >&2; exit 1; }
    WHY=${SECOND_REBUILD_WAIVED_REASON:-one operator holds every validator key and every host; no second operator exists to rebuild the genesis for this cut}
    echo "== ⚠⚠ SECOND_REBUILD_WAIVED=1 — pushing genesis $NEW WITHOUT a second operator's rebuild ($WHY); recorded in $CUT_RECORD"
    if ! grep -q "^second-rebuild-waived: .*genesis $NEW" "$CUT_RECORD"; then
      LINE=$(printf 'second-rebuild-waived: %s genesis %s by %s@%s: %s' "$(date -u +%FT%TZ)" "$NEW" "$(id -un)" "$(hostname -s)" "$WHY")
      local_write "append to $CUT_RECORD: $LINE" bash -c 'printf "%s\n" "$1" >> "$2"' _ "$LINE" "$CUT_RECORD"
    fi
  else
    second_rebuild_ok
  fi
  echo "== push $GENESIS (sha256 $SHA, genesis $NEW) to $NALL hosts $(date -u +%T)"
  for n in $ALL_N; do ( cp_to "$n" "$S/genesis-chain22.json" "$GENESIS" ) & done; wait
  each "$ALL_N" "set -e
    $(staged_ok)
    $(pushed_ok)
    echo \"\$H_NAME genesis $NEW verified by the staged v$WANT_VERSION binary, constraint set $WANT_CONSTRAINT_SET\"" \
    || { echo "push: not every host holds the genesis — do NOT stop chain 21; re-run push" >&2; exit 1; }
  rec "pushed genesis $NEW (file sha256 $SHA) to $NALL hosts; chain 21 still running"
  echo "PUSHED — chain 21 still runs; next: the owner's go, then CONFIRM_HALT_CHAIN21=halt-chain-21-for-$P … stop $GENESIS (alone; check \$?)"
  ;;
stop)
  GENESIS=${2:?stop <genesis file> — stop is gated on push (halt stops a fleet that does not run chain 21)}
  need_local_node
  need_genesis "$GENESIS"
  # THE HALT GUARD, before any host is contacted and before any marker is touched.
  PHRASE="halt-chain-21-for-$P"
  if [ "${CONFIRM_HALT_CHAIN21:-}" != "$PHRASE" ]; then
    if dry; then echo "== DRY RUN: the real stop REFUSES without CONFIRM_HALT_CHAIN21=$PHRASE; the dry run shows the rest and stops nothing"
    else
      echo "stop: REFUSED — this halts chain 21 on all $NALL hosts. Give the owner's go as CONFIRM_HALT_CHAIN21=$PHRASE (bound to this genesis, $NEW); got '${CONFIRM_HALT_CHAIN21:-nothing}'. Nothing contacted, nothing stopped" >&2; exit 1
    fi
  fi
  clear_markers
  need_new_shas
  need_old_shas
  second_rebuild_ok
  echo "== stop gate on $NALL hosts: the staged files at their pins, the pushed genesis $NEW, v$OLD_VERSION + chain 21's blob installed, no rand-guardian running, each validator's beacon seed opening its genesis commitment $(date -u +%T)"
  each "$ALL_N" "set -e
    $(staged_ok)
    $(staged_self)
    $(pushed_ok)
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET $VK:$OLD_VK_SHA; do n=\${b%%:*}; s=\${b#*:}
      [ -e /root/\$n.pre-c22 ] || [ \"\$(sha256sum /usr/local/bin/\$n | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"installed \$n is not chain 21's (switch would refuse to back it up)\"; exit 1; }
    done
    if [ \"\$H_KIND\" = guardian ]; then systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — bridge-stop first'; exit 1; }; fi
    $(r_paths)
    $(beacon_check $S/rand-node $S/genesis-chain22.json \$BDIR)
    echo \"\$H_NAME ready: staged v$WANT_VERSION, keys verified, genesis $NEW pushed, beacon \$BS\"" \
    || { echo "stop: not every host is ready (above) — NOTHING STOPPED; chain 21 keeps running" >&2; exit 1; }
  if dry; then echo "[dry-run] stop all $NALL (the real run, with the phrase)"; stop_all; exit 0; fi
  H0=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
  echo "== stop all $NALL $(date -u +%T) — chain 21 head at $BOOT1: ${H0:-?}"
  stop_all
  rec "stopped chain 21 (v$OLD_VERSION) on $NALL hosts at height ${H0:-?} at $BOOT1, for genesis $NEW (CONFIRM_HALT_CHAIN21 given)"
  echo "STOPPED $(date -u +%T) — next: switch $GENESIS (alone; check \$?)"
  ;;
halt)
  clear_markers
  echo "== halt: no host may be running chain 21 (its datadir -$OLD / data-21) $(date -u +%T)"
  each "$ALL_N" "D=\$(systemctl cat rand-node 2>/dev/null | grep -o -- '--datadir [^ ]*' | tail -1 | cut -d' ' -f2)
    if systemctl is-active --quiet rand-node; then
      [ -n \"\$D\" ] || { echo \"\$H_NAME is active and its unit names no --datadir — cannot tell its chain; refusing\"; exit 1; }
      case \"\$D\" in *-$OLD|*/data-21) echo \"\$H_NAME RUNS CHAIN 21 (\$D) — use stop <genesis>\"; exit 1;; esac
      G=\$(curl -s -m5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rand_getGenesisHash\",\"params\":[]}' | grep -oE '\"result\":\"[0-9a-f]+\"' | cut -d'\"' -f4 || true)
      [ \"\$G\" != '$OLD_HASH' ] || { echo \"\$H_NAME SERVES CHAIN 21's genesis — use stop <genesis>\"; exit 1; }
    fi
    echo \"\$H_NAME may halt (\$(systemctl is-active rand-node || true), \$D)\"" \
    || { echo "halt: a host runs chain 21 — nothing halted; chain 21 is stopped only by \`stop <genesis>\` with CONFIRM_HALT_CHAIN21" >&2; exit 1; }
  stop_all
  rec "halted (no host ran chain 21)"
  echo "HALTED $(date -u +%T) — next: rollback (or push + switch for a re-cut)"
  ;;
switch)
  need_local_node
  need_new_shas
  need_old_shas
  need_genesis "${2:?switch <genesis file>}"
  clear_markers
  second_rebuild_ok
  constraint_set_ok
  echo "== switch to chain 22, genesis $NEW (datadir suffix -$P / data-22), installing v$WANT_VERSION + the five key files $(date -u +%T)"
  # Order on each host: refuse while running; everything staged and pushed at its pins; the keys
  # verified by the STAGED binary — all before any change; then the backups (v$OLD_VERSION binaries
  # and chain 21's blob, once, only if they are chain 21's), the install, the installed keys re-
  # verified by the installed binary, the datadir init (its constraint-set marker), the beacon seed
  # copied in ON THE HOST and checked, the unit / drop-in rewrite.
  each "$ALL_N" "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    $(staged_ok)
    [ \"\$(sha256sum $S/genesis-chain22.json | cut -d' ' -f1)\" = '$SHA' ] || { echo 'genesis not pushed'; exit 1; }
    $(r_paths)
    D=/etc/systemd/system/rand-node.service.d
    if [ \"\$H_KIND\" = guardian ]; then
      systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — bridge-stop first'; exit 1; }
      if [ -f \$D/chain22.conf ]; then
        [ \"\$(cat /var/lib/randnode/data-22.genesis 2>/dev/null)\" = '$NEW' ] || { echo 'chain22.conf already runs another chain-22 genesis — a re-cut over a switched fleet needs rollback first; nothing switched'; exit 1; }
      else
        grep -q -- '--datadir /var/lib/randnode/data-21 ' \$D/chain21.conf || { echo 'chain21.conf has no data-21 datadir — nothing switched'; exit 1; }
      fi
    else
      grep -q -- '-$P ' /etc/systemd/system/rand-node.service || grep -q -- \"--datadir \$H_DD \" /etc/systemd/system/rand-node.service \\
        || { echo 'unit names neither the inventory datadir (chain 21) nor -$P (this genesis) — a re-cut over a switched fleet needs rollback first; nothing switched'; exit 1; }
    fi
    if [ \"\$H_VAL\" = 1 ]; then [ -f \$BDIR/beacon.seed.json ] || { echo 'no beacon seed in the staging dir — beacon-init; nothing switched'; exit 1; }; fi
    $(vk_check $S/rand-node $S/$VK)
    $(pvk_check $S/rand-node $S)
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET $VK:$OLD_VK_SHA; do n=\${b%%:*}; s=\${b#*:}
      if [ ! -e /root/\$n.pre-c22 ]; then
        [ \"\$(sha256sum /usr/local/bin/\$n | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"installed \$n is not chain 21's — no backup made, nothing switched\"; exit 1; }
        cp -a /usr/local/bin/\$n /root/\$n.pre-c22
      fi
    done
    install -m 755 $S/rand-node /usr/local/bin/rand-node; install -m 755 $S/rand /usr/local/bin/rand
    install -m 644 $S/$VK /usr/local/bin/$VK
    for f in $PVK_FILES; do install -m 644 $S/\$f /usr/local/bin/\$f; done
    $(vk_check /usr/local/bin/rand-node /usr/local/bin/$VK)
    $(pvk_check /usr/local/bin/rand-node /usr/local/bin)
    if [ \"\$H_KIND\" = guardian ]; then
      V=/var/lib/randnode
      if [ -d \$V/data-22/db ] && [ \"\$(cat \$V/data-22.genesis 2>/dev/null)\" != '$NEW' ]; then
        STALE=\$V/data-22.stale-\$(cut -c1-8 \$V/data-22.genesis 2>/dev/null || echo unknown)
        [ ! -e \$STALE ] || { echo \"\$V/data-22 is stale and \$STALE already exists — sort them out by hand\"; exit 1; }
        mv \$V/data-22 \$STALE; rm -f \$V/data-22.genesis
      fi
      install -d -o randnode -g randnode \$V/data-22
      install -m 644 -o randnode -g randnode $S/genesis-chain22.json \$HG
      [ -d \$V/data-22/db ] || runuser -u randnode -- /usr/local/bin/rand-node init --datadir \$V/data-22 --genesis \$HG >/dev/null
      echo '$NEW' > \$V/data-22.genesis
    else
      if [ -L \"\$H_DD\" ]; then T=\$(dirname \$(readlink \"\$H_DD\"))/\$(basename \$NEWDIR); mkdir -p \$T; ln -sfn \$T \$NEWDIR; fi
      [ -d \$NEWDIR/db ] || /usr/local/bin/rand-node init --datadir \$NEWDIR --genesis \$HG >/dev/null
    fi
    $(cs_check \$NEWDIR)
    if [ \"\$H_VAL\" = 1 ]; then
      if [ -f \$NEWDIR/beacon.seed.json ]; then cmp -s \$BDIR/beacon.seed.json \$NEWDIR/beacon.seed.json || { echo \"\$NEWDIR/beacon.seed.json differs from the staging seed — sort it out by hand\"; exit 1; }
      else install -m 600 -o \$OWN -g \$OWN \$BDIR/beacon.seed.json \$NEWDIR/beacon.seed.json; fi
    fi
    $(beacon_check /usr/local/bin/rand-node \$HG \$NEWDIR)
    if [ \"\$H_KIND\" = guardian ]; then
      if [ -f \$D/chain21.conf ]; then
        sed 's#--datadir /var/lib/randnode/data-21 #--datadir /var/lib/randnode/data-22 #' \$D/chain21.conf > \$D/chain22.conf
        mv \$D/chain21.conf /root/chain21.conf.c21
      fi
      grep -q -- '--datadir /var/lib/randnode/data-22 ' \$D/chain22.conf
    else
      U=/etc/systemd/system/rand-node.service
      if ! grep -q -- '-$P ' \$U; then
        [ -e /root/rand-node.service.$OLD.bak ] || cp -a \$U /root/rand-node.service.$OLD.bak
        sed -i \"s#--datadir \$H_DD #--datadir \$NEWDIR #\" \$U
      fi
      grep -q -- \"--datadir \$NEWDIR \" \$U
    fi
    systemctl daemon-reload
    echo \"\$H_NAME ready: \$(/usr/local/bin/rand-node --version), keys verified, set $WANT_CONSTRAINT_SET, beacon \$BS, \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"" \
    || { echo "switch: some hosts are not ready — fix them and re-run switch; do NOT start. Or roll back (the fleet is stopped): rollback → start → wait21, then the bridge on chain 21" >&2; exit 1; }
  mark "switched-$P" "$NEW"
  rec "switched $NALL hosts to genesis $NEW: v$WANT_VERSION installed, *.pre-c22 kept, constraint-set marker $WANT_CONSTRAINT_SET, beacon seeds checked on $NVALSET validators"
  echo "SWITCHED — marker $MARKER_DIR/switched-$P written; next: start (alone; check \$?)"
  ;;
rollback)
  clear_markers
  need_old_shas
  echo "== rollback to chain 21 (datadir -$OLD / data-21, v$OLD_VERSION binaries, chain 21's msauth blob) $(date -u +%T)"
  each "$ALL_N" "set -e
    systemctl is-active --quiet rand-node && { echo 'STILL RUNNING — refusing'; exit 1; }
    D=/etc/systemd/system/rand-node.service.d
    if [ \"\$H_KIND\" = guardian ]; then systemctl is-active --quiet rand-guardian && { echo 'rand-guardian still active — stop the bridge first'; exit 1; }; fi
    for b in rand-node:$OLD_SHA rand:$OLD_SHA_WALLET $VK:$OLD_VK_SHA; do n=\${b%%:*}; s=\${b#*:}
      if [ \"\$(sha256sum /usr/local/bin/\$n 2>/dev/null | cut -d' ' -f1)\" != \"\$s\" ]; then
        [ -f /root/\$n.pre-c22 ] || { echo \"no /root/\$n.pre-c22 to restore\"; exit 1; }
        [ \"\$(sha256sum /root/\$n.pre-c22 | cut -d' ' -f1)\" = \"\$s\" ] || { echo \"/root/\$n.pre-c22 is not chain 21's\"; exit 1; }
        m=755; [ \$n != $VK ] || m=644; install -m \$m /root/\$n.pre-c22 /usr/local/bin/\$n
      fi
    done
    if [ \"\$H_KIND\" = guardian ]; then
      if [ -f \$D/chain22.conf ]; then
        [ -f /root/chain21.conf.c21 ] || { echo 'no /root/chain21.conf.c21 to restore'; exit 1; }
        mv /root/chain21.conf.c21 \$D/chain21.conf; rm -f \$D/chain22.conf
      fi
      grep -q -- '--datadir /var/lib/randnode/data-21 ' \$D/chain21.conf
      [ -d /var/lib/randnode/data-21/db ] || { echo 'data-21 has no db'; exit 1; }
    else
      U=/etc/systemd/system/rand-node.service
      if ! grep -q -- \"--datadir \$H_DD \" \$U; then
        [ -f /root/rand-node.service.$OLD.bak ] || { echo 'no /root/rand-node.service.$OLD.bak to restore'; exit 1; }
        grep -q -- \"--datadir \$H_DD \" /root/rand-node.service.$OLD.bak || { echo 'the backup unit does not run the inventory datadir'; exit 1; }
        cp -a /root/rand-node.service.$OLD.bak \$U
      fi
      [ -d \"\$H_DD/db\" ] || { echo \"\$H_DD has no db\"; exit 1; }
    fi
    systemctl daemon-reload
    echo \"\$H_NAME on chain 21: \$(/usr/local/bin/rand-node --version), \$(systemctl cat rand-node | grep -o -- '--datadir [^ ]*' | tail -1)\"" \
    || { echo "rollback: some hosts are not back on chain 21 — fix them and re-run rollback; do NOT start" >&2; exit 1; }
  mark "rollback-$OLD" "ROLLBACK to chain 21 ($OLD)"
  rec "rolled $NALL hosts back to chain 21: v$OLD_VERSION binaries and chain 21's msauth blob restored from *.pre-c22, units / drop-ins restored"
  echo "ROLLED BACK — marker $MARKER_DIR/rollback-$OLD written; next: start (alone; check \$?), then the bridge on chain 21"
  ;;
start|start-archives)
  if dry; then
    echo "[dry-run] local: $PHASE needs $( [ "$PHASE" = start ] && echo "exactly one switched-* or rollback-* marker" || echo "first-<P> and limits-<P> markers") in $MARKER_DIR"
    KIND=switch; P="<P>"; MARK=""
  elif [ "$PHASE" = start ]; then
    # shellcheck disable=SC2046  # marker paths have no spaces
    set -- $(markers 'switched-*') $(markers 'rollback-*')
    [ $# -ge 1 ] || { echo "start: no switched-<P> / rollback-* marker in $MARKER_DIR — a successful switch (or rollback) writes it; refusing" >&2; exit 1; }
    [ $# -eq 1 ] || { echo "start: $# markers ($*) — ambiguous; remove the stale ones by hand; refusing" >&2; exit 1; }
    MARK=$1; case "$MARK" in */rollback-*) KIND=rollback;; *) KIND=switch; P=${MARK##*/switched-};; esac
    echo "== start on the $KIND recorded in $MARK: $(cat "$MARK")"
  else
    # shellcheck disable=SC2046
    set -- $(markers 'first-*')
    [ $# -eq 1 ] || { echo "start-archives: no single first-<P> marker in $MARKER_DIR — start (the first group) writes it; refusing" >&2; exit 1; }
    MARK=$1; KIND=switch; P=${MARK##*/first-}
    [ -f "$MARKER_DIR/limits-$P" ] || { echo "start-archives: no limits-$P marker — run check-limits against $BOOT1 first; refusing" >&2; exit 1; }
  fi
  GATE=""
  if [ "$KIND" = switch ]; then
    if [ "$PHASE" = start ]; then GROUP=$FIRST_N; GHOSTS=$ALL_N; else GROUP=$LATE_N; GHOSTS=$LATE_N; fi
    echo "== the start gate on $(wc -w <<<"$GHOSTS" | tr -d ' ') hosts: msauth + perps keys by the installed rand-node, constraint set $WANT_CONSTRAINT_SET, each validator's beacon seed $(date -u +%T)"
    each "$GHOSTS" "set -e
      $(installed_gate)
      echo \"\$H_NAME keys verified, set $WANT_CONSTRAINT_SET, beacon \$BS\"" \
      || { echo "$PHASE: the gate failed on a host (above) — nothing started (re-run switch on those hosts)" >&2; exit 1; }
    GATE="set -e; $(installed_gate);"
  else GROUP=$ALL_N; fi
  [ -n "$GROUP" ] || { echo "$PHASE: no host in this group"; exit 0; }
  ONE="$GATE systemctl start rand-node; sleep 2; systemctl is-active --quiet rand-node || { echo \"\$H_NAME NOT ACTIVE after start\"; exit 1; }; echo \"\$H_NAME active\""
  if dry; then each "$GROUP" "$ONE"; exit 0; fi
  RES=$(mktemp -d)
  start_one() { if on "$1" "$(hvars "$1")$ONE" > "$RES/$1" 2>&1; then echo ok > "$RES/$1.rc"; else echo FAIL > "$RES/$1.rc"; fi; }
  FAILED=""; OKN=0
  if [ "$PHASE" = start ]; then
    echo "== start the bootstraps ($BOOT_NAMES) $(date -u +%T)"
    for n in $BOOT_NAMES; do start_one "$n"; printf '   %-8s %s %s\n' "$n" "$(cat "$RES/$n.rc")" "$(tail -1 "$RES/$n")"; done
  fi
  echo "== start $( [ "$PHASE" = start ] && echo "the rest of the $( [ "$KIND" = switch ] && echo first group || echo fleet)" || echo "the archives / observers ($GROUP)") together $(date -u +%T)"
  for n in $GROUP; do case " $BOOT_NAMES " in *" $n "*) [ "$PHASE" = start ] && continue;; esac; start_one "$n" & done; wait
  for n in $GROUP; do
    case " $BOOT_NAMES " in *" $n "*) [ "$PHASE" = start ] || printf '   %-8s %s %s\n' "$n" "$(cat "$RES/$n.rc")" "$(tail -1 "$RES/$n")";; *) printf '   %-8s %s %s\n' "$n" "$(cat "$RES/$n.rc")" "$(tail -1 "$RES/$n")";; esac
    if [ "$(cat "$RES/$n.rc")" = ok ]; then OKN=$((OKN+1)); else FAILED="$FAILED $n"; fi
  done
  rm -rf "$RES"
  if [ -n "$FAILED" ]; then
    rec "NOT STARTED on:$FAILED ($OKN of $(wc -w <<<"$GROUP" | tr -d ' ') active)"
    echo "$PHASE: NOT STARTED on:$FAILED — $OKN of $(wc -w <<<"$GROUP" | tr -d ' ') active$( [ "$PHASE" = start ] && [ "$KIND" = switch ] && { [ "$OKN" -ge "$QUORUM" ] && echo " (≥ quorum $QUORUM: chain 22 can commit)" || echo " (BELOW quorum $QUORUM: chain 22 cannot commit)"; }); the marker $MARK is kept; fix those hosts and re-run $PHASE (or halt + rollback)" >&2; exit 1
  fi
  if [ "$KIND" = rollback ]; then
    local_write "rm -f $MARK" rm -f "$MARK"
    rec "started chain 21 again on $OKN hosts (rollback)"
    echo "START-DONE $(date -u +%T) — all $NALL active on chain 21; next: wait21"
  elif [ "$PHASE" = start ]; then
    local_write "rm -f $MARK" rm -f "$MARK"; mark "first-$P" "first group started"
    rec "started the first group on chain 22: $OKN validators ($FIRST_N), quorum $QUORUM; bootstraps $BOOT_NAMES first"
    echo "START-DONE $(date -u +%T) — $OKN of the first group active (≥ quorum $QUORUM); next: check-limits <genesis>, then start-archives"
  else
    unmark "first-$P"; unmark "limits-$P"
    rec "started the archives / observers on chain 22: $GROUP"
    echo "START-ARCHIVES-DONE $(date -u +%T) — next: wait <genesis>"
  fi
  ;;
check-limits)
  GENESIS=${2:?check-limits <genesis file>}
  need_local_node
  need_genesis "$GENESIS"
  RPC=${CHECK_LIMITS_RPC:-}
  TUN=""
  if [ -z "$RPC" ]; then
    PORT=${CHECK_LIMITS_PORT:-18545}
    if dry; then echo "[dry-run] local: ssh -N -L 127.0.0.1:$PORT:127.0.0.1:8545 root@$BOOT1 (a tunnel to the first node), then"
    else
      ip=$(iget "$BOOT1" ip); o=(); while IFS= read -r l; do o+=("$l"); done < <(sshopts "$BOOT1")
      ssh -N -o ExitOnForwardFailure=yes "${o[@]}" -L "127.0.0.1:$PORT:127.0.0.1:8545" "root@$ip" & TUN=$!
      trap '[ -z "$TUN" ] || kill "$TUN" 2>/dev/null || true' EXIT
      for _ in $(seq 1 15); do curl -s -m2 -o /dev/null "http://127.0.0.1:$PORT" && break; sleep 1; done
    fi
    RPC=http://127.0.0.1:$PORT
  fi
  if dry; then echo "[dry-run] local: NODE=$LOCAL_NODE $CUT_SCRIPT check-limits $RPC $GENESIS; on success write $MARKER_DIR/limits-$P"; exit 0; fi
  echo "== check-limits against $BOOT1 ($RPC) $(date -u +%T)"
  if env -u DRY_RUN -u SELFTEST NODE="$LOCAL_NODE" bash "$CUT_SCRIPT" check-limits "$RPC" "$GENESIS"; then
    mark "limits-$P" "$NEW"
    rec "check-limits passed against $BOOT1 for genesis $NEW"
    echo "CHECK-LIMITS OK — next: start-archives"
  else
    rec "check-limits FAILED against $BOOT1 for genesis $NEW"
    echo "check-limits: the cut script refused (above) — the archives are not started until it passes" >&2; exit 1
  fi
  ;;
wait)
  GENESIS=${2:?wait <genesis file>}
  need_local_node
  read -r NEW _ <<<"$(genesis_hash "$GENESIS")"; P=${NEW:0:8}
  if dry; then
    echo "[dry-run] every ${WAIT_SLEEP:-20} s, up to $WAIT_TRIES times: on each of the $NALL hosts rand_getGenesisHash == $NEW, rand_getHealth ok, rand_status.msauth_key loaded, perps_keys loaded (4); $BOOT1's height > 2; then check-beacon-seed.sh --rpc on the $NVALSET validators"
    rpc "$BOOT1" rand_status; each "$VAL_N" "$(r_paths); $(beacon_check /usr/local/bin/rand-node \$HG \$NEWDIR http://127.0.0.1:8545)"; exit 0
  fi
  [ ${#NEW} -eq 64 ] || { echo "wait: could not derive the genesis hash" >&2; exit 1; }
  for _ in $(seq 1 "$WAIT_TRIES"); do
    sleep "${WAIT_SLEEP:-20}"; ok=0; late=""
    for n in $ALL_N; do
      g=$(rpc "$n" rand_getGenesisHash | grep -oE '"result":"[0-9a-f]+"' | cut -d'"' -f4 || true)
      s=$(rpc "$n" rand_getHealth | grep -oE '"status":"[a-z_]+"' | cut -d'"' -f4 || true)
      st=$(rpc "$n" rand_status)
      k=$(grep -oE '"msauth_key":"[a-z]+"' <<<"$st" | cut -d'"' -f4 || true)
      pk=$(tr -d ' ' <<<"$st" | grep -oE '"perps_keys":\{[^}]*\}' || true)
      if [ "$g" = "$NEW" ] && [ "$s" = ok ] && [ "$k" = loaded ] && grep -q '"source":"loaded"' <<<"$pk" && grep -q '"keys":4' <<<"$pk"; then ok=$((ok+1)); else late="$late $n"; fi
    done
    H=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
    echo "  $(date -u +%T) $ok/$NALL on chain 22, healthy, msauth + perps keys loaded; $BOOT1 height ${H:-?}${late:+; not yet:$late}"
    if [ "$ok" = "$NALL" ] && [ -n "$H" ] && [ "$H" -gt 2 ]; then
      echo "== every validator's beacon seed against its running node (check-beacon-seed.sh --rpc)"
      each "$VAL_N" "set -e; $(r_paths); $(beacon_check /usr/local/bin/rand-node \$HG \$NEWDIR http://127.0.0.1:8545); echo \"\$H_NAME beacon seed opens the commitment in force\"" \
        || { rec "all $NALL on $NEW at height $H, but a validator's beacon seed does not open its commitment in force"; echo "wait: a validator's beacon seed does not open its commitment in force (above) — it misses its slots" >&2; exit 1; }
      rec "CHAIN 22 LIVE: all $NALL hosts on $NEW, healthy, msauth + perps keys loaded, $BOOT1 at height $H; beacon seeds open on $NVALSET validators"
      echo "=== $(date -u +%T) CUTOVER DONE: all $NALL on $NEW, committing at $H — next: bridge-start, verify"; exit 0
    fi
  done
  echo "=== not all $NALL healthy after $WAIT_TRIES polls — check the laggards"; exit 1
  ;;
verify)
  GENESIS=${2:?verify <genesis file>}
  need_local_node
  need_genesis "$GENESIS"
  echo "== verify: chain 22's CHAIN_CONSTRAINT_SETS row in this tree (issue #166) $(date -u +%T)"
  if constraint_set_ok row; then
    rec "verified: CHAIN_CONSTRAINT_SETS holds (22, $NEW, $WANT_CONSTRAINT_SET); a release for chain 22 may be tagged from this tree"
    echo "VERIFIED — the row is there; status follows"
  else
    rec "verify: CHAIN_CONSTRAINT_SETS does NOT hold chain 22's row yet"
    echo "verify: add the row the cut printed (cut record constraint-set-row:), commit, and re-run" >&2; exit 1
  fi
  for n in $ALL_N; do (
    v=$(rpc "$n" rand_getVersion | grep -oE '"version":"[^"]+"' | tr '\n' ' ' || true)
    h=$(rpc "$n" rand_status | grep -oE '"height":[0-9]+' | head -1 || true)
    printf '   %-8s %s %s\n' "$n" "$v" "${h:-no answer}" ) & done; wait
  ;;
wait21)
  if dry; then echo "[dry-run] every ${WAIT_SLEEP:-20} s, up to $WAIT_TRIES times: each of the $NALL hosts serves genesis $OLD…, healthy; $BOOT1's height strictly above the previous poll's"; rpc "$BOOT1" rand_status; exit 0; fi
  PREV=""
  for _ in $(seq 1 "$WAIT_TRIES"); do
    sleep "${WAIT_SLEEP:-20}"; ok=0; late=""
    for n in $ALL_N; do
      g=$(rpc "$n" rand_getGenesisHash | grep -oE '"result":"[0-9a-f]+"' | cut -d'"' -f4 || true)
      s=$(rpc "$n" rand_getHealth | grep -oE '"status":"[a-z_]+"' | cut -d'"' -f4 || true)
      if [ "$g" = "$OLD_HASH" ] && [ "$s" = ok ]; then ok=$((ok+1)); else late="$late $n"; fi
    done
    H=$(rpc "$BOOT1" rand_status | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2 || true)
    echo "  $(date -u +%T) $ok/$NALL on chain 21 and healthy; $BOOT1 height ${H:-?} (previous ${PREV:-?})${late:+; not yet:$late}"
    if [ "$ok" = "$NALL" ] && [ -n "$H" ] && [ -n "$PREV" ] && [ "$H" -gt "$PREV" ]; then
      rec "chain 21 committing again on all $NALL ($BOOT1 at $H)"
      echo "=== $(date -u +%T) CHAIN 21 COMMITTING AGAIN: all $NALL on $OLD…, $BOOT1 at $H (was $PREV)"; exit 0; fi
    PREV=$H
  done
  echo "=== chain 21 is not committing on all $NALL after 30 min"; exit 1
  ;;
quiet)
  GENESIS=${2:?quiet <genesis file>}
  if [ ! -f "$GENESIS" ]; then
    dry && { echo "== DRY RUN: $GENESIS is not a file — quiet would compare the bootstraps' rand_getBridgeState with its burn_sequence and Σ locked"; rpc "$BOOT1" rand_getBridgeState; exit 0; }
    echo "quiet: $GENESIS is not a file — the chain-22 genesis the fleet runs" >&2; exit 1
  fi
  WANT=$(python3 -c 'import json,sys
g=json.load(open(sys.argv[1])); b=g["bridge"]
locked=sum(int(k.get("locked",0)) for t in g["tokens"]["tokens"] for k in t["backings"])
print(b["burn_sequence"], locked)' "$GENESIS")
  echo "== genesis: burn_sequence ${WANT% *}, Σ locked ${WANT#* }"
  if dry; then rpc "$BOOT1" rand_getBridgeState; exit 0; fi
  bad=0
  for n in $BOOT_NAMES; do
    GOT=$(rpc "$n" rand_getBridgeState | python3 -c 'import json,sys
try:
    r=json.load(sys.stdin)["result"]
    print(r["burn_sequence"], sum(int(a.get("locked") or 0) for a in r.get("assets",[])))
except Exception as e:
    print("unreadable", e)' || true)
    if [ "$GOT" = "$WANT" ]; then echo "   $n: burn_sequence ${GOT% *}, Σ locked ${GOT#* } — as at genesis"
    else echo "   $n: $GOT — NOT the genesis values: something was burned or minted on chain 22"; bad=1; fi
  done
  [ $bad = 0 ] || { echo "quiet: chain 22 has bridge activity — a rollback loses it; the owner decides" >&2; exit 1; }
  echo "QUIET — nothing burned or minted on chain 22 (as the bootstraps report)"
  ;;
status)
  for n in $ALL_N; do (
    v=$(rpc "$n" rand_getVersion | grep -oE '"version":"[^"]+"|"git_sha":"[a-z0-9]+"|"chain_id":[0-9]+' | tr '\n' ' ' || true)
    h=$(rpc "$n" rand_status | grep -oE '"height":[0-9]+|"msauth_key":"[a-z]+"' | head -2 | tr '\n' ' ' || true)
    printf '   %-8s %s %s\n' "$n" "$v" "${h:-no answer}" ) & done; wait
  echo "   ($DROPPED_VALIDATORS: dropped, not contacted)"
  ;;
*) echo "unknown phase $PHASE" >&2; exit 1 ;;
esac
