#!/usr/bin/env bash
# All-stop, all-start roll of a same-chain node-only build (v0.5.5's procedure, kept for v0.5.6):
#
#   deploy/roll-all.sh <rand-node binary> <rand binary> <expected sha256 of rand-node> [<expected sha256 of rand>] [<msauth-vk-production.bin>]
#
#   The wallet's sha is the fourth argument or WANT_SHA_WALLET; without one the roll is refused —
#   `rand` is installed as root and run as root, so it is checked exactly like rand-node (OPS-2).
#
#   The msauth verifier key (private multisig, v0.8.0+, plan Task 2b) is the fifth argument or
#   MSAUTH_VK. A node on a chain naming `hc_auth_multisig` refuses to start without it, so the roll
#   is refused without one unless NO_MSAUTH_VK=1 says the chain has no multisig — itself refused
#   when any droplet's genesis (`<datadir>/genesis.json` of its rand-node unit) names
#   hc_auth_multisig or cannot be read, before anything is copied. Each host checks
#   the copy with the binary being installed: `rand-node.new keygen-msauth-vk --check` must equal
#   its own `--print-pinned production` (the SHA-256 pin compiled into that build); a mismatch
#   skips that host's install, binaries included. Installed to
#   /usr/local/bin/msauth-vk-production.bin, beside the binary, before anything restarts. Node A
#   on this Mac (when its launchd job is installed) gets the same file beside its own binary.
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
. "$(dirname "$0")/lib/fleet-env.sh"
require_fleet_env
NODE_BIN=$1; WALLET_BIN=$2; WANT=$3; WANT_WALLET=${4:-${WANT_SHA_WALLET:-}}; MSAUTH_VK=${5:-${MSAUTH_VK:-}}
[ -n "$WANT_WALLET" ] || { echo "no expected sha256 for $WALLET_BIN (fourth argument or WANT_SHA_WALLET) — the wallet binary is installed as root too"; exit 1; }
if [ -n "$MSAUTH_VK" ]; then
  [ -f "$MSAUTH_VK" ] || { echo "no msauth key blob at $MSAUTH_VK"; exit 1; }
  VK_SHA=$(shasum -a 256 "$MSAUTH_VK" | cut -d' ' -f1)
elif [ "${NO_MSAUTH_VK:-}" != 1 ]; then
  echo "no msauth-vk-production.bin (fifth argument or MSAUTH_VK): a v0.8.0+ node on a chain naming hc_auth_multisig refuses to start without it; pass it, or NO_MSAUTH_VK=1 for a chain without multisig"; exit 1
fi
. deploy/lib/verify-release.sh
if [ -n "${RELEASE_SUMS:-}" ] || [ -n "${RELEASE_SIG:-}" ]; then
  { [ -n "${RELEASE_SUMS:-}" ] && [ -n "${RELEASE_SIG:-}" ]; } || { echo "RELEASE_SUMS and RELEASE_SIG go together: the release's SHA256SUMS and its SHA256SUMS.sig"; exit 1; }
  verify_release_sums "$RELEASE_SUMS" "$RELEASE_SIG" || exit 1
  verify_binary "$NODE_BIN" "$RELEASE_SUMS" rand-node || exit 1
  verify_binary "$WALLET_BIN" "$RELEASE_SUMS" rand || exit 1
  [ "$WANT" = "$(release_sha "$RELEASE_SUMS" rand-node)" ] || { echo "the expected rand-node sha256 given here is not the one the signed SHA256SUMS lists — not rolling"; exit 1; }
  [ "$WANT_WALLET" = "$(release_sha "$RELEASE_SUMS" rand)" ] || { echo "the expected rand sha256 given here is not the one the signed SHA256SUMS lists — not rolling"; exit 1; }
  [ -z "$MSAUTH_VK" ] || verify_binary "$MSAUTH_VK" "$RELEASE_SUMS" msauth-vk-production.bin || exit 1
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
IPS=$(grep -oE '/ip4/[0-9.]+' "$NODES_ENV" | cut -d/ -f3 | sort -u)
# NO_MSAUTH_VK=1 says "this chain has no multisig"; a host whose genesis names hc_auth_multisig
# proves it wrong, and its new node would refuse to start without the blob (plan Task 3). So,
# before anything is copied, every droplet's genesis is read where the node reads it: the
# `--datadir` of the installed rand-node unit (the last one, either `--datadir P` or
# `--datadir=P`, as the cutover scripts read it),
# `<datadir>/genesis.json` (`node::load_genesis`). The check is a grep for the key
# `"hc_auth_multisig"`: serde writes every present field under its name and omits an absent one,
# so the key is in the file exactly when the genesis names it — no binary, no RPC, no running
# node needed (the cheapest reliable read; `rand_status` would need the node up and Task 5's
# field). A host whose genesis cannot be read refuses the roll too: "no multisig" is then
# unproved. Node A's launchd job (retired since 2026-09-27) is not read; pass the blob if it runs.
if [ -z "$MSAUTH_VK" ]; then
  for ip in $IPS; do
    ms=$(ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'D=$(systemctl cat rand-node 2>/dev/null | grep -oE -- "--datadir[= ][^ ]*" | tail -1 | sed -E "s/^--datadir[= ]//"); [ -n "$D" ] && [ -r "$D/genesis.json" ] || { echo "unreadable ${D:-<no --datadir in the rand-node unit>}/genesis.json"; exit 0; }; if grep -q "\"hc_auth_multisig\"" "$D/genesis.json"; then echo "multisig $D/genesis.json"; else echo "plain"; fi' 2>/dev/null)
    case "$ms" in
      plain) ;;
      multisig*) echo "NO_MSAUTH_VK=1 but $ip's genesis names hc_auth_multisig (${ms#multisig }): its node refuses to start without msauth-vk-production.bin — pass it (fifth argument or MSAUTH_VK)"; exit 1 ;;
      *) echo "NO_MSAUTH_VK=1 but $ip's genesis could not be read (${ms:-ssh failed}): cannot confirm the chain has no hc_auth_multisig — pass msauth-vk-production.bin, or fix the host first"; exit 1 ;;
    esac
  done
  [ -f ~/Library/LaunchAgents/org.randprotocol.node-a.plist ] && echo "   note: node A's launchd job is installed and its genesis is not checked under NO_MSAUTH_VK=1"
fi
echo "== install (no restart) $(date -u +%H:%M:%S)"
# The msauth key blob's check and install, run on the host before the binaries' install (empty
# when the roll carries no blob): the copy is intact (sha256) and is the blob the build being
# installed pins (SHA-256 too, `keygen-msauth-vk --check` against `--print-pinned production`).
# Under NO_MSAUTH_VK=1 a blob already installed on a host is still held to the new build's pin:
# a stale blob beside a new binary would refuse that node's start the day its chain names
# hc_auth_multisig, so a mismatch skips the host now, while it is visible.
VK_STEP="if [ -f /usr/local/bin/msauth-vk-production.bin ]; then vk_got=\$(/root/rand-node.new keygen-msauth-vk --check /usr/local/bin/msauth-vk-production.bin) && vk_pin=\$(/root/rand-node.new keygen-msauth-vk --print-pinned production) && [ \"\$vk_got\" = \"\$vk_pin\" ] || { echo \"   installed msauth key blob is not this build's pin \${vk_pin:-?} (has \${vk_got:-?}), skipping\"; rm -f /root/rand-node.new /root/rand.new; exit 1; }; fi;"
if [ -n "$MSAUTH_VK" ]; then
  VK_STEP="[ \"\$(sha256sum /root/msauth-vk-production.bin.new | cut -d' ' -f1)\" = \"$VK_SHA\" ] && vk_got=\$(/root/rand-node.new keygen-msauth-vk --check /root/msauth-vk-production.bin.new) && vk_pin=\$(/root/rand-node.new keygen-msauth-vk --print-pinned production) && [ \"\$vk_got\" = \"\$vk_pin\" ] || { echo \"   msauth key blob is not the pinned \${vk_pin:-?} (has \${vk_got:-?}), skipping\"; rm -f /root/rand-node.new /root/rand.new /root/msauth-vk-production.bin.new; exit 1; }; install -m 644 /root/msauth-vk-production.bin.new /usr/local/bin/msauth-vk-production.bin; rm -f /root/msauth-vk-production.bin.new;"
fi
for ip in $IPS; do
  scp -q -o ConnectTimeout=15 -o BatchMode=yes "$NODE_BIN" root@$ip:/root/rand-node.new && scp -q -o ConnectTimeout=15 -o BatchMode=yes "$WALLET_BIN" root@$ip:/root/rand.new || { echo "   $ip: copy failed"; ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'rm -f /root/rand-node.new /root/rand.new /root/msauth-vk-production.bin.new' 2>/dev/null; continue; }
  if [ -n "$MSAUTH_VK" ]; then
    scp -q -o ConnectTimeout=15 -o BatchMode=yes "$MSAUTH_VK" root@$ip:/root/msauth-vk-production.bin.new || { echo "   $ip: msauth key copy failed"; ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'rm -f /root/rand-node.new /root/rand.new /root/msauth-vk-production.bin.new' 2>/dev/null; continue; }
  fi
  ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip "set -e; [ \"\$(sha256sum /root/rand-node.new | cut -d' ' -f1)\" = \"$WANT\" ] && [ \"\$(sha256sum /root/rand.new | cut -d' ' -f1)\" = \"$WANT_WALLET\" ] || { echo '   sha mismatch, skipping'; rm -f /root/rand-node.new /root/rand.new /root/msauth-vk-production.bin.new; exit 1; }; chmod 755 /root/rand-node.new; $VK_STEP cp -f /usr/local/bin/rand-node /root/rand-node.prev; install -m 755 /root/rand-node.new /usr/local/bin/rand-node; install -m 755 /root/rand.new /usr/local/bin/rand; rm -f /root/rand-node.new /root/rand.new; echo \"   \$(hostname): installed \$(/usr/local/bin/rand-node --version)\"" 2>&1 | tail -1
done
# Node A on this Mac, when its launchd job is installed (retired to the droplet rand-node-a since
# 2026-09-27; run-a.sh refuses without RAND_NODE_A_ON_LAPTOP=1): the blob goes beside the binary
# run-a.sh runs, $NODE_A_HOME/$BINDIR/rand-node — the same "beside the binary" rule, which is also
# the only place it reads it (a binary outside a checkout's target/ never falls back to the
# source tree's copy). The check is that Mac binary's own: its `keygen-msauth-vk --check` must
# equal its `--print-pinned production`, so a blob and a node A build from different commits
# never pair; a binary without the subcommand (pre-v0.8.0) fails the check.
if [ -n "$MSAUTH_VK" ] && [ -f ~/Library/LaunchAgents/org.randprotocol.node-a.plist ]; then
  A_BINDIR="${NODE_A_HOME:-$HOME/rand-node-a}/${BINDIR:-bin-dd2ccbe}"
  a_got=$("$A_BINDIR/rand-node" keygen-msauth-vk --check "$MSAUTH_VK" 2>/dev/null)
  a_pin=$("$A_BINDIR/rand-node" keygen-msauth-vk --print-pinned production 2>/dev/null)
  if [ -n "$a_got" ] && [ "$a_got" = "$a_pin" ] && install -m 644 "$MSAUTH_VK" "$A_BINDIR/msauth-vk-production.bin"; then
    echo "   A: msauth key installed beside $A_BINDIR/rand-node (pin $a_pin)"
  else
    echo "   A: msauth key NOT installed at $A_BINDIR: its rand-node pins ${a_pin:-nothing}, the blob is ${a_got:-unreadable} (node A will refuse to start on a multisig chain)"
  fi
fi
echo "== stop all $(date -u +%H:%M:%S)"
launchctl bootout gui/$(id -u)/org.randprotocol.node-a 2>/dev/null && echo "   A stopped"
for ip in $IPS; do ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'systemctl stop rand-node; echo "   $(hostname): $(systemctl is-active rand-node)"' 2>&1 | tail -1 & done; wait
echo "== start all $(date -u +%H:%M:%S)"
for ip in $IPS; do ssh -o ConnectTimeout=15 -o BatchMode=yes root@$ip 'systemctl start rand-node; sleep 2; echo "   $(hostname): $(systemctl is-active rand-node)"' 2>&1 | tail -1 & done; wait
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.randprotocol.node-a.plist && echo "   A started"
echo "ROLL-DONE $(date -u +%H:%M:%S) — wait for rand_getHealth: ok on every node (deploy/fleet-watch.sh)"
