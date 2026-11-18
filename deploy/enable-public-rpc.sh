#!/usr/bin/env bash
# Open the node's own public RPC listener (--public-rpc 127.0.0.1:8546) on a host that serves
# public RPC traffic (VK-2): a fixed read-method set plus rand_sendTransaction; no viewing-key
# methods, no rand_mint, no rand_getPeers; no batches, no WebSocket; one meter for all callers.
# Point the reverse proxy or SSH tunnel at 8546, never at --rpc (8545).
#
#   deploy/enable-public-rpc.sh root@<host> [unit]        # edits the unit, does NOT restart
#   RESTART=1 deploy/enable-public-rpc.sh root@<host>     # ... and restarts it (one host at a time)
#   DROPIN=1 deploy/enable-public-rpc.sh root@<host>      # install the committed drop-in
#                                                         # (deploy/systemd/rand-node.service.d/
#                                                         # 60-public-rpc.conf) instead of editing
#                                                         # ExecStart (monorepo#17): works on any
#                                                         # unit, a multi-line ExecStart included.
#                                                         # Needs rand-node v0.8.7+ on the host (it
#                                                         # must read RAND_NODE_PUBLIC_RPC) and
#                                                         # refuses otherwise; when ExecStart already
#                                                         # has the flag it changes nothing.
#   SELFTEST=1 bash deploy/enable-public-rpc.sh           # the drop-in installer in a temp dir; no host
#
# Idempotent. The unit defaults to rand-node. Needs a build with --public-rpc (v0.6.8 or later);
# on an older binary the node refuses to start, so roll the binary first (update-droplet.sh).
# With RESTART=1 the host is then checked with deploy/check-public-rpc.sh --local, whose output is
# the record of the change: keep it.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
DROPIN_FILE=$HERE/systemd/rand-node.service.d/60-public-rpc.conf

# A script (text) for the HOST that installs the committed drop-in for UNIT under UNIT_DIR, given
# the node binary BIN. It prints `public-rpc: drop-in written <path>`, `public-rpc: drop-in
# unchanged <path>` or `public-rpc: ExecStart already has --public-rpc`, and fails when BIN does
# not read the variable or the unit does not exist.
dropin_install_script() {
  local unit=$1 unit_dir=${2:-/etc/systemd/system} bin=${3:-/usr/local/bin/rand-node}
  printf 'set -e\nf=%s/%s.service\nd=%s/%s.service.d\nbin=%s\n' "$unit_dir" "$unit" "$unit_dir" "$unit" "$bin"
  cat <<'HOST'
[ -f "$f" ] || { echo "$f: no such unit" >&2; exit 1; }
if grep -q -- '--public-rpc' "$f"; then echo "public-rpc: ExecStart already has --public-rpc"; exit 0; fi
"$bin" run --help 2>&1 | grep -q RAND_NODE_PUBLIC_RPC || { echo "rand-node here does not read RAND_NODE_PUBLIC_RPC (before v0.8.7): roll a newer binary, or run without DROPIN=1" >&2; exit 1; }
mkdir -p "$d"
cat > "$d/60-public-rpc.conf.new" <<'DROPIN'
HOST
  cat "$DROPIN_FILE"
  cat <<'HOST'
DROPIN
if [ -f "$d/60-public-rpc.conf" ] && cmp -s "$d/60-public-rpc.conf" "$d/60-public-rpc.conf.new"; then
  rm -f "$d/60-public-rpc.conf.new"
  echo "public-rpc: drop-in unchanged $d/60-public-rpc.conf"
else
  mv "$d/60-public-rpc.conf.new" "$d/60-public-rpc.conf"
  systemctl daemon-reload
  echo "public-rpc: drop-in written $d/60-public-rpc.conf"
fi
HOST
}

if [ "${SELFTEST:-}" = 1 ]; then
  ST=$(mktemp -d); trap 'rm -rf "$ST"' EXIT; PASS=0; FAIL=0
  mkdir -p "$ST/bin" "$ST/units"
  printf '#!/bin/sh\necho reload >> "%s/reloads"\n' "$ST" > "$ST/bin/systemctl"
  printf '#!/bin/sh\necho "      --public-rpc <PUBLIC_RPC>  [env: RAND_NODE_PUBLIC_RPC=]"\n' > "$ST/bin/new-node"
  printf '#!/bin/sh\necho "      --public-rpc <PUBLIC_RPC>"\n' > "$ST/bin/old-node"
  chmod +x "$ST/bin/"*
  : > "$ST/reloads"
  printf '[Service]\nExecStart=/usr/local/bin/rand-node run \\\n  --datadir /d --key /k\n' > "$ST/units/multi.service"
  printf '[Service]\nExecStart=/usr/local/bin/rand-node run --datadir /d --public-rpc 127.0.0.1:8546\n' > "$ST/units/flagged.service"
  run() { PATH="$ST/bin:$PATH" bash -c "$(dropin_install_script "$1" "$ST/units" "$ST/bin/$2")" 2>&1 || true; }
  reloads() { wc -l < "$ST/reloads" | tr -d ' '; }
  t() { local what=$1; shift; if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "  ok   $what"; else FAIL=$((FAIL+1)); echo "  FAIL $what"; fi; }
  has() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
  out=$(run multi new-node)
  t "a multi-line ExecStart gets the drop-in" has "$out" "drop-in written"
  t "the installed drop-in is the committed file" cmp -s "$ST/units/multi.service.d/60-public-rpc.conf" "$DROPIN_FILE"
  t "the unit file itself is untouched" grep -q -- '--datadir /d --key /k' "$ST/units/multi.service"
  t "systemd was reloaded once" test "$(reloads)" = 1
  out=$(run multi new-node)
  t "a second run changes nothing" has "$out" "drop-in unchanged"
  t "and reloads nothing" test "$(reloads)" = 1
  out=$(run flagged new-node)
  t "a unit whose ExecStart has the flag is left alone" has "$out" "already has --public-rpc"
  t "and gets no drop-in" test ! -e "$ST/units/flagged.service.d"
  rm -rf "$ST/units/multi.service.d"
  out=$(run multi old-node)
  t "a binary that does not read the variable is refused" has "$out" "does not read RAND_NODE_PUBLIC_RPC"
  t "and nothing is written for it" test ! -e "$ST/units/multi.service.d/60-public-rpc.conf"
  out=$(run missing new-node)
  t "a missing unit is refused" has "$out" "no such unit"
  echo "enable-public-rpc self-test: $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]; exit
fi

TARGET=${1:?usage: enable-public-rpc.sh root@<host> [unit]}
UNIT=${2:-rand-node}
ADDR=127.0.0.1:8546
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20 "$TARGET")
if [ "${DROPIN:-0}" = 1 ]; then
  "${SSH[@]}" "$(dropin_install_script "$UNIT")"
else
"${SSH[@]}" "set -e
  f=/etc/systemd/system/$UNIT.service
  [ -f \$f ] || { echo \"\$f: no such unit\" >&2; exit 1; }
  /usr/local/bin/rand-node run --help 2>&1 | grep -q -- --public-rpc || { echo 'rand-node here has no --public-rpc: roll a newer binary first' >&2; exit 1; }
  if grep -q '^ExecStart=.*\\\\\$' \$f; then echo \"\$f: ExecStart continues on the next line; add --public-rpc by hand, or use DROPIN=1\" >&2; exit 1; fi
  if grep -q -- '--public-rpc' \$f; then echo \"$TARGET: \$f already has --public-rpc\"; else
    sed -i 's|^ExecStart=\(.*\)\$|ExecStart=\1 --public-rpc $ADDR|' \$f
    systemctl daemon-reload
    echo \"$TARGET: --public-rpc $ADDR added to \$f\"
  fi"
fi
if [ "${RESTART:-0}" = 1 ]; then
    "${SSH[@]}" "systemctl restart $UNIT && sleep 4 && systemctl is-active $UNIT"
    # The whole check — the unit, the listener, every refused method, a batch — run on the host.
    "${SSH[@]}" "bash -s -- --local $UNIT" < "$HERE/check-public-rpc.sh" \
        || { echo "$TARGET: the public listener did not pass deploy/check-public-rpc.sh" >&2; exit 1; }
else
    echo "restart to apply: ssh $TARGET systemctl restart $UNIT   (one host at a time), then: ssh $TARGET 'bash -s -- --local $UNIT' < deploy/check-public-rpc.sh"
fi
