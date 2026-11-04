# Sourced by the scripts that install or roll rand-node (PROC-601). The ONE place the service's
# resource limits are written down: every script that sets up a host or rolls a binary onto one
# writes them as a systemd drop-in, so a merged limit reaches the fleet at the next roll instead
# of living in a unit template only a fresh host ever gets.
#
# Audit v12, PROC-601: MemoryHigh=85% (issue #157) sat in two unit templates (vps-setup.sh and the
# retired cutover-droplet-rand.sh); update-droplet.sh and roll-all.sh never wrote a unit, so 0 of
# 26 hosts carried it. LimitNOFILE is the open-files value the hosts' hand-placed nofile.conf
# carries since the 31 Oct halt (storage.rs keeps every SST open; rlimit.rs asks for the same).
#
#   unit_limits_dropin                      the drop-in's text
#   unit_limits_install_script SERVICE [UNIT_DIR]
#                                           a shell script (text) for the HOST: writes
#                                           UNIT_DIR/SERVICE.service.d/50-limits.conf when it is
#                                           missing or differs, then `systemctl daemon-reload`, and
#                                           prints `limits: written <path>`; when the file is
#                                           already right it prints `limits: unchanged <path>` and
#                                           reloads nothing. UNIT_DIR defaults to /etc/systemd/system.
#
# LimitNOFILE takes effect at the next start of the service; MemoryHigh at the daemon-reload.
# The roll scripts restart the node after writing it, so both apply.
#
#   SELFTEST=1 bash deploy/lib/unit-limits.sh   # temp dirs and a fake systemctl, no host touched

RAND_NODE_MEMORY_HIGH=85%
RAND_NODE_LIMIT_NOFILE=524288:524288
RAND_NODE_LIMITS_DROPIN=50-limits.conf

unit_limits_dropin() {
  printf '%s\n' \
    '[Service]' \
    '# Written by deploy/lib/unit-limits.sh at every setup and roll (PROC-601); edit it there.' \
    '# MemoryHigh (issue #157): reclaim and throttle above 85% of RAM rather than let the OOM killer' \
    '# take the node mid-burst. No MemoryMax: a cap kills, which is what this avoids.' \
    '# LimitNOFILE: RocksDB keeps every table file open (2026-10-28 archives, 2026-11-01 halt).' \
    "MemoryHigh=$RAND_NODE_MEMORY_HIGH" \
    "LimitNOFILE=$RAND_NODE_LIMIT_NOFILE"
}

unit_limits_install_script() {
  local service=$1 unit_dir=${2:-/etc/systemd/system}
  local dir="$unit_dir/$service.service.d"
  local f="$dir/$RAND_NODE_LIMITS_DROPIN"
  cat <<SCRIPT
rand_limits_f='$f'
rand_limits_new=\$(cat <<'RAND_LIMITS_EOF'
$(unit_limits_dropin)
RAND_LIMITS_EOF
)
if [ -f "\$rand_limits_f" ] && [ "\$(cat "\$rand_limits_f")" = "\$rand_limits_new" ]; then
  echo "limits: unchanged \$rand_limits_f"
else
  mkdir -p '$dir'
  printf '%s\n' "\$rand_limits_new" > "\$rand_limits_f.tmp"
  mv -f "\$rand_limits_f.tmp" "\$rand_limits_f"
  systemctl daemon-reload
  echo "limits: written \$rand_limits_f"
fi
SCRIPT
}

# ══ SELFTEST (only when this file is run, not sourced) ═══════════════════════════════════════
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${SELFTEST:-}" = 1 ]; then
  HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
  DEPLOY=$(dirname "$HERE")
  ST=$(mktemp -d "${TMPDIR:-/tmp}/unit-limits-selftest.XXXXXX"); trap 'rm -rf "$ST"' EXIT
  PASS=0; FAIL=0
  ok() { PASS=$((PASS+1)); echo "  ok   $1"; }
  no() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
  check() { local what=$1; shift; if "$@"; then ok "$what"; else no "$what"; fi; }
  mkdir -p "$ST/bin" "$ST/units"
  printf '#!/bin/sh\necho "$*" >> "%s/systemctl.log"\n' "$ST" > "$ST/bin/systemctl"; chmod +x "$ST/bin/systemctl"
  run_host() { PATH="$ST/bin:$PATH" bash -c "$(unit_limits_install_script rand-node "$ST/units")"; }
  F="$ST/units/rand-node.service.d/50-limits.conf"
  reloads() { grep -c '^daemon-reload$' "$ST/systemctl.log" 2>/dev/null || true; }

  out=$(run_host)
  check "a fresh host gets the drop-in written" test -f "$F"
  check "the drop-in carries MemoryHigh=85%" grep -qx 'MemoryHigh=85%' "$F"
  check "the drop-in carries LimitNOFILE=524288:524288" grep -qx 'LimitNOFILE=524288:524288' "$F"
  check "the drop-in is a [Service] section" grep -qx '\[Service\]' "$F"
  check "the drop-in is exactly unit_limits_dropin" test "$(cat "$F")" = "$(unit_limits_dropin)"
  check "writing it reloads systemd once" test "$(reloads)" = 1
  check "it says it wrote the file" test "$out" = "limits: written $F"
  out=$(run_host)
  check "a second run is idempotent (no reload)" test "$(reloads)" = 1
  check "a second run says unchanged" test "$out" = "limits: unchanged $F"
  printf '[Service]\nMemoryHigh=50%%\n' > "$F"
  run_host >/dev/null
  check "a drifted drop-in is rewritten" test "$(cat "$F")" = "$(unit_limits_dropin)"
  check "rewriting it reloads systemd" test "$(reloads)" = 2
  check "no temp file is left" test ! -e "$F.tmp"

  # The roll path and the setup path use this file; no other deploy script spells the values.
  check "update-droplet.sh writes the drop-in" grep -q 'unit_limits_install_script' "$DEPLOY/update-droplet.sh"
  check "roll-all.sh writes the drop-in" grep -q 'unit_limits_install_script' "$DEPLOY/roll-all.sh"
  check "vps-setup.sh writes the drop-in" grep -q 'unit_limits_install_script' "$DEPLOY/vps-setup.sh"
  stray=$(grep -lE '^[^#]*(MemoryHigh|LimitNOFILE)=' "$DEPLOY"/*.sh 2>/dev/null || true)
  check "no deploy script hard-codes MemoryHigh/LimitNOFILE (${stray:-none})" test -z "$stray"

  # The remote text survives being embedded in a double-quoted ssh command, as update-droplet.sh does.
  : > "$ST/systemctl.log"; rm -rf "$ST/units"
  embedded="set -e
  $(unit_limits_install_script rand-node "$ST/units")
  echo done"
  check "the script runs embedded in a larger set -e script" bash -c "PATH='$ST/bin':\$PATH; $embedded" >/dev/null
  check "embedded, it still writes the drop-in" test "$(cat "$F")" = "$(unit_limits_dropin)"

  echo "unit-limits selftest: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]; exit $?
fi
