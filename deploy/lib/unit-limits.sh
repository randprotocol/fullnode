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
#                                           reloads nothing. Either way any OTHER *.conf in that
#                                           directory that sets LimitNOFILE or MemoryHigh (the hosts'
#                                           hand-placed nofile.conf of 1 Nov sorts after 50-limits.conf
#                                           and so won: PROC-702) is moved aside to <name>.removed,
#                                           which systemd does not load, with one daemon-reload and a
#                                           `limits: removed legacy <path> …` line each.
#                                           UNIT_DIR defaults to /etc/systemd/system.
#
# LimitNOFILE takes effect at the next start of the service; MemoryHigh at the daemon-reload.
# The roll scripts restart the node after writing it, so both apply.
#
#   SELFTEST=1 bash deploy/lib/unit-limits.sh   # temp dirs and a fake systemctl, no host touched;
#                                               # runs update-droplet.sh (both branches) and roll-all.sh
#                                               # against stub ssh/scp/launchctl that only record
#                                               # (PROC-701)

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
rand_limits_reload=
if [ -f "\$rand_limits_f" ] && [ "\$(cat "\$rand_limits_f")" = "\$rand_limits_new" ]; then
  rand_limits_said="limits: unchanged \$rand_limits_f"
else
  mkdir -p '$dir'
  printf '%s\n' "\$rand_limits_new" > "\$rand_limits_f.tmp"
  mv -f "\$rand_limits_f.tmp" "\$rand_limits_f"
  rand_limits_reload=1
  rand_limits_said="limits: written \$rand_limits_f"
fi
echo "\$rand_limits_said"
for rand_limits_old in '$dir'/*.conf; do
  case "\$rand_limits_old" in "\$rand_limits_f"|*'*.conf') continue ;; esac
  if [ -f "\$rand_limits_old" ] && grep -qE '^[[:space:]]*(LimitNOFILE|MemoryHigh)=' "\$rand_limits_old"; then
    mv -f "\$rand_limits_old" "\$rand_limits_old.removed"
    rand_limits_reload=1
    echo "limits: removed legacy \$rand_limits_old (it set LimitNOFILE/MemoryHigh over $RAND_NODE_LIMITS_DROPIN; kept as \$rand_limits_old.removed)"
  fi
done
if [ -n "\$rand_limits_reload" ]; then systemctl daemon-reload; fi
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

  # Audit v13, PROC-702: every host kept the hand-placed nofile.conf of 1 Nov beside 50-limits.conf;
  # it sorts after it, so it set LimitNOFILE. Any other drop-in in the directory that sets
  # LimitNOFILE or MemoryHigh is moved aside (<name>.removed, which systemd does not load), with a
  # reload and a line saying so; one that sets neither is left alone.
  D="$ST/units/rand-node.service.d"
  printf '[Service]\nLimitNOFILE=524288\n' > "$D/nofile.conf"
  printf '[Service]\n  MemoryHigh=90%%\n' > "$D/90-memory.conf"
  printf '[Service]\nEnvironment=RUST_LOG=debug\n# LimitNOFILE=1 in a comment sets nothing\n' > "$D/env.conf"
  : > "$ST/systemctl.log"
  out=$(run_host)
  check "a legacy nofile.conf is removed" test ! -e "$D/nofile.conf"
  check "another drop-in that sets MemoryHigh is removed" test ! -e "$D/90-memory.conf"
  check "  … kept aside where systemd does not load it" test -f "$D/nofile.conf.removed" -a -f "$D/90-memory.conf.removed"
  check "a drop-in that sets neither is kept" test -f "$D/env.conf"
  check "50-limits.conf is untouched" test "$(cat "$F")" = "$(unit_limits_dropin)"
  check "removing them reloads systemd once" test "$(reloads)" = 1
  check "it reports each removal" test "$(printf '%s\n' "$out" | grep -c '^limits: removed legacy ')" = 2
  check "  … naming nofile.conf" grep -qF "limits: removed legacy $D/nofile.conf" <<<"$out"
  check "only 50-limits.conf now sets LimitNOFILE/MemoryHigh" \
    test "$(grep -lE '^[[:space:]]*(LimitNOFILE|MemoryHigh)=' "$D"/*.conf)" = "$F"
  out=$(run_host)
  check "a second run removes nothing (idempotent)" test "$out" = "limits: unchanged $F"
  check "  … and reloads nothing" test "$(reloads)" = 1
  printf '[Service]\nLimitNOFILE=524288\n' > "$D/nofile.conf"; rm -f "$F"
  out=$(run_host)
  check "written and removed in one run: one reload" test "$(reloads)" = 2
  check "  … both reported" test "$(printf '%s\n' "$out" | grep -c '^limits: \(written\|removed legacy\) ')" = 2
  rm -f "$D"/*.removed "$D/env.conf"

  # The roll paths, run (audit v13, PROC-701): a grep for the function's name stayed green with
  # the already-current refresh deleted from update-droplet.sh or the install step's call deleted
  # from roll-all.sh. Each script is RUN here against stub ssh/scp/launchctl that record every
  # remote command (none reaches a host), and each path must send this file's install script.
  mkdir -p "$ST/rec" "$ST/build" "$ST/home"
  : > "$ST/rec.idx"
  cat > "$ST/bin/ssh" <<'STUB'
#!/usr/bin/env bash
# The remote command is the last argument; the host the root@ one. Record both, answer what the
# scripts ask a host for, run nothing.
cmd=${!#}; host=; for a in "$@"; do case "$a" in root@*) host=${a#root@} ;; esac; done
f=$(mktemp "$STUB_ST/rec/c.XXXXXX"); printf '%s\n%s' "$host" "$cmd" > "$f"; echo "$f" >> "$STUB_ST/rec.idx"
case "$cmd" in
  "sha256sum /usr/local/bin/rand-node "*) echo "$STUB_HAVE_NODE" ;;
  "sha256sum /usr/local/bin/rand "*) echo "$STUB_HAVE_WALLET" ;;
  "sha256sum "*"/rand-node "*) echo "$STUB_NODE_SHA" ;;
  "sha256sum "*"/rand "*) echo "$STUB_WALLET_SHA" ;;
  *hc_auth_multisig*) echo plain ;;
  *rand_limits_f=*) echo "$STUB_LIMITS_ANSWER" ;;
esac
exit 0
STUB
  cat > "$ST/bin/scp" <<'STUB'
#!/usr/bin/env bash
# A copy to a host is recorded only; a copy from the build host fetches the stub build.
dest=${!#}
case "$dest" in *:*) echo "scp-to ${dest%%:*}" >> "$STUB_ST/scp.log"; exit 0 ;; esac
for a in "${@:1:$#-1}"; do case "$a" in -*) ;; *:*) cp "$STUB_ST/build/$(basename "${a#*:}")" "$dest/" ;; esac; done
STUB
  printf '#!/bin/sh\nexit 0\n' > "$ST/bin/launchctl"
  chmod +x "$ST/bin/ssh" "$ST/bin/scp" "$ST/bin/launchctl"
  echo node > "$ST/build/rand-node"; echo wallet > "$ST/build/rand"
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
  NODE_SHA=$(sha "$ST/build/rand-node"); WALLET_SHA=$(sha "$ST/build/rand")
  printf 'NODE_A=/ip4/198.18.0.1/tcp/30303/p2p/x\nNODE_B=/ip4/198.18.0.2/tcp/30303/p2p/y\n' > "$ST/nodes.env"
  LIMITS_SCRIPT=$(unit_limits_install_script rand-node)
  # Run one deploy script with the stubs first on PATH; the recorded commands start afresh.
  stubbed() {
    rm -f "$ST/rec"/c.* "$ST/scp.log"; : > "$ST/rec.idx"
    env PATH="$ST/bin:$PATH" HOME="$ST/home" STUB_ST="$ST" STUB_NODE_SHA="$NODE_SHA" STUB_WALLET_SHA="$WALLET_SHA" \
      NODES_ENV="$ST/nodes.env" ALLOW_UNSIGNED=1 SELFTEST= RELEASE_SUMS= RELEASE_SIG= "$@" > "$ST/run.out" 2>&1
  }
  # The recorded remote commands, in order: "<n> <host>" for those that carry the drop-in's install
  # script, and the position of the first `systemctl restart`/`stop` after it.
  rec() { local i=0 f; while read -r f; do i=$((i+1)); printf '%s\t%s\t%s\n' "$i" "$(head -1 "$f")" "$f"; done < "$ST/rec.idx"; }
  carrying_limits() { local n host f; while IFS=$'\t' read -r n host f; do
      [[ "$(tail -n +2 "$f")" == *"$LIMITS_SCRIPT"* ]] && echo "$n $host"; done < <(rec); }
  # shellcheck disable=SC2053  # $pat is a glob on purpose
  first_matching() { local pat=$1 n host f; while IFS=$'\t' read -r n host f; do
      [[ "$(tail -n +2 "$f")" == $pat ]] && { echo "$n"; return; }; done < <(rec); echo 0; }

  # update-droplet.sh, already on the binary (PROC-601's refresh branch).
  stubbed STUB_HAVE_NODE="$NODE_SHA" STUB_HAVE_WALLET="$WALLET_SHA" STUB_LIMITS_ANSWER="limits: written $F" \
    WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" 198.18.0.1 198.18.0.9
  check "update-droplet.sh (already current) runs to its end" grep -q 'already on' "$ST/run.out"
  check "update-droplet.sh (already current) sends the drop-in's install script to the host" \
    test "$(carrying_limits | cut -d' ' -f2)" = 198.18.0.1
  lim=$(carrying_limits | cut -d' ' -f1); rst=$(first_matching '*systemctl restart rand-node*')
  check "update-droplet.sh (already current) restarts the node after a written drop-in" test "${lim:-0}" -gt 0 -a "$rst" -gt "${lim:-0}"
  stubbed STUB_HAVE_NODE="$NODE_SHA" STUB_HAVE_WALLET="$WALLET_SHA" STUB_LIMITS_ANSWER="limits: unchanged $F" \
    WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" 198.18.0.1 198.18.0.9
  check "update-droplet.sh (already current) does not restart over an unchanged drop-in" test "$(first_matching '*systemctl restart*')" = 0
  stubbed STUB_HAVE_NODE="$NODE_SHA" STUB_HAVE_WALLET="$WALLET_SHA" \
    STUB_LIMITS_ANSWER="limits: unchanged $F"$'\n'"limits: removed legacy ${F%/*}/nofile.conf (…)" \
    WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" 198.18.0.1 198.18.0.9
  check "update-droplet.sh (already current) restarts the node after a legacy drop-in is removed (PROC-702)" \
    test "$(first_matching '*systemctl restart rand-node*')" -gt 0
  # update-droplet.sh, installing a new binary.
  stubbed STUB_HAVE_NODE=old STUB_HAVE_WALLET=old STUB_LIMITS_ANSWER= \
    WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" 198.18.0.1 198.18.0.9
  check "update-droplet.sh (new binary) runs to its end" grep -q 'updated to' "$ST/run.out"
  inst=$(first_matching '*install -m 755 /root/rand-node /root/rand /usr/local/bin/*')
  check "update-droplet.sh (new binary) writes the drop-in in its install command" test "$(carrying_limits | cut -d' ' -f1)" = "$inst"
  f=$(rec | awk -F'\t' -v n="$inst" '$1 == n { print $3 }')
  check "  … before that command's restart" bash -c '[ -n "$1" ] && c=$(cat "$1") && l=${c%%rand_limits_f=*} && r=${c%%systemctl restart*} && [ ${#l} -lt ${#r} ]' _ "$f"

  # roll-all.sh: every host's install step writes the drop-in, before the stop-all.
  stubbed NO_MSAUTH_VK=1 bash "$DEPLOY/roll-all.sh" "$ST/build/rand-node" "$ST/build/rand" "$NODE_SHA" "$WALLET_SHA"
  check "roll-all.sh runs to its end" grep -q 'ROLL-DONE' "$ST/run.out"
  check "roll-all.sh sends the drop-in's install script to every host" \
    test "$(carrying_limits | cut -d' ' -f2 | sort | tr '\n' ' ')" = "198.18.0.1 198.18.0.2 "
  last=$(carrying_limits | tail -1 | cut -d' ' -f1); stop=$(first_matching '*systemctl stop rand-node*')
  check "roll-all.sh writes them before it stops the fleet" test "${last:-0}" -gt 0 -a "$stop" -gt "${last:-0}"

  # vps-setup.sh runs on a fresh host as root (cloud-init, cargo, /root), so it is not run here:
  # its call must be a live line, ahead of the unit's first start.
  vcall=$(grep -nE '^[^#]*bash -c "\$\(unit_limits_install_script rand-node\)"' "$DEPLOY/vps-setup.sh" | head -1 | cut -d: -f1)
  vstart=$(grep -nE '^[^#]*systemctl (restart|start) rand-node' "$DEPLOY/vps-setup.sh" | head -1 | cut -d: -f1)
  check "vps-setup.sh runs the drop-in's install script before it starts the node" test "${vcall:-0}" -gt 0 -a "${vstart:-0}" -gt "${vcall:-0}"
  stray=$(grep -lE '^[^#]*(MemoryHigh|LimitNOFILE)=' "$DEPLOY"/*.sh 2>/dev/null || true)
  check "no deploy script hard-codes MemoryHigh/LimitNOFILE (${stray:-none})" test -z "$stray"

  # The remote text survives being embedded in a double-quoted ssh command, as update-droplet.sh does.
  : > "$ST/systemctl.log"; rm -rf "$ST/units"
  embedded="set -e
  $(unit_limits_install_script rand-node "$ST/units")
  echo done"
  check "the script runs embedded in a larger set -e script" bash -c "PATH='$ST/bin':\$PATH; { $embedded
  } >/dev/null"
  check "embedded, it still writes the drop-in" test "$(cat "$F")" = "$(unit_limits_dropin)"

  echo "unit-limits selftest: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]; exit $?
fi
