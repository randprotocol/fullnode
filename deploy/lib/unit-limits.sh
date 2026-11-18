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
#                                           and so won: PROC-702) stops setting them, with one
#                                           daemon-reload and a `limits: removed legacy …` line each:
#                                           - a drop-in that sets nothing else (comments, blank lines
#                                             and section headers aside) is moved to <name>.removed,
#                                             which systemd does not load;
#                                           - a drop-in that also carries other directives keeps them:
#                                             it is rewritten without the two keys' lines, and the
#                                             original is kept as <name>.removed (audit v14: moving the
#                                             whole file took an Environment= or ExecStartPre= with it).
#                                           A key line is matched as systemd reads it, blanks round the
#                                           `=` included. UNIT_DIR defaults to /etc/systemd/system.
#
# LimitNOFILE takes effect at the next start of the service; MemoryHigh at the daemon-reload.
# The roll scripts restart the node after writing it, so both apply.
#
#   SELFTEST=1 bash deploy/lib/unit-limits.sh   # no host touched. Runs update-droplet.sh (both
#                                               # branches), roll-all.sh and vps-setup.sh against the
#                                               # sandbox of deploy/lib/host-sandbox.sh, whose ssh stub
#                                               # RUNS each remote command in a temp root with a fake
#                                               # systemctl, and asserts on the files the "host" then
#                                               # holds and the limits its service started with
#                                               # (audit v14, PROC-701: the v0.8.6 stubs only recorded,
#                                               # so an install step sent in a dead branch passed)

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
  # A line that sets one of the two keys, as systemd reads it: leading blanks and blanks round
  # the `=` allowed (`LimitNOFILE = 65536` sets it too; audit v14, PROC-702 residual).
  local key_re='^[[:space:]]*(LimitNOFILE|MemoryHigh)[[:space:]]*='
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
  if [ -f "\$rand_limits_old" ] && grep -qE '$key_re' "\$rand_limits_old"; then
    if grep -vE '$key_re' "\$rand_limits_old" | grep -qvE '^[[:space:]]*([#;[]|\$)'; then
      cp -p "\$rand_limits_old" "\$rand_limits_old.removed"
      grep -vE '$key_re' "\$rand_limits_old" > "\$rand_limits_old.tmp"
      mv -f "\$rand_limits_old.tmp" "\$rand_limits_old"
      echo "limits: removed legacy LimitNOFILE/MemoryHigh lines from \$rand_limits_old (they overrode $RAND_NODE_LIMITS_DROPIN; its other directives stay; the original is kept as \$rand_limits_old.removed)"
    else
      mv -f "\$rand_limits_old" "\$rand_limits_old.removed"
      echo "limits: removed legacy \$rand_limits_old (it set LimitNOFILE/MemoryHigh over $RAND_NODE_LIMITS_DROPIN; kept as \$rand_limits_old.removed)"
    fi
    rand_limits_reload=1
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

  # Audit v14, PROC-702 residual. (1) A key written with blanks round the `=` sets it too, and was
  # not matched. (2) A legacy drop-in that also carries something the unit needs lost that with
  # the whole-file move: it now keeps its other directives and loses only the two keys' lines.
  sets_key() { grep -qE '^[[:space:]]*(LimitNOFILE|MemoryHigh)[[:space:]]*=' "$1"; }
  printf '[Service]\nLimitNOFILE = 65536\n' > "$D/spaced.conf"
  printf '[Service]\n# hand-placed 1 Nov\nEnvironment=RUST_LOG=debug\nLimitNOFILE=65536\n\tMemoryHigh\t= 90%%\nExecStartPre=/bin/true\n' > "$D/mixed.conf"
  MIXED_ORIG=$(cat "$D/mixed.conf")
  : > "$ST/systemctl.log"
  out=$(run_host)
  check "a key written with blanks round the = is matched: the drop-in is removed" test ! -e "$D/spaced.conf" -a -f "$D/spaced.conf.removed"
  check "a legacy drop-in with other directives stays in place" test -f "$D/mixed.conf"
  check "  … without its LimitNOFILE/MemoryHigh lines" bash -c '! grep -qE "^[[:space:]]*(LimitNOFILE|MemoryHigh)[[:space:]]*=" "$1"' _ "$D/mixed.conf"
  check "  … with its other directives, comment and section kept, in order" \
    test "$(cat "$D/mixed.conf")" = "$(printf '[Service]\n# hand-placed 1 Nov\nEnvironment=RUST_LOG=debug\nExecStartPre=/bin/true')"
  check "  … and the original kept as <name>.removed" test "$(cat "$D/mixed.conf.removed" 2>/dev/null)" = "$MIXED_ORIG"
  check "  … reported as a removal (update-droplet.sh restarts on that line)" \
    test "$(printf '%s\n' "$out" | grep -c '^limits: removed legacy ')" = 2
  check "  … with one reload for both" test "$(reloads)" = 1
  check "no temp file is left beside it" test ! -e "$D/mixed.conf.tmp"
  out=$(run_host)
  check "a second run leaves the kept directives alone (idempotent, no reload)" \
    test "$out" = "limits: unchanged $F" -a "$(reloads)" = 1 -a -f "$D/mixed.conf"
  rm -f "$D"/*.removed "$D/mixed.conf"

  # The roll paths, RUN (audit v13 PROC-701, audit v14 PROC-701): a grep for the function's name
  # stayed green with a call site deleted; stubs that only recorded the remote command stayed
  # green with the install step sent inside a branch that never executes. Each script is run here
  # against deploy/lib/host-sandbox.sh — its ssh stub RUNS what a host is sent, in a temp root —
  # and every check below reads what the "host" then holds, not the text it was sent.
  # shellcheck source=deploy/lib/host-sandbox.sh
  . "$HERE/host-sandbox.sh"
  sandbox_init "$ST/sandbox" || { no "the sandbox starts (not as root)"; echo "unit-limits selftest: $PASS passed, $FAIL failed"; exit 1; }
  mkdir -p "$ST/home"
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
  BUILD=198.18.0.9
  sandbox_host "$BUILD"; BUILD_DIR_S="$(sandbox_root "$BUILD")/root/fullnode/target/release"
  sandbox_fake_bins "$BUILD_DIR_S" new
  NODE_SHA=$(sha "$BUILD_DIR_S/rand-node"); WALLET_SHA=$(sha "$BUILD_DIR_S/rand")
  printf 'NODE_A=/ip4/198.18.0.1/tcp/30303/p2p/x\nNODE_B=/ip4/198.18.0.2/tcp/30303/p2p/y\n' > "$ST/nodes.env"
  # A host as the fleet's were before the v0.8.6 roll: binaries of build $1 (`new` = already on
  # the release), no 50-limits.conf.
  fresh_host() { rm -rf "$(sandbox_root "$1")"; sandbox_host "$1"; sandbox_fake_bins "$(sandbox_root "$1")/usr/local/bin" "$2"; }
  # Run one deploy script with the stubs first on PATH. PRUNE_ARGS is unset on purpose: from
  # 2026-09-24 to 2026-11-08 the new-binary path died under `set -u` without it (PROC-751).
  stubbed() {
    env -u PRUNE_ARGS PATH="$SANDBOX/bin:$PATH" HOME="$ST/home" SANDBOX="$SANDBOX" \
      NODES_ENV="$ST/nodes.env" ALLOW_UNSIGNED=1 SELFTEST= RELEASE_SUMS= RELEASE_SIG= "$@" > "$ST/run.out" 2>&1
  }
  H1=198.18.0.1; R1=$(sandbox_root $H1); U1="$R1/etc/systemd/system"; D1="$U1/rand-node.service.d"; F1="$D1/50-limits.conf"
  count() { grep -c -e "$1" "$2" 2>/dev/null || true; }
  # In a host's systemctl log: a daemon-reload, and after it a (re)start.
  reload_then_start() { awk '/^daemon-reload$/ { r = NR } /^(restart|start) rand-node$/ { if (r && NR > r) ok = 1 } END { exit !ok }' "$1/systemctl.log"; }
  on_host_limits() { test "$(cat "$1/etc/systemd/system/rand-node.service.d/50-limits.conf" 2>/dev/null)" = "$(unit_limits_dropin)"; }

  # update-droplet.sh, already on the binary (PROC-601's refresh branch); the host still carries
  # the hand-placed nofile.conf (PROC-702).
  fresh_host $H1 new; printf '[Service]\nLimitNOFILE=65536\n' > "$D1/nofile.conf"
  stubbed WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" $H1 $BUILD
  check "update-droplet.sh (already current) runs to its end" grep -q 'already on' "$ST/run.out"
  check "update-droplet.sh (already current): the host now holds 50-limits.conf, exactly the library's" on_host_limits "$R1"
  check "  … the legacy nofile.conf is moved aside on the host" test ! -e "$D1/nofile.conf" -a -f "$D1/nofile.conf.removed"
  check "  … the node was restarted after the reload" reload_then_start "$R1"
  check "  … and runs with LimitNOFILE=$RAND_NODE_LIMIT_NOFILE" test "$(cat "$R1/running-nofile")" = "$RAND_NODE_LIMIT_NOFILE"
  check "  … with MemoryHigh=$RAND_NODE_MEMORY_HIGH loaded" test "$(cat "$R1/loaded-memoryhigh")" = "$RAND_NODE_MEMORY_HIGH"
  : > "$R1/systemctl.log"
  stubbed WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" $H1 $BUILD
  check "update-droplet.sh (already current) does not restart over an unchanged drop-in" \
    test "$(count 'restart' "$R1/systemctl.log")" = 0 -a "$(count 'already on' "$ST/run.out")" = 1
  printf '[Service]\nLimitNOFILE = 65536\n' > "$D1/nofile.conf"
  SANDBOX_ROOT="$R1" SANDBOX_HOST=$H1 PATH="$SANDBOX/hostbin:$PATH" systemctl daemon-reload
  SANDBOX_ROOT="$R1" SANDBOX_HOST=$H1 PATH="$SANDBOX/hostbin:$PATH" systemctl restart rand-node
  check "(the sandbox's systemd lets a later drop-in win: the node runs with 65536)" test "$(cat "$R1/running-nofile")" = 65536
  : > "$R1/systemctl.log"
  stubbed WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" $H1 $BUILD
  check "update-droplet.sh (already current) restarts the node after only a legacy drop-in is removed (PROC-702)" \
    test "$(count '^restart rand-node' "$R1/systemctl.log")" = 1 -a "$(cat "$R1/running-nofile")" = "$RAND_NODE_LIMIT_NOFILE"

  # update-droplet.sh, installing a new binary, PRUNE_ARGS unset.
  fresh_host $H1 old; printf '[Service]\nLimitNOFILE=65536\n' > "$D1/nofile.conf"
  stubbed WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" $H1 $BUILD
  check "update-droplet.sh (new binary, PRUNE_ARGS unset) runs to its end" grep -q 'updated to' "$ST/run.out"
  check "update-droplet.sh (new binary): the host holds the release's rand-node and rand" \
    test "$(sha "$R1/usr/local/bin/rand-node")" = "$NODE_SHA" -a "$(sha "$R1/usr/local/bin/rand")" = "$WALLET_SHA"
  check "  … and 50-limits.conf, exactly the library's" on_host_limits "$R1"
  check "  … the legacy nofile.conf is moved aside" test ! -e "$D1/nofile.conf" -a -f "$D1/nofile.conf.removed"
  check "  … the drop-in was written and loaded before the restart" reload_then_start "$R1"
  check "  … so the new binary started with LimitNOFILE=$RAND_NODE_LIMIT_NOFILE" \
    test "$(cat "$R1/running-nofile")" = "$RAND_NODE_LIMIT_NOFILE" -a "$(cat "$R1/running-binary")" = "$NODE_SHA"
  check "  … and the unit's ExecStart is untouched without PRUNE_ARGS" bash -c '! grep -q -- "--prune-history" "$1"' _ "$U1/rand-node.service"
  fresh_host $H1 old
  stubbed PRUNE_ARGS="--prune-history 24h" WANT_SHA="$NODE_SHA" WANT_SHA_WALLET="$WALLET_SHA" bash "$DEPLOY/update-droplet.sh" $H1 $BUILD
  check "update-droplet.sh (new binary) with PRUNE_ARGS appends it to ExecStart once" \
    test "$(count '^ExecStart=.* --prune-history 24h$' "$U1/rand-node.service")" = 1
  check "  … and still writes the drop-in" on_host_limits "$R1"

  # roll-all.sh: every host gets the binary and the drop-in, loaded before the fleet starts again.
  H2=198.18.0.2; R2=$(sandbox_root $H2)
  fresh_host $H1 old; fresh_host $H2 old; printf '[Service]\nLimitNOFILE=65536\n' > "$D1/nofile.conf"
  stubbed NO_MSAUTH_VK=1 bash "$DEPLOY/roll-all.sh" "$BUILD_DIR_S/rand-node" "$BUILD_DIR_S/rand" "$NODE_SHA" "$WALLET_SHA"
  check "roll-all.sh runs to its end" grep -q 'ROLL-DONE' "$ST/run.out"
  check "roll-all.sh: every host holds the release's rand-node" \
    test "$(sha "$R1/usr/local/bin/rand-node")" = "$NODE_SHA" -a "$(sha "$R2/usr/local/bin/rand-node")" = "$NODE_SHA"
  check "roll-all.sh: every host holds 50-limits.conf, exactly the library's" bash -c "$(declare -f on_host_limits unit_limits_dropin); RAND_NODE_MEMORY_HIGH='$RAND_NODE_MEMORY_HIGH' RAND_NODE_LIMIT_NOFILE='$RAND_NODE_LIMIT_NOFILE'; on_host_limits '$R1' && on_host_limits '$R2'"
  check "  … written and loaded before the fleet's stop and start" bash -c "$(declare -f reload_then_start); reload_then_start '$R1' && reload_then_start '$R2'"
  check "  … so both nodes started with LimitNOFILE=$RAND_NODE_LIMIT_NOFILE" \
    test "$(cat "$R1/running-nofile")" = "$RAND_NODE_LIMIT_NOFILE" -a "$(cat "$R2/running-nofile")" = "$RAND_NODE_LIMIT_NOFILE"
  check "  … and the legacy nofile.conf is moved aside" test ! -e "$D1/nofile.conf" -a -f "$D1/nofile.conf.removed"

  # vps-setup.sh, RUN as a fresh host would run it (audit v14, PROC-701: it was only searched as
  # text, so the selftest stayed green with the line that loads this library deleted while a
  # fresh host would have started with no drop-in). The sandbox host has the checkout at
  # /root/fullnode (deploy/ is this tree's), a stub cargo and stand-in binaries.
  HV=198.18.0.7; RV=$(sandbox_root $HV); rm -rf "$RV"; sandbox_host $HV
  rm -f "$RV/etc/systemd/system/rand-node.service"; echo inactive > "$RV/state"; : > "$RV/running-nofile"
  mkdir -p "$RV/root/fullnode" "$RV/root/.cargo"; : > "$RV/root/.cloud-init-done"; : > "$RV/root/.cargo/env"
  ln -s "$DEPLOY" "$RV/root/fullnode/deploy"; sandbox_fake_bins "$RV/root/fullnode/target/release" new
  if sandbox_run_script $HV "$DEPLOY/vps-setup.sh" v "" validator > "$ST/run.out" 2>&1; then vrc=0; else vrc=$?; fi
  check "vps-setup.sh runs to its end in the sandbox (exit $vrc)" test "$vrc" = 0
  [ "$vrc" = 0 ] || sed 's/^/       | /' "$ST/run.out" | tail -5
  check "vps-setup.sh: the fresh host holds 50-limits.conf, exactly the library's" on_host_limits "$RV"
  check "  … written and loaded before the node's first start" reload_then_start "$RV"
  check "  … so the node's first start has LimitNOFILE=$RAND_NODE_LIMIT_NOFILE" \
    test "$(cat "$RV/state")" = active -a "$(cat "$RV/running-nofile")" = "$RAND_NODE_LIMIT_NOFILE"
  check "  … and it wrote the unit it started" grep -q '^ExecStart=.*rand-node run --datadir ' "$RV/etc/systemd/system/rand-node.service"
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
