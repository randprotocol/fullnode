#!/usr/bin/env bash
# The selftest of deploy/roll-fleet.sh (audit v14, PROC-751). Run it as
#
#   SELFTEST=1 bash deploy/roll-fleet.sh        (or: bash deploy/lib/roll-fleet-selftest.sh)
#
# No host, network or chain is touched: roll-fleet.sh and update-droplet.sh are RUN against the
# sandbox of deploy/lib/host-sandbox.sh, whose ssh stub executes each remote command in a temp
# root per host, with a fake systemctl and a fake node that answers rand_status. The scripts run
# from a copy of deploy/ whose release-signers holds a throwaway key made here (the committed
# list is the only one the scripts read, by design, so the copy is how a signed roll is tested).
#
# What it proves: the gate holds the next host back until the one before has rejoined (height,
# peers, and a chain that moves); a host that does not rejoin STOPS the roll and the hosts after
# it are untouched; the skip list is honoured and a mistyped name refused; an unsigned release, a
# signature that does not verify and a build host holding other bytes are refused; --dry-run
# contacts nothing; the record is written by the tool with what the gate read, and never names an
# address or writes over a record.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
DEPLOY=$(dirname "$HERE")
ST=$(mktemp -d "${TMPDIR:-/tmp}/roll-fleet-selftest.XXXXXX"); trap 'rm -rf "$ST"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "  ok   $1"; }
no() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else no "$what"; fi; }
finish() { echo "roll-fleet selftest: $PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]; exit $?; }
# shellcheck source=deploy/lib/host-sandbox.sh
. "$HERE/host-sandbox.sh"
sandbox_init "$ST/sandbox" || { no "the sandbox starts (not as root)"; finish; }
command -v ssh-keygen >/dev/null 2>&1 || { no "ssh-keygen is installed (the signed paths need it)"; finish; }

# The copy of deploy/ under test, with a throwaway release key as its only signer.
D="$ST/deploy"; mkdir -p "$D/lib" "$ST/home" "$ST/rel"
cp "$DEPLOY/roll-fleet.sh" "$DEPLOY/update-droplet.sh" "$D/"; cp "$HERE"/*.sh "$D/lib/"
[ -f "$DEPLOY/release-threshold" ] && cp "$DEPLOY/release-threshold" "$D/"
ssh-keygen -q -t ed25519 -N '' -C selftest -f "$ST/key" >/dev/null
printf 'release@selftest namespaces="rand-release" %s\n' "$(cut -d' ' -f1,2 "$ST/key.pub")" > "$D/release-signers"

# The fleet: five validators and two archives. E is the build host and the default reference.
NAMES="A B C D E ARCHIVE ARCHIVE2"
ip() { case "$1" in A) echo 198.18.0.1 ;; B) echo 198.18.0.2 ;; C) echo 198.18.0.3 ;; D) echo 198.18.0.4 ;; E) echo 198.18.0.5 ;; ARCHIVE) echo 198.18.0.6 ;; ARCHIVE2) echo 198.18.0.7 ;; esac; }
root() { sandbox_root "$(ip "$1")"; }
{ for n in A B C D E; do echo "NODE_$n=/ip4/$(ip $n)/tcp/30303/p2p/x$n   # $n"; done
  echo "ARCHIVE=/ip4/$(ip ARCHIVE)/tcp/30303/p2p/xo"; echo "ARCHIVE2=/ip4/$(ip ARCHIVE2)/tcp/30303/p2p/xp"; } > "$ST/nodes.env"
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
sandbox_fake_bins "$ST/rel" new
NEW=$(sha "$ST/rel/rand-node"); NEW_WALLET=$(sha "$ST/rel/rand")
( cd "$ST/rel" && shasum -a 256 rand-node rand > SHA256SUMS && ssh-keygen -q -Y sign -n rand-release -f "$ST/key" SHA256SUMS >/dev/null 2>&1 )
check "(setup) the throwaway key signed the selftest's SHA256SUMS" test -s "$ST/rel/SHA256SUMS.sig"

# Every host back on the old build, the release on E under /root/rel, logs empty.
reset_fleet() {
  local n r
  for n in $NAMES; do
    r=$(root "$n"); rm -rf "$r"; sandbox_host "$(ip "$n")"; sandbox_fake_bins "$r/usr/local/bin" old
  done
  mkdir -p "$(root E)/root/rel"; cp "$ST/rel/rand-node" "$ST/rel/rand" "$(root E)/root/rel/"
  : > "$SANDBOX/events.log"; : > "$SANDBOX/rec.idx"; rm -f "$SANDBOX/chain-halted" "$ST"/*.record
}
OLD=
# fleet [VAR=value …] -- <roll-fleet.sh arguments>; sets RC, output in $ST/run.out.
fleet() {
  local envs=()
  while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
  env -u PRUNE_ARGS -u WANT_SHA -u WANT_SHA_WALLET -u ALLOW_UNSIGNED -u RELEASE_SUMS -u RELEASE_SIG -u BUILD_HOST \
    PATH="$SANDBOX/bin:$PATH" HOME="$ST/home" SANDBOX="$SANDBOX" SELFTEST= NODES_ENV="$ST/nodes.env" \
    BUILD_DIR=/root/rel ${envs[@]+"${envs[@]}"} bash "$D/roll-fleet.sh" "$@" > "$ST/run.out" 2>&1
  RC=$?
}
SIGNED=(RELEASE_SUMS="$ST/rel/SHA256SUMS" RELEASE_SIG="$ST/rel/SHA256SUMS.sig")
ssh_calls() { grep -c '' "$SANDBOX/rec.idx" || true; }
on_new() { test "$(sha "$(root "$1")/usr/local/bin/rand-node")" = "$NEW"; }
untouched() { ! grep -q "^$(ip "$1") " "$SANDBOX/events.log" && test "$(sha "$(root "$1")/usr/local/bin/rand-node")" = "$OLD" -a "$(cat "$(root "$1")/state")" = active; }
# The line number in the event log of a host's first stop (0: never stopped).
first_stop() { local n; n=$(grep -n "^$(ip "$1") systemctl stop " "$SANDBOX/events.log" | head -1 | cut -d: -f1); echo "${n:-0}"; }
# The hosts in the order they were first stopped.
stop_order() { local l h n out=; while read -r l; do h=${l%% *}; for n in $NAMES; do [ "$(ip "$n")" = "$h" ] && case " $out " in *" $n "*) ;; *) out="$out $n" ;; esac; done; done < <(grep ' systemctl stop ' "$SANDBOX/events.log"); echo "${out# }"; }
recline() { grep -E "^$1" "$2" | head -1; }

reset_fleet; OLD=$(sha "$(root A)/usr/local/bin/rand-node")

# ── refusals before any host: unsigned, a bad signature, a mistyped name ─────────────────────
fleet -- --release t-unsigned --record "$ST/unsigned.record"
check "an unsigned release is refused (exit 1)" test "$RC" = 1
check "  … saying how to sign or override" grep -q 'refusing an unsigned roll' "$ST/run.out"
check "  … before any host is contacted" test "$(ssh_calls)" = 0
check "  … and no record is written" test ! -e "$ST/unsigned.record"
fleet ALLOW_UNSIGNED=1 -- --release t-unsigned --record "$ST/unsigned.record"
check "ALLOW_UNSIGNED=1 without both shas is refused, no host contacted" test "$RC" = 1 -a "$(ssh_calls)" = 0
fleet WANT_SHA="$NEW" WANT_SHA_WALLET="$NEW_WALLET" -- --release t-unsigned --record "$ST/unsigned.record"
check "both shas given but no signature and no ALLOW_UNSIGNED=1: still refused, no host contacted" test "$RC" = 1 -a "$(ssh_calls)" = 0 -a ! -e "$ST/unsigned.record"
cp "$ST/rel/SHA256SUMS" "$ST/rel/tampered"; cp "$ST/rel/SHA256SUMS.sig" "$ST/rel/tampered.sig"; echo "# changed after signing" >> "$ST/rel/tampered"
fleet RELEASE_SUMS="$ST/rel/tampered" RELEASE_SIG="$ST/rel/tampered.sig" -- --release t-tampered --record "$ST/tampered.record"
check "a SHA256SUMS changed after signing is refused, no host contacted, no record" test "$RC" = 1 -a "$(ssh_calls)" = 0 -a ! -e "$ST/tampered.record"
ssh-keygen -q -t ed25519 -N '' -C other -f "$ST/otherkey" >/dev/null
cp "$ST/rel/SHA256SUMS" "$ST/rel/other"; ( cd "$ST/rel" && ssh-keygen -q -Y sign -n rand-release -f "$ST/otherkey" other >/dev/null 2>&1 )
fleet RELEASE_SUMS="$ST/rel/other" RELEASE_SIG="$ST/rel/other.sig" -- --release t-other --record "$ST/other.record"
check "a signature by a key that is not listed is refused, no host contacted" test "$RC" = 1 -a "$(ssh_calls)" = 0
fleet "${SIGNED[@]}" -- --release t-typo --skip ARCHIVE3 --record "$ST/typo.record"
check "a --skip name that is not in the inventory is refused (a typo must not roll the host)" test "$RC" = 1 -a "$(ssh_calls)" = 0
fleet "${SIGNED[@]}" -- --record "$ST/norelease.record"
check "no --release is refused" test "$RC" = 1 -a "$(ssh_calls)" = 0

# ── --dry-run ───────────────────────────────────────────────────────────────────────────────
fleet "${SIGNED[@]}" -- --release t-dry --dry-run --skip archive2 --last ARCHIVE,E --record "$ST/dry.record"
check "--dry-run exits 0" test "$RC" = 0
check "  … prints the order, skipped host left out, --last hosts at the end" grep -q 'order (6): A B C D ARCHIVE E$' "$ST/run.out"
check "  … contacts no host and writes no record" test "$(ssh_calls)" = 0 -a ! -e "$ST/dry.record"
fleet -- --release t-dry --dry-run
check "--dry-run of an unsigned release refuses as the real run would" test "$RC" = 1

# ── the roll: gate, order, skip list, record ────────────────────────────────────────────────
# B comes back slowly: 9 blocks behind, then in step with 4 peers, then in step with 12.
reset_fleet; printf '9 12\n3 4\n2 12\n' > "$(root B)/rpc/seq"
fleet "${SIGNED[@]}" -- --release t-ok --skip ARCHIVE2 --last ARCHIVE,E --poll 0 --record "$ST/ok.record"
check "a signed roll runs to its end (exit $RC)" test "$RC" = 0
check "  … and says so" grep -q '^ROLL-DONE .*: 6 hosts' "$ST/run.out"
all_new=1; for n in A B C D E ARCHIVE; do on_new $n && [ "$(cat "$(root $n)/running-binary")" = "$NEW" ] || all_new=; done
check "every host in the order holds and runs the release's rand-node" test -n "$all_new"
check "the hosts were stopped one after another in the order given" test "$(stop_order)" = "A B C D ARCHIVE E"
b_probes_before_c=$(head -n "$(first_stop C)" "$SANDBOX/events.log" | grep -c "^$(ip B) probe ")
check "the gate held C back while B was behind, then short of peers ($b_probes_before_c probes of B before C's stop)" test "$b_probes_before_c" = 3
check "the skipped host was not contacted and keeps its binary" untouched ARCHIVE2
check "each host got the limits drop-in from update-droplet.sh" test -f "$(root C)/etc/systemd/system/rand-node.service.d/50-limits.conf"
R="$ST/ok.record"
check "the record is written" test -s "$R"
check "  … names the release and both full sha256s" grep -qx "binary: rand-node sha256 $NEW; rand sha256 $NEW_WALLET" "$R"
check "  … says how they were authenticated (the signed SHA256SUMS and its signer)" grep -q "^authenticated: signed: SHA256SUMS sha256 $(sha "$ST/rel/SHA256SUMS"), .*release@selftest" "$R"
check "  … states the gate's numbers" grep -q '^gate: height within 5 of the reference, at least 10 peers' "$R"
check "  … names the skipped host" grep -q '^skipped: ARCHIVE2 ' "$R"
check "  … has one host line per host rolled, in order" test "$(grep '^host: ' "$R" | cut -d' ' -f2 | tr '\n' ' ')" = "A B C D ARCHIVE E "
check "  … each with start, update and rejoin times" test "$(grep -cE '^host: [A-Z0-9]+ started=20[0-9T:-]+Z updated=20[0-9T:-]+Z rejoined=20[0-9T:-]+Z ' "$R")" = 6
bl=$(recline 'host: B ' "$R")
check "  … B's line carries what the gate read: 3 polls, 12 peers, the release's sha, the reference" \
  bash -c 'case "$1" in *" polls=3 active=active rand-node-sha256=$2 height="*" peers=12 ref=E ref-height="*" ref-height-before="*) exit 0 ;; esac; exit 1' _ "$bl" "$NEW"
bh=$(echo "$bl" | tr ' ' '\n' | sed -n 's/^height=//p'); brh=$(echo "$bl" | tr ' ' '\n' | sed -n 's/^ref-height=//p')
check "  … with a height within 5 of the reference's (${bh:-?} vs ${brh:-?})" test -n "$bh" -a -n "$brh" -a $(( ${brh:-99} - ${bh:-0} )) -le 5
check "  … E, the default reference, is compared with another host" grep -q '^host: E .* ref=A ' "$R"
check "  … ends complete, 6 of 6" test "$(recline 'result: ' "$R")" = "result: complete — every host in the order rolled and rejoined" -a "$(recline 'rolled: ' "$R")" = "rolled: 6 of 6"
check "  … and holds no address" bash -c '! grep -q "198\.18\." "$1"' _ "$R"
events_before=$(grep -c '' "$SANDBOX/events.log")
fleet "${SIGNED[@]}" -- --release t-ok --skip ARCHIVE2 --poll 0 --record "$ST/ok.record"
check "a record is never written over" test "$RC" = 1 -a "$(grep -c '' "$SANDBOX/events.log")" = "$events_before"

# ── a host that does not rejoin stops the roll ──────────────────────────────────────────────
reset_fleet; printf '50 12\n' > "$(root C)/rpc/seq"
fleet "${SIGNED[@]}" -- --release t-behind --skip ARCHIVE2 --last ARCHIVE,E --timeout 2 --poll 1 --record "$ST/behind.record"
check "a host that stays 50 blocks behind stops the roll (exit 2)" test "$RC" = 2
check "  … after the hosts before it rolled" bash -c "$(declare -f on_new root ip sha sandbox_root); SANDBOX='$SANDBOX' NEW='$NEW'; on_new A && on_new B"
check "  … and the hosts after it are untouched: D" untouched D
check "  … ARCHIVE" untouched ARCHIVE
check "  … E (probed as the reference, never stopped)" test "$(first_stop E)" = 0 -a "$(sha "$(root E)/usr/local/bin/rand-node")" = "$OLD"
R="$ST/behind.record"
check "  … the record says it stopped at C, with what the gate last read" grep -qE '^host: C .* rejoined=NO polls=[0-9]+ waited=[0-9]+s last: active=active .* peers=12 ref=E ' "$R"
check "  … names the result" grep -q '^result: STOPPED — at C: not back in step after ' "$R"
check "  … and the hosts not rolled" grep -qx 'not-rolled: D ARCHIVE E' "$R"
check "  … with 2 of 6 rolled" grep -qx 'rolled: 2 of 6' "$R"
# The same roll again once C is back: the hosts already on the release are not restarted.
: > "$(root C)/rpc/seq"; : > "$(root A)/systemctl.log"
fleet "${SIGNED[@]}" -- --release t-behind --skip ARCHIVE2 --last ARCHIVE,E --poll 0 --record "$ST/resume.record"
check "run again after the host is back, the roll completes" test "$RC" = 0 -a "$(recline 'rolled: ' "$ST/resume.record")" = "rolled: 6 of 6"
check "  … without restarting a host already on the release" bash -c '! grep -qE "^(restart|stop)" "$1"' _ "$(root A)/systemctl.log"

reset_fleet; printf '0 9\n' > "$(root A)/rpc/seq"
fleet "${SIGNED[@]}" -- --release t-peers --skip ARCHIVE2 --timeout 2 --poll 1 --record "$ST/peers.record"
check "a host in step but with 9 peers stops the roll at the first host" test "$RC" = 2 -a "$(first_stop B)" = 0
reset_fleet; printf '0 9\n' > "$(root A)/rpc/seq"
fleet "${SIGNED[@]}" -- --release t-peers9 --skip ARCHIVE2 --min-peers 9 --poll 0 --record "$ST/peers9.record"
check "  … and --min-peers 9 lets the same host pass" test "$RC" = 0
reset_fleet; printf '7 12\n' > "$(root A)/rpc/seq"
fleet "${SIGNED[@]}" -- --release t-within --skip ARCHIVE2 --within 3 --timeout 2 --poll 1 --record "$ST/within.record"
check "--within is the bound: 7 behind fails within 3 …" test "$RC" = 2
reset_fleet; printf '7 12\n' > "$(root A)/rpc/seq"
fleet "${SIGNED[@]}" -- --release t-within8 --skip ARCHIVE2 --within 8 --poll 0 --record "$ST/within8.record"
check "  … and passes within 8" test "$RC" = 0
reset_fleet; printf -- '-\n' > "$(root A)/rpc/seq"
fleet "${SIGNED[@]}" -- --release t-norpc --skip ARCHIVE2 --timeout 2 --poll 1 --record "$ST/norpc.record"
check "a host whose RPC does not answer stops the roll" test "$RC" = 2 -a "$(first_stop B)" = 0
reset_fleet; : > "$(root A)/INSTALL-NOOP"
fleet "${SIGNED[@]}" -- --release t-noinstall --skip ARCHIVE2 --timeout 2 --poll 1 --record "$ST/noinstall.record"
check "a host back in step but still on the old binary (the install did not take) stops the roll" test "$RC" = 2 -a "$(first_stop B)" = 0
check "  … and the record shows the sha256 the gate read on it" grep -q "^host: A .* rejoined=NO .* rand-node-sha256=$OLD height=" "$ST/noinstall.record"
reset_fleet; : > "$SANDBOX/chain-halted"
fleet "${SIGNED[@]}" -- --release t-halt --skip ARCHIVE2 --timeout 2 --poll 1 --record "$ST/halt.record"
check "a chain that does not move stops the roll, although every node is 'in step'" test "$RC" = 2 -a "$(first_stop B)" = 0
check "  … and the record shows the reference did not advance" bash -c 'l=$(grep "^host: A " "$1"); a=${l##*ref-height=}; a=${a%% *}; b=${l##*ref-height-before=}; [ -n "$a" ] && [ "$a" = "$b" ]' _ "$ST/halt.record"

# ── failures of the update itself, and of the reference ─────────────────────────────────────
reset_fleet; : > "$(root B)/DOWN"
fleet "${SIGNED[@]}" -- --release t-down --skip ARCHIVE2 --poll 0 --record "$ST/down.record"
check "an unreachable host that was not skipped stops the roll there (exit 2)" test "$RC" = 2
check "  … the host after it is untouched" untouched C
check "  … the record says the update failed at B" grep -q '^host: B .* update=FAILED ' "$ST/down.record"
reset_fleet; : > "$(root B)/DOWN"
fleet "${SIGNED[@]}" -- --release t-skipdown --skip ARCHIVE2,B --poll 0 --record "$ST/skipdown.record"
check "skipped by name, the same host is left out and the roll completes" test "$RC" = 0 -a "$(recline 'rolled: ' "$ST/skipdown.record")" = "rolled: 5 of 5"
check "  … with both skipped hosts on the record" grep -q '^skipped: ARCHIVE2 B ' "$ST/skipdown.record"
reset_fleet; : > "$(root E)/DOWN"
fleet "${SIGNED[@]}" BUILD_HOST="$(ip A)" -- --release t-refdown --skip ARCHIVE2 --ref E --poll 0 --record "$ST/refdown.record"
check "a reference that does not answer stops the roll before the first host is touched" test "$RC" = 2 -a "$(first_stop A)" = 0
check "  … and the record says so" grep -q '^result: STOPPED — before A: the reference E did not answer' "$ST/refdown.record"
reset_fleet; echo "not the release" >> "$(root E)/root/rel/rand-node"
fleet "${SIGNED[@]}" -- --release t-wrongbuild --skip ARCHIVE2 --poll 0 --record "$ST/wrongbuild.record"
check "a build host holding bytes the signed SHA256SUMS does not list stops the roll (exit $RC)" test "$RC" = 2
check "  … with the first host never stopped, still on its old binary" test "$(first_stop A)" = 0 -a "$(sha "$(root A)/usr/local/bin/rand-node")" = "$OLD"

# ── the explicit unsigned override ──────────────────────────────────────────────────────────
reset_fleet
fleet ALLOW_UNSIGNED=1 WANT_SHA="$NEW" WANT_SHA_WALLET="$NEW_WALLET" -- --release t-unsigned-ok --skip ARCHIVE2 --poll 0 --record "$ST/unsigned-ok.record"
check "ALLOW_UNSIGNED=1 with both shas rolls" test "$RC" = 0
check "  … and the record says the roll was unsigned" grep -q '^authenticated: UNSIGNED (ALLOW_UNSIGNED=1)' "$ST/unsigned-ok.record"

finish
