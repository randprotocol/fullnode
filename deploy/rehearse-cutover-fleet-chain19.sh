#!/usr/bin/env bash
# Rehearse deploy/cutover-fleet-chain19.sh end to end against 26 FAKE hosts — local directories
# behind a fake `ssh`/`scp`, addressed by TEST-NET-1 addresses (192.0.2.x, RFC 5737: unroutable).
# No network, no real host: the script under test is COPIED into a temp tree whose deploy/nodes.env
# names only the fake hosts, the fake `ssh` refuses any host outside 192.0.2.0/24, and the run
# aborts unless the fakes are first on PATH.
#
#   NODE=<v0.6.7 rand-node> WALLET=<v0.6.7 rand> deploy/rehearse-cutover-fleet-chain19.sh
#
# (macOS: ~/rand-node-a/bin-v067rc1/{rand-node,rand}.) It cuts two dry-run chain-19 genesis files
# (DRY_RUN=1 deploy/cut-chain19-genesis.sh — a first cut and a re-cut), builds 20 nodes.env-style
# hosts (two with the datadir behind a symlink, as obs1 and rand-archive-2) and 6 guardian hosts
# (ExecStart in a chain18.conf drop-in), all "running" chain 18, and drives every phase through the
# refusals that matter: preflight on a wrong binary / a stale data-19; start without a marker;
# switch while running, before push, with a rand-guardian active; push without LOCAL_NODE and of
# chain 18's own genesis; the happy path (units rewritten, datadirs initialised, no binary
# written, marker consumed by start, wait sees 26/26 on the new hash); rollback (units byte-equal
# to chain 18's again); and a re-cut, where a guardian host's stale data-19 must be moved aside
# and never reused.
#
# What it does NOT prove: the remote commands run under this machine's tools behind small shims
# (`systemctl`, `runuser`, `sha256sum`, `install -o`, GNU `sed -i`, the node's RPC), not on a real
# Ubuntu host under systemd. The lines shared with deploy/cutover-fleet-chain18.sh ran on the real
# fleet on 2026-09-29; `preflight`, `rollback` and the data-19 stamp are new here and have only
# ever run in this rehearsal.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:?a v0.6.7 rand-node on this machine}; WALLET=${WALLET:?the matching rand}
[ -x "$NODE" ] && [ -x "$WALLET" ] || { echo "rehearse: NODE / WALLET are not executable" >&2; exit 1; }
BIN=$(mktemp -d); T=$(mktemp -d); trap 'rm -rf "$T" "$BIN"' EXIT
ln -s "$(cd "$(dirname "$NODE")" && pwd)/$(basename "$NODE")" "$BIN/rand-node"
ln -s "$(cd "$(dirname "$WALLET")" && pwd)/$(basename "$WALLET")" "$BIN/rand"
mkdir -p "$T/repo/deploy" "$T/shim" "$T/rshim" "$T/hosts" "$T/markers"
SRC=$PWD/deploy/cutover-fleet-chain19.sh; G18=$PWD/deploy/genesis-chain18.json
G19=$T/genesis-chain19.DRY-RUN.json; G19B=$T/genesis-chain19.DRY-RUN-B.json
for g in "$G19" "$G19B"; do
  DRY_RUN=1 DRY_OUT=$g NODE=$BIN/rand-node WALLET=$BIN/rand deploy/cut-chain19-genesis.sh > "$T/dry.log" 2>&1 \
    || { echo "rehearse: the dry-run cut failed: $(tail -2 "$T/dry.log")" >&2; exit 1; }
done

# ── the fake ssh / scp (the laptop side) ───────────────────────────────────────────────────────
cat > $T/shim/ssh <<'FAKE_SSH'
#!/usr/bin/env bash
# FAKE ssh for the fleet-script rehearsal: runs the "remote" command locally inside a per-host fake root.
host=""; cmd=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n) shift;; -o|-i) shift 2;;
    root@*) host=${1#root@}; shift; cmd="$*"; break;;
    *) shift;;
  esac
done
case "$host" in 192.0.2.*) ;; *) echo "FAKE ssh: refusing non-TEST-NET host '$host'" >&2; exit 255;; esac
R=$FAKE_HOSTS/$host
[ -d "$R" ] || { echo "FAKE ssh: no such host $host" >&2; exit 255; }
[ ! -e "$R/unreachable" ] || exit 255
cmd=$(printf '%s' "$cmd" | /usr/bin/sed -e "s#/etc/systemd/system#$R/etc/systemd/system#g" -e "s#/usr/local/bin#$R/usr/local/bin#g" -e "s#/var/lib/randnode#$R/var/lib/randnode#g" -e "s#/root#$R/root#g")
FAKE_ROOT=$R FAKE_HOST=$host PATH="$FAKE_RSHIM:$PATH" bash -c "$cmd"
FAKE_SSH
cat > $T/shim/scp <<'FAKE_SCP'
#!/usr/bin/env bash
src=""; dst=""
while [ $# -gt 0 ]; do case "$1" in -q) shift;; -o|-i) shift 2;; root@*) dst=$1; shift;; *) src=$1; shift;; esac; done
host=${dst#root@}; path=${host#*:}; host=${host%%:*}
case "$host" in 192.0.2.*) ;; *) echo "FAKE scp: refusing $host" >&2; exit 255;; esac
cp "$src" "$FAKE_HOSTS/$host$path"
FAKE_SCP
# ── what a fake host's shell finds first on PATH (the host side) ───────────────────────────────
cat > $T/rshim/systemctl <<'FAKE_SYSTEMCTL'
#!/usr/bin/env bash
st=$FAKE_ROOT/state; mkdir -p $st
case "$1" in
  is-active) q=0; [ "$2" = --quiet ] && { q=1; shift; }; s=$(cat $st/$2 2>/dev/null || echo inactive); [ $q = 1 ] || echo $s; [ "$s" = active ];;
  stop) echo inactive > $st/$2;;
  start) echo active > $st/$2;;
  daemon-reload) :;;
  cat) cat $FAKE_ROOT/etc/systemd/system/$2.service $FAKE_ROOT/etc/systemd/system/$2.service.d/*.conf 2>/dev/null;;
  *) echo "fake systemctl: $*" >&2; exit 1;;
esac
FAKE_SYSTEMCTL
cat > $T/rshim/sha256sum <<'FAKE_SHA256SUM'
#!/usr/bin/env bash
exec shasum -a 256 "$@"
FAKE_SHA256SUM
cat > $T/rshim/hostname <<'FAKE_HOSTNAME'
#!/usr/bin/env bash
cat $FAKE_ROOT/hostname
FAKE_HOSTNAME
cat > $T/rshim/runuser <<'FAKE_RUNUSER'
#!/usr/bin/env bash
# runuser -u randnode -- cmd…
shift 3; exec "$@"
FAKE_RUNUSER
cat > $T/rshim/install <<'FAKE_INSTALL'
#!/usr/bin/env bash
a=(); while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2;; *) a+=("$1"); shift;; esac; done
exec /usr/bin/install "${a[@]}"
FAKE_INSTALL
cat > $T/rshim/sed <<'FAKE_SED'
#!/usr/bin/env bash
if [ "$1" = -i ]; then shift; exec /usr/bin/sed -i '' "$@"; fi
exec /usr/bin/sed "$@"
FAKE_SED
cat > $T/rshim/curl <<'FAKE_CURL'
#!/usr/bin/env bash
# FAKE node RPC on 127.0.0.1:8545: answers only while rand-node is "active", for the chain of the
# datadir the unit / drop-in names (chain 18's hash for the old datadir; for any other, the hash
# the installed binary derives from the genesis file the host holds).
[ "$(cat $FAKE_ROOT/state/rand-node 2>/dev/null)" = active ] || exit 7
body="$*"
dd=$(cat $FAKE_ROOT/etc/systemd/system/rand-node.service $FAKE_ROOT/etc/systemd/system/rand-node.service.d/*.conf 2>/dev/null | grep -o -- '--datadir [^ ]*' | tail -1 | cut -d' ' -f2)
case "$body" in
  *rand_getGenesisHash*)
    case "$dd" in
      *-a7cb020c|*/data-18) h=a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76;;
      *) [ -d "$dd/db" ] || exit 7; t=$(mktemp -d); h=$($FAKE_ROOT/usr/local/bin/rand-node init --datadir $t/p --genesis $FAKE_ROOT/root/genesis-chain19.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf $t;;
    esac
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"$h\"}";;
  *rand_getHealth*) echo '{"id":1,"jsonrpc":"2.0","result":{"status":"ok"}}';;
  *rand_status*) echo '{"id":1,"jsonrpc":"2.0","result":{"height":5,"view":6}}';;
  *rand_getVersion*) echo '{"id":1,"jsonrpc":"2.0","result":{"chain_id":0,"git_sha":"fake"}}';;
esac
FAKE_CURL
# ── the 26 fake hosts, on chain 18 ─────────────────────────────────────────────────────────────
cat > $T/mkfleet.sh <<'MKFLEET'
#!/usr/bin/env bash
# Build 26 fake hosts on chain 18: 20 nodes.env-style (two with the datadir behind a symlink, as obs1
# / rand-archive-2) and 6 guardian hosts (ExecStart in a chain18.conf drop-in, data-18).
set -euo pipefail
T=$1; BIN=$2; H=$T/hosts; rm -rf $H; mkdir -p $H
: > $T/repo/deploy/nodes.env; : > $T/guardian-hosts.txt
mk() { # ip name
  local R=$H/$1; mkdir -p $R/root $R/etc/systemd/system/rand-node.service.d $R/usr/local/bin $R/var/lib/randnode $R/state
  echo $2 > $R/hostname; ln -s $BIN/rand-node $R/usr/local/bin/rand-node; ln -s $BIN/rand $R/usr/local/bin/rand
  echo active > $R/state/rand-node; rmdir $R/etc/systemd/system/rand-node.service.d
}
for n in $(seq 1 20); do
  ip=192.0.2.$n; mk $ip rand-node-$n; R=$H/$ip
  echo "NODE_$n=/ip4/$ip/tcp/30303/p2p/12D3Fake$n" >> $T/repo/deploy/nodes.env
  dd=$R/root/data-n$n-a7cb020c
  if [ $n -ge 19 ]; then mkdir -p $R/mnt/volume/data-n$n-a7cb020c/db; ln -s $R/mnt/volume/data-n$n-a7cb020c $dd; else mkdir -p $dd/db; fi
  printf '[Service]\nExecStart=%s run --datadir %s --key %s/root/keys/node.key.json --validator\n' "$R/usr/local/bin/rand-node" "$dd" "$R" > $R/etc/systemd/system/rand-node.service
  printf '[Service]\nExecStart=old run --datadir %s --key x\n' "$R/root/data-n$n-d1afefc3" > $R/root/rand-node.service.d1afefc3.bak
done
for i in $(seq 1 6); do
  ip=192.0.2.10$i; mk $ip rand-guardian-$i; R=$H/$ip
  echo "$i $ip" >> $T/guardian-hosts.txt
  mkdir -p $R/etc/systemd/system/rand-node.service.d $R/var/lib/randnode/data-18/db
  printf '[Service]\nUser=randnode\n' > $R/etc/systemd/system/rand-node.service
  printf '[Service]\nExecStart=\nExecStart=%s run --datadir %s --key %s --validator\n' "$R/usr/local/bin/rand-node" "$R/var/lib/randnode/data-18" "$R/var/lib/randnode/node.key.json" > $R/etc/systemd/system/rand-node.service.d/chain18.conf
  echo inactive > $R/state/rand-guardian
done
MKFLEET
chmod +x "$T"/shim/* "$T"/rshim/* "$T/mkfleet.sh"
cp "$SRC" "$T/repo/deploy/cutover-fleet-chain19.sh"
"$T/mkfleet.sh" "$T" "$BIN"
export PATH="$T/shim:$PATH" FAKE_HOSTS=$T/hosts FAKE_RSHIM=$T/rshim
[ "$(command -v ssh)" = "$T/shim/ssh" ] && [ "$(command -v scp)" = "$T/shim/scp" ] || { echo "rehearse: the fake ssh/scp are not first on PATH — abort" >&2; exit 99; }
! grep -oE '/ip4/[0-9.]+' "$T/repo/deploy/nodes.env" | grep -qv '^/ip4/192\.0\.2\.' || { echo "rehearse: the fake nodes.env names a non-TEST-NET host — abort" >&2; exit 99; }
export GUARDIAN_HOSTS=$T/guardian-hosts.txt BOOTS="192.0.2.3 192.0.2.4" MARKER_GLOB=$T/markers/chain19-switched- WAIT_SLEEP=0
export WANT_SHA=$(shasum -a 256 "$BIN/rand-node" | cut -d' ' -f1) WANT_SHA_WALLET=$(shasum -a 256 "$BIN/rand" | cut -d' ' -f1)
F=$T/repo/deploy/cutover-fleet-chain19.sh
pass=0; fail=0
t() { # <description> <want rc: 0|!0> <grep phrase in output> cmd…
  local what=$1 want=$2 phrase=$3; shift 3
  "$@" > $T/out.log 2>&1; local rc=$?
  if { [ "$want" = 0 ] && [ $rc = 0 ]; } || { [ "$want" != 0 ] && [ $rc != 0 ]; }; then
    if grep -qF -- "$phrase" $T/out.log; then echo "ok   — $what (rc $rc): $(grep -F -- "$phrase" $T/out.log | tail -1 | cut -c1-150)"; pass=$((pass+1))
    else echo "FAIL — $what: rc $rc as wanted but no \"$phrase\": $(tail -2 $T/out.log | cut -c1-200)"; fail=$((fail+1)); fi
  else echo "FAIL — $what: rc $rc, wanted $want: $(tail -3 $T/out.log | cut -c1-300)"; fail=$((fail+1)); fi
}
chk() { if eval "$2"; then echo "ok   — $1"; pass=$((pass+1)); else echo "FAIL — $1"; fail=$((fail+1)); fi; }
nmark() { ls $T/markers | wc -l | tr -d ' '; }
units() { for h in $T/hosts/*; do cat $h/etc/systemd/system/rand-node.service $h/etc/systemd/system/rand-node.service.d/*.conf 2>/dev/null; done | shasum | cut -c1-16; }
active() { grep -l '^active$' $T/hosts/*/state/rand-node 2>/dev/null | wc -l | tr -d ' '; }
U0=$(units)

t "preflight on a healthy chain-18 fleet" 0 "PREFLIGHT OK" $F preflight
chk "preflight changed nothing" '[ "$(units)" = "$U0" ] && [ "$(active)" = 26 ] && [ "$(nmark)" = 0 ]'
rm $T/hosts/192.0.2.7/usr/local/bin/rand-node; cp $BIN/rand $T/hosts/192.0.2.7/usr/local/bin/rand-node
t "preflight with one host on another rand-node build" 1 "not every host is ready" $F preflight
grep -q 'installed rand-node is' $T/out.log && { echo "ok   — …and names the host's binary"; pass=$((pass+1)); } || { echo "FAIL — no binary message"; fail=$((fail+1)); }
rm $T/hosts/192.0.2.7/usr/local/bin/rand-node; ln -s $BIN/rand-node $T/hosts/192.0.2.7/usr/local/bin/rand-node
mkdir -p $T/hosts/192.0.2.103/var/lib/randnode/data-19
t "preflight with a stale data-19 on a guardian host" 1 "not every host is ready" $F preflight
rmdir $T/hosts/192.0.2.103/var/lib/randnode/data-19
t "start with no marker" 1 "no $MARKER_GLOB<prefix> marker" $F start
chk "…started nothing (26 still active from before, none changed)" '[ "$(units)" = "$U0" ]'
t "switch while the fleet still runs" 1 "some hosts are not ready" env LOCAL_NODE=$BIN/rand-node $F switch $G19
chk "…switched nothing, no marker" '[ "$(units)" = "$U0" ] && [ "$(nmark)" = 0 ]'
t "stop" 0 "STOPPED" $F stop
chk "all 26 inactive" '[ "$(active)" = 0 ]'
t "push without LOCAL_NODE" 1 "LOCAL_NODE is unset" $F push $G19
t "push of chain 18's genesis" 1 "has chain_id 18, not 19" env LOCAL_NODE=$BIN/rand-node $F push $G18
chk "…nothing copied" '! ls $T/hosts/*/root/genesis-chain19.json >/dev/null 2>&1'
t "switch before push" 1 "some hosts are not ready" env LOCAL_NODE=$BIN/rand-node $F switch $G19
chk "…no marker, units untouched" '[ "$(units)" = "$U0" ] && [ "$(nmark)" = 0 ]'
t "push of the chain-19 genesis" 0 "PUSHED" env LOCAL_NODE=$BIN/rand-node $F push $G19
chk "26 hosts hold the genesis, byte-identical" '[ "$(shasum $T/hosts/*/root/genesis-chain19.json | cut -d" " -f1 | sort -u | wc -l | tr -d " ")" = 1 ] && [ "$(ls $T/hosts/*/root/genesis-chain19.json | wc -l | tr -d " ")" = 26 ]'
echo active > $T/hosts/192.0.2.102/state/rand-guardian
t "switch with a rand-guardian still active" 1 "some hosts are not ready" env LOCAL_NODE=$BIN/rand-node $F switch $G19
chk "…no marker, so start still refuses" '[ "$(nmark)" = 0 ]'
t "start after a failed switch" 1 "refusing" $F start
chk "…nothing started" '[ "$(active)" = 0 ]'
echo inactive > $T/hosts/192.0.2.102/state/rand-guardian
t "switch (re-run over the 25 already switched)" 0 "SWITCHED" env LOCAL_NODE=$BIN/rand-node $F switch $G19
NEW=$(cut -d' ' -f1 $T/markers/*); P=${NEW:0:8}
chk "one marker, named after the genesis prefix $P" '[ "$(nmark)" = 1 ] && [ -f $T/markers/chain19-switched-$P ]'
chk "20 node units name -$P, none -a7cb020c; each new datadir initialised" '[ "$(grep -l -- "-$P " $T/hosts/192.0.2.{1..20}/etc/systemd/system/rand-node.service | wc -l | tr -d " ")" = 20 ] && ! grep -q -- "-a7cb020c " $T/hosts/192.0.2.{1..20}/etc/systemd/system/rand-node.service && [ "$(ls -d $T/hosts/192.0.2.{1..20}/root/data-n*-$P/db | wc -l | tr -d " ")" = 20 ]'
chk "the two symlinked (archive) hosts got their chain-19 datadir on the volume" '[ -L $T/hosts/192.0.2.19/root/data-n19-$P ] && [ -d $T/hosts/192.0.2.19/mnt/volume/data-n19-$P/db ] && [ -d $T/hosts/192.0.2.20/mnt/volume/data-n20-$P/db ]'
chk "every node host kept a chain-18 unit backup; chain-18 datadirs untouched" '[ "$(ls $T/hosts/192.0.2.{1..20}/root/rand-node.service.a7cb020c.bak | wc -l | tr -d " ")" = 20 ] && [ "$(ls -d $T/hosts/192.0.2.{1..18}/root/data-n*-a7cb020c/db | wc -l | tr -d " ")" = 18 ]'
chk "6 guardian hosts: chain19.conf on data-19, chain18.conf moved aside, stamp = the genesis" '[ "$(grep -l -- "/data-19 " $T/hosts/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain19.conf | wc -l | tr -d " ")" = 6 ] && ! ls $T/hosts/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain18.conf >/dev/null 2>&1 && [ "$(ls $T/hosts/192.0.2.10{1..6}/root/chain18.conf.c18 | wc -l | tr -d " ")" = 6 ] && [ "$(cat $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-19.genesis | sort -u)" = "$NEW" ] && [ -d $T/hosts/192.0.2.106/var/lib/randnode/data-19/db ] && [ -d $T/hosts/192.0.2.106/var/lib/randnode/data-18/db ]'
chk "no binary was written anywhere (every /usr/local/bin entry is still the harness symlink)" '[ "$(find $T/hosts/*/usr/local/bin -type l | wc -l | tr -d " ")" = 52 ] && [ "$(find $T/hosts/*/usr/local/bin -type f | wc -l | tr -d " ")" = 0 ] && ! ls $T/hosts/*/root/*.pre-c19 $T/hosts/*/root/*.c19 >/dev/null 2>&1'
t "start" 0 "START-DONE" $F start
chk "26 active, marker consumed" '[ "$(active)" = 26 ] && [ "$(nmark)" = 0 ]'
t "a second start" 1 "refusing" $F start
t "wait" 0 "CUTOVER DONE: all 26 on $NEW" env LOCAL_NODE=$BIN/rand-node $F wait $G19
t "rollback while running" 1 "not back on chain 18" $F rollback
chk "…no rollback marker" '[ "$(nmark)" = 0 ]'
t "stop (for the rollback)" 0 "STOPPED" $F stop
t "rollback" 0 "ROLLED BACK" $F rollback
chk "every unit / drop-in is byte-for-byte chain 18's again" '[ "$(units)" = "$U0" ]'
t "start after rollback" 0 "START-DONE" $F start
t "wait for chain 19 after a rollback never completes (the fleet serves chain 18)" 1 "0/26 on chain 19" env LOCAL_NODE=$BIN/rand-node bash -c "$F wait $G19 | head -1; exit 1"
t "preflight after the rollback flags the leftover chain-19 dirs on guardian hosts" 1 "not every host is ready" $F preflight
t "stop again" 0 "STOPPED" $F stop
t "push of a RE-CUT genesis" 0 "PUSHED" env LOCAL_NODE=$BIN/rand-node $F push $G19B
t "switch to the re-cut genesis (guardian hosts still hold the first cut's data-19)" 0 "SWITCHED" env LOCAL_NODE=$BIN/rand-node $F switch $G19B
NEWB=$(cut -d' ' -f1 $T/markers/*)
chk "each guardian host moved the first cut's data-19 aside (kept, with its db) and initialised a fresh one for the re-cut" '[ "$(ls -d $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-19.stale-$P/db | wc -l | tr -d " ")" = 6 ] && [ "$(ls -d $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-19/db | wc -l | tr -d " ")" = 6 ] && [ "$(cat $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-19.genesis | sort -u)" = "$NEWB" ] && [ "$NEWB" != "$NEW" ]'
# a data-19 stamped with the first cut's hash again, while that cut's aside name is already taken
echo "$NEW" > $T/hosts/192.0.2.104/var/lib/randnode/data-19.genesis
t "a stale data-19 whose aside name is taken is refused, not overwritten" 1 "some hosts are not ready" env LOCAL_NODE=$BIN/rand-node $F switch $G19B
grep -q 'sort them out by hand' $T/out.log && { echo "ok   — …and says so"; pass=$((pass+1)); } || { echo "FAIL — no by-hand message: $(grep 192.0.2.104 $T/out.log | cut -c1-200)"; fail=$((fail+1)); }
chk "…both directories still there, no marker" '[ -d $T/hosts/192.0.2.104/var/lib/randnode/data-19/db ] && [ -d $T/hosts/192.0.2.104/var/lib/randnode/data-19.stale-$P/db ] && [ "$(nmark)" = 0 ]'
echo "$NEWB" > $T/hosts/192.0.2.104/var/lib/randnode/data-19.genesis
t "switch to the re-cut again (every host already there)" 0 "SWITCHED" env LOCAL_NODE=$BIN/rand-node $F switch $G19B
t "start on the re-cut" 0 "START-DONE" $F start
t "wait on the re-cut" 0 "CUTOVER DONE" env LOCAL_NODE=$BIN/rand-node $F wait $G19B
t "wait for the FIRST cut's hash now fails" 1 "0/26 on chain 19" env LOCAL_NODE=$BIN/rand-node bash -c "$F wait $G19 | head -1; exit 1"
echo "fleet rehearsal: $pass passed, $fail failed"
[ $fail = 0 ]
