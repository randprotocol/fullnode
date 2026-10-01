#!/usr/bin/env bash
# Rehearse deploy/cutover-fleet-chain20.sh end to end against 26 FAKE hosts — local directories
# behind a fake `ssh`/`scp`, addressed by TEST-NET-1 addresses (192.0.2.x, RFC 5737: unroutable).
# No network, no real host: the script under test is COPIED into a temp tree whose deploy/nodes.env
# names only the fake hosts, the fake `ssh`/`scp` refuse any host outside 192.0.2.0/24, the fake
# `curl` serves downloads only from a local directory for the made-up https://rehearsal.invalid/
# base, and the run aborts unless the fakes are first on PATH.
#
#   NODE=<rand-node built from this tree> WALLET=<rand> deploy/rehearse-cutover-fleet-chain20.sh
#
# DERIVED from deploy/rehearse-cutover-fleet-chain19.sh, plus what chain 20 adds: a NEW BUILD. The
# fleet starts on "v0.6.7" and is staged and switched to "v0.6.8". Both are small wrapper scripts
# around $NODE / $WALLET with distinct sha256s: the old one answers `--version` as 0.6.7, the new one
# as 0.6.8 and adds a `--program-state-cell-fee` line to `genesis --help` (RPL-2 is not on main yet;
# the wrapper stands in for that one line so the script's default NEED_FLAGS is what is exercised).
# Every other call goes to the real binary — `init` really derives each genesis hash on every fake
# host. Two dry-run chain-20 genesis files are cut first (DRY_RUN=1 deploy/cut-chain20-genesis.sh
# with the REAL $NODE, a first cut and a re-cut).
#
# Driven: preflight (and its refusals: a wrong binary, a stale data-20, a leftover *.pre-c20);
# stage from a "release" (the fake curl), from a private url, from a local path (and the refusals:
# no pins, a local sha mismatch, a non-ELF file, a release whose bytes do not match — removed on
# every host, an http:// url); start without a marker; switch while running, before push, with a
# rand-guardian active, on a host whose installed binary is not v0.6.7; push without LOCAL_NODE, of
# chain 19's genesis, without and with a wrong `second-hash` in the cut record; the happy path
# (binaries installed and their v0.6.7 originals kept, units rewritten, datadirs initialised, marker
# consumed, wait sees 26/26); rollback (units AND binaries byte-equal to chain 19's again); a re-cut
# whose guardian hosts must move the first cut's data-20 aside.
#
# What it does NOT prove: the remote commands run under this machine's tools behind small shims
# (`systemctl`, `runuser`, `sha256sum`, `install -o`, GNU `sed -i`, the node's RPC, a download), not
# on a real Ubuntu host under systemd; the binaries are wrappers, not the v0.6.8 release. The lines
# shared with deploy/cutover-fleet-chain18.sh (stage, install) ran on the real fleet on 2026-09-29,
# those shared with chain 19's on 2026-10-01; STAGE_FROM=url/path, the sha-checked *.pre-c20 backup
# and the binary rollback are new here and have only ever run in this rehearsal.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE=${NODE:?a rand-node on this machine (built from this tree)}; WALLET=${WALLET:?the matching rand}
[ -x "$NODE" ] && [ -x "$WALLET" ] || { echo "rehearse: NODE / WALLET are not executable" >&2; exit 1; }
BIN=$(mktemp -d); T=$(mktemp -d); trap 'rm -rf "$T" "$BIN"' EXIT
RN=$(cd "$(dirname "$NODE")" && pwd)/$(basename "$NODE"); RW=$(cd "$(dirname "$WALLET")" && pwd)/$(basename "$WALLET")
mkdir -p "$BIN/old" "$BIN/new" "$BIN/badrel" "$T/repo/deploy/lib" "$T/shim" "$T/rshim" "$T/hosts" "$T/markers"
cat > "$BIN/old/rand-node" <<EOF
#!/usr/bin/env bash
# rehearsal wrapper: chain 19's build, "v0.6.7"
case "\${1:-}" in --version) echo "rand-node 0.6.7 (rehearsal wrapper: chain 19's build)"; exit 0;; esac
exec "$RN" "\$@"
EOF
cat > "$BIN/new/rand-node" <<EOF
#!/usr/bin/env bash
# rehearsal wrapper: chain 20's build, "v0.6.8"
case "\${1:-}" in --version) echo "rand-node 0.6.8 (rehearsal wrapper: chain 20's build)"; exit 0;; esac
if [ "\${1:-}" = genesis ] && [ "\${2:-}" = --help ]; then
  "$RN" genesis --help; echo "      --program-state-cell-fee <UNITS>  [rehearsal wrapper: RPL-2's flag, not in this binary]"; exit 0; fi
exec "$RN" "\$@"
EOF
printf '#!/usr/bin/env bash\n# rehearsal wrapper: chain 19 rand\nexec "%s" "$@"\n' "$RW" > "$BIN/old/rand"
printf '#!/usr/bin/env bash\n# rehearsal wrapper: chain 20 rand\nexec "%s" "$@"\n' "$RW" > "$BIN/new/rand"
cp "$BIN/new/rand" "$BIN/badrel/rand"; printf '#!/usr/bin/env bash\n# a tampered release\nexit 1\n' > "$BIN/badrel/rand-node"
chmod 755 "$BIN"/old/* "$BIN"/new/* "$BIN"/badrel/*
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
SRC=$PWD/deploy/cutover-fleet-chain20.sh; G19=$PWD/deploy/genesis-chain19.json
G20=$T/genesis-chain20.DRY-RUN.json; G20B=$T/genesis-chain20.DRY-RUN-B.json
for g in "$G20" "$G20B"; do
  DRY_RUN=1 DRY_RUN_NO_PROBE=1 DRY_OUT=$g NODE=$RN WALLET=$RW deploy/cut-chain20-genesis.sh > "$T/dry.log" 2>&1 \
    || { echo "rehearse: the dry-run cut failed: $(tail -2 "$T/dry.log")" >&2; exit 1; }
done
cp deploy/lib/cut-policy.sh deploy/lib/verify-release.sh "$T/repo/deploy/lib/"
cp deploy/cut-record.template "$T/repo/deploy/" 2>/dev/null || true

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
cmd=$(printf '%s' "$cmd" | /usr/bin/sed -e "s#/etc/systemd/system#$R/etc/systemd/system#g" -e "s#/usr/local/bin#$R/usr/local/bin#g" -e "s#/var/lib/randnode#$R/var/lib/randnode#g" -e "s#/root#$R/root#g")
FAKE_ROOT=$R FAKE_HOST=$host PATH="$FAKE_RSHIM:$PATH" bash -c "$cmd"
FAKE_SSH
cat > $T/shim/scp <<'FAKE_SCP'
#!/usr/bin/env bash
srcs=(); dst=""
while [ $# -gt 0 ]; do case "$1" in -q) shift;; -o|-i) shift 2;; root@*) dst=$1; shift;; *) srcs+=("$1"); shift;; esac; done
host=${dst#root@}; path=${host#*:}; host=${host%%:*}
case "$host" in 192.0.2.*) ;; *) echo "FAKE scp: refusing $host" >&2; exit 255;; esac
cp "${srcs[@]}" "$FAKE_HOSTS/$host$path"
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
printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' > $T/rshim/sha256sum
printf '#!/usr/bin/env bash\ncat $FAKE_ROOT/hostname\n' > $T/rshim/hostname
printf '#!/usr/bin/env bash\n# runuser -u randnode -- cmd...\nshift 3; exec "$@"\n' > $T/rshim/runuser
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
# FAKE curl. A download (-o FILE URL) is served from $FAKE_RELEASE_DIR for https://rehearsal.invalid/
# only. Otherwise the node RPC on 127.0.0.1:8545: it answers only while rand-node is "active", for
# the chain of the datadir the unit / drop-in names (chain 19's hash for the old datadir; for any
# other, the hash the INSTALLED binary derives from the chain-20 genesis file the host holds).
out=""; url=""
for a in "$@"; do [ "$prev" = -o ] && out=$a; case "$a" in https://*) url=$a;; esac; prev=$a; done
if [ -n "$out" ]; then
  case "$url" in https://rehearsal.invalid/*) ;; *) echo "FAKE curl: refusing $url" >&2; exit 22;; esac
  f=${url%%\?*}; f=${f##*/}; [ -f "$FAKE_RELEASE_DIR/$f" ] || exit 22
  cp "$FAKE_RELEASE_DIR/$f" "$out"; exit 0
fi
[ "$(cat $FAKE_ROOT/state/rand-node 2>/dev/null)" = active ] || exit 7
body="$*"
dd=$(cat $FAKE_ROOT/etc/systemd/system/rand-node.service $FAKE_ROOT/etc/systemd/system/rand-node.service.d/*.conf 2>/dev/null | grep -o -- '--datadir [^ ]*' | tail -1 | cut -d' ' -f2)
case "$body" in
  *rand_getGenesisHash*)
    case "$dd" in
      *-a3defc93|*/data-19) h=a3defc937d561d4beb1df9a08c9cb87a3dc32dadbfc2d1814ab6f627b0a2228a;;
      *) [ -d "$dd/db" ] || exit 7; t=$(mktemp -d); h=$($FAKE_ROOT/usr/local/bin/rand-node init --datadir $t/p --genesis $FAKE_ROOT/root/genesis-chain20.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf $t;;
    esac
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"$h\"}";;
  *rand_getHealth*) echo '{"id":1,"jsonrpc":"2.0","result":{"status":"ok"}}';;
  *rand_status*) echo '{"id":1,"jsonrpc":"2.0","result":{"height":5,"view":6}}';;
  *rand_getVersion*) echo '{"id":1,"jsonrpc":"2.0","result":{"chain_id":0,"git_sha":"fake","version":"fake"}}';;
esac
FAKE_CURL
# ── the 26 fake hosts, on chain 19, on the "v0.6.7" wrapper ────────────────────────────────────
cat > $T/mkfleet.sh <<'MKFLEET'
#!/usr/bin/env bash
set -euo pipefail
T=$1; OLDB=$2; H=$T/hosts; rm -rf $H; mkdir -p $H
: > $T/repo/deploy/nodes.env; : > $T/guardian-hosts.txt
mk() { # ip name — the installed binaries are COPIES (switch's `install` writes over them)
  local R=$H/$1; mkdir -p $R/root $R/etc/systemd/system $R/usr/local/bin $R/var/lib/randnode $R/state
  echo $2 > $R/hostname; cp $OLDB/rand-node $OLDB/rand $R/usr/local/bin/; echo active > $R/state/rand-node
}
for n in $(seq 1 20); do
  ip=192.0.2.$n; mk $ip rand-node-$n; R=$H/$ip
  echo "NODE_$n=/ip4/$ip/tcp/30303/p2p/12D3Fake$n" >> $T/repo/deploy/nodes.env
  dd=$R/root/data-n$n-a3defc93
  if [ $n -ge 19 ]; then mkdir -p $R/mnt/volume/data-n$n-a3defc93/db; ln -s $R/mnt/volume/data-n$n-a3defc93 $dd; else mkdir -p $dd/db; fi
  printf '[Service]\nExecStart=%s run --datadir %s --key %s/root/keys/node.key.json --validator\n' "$R/usr/local/bin/rand-node" "$dd" "$R" > $R/etc/systemd/system/rand-node.service
done
for i in $(seq 1 6); do
  ip=192.0.2.10$i; mk $ip rand-guardian-$i; R=$H/$ip
  echo "$i $ip" >> $T/guardian-hosts.txt
  mkdir -p $R/etc/systemd/system/rand-node.service.d $R/var/lib/randnode/data-19/db
  printf '[Service]\nUser=randnode\n' > $R/etc/systemd/system/rand-node.service
  printf '[Service]\nExecStart=\nExecStart=%s run --datadir %s --key %s --validator\n' "$R/usr/local/bin/rand-node" "$R/var/lib/randnode/data-19" "$R/var/lib/randnode/node.key.json" > $R/etc/systemd/system/rand-node.service.d/chain19.conf
  echo inactive > $R/state/rand-guardian
done
MKFLEET
chmod +x "$T"/shim/* "$T"/rshim/* "$T/mkfleet.sh"
cp "$SRC" "$T/repo/deploy/cutover-fleet-chain20.sh"
"$T/mkfleet.sh" "$T" "$BIN/old"
export PATH="$T/shim:$PATH" FAKE_HOSTS=$T/hosts FAKE_RSHIM=$T/rshim FAKE_RELEASE_DIR=$BIN/new
[ "$(command -v ssh)" = "$T/shim/ssh" ] && [ "$(command -v scp)" = "$T/shim/scp" ] || { echo "rehearse: the fake ssh/scp are not first on PATH — abort" >&2; exit 99; }
! grep -oE '/ip4/[0-9.]+' "$T/repo/deploy/nodes.env" | grep -qv '^/ip4/192\.0\.2\.' || { echo "rehearse: the fake nodes.env names a non-TEST-NET host — abort" >&2; exit 99; }
OLD_SHA=$(sha "$BIN/old/rand-node"); OLD_SHA_WALLET=$(sha "$BIN/old/rand")
NEW_SHA=$(sha "$BIN/new/rand-node"); NEW_SHA_WALLET=$(sha "$BIN/new/rand")
export GUARDIAN_HOSTS=$T/guardian-hosts.txt BOOTS="192.0.2.3 192.0.2.4" MARKER_GLOB=$T/markers/chain20-switched- WAIT_SLEEP=0 \
  OLD_SHA OLD_SHA_WALLET RELEASE_URL=https://rehearsal.invalid/v0.6.8 CUT_RECORD=$T/cut-record.txt
NEWENV=(WANT_SHA=$NEW_SHA WANT_SHA_WALLET=$NEW_SHA_WALLET)
LN=(LOCAL_NODE=$BIN/new/rand-node)
F=$T/repo/deploy/cutover-fleet-chain20.sh
hash_of() { local d; d=$(mktemp -d); "$RN" init --datadir "$d/p" --genesis "$1" | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2; rm -rf "$d"; }
H20=$(hash_of "$G20"); H20B=$(hash_of "$G20B")
record() { sed -e 's/<[^>]*>/filled (rehearsal)/' "$PWD/deploy/cut-record.template" | sed "s/^second-hash:.*/second-hash: $1/" > "$CUT_RECORD"; }
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
installed() { for h in $T/hosts/*; do sha $h/usr/local/bin/$1; done | sort | uniq -c | awk '{print $1":"$2}' | tr '\n' ' '; }
staged() { ls $T/hosts/*/root/rand-node.c20 2>/dev/null | wc -l | tr -d ' '; }
U0=$(units)

t "preflight on a healthy chain-19 fleet" 0 "PREFLIGHT OK" $F preflight
chk "preflight changed nothing" '[ "$(units)" = "$U0" ] && [ "$(active)" = 26 ] && [ "$(nmark)" = 0 ]'
cp $BIN/new/rand-node $T/hosts/192.0.2.7/usr/local/bin/rand-node
t "preflight with one host on another rand-node" 1 "not every host is ready" $F preflight
grep -q "not chain 19's v0.6.7" $T/out.log && { echo "ok   — …and names the host's binary"; pass=$((pass+1)); } || { echo "FAIL — no binary message"; fail=$((fail+1)); }
cp $BIN/old/rand-node $T/hosts/192.0.2.7/usr/local/bin/rand-node
mkdir -p $T/hosts/192.0.2.103/var/lib/randnode/data-20
t "preflight with a stale data-20 on a guardian host" 1 "not every host is ready" $F preflight
rmdir $T/hosts/192.0.2.103/var/lib/randnode/data-20
touch $T/hosts/192.0.2.9/root/rand.pre-c20
t "preflight with a leftover *.pre-c20" 1 "not every host is ready" $F preflight
rm $T/hosts/192.0.2.9/root/rand.pre-c20
# ── stage ──
t "stage without the v0.6.8 pins" 1 "WANT_SHA / WANT_SHA_WALLET must be" $F stage
t "stage with WANT_SHA = chain 19's binary" 1 "chain 20 needs v0.6.8" env WANT_SHA=$OLD_SHA WANT_SHA_WALLET=$NEW_SHA_WALLET $F stage
t "stage from a path whose rand-node is not WANT_SHA" 1 "is not WANT_SHA" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR=$BIN/old $F stage
t "stage from a path holding a non-ELF build" 1 "not a Linux ELF" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR=$BIN/new $F stage
chk "…nothing copied" '[ "$(staged)" = 0 ] && ! ls $T/hosts/*/root/*.part >/dev/null 2>&1'
t "stage from a release whose rand-node does not match" 1 "not every host staged" env "${NEWENV[@]}" FAKE_RELEASE_DIR=$BIN/badrel $F stage
grep -q 'SHA MISMATCH — removed' $T/out.log && { echo "ok   — …each host said SHA MISMATCH and removed it"; pass=$((pass+1)); } || { echo "FAIL — no mismatch message"; fail=$((fail+1)); }
chk "…no staged or partial file left anywhere" '[ "$(staged)" = 0 ] && ! ls $T/hosts/*/root/*.part >/dev/null 2>&1'
t "stage from url without STAGE_URL" 1 "needs STAGE_URL" env "${NEWENV[@]}" STAGE_FROM=url $F stage
t "stage from a plain-http url" 1 "is not https://" env "${NEWENV[@]}" STAGE_FROM=url STAGE_URL=http://rehearsal.invalid/x $F stage
t "stage from the release" 0 "STAGED" env "${NEWENV[@]}" $F stage
chk "26 hosts hold rand-node.c20 / rand.c20 at the pins; installed still v0.6.7; 26 still active" '[ "$(staged)" = 26 ] && [ "$(installed rand-node)" = "26:$OLD_SHA " ] && [ "$(active)" = 26 ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand-node.c20; sha $h/root/rand.c20; done | sort -u | tr "\n" " ")" = "$(printf "%s\n%s\n" $NEW_SHA $NEW_SHA_WALLET | sort | tr "\n" " ")" ]'
t "stage again from a private url (token kept out of the log)" 0 "STAGED" env "${NEWENV[@]}" STAGE_FROM=url "STAGE_URL=https://rehearsal.invalid/private/v068?token=SECRET123" $F stage
! grep -q SECRET123 $T/out.log && { echo "ok   — …the url's token is not in the output"; pass=$((pass+1)); } || { echo "FAIL — the token was printed"; fail=$((fail+1)); }
t "stage again from a local path (STAGE_ALLOW_NON_ELF=1: the rehearsal's wrappers are scripts)" 0 "STAGED" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR=$BIN/new STAGE_ALLOW_NON_ELF=1 $F stage
# ── the cut ──
t "start with no marker" 1 "no $MARKER_GLOB<prefix> marker" $F start
t "switch while the fleet still runs" 1 "some hosts are not ready" env "${NEWENV[@]}" "${LN[@]}" $F switch $G20
chk "…switched nothing, installed nothing, no marker" '[ "$(units)" = "$U0" ] && [ "$(installed rand-node)" = "26:$OLD_SHA " ] && [ "$(nmark)" = 0 ]'
t "stop" 0 "STOPPED" $F stop
chk "all 26 inactive" '[ "$(active)" = 0 ]'
t "push without LOCAL_NODE" 1 "LOCAL_NODE is unset" env "${NEWENV[@]}" $F push $G20
t "push with chain 19's v0.6.7 as LOCAL_NODE" 1 "not the v0.6.8 build" env "${NEWENV[@]}" LOCAL_NODE=$BIN/old/rand-node $F push $G20
t "push of chain 19's genesis" 1 "has chain_id 19, not 20" env "${NEWENV[@]}" "${LN[@]}" $F push $G19
t "push with no cut record" 1 "no cut record" env "${NEWENV[@]}" "${LN[@]}" $F push $G20
record "$H20B"
t "push with the second operator's hash differing" 1 "differ" env "${NEWENV[@]}" "${LN[@]}" $F push $G20
chk "…nothing copied" '! ls $T/hosts/*/root/genesis-chain20.json >/dev/null 2>&1'
record "$H20"
t "switch before push" 1 "some hosts are not ready" env "${NEWENV[@]}" "${LN[@]}" $F switch $G20
chk "…no marker, units and binaries untouched" '[ "$(units)" = "$U0" ] && [ "$(nmark)" = 0 ] && [ "$(installed rand-node)" = "26:$OLD_SHA " ]'
t "push of the chain-20 genesis" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" $F push $G20
chk "26 hosts hold the genesis, byte-identical" '[ "$(shasum $T/hosts/*/root/genesis-chain20.json | cut -d" " -f1 | sort -u | wc -l | tr -d " ")" = 1 ] && [ "$(ls $T/hosts/*/root/genesis-chain20.json | wc -l | tr -d " ")" = 26 ]'
cp $BIN/badrel/rand-node $T/hosts/192.0.2.12/usr/local/bin/rand-node
# (the first switch attempt: every other host switches in it — a failed switch is re-run, never undone)
t "switch on a host whose installed rand-node is not v0.6.7" 1 "some hosts are not ready" env "${NEWENV[@]}" "${LN[@]}" $F switch $G20
grep -q 'no backup made' $T/out.log && { echo "ok   — …that host made no backup and switched nothing"; pass=$((pass+1)); } || { echo "FAIL — no backup message"; fail=$((fail+1)); }
chk "…its unit still names chain 19, no .pre-c20 there" '[ ! -e $T/hosts/192.0.2.12/root/rand-node.pre-c20 ] && grep -q -- "-a3defc93 " $T/hosts/192.0.2.12/etc/systemd/system/rand-node.service'
cp $BIN/old/rand-node $T/hosts/192.0.2.12/usr/local/bin/rand-node
echo active > $T/hosts/192.0.2.102/state/rand-guardian
t "switch with a rand-guardian still active" 1 "some hosts are not ready" env "${NEWENV[@]}" "${LN[@]}" $F switch $G20
grep -q 'rand-guardian still active' $T/out.log && { echo "ok   — …that host names its active rand-guardian"; pass=$((pass+1)); } || { echo "FAIL — no guardian message"; fail=$((fail+1)); }
chk "…no marker, so start still refuses" '[ "$(nmark)" = 0 ]'
t "start after a failed switch" 1 "refusing" $F start
echo inactive > $T/hosts/192.0.2.102/state/rand-guardian
t "switch (re-run over the hosts already switched)" 0 "SWITCHED" env "${NEWENV[@]}" "${LN[@]}" $F switch $G20
NEW=$(cut -d' ' -f1 $T/markers/*); P=${NEW:0:8}
chk "one marker, named after the genesis prefix $P (= the hash the real binary derives)" '[ "$(nmark)" = 1 ] && [ -f $T/markers/chain20-switched-$P ] && [ "$NEW" = "$H20" ]'
chk "every host runs the v0.6.8 binaries and kept the v0.6.7 ones as *.pre-c20" '[ "$(installed rand-node)" = "26:$NEW_SHA " ] && [ "$(installed rand)" = "26:$NEW_SHA_WALLET " ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand-node.pre-c20; done | sort -u)" = "$OLD_SHA" ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand.pre-c20; done | sort -u)" = "$OLD_SHA_WALLET" ]'
chk "20 node units name -$P, none -a3defc93; each new datadir initialised" '[ "$(grep -l -- "-$P " $T/hosts/192.0.2.{1..20}/etc/systemd/system/rand-node.service | wc -l | tr -d " ")" = 20 ] && ! grep -q -- "-a3defc93 " $T/hosts/192.0.2.{1..20}/etc/systemd/system/rand-node.service && [ "$(ls -d $T/hosts/192.0.2.{1..20}/root/data-n*-$P/db | wc -l | tr -d " ")" = 20 ]'
chk "the two symlinked (archive) hosts got their chain-20 datadir on the volume" '[ -L $T/hosts/192.0.2.19/root/data-n19-$P ] && [ -d $T/hosts/192.0.2.19/mnt/volume/data-n19-$P/db ] && [ -d $T/hosts/192.0.2.20/mnt/volume/data-n20-$P/db ]'
chk "every node host kept a chain-19 unit backup; chain-19 datadirs untouched" '[ "$(ls $T/hosts/192.0.2.{1..20}/root/rand-node.service.a3defc93.bak | wc -l | tr -d " ")" = 20 ] && [ "$(ls -d $T/hosts/192.0.2.{1..18}/root/data-n*-a3defc93/db | wc -l | tr -d " ")" = 18 ]'
chk "6 guardian hosts: chain20.conf on data-20, chain19.conf moved aside, stamp = the genesis" '[ "$(grep -l -- "/data-20 " $T/hosts/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain20.conf | wc -l | tr -d " ")" = 6 ] && ! ls $T/hosts/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain19.conf >/dev/null 2>&1 && [ "$(ls $T/hosts/192.0.2.10{1..6}/root/chain19.conf.c19 | wc -l | tr -d " ")" = 6 ] && [ "$(cat $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-20.genesis | sort -u)" = "$NEW" ] && [ -d $T/hosts/192.0.2.106/var/lib/randnode/data-19/db ]'
t "start" 0 "START-DONE" $F start
chk "26 active, marker consumed" '[ "$(active)" = 26 ] && [ "$(nmark)" = 0 ]'
t "a second start" 1 "refusing" $F start
t "wait" 0 "CUTOVER DONE: all 26 on $NEW" env "${LN[@]}" $F wait $G20
# ── rollback ──
t "rollback while running" 1 "not back on chain 19" $F rollback
chk "…no rollback marker; still v0.6.8" '[ "$(nmark)" = 0 ] && [ "$(installed rand-node)" = "26:$NEW_SHA " ]'
t "stop (for the rollback)" 0 "STOPPED" $F stop
t "rollback" 0 "ROLLED BACK" $F rollback
chk "every unit / drop-in is byte-for-byte chain 19's again, and every binary is v0.6.7" '[ "$(units)" = "$U0" ] && [ "$(installed rand-node)" = "26:$OLD_SHA " ] && [ "$(installed rand)" = "26:$OLD_SHA_WALLET " ]'
t "start after rollback" 0 "START-DONE" $F start
t "wait for chain 20 after a rollback never completes (the fleet serves chain 19)" 1 "0/26 on chain 20" env "${LN[@]}" bash -c "$F wait $G20 | head -1; exit 1"
t "preflight after the rollback flags the leftovers (*.pre-c20, data-20)" 1 "not every host is ready" $F preflight
# ── a re-cut ──
t "stop again" 0 "STOPPED" $F stop
record "$H20B"
t "push of a RE-CUT genesis" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" $F push $G20B
t "switch to the re-cut genesis (guardian hosts still hold the first cut's data-20)" 0 "SWITCHED" env "${NEWENV[@]}" "${LN[@]}" $F switch $G20B
NEWB=$(cut -d' ' -f1 $T/markers/*)
chk "each guardian host moved the first cut's data-20 aside (kept) and initialised a fresh one" '[ "$(ls -d $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-20.stale-$P/db | wc -l | tr -d " ")" = 6 ] && [ "$(ls -d $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-20/db | wc -l | tr -d " ")" = 6 ] && [ "$(cat $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-20.genesis | sort -u)" = "$NEWB" ] && [ "$NEWB" != "$NEW" ]'
chk "…and the re-cut installed v0.6.8 again over the restored v0.6.7, keeping the one backup" '[ "$(installed rand-node)" = "26:$NEW_SHA " ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand-node.pre-c20; done | sort -u)" = "$OLD_SHA" ]'
t "start on the re-cut" 0 "START-DONE" $F start
t "wait on the re-cut" 0 "CUTOVER DONE" env "${LN[@]}" $F wait $G20B
t "wait for the FIRST cut's hash now fails" 1 "0/26 on chain 20" env "${LN[@]}" bash -c "$F wait $G20 | head -1; exit 1"
echo "fleet rehearsal: $pass passed, $fail failed"
[ $fail = 0 ]
