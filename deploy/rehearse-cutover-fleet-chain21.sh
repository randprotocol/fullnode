#!/usr/bin/env bash
# Rehearse deploy/cutover-fleet-chain21.sh end to end against 26 FAKE hosts — local directories
# behind a fake `ssh`/`scp`, addressed by TEST-NET-1 addresses (192.0.2.x, RFC 5737: unroutable).
# No network, no real host: the script under test is COPIED into a temp tree whose deploy/nodes.env
# names only the fake hosts and whose deploy/release-signers holds only a throwaway key made here;
# the fake `ssh`/`scp` refuse any host outside 192.0.2.0/24, the fake `curl` serves downloads only
# from a local directory for the made-up https://rehearsal.invalid/ base, and the run aborts unless
# the fakes are first on PATH.
#
#   NODE=<rand-node built from this tree> WALLET=<rand> deploy/rehearse-cutover-fleet-chain21.sh
#   SELFTEST=1 NODE=… WALLET=… deploy/cutover-fleet-chain21.sh        # the same
#
# DERIVED from deploy/rehearse-cutover-fleet-chain20.sh. The fleet starts on chain 20 on "v0.7.0"
# (what it really runs: 0.7.0, git_sha 806ed349 over rand_getVersion)
# (a wrapper that has no `keygen-msauth-vk`, as v0.7.0 has none) and is staged and switched to
# "v0.8.0" (a wrapper around $NODE: every call but --version goes to the real binary, so `init`
# really derives each chain-21 genesis hash on every fake host and `keygen-msauth-vk` really checks
# the committed blob crates/randprotocol-zkvm/keys/msauth-vk-production.bin against the pin
# compiled into $NODE). The release is SIGNED here: a SHA256SUMS over rand-node, rand and the blob,
# signed with a throwaway ssh key the temp tree's deploy/release-signers lists. Two dry-run chain-21
# genesis files are cut first (DRY_RUN=1 deploy/cut-chain21-genesis.sh with the REAL $NODE).
#
# What chain 21 adds to the cases: the signed sums are required (missing, tampered, a blob pin that
# is not the decided one); the blob is staged, refused on a byte mismatch, refused when the staged
# binary pins another key; the genesis must name hc_auth_multisig at the decided guest and limits;
# switch installs the blob after the staged binary verified it; start refuses the whole fleet when
# one host's installed blob is not verified; wait counts msauth_key "loaded"; a start after a
# rollback (v0.7.0) skips the key check. DRY_RUN prints and changes nothing.
#
# What it does NOT prove: the remote commands run under this machine's tools behind small shims
# (`systemctl`, `runuser`, `sha256sum`, `install -o`, GNU `sed -i`, the node's RPC, a download), not
# on a real Ubuntu host under systemd; the binaries are wrappers around a macOS build, not the
# v0.8.0 release; nothing here starts a real chain-21 node (the cut script's DRY_RUN loopback probe
# does that, with RAND_MSAUTH_VK).
set -uo pipefail
cd "$(dirname "$0")/.."
unset SELFTEST DRY_RUN   # reached as SELFTEST=1 deploy/cutover-fleet-chain21.sh: neither may leak into the scripts run below
NODE=${NODE:?a rand-node on this machine (built from this tree)}; WALLET=${WALLET:?the matching rand}
[ -x "$NODE" ] && [ -x "$WALLET" ] || { echo "rehearse: NODE / WALLET are not executable" >&2; exit 1; }
BLOB=$PWD/crates/randprotocol-zkvm/keys/msauth-vk-production.bin
TESTBLOB=$PWD/crates/randprotocol-zkvm/keys/msauth-vk-test.bin
[ -f "$BLOB" ] && [ -f "$TESTBLOB" ] || { echo "rehearse: the committed msauth blobs are missing" >&2; exit 1; }
"$NODE" keygen-msauth-vk --print-pinned production >/dev/null 2>&1 || { echo "rehearse: $NODE has no keygen-msauth-vk (not a v0.8.0-line build)" >&2; exit 1; }
BIN=$(mktemp -d); T=$(mktemp -d); trap 'rm -rf "$T" "$BIN"' EXIT
RN=$(cd "$(dirname "$NODE")" && pwd)/$(basename "$NODE"); RW=$(cd "$(dirname "$WALLET")" && pwd)/$(basename "$WALLET")
mkdir -p "$BIN/old" "$BIN/new" "$BIN/badrel" "$BIN/badvk" "$BIN/oldrel" "$T/repo/deploy/lib" "$T/shim" "$T/rshim" "$T/hosts" "$T/markers" "$T/key"
cat > "$BIN/old/rand-node" <<EOF
#!/usr/bin/env bash
# rehearsal wrapper: chain 20's build, "v0.7.0" (no keygen-msauth-vk, as v0.7.0 has none)
case "\${1:-}" in
  --version) echo "rand-node 0.7.0 (rehearsal wrapper: chain 20's build)"; exit 0;;
  keygen-msauth-vk) echo "error: unrecognized subcommand 'keygen-msauth-vk' (rehearsal wrapper: v0.7.0)" >&2; exit 2;;
esac
exec "$RN" "\$@"
EOF
cat > "$BIN/new/rand-node" <<EOF
#!/usr/bin/env bash
# rehearsal wrapper: chain 21's build, "v0.8.0". REHEARSE_PIN (rehearsal only) makes it pin another key.
case "\${1:-}" in --version) echo "rand-node 0.8.0 (rehearsal wrapper: chain 21's build)"; exit 0;; esac
if [ "\${1:-}" = keygen-msauth-vk ] && [ "\${2:-}" = --print-pinned ] && [ -n "\${REHEARSE_PIN:-}" ]; then echo "\$REHEARSE_PIN"; exit 0; fi
exec "$RN" "\$@"
EOF
printf '#!/usr/bin/env bash\n# rehearsal wrapper: chain 20 rand\nexec "%s" "$@"\n' "$RW" > "$BIN/old/rand"
printf '#!/usr/bin/env bash\n# rehearsal wrapper: chain 21 rand\nexec "%s" "$@"\n' "$RW" > "$BIN/new/rand"
cp "$BLOB" "$BIN/new/msauth-vk-production.bin"
cp "$BIN/new/rand" "$BIN/new/msauth-vk-production.bin" "$BIN/badrel/"; printf '#!/usr/bin/env bash\n# a tampered release\nexit 1\n' > "$BIN/badrel/rand-node"
cp "$BIN/new/rand-node" "$BIN/new/rand" "$BIN/badvk/"; cp "$TESTBLOB" "$BIN/badvk/msauth-vk-production.bin"   # right binaries, wrong blob bytes
chmod 755 "$BIN"/old/rand* "$BIN"/new/rand* "$BIN"/badrel/rand* "$BIN"/badvk/rand*
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
SRC=$PWD/deploy/cutover-fleet-chain21.sh; G20=$PWD/deploy/genesis-chain20.json
G21=$T/genesis-chain21.DRY-RUN.json; G21B=$T/genesis-chain21.DRY-RUN-B.json; G21X=$T/genesis-chain21.no-msauth.json
for g in "$G21" "$G21B"; do
  DRY_RUN=1 DRY_RUN_NO_PROBE=1 DRY_OUT=$g TREASURY=$T/no-treasury NODE=$RN WALLET=$RW deploy/cut-chain21-genesis.sh > "$T/dry.log" 2>&1 \
    || { echo "rehearse: the dry-run cut failed: $(tail -2 "$T/dry.log")" >&2; exit 1; }
done
python3 -c 'import json,sys; g=json.load(open(sys.argv[1])); g.pop("hc_auth_multisig"); json.dump(g, open(sys.argv[2],"w"), indent=1)' "$G21" "$G21X"
cp deploy/lib/cut-policy.sh deploy/lib/verify-release.sh "$T/repo/deploy/lib/"
cp deploy/cut-record.template "$T/repo/deploy/"
# ── the throwaway release key, and the signed SHA256SUMS of each fake release ─────────────────
ssh-keygen -q -t ed25519 -N '' -C rehearsal -f "$T/key/rel" >/dev/null
echo "rehearsal@randprotocol namespaces=\"rand-release\" $(cut -d' ' -f1,2 "$T/key/rel.pub")" > "$T/repo/deploy/release-signers"
sums() { (cd "$1" && shasum -a 256 rand-node rand msauth-vk-production.bin | sed 's/  / /') > "$2"; }
sign() { ssh-keygen -q -Y sign -n rand-release -f "$T/key/rel" "$1" >/dev/null 2>&1; }
sums "$BIN/new" "$T/SUMS"; sign "$T/SUMS"
# a signed file whose blob line is the test blob (the release workflow's self-check would refuse this)
sed "s/^$(sha "$BLOB") /$(sha "$TESTBLOB") /" "$T/SUMS" > "$T/SUMS-otherblob"; sign "$T/SUMS-otherblob"
cp "$T/SUMS" "$T/SUMS-tampered"; cp "$T/SUMS.sig" "$T/SUMS-tampered.sig"; echo "0000000000000000000000000000000000000000000000000000000000000000 extra" >> "$T/SUMS-tampered"
cp "$T/SUMS" "$T/SUMS-unsigned"
# v0.7.0's signed SHA256SUMS (rand-node, rand) — OLD_RELEASE_SUMS
(cd "$BIN/old" && shasum -a 256 rand-node rand | sed 's/  / /') > "$T/OLD-SUMS"; sign "$T/OLD-SUMS"

# ── the fake ssh / scp (the laptop side) ───────────────────────────────────────────────────────
cat > "$T/shim/ssh" <<'FAKE_SSH'
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
cat > "$T/shim/scp" <<'FAKE_SCP'
#!/usr/bin/env bash
srcs=(); dst=""
while [ $# -gt 0 ]; do case "$1" in -q) shift;; -o|-i) shift 2;; root@*) dst=$1; shift;; *) srcs+=("$1"); shift;; esac; done
host=${dst#root@}; path=${host#*:}; host=${host%%:*}
case "$host" in 192.0.2.*) ;; *) echo "FAKE scp: refusing $host" >&2; exit 255;; esac
cp "${srcs[@]}" "$FAKE_HOSTS/$host$path"
FAKE_SCP
# ── what a fake host's shell finds first on PATH (the host side) ───────────────────────────────
cat > "$T/rshim/systemctl" <<'FAKE_SYSTEMCTL'
#!/usr/bin/env bash
st=$FAKE_ROOT/state; mkdir -p $st
case "$1" in
  is-active) q=0; [ "$2" = --quiet ] && { q=1; shift; }; s=$(cat $st/$2 2>/dev/null || echo inactive); [ $q = 1 ] || echo $s; [ "$s" = active ];;
  stop) echo inactive > $st/$2;;
  start) [ -e $st/refuse-start ] || echo active > $st/$2;;   # refuse-start: the rehearsal's host that will not come up
  daemon-reload) :;;
  cat) cat $FAKE_ROOT/etc/systemd/system/$2.service $FAKE_ROOT/etc/systemd/system/$2.service.d/*.conf 2>/dev/null;;
  *) echo "fake systemctl: $*" >&2; exit 1;;
esac
FAKE_SYSTEMCTL
printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' > "$T/rshim/sha256sum"
printf '#!/usr/bin/env bash\ncat $FAKE_ROOT/hostname\n' > "$T/rshim/hostname"
printf '#!/usr/bin/env bash\n# runuser -u randnode -- cmd...\nshift 3; exec "$@"\n' > "$T/rshim/runuser"
cat > "$T/rshim/install" <<'FAKE_INSTALL'
#!/usr/bin/env bash
a=(); while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2;; *) a+=("$1"); shift;; esac; done
exec /usr/bin/install "${a[@]}"
FAKE_INSTALL
cat > "$T/rshim/sed" <<'FAKE_SED'
#!/usr/bin/env bash
if [ "$1" = -i ]; then shift; exec /usr/bin/sed -i '' "$@"; fi
exec /usr/bin/sed "$@"
FAKE_SED
cat > "$T/rshim/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
# FAKE curl. A download (-o FILE URL) is served from $FAKE_RELEASE_DIR for https://rehearsal.invalid/
# only. Otherwise the node RPC on 127.0.0.1:8545: it answers only while rand-node is "active", for
# the chain of the datadir the unit / drop-in names (chain 20's hash for the old datadir; for any
# other, the hash the INSTALLED binary derives from the chain-21 genesis file the host holds).
# rand_status.msauth_key is "loaded" when the installed binary verifies the installed blob.
out=""; url=""; prev=""
for a in "$@"; do [ "$prev" = -o ] && out=$a; case "$a" in https://*) url=$a;; esac; prev=$a; done
if [ -n "$out" ]; then
  case "$url" in https://rehearsal.invalid/*) ;; *) echo "FAKE curl: refusing $url" >&2; exit 22;; esac
  f=${url%%\?*}; f=${f##*/}; [ -f "$FAKE_RELEASE_DIR/$f" ] || exit 22
  cp "$FAKE_RELEASE_DIR/$f" "$out"; exit 0
fi
[ "$(cat $FAKE_ROOT/state/rand-node 2>/dev/null)" = active ] || exit 7
body="$*"
dd=$(cat $FAKE_ROOT/etc/systemd/system/rand-node.service $FAKE_ROOT/etc/systemd/system/rand-node.service.d/*.conf 2>/dev/null | grep -o -- '--datadir [^ ]*' | tail -1 | cut -d' ' -f2)
B=$FAKE_ROOT/usr/local/bin
case "$body" in
  *rand_getGenesisHash*)
    case "$dd" in
      *-6210cf07|*/data-20) h=6210cf071a390d7ac61d8cbea5dd9d139d1a493a862b54a45a498f36af2d5135;;
      *) [ -d "$dd/db" ] || exit 7; t=$(mktemp -d); h=$($B/rand-node init --datadir $t/p --genesis $FAKE_ROOT/root/genesis-chain21.json | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2); rm -rf $t;;
    esac
    [ "${REHEARSE_SERVE_OLD:-}" = "$FAKE_HOST" ] && h=6210cf071a390d7ac61d8cbea5dd9d139d1a493a862b54a45a498f36af2d5135
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"$h\"}";;
  *rand_getHealth*) echo '{"id":1,"jsonrpc":"2.0","result":{"status":"ok"}}';;
  *rand_getBridgeState*)
    python3 - "$FAKE_ROOT/root/genesis-chain21.json" "${REHEARSE_MINTED:-0}" <<'PY'
import json, sys
g = json.load(open(sys.argv[1])); b = g["bridge"]
assets = [{"locked": str(k.get("locked", 0))} for t in g["tokens"]["tokens"] for k in t["backings"]]
assets[0]["locked"] = str(int(assets[0]["locked"]) + int(sys.argv[2]))
print(json.dumps({"id": 1, "jsonrpc": "2.0", "result": {"enabled": True, "burn_sequence": b["burn_sequence"], "assets": assets}}))
PY
    ;;
  *rand_status*)
    n=$(( $(cat $FAKE_ROOT/state/height 2>/dev/null || echo 4) + 1 )); echo $n > $FAKE_ROOT/state/height
    k=absent; g=$($B/rand-node keygen-msauth-vk --check $B/msauth-vk-production.bin 2>/dev/null); p=$($B/rand-node keygen-msauth-vk --print-pinned production 2>/dev/null)
    [ -n "$g" ] && [ "$g" = "$p" ] && k=loaded
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"height\":$n,\"view\":6,\"msauth_key\":\"$k\"}}";;
  *rand_getVersion*)
    # what the INSTALLED build reports: v0.7.0 = tag 806ed349 (REHEARSE_V071_HOST: that host answers as
    # the never-rolled v0.7.1, a build whose binary sha the rehearsal does not model)
    case "$($B/rand-node --version 2>/dev/null)" in
      "rand-node 0.7.0"*) v=0.7.0; gs=806ed349e52a25045455f3e4a84bdb941daddc60;;
      *) v=0.8.0; gs=fake;;
    esac
    [ "${REHEARSE_V071_HOST:-}" = "$FAKE_HOST" ] && { v=0.7.1; gs=0000000000000000000000000000000000000071; }
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"chain_id\":20,\"git_sha\":\"$gs\",\"version\":\"$v\"}}";;
esac
FAKE_CURL
# ── the 26 fake hosts, on chain 20, on the "v0.7.0" wrapper ────────────────────────────────────
cat > "$T/mkfleet.sh" <<'MKFLEET'
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
  dd=$R/root/data-n$n-6210cf07
  if [ $n -ge 19 ]; then mkdir -p $R/mnt/volume/data-n$n-6210cf07/db; ln -s $R/mnt/volume/data-n$n-6210cf07 $dd; else mkdir -p $dd/db; fi
  printf '[Service]\nExecStart=%s run --datadir %s --key %s/root/keys/node.key.json --validator\n' "$R/usr/local/bin/rand-node" "$dd" "$R" > $R/etc/systemd/system/rand-node.service
done
for i in $(seq 1 6); do
  ip=192.0.2.10$i; mk $ip rand-guardian-$i; R=$H/$ip
  echo "$i $ip" >> $T/guardian-hosts.txt
  mkdir -p $R/etc/systemd/system/rand-node.service.d $R/var/lib/randnode/data-20/db
  printf '[Service]\nUser=randnode\n' > $R/etc/systemd/system/rand-node.service
  printf '[Service]\nExecStart=\nExecStart=%s run --datadir %s --key %s --validator\n' "$R/usr/local/bin/rand-node" "$R/var/lib/randnode/data-20" "$R/var/lib/randnode/node.key.json" > $R/etc/systemd/system/rand-node.service.d/chain20.conf
  echo inactive > $R/state/rand-guardian
done
MKFLEET
chmod +x "$T"/shim/* "$T"/rshim/* "$T/mkfleet.sh"
cp "$SRC" "$T/repo/deploy/cutover-fleet-chain21.sh"
mkdir -p "$T/repo/deploy/cut-records"
"$T/mkfleet.sh" "$T" "$BIN/old"
export PATH="$T/shim:$PATH" FAKE_HOSTS=$T/hosts FAKE_RSHIM=$T/rshim FAKE_RELEASE_DIR=$BIN/new
[ "$(command -v ssh)" = "$T/shim/ssh" ] && [ "$(command -v scp)" = "$T/shim/scp" ] || { echo "rehearse: the fake ssh/scp are not first on PATH — abort" >&2; exit 99; }
! grep -oE '/ip4/[0-9.]+' "$T/repo/deploy/nodes.env" | grep -qv '^/ip4/192\.0\.2\.' || { echo "rehearse: the fake nodes.env names a non-TEST-NET host — abort" >&2; exit 99; }
OLD_SHA=$(sha "$BIN/old/rand-node"); OLD_SHA_WALLET=$(sha "$BIN/old/rand")
NEW_SHA=$(sha "$BIN/new/rand-node"); NEW_SHA_WALLET=$(sha "$BIN/new/rand"); VK_SHA=$(sha "$BLOB")
export GUARDIAN_HOSTS=$T/guardian-hosts.txt BOOTS="192.0.2.3 192.0.2.4" MARKER_GLOB=$T/markers/chain21-switched- WAIT_SLEEP=0 \
  RELEASE_URL=https://rehearsal.invalid/v0.8.0 CUT_RECORD=$T/cut-record.txt
unset RELEASE_SUMS RELEASE_SUMS_SIG OLD_RELEASE_SUMS OLD_SHA_ENV WANT_SHA WANT_SHA_WALLET WANT_SHA_VK DRY_RUN SELFTEST
NEWENV=(RELEASE_SUMS=$T/SUMS)
OLDENV=(OLD_RELEASE_SUMS=$T/OLD-SUMS)
LN=(LOCAL_NODE=$BIN/new/rand-node)
F=$T/repo/deploy/cutover-fleet-chain21.sh
hash_of() { local d; d=$(mktemp -d); "$RN" init --datadir "$d/p" --genesis "$1" | grep -o 'genesis [0-9a-f]*' | cut -d' ' -f2; rm -rf "$d"; }
H21=$(hash_of "$G21"); H21B=$(hash_of "$G21B")
record() { sed -e 's/<[^>]*>/filled (rehearsal)/' "$PWD/deploy/cut-record.template" | sed "s/^second-hash:.*/second-hash: $1/" > "$CUT_RECORD"; }
pass=0; fail=0
t() { # <description> <want rc: 0|!0> <grep phrase in output> cmd…
  local what=$1 want=$2 phrase=$3; shift 3
  "$@" > "$T/out.log" 2>&1; local rc=$?
  if { [ "$want" = 0 ] && [ $rc = 0 ]; } || { [ "$want" != 0 ] && [ $rc != 0 ]; }; then
    if grep -qF -- "$phrase" "$T/out.log"; then echo "ok   — $what (rc $rc): $(grep -F -- "$phrase" "$T/out.log" | tail -1 | cut -c1-150)"; pass=$((pass+1))
    else echo "FAIL — $what: rc $rc as wanted but no \"$phrase\": $(tail -2 "$T/out.log" | cut -c1-200)"; fail=$((fail+1)); fi
  else echo "FAIL — $what: rc $rc, wanted $want: $(tail -3 "$T/out.log" | cut -c1-300)"; fail=$((fail+1)); fi
}
chk() { if eval "$2"; then echo "ok   — $1"; pass=$((pass+1)); else echo "FAIL — $1"; fail=$((fail+1)); fi; }
has() { if grep -qF -- "$2" "$T/out.log"; then echo "ok   — $1"; pass=$((pass+1)); else echo "FAIL — $1: no \"$2\""; fail=$((fail+1)); fi; }
nmark() { ls "$T/markers" | wc -l | tr -d ' '; }
units() { for h in "$T"/hosts/*; do cat $h/etc/systemd/system/rand-node.service $h/etc/systemd/system/rand-node.service.d/*.conf 2>/dev/null; done | shasum | cut -c1-16; }
tree() { find "$T/hosts" -type f -o -type l | sort | shasum | cut -c1-16; }
active() { grep -l '^active$' "$T"/hosts/*/state/rand-node 2>/dev/null | wc -l | tr -d ' '; }
installed() { for h in "$T"/hosts/*; do if [ -f $h/usr/local/bin/$1 ]; then sha $h/usr/local/bin/$1; else echo none; fi; done | sort | uniq -c | awk '{print $1":"$2}' | tr '\n' ' '; }
staged() { ls "$T"/hosts/*/root/rand-node.c21 2>/dev/null | wc -l | tr -d ' '; }
U0=$(units)

# ── DRY_RUN: prints, touches nothing ──
TR0=$(tree)
for ph in preflight stage status halt; do
  t "DRY_RUN=1 $ph with no inputs prints and touches nothing" 0 "[dry-run]" env DRY_RUN=1 $F $ph
done
t "DRY_RUN=1 push with every input prints the push" 0 "[dry-run] scp" env DRY_RUN=1 "${NEWENV[@]}" "${LN[@]}" $F push $G21
t "DRY_RUN=1 stop prints its gate" 0 "stop gate" env DRY_RUN=1 "${NEWENV[@]}" "${LN[@]}" $F stop $G21
t "DRY_RUN=1 switch prints the msauth key check" 0 "keygen-msauth-vk --check" env DRY_RUN=1 "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21
t "DRY_RUN=1 start prints the key gate" 0 "msauth key on every host" env DRY_RUN=1 $F start
t "DRY_RUN=1 quiet" 0 "rand_getBridgeState" env DRY_RUN=1 $F quiet $G21
t "DRY_RUN=1 quiet with no genesis file does not crash" 0 "is not a file" env DRY_RUN=1 $F quiet $T/no-such-genesis.json
t "DRY_RUN=1 rollback" 0 "[dry-run]" env DRY_RUN=1 "${OLDENV[@]}" $F rollback
t "DRY_RUN=1 wait" 0 "msauth_key loaded" env DRY_RUN=1 "${LN[@]}" $F wait $G21
t "DRY_RUN=1 wait20" 0 "serves genesis 6210cf07" env DRY_RUN=1 $F wait20
chk "…the dry runs changed no host, wrote no marker, no record" '[ "$(tree)" = "$TR0" ] && [ "$(active)" = 26 ] && [ "$(nmark)" = 0 ] && [ ! -e $CUT_RECORD ]'
# ── input hygiene (M1, M4) ──
cp "$GUARDIAN_HOSTS" "$T/gh.keep"; sed -i '' 's/^3 .*/3 192.0.2.103;touch/' "$GUARDIAN_HOSTS"
t "a guardian host that is not an IPv4 address is refused" 1 "is not an IPv4 address" $F status
cp "$T/gh.keep" "$GUARDIAN_HOSTS"
t "a WANT_VERSION with a quote and ';' is refused" 1 "shell metacharacter" env "WANT_VERSION=0.8.0'; touch /tmp/x" $F status
t "a STAGE_URL with a space is refused" 1 "shell metacharacter" env "STAGE_URL=https://rehearsal.invalid/a b" $F status
t "NEED_FLAGS with a non-flag word is refused" 1 "is not a --flag" env "NEED_FLAGS=--fees ;id" $F status

# ── preflight ──
t "preflight without v0.7.0's pins" 1 "OLD_SHA / OLD_SHA_WALLET" $F preflight
t "preflight on a healthy chain-20 fleet (v0.7.0, git_sha 806ed349 over RPC)" 0 "PREFLIGHT OK" env "${OLDENV[@]}" $F preflight
chk "preflight changed nothing" '[ "$(units)" = "$U0" ] && [ "$(active)" = 26 ] && [ "$(nmark)" = 0 ]'
cp "$BIN/new/rand-node" "$T/hosts/192.0.2.7/usr/local/bin/rand-node"
t "preflight with one host on another rand-node" 1 "not every host is ready" env "${OLDENV[@]}" $F preflight
has "…and names the host's binary" "not chain 20's v0.7.0"
cp "$BIN/old/rand-node" "$T/hosts/192.0.2.7/usr/local/bin/rand-node"
t "preflight with one node answering rand_getVersion as another build" 1 "not every host is ready" env "${OLDENV[@]}" REHEARSE_V071_HOST=192.0.2.8 $F preflight
has "…and names what it answers" "not 0.7.0 / 806ed349"
mkdir -p "$T/hosts/192.0.2.103/var/lib/randnode/data-21"
t "preflight with a stale data-21 on a guardian host" 1 "not every host is ready" env "${OLDENV[@]}" $F preflight
rmdir "$T/hosts/192.0.2.103/var/lib/randnode/data-21"
touch "$T/hosts/192.0.2.9/root/rand.pre-c21"
t "preflight with a leftover *.pre-c21" 1 "not every host is ready" env "${OLDENV[@]}" $F preflight
rm "$T/hosts/192.0.2.9/root/rand.pre-c21"
t "halt while chain 20 runs is refused (only stop <genesis> takes chain 20 down)" 1 "RUNS CHAIN 20" $F halt
chk "…nothing halted" '[ "$(active)" = 26 ]'
# ── stage ──
t "stage without RELEASE_SUMS" 1 "RELEASE_SUMS is unset" $F stage
t "stage with an unsigned SHA256SUMS" 1 "signature does not verify" env RELEASE_SUMS=$T/SUMS-unsigned $F stage
t "stage with a SHA256SUMS changed after signing" 1 "signature does not verify" env RELEASE_SUMS=$T/SUMS-tampered $F stage
t "stage with a signed SHA256SUMS whose blob is not the decided one" 1 "not the decided blob" env RELEASE_SUMS=$T/SUMS-otherblob $F stage
t "stage with a WANT_SHA that disagrees with the signed file" 1 "is not what the signed SHA256SUMS lists" env "${NEWENV[@]}" WANT_SHA=$OLD_SHA $F stage
t "stage from a path holding a non-ELF build" 1 "not a Linux ELF" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR=$BIN/new $F stage
t "stage from a path whose blob is not the signed one" 1 "not the signed blob" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR=$BIN/badvk STAGE_ALLOW_NON_ELF=1 $F stage
chk "…nothing copied" '[ "$(staged)" = 0 ] && ! ls $T/hosts/*/root/*.part >/dev/null 2>&1'
t "stage from a release whose rand-node does not match" 1 "not every host staged" env "${NEWENV[@]}" FAKE_RELEASE_DIR=$BIN/badrel $F stage
has "…each host said SHA MISMATCH and removed it" "SHA MISMATCH — removed"
t "stage from a release whose blob bytes do not match" 1 "not every host staged" env "${NEWENV[@]}" FAKE_RELEASE_DIR=$BIN/badvk $F stage
chk "…no staged or partial file left anywhere" '[ "$(staged)" = 0 ] && ! ls $T/hosts/*/root/*.part $T/hosts/*/root/msauth-vk-production.bin.c21 >/dev/null 2>&1'
t "stage with a staged binary that pins another key" 1 "not every host staged" env "${NEWENV[@]}" REHEARSE_PIN="$(sha "$TESTBLOB")" $F stage
has "…the host says the key is not verified" "msauth key NOT verified"
t "stage from url without STAGE_URL" 1 "needs STAGE_URL" env "${NEWENV[@]}" STAGE_FROM=url $F stage
t "stage from a plain-http url" 1 "is not https://" env "${NEWENV[@]}" STAGE_FROM=url STAGE_URL=http://rehearsal.invalid/x $F stage
t "stage from the release" 0 "STAGED" env "${NEWENV[@]}" $F stage
has "…each host verified the staged key with the staged binary" "msauth key ${VK_SHA:0:12}… verified"
chk "26 hosts hold rand-node.c21 / rand.c21 / the blob at the pins; installed still v0.7.0; 26 still active" '[ "$(staged)" = 26 ] && [ "$(installed rand-node)" = "26:$OLD_SHA " ] && [ "$(active)" = 26 ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand-node.c21; sha $h/root/rand.c21; sha $h/root/msauth-vk-production.bin.c21; done | sort -u | tr "\n" " ")" = "$(printf "%s\n%s\n%s\n" $NEW_SHA $NEW_SHA_WALLET $VK_SHA | sort | tr "\n" " ")" ]'
t "stage again from a private url (token kept out of the log)" 0 "STAGED" env "${NEWENV[@]}" STAGE_FROM=url "STAGE_URL=https://rehearsal.invalid/private/v080?token=SECRET123" $F stage
! grep -q SECRET123 "$T/out.log" && { echo "ok   — …the url's token is not in the output"; pass=$((pass+1)); } || { echo "FAIL — the token was printed"; fail=$((fail+1)); }
t "stage again from a local path (STAGE_ALLOW_NON_ELF=1: the rehearsal's wrappers are scripts)" 0 "STAGED" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR=$BIN/new STAGE_ALLOW_NON_ELF=1 $F stage
# ── push, with chain 20 still running ──
t "push without LOCAL_NODE" 1 "LOCAL_NODE is unset" env "${NEWENV[@]}" $F push $G21
t "push with chain 20's v0.7.0 as LOCAL_NODE" 1 "nothing done" env "${NEWENV[@]}" LOCAL_NODE=$BIN/old/rand-node $F push $G21
t "push without RELEASE_SUMS" 1 "RELEASE_SUMS is unset" env "${LN[@]}" $F push $G21
t "push of chain 20's genesis" 1 "has chain_id 20, not 21" env "${NEWENV[@]}" "${LN[@]}" $F push $G20
t "push of a chain-21 genesis without hc_auth_multisig" 1 "has hc_auth_multisig None" env "${NEWENV[@]}" "${LN[@]}" $F push $G21X
t "push with no cut record" 1 "no cut record" env "${NEWENV[@]}" "${LN[@]}" $F push $G21
record ""
t "push with a record whose second-hash is empty (as the cut leaves it)" 1 "no 'second-hash:' line" env "${NEWENV[@]}" "${LN[@]}" $F push $G21
record "$H21B"
t "push with the second operator's hash differing" 1 "differ" env "${NEWENV[@]}" "${LN[@]}" $F push $G21
chk "…nothing copied" '! ls $T/hosts/*/root/genesis-chain21.json >/dev/null 2>&1'
record "$H21"
t "start with no marker" 1 "no $MARKER_GLOB<prefix> marker" $F start
t "stop with no genesis argument" 1 "stop <genesis file>" $F stop
t "stop before push: refused, nothing stopped" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21
chk "…all 26 still active on chain 20" '[ "$(active)" = 26 ] && [ "$(units)" = "$U0" ]'
t "push of the chain-21 genesis while chain 20 runs" 0 "PUSHED — chain 20 still runs" env "${NEWENV[@]}" "${LN[@]}" $F push $G21
chk "26 hosts hold the genesis, byte-identical; all 26 still active" '[ "$(shasum $T/hosts/*/root/genesis-chain21.json | cut -d" " -f1 | sort -u | wc -l | tr -d " ")" = 1 ] && [ "$(ls $T/hosts/*/root/genesis-chain21.json | wc -l | tr -d " ")" = 26 ] && [ "$(active)" = 26 ]'
t "switch while the fleet still runs" 1 "some hosts are not ready" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21
chk "…switched nothing, installed nothing, no marker" '[ "$(units)" = "$U0" ] && [ "$(installed rand-node)" = "26:$OLD_SHA " ] && [ "$(installed msauth-vk-production.bin)" = "26:none " ] && [ "$(nmark)" = 0 ]'
# ── the gated stop ──
mv "$T/hosts/192.0.2.14/root/genesis-chain21.json" "$T/g.aside"
t "stop when one host lacks the pushed genesis" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21
has "…that host says the genesis is not pushed" "the chain-21 genesis is not pushed here"
chk "…all 26 still active" '[ "$(active)" = 26 ]'
mv "$T/g.aside" "$T/hosts/192.0.2.14/root/genesis-chain21.json"
cp "$TESTBLOB" "$T/hosts/192.0.2.16/root/msauth-vk-production.bin.c21"
t "stop when one host's staged blob changed since stage" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21
chk "…all 26 still active" '[ "$(active)" = 26 ]'
cp "$BLOB" "$T/hosts/192.0.2.16/root/msauth-vk-production.bin.c21"
record "$H21B"
t "stop when the record's second-hash is another genesis's" 1 "differ" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21
chk "…all 26 still active" '[ "$(active)" = 26 ]'
record "$H21"
t "stop without v0.7.0's pins" 1 "OLD_SHA / OLD_SHA_WALLET" env "${NEWENV[@]}" "${LN[@]}" $F stop $G21
chk "…all 26 still active" '[ "$(active)" = 26 ]'
echo active > "$T/hosts/192.0.2.104/state/rand-guardian"
t "stop while one guardian host's rand-guardian still runs" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21
has "…that host names its rand-guardian" "rand-guardian still active"
chk "…all 26 still active" '[ "$(active)" = 26 ]'
echo inactive > "$T/hosts/192.0.2.104/state/rand-guardian"
cp "$BIN/badrel/rand-node" "$T/hosts/192.0.2.13/usr/local/bin/rand-node"
t "stop while one host's installed rand-node is not v0.7.0" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21
has "…that host names its binary" "switch would refuse it"
cp "$BIN/old/rand-node" "$T/hosts/192.0.2.13/usr/local/bin/rand-node"
t "stop (gated: all 26 ready)" 0 "STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21
chk "all 26 inactive" '[ "$(active)" = 0 ]'
# ── switch ──
record ""
t "switch with the record's second-hash blanked after push (M3)" 1 "no 'second-hash:' line" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21
record "$H21"
t "switch without v0.7.0's pins" 1 "OLD_SHA / OLD_SHA_WALLET" env "${NEWENV[@]}" "${LN[@]}" $F switch $G21
# the first switch attempt: every other host switches in it — a failed switch is re-run, never undone
cp "$TESTBLOB" "$T/hosts/192.0.2.5/root/msauth-vk-production.bin.c21"
cp "$BIN/badrel/rand-node" "$T/hosts/192.0.2.12/usr/local/bin/rand-node"
t "switch with host 5's staged blob replaced and host 12 not on v0.7.0" 1 "rollback → start → wait20, then restart the bridge on chain 20" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21
has "…host 5 says its staged blob is not the pinned one (sha256, before the key check)" "files are not staged"
has "…host 12 made no backup" "no backup made"
chk "…host 5 installed nothing: still v0.7.0, no key, unit on chain 20; no marker" '[ "$(sha $T/hosts/192.0.2.5/usr/local/bin/rand-node)" = "$OLD_SHA" ] && [ ! -e $T/hosts/192.0.2.5/usr/local/bin/msauth-vk-production.bin ] && grep -q -- "-6210cf07 " $T/hosts/192.0.2.5/etc/systemd/system/rand-node.service && [ "$(nmark)" = 0 ]'
chk "…host 12's unit still names chain 20, no .pre-c21 there" '[ ! -e $T/hosts/192.0.2.12/root/rand-node.pre-c21 ] && grep -q -- "-6210cf07 " $T/hosts/192.0.2.12/etc/systemd/system/rand-node.service'
cp "$BLOB" "$T/hosts/192.0.2.5/root/msauth-vk-production.bin.c21"
cp "$BIN/old/rand-node" "$T/hosts/192.0.2.12/usr/local/bin/rand-node"
t "switch with the staged binary pinning another key (every host re-checks before anything)" 1 "some hosts are not ready" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" REHEARSE_PIN="$(sha "$TESTBLOB")" $F switch $G21
has "…the hosts say the key is not verified" "msauth key NOT verified"
chk "…host 5 still installed nothing" '[ "$(sha $T/hosts/192.0.2.5/usr/local/bin/rand-node)" = "$OLD_SHA" ] && [ "$(nmark)" = 0 ]'
echo active > "$T/hosts/192.0.2.102/state/rand-guardian"
t "switch with a rand-guardian still active" 1 "some hosts are not ready" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21
has "…that host names its active rand-guardian" "rand-guardian still active"
chk "…no marker, so start still refuses" '[ "$(nmark)" = 0 ]'
t "start after a failed switch" 1 "refusing" $F start
echo inactive > "$T/hosts/192.0.2.102/state/rand-guardian"
t "switch (re-run over the hosts already switched)" 0 "SWITCHED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21
NEW=$(cut -d' ' -f1 "$T"/markers/*); P=${NEW:0:8}
chk "one marker, named after the genesis prefix $P (= the hash the real binary derives)" '[ "$(nmark)" = 1 ] && [ -f $T/markers/chain21-switched-$P ] && [ "$NEW" = "$H21" ]'
chk "every host runs the v0.8.0 binaries + the decided key, and kept the v0.7.0 ones as *.pre-c21" '[ "$(installed rand-node)" = "26:$NEW_SHA " ] && [ "$(installed rand)" = "26:$NEW_SHA_WALLET " ] && [ "$(installed msauth-vk-production.bin)" = "26:$VK_SHA " ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand-node.pre-c21; done | sort -u)" = "$OLD_SHA" ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand.pre-c21; done | sort -u)" = "$OLD_SHA_WALLET" ]'
chk "20 node units name -$P, none -6210cf07; each new datadir initialised" '[ "$(grep -l -- "-$P " $T/hosts/192.0.2.{1..20}/etc/systemd/system/rand-node.service | wc -l | tr -d " ")" = 20 ] && ! grep -q -- "-6210cf07 " $T/hosts/192.0.2.{1..20}/etc/systemd/system/rand-node.service && [ "$(ls -d $T/hosts/192.0.2.{1..20}/root/data-n*-$P/db | wc -l | tr -d " ")" = 20 ]'
chk "the two symlinked (archive) hosts got their chain-21 datadir on the volume" '[ -L $T/hosts/192.0.2.19/root/data-n19-$P ] && [ -d $T/hosts/192.0.2.19/mnt/volume/data-n19-$P/db ] && [ -d $T/hosts/192.0.2.20/mnt/volume/data-n20-$P/db ]'
chk "every node host kept a chain-20 unit backup; chain-20 datadirs untouched" '[ "$(ls $T/hosts/192.0.2.{1..20}/root/rand-node.service.6210cf07.bak | wc -l | tr -d " ")" = 20 ] && [ "$(ls -d $T/hosts/192.0.2.{1..18}/root/data-n*-6210cf07/db | wc -l | tr -d " ")" = 18 ]'
chk "6 guardian hosts: chain21.conf on data-21, chain20.conf moved aside, stamp = the genesis" '[ "$(grep -l -- "/data-21 " $T/hosts/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain21.conf | wc -l | tr -d " ")" = 6 ] && ! ls $T/hosts/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain20.conf >/dev/null 2>&1 && [ "$(ls $T/hosts/192.0.2.10{1..6}/root/chain20.conf.c20 | wc -l | tr -d " ")" = 6 ] && [ "$(cat $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-21.genesis | sort -u)" = "$NEW" ] && [ -d $T/hosts/192.0.2.106/var/lib/randnode/data-20/db ]'
# ── start ──
cp "$TESTBLOB" "$T/hosts/192.0.2.15/usr/local/bin/msauth-vk-production.bin"
t "start with one host's installed key not verified" 1 "nothing started" $F start
chk "…no node started anywhere, the marker kept" '[ "$(active)" = 0 ] && [ "$(nmark)" = 1 ]'
cp "$BLOB" "$T/hosts/192.0.2.15/usr/local/bin/msauth-vk-production.bin"
touch "$T/hosts/192.0.2.11/state/refuse-start"
t "start with one host that does not come up (I3)" 1 "NOT STARTED on: 192.0.2.11" $F start
chk "…25 active, the marker KEPT" '[ "$(active)" = 25 ] && [ "$(nmark)" = 1 ]'
rm "$T/hosts/192.0.2.11/state/refuse-start"
t "start again once that host is fixed" 0 "START-DONE" $F start
has "…every host's key verified before the start" "msauth key ${VK_SHA:0:12}… verified"
chk "26 active, marker consumed" '[ "$(active)" = 26 ] && [ "$(nmark)" = 0 ]'
t "a second start" 1 "refusing" $F start
t "wait" 0 "CUTOVER DONE: all 26 on $NEW" env "${LN[@]}" $F wait $G21
echo inactive > "$T/hosts/192.0.2.17/state/rand-node"
t "wait with one node that does not answer yet (I1: a laggard, not a silent exit)" 1 "25/26 on chain 21" env "${LN[@]}" bash -c "$F wait $G21 | head -1; exit 1"
has "…and names it" "not yet: 192.0.2.17"
echo active > "$T/hosts/192.0.2.17/state/rand-node"
mv "$T/hosts/192.0.2.8/usr/local/bin/msauth-vk-production.bin" "$T/vk.aside"
t "wait with one node's key gone (msauth_key absent)" 1 "25/26 on chain 21" env "${LN[@]}" bash -c "$F wait $G21 | head -1; exit 1"
mv "$T/vk.aside" "$T/hosts/192.0.2.8/usr/local/bin/msauth-vk-production.bin"
echo inactive > "$T/hosts/192.0.2.18/state/rand-node"
t "status with one node not answering prints its line" 0 "no answer" $F status
echo active > "$T/hosts/192.0.2.18/state/rand-node"
# ── before a rollback, with chain 21 up: has anything bridge-side happened? ──
t "quiet: nothing burned or minted on chain 21" 0 "QUIET" $F quiet $G21
t "quiet when a deposit was minted on chain 21" 1 "NOT the genesis values" env REHEARSE_MINTED=5 $F quiet $G21
# ── a re-cut over a switched fleet, without a rollback, is refused (M2) ──
cp "$T/hosts/192.0.2.13/etc/systemd/system/rand-node.service" "$T/unit.keep"
sed -i '' 's/--datadir [^ ]*//' "$T/hosts/192.0.2.13/etc/systemd/system/rand-node.service"
t "halt with an active host whose datadir cannot be parsed" 1 "names no --datadir" $F halt
cp "$T/unit.keep" "$T/hosts/192.0.2.13/etc/systemd/system/rand-node.service"
t "halt with an active host that serves chain 20's genesis over RPC" 1 "SERVES CHAIN 20" env REHEARSE_SERVE_OLD=192.0.2.9 $F halt
chk "…nothing halted" '[ "$(active)" = 26 ]'
t "halt the chain-21 fleet" 0 "HALTED" $F halt
record "$H21B"
t "push of a re-cut while chain 21 is down" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" $F push $G21B
UB=$(units)
t "switch to a re-cut over the switched fleet (no rollback)" 1 "needs rollback first" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21B
chk "…no host changed its unit, no marker" '[ "$(units)" = "$UB" ] && [ "$(nmark)" = 0 ]'
# ── rollback (bridge stopped first, in the runbook) ──
t "rollback" 0 "ROLLED BACK" env "${OLDENV[@]}" $F rollback
chk "every unit / drop-in is byte-for-byte chain 20's again, and every binary is v0.7.0" '[ "$(units)" = "$U0" ] && [ "$(installed rand-node)" = "26:$OLD_SHA " ] && [ "$(installed rand)" = "26:$OLD_SHA_WALLET " ]'
t "start after rollback (v0.7.0: no msauth key check)" 0 "START-DONE" $F start
! grep -q "msauth key on every host" "$T/out.log" && { echo "ok   — …the key gate was skipped for the rollback"; pass=$((pass+1)); } || { echo "FAIL — the key gate ran on a rollback start"; fail=$((fail+1)); }
t "wait20: chain 20 serves on all 26 and C's height moves" 0 "CHAIN 20 COMMITTING AGAIN" $F wait20
t "rollback while running" 1 "not back on chain 20" env "${OLDENV[@]}" $F rollback
t "wait for chain 21 after a rollback never completes (the fleet serves chain 20)" 1 "0/26 on chain 21" env "${LN[@]}" bash -c "$F wait $G21 | head -1; exit 1"
t "preflight after the rollback flags the leftovers (*.pre-c21, data-21)" 1 "not every host is ready" env "${OLDENV[@]}" $F preflight
# ── the re-cut, in the right order: push (chain 20 running), stop, switch ──
record "$H21"   # the second-hash names the FIRST cut
t "push of a re-cut genesis whose second-hash is another cut's, no waiver" 1 "differ" env "${NEWENV[@]}" "${LN[@]}" $F push $G21B
record "$H21B"
t "push of the re-cut while chain 20 runs" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" $F push $G21B
t "stop for the re-cut (gated)" 0 "STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F stop $G21B
t "switch to the re-cut genesis (guardian hosts still hold the first cut's data-21)" 0 "SWITCHED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21B
NEWB=$(cut -d' ' -f1 "$T"/markers/*)
chk "each guardian host moved the first cut's data-21 aside (kept) and initialised a fresh one" '[ "$(ls -d $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-21.stale-$P/db | wc -l | tr -d " ")" = 6 ] && [ "$(ls -d $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-21/db | wc -l | tr -d " ")" = 6 ] && [ "$(cat $T/hosts/192.0.2.10{1..6}/var/lib/randnode/data-21.genesis | sort -u)" = "$NEWB" ] && [ "$NEWB" != "$NEW" ]'
chk "…and the re-cut installed v0.8.0 again over the restored v0.7.0, keeping the one backup" '[ "$(installed rand-node)" = "26:$NEW_SHA " ] && [ "$(for h in $T/hosts/*; do sha $h/root/rand-node.pre-c21; done | sort -u)" = "$OLD_SHA" ]'
t "start on the re-cut" 0 "START-DONE" $F start
t "wait on the re-cut" 0 "CUTOVER DONE" env "${LN[@]}" $F wait $G21B
# ── the waiver (kept from chain 20) ──
record ""
t "push with SECOND_REBUILD_WAIVED=1 prints why and records it" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" SECOND_REBUILD_WAIVED=1 $F push $G21B
chk "…the waiver is recorded once" '[ "$(grep -c "^second-rebuild-waived: .*genesis $H21B" $CUT_RECORD)" = 1 ]'
t "switch accepts the recorded waiver for that genesis (re-run over switched hosts)" 1 "STILL RUNNING" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" $F switch $G21B
has "…after reading the waiver" "second-rebuild WAIVER for genesis $H21B"
echo "fleet rehearsal (chain 21): $pass passed, $fail failed"
[ $fail = 0 ]
