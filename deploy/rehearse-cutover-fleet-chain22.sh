#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2030,SC2031,SC2034,SC2012,SC2086  # the chk bodies are single-quoted and eval'd: they expand later, and read the variables set here
# Rehearse deploy/cutover-fleet-chain22.sh end to end against 26 FAKE hosts — local directories
# behind a fake `ssh`/`scp`, addressed by TEST-NET-1 addresses (192.0.2.x, RFC 5737: unroutable).
# No network, no real host, NO BINARY: the script under test is COPIED into a temp tree whose
# inventory names only the fake hosts and whose deploy/release-signers holds only a throwaway key
# made here; the fake `ssh`/`scp` refuse any host outside 192.0.2.0/24 and log every host they are
# asked for; the fake `curl` serves downloads only from a local directory for the made-up
# https://rehearsal.invalid/ base; and the run aborts unless the fakes are first on PATH.
#
#   deploy/rehearse-cutover-fleet-chain22.sh
#   SELFTEST=1 deploy/cutover-fleet-chain22.sh        # the same
#
# DERIVED from deploy/rehearse-cutover-fleet-chain21.sh. Where chain 21's wrapped a real rand-node,
# this one uses STUBS (python): "v0.8.6" (chain 21's build: init accepts only chain 21, pins chain
# 21's msauth blob, has no `beacon` and no `keygen-perp-vk`) and "v0.8.7" (constraint set 11: init
# REFUSES every chain but 22 and writes the `constraint-set` marker 11; pins the set-11 msauth blob
# and the four perps keys; `beacon init / commitment / status` keep a seed file whose commitments
# re-derive from its seeds). The key FILES are the real ones: the committed set-11 msauth blob and
# four perp-vk files, and chain 21's msauth blob read from the v0.8.6 tag (`git show`). The REAL
# deploy/check-beacon-seed.sh and deploy/check-constraint-set.sh run, the first on the fake hosts.
# The cut script is a stub that logs its arguments and environment (its own SELFTEST covers it).
#
# The fleet: the inventory's 26 rows — the 18 genesis validators, obs1, archive2 and g1..g6 — with
# e and obs1 archives on symlinked volumes. archive2 has NO fake host: any ssh or scp to it fails,
# and the run checks at the end that the fake ssh/scp were never asked for its address.
#
# What it does NOT prove: the remote commands run under this machine's tools behind small shims
# (`systemctl`, `runuser`, `sha256sum`, `install -o`, GNU `sed -i`, `chown`, the node's RPC, a
# download), not on Ubuntu under systemd; the binaries are stubs, so nothing here derives a real
# genesis hash, loads a real key or opens a real beacon chain (the node's own tests do that).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
unset SELFTEST DRY_RUN
REPO=$PWD
BLOB=$PWD/crates/randprotocol-zkvm/keys/msauth-vk-production.bin
TESTBLOB=$PWD/crates/randprotocol-zkvm/keys/msauth-vk-test.bin
KEYS=$PWD/crates/randprotocol-zkvm/keys
for f in "$BLOB" "$TESTBLOB" "$KEYS"/perp-vk-production-t18-pg14-in16-pub{7,8,9,10}-p2h20.bin deploy/check-beacon-seed.sh deploy/check-constraint-set.sh; do
  [ -f "$f" ] || { echo "rehearse: $f is missing" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "rehearse: needs python3" >&2; exit 1; }
BIN=$(mktemp -d); T=$(mktemp -d)
if [ -n "${REHEARSE_KEEP:-}" ]; then echo "rehearse: keeping $T and $BIN"; else trap 'rm -rf "$T" "$BIN"' EXIT; fi
OLDBLOB=$BIN/old-msauth-vk-production.bin
git show v0.8.6:crates/randprotocol-zkvm/keys/msauth-vk-production.bin > "$OLDBLOB" 2>/dev/null \
  || git show 6591c884187126f118460c940d15715032bd124f:crates/randprotocol-zkvm/keys/msauth-vk-production.bin > "$OLDBLOB" 2>/dev/null \
  || { echo "rehearse: cannot read chain 21's msauth blob from the v0.8.6 tag (git show v0.8.6:…) — fetch the tags" >&2; exit 1; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
OLD_VK=68facb06c7f321aaf1d4d541acf6b5c0e9d7f17788ed1c9add6c5a8a8f7acd30
[ "$(sha "$OLDBLOB")" = "$OLD_VK" ] || { echo "rehearse: v0.8.6's msauth blob is not chain 21's $OLD_VK" >&2; exit 1; }
PVK7=perp-vk-production-t18-pg14-in16-pub7-p2h20.bin; PVK8=perp-vk-production-t18-pg14-in16-pub8-p2h20.bin
PVK10=perp-vk-production-t18-pg14-in16-pub10-p2h20.bin
mkdir -p "$BIN"/{old,new,badrel,badpvk,badvk} "$T/repo/deploy/lib" "$T/repo/deploy/cut-records" "$T/shim" "$T/rshim" "$T/hosts" "$T/markers" "$T/key" "$T/cs"

# ── the rand-node stubs ───────────────────────────────────────────────────────────────────────
cat > "$T/stub.py" <<'STUB'
import hashlib, json, os, secrets, shutil, sys
V = "@VERSION@"; NEW = V == "0.8.7"
E = os.environ; host = E.get("FAKE_HOST", "")
a = sys.argv[1:]
def opt(n): return a[a.index(n) + 1]
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
def die(m, rc=1): print(f"error: {m} (rehearsal stub v{V})", file=sys.stderr); sys.exit(rc)
def here(var): return E.get(var) and E.get(var + "_HOST", host) == host
PVK = {"perp-vk-production-t18-pg14-in16-pub7-p2h20.bin": "4dc1f18bdd6d9104ba1622710cf2c146f71759676dbdcb70dad036152242e8b4",
       "perp-vk-production-t18-pg14-in16-pub8-p2h20.bin": "6392e5e9b7348f3729ba2031e0e3ec9788d6ed62a14521526482c92615f55106",
       "perp-vk-production-t18-pg14-in16-pub9-p2h20.bin": "c31636aa281004163e6fe0debd81854f11d7bca6c8062a91b1501c7e593e5bf0",
       "perp-vk-production-t18-pg14-in16-pub10-p2h20.bin": "ae3d0dc276061fd2a87b2e91b239f6dcccb746b49dedeecfdb2aab977c95c370"}
FLAGS21 = "--testnet --binding-domain --proof-window-blocks --max-gas-price --gas-byte-load --program-state-cell-fee --fees --multisig --auth-multisig-guest"
FLAGS22 = FLAGS21 + " --program-state-refuse-panics --tokens-incremental-root --program-state-reference-block-window --beacon-commitment"
def commit(seed, addr, cid): return hashlib.sha256(f"{seed}|{addr}|{cid}".encode()).hexdigest()
if a[:1] == ["--version"]:
    print(f"rand-node {V} (rehearsal stub)")
elif a[:2] == ["genesis", "--help"]:
    print("usage: rand-node genesis " + (FLAGS22 if NEW else FLAGS21))
elif a[:1] == ["init"]:
    d, g = opt("--datadir"), opt("--genesis"); cid = json.load(open(g)).get("chain_id")
    if NEW and cid != 22: die(f"constraint set 11 cannot run chain {cid} (constraint_set::build_genesis)")
    if not NEW and cid != 21: die(f"v{V} runs chain 21, not {cid}")
    h = sha(g); os.makedirs(d + "/db", exist_ok=True); shutil.copy(g, d + "/genesis.json")
    open(d + "/genesis.hash", "w").write(h)
    open(d + "/constraint-set", "w").write((E["REHEARSE_SET"] if here("REHEARSE_SET") else ("11" if NEW else "9")) + "\n")
    print(f"initialised {d}: chain {cid}, genesis {h}")
elif a[:1] == ["keygen-msauth-vk"]:
    if a[1] == "--check": print(sha(a[2]))
    elif a[1] == "--print-pinned": print(E["REHEARSE_PIN"] if here("REHEARSE_PIN") else
          ("168d79a880b13b6d3e5b1f2a0f50561590712179c63189b52038cb2172a971b3" if NEW else "68facb06c7f321aaf1d4d541acf6b5c0e9d7f17788ed1c9add6c5a8a8f7acd30"))
    else: die("keygen-msauth-vk: --check or --print-pinned")
elif a[:1] == ["keygen-perp-vk"] and NEW:
    if a[1] == "--check": print(sha(a[2]))
    elif a[1] == "--print-pinned":
        for i, (f, p) in enumerate(PVK.items()): print(f, E["REHEARSE_PVK_PIN"] if i == 0 and here("REHEARSE_PVK_PIN") else p)
    else: die("keygen-perp-vk: --check or --print-pinned")
elif a[:1] == ["address"]:
    print("address: " + json.load(open(opt("--key")))["address"])
elif a[:2] == ["beacon", "init"] and NEW:
    d, k, cid = opt("--datadir"), opt("--key"), int(opt("--chain-id")); p = d + "/beacon.seed.json"
    if os.path.exists(p): die(f"{p} exists — refusing to overwrite")
    addr = json.load(open(k))["address"]; seed = secrets.token_hex(32); c = commit(seed, addr, cid)
    os.makedirs(d, exist_ok=True); fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps({"chain_id": cid, "validator": addr, "seeds": [{"seed": seed, "commitment": c}]}).encode()); os.close(fd)
    print(f"wrote {p} (secret; chain {cid}, validator {addr}). Never copy it to another host. Commitment:", file=sys.stderr); print(c)
elif a[:2] in (["beacon", "commitment"], ["beacon", "status"]) and NEW:
    p = opt("--datadir") + "/beacon.seed.json"
    try: f = json.load(open(p))
    except Exception as e: die(f"cannot read {p}: {e}")
    for s in f["seeds"]:
        if commit(s["seed"], f["validator"], f["chain_id"]) != s["commitment"]: die(f"{p}: a chain does not re-derive from its seed")
    c = f["seeds"][-1]["commitment"]
    if a[1] == "commitment":
        print(f"chain {f['chain_id']}, validator {f['validator']}, {len(f['seeds'])} chain(s); newest commitment:", file=sys.stderr); print(c)
    else:
        print(f"validator {f['validator']} on chain {f['chain_id']} at height 0; beacon value {'0' * 64}")
        print(f"commitment in force {c}: the seed file opens it; remaining reveals: 1000")
else:
    die(f"unrecognized subcommand {' '.join(a[:2])}", 2)
STUB
mkstub() { { echo '#!/usr/bin/env python3'; sed "s/@VERSION@/$2/" "$T/stub.py"; } > "$1"; chmod 755 "$1"; }
mkstub "$BIN/old/rand-node" 0.8.6; mkstub "$BIN/new/rand-node" 0.8.7
printf '#!/usr/bin/env bash\necho "rand 0.8.6 (rehearsal stub)"\n' > "$BIN/old/rand"
printf '#!/usr/bin/env bash\necho "rand 0.8.7 (rehearsal stub)"\n' > "$BIN/new/rand"
cp "$OLDBLOB" "$BIN/old/msauth-vk-production.bin"
cp "$BLOB" "$KEYS"/perp-vk-production-*.bin "$BIN/new/"
cp "$BIN"/new/* "$BIN/badrel/"; printf '#!/usr/bin/env bash\n# a tampered release\nexit 1\n' > "$BIN/badrel/rand-node"
cp "$BIN"/new/* "$BIN/badpvk/"; cp "$KEYS/$PVK8" "$BIN/badpvk/$PVK7"     # one perps key's bytes wrong
cp "$BIN"/new/* "$BIN/badvk/"; cp "$TESTBLOB" "$BIN/badvk/msauth-vk-production.bin"
chmod 755 "$BIN"/*/rand*

# ── the throwaway release key and the signed SHA256SUMS of each fake release ───────────────────
ssh-keygen -q -t ed25519 -N '' -C rehearsal -f "$T/key/rel" >/dev/null
echo "rehearsal@randprotocol namespaces=\"rand-release\" $(cut -d' ' -f1,2 "$T/key/rel.pub")" > "$T/repo/deploy/release-signers"
sums() { (cd "$1" && shasum -a 256 rand-node rand msauth-vk-production.bin perp-vk-production-*.bin | sed 's/  / /') > "$2"; }
sign() { ssh-keygen -q -Y sign -n rand-release -f "$T/key/rel" "$1" >/dev/null 2>&1; }
sums "$BIN/new" "$T/SUMS"; sign "$T/SUMS"
sed "s/^$(sha "$BLOB") /$(sha "$TESTBLOB") /" "$T/SUMS" > "$T/SUMS-otherblob"; sign "$T/SUMS-otherblob"
sed "s/^$(sha "$KEYS/$PVK7") /$(sha "$KEYS/$PVK8") /" "$T/SUMS" > "$T/SUMS-otherpvk"; sign "$T/SUMS-otherpvk"
grep -v " $PVK10\$" "$T/SUMS" > "$T/SUMS-nopvk"; sign "$T/SUMS-nopvk"
cp "$T/SUMS" "$T/SUMS-tampered"; cp "$T/SUMS.sig" "$T/SUMS-tampered.sig"; echo "0000000000000000000000000000000000000000000000000000000000000000 extra" >> "$T/SUMS-tampered"
cp "$T/SUMS" "$T/SUMS-unsigned"
(cd "$BIN/old" && shasum -a 256 rand-node rand | sed 's/  / /') > "$T/OLD-SUMS"; sign "$T/OLD-SUMS"

# ── the fake ssh / scp (the laptop side): log every host asked for ─────────────────────────────
cat > "$T/shim/ssh" <<'FAKE_SSH'
#!/usr/bin/env bash
host=""; cmd=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n|-N|-q) shift;; -o|-i|-L) shift 2;;
    root@*) host=${1#root@}; shift; cmd="$*"; break;;
    *) shift;;
  esac
done
echo "$host" >> "$FAKE_SSH_LOG"
case "$host" in 192.0.2.*) ;; *) echo "FAKE ssh: refusing non-TEST-NET host '$host'" >&2; exit 255;; esac
R=$FAKE_HOSTS/$host
[ -d "$R" ] || { echo "FAKE ssh: ssh: connect to host $host port 22: Connection timed out" >&2; exit 255; }
cmd=$(printf '%s' "$cmd" | /usr/bin/sed -e "s#/etc/systemd/system#$R/etc/systemd/system#g" -e "s#/usr/local/bin#$R/usr/local/bin#g" -e "s#/var/lib/randnode#$R/var/lib/randnode#g" -e "s#/root#$R/root#g")
FAKE_ROOT=$R FAKE_HOST=$host PATH="$FAKE_RSHIM:$PATH" bash -c "$cmd"
FAKE_SSH
cat > "$T/shim/scp" <<'FAKE_SCP'
#!/usr/bin/env bash
srcs=(); dst=""
while [ $# -gt 0 ]; do case "$1" in -q) shift;; -o|-i) shift 2;; root@*) dst=$1; shift;; *) srcs+=("$1"); shift;; esac; done
host=${dst#root@}; path=${host#*:}; host=${host%%:*}
echo "$host" >> "$FAKE_SSH_LOG"
case "$host" in 192.0.2.*) ;; *) echo "FAKE scp: refusing $host" >&2; exit 255;; esac
[ -d "$FAKE_HOSTS/$host" ] || { echo "FAKE scp: connect to $host: Connection timed out" >&2; exit 255; }
cp "${srcs[@]}" "$FAKE_HOSTS/$host$path"
FAKE_SCP
# ── what a fake host's shell finds first on PATH (the host side) ───────────────────────────────
cat > "$T/rshim/systemctl" <<'FAKE_SYSTEMCTL'
#!/usr/bin/env bash
st=$FAKE_ROOT/state; mkdir -p $st
case "$1" in
  is-active) q=0; [ "$2" = --quiet ] && { q=1; shift; }; s=$(cat $st/$2 2>/dev/null || echo inactive); [ $q = 1 ] || echo $s; [ "$s" = active ];;
  stop) echo inactive > $st/$2;;
  start) [ -e $st/refuse-start ] || echo active > $st/$2;;
  daemon-reload) :;;
  cat) cat $FAKE_ROOT/etc/systemd/system/$2.service $FAKE_ROOT/etc/systemd/system/$2.service.d/*.conf 2>/dev/null;;
  *) echo "fake systemctl: $*" >&2; exit 1;;
esac
FAKE_SYSTEMCTL
printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' > "$T/rshim/sha256sum"
printf '#!/usr/bin/env bash\ncat $FAKE_ROOT/hostname\n' > "$T/rshim/hostname"
printf '#!/usr/bin/env bash\n# runuser -u randnode -- cmd...\nshift 3; exec "$@"\n' > "$T/rshim/runuser"
printf '#!/usr/bin/env bash\n# chown: no randnode user here\nexit 0\n' > "$T/rshim/chown"
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
# FAKE curl. A download (-o FILE URL) or a HEAD (-I) is served from $FAKE_RELEASE_DIR for
# https://rehearsal.invalid/ only. Otherwise the node RPC on 127.0.0.1:8545, answered only while
# rand-node is "active", for the chain of the datadir the unit / drop-in names.
out=""; url=""; prev=""; head=0
for a in "$@"; do [ "$prev" = -o ] && out=$a; case "$a" in https://*) url=$a;; -fsSIL|-I) head=1;; esac; prev=$a; done
if [ -n "$url" ]; then
  case "$url" in https://rehearsal.invalid/*) ;; *) echo "FAKE curl: refusing $url" >&2; exit 22;; esac
  f=${url%%\?*}; f=${f##*/}; [ -f "$FAKE_RELEASE_DIR/$f" ] || exit 22
  [ $head = 1 ] && exit 0
  cp "$FAKE_RELEASE_DIR/$f" "$out"; exit 0
fi
[ "$(cat $FAKE_ROOT/state/rand-node 2>/dev/null)" = active ] || exit 7
body="$*"
dd=$(cat $FAKE_ROOT/etc/systemd/system/rand-node.service $FAKE_ROOT/etc/systemd/system/rand-node.service.d/*.conf 2>/dev/null | grep -o -- '--datadir [^ ]*' | tail -1 | cut -d' ' -f2)
B=$FAKE_ROOT/usr/local/bin
OLDH=ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a
case "$body" in
  *rand_getGenesisHash*)
    case "$dd" in *-ca76c276|*/data-21) h=$OLDH;; *) [ -f "$dd/genesis.hash" ] || exit 7; h=$(cat "$dd/genesis.hash");; esac
    [ "${REHEARSE_SERVE_OLD:-}" = "$FAKE_HOST" ] && h=$OLDH
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"$h\"}";;
  *rand_getHealth*) echo '{"id":1,"jsonrpc":"2.0","result":{"status":"ok"}}';;
  *rand_getBridgeState*)
    python3 - "$FAKE_ROOT/root/stage-c22/genesis-chain22.json" "${REHEARSE_MINTED:-0}" <<'PY'
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
    pk='{"source":"absent","keys":0}'; pins=$($B/rand-node keygen-perp-vk --print-pinned production 2>/dev/null)
    if [ -n "$pins" ]; then c=0; while read -r f s; do [ "$(shasum -a 256 $B/$f 2>/dev/null | cut -d' ' -f1)" = "$s" ] && c=$((c+1)); done <<<"$pins"; [ $c = 4 ] && pk='{"source":"loaded","keys":4}'; fi
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"height\":$n,\"view\":6,\"msauth_key\":\"$k\",\"perps_keys\":$pk}}";;
  *rand_getVersion*)
    case "$($B/rand-node --version 2>/dev/null)" in
      "rand-node 0.8.6"*) v=0.8.6; gs=6591c884187126f118460c940d15715032bd124f;;
      *) v=0.8.7; gs=fake;;
    esac
    echo "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"chain_id\":21,\"git_sha\":\"$gs\",\"version\":\"$v\"}}";;
esac
FAKE_CURL
# ── the 26 inventory rows; 25 fake hosts (archive2 has none), on chain 21, on "v0.8.6" ─────────
NAMES18="a b c d e f lon1 sfo3 tor1 blr1 syd1 atl1 ams3 nyc1 nyc2 sfo2 mkc1 mem1"
cat > "$T/mkfleet.sh" <<'MKFLEET'
#!/usr/bin/env bash
set -euo pipefail
T=$1; OLDB=$2; NAMES18=$3; H=$T/hosts; rm -rf $H; mkdir -p $H
INV=$T/inventory.tsv
printf 'name\tip\thostname\trole\tssh_key\tkey_path\tdatadir\taddress\tpeer_id\tbootstraps\textra_flags\tufw\tother_units\n' > $INV
mk() { # ip name — the installed files are COPIES (switch's `install` writes over them)
  local R=$H/$1; mkdir -p $R/root/keys $R/etc/systemd/system $R/usr/local/bin $R/var/lib/randnode $R/state
  echo $2 > $R/hostname; cp $OLDB/rand-node $OLDB/rand $OLDB/msauth-vk-production.bin $R/usr/local/bin/; echo active > $R/state/rand-node
}
i=0
for n in $NAMES18 obs1 archive2; do
  i=$((i+1)); ip=192.0.2.$i; role=validator; dd=/root/data-rand-node-$n-ca76c276
  case $n in e) role=validator+archive;; obs1) role=validator+archive; dd=/root/data-obs1-ca76c276;; archive2) role=validator+archive+prover-member; dd=/root/data-archive2-ca76c276;; esac
  printf '%s\t%s\trand-node-%s\t%s\t~/.ssh/id_ed25519\t/root/keys/node-%s.key.json\t%s\taddr-%s\t12D3Fake%s\t\t--validator\tactive\t\n' $n $ip $n $role $n $dd $n $n >> $INV
  [ $n != archive2 ] || continue          # archive2: dropped and unreachable — no fake host at all
  mk $ip rand-node-$n; R=$H/$ip
  echo "{\"address\": \"addr-$n\"}" > $R/root/keys/node-$n.key.json
  if [ $n = e ] || [ $n = obs1 ]; then mkdir -p $R/mnt/volume$dd/db; ln -s $R/mnt/volume$dd $R$dd; else mkdir -p $R$dd/db; fi
  printf '[Service]\nExecStart=%s run --datadir %s --key %s --validator\n' "$R/usr/local/bin/rand-node" "$R$dd" "$R/root/keys/node-$n.key.json" > $R/etc/systemd/system/rand-node.service
done
for g in 1 2 3 4 5 6; do
  ip=192.0.2.10$g; mk $ip rand-guardian-$g; R=$H/$ip
  printf 'g%s\t%s\trand-guardian-%s\tvalidator+guardian-host\t~/.ssh/rand_guardian_ed25519\t/var/lib/randnode/node.key.json\t/var/lib/randnode/data-21\taddr-g%s\t12D3FakeG%s\t\t--validator\tactive\trand-guardian.service\n' $g $ip $g $g $g >> $INV
  echo "{\"address\": \"addr-g$g\"}" > $R/var/lib/randnode/node.key.json
  mkdir -p $R/etc/systemd/system/rand-node.service.d $R/var/lib/randnode/data-21/db
  printf '[Service]\nUser=randnode\n' > $R/etc/systemd/system/rand-node.service
  printf '[Service]\nExecStart=\nExecStart=%s run --datadir %s --key %s --validator\n' "$R/usr/local/bin/rand-node" "$R/var/lib/randnode/data-21" "$R/var/lib/randnode/node.key.json" > $R/etc/systemd/system/rand-node.service.d/chain21.conf
  echo active > $R/state/rand-guardian
done
mkdir -p $H/192.0.2.150/state; echo rand-relayer-1 > $H/192.0.2.150/hostname; echo active > $H/192.0.2.150/state/rand-relayer   # the relayer
MKFLEET
chmod +x "$T"/shim/* "$T"/rshim/* "$T/mkfleet.sh"
# ── the temp tree: the script under test, the real helpers, a stub cut script ─────────────────
cp deploy/cutover-fleet-chain22.sh deploy/check-beacon-seed.sh deploy/check-constraint-set.sh deploy/cut-record.template "$T/repo/deploy/"
cp deploy/lib/cut-policy.sh deploy/lib/verify-release.sh deploy/lib/fleet-env.sh "$T/repo/deploy/lib/"
{ echo '#!/usr/bin/env bash'
  echo '# rehearsal stub of deploy/cut-chain22-genesis.sh: logs its arguments and environment; the validator lists are the real ones'
  grep -E '^(GENESIS_NAMES|BONDED|DROPPED_VALIDATORS)=' deploy/cut-chain22-genesis.sh
  echo 'echo "STUB $* PRUNED_SCAN_OK=${PRUNED_SCAN_OK:-} BEACON_TSV=${BEACON_TSV:-} NODE=${NODE:-} DRY_RUN=${DRY_RUN:-} WALLET=${WALLET:-} WALLET22=${WALLET22:-}" >> "$STUB_LOG"'
  echo 'echo "cut-chain22-genesis.sh (stub) ran: ${1:-cut}"'
  echo 'if [ "${1:-}" = check-limits ]; then exit "${STUB_LIMITS_RC:-0}"; fi; exit "${STUB_RC:-0}"'
} > "$T/repo/deploy/cut-chain22-genesis.sh"
cp crates/randprotocol-node/src/constraint_set.rs "$T/cs/no-row.rs"
export NODE_RS=$REPO/crates/randprotocol-node/src/node.rs VENDORED_MACHINE_RS=$REPO/crates/randprotocol-zkvm/src/machine.rs CONSTRAINT_SET_RS=$T/cs/no-row.rs
"$T/mkfleet.sh" "$T" "$BIN/old" "$NAMES18"
export PATH="$T/shim:$PATH" FAKE_HOSTS=$T/hosts FAKE_RSHIM=$T/rshim FAKE_RELEASE_DIR=$BIN/new FAKE_SSH_LOG=$T/ssh.log STUB_LOG=$T/stub.log
[ "$(command -v ssh)" = "$T/shim/ssh" ] && [ "$(command -v scp)" = "$T/shim/scp" ] || { echo "rehearse: the fake ssh/scp are not first on PATH — abort" >&2; exit 99; }
! cut -f2 "$T/inventory.tsv" | tail -n +2 | grep -qv '^192\.0\.2\.' || { echo "rehearse: the fake inventory names a non-TEST-NET host — abort" >&2; exit 99; }
: > "$T/ssh.log"; : > "$T/stub.log"
ARCHIVE2_IP=$(awk -F'\t' '$1 == "archive2" {print $2}' "$T/inventory.tsv")
OLD_SHA=$(sha "$BIN/old/rand-node"); OLD_SHA_WALLET=$(sha "$BIN/old/rand")
NEW_SHA=$(sha "$BIN/new/rand-node"); NEW_SHA_WALLET=$(sha "$BIN/new/rand"); VK_SHA=$(sha "$BLOB")
export INVENTORY=$T/inventory.tsv MARKER_DIR=$T/markers WAIT_SLEEP=0 MIN_FREE_GB=0 \
  RELEASE_URL=https://rehearsal.invalid/v0.8.7 CUT_RECORD=$T/cut-record.txt BEACON_TSV=$T/beacon.tsv \
  ROLL_RECORD=$T/roll.record GUARDIAN_KNOWN_HOSTS=$T/known_hosts CHECK_LIMITS_RPC=http://127.0.0.1:1/rehearsal
unset RELEASE_SUMS RELEASE_SUMS_SIG OLD_RELEASE_SUMS WANT_SHA WANT_SHA_WALLET LOCAL_NODE CONFIRM_HALT_CHAIN21 RELAYER_HOST RELAYER_HANDLED BRIDGE_ON_CHAIN22 PRUNED_SCAN_OK
NEWENV=("RELEASE_SUMS=$T/SUMS")
OLDENV=("OLD_RELEASE_SUMS=$T/OLD-SUMS")
LN=("LOCAL_NODE=$BIN/new/rand-node")
F=$T/repo/deploy/cutover-fleet-chain22.sh
hash_of() { sha "$1"; }   # the stub's init: the genesis hash is the file's sha256
record() { sed -e 's/<[^>]*>/filled (rehearsal)/' "$REPO/deploy/cut-record.template" | sed "s/^second-hash:.*/second-hash: $1/" > "$CUT_RECORD"; }
pass=0; fail=0
t() { # <description> <want rc: 0|!0> <grep phrase in output> cmd…
  local what=$1 want=$2 phrase=$3; shift 3
  "$@" > "$T/out.log" 2>&1; local rc=$?
  if { [ "$want" = 0 ] && [ $rc = 0 ]; } || { [ "$want" != 0 ] && [ $rc != 0 ]; }; then
    if grep -qF -- "$phrase" "$T/out.log"; then echo "ok   — $what (rc $rc): $(grep -F -- "$phrase" "$T/out.log" | tail -1 | cut -c1-140)"; pass=$((pass+1))
    else echo "FAIL — $what: rc $rc as wanted but no \"$phrase\": $(tail -3 "$T/out.log" | cut -c1-240)"; fail=$((fail+1)); cp "$T/out.log" "$T/fail-$fail.log"; fi
  else echo "FAIL — $what: rc $rc, wanted $want: $(tail -4 "$T/out.log" | cut -c1-300)"; fail=$((fail+1)); cp "$T/out.log" "$T/fail-$fail.log"; fi
}
chk() { if eval "$2"; then echo "ok   — $1"; pass=$((pass+1)); else echo "FAIL — $1"; fail=$((fail+1)); fi; }
has() { if grep -qF -- "$2" "$T/out.log"; then echo "ok   — $1"; pass=$((pass+1)); else echo "FAIL — $1: no \"$2\""; fail=$((fail+1)); fi; }
hasnt() { if ! grep -qF -- "$2" "$T/out.log"; then echo "ok   — $1"; pass=$((pass+1)); else echo "FAIL — $1: found \"$2\""; fail=$((fail+1)); fi; }
H=$T/hosts
ip_of() { awk -F'\t' -v n="$1" '$1 == n {print $2}' "$T/inventory.tsv"; }
nmark() { ls "$T/markers" | wc -l | tr -d ' '; }
units() { for h in "$H"/192.0.2.{1..19} "$H"/192.0.2.10{1..6}; do cat $h/etc/systemd/system/rand-node.service $h/etc/systemd/system/rand-node.service.d/*.conf 2>/dev/null; done | shasum | cut -c1-16; }
tree() { find "$H" -type f -o -type l | sort | xargs shasum 2>/dev/null | shasum | cut -c1-16; }
active() { grep -l '^active$' "$H"/192.0.2.{1..19}/state/rand-node "$H"/192.0.2.10{1..6}/state/rand-node 2>/dev/null | wc -l | tr -d ' '; }
installed() { for h in "$H"/192.0.2.{1..19} "$H"/192.0.2.10{1..6}; do if [ -f $h/usr/local/bin/$1 ]; then sha $h/usr/local/bin/$1; else echo none; fi; done | sort | uniq -c | awk '{print $1":"$2}' | tr '\n' ' '; }
staged() { ls "$H"/*/root/stage-c22/rand-node 2>/dev/null | wc -l | tr -d ' '; }
bdir() { case "$1" in 192.0.2.10?) echo "$H/$1/var/lib/randnode/beacon-c22";; *) echo "$H/$1/root/beacon-c22";; esac; }
sshn() { wc -l < "$T/ssh.log" | tr -d ' '; }
U0=$(units)

# ── DRY_RUN: prints, touches nothing, contacts no host ──
TR0=$(tree)
for ph in preflight stage beacon-init beacon-collect bridge-stop status halt rollback start start-archives wait21; do
  t "DRY_RUN=1 $ph with no inputs prints and touches nothing" 0 "[dry-run]" env DRY_RUN=1 "$F" $ph
done
t "DRY_RUN=1 snapshot shows the cut script with PRUNED_SCAN_OK=1" 0 "PRUNED_SCAN_OK=1" env DRY_RUN=1 "$F" snapshot "$T/snap"
t "DRY_RUN=1 cut shows BEACON_TSV" 0 "BEACON_TSV=$T/beacon.tsv" env DRY_RUN=1 "$F" cut
t "DRY_RUN=1 push prints the push" 0 "[dry-run] scp" env DRY_RUN=1 "$F" push "$T/no-genesis.json"
t "DRY_RUN=1 stop without the phrase says the real stop refuses, and stops nothing" 0 "REFUSES without CONFIRM_HALT_CHAIN21=halt-chain-21-for-" env DRY_RUN=1 "$F" stop "$T/no-genesis.json"
t "DRY_RUN=1 switch prints the perps key check" 0 "keygen-perp-vk --print-pinned production" env DRY_RUN=1 "$F" switch "$T/no-genesis.json"
t "DRY_RUN=1 check-limits prints the tunnel and the cut script" 0 "check-limits" env -u CHECK_LIMITS_RPC DRY_RUN=1 "$F" check-limits "$T/no-genesis.json"
t "DRY_RUN=1 wait prints check-beacon-seed.sh --rpc" 0 "--rpc 127.0.0.1:8545" env DRY_RUN=1 "$F" wait "$T/no-genesis.json"
t "DRY_RUN=1 bridge-start" 0 "systemctl start rand-guardian" env DRY_RUN=1 "$F" bridge-start
chk "…the dry runs changed no host, contacted none, wrote no marker, record, stub call or BEACON_TSV" '[ "$(tree)" = "$TR0" ] && [ "$(sshn)" = 0 ] && [ "$(active)" = 25 ] && [ "$(nmark)" = 0 ] && [ ! -e $ROLL_RECORD ] && [ ! -s $T/stub.log ] && [ ! -e $BEACON_TSV ]'
# ── the inventory and input hygiene ──
t "no INVENTORY" 1 "INVENTORY is unset" env -u INVENTORY "$F" status
sed 's/192\.0\.2\.7\t/203.0.113.7\t/' "$T/inventory.tsv" > "$T/inv-ph.tsv"
t "an inventory with a placeholder host" 1 "placeholder hosts" env INVENTORY="$T/inv-ph.tsv" "$F" status
grep -v '^archive2' "$T/inventory.tsv" > "$T/inv-noa2.tsv"
t "an inventory without archive2's row (not the fleet's)" 1 "no row for the dropped archive2" env INVENTORY="$T/inv-noa2.tsv" "$F" status
grep -v '^nyc2' "$T/inventory.tsv" > "$T/inv-24.tsv"
t "an inventory missing a validator (24)" 1 "are not chain 22's 25" env INVENTORY="$T/inv-24.tsv" "$F" status
sed 's/^g3\t192\.0\.2\.103/g3\t192.0.2.103;touch/' "$T/inventory.tsv" > "$T/inv-bad.tsv"
t "an address that is not IPv4" 1 "is not an IPv4 address" env INVENTORY="$T/inv-bad.tsv" "$F" status
sed 's#/root/keys/node-b.key.json#/root/keys/$(id).json#' "$T/inventory.tsv" > "$T/inv-meta.tsv"
t "a key path with shell metacharacters" 1 "is not a plain absolute path" env INVENTORY="$T/inv-meta.tsv" "$F" status
t "a WANT_VERSION with a quote and ';'" 1 "shell metacharacter" env "WANT_VERSION=0.8.7'; touch /tmp/x" "$F" status
t "archive2 as a bootstrap is refused" 1 "is not a first-group validator" env BOOT_NAMES="archive2 c" "$F" status
t "the relayer at archive2's address is refused" 1 "dropped validator's address" env RELAYER_HOST="$ARCHIVE2_IP" "$F" bridge-stop
chk "…none of these contacted a host" '[ "$(sshn)" = 0 ]'
# ── preflight ──
t "preflight without v0.8.6's pins" 1 "OLD_SHA / OLD_SHA_WALLET" env "${NEWENV[@]}" "$F" preflight
t "preflight without the signed v0.8.7 sums" 1 "RELEASE_SUMS is unset" env "${OLDENV[@]}" "$F" preflight
t "preflight with a v0.8.7 SHA256SUMS whose signature does not verify" 1 "signature does not verify" env "${OLDENV[@]}" RELEASE_SUMS="$T/SUMS-unsigned" "$F" preflight
t "preflight on the healthy chain-21 fleet: 25 hosts, the seven release files present" 0 "PREFLIGHT OK" env "${OLDENV[@]}" "${NEWENV[@]}" "$F" preflight
has "…25 validators, first group 23 ≥ quorum 17, archives late" "25 validators; first group 23 ≥ quorum 17; late: e obs1"
has "…the release holds all seven files" "all seven present"
chk "preflight changed nothing" '[ "$(units)" = "$U0" ] && [ "$(active)" = 25 ] && [ "$(nmark)" = 0 ]'
t "preflight with too little disk (MIN_FREE_GB=9999)" 1 "GB free under" env "${OLDENV[@]}" "${NEWENV[@]}" MIN_FREE_GB=9999 "$F" preflight
cp "$BIN/new/rand-node" "$H/192.0.2.7/usr/local/bin/rand-node"
t "preflight with one host on another rand-node" 1 "not chain 21's v0.8.6" env "${OLDENV[@]}" "${NEWENV[@]}" "$F" preflight
cp "$BIN/old/rand-node" "$H/192.0.2.7/usr/local/bin/rand-node"
cp "$BLOB" "$H/192.0.2.8/usr/local/bin/msauth-vk-production.bin"
t "preflight with one host not holding chain 21's msauth blob" 1 "the rollback needs it" env "${OLDENV[@]}" "${NEWENV[@]}" "$F" preflight
cp "$OLDBLOB" "$H/192.0.2.8/usr/local/bin/msauth-vk-production.bin"
sed 's#/root/data-rand-node-f-ca76c276#/root/data-rand-node-f-elsewhere-ca76c276#' "$T/inventory.tsv" > "$T/inv-dd.tsv"
t "preflight when the inventory's datadir is not the unit's" 1 "does not run the inventory's datadir" env INVENTORY="$T/inv-dd.tsv" "${OLDENV[@]}" "${NEWENV[@]}" "$F" preflight
t "halt while chain 21 runs is refused" 1 "RUNS CHAIN 21" "$F" halt
# ── stage ──
t "beacon-init before stage (no staged v0.8.7)" 1 "not every validator has a seed" env "${NEWENV[@]}" "$F" beacon-init
t "stage without RELEASE_SUMS" 1 "RELEASE_SUMS is unset" "$F" stage
t "stage with an unsigned SHA256SUMS" 1 "signature does not verify" env RELEASE_SUMS="$T/SUMS-unsigned" "$F" stage
t "stage with a SHA256SUMS changed after signing" 1 "signature does not verify" env RELEASE_SUMS="$T/SUMS-tampered" "$F" stage
t "stage with a signed SHA256SUMS whose msauth blob is not set 11's" 1 "not constraint set 11's decided blob" env RELEASE_SUMS="$T/SUMS-otherblob" "$F" stage
t "stage with a signed SHA256SUMS whose perps key is not the decided one" 1 "not the decided" env RELEASE_SUMS="$T/SUMS-otherpvk" "$F" stage
t "stage with a signed SHA256SUMS missing a perps key" 1 "a chain-22 node does not start without it" env RELEASE_SUMS="$T/SUMS-nopvk" "$F" stage
t "stage with a WANT_SHA that disagrees with the signed file" 1 "is not what the signed SHA256SUMS lists" env "${NEWENV[@]}" WANT_SHA="$OLD_SHA" "$F" stage
t "stage from a path holding a non-ELF build" 1 "not a Linux ELF" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR="$BIN/new" "$F" stage
t "stage from a path whose perps key is not the signed one" 1 "is not the signed" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR="$BIN/badpvk" STAGE_ALLOW_NON_ELF=1 "$F" stage
chk "…nothing staged" '[ "$(staged)" = 0 ]'
t "stage from a release whose rand-node does not match" 1 "not every host staged" env "${NEWENV[@]}" FAKE_RELEASE_DIR="$BIN/badrel" "$F" stage
has "…each host said SHA MISMATCH and removed it" "SHA MISMATCH ( rand-node) — removed"
t "stage from a release whose perps key bytes do not match" 1 "not every host staged" env "${NEWENV[@]}" FAKE_RELEASE_DIR="$BIN/badpvk" "$F" stage
has "…naming the key file" "SHA MISMATCH ( $PVK7) — removed"
chk "…no staged or partial file left anywhere" '[ "$(staged)" = 0 ] && ! ls $H/*/root/stage-c22/*.part >/dev/null 2>&1'
t "stage with a staged binary that pins another msauth key" 1 "msauth key NOT verified" env "${NEWENV[@]}" REHEARSE_PIN="$(sha "$TESTBLOB")" "$F" stage
t "stage with a staged binary that pins another perps key" 1 "perps keys NOT verified" env "${NEWENV[@]}" REHEARSE_PVK_PIN="$(sha "$TESTBLOB")" "$F" stage
t "stage from a plain-http url" 1 "is not https://" env "${NEWENV[@]}" STAGE_FROM=url STAGE_URL=http://rehearsal.invalid/x "$F" stage
t "stage from the release" 0 "STAGED" env "${NEWENV[@]}" "$F" stage
has "…each host verified the msauth key and the four perps keys with the staged binary" "msauth key ${VK_SHA:0:12}… and the four perps keys verified"
chk "25 hosts hold the seven files + the seed checker at their pins; installed still v0.8.6; 25 active" '[ "$(staged)" = 25 ] && [ "$(installed rand-node)" = "25:$OLD_SHA " ] && [ "$(active)" = 25 ] && [ "$(cat $H/*/root/stage-c22/check-beacon-seed.sh | shasum | cut -c1-40)" = "$(for i in $(seq 25); do cat deploy/check-beacon-seed.sh; done | shasum | cut -c1-40)" ] && [ "$(ls $H/*/root/stage-c22/perp-vk-production-*.bin | wc -l | tr -d " ")" = 100 ]'
t "stage again from a local path (STAGE_ALLOW_NON_ELF=1: the stubs are scripts)" 0 "STAGED" env "${NEWENV[@]}" STAGE_FROM=path STAGE_DIR="$BIN/new" STAGE_ALLOW_NON_ELF=1 "$F" stage
# ── the beacon: init on each host, collect the commitments ──
t "beacon-init on the 25 validators" 0 "BEACON-INIT DONE" env "${NEWENV[@]}" "$F" beacon-init
chk "25 seed files, each in its own host's staging dir (guardians under /var/lib/randnode), mode 0600, each naming its host's key" '[ "$(for i in $(seq 1 19) 101 102 103 104 105 106; do b=$(bdir 192.0.2.$i); python3 -c "import json,sys,os,stat; f=json.load(open(sys.argv[1])); k=json.load(open(sys.argv[2])); assert f[\"validator\"]==k[\"address\"] and f[\"chain_id\"]==22 and stat.S_IMODE(os.stat(sys.argv[1]).st_mode)==0o600; print(\"ok\")" $b/beacon.seed.json $( [ $i -gt 100 ] && echo $H/192.0.2.$i/var/lib/randnode/node.key.json || echo $H/192.0.2.$i/root/keys/*.key.json); done | grep -c ok)" = 25 ]'
SEEDS=$(for f in "$H"/*/root/beacon-c22/beacon.seed.json "$H"/*/var/lib/randnode/beacon-c22/beacon.seed.json; do python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["seeds"][0]["seed"])' "$f"; done)
chk "…no seed value appears in the phase's output" '! grep -qF -f <(printf "%s\n" $SEEDS) $T/out.log'
chk "…no seed file anywhere outside its host (none on the laptop side)" '[ -z "$(find $T $BIN -name beacon.seed.json -not -path "$H/*" 2>/dev/null)" ]'
S0=$(cat "$H"/*/root/beacon-c22/beacon.seed.json "$H"/*/var/lib/randnode/beacon-c22/beacon.seed.json | shasum)
t "beacon-init again keeps every seed" 0 "(kept; validator addr-" env "${NEWENV[@]}" "$F" beacon-init
chk "…byte for byte" '[ "$(cat $H/*/root/beacon-c22/beacon.seed.json $H/*/var/lib/randnode/beacon-c22/beacon.seed.json | shasum)" = "$S0" ]'
cp "$(bdir 192.0.2.1)/beacon.seed.json" "$T/a-seed.keep"; cp "$(bdir 192.0.2.101)/beacon.seed.json" "$(bdir 192.0.2.1)/beacon.seed.json"
t "beacon-collect when a seed file was copied from another host" 1 "not chain 22 and this key's address addr-a" env "${NEWENV[@]}" "$F" beacon-collect
cp "$T/a-seed.keep" "$(bdir 192.0.2.1)/beacon.seed.json"; chmod 600 "$(bdir 192.0.2.1)/beacon.seed.json"
chmod 644 "$(bdir 192.0.2.104)/beacon.seed.json"
t "beacon-collect when a seed file is mode 0644" 1 "not 0600" env "${NEWENV[@]}" "$F" beacon-collect
chmod 600 "$(bdir 192.0.2.104)/beacon.seed.json"
chk "…no BEACON_TSV written by the refusals" '[ ! -e $BEACON_TSV ]'
t "beacon-collect" 0 "COLLECTED" env "${NEWENV[@]}" "$F" beacon-collect
chk "BEACON_TSV: the 25 names of GENESIS_NAMES + BONDED, each with its host's own commitment" '[ "$(grep -v "^#" $BEACON_TSV | awk "{print \$1}" | tr "\n" " ")" = "$NAMES18 obs1 g1 g2 g3 g4 g5 g6 " ] && for n in a lon1 obs1 g3; do i=$(ip_of $n); c=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[\"seeds\"][-1][\"commitment\"])" $(bdir $i)/beacon.seed.json); grep -qx "$n $c" $BEACON_TSV || exit 1; done'
chk "…and no seed in it" '! grep -qF -f <(printf "%s\n" $SEEDS) $BEACON_TSV'
t "beacon-collect again: unchanged" 0 "already holds these 25 commitments" env "${NEWENV[@]}" "$F" beacon-collect
cp "$BEACON_TSV" "$T/beacon.keep"; sed -i '' '3s/ [0-9a-f]*$/ 1111111111111111111111111111111111111111111111111111111111111111/' "$BEACON_TSV"
t "beacon-collect over a BEACON_TSV holding other commitments" 1 "exists with OTHER commitments" env "${NEWENV[@]}" "$F" beacon-collect
t "…replaced on BEACON_TSV_REPLACE=1, the old one moved aside" 0 "moved aside" env "${NEWENV[@]}" BEACON_TSV_REPLACE=1 "$F" beacon-collect
chk "…the new file is the hosts' again" 'diff -q <(grep -v "^#" $T/beacon.keep) <(grep -v "^#" $BEACON_TSV) >/dev/null && ls $BEACON_TSV.replaced-* >/dev/null'
# ── the bridge, the snapshot and the cut (the cut script is a stub that logs) ──
t "snapshot while the guardians run" 1 "bridge-stop first" env CHAIN21_RPC=http://127.0.0.1:8545 "$F" snapshot "$T/snap"
t "bridge-stop without RELAYER_HOST" 1 "RELAYER_HOST is unset" "$F" bridge-stop
t "bridge-stop (guardians + the relayer)" 0 "BRIDGE-STOP DONE" env RELAYER_HOST=192.0.2.150 RELAYER_SSH_KEY="$T/key/rel" "$F" bridge-stop
chk "…six guardians and the relayer inactive" '[ "$(cat $H/192.0.2.10{1..6}/state/rand-guardian | sort -u)" = inactive ] && [ "$(cat $H/192.0.2.150/state/rand-relayer)" = inactive ]'
t "snapshot without CHAIN21_RPC" 1 "CHAIN21_RPC is unset" "$F" snapshot "$T/snap"
t "snapshot" 0 "rand-guardian inactive" env CHAIN21_RPC=http://127.0.0.1:8545 "$F" snapshot "$T/snap"
chk "…the cut script ran snapshot with PRUNED_SCAN_OK=1 and no DRY_RUN" 'grep -q "^STUB snapshot $T/snap PRUNED_SCAN_OK=1 .* DRY_RUN= WALLET=" $T/stub.log'
# constraint set 11: balances and the cut take chain 21's rand (WALLET) AND v0.8.7's (WALLET22)
t "balances without WALLET22" 1 "WALLET22=<unset> is not executable — the v0.8.7 rand" env CHAIN21_RPC=http://127.0.0.1:8545 WALLET="$BIN/old/rand" WALLET22= "$F" balances "$T/snap"
t "balances without WALLET" 1 "WALLET=<unset> is not executable — chain 21's" env CHAIN21_RPC=http://127.0.0.1:8545 WALLET= WALLET22="$BIN/new/rand" "$F" balances "$T/snap"
t "balances with chain 21's rand as WALLET22" 1 "WALLET and WALLET22 are the same binary" env CHAIN21_RPC=http://127.0.0.1:8545 WALLET="$BIN/old/rand" WALLET22="$BIN/old/rand" "$F" balances "$T/snap"
t "balances" 0 "inactive" env CHAIN21_RPC=http://127.0.0.1:8545 WALLET="$BIN/old/rand" WALLET22="$BIN/new/rand" "$F" balances "$T/snap"
chk "…with PRUNED_SCAN_OK=1 and both wallets passed through" 'grep -q "^STUB balances $T/snap PRUNED_SCAN_OK=1 .* WALLET=$BIN/old/rand WALLET22=$BIN/new/rand$" $T/stub.log'
chk "…and the roll record names WALLET22's sha256 (set 11)" 'grep -q "balances with PRUNED_SCAN_OK=1, WALLET22 sha256 $(cut -c1-16 <<<"$NEW_SHA_WALLET") (set 11), WALLET sha256 $(cut -c1-16 <<<"$OLD_SHA_WALLET")" "$ROLL_RECORD"'
export WALLET="$BIN/old/rand" WALLET22="$BIN/new/rand"
t "the cut without WALLET22" 1 "WALLET22=<unset> is not executable" env WALLET22= "$F" cut
t "a cut the cut script refuses" 1 "refused" env STUB_RC=1 "$F" cut
grep -v '^nyc2 ' "$BEACON_TSV" > "$T/beacon-24.tsv"
t "the cut with a BEACON_TSV missing a validator" 1 "does not name exactly chain 22's 25" env BEACON_TSV="$T/beacon-24.tsv" "$F" cut
t "the cut" 0 "(stub) ran: cut" "$F" cut
chk "…the cut script ran with PRUNED_SCAN_OK=1, the collected BEACON_TSV and both wallets" 'tail -1 $T/stub.log | grep -q "^STUB  PRUNED_SCAN_OK=1 BEACON_TSV=$BEACON_TSV NODE=.* DRY_RUN= WALLET=$BIN/old/rand WALLET22=$BIN/new/rand$"'
unset WALLET WALLET22
# The genesis files the cut would have written: chain 22's shape, the collected commitments.
cat > "$T/mkgen.py" <<'PY'
import json, sys
out, tsv, ts, variant = sys.argv[1:5]
pins = ["4dc1f18bdd6d9104ba1622710cf2c146f71759676dbdcb70dad036152242e8b4", "6392e5e9b7348f3729ba2031e0e3ec9788d6ed62a14521526482c92615f55106",
        "c31636aa281004163e6fe0debd81854f11d7bca6c8062a91b1501c7e593e5bf0", "ae3d0dc276061fd2a87b2e91b239f6dcccb746b49dedeecfdb2aab977c95c370"]
rows = [l.split() for l in open(tsv) if l.strip() and not l.startswith("#")]
g = {"chain_id": 22, "timestamp_ms": int(ts), "validators": [{"public_key": "pk-" + n} for n, _ in rows],
     "bridge": {"burn_sequence": 14}, "tokens": {"tokens": [{"backings": [{"locked": "100001999"}, {"locked": "0"}]}]},
     "max_proof_bytes": 6291456, "max_block_bytes": 19922944,
     "perps": {"engine_program_log_height": 14, "state_proof_keys": [{"tier": 18, "public_log_height": 7 + i, "sha256": p} for i, p in enumerate(pins)]},
     "hc_auth_multisig": "41db73c507ab1f24ebe76d9c425b42a08ed9a02b4b1284d410502729ce6b9cd1",
     "beacon": {"commit_delay_blocks": 256, "commitments": [{"validator": "addr-" + n, "commitment": c} for n, c in rows]}}
if variant == "chain21": g["chain_id"] = 21
if variant == "badhc": g["hc_auth_multisig"] = "9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247"
if variant == "nopvk": del g["perps"]["state_proof_keys"]
if variant == "nobeacon": del g["beacon"]
if variant == "otherbeacon": g["beacon"]["commitments"][4]["commitment"] = "22" * 32
json.dump(g, open(out, "w"), indent=1)
PY
G=$T/genesis-chain22.json; GB=$T/genesis-chain22-B.json
python3 "$T/mkgen.py" "$G" "$BEACON_TSV" 1763600000000 ok; python3 "$T/mkgen.py" "$GB" "$BEACON_TSV" 1763600099000 ok
for v in chain21 badhc nopvk nobeacon otherbeacon; do python3 "$T/mkgen.py" "$T/g-$v.json" "$BEACON_TSV" 1763600000000 $v; done
H22=$(hash_of "$G"); H22B=$(hash_of "$GB"); P=${H22:0:8}; PB=${H22B:0:8}
# ── push, chain 21 still running ──
t "push without LOCAL_NODE" 1 "LOCAL_NODE is unset" env "${NEWENV[@]}" "$F" push "$G"
t "push with chain 21's v0.8.6 as LOCAL_NODE" 1 "nothing done" env "${NEWENV[@]}" LOCAL_NODE="$BIN/old/rand-node" "$F" push "$G"
t "push of a chain-21 genesis" 1 "has chain_id 21, not 22" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$T/g-chain21.json"
t "push of a genesis with chain 21's msauth guest" 1 "not constraint set 11's" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$T/g-badhc.json"
t "push of a genesis without the pinned perps keys" 1 "CON-601" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$T/g-nopvk.json"
t "push of a genesis without a beacon" 1 "has no beacon section" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$T/g-nobeacon.json"
t "push of a genesis cut from other commitments than the hosts gave" 1 "(beacon-collect)" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$T/g-otherbeacon.json"
t "push with a LOCAL_NODE whose init says constraint set 9" 1 "the binary was not built from this tree" env "${NEWENV[@]}" "${LN[@]}" REHEARSE_SET=9 "$F" push "$G"
t "push with no cut record" 1 "no cut record" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$G"
record ""
t "push with the record's second-hash empty" 1 "no 'second-hash:' line" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$G"
record "$H22B"
t "push with the second operator's hash differing" 1 "differ" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$G"
chk "…nothing copied" '! ls $H/*/root/stage-c22/genesis-chain22.json >/dev/null 2>&1'
record "$H22"
t "push when one host's staged binary writes constraint set 9" 1 "not constraint set 11" env "${NEWENV[@]}" "${LN[@]}" REHEARSE_SET=9 REHEARSE_SET_HOST=192.0.2.7 "$F" push "$G"
t "push of the chain-22 genesis while chain 21 runs" 0 "PUSHED — chain 21 still runs" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$G"
has "…the constraint set: LOCAL_NODE 11 = this tree = the vendored zkVM" "LOCAL_NODE 11 = this tree = the vendored zkVM; chain 22's row is (22, \"$H22\", 11),"
has "…and the row is not committed yet (check-limits / verify will refuse)" "does not hold (22, \"$H22\", 11), yet"
chk "25 hosts hold the genesis, byte-identical; all 25 still active" '[ "$(shasum -a 256 $H/*/root/stage-c22/genesis-chain22.json | cut -d" " -f1 | sort -u)" = "$(sha $G)" ] && [ "$(ls $H/*/root/stage-c22/genesis-chain22.json | wc -l | tr -d " ")" = 25 ] && [ "$(active)" = 25 ]'
t "start with no marker" 1 "no switched-<P> / rollback-* marker" "$F" start
t "switch while the fleet still runs" 1 "some hosts are not ready" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" switch "$G"
chk "…installed nothing, no marker" '[ "$(units)" = "$U0" ] && [ "$(installed rand-node)" = "25:$OLD_SHA " ] && [ "$(nmark)" = 0 ]'
# ── the halt guard ──
N0=$(sshn)
t "stop without CONFIRM_HALT_CHAIN21" 1 "REFUSED — this halts chain 21 on all 25 hosts" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" stop "$G"
has "…and names the phrase, bound to this genesis" "CONFIRM_HALT_CHAIN21=halt-chain-21-for-$P"
t "stop with CONFIRM_HALT_CHAIN21=yes" 1 "got 'yes'" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" CONFIRM_HALT_CHAIN21=yes "$F" stop "$G"
t "stop with the phrase of ANOTHER genesis (a re-cut's)" 1 "REFUSED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" CONFIRM_HALT_CHAIN21="halt-chain-21-for-$PB" "$F" stop "$G"
chk "…the refused stops contacted no host and stopped nothing" '[ "$(sshn)" = "$N0" ] && [ "$(active)" = 25 ]'
GO=(CONFIRM_HALT_CHAIN21="halt-chain-21-for-$P")
# ── the gated stop ──
mv "$H/192.0.2.14/root/stage-c22/genesis-chain22.json" "$T/g.aside"
t "stop when one host lacks the pushed genesis" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$G"
has "…that host says so" "the chain-22 genesis is not pushed here"
mv "$T/g.aside" "$H/192.0.2.14/root/stage-c22/genesis-chain22.json"
mv "$(bdir 192.0.2.9)/beacon.seed.json" "$T/seed.aside"
t "stop when one validator has no beacon seed" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$G"
has "…that host's beacon check refused" "beacon seed NOT verified"
mv "$T/seed.aside" "$(bdir 192.0.2.9)/beacon.seed.json"
cp "$(bdir 192.0.2.10)/beacon.seed.json" "$T/s10.keep"; cp "$(bdir 192.0.2.11)/beacon.seed.json" "$(bdir 192.0.2.10)/beacon.seed.json"
t "stop when one validator's seed is another host's" 1 "a seed file copied from another host" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$G"
cp "$T/s10.keep" "$(bdir 192.0.2.10)/beacon.seed.json"; chmod 600 "$(bdir 192.0.2.10)/beacon.seed.json"
echo active > "$H/192.0.2.104/state/rand-guardian"
t "stop while one guardian's rand-guardian runs" 1 "rand-guardian still active" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$G"
echo inactive > "$H/192.0.2.104/state/rand-guardian"
cp "$TESTBLOB" "$H/192.0.2.13/usr/local/bin/msauth-vk-production.bin"
t "stop while one host's installed msauth blob is not chain 21's" 1 "switch would refuse to back it up" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$G"
cp "$OLDBLOB" "$H/192.0.2.13/usr/local/bin/msauth-vk-production.bin"
cp "$KEYS/$PVK8" "$H/192.0.2.16/root/stage-c22/$PVK7"
t "stop when one host's staged perps key changed since stage" 1 "NOTHING STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$G"
cp "$KEYS/$PVK7" "$H/192.0.2.16/root/stage-c22/$PVK7"
chk "…all 25 still active after every refused stop" '[ "$(active)" = 25 ]'
t "stop (the phrase given; gated: all 25 ready)" 0 "STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$G"
has "…every validator's seed opened its genesis commitment before the halt" "beacon ok"
chk "all 25 inactive" '[ "$(active)" = 0 ]'
# ── switch ──
record ""
t "switch with the record's second-hash blanked after push" 1 "no 'second-hash:' line" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" switch "$G"
record "$H22"
t "switch without v0.8.6's pins" 1 "OLD_SHA / OLD_SHA_WALLET" env "${NEWENV[@]}" "${LN[@]}" "$F" switch "$G"
cp "$KEYS/$PVK8" "$H/192.0.2.5/root/stage-c22/$PVK7"
cp "$BIN/badrel/rand-node" "$H/192.0.2.12/usr/local/bin/rand-node"
t "switch with host 5's staged perps key replaced and host 12 not on v0.8.6" 1 "rollback → start → wait21" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" switch "$G"
has "…host 5: its staged key is not the pinned file (before anything)" "staged $PVK7 is not the pinned v0.8.7 file"
has "…host 12 made no backup" "no backup made"
chk "…host 5 installed nothing: still v0.8.6, chain 21's blob, no perps key, unit on chain 21; no marker" '[ "$(sha $H/192.0.2.5/usr/local/bin/rand-node)" = "$OLD_SHA" ] && [ "$(sha $H/192.0.2.5/usr/local/bin/msauth-vk-production.bin)" = "$OLD_VK" ] && ! ls $H/192.0.2.5/usr/local/bin/perp-vk-* >/dev/null 2>&1 && grep -q -- "-ca76c276 " $H/192.0.2.5/etc/systemd/system/rand-node.service && [ "$(nmark)" = 0 ]'
chk "…host 12's unit still names chain 21, no .pre-c22 there" '[ ! -e $H/192.0.2.12/root/rand-node.pre-c22 ] && grep -q -- "-ca76c276 " $H/192.0.2.12/etc/systemd/system/rand-node.service'
cp "$KEYS/$PVK7" "$H/192.0.2.5/root/stage-c22/$PVK7"; cp "$BIN/old/rand-node" "$H/192.0.2.12/usr/local/bin/rand-node"
t "switch with the staged binary pinning another perps key (every host re-checks before anything)" 1 "perps keys NOT verified" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" REHEARSE_PVK_PIN="$(sha "$TESTBLOB")" "$F" switch "$G"
chk "…host 5 still installed nothing" '[ "$(sha $H/192.0.2.5/usr/local/bin/rand-node)" = "$OLD_SHA" ] && [ "$(nmark)" = 0 ]'
echo active > "$H/192.0.2.102/state/rand-guardian"
t "switch with a rand-guardian still active" 1 "rand-guardian still active" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" switch "$G"
t "start after a failed switch" 1 "refusing" "$F" start
echo inactive > "$H/192.0.2.102/state/rand-guardian"
t "switch (re-run over the hosts already switched)" 0 "SWITCHED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" switch "$G"
has "…each host's beacon seed checked in its new datadir" "beacon ok"
chk "one marker, switched-$P" '[ "$(nmark)" = 1 ] && [ -f $T/markers/switched-$P ]'
chk "every host runs v0.8.7 + the set-11 blob + the four perps keys beside the binary" '[ "$(installed rand-node)" = "25:$NEW_SHA " ] && [ "$(installed rand)" = "25:$NEW_SHA_WALLET " ] && [ "$(installed msauth-vk-production.bin)" = "25:$VK_SHA " ] && for f in $KEYS/perp-vk-production-*.bin; do [ "$(installed $(basename $f))" = "25:$(sha $f) " ] || exit 1; done'
chk "…and kept v0.8.6's rand-node, rand AND chain 21's msauth blob as *.pre-c22 (the rollback)" '[ "$(sha $H/192.0.2.*/root/rand-node.pre-c22 | sort -u)" = "$OLD_SHA" ] && [ "$(sha $H/192.0.2.*/root/rand.pre-c22 | sort -u)" = "$OLD_SHA_WALLET" ] && [ "$(for h in $H/192.0.2.{1..19} $H/192.0.2.10{1..6}; do sha $h/root/msauth-vk-production.bin.pre-c22; done | sort -u)" = "$OLD_VK" ]'
chk "19 node units name -$P, none -ca76c276; each new datadir initialised with constraint-set 11" '[ "$(grep -l -- "-$P " $H/192.0.2.{1..19}/etc/systemd/system/rand-node.service | wc -l | tr -d " ")" = 19 ] && ! grep -q -- "-ca76c276 " $H/192.0.2.{1..19}/etc/systemd/system/rand-node.service && [ "$(cat $H/192.0.2.{1..19}/root/data-*-$P/constraint-set $H/192.0.2.10{1..6}/var/lib/randnode/data-22/constraint-set | sort -u)" = 11 ]'
chk "the archives e and obs1 got their chain-22 datadir on the volume" '[ -L $H/$(ip_of e)/root/data-rand-node-e-$P ] && [ -d $H/$(ip_of e)/mnt/volume/root/data-rand-node-e-$P/db ] && [ -d $H/$(ip_of obs1)/mnt/volume/root/data-obs1-$P/db ]'
chk "each validator's new datadir holds ITS OWN staging seed (0600), byte-identical, nowhere else" 'for i in $(seq 1 19) 101 102 103 104 105 106; do case $i in 10?) d=$H/192.0.2.$i/var/lib/randnode/data-22;; *) d=$(ls -d $H/192.0.2.$i/root/data-*-$P);; esac; cmp -s $(bdir 192.0.2.$i)/beacon.seed.json $d/beacon.seed.json && [ "$(stat -f %Lp $d/beacon.seed.json)" = 600 ] || exit 1; done'
chk "chain-21 datadirs untouched; node unit backups kept" '[ "$(ls -d $H/192.0.2.{1..19}/root/data-*-ca76c276/db | wc -l | tr -d " ")" = 19 ] && [ "$(ls $H/192.0.2.{1..19}/root/rand-node.service.ca76c276.bak | wc -l | tr -d " ")" = 19 ] && [ -d $H/192.0.2.106/var/lib/randnode/data-21/db ]'
chk "6 guardian hosts: chain22.conf on data-22, chain21.conf moved aside, stamp = the genesis" '[ "$(grep -l -- "/data-22 " $H/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain22.conf | wc -l | tr -d " ")" = 6 ] && ! ls $H/192.0.2.10{1..6}/etc/systemd/system/rand-node.service.d/chain21.conf >/dev/null 2>&1 && [ "$(ls $H/192.0.2.10{1..6}/root/chain21.conf.c21 | wc -l | tr -d " ")" = 6 ] && [ "$(cat $H/192.0.2.10{1..6}/var/lib/randnode/data-22.genesis | sort -u)" = "$H22" ]'
# ── start: the first group (23 ≥ quorum 17), the gates ──
cp "$KEYS/$PVK8" "$H/192.0.2.15/usr/local/bin/$PVK7"
t "start with one host's installed perps key not the pinned one" 1 "nothing started" "$F" start
has "…that host's key check says so" "perps key NOT verified"
cp "$KEYS/$PVK7" "$H/192.0.2.15/usr/local/bin/$PVK7"
D6=$(ls -d "$H"/192.0.2.6/root/data-*-"$P"); cp "$D6/beacon.seed.json" "$T/d6.keep"; cp "$(bdir 192.0.2.7)/beacon.seed.json" "$D6/beacon.seed.json"
t "start with one validator's datadir seed swapped for another host's" 1 "nothing started" "$F" start
has "…its beacon check names the copy" "a seed file copied from another host"
cp "$T/d6.keep" "$D6/beacon.seed.json"; chmod 600 "$D6/beacon.seed.json"
echo 9 > "$D6/constraint-set"
t "start with one datadir's constraint-set marker at 9" 1 "not constraint set 11" "$F" start
echo 11 > "$D6/constraint-set"
chk "…no node started anywhere, the marker kept" '[ "$(active)" = 0 ] && [ -f $T/markers/switched-$P ]'
touch "$H/$(ip_of lon1)/state/refuse-start"
t "start with one first-group host that does not come up" 1 "NOT STARTED on: lon1" "$F" start
has "…22 of 23 active: still above the quorum" "22 of 23 active (≥ quorum 17: chain 22 can commit)"
chk "…22 active, the marker KEPT" '[ "$(active)" = 22 ] && [ -f $T/markers/switched-$P ]'
rm "$H/$(ip_of lon1)/state/refuse-start"
t "start again once that host is fixed" 0 "START-DONE" "$F" start
chk "the first group (23) active, e and obs1 NOT yet; marker first-$P" '[ "$(active)" = 23 ] && [ "$(cat $H/$(ip_of e)/state/rand-node)" = inactive ] && [ "$(cat $H/$(ip_of obs1)/state/rand-node)" = inactive ] && [ -f $T/markers/first-$P ] && [ ! -e $T/markers/switched-$P ]'
t "a second start" 1 "refusing" "$F" start
t "start-archives before check-limits" 1 "run check-limits against c first" "$F" start-archives
t "check-limits the cut script refuses" 1 "the archives are not started" env "${LN[@]}" STUB_LIMITS_RC=1 "$F" check-limits "$G"
t "check-limits" 0 "CHECK-LIMITS OK" env "${LN[@]}" "$F" check-limits "$G"
chk "…the cut script's check-limits ran against the first node with NODE=LOCAL_NODE" 'tail -1 $T/stub.log | grep -q "^STUB check-limits $CHECK_LIMITS_RPC $G .*NODE=$BIN/new/rand-node"'
t "start-archives" 0 "START-ARCHIVES-DONE" "$F" start-archives
chk "all 25 active; no marker left" '[ "$(active)" = 25 ] && [ "$(nmark)" = 0 ]'
t "wait" 0 "CUTOVER DONE: all 25 on $H22" env "${LN[@]}" "$F" wait "$G"
has "…every validator's seed against its running node (--rpc)" "beacon seed opens the commitment in force"
mv "$H/192.0.2.17/usr/local/bin/$PVK10" "$T/pvk.aside"
t "wait with one node's perps key gone (perps_keys absent)" 1 "24/25 on chain 22" env "${LN[@]}" WAIT_TRIES=2 "$F" wait "$G"
has "…and names it" "not yet: mkc1"
mv "$T/pvk.aside" "$H/192.0.2.17/usr/local/bin/$PVK10"
t "bridge-start without BRIDGE_ON_CHAIN22=yes" 1 "BRIDGE_ON_CHAIN22=yes is required" env RELAYER_HANDLED=yes "$F" bridge-start
t "bridge-start" 0 "BRIDGE-START DONE" env BRIDGE_ON_CHAIN22=yes RELAYER_HOST=192.0.2.150 RELAYER_SSH_KEY="$T/key/rel" "$F" bridge-start
chk "…six guardians and the relayer active" '[ "$(cat $H/192.0.2.10{1..6}/state/rand-guardian | sort -u)" = active ] && [ "$(cat $H/192.0.2.150/state/rand-relayer)" = active ]'
t "verify without the CHAIN_CONSTRAINT_SETS row" 1 "does not hold chain 22's row" env "${LN[@]}" "$F" verify "$G"
sed "s/^    (21, \"ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a\", 9),\$/&\\
    (22, \"$H22\", 11),/" "$T/cs/no-row.rs" > "$T/cs/row.rs"
t "verify with the row committed" 0 "VERIFIED" env "${LN[@]}" CONSTRAINT_SET_RS="$T/cs/row.rs" "$F" verify "$G"
t "status" 0 "archive2: dropped, not contacted" "$F" status
t "quiet: nothing burned or minted on chain 22" 0 "QUIET" "$F" quiet "$G"
t "quiet when a deposit was minted" 1 "NOT the genesis values" env REHEARSE_MINTED=5 "$F" quiet "$G"
# ── a re-cut over a switched fleet, without a rollback, is refused ──
t "halt with an active host that serves chain 21's genesis" 1 "SERVES CHAIN 21" env REHEARSE_SERVE_OLD=192.0.2.9 "$F" halt
t "halt the chain-22 fleet" 0 "HALTED" "$F" halt
record "$H22B"
t "push of a re-cut while chain 22 is down" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$GB"
UB=$(units)
t "switch to a re-cut over the switched fleet (no rollback)" 1 "needs rollback first" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" switch "$GB"
chk "…no unit changed, no marker" '[ "$(units)" = "$UB" ] && [ "$(nmark)" = 0 ]'
# ── rollback ──
t "rollback while a guardian runs" 1 "rand-guardian still active" env "${OLDENV[@]}" "$F" rollback
t "bridge-stop before the rollback" 0 "BRIDGE-STOP DONE" env RELAYER_HANDLED=yes "$F" bridge-stop
t "rollback" 0 "ROLLED BACK" env "${OLDENV[@]}" "$F" rollback
chk "every unit / drop-in is byte for byte chain 21's again; v0.8.6 binaries and CHAIN 21's msauth blob restored" '[ "$(units)" = "$U0" ] && [ "$(installed rand-node)" = "25:$OLD_SHA " ] && [ "$(installed rand)" = "25:$OLD_SHA_WALLET " ] && [ "$(installed msauth-vk-production.bin)" = "25:$OLD_VK " ]'
t "start after rollback (all 25, C and D first, no chain-22 gate)" 0 "all 25 active on chain 21" "$F" start
hasnt "…the chain-22 start gate was skipped" "the start gate"
t "wait21: chain 21 on all 25, C's height moves" 0 "CHAIN 21 COMMITTING AGAIN" "$F" wait21
t "rollback while running" 1 "STILL RUNNING" env "${OLDENV[@]}" "$F" rollback
t "preflight after the rollback flags the leftovers (*.pre-c22, data-22)" 1 "not every host is ready" env "${OLDENV[@]}" "${NEWENV[@]}" "$F" preflight
# ── the re-cut, in order: push (chain 21 running), stop, switch, start, … — the seeds are reused ──
record "$H22B"
t "push of the re-cut while chain 21 runs" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" "$F" push "$GB"
t "stop for the re-cut with the FIRST cut's phrase" 1 "REFUSED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "${GO[@]}" "$F" stop "$GB"
t "stop for the re-cut (its own phrase)" 0 "STOPPED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" CONFIRM_HALT_CHAIN21="halt-chain-21-for-$PB" "$F" stop "$GB"
t "switch to the re-cut (guardians still hold the first cut's data-22)" 0 "SWITCHED" env "${NEWENV[@]}" "${OLDENV[@]}" "${LN[@]}" "$F" switch "$GB"
chk "each guardian host moved the first cut's data-22 aside and initialised a fresh one, with the same seed" '[ "$(ls -d $H/192.0.2.10{1..6}/var/lib/randnode/data-22.stale-$P/db | wc -l | tr -d " ")" = 6 ] && [ "$(cat $H/192.0.2.10{1..6}/var/lib/randnode/data-22.genesis | sort -u)" = "$H22B" ] && for g in 1 2 3 4 5 6; do cmp -s $H/192.0.2.10$g/var/lib/randnode/beacon-c22/beacon.seed.json $H/192.0.2.10$g/var/lib/randnode/data-22/beacon.seed.json || exit 1; done'
chk "…v0.8.7 installed again over the restored v0.8.6, keeping the one set of backups" '[ "$(installed rand-node)" = "25:$NEW_SHA " ] && [ "$(sha $H/192.0.2.*/root/rand-node.pre-c22 | sort -u)" = "$OLD_SHA" ] && [ "$(for h in $H/192.0.2.{1..19}; do sha $h/root/msauth-vk-production.bin.pre-c22; done | sort -u)" = "$OLD_VK" ]'
t "start on the re-cut" 0 "START-DONE" "$F" start
t "check-limits on the re-cut" 0 "CHECK-LIMITS OK" env "${LN[@]}" "$F" check-limits "$GB"
t "start-archives on the re-cut" 0 "START-ARCHIVES-DONE" "$F" start-archives
t "wait on the re-cut" 0 "CUTOVER DONE: all 25 on $H22B" env "${LN[@]}" "$F" wait "$GB"
# ── the waiver ──
record ""
t "push with SECOND_REBUILD_WAIVED=1 records the waiver" 0 "PUSHED" env "${NEWENV[@]}" "${LN[@]}" SECOND_REBUILD_WAIVED=1 "$F" push "$GB"
chk "…once" '[ "$(grep -c "^second-rebuild-waived: .*genesis $H22B" $CUT_RECORD)" = 1 ]'
# ── archive2, the record ──
chk "archive2 was NEVER contacted: the fake ssh/scp were not once asked for its address ($(sshn) ssh/scp calls in all)" '[ "$(sshn)" -gt 1000 ] && ! grep -qx "$ARCHIVE2_IP" $T/ssh.log && [ ! -e $H/$ARCHIVE2_IP ]'
chk "the roll record names every phase that changed something, and no address" 'for p in stage beacon-init beacon-collect bridge-stop push stop switch start check-limits start-archives wait bridge-start verify halt rollback wait21; do grep -q "^$p: " $ROLL_RECORD || { echo "no $p: line"; exit 1; }; done && ! grep -q "192\.0\.2\." $ROLL_RECORD && grep -q "^skipped: archive2" $ROLL_RECORD && grep -q "CHAIN 22 LIVE" $ROLL_RECORD && grep -q "CONFIRM_HALT_CHAIN21 given" $ROLL_RECORD'
echo "fleet rehearsal (chain 22): $pass passed, $fail failed"
[ $fail = 0 ]
