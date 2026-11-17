# shellcheck shell=bash
# Sourced by the deploy selftests only (audit v14: PROC-701, PROC-751). A sandbox in which the
# commands the roll scripts send to a host are RUN, so a selftest can assert on what a host would
# hold afterwards (files, the limits systemd loaded, the binary installed) instead of on the text
# that was sent. Until v0.8.6 the selftest's ssh stub recorded each remote command and ran none:
# an install step sent inside `if false; then … fi` stayed green.
#
# No host, network or real unit directory is touched. Each "host" is a directory:
#
#   $SANDBOX/hosts/<name>/            the host's root: etc/systemd/system, usr/local/bin, root
#   $SANDBOX/bin/{ssh,scp,launchctl}  put first on PATH of the script under test
#   $SANDBOX/hostbin/…                what a host's own commands resolve to: systemctl, curl, sleep,
#                                     hostname, cargo, sed, install (and sha256sum where the OS
#                                     has none)
#
# The ssh stub takes the remote command (its last argument), rewrites the three absolute roots the
# deploy scripts use (/etc/systemd/system, /usr/local/bin, /root) to the host's directory, and runs
# it with bash there; its output and exit status are the "host's". A host with no directory, or
# with a file DOWN in it, is unreachable (exit 255). scp copies between those directories.
#
# The rewrite is textual, so a path it does not know would be the real one: the sandbox refuses to
# start as root, and the stubs fail closed when SANDBOX is unset.
#
#   sandbox_init DIR                 create the stubs under DIR (exports SANDBOX)
#   sandbox_host NAME [DATADIR]      create host NAME: a rand-node unit, an empty drop-in directory,
#                                    service active, limits "loaded" as systemd would have them
#   sandbox_fake_bins DIR TAG        write runnable stand-ins DIR/rand-node and DIR/rand (their
#                                    sha256 differs by TAG)
#   sandbox_root NAME                print the host's root directory
#   sandbox_run_script NAME FILE [ARGS…]   run a script meant to run ON a host (vps-setup.sh) there
#   sandbox_env CMD…                 run CMD with the ssh/scp/launchctl stubs first on PATH
#
# The fake systemctl keeps what systemd would: `daemon-reload` reads the unit's drop-ins in name
# order (the last LimitNOFILE / MemoryHigh wins, spaces round `=` allowed) into loaded-*; `start`
# and `restart` copy LimitNOFILE to running-nofile — LimitNOFILE applies at a start, and only as of
# the last reload. So "the node runs with the new limit" is a file to compare, and a drop-in
# written without a reload, or after the restart, shows.
#
# The fake node answers rand_status over the fake curl: every call moves the sandbox's chain one
# block (chain-height); a host reports that height less its lag, and its peers, from the lines of
# rpc/seq ("<lag> <peers>", one per poll since its last start, the last line repeating; "-" is no
# answer; no file: lag 0, 12 peers). A stopped service refuses the connection. A file
# $SANDBOX/chain-halted stops the chain: every node then answers the same height for ever.

sandbox_init() {
  SANDBOX=$1; export SANDBOX
  if [ "$(id -u)" = 0 ]; then
    echo "host-sandbox: refusing to run as root — the sandbox rewrites paths in text, and one it missed would be this machine's" >&2
    return 1
  fi
  mkdir -p "$SANDBOX/bin" "$SANDBOX/hostbin" "$SANDBOX/hosts" "$SANDBOX/rec"
  : > "$SANDBOX/rec.idx"; : > "$SANDBOX/events.log"; echo 1000 > "$SANDBOX/chain-height"

  cat > "$SANDBOX/bin/sandbox-rewrite" <<'STUB'
#!/usr/bin/env bash
# stdin → stdout, the deploy scripts' absolute roots moved under $SANDBOX_ROOT (one pass, so a
# rewritten path is never rewritten again).
[ -n "${SANDBOX_ROOT:-}" ] || { echo "sandbox-rewrite: SANDBOX_ROOT is unset" >&2; exit 1; }
exec perl -pe 's{(?<![\w./])(/etc/systemd/system|/usr/local/bin|/root)(?![\w.-])}{$ENV{SANDBOX_ROOT}$1}g'
STUB

  cat > "$SANDBOX/bin/ssh" <<'STUB'
#!/usr/bin/env bash
# The remote command is the last argument; the host is the root@ one. Record both, then RUN the
# command in the host's sandbox directory.
[ -n "${SANDBOX:-}" ] || { echo "ssh stub: SANDBOX is unset" >&2; exit 255; }
cmd=${!#}; host=; for a in "$@"; do case "$a" in root@*) host=${a#root@} ;; esac; done
f=$(mktemp "$SANDBOX/rec/c.XXXXXX"); printf '%s\n%s' "$host" "$cmd" > "$f"; echo "$f" >> "$SANDBOX/rec.idx"
root="$SANDBOX/hosts/$host"
if [ -z "$host" ] || [ ! -d "$root" ] || [ -e "$root/DOWN" ]; then
  echo "ssh: connect to host $host: unreachable (sandbox)" >&2; exit 255
fi
export SANDBOX_ROOT="$root" SANDBOX_HOST="$host"
script=$(printf '%s\n' "$cmd" | "$SANDBOX/bin/sandbox-rewrite") || exit 255
cd "$root/root" || exit 255
PATH="$SANDBOX/hostbin:$PATH" HOME="$root/root" exec bash -c "$script" </dev/null
STUB

  cat > "$SANDBOX/bin/scp" <<'STUB'
#!/usr/bin/env bash
# root@<host>:<path> is <host's sandbox directory><path>; everything else is a local path.
[ -n "${SANDBOX:-}" ] || { echo "scp stub: SANDBOX is unset" >&2; exit 1; }
args=()
while [ $# -gt 0 ]; do
  case "$1" in -o) shift ;; -*) ;; *) args+=("$1") ;; esac
  shift
done
map() {
  case "$1" in
    root@*:*) h=${1#root@}; p=${h#*:}; h=${h%%:*}
      { [ -d "$SANDBOX/hosts/$h" ] && [ ! -e "$SANDBOX/hosts/$h/DOWN" ]; } || { echo "scp: $h: unreachable (sandbox)" >&2; return 1; }
      echo "scp $h" >> "$SANDBOX/events.log"
      echo "$SANDBOX/hosts/$h$p" ;;
    *) echo "$1" ;;
  esac
}
n=${#args[@]}; [ "$n" -ge 2 ] || exit 1
dest=$(map "${args[$((n-1))]}") || exit 1
i=0; while [ "$i" -lt $((n-1)) ]; do
  src=$(map "${args[$i]}") || exit 1
  cp "$src" "$dest" || exit 1
  i=$((i+1))
done
STUB

  printf '#!/bin/sh\nexit 0\n' > "$SANDBOX/bin/launchctl"

  cat > "$SANDBOX/hostbin/systemctl" <<'STUB'
#!/usr/bin/env bash
r=${SANDBOX_ROOT:?}; unit_dir="$r/etc/systemd/system"
echo "$*" >> "$r/systemctl.log"; echo "$SANDBOX_HOST systemctl $*" >> "$SANDBOX/events.log"
verb=${1:-}; svc=rand-node
for a in "$@"; do case "$a" in -*|"$verb") ;; *) svc=${a%.service} ;; esac; done
shopt -s extglob
# What systemd would hold for a key after a reload: the unit, then its drop-ins in name order.
effective() {
  local key=$1 f v=
  for f in "$unit_dir/$svc.service" "$unit_dir/$svc.service.d"/*.conf; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
      case "$line" in
        *([[:space:]])"$key"*([[:space:]])=*) v=${line#*=}; v=${v#"${v%%[![:space:]]*}"} ;;
      esac
    done < "$f"
  done
  echo "$v"
}
case "$verb" in
  daemon-reload) effective LimitNOFILE > "$r/loaded-nofile"; effective MemoryHigh > "$r/loaded-memoryhigh" ;;
  stop) echo inactive > "$r/state" ;;
  start|restart)
    [ -f "$unit_dir/$svc.service" ] || { echo "Unit $svc.service not found." >&2; exit 5; }
    echo active > "$r/state"; mkdir -p "$r/rpc"; echo 0 > "$r/rpc/polls"
    cp "$r/loaded-nofile" "$r/running-nofile" 2>/dev/null || : > "$r/running-nofile"
    sha256sum "$r/usr/local/bin/rand-node" 2>/dev/null | cut -d' ' -f1 > "$r/running-binary" ;;
  is-active) s=$(cat "$r/state" 2>/dev/null || echo inactive); echo "$s"; [ "$s" = active ] ;;
  cat) cat "$unit_dir/$svc.service" 2>/dev/null || exit 1
       for f in "$unit_dir/$svc.service.d"/*.conf; do [ -f "$f" ] && cat "$f"; done; exit 0 ;;
  disable) [ "$svc" = rand-node ] || exit 1 ;;
  enable|status|--no-pager) ;;
esac
exit 0
STUB

  cat > "$SANDBOX/hostbin/curl" <<'STUB'
#!/usr/bin/env bash
r=${SANDBOX_ROOT:?}
case "$*" in *rand_status*) ;; *) exit 0 ;; esac
[ "$(cat "$r/state" 2>/dev/null)" = active ] || exit 7
h=$(cat "$SANDBOX/chain-height")
[ -e "$SANDBOX/chain-halted" ] || { h=$((h + 1)); echo "$h" > "$SANDBOX/chain-height"; }
polls=$(( $(cat "$r/rpc/polls" 2>/dev/null || echo 0) + 1 )); mkdir -p "$r/rpc"; echo "$polls" > "$r/rpc/polls"
lag=0; peers=12
if [ -s "$r/rpc/seq" ]; then
  n=$(grep -c '' "$r/rpc/seq"); [ "$polls" -lt "$n" ] && n=$polls
  line=$(sed -n "${n}p" "$r/rpc/seq")
  [ "$line" = - ] && { echo "$SANDBOX_HOST probe none" >> "$SANDBOX/events.log"; exit 7; }
  lag=${line%% *}; peers=${line##* }
fi
echo "$SANDBOX_HOST probe $((h - lag)) $peers" >> "$SANDBOX/events.log"
printf '{"jsonrpc":"2.0","id":1,"result":{"chain_id":21,"height":%s,"view":%s,"peer_count":%s}}\n' "$((h - lag))" "$((h - lag + 3))" "$peers"
STUB

  printf '#!/bin/sh\nexit 0\n' > "$SANDBOX/hostbin/sleep"
  # A host with a file INSTALL-NOOP in its root "installs" nothing and says it did: the install
  # that did not take, which only a read-back of the installed binary's sha256 catches.
  real_install=$(command -v install)
  printf '#!/bin/sh\n[ -e "$SANDBOX_ROOT/INSTALL-NOOP" ] && exit 0\nexec %s "$@"\n' "$real_install" > "$SANDBOX/hostbin/install"
  printf '#!/bin/sh\nexit 0\n' > "$SANDBOX/hostbin/cargo"
  printf '#!/bin/sh\necho "rand-node-$SANDBOX_HOST"\n' > "$SANDBOX/hostbin/hostname"
  # GNU `sed -i SCRIPT FILE` (what the hosts run) on a BSD sed, which wants `-i ''`.
  real_sed=$(command -v sed)
  if sed --version >/dev/null 2>&1; then
    printf '#!/bin/sh\nexec %s "$@"\n' "$real_sed" > "$SANDBOX/hostbin/sed"
  else
    printf '#!/bin/sh\nif [ "$1" = -i ]; then shift; exec %s -i "" "$@"; fi\nexec %s "$@"\n' "$real_sed" "$real_sed" > "$SANDBOX/hostbin/sed"
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    printf '#!/bin/sh\nexec shasum -a 256 "$@"\n' > "$SANDBOX/hostbin/sha256sum"
  fi
  chmod +x "$SANDBOX/bin"/* "$SANDBOX/hostbin"/*
}

sandbox_root() { echo "$SANDBOX/hosts/$1"; }

sandbox_fake_bins() {
  local dir=$1 tag=$2
  mkdir -p "$dir"
  cat > "$dir/rand-node" <<BIN
#!/usr/bin/env bash
# sandbox stand-in for rand-node, build $tag
case "\${1:-}" in
  --version) echo "rand-node $tag" ;;
  init) d=; while [ \$# -gt 0 ]; do [ "\$1" = --datadir ] && d=\$2; shift; done; mkdir -p "\$d/db"; echo "genesis 0123456789abcdef0123456789abcdef" ;;
  keygen) f=; while [ \$# -gt 0 ]; do [ "\$1" = --out ] && f=\$2; shift; done; echo '{"sandbox":"key"}' > "\$f"; echo "wrote \$f" ;;
  address) echo rand1sandbox ;;
esac
BIN
  cat > "$dir/rand" <<BIN
#!/usr/bin/env bash
# sandbox stand-in for rand (the wallet), build $tag
case "\${1:-}" in status) printf '  "chain_id": 21,\n  "height": 1,\n  "peer_count": 12,\n' ;; esac
BIN
  chmod 755 "$dir/rand-node" "$dir/rand"
}

sandbox_host() {
  local name=$1 r
  r=$(sandbox_root "$name")
  mkdir -p "$r/etc/systemd/system/rand-node.service.d" "$r/usr/local/bin" "$r/root" "$r/rpc"
  local data=${2:-$r/root/data-$name}
  mkdir -p "$data"; echo '{"chain_id":21}' > "$data/genesis.json"
  # A path already inside the sandbox: file contents are not rewritten, only the commands sent.
  printf '%s\n' '[Unit]' "Description=RAND full node ($name)" '[Service]' \
    "ExecStart=$r/usr/local/bin/rand-node run --datadir $data --rpc 127.0.0.1:8545" \
    'Restart=always' > "$r/etc/systemd/system/rand-node.service"
  : > "$r/systemctl.log"; echo active > "$r/state"; echo 0 > "$r/rpc/polls"
  SANDBOX_ROOT="$r" SANDBOX_HOST="$name" PATH="$SANDBOX/hostbin:$PATH" systemctl daemon-reload
  cp "$r/loaded-nofile" "$r/running-nofile"
  : > "$r/systemctl.log"
}

sandbox_run_script() {
  local name=$1 file=$2 r; shift 2
  r=$(sandbox_root "$name")
  SANDBOX_ROOT="$r" "$SANDBOX/bin/sandbox-rewrite" < "$file" > "$r/root/.sandbox-script.sh" || return 1
  ( cd "$r/root" && SANDBOX_ROOT="$r" SANDBOX_HOST="$name" PATH="$SANDBOX/hostbin:$PATH" HOME="$r/root" \
      bash "$r/root/.sandbox-script.sh" "$@" </dev/null )
}

sandbox_env() { env PATH="$SANDBOX/bin:$PATH" SANDBOX="$SANDBOX" "$@"; }
