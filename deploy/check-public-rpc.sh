#!/usr/bin/env bash
# Check that a public RPC hop ends at the node's own public listener (VK-2, monorepo#17), and
# print a record of what was seen. Read-only: a handful of JSON-RPC calls, and with --local one
# `systemctl show`.
#
#   deploy/check-public-rpc.sh --url http://127.0.0.1:8546     # a listener, or the far end of a tunnel
#   deploy/check-public-rpc.sh --local [unit]                  # on the node: the unit, then 127.0.0.1:8546
#   deploy/check-public-rpc.sh --behind-proxy --url https://…  # through a proxy that has its own method list
#
# What passes:
#   - rand_chainId answers (the listener is up and is a rand-node);
#   - rand_getPeers, rand_mint, rand_importViewingKey, rand_getViewingNotes and
#     rand_removeViewingKey are each refused with the node's own words, "not served on this
#     node's public listener". A method that is *served*, or refused in any other words, fails:
#     the hop then ends at the operator listener (--rpc, 8545), where every proxied caller is
#     loopback and the viewing-key methods answer — the state VK-2 is about;
#   - a batch (a top-level array) is refused.
# With --behind-proxy a refusal in the proxy's words (-32601) passes too, and the record says
# `gate: proxy` for it: that shows the proxy's list, not where the hop ends, so also run the check
# without the flag against the tunnel's local end.
# With --local it first requires the unit to turn the listener on: `--public-rpc` in ExecStart,
# or RAND_NODE_PUBLIC_RPC in its environment (deploy/systemd/rand-node.service.d/60-public-rpc.conf).
#
# Exit 0 and a last line `public-rpc: ok` when everything passes; exit 1 and `public-rpc: FAIL`
# with one `fail:` line per reason otherwise. Keep the output: it is the deploy record's evidence.
set -uo pipefail
URL=""; LOCAL=0; UNIT=rand-node; PROXY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL=${2:?--url needs a value}; shift 2 ;;
    --local) LOCAL=1; shift; if [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; then UNIT=$1; shift; fi ;;
    --behind-proxy) PROXY=1; shift ;;
    *) echo "usage: check-public-rpc.sh (--url URL | --local [unit]) [--behind-proxy]" >&2; exit 2 ;;
  esac
done
if [ "$LOCAL" = 1 ] && [ -z "$URL" ]; then URL=http://127.0.0.1:8546; fi
[ -n "$URL" ] || { echo "usage: check-public-rpc.sh (--url URL | --local [unit]) [--behind-proxy]" >&2; exit 2; }

REFUSED_METHODS="rand_getPeers rand_mint rand_importViewingKey rand_getViewingNotes rand_removeViewingKey"
NODE_WORDS="not served on this node's public listener"
fails=()
post() { curl -s -m 10 -X POST -H 'content-type: application/json' --data "$1" "$URL"; }

echo "public-rpc: checked $(date -u +%Y-%m-%dT%H:%M:%SZ) url $URL$([ "$PROXY" = 1 ] && echo ' (behind a proxy)')"

if [ "$LOCAL" = 1 ]; then
  exec_start=$(systemctl show "$UNIT" -p ExecStart --value 2>/dev/null)
  environment=$(systemctl show "$UNIT" -p Environment --value 2>/dev/null)
  case "$exec_start" in
    *--public-rpc*) echo "unit: $UNIT turns it on with --public-rpc in ExecStart" ;;
    *) case "$environment" in
         *RAND_NODE_PUBLIC_RPC=*) echo "unit: $UNIT turns it on with RAND_NODE_PUBLIC_RPC in its environment" ;;
         *) echo "unit: $UNIT has neither --public-rpc nor RAND_NODE_PUBLIC_RPC"; fails+=("the unit $UNIT does not turn the public listener on") ;;
       esac ;;
  esac
fi

chain=$(post '{"jsonrpc":"2.0","id":1,"method":"rand_chainId","params":[]}')
chain_id=$(printf '%s' "$chain" | sed -n 's/.*"result":\([0-9][0-9]*\).*/\1/p')
if [ -n "$chain_id" ]; then echo "rand_chainId: $chain_id"; else echo "rand_chainId: no answer"; fails+=("rand_chainId did not answer at $URL"); fi
version=$(post '{"jsonrpc":"2.0","id":1,"method":"rand_getVersion","params":[]}')
build=$(printf '%s' "$version" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
sha=$(printf '%s' "$version" | sed -n 's/.*"git_sha":"\([0-9a-f]*\)".*/\1/p' | cut -c1-8)
echo "build: ${build:-?} ${sha:-?}"

for m in $REFUSED_METHODS; do
  out=$(post "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$m\",\"params\":[]}")
  case "$out" in
    *"$NODE_WORDS"*) echo "$m: refused, gate: node" ;;
    *'"code":-32601'*)
      if [ "$PROXY" = 1 ]; then echo "$m: refused, gate: proxy"
      else echo "$m: refused, but not by the node's public listener"; fails+=("$m was refused in other words than the public listener's: the hop does not end at --public-rpc (or pass --behind-proxy)"); fi ;;
    "") echo "$m: no answer"; fails+=("$m got no answer") ;;
    *) echo "$m: SERVED OR NOT GATED"; fails+=("$m is not refused: the hop ends at the operator listener") ;;
  esac
done

batch=$(post '[{"jsonrpc":"2.0","id":1,"method":"rand_chainId","params":[]},{"jsonrpc":"2.0","id":2,"method":"rand_chainId","params":[]}]')
case "$batch" in
  \[*'"result"'*) echo "batch: SERVED"; fails+=("a batch is served: the hop ends at the operator listener") ;;
  "") echo "batch: no answer"; fails+=("a batch got no answer") ;;
  *) echo "batch: refused" ;;
esac

if [ ${#fails[@]} -eq 0 ]; then echo "public-rpc: ok"; exit 0; fi
for f in "${fails[@]}"; do echo "fail: $f"; done
echo "public-rpc: FAIL"
exit 1
