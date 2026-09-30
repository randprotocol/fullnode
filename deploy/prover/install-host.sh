#!/usr/bin/env bash
# Make one validator host a prover of the prover.randprotocol.org pool (deploy/prover/README.md).
#
#   POOL_HOME=~/rand-prover-trusted/home TUNNEL_PUBKEY=~/rand-prover-trusted/public/web-tunnel.pub \
#     deploy/prover/install-host.sh root@<ip> [-i <ssh key>]
#
# Idempotent. It installs the release's rand-prover (sha256-checked on the host), the pool's key
# and pairing store (the SAME two files on every host of the pool), the sandboxed
# rand-prover.service beside rand-node, and a no-shell user through which the web droplet's tunnel
# may reach 127.0.0.1:8600 and nothing else. It never touches rand-node, its unit, key or data.
set -euo pipefail

TARGET=${1:?usage: install-host.sh root@<ip> [ssh options]}; shift
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20 "$@" "$TARGET")
SCP=(scp -q -o BatchMode=yes "$@")

# v0.6.7-prover.1 is v0.6.7 with the prover built on every core (rand-prover only).
TAG=${TAG:-v0.6.7-prover.1}
WANT_SHA_PROVER=${WANT_SHA_PROVER:-cb634a25c393442220297251dd3e46d5b7d477be4c311fdfa9dc6aebd67f4a39}
POOL_HOME=${POOL_HOME:?POOL_HOME: the directory holding the pool\'s prover.key.json and pairings.json}
TUNNEL_PUBKEY=${TUNNEL_PUBKEY:?TUNNEL_PUBKEY: the web droplet\'s tunnel public key file}
HERE=$(cd "$(dirname "$0")" && pwd)

for f in "$POOL_HOME/prover.key.json" "$POOL_HOME/pairings.json" "$TUNNEL_PUBKEY" "$HERE/rand-prover.service"; do
    [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done

# One proof at a time: PROVER_PEAK_BYTES (5.74 GB; 5.88 GB measured on the parallel build) plus the
# gate's 1 GiB of headroom, on every core but one, which stays the validator's. Refuse a host that
# cannot hold that beside its node.
read -r CPUS AVAIL_MB < <("${SSH[@]}" 'echo "$(nproc) $(free -m | awk "/Mem:/{print \$7}")"')
if [ "$AVAIL_MB" -lt 8000 ] || [ "$CPUS" -lt 2 ]; then
    echo "$TARGET: $CPUS cpu(s), $AVAIL_MB MB available — a prover needs 8 GB available beside the validator and a second core. Resize the host first." >&2
    exit 1
fi
THREADS=$((CPUS - 1))
MEMORY_MAX=8G
echo "$TARGET: $CPUS cpus, $AVAIL_MB MB available -> one proving slot on $THREADS threads, MemoryMax $MEMORY_MAX"

"${SSH[@]}" "set -e
    id randprover >/dev/null 2>&1 || useradd --system --home-dir /var/lib/randprover --shell /usr/sbin/nologin randprover
    install -d -m 0700 -o randprover -g randprover /var/lib/randprover
    cd /tmp && curl -fsSL -o rand-prover.new https://github.com/randprotocol/fullnode/releases/download/$TAG/rand-prover
    echo '$WANT_SHA_PROVER  rand-prover.new' | sha256sum -c -
    install -m 0755 rand-prover.new /usr/local/bin/rand-prover && rm rand-prover.new
    id provertunnel >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/provertunnel --shell /usr/sbin/nologin provertunnel
    install -d -m 0700 -o provertunnel -g provertunnel /home/provertunnel/.ssh"

"${SCP[@]}" "$POOL_HOME/prover.key.json" "$POOL_HOME/pairings.json" "$TARGET:/var/lib/randprover/"
sed -e "s/@THREADS@/$THREADS/g" -e "s/@MEMORY_MAX@/$MEMORY_MAX/g" "$HERE/rand-prover.service" | "${SSH[@]}" 'cat > /etc/systemd/system/rand-prover.service'
{ printf 'restrict,port-forwarding,permitopen="127.0.0.1:8600",command="/usr/sbin/nologin" '; cat "$TUNNEL_PUBKEY"; } \
    | "${SSH[@]}" 'cat > /home/provertunnel/.ssh/authorized_keys && chown provertunnel:provertunnel /home/provertunnel/.ssh/authorized_keys && chmod 0600 /home/provertunnel/.ssh/authorized_keys'

"${SSH[@]}" 'set -e
    chown randprover:randprover /var/lib/randprover/prover.key.json /var/lib/randprover/pairings.json
    chmod 0600 /var/lib/randprover/prover.key.json /var/lib/randprover/pairings.json
    systemctl daemon-reload
    systemctl enable -q rand-prover
    systemctl restart rand-prover
    for i in 1 2 3 4 5 6 7 8 9 10; do
        out=$(curl -s -m 3 -X POST -H "content-type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prover_info\",\"params\":[]}" http://127.0.0.1:8600 || true)
        [ -n "$out" ] && break; sleep 1
    done
    [ -n "$out" ] || { journalctl -u rand-prover -n 20 --no-pager >&2; exit 1; }
    echo "$out" | python3 -c "import json,sys; r=json.load(sys.stdin)[\"result\"]; print(\"prover\", r[\"version\"], r[\"kem_fingerprint\"], r[\"witness_kinds\"], r[\"queue\"], \"fee\", r[\"fee\"])"
    systemctl is-active rand-node'
