#!/usr/bin/env bash
# Make one host a member of the prover.randprotocol.org pool (deploy/prover/README.md).
#
#   MEMBER=nyc3 TUNNEL_PUBKEY=~/rand-prover-trusted/public/web-tunnel.pub \
#     deploy/prover/install-host.sh root@<ip> [-i <ssh key>]
#
# Idempotent. On the host it installs:
#   - the release's rand-prover, ONLY after the release's SHA256SUMS has verified against its
#     SHA256SUMS.sig and deploy/release-signers here (deploy/lib/verify-release.sh) and the binary
#     matches the signed file — and matches it again on the host before install (audit v7, OPS-9);
#   - rand-prover-member.service: the member's OWN prover key, generated on the host the first time
#     and never copied anywhere, so one host (and there is no backup) opens only the jobs sealed to
#     that member (audit v7, VK-9). It listens on 127.0.0.1:8610; its pairing link, for
#     https://prover.randprotocol.org/m/<MEMBER>, is saved to $PUBLIC_DIR/members/<MEMBER>.link for
#     the pool descriptor the clients pin;
#   - the watchdog timer, and a no-shell user the web droplet's tunnel uses to reach the prover
#     ports (8610, and 8600 while the retiring shared-key unit, rand-prover.service, still runs).
# It never touches rand-node, rand-guardian or the shared-key unit; see retire-shared.sh for that.
set -euo pipefail

TARGET=${1:?usage: MEMBER=<name> install-host.sh root@<ip> [ssh options]}; shift
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20 "$@" "$TARGET")
SCP=(scp -q -o BatchMode=yes "$@")

MEMBER=${MEMBER:?MEMBER: the member name, 1-16 of a-z0-9, used in its URL /m/<MEMBER>}
[[ "$MEMBER" =~ ^[a-z0-9]{1,16}$ ]] || { echo "MEMBER must be 1-16 of a-z0-9" >&2; exit 1; }
# A release whose SHA256SUMS carries the release key's SHA256SUMS.sig. Never v0.6.7-prover.1 or .2:
# they can deadlock (AGENTS.md, the prover pool entry).
TAG=${TAG:-v0.6.9}
TUNNEL_PUBKEY=${TUNNEL_PUBKEY:?TUNNEL_PUBKEY: the web droplet\'s tunnel public key file}
PUBLIC_DIR=${PUBLIC_DIR:-$HOME/rand-prover-trusted/public}
POOL_URL=${POOL_URL:-https://prover.randprotocol.org}
HOME_DIR=/var/lib/randprover-member
PORT=8610
HERE=$(cd "$(dirname "$0")" && pwd)

for f in "$TUNNEL_PUBKEY" "$HERE/rand-prover.service" "$HERE/prover-watchdog.sh"; do
    [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done

# --- the signed release, verified here before anything reaches the host ------------------------
REL=$(mktemp -d); trap 'rm -rf "$REL"' EXIT
gh release download "$TAG" -R randprotocol/fullnode -D "$REL" -p SHA256SUMS -p SHA256SUMS.sig -p rand-prover
bash -c 'source "$1/../lib/verify-release.sh" && verify_release_sums "$2/SHA256SUMS" "$2/SHA256SUMS.sig" && verify_binary "$2/rand-prover" "$2/SHA256SUMS"' _ "$HERE" "$REL"
WANT_SHA=$(bash -c 'source "$1/../lib/verify-release.sh" && release_sha "$2/SHA256SUMS" rand-prover' _ "$HERE" "$REL")

# --- the host can hold a proof beside whatever else it runs ------------------------------------
read -r CPUS AVAIL_MB < <("${SSH[@]}" 'echo "$(nproc) $(free -m | awk "/Mem:/{print \$7}")"')
if [ "$AVAIL_MB" -lt 7000 ] || [ "$CPUS" -lt 2 ]; then
    echo "$TARGET: $CPUS cpu(s), $AVAIL_MB MB available — a prover needs ~7 GB available and a second core. Resize the host first." >&2
    exit 1
fi
THREADS=$((CPUS - 1)); [ "$THREADS" -le 8 ] || THREADS=8   # rand-prover's own default (docs/node-hardware.md §6)
MEMORY_MAX=8G
echo "$TARGET ($MEMBER): $CPUS cpus, $AVAIL_MB MB available; $TAG rand-prover ${WANT_SHA:0:16}… (signature verified)"

"${SCP[@]}" "$REL/rand-prover" "$TARGET:/tmp/rand-prover.new"
"${SSH[@]}" "set -e
    echo '$WANT_SHA  /tmp/rand-prover.new' | sha256sum -c - >/dev/null
    install -m 0755 /tmp/rand-prover.new /usr/local/bin/rand-prover && rm /tmp/rand-prover.new
    id randprover >/dev/null 2>&1 || useradd --system --home-dir /var/lib/randprover --shell /usr/sbin/nologin randprover
    install -d -m 0700 -o randprover -g randprover $HOME_DIR
    id provertunnel >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/provertunnel --shell /usr/sbin/nologin provertunnel
    install -d -m 0700 -o provertunnel -g provertunnel /home/provertunnel/.ssh
    if [ ! -f $HOME_DIR/prover.key.json ]; then
        runuser -u randprover -- /usr/local/bin/rand-prover --home $HOME_DIR keygen >/dev/null
        runuser -u randprover -- /usr/local/bin/rand-prover --home $HOME_DIR pair --name public --url $POOL_URL/m/$MEMBER > $HOME_DIR/link.txt 2>/dev/null
    fi"
LINK=$("${SSH[@]}" "tail -1 $HOME_DIR/link.txt")
case "$LINK" in randprover:*) ;; *) echo "$TARGET: no pairing link came back" >&2; exit 1 ;; esac
mkdir -p "$PUBLIC_DIR/members"
printf '%s\n' "$LINK" > "$PUBLIC_DIR/members/$MEMBER.link"

sed -e "s/@THREADS@/$THREADS/g" -e "s/@MEMORY_MAX@/$MEMORY_MAX/g" -e "s|@HOME@|$HOME_DIR|g" -e "s/@PORT@/$PORT/g" "$HERE/rand-prover.service" \
    | "${SSH[@]}" 'cat > /etc/systemd/system/rand-prover-member.service'
"${SCP[@]}" "$HERE/prover-watchdog.service" "$HERE/prover-watchdog.timer" "$TARGET:/etc/systemd/system/"
"${SCP[@]}" "$HERE/prover-watchdog.sh" "$TARGET:/usr/local/bin/prover-watchdog.sh"
{ printf 'restrict,port-forwarding,permitopen="127.0.0.1:8610",permitopen="127.0.0.1:8600",command="/usr/sbin/nologin" '; cat "$TUNNEL_PUBKEY"; } \
    | "${SSH[@]}" 'cat > /home/provertunnel/.ssh/authorized_keys && chown provertunnel:provertunnel /home/provertunnel/.ssh/authorized_keys && chmod 0600 /home/provertunnel/.ssh/authorized_keys'

"${SSH[@]}" "set -e
    chown -R randprover:randprover $HOME_DIR
    chmod 0600 $HOME_DIR/prover.key.json $HOME_DIR/pairings.json
    chmod 0755 /usr/local/bin/prover-watchdog.sh
    systemctl daemon-reload
    systemctl enable -q rand-prover-member prover-watchdog.timer
    systemctl restart rand-prover-member
    systemctl is-enabled -q rand-prover 2>/dev/null && systemctl restart rand-prover || true
    systemctl start prover-watchdog.timer
    for i in \$(seq 1 10); do
        out=\$(curl -s -m 3 -X POST -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prover_info\",\"params\":[]}' http://127.0.0.1:$PORT || true)
        [ -n \"\$out\" ] && break; sleep 1
    done
    [ -n \"\$out\" ] || { journalctl -u rand-prover-member -n 20 --no-pager >&2; exit 1; }
    echo \"\$out\" | python3 -c 'import json,sys; r=json.load(sys.stdin)[\"result\"]; print(\"member\", r[\"version\"], r[\"kem_fingerprint\"], r[\"witness_kinds\"], r[\"queue\"], \"fee\", r[\"fee\"])'
    echo \"shared-key unit: \$(systemctl is-active rand-prover 2>/dev/null || echo absent); rand-node: \$(systemctl is-active rand-node 2>/dev/null || echo absent)\""
echo "member $MEMBER: link saved to $PUBLIC_DIR/members/$MEMBER.link"
