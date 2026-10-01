#!/usr/bin/env bash
# The web droplet's half of prover.randprotocol.org (deploy/prover/README.md): one SSH tunnel per
# prover host, the router, the nginx vhost, the pairing document. Run after install-host.sh has
# run on every host named here, and after the DNS record exists (certbot needs it).
#
#   WEB=root@159.65.138.161 PUBLIC_DIR=~/rand-prover-trusted/public \
#     deploy/prover/install-web.sh a:8611=139.59.238.151 nyc3:8613=138.197.113.180 8603=138.197.113.180 …
#
# An argument <name>:<local port>=<ip> is a MEMBER with its own key (audit v7, VK-9): its tunnel
# reaches the host's rand-prover-member on 8610 and https://prover.randprotocol.org/m/<name> goes
# straight to it; the members' links and fingerprints become the pool descriptor at
# /.well-known/rand-prover-pool.json, which clients pin. An argument <local port>=<ip> is a
# backend of the RETIRING shared-key pool (wallet 0.6.8) behind the root URL and the router: its
# tunnel reaches the shared-key unit on 8600. Idempotent; a tunnel not named is stopped and
# disabled. `install-web.sh --key` only creates (once) and prints the
# tunnel's public key, which install-host.sh needs first.
set -euo pipefail

WEB=${WEB:?WEB: the web droplet, e.g. root@159.65.138.161}
if [ "${1:-}" = "--key" ]; then
    ssh -o BatchMode=yes -o ConnectTimeout=20 "$WEB" 'set -e
        install -d -m 0700 /etc/rand-prover-pool
        [ -f /etc/rand-prover-pool/tunnel_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -C "web-droplet prover pool tunnel" -f /etc/rand-prover-pool/tunnel_ed25519
        cat /etc/rand-prover-pool/tunnel_ed25519.pub'
    exit 0
fi
PUBLIC_DIR=${PUBLIC_DIR:?PUBLIC_DIR: the directory holding trusted-prover.json}
HERE=$(cd "$(dirname "$0")" && pwd)
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20 "$WEB")
[ $# -ge 1 ] || { echo "name at least one <port>=<ip>" >&2; exit 1; }
[ -f "$PUBLIC_DIR/trusted-prover.json" ] || { echo "missing $PUBLIC_DIR/trusted-prover.json" >&2; exit 1; }

"${SSH[@]}" 'set -e
    install -d -m 0755 /opt/rand-prover-pool /var/www/prover/.well-known
    install -d -m 0700 /etc/rand-prover-pool
    [ -f /etc/rand-prover-pool/tunnel_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -C "web-droplet prover pool tunnel" -f /etc/rand-prover-pool/tunnel_ed25519
    touch /etc/rand-prover-pool/known_hosts'

scp -q -o BatchMode=yes "$HERE/router.py" "$WEB:/opt/rand-prover-pool/router.py"
scp -q -o BatchMode=yes "$HERE/rand-prover-router.service" "$HERE/prover-tunnel@.service" "$WEB:/etc/systemd/system/"
scp -q -o BatchMode=yes "$PUBLIC_DIR/trusted-prover.json" "$WEB:/var/www/prover/.well-known/rand-prover.json"
scp -q -o BatchMode=yes "$HERE/nginx-prover.conf" "$WEB:/etc/nginx/sites-available/prover-randprotocol"

BACKENDS=""
PORTS=""
MEMBERS_ENV=""
MEMBER_LOCATIONS=""
DESCRIPTOR_ROWS=""
for arg in "$@"; do
    name=""; rest=$arg
    case "$arg" in *:*=*) name=${arg%%:*}; rest=${arg#*:} ;; esac
    port=${rest%%=*}; ip=${rest#*=}
    PORTS="$PORTS $port"
    # The host key is pinned the first time this host is added, from the operator's own
    # known_hosts (the machine running this script has already talked to it), never blindly.
    key=$(ssh-keygen -F "$ip" | grep -v '^#' | grep ed25519 | head -1 | awk '{print $2" "$3}')
    [ -n "$key" ] || { echo "no ed25519 host key for $ip in this machine's known_hosts" >&2; exit 1; }
    if [ -n "$name" ]; then
        [ -f "$PUBLIC_DIR/members/$name.link" ] || { echo "no $PUBLIC_DIR/members/$name.link: run install-host.sh with MEMBER=$name first" >&2; exit 1; }
        remote=8610
        MEMBER_LOCATIONS="$MEMBER_LOCATIONS
    location = /m/$name {
        limit_req zone=prover burst=60 nodelay;
        limit_req_status 429;
        client_max_body_size 140k;
        proxy_pass http://127.0.0.1:8650/m/$name;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Connection \"\";
        proxy_read_timeout 30s;
    }"
        DESCRIPTOR_ROWS="$DESCRIPTOR_ROWS $name=$port"
        MEMBERS_ENV="${MEMBERS_ENV:+$MEMBERS_ENV,}$name=http://127.0.0.1:$port"
    else
        remote=8600
        BACKENDS="${BACKENDS:+$BACKENDS,}http://127.0.0.1:$port"
    fi
    "${SSH[@]}" "set -e
        grep -q '^$ip ' /etc/rand-prover-pool/known_hosts || echo '$ip $key' >> /etc/rand-prover-pool/known_hosts
        printf 'REMOTE=provertunnel@$ip\\nREMOTE_PORT=$remote\\n' > /etc/rand-prover-pool/$port.env"
done
printf '%s\n' "$MEMBER_LOCATIONS" | "${SSH[@]}" 'cat > /etc/nginx/snippets/prover-members.conf'

"${SSH[@]}" "set -e
    echo 'PROVER_BACKENDS=$BACKENDS' > /etc/rand-prover-pool/router.env
    echo 'PROVER_MEMBERS=$MEMBERS_ENV' >> /etc/rand-prover-pool/router.env
    echo 'ROUTER_LISTEN=127.0.0.1:8650' >> /etc/rand-prover-pool/router.env
    chmod 0644 /etc/rand-prover-pool/router.env
    systemctl daemon-reload
    for unit in \$(systemctl list-units --all --plain --no-legend 'prover-tunnel@*' | awk '{print \$1}'); do
        p=\${unit#prover-tunnel@}; p=\${p%.service}
        case ' $PORTS ' in *\" \$p \"*) ;; *) systemctl disable -q --now \"\$unit\"; rm -f /etc/rand-prover-pool/\$p.env ;; esac
    done
    for p in $PORTS; do systemctl enable -q prover-tunnel@\$p; systemctl restart prover-tunnel@\$p; done
    systemctl enable -q rand-prover-router
    systemctl restart rand-prover-router
    echo 'limit_req_zone \$binary_remote_addr zone=prover:2m rate=240r/m;' > /etc/nginx/conf.d/prover.conf
    if [ ! -f /etc/letsencrypt/live/prover.randprotocol.org/fullchain.pem ]; then
        # First time: an http-only vhost serves the ACME challenge (the name is DNS-only, so port 80
        # reaches this host directly), then the real vhost replaces it.
        install -d -m 0755 /var/www/letsencrypt
        printf 'server {\n    listen 80;\n    listen [::]:80;\n    server_name prover.randprotocol.org;\n    location /.well-known/acme-challenge/ { root /var/www/letsencrypt; }\n    location / { return 301 https://\$host\$request_uri; }\n}\n' > /etc/nginx/sites-available/prover-randprotocol-acme
        ln -sf /etc/nginx/sites-available/prover-randprotocol-acme /etc/nginx/sites-enabled/prover-randprotocol-acme
        rm -f /etc/nginx/sites-enabled/prover-randprotocol
        nginx -t && systemctl reload nginx
        certbot certonly --webroot -w /var/www/letsencrypt -d prover.randprotocol.org --non-interactive --agree-tos 2>&1 | tail -3
        rm -f /etc/nginx/sites-enabled/prover-randprotocol-acme
    fi
    ln -sf /etc/nginx/sites-available/prover-randprotocol /etc/nginx/sites-enabled/prover-randprotocol
    nginx -t && systemctl reload nginx
    sleep 3
    systemctl is-active rand-prover-router \$(for p in $PORTS; do echo prover-tunnel@\$p; done)"

# The pool descriptor: every member's link, URL and the fingerprint its prover answers with, read
# through its tunnel now — a member whose answer does not match its link is not published.
if [ -n "$DESCRIPTOR_ROWS" ]; then
    rows=""
    for row in $DESCRIPTOR_ROWS; do
        name=${row%%=*}; port=${row#*=}
        fp=$("${SSH[@]}" "curl -s -m 5 -X POST -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prover_info\",\"params\":[]}' http://127.0.0.1:$port" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["kem_fingerprint"])')
        # The link holds %-escapes (url=https%3A%2F…): never pass it through a printf format.
        rows="$rows$name $fp $(cat "$PUBLIC_DIR/members/$name.link")"$'\n'
    done
    printf '%s' "$rows" | python3 -c '
import json, sys
members = []
for line in sys.stdin.read().split("\n"):
    if not line.strip(): continue
    name, fp, link = line.split(" ", 2)
    url = "https://prover.randprotocol.org/m/" + name
    from urllib.parse import quote
    assert ("url=" + quote(url, safe="-._~")) in link, name + ": the link does not carry " + url
    members.append({"name": name, "url": url, "fingerprint": fp, "link": link})
doc = {"version": 1, "members": members, "witness_kinds": ["viewing_key"], "fee": None,
       "learns": "the wallet viewing key and a one-time salt: it can read that wallet whole history, past and future, and cannot spend"}
print(json.dumps(doc, indent=2))' > "$PUBLIC_DIR/pool.json"
    scp -q -o BatchMode=yes "$PUBLIC_DIR/pool.json" "$WEB:/var/www/prover/.well-known/rand-prover-pool.json"
    echo "descriptor: $PUBLIC_DIR/pool.json ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["members"]))' "$PUBLIC_DIR/pool.json") members)"
fi
