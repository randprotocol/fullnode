#!/usr/bin/env bash
# The web droplet's half of prover.randprotocol.org (deploy/prover/README.md): one SSH tunnel per
# prover host, the router, the nginx vhost, the pairing document. Run after install-host.sh has
# run on every host named here, and after the DNS record exists (certbot needs it).
#
#   WEB=root@159.65.138.161 PUBLIC_DIR=~/rand-prover-trusted/public \
#     deploy/prover/install-web.sh 8601=139.59.238.151 8602=206.81.29.236 …
#
# Each argument is <local port>=<prover host ip>. Idempotent; a host removed from the arguments
# has its tunnel stopped and disabled. `install-web.sh --key` only creates (once) and prints the
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
for pair in "$@"; do
    port=${pair%%=*}; ip=${pair#*=}
    BACKENDS="${BACKENDS:+$BACKENDS,}http://127.0.0.1:$port"
    PORTS="$PORTS $port"
    # The host key is pinned the first time this host is added, from the operator's own
    # known_hosts (the machine running this script has already talked to it), never blindly.
    key=$(ssh-keygen -F "$ip" | grep -v '^#' | grep ed25519 | head -1 | awk '{print $2" "$3}')
    [ -n "$key" ] || { echo "no ed25519 host key for $ip in this machine's known_hosts" >&2; exit 1; }
    "${SSH[@]}" "set -e
        grep -q '^$ip ' /etc/rand-prover-pool/known_hosts || echo '$ip $key' >> /etc/rand-prover-pool/known_hosts
        echo 'REMOTE=provertunnel@$ip' > /etc/rand-prover-pool/$port.env"
done

"${SSH[@]}" "set -e
    echo 'PROVER_BACKENDS=$BACKENDS' > /etc/rand-prover-pool/router.env
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
