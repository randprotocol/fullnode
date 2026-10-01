#!/usr/bin/env bash
# Remove the shared pool key (fingerprint RGTF-7HKJ-XZFV-GQ1J, audit v7 VK-9) from one host:
# stop and disable rand-prover.service and shred /var/lib/randprover's key and pairings. The
# member's own prover (rand-prover-member.service) is not touched.
#
#   deploy/prover/retire-shared.sh root@<ip> [ssh options]
#
# Wallet 0.6.8 pins the shared key: run this on the last hosts that hold it only after wallet 0.6.9
# (the per-member descriptor) is published and the owner has decided the cut-over, then shred the
# operator's copy (~/rand-prover-trusted/home) too.
set -euo pipefail
TARGET=${1:?usage: retire-shared.sh root@<ip> [ssh options]}; shift
ssh -o BatchMode=yes -o ConnectTimeout=20 "$@" "$TARGET" 'set -e
    systemctl disable -q --now rand-prover 2>/dev/null || true
    rm -f /etc/systemd/system/rand-prover.service
    systemctl daemon-reload
    if [ -d /var/lib/randprover ]; then
        for f in /var/lib/randprover/prover.key.json /var/lib/randprover/pairings.json; do [ -f "$f" ] && shred -u "$f"; done
        rm -rf /var/lib/randprover
    fi
    echo "shared key removed; member unit: $(systemctl is-active rand-prover-member 2>/dev/null || echo absent)"'
