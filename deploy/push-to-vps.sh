#!/usr/bin/env bash
# Run locally: push-to-vps.sh <ip> <node-letter> "<bootstrap multiaddrs>"  — rsyncs the source and runs vps-setup.sh there.
set -euo pipefail
IP=$1; NODE=$2; BOOT=${3:-}; ROLE=${4:-validator}
cd "$(dirname "$0")/.."
SSH="ssh -i ${SSH_KEY:-~/.ssh/id_ed25519} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 root@$IP"
rsync -az --delete -e "ssh -i ${SSH_KEY:-~/.ssh/id_ed25519} -o StrictHostKeyChecking=accept-new" \
    --exclude target --exclude 'data-*' --exclude testnet --exclude .git ./ root@$IP:/root/fullnode/
$SSH "bash /root/fullnode/deploy/vps-setup.sh $NODE \"$BOOT\" $ROLE"
