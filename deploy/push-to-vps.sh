#!/usr/bin/env bash
# Run locally: push-to-vps.sh <ip> <node-letter> "<bootstrap multiaddrs>"  — rsyncs the source and runs vps-setup.sh there.
set -euo pipefail
IP=$1; NODE=$2; BOOT=${3:-}; ROLE=${4:-validator}
cd "$(dirname "$0")/.."
KEY=${SSH_KEY:-~/.ssh/id_ed25519}
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 root@$IP"
rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
    --exclude target --exclude 'data-*' --exclude testnet --exclude .git ./ root@$IP:/root/fullnode/
# The zkVM manifest has an optional path dependency on ../../../circuits/rand-zkvm-cuda; cargo needs the
# manifest to exist even for default builds, so ship that crate's sources alongside (no GPU code is built).
CUDA=$(cd "$(dirname "$0")/../../circuits/rand-zkvm-cuda" 2>/dev/null && pwd || true)
if [ -n "$CUDA" ]; then rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" --exclude target "$CUDA/" root@$IP:/root/circuits/rand-zkvm-cuda/; fi
$SSH "bash /root/fullnode/deploy/vps-setup.sh $NODE \"$BOOT\" $ROLE"
