#!/usr/bin/env bash
# Run locally: push-to-vps.sh <ip> <node-letter> "<bootstrap multiaddrs>"  — rsyncs the source and runs vps-setup.sh there.
set -euo pipefail
IP=$1; NODE=$2; BOOT=${3:-}; ROLE=${4:-validator}
cd "$(dirname "$0")/.."
KEY=${SSH_KEY:-~/.ssh/id_ed25519}
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 root@$IP"
# Only the commit's tracked files go to the host (OPS-1): see deploy/lib/clean-tree.sh.
. deploy/lib/clean-tree.sh
stage_clean_tree
rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
    --exclude target --exclude 'data-*' --exclude testnet --exclude .git "$STAGE/" root@$IP:/root/fullnode/
# The zkVM's CUDA backend is a git dependency since PROC-2 (#109); nothing beside the tree is shipped.
$SSH "bash /root/fullnode/deploy/vps-setup.sh $NODE \"$BOOT\" $ROLE"
