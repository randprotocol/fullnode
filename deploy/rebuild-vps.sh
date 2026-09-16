#!/usr/bin/env bash
# Run locally: rebuild-vps.sh <ip>  — rsync latest source, rebuild, reinstall binaries, restart the service (datadir kept).
set -euo pipefail
IP=$1
cd "$(dirname "$0")/.."
KEY=${SSH_KEY:-~/.ssh/id_ed25519}
rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
    --exclude target --exclude 'data-*' --exclude testnet --exclude .git ./ root@$IP:/root/fullnode/
CUDA=$(cd "$(dirname "$0")/../../circuits/rand-zkvm-cuda" 2>/dev/null && pwd || true)
if [ -n "$CUDA" ]; then ssh -i $KEY -o StrictHostKeyChecking=accept-new root@$IP 'mkdir -p /root/circuits/rand-zkvm-cuda'; rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" --exclude target "$CUDA/" root@$IP:/root/circuits/rand-zkvm-cuda/; fi
ssh -i $KEY -o StrictHostKeyChecking=accept-new root@$IP 'set -e; source /root/.cargo/env; cd /root/fullnode
  git_rev=$(cat .git-rev 2>/dev/null || echo unknown)
  cargo build --release -p randprotocol-node -p randprotocol-client 2>&1 | grep -E "^(error|warning: unused)|Finished" || true
  install -m 755 target/release/rand-node target/release/rand /usr/local/bin/
  systemctl restart rand-node; sleep 5; systemctl is-active rand-node; rand status | grep -E "\"(height|peer_count)\""'
