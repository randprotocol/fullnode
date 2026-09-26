#!/usr/bin/env bash
# Run locally: rebuild-vps.sh <ip>  — rsync the commit's tracked files, rebuild, reinstall binaries, restart the service (datadir kept).
set -euo pipefail
IP=$1
cd "$(dirname "$0")/.."
KEY=${SSH_KEY:-~/.ssh/id_ed25519}
# Only the commit's tracked files go to the host (OPS-1): `git archive HEAD` into a scratch
# directory, or with ALLOW_DIRTY=1 the working copies of tracked files — never an untracked file
# (wallets/*.key.json, logs). The stage carries .git-rev, written fresh on every rebuild (a stale
# one reports the wrong build), -dirty when tracked files differ from HEAD. --delete removes from
# /root/fullnode whatever the commit does not hold; the host's own target, data dirs and .git stay.
. deploy/lib/clean-tree.sh
stage_clean_tree
rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
    --exclude target --exclude 'data-*' --exclude testnet --exclude .git "$STAGE/" root@$IP:/root/fullnode/
CUDA=$(cd "$(dirname "$0")/../../circuits/rand-zkvm-cuda" 2>/dev/null && pwd || true)
if [ -n "$CUDA" ]; then ssh -i $KEY -o StrictHostKeyChecking=accept-new root@$IP 'mkdir -p /root/circuits/rand-zkvm-cuda'; rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" --exclude target "$CUDA/" root@$IP:/root/circuits/rand-zkvm-cuda/; fi
# RAND_BUILD_SHA overrides build.rs's own git lookup: E's tree keeps a stale .git left over
# from long ago (rsync's --exclude .git above protects it from --delete), so git rev-parse HEAD
# there would answer with some other commit even though .git-rev was just written fresh. Pass
# the same $REV straight into the remote build's environment instead of trusting that repo.
# The value is a local shell variable going into a single-quoted remote script, so the quote is
# closed and reopened around it.
ssh -i $KEY -o StrictHostKeyChecking=accept-new root@$IP 'set -e; source /root/.cargo/env; cd /root/fullnode
  git_rev=$(cat .git-rev 2>/dev/null || echo unknown)
  RAND_BUILD_SHA='"$REV"' cargo build --release -p randprotocol-node -p randprotocol-client 2>&1 | grep -E "^(error|warning: unused)|Finished" || true
  install -m 755 target/release/rand-node target/release/rand /usr/local/bin/
  systemctl restart rand-node; sleep 5; systemctl is-active rand-node; rand status | grep -E "\"(height|peer_count)\""'
