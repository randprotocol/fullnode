#!/usr/bin/env bash
# Check origin/main for new commits; if any, pull, rebuild, and restart node B.
# Prints "up-to-date" or "updated <old> -> <new>"; exits non-zero on build failure.
set -euo pipefail
cd "$(dirname "$0")/.."
git fetch origin main >/dev/null 2>&1
LOCAL=$(git rev-parse HEAD)
# .update-pin holds a commit to stay on (e.g. during a coordinated hard fork);
# remove the file to resume tracking origin/main.
if [ -f .update-pin ]; then
    REMOTE=$(git rev-parse "$(cat .update-pin)")
    PIN=" (pinned by .update-pin; origin/main is $(git rev-parse --short origin/main))"
else
    REMOTE=$(git rev-parse origin/main)
    PIN=""
fi
if [ "$LOCAL" = "$REMOTE" ]; then
    echo "up-to-date at ${LOCAL:0:7}$PIN"
    exit 0
fi
echo "updating ${LOCAL:0:7} -> ${REMOTE:0:7}"
git log --oneline "$LOCAL..$REMOTE" 2>/dev/null || true
git reset --hard "$REMOTE"
cargo build --release 2>&1 | tail -3
pkill -INT -f 'shrugg-node run' || true
sleep 3
RUST_LOG=${RUST_LOG:-info,shrugg_node=debug,libp2p=warn,libp2p_mdns=off} \
    nohup ./deploy/run-b.sh >> node-b-chain4.log 2>&1 &
sleep 5
curl -s -m 5 -X POST 127.0.0.1:8545 -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"shrugg_status","params":[]}' || echo "WARN: rpc not up yet"
echo
echo "updated ${LOCAL:0:7} -> ${REMOTE:0:7} and restarted node B"
