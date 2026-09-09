#!/usr/bin/env bash
# Snapshot local changes onto branch node-b-ops and push, without touching the
# working tree, index, or HEAD (node B runs from a pinned checkout).
set -euo pipefail
cd "$(dirname "$0")/.."
BRANCH=node-b-ops

# runtime artifacts stay out of git (local excludes survive resets/checkouts)
EXCL=.git/info/exclude
for p in 'node-b*.log*' 'shrugg-audit.log' 'audit-state.json' 'audit-wallet.key.json' 'nohup.out'; do
    grep -qxF "$p" "$EXCL" 2>/dev/null || echo "$p" >> "$EXCL"
done

PARENT=$(git rev-parse -q --verify "refs/heads/$BRANCH" || git rev-parse HEAD)
TMPIDX=$(mktemp)
trap 'rm -f "$TMPIDX"' EXIT
GIT_INDEX_FILE=$TMPIDX git read-tree HEAD
GIT_INDEX_FILE=$TMPIDX git add -A
TREE=$(GIT_INDEX_FILE=$TMPIDX git write-tree)

if git rev-parse -q --verify "refs/heads/$BRANCH" >/dev/null \
   && [ "$TREE" = "$(git rev-parse "$BRANCH^{tree}")" ]; then
    echo "no changes since last snapshot on $BRANCH"
    exit 0
fi

MSG="ops(node-b): snapshot $(date '+%Y-%m-%d %H:%M %z') on $(git rev-parse --short HEAD)"
COMMIT=$(git commit-tree "$TREE" -p "$PARENT" -m "$MSG" \
    -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>" \
    -m "Claude-Session: https://claude.ai/code/session_01EuJqDbdpFHYrzR7LWKMKVm")
git update-ref "refs/heads/$BRANCH" "$COMMIT"
git push origin "$BRANCH" 2>&1 | tail -2
echo "pushed $BRANCH @ ${COMMIT:0:7}: $MSG"
