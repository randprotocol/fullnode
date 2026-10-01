#!/bin/bash
# Restarts rand-prover when a proof has been "proving" for longer than any proof can take. A bundle
# proof is useful for about five minutes (ledger::TIME_WINDOW) and takes ~70 s here, so a slot
# still busy after ten minutes is a wedged job (seen 2026-10-01 on rand-guardian-1: three rayon
# workers spinning in HidingFriPcs for hours, the slot gone from the pool until a restart). The
# restart drops the job; the wallet that sent it has long since timed out and cancelled.
# Run every minute by prover-watchdog.timer.
STATE=/run/rand-prover-watchdog
LIMIT=${LIMIT:-600}
mkdir -p "$STATE"
proving=$(curl -s -m 5 -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"prover_info","params":[]}' http://127.0.0.1:8600 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["queue"]["proving"])' 2>/dev/null)
if [ -z "$proving" ]; then
    # No answer at all: systemd's Restart= handles a dead process; a live one that does not answer
    # for two minutes is restarted here.
    [ -f "$STATE/silent" ] && [ $(( $(date +%s) - $(cat "$STATE/silent") )) -ge 120 ] && { logger -t rand-prover-watchdog "no prover_info answer for 120 s: restarting"; systemctl restart rand-prover; rm -f "$STATE/silent" "$STATE/since"; exit 0; }
    [ -f "$STATE/silent" ] || date +%s > "$STATE/silent"
    exit 0
fi
rm -f "$STATE/silent"
if [ "$proving" = 0 ]; then rm -f "$STATE/since"; exit 0; fi
[ -f "$STATE/since" ] || date +%s > "$STATE/since"
if [ $(( $(date +%s) - $(cat "$STATE/since") )) -ge "$LIMIT" ]; then
    logger -t rand-prover-watchdog "a proof has been running for over $LIMIT s: restarting rand-prover"
    systemctl restart rand-prover
    rm -f "$STATE/since"
fi
