#!/usr/bin/env bash
# The local-versus-delegated proving benchmark (docs/delegated-proving.md, spec §11).
#
# Every INTERVAL seconds, for DURATION seconds, one cycle of five operations through one wallet:
#   mint (faucet, no proof) → transfer (one bundle proof) → bond (one bundle proof; the chain's
#   only burn, since chain 12 has no bridge) → deploy (a fresh private_payment guest, paid by a
#   bundle proof) → call (a program proof plus a bundle proof, with an input envelope).
# A cycle that overruns the interval starts the next one at once.
#
# Per operation it records: wall clock from command start to commit, every "proved in" the
# wallet printed, every "verified in … (cold), … (warm)" (RAND_TIME_VERIFY=1 makes the wallet
# verify its own proof twice before submitting: cold = verifier-key build + verify, warm = the
# per-proof cost every validator pays at admission), proof bytes, and the committing height.
# At the end it reads every block of the window and reports transactions per second.
#
# Which prover is used is the environment's business: unset RAND_PROVER for local proving; set
# RAND_PROVER / RAND_PROVER_ADDRESS / RAND_PROVER_TOKEN for delegation. LABEL names the run.
#
# Usage: scripts/proving-benchmark.sh
#   env: BIN (rand binary), WALLET, WALLET2 (recipient key), RPC, VALIDATOR (bond target),
#        LABEL, DURATION (s, default 7200), INTERVAL (s, default 300), OUT (dir)
# Output: $OUT/$LABEL.csv (one row per operation), $OUT/$LABEL.log, $OUT/$LABEL-summary.txt
set -uo pipefail
BIN=${BIN:-target/release/rand}
WALLET=${WALLET:?wallet key file}
WALLET2=${WALLET2:?recipient key file}
RPC=${RPC:-http://127.0.0.1:8545}
VALIDATOR=${VALIDATOR:?validator address to bond onto}
LABEL=${LABEL:-local}
DURATION=${DURATION:-7200}
INTERVAL=${INTERVAL:-300}
OUT=${OUT:-benchmarks}
mkdir -p "$OUT"
CSV="$OUT/$LABEL.csv"; LOG="$OUT/$LABEL.log"; SUM="$OUT/$LABEL-summary.txt"
export RAND_TIME_VERIFY=1
TMP=$(mktemp -d)

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }
rpc() { curl -s --max-time 15 "$RPC" -H 'content-type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"; }
num() { grep -o "\"$2\":[0-9]*" <<<"$1" | head -1 | cut -d: -f2; }
# Rust `Duration` debug form ("97.3s", "18.4ms", "2.1µs") to seconds.
secs() { awk '{ v=$1; if (v ~ /ms$/) { sub(/ms$/,"",v); print v/1000 } else if (v ~ /µs$/) { sub(/µs$/,"",v); print v/1000000 } else if (v ~ /ns$/) { sub(/ns$/,"",v); print v/1e9 } else { sub(/s$/,"",v); print v } }' <<<"$1"; }
hash_of() { grep -o "submitted $2 [0-9a-f]*" <<<"$1" | head -1 | awk '{print $3}'; }
# Sum of every "proved in X" line (a call prints two: the program proof and its fee bundle).
proved_total() { local t=0 x; while read -r x; do t=$(awk -v a="$t" -v b="$(secs "$x")" 'BEGIN{print a+b}'); done < <(grep -o 'proved in [0-9.]*[a-zµ]*' <<<"$1" | awk '{print $3}'); echo "$t"; }
proof_bytes() { grep -o 'proved in [^:]*: tier [0-9]*, [0-9]* bytes' <<<"$1" | awk '{s+=$(NF-1)} END{print s+0}'; }
verify_cold() { grep -o 'verified in [0-9.]*[a-zµ]* (cold)' <<<"$1" | awk '{print $3}' | { t=0; while read -r x; do t=$(awk -v a="$t" -v b="$(secs "$x")" 'BEGIN{print a+b}'); done; echo "$t"; }; }
verify_warm() { grep -o '(cold), [0-9.]*[a-zµ]* (warm)' <<<"$1" | awk '{print $2}' | { t=0; while read -r x; do t=$(awk -v a="$t" -v b="$(secs "$x")" 'BEGIN{print a+b}'); done; echo "$t"; }; }
# Poll until the transaction is committed; print "height block_timestamp_ms".
committed() {
  local h=$1 i r height ts
  for i in $(seq 1 120); do
    r=$(rpc rand_getTransaction "[\"$h\"]")
    height=$(num "$r" height)
    if [ -n "$height" ]; then
      ts=$(num "$(rpc rand_getBlockByHeight "[$height]")" timestamp_ms)
      echo "$height ${ts:-0}"; return 0
    fi
    sleep 2
  done
  echo "0 0"; return 1
}
# One operation: run the wallet command, time it end to end, record the row.
op() {
  local cycle=$1 name=$2 kind=$3; shift 3
  local t0 out h hc e2e proved bytes vc vw
  t0=$(date +%s.%N)
  out=$("$@" 2>&1); rc=$?
  h=$(hash_of "$out" "$kind")
  if [ $rc -ne 0 ] || [ -z "$h" ]; then
    log "cycle $cycle $name FAIL: $(tail -1 <<<"$out")"
    printf '%s,%s,%s,FAIL,,,,,,,\n' "$LABEL" "$cycle" "$name" >> "$CSV"; return 1
  fi
  hc=$(committed "$h")
  e2e=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')
  proved=$(proved_total "$out"); bytes=$(proof_bytes "$out"); vc=$(verify_cold "$out"); vw=$(verify_warm "$out")
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$LABEL" "$cycle" "$name" "$h" "$e2e" "$proved" "$vc" "$vw" "$bytes" ${hc} >> "$CSV"
  log "cycle $cycle $name ok $h e2e ${e2e}s proof ${proved}s verify cold ${vc}s warm ${vw}s bytes $bytes height ${hc%% *}"
  echo "$out" > "$TMP/$name-$cycle.out"
}

TO=$("$BIN" --key "$WALLET2" address)
echo "label,cycle,op,hash,e2e_s,proof_s,verify_cold_s,verify_warm_s,proof_bytes,height,block_ts_ms" > "$CSV"
H_START=$(num "$(rpc rand_getHead '[]')" height)
T_START=$(date +%s)
log "benchmark $LABEL start: rpc $RPC head $H_START prover ${RAND_PROVER:-local} duration ${DURATION}s interval ${INTERVAL}s"
cycle=0
while [ $(( $(date +%s) - T_START )) -lt "$DURATION" ]; do
  cycle=$((cycle + 1)); c0=$(date +%s)
  log "cycle $cycle start (head $(num "$(rpc rand_getHead '[]')" height))"
  op "$cycle" mint mint "$BIN" faucet --key "$WALLET" --rpc "$RPC" --amount 10
  op "$cycle" transfer transfer "$BIN" send "$TO" 1.5 --key "$WALLET" --rpc "$RPC"
  op "$cycle" bond bond "$BIN" bond "$VALIDATOR" 1 --key "$WALLET" --rpc "$RPC"
  pj="$TMP/pp-$cycle.json"
  "$BIN" program build --guest private_payment --arg $((100 + cycle)) --out "$pj" >/dev/null 2>&1
  if op "$cycle" deploy deploy "$BIN" program deploy "$pj" --key "$WALLET" --rpc "$RPC"; then
    # The wallet prints "program id: <hex> (N words)" after the deploy commits; the transaction's
    # own record is the fallback.
    pid=$(grep -o 'program id: [0-9a-f]*' "$TMP/deploy-$cycle.out" | awk '{print $3}')
    if [ -z "$pid" ]; then
      dh=$(hash_of "$(cat "$TMP/deploy-$cycle.out")" deploy)
      pid=$(rpc rand_getTransaction "[\"$dh\"]" | grep -o '"program":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)
    fi
    if [ -n "$pid" ]; then
      op "$cycle" call call "$BIN" call "$pid" --input 400 --input 250 --input 300 --input 75 --key "$WALLET" --rpc "$RPC"
    else
      log "cycle $cycle call SKIP: no program id in the deploy's transaction"
    fi
  fi
  log "cycle $cycle done in $(( $(date +%s) - c0 ))s"
  next=$((c0 + INTERVAL)); now=$(date +%s)
  [ "$next" -gt "$now" ] && [ $(( next - T_START )) -lt "$DURATION" ] && sleep $((next - now))
done

# Throughput over the window: every block from H_START to the head, by tx_count and timestamps.
H_END=$(num "$(rpc rand_getHead '[]')" height)
txs=0; ts0=$(num "$(rpc rand_getBlockByHeight "[$H_START]")" timestamp_ms); ts1=$(num "$(rpc rand_getBlockByHeight "[$H_END]")" timestamp_ms)
for hgt in $(seq "$H_START" "$H_END"); do
  n=$(num "$(rpc rand_getBlockByHeight "[$hgt]")" tx_count); txs=$((txs + ${n:-0}))
done
window=$(awk -v a="$ts0" -v b="$ts1" 'BEGIN{printf "%.1f", (b-a)/1000}')
{
  echo "benchmark $LABEL: $(date -u +%FT%TZ)"
  echo "window: heights $H_START..$H_END, $((H_END - H_START + 1)) blocks over ${window}s, $txs transactions"
  awk -v w="$window" -v t="$txs" 'BEGIN{ if (w>0) printf "chain tps: %.4f (%.3f blocks/s)\n", t/w, 0 }'
  awk -v w="$window" -v b="$((H_END - H_START + 1))" 'BEGIN{ if (w>0) printf "block rate: %.3f blocks/s\n", b/w }'
  echo "cycles: $cycle"
  echo
  echo "per operation (mean over successful rows): e2e_s proof_s verify_cold_s verify_warm_s proof_bytes n"
  awk -F, 'NR>1 && $4!="FAIL" { n[$3]++; e[$3]+=$5; p[$3]+=$6; c[$3]+=$7; w[$3]+=$8; b[$3]+=$9 }
           END { for (k in n) printf "  %-9s %7.1f %7.1f %7.2f %7.3f %9.0f %3d\n", k, e[k]/n[k], p[k]/n[k], c[k]/n[k], w[k]/n[k], b[k]/n[k], n[k] }' "$CSV" | sort
  echo
  echo "failures: $(grep -c ',FAIL,' "$CSV")"
} | tee "$SUM"
log "benchmark $LABEL done"
