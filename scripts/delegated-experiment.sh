#!/usr/bin/env bash
# The spec §11 loop: N sends, each timed from submission to the commit the wallet waits for,
# under whatever RAND_PROVER* is (or is not) set in the environment. Prints one line per run and
# a summary. Usage: scripts/delegated-experiment.sh <to rand1…> [amount RAND=0.5] [runs=20]
set -euo pipefail
TO=${1:?destination address}
AMOUNT=${2:-0.5}
RUNS=${3:-20}
RAND=${RAND_BIN:-target/release/rand}
label="local"; [ -n "${RAND_PROVER:-}" ] && label="delegated ${RAND_PROVER}"
echo "mode: $label; runs: $RUNS; amount: $AMOUNT"
total=0
for i in $(seq 1 "$RUNS"); do
  start=$(date +%s.%N)
  "$RAND" send "$TO" "$AMOUNT" >/dev/null
  end=$(date +%s.%N)
  secs=$(echo "$end - $start" | bc)
  total=$(echo "$total + $secs" | bc)
  printf 'run %2d: %7.1f s\n' "$i" "$secs"
done
printf 'mean: %.1f s over %d runs (%s)\n' "$(echo "$total / $RUNS" | bc -l)" "$RUNS" "$label"
