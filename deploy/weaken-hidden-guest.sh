#!/usr/bin/env bash
# deploy/weaken-hidden-guest.sh — does the hidden-asset guest's mutation fuzz have teeth?
#
# For each check of `guests::bundle_hidden()` (spec docs/superpowers/specs/2026-09-19-hidden-asset-
# bundle-design.md §3.3), this weakens exactly that one check in a *throwaway* edit of
# crates/randprotocol-zkvm/src/guests.rs, runs the mutation fuzz
# (tests/hidden_cheating.rs, `mutation_fuzz_every_…`) against it, and restores the file. A
# weakened guest the fuzz still passes is a check the fuzz cannot see: the script prints MISSED
# for it and exits 1. Every variant CAUGHT is the evidence behind the soundness table's fuzz
# column in docs/confidential.md.
#
# Run from the repository root:  deploy/weaken-hidden-guest.sh [variant ...]   (default: all)
# Environment: HIDDEN_FUZZ_SEED / HIDDEN_FUZZ_ITERS pass through to the fuzz.
#
# Safety:
# - guests.rs is restored from a copy on every exit (trap), and compared byte-for-byte after.
#   The script refuses to start if guests.rs has uncommitted changes, so the copy is HEAD's.
# - Each edit is anchored inside `bundle_hidden` (after its `pub fn` line): the first line there
#   equal to the expected text is replaced, and none is a stop: a drifted guest fails loudly, never
#   a silent no-op.
# - It rebuilds the zkvm crate with the weakened guest. Do not run it while this worktree's own
#   proofs or node/client tests are compiling or running — they would build the weakened guest.
set -euo pipefail

GUESTS=crates/randprotocol-zkvm/src/guests.rs
[ -f "$GUESTS" ] || { echo "run from the repository root" >&2; exit 2; }
if ! git diff --quiet -- "$GUESTS"; then
  echo "$GUESTS has uncommitted changes; commit or stash them first" >&2
  exit 2
fi
BACKUP=$(mktemp "${TMPDIR:-/tmp}/guests.rs.XXXXXX")
cp "$GUESTS" "$BACKUP"
restore() { cp "$BACKUP" "$GUESTS"; cmp -s "$BACKUP" "$GUESTS" && rm -f "$BACKUP"; }
trap restore EXIT

# name | the exact line (inside bundle_hidden, first occurrence) | its replacement
VARIANTS=(
  "anchor|        emit_or_into(&mut a, BAD, T7);|        // WEAKENED: the root == anchor taint removed"
  "asset|        emit_or_into(&mut a, BAD, T0);|        // WEAKENED: the input asset taint removed"
  "asset_r|        emit_or_into(&mut a, BAD, T0);|        if k < 2 { emit_or_into(&mut a, BAD, T0); } // WEAKENED: R slots unchecked"
  "asset_a|        emit_or_into(&mut a, BAD, T0);|        if k >= 2 { emit_or_into(&mut a, BAD, T0); } // WEAKENED: A slots unchecked"
  "dup_all|                emit_or_into(&mut a, BAD, T7); // taint on equality|                // WEAKENED: no duplicate taint"
  "dup_nf|    for region in [NF, CM_OUT] {|    for region in [CM_OUT] { // WEAKENED: nullifier pairs unchecked"
  "dup_cm|    for region in [NF, CM_OUT] {|    for region in [NF] { // WEAKENED: output pairs unchecked"
  "range|        emit_or_into(&mut a, BAD, T2);|        // WEAKENED: the range taint removed"
  "carry|            emit_or_into(a, BAD, T5);|            // WEAKENED: the carry taint removed"
  "compare|        emit_or_into(a, BAD, T2);|        // WEAKENED: both sum comparisons removed"
  "skip_lo|        a.push(or(T1, T1, T2));|        a.push(or(T1, T1, REG_ZERO)); // WEAKENED: the dummy skip reads the low word only"
  "burnmask|    a.push(and(T1, T1, T0));|    // WEAKENED: burn_asset = A unmasked"
)

weaken() { # line replacement — first exact match after `pub fn bundle_hidden`
  python3 - "$GUESTS" "$1" "$2" <<'EOF'
import sys
path, old, new = sys.argv[1:]
lines = open(path).read().split("\n")
start = next(i for i, l in enumerate(lines) if l.startswith("pub fn bundle_hidden()"))
hits = [i for i in range(start, len(lines)) if lines[i] == old]
if not hits:
    sys.exit(f"weaken: {old!r} not found in bundle_hidden — the guest drifted; update the variant")
lines[hits[0]] = new
open(path, "w").write("\n".join(lines))
EOF
}

want=("$@")
missed=0
for v in "${VARIANTS[@]}"; do
  IFS='|' read -r name old new <<<"$v"
  if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " =~ " $name " ]]; then continue; fi
  cp "$BACKUP" "$GUESTS"
  weaken "$old" "$new"
  log=$(mktemp "${TMPDIR:-/tmp}/weaken-$name.XXXXXX")
  started=$(date +%s)
  if cargo test --release -p randprotocol-zkvm --test hidden_cheating mutation_fuzz_every -- --nocapture >"$log" 2>&1; then
    echo "MISSED  $name — the fuzz passed against a guest without this check ($(( $(date +%s) - started )) s; log $log)"
    missed=1
  elif grep -q "The guest published\|did not publish its honest digest\|trapped instead of tainting" "$log"; then
    where=$(grep -o "base [0-9]*, mutation [0-9]*: [^.]*\|base [0-9]*: an honest witness did not publish its honest digest" "$log" | head -1)
    echo "CAUGHT  $name — $where ($(( $(date +%s) - started )) s)"
    rm -f "$log"
  else
    echo "ERROR   $name — the run failed for another reason (build?); log $log"
    missed=1
  fi
done
restore
trap - EXIT
git diff --quiet -- "$GUESTS" && echo "restored: $GUESTS is identical to HEAD"
exit $missed
