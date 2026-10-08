#!/usr/bin/env bash
# Checks (or re-proves) the recursion fixture set the node suite reads (issue #131).
#
#   scripts/recursion-fixtures.sh --check [<cache dir>]               check only
#   scripts/recursion-fixtures.sh <circuits checkout> [<cache dir>]   prove what is missing or
#                                                                     stale, then check
#
# <cache dir> defaults to $RECURSION_FIXTURES, else the in-repo set
# crates/randprotocol-node/fixtures/recursion — the same default `fixture_proof` uses, so a plain
# `cargo test -p randprotocol-node --lib` reads the directory a plain `--check` checks.
#
# Exit codes: 0 the set is complete and is the pinned bytes; 1 a file is missing, the checkout
# was refused, or a generator process failed; 2 usage; 3 the set is complete but not the pinned
# bytes (a fresh proving run ends here: see "The pinned set").
#
# The set is exactly what `fixture_proof(k)` (crates/randprotocol-node/src/agg_executor.rs) is
# called with — `<dir>/Test-{k}.proof`, a 32-byte `hc` then the postcard proof:
#
#   Test-0  every literal `fixture_proof(0)`: agg_executor::'s admission and executor tests, the
#           covered-assembly tests in node::, the aggregation tests in rpc::, storage::seal_tests::
#           (all run in CI on the in-repo set; ci.yml runs `--check` before them).
#   Test-1, Test-2
#           agg_executor::tests::the_admission_recompute_reproduces_the_pinned_vectors_byte_for_byte
#           (`for k in 1..3`).
#
# A test that calls `fixture_proof` with a new k adds it to REQUIRED here, once.
#
# The pinned set. A fixture's notes are random, and the pinned-vectors test pins the 118-word
# interface list and its digest (`3534960f…`) that those notes produce, so it passes on exactly
# one set of bytes: the cache re-proved 2026-10-03 that the phase-2 re-vendor measured, committed
# as crates/randprotocol-node/fixtures/recursion (#131). A freshly proved set satisfies every
# other fixture-backed test and fails that one at "the pinned 118-word interface list" (measured
# 2026-10-06). So the check compares the three files against PINNED_SHA256 and exits 3 on a
# difference. Proving is for a re-pin, when the vendored zkVM moves: prove into the in-repo
# directory, then re-measure the test's constants and circuits' recursion/docs/02-aggregate.md on
# the new files, and move PINNED_SHA256 with them, in one commit.
#
# The checkout. The fixtures are proofs by circuits' zkVM — `research/` (the prover and the inner
# bundle machine) running the bundle guest from `guests-compiled/` — so those two trees must be
# the ones this repo vendors: .github/workflows/ci.yml's CIRCUITS_PIN (docs and `license` lines
# aside); the script refuses otherwise. A cache proved by another zkVM is what issue #131 found:
# the suite panics with "cs8 proofs carry pv::NUM public values". `recursion/` may drift from the
# pin: it is the rVM, the outer machine (vendored separately into crates/randprotocol-rvm), and
# only hosts the generator, whose harness chooses the witness — random notes either way — and
# writes the file; it does not change what the inner proof proves.
#
# Proving is circuits' `recursion/tests/fixtures.rs` generator (`#[ignore]`d), one process per k,
# in parallel: ~4.6 min a Test proof on an M4 Max (2026-10-06, two in parallel). The generator
# skips a fixture that is cached and still verifies, and re-proves one that does not (stale), so
# every required k is handed to it; a current set costs one verification per k (~5 s).
#
# --check checks that every required file is present (longer than its 32-byte hc) and is the
# pinned bytes; it does not run the verifier. A file from another zkVM cannot be the pinned bytes,
# so a stale cache fails --check with exit 3.
set -euo pipefail

REQUIRED=(Test-0 Test-1 Test-2)
# sha256 of Test-0, Test-1, Test-2 in the pinned cache, in REQUIRED's order.
PINNED_SHA256=(
  162a5199702dc26ea1d60a9053d4b975de91ef76378bec509c9fec9f40bc62d5
  3cd04ebcd16c91664a774342246fef8c5caeb225a335e5b724d988dfcd101a55
  187935fd58a016071236ac2c523fda2be1f1d397c1c8e591e1cfec24ad82645f
)

usage() {
  echo "usage: $0 <circuits checkout> [<cache dir>]   (prove the missing fixtures, then check)" >&2
  echo "       $0 --check [<cache dir>]               (check only)" >&2
  echo "<cache dir> defaults to \$RECURSION_FIXTURES, else crates/randprotocol-node/fixtures/recursion" >&2
  echo "(fixture_proof's default too); exit 3 = complete but not the pinned bytes" >&2
  echo "warning: a prove run without <cache dir> writes into the committed fixtures/recursion set" >&2
  echo "(the re-pin flow); otherwise pass a scratch cache dir" >&2
  exit 2
}

check_only=0
circuits=
if [ "${1:-}" = --check ]; then
  check_only=1
  shift
elif [ $# -ge 1 ] && [ "${1#-}" = "$1" ]; then
  circuits=$1
  shift
else
  usage
fi
[ $# -le 1 ] || usage
repo=$(cd "$(dirname "$0")/.." && pwd)
cache=${1:-${RECURSION_FIXTURES:-$repo/crates/randprotocol-node/fixtures/recursion}}

check() {
  missing=()
  for f in "${REQUIRED[@]}"; do
    # A fixture is at least the 32-byte hc and a proof; an empty or truncated file is missing.
    if [ ! -f "$cache/$f.proof" ] || [ "$(wc -c < "$cache/$f.proof")" -le 32 ]; then
      missing+=("$f.proof")
    fi
  done
  if [ ${#missing[@]} -ne 0 ]; then
    echo "recursion fixtures: $cache is missing ${missing[*]} (the node suite needs ${REQUIRED[*]})" >&2
    echo "prove them: $0 <circuits checkout at CIRCUITS_PIN> $cache" >&2
    exit 1
  fi
  unpinned=()
  i=0
  for f in "${REQUIRED[@]}"; do
    sum=$(shasum -a 256 "$cache/$f.proof" | cut -d' ' -f1)
    if [ "$sum" = "${PINNED_SHA256[$i]}" ]; then mark=pinned; else mark=unpinned; unpinned+=("$f.proof"); fi
    printf '  %s.proof  %s bytes  %s  %s\n' "$f" "$(wc -c < "$cache/$f.proof" | tr -d ' ')" "$sum" "$mark"
    i=$((i + 1))
  done
  if [ ${#unpinned[@]} -ne 0 ]; then
    echo "recursion fixtures: $cache has the set, but ${unpinned[*]} are not the pinned bytes:" >&2
    echo "the_admission_recompute_reproduces_the_pinned_vectors_byte_for_byte will fail" >&2
    echo "(the fixtures' notes are random); use the in-repo set, or re-pin (see this script's header)" >&2
    exit 3
  fi
  echo "recursion fixtures: $cache holds the node suite's set, the pinned bytes"
}

if [ "$check_only" = 1 ]; then
  check
  exit 0
fi

[ -f "$circuits/recursion/tests/fixtures.rs" ] || {
  echo "$circuits: not a circuits checkout (no recursion/tests/fixtures.rs)" >&2
  exit 1
}
pin=$(sed -n 's/^ *CIRCUITS_PIN: *\([0-9a-f]*\).*/\1/p' "$repo/.github/workflows/ci.yml")
[ -n "$pin" ] || { echo "no CIRCUITS_PIN in .github/workflows/ci.yml" >&2; exit 1; }
git -C "$circuits" cat-file -e "$pin^{commit}" 2>/dev/null || {
  echo "$circuits does not have CIRCUITS_PIN $pin: fetch it, or check it out" >&2
  exit 1
}
# Docs and the crates' `license =` metadata do not change what is proved.
git -C "$circuits" diff --quiet -I'^license = ' "$pin" -- research guests-compiled ':(exclude)*.md' || {
  echo "$circuits: research/ or guests-compiled/ differ from CIRCUITS_PIN $pin;" >&2
  echo "the fixtures would prove a zkVM this repo does not vendor. Check out $pin." >&2
  exit 1
}

mkdir -p "$cache"
cache=$(cd "$cache" && pwd)
cd "$circuits/recursion"
# Build once; parallel `cargo test` processes would serialise on the build lock anyway.
cargo test --release --test fixtures --no-run
pids=()
for f in "${REQUIRED[@]}"; do
  k=${f#Test-}
  echo "recursion fixtures: $f (proving unless cached and verifying; ~4.6 min a proof on an M4 Max)"
  FIXTURE_PROFILE=Test FIXTURE_KS=$k RECURSION_FIXTURES=$cache \
    cargo test --release --test fixtures -- --ignored --nocapture &
  pids+=($!)
done
failed=0
for p in "${pids[@]}"; do wait "$p" || failed=1; done
# A generator failure is exit 1, never the check's verdict on a half-written set.
if [ "$failed" != 0 ]; then
  echo "recursion fixtures: a generator process failed (output above)" >&2
  exit 1
fi
check
