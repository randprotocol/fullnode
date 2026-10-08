#!/usr/bin/env bash
# Prints the `--skip` arguments CI passes to the test harness, one list for every job
# (.github/workflows/ci.yml: check-and-test and nightly-proving both run
# `cargo test … -- $(scripts/ci-fixture-skips.sh)`; coverage.yml measures the same run).
#
# Why one list (audit v6, PROC-7): the fast job skipped the fixture-backed aggregation tests by
# name "as covered by the nightly job", and the nightly skipped only `agg_executor::`, set no
# RECURSION_FIXTURES, and so died on the same tests at `randprotocol-node --lib` on every run —
# which also stopped cargo before the zkVM and rVM suites. Two hand-kept lists drift; this is the
# one place.
#
# What is skipped, and why (checked by running them, not by reading names):
#
#   a_one_proof_aggregate_round_trips_and_tampered_variants_are_refused and
#   two_test_profile_bundle_proofs_aggregate_and_verify_natively are the rVM's own long proving
#     tests (tier 19 and 20, tens of GB), in `crates/randprotocol-rvm/tests/aggregate.rs`. Named
#     in full: `--skip` is a substring match, and the bare `round_trips` this list used to carry
#     also skipped every other `…_round_trips…` test in the workspace (nine runnable ones in the
#     node's lib suite alone, and the zkVM's and rVM's codec/ISA round trips).
#
# What is no longer skipped (2026-10-08): the node's fixture-backed aggregation tests —
# `agg_executor::`, `storage::seal_tests::`, the covered-assembly tests in node:: and the
# aggregation tests in rpc::. They read real bundle proofs through `fixture_proof(k)`, and the
# pinned set they need (`Test-0..2`) is committed at crates/randprotocol-node/fixtures/recursion
# and is `fixture_proof`'s default (issue #131), so a clean runner has it. check-and-test runs
# `scripts/recursion-fixtures.sh --check` before the suites, so a missing or edited fixture fails
# there, by name, before a test panics on it. That closes PROC-7's open half for the node crate:
# every one of these tests runs in CI. Measured 2026-10-08: `cargo test -p randprotocol-node --lib
# --release` with no skips at all is 546 passed, 0 failed, 1 ignored (the ignored one is
# agg_executor's tier-18 aggregate prove, `#[ignore]`d in the source, not here); no node test
# needs a fixture outside the in-repo set.
#
# A test that cannot run on a hosted runner is added HERE, once, with its reason. With
# CI_FIXTURE_SKIPS_LIST=1 the patterns are printed one per line without `--skip`, for a reader or
# a script.
set -euo pipefail

PATTERNS=(
  a_one_proof_aggregate_round_trips_and_tampered_variants_are_refused
  two_test_profile_bundle_proofs_aggregate_and_verify_natively
)

if [ "${CI_FIXTURE_SKIPS_LIST:-}" = 1 ]; then
  printf '%s\n' "${PATTERNS[@]}"
  exit 0
fi
out=()
for p in "${PATTERNS[@]}"; do out+=(--skip "$p"); done
echo "${out[*]}"
