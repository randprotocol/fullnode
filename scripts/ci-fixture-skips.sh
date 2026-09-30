#!/usr/bin/env bash
# Prints the `--skip` arguments CI passes to the test harness, one list for every job
# (.github/workflows/ci.yml: check-and-test and nightly-proving both run
# `cargo test … -- $(scripts/ci-fixture-skips.sh)`).
#
# Why one list (audit v6, PROC-7): the fast job skipped the fixture-backed aggregation tests by
# name "as covered by the nightly job", and the nightly skipped only `agg_executor::`, set no
# RECURSION_FIXTURES, and so died on the same tests at `randprotocol-node --lib` on every run —
# which also stopped cargo before the zkVM and rVM suites. Two hand-kept lists drift; this is the
# one place.
#
# What is skipped, and why (checked by running them, not by reading names):
#
#   agg_executor::, storage::seal_tests::, and the aggregation tests scattered through node::
#     and rpc:: need a RECURSION_FIXTURES cache. A fixture is minutes of real proving, and
#     `fixture_proof` panics loudly rather than skipping when the cache is absent — deliberately,
#     so a fleet build cannot quietly not test aggregation. A clean runner has no cache.
#     **Nothing in CI runs these tests today**: they run only on a machine that holds a cache
#     (RECURSION_FIXTURES=<dir> cargo test -p randprotocol-node --lib --release). Provisioning a
#     cache for the nightly is the open half of PROC-7; aggregation is off on every chain.
#   round_trips / two_test_profile are the rVM's own long proving tests (tier 19 and 20, tens of
#     GB), in `crates/randprotocol-rvm/tests/aggregate.rs`.
#
# A new fixture-backed test is added HERE, once. With CI_FIXTURE_SKIPS_LIST=1 the patterns are
# printed one per line without `--skip`, for a reader or a script.
set -euo pipefail

PATTERNS=(
  agg_executor::
  round_trips
  two_test_profile
  node::tests::a_batch_cut
  node::tests::a_proposal_carrying_an_aggregate
  node::tests::assembly_
  node::tests::the_covered_source_answers_replayed_history_past_the_window
  node::tests::the_extension_stops_at_the_reader_limit_and_serves_what_it_can
  node::tests::the_sealed_coverage_rule_accepts_marks_and_batch_and_falls_back_otherwise
  node::tests::the_serve_form_carries_the_marker_and_the_table_once_pruned
  node::tests::validate_for_pool_
  rpc::tests::get_emission_is_zero_inflation_and_the_subsidy_schedule
  rpc::tests::the_aggregation_rpc_surface_reports
  storage::seal_tests::
)

if [ "${CI_FIXTURE_SKIPS_LIST:-}" = 1 ]; then
  printf '%s\n' "${PATTERNS[@]}"
  exit 0
fi
out=()
for p in "${PATTERNS[@]}"; do out+=(--skip "$p"); done
echo "${out[*]}"
