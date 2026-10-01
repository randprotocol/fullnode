#!/usr/bin/env bash
# Mutation controls for the Fixed zkVM / rVM findings (final security audit v6, HB-4, §8.28
# option 2; issue #100).
#
# "A test exists" is not "the test catches the fix's removal". For each finding below this script
# applies ONE named one-line source edit that removes (or, where noted, defeats) the fix, runs the
# ONE named test that guards it, asserts that the test FAILS, and restores the file. It prints
#
#   ok <ID>: <test> went red
#   MISSING <ID>: <test> stayed green          <- the test does not catch the fix's removal
#   ERROR <ID>: ...                            <- the mutation did not apply / compile, or the
#                                                 test name matched nothing, or the unmutated
#                                                 test was already red (the baseline)
#
# and exits non-zero on any MISSING or ERROR. A MISSING is a finding about the test suite, not a
# reason to soften the mutation.
#
# How it runs. In place, on a CLEAN tree (it refuses a file with uncommitted changes, and restores
# every mutated file with `git checkout --` on every exit path, ctrl-c included), one control at a
# time. First every named test is run unmutated (the baseline: a control on a test that is already
# red, or that names no test, proves nothing); `BASELINE=0` skips that. `ONLY="ID ID"` runs a
# subset. Vendored files ARE edited here, and only here: the edit is applied and restored by this
# script and never committed (`deploy/sync-zkvm.sh` owns their content).
#
#   CARGO_INCREMENTAL=0 scripts/mutation-controls.sh                 # all, ~1-2 h on a laptop
#   ONLY="ZKV-1 HB-3" scripts/mutation-controls.sh
#
# Each control is the finding id, the file, the exact text the edit replaces (first occurrence;
# the script refuses to run a control whose text is not found), the replacement, and the test as
# `cargo test` arguments then the test's full path (run `--exact`, one thread). Every mutation
# recompiles the crate it touches and what depends on it, in release.
#
# Controls the audit already reproduced in its own cycle (not repeated here): INT-1 / COV-2 /
# INT-6 (the 2^7 floors; tests/privacy_floor.rs, cheating.rs), INT-2 / GV-1 (the blinds;
# tests/logup_blind.rs), RVM-1, RVM-2 (= COV-1), TABLES-1, V-TABLES-1 (rVM; ci.yml's zk-guards
# job runs those suites).
#
# No control, and why:
#   CS6-3          the finding is the absence of negative tests; its fix IS a test suite
#                  (tests/hidden_cheating.rs, tests/hidden_trace_forgery.rs).
#   AGG-2          the fix is the aggregate interface itself (the binding words recomputed by the
#                  ledger and checked in the rVM program): no one-line edit removes it and still
#                  lets an honest aggregate verify, and the rVM half needs a >=64 GB proof.
#   INT-4 / ZKM-2  the call binding is a prover change and a verifier change together (the segment
#                  the proof commits to); a one-line removal on either side breaks every honest call,
#                  which any test catches, so the control would say nothing about the guard.
#   INTERFACE-2,-3 their tests (storage seal_tests) need a RECURSION_FIXTURES cache; not runnable
#                  where this script runs. INTERFACE-5 is a performance fix with no correctness test.
#   V-INTERFACE-1, INTERFACE-1's apply twin, the rVM Lows (TABLES-2, OPCODES-3/4, ARITH-4):
#                  dormant (aggregation is off on every chain); not done in this pass.
#   CPU-2, ARITH-1, ZKM-3, ZKM-V1, ISA-V1: one predicate with ISA-1 (pc_window_fits), whose
#                  verifier half is controlled below. ISA-2, ARITH-3, HCS-5, COV-4: the same RANGE8
#                  limbs as ZKM-1 (input), controlled below. VERIFIER-2, V-VERIFIER-1, ISA-5, HB-1:
#                  not done in this pass.
#
# Notes recorded by the first run (2026-10-01; 13 ok, 3 MISSING — the commit message has the output):
#   HCS-1  `key_derivation_v2::ACTIVE` is read by nothing — setting it false changes no key — so
#          the control edits the derivation itself (the two labels swapped in `key_rngs`) and shows
#          the verifier-key pins catch a change to it. The constant is documentation, not a switch.
#   AGG-1, INTERFACE-1  MISSING: each fix has a validate half and an apply half that refuse with
#          the SAME error, and the named tests go through `apply_tx`/`apply_block_with_covered`, so
#          with the validate half removed the apply half still answers and the test cannot tell.
#          What no test pins: `Ledger::validate` alone (the pool's admission path) refusing a
#          re-covered bundle (step 4) or a `SlashAggregator`. Dormant (no chain aggregates).
#   CPUV-1 MISSING: with `warm_bundle` building the bundle key into the shared program-key
#          `Machine`, the test still passes — its twelve program shapes cannot evict anything from
#          the vendored cache (LRU, `KEY_CACHE_CAPACITY` = 64 keys, since constraint set 7 / #54). The
#          test's premise (a FIFO that eleven shapes overflow) is stale; it no longer shows the
#          bundle key needs its own `Machine`.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
LOGDIR="${LOGDIR:-${TMPDIR:-/tmp}/mutation-controls.$$}"
mkdir -p "$LOGDIR"

Z=crates/randprotocol-zkvm/src
C=crates/randprotocol-core/src

# id | file | from | to | cargo args | test path
CONTROLS=(
  "ZKV-1|$Z/machine.rs|Self::Production => 80,|Self::Production => 27,|-p randprotocol-zkvm --lib|machine::fri_soundness_tests::production_profile_meets_the_100_bit_conjectured_target"
  "ZKV-2|$Z/poseidon2_constants.rs|0xee75a7f2107126c1|0xee75a7f2107126c0|-p randprotocol-zkvm --lib|poseidon2_constants::tests::the_permutation_answers_its_known_vectors"
  "HCS-1|$Z/key_derivation_v2.rs|(KeyRngV2::from_label(MMCS_LABEL), KeyRngV2::from_label(PCS_LABEL))|(KeyRngV2::from_label(PCS_LABEL), KeyRngV2::from_label(MMCS_LABEL))|-p randprotocol-zkvm --test verifier_key|the_verifier_keys_answer_their_known_digests"
  "AGG-1|$C/ledger/aggregation.rs|if !ledger.unsealed_fees.contains_key(cover) {|if false {|-p randprotocol-core --lib|ledger::aggregation::payment_tests::an_aggregate_over_an_already_covered_bundle_is_refused_under_a_fresh_nonce"
  "INTERFACE-1|$C/ledger/aggregation.rs|return Err(AggregationError::SlashingRetired.into());|return Ok(());|-p randprotocol-core --lib|ledger::aggregation::register_tests::a_slash_is_refused_whatever_its_headers"
  "CH-3|$Z/executor.rs|if tier > MAX_CALL_TIER {|if false {|-p randprotocol-zkvm --test executor|a_call_declaring_a_tier_above_the_cap_is_refused_before_any_key_is_built"
  "CPU-1|$C/ledger/mod.rs|if words.len() > max_words {|if false {|-p randprotocol-core --lib|ledger::tests::under_hardening_v6_a_deploy_no_call_can_hold_is_refused"
  "CPUV-1|$Z/executor.rs|let _ = self.bundle_machine.verifier_key(|let _ = self.machine.verifier_key(|-p randprotocol-zkvm --test executor|the_bundle_key_survives_eleven_program_shapes_warmed_after_it"
  "ISA-4|$Z/isa.rs|OP_JALR => { if f3 != 0 {|OP_JALR => { if false {|-p randprotocol-zkvm --test next_constraint_set|a_jalr_with_a_nonzero_funct3_is_refused"
  "ZKM-1|$Z/tables/input.rs|b.assert_zero(v(IS_REAL) * (v(WORD) - word));|b.assert_zero(v(IS_REAL) * (word.clone() - word));|-p randprotocol-zkvm --test next_constraint_set|a_non_u32_input_word_is_refused_by_the_air"
  "ARITH-2|$Z/tables/alu.rs|bus::AND4.lookup_key(b, [v(QH3), AB::Expr::from_u32(8), AB::Expr::ZERO], Count::bounded(sll.clone(), 1));|// mutation: the SLL overflow guard removed|-p randprotocol-zkvm --test cheating|an_sll_that_wraps_the_field_is_refused_by_the_overflow_guard"
  "VERIFIER-1|$Z/machine.rs|Some(round) => Err(VerifyError::CommitPowWitness { round }),|Some(_round) => Ok(()),|-p randprotocol-zkvm --test cheating|a_rewritten_commit_phase_pow_word_is_refused"
  "INT-5|$Z/executor.rs|if proof.mem_log_height > ceiling {|if false {|-p randprotocol-zkvm --lib|executor::tests::int5_a_hash_bearing_calls_memory_height_is_capped_by_its_declared_shape"
  "HB-2|$Z/executor.rs|&& proof.mem_log_height != proof.tier.min_mem_log_height()|&& false|-p randprotocol-node --lib|admission::tests::a_proof_with_a_non_canonical_header_is_not_pooled"
  "HB-3|$C/ledger/mod.rs|if self.tree.remaining() < MAX_LEAVES_PER_TX {|if false {|-p randprotocol-core --lib|ledger::tests::a_transaction_that_would_overflow_the_commitment_tree_is_refused_not_a_panic"
  "ISA-1|$Z/machine.rs|if !crate::tables::program::pc_window_fits(entry_pc, proof.program_log_height) {|if false {|-p randprotocol-zkvm --test pc_window|the_verifier_refuses_a_claimed_entry_pc_past_the_window_before_building_a_key"
)

MUTATED=""
restore() {
  if [ -n "$MUTATED" ]; then
    git checkout -- "$MUTATED" && echo "restored $MUTATED" >&2
    MUTATED=""
  fi
}
trap restore EXIT
trap 'restore; exit 130' INT TERM

selected() {
  [ -z "${ONLY:-}" ] && return 0
  for o in $ONLY; do [ "$o" = "$1" ] && return 0; done
  return 1
}

# Runs one test; prints passed|failed|none|build. $1 = log file, $2 = cargo args, $3 = test.
run_test() {
  local log="$1" args="$2" test="$3"
  # shellcheck disable=SC2086
  cargo test --release $args -- --exact "$test" --test-threads=1 >"$log" 2>&1
  if grep -q "^test result: ok\. 1 passed" "$log"; then echo passed
  elif grep -q "1 failed" "$log"; then echo failed
  elif grep -qE "^error(\[E[0-9]+\])?:|could not compile" "$log"; then echo build
  else echo none
  fi
}

fail=0
for c in "${CONTROLS[@]}"; do
  IFS='|' read -r id file from to args test <<<"$c"
  selected "$id" || continue
  if ! git diff --quiet -- "$file"; then
    echo "ERROR $id: $file has uncommitted changes; refusing to mutate it"; fail=1; continue
  fi
  if [ "${BASELINE:-1}" != 0 ]; then
    r=$(run_test "$LOGDIR/$id.baseline.log" "$args" "$test")
    if [ "$r" != passed ]; then
      echo "ERROR $id: the unmutated $test is $r (log $LOGDIR/$id.baseline.log)"; fail=1; continue
    fi
  fi
  if ! FROM="$from" TO="$to" perl -0pi -e 'BEGIN { $f = $ENV{FROM}; $t = $ENV{TO} } $n += s/\Q$f\E/$t/; END { exit($n ? 0 : 3) }' "$file"; then
    echo "ERROR $id: the text to replace is not in $file"; fail=1; git checkout -- "$file"; continue
  fi
  MUTATED="$file"
  r=$(run_test "$LOGDIR/$id.mutated.log" "$args" "$test")
  restore
  case "$r" in
    failed) echo "ok $id: $test went red" ;;
    passed) echo "MISSING $id: $test stayed green"; fail=1 ;;
    build)  echo "ERROR $id: the mutation does not compile (log $LOGDIR/$id.mutated.log)"; fail=1 ;;
    *)      echo "ERROR $id: $test ran no test (log $LOGDIR/$id.mutated.log)"; fail=1 ;;
  esac
done
echo "logs: $LOGDIR" >&2
exit $fail
