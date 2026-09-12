//! Shared by the integration tests (`mod common;`), which are separate crates and so cannot
//! `use` each other's items. Home of `rejects()`, the one definition of what counts as "the
//! constraint system caught this" — it lived in `tests/cheating.rs` and had been copied, in
//! slightly weaker form, into `tests/viewing.rs` and `tests/bundle.rs`; the copies drifted
//! (neither accepted `LOOKUP_BALANCE_PANIC`), which is exactly how a test starts passing for
//! the wrong reason. `tests/cheating.rs` owns the test that checks this helper itself
//! (`rejects_only_counts_a_constraint_failure_or_a_verify_error`).
//!
//! Each test crate compiles its own copy of this module and uses only part of it, hence the
//! blanket `dead_code` allow.
#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};

/// The panic `p3-batch-stark`'s debug constraint checker raises when a row violates a
/// constraint. Its full form is
/// `"constraints not satisfied on row {row_index}: failed constraints = {rendered}"` —
/// the `panic!` at the end of the row loop in
/// `~/.cargo/registry/src/index.crates.io-*/p3-batch-stark-0.7.0/src/check_constraints.rs`
/// (line 132 in that release). Matching the fixed prefix is what separates "the constraint
/// system caught this" from any other unwind. This check runs *per AIR instance*, using only
/// that instance's own trace, so it only catches a violation that's local to one table's own
/// row constraints (e.g. the range table's `mp·(1 − is_pow2) = 0`).
pub const CONSTRAINT_PANIC: &str = "constraints not satisfied on row";

/// The panic `p3-lookup`'s debug bus-balance checker
/// (`p3_lookup::debug_util::check_lookups`, `check_lookups`'s `assert_empty`) raises when a
/// *global* lookup — one whose provider and consumers live in different AIR instances, which
/// is every bus in this crate except the ALU/CPU's shared-table cases — has a nonzero net
/// multiplicity for some tuple, after every instance's own `CONSTRAINT_PANIC` pass has
/// already run clean. For a table with no row-level validity marker of its own — the nibble
/// table's every `(a, b)` row is a genuine AND/OR/XOR entry, unlike the range table's
/// `is_pow2` flag — an unpaid extra multiplicity is *only* visible cross-instance: the row
/// itself is perfectly well-formed, so `CONSTRAINT_PANIC` never fires, and this is the sole
/// mechanism left to catch it. It is exactly as much "the constraint system caught this" as
/// `CONSTRAINT_PANIC` — just checked at the scope of the whole batch instead of one row of
/// one instance.
pub const LOOKUP_BALANCE_PANIC: &str = "Lookup mismatch (";

/// A tamper counts as rejected only if `verify` returned an error, or if the panic came from
/// one of the two constraint-system checks above. Anything else — a trace-builder `assert!`,
/// an index out of bounds — means the test tripped over something other than the constraint
/// it was written for, so it must fail rather than pass for the wrong reason.
pub fn rejects(f: impl FnOnce() -> Result<(), shrugg_zkvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => false,
        Ok(Err(_)) => true,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let is_constraint = msg.contains(CONSTRAINT_PANIC) || msg.contains(LOOKUP_BALANCE_PANIC);
            if !is_constraint { eprintln!("rejects(): panic was not a constraint failure: {msg}"); }
            is_constraint
        }
    }
}
