//! Constraint set 8: what a run costs in gas (fullnode spec 2026-09-28 §3.1). One cpu row is one
//! gas; a `POSEIDON2` absorb row pulls one 32-row permutation into the poseidon2 table (+2); a
//! `KECCAK` row pulls 32 rows of 2 612 columns and 100 memory rows (+191); a `SHA256` row 64 rows
//! of 466 columns (+63). The cpu AIR accumulates exactly these weights in its `GAS` column.
use crate::emulator::{CycleEvent, Syscall};
use crate::isa::Program;
use crate::machine::Tier;

pub const KECCAK_GAS: u64 = 192;
pub const SHA256_GAS: u64 = 64;
pub const POSEIDON2_ABSORB_GAS: u64 = 3;

/// The gas the cpu AIR's `GAS` column accumulates for this execution (spec §3.1): the digest
/// prefix rows (program, input, public — real rows, one gas each, since they precede any cycle
/// and are never charged twice), then every cycle at its row weight (`row_gas`).
pub fn gas_of(program: &Program, inputs: &[u32], public: &[u32], events: &[CycleEvent]) -> u64 {
    let prefix = program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len());
    prefix as u64 + events.iter().map(row_gas).sum::<u64>()
}

/// One cycle's weight (spec §3.1): a row is 1; a `POSEIDON2`/`POSEIDON2_LEN` absorb row adds
/// `POSEIDON2_ABSORB_GAS - 1` for its permutation; a `KECCAK` row adds `KECCAK_GAS - 1`; a
/// `SHA256` row adds `SHA256_GAS - 1`. A row is never more than one of these — the ecall row and
/// the two digest write-back rows of a `POSEIDON2` group carry no extra weight of their own.
pub fn row_gas(ev: &CycleEvent) -> u64 {
    1 + match ev.sys {
        Some(Syscall::Keccak { .. }) => KECCAK_GAS - 1,
        Some(Syscall::Sha256 { .. }) => SHA256_GAS - 1,
        _ => 0,
    } + if ev.hash_row.as_ref().is_some_and(|h| h.is_absorb()) { POSEIDON2_ABSORB_GAS - 1 } else { 0 }
}

/// The gas no run under this header can exceed — the header's ceiling, and the verifier refuses
/// a `GAS_LIMIT` above it. Four terms, each the most its row kind can contribute at this header:
///
/// - `2^t − 1`: the tier's cycle budget, one gas per cpu row;
/// - `2^(t−2)`: every `POSEIDON2`/`POSEIDON2_LEN` absorb row adds `POSEIDON2_ABSORB_GAS − 1 = 2`
///   beyond its own cycle, and each absorb row pulls one permutation into the poseidon2 table,
///   whose height `2^(t+2)` holds `2^(t+2) / 32 = 2^(t−3)` permutation slots — so at most
///   `2^(t−3)` absorb rows, `2 · 2^(t−3) = 2^(t−2)` gas (the final review's probe, 30 absorbs in
///   a 1 016-row tier-10 run, spent 1 078 against the old `2^t − 1` ceiling);
/// - `191 · 2^klh / 32`: every `KECCAK` row adds 191 and occupies one 32-row keccak block;
/// - `63 · 2^slh / 64`: every `SHA256` row adds 63 and occupies one 64-row sha256 block.
///
/// Height `0` = no such table. The tier is clamped to `[10, 20]` (`machine::TIERS`) and each height
/// to 40 before any shift: the arguments come from an untrusted proof header, and
/// `check_public_values` reaches this before `check_declared_heights` refuses them.
pub fn gas_max(tier: Tier, keccak_log_height: u8, sha256_log_height: u8) -> u64 {
    let t = tier.0.clamp(crate::machine::TIERS[0], crate::machine::TIERS[crate::machine::TIERS.len() - 1]);
    let cycles = (1u64 << t) - 1;
    let absorbs = 1u64 << (t - 2);
    let blocks = |h: u8, block: u64| if h == 0 { 0 } else { (1u64 << h.min(40)) / block };
    cycles + absorbs + blocks(keccak_log_height, 32) * (KECCAK_GAS - 1) + blocks(sha256_log_height, 64) * (SHA256_GAS - 1)
}
