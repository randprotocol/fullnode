//! What a run costs in gas (fullnode spec 2026-09-28 §3.1; constraint set 8), at the weights of
//! constraint set 11 (ZKVM-202). One cpu row is one gas, and with it the tier's slot: two alu rows
//! and four memory rows. A row that pulls a block into another table weighs what that block and
//! the chip's own memory rows come to in committed trace cells, in slots, rounded
//! (`docs/07-gas.md` has the count, `tests/gas_cells.rs` enforces it within ±15 %):
//!
//! | row | pulls | weight | through set 10 |
//! |---|---|---:|---:|
//! | `POSEIDON2` absorb row, digest-prefix row | one 32-row permutation | 4 | 3 |
//! | `KECCAK` | 32 keccak rows, 100 memory rows | 134 | 192 |
//! | `SHA256` | 64 sha256 rows, 32 memory rows | 49 | 64 |
//! | `MODQ` `NTT`, `INTT` | 1 024 modq rows, 512 memory rows | 193 | 168 |
//! | `MODQ` `DOT4` | 1 024 modq rows, 2 304 memory rows | 264 | 168 |
//! | `MODQ` `MSUB4` | 1 024 modq rows, 3 328 memory rows | 304 | 168 |
//!
//! The cpu AIR accumulates exactly these weights in its `GAS` column. A `MODQ` row's weight depends
//! on its op, which the cpu row does not decompose: the modq chip supplies it on the `MODQ` bus
//! (`tables::modq`, rule 7) into the cpu's `MODQ_W` column.
use crate::emulator::{CycleEvent, Syscall};
use crate::isa::Program;
use crate::machine::Tier;
use crate::modq::Op;

pub const KECCAK_GAS: u64 = 134;
pub const SHA256_GAS: u64 = 49;
pub const POSEIDON2_ABSORB_GAS: u64 = 4;
/// A `MODQ` call's weight by op (constraint set 11; one flat 168 through set 10, derived from the
/// chip's block alone). Every op pulls one 1 024-row block into the modq table; what differs is the
/// memory rows the chip sends for it — 512 for a transform, 2 304 for `DOT4`, 3 328 for `MSUB4`.
pub const MODQ_NTT_GAS: u64 = 193;
pub const MODQ_INTT_GAS: u64 = 193;
pub const MODQ_DOT4_GAS: u64 = 264;
pub const MODQ_MSUB4_GAS: u64 = 304;
/// The heaviest `MODQ` op's weight: what a header's ceiling must allow every modq block.
pub const MODQ_MAX_GAS: u64 = MODQ_MSUB4_GAS;

/// A `MODQ` row's total weight for `op`.
pub const fn modq_gas(op: Op) -> u64 {
    match op {
        Op::Ntt => MODQ_NTT_GAS,
        Op::Intt => MODQ_INTT_GAS,
        Op::Dot4 => MODQ_DOT4_GAS,
        Op::Msub4 => MODQ_MSUB4_GAS,
    }
}

/// The op a `MODQ` call's `a1` names: its low two bits, as the modq chip's `A1` identity reads
/// them. Total on every word — reserved bits are the chip's to refuse, not the meter's.
pub const fn modq_op(a1: u32) -> Op {
    match a1 & 0b11 {
        0 => Op::Ntt,
        1 => Op::Intt,
        2 => Op::Dot4,
        _ => Op::Msub4,
    }
}

/// The gas the cpu AIR's `GAS` column accumulates for this execution (spec §3.1): the digest
/// prefix rows (program, input, public — real rows that precede any cycle and are never charged
/// twice, each one permutation and so `POSEIDON2_ABSORB_GAS`, ZKV-5), then every cycle at its row
/// weight (`row_gas`).
pub fn gas_of(program: &Program, inputs: &[u32], public: &[u32], events: &[CycleEvent]) -> u64 {
    let prefix = program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len());
    prefix as u64 * POSEIDON2_ABSORB_GAS + events.iter().map(row_gas).sum::<u64>()
}

/// One cycle's weight (spec §3.1): a row is 1; a `POSEIDON2`/`POSEIDON2_LEN` absorb row adds
/// `POSEIDON2_ABSORB_GAS - 1` for its permutation; a `KECCAK` row adds `KECCAK_GAS - 1`; a
/// `SHA256` row adds `SHA256_GAS - 1`; a `MODQ` row adds its op's `modq_gas(op) - 1`. A row is never more than one of these — the ecall row and
/// the two digest write-back rows of a `POSEIDON2` group carry no extra weight of their own.
pub fn row_gas(ev: &CycleEvent) -> u64 {
    1 + match ev.sys {
        Some(Syscall::Keccak { .. }) => KECCAK_GAS - 1,
        Some(Syscall::Sha256 { .. }) => SHA256_GAS - 1,
        Some(Syscall::Modq { a1, .. }) => modq_gas(modq_op(a1)) - 1,
        _ => 0,
    } + if ev.hash_row.as_ref().is_some_and(|h| h.is_absorb()) { POSEIDON2_ABSORB_GAS - 1 } else { 0 }
}

/// The gas no run under this header can exceed — the header's ceiling, and the verifier refuses
/// a `GAS_LIMIT` above it. Four terms, each the most its row kind can contribute at this header:
///
/// - `2^t − 1`: the tier's cycle budget, one gas per cpu row, prefix rows included;
/// - `3 · 2^(t−3)`: every `POSEIDON2`/`POSEIDON2_LEN` absorb row and every digest-prefix row adds
///   `POSEIDON2_ABSORB_GAS − 1 = 3` beyond its own row, and each pulls one permutation into the
///   poseidon2 table, whose height `2^(t+2)` holds `2^(t+2) / 32 = 2^(t−3)` permutation slots — so
///   at most `2^(t−3)` such rows together (the final review's probe, 30 absorbs in a 1 016-row
///   tier-10 run, passed the old `2^t − 1` ceiling);
/// - `133 · 2^klh / 32`: every `KECCAK` row adds 133 and occupies one 32-row keccak block;
/// - `48 · 2^slh / 64`: every `SHA256` row adds 48 and occupies one 64-row sha256 block.
///
/// Height `0` = no such table. The tier is clamped to `[10, 20]` (`machine::TIERS`) and each height
/// to 40 before any shift: the arguments come from an untrusted proof header, and
/// `check_public_values` reaches this before `check_declared_heights` refuses them.
pub fn gas_max(tier: Tier, keccak_log_height: u8, sha256_log_height: u8) -> u64 {
    gas_max_with_modq(tier, keccak_log_height, sha256_log_height, 0)
}

/// [`gas_max`] with the modq table's height (private multisig phase 3): a fifth term,
/// `303 · 2^mlh / 1024` — every `MODQ` row occupies one 1 024-row modq block and adds at most
/// `MODQ_MAX_GAS − 1`, the heaviest op's (`MSUB4`): a ceiling has to cover a table full of them. `modq_log_height = 0` (no modq table) is exactly `gas_max`; the height is clamped at 40
/// like the others. The poseidon2 table is at the tier's full `2^(t+2)`; [`gas_max_declared`]
/// takes a declared height.
pub fn gas_max_with_modq(tier: Tier, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8) -> u64 {
    // `u8::MAX` is clamped to the (clamped) tier's own `t + 2` inside, so an absurd tier is
    // still the nearest real tier's full-height ceiling.
    gas_max_declared(tier, keccak_log_height, sha256_log_height, modq_log_height, u8::MAX)
}

/// [`gas_max_with_modq`] with the poseidon2 table's declared height (constraint set 11, ZKVM-112):
/// the permutation term is `3 · 2^p2lh / 32` — the table's `2^p2lh / 32` permutation slots, each at
/// most one absorb or digest-prefix row — where it was `3 · 2^(t−3)`, the tier's full table. Sound
/// for the same reason as before (constraint set 10's argument): every such row sends one message
/// on the `POSEIDON2` bus that a real block of the declared table must receive, so the run has at
/// most that many of them. `p2lh` is clamped to `[5, t + 2]` before the shift (it comes from an
/// untrusted header; `check_declared_heights_with_modq` refuses anything outside the admitted set
/// later), so the term is never more than the full table's.
pub fn gas_max_declared(tier: Tier, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, poseidon2_log_height: u8) -> u64 {
    let t = tier.0.clamp(crate::machine::TIERS[0], crate::machine::TIERS[crate::machine::TIERS.len() - 1]);
    let cycles = (1u64 << t) - 1;
    let p2 = (poseidon2_log_height as usize).clamp(5, t + 2);
    let absorbs = (POSEIDON2_ABSORB_GAS - 1) << (p2 - 5);
    let blocks = |h: u8, block: u64| if h == 0 { 0 } else { (1u64 << h.min(40)) / block };
    cycles + absorbs + blocks(keccak_log_height, 32) * (KECCAK_GAS - 1) + blocks(sha256_log_height, 64) * (SHA256_GAS - 1)
        + blocks(modq_log_height, crate::tables::modq::BLOCK as u64) * (MODQ_MAX_GAS - 1)
}
