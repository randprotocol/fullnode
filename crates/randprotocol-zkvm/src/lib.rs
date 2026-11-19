pub mod isa;
pub mod asm;
pub mod guests;
pub mod emulator;
pub mod tables;
pub mod machine;
/// Vendored: the gas meter (`gas_of`, `row_gas`, `gas_max_declared`; constraint set 11's cell-count
/// weights, the per-op `MODQ` prices).
pub mod gas;
/// Vendored: HCS-1's stable key derivation, written for the next constraint set, not wired in.
pub mod key_derivation_v2;
/// Vendored: the committed Poseidon2 round-constant table (audit finding ZKV-2); since constraint
/// set 11 the Grain-derived constants (ZKVM-107).
pub mod poseidon2_constants;
/// Vendored (constraint set 11, ZKVM-107): the Grain LFSR that re-derives the table, and its tests.
pub mod poseidon2_grain;
pub mod hash;
/// Vendored (ZKVM-108): the salted program commitment and the admitted-programs tree, host
/// arithmetic only (no constraint uses it yet).
pub mod program_commitment;
pub mod keccak;
pub mod sha256;
/// Vendored (private multisig phase 4): the `MODQ` syscall's host model (`Args`, the ops over Z_q).
pub mod modq;
/// Vendored (private multisig phase 4): the `msauth` guest's host model — layout, tags 65-69, witness.
pub mod msauth;
/// Vendored (private multisig phase 4): host-side Keccak for `dilithium-core` (tests and witnesses).
/// Not on wasm32, where `dilithium-core`'s `asm!` barrier does not compile (`Cargo.toml`).
#[cfg(not(target_arch = "wasm32"))]
pub mod dilithium_host;
pub mod sbpf;
pub mod notes;
/// Node-local (not vendored): the hidden-asset bundle's layout, digest and witness builder.
pub mod hidden;
/// Node-local (not vendored): delegated proving's auth guest — its input layout and commitment.
pub mod auth;
/// Node-local (not vendored): RPL-3 perps' Poseidon2 domain tags.
pub mod perps;
pub mod evm;
pub mod viewing;
pub mod ledger;
pub mod address;
pub mod call_envelope;
pub mod executor;
pub mod codec;
