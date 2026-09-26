pub mod isa;
pub mod asm;
pub mod guests;
pub mod emulator;
pub mod tables;
pub mod machine;
/// Vendored: the committed Poseidon2 round-constant table (audit finding ZKV-2).
pub mod poseidon2_constants;
pub mod hash;
pub mod keccak;
pub mod sha256;
pub mod sbpf;
pub mod notes;
/// Node-local (not vendored): the hidden-asset bundle's layout, digest and witness builder.
pub mod hidden;
pub mod evm;
pub mod viewing;
pub mod ledger;
pub mod address;
pub mod call_envelope;
pub mod executor;
pub mod codec;
