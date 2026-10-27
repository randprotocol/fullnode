//! Delegated proving (`docs/superpowers/specs/2026-09-28-delegated-proving-design.md`): the job a
//! wallet seals to a prover, the prover's key and pairings, and — behind `service` — the queue and
//! the `prover_*` listener. The wire half builds for wasm; the service half does not need to.
/// One tier-14 hidden-asset bundle proof's peak resident memory, measured at the live provers
/// (6.20 GB, 2026-10-27; `docs/node-hardware.md`). The prover's start-up gate (`memory`, `service`
/// builds) and the `rand` CLI's local-proving gate (`randprotocol-client::memory`) both read it.
pub const PROVER_PEAK_BYTES: u64 = 6_200_000_000;
pub mod wire;
pub mod key;
pub mod pairing;
pub mod origins;
pub mod proving;
#[cfg(feature = "service")]
pub mod service;
#[cfg(feature = "service")]
pub mod http;
#[cfg(feature = "service")]
pub mod memory;
