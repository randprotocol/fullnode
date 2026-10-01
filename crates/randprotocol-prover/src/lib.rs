//! Delegated proving (`docs/superpowers/specs/2026-09-28-delegated-proving-design.md`): the job a
//! wallet seals to a prover, the prover's key and pairings, and — behind `service` — the queue and
//! the `prover_*` listener. The wire half builds for wasm; the service half does not need to.
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
