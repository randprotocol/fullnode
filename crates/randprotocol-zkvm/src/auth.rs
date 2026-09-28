//! Delegated proving, Phase 2 (`docs/superpowers/specs/2026-09-28-delegated-proving-design.md`
//! §4): the **auth guest**'s host side — its private-input layout and the commitment it
//! publishes. The guest itself is `guests::auth()`.
//!
//! The split: a light client proves a tiny statement about its spend key itself, and hands the
//! bundle proof (which then needs only `nk`) to a prover. The auth guest reads `sk` and a
//! fresh per-transaction `salt`, derives `nk = H(NK, sk)` exactly as every spend does, and
//! publishes `c = H(AUTH, nk, salt)`. It is proved against the transaction's binding as the
//! public segment (the guest never reads it; `H_PUB` binds it), so an auth proof cannot be
//! replayed onto another transaction. The v3 bundle guest (Task 2) recomputes the same `c`
//! from `nk` and `salt` and folds it into its digest.
//!
//! **Node-local, not vendored.** Like `hidden.rs`, this module is on `deploy/sync-zkvm.sh`'s
//! rsync exclude list, and builds only on the vendored note layer's primitives
//! (`notes::hash`, `SpendKey`), so the `nk` it commits to is the pool's own.

use crate::notes::{hash, SpendKey, Word8};

/// The auth commitment's domain tag. The same reasoning as `hidden::HIDDEN_BUNDLE_DOMAIN` (64):
/// upstream's `notes::domain` allocates its tags sequentially from 1 (plus `TEST = 0xff`), so a
/// node-local tag sits clear of `1..=0x3f` where a future resync cannot collide with it silently.
/// 65 (`0x41`) is the next node-local tag after the hidden bundle's. `tests/auth_spike.rs`
/// asserts it is outside `1..=0x3f`, not `0xff`, not 64, and distinct from every tag this crate
/// has.
pub const AUTH_DOMAIN: u32 = 65;

/// Private-input layout of `guests::auth()` — 16 words, always all present.
pub mod auth_input {
    /// The 8-word spend key.
    pub const SK: usize = 0;
    /// The 8-word per-transaction salt (256 fresh random bits; a repeated salt repeats `c` and
    /// links two transactions — the wallet, not the guest, enforces freshness).
    pub const SALT: usize = 8;
    pub const COUNT: usize = 16;
}

/// `c = H(AUTH, nk ‖ salt)` — a fixed 17-word message (the tag plus 16 words), what the auth
/// guest publishes at outputs `0..8`.
pub fn auth_commit(nk: &Word8, salt: &Word8) -> Word8 {
    let mut msg = [0u32; 16];
    msg[..8].copy_from_slice(nk);
    msg[8..].copy_from_slice(salt);
    hash(AUTH_DOMAIN, &msg)
}

/// The auth guest's private inputs, laid out as [`auth_input`].
pub fn auth_inputs(sk: &SpendKey, salt: &Word8) -> Vec<u32> {
    let mut v = Vec::with_capacity(auth_input::COUNT);
    v.extend_from_slice(&sk.0);
    v.extend_from_slice(salt);
    debug_assert_eq!(v.len(), auth_input::COUNT);
    v
}
