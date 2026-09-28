//! The hidden-asset bundle's host side: its private-input layout, its public digest and the
//! witness builder a wallet proves `guests::bundle_hidden()` with
//! (`docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md`).
//!
//! **Node-local, not vendored.** `notes.rs` — where today's `bundle_input` layout and
//! `bundle_digest` live — is vendored from the research crate by `deploy/sync-zkvm.sh`, and a
//! resync would erase anything added to it; this module is on that script's rsync exclude list
//! instead (as are `guests.rs`/`executor.rs`, where the guest and its prover/verifier live). It
//! builds only on the vendored note layer's own primitives (`notes::hash`, `Note`, `SpendKey`,
//! `DEPTH`), so the commitments, nullifiers and tree it proves against are exactly the pool's.
//!
//! One bundle, four input and four output slots. Slots 0–1 (in and out) carry a **private** asset
//! `A` (`hidden_input::ASSET_A`, a witness word the chain never sees); slots 2–3 carry RAND
//! (asset 0). `A` may be 0, in which case every slot is RAND. What the chain sees is the digest
//! below, and nothing in it names `A`.

use crate::notes::{hash, Note, SpendKey, ViewingKey, Word8, DEPTH};

/// The hidden bundle digest's domain tag. `notes::domain` is vendored, and upstream allocates
/// its tags sequentially from 1 (1–15 here; upstream's research crate is already at 16, a
/// host-only `KEM_SEED_VERSION` this repository never vendored) plus `TEST = 0xff`. A node-local
/// tag therefore sits well clear of that range: 64 (`0x40`), so a future resync cannot collide
/// with it silently — `tests/hidden_bundle.rs` asserts it is outside `1..=0x3f` and not `0xff`,
/// as well as distinct from every tag this crate has.
pub const HIDDEN_BUNDLE_DOMAIN: u32 = 64;

/// Number of input and of output slots.
pub const SLOTS: usize = 4;
/// Slots `0..A_SLOTS` (in and out) carry the private asset `A`; the rest carry RAND.
pub const A_SLOTS: usize = 2;

/// Private-input layout of `guests::bundle_hidden()` — 1 204 words, always all present (a
/// dummy is a zero-amount note, not a shorter witness).
///
/// `sk` 8; four input slots of [`IN_SLOT_WORDS`] (`from` 8, `amount_lo`, `amount_hi`, `asset`,
/// `time`, `r` 8, path `DEPTH × 8`, `index`); `anchor` 8; four outputs of [`OUT_WORDS`] (`pk` 8,
/// `amount_lo`, `amount_hi`, `r` 8 — an output's `from`, asset and time are not witness words:
/// the guest supplies them); `fee` 2, `burn_a` 2, `burn_r` 2, `asset_a`, `time`.
pub mod hidden_input {
    use super::{DEPTH, SLOTS};
    pub const SK: usize = 0;
    /// One input slot: the spent note's fields but its owner (always `pk_self`), its Merkle
    /// path and its leaf index.
    pub const IN_SLOT_WORDS: usize = 8 + 4 + 8 + DEPTH * 8 + 1; // 277
    pub const S_FROM: usize = 0;
    pub const S_AMOUNT_LO: usize = 8;
    pub const S_AMOUNT_HI: usize = 9;
    pub const S_ASSET: usize = 10;
    pub const S_TIME: usize = 11;
    pub const S_R: usize = 12;
    /// The note words of a slot (`from`..`r`), read into RAM up front; the path is not.
    pub const S_NOTE_WORDS: usize = 20;
    pub const S_PATH: usize = 20;
    pub const S_INDEX: usize = S_PATH + DEPTH * 8; // 276
    pub const IN_SLOTS: usize = 8;
    /// Base index of input slot `k`.
    pub const fn in_slot(k: usize) -> usize { IN_SLOTS + k * IN_SLOT_WORDS }
    pub const ANCHOR: usize = in_slot(SLOTS); // 1116
    pub const OUT_WORDS: usize = 18;
    pub const O_PK: usize = 0;
    pub const O_AMOUNT_LO: usize = 8;
    pub const O_AMOUNT_HI: usize = 9;
    pub const O_R: usize = 10;
    pub const OUTS: usize = ANCHOR + 8; // 1124
    /// Base index of output `k`.
    pub const fn out(k: usize) -> usize { OUTS + k * OUT_WORDS }
    pub const FEE_LO: usize = out(SLOTS); // 1196
    pub const FEE_HI: usize = FEE_LO + 1;
    pub const BURN_A_LO: usize = FEE_LO + 2;
    pub const BURN_A_HI: usize = FEE_LO + 3;
    pub const BURN_R_LO: usize = FEE_LO + 4;
    pub const BURN_R_HI: usize = FEE_LO + 5;
    /// PRIVATE: the asset of slots 0–1. Never published.
    pub const ASSET_A: usize = FEE_LO + 6;
    pub const TIME: usize = FEE_LO + 7;
    pub const COUNT: usize = FEE_LO + 8; // 1204
}

/// The plaintext the chain holds for a hidden bundle — everything its digest commits to. `A` is
/// not here: a transfer of any asset publishes the same fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HiddenDigestInput {
    pub anchor: Word8,
    pub nullifiers: [Word8; SLOTS],
    pub commitments: [Word8; SLOTS],
    pub fee: u64,
    /// Burned from slots 0–1 (asset `A`).
    pub burn_a: u64,
    /// Burned from slots 2–3 (RAND).
    pub burn_r: u64,
    /// `A` if `burn_a != 0`, else 0 — a burn is a public boundary, so it names its asset.
    pub burn_asset: u32,
    pub time: u32,
}

/// Words of the digest's message, after the domain tag: `anchor` 8, 4 nullifiers, 4
/// commitments, `fee` 2, `burn_a` 2, `burn_r` 2, `burn_asset`, `time`, `bad` — 82 hashed with
/// the tag, one `POSEIDON2` call in the guest.
pub const PREIMAGE_WORDS: usize = 8 + 8 * SLOTS * 2 + 2 + 2 + 2 + 1 + 1 + 1; // 81

/// The digest's message (without the domain tag), with `bad = 0` — the honest preimage, in the
/// exact word order the guest stages. Exposed for tests that need the tainted (`bad = 1`) value.
pub fn hidden_bundle_preimage(i: &HiddenDigestInput) -> [u32; PREIMAGE_WORDS] {
    let mut m = [0u32; PREIMAGE_WORDS];
    m[0..8].copy_from_slice(&i.anchor);
    for k in 0..SLOTS {
        m[8 + 8 * k..16 + 8 * k].copy_from_slice(&i.nullifiers[k]);
        m[40 + 8 * k..48 + 8 * k].copy_from_slice(&i.commitments[k]);
    }
    let tail = [
        i.fee as u32,
        (i.fee >> 32) as u32,
        i.burn_a as u32,
        (i.burn_a >> 32) as u32,
        i.burn_r as u32,
        (i.burn_r >> 32) as u32,
        i.burn_asset,
        i.time,
        0, // bad: always 0 for the honest host-side reference (see `domain::BUNDLE`'s doc)
    ];
    m[72..].copy_from_slice(&tail);
    m
}

/// `H(HIDDEN_BUNDLE_DOMAIN, anchor, nf0..3, cm0..3, fee, burn_a, burn_r, burn_asset, time, bad = 0)`
/// — what the ledger recomputes from a hidden bundle's plaintext, and what an honest run of
/// `guests::bundle_hidden()` publishes at `notes::output::DIGEST`. A run that tainted `bad`
/// publishes the same message with `bad = 1`, which no plaintext reproduces.
pub fn hidden_bundle_digest(i: &HiddenDigestInput) -> Word8 {
    hash(HIDDEN_BUNDLE_DOMAIN, &hidden_bundle_preimage(i))
}

/// The asset of slot `k` (input or output) in a bundle whose private asset is `asset_a`.
pub const fn slot_asset(k: usize, asset_a: u32) -> u32 {
    if k < A_SLOTS { asset_a } else { 0 }
}

/// An output as the witness carries it: only what the sender chooses. Its `from`, asset and time
/// are not the sender's to choose — the guest commits every output with `from = pk_self`, its
/// slot's asset and the bundle's time — so they are not fields here, and a wallet cannot build a
/// witness whose output commitments differ from the notes it seals (use [`HiddenOutput::note`]
/// for those).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HiddenOutput {
    pub pk: Word8,
    pub amount: u64,
    pub r: Word8,
}

impl HiddenOutput {
    /// The note the guest commits for this output in slot `k`: `from = pk_self`, asset
    /// `slot_asset(k, asset_a)`, the bundle's `time`. What the wallet seals in the envelope.
    pub fn note(&self, k: usize, pk_self: Word8, asset_a: u32, time: u32) -> Note {
        Note { pk: self.pk, from: pk_self, amount: self.amount, asset: slot_asset(k, asset_a), time, r: self.r }
    }
}

/// Builds `guests::bundle_hidden()`'s private-input vector ([`hidden_input::COUNT`] words).
///
/// `inputs[k]` is `(note, path, index)` for input slot `k`; a dummy is `Note::new(pk_self, _, 0,
/// _, _)` with any path (the guest never dereferences a dummy's path) — but, like every note, a
/// **fresh `r`**: two identical dummies share a nullifier and taint the proof. The guest stages
/// every input under its own `pk_self`, so an input note owned by any other key is refused here
/// (panics): its proof would nullify a note that is not the one the caller holds.
///
/// `outputs[k]` gives the output's `pk`, `amount` and `r` ([`HiddenOutput`]). Dummy outputs need
/// a fresh `r` too: two identical outputs taint the proof.
#[allow(clippy::too_many_arguments)]
pub fn hidden_bundle_inputs(
    sk: &SpendKey,
    inputs: &[(Note, [Word8; DEPTH], u32); SLOTS],
    outputs: &[HiddenOutput; SLOTS],
    anchor: Word8,
    fee: u64,
    burn_a: u64,
    burn_r: u64,
    asset_a: u32,
    time: u32,
) -> Vec<u32> {
    let mut v = witness_body(&sk.viewing_key().pk(), "spend key", inputs, outputs, anchor, fee, burn_a, burn_r, asset_a, time);
    v[hidden_input::SK..hidden_input::SK + 8].copy_from_slice(&sk.0);
    v
}

/// The [`hidden_input::COUNT`] words every hidden guest's witness shares — everything but words
/// `0..8` (the spend key in v1/v2, `nk` in v3), left zero for the caller. Refuses (panics) an
/// input not owned by `pk_self`, naming the caller's key as `key` ("spend key", "viewing key").
#[allow(clippy::too_many_arguments)]
fn witness_body(
    pk_self: &Word8,
    key: &str,
    inputs: &[(Note, [Word8; DEPTH], u32); SLOTS],
    outputs: &[HiddenOutput; SLOTS],
    anchor: Word8,
    fee: u64,
    burn_a: u64,
    burn_r: u64,
    asset_a: u32,
    time: u32,
) -> Vec<u32> {
    use hidden_input::*;
    let pk_self = *pk_self;
    let mut v = vec![0u32; COUNT];
    for (k, (note, path, index)) in inputs.iter().enumerate() {
        assert_eq!(note.pk, pk_self, "input {k} is not owned by this {key}");
        let b = in_slot(k);
        v[b + S_FROM..b + S_FROM + 8].copy_from_slice(&note.from);
        v[b + S_AMOUNT_LO] = note.amount as u32;
        v[b + S_AMOUNT_HI] = (note.amount >> 32) as u32;
        v[b + S_ASSET] = note.asset;
        v[b + S_TIME] = note.time;
        v[b + S_R..b + S_R + 8].copy_from_slice(&note.r);
        for (level, sib) in path.iter().enumerate() {
            v[b + S_PATH + 8 * level..b + S_PATH + 8 * level + 8].copy_from_slice(sib);
        }
        v[b + S_INDEX] = *index;
    }
    v[ANCHOR..ANCHOR + 8].copy_from_slice(&anchor);
    for (k, o) in outputs.iter().enumerate() {
        let b = out(k);
        v[b + O_PK..b + O_PK + 8].copy_from_slice(&o.pk);
        v[b + O_AMOUNT_LO] = o.amount as u32;
        v[b + O_AMOUNT_HI] = (o.amount >> 32) as u32;
        v[b + O_R..b + O_R + 8].copy_from_slice(&o.r);
    }
    v[FEE_LO] = fee as u32;
    v[FEE_HI] = (fee >> 32) as u32;
    v[BURN_A_LO] = burn_a as u32;
    v[BURN_A_HI] = (burn_a >> 32) as u32;
    v[BURN_R_LO] = burn_r as u32;
    v[BURN_R_HI] = (burn_r >> 32) as u32;
    v[ASSET_A] = asset_a;
    v[TIME] = time;
    v
}

/// Delegated proving, Phase 2 (`docs/superpowers/specs/2026-09-28-delegated-proving-design.md`
/// §4.1): private-input layout of **bundle guest v3** (`guests::bundle_hidden_v3()`) — 1 212
/// words. It is [`hidden_input`] with two changes and nothing else moved: `nk` takes `sk`'s eight
/// words at 0 (the guest never sees the spend key; `pk_self = H(PK, nk)` is derived from `nk`
/// directly), and the 8-word per-transaction `salt` is appended after `time`, at 1 204. Every
/// other offset is [`hidden_input`]'s own, re-exported rather than copied.
pub mod hidden_input_v3 {
    pub use super::hidden_input::{
        in_slot, out, ANCHOR, ASSET_A, BURN_A_HI, BURN_A_LO, BURN_R_HI, BURN_R_LO, FEE_HI, FEE_LO, IN_SLOTS, IN_SLOT_WORDS,
        OUTS, OUT_WORDS, O_AMOUNT_HI, O_AMOUNT_LO, O_PK, O_R, S_AMOUNT_HI, S_AMOUNT_LO, S_ASSET, S_FROM, S_INDEX,
        S_NOTE_WORDS, S_PATH, S_R, S_TIME, TIME,
    };
    /// The 8-word nullifier key `nk = H(NK, sk)` — where v1/v2 hold `sk`.
    pub const NK: usize = 0;
    /// The 8-word per-transaction salt the auth proof commits to (`auth::auth_commit`).
    pub const SALT: usize = super::hidden_input::COUNT; // 1204
    pub const COUNT: usize = SALT + 8; // 1212
}

/// What the chain holds for a v3 hidden bundle: v1's plaintext plus the public auth commitment
/// `c = auth::auth_commit(nk, salt)` (the `Bundle`'s `auth_commit`), which the auth proof
/// publishes and the bundle digest folds in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HiddenDigestInputV3 {
    pub base: HiddenDigestInput,
    pub auth_commit: Word8,
}

/// Words of the v3 digest's message, after the domain tag: [`PREIMAGE_WORDS`] plus the eight of
/// `auth_commit` — 89, 90 hashed with the tag.
pub const PREIMAGE_WORDS_V3: usize = PREIMAGE_WORDS + 8; // 89

/// The v3 digest's message (without the tag), `bad = 0`: v1's preimage with `auth_commit`
/// inserted immediately before `bad` — `m[0..72]` as v1, `m[72..80]` the tail `fee .. time`,
/// `m[80..88] = auth_commit`, `m[88] = bad`. The exact word order `guests::bundle_hidden_v3()`
/// stages.
pub fn hidden_bundle_preimage_v3(i: &HiddenDigestInputV3) -> [u32; PREIMAGE_WORDS_V3] {
    let v1 = hidden_bundle_preimage(&i.base);
    let mut m = [0u32; PREIMAGE_WORDS_V3];
    m[..PREIMAGE_WORDS - 1].copy_from_slice(&v1[..PREIMAGE_WORDS - 1]);
    m[PREIMAGE_WORDS - 1..PREIMAGE_WORDS_V3 - 1].copy_from_slice(&i.auth_commit);
    m[PREIMAGE_WORDS_V3 - 1] = v1[PREIMAGE_WORDS - 1]; // bad = 0
    m
}

/// `H(HIDDEN_BUNDLE_DOMAIN, anchor, nf0..3, cm0..3, fee, burn_a, burn_r, burn_asset, time,
/// auth_commit, bad = 0)` — what an honest run of `guests::bundle_hidden_v3()` publishes.
///
/// **The same tag, 64, as v1/v2**, and why that is safe *for these two lengths only*.
/// `notes::hash` is p3's `PaddingFreeSponge<_, 8, 4, 4>` over `[tag, msg…]`: rate 4, overwrite
/// mode, zero initial state, no padding, no length binding. A partial final block overwrites only
/// the lanes it has words for; the rest keep the previous permutation's output, which anyone can
/// compute from the message. So a message `M` of length `4k + 2` and `M ‖ [S[2], S[3]]` (length
/// `4k + 4`, `S` the state before the last absorption) collide **by construction, for every `k`**
/// — ZKH-3's zero-extension in the first block is only the `k = 0` case. Reusing one tag for two
/// preimage lengths that end in the same block is therefore NOT safe: an 82- and an 84-word
/// message under tag 64 would be forgeable into each other.
///
/// v1/v2's message is 82 words with the tag (`4·20 + 2`, 21 permutations) and v3's is 90
/// (`4·22 + 2`, 23 permutations): they absorb a different number of blocks, so no such
/// construction links them, and a v3 digest equal to a v1/v2 digest needs a generic collision of
/// the sponge (124-bit capacity). And no chain accepts both: a genesis pins one `hc_bundle`, and
/// the ledger recomputes that guest's digest only. A future preimage length must be checked the
/// same way, or given its own tag.
pub fn hidden_bundle_digest_v3(i: &HiddenDigestInputV3) -> Word8 {
    hash(HIDDEN_BUNDLE_DOMAIN, &hidden_bundle_preimage_v3(i))
}

/// Builds `guests::bundle_hidden_v3()`'s private-input vector ([`hidden_input_v3::COUNT`] words):
/// [`hidden_bundle_inputs`]' witness with `vk.nk` in place of the spend key and `salt` appended.
/// What a light client hands a prover — no word of it can move a note without the auth proof,
/// which only the spend key's holder can make. Every input must be owned by `vk.pk()` (panics
/// otherwise — "not owned by this viewing key" — as [`hidden_bundle_inputs`] does for its spend
/// key); the same fresh-`r` rule for dummies holds.
#[allow(clippy::too_many_arguments)]
pub fn hidden_bundle_inputs_v3(
    vk: &ViewingKey,
    salt: &Word8,
    inputs: &[(Note, [Word8; DEPTH], u32); SLOTS],
    outputs: &[HiddenOutput; SLOTS],
    anchor: Word8,
    fee: u64,
    burn_a: u64,
    burn_r: u64,
    asset_a: u32,
    time: u32,
) -> Vec<u32> {
    use hidden_input_v3::{COUNT, NK, SALT};
    let mut v = witness_body(&vk.pk(), "viewing key", inputs, outputs, anchor, fee, burn_a, burn_r, asset_a, time);
    v[NK..NK + 8].copy_from_slice(&vk.nk);
    debug_assert_eq!(v.len(), SALT);
    v.extend_from_slice(salt);
    debug_assert_eq!(v.len(), COUNT);
    v
}
