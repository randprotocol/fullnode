//! The Poseidon2 sponge exactly as the `POSEIDON2` syscall/chip compute it, for host-side use
//! (guest wrapper generation, the emulator's own reference implementation, and any future
//! ledger/tree code). The chip proves the same sponge, round by round, over the `POSEIDON2`
//! bus (`tables::poseidon2`); this module has no trace columns and no AIR, only the plain
//! arithmetic, so it doubles as the M3-correctness anchor tests compare the emulator/chip
//! against.
use crate::machine::{permutation, Perm, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, Permutation};
use std::sync::OnceLock;

/// `notes::domain::HC` (= 8), inlined: `notes.rs` isn't vendored into this crate (it drags in
/// ml-kem/chacha20poly1305 for a viewing-key stack the node has no use for yet — see
/// `deploy/sync-zkvm.sh`'s header comment), but `program_digest` below and `tables::cpu`'s
/// digest-row prefix both need this exact domain tag to agree. Keep in sync with
/// `research/src/notes.rs`'s `domain::HC` by hand across a resync.
pub(crate) const HC_DOMAIN: u32 = 8;

/// `machine::permutation()` redraws the whole round-constant RNG stream on every call; this
/// crate's hash paths (absorbing one 32-row block per call) run it often enough — up to 1024
/// times for a single `n = 4096` syscall — that redoing that draw per call is wasteful (the
/// arithmetic below is the cheap part). Cached the same way `tables::poseidon2::round_constants`
/// caches its own RNG replay.
fn perm() -> &'static Perm {
    static PERM: OnceLock<Perm> = OnceLock::new();
    PERM.get_or_init(permutation)
}

/// One raw width-8 permutation over field elements — exactly what the `POSEIDON2` chip's bus
/// entry carries and what `emulator.rs`'s absorb loop chains between blocks. A sponge state's
/// lanes are *not* bounded to `u32` in general (only the rate lanes get overwritten by small
/// absorbed words; the capacity lanes, and any lane after a permutation, are uniformly-
/// distributed field elements that routinely exceed `u32::MAX`), so the emulator must carry the
/// running state as `[Val; 8]`, not `[u32; 8]` — [`permute_words`] below, which round-trips
/// through `u32`, is only a test convenience for states that happen to be small.
pub fn permute_state(state: [Val; 8]) -> [Val; 8] {
    let mut s = state;
    perm().permute_mut(&mut s);
    s
}

/// `permute_state` with a lossy `u32` in/out convenience wrapper: **only** correct when both
/// the input and the output lanes are individually known to be `< 2^32` (e.g. a test fixture's
/// small hand-picked state). It must never be used for the real absorb chain (see
/// `permute_state`'s doc comment) or to read out a final digest (whose canonical `u64` can
/// exceed `u32::MAX` — use [`split_digest`] for that).
pub fn permute_words(state: [u32; 8]) -> [u32; 8] {
    let s = permute_state(state.map(Val::from_u32));
    s.map(|x| x.as_canonical_u64() as u32)
}

/// Splits 4 canonical Goldilocks field-element digest lanes into 8 lo/hi machine words: lane
/// `i`'s canonical `u64` becomes words `2i` (low 32 bits) and `2i+1` (high 32 bits).
pub fn split_digest(elems: [Val; 4]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, e) in elems.iter().enumerate() {
        let v = e.as_canonical_u64();
        out[2 * i] = v as u32;
        out[2 * i + 1] = (v >> 32) as u32;
    }
    out
}

/// The sponge the `POSEIDON2` syscall computes over `msg` (each element already a small `u32`,
/// absorbed as a field element directly — rate 4, overwrite mode, no padding:
/// `PaddingFreeSponge<_, 8, 4, 4>` semantics, matching `p3_symmetric::sponge::PaddingFreeSponge`
/// exactly, empty input included: `sponge_hash(&[])` performs no permutation and returns the
/// all-zero digest), returning the 8 lo/hi digest words.
pub fn sponge_hash(msg: &[u32]) -> [u32; 8] {
    let sponge = PaddingFreeSponge::<_, 8, 4, 4>::new(perm().clone());
    let elems: Vec<Val> = msg.iter().copied().map(Val::from_u32).collect();
    let digest: [Val; 4] = sponge.hash_iter(elems);
    split_digest(digest)
}

/// hc (M3.4): the in-circuit program digest, exactly what `tables::cpu`'s digest rows
/// compute and `pv::HC0..HC7` publish. `Program::digest` (`isa.rs`) is a thin wrapper over
/// this.
///
/// Deliberately **not** `sponge_hash([HC_DOMAIN, base_pc, len, words...])` (a plain
/// message-prefixed sponge, `notes::hash`'s own convention): a message-prefixed sponge's
/// block count is `ceil((3 + len) / 4)`, which depends on `len mod 4` in a way that does not
/// match the `⌈len/4⌉` permutation-per-block cost the cpu table's digest rows are built
/// around (each digest row absorbs up to 4 *program words* into the rate lanes — nothing
/// else — so that its `PROGRAM_WORD` lookups line up one-to-one with `Program::pc_of`).
/// Instead, the domain tag, `base_pc` and `len` are folded into the **capacity** lanes
/// (4..7) of the very first permutation's input, before any word is absorbed: `state_in =
/// [0,0,0,0, HC_DOMAIN, base_pc, len, 0]` rather than the usual all-zero start. That is
/// still "domain and length absorbed first" in the sense that matters (they are inputs to
/// the very first permutation, mixed through it before any word content reaches the output)
/// and still closes the padding-free-sponge trailing-zero concern (two programs with
/// different `len`, or the same words at a different `base_pc`, feed a different state into
/// that first permutation, so no trailing-zero padding trick can make one `hc` a prefix
/// collision of another) — it just does it without spending a rate slot (and hence an extra
/// row) on the header, which is what lets the cost be exactly `Program::digest_rows()`
/// permutations, the number `docs/06-viewing-keys.md`'s cost table and `Tier::poseidon2_height`
/// are measured against.
///
/// Inactive lanes (the last, possibly-partial block) carry the *previous* state forward
/// rather than being zeroed — the same overwrite-mode convention `SYS_POSEIDON2`'s absorb
/// loop and `tables::cpu`'s `IS_HASH` rows already use (`emulator.rs`'s `HashRow::Absorb`
/// doc comment) — so this is bit-for-bit what the cpu AIR's `IS_DIGEST` rows compute.
pub fn program_digest(base_pc: u32, words: &[u32]) -> [u32; 8] {
    let blocks = program_digest_rows(base_pc, words);
    let state = blocks.last().expect("program_digest_rows always returns at least one block").state_out;
    split_digest([state[0], state[1], state[2], state[3]])
}

/// One `tables::cpu` digest row's worth of absorb data — the M3.4 twin of
/// `emulator::HashRow::Absorb`, built directly here (rather than by the emulator) since digest
/// rows are not `CycleEvent`s: `tables::cpu::cpu_trace` uses this to fill `HS0..7`/`HV0..3`/
/// `ACT0..3`/`HASH_LEFT`/`HASH_IDX` for the digest-row prefix exactly as it fills them for a
/// `POSEIDON2` syscall's absorb rows, and the last block's `state_out` is what gets encoded
/// into `pv::HC0..HC7`. Always at least one block (see `program_digest`'s doc comment on why
/// the header alone still costs one permutation).
#[derive(Clone, Copy, Debug)]
pub struct DigestBlock {
    pub idx: u32,
    pub left_before: u32,
    pub words: [u32; 4],
    pub active: [bool; 4],
    pub state_in: [Val; 8],
    pub state_out: [Val; 8],
}

pub fn program_digest_rows(base_pc: u32, words: &[u32]) -> Vec<DigestBlock> {
    let mut state = [Val::ZERO; 8];
    state[4] = Val::from_u32(crate::hash::HC_DOMAIN);
    state[5] = Val::from_u32(base_pc);
    state[6] = Val::from_u32(words.len() as u32);
    let n = words.len();
    let rows = n.div_ceil(4).max(1);
    let mut out = Vec::with_capacity(rows);
    for i in 0..rows {
        let state_in = state;
        let mut block_words = [0u32; 4];
        let mut active = [false; 4];
        let mut merged = state;
        for k in 0..4 {
            let idx = i * 4 + k;
            if idx < n {
                block_words[k] = words[idx];
                active[k] = true;
                merged[k] = Val::from_u32(words[idx]);
            }
        }
        let left_before = (n - i * 4) as u32;
        state = permute_state(merged);
        out.push(DigestBlock { idx: i as u32, left_before, words: block_words, active, state_in, state_out: state });
    }
    out
}
