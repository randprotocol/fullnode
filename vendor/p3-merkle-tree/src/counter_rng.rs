//! RandProtocol patch (fullnode #151, v0.8.3): counter-mode randomness for the hiding PCS and
//! the hiding MMCS, generated in parallel.
//!
//! Both hiding layers only need their random values to be **uniform over the field and secret**;
//! nothing in the protocol (prover or verifier) depends on them being drawn one after another
//! from a single sequential stream. Upstream Plonky3 nevertheless drew every random column and
//! every Merkle salt from one generator behind a lock, serially: on a tier-14 bundle proof that
//! was ~7.5 s of single-threaded work, 41% of the proof.
//!
//! The construction here: per call (one `commit`, one quotient randomisation, …) the caller's
//! generator `R` supplies one fresh 256-bit secret key ([`CounterModeRng::counter_mode_key`]).
//! The values are then ChaCha20 keyed by that secret, with the 64-bit ChaCha nonce ("stream")
//! set to `lane << 32 | chunk`: `lane` names the matrix (or block) within the call, `chunk` a run
//! of [`CHUNK_ROWS`] consecutive rows. Each chunk is filled by its own stream, so chunks are
//! filled in parallel; distinct `(lane, chunk)` pairs are distinct ChaCha nonces under one key,
//! so the streams never overlap (each nonce has 2^64 blocks of its own, far beyond any chunk).
//!
//! **Security argument.** ChaCha20 is a PRF in (key, nonce, block counter). Keyed by a uniformly
//! random secret key that the caller's cryptographic generator drew, its outputs over distinct
//! (nonce, counter) inputs are computationally indistinguishable from independent uniform words
//! — the same assumption the previous generators already rested on (`rand`'s `StdRng` is
//! ChaCha12; the Poseidon2 sponge of `KeyRngV2::from_seed` is a keyed permutation). Field
//! elements are sampled from those words exactly as before: `StandardUniform`'s rejection
//! sampling for the field (`p3-goldilocks`: draw a `u64`, keep it if it is below the modulus),
//! one stream per chunk, so every value is uniform over the field and independent of the others.
//!
//! **Determinism.** The chunking is a fixed function of the matrix height ([`CHUNK_ROWS`]), never
//! of the thread count, so a run seeded deterministically produces the same values on one thread
//! and on sixty-four.
//!
//! **What does not change.** The values are still committed exactly as before (same widths, same
//! layout, same salts per leaf), so the proof's wire format and the verifier are untouched: the
//! verifier never sees *how* a random value was drawn. A generator that returns `None` from
//! [`CounterModeRng::counter_mode_key`] keeps the old serial path bit for bit — the verifier-key
//! salt streams (`KeyRngV2::from_label`), which are public, consensus-pinned, and must not move.

use alloc::vec::Vec;

use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::{ChaCha20Rng, StdRng};
use rand::{CryptoRng, Rng, RngExt, SeedableRng};

/// Rows per counter-mode chunk: the unit of parallel work and of stream assignment. Fixed, so the
/// values do not depend on the thread count.
pub const CHUNK_ROWS: usize = 1 << 10;

/// A cryptographic generator that may hand out a fresh secret key for counter-mode generation.
pub trait CounterModeRng: CryptoRng {
    /// A fresh 256-bit secret key drawn from this generator (advancing it), or `None` when this
    /// generator's own serial stream must be used unchanged — a deterministic, public stream
    /// whose exact output is pinned elsewhere (a verifier key's salts).
    fn counter_mode_key(&mut self) -> Option<[u8; 32]>;
}

/// Draws 32 bytes from `rng`: the key a secret-seeded generator hands out.
pub fn draw_key<R: Rng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

impl CounterModeRng for StdRng {
    fn counter_mode_key(&mut self) -> Option<[u8; 32]> {
        Some(draw_key(self))
    }
}

impl CounterModeRng for ChaCha20Rng {
    fn counter_mode_key(&mut self) -> Option<[u8; 32]> {
        Some(draw_key(self))
    }
}

/// The stream for `(lane, chunk)` under `key`: ChaCha20, nonce `lane << 32 | chunk`, from block 0.
pub fn stream(key: &[u8; 32], lane: u32, chunk: usize) -> ChaCha20Rng {
    let chunk = u32::try_from(chunk).expect("fewer than 2^32 chunks of CHUNK_ROWS rows");
    let mut rng = ChaCha20Rng::from_seed(*key);
    rng.set_stream((u64::from(lane) << 32) | u64::from(chunk));
    rng
}

/// Fills `values` — row-major, `width` per row — with uniform elements, chunk `c` (rows
/// `c·CHUNK_ROWS ..`) from [`stream`]`(key, lane, c)`, chunks in parallel.
pub fn fill<T: Send>(values: &mut [T], width: usize, key: &[u8; 32], lane: u32)
where
    StandardUniform: Distribution<T>,
{
    if width == 0 || values.is_empty() {
        return;
    }
    values
        .par_chunks_mut(CHUNK_ROWS * width)
        .enumerate()
        .for_each(|(c, chunk)| {
            let mut rng = stream(key, lane, c);
            for v in chunk {
                *v = rng.random();
            }
        });
}

/// A `height × width` matrix of uniform elements — the counter-mode twin of
/// `RowMajorMatrix::rand` — chunk `c` from [`stream`]`(key, lane, c)`, chunks in parallel.
pub fn random_matrix<T: Clone + Send + Sync>(
    height: usize,
    width: usize,
    key: &[u8; 32],
    lane: u32,
) -> RowMajorMatrix<T>
where
    StandardUniform: Distribution<T>,
{
    let values: Vec<T> = if width == 0 {
        Vec::new()
    } else {
        (0..height.div_ceil(CHUNK_ROWS))
            .into_par_iter()
            .flat_map_iter(|c| {
                let rows = CHUNK_ROWS.min(height - c * CHUNK_ROWS);
                let mut rng = stream(key, lane, c);
                (0..rows * width).map(move |_| rng.random())
            })
            .collect()
    };
    RowMajorMatrix::new(values, width)
}

// Tests: `randprotocol-zkvm/tests/counter_rng.rs` (this vendored copy carries no dev-dependencies).
