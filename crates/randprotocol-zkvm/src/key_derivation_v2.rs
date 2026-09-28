//! HCS-1 (the 2026-09-27 zkVM review): the verifier-key salt stream. **Live since constraint set 7**
//! ([`ACTIVE`]): every verifier key's preprocessed commitment — here and in `recursion` — is salted
//! from [`KeyRngV2`], and no consensus-facing value reads `rand`'s `StdRng` any more.
//!
//! **Why it exists.** Every verifier key's preprocessed commitment goes through the *hiding* MMCS,
//! which salts every committed row with elements drawn from its RNG (`hiding_mmcs.rs`'s
//! `RowMajorMatrix::rand(rng, height, SALT_ELEMS)`), so the salts are inside the Merkle cap the
//! Fiat–Shamir transcript absorbs first. Through constraint set 6 that RNG was
//! `StdRng::seed_from_u64(KEY_SEED)` (`machine::key_config`), and `rand` documents `StdRng` as *not*
//! reproducible across releases — both its algorithm (ChaCha12 today) and `rand_core`'s
//! `seed_from_u64` expansion (PCG32 today) may change. Chain 15 is protected by an exact pin of
//! `rand`, `rand_core` and `chacha20` (`Cargo.toml`) and by `tests/verifier_key.rs`. That is a guard,
//! not a fix: the chain's keys should be a function of things this repository specifies. This
//! module is that function. (Measured while writing it: the *PCS* RNG, the second of `key_rngs`'
//! pair, does not enter the key at all — perturbing its seed leaves every pinned digest unchanged —
//! so only the MMCS stream needed replacing. The pair is derived anyway so the switch is
//! type-for-type.)
//!
//! **What it is.** A sponge over the committed Poseidon2 permutation (`poseidon2_constants` — the
//! table ZKV-2 froze, the same one the chip proves), width 8, rate 4, capacity 4:
//!
//! 1. The preimage is `u32` words: `DOMAIN`'s bytes and then the caller's bytes, each as
//!    `[byte length, bytes packed four to a word little-endian, zero-padded]`. `DOMAIN` is
//!    `"rand-vk-salt-v2"`; a label constructor adds the marker `"label"` before the label, a seed
//!    constructor `"seed"` before the 32 seed bytes, so a label can never be read as a seed.
//! 2. The capacity lane `state[7]` starts at the preimage's word count — the length is in the
//!    capacity, which is exactly what the `POSEIDON2` syscall lacks (HCS-4: `[a]` and `[a, 0]`
//!    collide there), so no two preimages share a state.
//! 3. Absorb four words at a time *by addition* into `state[0..4]`, permuting after every block
//!    (the last one zero-padded — unambiguous because of step 2).
//! 4. Squeeze: permute, emit the low 32 bits of `state[0..4]`'s canonical values, repeat. The low
//!    32 bits of a uniform Goldilocks element are within `2^-32` of uniform (the field is
//!    `2^64 − 2^32 + 1`); `next_u64` is two such words, low first.
//!
//! Nothing here touches `rand`'s generators: the traits it implements are `rand_core`'s (so
//! `MerkleTreeHidingMmcs<…, SaltRng, …>` and `HidingFriPcs<…, SaltRng>` type-check), but the stream
//! is this file's arithmetic over this repository's constants.
//!
//! **How it is wired (constraint set 7).** One configuration type serves the verifier key and the
//! proof — `prove_batch` takes the proving config and the key's `ProverData`, and both must be the
//! same `StarkGenericConfig` — so the salt generator is one type, [`SaltRng`], with two sources: a
//! key config's is [`SaltRng::Key`] (this stream, from [`key_rngs`]'s labels — `recursion` derives
//! its own from its own labels), a proving config's is [`SaltRng::Fresh`] (`StdRng` from OS
//! entropy — proving blinding, which *should* be random, and is where `rand` stays). The one place
//! the two could meet is a clone: `MerkleTreeHidingMmcs` and `HidingFriPcs` clone themselves by
//! re-seeding `R::from_rng(&mut self.rng)`, and `SeedableRng::from_seed` for `SaltRng` always
//! builds a [`KeyRngV2`] — so a clone of a key config is still `StdRng`-free whatever p3 clones,
//! and a clone of a proving config is a Poseidon2 sponge keyed by 32 bytes of OS entropy (which the
//! `TryCryptoRng` note below covers; it salts only the FRI commit-phase trees, a few hundred
//! thousand elements a proof, so the slower generator costs milliseconds). `KEY_SEED` is gone; the
//! three exact `rand` pins stay (they cost nothing, and `rand` still decides proving's salts).
use crate::machine::Val;
use core::convert::Infallible;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use rand_core::{SeedableRng, TryCryptoRng, TryRng};

/// `true` from constraint set 7 (chain 16): every verifier key is salted from this module's stream.
/// `false` on chains up to 15, whose keys were `StdRng::seed_from_u64(KEY_SEED)`'s. Nothing reads
/// it; it exists so the state of the switch is a named fact, tested
/// (`tests/key_derivation_v2.rs::v2_is_the_live_derivation`), rather than folklore.
pub const ACTIVE: bool = true;

/// The derivation's domain tag, absorbed before anything else.
pub const DOMAIN: &[u8] = b"rand-vk-salt-v2";
/// The label [`key_rngs`] derives the value-MMCS salt stream from.
pub const MMCS_LABEL: &[u8] = b"key/mmcs";
/// The label [`key_rngs`] derives the PCS stream from (unused by the key today — see the module
/// comment — but derived, so the pair stays type-for-type with `machine::key_rngs`).
pub const PCS_LABEL: &[u8] = b"key/pcs";

/// The Poseidon2 sponge generator the module comment specifies.
#[derive(Clone, Debug)]
pub struct KeyRngV2 {
    state: [Val; 8],
    /// Squeezed words not yet handed out, consumed from `pos`.
    out: [u32; 4],
    pos: usize,
}

/// `[byte length, bytes packed four to a word, little-endian, zero-padded]` — step 1.
fn push_bytes(words: &mut Vec<u32>, bytes: &[u8]) {
    words.push(u32::try_from(bytes.len()).expect("a label is far below 4 GiB"));
    for chunk in bytes.chunks(4) {
        let mut w = [0u8; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_le_bytes(w));
    }
}

impl KeyRngV2 {
    fn from_parts(marker: &[u8], bytes: &[u8]) -> Self {
        let mut words = Vec::new();
        push_bytes(&mut words, DOMAIN);
        push_bytes(&mut words, marker);
        push_bytes(&mut words, bytes);
        let mut state = [Val::ZERO; 8];
        state[7] = Val::from_u64(words.len() as u64);
        for block in words.chunks(4) {
            for (lane, w) in state.iter_mut().zip(block) {
                *lane += Val::from_u32(*w);
            }
            state = crate::hash::permute_state(state);
        }
        // `pos == 4`: the first draw squeezes.
        Self { state, out: [0; 4], pos: 4 }
    }

    /// The stream for `label`: a pure function of `DOMAIN`, `label` and the committed Poseidon2
    /// table.
    pub fn from_label(label: &[u8]) -> Self { Self::from_parts(b"label", label) }

    fn squeeze(&mut self) {
        self.state = crate::hash::permute_state(self.state);
        self.out = std::array::from_fn(|i| self.state[i].as_canonical_u64() as u32);
        self.pos = 0;
    }

    fn word(&mut self) -> u32 {
        if self.pos == 4 {
            self.squeeze();
        }
        let w = self.out[self.pos];
        self.pos += 1;
        w
    }
}

impl TryRng for KeyRngV2 {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> { Ok(self.word()) }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let lo = self.word() as u64;
        Ok(lo | (self.word() as u64) << 32)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(4) {
            let w = self.word().to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
        Ok(())
    }
}

/// A Poseidon2 sponge with a four-element (~256-bit) capacity and a secret 32-byte seed absorbed is a
/// cryptographic generator in the sense p3's hiding MMCS asks for (`CryptoRng` "rules out
/// generators known to be unsuitable"). For a verifier key the question never arises — its salts
/// are public by construction — but the proving configs would seed this type from OS entropy at the
/// switch, and there the salts must be unpredictable.
impl TryCryptoRng for KeyRngV2 {}

impl SeedableRng for KeyRngV2 {
    type Seed = [u8; 32];
    /// Domain-separated from [`KeyRngV2::from_label`] by its marker. Note that `SeedableRng`'s
    /// *provided* `seed_from_u64` expands a `u64` through `rand_core`'s own PCG32 — a stream this
    /// module exists to stop depending on — so a consensus-facing caller uses `from_label` (or
    /// `from_seed` with bytes it specifies), never `seed_from_u64`.
    fn from_seed(seed: [u8; 32]) -> Self { Self::from_parts(b"seed", &seed) }
}

/// The `(mmcs_rng, pcs_rng)` pair behind `machine::key_config`, from [`MMCS_LABEL`] and
/// [`PCS_LABEL`].
pub fn key_rngs() -> (KeyRngV2, KeyRngV2) { (KeyRngV2::from_label(MMCS_LABEL), KeyRngV2::from_label(PCS_LABEL)) }

/// The salt generator every `Config` in this crate (and `recursion`'s) is built over — the module
/// comment's "How it is wired" has why one type has two sources. Not `Clone` (`StdRng` is not,
/// deliberately: a cloned generator repeats its stream); p3 copies a generator by re-seeding one from
/// it, `SeedableRng::from_rng`, below.
#[derive(Debug)]
pub enum SaltRng {
    /// A verifier key's: this module's Poseidon2 stream, a pure function of a label.
    Key(KeyRngV2),
    /// A proof's: `rand`'s `StdRng`, seeded from OS entropy ([`SaltRng::fresh`]).
    Fresh(rand::rngs::StdRng),
}

impl SaltRng {
    /// A proving config's generator: fresh OS entropy.
    pub fn fresh() -> Self { SaltRng::Fresh(rand::rngs::StdRng::from_rng(&mut rand::rng())) }
    /// A key config's generator for `label` — [`KeyRngV2::from_label`].
    pub fn key(label: &[u8]) -> Self { SaltRng::Key(KeyRngV2::from_label(label)) }
}

impl TryRng for SaltRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        match self { SaltRng::Key(r) => r.try_next_u32(), SaltRng::Fresh(r) => r.try_next_u32() }
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        match self { SaltRng::Key(r) => r.try_next_u64(), SaltRng::Fresh(r) => r.try_next_u64() }
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        match self { SaltRng::Key(r) => r.try_fill_bytes(dst), SaltRng::Fresh(r) => r.try_fill_bytes(dst) }
    }
}

/// Both sources are cryptographic generators: `StdRng` is, and [`KeyRngV2`] keyed by a secret seed
/// is (its own `TryCryptoRng` note).
impl TryCryptoRng for SaltRng {}

impl SeedableRng for SaltRng {
    type Seed = [u8; 32];
    /// Always a [`KeyRngV2`] — never `StdRng`. This is what p3's `Clone` for the hiding MMCS and
    /// PCS calls (`R::from_rng(&mut self.rng)`), and it keeps every clone of a key config on this
    /// module's stream (the module comment, "How it is wired").
    fn from_seed(seed: [u8; 32]) -> Self { SaltRng::Key(KeyRngV2::from_seed(seed)) }
}
