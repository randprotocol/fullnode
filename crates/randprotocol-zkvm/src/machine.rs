//! Plonky3 configuration, the `Chip` enum, gas tiers, prove and verify.
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
pub use crate::key_derivation_v2::SaltRng;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub type Perm = Poseidon2Goldilocks<8>;
/// The leaf hasher: a padding-free sponge over the width-8 permutation, rate 4, digest 4.
/// `pub` so that a crate verifying this machine's proofs — `recursion`'s rVM programs — names this
/// alias instead of re-deriving the constants and hoping they match. `#[doc(hidden)]` with the two
/// accessors below: nameable by path, not part of this crate's documented surface.
#[doc(hidden)]
pub type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
/// The internal-node compressor: two 4-element digests into the eight lanes, permuted, first four
/// lanes kept. `pub` for the same reason as [`Hash`].
#[doc(hidden)]
pub type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
type Packing = <Val as Field>::Packing;
/// HCS-1 (constraint set 7): salted through [`SaltRng`] — `key_derivation_v2`'s stream for a verifier
/// key, OS entropy for a proof.
pub type ValMmcs = MerkleTreeHidingMmcs<Packing, Packing, Hash, Compress, SaltRng, 2, 4, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type Dft = Radix2DitParallel<Val>;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SaltRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// The seed the Poseidon2 round constants were once drawn from. The constants themselves are a
/// committed table now (`poseidon2_constants`, audit finding ZKV-2 — a seeded `StdRng` is not
/// stable across `rand` releases); this name remains the key `rand-zkvm-cuda`'s engines take
/// (`constants::permutation(PERM_SEED)` reads the same table). (It was also `val_mmcs_for_tests`'
/// salt seed until HCS-1 took `StdRng` out of every deterministic salt stream; that accessor reads
/// a `key_derivation_v2` label now.)
#[cfg_attr(not(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda")), allow(dead_code))]
pub(crate) const PERM_SEED: u64 = crate::poseidon2_constants::PERM_SEED; // "RandZK"

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FriProfile {
    /// 16 queries, 4 PoW bits, blowup 4 — for `cargo test`. Not a production target, only fast
    /// enough for the suite. Constraint set 11 (ZKVM-111) moved it from blowup 8 to blowup 4 with
    /// `Production`, so the suite proves at the rate the chain does.
    Test,
    /// Rate 1/4 — blowup 4, 92 queries, 24 grinding bits (constraint set 11, ZKVM-111): the
    /// parameters the rVM's own proofs took in `recursion/docs/07-rvm-rate-quarter.md`, which
    /// derives 86.38 proven bits for them against 86.41 for the 80/8/20 profile this replaced (the
    /// whitepaper's table, Draft 3 Part III; ZM1, 2026-09-12, kept 80 queries over the conjectured
    /// 100-bit retune because the *proven* proximity-gaps bound is what the query count buys).
    /// `tests/security.rs` repeats that computation over this machine's own chip shapes. This
    /// profile is consensus-facing (genesis-bound through the node's chain config, never
    /// proof-supplied). It halves every LDE: at tier 14 the prover's peak heap is −58.5 % against
    /// the 80/8/20 profile with the per-chunk quotient layout (`docs/05-roadmap.md`, "ZKVM-111").
    Production,
}

impl FriProfile {
    pub const fn num_queries(self) -> usize {
        match self {
            Self::Test => 16,
            Self::Production => 92,
        }
    }
    pub fn pow_bits(self) -> usize {
        match self {
            Self::Test => 4,
            Self::Production => 24,
        }
    }
    /// The FRI blowup, as a base-2 log: 2 (rate 1/4) for both profiles since constraint set 11
    /// (3, rate 1/8, before).
    pub const fn log_blowup(self) -> usize {
        match self {
            Self::Test | Self::Production => LOG_BLOWUP,
        }
    }
}

/// The width-8 Poseidon2 permutation, built from the committed round-constant table
/// (`poseidon2_constants`) — the same constants the in-circuit chip and the GPU engines read.
pub fn permutation() -> Perm {
    crate::poseidon2_constants::permutation()
}

/// This machine's own `ValMmcs`, deterministically seeded — a test accessor, not a proving path.
///
/// `build_config` keeps its MMCS private behind a seeding strategy, which is right for proving: a
/// hiding commitment must not be salted from a fixed seed. A *verifier* differential test needs the
/// opposite — the same hasher and compressor this machine commits with, reproducible run to run —
/// and gets it here. The salt stream is irrelevant to what such a test checks (it commits and opens
/// through one object), and nothing that proves anything calls this — which is why it is
/// `#[doc(hidden)]`: a deterministically seeded hiding MMCS has no business on the documented surface.
#[doc(hidden)]
pub fn val_mmcs_for_tests() -> ValMmcs {
    let perm = permutation();
    ValMmcs::new(Hash::new(perm.clone()), Compress::new(perm), 2, SaltRng::key(b"tests/val-mmcs"))
}

/// One full Merkle authentication path per query, restored from a pruned multiproof — a test
/// accessor over `MerkleTreeMmcs::restore_and_recompute_paths`.
///
/// `restore_and_recompute_paths` exists in Plonky3 0.7 for exactly this caller: "an in-circuit
/// verifier built around a single-path-per-query gadget, with no notion of a shared/amortized
/// proof" (`p3-merkle-tree-0.7.0/src/mmcs/mod.rs:899-913`). It lives on the *inner*
/// `MerkleTreeMmcs`, which the hiding wrapper keeps private, so this re-attaches the salts and
/// widens the dimensions the way `MerkleTreeHidingMmcs::verify_multi_batch` does
/// (`hiding_mmcs.rs:232-275`) and then hands the job to the inner tree. `dimensions` and
/// `opened_values` are the *unsalted* ones, as the caller of `verify_multi_batch` has them.
///
/// Nothing is checked against the commitment here: `verify_multi_batch` does that, and the two do
/// the same walk.
#[doc(hidden)]
pub fn restore_paths_for_tests(
    mmcs: &ValMmcs,
    dimensions: &[p3_matrix::Dimensions],
    indices: &[usize],
    opened_values: &[Vec<Vec<Val>>],
    multi: &(Vec<Vec<Vec<Val>>>, p3_merkle_tree::PrunedMerklePaths<Val, 4>),
) -> Vec<p3_merkle_tree::MerkleAuthPath<Val, 4>> {
    const SALT_ELEMS: usize = 4;
    type Inner = p3_merkle_tree::MerkleTreeMmcs<Packing, Packing, Hash, Compress, 2, 4>;
    let perm = permutation();
    let inner = Inner::new(Hash::new(perm.clone()), Compress::new(perm), mmcs.cap_height());

    let (salts, pruned) = multi;
    let salted: Vec<Vec<Vec<Val>>> = opened_values
        .iter()
        .zip(salts)
        .map(|(rows, salts_at_index)| {
            rows.iter()
                .zip(salts_at_index)
                .map(|(row, salt)| row.iter().chain(salt.iter()).copied().collect())
                .collect()
        })
        .collect();
    let salted_dims: Vec<p3_matrix::Dimensions> = dimensions
        .iter()
        .map(|d| p3_matrix::Dimensions { width: d.width + SALT_ELEMS, height: d.height })
        .collect();
    inner
        .restore_and_recompute_paths(&salted_dims, indices, &salted, pruned)
        .expect("the multiproof verified, so its paths restore")
}

/// Builds a `Config` from two explicit RNGs: `mmcs_rng` seeds the value MMCS's per-commit
/// hiding salts (used for *every* commit through it, preprocessed traces included — see
/// `p3_merkle_tree::hiding_mmcs::MerkleTreeHidingMmcs::commit`), `pcs_rng` seeds the PCS's own
/// random codewords/quotient blinding. Kept private: callers pick a seeding strategy through
/// `make_config` (fresh OS entropy, for proving) or `key_config` (deterministic, for a
/// preprocessed commitment any verifier can recompute).
fn build_config(profile: FriProfile, mmcs_rng: SaltRng, pcs_rng: SaltRng) -> Config {
    let perm = permutation();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm);
    let val_mmcs = ValMmcs::new(hash, compress, 2, mmcs_rng);
    generic_config(profile, Dft::default(), val_mmcs, pcs_rng)
}

/// A proving `Config` salted from two labels instead of OS entropy — a test accessor, not a proving
/// path (`tests/parallel.rs`: what of a proof does and does not depend on thread scheduling can only
/// be measured with the entropy held fixed). A proof made with it is not hiding, which is why
/// `make_config` never does this and why it is `#[doc(hidden)]`, like `val_mmcs_for_tests`.
#[doc(hidden)]
pub fn seeded_config_for_tests(profile: FriProfile, mmcs_label: &[u8], pcs_label: &[u8]) -> Config {
    build_config(profile, SaltRng::key(mmcs_label), SaltRng::key(pcs_label))
}

/// FRI's rate, as a base-2 log: every committed matrix is extended to `2^LOG_BLOWUP` times its
/// (zero-knowledge-doubled) height. One name for `generic_config`'s parameter and for
/// `prover_data_bytes`, which sizes a cached preprocessed tree from it. 2 (rate 1/4) since
/// constraint set 11 (ZKVM-111); 3 before.
pub const LOG_BLOWUP: usize = 2;

/// The FRI/PCS setup, written once over any value-MMCS and DFT. Every backend goes through
/// here, so "the reference backend uses the same FRI parameters as the CPU one" is not a
/// comment that can drift — `build_config` is literally this function with the Plonky3
/// `ValMmcs`/`Radix2DitParallel` pair, and `reference_cfg`/`cuda_cfg` call it with theirs.
fn generic_config<D, M>(
    profile: FriProfile,
    dft: D,
    val_mmcs: M,
    pcs_rng: SaltRng,
) -> StarkConfig<HidingFriPcs<Val, D, M, ExtensionMmcs<Val, Challenge, M>, SaltRng>, Challenge, Challenger>
where
    D: p3_dft::TwoAdicSubgroupDft<Val>,
    M: p3_commit::Mmcs<Val, MultiProof: Sync, Error: Sync> + Clone,
{
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let fri = FriParameters {
        log_blowup: profile.log_blowup(),
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: profile.num_queries(),
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: profile.pow_bits(),
        mmcs: challenge_mmcs,
    };
    let pcs = HidingFriPcs::new(dft, val_mmcs, fri, 4, pcs_rng);
    StarkConfig::new(pcs, Challenger::new(permutation()))
}

/// The reference (CPU-twin) backend: `rand-zkvm-cuda`'s own Merkle tree and NTT, running on
/// the host. Structurally identical to `Config` — same Poseidon2 permutation, same salt
/// stream, same FRI parameters — so its proofs decode as CPU proofs (see `prove_on`).
#[cfg(feature = "reference-backend")]
mod reference_cfg {
    use super::*;
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::merkle::cpu::CpuHashEngine, SaltRng>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::ntt::cpu::CpuNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, SaltRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(profile: FriProfile, mmcs_rng: SaltRng, pcs_rng: SaltRng) -> Config {
        let engine = std::sync::Arc::new(rand_zkvm_cuda::merkle::cpu::CpuHashEngine::new(PERM_SEED));
        let mmcs = Mmcs::new(engine, PERM_SEED, 2, mmcs_rng);
        super::generic_config(profile, Dft::default(), mmcs, pcs_rng)
    }
}

/// The CUDA backend. With `mock-cuda` the same code runs against the mock driver, so the
/// whole `Backend::Cuda` path is exercised on a machine with no GPU.
#[cfg(any(feature = "cuda", feature = "mock-cuda"))]
mod cuda_cfg {
    use super::*;
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::gpu::hash::CudaHashEngine, SaltRng>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::gpu::ntt::CudaNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, SaltRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(
        profile: FriProfile,
        gpu: std::sync::Arc<rand_zkvm_cuda::gpu::GpuProver>,
        mmcs_rng: SaltRng,
        pcs_rng: SaltRng,
    ) -> Config {
        let engine = std::sync::Arc::new(rand_zkvm_cuda::gpu::hash::CudaHashEngine { gpu: gpu.clone() });
        let mmcs = Mmcs::new(engine, PERM_SEED, 2, mmcs_rng);
        // The tuple-struct constructor, not the alias: `Dft` here is a `type`, and a type
        // alias cannot be called.
        let dft = rand_zkvm_cuda::dft::Dft(std::sync::Arc::new(rand_zkvm_cuda::gpu::ntt::CudaNttEngine { gpu }));
        super::generic_config(profile, dft, mmcs, pcs_rng)
    }
}

/// A test instrument (fullnode #151): a `Config` over explicit generators — a seeded pair makes a
/// proof reproducible (`tests/counter_rng.rs`). Never a production path: `make_config` (fresh
/// entropy) proves, `key_config` (label streams) keys.
#[doc(hidden)]
pub fn config_with_rngs(profile: FriProfile, mmcs_rng: SaltRng, pcs_rng: SaltRng) -> Config {
    build_config(profile, mmcs_rng, pcs_rng)
}

pub fn make_config(profile: FriProfile) -> Config {
    // Fresh entropy per proof, taken from the OS: this is the config actually used to prove,
    // so main-trace and quotient commitments stay hiding.
    build_config(profile, SaltRng::fresh(), SaltRng::fresh())
}

use crate::emulator::{execute, ExecError, Execution};
use crate::isa::Program;
use crate::tables::alu::{alu_trace, AluAir};
use crate::tables::cpu::{cpu_trace, public_values, CpuAir};
use crate::tables::keccak::{keccak_trace, KeccakAir, KeccakEvent};
use crate::tables::memory::{memory_trace, MemoryAir};
use crate::tables::nibble::{nibble_trace, NibbleAir, NibbleCounts};
use crate::tables::poseidon2::{poseidon2_trace, Poseidon2Air, Poseidon2Event};
use crate::tables::program::{self, program_trace, ProgramAir};
use crate::tables::range::{range_trace, RangeAir, RangeCounts};
use crate::tables::sha256::{sha256_trace, Sha256Air, Sha256Event};
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_batch_stark::{BatchProof, CommonData, ProverData, StarkInstance};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::StarkGenericConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const TIERS: [usize; 6] = [10, 12, 14, 16, 18, 20];

/// Constraint set 11 (ZKVM-112): admitted poseidon2 heights are this many doublings apart, counted
/// down from the tier's `t + 2` ([`Tier::admitted_poseidon2_log_heights`]). 2 rather than 1: each
/// admitted height is a distinct verifier key, and 2 keeps them to `(t − 4) / 2` per tier where 1
/// would be `t − 4`, at the price of a table at most four times taller than a run needs (1 would
/// halve that worst case). The table is a fifth to a fifth and a half of a run's main cells at the
/// shapes measured (`docs/05-roadmap.md`, "ZKVM-112"), so the over-allocation costs less than a
/// doubled key set does on a verifier that caches keys by shape.
pub const POSEIDON2_HEIGHT_STEP: u8 = 2;

/// How this machine commits each instance's quotient chunks: one matrix per instance (constraint
/// set 11, ZKVM-111), as the rVM (`../recursion`, `machine::QUOTIENT_LAYOUT`) does. Through set 10
/// it was upstream Plonky3's one matrix per chunk; the per-instance layout commits the same
/// polynomials in fewer, wider matrices, which cut the prover's peak heap by 29.8 % and the proof
/// by 21.1 % at tier 14 (`docs/05-roadmap.md`, "ZKVM-111"). It is a proof-format change: a verifier
/// lists the quotient round under this layout and refuses a proof committed under the other.
///
/// `QuotientLayout` exists only in the vendored fork (`../vendor/p3-batch-stark`), which a package's
/// `[patch]` gives its own builds but not a crate that depends on it — so every crate that builds
/// this one (`evm2rv`, `sbpf2rv`, `rand-guest`, `recursion`, `rand-zkvm-cuda`'s users, the
/// fullnode) patches `p3-batch-stark` to the fork in its own `[patch.crates-io]`.
pub const QUOTIENT_LAYOUT: p3_batch_stark::QuotientLayout = p3_batch_stark::QuotientLayout::PerInstance;

// Audit COV-2 / INT-6: the private-data floor (`tables::MIN_PRIVATE_TABLE_LOG_HEIGHT`) must fit
// every ceiling a floored table meets at the *smallest* tier, or an honest small call would be
// refused for a height the prover chose, not one its workload needed. The verifier's own
// tier-relative ceilings are `keccak ≤ t + 5` and `sha256 ≤ t + 6`; a chain's call rule adds
// `input ≤ t + 2` (fullnode's `max_input_log_height`) — the tightest, hence `t ≥ 5`. `TIERS[0]`
// is 10, so no tier ever needs raising and no `ProveError` exists for it; this assertion is what
// would say so first if a smaller tier were ever added.
const _: () = assert!(crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT as usize <= TIERS[0] + 2);
// And the floor's own derivation: 92 production queries plus the two out-of-domain points must
// not outnumber the table's random rows (`tables::MIN_PRIVATE_TABLE_LOG_HEIGHT`'s doc comment).
const _: () = assert!(1usize << crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT >= FriProfile::Production.num_queries() + 2);

/// M4.2 (controller ruling 1): the sanity ceiling on `Proof::mem_log_height`, the analogue of
/// `tables::program::MAX_LOG_HEIGHT` for a table that has no module of its own to hold one.
/// Like every other declared height it is a *defensive* bound (nothing may reach
/// `1usize << mem_log_height` unchecked), not a soundness one — see `Proof::mem_log_height`.
///
/// 2^24 rows is 16.7 million accesses. Where that actually sits relative to the tiers, since
/// this is the one declared height whose ceiling is *not* comfortably unreachable: a
/// `KECCAK` call costs about three instructions (two `li`s and the `ecall`) and 100 accesses,
/// so a guest doing nothing else reaches roughly `100 · 2^t / 3` accesses at tier `t` —
/// ~0.5 M at tier 14 (2^20), ~2.2 M at tier 16 (2^22), ~8.7 M at tier 18 (2^24, right at the
/// ceiling) and ~35 M at tier 20 (2^26, past it). A keccak-saturated tier-18 or tier-20 guest
/// is therefore the one shape this constant would refuse with
/// `ProveError::TooManyMemoryAccesses` — an honest execution the prover declines rather than
/// an unsound one it accepts, and a proof at either tier is far outside what this crate
/// actually proves today (tier 12 already takes ~24 s). Raising the constant is a one-line
/// change with no soundness consequence if a guest ever gets there.
pub const MAX_MEM_LOG_HEIGHT: u8 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tier(pub usize);
impl Tier {
    pub fn for_cycles(cycles: usize) -> Option<Tier> { TIERS.iter().copied().map(Tier).find(|t| cycles <= t.max_cycles()) }
    /// Audit ZH1 (2026-09-12): the auto-tier pick must fit the *Poseidon2 permutation* budget
    /// too, not just the cycle budget. Since M3.4/M4.1 every digest, indigest and absorb row is
    /// one cycle *and* one permutation, so up to ~`2^t` permutations fit the `2^t - 1` cycle
    /// budget while the poseidon2 table holds only `2^(t+2) / BLOCK = 2^(t-3)` blocks — a
    /// cycles-only pick walked workloads in that band (e.g. a ~600-word barely-executed program
    /// at tier 10: 151 permutations against 128 blocks) straight into `poseidon2_trace`'s
    /// capacity `assert!` instead of climbing to the next tier. `build_traces_salted` re-checks
    /// both budgets regardless of how the tier was chosen.
    ///
    /// The keccak table needs no term here: one permutation is one `SYS_KECCAK` *cycle*, so the
    /// cycle budget already bounds it (`Tier::max_keccak_log_height`'s own argument).
    pub fn for_workload(cycles: usize, permutations: usize) -> Option<Tier> {
        TIERS.iter().copied().map(Tier)
            .find(|t| cycles <= t.max_cycles() && permutations * crate::tables::poseidon2::BLOCK <= t.poseidon2_height())
    }
    pub fn cpu_height(self) -> usize { 1 << self.0 }
    pub fn alu_height(self) -> usize { 1 << (self.0 + 1) }
    /// The memory table's *floor*, `2^(t+2)`: four accesses per cycle (the cpu row's four
    /// slots) times `2^t` cycles. Through M4.1 this was the memory table's height, full stop.
    ///
    /// M4.2 (controller ruling 1) makes it only a floor, because a `KECCAK` row makes 100
    /// memory accesses (50 reads + 50 writes, all sent by the *keccak* chip, all recorded
    /// here) rather than four. The first cut of M4.2 sized the table
    /// `log2_ceil(2^(t+2) + 100·2^(klh−5))` — verifier-computable, but it charged every proof
    /// in existence for a whole extra bit of memory table, since `klh` floors at
    /// `MIN_LOG_HEIGHT` and so the `100·2^(klh−5)` term is never zero: at tier 10 that is
    /// `4 096 + 100 → 2^13`, an exactly doubled table for a guest that never calls `KECCAK`.
    /// The height is a **proof-declared** parameter instead (`Proof::mem_log_height`), the
    /// same treatment `program`/`input`/`keccak` already get: the prover declares
    /// `max(t + 2, log2_ceil(actual accesses + 1))` and the verifier checks only that the
    /// declaration lies in `[t + 2, MAX_MEM_LOG_HEIGHT]`. See `Proof::mem_log_height` for why
    /// that one-sided check is all the soundness argument needs.
    pub fn min_mem_log_height(self) -> u8 { (self.0 + 2) as u8 }
    /// M4.2 (controller ruling 2): the largest `keccak_log_height` this tier can honestly
    /// need. One permutation is one `SYS_KECCAK` cpu row, i.e. one cycle, and a tier holds at
    /// most `2^t` cycles; one permutation occupies one `BLOCK` (`2^MIN_LOG_HEIGHT`) keccak
    /// rows. So `32 · n_perms ≤ 2^(t+5)` and `klh ≤ t + 5` — the *honest-shape* ceiling
    /// `build_traces_salted` (as `ProveError::TooManyPermutations`) and
    /// `check_declared_heights` (as `VerifyError::KeccakHeightExceedsTier`) enforce. It is the
    /// tighter of the two bounds at every tier but the largest: at tier 10 it admits 15 where
    /// the flat `tables::keccak::MAX_LOG_HEIGHT` admits 20 (32 768 permutation slots for at
    /// most 1 023 possible calls).
    ///
    /// M4.2 (Task 5 review): it is *not* the only ceiling. At tier 20 this permits `klh = 25`,
    /// a 2^25-row preprocessed keccak trace the verifier would build before any later check
    /// could reject the proof, so the flat `tables::keccak::MAX_LOG_HEIGHT = 20` is enforced
    /// alongside it and the effective bound is `min(t + 5, MAX_LOG_HEIGHT)`. The two are not
    /// rival answers to one question: this one says what a tier can honestly *need*, the flat
    /// one what an untrusted `u8` may ever *cost* — see `tables::keccak::MAX_LOG_HEIGHT`.
    pub fn max_keccak_log_height(self) -> u8 { (self.0 + crate::tables::keccak::MIN_LOG_HEIGHT as usize) as u8 }
    /// M4.4: the sha256 table's analogue — the largest `sha256_log_height` this tier can honestly
    /// need. One compression is one `SYS_SHA256` cpu row, i.e. one cycle, and a tier holds at most
    /// `2^t` cycles; one compression occupies one `BLOCK` (`2^MIN_LOG_HEIGHT`, 64) sha256 rows. So
    /// `64 · n_compressions ≤ 2^(t+6)` and `slh ≤ t + 6`.
    ///
    /// **Unlike `max_keccak_log_height` this folds the flat cap in**, returning
    /// `min(t + 6, tables::sha256::MAX_LOG_HEIGHT)`. Both bounds exist for the two distinct
    /// reasons M4.2's Task 5 review spelled out — the tier one says what a proof can honestly
    /// *need*, the flat one what an untrusted `u8` may ever *cost* (at tier 20 the tier relation
    /// alone would admit `slh = 26`, a 2^26-row, 10-column preprocessed trace the verifier would
    /// build before any later check could reject the proof) — but keeping them in one method means
    /// no caller can apply one and forget the other, which is exactly the bug that review found.
    /// `check_declared_heights` still runs the flat range check *first*, so a declaration past
    /// both is reported as `VerifyError::Sha256Height` and one that is flat-legal but past the
    /// tier as `Sha256HeightExceedsTier`.
    pub fn max_sha256_log_height(self) -> u8 {
        ((self.0 + crate::tables::sha256::MIN_LOG_HEIGHT as usize) as u8).min(crate::tables::sha256::MAX_LOG_HEIGHT)
    }
    /// Private multisig phase 3 (spec §3.4): the modq table's analogue — one call is one cycle
    /// and one 1 024-row block, so `mlh ≤ t + 10`, folded with the flat
    /// `tables::modq::MAX_LOG_HEIGHT` the way `max_sha256_log_height` folds its own. The tier
    /// bound `min(t + 10, 20)` never binds for `TIERS` (`t + 10 >= 20` from tier 10), so a tier-10
    /// header may declare a 2^20 modq table, the same as the existing flat caps.
    pub fn max_modq_log_height(self) -> u8 {
        ((self.0 + crate::tables::modq::MIN_LOG_HEIGHT as usize) as u8).min(crate::tables::modq::MAX_LOG_HEIGHT)
    }
    /// One padding row is always kept.
    pub fn max_cycles(self) -> usize { self.cpu_height() - 1 }
    /// `2^(t+2)`, i.e. `2^(t-3)` Poseidon2 permutation slots (each block is 32 rows) —
    /// decoupled from `cpu_height`. History: M3.2 shipped `2^t` (`2^(t-5)` slots); M3.3
    /// measured `transfer` at 190 permutations at tier 12 and bumped this to `2^(t+1)`
    /// (256 slots, room to spare). M3.4 added the program digest's own `⌈len/4⌉`
    /// permutations to *every* proof's cost, `transfer`'s included — and `transfer`'s program
    /// is 4 554 words, i.e. 1 139 digest-row permutations on top of its 190 hash-syscall ones,
    /// 1 329 total (`docs/06-viewing-keys.md`'s cost table). Digest rows also count as cycles
    /// (M3.4 ruling), so `transfer`'s total cycle count (3 764 + 1 139 = 4 903) no longer fits
    /// tier 12's 4 095-cycle budget either — it needs at least tier 14 regardless of the
    /// Poseidon2 budget. At tier 14, `2^(t+1)` gives only 1 024 slots (still short of 1 329);
    /// `2^(t+2)` gives 2 048, comfortably enough, so this is the smallest bump that clears the
    /// measured need at the tier `transfer` is forced to anyway — cheaper in proof size than
    /// moving to tier 16 (whose unmodified `2^(t+1)` would also clear it, but at every other
    /// table's much larger tier-16 height too).
    pub fn poseidon2_height(self) -> usize { 1 << (self.0 + 2) }
    /// Constraint set 11 (ZKVM-112): the tallest poseidon2 table this tier admits, as a base-2
    /// log — `t + 2`, the height every proof carried through set 10 ([`Self::poseidon2_height`]).
    /// Saturating, so an untrusted tier cannot overflow it; callers range-check the tier first.
    pub fn max_poseidon2_log_height(self) -> u8 { self.0.saturating_add(2).min(u8::MAX as usize) as u8 }
    /// Constraint set 11 (ZKVM-112): the poseidon2 heights a proof at this tier may declare,
    /// smallest first — `t + 2, t, t − 2, …` ([`POSEIDON2_HEIGHT_STEP`] apart) down to the
    /// private-data floor (`tables::MIN_PRIVATE_TABLE_LOG_HEIGHT`). At the even tiers of `TIERS`
    /// that is `8, 10, …, t + 2`: `(t − 4) / 2` shapes, 3 at tier 10 and 8 at tier 20.
    pub fn admitted_poseidon2_log_heights(self) -> Vec<u8> {
        let max = self.max_poseidon2_log_height() as i32;
        let floor = crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT as i32;
        let mut v: Vec<u8> = (0..).map(|k| max - k * POSEIDON2_HEIGHT_STEP as i32).take_while(|h| *h >= floor).map(|h| h as u8).collect();
        v.reverse();
        v
    }
    /// The poseidon2 height a prover declares by default for `permutations` permutations at this
    /// tier: the smallest admitted one whose table holds them (one 32-row block each). `None` if
    /// even `t + 2` does not.
    pub fn poseidon2_log_height_for(self, permutations: usize) -> Option<u8> {
        self.admitted_poseidon2_log_heights().into_iter().find(|h| permutations * crate::tables::poseidon2::BLOCK <= 1usize << h)
    }
    // M3.4 (fix): there is no `Tier::program_height`. The first cut made the program table's
    // height `cpu_height()` — wrong: a digest row absorbs up to 4 `PROGRAM_WORD`s per *cycle*,
    // so a program with `len` up to `4·(cpu_height − 1)` words fits the cycle budget while
    // needing far more than `cpu_height` program-table rows to hold its own words (and
    // `program_trace`'s own `assert!` would panic, not error, on the mismatch). The program
    // table's height is a **proof-declared** parameter instead — see
    // `tables::program::program_log_height`'s doc comment for the exact rule and the
    // soundness argument for why the verifier does not need to independently bound it against
    // anything besides a sanity ceiling.
}

#[derive(Clone)]
pub enum Chip { Program(ProgramAir), Cpu(CpuAir), Memory(MemoryAir), Alu(AluAir), Range(RangeAir), Nibble(NibbleAir), Poseidon2(Poseidon2Air, usize), Input(crate::tables::input::InputAir), Keccak(KeccakAir, usize), Sha256(Sha256Air, usize), Modq(crate::tables::modq::ModqAir, usize), Public(crate::tables::public::PublicAir) }

impl Chip {
    /// The table's own width — its `col::WIDTH` — without constraint set 7's blind columns. What a
    /// `Traces` matrix is; `BaseAir::width` (and so the committed trace) is this plus
    /// `tables::blind::col::WIDTH`.
    pub fn table_width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::width(a), Chip::Cpu(a) => BaseAir::<Val>::width(a), Chip::Memory(a) => BaseAir::<Val>::width(a), Chip::Alu(a) => BaseAir::<Val>::width(a), Chip::Range(a) => BaseAir::<Val>::width(a), Chip::Nibble(a) => BaseAir::<Val>::width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::width(a), Chip::Input(a) => BaseAir::<Val>::width(a), Chip::Keccak(a, _) => BaseAir::<Val>::width(a), Chip::Sha256(a, _) => BaseAir::<Val>::width(a), Chip::Modq(a, _) => BaseAir::<Val>::width(a), Chip::Public(a) => BaseAir::<Val>::width(a) }
    }
}

impl BaseAir<Val> for Chip {
    /// Constraint set 7: every table carries the LogUp blind's five columns after its own
    /// (`tables::blind`). They are added here, once, rather than in each table's `col` list, so no
    /// table's layout moves and the blind is one piece of code for all eleven.
    fn width(&self) -> usize { self.table_width() + crate::tables::blind::col::WIDTH }
    fn preprocessed_width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Range(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Nibble(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::preprocessed_width(a), Chip::Keccak(a, _) => BaseAir::<Val>::preprocessed_width(a), Chip::Sha256(a, _) => BaseAir::<Val>::preprocessed_width(a), Chip::Modq(a, _) => BaseAir::<Val>::preprocessed_width(a), _ => 0 }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Chip::Program(a) => BaseAir::<Val>::preprocessed_trace(a),
            Chip::Range(a) => BaseAir::<Val>::preprocessed_trace(a),
            Chip::Nibble(a) => BaseAir::<Val>::preprocessed_trace(a),
            // `Poseidon2Air`'s own `BaseAir::preprocessed_trace` deliberately panics (its
            // preprocessed trace depends on the tier's height, which isn't available through
            // that trait method) — go through the height-carrying inherent method instead.
            Chip::Poseidon2(_, height) => Some(Poseidon2Air::preprocessed_trace_at(*height)),
            // Same split, same reason: the keccak table's round/idle selectors and round
            // constants are periodic with period 32 and depend only on the height.
            Chip::Keccak(_, height) => Some(KeccakAir::preprocessed_trace_at(*height)),
            // M4.4: and the sha256 table's row selectors, round constants `K[t]` and the tail
            // one-hots — periodic with period 64, a function of the height alone.
            Chip::Sha256(_, height) => Some(Sha256Air::preprocessed_trace_at(*height)),
            // Private multisig phase 3: and the modq table's 16 period-1 024 columns (stage,
            // butterfly pairs, twiddles, pointwise indices). `ModqAir::preprocessed_trace` is
            // `unreachable!` for the same reason as the three above.
            Chip::Modq(_, height) => Some(crate::tables::modq::ModqAir::preprocessed_trace_at(*height)),
            _ => None,
        }
    }
    fn num_public_values(&self) -> usize { match self { Chip::Cpu(a) => BaseAir::<Val>::num_public_values(a), _ => 0 } }
}

impl<AB> Air<AB> for Chip
where
    AB: AirBuilder<F = Val> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        match self { Chip::Program(a) => a.eval(b), Chip::Cpu(a) => a.eval(b), Chip::Memory(a) => a.eval(b), Chip::Alu(a) => a.eval(b), Chip::Range(a) => a.eval(b), Chip::Nibble(a) => a.eval(b), Chip::Poseidon2(a, _) => a.eval(b), Chip::Input(a) => a.eval(b), Chip::Keccak(a, _) => a.eval(b), Chip::Sha256(a, _) => a.eval(b), Chip::Modq(a, _) => a.eval(b), Chip::Public(a) => a.eval(b) }
        // Constraint set 7: the blind, on the columns after the table's own.
        crate::tables::blind::eval(b, self.table_width());
    }
}

/// New chips are appended at the end: `i == 1` (`Cpu`) must stay the public-values slot that
/// `prove_traces`/`verify` hard-code, so every new chip since M2 has gone at the end rather
/// than disturbing that index. M3.4: no longer takes a `Program` — `ProgramAir` is shape-only
/// now (like `CpuAir`), so the whole chip set is a pure function of `tier`, and `verifier_key`
/// collapses to one entry per tier.
/// M4.2: `keccak_log_height` is the *proof-declared* keccak table height, as a base-2 log — not
/// a tier-derived one, the same treatment `program`'s and `input`'s heights get, and for the
/// same reason (a guest's permutation count has nothing to do with its cycle budget). The
/// height reaches the chip set the way `poseidon2_height` does, as a field of the variant,
/// because the keccak table has preprocessed columns whose height it needs.
///
/// M4.2 (Task 6): **the keccak table is optional per proof.** `keccak_log_height == 0` means the
/// proof declares no keccak table and this returns eight chips; any other value returns nine,
/// with `Chip::Keccak` last. The keccak chip is 2 612 + 99 columns and every FRI query opens a
/// leaf of that width, so carrying it unused cost ~1.91 MB per production proof (80 queries; the
/// same measurement was ~705 KB at the 27 queries in force when M4.2 took it) — enough to push
/// a ~300 KB shielded bundle proof past the node's 1 MiB cap (`docs/03-privacy.md`'s M4.2
/// measurement). Dropping it is safe because the `KECCAK` bus then has no provider at all: a cpu
/// row with `SYS_KECCAK = 1` leaves the bus unbalanced and cannot be proved. Nothing about the
/// cpu table or the keccak AIR changes — only whether the instance is in the batch.
///
/// The keccak instance is appended **last** precisely so that dropping it cannot disturb any
/// other chip's index — in particular `i == 1` (`Cpu`), the public-values slot `prove_traces`
/// and `verify` hard-code, and `i == 2` (`Memory`), which `tests/cheating.rs` indexes directly.
///
/// M4.4 appends `Chip::Sha256` after it, on the same terms and for the same reasons
/// (`sha256_log_height == 0` means no sha256 table; the chip is 466 + 10 columns). The two are
/// independent, so this returns eight, nine or ten chips — and because both optional instances
/// are at the end, in a fixed order (keccak then sha256), a batch that carries only the sha256
/// table still has it at the *ninth* position with no other index disturbed.
///
/// Constraint set 6 appends `Chip::Public` **after both of them**, and it is mandatory — every
/// proof carries a public table, even an empty one (four rows). Last, rather than beside
/// `Chip::Input` where it structurally belongs, for the reason every chip since M4.2 has gone
/// last: `i == 1` (`Cpu`) is the public-values slot `prove_traces`/`verify` hard-code and
/// `i == 2` (`Memory`) is indexed directly by `tests/cheating.rs`, and inserting in the middle
/// would move both. Its own index is therefore `8 + (klh != 0) + (slh != 0) + (mlh != 0)` — 8 to 11 — and
/// the batch carries nine to twelve instances.
pub fn chips(tier: Tier, keccak_log_height: u8, sha256_log_height: u8) -> Vec<Chip> {
    chips_with_modq(tier, keccak_log_height, sha256_log_height, 0)
}

/// [`chips`] with the modq table's declared height (private multisig phase 3). `0` declares no
/// modq table and is exactly `chips`; any other value pushes `Chip::Modq` after `Sha256` and
/// before the mandatory `Public`, so no earlier index moves. The poseidon2 table is at the tier's
/// full height; [`chips_at`] takes a declared one.
pub fn chips_with_modq(tier: Tier, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8) -> Vec<Chip> {
    chips_at(tier, keccak_log_height, sha256_log_height, modq_log_height, tier.poseidon2_height())
}

/// [`chips_with_modq`] with the poseidon2 table's height (rows, not a log) as an argument —
/// constraint set 11's chip set (ZKVM-112): the poseidon2 table is as tall as the proof declares
/// (`Proof::poseidon2_log_height`). [`chips`] and [`chips_with_modq`] are this at the tier's full
/// `2^(t+2)` — the right chip set for a proof only when it declares that height.
pub fn chips_at(tier: Tier, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, poseidon2_height: usize) -> Vec<Chip> {
    let _ = tier;
    let mut v = vec![
        Chip::Program(ProgramAir),
        Chip::Cpu(CpuAir),
        Chip::Memory(MemoryAir),
        Chip::Alu(AluAir),
        Chip::Range(RangeAir),
        Chip::Nibble(NibbleAir),
        Chip::Poseidon2(Poseidon2Air, poseidon2_height),
        Chip::Input(crate::tables::input::InputAir),
    ];
    if keccak_log_height != 0 {
        v.push(Chip::Keccak(KeccakAir, 1usize << keccak_log_height));
    }
    if sha256_log_height != 0 {
        v.push(Chip::Sha256(Sha256Air, 1usize << sha256_log_height));
    }
    if modq_log_height != 0 {
        v.push(Chip::Modq(crate::tables::modq::ModqAir, 1usize << modq_log_height));
    }
    v.push(Chip::Public(crate::tables::public::PublicAir));
    v
}

pub struct Traces {
    pub program: RowMajorMatrix<Val>, pub cpu: RowMajorMatrix<Val>, pub memory: RowMajorMatrix<Val>,
    pub alu: RowMajorMatrix<Val>, pub range: RowMajorMatrix<Val>, pub nibble: RowMajorMatrix<Val>,
    pub poseidon2: RowMajorMatrix<Val>, pub public_values: Vec<Val>,
    /// M3.4 (fix): the program table's height, as a base-2 log — see `tables::program::
    /// program_log_height`'s doc comment. Carried alongside the traces (rather than
    /// recomputed from `self.program.height()`) so `prove_traces`/`prove_on` and the eventual
    /// `Proof` agree on exactly the value `build_traces` chose.
    pub program_log_height: u8,
    pub input: RowMajorMatrix<Val>,
    /// M4.1: the input table's height, as a base-2 log — the `program_log_height` doc
    /// comment's rule, applied to `tables::input::input_log_height`.
    pub input_log_height: u8,
    /// M4.2 (Task 6): `None` for a guest that never calls `KECCAK` — the batch then has eight
    /// instances, not nine, and the `KECCAK` bus no provider. `Some` iff
    /// `keccak_log_height != 0`; the two are set together and `as_slice`/`chips` must agree.
    pub keccak: Option<RowMajorMatrix<Val>>,
    /// M4.2: the keccak table's height, as a base-2 log — the same rule again, applied to
    /// `tables::keccak::keccak_log_height` (one 32-row block per permutation, floored at one
    /// block). M4.2 (Task 6): `0` is the distinguished "no keccak table in this proof" value,
    /// not a height — see `keccak` above and `machine::chips`.
    pub keccak_log_height: u8,
    /// M4.4: `None` for a guest that never calls `SHA256` — independently of `keccak`, so a batch
    /// may carry either table, both or neither. `Some` iff `sha256_log_height != 0`; the two are
    /// set together and `as_slice`/`chips` must agree.
    pub sha256: Option<RowMajorMatrix<Val>>,
    /// M4.4: the sha256 table's height, as a base-2 log — `tables::sha256::sha256_log_height`
    /// (one 64-row block per compression, floored at one block), with `0` the distinguished
    /// "no sha256 table in this proof" value.
    pub sha256_log_height: u8,
    /// Private multisig phase 3: `None` for a guest that never calls `MODQ` (and no
    /// `min_modq_log_height` floor). `Some` iff `modq_log_height != 0`.
    pub modq: Option<RowMajorMatrix<Val>>,
    /// The modq table's height, as a base-2 log (`tables::modq::modq_log_height`, one 1 024-row
    /// block per call), `0` meaning no modq table.
    pub modq_log_height: u8,
    /// M4.2 (controller ruling 1): the memory table's height, as a base-2 log — proof-declared
    /// like the four above, but with a tier-derived *floor* the others have no analogue
    /// of (`Tier::min_mem_log_height`). See `Proof::mem_log_height`.
    pub mem_log_height: u8,
    /// Constraint set 6: the public-input table. Mandatory — unlike `keccak`/`sha256` there is
    /// no `None`, because every proof commits to a public segment even when it is empty.
    pub public: RowMajorMatrix<Val>,
    /// Constraint set 6: the public table's height, as a base-2 log — `program_log_height`'s
    /// rule again, applied to `tables::public::public_log_height`.
    pub public_log_height: u8,
    /// Constraint set 11 (ZKVM-112): the poseidon2 table's height, as a base-2 log — the
    /// smallest admitted height that holds the run (`Tier::poseidon2_log_height_for`), or
    /// `ProveOptions::poseidon2_log_height`. See `Proof::poseidon2_log_height`.
    pub poseidon2_log_height: u8,
}
impl Traces {
    /// The traces in `chips()` order — eight entries, plus one per optional hash table this proof
    /// declares (M4.2, Task 6: a `Vec`, not a fixed-size array, because the batch's instance count
    /// is now per-proof; M4.4 adds the sha256 table as the second such and private multisig phase 3
    /// the modq table as the third, so the count is 8 to 11). The `i`-th entry pairs with the `i`-th chip, which is what keeps `i == 1`'s
    /// public-values slot correct in every shape.
    pub fn as_slice(&self) -> Vec<&RowMajorMatrix<Val>> {
        let mut v = vec![&self.program, &self.cpu, &self.memory, &self.alu, &self.range, &self.nibble, &self.poseidon2, &self.input];
        if let Some(keccak) = &self.keccak { v.push(keccak); }
        if let Some(sha256) = &self.sha256 { v.push(sha256); }
        if let Some(modq) = &self.modq { v.push(modq); }
        // Constraint set 6: last, matching `chips()` — see that function's doc comment for why
        // the mandatory public table is appended after the two optional ones.
        v.push(&self.public);
        v
    }
    pub fn heights(&self) -> Vec<usize> { self.as_slice().iter().map(|m| m.height()).collect() }
    /// Everything a `Proof` takes from a trace set besides the matrices themselves.
    fn head(&self) -> TraceHead {
        TraceHead { public_values: self.public_values.clone(), program_log_height: self.program_log_height, input_log_height: self.input_log_height, keccak_log_height: self.keccak_log_height, sha256_log_height: self.sha256_log_height, modq_log_height: self.modq_log_height, public_log_height: self.public_log_height, mem_log_height: self.mem_log_height, poseidon2_log_height: self.poseidon2_log_height }
    }
    /// The verifier-key shape these traces prove under.
    pub fn shape(&self, tier: Tier) -> VerifierKeyShape {
        self.head().shape(tier)
    }
    /// [`Self::as_slice`], owned: the matrices in `chips()` order, for a prover that is done with
    /// the trace set and wants to widen each in place (`tables::blind::widen_owned`).
    fn into_matrices(self) -> Vec<RowMajorMatrix<Val>> {
        let mut v = vec![self.program, self.cpu, self.memory, self.alu, self.range, self.nibble, self.poseidon2, self.input];
        v.extend(self.keccak);
        v.extend(self.sha256);
        v.extend(self.modq);
        v.push(self.public);
        v
    }
}

/// A trace set's public values and declared heights without its matrices — what the prover still
/// needs once the matrices have been handed to the batch (`Traces::head`).
struct TraceHead {
    public_values: Vec<Val>,
    program_log_height: u8,
    input_log_height: u8,
    keccak_log_height: u8,
    sha256_log_height: u8,
    modq_log_height: u8,
    public_log_height: u8,
    mem_log_height: u8,
    poseidon2_log_height: u8,
}
impl TraceHead {
    fn shape(&self, tier: Tier) -> VerifierKeyShape {
        VerifierKeyShape { tier, program_log_height: self.program_log_height, input_log_height: self.input_log_height, keccak_log_height: self.keccak_log_height, sha256_log_height: self.sha256_log_height, modq_log_height: self.modq_log_height, public_log_height: self.public_log_height, poseidon2_log_height: self.poseidon2_log_height }
    }
}

#[derive(Debug)]
pub enum ProveError {
    Exec(ExecError), NoTier(usize), TooManyCycles { cycles: usize, tier: Tier }, Backend(String),
    /// M3.4 (fix): the program's `program_log_height` (`tables::program::program_log_height`)
    /// exceeds `program::MAX_LOG_HEIGHT` — an error, not the `assert!` panic
    /// `tables::program::program_trace` itself still carries as a defense-in-depth invariant
    /// for direct callers.
    ProgramTooLarge { len: usize, log_height: u8 },
    /// M4.1: the input table's own analogue of `ProgramTooLarge` — `inputs.len()`'s declared
    /// `tables::input::input_log_height` exceeds `tables::input::MAX_LOG_HEIGHT`.
    InputTooLarge { len: usize, log_height: u8 },
    /// Constraint set 6: the public table's analogue of `InputTooLarge` — `public.len()`'s
    /// declared `tables::public::public_log_height` exceeds `tables::public::MAX_LOG_HEIGHT`.
    PublicTooLarge { len: usize, log_height: u8 },
    /// M4.2: the keccak table's analogue — more `KECCAK` calls than the enforced ceiling
    /// `min(Tier::max_keccak_log_height(), tables::keccak::MAX_LOG_HEIGHT)` (`t + 5` capped at
    /// 20, the same bound `check_declared_heights` applies) allows. Unreachable from an `Execution`
    /// that passed the cycle check above (a permutation costs a cycle, so `n_perms ≤ 2^t`),
    /// kept for the same reason the other two are: an error rather than a panic on an absurd
    /// shift, for a direct caller who hand-builds an `Execution`.
    TooManyPermutations { perms: usize, log_height: u8 },
    /// M4.4: the sha256 table's analogue of `TooManyPermutations` — more `SHA256` calls than
    /// `Tier::max_sha256_log_height` (`min(t + 6, tables::sha256::MAX_LOG_HEIGHT)`, the same bound
    /// `check_declared_heights` applies) allows. Unreachable from an `Execution` that passed the
    /// cycle check above (a compression costs a cycle, so `n ≤ 2^t`), and kept for the same reason:
    /// an error rather than a panic for a direct caller who hand-builds an `Execution`.
    TooManyCompressions { compressions: usize, log_height: u8 },
    /// Private multisig phase 3: the modq table's analogue — the declared `modq_log_height`
    /// (calls, or the `min_modq_log_height` floor) exceeds `Tier::max_modq_log_height`.
    TooManyModqCalls { calls: usize, log_height: u8 },
    /// M4.2 (controller ruling 1): the memory table's analogue — this execution makes more
    /// accesses than `MAX_MEM_LOG_HEIGHT` rows can hold. Unlike the three above this is not
    /// quite unreachable: a guest doing nothing but `KECCAK` passes it at tier 18-20 (see
    /// `MAX_MEM_LOG_HEIGHT` for the arithmetic). It is still an honest execution the prover
    /// declines, not an unsound one it accepts.
    TooManyMemoryAccesses { accesses: usize, log_height: u8 },
    /// Audit ZH1 (2026-09-12): the *Poseidon2* table's analogue — this workload's permutation
    /// count (program-digest rows + input-digest rows + hash absorb rows; each is one cycle
    /// *and* one permutation) exceeds the tier's `2^(t-3)` blocks, which the cycle budget alone
    /// (`2^t - 1`) does not bound. An error, not `poseidon2_trace`'s capacity `assert!` panic.
    ///
    /// Named apart from `TooManyPermutations` deliberately: that variant is M4.2's, and means
    /// *keccak* permutations against the declared keccak height. Two different tables, two
    /// different budgets, two different variants.
    ///
    /// Constraint set 11 (ZKVM-112): also the refusal of a `ProveOptions::poseidon2_log_height`
    /// that is not admitted at the tier or does not hold the run.
    TooManyPoseidon2Permutations { perms: usize, tier: Tier },
    /// Audit ZH2 (2026-09-12): the program-digest rows' `HASH_LEFT` is a 16-bit value in the
    /// AIR (`tables::cpu`'s `LEFT0..1` byte limbs), so a program longer than 65535 words can
    /// never satisfy it at any tier — reject here instead of failing deep inside `prove_batch`
    /// (a debug `CONSTRAINT_PANIC`, or an unverifiable proof in release). Distinct from
    /// `ProgramTooLarge`, which is about the program *table*'s declared shape.
    ProgramTooLong { len: usize },
    /// Audit ZH2 (2026-09-12): the same 16-bit `HASH_LEFT` bound caps the private-input vector
    /// (H_IN's indigest rows) at 65535 words.
    InputTooLong { len: usize },
    /// Constraint set 6: the same 16-bit `HASH_LEFT` bound caps the **public** input segment
    /// (H_PUB's pubdigest rows) at 65535 words, for the reason `InputTooLong` gives.
    PublicTooLong { len: usize },
    /// Audit ZH3 (2026-09-12): an explicit `Some(tier)` outside `TIERS` — rejected before
    /// `Tier::cpu_height`/`alu_height`/`mem_height` shift by it (a shift-overflow panic in debug
    /// builds, a masked shift plus an abort-scale allocation in release). The prove-side mirror
    /// of `check_declared_heights`' own `TIERS.contains` guard on the untrusted-proof side.
    BadTier(usize),
    /// ISA-1 residual (randprotocol/fullnode#53): the program's declared table — `2^log_height`
    /// rows from `base_pc`, floored at `2^7` — crosses the u32 pc wrap
    /// (`tables::program::pc_window_fits`). The circuit's PCs are field sums and the emulator's
    /// wrap, so no honest proof of such a program verifies; refused before any trace is built.
    PcWindow { base_pc: u32, log_height: u8 },
    /// Constraint set 8: the requested gas limit is below what this run spends (`gas::gas_of`) —
    /// the `HALT` row's `GD0..3` limbs cannot represent a negative slack, so no trace built with
    /// it could verify. Refused before the cpu trace is built.
    GasLimitBelowRun { gas: u64, limit: u64 },
    /// Constraint set 8: the requested gas limit is above this proof's own header ceiling
    /// (`gas::gas_max(tier, keccak_log_height, sha256_log_height)`), which `check_public_values`
    /// refuses. Refused before the cpu trace is built.
    GasLimitAboveHeader { limit: u64, max: u64 },
}
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    PublicValues, Tier, Batch(String),
    /// M3.4 (fix): `proof.program_log_height` is outside `[program::MIN_LOG_HEIGHT,
    /// program::MAX_LOG_HEIGHT]` — rejected before it can be used to size a table (`1usize <<
    /// log_height`) and panic on an absurd shift, the same defensive pattern `Tier`'s own
    /// out-of-range check already uses.
    ProgramHeight,
    /// M4.1: the input table's own analogue of `ProgramHeight` — `proof.input_log_height` is
    /// outside `[tables::input::MIN_LOG_HEIGHT, tables::input::MAX_LOG_HEIGHT]`.
    InputHeight,
    /// Constraint set 6: the public table's own analogue of `InputHeight` —
    /// `proof.public_log_height` is outside `[tables::public::MIN_LOG_HEIGHT,
    /// tables::public::MAX_LOG_HEIGHT]`. A plain range check with no `0` escape, because the
    /// public table is mandatory.
    PublicHeight,
    /// M4.2: the keccak table's own analogue of `ProgramHeight`/`InputHeight` —
    /// `proof.keccak_log_height` is non-zero and outside `[tables::keccak::MIN_LOG_HEIGHT,
    /// tables::keccak::MAX_LOG_HEIGHT]`. Checked before the declared height is used to size a
    /// table. M4.2 (Task 6): `0` is exempt, and means the proof declares no keccak table at
    /// all. M4.2 (Task 5 review): the upper half of the range is this variant's too — the flat
    /// cap was reintroduced because the tier bound alone lets a tier-20 header ask for a
    /// 2^25-row preprocessed trace (see `tables::keccak::MAX_LOG_HEIGHT`).
    KeccakHeight,
    /// M4.2 (controller ruling 2): `proof.keccak_log_height` is inside the flat range above but
    /// exceeds what the declared *tier* could possibly need — `Tier::max_keccak_log_height`,
    /// `t + 5`, since a permutation costs a cycle. Separate from `KeccakHeight` because it is a
    /// *relation* between two declared values rather than a range check on one, and because the
    /// test that pins it (`tests/cheating.rs`) asserts on the exact variant. The two together
    /// enforce `klh ≤ min(t + 5, MAX_LOG_HEIGHT)`; which variant a given forgery earns is
    /// decided by the order `check_declared_heights` runs them in (range first).
    KeccakHeightExceedsTier,
    /// M4.4: the sha256 table's own analogue of `KeccakHeight` — `proof.sha256_log_height` is
    /// non-zero and outside `[tables::sha256::MIN_LOG_HEIGHT, tables::sha256::MAX_LOG_HEIGHT]`.
    /// Checked before the declared height is used to size a table. `0` is exempt, and means the
    /// proof declares no sha256 table at all.
    Sha256Height,
    /// M4.4: `proof.sha256_log_height` is inside the flat range above but exceeds what the
    /// declared *tier* could possibly need — `Tier::max_sha256_log_height`, `t + 6`, since a
    /// compression costs a cycle and occupies one 64-row block. Separate from `Sha256Height`
    /// because it is a *relation* between two declared values rather than a range check on one,
    /// and because the test that pins it asserts on the exact variant.
    Sha256HeightExceedsTier,
    /// Private multisig phase 3: `proof.modq_log_height` is non-zero and outside
    /// `[tables::modq::MIN_LOG_HEIGHT, Tier::max_modq_log_height]` (the flat cap folded in). `0`
    /// is exempt and means no modq table.
    ModqHeight,
    /// M4.2 (controller ruling 1): `proof.mem_log_height` is outside `[tier.min_mem_log_height(),
    /// MAX_MEM_LOG_HEIGHT]`. The lower bound is the load-bearing half — see
    /// `Proof::mem_log_height`.
    MemoryHeight,
    /// Audit ZKA-1: public output slot `OUT0 + slot` holds a canonical field element above
    /// `u32::MAX`. An output slot is a 32-bit word — `SYS_WRITE_OUTPUT` publishes a register — but
    /// the circuit does not pin that on its own (`SYS_READ` hands a guest the input table's
    /// `WORD`, which no lookup range-checks), so `check_public_values` does.
    OutputNotU32 { slot: usize },
    /// Audit VERIFIER-1 (2026-09-27): FRI's commit-phase proof-of-work word for folding round
    /// `round` is not the honest `0`. This machine grinds zero bits there, so p3 neither checks nor
    /// even observes the word — it was free, and rewriting it re-encoded a valid proof (a second
    /// transaction id for one bundle). `check_commit_pow_witnesses` has the reasoning.
    CommitPowWitness { round: usize },
    /// ISA-1 residual (randprotocol/fullnode#53): the proof's claimed entry pc (`pv::PC_ENTRY`,
    /// the program's `base_pc`) plus its declared program table (`4 · 2^program_log_height`
    /// bytes) runs past 2^32 (`tables::program::pc_window_fits`). No honest proof has such a
    /// header; refused with the other cheap checks, before any key is built.
    PcWindow { entry_pc: u64, program_log_height: u8 },
    /// Constraint set 8: `proof.public_values[pv::GAS]` exceeds `gas::gas_max` for this proof's
    /// own declared header (`tier`, `keccak_log_height`, `sha256_log_height`) — a larger value
    /// could only be a mispriced header, refused natively before any key is built.
    GasLimit,
    /// Constraint set 11 (ZKVM-112): `proof.poseidon2_log_height` is under the private-data floor.
    Poseidon2HeightBelowFloor { declared: u8 },
    /// Constraint set 11: `proof.poseidon2_log_height` exceeds the tier's `t + 2`.
    Poseidon2HeightExceedsTier { declared: u8, max: u8 },
    /// Constraint set 11: `proof.poseidon2_log_height` is inside the range but not one of the
    /// tier's admitted heights (`Tier::admitted_poseidon2_log_heights`, `POSEIDON2_HEIGHT_STEP`).
    Poseidon2HeightNotAdmitted { declared: u8 },
}

/// Every check `verify` runs on a proof's public values before any of its batch is touched:
/// the count, canonical encoding, the program digest against `hc`, and the tier echo.
/// Extracted from `verify` (like `check_declared_heights`) so the checks are testable on their
/// own, without a proof that gets past the batch verifier.
pub fn check_public_values(hc: &[u32; 8], proof: &Proof) -> Result<(), VerifyError> {
    use crate::tables::cpu::pv;
    if proof.public_values.len() != pv::NUM { return Err(VerifyError::PublicValues); }
    // `public_values` is deserialized from untrusted bytes as raw `u64`s, and
    // `Val::from_u64` does not reduce: `out0` and `out0 + p` are the same field element
    // and both verify, but they are different `to_bytes()` and different numbers to
    // anyone reading the proof. Insist on the canonical representative so a proof has
    // exactly one encoding of its outputs.
    if proof.public_values.iter().any(|x| *x >= Val::ORDER_U64) { return Err(VerifyError::PublicValues); }
    for i in 0..8 {
        if proof.public_values[pv::HC0 + i] != hc[i] as u64 { return Err(VerifyError::PublicValues); }
    }
    if proof.public_values[pv::TIER] != proof.tier.0 as u64 { return Err(VerifyError::Tier); }
    // An untrusted tier outside `TIERS` is refused here too, before the gas check reads it (the
    // same guard `check_declared_heights` runs; `gas_max` clamps regardless).
    if !TIERS.contains(&proof.tier.0) { return Err(VerifyError::Tier); }
    // Constraint set 8: the declared gas limit is canonical (checked above) and never past what
    // the header itself allows — a larger value could only be a mispriced header.
    // Constraint set 11 (ZKVM-112): the permutation term follows the declared poseidon2 height
    // (`gas::gas_max_declared`), which `gas_max_declared` clamps before any shift.
    if proof.public_values[pv::GAS] > crate::gas::gas_max_declared(proof.tier, proof.keccak_log_height, proof.sha256_log_height, proof.modq_log_height, proof.poseidon2_log_height) {
        return Err(VerifyError::GasLimit);
    }
    // Audit ZKA-1: an output slot is a 32-bit word, and every consumer reads it as one — but the
    // canonical check above admits anything below `p ≈ 2^64`, and the circuit does not close the
    // gap by itself: `SYS_READ` hands the guest the input table's `WORD` column, which no lookup
    // range-checks, so the AIR alone does not guarantee that every value a register can carry to
    // `SYS_WRITE_OUTPUT` is below `2^32` (the audit's ZKA-1). Rather than argue every path from
    // that register to an output slot range-checks it, the verifier checks the one place the
    // value becomes public. A chain's executor already refuses such outputs itself (fullnode's
    // `verify_call`, and the ledger's call-output checks); this makes `verify`'s own answer agree,
    // for every caller that is not a chain. An honest proof never trips it — the emulator's
    // registers are `u32`.
    for slot in 0..crate::isa::NUM_OUTPUTS {
        if proof.public_values[pv::OUT0 + slot] > u32::MAX as u64 {
            return Err(VerifyError::OutputNotU32 { slot });
        }
    }
    Ok(())
}

/// Audit VERIFIER-1 (2026-09-27): every FRI commit-phase proof-of-work word must be the honest `0`.
///
/// `generic_config` grinds `commit_proof_of_work_bits: 0`, and at zero bits p3's
/// `GrindingChallenger::check_witness` returns `true` before it observes the witness
/// (`p3-challenger-0.7.0/src/grinding_challenger.rs:42-48`), so the words — one per folding round —
/// are carried in the proof but bound to nothing in the transcript. The honest prover's `grind(0)`
/// writes `F::ZERO` (`grinding_challenger.rs:117-120`); any other value verified just as well, which
/// made every proof re-encodable into as many valid byte strings as there are field elements per
/// round. That is not a soundness hole — the statement proved is unchanged — but bytes are an
/// identity on a chain: a bundle's transaction id hashes its proof, so a relayer could re-encode a
/// pending bundle and have the chain commit it under an id the wallet never saw. Requiring the honest
/// value gives every proof one encoding of these words again, and costs a comparison per round.
///
/// Why this is safe on a live chain whose proofs were made before it existed: every proof ever
/// produced by this crate's prover (any backend — the reference and CUDA configs share
/// `generic_config`) carries zeros here, so no honestly produced proof is refused. What it refuses is
/// only a proof someone rewrote. (A node running this check next to one that does not would disagree
/// only on such a rewritten proof — the rollout's concern, not the check's.)
///
/// The count of words is p3's to check (`FriError::CommitPowWitnessCountMismatch`); this only reads
/// what is there. The query-phase word needs nothing of the kind: it is observed before the query
/// indices are drawn, so another passing witness moves every query and the openings stop matching.
///
/// The rVM's in-circuit verifier makes the same check (constraint set 7, the chain-16 cut):
/// `recursion/src/programs/rv32.rs`'s FRI-commits loop asserts each hinted word of the `FriCommits`
/// tape segment zero, the trap named `commit pow witness[r]`, and the host replay
/// (`recursion::reference::replay`) refuses it as `PowWitness("commit phase")` — so an aggregate
/// accepts exactly the inner proofs this `verify` accepts on these words. The rVM's own native
/// verifier carries a copy of this function for its own proofs (`recursion::machine::
/// check_commit_pow_witnesses`). The in-program assertion moved every aggregate program digest
/// (`recursion/docs/02-aggregate.md`, VERIFIER-1).
pub fn check_commit_pow_witnesses(proof: &Proof) -> Result<(), VerifyError> {
    let fri = &proof.batch.opening_proof.1;
    match fri.commit_pow_witnesses.iter().position(|w| *w != Val::ZERO) {
        Some(round) => Err(VerifyError::CommitPowWitness { round }),
        None => Ok(()),
    }
}

/// Every range check `verify` runs on a proof's *declared shape* — the tier and the four
/// declared table heights — before a single byte of that shape is used to size anything.
///
/// M4.2 (Task 5 review): extracted from `verify` for two reasons. It is the whole of the
/// verifier's defence against a header that asks it to do absurd work (the checks all precede
/// `log_ext_degrees`, `verifier_key` and `chips`, so a bogus declaration costs a handful of
/// comparisons rather than a preprocessed-commitment recomputation), and as a free function
/// over the declared values it is testable at tiers and heights no test could afford to
/// actually *prove* at — a tier-20 header is a `check_declared_heights(Tier(20), …)` call here,
/// not a multi-minute proof.
///
/// The order is load-bearing where two checks overlap: `keccak_log_height`'s flat range comes
/// before its tier relation, so a declaration past both (tier 10, `klh = 25`) is reported as
/// `KeccakHeight`, and `KeccakHeightExceedsTier` names exactly the case of a flat-legal height
/// the tier cannot need.
pub fn check_declared_heights(
    tier: Tier,
    program_log_height: u8,
    input_log_height: u8,
    keccak_log_height: u8,
    sha256_log_height: u8,
    public_log_height: u8,
    mem_log_height: u8,
) -> Result<(), VerifyError> {
    check_declared_heights_with_modq(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, 0, public_log_height, mem_log_height, tier.max_poseidon2_log_height())
}

/// [`check_declared_heights`] with the modq table's declared height (private multisig phase 3):
/// `0` declares no modq table; any other value must lie in
/// `[max(tables::modq::MIN_LOG_HEIGHT, floor), Tier::max_modq_log_height]`, else `ModqHeight`.
/// And, since constraint set 11 (ZKVM-112), the poseidon2 table's declared height, which must be
/// one of the tier's admitted heights ([`check_poseidon2_log_height`], run last). The
/// modq-free, full-height [`check_declared_heights`] passes `tier.max_poseidon2_log_height()`.
#[allow(clippy::too_many_arguments)]
pub fn check_declared_heights_with_modq(
    tier: Tier,
    program_log_height: u8,
    input_log_height: u8,
    keccak_log_height: u8,
    sha256_log_height: u8,
    modq_log_height: u8,
    public_log_height: u8,
    mem_log_height: u8,
    poseidon2_log_height: u8,
) -> Result<(), VerifyError> {
    // `tier` is deserialized from untrusted bytes: an attacker-supplied out-of-range tier
    // (anything not in TIERS) must be rejected first of all, since every check below it — and
    // `log_ext_degrees` after them — calls `Tier::cpu_height`/`alu_height`/`min_mem_log_height`,
    // which shift by `self.0` and panic in debug builds for a large enough tier (`1usize << 99`).
    if !TIERS.contains(&tier.0) { return Err(VerifyError::Tier); }
    // Constraint set 7 (audit INT-2): every declared table is at least `2^7` rows —
    // `tables::MIN_PRIVATE_TABLE_LOG_HEIGHT`, raised from a prover-side floor on three tables to
    // the verifier's floor on all five. Below it a table's committed columns — its permutation
    // (running-sum) columns included, which carry the terminal the LogUp blind hides — are opened at
    // more points than the hiding PCS has random rows (`tables::blind`'s module comment). Each
    // range check below starts at `max(table floor, floor)`, so a short table earns its own
    // table's variant, exactly as a too-tall one does.
    let floor = crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT;
    // M3.4 (fix): `program_log_height` is untrusted the same way — reject anything outside the
    // sane range before it sizes a table (`1usize << log_height` inside
    // `log_ext_degrees`/`verifier_key`) and panics on an absurd shift.
    if !(program::MIN_LOG_HEIGHT.max(floor)..=program::MAX_LOG_HEIGHT).contains(&program_log_height) {
        return Err(VerifyError::ProgramHeight);
    }
    // M4.1: the input table's height, same treatment.
    if !(crate::tables::input::MIN_LOG_HEIGHT.max(floor)..=crate::tables::input::MAX_LOG_HEIGHT).contains(&input_log_height) {
        return Err(VerifyError::InputHeight);
    }
    // M4.2 (Task 6): `keccak_log_height == 0` declares *no* keccak table — the batch has eight
    // instances, the `KECCAK` bus has no provider, and there is no height to range-check.
    // Nothing about that needs the verifier's trust: `chips` and `log_ext_degrees` both read the
    // same declared `0`, so `verify`'s degree-bits equality check pins the instance count, and a
    // cpu row claiming `SYS_KECCAK` on an unprovided bus cannot balance
    // (`tests/cheating.rs::a_keccak_syscall_without_a_keccak_table_is_rejected`). A non-zero
    // declaration gets both ceilings.
    if keccak_log_height != 0 {
        // M4.2 (Task 5 review): the flat range first — `[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]`. The
        // lower end rejects a table too short to hold the permutation it claims; the upper end
        // is the cap that keeps a declared `u8` from sizing a preprocessed trace the verifier
        // would spend minutes building, which the tier bound below does *not* do on its own (at
        // tier 20 it admits `klh = 25`, a 2^25-row, 99-column preprocessed keccak trace).
        if !(crate::tables::keccak::MIN_LOG_HEIGHT.max(floor)..=crate::tables::keccak::MAX_LOG_HEIGHT).contains(&keccak_log_height) {
            return Err(VerifyError::KeccakHeight);
        }
        // M4.2 (controller ruling 2): and then the tier, which is already known good —
        // `klh ≤ t + 5`, since a permutation costs a cycle. This is the check that stops a proof
        // from asking a tier-10 verifier to build (and a tier-10 prover to commit to) a keccak
        // table with more permutation slots than the tier has cycles.
        if keccak_log_height > tier.max_keccak_log_height() {
            return Err(VerifyError::KeccakHeightExceedsTier);
        }
    }
    // M4.4: the sha256 table gets the identical treatment, and is independent of the keccak one —
    // `0` declares no sha256 table (the `SHA256` bus then has no provider, which is what makes a
    // cpu row claiming `SYS_SHA256` unprovable: `tests/cheating.rs::
    // sha256_row_without_a_sha256_table_is_rejected`), any other value gets both ceilings in the
    // same order.
    if sha256_log_height != 0 {
        if !(crate::tables::sha256::MIN_LOG_HEIGHT.max(floor)..=crate::tables::sha256::MAX_LOG_HEIGHT).contains(&sha256_log_height) {
            return Err(VerifyError::Sha256Height);
        }
        // `Tier::max_sha256_log_height` is `min(t + 6, MAX_LOG_HEIGHT)` — it folds the flat cap in,
        // so this relation is the tier's own bound wherever the tier is the tighter of the two and
        // a restatement of the range check above where it is not (see that method's doc comment).
        if sha256_log_height > tier.max_sha256_log_height() {
            return Err(VerifyError::Sha256HeightExceedsTier);
        }
    }
    // Private multisig phase 3: the modq table, on the same terms — `0` declares none (the `MODQ`
    // bus then has no provider, so a cpu row claiming `SYS_MODQ` is unprovable), any other value
    // gets one range whose top is `Tier::max_modq_log_height` (the flat cap folded in).
    if modq_log_height != 0
        && !(crate::tables::modq::MIN_LOG_HEIGHT.max(floor)..=tier.max_modq_log_height()).contains(&modq_log_height)
    {
        return Err(VerifyError::ModqHeight);
    }
    // The public table is mandatory — unlike the two hash chips there is no "0 means absent"
    // value — so this is a plain range check, `tables::input`'s exactly.
    if !(crate::tables::public::MIN_LOG_HEIGHT.max(floor)..=crate::tables::public::MAX_LOG_HEIGHT).contains(&public_log_height) {
        return Err(VerifyError::PublicHeight);
    }
    // M4.2 (controller ruling 1): `mem_log_height` is untrusted the same way. The floor is the
    // tier's own `2^(t+2)` (so the declaration reveals nothing the tier did not already), the
    // ceiling the usual defensive one — see `Proof::mem_log_height` for why the verifier needs no
    // tighter bound than this.
    if !(tier.min_mem_log_height()..=MAX_MEM_LOG_HEIGHT).contains(&mem_log_height) {
        return Err(VerifyError::MemoryHeight);
    }
    // Constraint set 11 (ZKVM-112): the poseidon2 table's height, one of the tier's admitted ones.
    check_poseidon2_log_height(tier, poseidon2_log_height)
}

/// Constraint set 11 (ZKVM-112): the range check on a declared poseidon2 height — at least the
/// private-data floor, at most the tier's `t + 2`, and a whole number of [`POSEIDON2_HEIGHT_STEP`]s
/// below `t + 2`. An unknown tier is refused (`Tier`) before its height is computed.
///
/// **Why the declared height needs no lower bound from the run.** A table too short for the run's
/// permutations is not a forgery, it is unprovable: every digest-prefix and absorb row of the cpu
/// table sends one `POSEIDON2` message, and each must be received by a real block of the poseidon2
/// table or the bus does not balance — the memory table's argument (`Proof::mem_log_height`). A
/// table taller than the run needs is padding blocks, which receive nothing. So the verifier only
/// bounds the height to the admitted set, which is what keeps the number of verifier keys small
/// and the preprocessed trace a verifier builds bounded by the tier's.
pub fn check_poseidon2_log_height(tier: Tier, declared: u8) -> Result<(), VerifyError> {
    if !TIERS.contains(&tier.0) { return Err(VerifyError::Tier); }
    if declared < crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT {
        return Err(VerifyError::Poseidon2HeightBelowFloor { declared });
    }
    let max = tier.max_poseidon2_log_height();
    if declared > max {
        return Err(VerifyError::Poseidon2HeightExceedsTier { declared, max });
    }
    if (max - declared) % POSEIDON2_HEIGHT_STEP != 0 {
        return Err(VerifyError::Poseidon2HeightNotAdmitted { declared });
    }
    Ok(())
}

/// Draws a fresh H_IN salt from OS entropy and delegates to [`build_traces_salted`] — the
/// direct-caller (non-`Machine`) mirror of `Machine::prove`/`Machine::prove_salted`'s own
/// split (review round 1, M6). Most callers (`main.rs`'s demo sections included) don't need a
/// *particular* salt, just a fresh one; use `build_traces_salted` where a fixed, reproducible
/// H_IN is specifically needed (e.g. two traces that must be compared).
///
/// Constraint set 8: declares the header's own ceiling (`gas::gas_max`) as the gas limit, as
/// `Machine::prove` does.
pub fn build_traces(program: &Program, inputs: &[u32], public: &[u32], exec: &Execution, tier: Tier) -> Result<Traces, ProveError> {
    use rand::RngExt;
    let salt: [u32; 4] = rand::rng().random();
    build_traces_salted_with(program, inputs, public, salt, exec, tier, ProveOptions::default())
}

/// Prover-side choices that change what a proof *reveals* but not what it proves: every option here
/// produces a proof the ordinary `Machine::verify` accepts, with no verifier or key change, and the
/// default is exactly the prover as it always was.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProveOptions {
    /// HCS-3 (the 2026-09-27 zkVM review): declare the keccak and sha256 tables even when the run
    /// never calls `KECCAK`/`SHA256`, as all-padding tables at the private-data floor
    /// (`tables::MIN_PRIVATE_TABLE_LOG_HEIGHT`, 128 rows each).
    ///
    /// **What it hides.** A proof's header declares `keccak_log_height` and `sha256_log_height`, and
    /// `0` means "no such table" — so without this option every proof tells anyone who reads the
    /// header whether the call hashed with either precompile at all, and (above the floor) roughly
    /// how often. With it, a call that never hashes declares `7`/`7`, exactly what a call making one
    /// to four keccak permutations or one or two sha256 compressions declares: presence becomes
    /// indistinguishable from absence at the floor. Counts above the floor still show to within a
    /// factor of two (the table doubles), and the memory table's declared height is untouched — a
    /// hashing call's memory traffic can still lift it where an idle table adds none.
    ///
    /// **Why it needs no verifier change.** An idle block is not a new kind of row: every table
    /// whose permutation count is not a multiple of its block count already ends in idle padding
    /// blocks, and the COV-2 floor itself pads a one-permutation keccak table with three of them.
    /// An all-idle table sends nothing on `KECCAK`/`SHA256` (the `MULT` column is zero on every idle
    /// row) and nothing on `MEMORY`, so the buses balance exactly as they do with no table; the
    /// declared heights (`7`) sit inside `check_declared_heights`' ranges and the tier bounds at every
    /// tier, and inside the chain's call caps (fullnode's `verify_call`: keccak ≤ 12, sha256 ≤ 13).
    /// `tests/privacy_floor.rs::padded_hash_tables_verify_and_hide_presence` proves and verifies one.
    ///
    /// **What it costs, and why it is off.** Two extra instances in the batch: 128 rows each of the
    /// wide keccak and sha256 tables, committed, opened at every query and quotient-checked. Measured
    /// on a tier-10 call that never hashes (`guests::balance_check`, laptop, one run each): the
    /// Production proof grows from 1 305 415 to 3 622 604 bytes, proving time 6.3 s → 7.2 s; at the
    /// Test profile 300 708 → 850 026 bytes. The bytes are the real cost: a chain charges for them,
    /// and 3.6 MB is over the 2 MiB default `max_proof_bytes` (fullnode's `gas::MAX_PROOF_BYTES`) —
    /// chain 15's genesis sets 8 MiB, so it fits there, but a chain on the default would refuse
    /// every padded call. It hides nothing unless the
    /// calls it hides among use it too (an anonymity set of one is no set), so it is a wallet- or
    /// chain-wide policy decision, not a per-call one. A verifier also builds one more key shape per
    /// `(tier, program, input, public)` it sees with the tables declared.
    ///
    /// The CPU prover (`prove_with_options`, `build_traces_salted_with`) honours it; the backend
    /// entry points (`prove_with`) keep the default.
    pub pad_absent_hash_tables: bool,

    /// cs8: the `GAS_LIMIT` to declare; `None` = `gas::gas_max(header)` (spec §5: leaks nothing
    /// new — every verifier already learns the tier and both hash-table heights from the header,
    /// and the default limit is a pure function of those). Must lie in `[gas::gas_of(run),
    /// gas::gas_max(header)]` or `build_traces_inner` refuses before the cpu trace is built
    /// (`ProveError::GasLimitBelowRun`/`GasLimitAboveHeader`).
    ///
    /// HCS-3's `pad_absent_hash_tables` above changes what the *default* limit is, not just what
    /// it hides: declaring the keccak/sha256 tables at the private-data floor
    /// (`MIN_PRIVATE_TABLE_LOG_HEIGHT`, 128 rows each) when a call never hashes raises `gas_max` by
    /// `4·133 + 2·48` — the floor's four idle keccak blocks and two idle sha256 blocks, each priced
    /// at `KECCAK_GAS - 1` / `SHA256_GAS - 1` — so a call that pads its hash tables *and* leaves
    /// `gas_limit` at `None` declares a higher ceiling than the same call without padding, even
    /// though it spends the same gas either way. A caller that wants the proof to price its actual
    /// work, not the header's ceiling, passes the exact `gas` (`gas::gas_of`) rather than relying
    /// on the default.
    pub gas_limit: Option<u64>,

    /// Private multisig phase 3 (spec §5, pre-flight ruling 3 — the shape leak): floors on three
    /// declared heights, so a prover that pins its tier can also pin every variable height to a
    /// worst-case value and the header stops leaking how many calls (or accesses) the run made.
    /// `0` = no floor. Prover-side only: the verifier is unchanged, because idle padding blocks
    /// and padding memory rows verify already. A floor must still lie inside
    /// `check_declared_heights_with_modq`' range for its table, or `build_traces_inner` refuses
    /// (`TooManyModqCalls` / `TooManyPermutations` / `TooManyMemoryAccesses`).
    ///
    /// `min_modq_log_height` declares an idle modq table even when the run makes no `MODQ` call
    /// (`pad_absent_hash_tables` never does). The `msauth` prover sets all three to their
    /// `M_MAX` values.
    pub min_modq_log_height: u8,
    /// The keccak table's floor; non-zero declares an idle keccak table on a keccak-free run.
    pub min_keccak_log_height: u8,
    /// The memory table's floor, above the tier's own `t + 2`.
    pub min_mem_log_height: u8,
    /// Constraint set 11 (ZKVM-112): the poseidon2 table's height to declare; `None` = the
    /// smallest admitted height that holds the run (`Tier::poseidon2_log_height_for`), raised —
    /// by admitted steps — until the header's ceiling (`gas::gas_max_declared`) covers an explicit
    /// `gas_limit`, so a limit any full-height header could carry is still provable. A height
    /// the tier does not admit, or one too short for the run's permutations, is refused
    /// (`ProveError::TooManyPoseidon2Permutations`) — the prover refuses what the verifier would.
    /// Like the floors above, a taller declaration hides the permutation count to the resolution of
    /// the height declared, and `Some(tier.max_poseidon2_log_height())` hides it to the tier's, as
    /// every proof did through constraint set 10. The `msauth` prover pins it.
    pub poseidon2_log_height: Option<u8>,
}

/// Constraint set 8: `gas_limit` is the proof's declared `pv::GAS`, and must lie in
/// `[gas::gas_of(run), gas::gas_max(header)]` — `ProveError::GasLimitBelowRun` /
/// `GasLimitAboveHeader` otherwise, before the cpu trace is built. A caller with no better value
/// passes the header's ceiling; [`build_traces_salted_with`] does exactly that.
pub fn build_traces_salted(program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], exec: &Execution, tier: Tier, gas_limit: u64) -> Result<Traces, ProveError> {
    build_traces_inner(program, inputs, public, salt, exec, tier, ProveOptions::default(), Some(gas_limit), None)
}

/// Cheating-suite hook (spec §5, pre-flight ruling 1; `cheating` feature only):
/// [`build_traces_salted`] with the modq table forged by `tables::modq::forge_block(events,
/// height, lie)` over the run's own (clk-offset) events. The memory table records the forged
/// block's own accesses in place of the emulator's — with the builder's consistency asserts off
/// (`tables::memory::memory_trace_forged`'s terms), so the memory AIR is what judges them — and the
/// forged `RangeCounts` join the range table. `Lie::NoModqTable` instead declares no modq table at
/// all, its memory traffic and range counts left out with it. Everything else is
/// `build_traces_salted`'s. No prover path calls this.
#[cfg(feature = "cheating")]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn build_traces_forged(program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], exec: &Execution, tier: Tier, gas_limit: u64, lie: crate::tables::modq::Lie) -> Result<Traces, ProveError> {
    use crate::tables::modq::{forge_block, Lie, MIN_LOG_HEIGHT};
    let forge = |events: &[crate::tables::modq::ModqEvent], log_height: u8| {
        // A `RealPadding` block on a run with no call at all declares the one-block floor: the
        // table nobody asked for is the lie (`Defence::Handshake`'s test).
        if lie == Lie::NoModqTable || (log_height == 0 && !matches!(lie, Lie::RealPadding { .. })) {
            return ModqOverride { log_height: 0, trace: None, range: RangeCounts::default(), accesses: Vec::new() };
        }
        let log_height = log_height.max(MIN_LOG_HEIGHT);
        let f = forge_block(events, log_height, lie);
        let accesses = f.accesses.iter().flat_map(|(clk, acc)| acc.iter().map(move |a| (*clk, *a))).collect();
        ModqOverride { log_height, trace: Some(f.trace), range: f.range, accesses }
    };
    build_traces_inner(program, inputs, public, salt, exec, tier, ProveOptions::default(), Some(gas_limit), Some(&forge))
}

/// What the cheating suite puts in place of the run's modq table (`build_traces_forged`): the
/// declared height, the table (`None`: no table), its range counts, and the memory accesses it
/// sends at absolute clocks, which replace the emulator's modq accesses in the memory table.
#[cfg_attr(not(feature = "cheating"), allow(dead_code))]
struct ModqOverride {
    log_height: u8,
    trace: Option<RowMajorMatrix<Val>>,
    range: RangeCounts,
    accesses: Vec<(u32, crate::emulator::MemAccess)>,
}
type ModqForge<'a> = &'a dyn Fn(&[crate::tables::modq::ModqEvent], u8) -> ModqOverride;

/// [`build_traces_salted`] under explicit [`ProveOptions`]: `opts.gas_limit` is the declared
/// limit, `None` meaning the header's own ceiling (`gas::gas_max`) — what every `Machine::prove*`
/// entry point declares by default.
pub fn build_traces_salted_with(program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], exec: &Execution, tier: Tier, opts: ProveOptions) -> Result<Traces, ProveError> {
    let gas_limit = opts.gas_limit;
    build_traces_inner(program, inputs, public, salt, exec, tier, opts, gas_limit, None)
}

/// The one trace builder. `gas_limit: None` = the header's ceiling, resolved once the declared
/// keccak/sha256/modq heights are known.
#[allow(clippy::too_many_arguments)]
/// `forge`: `build_traces_forged`'s override, `None` on every prover path.
#[allow(clippy::too_many_arguments)]
fn build_traces_inner(program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], exec: &Execution, tier: Tier, opts: ProveOptions, gas_limit: Option<u64>, forge: Option<ModqForge>) -> Result<Traces, ProveError> {
    // M3.4: digest rows count as cycles too — the digest prefix is part of every proof's cpu
    // table, not just `exec.events`. M4.1: so does the input-digest prefix.
    let input_digest_rows = crate::hash::input_digest_row_count(inputs.len());
    // Constraint set 6: and so does the public-input-digest prefix.
    let public_digest_rows = crate::hash::public_digest_row_count(public.len());
    let cycles = exec.cycles() + program.digest_rows() + input_digest_rows + public_digest_rows;
    if cycles > tier.max_cycles() { return Err(ProveError::TooManyCycles { cycles, tier }); }
    // Audit fixes (2026-09-12): reject workloads the AIR can never satisfy *here*, where a clean
    // error is still possible, rather than deep inside `prove_batch`.
    //
    // ZH2: `HASH_LEFT` is a 16-bit value on every digest/indigest row (`tables::cpu`'s
    // `LEFT0..1` byte limbs) and the *first* such row carries the program's word count (resp.
    // `n_in`), so a program or input vector longer than 65535 words is unprovable at any tier.
    if program.len() > u16::MAX as usize { return Err(ProveError::ProgramTooLong { len: program.len() }); }
    if inputs.len() > u16::MAX as usize { return Err(ProveError::InputTooLong { len: inputs.len() }); }
    if public.len() > u16::MAX as usize { return Err(ProveError::PublicTooLong { len: public.len() }); }
    // ZH1: the poseidon2 table holds `2^(t-3)` permutation blocks against up to ~`2^t`
    // permutation-emitting rows under the cycle budget alone, so cycles fitting says nothing
    // about permutations fitting. Counted the same way the trace builder below counts them:
    // one per digest row, one per indigest row, one per absorb row.
    let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
    let permutations = program.digest_rows() + input_digest_rows + public_digest_rows + absorb_rows;
    if permutations * crate::tables::poseidon2::BLOCK > tier.poseidon2_height() {
        return Err(ProveError::TooManyPoseidon2Permutations { perms: permutations, tier });
    }
    // Constraint set 11 (ZKVM-112): the poseidon2 table's height is declared — the smallest
    // admitted height that holds these permutations, or the caller's, which must be admitted and
    // hold them too (the verifier would refuse the one, the bus the other). An explicit gas limit
    // may raise the default further, below.
    let poseidon2_log_height = match opts.poseidon2_log_height {
        None => tier.poseidon2_log_height_for(permutations),
        Some(h) => (check_poseidon2_log_height(tier, h).is_ok() && permutations * crate::tables::poseidon2::BLOCK <= 1usize << h).then_some(h),
    }
    .ok_or(ProveError::TooManyPoseidon2Permutations { perms: permutations, tier })?;
    let mut poseidon2_log_height = poseidon2_log_height;
    // M3.4 (fix): the program table's height is proof-declared, not tier-derived — see
    // `tables::program::program_log_height`'s doc comment.
    let program_log_height = program::program_log_height(program.len());
    if program_log_height > program::MAX_LOG_HEIGHT {
        return Err(ProveError::ProgramTooLarge { len: program.len(), log_height: program_log_height });
    }
    // ISA-1 residual (randprotocol/fullnode#53): the declared, floored table must sit below the
    // u32 pc wrap, or its padding rows carry field PCs no execution produces and the proof built
    // here could never verify (`tables::program::pc_window_fits`).
    if !program::pc_window_fits(program.base_pc as u64, program_log_height) {
        return Err(ProveError::PcWindow { base_pc: program.base_pc, log_height: program_log_height });
    }
    // M4.1: the input table's height is proof-declared the same way.
    let input_log_height = crate::tables::input::input_log_height(inputs.len());
    if input_log_height > crate::tables::input::MAX_LOG_HEIGHT {
        return Err(ProveError::InputTooLarge { len: inputs.len(), log_height: input_log_height });
    }
    // Constraint set 6: and the public table's, on identical terms.
    let public_log_height = crate::tables::public::public_log_height(public.len());
    if public_log_height > crate::tables::public::MAX_LOG_HEIGHT {
        return Err(ProveError::PublicTooLarge { len: public.len(), log_height: public_log_height });
    }
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    // M4.2: one `KeccakEvent` per `KECCAK` row, in execution order — the same order the cpu
    // table's `SYS_KECCAK` rows claim them in. `clk` is the cpu table's own (digest-prefix
    // shifted) clock, because that is what both sides of the `KECCAK` bus carry and what the
    // chip's memory timestamps (`4·CLK`, `4·CLK + 1`) are built from.
    let clk_offset = (program.digest_rows() + input_digest_rows + public_digest_rows) as u32;
    let keccak_events: Vec<KeccakEvent> = exec.events.iter()
        .filter_map(|e| e.keccak_row.as_ref().map(|r| KeccakEvent { clk: clk_offset + e.clk, ptr: r.ptr, input: r.input }))
        .collect();
    // HCS-3: with `pad_absent_hash_tables`, "no permutations" declares an all-idle table at the
    // private-data floor instead of no table — `ProveOptions`' doc comment has why the verifier
    // accepts it unchanged. A run that does hash is untouched (its height is already ≥ the floor).
    let keccak_log_height = match crate::tables::keccak::keccak_log_height(keccak_events.len()) {
        0 if opts.pad_absent_hash_tables => crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT,
        h => h,
    };
    // M4.2 (controller ruling 2, tightened by the Task 5 review): two ceilings, both of which
    // `check_declared_heights` re-checks on the verifier's side — the tier's honest-shape bound
    // `klh ≤ t + 5` (`Tier::max_keccak_log_height`) and the flat defensive cap
    // `tables::keccak::MAX_LOG_HEIGHT`. The prover enforces the same `min` the verifier does, so
    // no honest proof is built that the verifier would then refuse to look at.
    // Private multisig phase 3: the prover-side floor (`ProveOptions::min_keccak_log_height`),
    // which may declare an idle table on a keccak-free run.
    let keccak_log_height = keccak_log_height.max(opts.min_keccak_log_height);
    if keccak_log_height > tier.max_keccak_log_height().min(crate::tables::keccak::MAX_LOG_HEIGHT)
        || (keccak_log_height != 0 && keccak_log_height < crate::tables::keccak::MIN_LOG_HEIGHT.max(crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT))
    {
        return Err(ProveError::TooManyPermutations { perms: keccak_events.len(), log_height: keccak_log_height });
    }
    // M4.2 (Task 6): no permutations, no table. `keccak_log_height == 0` and `keccak == None`
    // are set here together and travel together from this point on — `chips` builds eight
    // instances from the first, `as_slice` supplies eight traces from the second.
    let keccak_t = (keccak_log_height != 0).then(|| keccak_trace(&keccak_events, 1usize << keccak_log_height));
    // M4.4: one `Sha256Event` per `SHA256` row, in execution order — the same order the cpu
    // table's `SYS_SHA256` rows claim them in, and the order `sha256_trace` fills its blocks in.
    // `clk` is the cpu table's own (digest-prefix shifted) clock for the same reason keccak's is:
    // it is what both sides of the `SHA256` bus carry and what the chip's memory timestamps
    // (`4·CLK`, `4·CLK + 1`) are built from. `Sha256Row::clk` is the *emulator's* unshifted clock,
    // so it is deliberately not the value used here.
    let sha256_events: Vec<Sha256Event> = exec.events.iter()
        .filter_map(|e| e.sha256_row.as_ref().map(|r| Sha256Event { clk: clk_offset + e.clk, ptr: r.ptr, block: r.block, h_in: r.h_in }))
        .collect();
    // HCS-3: the same option, the same floor, for the sha256 table.
    let sha256_log_height = match crate::tables::sha256::sha256_log_height(sha256_events.len()) {
        0 if opts.pad_absent_hash_tables => crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT,
        h => h,
    };
    // The prover enforces the same ceiling the verifier does (`Tier::max_sha256_log_height` already
    // folds in the flat `tables::sha256::MAX_LOG_HEIGHT`), so no honest proof is built that
    // `check_declared_heights` would then refuse to look at.
    if sha256_log_height > tier.max_sha256_log_height() {
        return Err(ProveError::TooManyCompressions { compressions: sha256_events.len(), log_height: sha256_log_height });
    }
    // No compressions, no table: `sha256_log_height == 0` and `sha256 == None` are set here
    // together and travel together from this point on.
    let sha256_t = (sha256_log_height != 0).then(|| sha256_trace(&sha256_events, sha256_log_height));
    // Private multisig phase 3: one `ModqEvent` per `MODQ` row, in execution order, at the cpu
    // table's own (digest-prefix shifted) clock — what both sides of `bus::MODQ` carry and what the
    // chip's memory timestamps `4·CLK`/`4·CLK + 1` are built from.
    let modq_events: Vec<crate::tables::modq::ModqEvent> = exec.events.iter()
        .filter_map(|e| e.modq.as_ref().map(|m| crate::tables::modq::ModqEvent { clk: clk_offset + e.clk, base: m.base, a1: m.a1, inputs: m.inputs.clone() }))
        .collect();
    // No calls and no floor: no table. Otherwise one block per call, raised to the floor
    // (`ProveOptions::min_modq_log_height`) — a floor alone declares an all-idle table, which
    // claims nothing on `MODQ` and sends nothing on `MEMORY`. `pad_absent_hash_tables` does not
    // touch this table.
    let mut modq_log_height = crate::tables::modq::modq_log_height(modq_events.len());
    if modq_log_height != 0 || opts.min_modq_log_height != 0 {
        modq_log_height = modq_log_height.max(opts.min_modq_log_height).max(crate::tables::modq::MIN_LOG_HEIGHT);
    }
    if modq_log_height != 0 && modq_log_height > tier.max_modq_log_height() {
        return Err(ProveError::TooManyModqCalls { calls: modq_events.len(), log_height: modq_log_height });
    }
    // The cheating suite's override (`build_traces_forged`): a forged modq block, or none at all.
    let forged = forge.map(|f| f(&modq_events, modq_log_height));
    if let Some(f) = &forged { modq_log_height = f.log_height; }
    // Constraint set 8: the declared gas limit sits between what this run spends and what its
    // header could ever need — refused here, before the cpu trace (whose `HALT` row encodes the
    // difference in four byte limbs) is built. `gas_max` < 2^32 at every admissible header
    // (`tests/gas.rs` pins the largest), so the slack always fits the limbs.
    let gas = crate::gas::gas_of(program, inputs, public, &exec.events);
    // Constraint set 11: an explicit gas limit above the default poseidon2 height's ceiling raises
    // that height (by admitted steps, up to `t + 2`) until the header can carry the limit — a
    // prover-side choice the verifier does not see as anything but a taller table. Only when the
    // caller left the height to the prover; a pinned height is never moved.
    if let (Some(limit), None) = (gas_limit, opts.poseidon2_log_height) {
        while crate::gas::gas_max_declared(tier, keccak_log_height, sha256_log_height, modq_log_height, poseidon2_log_height) < limit && poseidon2_log_height < tier.max_poseidon2_log_height() {
            poseidon2_log_height += POSEIDON2_HEIGHT_STEP;
        }
    }
    let max = crate::gas::gas_max_declared(tier, keccak_log_height, sha256_log_height, modq_log_height, poseidon2_log_height);
    let gas_limit = gas_limit.unwrap_or(max);
    if gas_limit < gas { return Err(ProveError::GasLimitBelowRun { gas, limit: gas_limit }); }
    if gas_limit > max { return Err(ProveError::GasLimitAboveHeader { limit: gas_limit, max }); }
    let cpu = cpu_trace(program, inputs, public, salt, &exec.events, tier.cpu_height(), gas_limit, &mut range, &mut nibble);
    // M4.2 (controller ruling 1): the memory table's height is declared, not derived. Count the
    // rows `memory_trace` will actually hold — one per `accesses` entry and one per
    // `keccak_accesses` entry, which is every row it pushes (read it: the two chained iterators
    // are its whole input) — and declare the smallest power of two that holds them *plus the
    // padding row the table's own `assert!` requires*, floored at the tier's `2^(t+2)`.
    //
    // M4.4: `sha256_accesses` joins the count — a `SYS_SHA256` row makes 32 accesses (24 reads of
    // the buffer plus 8 write-backs) instead of four, all of them sent by the *sha256* chip and
    // all recorded here. Expressed as the plan's formula, the table holds
    // `4·cycles + 100·n_keccak + 32·n_sha256` accesses; counted here the way `memory_trace` will
    // actually consume them, which is per event rather than per formula.
    // An override's accesses replace the emulator's modq accesses in the memory table.
    let mem_accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len() + e.sha256_accesses.len() + if forged.is_some() { 0 } else { e.modq.as_ref().map_or(0, |m| m.accesses.len()) }).sum::<usize>() + forged.as_ref().map_or(0, |f| f.accesses.len());
    // Private multisig phase 3: and the prover-side floor `ProveOptions::min_mem_log_height`.
    let mem_log_height = tier
        .min_mem_log_height()
        .max((mem_accesses + 1).next_power_of_two().trailing_zeros() as u8)
        .max(opts.min_mem_log_height);
    if mem_log_height > MAX_MEM_LOG_HEIGHT {
        return Err(ProveError::TooManyMemoryAccesses { accesses: mem_accesses, log_height: mem_log_height });
    }
    let memory = if let Some(f) = &forged {
        let mut events = exec.events.clone();
        for m in events.iter_mut().filter_map(|e| e.modq.as_mut()) { m.accesses.clear(); }
        crate::tables::memory::memory_trace_inner(&events, clk_offset, 1usize << mem_log_height, &mut range, &f.accesses, false)
    } else {
        memory_trace(&exec.events, clk_offset, 1usize << mem_log_height, &mut range)
    };
    let alu = alu_trace(&exec.events, tier.alu_height(), &mut range, &mut nibble);
    let read_counts = crate::tables::input::read_counts(inputs.len(), &exec.events);
    // ZKM-1/ZKH-2 (next constraint set): the input and public tables' word limbs are `RANGE8`
    // lookups too, so both are built before the range table is.
    let input_t = crate::tables::input::input_trace(inputs, &read_counts, 1usize << input_log_height, &mut range);
    // Constraint set 6: the public table, `input`'s twin — `MULT_READ` counted off the
    // `SYS_READ_PUBLIC` events the same way.
    let public_read_counts = crate::tables::public::read_counts(public.len(), &exec.events);
    let public_t = crate::tables::public::public_trace(public, &public_read_counts, 1usize << public_log_height, &mut range);
    // Private multisig phase 3: the modq table counts its 29 limbs per real row into `range`, so it
    // is built before the range table is.
    let modq_t = match forged {
        Some(f) => {
            range.absorb(&f.range);
            f.trace
        }
        None => (modq_log_height != 0).then(|| crate::tables::modq::modq_trace(&modq_events, modq_log_height, &mut range)),
    };
    let range_t = range_trace(&range);
    let nibble_t = nibble_trace(&nibble);
    let program_t = program_trace(program, &exec.events, 1usize << program_log_height);
    // M3.4: the digest prefix's own permutations, in the same row order `tables::cpu`'s
    // `IS_DIGEST` rows issue them (`fill_digest_rows`) — these come *first*, since the digest
    // rows precede every ordinary cycle in the cpu table.
    let digest_blocks = crate::hash::program_digest_rows(program.base_pc, &program.words);
    let digest_events: Vec<Poseidon2Event> = digest_blocks.iter().map(|blk| {
        let mut input = blk.state_in;
        for k in 0..4 { if blk.active[k] { input[k] = Val::from_u32(blk.words[k]); } }
        Poseidon2Event { input, output: blk.state_out }
    }).collect();
    // M4.1: the input-digest prefix's own permutations, right after the program-digest ones
    // (matching the row order `IS_INDIGEST` rows occupy in the cpu table).
    let indigest_blocks = crate::hash::input_digest_rows(salt, inputs);
    let indigest_events: Vec<Poseidon2Event> = indigest_blocks.iter().map(|blk| {
        let mut input = blk.state_in;
        for k in 0..4 { if blk.active[k] { input[k] = Val::from_u32(blk.words[k]); } }
        Poseidon2Event { input, output: blk.state_out }
    }).collect();
    // M3.2: one `Poseidon2Event` per absorbed block, in emission order — exactly the
    // permutations the cpu table's absorb rows ask for over the `POSEIDON2` bus (see
    // `tables::cpu`'s eval). Any block beyond these is padding, still a genuine,
    // AIR-satisfying permutation trace — see `tables::poseidon2`'s module doc comment.
    let hash_events: Vec<Poseidon2Event> = exec.events.iter().filter_map(|e| match e.hash_row {
        // `state_in` is `HS0..7` (the state as of the end of the *previous* block, before this
        // block's overwrite) — the permutation's real input additionally overwrites lanes 0..3
        // with this row's active `words`, exactly as the cpu AIR's own `state_in` message does.
        Some(crate::emulator::HashRow::Absorb { words, active, state_in, state_out, .. }) => {
            let mut input = state_in;
            for k in 0..4 { if active[k] { input[k] = Val::from_u32(words[k]); } }
            Some(Poseidon2Event { input, output: state_out })
        }
        _ => None,
    }).collect();
    // Constraint set 6: the public-input-digest prefix's own permutations, after the indigest
    // ones and before the absorb ones — matching the row order `IS_PUBDIGEST` rows occupy.
    let pubdigest_blocks = crate::hash::public_digest_rows(public);
    let pubdigest_events: Vec<Poseidon2Event> = pubdigest_blocks.iter().map(|blk| {
        let mut input = blk.state_in;
        for k in 0..4 { if blk.active[k] { input[k] = Val::from_u32(blk.words[k]); } }
        Poseidon2Event { input, output: blk.state_out }
    }).collect();
    let all_hash_events: Vec<Poseidon2Event> = digest_events.into_iter().chain(indigest_events).chain(pubdigest_events).chain(hash_events).collect();
    let poseidon2_t = poseidon2_trace(&all_hash_events, 1usize << poseidon2_log_height);
    let hc = program.digest();
    let hin = crate::hash::input_digest(salt, inputs);
    let hpub = crate::hash::public_digest(public);
    Ok(Traces {
        program: program_t, cpu, memory, alu, range: range_t, nibble: nibble_t, poseidon2: poseidon2_t, input: input_t,
        keccak: keccak_t,
        sha256: sha256_t,
        modq: modq_t,
        public: public_t,
        // Constraint set 8: the limit checked above, the same one the cpu trace's `HALT` row
        // encodes (the `Machine::prove*` paths pass the header's own ceiling by default;
        // `ProveOptions::gas_limit` overrides it).
        public_values: public_values(program.base_pc, tier.0, &exec.outputs, &hc, &hin, &hpub, gas_limit),
        program_log_height, input_log_height, keccak_log_height, sha256_log_height, modq_log_height, public_log_height, mem_log_height, poseidon2_log_height,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof {
    pub tier: Tier,
    /// M3.4 (fix): the program table's height, declared by the prover — see `tables::program::
    /// program_log_height`'s doc comment for the rule and the soundness argument.
    pub program_log_height: u8,
    /// M4.1: the input table's height, declared by the prover — see `tables::input::
    /// input_log_height`'s doc comment (mirrors `program_log_height`'s rule).
    pub input_log_height: u8,
    /// M4.2: the keccak table's height, declared by the prover — the same rule once more
    /// (`tables::keccak::keccak_log_height`), bounded above by the declared tier
    /// (`Tier::max_keccak_log_height`) *and* by the flat `tables::keccak::MAX_LOG_HEIGHT`,
    /// whichever is smaller (M4.2, Task 5 review).
    ///
    /// M4.2 (Task 6): **`0` means the batch carries no keccak table**, and is the value every
    /// proof whose guest never executes a `KECCAK` gets. It is public, and it says exactly one
    /// thing a non-zero height does not: "this program made no `KECCAK` call". That is the same
    /// class of leak `program_log_height` already is — a coarse, structural fact about the
    /// program rather than about its data (`docs/03-privacy.md`'s "What a proof leaks").
    /// The saving is large: the keccak chip is 2 612 + 99 columns, and every FRI query opens a
    /// leaf of that width whether the table has 32 rows or 32 768, so a padding-block-only table
    /// cost ~1.91 MB of every production proof (80 queries; ~705 KB at the 27 queries M4.2
    /// measured — `docs/03-privacy.md`).
    pub keccak_log_height: u8,
    /// M4.4: the sha256 table's height, declared by the prover — `tables::sha256::
    /// sha256_log_height`, bounded above by `Tier::max_sha256_log_height` (`min(t + 6,
    /// tables::sha256::MAX_LOG_HEIGHT)`).
    ///
    /// **`0` means the batch carries no sha256 table**, and is the value every proof whose guest
    /// never executes a `SHA256` gets. It is public, and says exactly one thing a non-zero height
    /// does not: "this program made no `SHA256` call" — the same class of coarse, structural leak
    /// `program_log_height` and `keccak_log_height` already are (`docs/03-privacy.md`'s "What a
    /// proof leaks"). The saving is the same kind too, if smaller than keccak's: the sha256 chip is
    /// 466 + 10 columns against keccak's 2 612 + 99, and every FRI query opens a leaf of the
    /// batch's full width whether the table holds 64 rows or 65 536.
    pub sha256_log_height: u8,
    /// Private multisig phase 3: the modq table's height, declared by the prover —
    /// `tables::modq::modq_log_height` (one 1 024-row block per call), or a prover's floor —
    /// bounded by `[tables::modq::MIN_LOG_HEIGHT, Tier::max_modq_log_height]`. `0` means the batch
    /// carries no modq table. Placed after `sha256_log_height`; postcard adds one byte.
    pub modq_log_height: u8,
    /// Constraint set 6: the public table's height, declared by the prover —
    /// `tables::public::public_log_height`, range-checked against
    /// `[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]` by `check_declared_heights`. Mandatory: unlike the two
    /// hash heights there is no `0` "no such table" value.
    ///
    /// What it leaks is `n_pub` to within a factor of two — the same coarse, structural class of
    /// leak `program_log_height` and `input_log_height` already are (`docs/03-privacy.md`'s
    /// "What a proof leaks"), and a far smaller one here, since the public segment's *words* are
    /// published with the transaction anyway (that is what `Machine::verify_public` checks).
    /// `MIN_LOG_HEIGHT` is *not* the "no public segment" marker `keccak_log_height = 0` is: the
    /// table's `MIN_HEIGHT` is 4 and one row is always padding, so the floor covers every
    /// `n_pub` in `0..=3` alike. "This proof has no public segment" is not something the height
    /// alone says — only that the segment is at most three words long.
    pub public_log_height: u8,
    /// M4.2 (controller ruling 1): the memory table's height, declared by the prover as
    /// `max(t + 2, log2_ceil(accesses + 1))`. `verify` checks only
    /// `t + 2 ≤ mem_log_height ≤ MAX_MEM_LOG_HEIGHT`.
    ///
    /// **Why a one-sided check suffices.** The memory table is not a resource the prover can
    /// win by over- or under-declaring. Declaring it *too large* only costs the prover: the
    /// extra rows are padding (`IS_REAL = 0`), which the table's own "padding is a suffix" and
    /// per-row constraints already pin to send nothing on any bus, so a bigger table proves
    /// the same statement more expensively. Declaring it *too small* is not an attack either,
    /// it is simply impossible: every access the cpu and keccak tables send on `MEMORY` must
    /// be received by a real row here or the bus does not balance, so the table has to be at
    /// least as tall as the traffic it is answering. The tier-derived floor (`t + 2`) is kept
    /// not for soundness but so a proof cannot advertise its own memory-access count below the
    /// resolution the tier already reveals — a tier-10 guest making 200 accesses and one
    /// making 4 000 both declare `mem_log_height = 12`, exactly as every tier-10 proof did
    /// before M4.2.
    /// `MAX_MEM_LOG_HEIGHT` is the usual defensive ceiling on an untrusted shift amount.
    pub mem_log_height: u8,
    /// Constraint set 11 (ZKVM-112): the poseidon2 table's height, declared by the prover — one
    /// of the tier's admitted heights (`t + 2, t, …` down to the private-data floor;
    /// `check_poseidon2_log_height` has the rule and why no lower bound from the run is needed).
    /// Through constraint set 10 the table was `2^(t+2)` rows at every tier whether or not the
    /// guest hashed, and was about a fifth of a run's main cells.
    ///
    /// Public, like the others: it bounds the number of Poseidon2 permutations the run made
    /// (program, input and public digests included) to within the admitted set's factor of four —
    /// the same class of coarse, structural leak `keccak_log_height` is (`docs/03-privacy.md`,
    /// "What a proof leaks"). A prover that wants the old resolution declares `t + 2`
    /// (`ProveOptions::poseidon2_log_height`). It is one more component of the verifier-key shape
    /// and sizes the gas ceiling's permutation term (`gas::gas_max_declared`).
    pub poseidon2_log_height: u8,
    pub public_values: Vec<u64>,
    pub batch: BatchProof<Config>,
}
impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("proof serialises") }
    pub fn size(&self) -> usize { self.to_bytes().len() }
}

/// A `Config` whose value-MMCS salts and PCS random codewords are both seeded deterministically
/// instead of from OS entropy, so that the resulting preprocessed commitment
/// (`Machine::verifier_key`) is a pure function of the declared shape: any verifier can recompute
/// it standalone, without having witnessed the proving session or holding the program.
///
/// M3.4 seeded it from a fixed `KEY_SEED` rather than the program (the preprocessed columns — the
/// range/nibble tables, the Poseidon2 round constants, the hash chips' periodic columns — depend on
/// no program). HCS-1, constraint set 7: the seed was fixed, but the salts were `rand`'s `StdRng`
/// stream from it, which `rand` does not promise to keep across releases — the stream was
/// consensus. They are `key_derivation_v2`'s now, a Poseidon2 sponge over this repository's own
/// constants and two labels (`key_rngs` below), so no dependency update can move a key.
///
/// Never used for the actual `prove_batch` call, whose main-trace/quotient/permutation
/// commitments must keep fresh entropy (see `make_config`) or two proofs of the same run
/// would be distinguishable, breaking zero-knowledge.
pub(crate) fn key_config(profile: FriProfile) -> Config {
    let (mmcs_rng, pcs_rng) = key_rngs();
    build_config(profile, mmcs_rng, pcs_rng)
}

/// The deterministic `(mmcs_rng, pcs_rng)` pair behind `key_config`, factored out so every
/// backend seeds its own key config identically and therefore produces a preprocessed
/// commitment byte-identical to the one `verifier_key` recomputes on the CPU.
fn key_rngs() -> (SaltRng, SaltRng) {
    // Two labels, so the two streams do not start identically (`key_derivation_v2::key_rngs`).
    let (mmcs, pcs) = crate::key_derivation_v2::key_rngs();
    (SaltRng::Key(mmcs), SaltRng::Key(pcs))
}

/// Which prover implementation `Machine::prove_with` runs the batch STARK on. Every variant
/// produces a `Proof` the ordinary CPU `Machine::verify` accepts; they differ only in who
/// computes the NTTs and Poseidon2 hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Plonky3's own `Radix2DitParallel` + `MerkleTreeHidingMmcs`.
    Cpu,
    /// `rand-zkvm-cuda`'s engines running on the host: the CPU twin of the GPU path.
    #[cfg(feature = "reference-backend")]
    Reference,
    /// `rand-zkvm-cuda`'s CUDA engines (or the mock driver under `mock-cuda`).
    #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
    Cuda,
}

/// Best-effort text of a caught panic payload: `panic!("{e}")` and `panic!("literal")` cover
/// every panic the backend engines raise.
#[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() { return format!("backend panicked: {s}"); }
    if let Some(s) = p.downcast_ref::<&str>() { return format!("backend panicked: {s}"); }
    "backend panicked".to_string()
}

/// Bound on the number of verifier keys `Machine::verifier_key` keeps in memory at once. Past
/// this, the least recently used key is evicted to make room for the new one (CPUV-1 residual,
/// randprotocol/fullnode#54: it was FIFO, so a burst of distinct shapes evicted a key in constant
/// use — a node's bundle key — however hot it was, and a rebuild costs seconds and hundreds of MB
/// at a node's call-shape cap). The bound is on entries, not bytes: an entry is a verifier's
/// `CommonData` (a Merkle cap and the packed lookups), whose size is a function of the shape.
const KEY_CACHE_CAPACITY: usize = 64;

/// A bounded, least-recently-used cache of `Machine::verifier_key` results with single-flight
/// builds (#54: each entry is a `OnceLock` slot, so concurrent first callers of one shape wait for
/// one build instead of each running the preprocessing pass), keyed by `(tier.0,
/// program_log_height, input_log_height, keccak_log_height)` (M3.4 fix: the program table's height is
/// proof-declared, not tier-derived — `tables::program::program_log_height`'s doc comment —
/// so `CommonData`'s per-instance degree-bit bookkeeping depends on it too, even though the
/// program table has no preprocessed *columns* of its own any more; M4.1 adds the input
/// table's own height as a third, independent key component for the same reason; M4.2 adds the
/// keccak table's as a fourth; M4.2 Task 6 makes `klh = 0` — the eight-chip, keccak-table-free
/// batch — a distinct fourth-component value rather than an impossible one, and it must be,
/// since its `CommonData` has eight `lookups` entries and no keccak preprocessed columns).
/// The memory table's own declared height (M4.2, controller
/// ruling 1) is deliberately *not* a component of its own — see `Machine::verifier_key` for why the
/// `CommonData` this caches is invariant to it. Bounded by
/// `TIERS.len() * (program::MAX_LOG_HEIGHT − program::MIN_LOG_HEIGHT + 1) *
/// (input::MAX_LOG_HEIGHT − input::MIN_LOG_HEIGHT + 1) *
/// (keccak range, `min(t + 5, keccak::MAX_LOG_HEIGHT) − keccak::MIN_LOG_HEIGHT + 2` = 17 at
/// tier 20, the `+ 2` counting M4.2 Task 6's `klh = 0`, "no keccak table", as its own value) *
/// (the sha256 range, counted the same way) *
/// (modq range, `min(t + 10, modq::MAX_LOG_HEIGHT) − modq::MIN_LOG_HEIGHT + 2` = 12 at any tier
/// from 10, the `+ 2` counting `mlh = 0`, "no modq table", as its own value) *
/// (the public range)` distinct keys in the worst case —
/// comfortably able to exceed `KEY_CACHE_CAPACITY` if a caller proves at many different
/// program/input sizes, unlike the tier-only cache this replaces, so the eviction here is
/// a real policy again, not just defense in depth.
/// Private multisig phase 3: the 7-tuple `(tier, program, input, keccak, sha256, modq, public)`;
/// `modq = 0` is the modq-free key every pre-phase-3 call keeps reaching. Constraint set 11
/// (ZKVM-112): the 8-tuple, with the declared poseidon2 height last — at most
/// `(t − 4) / 2` more keys per shape (`Tier::admitted_poseidon2_log_heights`).
type KeyShape = (usize, u8, u8, u8, u8, u8, u8, u8);
type KeySlot = Arc<std::sync::OnceLock<Arc<CommonData<Config>>>>;

struct KeyCache {
    /// Each shape's slot, the tick of its last use, and whether it is pinned: a key installed by
    /// `Machine::install_verifier_key` is never evicted (a consumer that installs a key never
    /// rebuilds it).
    map: HashMap<KeyShape, (KeySlot, u64, bool)>,
    tick: u64,
    capacity: usize,
}
impl Default for KeyCache {
    fn default() -> Self { Self { map: HashMap::new(), tick: 0, capacity: KEY_CACHE_CAPACITY } }
}
impl KeyCache {
    /// The slot for `key`, marked used now — an existing one (built, or being built by another
    /// caller) or a fresh, empty one, making room first by evicting the least recently used
    /// entries. An evicted slot that is still being built is only dropped from the map: its
    /// builder holds its own handle and returns the key it builds. Pinned entries are never
    /// evicted; when only pinned entries remain, the cache grows past `capacity` instead.
    fn slot(&mut self, key: KeyShape) -> KeySlot {
        self.tick += 1;
        let now = self.tick;
        if let Some((slot, used, _)) = self.map.get_mut(&key) {
            *used = now;
            return slot.clone();
        }
        while self.map.len() >= self.capacity {
            let Some(lru) = self.map.iter().filter(|(_, (_, _, pinned))| !*pinned).min_by_key(|(_, (_, used, _))| *used).map(|(k, _)| *k) else { break };
            self.map.remove(&lru);
        }
        let slot = KeySlot::default();
        self.map.insert(key, (slot.clone(), now, false));
        slot
    }
    /// Marks `key`'s entry (which must exist) as never evictable.
    fn pin(&mut self, key: &KeyShape) {
        if let Some(e) = self.map.get_mut(key) { e.2 = true; }
    }
    /// Whether `key`'s slot is present and built (a lookup, not a use).
    fn is_built(&self, key: &KeyShape) -> bool {
        self.map.get(key).is_some_and(|(slot, _, _)| slot.get().is_some())
    }
    /// The number of built keys held.
    fn built(&self) -> usize { self.map.values().filter(|(slot, _, _)| slot.get().is_some()).count() }
}

/// Default byte budget of the prover-side preprocessed cache ([`Machine::set_prover_key_budget`]):
/// 1 GiB. An entry is one shape's committed preprocessed tree — measured (`tests/memprofile.rs`,
/// 2026-11-17, a batch with no hash chip) at 13.0 MiB at tier 10, 50.5 MiB at tier 12 and 200.5 MiB
/// at tier 14, four times as much per two tiers (the Poseidon2 round-constant table is nearly all
/// of it), so about 0.8 GiB at tier 16, 3.1 GiB at tier 18 and 12.5 GiB at tier 20 — those three
/// are the scaling, not measurements. The default therefore keeps the shapes through tier 14
/// several at a time, one tier-16 shape, and **nothing from tier 18 up**: those are the tiers where
/// the host's memory is the binding constraint, and an entry larger than the budget is built, used
/// for its one proof and dropped, exactly as before the cache existed. A prover that serves one
/// large shape all day raises the budget; one that wants the old behaviour sets it to 0.
pub const PROVER_KEY_BUDGET: usize = 1 << 30;

/// What a cached [`ProverData`] is a function of, and so the prover cache's key: the constraint
/// set, the FRI profile and the eight-component shape the verifier key is keyed on. The first two
/// are constants of a build and of a `Machine`, and the cache lives in the `Machine`, so they could
/// not differ between two lookups even without being here; they are in the key so that it says
/// everything the data depends on by itself, and no later change (a cache shared between machines,
/// say) can make it serve another constraint set's or profile's tree. **The program is not a
/// component, deliberately**: since M3.4 no preprocessed column depends on it (`key_config`'s doc
/// comment), which is the same fact that lets `verify` take `hc` and no program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProverKey {
    constraint_set: u32,
    profile: FriProfile,
    shape: KeyShape,
}

type ByteSlot<V> = Arc<std::sync::OnceLock<Arc<V>>>;

/// A least-recently-used cache bounded by **bytes**, with single-flight builds — `KeyCache`'s
/// shape (one `OnceLock` slot per key, built outside the lock) with a byte budget where that one
/// counts entries, because a prover's preprocessed data is megabytes to gigabytes where a
/// verifier's `CommonData` is kilobytes. An entry's size is known only once it is built, so a slot
/// is inserted unsized, and its builder reports the size afterwards ([`Self::settle`]), which is
/// when eviction runs: least recently used first, until what is held fits the budget. An entry that
/// is alone larger than the budget is not kept at all, and evicts nothing. An evicted or
/// over-budget entry is only dropped from the map: whoever holds its `Arc` keeps using it, and it
/// is freed when they finish.
///
/// So the cache holds at most `budget` bytes between proofs, and a prove can run with at most
/// `budget` bytes of other shapes' entries held beside its own working set.
struct ByteLru<K, V> {
    /// Each key's slot, the tick of its last use, and its size once settled.
    map: HashMap<K, (ByteSlot<V>, u64, Option<usize>)>,
    tick: u64,
    budget: usize,
    held: usize,
}
impl<K: Copy + Eq + std::hash::Hash, V> ByteLru<K, V> {
    fn new(budget: usize) -> Self { Self { map: HashMap::new(), tick: 0, budget, held: 0 } }
    /// The slot for `key`, marked used now: the existing one (built, or being built by another
    /// caller) or a fresh, empty one. Only ever `key`'s own — the map is the one place a slot is
    /// found, and it is found by the whole key.
    fn slot(&mut self, key: K) -> ByteSlot<V> {
        self.tick += 1;
        let now = self.tick;
        let e = self.map.entry(key).or_insert_with(|| (ByteSlot::<V>::default(), now, None));
        e.1 = now;
        e.0.clone()
    }
    /// Records that `slot` — the one [`Self::slot`] returned for `key` — is built and `bytes` big,
    /// then evicts down to the budget. A no-op on the accounting when the entry is already sized
    /// (a second caller of the same build) or is no longer `key`'s entry (evicted meanwhile).
    fn settle(&mut self, key: K, slot: &ByteSlot<V>, bytes: usize) {
        if let Some(e) = self.map.get_mut(&key) {
            if Arc::ptr_eq(&e.0, slot) && e.2.is_none() {
                if bytes > self.budget {
                    // Larger than the whole budget: not kept, and nothing else is evicted for it.
                    self.map.remove(&key);
                } else {
                    e.2 = Some(bytes);
                    self.held += bytes;
                }
            }
        }
        self.evict();
    }
    fn set_budget(&mut self, budget: usize) {
        self.budget = budget;
        self.evict();
    }
    /// Drops least-recently-used sized entries until the held bytes fit the budget. An unsized
    /// entry (still being built) holds nothing yet and is left for its builder to settle.
    fn evict(&mut self) {
        while self.held > self.budget {
            let Some((lru, bytes)) = self.map.iter().filter_map(|(k, (_, used, bytes))| bytes.map(|b| (*used, *k, b))).min_by_key(|(used, _, _)| *used).map(|(_, k, b)| (k, b)) else { break };
            self.map.remove(&lru);
            self.held -= bytes;
        }
    }
    /// Whether `key`'s entry is present and built (a lookup, not a use).
    fn is_built(&self, key: &K) -> bool { self.map.get(key).is_some_and(|(slot, _, _)| slot.get().is_some()) }
}

/// The bytes one cached [`ProverData`] keeps alive — the committed preprocessed tree: per
/// preprocessed matrix its low-degree extension (`2^(degree_bits + LOG_BLOWUP)` rows of the
/// matrix's width plus the hiding MMCS's four salt elements), and the digest layers above the
/// tallest (under two four-element digests per leaf row). Computed from the data's own metadata
/// rather than counted, because Plonky3 does not expose the tree; `tests/memprofile.rs` prints it
/// beside what the allocator says the cache holds, and the two agree to within a percent. The
/// packed lookups and the cap are kilobytes and are not counted.
fn prover_data_bytes(data: &ProverData<Config>) -> usize {
    const SALT_ELEMS: usize = 4;
    const DIGEST_ELEMS: usize = 4;
    let word = std::mem::size_of::<Val>();
    let Some(pre) = data.common.preprocessed.as_ref() else { return 0 };
    let (mut bytes, mut tallest) = (0usize, 0usize);
    for meta in pre.instances.iter().flatten() {
        let height = 1usize << (meta.degree_bits + LOG_BLOWUP);
        bytes += height * (meta.width + SALT_ELEMS) * word;
        tallest = tallest.max(height);
    }
    bytes + 2 * tallest * DIGEST_ELEMS * word
}

/// The constraint set this crate's AIRs implement: 11 re-weights the gas meter to the committed-cell
/// count and prices a `MODQ` call by op, through the cpu's new `MODQ_W` column and a fourth field
/// on the `MODQ` bus (ZKVM-202, `docs/07-gas.md`; `docs/05-roadmap.md`, "Constraint set 11"), after
/// constraint set 10's digest-prefix price (ZKV-5), constraint set 9's MODQ chip and constraint
/// set 8's gas meter. It is stamped into every
/// [`VerifierKeyBlob`] and checked on install, so a key exported by one constraint set is never
/// installed by a machine of another (whose `CommonData` for the same shape usually differs —
/// `tests/verifier_key.rs` pins those digests — and whose constraints differ even when it does not,
/// as constraint set 10's did not). Bump it with every constraint change, re-pin or no re-pin.
pub const CONSTRAINT_SET: u32 = 11;

/// The [`VerifierKeyBlob`] wire format's version: the header layout and the `CommonData` mirror
/// (`CommonDataWire`). Format 1 is the first; format 2 (constraint set 11) adds
/// `VerifierKeyShape::poseidon2_log_height` to the header.
pub const VERIFIER_KEY_BLOB_FORMAT: u32 = 2;

/// One verifier-key shape: the tier and the seven declared table heights the key cache is keyed
/// on — `(tier, program, input, keccak, sha256, modq, public, poseidon2)`. `mem_log_height` is
/// deliberately absent (every valid memory height yields the same `CommonData`;
/// `Machine::verifier_key`). `poseidon2_log_height` is constraint set 11's (ZKVM-112): the
/// poseidon2 table has preprocessed columns, so its height is part of the commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKeyShape {
    pub tier: Tier,
    pub program_log_height: u8,
    pub input_log_height: u8,
    pub keccak_log_height: u8,
    pub sha256_log_height: u8,
    pub modq_log_height: u8,
    pub public_log_height: u8,
    pub poseidon2_log_height: u8,
}
impl VerifierKeyShape {
    /// The shape `Machine::verify` looks the key up under for `proof`.
    pub fn of_proof(proof: &Proof) -> Self {
        Self {
            tier: proof.tier,
            program_log_height: proof.program_log_height,
            input_log_height: proof.input_log_height,
            keccak_log_height: proof.keccak_log_height,
            sha256_log_height: proof.sha256_log_height,
            modq_log_height: proof.modq_log_height,
            public_log_height: proof.public_log_height,
            poseidon2_log_height: proof.poseidon2_log_height,
        }
    }
    /// The shape with the poseidon2 table at the tier's full `t + 2` — what every shape was
    /// through constraint set 10, and what the 6-height `verifier_key*` entry points build.
    pub fn full_height(tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8) -> Self {
        Self { tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, modq_log_height, public_log_height, poseidon2_log_height: tier.max_poseidon2_log_height() }
    }
    /// The shape's chip set, in `chips()` order ([`chips_at`] at the declared poseidon2 height).
    /// The caller has range-checked the shape.
    pub fn chips(&self) -> Vec<Chip> {
        chips_at(self.tier, self.keccak_log_height, self.sha256_log_height, self.modq_log_height, 1usize << self.poseidon2_log_height)
    }
    /// The range checks a proof of this shape passes, at the tier's memory floor.
    pub fn check(&self) -> Result<(), VerifyError> {
        check_declared_heights_with_modq(self.tier, self.program_log_height, self.input_log_height, self.keccak_log_height, self.sha256_log_height, self.modq_log_height, self.public_log_height, self.tier.min_mem_log_height(), self.poseidon2_log_height)
    }
    fn key(&self) -> KeyShape {
        (self.tier.0, self.program_log_height, self.input_log_height, self.keccak_log_height, self.sha256_log_height, self.modq_log_height, self.public_log_height, self.poseidon2_log_height)
    }
}

/// A verifier key for ONE shape, exported after a build so another host can install it without
/// rebuilding it ([`Machine::export_verifier_key_with_modq`], [`Machine::install_verifier_key`]).
/// Exists for the fullnode's tier-18 `msauth` key: ~80 s and ~4 GB to build, more than a 4 GB
/// validator can spare, so it is built once and shipped.
///
/// A header — `format_version` ([`VERIFIER_KEY_BLOB_FORMAT`]), the FRI `profile`, the `shape` and
/// the `constraint_set` ([`CONSTRAINT_SET`]) — and `common`, the postcard bytes of the shape's
/// `CommonData` (the preprocessed commitment, each instance's preprocessed placement and every
/// instance's packed lookups). The whole blob is postcard ([`Self::to_bytes`]).
///
/// **Trust: the blob is a trust root.** `install_verifier_key` checks the header, the structure of
/// `common` (instance count, preprocessed widths and degree bits, the matrix map) and the packed
/// lookups — recomputed from this machine's chips, cheaply, with no trace or commitment — so after
/// those checks the only unchecked part is the preprocessed **commitment**, which cannot be checked
/// without the build the blob exists to avoid. A crafted commitment is not merely a key that makes
/// honest proofs fail: it fixes the "preprocessed" columns (range, nibble, round constants, periodic
/// tables) to whatever its author committed, and a prover who knows those columns can make FORGED
/// proofs verify. The consumer must therefore pin the SHA-256 of the whole `to_bytes()` out of band
/// and check it on the raw bytes *before* decoding anything — [`Machine::install_verifier_key_pinned`]
/// does exactly that (the decoded lookups are recursive symbolic expressions of unbounded depth, so
/// unpinned bytes should never reach the decoder). `verify`'s own declared-height and degree-bit
/// checks still run on every proof, so a key is only ever used for the shape in its header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKeyBlob {
    pub format_version: u32,
    pub profile: FriProfile,
    pub shape: VerifierKeyShape,
    pub constraint_set: u32,
    /// postcard(`CommonDataWire`) — the shape's `CommonData`.
    pub common: Vec<u8>,
}
impl VerifierKeyBlob {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("a key blob serialises") }
    /// Decodes a whole blob; trailing bytes are refused, so one blob has one encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InstallKeyError> {
        let (blob, rest) = postcard::take_from_bytes::<Self>(bytes).map_err(|e| InstallKeyError::Decode(e.to_string()))?;
        if !rest.is_empty() { return Err(InstallKeyError::Decode(format!("{} trailing bytes", rest.len()))); }
        Ok(blob)
    }
}

/// Why [`Machine::install_verifier_key`] refused a blob. Nothing is installed on any error.
#[derive(Debug, PartialEq)]
pub enum InstallKeyError {
    /// `format_version` is not [`VERIFIER_KEY_BLOB_FORMAT`].
    Format { blob: u32, machine: u32 },
    /// The blob was exported under another FRI profile than this machine's.
    Profile { blob: FriProfile, machine: FriProfile },
    /// `constraint_set` is not [`CONSTRAINT_SET`].
    ConstraintSet { blob: u32, machine: u32 },
    /// The header's shape fails `check_declared_heights_with_modq` (at the tier's memory floor).
    Shape(VerifyError),
    /// The blob (or its `common` bytes) does not decode, or decodes with trailing bytes.
    Decode(String),
    /// `common` decodes but disagrees with this machine's chips for `shape` (instance count,
    /// a preprocessed width or degree bits, the matrix map).
    Structure(String),
    /// The slot for `shape` already holds a *different* key; it is never replaced.
    SlotFilled,
    /// `install_verifier_key_pinned`: the raw bytes' SHA-256 is not the expected pin.
    Pin { got: [u8; 32] },
}

/// The serialisable mirror of `CommonData<Config>` (Plonky3's own type derives no serde; its
/// fields are public and each part is serialisable). Field for field, in `CommonData`'s order.
#[derive(Serialize, Deserialize)]
struct CommonDataWire {
    preprocessed: Option<PreprocessedWire>,
    lookups: Vec<p3_lookup::Lookups<Val>>,
}
#[derive(Serialize, Deserialize)]
struct PreprocessedWire {
    commitment: p3_batch_stark::config::Commitment<Config>,
    /// `(matrix_index, width, degree_bits)` per instance, `None` for no preprocessed columns.
    instances: Vec<Option<(u64, u64, u64)>>,
    matrix_to_instance: Vec<u64>,
}
fn common_to_bytes(c: &CommonData<Config>) -> Vec<u8> {
    let wire = CommonDataWire {
        preprocessed: c.preprocessed.as_ref().map(|p| PreprocessedWire {
            commitment: p.commitment.clone(),
            instances: p.instances.iter().map(|m| m.as_ref().map(|m| (m.matrix_index as u64, m.width as u64, m.degree_bits as u64))).collect(),
            matrix_to_instance: p.matrix_to_instance.iter().map(|&i| i as u64).collect(),
        }),
        lookups: c.lookups.clone(),
    };
    postcard::to_allocvec(&wire).expect("CommonData serialises")
}
/// Each instance's packed lookups, exactly as `ProverData::from_airs_and_degrees` derives them
/// (p3-batch-stark 0.7.0 `common.rs`, the lookups loop with every budget override `0`):
/// `Lookups::from_air` → `get_log_num_quotient_chunks` → `pack_same_bus` at the free budget.
/// Symbolic only — no trace, no commitment. `install_verifier_key` checks a blob's against it;
/// `tests/key_blob.rs` checks it against a real build.
fn lookups_for_airs_and_degrees(airs: &[Chip], trace_ext_degree_bits: &[usize], is_zk: usize) -> Vec<p3_lookup::Lookups<Val>> {
    use p3_lookup::{LogUpGadget, Lookups};
    let gadget = LogUpGadget::new();
    airs.iter()
        .zip(trace_ext_degree_bits)
        .map(|(air, &ext_db)| {
            let trace_len = 1usize << (ext_db - is_zk);
            let unpacked = Lookups::<Val>::from_air::<Challenge, Chip>(air);
            let log_chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, Chip, LogUpGadget>(
                air,
                p3_air::symbolic::AirLayout::from_air(air),
                trace_len,
                &unpacked,
                is_zk,
                &gadget,
            );
            let free_budget = (1usize << log_chunks) + 1 - is_zk;
            unpacked.pack_same_bus(&gadget, free_budget)
        })
        .collect()
}
fn common_from_bytes(bytes: &[u8]) -> Result<CommonData<Config>, InstallKeyError> {
    let (wire, rest) = postcard::take_from_bytes::<CommonDataWire>(bytes).map_err(|e| InstallKeyError::Decode(format!("common: {e}")))?;
    if !rest.is_empty() { return Err(InstallKeyError::Decode(format!("common: {} trailing bytes", rest.len()))); }
    let us = |x: u64| usize::try_from(x).map_err(|_| InstallKeyError::Decode("common: index overflows usize".into()));
    let preprocessed = match wire.preprocessed {
        None => None,
        Some(p) => Some(p3_batch_stark::common::GlobalPreprocessed {
            commitment: p.commitment,
            instances: p.instances.into_iter().map(|m| m.map(|(a, b, c)| Ok::<_, InstallKeyError>(p3_batch_stark::common::PreprocessedInstanceMeta { matrix_index: us(a)?, width: us(b)?, degree_bits: us(c)? })).transpose()).collect::<Result<_, _>>()?,
            matrix_to_instance: p.matrix_to_instance.into_iter().map(us).collect::<Result<_, _>>()?,
        }),
    };
    Ok(CommonData { preprocessed, lookups: wire.lookups })
}

/// The batch prover every honest CPU path calls: `prove_batch_with_layout` under
/// [`QUOTIENT_LAYOUT`] (constraint set 11, ZKVM-111; through set 10 upstream's `prove_batch`, which
/// is the fork's `PerChunk`).
fn prove_live<'a>(cfg: &'a Config, instances: &'a [StarkInstance<'a, Config, Chip>], prover_data: &'a ProverData<Config>) -> BatchProof<Config> {
    p3_batch_stark::prove_batch_with_layout(cfg, instances, prover_data, QUOTIENT_LAYOUT)
}

pub struct Machine { pub config: Config, pub profile: FriProfile, keys: Mutex<KeyCache>, key_builds: std::sync::atomic::AtomicUsize, prover_keys: Mutex<ByteLru<ProverKey, ProverData<Config>>>, prover_key_builds: std::sync::atomic::AtomicUsize, build_gate: std::sync::OnceLock<KeyBuildGate> }

/// A wrapper every verifier-key build of a machine runs inside ([`Machine::set_key_build_gate`]):
/// called with the build, it must run it exactly once (fullnode CON-60 holds it to one build at
/// a time across its state-proof machines).
pub type KeyBuildGate = Arc<dyn Fn(&mut dyn FnMut()) + Send + Sync>;

impl Machine {
    pub fn new(profile: FriProfile) -> Self { Self::with_key_cache_capacity(profile, KEY_CACHE_CAPACITY) }

    /// A test instrument (`tests/key_cache.rs`): a machine whose verifier-key cache holds
    /// `capacity` keys instead of `KEY_CACHE_CAPACITY`, so eviction is observable in a few builds.
    #[doc(hidden)]
    pub fn with_key_cache_capacity(profile: FriProfile, capacity: usize) -> Self {
        assert!(capacity > 0, "a key cache holds at least one key");
        Self {
            config: make_config(profile),
            profile,
            keys: Mutex::new(KeyCache { capacity, ..KeyCache::default() }),
            key_builds: std::sync::atomic::AtomicUsize::new(0),
            prover_keys: Mutex::new(ByteLru::new(PROVER_KEY_BUDGET)),
            prover_key_builds: std::sync::atomic::AtomicUsize::new(0),
            build_gate: std::sync::OnceLock::new(),
        }
    }

    /// Run every later verifier-key build of this machine inside `gate` (set once; a second call
    /// is ignored). Only builds: a cached key is returned without it.
    pub fn set_key_build_gate(&self, gate: KeyBuildGate) { let _ = self.build_gate.set(gate); }

    /// Sets the byte budget of the prover-side preprocessed cache ([`PROVER_KEY_BUDGET`] by
    /// default) and evicts down to it at once. `0` turns the cache off: every prove then builds its
    /// preprocessed data and drops it, as every prove did before ZKVM-110. Raise it on a prover
    /// that serves one large shape repeatedly and has the memory (the constant's doc comment has
    /// the per-tier sizes); the cache never holds more than this between proofs.
    pub fn set_prover_key_budget(&self, bytes: usize) { self.prover_keys.lock().unwrap().set_budget(bytes); }

    /// A test instrument: how many times this machine has built a prover's preprocessed data (a
    /// prove that missed the prover cache), since construction.
    #[doc(hidden)]
    pub fn prover_key_builds(&self) -> usize { self.prover_key_builds.load(std::sync::atomic::Ordering::SeqCst) }

    /// A test instrument: the bytes the prover cache holds right now, by its own accounting.
    #[doc(hidden)]
    pub fn prover_key_bytes(&self) -> usize { self.prover_keys.lock().unwrap().held }

    /// A test instrument: whether the prover's preprocessed data for `shape` is cached right now (a
    /// lookup that does not count as a use).
    #[doc(hidden)]
    pub fn has_cached_prover_key(&self, shape: VerifierKeyShape) -> bool {
        self.prover_keys.lock().unwrap().is_built(&ProverKey { constraint_set: CONSTRAINT_SET, profile: self.profile, shape: shape.key() })
    }

    /// The prover's half of [`Self::verifier_key_with_modq`]: the same
    /// `ProverData::from_airs_and_degrees(key_config, chips, degrees)` call, kept whole — the
    /// committed preprocessed tree a prove opens, not only the `CommonData` a verifier needs — and
    /// cached by bytes (ZKVM-110: every prove rebuilt it, about 8 % of a prove's wall time under
    /// `--features parallel`).
    ///
    /// **Reusing it across proofs is exactly as hiding as rebuilding it, because it holds nothing
    /// drawn per proof.** Everything in it is a function of the key: the preprocessed traces are the
    /// chips' fixed tables; `HidingFriPcs::commit_preprocessing` pads them with *zero* rows, not
    /// random ones, and adds no random codeword (`../vendor/p3-fri/src/hiding_pcs.rs`); the one
    /// thing "random" in the tree is the hiding MMCS's per-row salts
    /// (`../vendor/p3-merkle-tree/src/hiding_mmcs.rs`, `commit`), and those come from `key_config`'s
    /// stream — a fixed, public derivation (`key_derivation_v2`), restarted from its label at every
    /// call, which is what lets any verifier recompute the same cap. So two builds for one key are
    /// the same bytes, the prover before this cache already used identical preprocessed salts in
    /// every proof of a shape, and the tree commits only public data. A proof's own blinding — the
    /// main, permutation and quotient commitments' random rows, codewords and salts, the
    /// randomisation polynomial, the LogUp blinds, `H_IN`'s salt — is drawn from `self.config`'s OS
    /// entropy inside `prove_batch` and by `tables::blind::fresh`, per proof, and none of it is
    /// stored here. `prove_batch` only reads this data (`&ProverData`).
    ///
    /// Built at the tier's memory floor, as the verifier key is and for its reason: the memory table
    /// has no preprocessed columns and its packed lookups do not depend on its height
    /// (`Self::verifier_key`'s doc comment), so every valid `mem_log_height` gives this same data,
    /// and the floor makes the entry independent of which proof missed first
    /// (`prover_data_is_the_same_at_every_memory_height` pins it).
    fn prover_key(&self, shape: VerifierKeyShape) -> Arc<ProverData<Config>> {
        let key = ProverKey { constraint_set: CONSTRAINT_SET, profile: self.profile, shape: shape.key() };
        // As `verifier_key_with_modq`: the lock is held only to find or make the slot, the build
        // runs outside it, and concurrent first callers of one key share one build.
        let slot = self.prover_keys.lock().unwrap().slot(key);
        let data = slot.get_or_init(|| {
            self.prover_key_builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Arc::new(ProverData::from_airs_and_degrees(&key_config(self.profile), &shape.chips(), &self.log_ext_degrees_for(shape, shape.tier.min_mem_log_height())))
        }).clone();
        self.prover_keys.lock().unwrap().settle(key, &slot, prover_data_bytes(&data));
        data
    }

    /// A test instrument: how many verifier keys this machine has built (cache misses that ran
    /// the preprocessing pass), since construction.
    #[doc(hidden)]
    pub fn key_builds(&self) -> usize { self.key_builds.load(std::sync::atomic::Ordering::SeqCst) }

    /// A test instrument: whether the key for this shape is cached right now (a lookup that does
    /// not count as a use).
    #[doc(hidden)]
    pub fn has_cached_key(&self, shape: VerifierKeyShape) -> bool {
        self.keys.lock().unwrap().is_built(&shape.key())
    }

    /// Each instance's extended trace degree bits, in `chips()` order — a pure function of the
    /// tier and the declared heights, which is why it can be `pub`: the free function
    /// [`max_constraint_degrees`] already computes the same thing publicly, and `verify` checks
    /// `proof.batch.degree_bits` against it rather than trusting the proof.
    ///
    /// `pub` for M5.1's `recursion` crate: its `InnerShape` must derive `degree_bits` from the
    /// machine rather than from the proof — the whole point of a *shape* is that it is not
    /// proof-supplied — and this is where the machine says what they are.
    pub fn log_ext_degrees(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Vec<usize> {
        self.log_ext_degrees_with_modq(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, 0, public_log_height, mem_log_height)
    }

    /// [`Self::log_ext_degrees`] with the modq table's declared height (private multisig phase
    /// 3): its entry, when non-zero, sits after sha256's and before public's, matching
    /// `chips_with_modq`.
    #[allow(clippy::too_many_arguments)]
    pub fn log_ext_degrees_with_modq(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Vec<usize> {
        self.log_ext_degrees_at(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, modq_log_height, public_log_height, mem_log_height, tier.poseidon2_height())
    }

    /// [`Self::log_ext_degrees_at`] for a shape and a declared memory height — what `verify`
    /// compares `proof.batch.degree_bits` against.
    pub fn log_ext_degrees_for(&self, shape: VerifierKeyShape, mem_log_height: u8) -> Vec<usize> {
        let s = shape;
        self.log_ext_degrees_at(s.tier, s.program_log_height, s.input_log_height, s.keccak_log_height, s.sha256_log_height, s.modq_log_height, s.public_log_height, mem_log_height, 1usize << s.poseidon2_log_height)
    }

    /// [`Self::log_ext_degrees_with_modq`] with the poseidon2 table's height (rows) as an
    /// argument — constraint set 11's declared height (ZKVM-112); see [`chips_at`].
    #[allow(clippy::too_many_arguments)]
    pub fn log_ext_degrees_at(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8, mem_log_height: u8, poseidon2_height: usize) -> Vec<usize> {
        let zk = self.config.is_zk();
        // Order matches `chips()`: program, cpu, memory, alu, range, nibble, poseidon2, input,
        // then — only when this proof declares them — keccak and sha256, and finally the
        // mandatory public table.
        // M4.2 (controller ruling 1): the memory entry is the *declared*
        // `mem_log_height`, not a tier-derived one — `build_traces_salted` sizes the memory
        // trace with exactly the value it puts in `Traces`/`Proof`, so the two cannot drift,
        // and `verify` range-checks the declaration before it reaches here.
        let mut v = vec![program_log_height as usize + zk];
        v.push(tier.cpu_height().trailing_zeros() as usize + zk);
        v.push(mem_log_height as usize + zk);
        v.extend(
            [tier.alu_height(), crate::tables::range::HEIGHT, crate::tables::nibble::HEIGHT, poseidon2_height]
                .iter().map(|h| h.trailing_zeros() as usize + zk),
        );
        v.push(input_log_height as usize + zk);
        // M4.2 (Task 6): the keccak entry exists only when the proof declares a keccak table.
        // `keccak_log_height == 0` means there is no ninth instance, so there is no ninth
        // degree-bit either — and `verify`'s `proof.batch.degree_bits != …` equality check
        // therefore also pins the batch's instance *count* to what `chips` builds.
        if keccak_log_height != 0 {
            v.push(keccak_log_height as usize + zk);
        }
        // M4.4: and the sha256 entry, on the same terms — after keccak's, matching `chips()`.
        if sha256_log_height != 0 {
            v.push(sha256_log_height as usize + zk);
        }
        if modq_log_height != 0 {
            v.push(modq_log_height as usize + zk);
        }
        // Constraint set 6: the public table is mandatory and last, so its entry is
        // unconditional and always the final one — see `chips()`.
        v.push(public_log_height as usize + zk);
        v
    }

    /// The preprocessed commitment (range + nibble tables + Poseidon2 round constants, plus
    /// the degree-bit bookkeeping every instance needs including `program`'s and `input`'s)
    /// for `(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height,
    /// public_log_height)`,
    /// cached — see
    /// `KeyCache`. M4.2 (Task 6): `keccak_log_height = 0` is a perfectly ordinary key value —
    /// it selects a batch whose preprocessed commitment omits the keccak table's
    /// 99 periodic columns entirely, so it genuinely is a *different* key, not a missing one.
    /// M4.4: `sha256_log_height` is the fifth component and says the same thing about that
    /// chip's 10 periodic columns; the two are independent, so all four combinations are keys.
    /// Constraint set 6: `public_log_height` is the sixth, for the reason `input_log_height` is
    /// the third — the public table declares no preprocessed columns either, but its declared
    /// height is part of the batch's per-instance degree-bit bookkeeping.
    /// **The arity change is vendoring-visible** — the fullnode's `deploy/sync-zkvm.sh` anchors
    /// on this signature — so re-vendoring this constraint set has to update that script (not
    /// done here; this plan does not re-vendor the node).
    /// M4.2 (controller ruling 1): **`mem_log_height` is not a parameter of this function**, and
    /// that is not an omission. The memory table declares no preprocessed columns, so it
    /// contributes nothing to the global preprocessed commitment (`from_airs_and_degrees`
    /// pushes `None` for it regardless of its degree bits), and it declares no periodic columns
    /// either, so `get_max_constraint_degree` short-circuits before the only place a trace
    /// length can change a symbolic degree — its packed `Lookups` are therefore identical at
    /// every `mem_log_height`. Every valid declared memory height yields the *same*
    /// `CommonData`, which is why the cache key never carried one; this function therefore feeds
    /// `log_ext_degrees` the tier's own floor (`Tier::min_mem_log_height`) rather than taking a
    /// height it would ignore. (Before the M4.2 review it took one, and a caller could be
    /// forgiven for reading the cache as keyed on it.) The same argument is why `tests/tables.rs::
    /// alu_max_constraint_degree_is_pinned` can pin every table's degree at one arbitrary tier.
    /// The degree bits themselves are not taken from here: `verify` checks
    /// `proof.batch.degree_bits` against `log_ext_degrees` directly. M3.4:
    /// program-*content*-independent, so this is the *verifier's* key — computable by anyone
    /// who knows the tier and the declared program/input heights alone, without the program or
    /// inputs themselves or the proving session. Recomputing it from scratch runs the full
    /// `ProverData::from_airs_and_degrees` preprocessing pass (in particular building the range
    /// and nibble tables' Merkle trees every time), which is the cost this cache exists to
    /// amortize across repeated `verify` calls at the same `(tier, program_log_height,
    /// input_log_height)`.
    /// Public wrapper used by the chain executor to check a proof's degree bits. Takes the
    /// declared `mem_log_height` as well as `verifier_key`'s six key components: the degree
    /// vector depends on it even though the verifier key does not, and `verify` compares
    /// `proof.batch.degree_bits` against exactly this call.
    pub fn log_ext_degrees_pub(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Vec<usize> { self.log_ext_degrees(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, public_log_height, mem_log_height) }

    pub fn verifier_key(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, public_log_height: u8) -> Arc<CommonData<Config>> {
        self.verifier_key_with_modq(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, 0, public_log_height)
    }

    /// [`Self::verifier_key`] with the modq table's declared height (private multisig phase 3) as
    /// the key's sixth component; `modq_log_height = 0` is the same cache slot `verifier_key`
    /// uses.
    /// The poseidon2 table is at the tier's full `t + 2` ([`VerifierKeyShape::full_height`]); a
    /// proof that declares a shorter one is verified under [`Self::verifier_key_for`] its shape.
    #[allow(clippy::too_many_arguments)]
    pub fn verifier_key_with_modq(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8) -> Arc<CommonData<Config>> {
        self.verifier_key_for(VerifierKeyShape::full_height(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, modq_log_height, public_log_height))
    }

    /// The verifier key for one shape — every declared height a key depends on, the poseidon2
    /// table's included (constraint set 11). What `verify` uses; the caller has range-checked the
    /// shape (`VerifierKeyShape::check`).
    pub fn verifier_key_for(&self, shape: VerifierKeyShape) -> Arc<CommonData<Config>> {
        let key = shape.key();
        let tier = shape.tier;
        // The cache lock is held only to find or make the slot; the build runs outside it, and
        // `OnceLock::get_or_init` makes every concurrent caller of this shape wait for the one
        // build (#54's single flight) — a caller of another shape is never held up by it.
        let slot = self.keys.lock().unwrap().slot(key);
        slot.get_or_init(|| {
            // Any valid `mem_log_height` gives the same `CommonData` (see above); the tier's
            // floor is the canonical one, and using it makes this function's result independent
            // of which proof happened to miss the cache first.
            let mem_log_height = tier.min_mem_log_height();
            let mut built = None;
            let mut build = || {
                self.key_builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                built = Some(Arc::new(ProverData::from_airs_and_degrees(&key_config(self.profile), &shape.chips(), &self.log_ext_degrees_for(shape, mem_log_height)).common));
            };
            match self.build_gate.get() { Some(gate) => gate(&mut build), None => build() }
            built.expect("a key-build gate runs the build")
        })
        .clone()
    }

    /// Number of `(tier, program_log_height, input_log_height, keccak_log_height,
    /// sha256_log_height, modq_log_height, public_log_height, poseidon2_log_height)` verifier keys
    /// currently cached.
    pub fn cached_keys(&self) -> usize { self.keys.lock().unwrap().built() }

    /// The verifier key for one shape, as a [`VerifierKeyBlob`] another host can
    /// [`install`](Self::install_verifier_key) without building it. Builds the key (or takes it
    /// from the cache) exactly as [`Self::verifier_key_for`] does. Constraint set 11: the shape
    /// names the poseidon2 height (`VerifierKeyShape::of_proof` of a proof of the shape is the
    /// simplest way to get it right), so an exporter cannot ship the full-height key for proofs
    /// that declare a shorter table.
    pub fn export_verifier_key(&self, shape: VerifierKeyShape) -> VerifierKeyBlob {
        let common = self.verifier_key_for(shape);
        VerifierKeyBlob {
            format_version: VERIFIER_KEY_BLOB_FORMAT,
            profile: self.profile,
            shape,
            constraint_set: CONSTRAINT_SET,
            common: common_to_bytes(&common),
        }
    }

    /// [`Self::export_verifier_key`] for a key that is built and cached now, and `None`
    /// otherwise: never a build (fullnode CON-60's keep, which runs on the node loop).
    pub fn export_cached_verifier_key(&self, shape: VerifierKeyShape) -> Option<VerifierKeyBlob> {
        let common = self.keys.lock().unwrap().map.get(&shape.key()).and_then(|(slot, _, _)| slot.get().cloned())?;
        Some(VerifierKeyBlob {
            format_version: VERIFIER_KEY_BLOB_FORMAT,
            profile: self.profile,
            shape,
            constraint_set: CONSTRAINT_SET,
            common: common_to_bytes(&common),
        })
    }

    /// Installs `blob`'s key into the cache slot for `blob.shape` without building it, so
    /// `verify`/`verify_public` of a proof of that shape use it (and `key_builds` does not move).
    /// Refuses a blob of another format, profile or constraint set, a shape `verify` would refuse,
    /// `common` bytes that do not decode or whose structure disagrees with this machine's chips for
    /// the shape, and — never replacing a key — a slot already holding a different one
    /// (`SlotFilled`); re-installing the identical key is a no-op. The slot is an ordinary cache
    /// entry: LRU eviction applies to it, after which the shape is rebuilt on its next use.
    /// See [`VerifierKeyBlob`] for what the caller must pin.
    pub fn install_verifier_key(&self, blob: &VerifierKeyBlob) -> Result<(), InstallKeyError> {
        if blob.format_version != VERIFIER_KEY_BLOB_FORMAT { return Err(InstallKeyError::Format { blob: blob.format_version, machine: VERIFIER_KEY_BLOB_FORMAT }); }
        if blob.profile != self.profile { return Err(InstallKeyError::Profile { blob: blob.profile, machine: self.profile }); }
        if blob.constraint_set != CONSTRAINT_SET { return Err(InstallKeyError::ConstraintSet { blob: blob.constraint_set, machine: CONSTRAINT_SET }); }
        let s = blob.shape;
        // The shape is untrusted the way a proof header is: range-check it before it sizes
        // anything (`Tier` in `TIERS` first of all), at the tier's own memory floor.
        s.check().map_err(InstallKeyError::Shape)?;
        let common = common_from_bytes(&blob.common)?;
        // Structure: what this machine's chips and degree bits say for the shape — cheap, no trace.
        let chips = s.chips();
        let degrees = self.log_ext_degrees_for(s, s.tier.min_mem_log_height());
        let bad = |m: String| Err(InstallKeyError::Structure(m));
        if common.lookups.len() != chips.len() { return bad(format!("{} lookups for {} instances", common.lookups.len(), chips.len())); }
        let Some(pre) = common.preprocessed.as_ref() else { return bad("no preprocessed commitment".into()) };
        if pre.instances.len() != chips.len() { return bad(format!("{} preprocessed entries for {} instances", pre.instances.len(), chips.len())); }
        let mut next = 0usize;
        for (i, (chip, meta)) in chips.iter().zip(&pre.instances).enumerate() {
            let width = <Chip as BaseAir<Val>>::preprocessed_width(chip);
            match meta {
                None if width == 0 => {}
                Some(m) if width != 0 && m.width == width && m.degree_bits == degrees[i] && m.matrix_index == next && pre.matrix_to_instance.get(next) == Some(&i) => next += 1,
                _ => return bad(format!("instance {i}: preprocessed placement disagrees with the chip")),
            }
        }
        if pre.matrix_to_instance.len() != next { return bad("matrix_to_instance length".into()); }
        // The packed lookups are derivable without a trace or a commitment: recompute them and
        // require the blob's to be byte-identical, so the commitment is the only trusted part.
        let want = lookups_for_airs_and_degrees(&chips, &degrees, self.config.is_zk());
        for (i, (got, want)) in common.lookups.iter().zip(&want).enumerate() {
            if postcard::to_allocvec(got).expect("lookups serialise") != postcard::to_allocvec(want).expect("lookups serialise") {
                return bad(format!("instance {i}: packed lookups disagree with the chip"));
            }
        }
        let key = s.key();
        let slot = self.keys.lock().unwrap().slot(key);
        let result = match slot.set(Arc::new(common)) {
            Ok(()) => Ok(()),
            Err(_) => {
                let held = slot.get().expect("set failed, so the slot is filled");
                if common_to_bytes(held) == blob.common { Ok(()) } else { Err(InstallKeyError::SlotFilled) }
            }
        };
        if result.is_ok() { self.keys.lock().unwrap().pin(&key); }
        result
    }

    /// [`Self::install_verifier_key`] from raw blob bytes, refusing them unless their SHA-256
    /// (`crate::sha256::sha256` over the whole `VerifierKeyBlob::to_bytes()`) is `expected` —
    /// checked BEFORE the bytes are decoded, so unpinned input never reaches the decoder. This is
    /// the entry a consumer should use (`VerifierKeyBlob`'s trust paragraph).
    pub fn install_verifier_key_pinned(&self, bytes: &[u8], expected: &[u8; 32]) -> Result<(), InstallKeyError> {
        let got = crate::sha256::sha256(bytes);
        if &got != expected { return Err(InstallKeyError::Pin { got }); }
        self.install_verifier_key(&VerifierKeyBlob::from_bytes(bytes)?)
    }

    /// Draws a fresh per-proof salt from OS entropy and delegates to [`Self::prove_salted`] —
    /// see that method's doc comment (controller ruling: H_IN, `pv::IN0..7`, must be salted or
    /// it is a guessable commitment to the private inputs). Every ordinary caller wants this;
    /// `prove_salted` exists only for tests that need a fixed salt to check against.
    pub fn prove(&self, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        use rand::RngExt;
        let salt: [u32; 4] = rand::rng().random();
        self.prove_salted(program, inputs, public, salt, tier)
    }

    /// The body of `prove`, taking the H_IN salt explicitly instead of drawing it from OS
    /// entropy — what every backend variant (`prove_with`/`prove_on`) also threads through.
    /// `verify(hc, proof)` does not take the salt: it never leaves the prover except folded,
    /// non-invertibly, into `pv::IN0..7` (`hash::input_digest`'s doc comment).
    pub fn prove_salted(&self, program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        self.prove_salted_with(program, inputs, public, salt, tier, ProveOptions::default())
    }

    /// `prove` under explicit [`ProveOptions`] (a fresh H_IN salt, as `prove` draws).
    pub fn prove_with_options(&self, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>, opts: ProveOptions) -> Result<(Proof, Execution), ProveError> {
        use rand::RngExt;
        let salt: [u32; 4] = rand::rng().random();
        self.prove_salted_with(program, inputs, public, salt, tier, opts)
    }

    /// `prove_salted` under explicit [`ProveOptions`].
    pub fn prove_salted_with(&self, program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], tier: Option<Tier>, opts: ProveOptions) -> Result<(Proof, Execution), ProveError> {
        // Run up to the largest tier's cycle budget; a program that has not halted by then
        // can never be proved, so `OutOfCycles` and `TooManyCycles` agree on the limit.
        let exec = execute(program, inputs, public, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier {
            // Audit ZH3 (2026-09-12): an out-of-`TIERS` tier is an error here, not a
            // shift-overflow panic (debug) or a masked shift plus an abort-scale allocation
            // (release) inside `Tier::cpu_height` — the mirror of `check_declared_heights`' own
            // `TIERS.contains` guard on the untrusted-proof side.
            Some(t) if TIERS.contains(&t.0) => t,
            Some(t) => return Err(ProveError::BadTier(t.0)),
            None => {
                let cycles = exec.cycles() + program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len());
                // Audit ZH1 (2026-09-12): fit the Poseidon2 permutation budget too — the cycle
                // budget alone does not imply it (`2^(t-3)` blocks against up to ~`2^t`
                // permutation-emitting rows), so the old cycles-only pick could walk straight
                // into `poseidon2_trace`'s capacity assert.
                let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
                let permutations = program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len()) + absorb_rows;
                Tier::for_workload(cycles, permutations).ok_or(ProveError::NoTier(cycles))?
            }
        };
        let traces = build_traces_salted_with(program, inputs, public, salt, &exec, tier, opts)?;
        // ZKVM-110: the trace set is this function's own, so it is widened in place rather than
        // copied (`prove_traces`, which only borrows one, has to copy).
        let head = traces.head();
        let narrow = traces.into_matrices();
        let blinds = crate::tables::blind::fresh(narrow.len());
        let wide = narrow.into_iter().zip(&blinds).map(|(m, b)| crate::tables::blind::widen_owned(m, b)).collect();
        Ok((self.prove_wide(&head, wide, tier, prove_live), exec))
    }

    /// NOTE: the body below is duplicated, deliberately, by `prove_on` (the generic-over-config
    /// twin used by `Backend::Reference`/`Backend::Cuda`). The two must stay identical in every
    /// proof-shaping respect — instance construction, the `i == 1` public-values placement, and
    /// the `key_config`/`self.config` split between the key's prover data and `prove_batch` —
    /// or a backend proof stops matching what the CPU verifier recomputes. Change one, change
    /// the other.
    /// `program` is no longer read here (M3.4: `chips`/`key_config` are program-independent,
    /// and `traces` already carries everything the witness needs, `hc` included via
    /// `public_values`) — kept in the signature for symmetry with `prove`/`prove_on`, which
    /// still need the program to execute it and build `traces` in the first place.
    ///
    /// Constraint set 7: draws fresh LogUp blinds (`tables::blind::fresh`) and appends them to the
    /// traces — `Traces` holds each table at its own width, the committed trace is five columns
    /// wider (`Chip`'s `BaseAir::width`). The trace set is only borrowed here, so the widening
    /// copies each trace once and both copies live until the proof is done — one trace set more,
    /// 1.4 % of the proof's peak live heap (ZKVM-110, measured). `prove` and its variants own their
    /// trace set and widen it in place instead (`tables::blind::widen_owned`); a caller of this
    /// function that builds its own `Traces` pays the copy.
    pub fn prove_traces(&self, program: &Program, traces: &Traces, tier: Tier) -> Proof {
        let blinds = crate::tables::blind::fresh(traces.as_slice().len());
        self.prove_traces_with_blinds(program, traces, tier, &blinds)
    }

    /// [`Self::prove_traces`] with the blinds given instead of drawn — one per instance, in
    /// `chips()` order. A test hook: an honest caller wants [`Self::prove_traces`]' fresh ones, and
    /// blinds that do not balance (`tests/cheating.rs`) are refused like any other unbalanced bus.
    #[doc(hidden)]
    pub fn prove_traces_with_blinds(&self, _program: &Program, traces: &Traces, tier: Tier, blinds: &[crate::tables::blind::Blind]) -> Proof {
        self.prove_traces_via(traces, tier, blinds, prove_live)
    }

    /// Cheating-suite hook (`cheating` feature only; audit CS9-2): [`Self::prove_traces`] with the
    /// batch prover's debug-build self-checks off (`p3_batch_stark::SelfCheck::Skip`), so a *forged*
    /// trace set is proved as given and [`Self::verify`] is what refuses it — with its typed error,
    /// the thing a forgery test asserts on. Under plain `cargo test` (`debug_assertions` on) the
    /// prover otherwise checks every instance's constraints and the global lookup balance before it
    /// commits, and panics on the lie first; `--release` has no such check, which is why the three
    /// tests this exists for (`tests/modq_cheating.rs`) used to pass there and fail in debug. Not a
    /// soundness lever: a skipped self-check only lets a proof the verifier then rejects be built.
    /// Fresh blinds, the same instances, the same key split as `prove_traces`; no prover path calls
    /// this.
    #[cfg(feature = "cheating")]
    #[doc(hidden)]
    pub fn prove_traces_without_self_check(&self, _program: &Program, traces: &Traces, tier: Tier) -> Proof {
        use p3_batch_stark::{prove_batch_with_layout_and_self_check, SelfCheck};
        let blinds = crate::tables::blind::fresh(traces.as_slice().len());
        self.prove_traces_via(traces, tier, &blinds, |cfg, instances, prover_data| {
            prove_batch_with_layout_and_self_check(cfg, instances, prover_data, QUOTIENT_LAYOUT, SelfCheck::Skip)
        })
    }

    /// The one body behind [`Self::prove_traces_with_blinds`] and
    /// [`Self::prove_traces_without_self_check`]: the instances, the `i == 1` public-values slot and
    /// the `key_config`/`self.config` split, with `prove` the batch prover call itself —
    /// [`prove_live`] (`prove_batch_with_layout` under [`QUOTIENT_LAYOUT`]) on every honest path.
    fn prove_traces_via(
        &self,
        traces: &Traces,
        tier: Tier,
        blinds: &[crate::tables::blind::Blind],
        prove: impl for<'a> FnOnce(&'a Config, &'a [StarkInstance<'a, Config, Chip>], &'a ProverData<Config>) -> BatchProof<Config>,
    ) -> Proof {
        assert_eq!(traces.as_slice().len(), blinds.len(), "one blind per instance");
        let wide: Vec<RowMajorMatrix<Val>> = traces.as_slice().iter().zip(blinds).map(|(m, b)| crate::tables::blind::widen(m, b)).collect();
        self.prove_wide(&traces.head(), wide, tier, prove)
    }

    /// The batch proof of a trace set already at its committed width — `wide`, one matrix per chip
    /// in `chips()` order, each with its blind columns — and `traces`' public values and heights.
    /// The body of [`Self::prove_traces_via`] (which copies a borrowed trace set to get `wide`) and
    /// of `prove_salted_with` (which widens its own in place).
    fn prove_wide(
        &self,
        traces: &TraceHead,
        wide: Vec<RowMajorMatrix<Val>>,
        tier: Tier,
        prove: impl for<'a> FnOnce(&'a Config, &'a [StarkInstance<'a, Config, Chip>], &'a ProverData<Config>) -> BatchProof<Config>,
    ) -> Proof {
        let shape = traces.shape(tier);
        let airs = shape.chips();
        // M4.2 (Task 6): `keccak_log_height` picks the chip set and `keccak` supplies the
        // traces, so the two must agree — a mismatch would `zip` short and silently prove a
        // different batch than the degree bits describe.
        assert_eq!(airs.len(), wide.len(), "one trace per chip: the declared keccak/sha256/modq heights and Traces::keccak/sha256 disagree");
        let mats: Vec<&RowMajorMatrix<Val>> = wide.iter().collect();
        let instances: Vec<StarkInstance<'_, Config, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        // Built with `key_config` so the preprocessed tree's commitment (and the leaf data
        // `prove_batch` opens it against) matches exactly what a verifier will recompute via
        // `verifier_key`. `prove_batch` itself still runs against `self.config` (fresh entropy)
        // for the main trace, quotient, and permutation commitments: see the doc comment on
        // `key_config` and the confirmation below that `prove_batch` never re-derives the
        // preprocessed commitment from its `config` argument.
        //
        // Confirmed in `p3-batch-stark-0.7.0/src/prover.rs`: `prove_batch` reads the
        // preprocessed commitment and metadata from `prover_data.common.preprocessed`, and
        // opens it using `prover_data.prover_only.preprocessed_prover_data` directly (see the
        // "Round 3" block that builds `rounds` for `pcs.open_with_preprocessing`). It only
        // calls `config.pcs()` for the PCS's structural operations (domains, the main/quotient/
        // permutation commits, and the actual opening machinery) — never to recompute or
        // re-commit the preprocessed trace. So `config` and the config used to build
        // `prover_data` only need to be *structurally* compatible (same hash/compress/Dft/FRI
        // parameters, which `key_config` and `make_config` share via `build_config`); their
        // RNG state can differ freely.
        //
        // ZKVM-110: that data is now taken from the prover cache (`prover_key`, whose doc comment
        // has why reusing it across proofs changes nothing a proof hides) instead of being rebuilt
        // here on every prove.
        // Keyed on the whole shape, the declared poseidon2 height included (constraint set 11).
        let prover_data = self.prover_key(shape);
        let batch = prove(&self.config, &instances, &prover_data);
        Proof { tier, program_log_height: traces.program_log_height, input_log_height: traces.input_log_height, keccak_log_height: traces.keccak_log_height, sha256_log_height: traces.sha256_log_height, modq_log_height: traces.modq_log_height, public_log_height: traces.public_log_height, mem_log_height: traces.mem_log_height, poseidon2_log_height: traces.poseidon2_log_height, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }
    }

    /// Prove on `backend`. `Backend::Cpu` is exactly `prove`; the other backends run the same
    /// batch STARK with `rand-zkvm-cuda`'s engines and hand back a `Proof` that this
    /// `Machine`'s own `verify` accepts.
    pub fn prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        match backend {
            Backend::Cpu => self.prove(program, inputs, public, tier),
            #[cfg(feature = "reference-backend")]
            Backend::Reference => {
                // Fresh entropy for the proving config (hiding), deterministic for the key
                // config — the same split `make_config`/`key_config` make on the CPU.
                let cfg = reference_cfg::config(self.profile, SaltRng::fresh(), SaltRng::fresh());
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = reference_cfg::config(self.profile, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, public, tier)
            }
            #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
            Backend::Cuda => {
                let gpu = rand_zkvm_cuda::gpu::GpuProver::probe(PERM_SEED).map_err(|e| ProveError::Backend(e.to_string()))?;
                let cfg = cuda_cfg::config(self.profile, gpu.clone(), SaltRng::fresh(), SaltRng::fresh());
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = cuda_cfg::config(self.profile, gpu, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, public, tier)
            }
        }
    }

    /// The body of `prove`/`prove_traces` over any structurally compatible config. The proof
    /// is converted to the CPU `Config` by a postcard round trip: the alternative configs
    /// commit with the same Poseidon2 permutation, the same salt stream and the same FRI
    /// parameters, so the wire encodings of their commitments and opening proofs are
    /// byte-identical to the CPU ones and the decode is a pure retyping.
    ///
    /// `key_cfg` must be seeded from `key_rngs`: the preprocessed commitment is what the
    /// verifier recomputes on the CPU via `verifier_key`, and the backend has to reproduce it
    /// exactly or verification fails at the first check.
    ///
    /// NOTE: this body is a deliberate duplicate of `prove_traces`'s (which cannot be generic
    /// over `SC` because `Proof` names the CPU `Config`). Instance construction, the `i == 1`
    /// public-values placement, and the `key_cfg`/`cfg` split must stay identical in both, or a
    /// backend proof stops matching what the CPU verifier recomputes. Change one, change the
    /// other.
    #[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
    fn prove_on<SC>(&self, cfg: &SC, key_cfg: &SC, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>
    where
        SC: StarkGenericConfig<Challenge = Challenge, Challenger = Challenger>,
        // Bounds copied from `p3_batch_stark::prove_batch`'s signature, plus the pin that
        // makes this config's base field our `Val` so `Chip`'s `Air` impls apply.
        SC::Pcs: p3_commit::Pcs<Challenge, Challenger, Domain: p3_commit::PolynomialSpace<Val = Val>> + Sync,
        p3_batch_stark::Domain<SC>: Send + Sync,
        <SC::Pcs as p3_commit::Pcs<Challenge, Challenger>>::ProverData: Sync,
        <SC::Pcs as p3_commit::Pcs<Challenge, Challenger>>::Commitment: Sync,
    {
        // Mirrors `prove`: run up to the largest tier's cycle budget, so `OutOfCycles` and
        // `TooManyCycles` agree on the limit here exactly as they do on the CPU path, and draw
        // the same fresh-per-proof H_IN salt from OS entropy `prove`/`prove_salted` do.
        use rand::RngExt;
        let salt: [u32; 4] = rand::rng().random();
        let exec = execute(program, inputs, public, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier {
            // Audit ZH3 (2026-09-12): an out-of-`TIERS` tier is an error here, not a
            // shift-overflow panic (debug) or a masked shift plus an abort-scale allocation
            // (release) inside `Tier::cpu_height` — the mirror of `check_declared_heights`' own
            // `TIERS.contains` guard on the untrusted-proof side.
            Some(t) if TIERS.contains(&t.0) => t,
            Some(t) => return Err(ProveError::BadTier(t.0)),
            None => {
                let cycles = exec.cycles() + program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len());
                // Audit ZH1 (2026-09-12): fit the Poseidon2 permutation budget too — the cycle
                // budget alone does not imply it (`2^(t-3)` blocks against up to ~`2^t`
                // permutation-emitting rows), so the old cycles-only pick could walk straight
                // into `poseidon2_trace`'s capacity assert.
                let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
                let permutations = program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len()) + absorb_rows;
                Tier::for_workload(cycles, permutations).ok_or(ProveError::NoTier(cycles))?
            }
        };
        let traces = build_traces_salted_with(program, inputs, public, salt, &exec, tier, ProveOptions::default())?;
        let shape = traces.shape(tier);
        let airs = shape.chips();
        // M4.2 (Task 6): `keccak_log_height` picks the chip set and `keccak` supplies the
        // traces, so the two must agree — a mismatch would `zip` short and silently prove a
        // different batch than the degree bits describe.
        assert_eq!(airs.len(), traces.as_slice().len(), "one trace per chip: the declared keccak/sha256/modq heights and Traces::keccak/sha256 disagree");
        // Constraint set 7: fresh blinds, appended — `prove_salted_with`'s step, duplicated with it,
        // in place for the same reason (ZKVM-110: this function owns its trace set).
        let blinds = crate::tables::blind::fresh(airs.len());
        let (traces, narrow) = (traces.head(), traces.into_matrices());
        let wide: Vec<RowMajorMatrix<Val>> = narrow.into_iter().zip(&blinds).map(|(m, b)| crate::tables::blind::widen_owned(m, b)).collect();
        let mats: Vec<&RowMajorMatrix<Val>> = wide.iter().collect();
        let instances: Vec<StarkInstance<'_, SC, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        // `log_ext_degrees` reads `self.config.is_zk()` — the *CPU* config — not `key_cfg`'s.
        // That is invariant, not a leak: every backend config (`reference_cfg`, `cuda_cfg`) is
        // built on `HidingFriPcs` just as `make_config` is, so `is_zk()` is `true` for all of
        // them and the degree bits agree with what `verify` recomputes.
        // ZKVM-110: this path still builds its preprocessed data on every prove. `Machine`'s prover
        // cache holds the CPU `Config`'s `ProverData`; a backend's is a different type (its own
        // Merkle tree and, on CUDA, device handles), so caching it is that backend's own work.
        let prover_data = ProverData::from_airs_and_degrees(key_cfg, &airs, &self.log_ext_degrees_for(shape, traces.mem_log_height));
        // The engines panic (rather than return) on a device failure — `CudaHashEngine::ok`
        // and friends — so a backend fault must not take the caller's process down with it.
        // Constraint set 11 (ZKVM-111): the live quotient layout, as `prove_live` on the CPU.
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p3_batch_stark::prove_batch_with_layout(cfg, &instances, &prover_data, QUOTIENT_LAYOUT)))
            .map_err(|p| ProveError::Backend(panic_message(p)))?;
        let bytes = postcard::to_allocvec(&batch).map_err(|e| ProveError::Backend(format!("proof serialise: {e}")))?;
        let batch: BatchProof<Config> = postcard::from_bytes(&bytes).map_err(|e| ProveError::Backend(format!("proof convert: {e}")))?;
        Ok((Proof { tier, program_log_height: traces.program_log_height, input_log_height: traces.input_log_height, keccak_log_height: traces.keccak_log_height, sha256_log_height: traces.sha256_log_height, modq_log_height: traces.modq_log_height, public_log_height: traces.public_log_height, mem_log_height: traces.mem_log_height, poseidon2_log_height: traces.poseidon2_log_height, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }, exec))
    }

    /// Every refusal [`Self::verify`] makes before it builds or looks up a verifier key — the
    /// public values against `hc`, the declared shape, the pc window, the commit PoW witnesses
    /// and the degree bits — in `verify`'s order. `verify` runs exactly this first, so a caller
    /// that must not spend a key build on a proof `verify` would refuse for free (a node's pool,
    /// fullnode CON-60) asks the same function and cannot drift from it.
    pub fn check_pre_key(&self, hc: &[u32; 8], proof: &Proof) -> Result<(), VerifyError> {
        check_public_values(hc, proof)?;
        // M4.2 (Task 5 review): every range check on the proof's declared shape, in one place
        // and before anything is sized from it — `check_declared_heights`' doc comment has the
        // reasoning and the order. It runs *before* `log_ext_degrees`, `verifier_key` and
        // `chips`, so a forged header (with `degree_bits` edited to match, which is what an
        // attacker would have to do to reach the equality check below) costs the verifier a
        // handful of comparisons rather than a multi-second — at an absurd declared height,
        // multi-minute — preprocessed-commitment recomputation. `tests/cheating.rs` observes
        // exactly that as `cached_keys() == 0` after a rejection. Constraint set 11 adds the
        // declared poseidon2 height to the checks (`check_poseidon2_log_height`).
        check_declared_heights_with_modq(
            proof.tier,
            proof.program_log_height,
            proof.input_log_height,
            proof.keccak_log_height,
            proof.sha256_log_height,
            proof.modq_log_height,
            proof.public_log_height,
            proof.mem_log_height,
            proof.poseidon2_log_height,
        )?;
        // ISA-1 residual (randprotocol/fullnode#53): the claimed entry pc plus the declared (and,
        // above, range-checked) program table must end at or below 2^32 — the prover's own
        // `PcWindow` refusal, made again on the untrusted header. `PC_ENTRY` is bound in-circuit to
        // the first cpu row's `PC`, and `hc` absorbs `base_pc`, so this reads the program's own
        // `base_pc`; no honest proof trips it.
        let entry_pc = proof.public_values[crate::tables::cpu::pv::PC_ENTRY];
        if !crate::tables::program::pc_window_fits(entry_pc, proof.program_log_height) {
            return Err(VerifyError::PcWindow { entry_pc, program_log_height: proof.program_log_height });
        }
        // Audit VERIFIER-1: the commit-phase proof-of-work words, unobserved at zero bits, must be
        // the honest zero — one encoding per proof (`check_commit_pow_witnesses`). A comparison per
        // round, so it goes with the other cheap checks, before the key is built.
        check_commit_pow_witnesses(proof)?;
        let shape = VerifierKeyShape::of_proof(proof);
        // M4.2 (Task 6): a `Vec` comparison, so this is simultaneously the check that
        // `degree_bits.len()` equals the batch's chip count — eight without a keccak table, nine
        // with one — and the check that every declared height matches (the poseidon2 table's
        // too, since constraint set 11). A proof that claims `keccak_log_height = 0` while
        // carrying nine instances (or vice versa) fails here, before `chips` builds anything.
        if proof.batch.degree_bits != self.log_ext_degrees_for(shape, proof.mem_log_height) { return Err(VerifyError::Tier); }
        Ok(())
    }

    /// M3.4: takes `hc`, not the program — the verifier no longer holds the program at all
    /// (`docs/03-privacy.md`). `hc` is checked against `pv::HC0..HC7`, the in-circuit program
    /// digest `tables::cpu`'s digest rows compute and pin; `pc_entry` is no longer
    /// independently checkable here (the verifier has no `base_pc` from anywhere except the
    /// proof itself) — it is read out of the proof, still bound in-circuit to the digest
    /// group's own `PC` (see `tables::cpu`'s `eval`), and indirectly to `hc` too, since
    /// `Program::digest` absorbs `base_pc`: a mismatched `pc_entry` claim would need a
    /// matching-but-different program producing the same `hc`, a genuine hash collision, not
    /// a free forgery.
    pub fn verify(&self, hc: &[u32; 8], proof: &Proof) -> Result<(), VerifyError> {
        self.verify_under(hc, proof, QUOTIENT_LAYOUT)
    }

    /// [`Self::verify`]'s body, with the quotient layout the batch verifier lists the quotient
    /// round under: `verify` passes [`QUOTIENT_LAYOUT`] (`PerInstance` since constraint set 11) and
    /// only the test hook `verify_with_layout` passes anything else.
    fn verify_under(&self, hc: &[u32; 8], proof: &Proof, layout: p3_batch_stark::QuotientLayout) -> Result<(), VerifyError> {
        self.check_pre_key(hc, proof)?;
        let shape = VerifierKeyShape::of_proof(proof);
        let airs = shape.chips();
        let pv_vals: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..airs.len()).map(|i| if i == 1 { pv_vals.clone() } else { vec![] }).collect();
        let common = self.verifier_key_for(shape);
        p3_batch_stark::verify_batch_with_layout(&self.config, &airs, &proof.batch, &pvs, &common, layout).map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }

    /// A test hook (`tests/quotient_layout.rs`): [`Self::verify`] with the batch verifier told the
    /// quotient layout. The live verifier is `verify`, which accepts [`QUOTIENT_LAYOUT`] proofs
    /// only; a verifier must never let a proof choose how it is checked.
    #[doc(hidden)]
    pub fn verify_with_layout(&self, hc: &[u32; 8], proof: &Proof, layout: p3_batch_stark::QuotientLayout) -> Result<(), VerifyError> {
        self.verify_under(hc, proof, layout)
    }

    /// A test hook (`tests/quotient_layout.rs`): [`Self::prove_traces`] with the batch prover told
    /// how to commit the quotient chunks. [`QUOTIENT_LAYOUT`] is `prove_traces`.
    #[doc(hidden)]
    pub fn prove_traces_with_layout(&self, traces: &Traces, tier: Tier, layout: p3_batch_stark::QuotientLayout) -> Proof {
        let blinds = crate::tables::blind::fresh(traces.as_slice().len());
        self.prove_traces_via(traces, tier, &blinds, |cfg, instances, prover_data| p3_batch_stark::prove_batch_with_layout(cfg, instances, prover_data, layout))
    }

    /// `verify`, plus the check the public segment exists for: `hash::public_digest(public_words)`
    /// recomputed natively and compared against `pv::PUB0..7`. This is what a chain calls — it
    /// publishes the words with the transaction and checks that the proof committed to exactly
    /// them. `verify` alone leaves `pv::PUB0..7` unchecked against anything outside the proof
    /// (it is still pinned *in-circuit* to whatever the `public` table supplied, so the guest's
    /// reads and the digest agree; what `verify` cannot know is which words those were).
    pub fn verify_public(&self, hc: &[u32; 8], public_words: &[u32], proof: &Proof) -> Result<(), VerifyError> {
        self.verify(hc, proof)?;
        let want = crate::hash::public_digest(public_words);
        for i in 0..8 {
            if proof.public_values[crate::tables::cpu::pv::PUB0 + i] != want[i] as u64 {
                return Err(VerifyError::PublicValues);
            }
        }
        Ok(())
    }
}

/// Symbolic max constraint degree of each chip, in `chips()` order — computed the same way
/// `ProverData::from_airs_and_degrees` (i.e. `verifier_key`) derives each instance's quotient
/// chunk count: against the real, same-bus-packed lookup contexts for `tier`, not a
/// hand-counted estimate (M3.4: no longer program-*content*-dependent — every chip's shape,
/// `Chip::Program` included, is a pure function of the tier and the declared
/// `program_log_height`; the *symbolic* degree the caller cares about here is height-invariant
/// regardless, same as it's tier-invariant — see the comment at the call site). No proving
/// happens here — only the symbolic constraint walk
/// (`p3_batch_stark::symbolic::get_max_constraint_degree`) plus the one preprocessed-column
/// commitment `from_airs_and_degrees` always does, so this stays fast.
///
/// Exists to back `tests/tables.rs`'s per-table constraint-degree regression tests: each
/// table's degree is pinned to a specific number there, with a comment on *why*; a change
/// here should come with a matching update to those assertions and to
/// `docs/02-tables-and-buses.md`.
pub fn max_constraint_degrees(tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Vec<usize> {
    max_constraint_degrees_with_modq(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, 0, public_log_height, mem_log_height)
}

/// [`max_constraint_degrees`] with the modq table's declared height (private multisig phase 3).
#[allow(clippy::too_many_arguments)]
pub fn max_constraint_degrees_with_modq(tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8, public_log_height: u8, mem_log_height: u8) -> Vec<usize> {
    let machine = Machine::new(FriProfile::Test);
    let key_cfg = key_config(machine.profile);
    let airs = chips_with_modq(tier, keccak_log_height, sha256_log_height, modq_log_height);
    let is_zk = machine.config.is_zk();
    let ext_degrees = machine.log_ext_degrees_with_modq(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height, modq_log_height, public_log_height, mem_log_height);
    let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &ext_degrees);
    let lookup_gadget = p3_lookup::LogUpGadget::new();
    airs.iter()
        .zip(prover_data.common.lookups.iter())
        .zip(ext_degrees.iter())
        .map(|((air, lookups), &ext_db)| {
            let trace_len = 1usize << (ext_db - is_zk);
            p3_batch_stark::symbolic::get_max_constraint_degree::<Val, Challenge, Chip, _>(
                air,
                p3_air::symbolic::AirLayout::from_air(air),
                trace_len,
                lookups,
                &lookup_gadget,
            )
        })
        .collect()
}

#[cfg(test)]
mod key_cache_tests {
    use super::*;

    /// Installed (pinned) entries survive any amount of churn past capacity; unpinned ones go LRU.
    #[test]
    fn a_pinned_entry_is_never_evicted() {
        let mut c = KeyCache { capacity: 4, ..KeyCache::default() };
        let k = |i: u8| (10usize, i, 7, 0, 0, 0, 7, 12);
        c.slot(k(0));
        c.pin(&k(0));
        for i in 1..100 { c.slot(k(i)); }
        assert!(c.map.contains_key(&k(0)), "the pinned entry survived 99 other shapes");
        assert_eq!(c.map.len(), 4);
        assert!(c.map.contains_key(&k(99)) && !c.map.contains_key(&k(1)), "unpinned entries still go LRU");
        // All pinned: the cache grows past capacity rather than evict one.
        for i in 96..100 { c.pin(&k(i)); }
        c.slot(k(200));
        assert_eq!(c.map.len(), 5);
    }
}

#[cfg(test)]
mod prover_cache_tests {
    use super::*;

    fn built(c: &mut ByteLru<u8, u32>, key: u8, value: u32, bytes: usize) {
        let slot = c.slot(key);
        slot.get_or_init(|| Arc::new(value));
        c.settle(key, &slot, bytes);
    }

    #[test]
    fn the_byte_budget_evicts_the_least_recently_used_entry() {
        let mut c = ByteLru::<u8, u32>::new(100);
        built(&mut c, 1, 10, 40);
        built(&mut c, 2, 20, 40);
        assert_eq!(c.held, 80);
        c.slot(1); // a hit: 1 is now the most recently used
        built(&mut c, 3, 30, 40); // 120 > 100: the least recently used, 2, goes
        assert_eq!(c.held, 80);
        assert!(c.is_built(&1) && !c.is_built(&2) && c.is_built(&3));
        // Settling an entry twice (a second caller of the same build) charges it once.
        let slot = c.slot(3);
        c.settle(3, &slot, 40);
        assert_eq!(c.held, 80);
        // The budget is never exceeded, whatever is asked of it.
        for k in 10..60 {
            built(&mut c, k, k as u32, 7 + (k as usize % 5) * 11);
            assert!(c.held <= 100, "held {} after key {k}", c.held);
        }
        assert_eq!(c.held, c.map.values().map(|e| e.2.unwrap()).sum::<usize>(), "the count is the sum of what is held");
    }

    #[test]
    fn an_entry_larger_than_the_budget_is_not_kept_and_evicts_nothing() {
        let mut c = ByteLru::<u8, u32>::new(100);
        built(&mut c, 1, 10, 60);
        built(&mut c, 2, 20, 101);
        assert!(c.is_built(&1) && !c.is_built(&2));
        assert_eq!(c.held, 60);
        // Budget 0 is "off": nothing is ever kept.
        let mut off = ByteLru::<u8, u32>::new(0);
        built(&mut off, 1, 10, 1);
        assert!(off.map.is_empty() && off.held == 0);
        // And lowering the budget evicts at once.
        built(&mut c, 3, 30, 40);
        c.set_budget(50);
        assert!(!c.is_built(&1) && c.is_built(&3) && c.held == 40);
        c.set_budget(0);
        assert!(c.map.is_empty() && c.held == 0);
    }

    /// An entry that was evicted while its builder was still using it is not charged when that
    /// builder settles, and a new caller of the key gets a new, empty slot.
    #[test]
    fn a_slot_evicted_before_it_settles_is_not_charged() {
        let mut c = ByteLru::<u8, u32>::new(100);
        let old = c.slot(1);
        c.map.remove(&1);
        let new = c.slot(1);
        assert!(!Arc::ptr_eq(&old, &new));
        old.get_or_init(|| Arc::new(1));
        c.settle(1, &old, 40);
        assert_eq!(c.held, 0, "the stale slot is not this key's entry any more");
        assert!(new.get().is_none(), "and the key's own slot is still to be built");
    }

    /// The key is the whole of what the data depends on: change any one component — the constraint
    /// set, the profile, or any of the eight shape components — and the cache hands out a different
    /// slot, never the first key's data; the same key gets its own back.
    #[test]
    fn a_key_differing_in_any_component_never_gets_another_keys_data() {
        let base = ProverKey { constraint_set: CONSTRAINT_SET, profile: FriProfile::Test, shape: (10, 7, 7, 0, 0, 0, 7, 12) };
        let mut others = vec![
            ProverKey { constraint_set: CONSTRAINT_SET + 1, ..base },
            ProverKey { profile: FriProfile::Production, ..base },
        ];
        let s = base.shape;
        others.extend([
            (12, s.1, s.2, s.3, s.4, s.5, s.6, s.7),
            (s.0, 8, s.2, s.3, s.4, s.5, s.6, s.7),
            (s.0, s.1, 8, s.3, s.4, s.5, s.6, s.7),
            (s.0, s.1, s.2, 7, s.4, s.5, s.6, s.7),
            (s.0, s.1, s.2, s.3, 7, s.5, s.6, s.7),
            (s.0, s.1, s.2, s.3, s.4, 10, s.6, s.7),
            (s.0, s.1, s.2, s.3, s.4, s.5, 8, s.7),
            (s.0, s.1, s.2, s.3, s.4, s.5, s.6, 8),
        ].map(|shape| ProverKey { shape, ..base }));
        let mut c = ByteLru::<ProverKey, usize>::new(1 << 20);
        let first = c.slot(base);
        first.get_or_init(|| Arc::new(usize::MAX));
        c.settle(base, &first, 1);
        for (i, k) in others.iter().enumerate() {
            let slot = c.slot(*k);
            assert!(!Arc::ptr_eq(&slot, &first), "{k:?} shares the base key's slot");
            assert!(slot.get().is_none(), "{k:?} was served data before it built any");
            slot.get_or_init(|| Arc::new(i));
            c.settle(*k, &slot, 1);
        }
        assert_eq!(**c.slot(base).get().unwrap(), usize::MAX);
        for (i, k) in others.iter().enumerate() {
            assert_eq!(**c.slot(*k).get().unwrap(), i, "{k:?}");
        }
        assert_eq!(c.map.len(), others.len() + 1);
    }

    /// The whole committed preprocessed tree, as the SHA-256 of its opening at every leaf index:
    /// each opening is that row of every matrix, the row's salts and its sibling digests up to the
    /// cap, so all of them together are every leaf, every salt and every digest layer. (Plonky3
    /// keeps the tree's fields private; the openings are what a proof reads from it anyway.)
    fn tree_bytes(data: &ProverData<Config>) -> Vec<u8> {
        use p3_commit::Mmcs;
        let tree = data.prover_only.preprocessed_prover_data.as_ref().expect("a preprocessed tree");
        let mmcs = val_mmcs_for_tests();
        (0..mmcs.get_max_height(tree))
            .flat_map(|i| crate::sha256::sha256(&postcard::to_allocvec(&mmcs.open_batch(i, tree)).expect("an opening serialises")))
            .collect()
    }
    fn shape_of(s: KeyShape) -> VerifierKeyShape {
        VerifierKeyShape { tier: Tier(s.0), program_log_height: s.1, input_log_height: s.2, keccak_log_height: s.3, sha256_log_height: s.4, modq_log_height: s.5, public_log_height: s.6, poseidon2_log_height: s.7 }
    }
    fn build(m: &Machine, s: KeyShape, mem_log_height: u8) -> ProverData<Config> {
        let shape = shape_of(s);
        ProverData::from_airs_and_degrees(&key_config(m.profile), &shape.chips(), &m.log_ext_degrees_for(shape, mem_log_height))
    }

    /// What makes the cache safe to have at all: the prover's preprocessed data is a function of
    /// the key and nothing else. Two builds for one key are the same bytes — the whole committed
    /// tree, leaves, salts and digests, not only its cap — so it holds nothing drawn per proof, and
    /// handing one build to many proofs is what rebuilding it for each already did.
    #[test]
    fn two_builds_of_one_key_are_the_same_bytes() {
        let m = Machine::new(FriProfile::Test);
        for shape in [(10usize, 7u8, 7u8, 0u8, 0u8, 0u8, 7u8, 12u8), (10, 7, 7, 7, 7, 0, 7, 8)] {
            let (a, b) = (build(&m, shape, Tier(shape.0).min_mem_log_height()), build(&m, shape, Tier(shape.0).min_mem_log_height()));
            assert_eq!(common_to_bytes(&a.common), common_to_bytes(&b.common));
            assert!(tree_bytes(&a) == tree_bytes(&b), "the preprocessed tree differs between two builds of {shape:?}");
        }
    }

    /// The cache builds at the tier's memory floor whatever the proof's own memory height is; the
    /// data is the same at every one of them (no preprocessed column and no packed lookup depends
    /// on the memory table's height).
    #[test]
    fn prover_data_is_the_same_at_every_memory_height() {
        let m = Machine::new(FriProfile::Test);
        let shape = (10usize, 7u8, 7u8, 0u8, 0u8, 0u8, 7u8, 8u8);
        let floor = Tier(10).min_mem_log_height();
        let at_floor = build(&m, shape, floor);
        for mem in [floor + 1, floor + 3] {
            let higher = build(&m, shape, mem);
            assert_eq!(common_to_bytes(&higher.common), common_to_bytes(&at_floor.common), "mem 2^{mem}");
            assert!(tree_bytes(&higher) == tree_bytes(&at_floor), "mem 2^{mem}");
            assert_eq!(prover_data_bytes(&higher), prover_data_bytes(&at_floor));
        }
    }

    /// Through the machine, with a budget that holds one of these shapes at a time so every lookup
    /// after the first evicts: each shape is always served the data a fresh build of *that* shape
    /// gives, and its `CommonData` is the verifier key's for that shape.
    #[test]
    fn the_machine_serves_each_shape_its_own_data_across_evictions() {
        let m = Machine::new(FriProfile::Test);
        let shapes = [(10usize, 7u8, 7u8, 0u8, 0u8, 0u8, 7u8, 12u8), (10, 7, 7, 7, 0, 0, 7, 12), (10, 7, 7, 0, 7, 0, 7, 12), (10, 8, 7, 0, 0, 0, 7, 12), (10, 7, 7, 0, 0, 0, 7, 8)];
        let fresh: Vec<_> = shapes.iter().map(|s| build(&m, *s, Tier(s.0).min_mem_log_height())).collect();
        assert!(tree_bytes(&fresh[0]) != tree_bytes(&fresh[1]) && tree_bytes(&fresh[0]) != tree_bytes(&fresh[2]) && tree_bytes(&fresh[1]) != tree_bytes(&fresh[2]), "the plain, keccak and sha256 shapes commit different trees, so serving one for another would show");
        let largest = fresh.iter().map(prover_data_bytes).max().unwrap();
        m.set_prover_key_budget(largest);
        for round in 0..3 {
            for (s, want) in shapes.iter().zip(&fresh) {
                let got = m.prover_key(shape_of(*s));
                assert!(tree_bytes(&got) == tree_bytes(want), "round {round}: {s:?} was served another tree");
                assert_eq!(common_to_bytes(&got.common), common_to_bytes(&want.common), "round {round}: {s:?}");
                assert_eq!(common_to_bytes(&got.common), common_to_bytes(&m.verifier_key_for(shape_of(*s))), "round {round}: {s:?} against the verifier key");
                assert!(m.prover_key_bytes() <= largest, "the budget holds");
            }
        }
        // A hit is a hit: the same shape twice in a row builds once.
        let before = m.prover_key_builds();
        let s = shapes[0];
        m.prover_key(shape_of(s));
        m.prover_key(shape_of(s));
        assert_eq!(m.prover_key_builds(), before + 1);
    }
}

#[cfg(test)]
mod fri_soundness_tests {
    use super::*;
    use p3_fri::FriParameters;

    /// `log_blowup` is `generic_config`'s own (`LOG_BLOWUP`). `mmcs: ()` is valid
    /// because `conjectured_soundness_bits` has no bound on `M`.
    #[test]
    fn production_profile_meets_the_100_bit_conjectured_target() {
        let fri: FriParameters<()> = FriParameters {
            log_blowup: LOG_BLOWUP,
            log_final_poly_len: 0,
            max_log_arity: 3,
            num_queries: FriProfile::Production.num_queries(),
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: FriProfile::Production.pow_bits(),
            mmcs: (),
        };
        // Constraint set 11 (ZKVM-111): rate 1/4 — 92 queries / blowup 4 / 24 grinding bits,
        // conjectured `2·92+24 = 208` here. The proven figure (the reason for 92 queries rather than
        // the conjectured-only minimum, audit ZM1) is `tests/security.rs`'s, over this machine's
        // chip shapes. Through set 10: 80 / 8 / 20.
        assert_eq!(FriProfile::Production.num_queries(), 92);
        assert_eq!(FriProfile::Production.pow_bits(), 24);
        assert_eq!(LOG_BLOWUP, 2);
        assert!(fri.conjectured_soundness_bits() >= 100, "got {}", fri.conjectured_soundness_bits());
    }
}
