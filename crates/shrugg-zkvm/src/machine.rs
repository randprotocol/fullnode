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
use rand::rngs::StdRng;
use rand::SeedableRng;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub type Perm = Poseidon2Goldilocks<8>;
type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
type Packing = <Val as Field>::Packing;
pub type ValMmcs = MerkleTreeHidingMmcs<Packing, Packing, Hash, Compress, StdRng, 2, 4, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type Dft = Radix2DitParallel<Val>;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// Fixed seed for the Poseidon2 round constants. Prover and verifier derive the
/// same permutation from it. Production swaps this for the published
/// `GOLDILOCKS_POSEIDON2_RC_8_*` constants; the circuit does not change.
///
/// `pub(crate)`, not private: `tables::poseidon2::round_constants` reproduces the exact same
/// `ExternalLayerConstants::new_from_rng`/internal-constants RNG draw that `permutation()`
/// below makes, so the M3 Poseidon2 *chip*'s round constants are byte-identical to this
/// machine's own hashing permutation — see that module's doc comment for why (`p3_poseidon2`
/// consumes its constants into opaque `external_layer`/`internal_layer` fields with no
/// accessor, so the only way to recover them is to redraw them from the same seed).
pub(crate) const PERM_SEED: u64 = 0x5261_6e64_5a4b; // "RandZK"

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FriProfile {
    /// 16 queries, 4 PoW bits — for `cargo test`. 3·16+4 = 52 conjectured bits; not a
    /// production target, only fast enough for the suite.
    Test,
    /// 80 queries, 20 PoW bits, blowup 8 — the whitepaper's parameter table (Draft 3, Part
    /// III: FRI 80/8/20). The M2.2 retune to 27 queries (`3·27+20 = 101`) hit the ethSTARK
    /// *conjectured* 100-bit target but quietly abandoned the *proven* floor the 80-query
    /// choice exists to keep: the proven proximity-gaps bound is ~86 bits at q=80, g=20 and
    /// scales ~linearly in the query count, so 27 queries leaves only ~42 proven bits (a
    /// provable 100 would need q=97 or g=34). The paper's Part III reconciliation weighed
    /// exactly this trade and kept q=80/g=20; this profile is consensus-facing (genesis-bound
    /// through the node's chain config, never proof-supplied), so it follows the paper.
    /// Reverted 2026-09-12 on the zk audit's finding ZM1.
    Production,
}

impl FriProfile {
    pub fn num_queries(self) -> usize {
        match self {
            Self::Test => 16,
            Self::Production => 80,
        }
    }
    pub fn pow_bits(self) -> usize {
        match self {
            Self::Test => 4,
            Self::Production => 20,
        }
    }
}

pub fn permutation() -> Perm {
    Perm::new_from_rng_128(&mut StdRng::seed_from_u64(PERM_SEED))
}

/// Builds a `Config` from two explicit RNGs: `mmcs_rng` seeds the value MMCS's per-commit
/// hiding salts (used for *every* commit through it, preprocessed traces included — see
/// `p3_merkle_tree::hiding_mmcs::MerkleTreeHidingMmcs::commit`), `pcs_rng` seeds the PCS's own
/// random codewords/quotient blinding. Kept private: callers pick a seeding strategy through
/// `make_config` (fresh OS entropy, for proving) or `key_config` (deterministic, for a
/// preprocessed commitment any verifier can recompute).
fn build_config(profile: FriProfile, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
    let perm = permutation();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm);
    let val_mmcs = ValMmcs::new(hash, compress, 2, mmcs_rng);
    generic_config(profile, Dft::default(), val_mmcs, pcs_rng)
}

/// The FRI/PCS setup, written once over any value-MMCS and DFT. Every backend goes through
/// here, so "the reference backend uses the same FRI parameters as the CPU one" is not a
/// comment that can drift — `build_config` is literally this function with the Plonky3
/// `ValMmcs`/`Radix2DitParallel` pair, and `reference_cfg`/`cuda_cfg` call it with theirs.
fn generic_config<D, M>(
    profile: FriProfile,
    dft: D,
    val_mmcs: M,
    pcs_rng: StdRng,
) -> StarkConfig<HidingFriPcs<Val, D, M, ExtensionMmcs<Val, Challenge, M>, StdRng>, Challenge, Challenger>
where
    D: p3_dft::TwoAdicSubgroupDft<Val>,
    M: p3_commit::Mmcs<Val, MultiProof: Sync, Error: Sync> + Clone,
{
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let fri = FriParameters {
        log_blowup: 3,
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
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::merkle::cpu::CpuHashEngine>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::ntt::cpu::CpuNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, StdRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(profile: FriProfile, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
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
    pub type Mmcs = rand_zkvm_cuda::merkle::mmcs::HidingMmcs<rand_zkvm_cuda::gpu::hash::CudaHashEngine>;
    pub type Dft = rand_zkvm_cuda::dft::Dft<rand_zkvm_cuda::gpu::ntt::CudaNttEngine>;
    pub type Pcs = HidingFriPcs<Val, Dft, Mmcs, ExtensionMmcs<Val, Challenge, Mmcs>, StdRng>;
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
    pub fn config(
        profile: FriProfile,
        gpu: std::sync::Arc<rand_zkvm_cuda::gpu::GpuProver>,
        mmcs_rng: StdRng,
        pcs_rng: StdRng,
    ) -> Config {
        let engine = std::sync::Arc::new(rand_zkvm_cuda::gpu::hash::CudaHashEngine { gpu: gpu.clone() });
        let mmcs = Mmcs::new(engine, PERM_SEED, 2, mmcs_rng);
        // The tuple-struct constructor, not the alias: `Dft` here is a `type`, and a type
        // alias cannot be called.
        let dft = rand_zkvm_cuda::dft::Dft(std::sync::Arc::new(rand_zkvm_cuda::gpu::ntt::CudaNttEngine { gpu }));
        super::generic_config(profile, dft, mmcs, pcs_rng)
    }
}

pub fn make_config(profile: FriProfile) -> Config {
    // Fresh entropy per proof, taken from the OS: this is the config actually used to prove,
    // so main-trace and quotient commitments stay hiding.
    build_config(profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()))
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
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, CommonData, ProverData, StarkInstance};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::StarkGenericConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

pub const TIERS: [usize; 6] = [10, 12, 14, 16, 18, 20];

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
pub enum Chip { Program(ProgramAir), Cpu(CpuAir), Memory(MemoryAir), Alu(AluAir), Range(RangeAir), Nibble(NibbleAir), Poseidon2(Poseidon2Air, usize), Input(crate::tables::input::InputAir), Keccak(KeccakAir, usize) }

impl BaseAir<Val> for Chip {
    fn width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::width(a), Chip::Cpu(a) => BaseAir::<Val>::width(a), Chip::Memory(a) => BaseAir::<Val>::width(a), Chip::Alu(a) => BaseAir::<Val>::width(a), Chip::Range(a) => BaseAir::<Val>::width(a), Chip::Nibble(a) => BaseAir::<Val>::width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::width(a), Chip::Input(a) => BaseAir::<Val>::width(a), Chip::Keccak(a, _) => BaseAir::<Val>::width(a) }
    }
    fn preprocessed_width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Range(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Nibble(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::preprocessed_width(a), Chip::Keccak(a, _) => BaseAir::<Val>::preprocessed_width(a), _ => 0 }
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
        match self { Chip::Program(a) => a.eval(b), Chip::Cpu(a) => a.eval(b), Chip::Memory(a) => a.eval(b), Chip::Alu(a) => a.eval(b), Chip::Range(a) => a.eval(b), Chip::Nibble(a) => a.eval(b), Chip::Poseidon2(a, _) => a.eval(b), Chip::Input(a) => a.eval(b), Chip::Keccak(a, _) => a.eval(b) }
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
pub fn chips(tier: Tier, keccak_log_height: u8) -> Vec<Chip> {
    let mut v = vec![
        Chip::Program(ProgramAir),
        Chip::Cpu(CpuAir),
        Chip::Memory(MemoryAir),
        Chip::Alu(AluAir),
        Chip::Range(RangeAir),
        Chip::Nibble(NibbleAir),
        Chip::Poseidon2(Poseidon2Air, tier.poseidon2_height()),
        Chip::Input(crate::tables::input::InputAir),
    ];
    if keccak_log_height != 0 {
        v.push(Chip::Keccak(KeccakAir, 1usize << keccak_log_height));
    }
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
    /// M4.2 (controller ruling 1): the memory table's height, as a base-2 log — proof-declared
    /// like the three above, but with a tier-derived *floor* the other three have no analogue
    /// of (`Tier::min_mem_log_height`). See `Proof::mem_log_height`.
    pub mem_log_height: u8,
}
impl Traces {
    /// The traces in `chips()` order — eight entries, or nine when this proof declares a keccak
    /// table (M4.2, Task 6: a `Vec`, not a fixed-size array, because the batch's instance count
    /// is now per-proof). The `i`-th entry pairs with the `i`-th chip, which is what keeps
    /// `i == 1`'s public-values slot correct in both shapes.
    pub fn as_slice(&self) -> Vec<&RowMajorMatrix<Val>> {
        let mut v = vec![&self.program, &self.cpu, &self.memory, &self.alu, &self.range, &self.nibble, &self.poseidon2, &self.input];
        if let Some(keccak) = &self.keccak { v.push(keccak); }
        v
    }
    pub fn heights(&self) -> Vec<usize> { self.as_slice().iter().map(|m| m.height()).collect() }
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
    /// M4.2: the keccak table's analogue — more `KECCAK` calls than the enforced ceiling
    /// `min(Tier::max_keccak_log_height(), tables::keccak::MAX_LOG_HEIGHT)` (`t + 5` capped at
    /// 20, the same bound `check_declared_heights` applies) allows. Unreachable from an `Execution`
    /// that passed the cycle check above (a permutation costs a cycle, so `n_perms ≤ 2^t`),
    /// kept for the same reason the other two are: an error rather than a panic on an absurd
    /// shift, for a direct caller who hand-builds an `Execution`.
    TooManyPermutations { perms: usize, log_height: u8 },
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
    /// Audit ZH3 (2026-09-12): an explicit `Some(tier)` outside `TIERS` — rejected before
    /// `Tier::cpu_height`/`alu_height`/`mem_height` shift by it (a shift-overflow panic in debug
    /// builds, a masked shift plus an abort-scale allocation in release). The prove-side mirror
    /// of `check_declared_heights`' own `TIERS.contains` guard on the untrusted-proof side.
    BadTier(usize),
}
#[derive(Debug)]
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
    /// M4.2 (controller ruling 1): `proof.mem_log_height` is outside `[tier.min_mem_log_height(),
    /// MAX_MEM_LOG_HEIGHT]`. The lower bound is the load-bearing half — see
    /// `Proof::mem_log_height`.
    MemoryHeight,
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
    mem_log_height: u8,
) -> Result<(), VerifyError> {
    // `tier` is deserialized from untrusted bytes: an attacker-supplied out-of-range tier
    // (anything not in TIERS) must be rejected first of all, since every check below it — and
    // `log_ext_degrees` after them — calls `Tier::cpu_height`/`alu_height`/`min_mem_log_height`,
    // which shift by `self.0` and panic in debug builds for a large enough tier (`1usize << 99`).
    if !TIERS.contains(&tier.0) { return Err(VerifyError::Tier); }
    // M3.4 (fix): `program_log_height` is untrusted the same way — reject anything outside the
    // sane range before it sizes a table (`1usize << log_height` inside
    // `log_ext_degrees`/`verifier_key`) and panics on an absurd shift.
    if !(program::MIN_LOG_HEIGHT..=program::MAX_LOG_HEIGHT).contains(&program_log_height) {
        return Err(VerifyError::ProgramHeight);
    }
    // M4.1: the input table's height, same treatment.
    if !(crate::tables::input::MIN_LOG_HEIGHT..=crate::tables::input::MAX_LOG_HEIGHT).contains(&input_log_height) {
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
        if !(crate::tables::keccak::MIN_LOG_HEIGHT..=crate::tables::keccak::MAX_LOG_HEIGHT).contains(&keccak_log_height) {
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
    // M4.2 (controller ruling 1): `mem_log_height` is untrusted the same way. The floor is the
    // tier's own `2^(t+2)` (so the declaration reveals nothing the tier did not already), the
    // ceiling the usual defensive one — see `Proof::mem_log_height` for why the verifier needs no
    // tighter bound than this.
    if !(tier.min_mem_log_height()..=MAX_MEM_LOG_HEIGHT).contains(&mem_log_height) {
        return Err(VerifyError::MemoryHeight);
    }
    Ok(())
}

/// Draws a fresh H_IN salt from OS entropy and delegates to [`build_traces_salted`] — the
/// direct-caller (non-`Machine`) mirror of `Machine::prove`/`Machine::prove_salted`'s own
/// split (review round 1, M6). Most callers (`main.rs`'s demo sections included) don't need a
/// *particular* salt, just a fresh one; use `build_traces_salted` where a fixed, reproducible
/// H_IN is specifically needed (e.g. two traces that must be compared).
pub fn build_traces(program: &Program, inputs: &[u32], exec: &Execution, tier: Tier) -> Result<Traces, ProveError> {
    use rand::RngExt;
    let salt: [u32; 4] = rand::rng().random();
    build_traces_salted(program, inputs, salt, exec, tier)
}

pub fn build_traces_salted(program: &Program, inputs: &[u32], salt: [u32; 4], exec: &Execution, tier: Tier) -> Result<Traces, ProveError> {
    // M3.4: digest rows count as cycles too — the digest prefix is part of every proof's cpu
    // table, not just `exec.events`. M4.1: so does the input-digest prefix.
    let input_digest_rows = crate::hash::input_digest_row_count(inputs.len());
    let cycles = exec.cycles() + program.digest_rows() + input_digest_rows;
    if cycles > tier.max_cycles() { return Err(ProveError::TooManyCycles { cycles, tier }); }
    // Audit fixes (2026-09-12): reject workloads the AIR can never satisfy *here*, where a clean
    // error is still possible, rather than deep inside `prove_batch`.
    //
    // ZH2: `HASH_LEFT` is a 16-bit value on every digest/indigest row (`tables::cpu`'s
    // `LEFT0..1` byte limbs) and the *first* such row carries the program's word count (resp.
    // `n_in`), so a program or input vector longer than 65535 words is unprovable at any tier.
    if program.len() > u16::MAX as usize { return Err(ProveError::ProgramTooLong { len: program.len() }); }
    if inputs.len() > u16::MAX as usize { return Err(ProveError::InputTooLong { len: inputs.len() }); }
    // ZH1: the poseidon2 table holds `2^(t-3)` permutation blocks against up to ~`2^t`
    // permutation-emitting rows under the cycle budget alone, so cycles fitting says nothing
    // about permutations fitting. Counted the same way the trace builder below counts them:
    // one per digest row, one per indigest row, one per absorb row.
    let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
    let permutations = program.digest_rows() + input_digest_rows + absorb_rows;
    if permutations * crate::tables::poseidon2::BLOCK > tier.poseidon2_height() {
        return Err(ProveError::TooManyPoseidon2Permutations { perms: permutations, tier });
    }
    // M3.4 (fix): the program table's height is proof-declared, not tier-derived — see
    // `tables::program::program_log_height`'s doc comment.
    let program_log_height = program::program_log_height(program.len());
    if program_log_height > program::MAX_LOG_HEIGHT {
        return Err(ProveError::ProgramTooLarge { len: program.len(), log_height: program_log_height });
    }
    // M4.1: the input table's height is proof-declared the same way.
    let input_log_height = crate::tables::input::input_log_height(inputs.len());
    if input_log_height > crate::tables::input::MAX_LOG_HEIGHT {
        return Err(ProveError::InputTooLarge { len: inputs.len(), log_height: input_log_height });
    }
    let mut range = RangeCounts::default();
    let mut nibble = NibbleCounts::default();
    // M4.2: one `KeccakEvent` per `KECCAK` row, in execution order — the same order the cpu
    // table's `SYS_KECCAK` rows claim them in. `clk` is the cpu table's own (digest-prefix
    // shifted) clock, because that is what both sides of the `KECCAK` bus carry and what the
    // chip's memory timestamps (`4·CLK`, `4·CLK + 1`) are built from.
    let clk_offset = (program.digest_rows() + input_digest_rows) as u32;
    let keccak_events: Vec<KeccakEvent> = exec.events.iter()
        .filter_map(|e| e.keccak_row.as_ref().map(|r| KeccakEvent { clk: clk_offset + e.clk, ptr: r.ptr, input: r.input }))
        .collect();
    let keccak_log_height = crate::tables::keccak::keccak_log_height(keccak_events.len());
    // M4.2 (controller ruling 2, tightened by the Task 5 review): two ceilings, both of which
    // `check_declared_heights` re-checks on the verifier's side — the tier's honest-shape bound
    // `klh ≤ t + 5` (`Tier::max_keccak_log_height`) and the flat defensive cap
    // `tables::keccak::MAX_LOG_HEIGHT`. The prover enforces the same `min` the verifier does, so
    // no honest proof is built that the verifier would then refuse to look at.
    if keccak_log_height > tier.max_keccak_log_height().min(crate::tables::keccak::MAX_LOG_HEIGHT) {
        return Err(ProveError::TooManyPermutations { perms: keccak_events.len(), log_height: keccak_log_height });
    }
    // M4.2 (Task 6): no permutations, no table. `keccak_log_height == 0` and `keccak == None`
    // are set here together and travel together from this point on — `chips` builds eight
    // instances from the first, `as_slice` supplies eight traces from the second.
    let keccak_t = (keccak_log_height != 0).then(|| keccak_trace(&keccak_events, 1usize << keccak_log_height));
    let cpu = cpu_trace(program, inputs, salt, &exec.events, tier.cpu_height(), &mut range, &mut nibble);
    // M4.2 (controller ruling 1): the memory table's height is declared, not derived. Count the
    // rows `memory_trace` will actually hold — one per `accesses` entry and one per
    // `keccak_accesses` entry, which is every row it pushes (read it: the two chained iterators
    // are its whole input) — and declare the smallest power of two that holds them *plus the
    // padding row the table's own `assert!` requires*, floored at the tier's `2^(t+2)`.
    let mem_accesses: usize = exec.events.iter().map(|e| e.accesses.len() + e.keccak_accesses.len()).sum();
    let mem_log_height = tier
        .min_mem_log_height()
        .max((mem_accesses + 1).next_power_of_two().trailing_zeros() as u8);
    if mem_log_height > MAX_MEM_LOG_HEIGHT {
        return Err(ProveError::TooManyMemoryAccesses { accesses: mem_accesses, log_height: mem_log_height });
    }
    let memory = memory_trace(&exec.events, clk_offset, 1usize << mem_log_height, &mut range);
    let alu = alu_trace(&exec.events, tier.alu_height(), &mut range, &mut nibble);
    let range_t = range_trace(&range);
    let nibble_t = nibble_trace(&nibble);
    let program_t = program_trace(program, &exec.events, 1usize << program_log_height);
    let read_counts = crate::tables::input::read_counts(inputs.len(), &exec.events);
    let input_t = crate::tables::input::input_trace(inputs, &read_counts, 1usize << input_log_height);
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
    let all_hash_events: Vec<Poseidon2Event> = digest_events.into_iter().chain(indigest_events).chain(hash_events).collect();
    let poseidon2_t = poseidon2_trace(&all_hash_events, tier.poseidon2_height());
    let hc = program.digest();
    let hin = crate::hash::input_digest(salt, inputs);
    Ok(Traces {
        program: program_t, cpu, memory, alu, range: range_t, nibble: nibble_t, poseidon2: poseidon2_t, input: input_t,
        keccak: keccak_t,
        public_values: public_values(program.base_pc, tier.0, &exec.outputs, &hc, &hin),
        program_log_height, input_log_height, keccak_log_height, mem_log_height,
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
    pub public_values: Vec<u64>,
    pub batch: BatchProof<Config>,
}
impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("proof serialises") }
    pub fn size(&self) -> usize { self.to_bytes().len() }
}

/// M3.4: the fixed seed behind `key_config`'s RNGs. Before M3.4 this was derived from the
/// program (`program_digest`, an FNV-1a-style fold over `base_pc` and every word) — but the
/// preprocessed columns are now the range/nibble tables and the Poseidon2 round-constant
/// table alone (`Machine::verifier_key`'s doc comment), none of which depend on any specific
/// program, so seeding from the program would only make the same `(tier)` verifier key
/// non-reproducible from one build to the next for no benefit. A single fixed constant
/// (arbitrary, like `machine::PERM_SEED`) is all a program-independent preprocessed
/// commitment needs.
const KEY_SEED: u64 = 0x4b45_595f_4d33_5f34; // "KEY_M3_4"

/// A `Config` whose value-MMCS salts and PCS random codewords are both seeded deterministically
/// from `KEY_SEED` (M3.4: no longer the program — see that constant's doc comment) instead of
/// OS entropy, so that the resulting preprocessed commitment (`Machine::verifier_key`) is a
/// pure function of the tier: any verifier can recompute it standalone, without having
/// witnessed the proving session or holding the program.
///
/// Never used for the actual `prove_batch` call, whose main-trace/quotient/permutation
/// commitments must keep fresh entropy (see `make_config`) or two proofs of the same run
/// would be distinguishable, breaking zero-knowledge.
fn key_config(profile: FriProfile) -> Config {
    let (mmcs_rng, pcs_rng) = key_rngs();
    build_config(profile, mmcs_rng, pcs_rng)
}

/// The deterministic `(mmcs_rng, pcs_rng)` pair behind `key_config`, factored out so every
/// backend seeds its own key config identically and therefore produces a preprocessed
/// commitment byte-identical to the one `verifier_key` recomputes on the CPU.
fn key_rngs() -> (StdRng, StdRng) {
    // XOR with an arbitrary odd constant so the two RNG streams don't start identically.
    (StdRng::seed_from_u64(KEY_SEED), StdRng::seed_from_u64(KEY_SEED ^ 0x9E37_79B9_7F4A_7C15))
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

/// Bound on the number of `(program digest, tier)` verifier keys `Machine::verifier_key`
/// keeps in memory at once. Past this, the oldest entry is evicted (FIFO) to make room for the
/// new one — a preprocessed commitment is cheap enough to recompute that a fancier (e.g. LRU)
/// policy is not worth the complexity here.
const KEY_CACHE_CAPACITY: usize = 64;

/// A bounded, FIFO-evicted cache of `Machine::verifier_key` results, keyed by `(tier.0,
/// program_log_height, input_log_height, keccak_log_height)` (M3.4 fix: the program table's height is
/// proof-declared, not tier-derived — `tables::program::program_log_height`'s doc comment —
/// so `CommonData`'s per-instance degree-bit bookkeeping depends on it too, even though the
/// program table has no preprocessed *columns* of its own any more; M4.1 adds the input
/// table's own height as a third, independent key component for the same reason; M4.2 adds the
/// keccak table's as a fourth; M4.2 Task 6 makes `klh = 0` — the eight-chip, keccak-table-free
/// batch — a distinct fourth-component value rather than an impossible one, and it must be,
/// since its `CommonData` has eight `lookups` entries and no keccak preprocessed columns).
/// The memory table's own declared height (M4.2, controller
/// ruling 1) is deliberately *not* a fifth component — see `Machine::verifier_key` for why the
/// `CommonData` this caches is invariant to it. Bounded by
/// `TIERS.len() * (program::MAX_LOG_HEIGHT − program::MIN_LOG_HEIGHT + 1) *
/// (input::MAX_LOG_HEIGHT − input::MIN_LOG_HEIGHT + 1) *
/// (keccak range, `min(t + 5, keccak::MAX_LOG_HEIGHT) − keccak::MIN_LOG_HEIGHT + 2` = 17 at
/// tier 20, the `+ 2` counting M4.2 Task 6's `klh = 0`, "no keccak table", as its own value)` distinct
/// keys in the worst case —
/// comfortably able to exceed `KEY_CACHE_CAPACITY` if a caller proves at many different
/// program/input sizes, unlike the tier-only cache this replaces, so the FIFO eviction here is
/// a real policy again, not just defense in depth.
#[derive(Default)]
struct KeyCache {
    map: HashMap<(usize, u8, u8, u8), Arc<CommonData<Config>>>,
    order: VecDeque<(usize, u8, u8, u8)>,
}
impl KeyCache {
    fn get(&self, key: &(usize, u8, u8, u8)) -> Option<Arc<CommonData<Config>>> {
        self.map.get(key).cloned()
    }
    fn insert(&mut self, key: (usize, u8, u8, u8), value: Arc<CommonData<Config>>) {
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= KEY_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(key);
        self.map.insert(key, value);
    }
}

pub struct Machine { pub config: Config, pub profile: FriProfile, keys: Mutex<KeyCache> }

impl Machine {
    pub fn new(profile: FriProfile) -> Self { Self { config: make_config(profile), profile, keys: Mutex::new(KeyCache::default()) } }

    fn log_ext_degrees(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, mem_log_height: u8) -> Vec<usize> {
        let zk = self.config.is_zk();
        // Order matches `chips()`: program, cpu, memory, alu, range, nibble, poseidon2, input,
        // and — only when this proof declares a keccak table — keccak.
        // M4.2 (controller ruling 1): the memory entry is the *declared*
        // `mem_log_height`, not a tier-derived one — `build_traces_salted` sizes the memory
        // trace with exactly the value it puts in `Traces`/`Proof`, so the two cannot drift,
        // and `verify` range-checks the declaration before it reaches here.
        let mut v = vec![program_log_height as usize + zk];
        v.push(tier.cpu_height().trailing_zeros() as usize + zk);
        v.push(mem_log_height as usize + zk);
        v.extend(
            [tier.alu_height(), crate::tables::range::HEIGHT, crate::tables::nibble::HEIGHT, tier.poseidon2_height()]
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
        v
    }

    /// The preprocessed commitment (range + nibble tables + Poseidon2 round constants, plus
    /// the degree-bit bookkeeping every instance needs including `program`'s and `input`'s)
    /// for `(tier, program_log_height, input_log_height, keccak_log_height)`, cached — see
    /// `KeyCache`. M4.2 (Task 6): `keccak_log_height = 0` is a perfectly ordinary key value —
    /// it selects the eight-chip batch, whose preprocessed commitment omits the keccak table's
    /// 99 periodic columns entirely, so it genuinely is a *different* key, not a missing one.
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
    /// declared `mem_log_height` as well as `verifier_key`'s four key components: the degree
    /// vector depends on it even though the verifier key does not, and `verify` compares
    /// `proof.batch.degree_bits` against exactly this call.
    pub fn log_ext_degrees_pub(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, mem_log_height: u8) -> Vec<usize> { self.log_ext_degrees(tier, program_log_height, input_log_height, keccak_log_height, mem_log_height) }

    pub fn verifier_key(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8) -> Arc<CommonData<Config>> {
        let key = (tier.0, program_log_height, input_log_height, keccak_log_height);
        if let Some(hit) = self.keys.lock().unwrap().get(&key) {
            return hit;
        }
        // Any valid `mem_log_height` gives the same `CommonData` (see above); the tier's floor is
        // the canonical one, and using it makes this function's result independent of which
        // proof happened to miss the cache first.
        let mem_log_height = tier.min_mem_log_height();
        let common = Arc::new(ProverData::from_airs_and_degrees(&key_config(self.profile), &chips(tier, keccak_log_height), &self.log_ext_degrees(tier, program_log_height, input_log_height, keccak_log_height, mem_log_height)).common);
        self.keys.lock().unwrap().insert(key, common.clone());
        common
    }

    /// Number of `(tier, program_log_height, input_log_height, keccak_log_height)` verifier keys
    /// currently cached.
    pub fn cached_keys(&self) -> usize { self.keys.lock().unwrap().map.len() }

    /// Draws a fresh per-proof salt from OS entropy and delegates to [`Self::prove_salted`] —
    /// see that method's doc comment (controller ruling: H_IN, `pv::IN0..7`, must be salted or
    /// it is a guessable commitment to the private inputs). Every ordinary caller wants this;
    /// `prove_salted` exists only for tests that need a fixed salt to check against.
    pub fn prove(&self, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        use rand::RngExt;
        let salt: [u32; 4] = rand::rng().random();
        self.prove_salted(program, inputs, salt, tier)
    }

    /// The body of `prove`, taking the H_IN salt explicitly instead of drawing it from OS
    /// entropy — what every backend variant (`prove_with`/`prove_on`) also threads through.
    /// `verify(hc, proof)` does not take the salt: it never leaves the prover except folded,
    /// non-invertibly, into `pv::IN0..7` (`hash::input_digest`'s doc comment).
    pub fn prove_salted(&self, program: &Program, inputs: &[u32], salt: [u32; 4], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        // Run up to the largest tier's cycle budget; a program that has not halted by then
        // can never be proved, so `OutOfCycles` and `TooManyCycles` agree on the limit.
        let exec = execute(program, inputs, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier {
            // Audit ZH3 (2026-09-12): an out-of-`TIERS` tier is an error here, not a
            // shift-overflow panic (debug) or a masked shift plus an abort-scale allocation
            // (release) inside `Tier::cpu_height` — the mirror of `check_declared_heights`' own
            // `TIERS.contains` guard on the untrusted-proof side.
            Some(t) if TIERS.contains(&t.0) => t,
            Some(t) => return Err(ProveError::BadTier(t.0)),
            None => {
                let cycles = exec.cycles() + program.digest_rows() + crate::hash::input_digest_row_count(inputs.len());
                // Audit ZH1 (2026-09-12): fit the Poseidon2 permutation budget too — the cycle
                // budget alone does not imply it (`2^(t-3)` blocks against up to ~`2^t`
                // permutation-emitting rows), so the old cycles-only pick could walk straight
                // into `poseidon2_trace`'s capacity assert.
                let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
                let permutations = program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + absorb_rows;
                Tier::for_workload(cycles, permutations).ok_or(ProveError::NoTier(cycles))?
            }
        };
        let traces = build_traces_salted(program, inputs, salt, &exec, tier)?;
        Ok((self.prove_traces(program, &traces, tier), exec))
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
    pub fn prove_traces(&self, _program: &Program, traces: &Traces, tier: Tier) -> Proof {
        let airs = chips(tier, traces.keccak_log_height);
        let mats = traces.as_slice();
        // M4.2 (Task 6): `keccak_log_height` picks the chip set and `keccak` supplies the
        // traces, so the two must agree — a mismatch would `zip` short and silently prove a
        // different batch than the degree bits describe.
        assert_eq!(airs.len(), mats.len(), "one trace per chip: keccak_log_height and Traces::keccak disagree");
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
        let key_cfg = key_config(self.profile);
        let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &self.log_ext_degrees(tier, traces.program_log_height, traces.input_log_height, traces.keccak_log_height, traces.mem_log_height));
        let batch = prove_batch(&self.config, &instances, &prover_data);
        Proof { tier, program_log_height: traces.program_log_height, input_log_height: traces.input_log_height, keccak_log_height: traces.keccak_log_height, mem_log_height: traces.mem_log_height, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }
    }

    /// Prove on `backend`. `Backend::Cpu` is exactly `prove`; the other backends run the same
    /// batch STARK with `rand-zkvm-cuda`'s engines and hand back a `Proof` that this
    /// `Machine`'s own `verify` accepts.
    pub fn prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        match backend {
            Backend::Cpu => self.prove(program, inputs, tier),
            #[cfg(feature = "reference-backend")]
            Backend::Reference => {
                // Fresh entropy for the proving config (hiding), deterministic for the key
                // config — the same split `make_config`/`key_config` make on the CPU.
                let cfg = reference_cfg::config(self.profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = reference_cfg::config(self.profile, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, tier)
            }
            #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
            Backend::Cuda => {
                let gpu = rand_zkvm_cuda::gpu::GpuProver::probe(PERM_SEED).map_err(|e| ProveError::Backend(e.to_string()))?;
                let cfg = cuda_cfg::config(self.profile, gpu.clone(), StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = cuda_cfg::config(self.profile, gpu, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, tier)
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
    fn prove_on<SC>(&self, cfg: &SC, key_cfg: &SC, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>
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
        let exec = execute(program, inputs, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier {
            // Audit ZH3 (2026-09-12): an out-of-`TIERS` tier is an error here, not a
            // shift-overflow panic (debug) or a masked shift plus an abort-scale allocation
            // (release) inside `Tier::cpu_height` — the mirror of `check_declared_heights`' own
            // `TIERS.contains` guard on the untrusted-proof side.
            Some(t) if TIERS.contains(&t.0) => t,
            Some(t) => return Err(ProveError::BadTier(t.0)),
            None => {
                let cycles = exec.cycles() + program.digest_rows() + crate::hash::input_digest_row_count(inputs.len());
                // Audit ZH1 (2026-09-12): fit the Poseidon2 permutation budget too — the cycle
                // budget alone does not imply it (`2^(t-3)` blocks against up to ~`2^t`
                // permutation-emitting rows), so the old cycles-only pick could walk straight
                // into `poseidon2_trace`'s capacity assert.
                let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
                let permutations = program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + absorb_rows;
                Tier::for_workload(cycles, permutations).ok_or(ProveError::NoTier(cycles))?
            }
        };
        let traces = build_traces_salted(program, inputs, salt, &exec, tier)?;
        let airs = chips(tier, traces.keccak_log_height);
        let mats = traces.as_slice();
        // M4.2 (Task 6): `keccak_log_height` picks the chip set and `keccak` supplies the
        // traces, so the two must agree — a mismatch would `zip` short and silently prove a
        // different batch than the degree bits describe.
        assert_eq!(airs.len(), mats.len(), "one trace per chip: keccak_log_height and Traces::keccak disagree");
        let instances: Vec<StarkInstance<'_, SC, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        // `log_ext_degrees` reads `self.config.is_zk()` — the *CPU* config — not `key_cfg`'s.
        // That is invariant, not a leak: every backend config (`reference_cfg`, `cuda_cfg`) is
        // built on `HidingFriPcs` just as `make_config` is, so `is_zk()` is `true` for all of
        // them and the degree bits agree with what `verify` recomputes.
        let prover_data = ProverData::from_airs_and_degrees(key_cfg, &airs, &self.log_ext_degrees(tier, traces.program_log_height, traces.input_log_height, traces.keccak_log_height, traces.mem_log_height));
        // The engines panic (rather than return) on a device failure — `CudaHashEngine::ok`
        // and friends — so a backend fault must not take the caller's process down with it.
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_batch(cfg, &instances, &prover_data)))
            .map_err(|p| ProveError::Backend(panic_message(p)))?;
        let bytes = postcard::to_allocvec(&batch).map_err(|e| ProveError::Backend(format!("proof serialise: {e}")))?;
        let batch: BatchProof<Config> = postcard::from_bytes(&bytes).map_err(|e| ProveError::Backend(format!("proof convert: {e}")))?;
        Ok((Proof { tier, program_log_height: traces.program_log_height, input_log_height: traces.input_log_height, keccak_log_height: traces.keccak_log_height, mem_log_height: traces.mem_log_height, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }, exec))
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
        // M4.2 (Task 5 review): every range check on the proof's declared shape, in one place
        // and before anything is sized from it — `check_declared_heights`' doc comment has the
        // reasoning and the order. It runs *before* `log_ext_degrees`, `verifier_key` and
        // `chips`, so a forged header (with `degree_bits` edited to match, which is what an
        // attacker would have to do to reach the equality check below) costs the verifier a
        // handful of comparisons rather than a multi-second — at an absurd declared height,
        // multi-minute — preprocessed-commitment recomputation. `tests/cheating.rs` observes
        // exactly that as `cached_keys() == 0` after a rejection.
        check_declared_heights(
            proof.tier,
            proof.program_log_height,
            proof.input_log_height,
            proof.keccak_log_height,
            proof.mem_log_height,
        )?;
        // M4.2 (Task 6): a `Vec` comparison, so this is simultaneously the check that
        // `degree_bits.len()` equals the batch's chip count — eight without a keccak table, nine
        // with one — and the check that every declared height matches. A proof that claims
        // `keccak_log_height = 0` while carrying nine instances (or vice versa) fails here,
        // before `chips` builds anything.
        if proof.batch.degree_bits != self.log_ext_degrees(proof.tier, proof.program_log_height, proof.input_log_height, proof.keccak_log_height, proof.mem_log_height) { return Err(VerifyError::Tier); }
        let airs = chips(proof.tier, proof.keccak_log_height);
        let pv_vals: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..airs.len()).map(|i| if i == 1 { pv_vals.clone() } else { vec![] }).collect();
        let common = self.verifier_key(proof.tier, proof.program_log_height, proof.input_log_height, proof.keccak_log_height);
        verify_batch(&self.config, &airs, &proof.batch, &pvs, &common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
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
pub fn max_constraint_degrees(tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, mem_log_height: u8) -> Vec<usize> {
    let machine = Machine::new(FriProfile::Test);
    let key_cfg = key_config(machine.profile);
    let airs = chips(tier, keccak_log_height);
    let is_zk = machine.config.is_zk();
    let ext_degrees = machine.log_ext_degrees(tier, program_log_height, input_log_height, keccak_log_height, mem_log_height);
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
mod fri_soundness_tests {
    use super::*;
    use p3_fri::FriParameters;

    /// `log_blowup` here mirrors the literal in `generic_config` — if that literal ever
    /// changes, this test's own `log_blowup` must change with it. `mmcs: ()` is valid
    /// because `conjectured_soundness_bits` has no bound on `M`.
    #[test]
    fn production_profile_meets_the_100_bit_conjectured_target() {
        let fri: FriParameters<()> = FriParameters {
            log_blowup: 3,
            log_final_poly_len: 0,
            max_log_arity: 3,
            num_queries: FriProfile::Production.num_queries(),
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: FriProfile::Production.pow_bits(),
            mmcs: (),
        };
        // The whitepaper table (Draft 3, Part III): 80 queries / blowup 8 / 20 grinding bits —
        // conjectured `3·80+20 = 260` here, and ~86 bits on the *proven* proximity-gaps bound at
        // these parameters (the reason the paper keeps q=80 rather than dropping to the
        // conjectured-only minimum; see `FriProfile`'s doc comment). Audit ZM1, 2026-09-12.
        assert_eq!(FriProfile::Production.num_queries(), 80);
        assert_eq!(FriProfile::Production.pow_bits(), 20);
        assert!(fri.conjectured_soundness_bits() >= 100, "got {}", fri.conjectured_soundness_bits());
    }
}
