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
    /// 27 queries, 20 PoW bits, blowup 8. Chosen so the ethSTARK conjectured bound
    /// `log_blowup·num_queries + query_pow_bits ≥ 100`: 3·27+20 = 101.
    Production,
}

impl FriProfile {
    pub fn num_queries(self) -> usize {
        match self {
            Self::Test => 16,
            Self::Production => 27,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tier(pub usize);
impl Tier {
    pub fn for_cycles(cycles: usize) -> Option<Tier> { TIERS.iter().copied().map(Tier).find(|t| cycles <= t.max_cycles()) }
    pub fn cpu_height(self) -> usize { 1 << self.0 }
    pub fn alu_height(self) -> usize { 1 << (self.0 + 1) }
    pub fn mem_height(self) -> usize { 1 << (self.0 + 2) }
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
pub enum Chip { Program(ProgramAir), Cpu(CpuAir), Memory(MemoryAir), Alu(AluAir), Range(RangeAir), Nibble(NibbleAir), Poseidon2(Poseidon2Air, usize), Input(crate::tables::input::InputAir) }

impl BaseAir<Val> for Chip {
    fn width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::width(a), Chip::Cpu(a) => BaseAir::<Val>::width(a), Chip::Memory(a) => BaseAir::<Val>::width(a), Chip::Alu(a) => BaseAir::<Val>::width(a), Chip::Range(a) => BaseAir::<Val>::width(a), Chip::Nibble(a) => BaseAir::<Val>::width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::width(a), Chip::Input(a) => BaseAir::<Val>::width(a) }
    }
    fn preprocessed_width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Range(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Nibble(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Poseidon2(a, _) => BaseAir::<Val>::preprocessed_width(a), _ => 0 }
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
        match self { Chip::Program(a) => a.eval(b), Chip::Cpu(a) => a.eval(b), Chip::Memory(a) => a.eval(b), Chip::Alu(a) => a.eval(b), Chip::Range(a) => a.eval(b), Chip::Nibble(a) => a.eval(b), Chip::Poseidon2(a, _) => a.eval(b), Chip::Input(a) => a.eval(b) }
    }
}

/// `Poseidon2` is appended last: `i == 1` (`Cpu`) must stay the public-values slot that
/// `prove_traces`/`verify` hard-code, so every new chip since M2 has gone at the end rather
/// than disturbing that index. M3.4: no longer takes a `Program` — `ProgramAir` is shape-only
/// now (like `CpuAir`), so the whole chip set is a pure function of `tier`, and `verifier_key`
/// collapses to one entry per tier.
pub fn chips(tier: Tier) -> Vec<Chip> {
    vec![
        Chip::Program(ProgramAir),
        Chip::Cpu(CpuAir),
        Chip::Memory(MemoryAir),
        Chip::Alu(AluAir),
        Chip::Range(RangeAir),
        Chip::Nibble(NibbleAir),
        Chip::Poseidon2(Poseidon2Air, tier.poseidon2_height()),
        Chip::Input(crate::tables::input::InputAir),
    ]
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
}
impl Traces {
    pub fn as_slice(&self) -> [&RowMajorMatrix<Val>; 8] { [&self.program, &self.cpu, &self.memory, &self.alu, &self.range, &self.nibble, &self.poseidon2, &self.input] }
    pub fn heights(&self) -> [usize; 8] { self.as_slice().map(|m| m.height()) }
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
    let cpu = cpu_trace(program, inputs, salt, &exec.events, tier.cpu_height(), &mut range, &mut nibble);
    let memory = memory_trace(&exec.events, (program.digest_rows() + input_digest_rows) as u32, tier.mem_height(), &mut range);
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
        public_values: public_values(program.base_pc, tier.0, &exec.outputs, &hc, &hin),
        program_log_height, input_log_height,
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
/// program_log_height, input_log_height)` (M3.4 fix: the program table's height is
/// proof-declared, not tier-derived — `tables::program::program_log_height`'s doc comment —
/// so `CommonData`'s per-instance degree-bit bookkeeping depends on it too, even though the
/// program table has no preprocessed *columns* of its own any more; M4.1 adds the input
/// table's own height as a third, independent key component for the same reason). Bounded by
/// `TIERS.len() * (program::MAX_LOG_HEIGHT − program::MIN_LOG_HEIGHT + 1) *
/// (input::MAX_LOG_HEIGHT − input::MIN_LOG_HEIGHT + 1)` distinct keys in the worst case —
/// comfortably able to exceed `KEY_CACHE_CAPACITY` if a caller proves at many different
/// program/input sizes, unlike the tier-only cache this replaces, so the FIFO eviction here is
/// a real policy again, not just defense in depth.
#[derive(Default)]
struct KeyCache {
    map: HashMap<(usize, u8, u8), Arc<CommonData<Config>>>,
    order: VecDeque<(usize, u8, u8)>,
}
impl KeyCache {
    fn get(&self, key: &(usize, u8, u8)) -> Option<Arc<CommonData<Config>>> {
        self.map.get(key).cloned()
    }
    fn insert(&mut self, key: (usize, u8, u8), value: Arc<CommonData<Config>>) {
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

    fn log_ext_degrees(&self, tier: Tier, program_log_height: u8, input_log_height: u8) -> Vec<usize> {
        let zk = self.config.is_zk();
        // Order matches `chips()`: program, cpu, memory, alu, range, nibble, poseidon2, input.
        let mut v = vec![program_log_height as usize + zk];
        v.extend(
            [tier.cpu_height(), tier.mem_height(), tier.alu_height(), crate::tables::range::HEIGHT, crate::tables::nibble::HEIGHT, tier.poseidon2_height()]
                .iter().map(|h| h.trailing_zeros() as usize + zk),
        );
        v.push(input_log_height as usize + zk);
        v
    }

    /// The preprocessed commitment (range + nibble tables + Poseidon2 round constants, plus
    /// the degree-bit bookkeeping every instance needs including `program`'s and `input`'s)
    /// for `(tier, program_log_height, input_log_height)`, cached — see `KeyCache`. M3.4:
    /// program-*content*-independent, so this is the *verifier's* key — computable by anyone
    /// who knows the tier and the declared program/input heights alone, without the program or
    /// inputs themselves or the proving session. Recomputing it from scratch runs the full
    /// `ProverData::from_airs_and_degrees` preprocessing pass (in particular building the range
    /// and nibble tables' Merkle trees every time), which is the cost this cache exists to
    /// amortize across repeated `verify` calls at the same `(tier, program_log_height,
    /// input_log_height)`.
    /// Public wrapper used by the chain executor to check a proof's degree bits.
    pub fn log_ext_degrees_pub(&self, tier: Tier, program_log_height: u8, input_log_height: u8) -> Vec<usize> { self.log_ext_degrees(tier, program_log_height, input_log_height) }

    pub fn verifier_key(&self, tier: Tier, program_log_height: u8, input_log_height: u8) -> Arc<CommonData<Config>> {
        let key = (tier.0, program_log_height, input_log_height);
        if let Some(hit) = self.keys.lock().unwrap().get(&key) {
            return hit;
        }
        let common = Arc::new(ProverData::from_airs_and_degrees(&key_config(self.profile), &chips(tier), &self.log_ext_degrees(tier, program_log_height, input_log_height)).common);
        self.keys.lock().unwrap().insert(key, common.clone());
        common
    }

    /// Number of `(tier, program_log_height, input_log_height)` verifier keys currently cached.
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
            Some(t) => t,
            None => {
                let cycles = exec.cycles() + program.digest_rows() + crate::hash::input_digest_row_count(inputs.len());
                Tier::for_cycles(cycles).ok_or(ProveError::NoTier(cycles))?
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
        let airs = chips(tier);
        let mats = traces.as_slice();
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
        let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &self.log_ext_degrees(tier, traces.program_log_height, traces.input_log_height));
        let batch = prove_batch(&self.config, &instances, &prover_data);
        Proof { tier, program_log_height: traces.program_log_height, input_log_height: traces.input_log_height, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }
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
            Some(t) => t,
            None => {
                let cycles = exec.cycles() + program.digest_rows() + crate::hash::input_digest_row_count(inputs.len());
                Tier::for_cycles(cycles).ok_or(ProveError::NoTier(cycles))?
            }
        };
        let traces = build_traces_salted(program, inputs, salt, &exec, tier)?;
        let airs = chips(tier);
        let mats = traces.as_slice();
        let instances: Vec<StarkInstance<'_, SC, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        // `log_ext_degrees` reads `self.config.is_zk()` — the *CPU* config — not `key_cfg`'s.
        // That is invariant, not a leak: every backend config (`reference_cfg`, `cuda_cfg`) is
        // built on `HidingFriPcs` just as `make_config` is, so `is_zk()` is `true` for all of
        // them and the degree bits agree with what `verify` recomputes.
        let prover_data = ProverData::from_airs_and_degrees(key_cfg, &airs, &self.log_ext_degrees(tier, traces.program_log_height, traces.input_log_height));
        // The engines panic (rather than return) on a device failure — `CudaHashEngine::ok`
        // and friends — so a backend fault must not take the caller's process down with it.
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_batch(cfg, &instances, &prover_data)))
            .map_err(|p| ProveError::Backend(panic_message(p)))?;
        let bytes = postcard::to_allocvec(&batch).map_err(|e| ProveError::Backend(format!("proof serialise: {e}")))?;
        let batch: BatchProof<Config> = postcard::from_bytes(&bytes).map_err(|e| ProveError::Backend(format!("proof convert: {e}")))?;
        Ok((Proof { tier, program_log_height: traces.program_log_height, input_log_height: traces.input_log_height, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }, exec))
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
        // `proof.tier` is deserialized from untrusted bytes: an attacker-supplied out-of-range
        // tier (anything not in TIERS) must be rejected here, before `log_ext_degrees` calls
        // `Tier::cpu_height`/`alu_height`/`mem_height`, which shift by `self.0` and panic in
        // debug builds for a large enough tier (e.g. `1usize << 99`).
        if !TIERS.contains(&proof.tier.0) { return Err(VerifyError::Tier); }
        // M3.4 (fix): `proof.program_log_height` is untrusted the same way `proof.tier` is —
        // reject anything outside the sane range before it sizes a table (`1usize <<
        // log_height` inside `log_ext_degrees`/`verifier_key`) and panics on an absurd shift.
        if !(program::MIN_LOG_HEIGHT..=program::MAX_LOG_HEIGHT).contains(&proof.program_log_height) {
            return Err(VerifyError::ProgramHeight);
        }
        // M4.1: `proof.input_log_height` is untrusted the same way — reject anything outside
        // the sane range before it sizes the input table and panics on an absurd shift.
        if !(crate::tables::input::MIN_LOG_HEIGHT..=crate::tables::input::MAX_LOG_HEIGHT).contains(&proof.input_log_height) {
            return Err(VerifyError::InputHeight);
        }
        if proof.batch.degree_bits != self.log_ext_degrees(proof.tier, proof.program_log_height, proof.input_log_height) { return Err(VerifyError::Tier); }
        let airs = chips(proof.tier);
        let pv_vals: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..airs.len()).map(|i| if i == 1 { pv_vals.clone() } else { vec![] }).collect();
        let common = self.verifier_key(proof.tier, proof.program_log_height, proof.input_log_height);
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
pub fn max_constraint_degrees(tier: Tier, program_log_height: u8, input_log_height: u8) -> Vec<usize> {
    let machine = Machine::new(FriProfile::Test);
    let key_cfg = key_config(machine.profile);
    let airs = chips(tier);
    let is_zk = machine.config.is_zk();
    let ext_degrees = machine.log_ext_degrees(tier, program_log_height, input_log_height);
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
        assert_eq!(FriProfile::Production.num_queries(), 27);
        assert_eq!(FriProfile::Production.pow_bits(), 20);
        assert!(fri.conjectured_soundness_bits() >= 100, "got {}", fri.conjectured_soundness_bits());
    }
}
