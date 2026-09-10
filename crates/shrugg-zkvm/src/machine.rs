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
const PERM_SEED: u64 = 0x5261_6e64_5a4b; // "RandZK"

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FriProfile {
    /// 16 queries, 4 PoW bits — for `cargo test`.
    Test,
    /// 80 queries, 20 PoW bits, blowup 8 — the whitepaper table.
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
        max_log_arity: 1,
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
use crate::tables::byte::{byte_trace, ByteAir, ByteCounts};
use crate::tables::cpu::{cpu_trace, public_values, CpuAir};
use crate::tables::memory::{memory_trace, MemoryAir};
use crate::tables::program::{program_trace, ProgramAir};
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, CommonData, ProverData, StarkInstance};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::StarkGenericConfig;
use serde::{Deserialize, Serialize};

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
}

#[derive(Clone)]
pub enum Chip { Program(ProgramAir), Cpu(CpuAir), Memory(MemoryAir), Alu(AluAir), Byte(ByteAir) }

impl BaseAir<Val> for Chip {
    fn width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::width(a), Chip::Cpu(a) => BaseAir::<Val>::width(a), Chip::Memory(a) => BaseAir::<Val>::width(a), Chip::Alu(a) => BaseAir::<Val>::width(a), Chip::Byte(a) => BaseAir::<Val>::width(a) }
    }
    fn preprocessed_width(&self) -> usize {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_width(a), Chip::Byte(a) => BaseAir::<Val>::preprocessed_width(a), _ => 0 }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self { Chip::Program(a) => BaseAir::<Val>::preprocessed_trace(a), Chip::Byte(a) => BaseAir::<Val>::preprocessed_trace(a), _ => None }
    }
    fn num_public_values(&self) -> usize { match self { Chip::Cpu(a) => BaseAir::<Val>::num_public_values(a), _ => 0 } }
}

impl<AB> Air<AB> for Chip
where
    AB: AirBuilder<F = Val> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        match self { Chip::Program(a) => a.eval(b), Chip::Cpu(a) => a.eval(b), Chip::Memory(a) => a.eval(b), Chip::Alu(a) => a.eval(b), Chip::Byte(a) => a.eval(b) }
    }
}

pub fn chips(program: &Program) -> Vec<Chip> {
    vec![Chip::Program(ProgramAir { program: program.clone() }), Chip::Cpu(CpuAir), Chip::Memory(MemoryAir), Chip::Alu(AluAir), Chip::Byte(ByteAir)]
}

pub struct Traces {
    pub program: RowMajorMatrix<Val>, pub cpu: RowMajorMatrix<Val>, pub memory: RowMajorMatrix<Val>,
    pub alu: RowMajorMatrix<Val>, pub byte: RowMajorMatrix<Val>, pub public_values: Vec<Val>,
}
impl Traces {
    pub fn as_slice(&self) -> [&RowMajorMatrix<Val>; 5] { [&self.program, &self.cpu, &self.memory, &self.alu, &self.byte] }
    pub fn heights(&self) -> [usize; 5] { self.as_slice().map(|m| m.height()) }
}

#[derive(Debug)]
pub enum ProveError { Exec(ExecError), NoTier(usize), TooManyCycles { cycles: usize, tier: Tier }, Backend(String) }
#[derive(Debug)]
pub enum VerifyError { PublicValues, Tier, Batch(String) }

pub fn build_traces(program: &Program, exec: &Execution, tier: Tier) -> Result<Traces, ProveError> {
    let cycles = exec.cycles();
    if cycles > tier.max_cycles() { return Err(ProveError::TooManyCycles { cycles, tier }); }
    let mut counts = ByteCounts::default();
    let cpu = cpu_trace(&exec.events, tier.cpu_height(), &mut counts);
    let memory = memory_trace(&exec.events, tier.mem_height(), &mut counts);
    let alu = alu_trace(&exec.events, tier.alu_height(), &mut counts);
    let byte = byte_trace(&counts);
    let program_t = program_trace(program, &exec.events);
    Ok(Traces { program: program_t, cpu, memory, alu, byte, public_values: public_values(program.base_pc, tier.0, &exec.outputs) })
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof { pub tier: Tier, pub public_values: Vec<u64>, pub batch: BatchProof<Config> }
impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("proof serialises") }
    pub fn size(&self) -> usize { self.to_bytes().len() }
}

/// Deterministic 64-bit digest of a program: an FNV-1a-style fold over `base_pc` and every
/// word. Used only to seed `key_config`'s RNGs, never for anything cryptographic in its own
/// right — it just needs to be a pure function of the program.
fn program_digest(program: &Program) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (program.base_pc as u64);
    // Length first, so the fold cannot collide two programs that differ only in how many
    // words they have. (`hc` itself is the preprocessed Merkle root, which already commits
    // to the padded height; this digest only seeds that commitment's salt, but there is no
    // reason to leave it length-extendable.)
    h ^= program.words.len() as u64;
    h = h.wrapping_mul(0x0000_0001_0000_01b3);
    for &w in &program.words {
        h ^= w as u64;
        h = h.wrapping_mul(0x0000_0001_0000_01b3);
    }
    h
}

/// A `Config` whose value-MMCS salts and PCS random codewords are both seeded deterministically
/// from `program` (and nothing else) instead of OS entropy, so that the resulting preprocessed
/// commitment (`Machine::verifier_key`/`code_hash`) is a pure function of the program: any
/// verifier can recompute it standalone, without having witnessed the proving session.
///
/// A salt that is a function of the message is *binding but not hiding*: it is brute-forceable
/// over any guessable program space, and two deployments of the same program produce the same
/// `hc` and are therefore linkable. That is acceptable here only because milestone 1 is not
/// trying to hide the program at all — `verify` takes the whole `Program` in the clear, so the
/// verifier already holds every word (`docs/03-privacy.md`). It is *not* a claim that a
/// program-derived salt costs nothing in general. A hiding program commitment belongs with
/// milestone 3's in-circuit digest, where the verifier stops holding the code. Never
/// used for the actual `prove_batch` call, whose main-trace/quotient/permutation commitments
/// must keep fresh entropy (see `make_config`) or two proofs of the same run would be
/// distinguishable, breaking zero-knowledge.
fn key_config(profile: FriProfile, program: &Program) -> Config {
    let (mmcs_rng, pcs_rng) = key_rngs(program);
    build_config(profile, mmcs_rng, pcs_rng)
}

/// The deterministic `(mmcs_rng, pcs_rng)` pair behind `key_config`, factored out so every
/// backend seeds its own key config identically and therefore produces a preprocessed
/// commitment byte-identical to the one `verifier_key` recomputes on the CPU.
fn key_rngs(program: &Program) -> (StdRng, StdRng) {
    let seed = program_digest(program);
    // XOR with an arbitrary odd constant so the two RNG streams don't start identically.
    (StdRng::seed_from_u64(seed), StdRng::seed_from_u64(seed ^ 0x9E37_79B9_7F4A_7C15))
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

pub struct Machine { pub config: Config, pub profile: FriProfile }

impl Machine {
    pub fn new(profile: FriProfile) -> Self { Self { config: make_config(profile), profile } }

    fn log_ext_degrees(&self, program: &Program, tier: Tier) -> Vec<usize> {
        let zk = self.config.is_zk();
        let prog_h = ProgramAir { program: program.clone() }.height();
        [prog_h, tier.cpu_height(), tier.mem_height(), tier.alu_height(), crate::tables::byte::HEIGHT]
            .iter().map(|h| h.trailing_zeros() as usize + zk).collect()
    }

    /// Public wrapper used by the chain executor to check a proof's degree bits.
    pub fn log_ext_degrees_pub(&self, program: &Program, tier: Tier) -> Vec<usize> { self.log_ext_degrees(program, tier) }

    pub fn verifier_key(&self, program: &Program, tier: Tier) -> CommonData<Config> {
        ProverData::from_airs_and_degrees(&key_config(self.profile, program), &chips(program), &self.log_ext_degrees(program, tier)).common
    }

    /// The code hash hc: the Merkle root of the preprocessed columns (program + byte table).
    pub fn code_hash(&self, program: &Program, tier: Tier) -> String {
        let key = self.verifier_key(program, tier);
        let com = key.preprocessed.as_ref().expect("program table is preprocessed");
        postcard::to_allocvec(&com.commitment).unwrap().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn prove(&self, program: &Program, inputs: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        let exec = execute(program, inputs, 1 << 20).map_err(ProveError::Exec)?;
        let tier = match tier { Some(t) => t, None => Tier::for_cycles(exec.cycles()).ok_or(ProveError::NoTier(exec.cycles()))? };
        let traces = build_traces(program, &exec, tier)?;
        Ok((self.prove_traces(program, &traces, tier), exec))
    }

    /// NOTE: the body below is duplicated, deliberately, by `prove_on` (the generic-over-config
    /// twin used by `Backend::Reference`/`Backend::Cuda`). The two must stay identical in every
    /// proof-shaping respect — instance construction, the `i == 1` public-values placement, and
    /// the `key_config`/`self.config` split between the key's prover data and `prove_batch` —
    /// or a backend proof stops matching what the CPU verifier recomputes. Change one, change
    /// the other.
    pub fn prove_traces(&self, program: &Program, traces: &Traces, tier: Tier) -> Proof {
        let airs = chips(program);
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
        let key_cfg = key_config(self.profile, program);
        let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &self.log_ext_degrees(program, tier));
        let batch = prove_batch(&self.config, &instances, &prover_data);
        Proof { tier, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }
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
                let (mmcs_rng, pcs_rng) = key_rngs(program);
                let key = reference_cfg::config(self.profile, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, tier)
            }
            #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
            Backend::Cuda => {
                let gpu = rand_zkvm_cuda::gpu::GpuProver::probe(PERM_SEED).map_err(|e| ProveError::Backend(e.to_string()))?;
                let cfg = cuda_cfg::config(self.profile, gpu.clone(), StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs(program);
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
        let exec = execute(program, inputs, 1 << 20).map_err(ProveError::Exec)?;
        let tier = match tier { Some(t) => t, None => Tier::for_cycles(exec.cycles()).ok_or(ProveError::NoTier(exec.cycles()))? };
        let traces = build_traces(program, &exec, tier)?;
        let airs = chips(program);
        let mats = traces.as_slice();
        let instances: Vec<StarkInstance<'_, SC, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == 1 { traces.public_values.clone() } else { vec![] },
        }).collect();
        // `log_ext_degrees` reads `self.config.is_zk()` — the *CPU* config — not `key_cfg`'s.
        // That is invariant, not a leak: every backend config (`reference_cfg`, `cuda_cfg`) is
        // built on `HidingFriPcs` just as `make_config` is, so `is_zk()` is `true` for all of
        // them and the degree bits agree with what `verify` recomputes.
        let prover_data = ProverData::from_airs_and_degrees(key_cfg, &airs, &self.log_ext_degrees(program, tier));
        // The engines panic (rather than return) on a device failure — `CudaHashEngine::ok`
        // and friends — so a backend fault must not take the caller's process down with it.
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_batch(cfg, &instances, &prover_data)))
            .map_err(|p| ProveError::Backend(panic_message(p)))?;
        let bytes = postcard::to_allocvec(&batch).map_err(|e| ProveError::Backend(format!("proof serialise: {e}")))?;
        let batch: BatchProof<Config> = postcard::from_bytes(&bytes).map_err(|e| ProveError::Backend(format!("proof convert: {e}")))?;
        Ok((Proof { tier, public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(), batch }, exec))
    }

    pub fn verify(&self, program: &Program, proof: &Proof) -> Result<(), VerifyError> {
        if proof.public_values.len() != crate::tables::cpu::pv::NUM { return Err(VerifyError::PublicValues); }
        // `public_values` is deserialized from untrusted bytes as raw `u64`s, and
        // `Val::from_u64` does not reduce: `out0` and `out0 + p` are the same field element
        // and both verify, but they are different `to_bytes()` and different numbers to
        // anyone reading the proof. Insist on the canonical representative so a proof has
        // exactly one encoding of its outputs.
        if proof.public_values.iter().any(|x| *x >= Val::ORDER_U64) { return Err(VerifyError::PublicValues); }
        if proof.public_values[crate::tables::cpu::pv::PC_ENTRY] != program.base_pc as u64 { return Err(VerifyError::PublicValues); }
        if proof.public_values[crate::tables::cpu::pv::TIER] != proof.tier.0 as u64 { return Err(VerifyError::Tier); }
        // `proof.tier` is deserialized from untrusted bytes: an attacker-supplied out-of-range
        // tier (anything not in TIERS) must be rejected here, before `log_ext_degrees` calls
        // `Tier::cpu_height`/`alu_height`/`mem_height`, which shift by `self.0` and panic in
        // debug builds for a large enough tier (e.g. `1usize << 99`).
        if !TIERS.contains(&proof.tier.0) { return Err(VerifyError::Tier); }
        if proof.batch.degree_bits != self.log_ext_degrees(program, proof.tier) { return Err(VerifyError::Tier); }
        let airs = chips(program);
        let pv: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..5).map(|i| if i == 1 { pv.clone() } else { vec![] }).collect();
        let common = self.verifier_key(program, proof.tier);
        verify_batch(&self.config, &airs, &proof.batch, &pvs, &common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }
}
