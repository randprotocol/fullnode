//! The alternative proving backends' Plonky3 configurations (M5.4 Task 1) —
//! `research/src/machine.rs`'s `reference_cfg`/`cuda_cfg` modules, mirrored on the rVM's own
//! [`super::generic_config`]. Every backend config is structurally identical to the CPU
//! `Config` — same Poseidon2 permutation, same salt stream, same FRI parameters — so its
//! proofs decode as CPU proofs (see [`super::Machine::prove_on`]).
//!
//! The seed is `research`'s `poseidon2_constants::PERM_SEED` ("RandZK"): the engines key their
//! permutation on it (`rand_zkvm_cuda::constants::permutation`), which for this seed reads the
//! same committed round-constant table `randprotocol_zkvm::machine::permutation()` is built from — any
//! other seed would diverge the wire encodings. The equivalence suite (`tests/backend.rs`) is
//! what proves they match.

use super::*;

/// `research`'s `poseidon2_constants::PERM_SEED` ("RandZK") — see the module comment.
pub const PERM_SEED: u64 = randprotocol_zkvm::poseidon2_constants::PERM_SEED;

/// The reference (CPU-twin) backend: `rand-zkvm-cuda`'s own Merkle tree and NTT, running on
/// the host.
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

#[cfg(feature = "reference-backend")]
pub use reference_cfg::config as reference_config;
#[cfg(any(feature = "cuda", feature = "mock-cuda"))]
pub use cuda_cfg::config as cuda_config;
