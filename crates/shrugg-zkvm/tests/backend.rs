//! The alternative proving backends: every guest proves on the selected backend and the
//! resulting proof verifies on the ordinary CPU verifier, byte-for-byte through `to_bytes`.
//!
//! Run as `cargo test --features reference-backend --test backend` (the CPU-twin engines of
//! `rand-zkvm-cuda`) or `cargo test --features mock-cuda --test backend` (the full
//! `Backend::Cuda` path driven by the mock CUDA driver).
#![cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
use shrugg_zkvm::emulator::execute;
use shrugg_zkvm::guests;
use shrugg_zkvm::machine::{Backend, FriProfile, Machine, Proof};

/// Either CUDA feature exercises the full `Backend::Cuda` path — `cuda` against a real device,
/// `mock-cuda` against the host mock — and otherwise this is the reference backend. Two
/// definitions rather than one with an inner `#[cfg]`, because under a CUDA feature alone
/// `Backend::Reference` is not a variant that exists.
#[cfg(any(feature = "cuda", feature = "mock-cuda"))]
fn backend() -> Backend {
    // Only the mock driver needs a PTX file planted: `GpuProver::probe` just has to find one,
    // since the mock ignores its contents and runs the shared kernel bodies on the host. A
    // real `cuda` build must load the real PTX from its default path, so it is left alone.
    //
    // `set_var` writes process-global state while the other test's `probe` may be reading it
    // on another thread, so it happens exactly once, before any `probe` this helper leads to.
    #[cfg(feature = "mock-cuda")]
    {
        static PLANT_MOCK_PTX: std::sync::Once = std::sync::Once::new();
        PLANT_MOCK_PTX.call_once(|| {
            let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock");
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("k.ptx");
            std::fs::write(&p, "// mock").unwrap();
            std::env::set_var("RAND_ZKVM_PTX", &p);
        });
    }
    Backend::Cuda
}

#[cfg(all(feature = "reference-backend", not(any(feature = "cuda", feature = "mock-cuda"))))]
fn backend() -> Backend {
    Backend::Reference
}

#[test]
fn every_guest_proves_on_the_backend_and_verifies_on_the_cpu() {
    let m = Machine::new(FriProfile::Test);
    for (name, program, inputs) in guests::all() {
        let (proof, exec) = m
            .prove_with(backend(), &program, &inputs, None)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let expected = execute(&program, &inputs, 1 << 20).unwrap();
        assert_eq!(exec.outputs, expected.outputs, "{name}");
        m.verify(&program, &proof).unwrap_or_else(|e| panic!("{name}: verify {e:?}"));
        let bytes = proof.to_bytes();
        let decoded: Proof = postcard::from_bytes(&bytes).unwrap();
        m.verify(&program, &decoded).unwrap_or_else(|e| panic!("{name}: verify decoded {e:?}"));
    }
}

#[test]
fn backend_proof_has_the_same_shape_as_a_cpu_proof() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (a, _) = m.prove_with(backend(), &p, &[], None).unwrap();
    let (b, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(a.tier, b.tier);
    assert_eq!(a.public_values, b.public_values);
    assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
    // sizes agree to within the FRI query randomness
    assert!((a.size() as i64 - b.size() as i64).abs() < 4096, "{} vs {}", a.size(), b.size());
}

/// `Backend::Cpu` goes through the same `prove_with` entry point and must be exactly `prove`.
#[test]
fn cpu_backend_still_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove_with(Backend::Cpu, &p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();
}
