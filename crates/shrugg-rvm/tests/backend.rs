//! The alternative proving backends (M5.4 Task 1): a program proves on the selected backend and
//! the resulting proof verifies on the ordinary CPU verifier, byte-for-byte through `to_bytes` —
//! the fullnode's `crates/shrugg-zkvm/tests/backend.rs` discipline, mirrored on the rVM.
//!
//! Run as `cargo test --features reference-backend --test backend` (the CPU-twin engines of
//! `rand-zkvm-cuda`) or `cargo test --features mock-cuda --test backend` (the full
//! `Backend::Cuda` path driven by the mock CUDA driver). The vehicle is the cheating suite's
//! table-covering toy program at the smallest tier: the backend is a config concern, so the
//! proof's size is irrelevant to what is being pinned.
#![cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
use p3_field::PrimeCharacteristicRing;
use shrugg_rvm::isa::{F, Instr, Op, Program};
use shrugg_rvm::machine::{Backend, FriProfile, Machine, Proof};

fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}
fn ir(op: Op, rd: u8, ra: u8, rb: u8) -> Instr {
    i(op, rd, ra, rb as u64)
}

/// `tests/cheating.rs`'s honest setup, verbatim: one program touching every table — base and
/// extension arithmetic, an `INV`, a store/load round trip, a permutation, and the four
/// published words R5 requires.
fn table_covering_program() -> Program {
    Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7),          // 0
            i(Op::Faddi, 2, 0, 5),          // 1
            ir(Op::Fadd, 3, 1, 2),          // 2: r3 = 12
            i(Op::Inv, 4, 3, 0),            // 3: r4 = 12^-1
            i(Op::Faddi, 5, 0, 100),        // 4
            i(Op::Store, 2, 5, 3),          // 5: mem[103] = 5
            i(Op::Load, 6, 5, 3),           // 6: r6 = 5
            i(Op::Faddi, 7, 0, 64),         // 7: ptr
            i(Op::Store, 1, 7, 0),          // 8: mem[64] = 7
            i(Op::Store, 2, 7, 1),          // 9: mem[65] = 5
            i(Op::Poseidon2, 0, 7, 0),      // 10: permute cells 64..71
            i(Op::Load, 8, 7, 0),           // 11
            i(Op::Public, 0, 3, 0),         // 12
            i(Op::Public, 0, 6, 0),         // 13
            i(Op::Public, 0, 8, 0),         // 14
            i(Op::Public, 0, 4, 0),         // 15
            i(Op::Halt, 0, 0, 0),           // 16
        ],
        checkpoints: vec![],
    }
}

/// Either CUDA feature exercises the full `Backend::Cuda` path — `cuda` against a real device,
/// `mock-cuda` against the host mock — and otherwise this is the reference backend. Two
/// definitions rather than one with an inner `#[cfg]`, because under a CUDA feature alone
/// `Backend::Reference` is not a variant that exists (the fullnode's own comment, verbatim).
#[cfg(any(feature = "cuda", feature = "mock-cuda"))]
fn backend() -> Backend {
    // Only the mock driver needs a PTX file planted: `GpuProver::probe` just has to find one,
    // since the mock ignores its contents and runs the shared kernel bodies on the host. A
    // real `cuda` build must load the real PTX from its default path, so it is left alone.
    //
    // `set_var` writes process-global state while the other test's `probe` may be reading it
    // on another thread, so it happens exactly once, before any `probe` this helper leads to.
    static PLANT_MOCK_PTX: std::sync::Once = std::sync::Once::new();
    PLANT_MOCK_PTX.call_once(|| {
        let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k.ptx");
        std::fs::write(&p, "// mock").unwrap();
        std::env::set_var("RAND_ZKVM_PTX", &p);
    });
    Backend::Cuda
}

#[cfg(all(feature = "reference-backend", not(any(feature = "cuda", feature = "mock-cuda"))))]
fn backend() -> Backend {
    Backend::Reference
}

#[test]
fn a_table_covering_program_proves_on_the_backend_and_verifies_on_the_cpu() {
    let m = Machine::new(FriProfile::Test);
    let p = table_covering_program();
    let (proof, _exec) = m.prove_with(backend(), &p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();
    let bytes = proof.to_bytes();
    let decoded: Proof = postcard::from_bytes(&bytes).unwrap();
    m.verify(&p, &decoded).unwrap();
}

#[test]
fn backend_proof_has_the_same_shape_as_a_cpu_proof() {
    let m = Machine::new(FriProfile::Test);
    let p = table_covering_program();
    let (a, _) = m.prove_with(backend(), &p, &[], None).unwrap();
    let (b, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(a.tier, b.tier);
    assert_eq!(a.public_values, b.public_values);
    assert_eq!(a.batch.degree_bits, b.batch.degree_bits);

    // The commitment set: which optional commitments are present is fixed by the batch shape
    // (ZK on => `random`; lookups present => `permutation`), so it must match exactly.
    assert_eq!(a.batch.commitments.permutation.is_some(), b.batch.commitments.permutation.is_some());
    assert_eq!(a.batch.commitments.random.is_some(), b.batch.commitments.random.is_some());
    assert_eq!(a.batch.lookup_terminals.len(), b.batch.lookup_terminals.len());
    let present = |t: &[Option<_>]| t.iter().map(|x| x.is_some()).collect::<Vec<_>>();
    assert_eq!(present(&a.batch.lookup_terminals), present(&b.batch.lookup_terminals));

    // Every opened run's length (and every `Option`'s presence) is determined by the AIR
    // widths and the batch geometry, never by the FRI randomness, so the two proofs must nest
    // identically (the fullnode's shape test, verbatim).
    let ai = &a.batch.opened_values.instances;
    let bi = &b.batch.opened_values.instances;
    assert_eq!(ai.len(), bi.len());
    for (i, (x, y)) in ai.iter().zip(bi).enumerate() {
        assert_eq!(x.permutation_local.len(), y.permutation_local.len(), "instance {i} permutation_local");
        assert_eq!(x.permutation_next.len(), y.permutation_next.len(), "instance {i} permutation_next");
        let (xo, yo) = (&x.base_opened_values, &y.base_opened_values);
        assert_eq!(xo.trace_local.len(), yo.trace_local.len(), "instance {i} trace_local");
        assert_eq!(
            xo.trace_next.as_ref().map(Vec::len),
            yo.trace_next.as_ref().map(Vec::len),
            "instance {i} trace_next"
        );
        assert_eq!(
            xo.preprocessed_local.as_ref().map(Vec::len),
            yo.preprocessed_local.as_ref().map(Vec::len),
            "instance {i} preprocessed_local"
        );
        assert_eq!(
            xo.preprocessed_next.as_ref().map(Vec::len),
            yo.preprocessed_next.as_ref().map(Vec::len),
            "instance {i} preprocessed_next"
        );
        assert_eq!(
            xo.quotient_chunks.iter().map(Vec::len).collect::<Vec<_>>(),
            yo.quotient_chunks.iter().map(Vec::len).collect::<Vec<_>>(),
            "instance {i} quotient_chunks"
        );
        assert_eq!(
            xo.random.as_ref().map(Vec::len),
            yo.random.as_ref().map(Vec::len),
            "instance {i} random"
        );
    }

    // Only a *relative* size check is possible. An absolute byte bound cannot work: the two
    // proofs are salted by independent hiding-MMCS streams, so they have different transcripts,
    // hence different FRI query indices, hence a different number of *shared* sibling hashes
    // pruned out of the opening paths. That difference scales with the proof, not with a
    // constant.
    assert!(
        (a.size() as i64 - b.size() as i64).abs() * 4 < a.size().max(b.size()) as i64,
        "{} vs {}",
        a.size(),
        b.size()
    );
}

/// `Backend::Cpu` goes through the same `prove_with` entry point and must be exactly `prove`.
#[test]
fn cpu_backend_still_proves_and_verifies() {
    let m = Machine::new(FriProfile::Test);
    let p = table_covering_program();
    let (proof, _) = m.prove_with(Backend::Cpu, &p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();
}
