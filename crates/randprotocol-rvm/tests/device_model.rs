//! The device-memory model (M5.4 Task 2): the rVM CUDA backend's chunking arithmetic, recorded
//! from the backend's own code and pinned — no GPU on this box, so the model is computed
//! arithmetic with its code anchors exercised through the mock driver where it has them.
//!
//! Two formulas, both verbatim from `rand-zkvm-cuda`:
//!
//! - NTT chunk sizing: `max_columns(n) = (free_bytes / 2) / (n · 8 · 4)`, clamped to ≥ 1
//!   (`src/gpu/ntt.rs:21-24` — "LDE keeps ~4 buffers of n×wc u64 alive; leave headroom").
//! - The whole-matrix upload guard: an upload of `values.len() · 8 > free_bytes` fails
//!   `CudaError::Alloc { bytes, free }` ("use a lower tier") before any copy
//!   (`src/gpu/ntt.rs:26-29`, `src/gpu/hash.rs:16-19`; the engines surface it as a panic,
//!   which `prove_on` converts to `ProveError::Backend`).
//!
//! The plan's R3 table had an arithmetic slip in the NTT column (it read ~74 columns per pass
//! at 80 GB; the formula gives 20) — measured arithmetic replaces derived, exactly the plan's
//! own discipline.

use randprotocol_rvm::machine::{Tier, TIERS};

/// `max_columns`, verbatim from `rand-zkvm-cuda/src/gpu/ntt.rs:21-24` (host mirror; the
/// mock-driver test below anchors it to the real call at the mock's one `free_bytes`).
fn max_columns(free_bytes: usize, n: usize) -> usize {
    ((free_bytes / 2) / (n * 8 * 4)).max(1)
}

/// The cpu LDE matrix's salted upload size at a tier: `2^(t+3)` rows (log_blowup 3) times
/// `66 + 4` columns (the rVM cpu width plus the hiding salts) times 8 bytes.
fn cpu_lde_upload_bytes(tier: usize) -> usize {
    (1usize << (tier + 3)) * 70 * 8
}

/// A hiding Merkle tree's digest-layer traffic per matrix: one 32-byte digest per leaf row,
/// and the internal layers sum to about another.
fn digest_layers_bytes(tier: usize) -> usize {
    2 * 32 * (1usize << (tier + 3))
}

const GIB: usize = 1 << 30;

#[test]
fn the_tier_23_rung_exists_with_its_machine_class() {
    assert!(TIERS.contains(&23), "the production N=3 aggregate rung (M5.4)");
    assert_eq!(Tier::for_cycles(5_905_862), Some(Tier(23)), "production N=3's derived rows");
    assert_eq!(Tier::for_cycles(9_000_000), None, "and the ladder ends there");
}

/// The NTT chunk table the plan's R3 sketched, recomputed from the formula: columns per pass at
/// the tier's cpu LDE height, and passes over the cpu table's 66 columns.
#[test]
fn the_ntt_chunk_table_is_the_formulas_own_arithmetic() {
    // max_columns at the cpu LDE height 2^(t+3), per card class.
    let cases: [(usize, usize, [usize; 3]); 3] = [
        // (tier, lde height, [max_columns at 24/40/80 GB])
        (21, 1 << 24, [24, 40, 80]),
        (22, 1 << 25, [12, 20, 40]),
        (23, 1 << 26, [6, 10, 20]),
    ];
    for (tier, n, want) in cases {
        for (free, want_cols) in [(24 * GIB, want[0]), (40 * GIB, want[1]), (80 * GIB, want[2])] {
            assert_eq!(
                max_columns(free, n),
                want_cols,
                "tier {tier}, {free} bytes free: {want_cols} columns per NTT pass"
            );
        }
        // Passes over the cpu table's 66 columns at 80 GB: 1, 2, and 4 — the cpu trace's NTT
        // always fits in passes, and tier 23 takes four.
        let at_80 = max_columns(80 * GIB, n);
        assert_eq!(66_usize.div_ceil(at_80), 1 << (tier - 21), "tier {tier} passes at 80 GB");
    }
}

/// The whole-matrix upload sizes the guard is compared against: the cpu LDE matrix dominates,
/// and at tier 23 it is 37.6 GB. The engine's own accounting is the two guarantees it gives
/// and no more: any single upload ≤ `free_bytes` (the guard), and an NTT working set ≤
/// `free_bytes / 2` (the divisor). Read them honestly: the guard alone refuses tier 23's cpu
/// matrix only below ~38 GB — at 40 GiB the upload *passes*, and whether the full device
/// working set (matrix + digest layers + the NTT working set, which the divisor caps at
/// `free/2`) then fits is a phase-liveness question — **T3's hardware measurement, not this
/// file's claim.** (The plan's R3 said a 40 GB card runs "tier 23 only with the stretch":
/// wrong at guard level, and the plan's NTT column read ~74 where the formula gives 20.
/// Measured arithmetic replaces derived, exactly the plan's own discipline.)
#[test]
fn the_merkle_upload_sizes_make_the_device_class() {
    assert_eq!(cpu_lde_upload_bytes(21), 9_395_240_960);
    assert_eq!(cpu_lde_upload_bytes(22), 18_790_481_920);
    assert_eq!(cpu_lde_upload_bytes(23), 37_580_963_840);
    // The digest-layer traffic beside the matrix (what the tree itself costs on device).
    assert_eq!(digest_layers_bytes(23), 4_294_967_296);
    // The guard, as arithmetic, per card class: a 24 GiB card admits tiers 21 and 22 and
    // refuses tier 23's cpu matrix; at 40 GiB every tier's cpu upload passes the guard.
    let card_24 = 24 * GIB;
    assert!(cpu_lde_upload_bytes(21) < card_24 && cpu_lde_upload_bytes(22) < card_24);
    assert!(cpu_lde_upload_bytes(23) > card_24, "tier 23's cpu upload exceeds a 24 GiB card");
    let card_40 = 40 * GIB;
    for tier in [21, 22, 23] {
        assert!(cpu_lde_upload_bytes(tier) < card_40, "tier {tier}'s cpu upload passes at 40 GiB");
    }
    // The NTT working set is `free/2` by construction: 4 buffers of `n × max_columns` u64
    // cost exactly `4 · n · max_columns(free, n) · 8 ≤ free/2` — check the inequality closes.
    for (free, n) in [(80 * GIB, 1 << 26), (40 * GIB, 1 << 24)] {
        let wc = max_columns(free, n);
        assert!(4 * n * wc * 8 <= free / 2, "the NTT working set exceeds free/2 at {free}/{n}");
        assert!(4 * n * (wc + 1) * 8 > free / 2, "and it is within one column of it");
    }
}

// ── the mock-driver anchors: the formulas above, exercised against the real engine code ──────
#[cfg(any(feature = "cuda", feature = "mock-cuda"))]
mod mock_driver {
    use super::*;
    use rand_zkvm_cuda::gpu::GpuProver;
    use rand_zkvm_cuda::ntt::NttEngine;
    use std::sync::Arc;

    fn plant_mock_ptx() {
        static PLANT: std::sync::Once = std::sync::Once::new();
        PLANT.call_once(|| {
            let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock");
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("k.ptx");
            std::fs::write(&p, "// mock").unwrap();
            std::env::set_var("RAND_ZKVM_PTX", &p);
        });
    }

    /// The mock driver reports 1 GiB free (`rand-zkvm-cuda/src/gpu/driver/mock.rs:45-46`) — the
    /// one `free_bytes` the real `CudaNttEngine::max_columns` can be called at here, and the
    /// mirror must agree with it there.
    #[test]
    fn max_columns_agrees_with_the_real_engine_at_the_mocks_free_bytes() {
        plant_mock_ptx();
        let gpu = GpuProver::probe(0x5261_6e64_5a4b).unwrap();
        assert_eq!(gpu.free_bytes, 1 << 30, "the mock driver's free_bytes, pinned");
        let engine = rand_zkvm_cuda::gpu::ntt::CudaNttEngine { gpu: gpu.clone() };
        for n in [1 << 20, 1 << 24, 1 << 26] {
            assert_eq!(
                engine.max_columns(n),
                max_columns(gpu.free_bytes, n),
                "the mirror and the real engine disagree at n = {n}"
            );
        }
    }

    /// The upload guard, exercised through the real engine: an upload past the mock's 1 GiB
    /// panics with the `Alloc` text (the engines panic on device failure; `prove_on`'s
    /// `catch_unwind` is what turns that into `ProveError::Backend`).
    #[test]
    fn the_upload_guard_fires_before_any_copy() {
        plant_mock_ptx();
        let gpu = GpuProver::probe(0x5261_6e64_5a4b).unwrap();
        let engine = rand_zkvm_cuda::gpu::hash::CudaHashEngine { gpu: gpu.clone() };
        let too_big = vec![0u64; (gpu.free_bytes / 8) + 1];
        let engine = Arc::new(engine);
        let msg = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            use rand_zkvm_cuda::merkle::HashEngine;
            let _ = engine.upload(&too_big, 70);
        }))
        .expect_err("an upload past free_bytes must fail")
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
        assert!(
            msg.contains("device allocation") && msg.contains("use a lower tier"),
            "the guard's message: {msg}"
        );
    }
}
