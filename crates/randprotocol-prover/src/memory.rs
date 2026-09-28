//! The free-memory gate `rand-prover run` passes before it serves: every proving slot needs one
//! tier-14 bundle's peak, and a prover that swaps or is OOM-killed mid-proof serves no one.

/// One tier-14 hidden-asset bundle proof's peak resident memory (`docs/node-hardware.md`).
pub const PROVER_PEAK_BYTES: u64 = 5_740_000_000;
/// Left over for the process itself, the listener and the OS.
pub const HEADROOM_BYTES: u64 = 1 << 30;

pub fn required_bytes(max_parallel: usize) -> u64 {
    PROVER_PEAK_BYTES.saturating_mul(max_parallel as u64).saturating_add(HEADROOM_BYTES)
}

/// Memory the OS reports available now, in bytes (memory only; no process scan).
pub fn available_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.available_memory()
}

fn gb(b: u64) -> f64 { b as f64 / 1e9 }

/// `Err` names both numbers when `max_parallel` proofs would not fit in available memory.
pub fn check(max_parallel: usize) -> Result<(), String> {
    let need = required_bytes(max_parallel);
    let have = available_bytes();
    if have < need {
        return Err(format!(
            "{max_parallel} proving slot(s) need {:.1} GB of available memory ({:.2} GB each plus {:.1} GB headroom); \
             this machine has {:.1} GB available — lower --max-parallel, or pass --skip-memory-check",
            gb(need), gb(PROVER_PEAK_BYTES), gb(HEADROOM_BYTES), gb(have)
        ));
    }
    Ok(())
}
