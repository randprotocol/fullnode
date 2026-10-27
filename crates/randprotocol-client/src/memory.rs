//! The local-proving memory gate: a bundle proof made on this machine peaks at
//! [`PROVER_PEAK_BYTES`] (the prover crate's constant, the one `rand-prover run` gates on), and a
//! machine that cannot hold it is OOM-killed mid-proof with nothing to show. Refuse before any work
//! instead, and point at the RandProtocol provers.

pub use randprotocol_prover::PROVER_PEAK_BYTES;

/// Set by `--skip-memory-check` / `RAND_SKIP_MEMORY_CHECK` (the flag `rand-prover run` has too).
static SKIP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_skip(skip: bool) {
    SKIP.store(skip, std::sync::atomic::Ordering::Relaxed);
}

fn gb(b: u64) -> f64 {
    b as f64 / 1e9
}

/// The decision, apart from reading the machine: `Err(message)` when `available` cannot hold one
/// proof's peak.
pub fn decide(available: u64, peak: u64) -> Result<(), String> {
    if available >= peak {
        return Ok(());
    }
    Err(format!(
        "proving on this machine needs {:.1} GB of available memory and only {:.1} GB is free, so it would be killed partway. \
         Have the RandProtocol provers make the proof instead: pass --prover (after `rand prover pair --trusted`, once). \
         To try anyway, pass --skip-memory-check.",
        gb(peak),
        gb(available)
    ))
}

/// Memory the OS reports available now, in bytes.
fn available_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.available_memory()
}

/// Call before a proof is made here. Cheap; the single check every local-proving path shares.
pub fn check_local() -> anyhow::Result<()> {
    if SKIP.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    decide(available_bytes(), PROVER_PEAK_BYTES).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enough_memory_passes_and_too_little_names_both_numbers_and_the_way_out() {
        assert!(decide(PROVER_PEAK_BYTES, PROVER_PEAK_BYTES).is_ok());
        assert!(decide(16_000_000_000, PROVER_PEAK_BYTES).is_ok());
        let e = decide(4_200_000_000, PROVER_PEAK_BYTES).unwrap_err();
        assert!(e.contains("6.2 GB") && e.contains("4.2 GB"), "{e}");
        assert!(e.contains("--prover") && e.contains("rand prover pair --trusted"), "{e}");
    }

    #[test]
    fn the_peak_is_the_measured_live_figure() {
        assert_eq!(PROVER_PEAK_BYTES, 6_200_000_000);
    }
}
