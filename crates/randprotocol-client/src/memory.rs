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

/// What a command is about to prove, which decides what advice a refusal can give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    /// A bundle: the RandProtocol provers can make it instead (`--prover`).
    Bundle,
    /// A call or invoke proof: always made on this computer, `--prover` moves only the bundle
    /// (its witness is the program's private inputs; wallet apps make it locally too).
    AlwaysLocal,
}

/// The decision, apart from reading the machine: `Err(message)` when `available` cannot hold one
/// proof's peak. For `AlwaysLocal` the peak is a floor (a larger call needs more, `docs/node-hardware.md`).
pub fn decide(available: u64, peak: u64, proof: Proof) -> Result<(), String> {
    if available >= peak {
        return Ok(());
    }
    Err(match proof {
        Proof::Bundle => format!(
            "proving on this machine needs {:.1} GB of available memory and only {:.1} GB is available, so it would be killed partway. \
             Have the RandProtocol provers make the proof instead: pass --prover (after `rand prover pair --trusted`, once). \
             To try anyway, pass --skip-memory-check.",
            gb(peak),
            gb(available)
        ),
        Proof::AlwaysLocal => format!(
            "this command proves on this computer (--prover cannot move it) and needs at least {:.1} GB of available memory; \
             only {:.1} GB is available, so it would be killed partway. Close other programs, or run it on a machine with more memory. \
             To try anyway, pass --skip-memory-check.",
            gb(peak),
            gb(available)
        ),
    })
}

/// Memory the OS reports available now, in bytes.
fn available_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.available_memory()
}

/// Call before a proof is made here. Cheap; the single check every local-proving path shares.
pub fn check_local(proof: Proof) -> anyhow::Result<()> {
    if SKIP.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    decide(available_bytes(), PROVER_PEAK_BYTES, proof).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enough_memory_passes_for_either_kind_of_proof() {
        for p in [Proof::Bundle, Proof::AlwaysLocal] {
            assert!(decide(PROVER_PEAK_BYTES, PROVER_PEAK_BYTES, p).is_ok());
            assert!(decide(16_000_000_000, PROVER_PEAK_BYTES, p).is_ok());
        }
    }

    #[test]
    fn a_bundle_refusal_names_both_numbers_and_the_provers() {
        let e = decide(4_200_000_000, PROVER_PEAK_BYTES, Proof::Bundle).unwrap_err();
        assert!(e.contains("6.2 GB") && e.contains("4.2 GB") && e.contains("available"), "{e}");
        assert!(e.contains("--prover") && e.contains("rand prover pair --trusted"), "{e}");
    }

    #[test]
    fn an_always_local_refusal_never_offers_the_provers() {
        let e = decide(4_200_000_000, PROVER_PEAK_BYTES, Proof::AlwaysLocal).unwrap_err();
        assert!(e.contains("at least 6.2 GB") && e.contains("4.2 GB"), "{e}");
        assert!(!e.contains("pair --trusted") && !e.contains("pass --prover"), "{e}");
        assert!(e.contains("--skip-memory-check"), "{e}");
    }

    #[test]
    fn the_peak_is_the_measured_live_figure() {
        assert_eq!(PROVER_PEAK_BYTES, 6_200_000_000);
    }
}
