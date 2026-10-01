//! What a proof runs on: how many CPU threads, and whether the CUDA backend is used.
//!
//! Every binary that proves (`rand`, `rand-prover`, `rand-node run --prover`) decides both the
//! same way, through this module, so a user who runs one of them gets the same behaviour from
//! the others:
//!
//! - **Threads.** `--threads N` wins; else `RAYON_NUM_THREADS`; else a default chosen by the
//!   binary's role ([`default_threads`]). The measured curve behind the default (a production
//!   tier-14 bundle proof on an Apple M4 Max, 2026-10-01, `docs/node-hardware.md` §6):
//!   1 thread 107.5 s, 4 threads 30.7 s (87 % parallel efficiency), 8 threads 17.1 s (78 %),
//!   16 threads 13.9 s (about 48 %). A wallet proves one bundle and its user waits, so it takes
//!   every core; a prover service shares its host (the pool's members run beside a validator)
//!   and runs jobs back to back, so it leaves one core free and stops where the marginal thread
//!   is worth less than half of itself — [`SERVICE_THREAD_CAP`] — and takes more parallel jobs
//!   instead.
//! - **Backend.** `--cuda` is the GPU and nothing else (no CPU fallback: a proof is never quietly
//!   made somewhere other than where it was asked for), `--cpu` is the CPU, and with neither a
//!   build that has the CUDA backend uses it when a GPU is visible ([`gpu_visible`]) and says so;
//!   a build without it says, once, that a GPU is going unused. The GPU backend covers the Merkle
//!   hashing and the FFTs, 87.4 % of a bundle proof's CPU time.
use std::path::Path;

/// Who is proving: decides the thread default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// `rand`: one proof at a time, a person waiting for it.
    Wallet,
    /// `rand-prover run` / `rand-node run --prover`: jobs back to back, on a shared host.
    Service,
}

/// The most threads a service takes by default: the eighth thread still returns 78 % of
/// itself, the sixteenth about 48 % (module doc). A host with more cores serves more jobs at
/// once (`--max-parallel`) rather than one job on more threads.
pub const SERVICE_THREAD_CAP: usize = 8;

/// The role's default for a machine with `available` logical CPUs (never 0).
pub fn default_threads(available: usize, role: Role) -> usize {
    let available = available.max(1);
    match role {
        Role::Wallet => available,
        Role::Service => available.saturating_sub(1).clamp(1, SERVICE_THREAD_CAP),
    }
}

/// The thread count a binary runs with: `flag` (`--threads`) first, then `env`
/// (`RAYON_NUM_THREADS`), then [`default_threads`]. Zero, or an env value that is not a count,
/// is refused with the reason — never silently turned into a default.
pub fn threads_for(flag: Option<usize>, env: Option<&str>, available: usize, role: Role) -> Result<usize, String> {
    if let Some(n) = flag {
        return if n == 0 { Err("--threads 0: a proof needs at least one thread".into()) } else { Ok(n) };
    }
    if let Some(v) = env {
        let v = v.trim();
        return match v.parse::<usize>() {
            Ok(0) => Err("RAYON_NUM_THREADS=0: a proof needs at least one thread".into()),
            Ok(n) => Ok(n),
            Err(_) => Err(format!("RAYON_NUM_THREADS={v:?} is not a thread count")),
        };
    }
    Ok(default_threads(available, role))
}

/// This machine's logical CPU count (1 when it cannot be read).
pub fn available_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Builds the process-wide rayon pool with `n` threads, before the first proof. Under the
/// `parallel` feature only; without it the prover is single-threaded and `n` is ignored. An
/// `Err` means the pool was already built (some code proved, or asked for the pool, first): the
/// caller reports it and goes on with the pool that exists.
pub fn install_thread_pool(n: usize) -> Result<(), String> {
    #[cfg(feature = "parallel")]
    {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n.max(1))
            .thread_name(|i| format!("rand-prove-{i}"))
            .build_global()
            .map_err(|e| format!("thread pool: {e}"))
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = n;
        Ok(())
    }
}

/// Where a proof is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Cpu,
    Cuda,
}

/// Whether this build carries the CUDA backend (`cuda`, or the host mock under `mock-cuda`).
pub const BUILD_HAS_CUDA: bool = cfg!(any(feature = "cuda", feature = "mock-cuda"));

/// `--cuda` / `--cpu` against what the build and the machine have. The second value is a note
/// for the user (stderr or the log) when the decision was made for them.
pub fn choose_backend(cuda: bool, cpu: bool, build_has_cuda: bool, gpu_visible: bool) -> Result<(Choice, Option<String>), String> {
    match (cuda, cpu) {
        (true, true) => Err("--cuda and --cpu: a proof is made on one of them".into()),
        (true, false) if build_has_cuda => Ok((Choice::Cuda, None)),
        (true, false) => Err("built without CUDA support; rebuild with --features cuda".into()),
        (false, true) => Ok((Choice::Cpu, None)),
        (false, false) => Ok(match (build_has_cuda, gpu_visible) {
            (true, true) => (Choice::Cuda, Some("a GPU is visible: proving on the CUDA backend (--cpu proves on the CPU instead)".into())),
            (false, true) => (Choice::Cpu, Some("a GPU is visible but this build has no CUDA support (rebuild with --features cuda to prove on it)".into())),
            _ => (Choice::Cpu, None),
        }),
    }
}

/// Whether an NVIDIA GPU is visible to this process: the driver's device nodes or its `/proc`
/// entry on Linux, or `nvidia-smi` on the `PATH`. A cheap presence check, not a probe — an
/// explicit `--cuda` still fails loudly on a device that will not open.
pub fn gpu_visible() -> bool {
    gpu_visible_at(Path::new("/"), std::env::var_os("PATH").as_deref())
}

/// [`gpu_visible`] against a root and a `PATH` (for tests).
pub fn gpu_visible_at(root: &Path, path: Option<&std::ffi::OsStr>) -> bool {
    for rel in ["dev/nvidia0", "dev/nvidiactl", "proc/driver/nvidia/version"] {
        if root.join(rel).exists() {
            return true;
        }
    }
    path.map(|p| std::env::split_paths(p).any(|dir| dir.join("nvidia-smi").is_file())).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wallet_takes_every_core_and_a_service_leaves_one_up_to_the_cap() {
        assert_eq!(default_threads(16, Role::Wallet), 16);
        assert_eq!(default_threads(1, Role::Wallet), 1);
        assert_eq!(default_threads(0, Role::Wallet), 1);
        assert_eq!(default_threads(8, Role::Service), 7, "the pool's c-8 members: cores minus one");
        assert_eq!(default_threads(16, Role::Service), SERVICE_THREAD_CAP);
        assert_eq!(default_threads(2, Role::Service), 1);
        assert_eq!(default_threads(1, Role::Service), 1);
        assert_eq!(default_threads(0, Role::Service), 1);
    }

    #[test]
    fn the_flag_beats_the_env_which_beats_the_default() {
        assert_eq!(threads_for(Some(3), Some("12"), 16, Role::Wallet), Ok(3));
        assert_eq!(threads_for(None, Some("12"), 16, Role::Wallet), Ok(12));
        assert_eq!(threads_for(None, Some(" 5 "), 16, Role::Service), Ok(5));
        assert_eq!(threads_for(None, None, 16, Role::Service), Ok(8));
        assert_eq!(threads_for(None, None, 16, Role::Wallet), Ok(16));
    }

    #[test]
    fn zero_and_junk_are_refused_not_defaulted() {
        assert!(threads_for(Some(0), None, 8, Role::Wallet).unwrap_err().contains("--threads 0"));
        assert!(threads_for(None, Some("0"), 8, Role::Wallet).unwrap_err().contains("RAYON_NUM_THREADS=0"));
        assert!(threads_for(None, Some("many"), 8, Role::Wallet).unwrap_err().contains("not a thread count"));
    }

    #[test]
    fn explicit_flags_decide_and_never_fall_back() {
        assert_eq!(choose_backend(true, false, true, false), Ok((Choice::Cuda, None)), "--cuda on a CUDA build proves on the GPU even when none is visible: it fails there, loudly");
        assert!(choose_backend(true, false, false, true).unwrap_err().contains("--features cuda"));
        assert_eq!(choose_backend(false, true, true, true), Ok((Choice::Cpu, None)), "--cpu on a GPU box stays on the CPU, silently");
        assert!(choose_backend(true, true, true, true).unwrap_err().contains("--cuda and --cpu"));
    }

    #[test]
    fn with_no_flag_a_cuda_build_takes_a_visible_gpu_and_says_so() {
        let (c, note) = choose_backend(false, false, true, true).unwrap();
        assert_eq!(c, Choice::Cuda);
        assert!(note.unwrap().contains("--cpu"));
        assert_eq!(choose_backend(false, false, true, false), Ok((Choice::Cpu, None)), "a CUDA build with no GPU visible proves on the CPU without comment");
    }

    #[test]
    fn with_no_flag_a_cpu_build_names_the_unused_gpu_once() {
        let (c, note) = choose_backend(false, false, false, true).unwrap();
        assert_eq!(c, Choice::Cpu);
        assert!(note.unwrap().contains("rebuild with --features cuda"));
        assert_eq!(choose_backend(false, false, false, false), Ok((Choice::Cpu, None)));
    }

    #[test]
    fn a_gpu_is_visible_by_a_device_node_or_nvidia_smi_on_the_path() {
        let root = tempfile::tempdir().unwrap();
        assert!(!gpu_visible_at(root.path(), None));
        let bin = tempfile::tempdir().unwrap();
        assert!(!gpu_visible_at(root.path(), Some(bin.path().as_os_str())));
        std::fs::write(bin.path().join("nvidia-smi"), b"").unwrap();
        assert!(gpu_visible_at(root.path(), Some(bin.path().as_os_str())));
        std::fs::create_dir_all(root.path().join("dev")).unwrap();
        std::fs::write(root.path().join("dev/nvidia0"), b"").unwrap();
        assert!(gpu_visible_at(root.path(), None));
    }

    #[test]
    fn the_build_flag_mirrors_the_features() {
        assert_eq!(BUILD_HAS_CUDA, cfg!(any(feature = "cuda", feature = "mock-cuda")));
    }
}
