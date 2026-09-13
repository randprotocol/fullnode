//! One bundle proof at a time, across every test binary in the workspace.
//!
//! A bundle test reads an anchor, spends one to four minutes proving against it, and has to be
//! committed while that anchor and its own `time` word are still inside `ANCHOR_WINDOW` /
//! `TIME_WINDOW` — 256 *blocks*. What kept that true until now was block spacing alone
//! (this chain's three-second blocks, and `PROVING` in `shrugg-node`'s `cluster.rs`): blocks slow
//! enough that even a proof competing with six others for the same cores finished inside the
//! window. That is a margin, not a bound — it holds only as long as nobody adds another proving
//! test and nobody runs on fewer cores.
//!
//! This is the bound. [`proving_slot`] hands out one permit at a time, so a proof is the only
//! proof running: the ~100 s a tier-14 bundle takes alone, not the ~255 s measured with seven at
//! once. The permit is a file lock on one path under `CARGO_TARGET_TMPDIR` — cargo's own scratch
//! directory for integration tests, `<target-dir>/tmp`, which is one directory for the whole
//! workspace — rather than a `static Mutex`, for two reasons:
//!
//! - cargo runs the tests *within* one binary in parallel, which a mutex would bound, but it is
//!   normal in this repo for two sessions to run `cargo test` in the same checkout at once
//!   (AGENTS.md, "Repo workflow traps"), which a mutex would not bound at all;
//! - the kernel releases a file lock when the process holding it exits, so a test run that is
//!   killed mid-proof frees the slot instead of wedging every later run.
//!
//! Two rules for callers. **Take the slot before reading the anchor** — i.e. around the whole
//! `wallet::send`/`submit`/`submit_burn` call, not around some inner part of it — so that the
//! queueing happens before the window starts rather than inside it. And **never nest it**: a
//! second acquisition on the same thread waits for the first, which will not be released. The one
//! test here proves a sequence of bundles and takes the slot once per proof — the call's program
//! proof and the bundle that pays for it sharing a single hold, since they are one stretch of
//! prover work — so that nothing else in the workspace is proving beside it.
//!
//! This file has a twin at `crates/shrugg-node/tests/proving_slot/mod.rs`, because both test
//! binaries need it and they belong to different crates. The only thing the two copies have to
//! agree on is [`lock_path`].

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The lock file every test binary opens. `CARGO_TARGET_TMPDIR` is set by cargo whenever it
/// builds an integration test and names `<target-dir>/tmp`, which is one directory for every
/// crate in the workspace — so this module's two copies name a single file, and the slot spans
/// test binaries and concurrent `cargo test` runs.
fn lock_path() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("shrugg-proving-slot.lock")
}

/// The slot, held for as long as one proof is being produced. Dropping it — or the process
/// exiting, however it exits — hands the slot to whoever is waiting.
#[must_use = "the slot is held for as long as this guard lives, so it has to be bound to a name"]
pub struct ProvingSlot(std::fs::File);

impl Drop for ProvingSlot {
    fn drop(&mut self) {
        // Closing the file releases the lock on its own; unlocking here says so out loud.
        let _ = self.0.unlock();
    }
}

/// Wait for the proving slot and take it.
///
/// The wait is a blocking `flock` on a blocking thread, so the test's own cluster keeps making
/// blocks and answering RPC while it queues — which is exactly why the slot has to be taken
/// before the anchor is read.
pub async fn proving_slot() -> ProvingSlot {
    let started = Instant::now();
    let file = tokio::task::spawn_blocking(|| {
        let path = lock_path();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("opening the proving slot at {}: {e}", path.display()));
        file.lock().expect("taking the proving slot");
        file
    })
    .await
    .expect("the thread waiting for the proving slot did not panic");
    let waited = started.elapsed();
    // Only worth a line when something was actually in front: a suite that reports no waits ran
    // its proofs one at a time anyway.
    if waited > Duration::from_secs(1) {
        eprintln!("waited {waited:.1?} for the proving slot ({})", lock_path().display());
    }
    ProvingSlot(file)
}

/// The claim the module comment makes about `CARGO_TARGET_TMPDIR`, as an assertion: the path is
/// inside the target directory's shared `tmp`, not somewhere private to this crate. Printed as
/// well, so the two copies' paths can be compared by eye in a suite log.
#[test]
fn the_slot_is_one_path_for_the_whole_workspace() {
    let path = lock_path();
    eprintln!("proving slot: {}", path.display());
    assert!(path.ends_with("tmp/shrugg-proving-slot.lock"), "{}", path.display());
    assert!(path.parent().expect("the lock file has a parent").is_dir(), "cargo creates {}", path.display());
}
