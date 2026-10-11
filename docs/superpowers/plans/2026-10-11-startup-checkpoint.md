# Startup Checkpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a restart of the same clean build on a store it already verified opens the RPC
without walking the chain. It still checks the snapshot against the head's state root (OPS-5)
and runs one `load_ledger` instead of two.

**Architecture:**
- A `verified_head` META row, bound to the build's git SHA, records that this build verified
  the store through its head.
- `Storage::commit` carries the marker forward atomically with `head_height`, and
  `truncate_to` clears it.
- A new `node::startup_check` decides between skip and walk, writes the marker after a
  successful walk, and hands the stored ledger it loaded on to `resume_consensus_from`.

**Tech Stack:** Rust 2021, RocksDB (`WriteBatch`), bincode, serde, tokio cluster tests.

**Spec:** `docs/superpowers/specs/2026-10-11-startup-checkpoint-design.md` (commit d6aeea47).
Read it first.

**Worktree:** `~/rand-worktrees/fullnode-startup-checkpoint`, branch `feat/startup-checkpoint`.
Every command below runs from the worktree root. Other sessions are working in other
worktrees: don't touch `main` and don't push.

## Global Constraints

- The marker is honoured or written only when the build SHA is exactly 40 lowercase hex
  characters (`-dirty`, `unknown` and anything else never count).
- `marker.build_sha` must equal this binary's SHA (`env!("RAND_GIT_SHA")`, the same value as
  `rpc::GIT_SHA`).
- `Storage::commit` never creates a marker; it only rewrites one that equals the pre-commit
  head and carries this build's SHA. The write goes in the same `WriteBatch` as
  `META_HEAD_HEIGHT`.
- `snapshot_is_the_head_state` (OPS-5) runs on every start, the fast path included.
- `--verify-chain` accepts `off | quick | replay | full`. Only `quick` honours the marker.
  `replay` is `quick` with the marker ignored, and `full` is unchanged.
- `rand-node verify` keeps calling `Storage::verify_chain` directly and stays unchanged.
  Its `--mode` also gains `replay`, which behaves like `quick`.
- Under `#[cfg(test)]` a new `Storage` has no trusted build (`None`), so every existing unit
  test behaves exactly as before unless it opts in.
- No consensus-visible change: no genesis field, no wire change.
- Log lines, verbatim:
  - `chain verified: checkpoint at {h} (build {sha12}), replay skipped`
  - `startup verify ({mode:?}): {reason}`
- Clippy with `-D warnings` must pass before every commit:
  `cargo clippy -p randprotocol-node --all-targets -- -D warnings`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **An archive's non-root counters are not re-audited on the fast path.** `base_fees_burned`,
   `unsealed_fees` and perp input rows sit outside the state root, so only the walk compares
   them. Expected: the docs say so plainly (Task 5), and `--verify-chain replay` is the way to
   audit them. Pinned by the Task 4 test `replay_ignores_a_valid_checkpoint`.
2. **A crash between a successful walk and the marker write.** Expected: the next start walks
   again and nothing is wrong. Pinned by the Task 4 test
   `a_walk_without_a_marker_write_walks_again`.
3. **A marker row that doesn't decode** (truncated bytes, an older layout). Expected: treated
   as missing, warned once, overwritten after the walk. Pinned by the Task 1 test
   `an_undecodable_marker_reads_as_none`.
4. **Blocks committed by another build after this build's marker was written** (a downgrade,
   then an upgrade again). Expected: the marker is not carried by the other build, so this
   build walks on its next start. Pinned by the Task 2 test
   `commit_does_not_carry_another_builds_marker`.
5. **`--verify-chain off` with a stale marker.** Expected: `off` neither reads nor writes the
   marker, and a later `quick` start sees `head moved` and walks. Pinned by the Task 4 test
   `off_leaves_the_marker_alone_and_quick_then_walks`.

---

## File Structure

- `crates/randprotocol-node/src/storage.rs`
  - `VerifiedHead`, `trusted_build`, `this_build_checkpoint`;
  - the `Storage` fields `checkpoint_build` and `ledger_loads`;
  - `verified_head`, `mark_verified_head`, `clear`-in-`truncate_to`, carry-forward in
    `commit`;
  - `ChainCheck.stored`;
  - `VerifyMode::Replay`.
- `crates/randprotocol-node/src/node.rs`
  - `StartupVerify`, `WalkReason`, `StartupCheck`, `startup_check`;
  - `check_and_repair_chain` delegating to `startup_check`;
  - `reload_ledger_from`, `resume_consensus_from`, the `start_with` wiring and
    `NodeHandle.startup`.
- `crates/randprotocol-node/src/main.rs`: the `--verify-chain` help text.
- `crates/randprotocol-node/tests/common/cluster.rs`: `start_in_verify` helper.
- `crates/randprotocol-node/tests/cluster.rs`: the restart test.
- Docs: `docs/cli.md`, `docs/architecture.md`, `docs/node-hardware.md`, `deploy/README.md`,
  `AGENTS.md`.

---

### Task 1: The marker in storage

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs`:
  - the `META_*` constants near line 164;
  - the `Storage` struct near line 437 and its constructor near line 923;
  - `load_ledger` at line 2776;
  - `VerifyMode` at lines 3433–3456.
- Test: the `mod tests` in the same file (line ~5651).

**Interfaces:**
- Produces:
  - `pub struct VerifiedHead { pub height: u64, pub block_hash: Hash, pub state_root: Hash, pub build_sha: String }`
    (derives `Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize`).
  - `pub fn trusted_build(sha: &str) -> Option<&str>`.
  - `pub fn this_build_checkpoint() -> Option<&'static str>`, which is
    `trusted_build(env!("RAND_GIT_SHA"))`.
  - `Storage::checkpoint_build(&self) -> Option<String>`.
  - `#[doc(hidden)] pub fn set_checkpoint_build_for_testing(&self, sha: Option<&str>)`. It
    stores `sha` filtered through `trusted_build`, so an untrusted value becomes `None`.
  - `Storage::verified_head(&self) -> Result<Option<VerifiedHead>>`.
  - `Storage::mark_verified_head(&self) -> Result<bool>`. It writes the marker for the
    current head (height, hash, header `state_root`) when the build is trusted, returns
    whether it wrote, and syncs the write.
  - `#[doc(hidden)] pub fn ledger_loads(&self) -> usize`.
  - `VerifyMode::Replay`.

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in storage.rs):

```rust
    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn only_a_clean_forty_hex_sha_is_a_trusted_build() {
        assert_eq!(trusted_build(SHA_A), Some(SHA_A));
        assert_eq!(trusted_build(&format!("{SHA_A}-dirty")), None);
        assert_eq!(trusted_build("unknown"), None);
        assert_eq!(trusted_build(&SHA_A[..39]), None);
        assert_eq!(trusted_build(&SHA_A.to_uppercase()), None);
        assert_eq!(trusted_build("gggggggggggggggggggggggggggggggggggggggg"), None);
    }

    #[test]
    fn a_test_store_has_no_trusted_build_until_one_is_set() {
        let (_d, st, _gs, _) = chain_fixture(2);
        assert_eq!(st.checkpoint_build(), None);
        assert!(!st.mark_verified_head().unwrap(), "no trusted build, no marker");
        assert_eq!(st.verified_head().unwrap(), None);
        st.set_checkpoint_build_for_testing(Some("unknown"));
        assert_eq!(st.checkpoint_build(), None, "an untrusted sha stays untrusted");
    }

    #[test]
    fn mark_verified_head_records_the_head_and_the_build() {
        let (_d, st, _gs, blocks) = chain_fixture(3);
        st.set_checkpoint_build_for_testing(Some(SHA_A));
        assert!(st.mark_verified_head().unwrap());
        let head = blocks.last().unwrap().block.clone();
        assert_eq!(
            st.verified_head().unwrap(),
            Some(VerifiedHead { height: 3, block_hash: head.hash(), state_root: head.header.state_root, build_sha: SHA_A.into() })
        );
    }

    #[test]
    fn an_undecodable_marker_reads_as_none() {
        let (_d, st, _gs, _) = chain_fixture(1);
        st.db.put_cf(st.cf(CF_META), META_VERIFIED_HEAD, b"\x01\x02").unwrap();
        assert_eq!(st.verified_head().unwrap(), None);
    }

    #[test]
    fn replay_parses_and_unknown_modes_name_all_four() {
        assert_eq!("replay".parse::<VerifyMode>().unwrap(), VerifyMode::Replay);
        let err = "fast".parse::<VerifyMode>().unwrap_err();
        assert_eq!(err, "unknown verify mode fast (off|quick|replay|full)");
    }

    #[test]
    fn ledger_loads_counts_each_load() {
        let (_d, st, _gs, _) = chain_fixture(1);
        let before = st.ledger_loads();
        st.load_ledger(&StubExecutor).unwrap();
        assert_eq!(st.ledger_loads(), before + 1);
    }
```

(`SHA_B` is used by Task 2's tests; define both here.)

- [ ] **Step 2: Run them and confirm they fail to compile.**
  Run: `cargo test -p randprotocol-node --lib storage::tests::only_a_clean 2>&1 | tail -5`
  Expected: errors naming `trusted_build`, `VerifiedHead` and the rest.

- [ ] **Step 3: Implement.**

Next to the other `META_*` constants:

```rust
/// The startup checkpoint (startup-checkpoint spec §3): the head this build last verified the
/// store through, and the build. Local state, outside consensus; `commit` carries it forward,
/// `truncate_to` clears it.
const META_VERIFIED_HEAD: &str = "verified_head";
```

Beside `NoteRow`:

```rust
/// The startup checkpoint row (startup-checkpoint spec §3): `build_sha` verified this store's
/// history through `height` — a replay on an archive, the structural walk on a pruned store —
/// or committed every block above its own verification itself.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedHead {
    pub height: u64,
    pub block_hash: Hash,
    /// The head header's `state_root`, copied, not recomputed.
    pub state_root: Hash,
    pub build_sha: String,
}

/// A build may write or honour the checkpoint only under a clean commit sha: `-dirty` and
/// `unknown` do not change when the code does (spec §3.1).
pub fn trusted_build(sha: &str) -> Option<&str> {
    (sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then_some(sha)
}

/// This binary's checkpoint identity, if it has one.
pub fn this_build_checkpoint() -> Option<&'static str> {
    trusted_build(env!("RAND_GIT_SHA"))
}
```

Add `RAND_GIT_SHA` to the crate's environment in the library. It is already set by `build.rs`
through `cargo:rustc-env`, so `env!` works in `storage.rs` as it does in `rpc.rs`.

Add two fields to `Storage`, beside `tree_builds`:

```rust
    /// The build the checkpoint is written and honoured under (spec §3.1): this binary's sha
    /// when it is a clean commit, else `None`. `None` in unit tests unless a test sets one.
    checkpoint_build: std::sync::Mutex<Option<String>>,
    /// How many times `load_ledger` ran, for the tests that pin one load per startup.
    ledger_loads: std::sync::atomic::AtomicUsize,
```

Initialize them in the constructor:

```rust
            checkpoint_build: std::sync::Mutex::new(if cfg!(test) { None } else { this_build_checkpoint().map(String::from) }),
            ledger_loads: std::sync::atomic::AtomicUsize::new(0),
```

In `impl Storage` (near `tree_builds()`):

```rust
    pub fn checkpoint_build(&self) -> Option<String> {
        self.checkpoint_build.lock().unwrap().clone()
    }

    #[doc(hidden)]
    pub fn set_checkpoint_build_for_testing(&self, sha: Option<&str>) {
        *self.checkpoint_build.lock().unwrap() = sha.and_then(trusted_build).map(String::from);
    }

    #[doc(hidden)]
    pub fn ledger_loads(&self) -> usize {
        self.ledger_loads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The checkpoint row, or `None` when there is none or it does not decode (an older layout,
    /// a torn write): either way the next startup walks and rewrites it (spec §5).
    pub fn verified_head(&self) -> Result<Option<VerifiedHead>> {
        let Some(bytes) = self.get_meta_raw(META_VERIFIED_HEAD)? else { return Ok(None) };
        match bincode::deserialize::<VerifiedHead>(&bytes) {
            Ok(v) => Ok(Some(v)),
            Err(e) => {
                tracing::warn!("startup checkpoint row does not decode ({e}); treating it as absent");
                Ok(None)
            }
        }
    }

    /// Record that this build verified the store through its current head (spec §3.2.1).
    /// Nothing is written without a trusted build; returns whether the row was written.
    pub fn mark_verified_head(&self) -> Result<bool> {
        let Some(build_sha) = self.checkpoint_build() else { return Ok(false) };
        let head = self.head_block()?;
        let row = VerifiedHead { height: head.height(), block_hash: head.hash(), state_root: head.header.state_root, build_sha };
        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_META), META_VERIFIED_HEAD, bincode::serialize(&row)?);
        self.db.write_opt(batch, &sync_opts())?;
        Ok(true)
    }
```

At the top of `load_ledger`:

```rust
        self.ledger_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
```

In `VerifyMode`, add the variant between `Quick` and `Full`:

```rust
    /// `Quick`, with the startup checkpoint ignored (startup-checkpoint spec §4.1). Inside
    /// `verify_chain` it is `Quick`.
    Replay,
```

Add `"replay" => Ok(VerifyMode::Replay),` to `FromStr`, and change the error to
`"unknown verify mode {other} (off|quick|replay|full)"`.

Search `verify_chain` and `verify_pruned` for `VerifyMode::Quick` and `mode ==` comparisons.
The only Full-only branches are `mode == VerifyMode::Full` (storage.rs:3653, 3967), which
`Replay` must not enter, so they stay as they are. If any `match mode` is exhaustive, give
`Replay` the `Quick` arm.

- [ ] **Step 4: Run the tests and confirm they pass.**
  Run: `cargo test -p randprotocol-node --lib storage::tests 2>&1 | tail -5`
  Expected: PASS, including every pre-existing storage test.

- [ ] **Step 5: Run clippy and commit.**

```bash
cargo clippy -p randprotocol-node --all-targets -- -D warnings
git add crates/randprotocol-node/src/storage.rs
git commit -m "storage: the startup checkpoint row (VerifiedHead), trusted builds, VerifyMode::Replay, a load_ledger counter

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Carry the marker in `commit`, clear it in `truncate_to`

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs`:
  - `commit` at line 2863: the batch before the `META_HEAD_HEIGHT` put, near line 3247;
  - `truncate_to` at line 3989;
  - the test helper `chain_fixture_with` at line 5555.
- Test: storage.rs `mod tests`.

**Interfaces:**
- Consumes (Task 1): `VerifiedHead`, `META_VERIFIED_HEAD`, `checkpoint_build()`,
  `verified_head()`, `mark_verified_head()`, `set_checkpoint_build_for_testing`, `SHA_A`,
  `SHA_B`.
- Produces: `pub(crate) fn chain_fixture_hooked(n: u64, tweak: impl FnOnce(&mut GenesisState), on_block: impl FnMut(&Storage, u64)) -> (tempfile::TempDir, Storage, GenesisState, Vec<CommittedBlock>)`.
  `on_block(&st, h)` runs just before block `h` is committed.

- [ ] **Step 1: Refactor the fixture.** Rename the body of `chain_fixture_with` to
  `chain_fixture_hooked`, adding the `on_block` parameter and calling `on_block(&st, h);`
  immediately before `st.commit(...)` in the loop. `chain_fixture_with(n, tweak)` becomes
  `chain_fixture_hooked(n, tweak, |_, _| {})`.
  Run: `cargo test -p randprotocol-node --lib storage::tests 2>&1 | tail -3`. Expected: PASS.

- [ ] **Step 2: Write the failing tests:**

```rust
    #[test]
    fn commit_carries_this_builds_marker_to_the_new_head() {
        let (_d, st, _gs, blocks) = chain_fixture_hooked(4, |_| {}, |st, h| {
            if h == 2 {
                st.set_checkpoint_build_for_testing(Some(SHA_A));
                assert!(st.mark_verified_head().unwrap(), "marker at height 1");
            }
        });
        let head = blocks.last().unwrap().block.clone();
        assert_eq!(
            st.verified_head().unwrap(),
            Some(VerifiedHead { height: 4, block_hash: head.hash(), state_root: head.header.state_root, build_sha: SHA_A.into() })
        );
    }

    #[test]
    fn commit_does_not_create_a_marker() {
        let (_d, st, _gs, _) = chain_fixture_hooked(3, |_| {}, |st, h| {
            if h == 1 {
                st.set_checkpoint_build_for_testing(Some(SHA_A));
            }
        });
        assert_eq!(st.verified_head().unwrap(), None);
    }

    #[test]
    fn commit_does_not_carry_another_builds_marker() {
        let (_d, st, _gs, _) = chain_fixture_hooked(3, |_| {}, |st, h| {
            if h == 2 {
                st.set_checkpoint_build_for_testing(Some(SHA_A));
                st.mark_verified_head().unwrap();
                st.set_checkpoint_build_for_testing(Some(SHA_B));
            }
        });
        let m = st.verified_head().unwrap().expect("the old row stays");
        assert_eq!((m.height, m.build_sha.as_str()), (1, SHA_A), "not carried: it is another build's");
    }

    #[test]
    fn commit_does_not_carry_a_stale_marker() {
        let (_d, st, _gs, _) = chain_fixture_hooked(4, |_| {}, |st, h| {
            if h == 2 {
                st.set_checkpoint_build_for_testing(Some(SHA_A));
                st.mark_verified_head().unwrap();
                // As if another build committed block 2 without carrying it.
                st.set_checkpoint_build_for_testing(None);
            }
            if h == 3 {
                st.set_checkpoint_build_for_testing(Some(SHA_A));
            }
        });
        let m = st.verified_head().unwrap().expect("the old row stays");
        assert_eq!(m.height, 1, "head moved past it without this build, so it is never carried again");
    }

    #[test]
    fn truncate_to_clears_the_marker() {
        let (_d, st, gs, _) = chain_fixture(4);
        st.set_checkpoint_build_for_testing(Some(SHA_A));
        st.mark_verified_head().unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        st.truncate_to(&gs, 2, &c.ledger).unwrap();
        assert_eq!(st.verified_head().unwrap(), None);
    }
```

The `truncate_to` test passes the full-chain ledger only to satisfy the signature. If
`truncate_to` checks the ledger against height 2, take the ledger from a
`verify_chain` run on a store truncated by `corrupted_block_is_detected_and_truncated`'s method
instead: overwrite block 4's bytes, `verify_chain`, then `truncate_to(&gs, c.last_good, &c.ledger)`.

- [ ] **Step 3: Run them and confirm the carry/clear tests fail.**
  Run: `cargo test -p randprotocol-node --lib storage::tests::commit_carries 2>&1 | tail -5`
  Expected: FAIL. The marker is still at height 1.

- [ ] **Step 4: Implement.** In `commit`, after `let head = self.head()?;` read the marker once:

```rust
        // The startup checkpoint is carried, never created (spec §3.2.2): only a row this build
        // wrote for exactly the head this commit extends moves up with it.
        let carry = match (self.checkpoint_build(), self.verified_head()?) {
            (Some(build), Some(m)) if m.build_sha == build && m.height == head.height && m.block_hash == head.hash => Some(build),
            _ => None,
        };
```

Immediately before `batch.put_cf(self.cf(CF_META), META_HEAD_HEIGHT, height_key(last_height));`:

```rust
        if let Some(build_sha) = carry {
            let row = VerifiedHead { height: last.block.height(), block_hash: last.block.hash(), state_root: last.block.header.state_root, build_sha };
            batch.put_cf(self.cf(CF_META), META_VERIFIED_HEAD, bincode::serialize(&row)?);
        }
```

The empty-`blocks` early return writes only epoch sets and doesn't touch the marker. In
`truncate_to`, add to its batch:

```rust
        // The checkpoint described the old head (spec §3.3); the repair re-verifies and rewrites it.
        batch.delete_cf(self.cf(CF_META), META_VERIFIED_HEAD);
```

- [ ] **Step 5: Run the whole storage suite and confirm it passes.**
  Run: `cargo test -p randprotocol-node --lib storage::tests 2>&1 | tail -5`
  Expected: PASS.

- [ ] **Step 6: Run clippy and commit** (message: `storage: commit carries the startup
  checkpoint in the head's batch; truncate_to clears it`, plus the Co-Authored-By line).

---

### Task 3: `ChainCheck.stored`, the stored ledger `verify_chain` loaded

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs`:
  - `ChainCheck` at line 3460 and its construction at line 3505;
  - the archive tail at lines 3762–3901;
  - `verify_pruned` returns at lines 3976–3982;
  - the `Off` branch at line 3538.
- Test: storage.rs `mod tests`.

**Interfaces:**
- Produces: the field `pub stored: Option<Ledger>` on `ChainCheck`. It is `Some` exactly when
  the stored ledger loaded *and* `problem` is `None`.

- [ ] **Step 1: Write the failing tests:**

```rust
    #[test]
    fn verify_chain_hands_over_the_stored_ledger_it_loaded() {
        let (_d, st, gs, _) = chain_fixture(5);
        for mode in [VerifyMode::Quick, VerifyMode::Replay, VerifyMode::Full] {
            let loads = st.ledger_loads();
            let c = st.verify_chain(&gs, mode, &StubExecutor).unwrap();
            assert!(c.is_ok(), "{:?}", c.problem);
            assert_eq!(st.ledger_loads(), loads + 1, "{mode:?}: one load");
            let stored = c.stored.expect("the stored ledger is handed over");
            assert_eq!(stored.state_root(), st.load_ledger(&StubExecutor).unwrap().state_root());
        }
    }

    #[test]
    fn verify_chain_hands_over_nothing_when_it_found_a_problem() {
        let (_d, st, gs, _) = chain_fixture(6);
        st.overwrite_block_bytes_for_testing(4, b"garbage").unwrap();
        let c = st.verify_chain(&gs, VerifyMode::Quick, &StubExecutor).unwrap();
        assert!(!c.is_ok());
        assert!(c.stored.is_none());
    }
```

Add a pruned-store case to `verify_chain_on_a_pruned_store_recomputes_the_direct_ledger`
(line ~10151): after its successful `verify_chain`, assert
`check.stored.as_ref().map(|l| l.state_root()) == Some(check.ledger.state_root())`.

- [ ] **Step 2: Run them and confirm they fail** (`no field stored`).

- [ ] **Step 3: Implement.**
  - Add the field, with the doc comment "The stored ledger this check loaded (with the
    genesis setters it applies), when it loaded and nothing was wrong. `node::startup_check`
    hands it to `resume_consensus_from`, so a startup loads the ledger once (spec §4.5)."
  - Initialize it to `None` in the constructor.
  - **Archive tail:** right after `let same = …;`, add
    `let stored_copy = if same { loaded.as_ref().ok().cloned() } else { None };`. The clone
    shares the `SharedSet` bases, so it is cheap. After the `match`, before `Ok(check)`, add
    `check.stored = if check.problem.is_none() { stored_copy } else { None };`.
  - **Pruned success** (line 3981): `let stored = self.load_ledger(executor)?;`, then
    `check.ledger = stored.clone(); check.stored = Some(stored);`.
  - **Pruned problem path** (3976) and the **`Off` branch:** leave `stored` as `None`. The
    `Off` branch is only reached from `rand-node verify`, which ignores it.

- [ ] **Step 4: Run the storage suite and confirm it passes.**

- [ ] **Step 5: Run clippy and commit** (`storage: verify_chain hands over the stored ledger it
  loaded (ChainCheck.stored)`).

---

### Task 4: `startup_check` and one `load_ledger` at startup

**Files:**
- Modify: `crates/randprotocol-node/src/node.rs`:
  - `reload_ledger` at line 163;
  - `resume_consensus` at line 375;
  - `check_and_repair_chain` at line 478;
  - `start_with` at lines 2246–2254;
  - `NodeHandle` at line 90 and its construction at line 2549.
- Test: node.rs `mod tests` (line 4715).

**Interfaces:**
- Consumes:
  - Task 1: `verified_head`, `mark_verified_head`, `checkpoint_build`,
    `set_checkpoint_build_for_testing`, `ledger_loads`, `VerifyMode::Replay`, `VerifiedHead`.
  - Task 3: `ChainCheck.stored`.
- Produces:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalkReason {
    NoCheckpoint,
    OtherBuild(String),
    UntrustedBuild,
    HeadMoved { checkpoint: u64, head: u64 },
    Forced(VerifyMode),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupVerify {
    /// `--verify-chain off`.
    Off,
    /// The checkpoint matched: no walk.
    Skipped { height: u64 },
    /// The chain was walked, and why.
    Walked(WalkReason),
}

pub struct StartupCheck {
    pub resume: u64,
    pub stored: Option<Ledger>,
    pub verify: StartupVerify,
}

pub fn startup_check(storage: &Storage, gs: &GenesisState, mode: VerifyMode, executor: &dyn ConfidentialExecutor) -> Result<StartupCheck>;
pub fn check_and_repair_chain(storage: &Storage, gs: &GenesisState, mode: VerifyMode, executor: &dyn ConfidentialExecutor) -> Result<u64>; // = startup_check(..)?.resume
pub fn reload_ledger_from(storage: &Storage, gs: &GenesisState, executor: &dyn ConfidentialExecutor, stored: Option<Ledger>) -> Result<Ledger>;
pub fn reload_ledger(storage: &Storage, gs: &GenesisState, executor: &dyn ConfidentialExecutor) -> Result<Ledger>; // = reload_ledger_from(.., None)
pub fn resume_consensus_from(storage: &Storage, gs: &GenesisState, signer: Option<Keypair>, base_timeout: Duration, max_timeout: Duration, executor: Arc<dyn ConfidentialExecutor>, stored: Option<Ledger>) -> Result<HotStuff>;
pub fn resume_consensus(/* unchanged signature */) -> Result<HotStuff>; // = resume_consensus_from(.., None)
// NodeHandle gains: pub startup: StartupVerify,
```

`impl std::fmt::Display for WalkReason` produces exactly:
- `no checkpoint`
- `checkpoint from build {old12}`, where `old12` is the first 12 characters
- `untrusted build {sha}`, where `sha` is `env!("RAND_GIT_SHA")`
- `checkpoint at {checkpoint} but head is {head}`
- `forced by --verify-chain {mode}`, lowercase: `replay` or `full`

- [ ] **Step 1: Write the failing tests** (node.rs `mod tests`; `chain_past_a_boundary` is the
  fixture, and `use crate::storage::VerifiedHead;` goes at the top of the module if needed):

```rust
    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn startup(storage: &Storage, gs: &GenesisState, mode: VerifyMode) -> StartupCheck {
        startup_check(storage, gs, mode, &StubExecutor).unwrap()
    }

    #[test]
    fn a_restart_of_the_same_build_skips_the_walk_and_loads_once() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        storage.set_checkpoint_build_for_testing(Some(SHA_A));
        let first = startup(&storage, &gs, VerifyMode::Quick);
        assert_eq!(first.verify, StartupVerify::Walked(WalkReason::NoCheckpoint));
        let head = storage.head().unwrap().height;
        let loads = storage.ledger_loads();
        let again = startup(&storage, &gs, VerifyMode::Quick);
        assert_eq!(again.verify, StartupVerify::Skipped { height: head });
        assert!(again.stored.is_none());
        assert_eq!(storage.ledger_loads(), loads, "the skip loads nothing");
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let hs = resume_consensus_from(&storage, &gs, Some(key(1)), Duration::from_secs(1), Duration::from_secs(8), executor, again.stored).unwrap();
        assert_eq!(storage.ledger_loads(), loads + 1, "one load for the whole startup");
        assert_eq!(hs.committed_ledger().state_root(), storage.head_block().unwrap().header.state_root);
    }

    #[test]
    fn a_walking_startup_loads_the_ledger_once_and_hands_it_over() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        let loads = storage.ledger_loads();
        let check = startup(&storage, &gs, VerifyMode::Quick);
        assert!(matches!(check.verify, StartupVerify::Walked(_)));
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let handed = reload_ledger_from(&storage, &gs, executor.as_ref(), check.stored).unwrap();
        assert_eq!(storage.ledger_loads(), loads + 1, "the walk's load is reused");
        let fresh = reload_ledger(&storage, &gs, executor.as_ref()).unwrap();
        assert!(handed == fresh, "the handed-over ledger is the one a fresh reload builds");
        assert_eq!(handed.state_root(), fresh.state_root());
    }

    #[test]
    fn another_build_walks_and_takes_the_checkpoint_over() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        storage.set_checkpoint_build_for_testing(Some(SHA_A));
        startup(&storage, &gs, VerifyMode::Quick);
        storage.set_checkpoint_build_for_testing(Some(SHA_B));
        let c = startup(&storage, &gs, VerifyMode::Quick);
        assert_eq!(c.verify, StartupVerify::Walked(WalkReason::OtherBuild(SHA_A.into())));
        assert_eq!(storage.verified_head().unwrap().unwrap().build_sha, SHA_B);
        assert!(matches!(startup(&storage, &gs, VerifyMode::Quick).verify, StartupVerify::Skipped { .. }));
    }

    #[test]
    fn an_untrusted_build_always_walks_and_writes_nothing() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        for _ in 0..2 {
            assert_eq!(startup(&storage, &gs, VerifyMode::Quick).verify, StartupVerify::Walked(WalkReason::UntrustedBuild));
        }
        assert_eq!(storage.verified_head().unwrap(), None);
    }

    #[test]
    fn a_checkpoint_below_the_head_walks() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        storage.set_checkpoint_build_for_testing(Some(SHA_A));
        startup(&storage, &gs, VerifyMode::Quick);
        let head = storage.head_block().unwrap();
        // A row for a lower height, as a crash-free but non-carrying commit would leave.
        let stale = VerifiedHead { height: head.height() - 1, block_hash: head.parent(), state_root: head.header.state_root, build_sha: SHA_A.into() };
        storage.put_verified_head_for_testing(&stale).unwrap();
        let c = startup(&storage, &gs, VerifyMode::Quick);
        assert_eq!(c.verify, StartupVerify::Walked(WalkReason::HeadMoved { checkpoint: head.height() - 1, head: head.height() }));
    }

    #[test]
    fn a_walk_without_a_marker_write_walks_again() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        storage.set_checkpoint_build_for_testing(Some(SHA_A));
        startup(&storage, &gs, VerifyMode::Quick);
        storage.delete_meta_for_testing("verified_head").unwrap(); // the crash between walk and write
        assert_eq!(startup(&storage, &gs, VerifyMode::Quick).verify, StartupVerify::Walked(WalkReason::NoCheckpoint));
    }

    #[test]
    fn replay_ignores_a_valid_checkpoint() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        storage.set_checkpoint_build_for_testing(Some(SHA_A));
        startup(&storage, &gs, VerifyMode::Quick);
        for mode in [VerifyMode::Replay, VerifyMode::Full] {
            assert_eq!(startup(&storage, &gs, mode).verify, StartupVerify::Walked(WalkReason::Forced(mode)));
        }
    }

    #[test]
    fn off_leaves_the_marker_alone_and_quick_then_walks() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        storage.set_checkpoint_build_for_testing(Some(SHA_A));
        startup(&storage, &gs, VerifyMode::Quick);
        let before = storage.verified_head().unwrap();
        assert_eq!(startup(&storage, &gs, VerifyMode::Off).verify, StartupVerify::Off);
        assert_eq!(storage.verified_head().unwrap(), before);
    }

    #[test]
    fn a_valid_checkpoint_does_not_save_an_altered_snapshot() {
        let (_d, storage, gs, _) = chain_past_a_boundary();
        storage.set_checkpoint_build_for_testing(Some(SHA_A));
        startup(&storage, &gs, VerifyMode::Quick);
        storage.plant_nullifier_for_testing(&[0xdead_beef; 8]).unwrap();
        let c = startup(&storage, &gs, VerifyMode::Quick);
        assert!(matches!(c.verify, StartupVerify::Skipped { .. }), "the walk is skipped…");
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let err = resume_consensus_from(&storage, &gs, Some(key(1)), Duration::from_secs(1), Duration::from_secs(8), executor, c.stored)
            .err()
            .expect("…but OPS-5 still refuses the altered snapshot")
            .to_string();
        assert!(err.contains("ledger snapshot") && err.contains("state root"), "{err}");
    }
```

Add to storage.rs, beside `delete_meta_for_testing` (line ~3419), a test-only writer the
node tests use:

```rust
    #[cfg(test)]
    pub(crate) fn put_verified_head_for_testing(&self, row: &VerifiedHead) -> Result<()> {
        self.db.put_cf(self.cf(CF_META), META_VERIFIED_HEAD, bincode::serialize(row)?)?;
        Ok(())
    }
```

If `delete_meta_for_testing` is private to storage, make it `pub(crate)`. It already is at
line 3419.

`off_leaves_the_marker_alone_and_quick_then_walks` pins only the `off` half: the row is
neither read nor rewritten. The "then walks" half (a head above the row gives `HeadMoved`) is
`a_checkpoint_below_the_head_walks`.

- [ ] **Step 2: Run them and confirm they fail to compile** (`startup_check`,
  `StartupVerify` and the rest are missing).

- [ ] **Step 3: Implement.**

`reload_ledger_from`: today's `reload_ledger` body, with its first line replaced by

```rust
    // A startup that walked the chain already loaded the stored ledger (spec §4.5); the
    // genesis setters below are values from the file, so applying them again is idempotent.
    let mut ledger = match stored {
        Some(l) => l,
        None => storage.load_ledger(executor)?,
    };
```

and `reload_ledger(storage, gs, executor)` becomes `reload_ledger_from(storage, gs, executor, None)`.
Keep the existing doc comment on `reload_ledger_from`; give `reload_ledger` a one-line
"[`reload_ledger_from`] with no preloaded ledger."

`resume_consensus_from`: today's `resume_consensus` body with
`let ledger = reload_ledger_from(storage, gs, executor.as_ref(), stored)?;`.
`resume_consensus` delegates with `None`.

`startup_check`: move today's `check_and_repair_chain` body into it. Each `Ok(x)` becomes a
`StartupCheck`, and the decision goes in front:

```rust
pub fn startup_check(storage: &Storage, gs: &GenesisState, mode: VerifyMode, executor: &dyn ConfidentialExecutor) -> Result<StartupCheck> {
    if mode == VerifyMode::Off {
        return Ok(StartupCheck { resume: storage.head()?.height, stored: None, verify: StartupVerify::Off });
    }
    let head = storage.head()?;
    let reason = match (mode, storage.checkpoint_build(), storage.verified_head()?) {
        (VerifyMode::Replay | VerifyMode::Full, _, _) => WalkReason::Forced(mode),
        (_, None, _) => WalkReason::UntrustedBuild,
        (_, Some(_), None) => WalkReason::NoCheckpoint,
        (_, Some(build), Some(m)) if m.build_sha != build => WalkReason::OtherBuild(m.build_sha),
        (_, Some(_), Some(m)) if m.height != head.height || m.block_hash != head.hash => {
            WalkReason::HeadMoved { checkpoint: m.height, head: head.height }
        }
        (_, Some(build), Some(_)) => {
            tracing::info!("chain verified: checkpoint at {} (build {}), replay skipped", head.height, &build[..12]);
            return Ok(StartupCheck { resume: head.height, stored: None, verify: StartupVerify::Skipped { height: head.height } });
        }
    };
    tracing::info!("startup verify ({mode:?}): {reason}");
    let t = Instant::now();
    let check = storage.verify_chain(gs, mode, executor)?;
    // … today's pruned / archive / repair arms, unchanged, except:
    //   - pruned ok:  storage.mark_verified_head()?; return Ok(StartupCheck { resume: check.head, stored: check.stored, verify: StartupVerify::Walked(reason) })
    //   - archive ok: storage.mark_verified_head()?; Ok(StartupCheck { resume: check.head, stored: check.stored, verify: StartupVerify::Walked(reason) })
    //   - repaired:   after `again` passes: storage.mark_verified_head()?;
    //                 Ok(StartupCheck { resume, stored: again.stored, verify: StartupVerify::Walked(reason) })
}

pub fn check_and_repair_chain(storage: &Storage, gs: &GenesisState, mode: VerifyMode, executor: &dyn ConfidentialExecutor) -> Result<u64> {
    Ok(startup_check(storage, gs, mode, executor)?.resume)
}
```

Write out the three arms in full. The comment above only marks where the marker write and
the new return value go inside the existing code. `again` must be bound (it already is) so
`again.stored` can be moved out after the `if let Some(p) = again.problem` check. Change
that check to `if let Some(p) = &again.problem`.

`WalkReason`'s `Display` implements the five strings listed under Interfaces. For `Forced`,
use `match mode { VerifyMode::Replay => "replay", VerifyMode::Full => "full", VerifyMode::Quick => "quick", VerifyMode::Off => "off" }`.

In `start_with`, replace lines 2246 and 2254:

```rust
    let startup = startup_check(&storage, &gs, cfg.verify, executor.as_ref())?;
    // … (lines between unchanged)
    let mut hs = resume_consensus_from(&storage, &gs, signer, cfg.base_timeout, cfg.max_timeout, executor.clone(), startup.stored)?;
```

Move `startup.stored` out with `let StartupCheck { stored, verify: startup_verify, .. } = startup;`
so `startup_verify` is still available for `NodeHandle { …, startup: startup_verify }` at
line 2549. Add `pub startup: StartupVerify,` to `NodeHandle` with the doc comment "What the
startup integrity check did (startup-checkpoint spec §4)." Lines 2246–2254 may use the
resume height, so read them before editing.

- [ ] **Step 4: Run the node and storage suites and confirm they pass.**
  Run: `cargo test -p randprotocol-node --lib 2>&1 | tail -5`
  Expected: PASS. Every pre-existing restart test still passes, because tests have no trusted
  build unless they set one.

- [ ] **Step 5: Run clippy and commit** (`node: startup_check — a same-build checkpoint skips
  the startup walk; one load_ledger per startup (resume_consensus_from)`).

---

### Task 5: CLI help, the cluster test, docs

**Files:**
- Modify:
  - `crates/randprotocol-node/src/main.rs:757-759` (the `verify_chain` help);
  - the `rand-node verify --mode` help near the `Verify` command, which uses the same parser.
- Modify: `crates/randprotocol-node/tests/common/cluster.rs` (add `start_in_verify`).
- Test: `crates/randprotocol-node/tests/cluster.rs` (a new test after
  `validator_restarts_from_disk_and_resumes`, line ~597).
- Modify docs:
  - `docs/cli.md:399` and `:447`;
  - `docs/architecture.md:346-347` and `:657`;
  - `docs/node-hardware.md:56`;
  - `deploy/README.md:424-426`;
  - `AGENTS.md:2136`.

**Interfaces:**
- Consumes (Task 4): `NodeHandle.startup: StartupVerify`, `WalkReason`. Also
  `storage::this_build_checkpoint()` (Task 1).

- [ ] **Step 1: Update the help text.**
  - `--verify-chain`: `/// Startup chain integrity check: off, quick (skipped when this same clean build already verified the store through its head; otherwise structure + ledger replay), replay (quick, never skipped), full (replay plus every QC's votes).`
  - `rand-node verify --mode`: add `replay` (the same as `quick` there).

- [ ] **Step 2: Add the harness helper** to `tests/common/cluster.rs`. Refactor
  `start_in_pruned`'s body into
  `pub async fn start_in_verify(dir, key, bootstrap, validator, block_interval, prune_history, verify: randprotocol_node::storage::VerifyMode) -> TestNode`.
  `start_in_pruned` becomes a call to it with `VerifyMode::Full`.

- [ ] **Step 3: Write the cluster test:**

```rust
/// Startup checkpoint (spec §6): a validator restarted on the same binary in `quick` mode skips
/// the walk when this build is a clean commit — which the CI clean-clone job is — and walks,
/// saying why, when it is not. Either way it rejoins and commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_same_build_restart_skips_the_startup_walk() {
    use randprotocol_node::node::{StartupVerify, WalkReason};
    use randprotocol_node::storage::{this_build_checkpoint, VerifyMode};
    init_tracing();
    let ks = keys(2);
    let gen = genesis(&ks);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), gen.to_json()).unwrap();
    let b = start_in_verify(dir, &ks[1], vec![bootstrap_addr(&a)], true, FAST, None, VerifyMode::Quick).await;
    wait_height(&[&a, &b], 4, Duration::from_secs(40)).await;
    let (dir, _) = stop_and_head(b).await;
    let b = start_in_verify(dir, &ks[1], vec![bootstrap_addr(&a)], true, FAST, None, VerifyMode::Quick).await;
    match this_build_checkpoint() {
        Some(_) => assert!(matches!(b.handle.startup, StartupVerify::Skipped { .. }), "{:?}", b.handle.startup),
        None => assert_eq!(b.handle.startup, StartupVerify::Walked(WalkReason::UntrustedBuild)),
    }
    let target = a.height().max(b.height()) + 4;
    wait_height(&[&a, &b], target, Duration::from_secs(60)).await;
}
```

Use the names the file already imports: `keys`, `genesis`, `start_node`, `bootstrap_addr`,
`wait_height`, `stop_and_head`, `FAST`, `init_tracing`. If one is spelled differently, follow
the file. `StartupVerify` and `WalkReason` must be reachable as `randprotocol_node::node::…`;
if `node` isn't a public module path, re-export them where `NodeHandle` is re-exported.

- [ ] **Step 4: Run the test on its own.**
  Run: `cargo test -p randprotocol-node --test cluster a_same_build_restart_skips_the_startup_walk -- --nocapture 2>&1 | tail -15`
  Expected: PASS. With uncommitted edits the build is `-dirty`, so the `UntrustedBuild` arm
  runs. After committing, run it again: the build is clean and the `Skipped` arm must run.
  Record both runs in the report.

- [ ] **Step 5: Update the docs.**

  - **`docs/cli.md:399`.** Replace the row with:
    `| --verify-chain <MODE> | quick | startup integrity check: off; quick (skipped when this same clean build already verified the store through its head — the startup checkpoint, docs/architecture.md; otherwise structure plus a ledger replay, which re-checks proposer signatures and bundle proofs); replay (quick, never skipped); full (replay plus every QC's votes) |`
  - **`docs/cli.md:447`:** `quick, replay or full, as for --verify-chain (no checkpoint here: rand-node verify always walks)`.
  - **`docs/architecture.md`:**
    - Fix the claim at :346-347 and :657 that only `full` checks proposer signatures: `quick`
      checks them through `apply_block_for_sync`, and `full` adds only every QC's votes.
    - In the startup section, add a paragraph covering:
      - the checkpoint row (height, hash, state root, build sha);
      - the trusted-build rule;
      - carry-forward in `commit`, and clearing in `truncate_to`;
      - that OPS-5 still runs on every start;
      - that on an archive's fast path the counters outside the state root (base fees burned,
        unsealed fees, perp input rows) are not re-audited, and `--verify-chain replay` is how
        to audit them.
  - **`docs/node-hardware.md:56`:** the startup row reads: "a restart of the same build:
    seconds (one ledger load and the head's state root; the startup checkpoint). The first
    start of a new build: the full check, which took 239 s at 59 183 blocks (chain 12,
    unpruned) and up to 30 min at 259 k blocks on 48 GB droplets. A pruned node's check is
    structural, not a replay."
  - **`deploy/README.md:424-426` and `AGENTS.md:2136`:** add one sentence each. "The first
    start of a new build still runs the full check (plan the pause for it); a restart of the
    same build skips it (startup checkpoint, v0.7.2+)." If the next release has a different
    version, use that version.

- [ ] **Step 6: Run the full suites once.**

```bash
cargo clippy -p randprotocol-node --all-targets -- -D warnings
cargo test -p randprotocol-node --lib 2>&1 | tail -3
cargo test -p randprotocol-core 2>&1 | grep "test result" | tail -3
cargo test -p randprotocol-node --test cluster 2>&1 | tail -5
```

Expected: everything passes. Run the cluster binary once and keep the full output in the
report. If one test fails, rerun only that test on its own up to 4 times and report both runs.
Don't rerun the whole binary without asking.

- [ ] **Step 7: Commit** (`startup checkpoint: --verify-chain replay, the same-build restart
  cluster test, docs (cli, architecture signature fix, node-hardware, deploy, AGENTS)`).
