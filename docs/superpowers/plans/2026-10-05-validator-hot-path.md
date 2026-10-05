# Validator Hot Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the validator's block-apply path flat in state size: a `rand-node bench apply` harness that measures it, an O(delta) ledger clone, an O(log n) genesis-gated nullifier root, verify workers sized to the host, and parallel, once-per-certificate QC verification.

**Architecture:** The ledger's two O(state) sets (`commitments`, `nullifiers`) become a `SharedSet`: an `Arc<RwLock<BTreeSet>>` committed base shared by every clone plus an owned delta, drained into the base at HotStuff commit. Under a genesis flag the nullifier root is a Merkle Mountain Range in insertion order whose peaks persist in RocksDB metadata, taking the sorted root's slot and re-domaining the state root. The harness drives a one-validator `HotStuff` on the `StubExecutor` and prints a timing table; it is the regression test for both changes.

**Tech Stack:** Rust 1.98.1 (`rust-toolchain.toml`), std only (no new crates: `libc` is already a node dependency, `rand 0.8` and `bincode` already core dependencies), RocksDB via the existing `Storage`.

**Spec:** `docs/superpowers/specs/2026-10-05-validator-hot-path-design.md` — read it first. Where this plan and the spec differ, this plan wins; the differences are listed under "Spec corrections" below.

**Worktree:** `~/rand-worktrees/fullnode-hot-path`, branch `feat/hot-path`, based on `main` at `4c03dcb1`. Every path below is relative to it. Commit messages end with the two attribution lines in the repo's current session reminder (`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and the `Claude-Session:` line).

## Spec corrections (found while planning; the spec is amended by this list)

1. **The covered path adds no nullifiers today**: an aggregate covers bundles already applied raw. The harness has one shape, raw bundles at the `MAX_BLOCK_TXS` cap of 2 000, two nullifiers and four commitments each: 4 000 nullifiers and 8 000 commitments a block, 40 M nullifiers at 10 000 blocks — the §3.6 count. `--shape` is dropped; `--bundles` (default 2 000) replaces `--records`.
2. **The proposer clones the ledger once per candidate** (`hotstuff.rs:1321`, `let mut trial = ledger.clone()`), 2 000 times a block. Task 4 replaces it with apply-and-replay-on-failure, bounded to 8 replays a block. Without it the shared set alone leaves `propose` at seconds a block.
3. **This branch has no perps section.** The last genesis-hash tag is `tokens_incremental_root` (`genesis.rs:1475-1478`); the new tag goes after it. `state_root_preimage` does not exist on this branch; the slot swap happens in `state_root_leaves`.
4. **`Ledger` has a hand-written `PartialEq`** (`mod.rs:785-826`) used by `Storage::verify_chain`; `SharedSet` implements `PartialEq` over the logical set.
5. **No `proptest`** in the workspace; randomised tests use `rand::rngs::StdRng::seed_from_u64` (already a core dependency) with fixed seeds.
6. **Shared base and lineages**: `HotStuff::new` detaches its ledger's base (a private copy, O(state) once, tiny at genesis); `HotStuff::resume` folds the incoming ledger's delta into the base. `len()` is exact always (counts delta entries not in the base), not only after absorb.

## Global Constraints

- Toolchain pinned: `channel = "1.98.1"`. Build with `cargo build --release -p randprotocol-node`; test with `cargo test -p randprotocol-core` / `-p randprotocol-node` as named per task.
- No new dependencies. `deny.toml` licence allow-list is unchanged.
- Every consensus-visible change is genesis-gated: a ledger without `incremental_nullifier_root` commits byte-identical state roots to today, and every existing genesis hash is unchanged.
- The `SharedSet` base is written only by `commit()` / `detach()`, only from `HotStuff` (commit, `new`, `resume`).
- Clippy clean: `cargo clippy -p randprotocol-core -p randprotocol-node --all-targets -- -D warnings` must pass before each commit (the repo's CI runs it).
- Doc comments in this repo are prose that says what and why, with audit/spec references; match that style. No `TODO`s.

## Review Focus

Inputs the spec implies but no task's tests would otherwise exercise; each line's test is added to the owning task.

1. **A `--bundles` above the 2 000 cap** → the harness must refuse at argument parsing with the cap named, not propose a block the ledger rejects. (Task 1)
2. **A candidate whose failure happens after a *successful* candidate changed small state (validator rewards)** → the replay must reproduce the same state root the replica computes; test with a block of two bundles where the second double-spends the first and a third follows. (Task 4)
3. **A clone taken from the committed ledger *before* a commit, used *after* it** (the node's verify-worker snapshot) → `contains` still answers correctly and `len()` is exact. (Task 2)
4. **A flag-on store with the accumulator row missing or truncated** → startup refuses with a message naming the row and the remedy, never rebuilds. (Task 7)
5. **A QC that verified under epoch N's set presented against epoch N+1's set** → the cache must not vouch for it; the key covers the set. (Task 9)

---

### Task 1: `rand-node bench apply` harness

**Files:**
- Create: `crates/randprotocol-node/src/bench.rs`
- Modify: `crates/randprotocol-node/src/lib.rs` (add `pub mod bench;`)
- Modify: `crates/randprotocol-node/src/main.rs` (`Cmd` enum ~line 374; dispatch `match cli.cmd` ~line 1546)
- Test: unit tests inside `bench.rs`

**Interfaces:**
- Consumes: `randprotocol_core::consensus::{HotStuff, ConsensusConfig, Action, ConsensusMessage}`, `randprotocol_core::genesis::{Genesis, GenesisValidator, GenesisState}`, `randprotocol_core::confidential::StubExecutor`, `randprotocol_core::notes::{Bundle, Envelope, Word8, word8_to_hex, ShieldedAddress, KEM_EK_BYTES, pad4}`, `randprotocol_core::types::{Transaction, Action as TxAction}`, `randprotocol_core::gas`.
- Produces: `pub struct BenchArgs { bundles: usize, blocks: u64, report_every: u64, incremental_nullifier_root: bool, fail_over_ms: u64 }`, `pub fn run(args: &BenchArgs) -> anyhow::Result<Verdict>`, `pub struct Row { height, propose_ms, apply_ms, root_ms, clone_ms, nullifiers, rss_mb, peak_rss_mb }`, `pub struct Verdict { last: Row, passed: bool }`. `incremental_nullifier_root` is wired in Task 6; until then it is accepted and ignored with a printed note.

- [ ] **Step 1: Confirm the names this task imports**

Run:
```bash
cd ~/rand-worktrees/fullnode-hot-path
grep -n "pub fn word8_to_hex\|pub const KEM_EK_BYTES\|pub fn pad4\|pub fn digest_input" crates/randprotocol-core/src/notes.rs crates/randprotocol-core/src/types/*.rs
grep -n "pub struct GenesisValidator" -A 5 crates/randprotocol-core/src/genesis.rs
grep -n "pub fn shielded" crates/randprotocol-core/src/types/transaction.rs
grep -n "pub enum Action" -A 8 crates/randprotocol-core/src/consensus/mod.rs
```
Expected: each name resolves to one definition. If `pad4` or `word8_to_hex` live elsewhere, adjust the `use` lines below; nothing else changes.

- [ ] **Step 2: Write the failing smoke test**

Create `crates/randprotocol-node/src/bench.rs` with only the test module and the type stubs the test names:

```rust
//! `rand-node bench apply`: the validator hot path at synthetic load
//! (`docs/superpowers/specs/2026-10-05-validator-hot-path-design.md` §3, the acceptance of
//! `docs/compute-optimization.md` §3.6). One validator, the `StubExecutor`, `--bundles`
//! synthetic bundles a block for `--blocks` blocks through the real `HotStuff` path — propose,
//! apply, vote, QC, commit, prune — with one timing row every `--report-every` blocks.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_run_fills_every_block_and_reports_the_last_row() {
        let args = BenchArgs { bundles: 16, blocks: 12, report_every: 4, incremental_nullifier_root: false, fail_over_ms: 10_000 };
        let v = run(&args).expect("the harness runs");
        assert_eq!(v.last.height, 12, "the last row is the last block");
        // Two nullifiers per bundle, every candidate carried (the harness aborts otherwise).
        assert_eq!(v.last.nullifiers, 12 * 16 * 2);
        assert!(v.passed, "a 12-block run is under any sane budget: {:?}", v.last);
    }

    #[test]
    fn bundles_above_the_cap_are_refused_before_any_block() {
        let args = BenchArgs { bundles: randprotocol_core::gas::MAX_BLOCK_TXS + 1, blocks: 1, report_every: 1, incremental_nullifier_root: false, fail_over_ms: 1 };
        let err = run(&args).err().expect("refused").to_string();
        assert!(err.contains("MAX_BLOCK_TXS") && err.contains("2000"), "{err}");
    }
}
```

- [ ] **Step 3: Run it to see it fail to compile**

Run: `cargo test -p randprotocol-node bench:: 2>&1 | tail -5`
Expected: errors about `BenchArgs`, `run` not found.

- [ ] **Step 4: Implement the harness**

Above the test module in `bench.rs`:

```rust
use anyhow::{bail, Context};
use randprotocol_core::confidential::StubExecutor;
use randprotocol_core::consensus::{Action, ConsensusConfig, ConsensusMessage, HotStuff};
use randprotocol_core::crypto::Keypair;
use randprotocol_core::gas;
use randprotocol_core::genesis::{Genesis, GenesisState, GenesisValidator};
use randprotocol_core::ledger::Ledger;
use randprotocol_core::notes::{pad4, word8_to_hex, Bundle, Envelope, ShieldedAddress, Word8, KEM_EK_BYTES};
use randprotocol_core::types::{Action as TxAction, Block, Transaction};
use std::sync::Arc;
use std::time::Instant;

/// The bundle guest commitment the harness genesis pins; every synthetic proof is made for it.
const HC: Word8 = [3; 8];
const CHAIN_ID: u64 = 1;

#[derive(Clone, Debug)]
pub struct BenchArgs {
    pub bundles: usize,
    pub blocks: u64,
    pub report_every: u64,
    pub incremental_nullifier_root: bool,
    pub fail_over_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Row {
    pub height: u64,
    pub propose_ms: f64,
    pub apply_ms: f64,
    pub root_ms: f64,
    pub clone_ms: f64,
    pub nullifiers: usize,
    pub rss_mb: f64,
    pub peak_rss_mb: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct Verdict {
    pub last: Row,
    pub passed: bool,
}

/// The one-validator genesis: faucet and confidential on, no staking/tokens/gas sections, the
/// test FRI profile (nothing is proved), and the accumulator flag when asked.
fn genesis(key: &Keypair, incremental_nullifier_root: bool) -> anyhow::Result<GenesisState> {
    let payout = ShieldedAddress { pk: [1; 8], kem_ek: vec![1; KEM_EK_BYTES] }.to_string();
    let g = Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: vec![GenesisValidator {
            public_key: key.public_key().clone(),
            stake: randprotocol_core::ledger::staking::MIN_STAKE as u128,
            payout,
        }],
        alloc: Vec::new(),
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&HC),
        bridge: None,
        tokens: None,
        aggregation: None,
        consensus_domain: None,
        staking: None,
        epoch_blocks: 1_000_000,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        envelope_bytes: None,
        vesting: None,
        hardening_v6: None,
        hc_auth: None,
        gas: None,
        testnet: None,
        binding_domain: None,
        proof_window_blocks: None,
        program_state: None,
    };
    let _ = incremental_nullifier_root; // Task 6 sets `g.incremental_nullifier_root`.
    g.build(&StubExecutor).context("building the harness genesis")
}

fn envelope() -> Envelope {
    Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
}

/// A fresh nullifier or commitment: distinct across the whole run, so every insert grows the
/// sets and every membership probe runs at the real set size.
fn fresh_word(counter: &mut u64) -> Word8 {
    *counter += 1;
    let h = randprotocol_core::crypto::Hash::digest_domain(b"rand-bench-apply-word", &counter.to_be_bytes());
    randprotocol_core::notes::word8_from_bytes(h.as_bytes()).expect("32 bytes")
}

/// `bundles` synthetic bundle transactions against `tip`: two spends, four outputs, anchored at
/// the tip root, timed at the block being proposed, stub-proved and bound.
fn candidates(tip: &Ledger, height: u64, bundles: usize, counter: &mut u64) -> Vec<Transaction> {
    (0..bundles)
        .map(|_| {
            let nfs = [fresh_word(counter), fresh_word(counter)];
            let cms = [fresh_word(counter), fresh_word(counter)];
            let mut b = Bundle {
                anchor: tip.root(),
                nullifiers: pad4(nfs),
                commitments: pad4(cms),
                fee: gas::BUNDLE_BASE,
                burn_a: 0,
                burn_r: 0,
                burn_asset: 0,
                time: height as u32,
                envelopes: [envelope(), envelope(), envelope(), envelope()],
                proof: vec![],
                auth_commit: [0; 8],
                auth_proof: Vec::new(),
            };
            let d = randprotocol_core::confidential::ConfidentialExecutor::bundle_digest(&StubExecutor, &b.digest_input());
            b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
            StubExecutor::bound(Transaction::shielded(CHAIN_ID, b, TxAction::None))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4096)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn current_rss_bytes() -> u64 {
    // SAFETY: task_info on the calling task with a correctly sized out-struct; the only
    // observable effect is the struct being filled.
    unsafe {
        let mut info: libc::mach_task_basic_info = std::mem::zeroed();
        let mut count = (std::mem::size_of::<libc::mach_task_basic_info>() / std::mem::size_of::<libc::natural_t>())
            as libc::mach_msg_type_number_t;
        let kr = libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as libc::task_info_t,
            &mut count,
        );
        if kr == libc::KERN_SUCCESS { info.resident_size } else { 0 }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_rss_bytes() -> u64 { 0 }

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage fills a plain struct for the calling process.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let v = ru.ru_maxrss as u64;
    if cfg!(target_os = "macos") { v } else { v * 1024 }
}

fn ms(t: Instant) -> f64 { t.elapsed().as_secs_f64() * 1_000.0 }

pub fn header() -> String {
    format!("{:>7} {:>11} {:>9} {:>8} {:>9} {:>11} {:>8} {:>12}", "height", "propose_ms", "apply_ms", "root_ms", "clone_ms", "nullifiers", "rss_mb", "peak_rss_mb")
}

pub fn format_row(r: &Row) -> String {
    format!("{:>7} {:>11.1} {:>9.1} {:>8.2} {:>9.2} {:>11} {:>8.0} {:>12.0}", r.height, r.propose_ms, r.apply_ms, r.root_ms, r.clone_ms, r.nullifiers, r.rss_mb, r.peak_rss_mb)
}

pub fn run(args: &BenchArgs) -> anyhow::Result<Verdict> {
    if args.bundles > gas::MAX_BLOCK_TXS {
        bail!("--bundles {} is over MAX_BLOCK_TXS ({}); the raw lane is capped there", args.bundles, gas::MAX_BLOCK_TXS);
    }
    if args.blocks == 0 || args.report_every == 0 {
        bail!("--blocks and --report-every must be at least 1");
    }
    let key = Keypair::from_seed([1; 32]).context("key")?;
    let gs = genesis(&key, args.incremental_nullifier_root)?;
    let mut cfg = ConsensusConfig::new(CHAIN_ID, gs.validators.clone(), gs.hash());
    cfg.epoch_blocks = gs.epoch_blocks;
    cfg.domain = gs.signing_domain();
    let mut node = HotStuff::new(cfg, Some(key), gs.block.clone(), gs.ledger.clone(), Arc::new(StubExecutor));
    let _ = node.start();

    println!("{}", header());
    let mut counter = 0u64;
    let mut now_ms = 1u64;
    let mut last = None;
    for height in 1..=args.blocks {
        now_ms += 1;
        let txs = candidates(node.tip_ledger(), height, args.bundles, &mut counter);
        // The replica's cost, measured apart from the leader's: apply the proposed block on a
        // clone of the pre-block tip, as a validator would.
        let mut replica = node.tip_ledger().clone();

        let t = Instant::now();
        let actions = node.propose(height, txs, now_ms).with_context(|| format!("propose at height {height}"))?;
        let propose_ms = ms(t);

        let block: &Block = actions
            .iter()
            .find_map(|a| match a { Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b), _ => None })
            .context("propose broadcast no proposal")?;
        if block.transactions.len() != args.bundles {
            bail!("block {height} carries {} of {} candidates; the synthetic bundles are being refused", block.transactions.len(), args.bundles);
        }
        let t = Instant::now();
        replica
            .apply_block_for_sync(block, &Default::default(), &[], &StubExecutor, &randprotocol_core::ledger::NoVerified)
            .map_err(|e| anyhow::anyhow!("replica apply at {height}: {e:?}"))?;
        let apply_ms = ms(t);
        drop(replica);

        if height % args.report_every == 0 || height == args.blocks {
            let tip = node.tip_ledger();
            let t = Instant::now();
            let _ = tip.state_root();
            let root_ms = ms(t);
            let t = Instant::now();
            let c = tip.clone();
            let clone_ms = ms(t);
            drop(c);
            let row = Row {
                height,
                propose_ms,
                apply_ms,
                root_ms,
                clone_ms,
                nullifiers: tip.nullifiers().len(),
                rss_mb: current_rss_bytes() as f64 / 1e6,
                peak_rss_mb: peak_rss_bytes() as f64 / 1e6,
            };
            println!("{}", format_row(&row));
            last = Some(row);
        }
    }
    let last = last.expect("at least one row");
    let passed = last.apply_ms <= args.fail_over_ms as f64;
    println!(
        "verdict: apply {:.1} ms at block {} ({} nullifiers) — {} the {} ms budget",
        last.apply_ms, last.height, last.nullifiers, if passed { "within" } else { "OVER" }, args.fail_over_ms
    );
    Ok(Verdict { last, passed })
}
```

Notes for the implementer:
- `HotStuff::propose(view, candidates, now_ms)` with one validator self-votes, forms the QC and commits on the three-chain rule, so the tree holds three speculative entries as on a live chain. The view number equals the height on a chain that never times out.
- `apply_block_for_sync`'s second parameter is `&BTreeMap<usize, Vec<CoveredBundle>>`; `Default::default()` is the empty map. `NoVerified` is `randprotocol_core::ledger::NoVerified` (check with `grep -rn "pub struct NoVerified" crates/randprotocol-core/src`).
- If `propose` refuses candidates (block shorter than `bundles`), the usual causes are the bundle `time` (must equal the block height — mirror `ledger/mod.rs` test helper `bundle4`, `time: l.height as u32`) or the anchor (`tip.root()`); fix the candidate, never relax the check.
- `Ledger::nullifiers().len()` is a `BTreeSet` today and a `SharedSet` after Task 2; both have `len()`.

Add to `lib.rs`: `pub mod bench;`.

In `main.rs`, add to `enum Cmd` (after `Aggregate { .. }`):

```rust
    /// Benchmarks of the node's own paths; no network, no database.
    Bench {
        #[command(subcommand)]
        cmd: BenchCmd,
    },
```
and the new enum beside `Cmd`:
```rust
#[derive(Subcommand)]
enum BenchCmd {
    /// The validator hot path at synthetic load: one validator on the StubExecutor, `--bundles`
    /// bundles a block (two nullifiers, four commitments each) for `--blocks` blocks through the
    /// real HotStuff propose/apply/commit path. Prints one timing row every `--report-every`
    /// blocks and exits non-zero if the last block's apply time is over `--fail-over-ms`
    /// (`docs/compute-optimization.md` §3.6).
    Apply {
        #[arg(long, default_value_t = randprotocol_core::gas::MAX_BLOCK_TXS)]
        bundles: usize,
        #[arg(long, default_value_t = 10_000)]
        blocks: u64,
        #[arg(long, default_value_t = 500)]
        report_every: u64,
        /// Cut the harness genesis with `incremental_nullifier_root: true`.
        #[arg(long)]
        incremental_nullifier_root: bool,
        #[arg(long, default_value_t = 300)]
        fail_over_ms: u64,
    },
}
```
and the dispatch arm in `main`'s `match cli.cmd`:
```rust
        Cmd::Bench { cmd: BenchCmd::Apply { bundles, blocks, report_every, incremental_nullifier_root, fail_over_ms } } => {
            let v = randprotocol_node::bench::run(&randprotocol_node::bench::BenchArgs { bundles, blocks, report_every, incremental_nullifier_root, fail_over_ms })?;
            if !v.passed {
                std::process::exit(2);
            }
        }
```
(If `main.rs` refers to the library crate by another path, e.g. `crate::` because it is a `[[bin]]` in the same crate with `mod` declarations, follow what the `Status` arm does for `RpcClient`.)

- [ ] **Step 5: Run the tests**

Run: `cargo test -p randprotocol-node bench:: 2>&1 | tail -8`
Expected: both tests PASS.

- [ ] **Step 6: Build and run the baseline**

Run:
```bash
cargo build --release -p randprotocol-node 2>&1 | tail -2
./target/release/rand-node bench apply --blocks 300 --report-every 50 --fail-over-ms 100000 | tee /tmp/bench-baseline-300.txt
```
Expected: a header, six rows, a verdict line. On `main`'s code `propose_ms` and `clone_ms` grow with height (2 000 clones a block of a growing set). Record the output; Task 10 puts it in the docs. Do not run 10 000 blocks on the baseline; it will not finish in reasonable time, which is the point.

- [ ] **Step 7: Clippy, commit**

```bash
cargo clippy -p randprotocol-node --all-targets -- -D warnings 2>&1 | tail -3
git add crates/randprotocol-node/src/bench.rs crates/randprotocol-node/src/lib.rs crates/randprotocol-node/src/main.rs
git commit -m "node: rand-node bench apply — the validator hot path at synthetic load (one validator, StubExecutor, 2 000 bundles a block through the real HotStuff path), one timing row per report interval, exit 2 over the apply budget

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 2: `SharedSet` and the ledger's two sets

**Files:**
- Create: `crates/randprotocol-core/src/ledger/shared_set.rs`
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` — module declaration near line 1-30; struct fields `:579-580`; doc comment `:561-569`; `new` `:848-849`; `from_parts` `:912-913`; accessors `:1699`, `:1708`; `state_root_leaves` `:2969-2975`; test `:5072-5073`
- Modify: `crates/randprotocol-core/src/ledger/aggregation.rs:927-929` (test helper)
- Test: unit tests in `shared_set.rs`; existing ledger tests

**Interfaces:**
- Produces:
  ```rust
  pub struct SharedSet;                       // Clone, Debug, Default, PartialEq, Eq
  impl SharedSet {
      pub fn new() -> SharedSet;
      pub fn from_set(set: BTreeSet<Word8>) -> SharedSet;
      pub fn contains(&self, x: &Word8) -> bool;
      pub fn insert(&mut self, x: Word8) -> bool;    // false if present anywhere
      pub fn len(&self) -> usize;                     // exact: base + delta entries not in base
      pub fn is_empty(&self) -> bool;
      pub fn added_len(&self) -> usize;               // the delta's size (tests, the harness)
      pub fn snapshot(&self) -> BTreeSet<Word8>;      // base ∪ delta, a full copy
      pub fn for_each_sorted(&self, f: impl FnMut(&Word8)); // merged ascending order, no duplicates
      pub fn commit(&mut self);   // drain delta into base, O(delta)
      pub fn absorb(&mut self);   // drop delta entries the base has
      pub fn detach(&mut self);   // private copy of the base
  }
  ```
  On `Ledger`: `pub fn nullifiers(&self) -> &SharedSet`, `pub fn commitments_set(&self) -> &SharedSet`, `pub fn commit_shared_sets(&mut self)`, `pub fn absorb_shared_sets(&mut self)`, `pub fn detach_shared_sets(&mut self)`.
- Consumed by: Task 3 (HotStuff), Task 1's harness (`len()`), Task 6 (`for_each_sorted` in the legacy root).

- [ ] **Step 1: Write the failing tests**

Create `crates/randprotocol-core/src/ledger/shared_set.rs` with the test module first:

```rust
//! A set of words with a committed base shared by every clone and an owned delta
//! (`docs/superpowers/specs/2026-10-05-validator-hot-path-design.md` §5). The ledger's
//! `commitments` and `nullifiers` hold every entry the chain ever produced, and the ledger is
//! cloned per speculative block, per trial apply and per block apply; before this type each
//! clone copied both sets (28 ms at 10⁶ entries, audit v6). Now a clone copies the delta.
//!
//! The base is written by `commit` (drain the delta in) and `detach` (a private copy) only, and
//! `HotStuff` is the only caller of either: at commit, after the tree keeps only descendants of
//! the new head, so every surviving clone already holds the committed delta and `absorb` drops
//! it as redundant. Sound because consensus state is `base ∪ delta` and a commit moves entries
//! between the two halves of the chain's own ancestors, never adds one.

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn w(n: u32) -> Word8 { [n, 0, 0, 0, 0, 0, 0, 0] }

    #[test]
    fn a_clone_shares_the_base_and_owns_its_delta() {
        let mut a = SharedSet::from_set([w(1), w(2)].into_iter().collect());
        let mut b = a.clone();
        assert!(b.insert(w(3)));
        assert!(!a.contains(&w(3)), "the clone's insert is its own");
        assert!(b.contains(&w(1)), "the base is visible through the clone");
        assert!(!a.insert(w(2)), "a base entry is not inserted twice");
        assert_eq!((a.len(), b.len(), a.added_len(), b.added_len()), (2, 3, 0, 1));
    }

    #[test]
    fn commit_moves_the_delta_into_the_base_and_absorb_drops_what_the_base_gained() {
        let mut committed = SharedSet::from_set([w(1)].into_iter().collect());
        let mut child = committed.clone();
        child.insert(w(2));
        let mut grandchild = child.clone();
        grandchild.insert(w(3));
        // The child commits: its delta {2} becomes base.
        committed = child.clone();
        committed.commit();
        assert_eq!((committed.len(), committed.added_len()), (2, 0));
        // The grandchild's view is unchanged as a set, and its delta still holds the redundant 2
        // until it absorbs — len() is exact either way.
        assert_eq!((grandchild.len(), grandchild.added_len()), (3, 2));
        grandchild.absorb();
        assert_eq!((grandchild.len(), grandchild.added_len()), (3, 1));
        assert!(grandchild.contains(&w(2)) && grandchild.contains(&w(3)));
        // A clone taken before the commit and kept (the node's verify snapshot) still answers.
        assert!(child.contains(&w(2)) && !child.contains(&w(3)));
        assert_eq!(child.len(), 2);
    }

    #[test]
    fn detach_gives_a_private_base() {
        let a = SharedSet::from_set([w(1)].into_iter().collect());
        let mut b = a.clone();
        b.detach();
        b.insert(w(2));
        b.commit();
        assert!(!a.contains(&w(2)), "a's base did not move");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn sorted_iteration_merges_without_duplicates_and_equality_is_logical() {
        let mut s = SharedSet::from_set([w(5), w(1)].into_iter().collect());
        s.insert(w(3));
        let mut seen = Vec::new();
        s.for_each_sorted(|x| seen.push(*x));
        assert_eq!(seen, vec![w(1), w(3), w(5)]);
        let flat = SharedSet::from_set([w(1), w(3), w(5)].into_iter().collect());
        assert_eq!(s, flat, "equal as sets however the entries are split");
        assert_eq!(s.snapshot(), flat.snapshot());
    }

    /// Random insert/clone/commit/absorb programs across a family of clones, against a plain
    /// `BTreeSet` oracle per clone. Seeded, so a failure reproduces.
    #[test]
    fn random_programs_agree_with_a_btreeset_oracle() {
        for seed in 0..32u64 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut sets: Vec<(SharedSet, std::collections::BTreeSet<Word8>)> = vec![(SharedSet::new(), Default::default())];
            for _ in 0..400 {
                let i = rng.gen_range(0..sets.len());
                match rng.gen_range(0..10) {
                    0..=5 => {
                        let x = w(rng.gen_range(0..64));
                        let (s, o) = &mut sets[i];
                        assert_eq!(s.insert(x), o.insert(x), "seed {seed}");
                    }
                    6 => {
                        let c = sets[i].clone();
                        if sets.len() < 6 { sets.push(c); }
                    }
                    7 => {
                        // Commit i, then absorb every clone (what HotStuff does): only clones
                        // that are supersets of i stay consistent, so make them so first.
                        let committed = sets[i].1.clone();
                        for (s, o) in sets.iter_mut() {
                            for x in &committed { if o.insert(*x) { s.insert(*x); } }
                        }
                        sets[i].0.commit();
                        for (s, _) in sets.iter_mut() { s.absorb(); }
                    }
                    8 => sets[i].0.detach(),
                    _ => {
                        let x = w(rng.gen_range(0..64));
                        let (s, o) = &sets[i];
                        assert_eq!(s.contains(&x), o.contains(&x), "seed {seed}");
                    }
                }
                for (s, o) in &sets {
                    assert_eq!(s.len(), o.len(), "seed {seed}: len");
                    assert_eq!(s.snapshot(), *o, "seed {seed}: contents");
                }
            }
        }
    }
}
```

- [ ] **Step 2: Run to see them fail**

Add `mod shared_set; pub use shared_set::SharedSet;` to `ledger/mod.rs` near the other `mod` lines (search `pub mod aggregation;`). Run: `cargo test -p randprotocol-core shared_set:: 2>&1 | tail -5`. Expected: compile errors, `SharedSet` undefined.

- [ ] **Step 3: Implement `SharedSet`**

Above the tests in `shared_set.rs`:

```rust
use crate::notes::Word8;
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default)]
pub struct SharedSet {
    /// The committed entries. Shared by every clone of a lineage; written only by [`Self::commit`]
    /// and replaced only by [`Self::detach`].
    base: Arc<RwLock<BTreeSet<Word8>>>,
    /// Entries this value inserted (or inherited from the clone it was made from) since the base.
    added: BTreeSet<Word8>,
}

impl SharedSet {
    pub fn new() -> SharedSet {
        SharedSet::default()
    }

    pub fn from_set(set: BTreeSet<Word8>) -> SharedSet {
        SharedSet { base: Arc::new(RwLock::new(set)), added: BTreeSet::new() }
    }

    fn base(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<Word8>> {
        // A poisoned lock means a panic while draining a delta in; there is no state to recover.
        self.base.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn contains(&self, x: &Word8) -> bool {
        self.added.contains(x) || self.base().contains(x)
    }

    /// `true` if `x` was absent from both halves and is now in the delta.
    pub fn insert(&mut self, x: Word8) -> bool {
        if self.base().contains(&x) {
            return false;
        }
        self.added.insert(x)
    }

    /// Exact: the base plus the delta entries the base does not hold. Between a lineage's
    /// `commit` and this clone's `absorb` the two can overlap; the count does not double.
    pub fn len(&self) -> usize {
        let base = self.base();
        base.len() + self.added.iter().filter(|x| !base.contains(*x)).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn added_len(&self) -> usize {
        self.added.len()
    }

    pub fn snapshot(&self) -> BTreeSet<Word8> {
        let mut out = self.base().clone();
        out.extend(self.added.iter().copied());
        out
    }

    /// Every entry once, ascending: a merge of the two sorted halves.
    pub fn for_each_sorted(&self, mut f: impl FnMut(&Word8)) {
        let base = self.base();
        let mut a = base.iter().peekable();
        let mut b = self.added.iter().peekable();
        loop {
            match (a.peek(), b.peek()) {
                (Some(x), Some(y)) => match x.cmp(y) {
                    std::cmp::Ordering::Less => { f(x); a.next(); }
                    std::cmp::Ordering::Greater => { f(y); b.next(); }
                    std::cmp::Ordering::Equal => { f(x); a.next(); b.next(); }
                },
                (Some(x), None) => { f(x); a.next(); }
                (None, Some(y)) => { f(y); b.next(); }
                (None, None) => return,
            }
        }
    }

    /// Drain the delta into the shared base: the commit step. O(delta); the base is not copied.
    pub fn commit(&mut self) {
        if self.added.is_empty() {
            return;
        }
        let mut base = self.base.write().unwrap_or_else(|e| e.into_inner());
        base.extend(std::mem::take(&mut self.added));
    }

    /// Drop delta entries the base has gained since: a surviving speculative clone after its
    /// ancestor committed. O(delta · log n).
    pub fn absorb(&mut self) {
        if self.added.is_empty() {
            return;
        }
        let base = self.base();
        self.added.retain(|x| !base.contains(x));
    }

    /// A private copy of the base, so this value's lineage stops sharing with the one it was
    /// cloned from. O(state); `HotStuff::new` only.
    pub fn detach(&mut self) {
        let copy = self.base().clone();
        self.base = Arc::new(RwLock::new(copy));
    }
}

impl PartialEq for SharedSet {
    fn eq(&self, other: &SharedSet) -> bool {
        if Arc::ptr_eq(&self.base, &other.base) && self.added == other.added {
            return true;
        }
        self.len() == other.len() && self.snapshot() == other.snapshot()
    }
}

impl Eq for SharedSet {}
```

- [ ] **Step 4: Run the new tests**

Run: `cargo test -p randprotocol-core shared_set:: 2>&1 | tail -8`. Expected: 5 PASS.

- [ ] **Step 5: Swap the ledger's fields**

In `ledger/mod.rs`:

1. Fields (`:579-580`): `commitments: SharedSet,` and `nullifiers: SharedSet,`. Rewrite the struct doc comment at `:561-569` to say: cloning is O(delta) since the sets are `SharedSet` (base shared, delta owned), the base moves only at `HotStuff` commit; keep the audit-v6 measurement sentence as history.
2. `Ledger::new` (`:848-849`): `commitments: SharedSet::new(), nullifiers: SharedSet::new(),`.
3. `from_parts` (`:912-913`): `commitments: SharedSet::from_set(commitments), nullifiers: SharedSet::from_set(nullifiers),` — the parameter types stay `BTreeSet<Word8>`.
4. Accessors (`:1699`, `:1708`): return `&SharedSet`. `is_spent` / `has_commitment` are unchanged (`.contains`).
5. `state_root_leaves` (`:2969-2975`): replace the `.iter().map(..).collect()` with
   ```rust
   let mut nf_leaves: Vec<Hash> = Vec::with_capacity(self.nullifiers.len());
   self.nullifiers.for_each_sorted(|nf| nf_leaves.push(Hash::digest_domain(b"rand-nullifier-leaf", &word8_to_bytes(nf))));
   ```
6. Add after `set_tokens_incremental_root` (~`:1346`):
   ```rust
   /// The commit step of the shared sets (spec 2026-10-05 §5.2): the committed ledger's deltas
   /// become base. `HotStuff` calls it once per commit, on the committed ledger only.
   pub fn commit_shared_sets(&mut self) {
       self.commitments.commit();
       self.nullifiers.commit();
   }

   /// Drop delta entries the base gained: every surviving speculative ledger, after a commit.
   pub fn absorb_shared_sets(&mut self) {
       self.commitments.absorb();
       self.nullifiers.absorb();
   }

   /// A private base for this ledger's lineage (`HotStuff::new`): a replica must not share a
   /// base with the genesis state or with another replica in the same process.
   pub fn detach_shared_sets(&mut self) {
       self.commitments.detach();
       self.nullifiers.detach();
   }
   ```
7. The manual `PartialEq` at `:790-791` compiles unchanged (`SharedSet: PartialEq`).
8. Test at `:5072-5073`: `l.commitments_set().snapshot(), l.nullifiers().snapshot()`.
9. `aggregation.rs:927-929` test helper: replace `l.nullifiers().iter().map(..)` with a `for_each_sorted` push into a `Vec<Hash>`, same leaf domain.

Run `cargo build -p randprotocol-core -p randprotocol-node 2>&1 | grep -E "^error" -A 5 | head -40` and fix any remaining call site the same way (the explorer's list: `node.rs:2459` uses `.len()` and compiles; the zkvm crate's `ledger.rs` is its own type).

- [ ] **Step 6: Add the ledger-level test**

In `ledger/mod.rs` tests (next to `state_root_covers_tree_nullifiers_validators_and_programs`):

```rust
    /// Spec 2026-10-05 §5.3: a clone taken before a commit keeps answering, and the committed
    /// ledger's delta is empty after the commit step.
    #[test]
    fn shared_sets_commit_and_a_pre_commit_clone_still_answers() {
        let (a, _) = keys();
        let mut l = ledger();
        let t1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let good = signed_block(vec![t1], &a, 1, root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1));
        let snapshot = l.clone();
        l.apply_block(&good, &StubExecutor).unwrap();
        assert_eq!(l.nullifiers().added_len(), 2);
        l.commit_shared_sets();
        assert_eq!((l.nullifiers().added_len(), l.nullifiers().len()), (0, 2));
        assert!(l.is_spent(&[1; 8]));
        // The snapshot shares the base and now sees the committed spends — by design, since every
        // live clone descends from the committed head; its len() is exact.
        assert!(snapshot.is_spent(&[1; 8]));
        assert_eq!(snapshot.nullifiers().len(), 2);
    }
```
(`keys`, `ledger`, `tx`, `signed_block`, `root_after` are the existing helpers in that test module; `tx` builds the same bundle twice because `Transaction` is consumed by the block.)

- [ ] **Step 7: Run the whole core and node suites**

Run: `cargo test -p randprotocol-core 2>&1 | tail -4 && cargo test -p randprotocol-node 2>&1 | tail -4`
Expected: all PASS. The consensus simulator tests exercise clone-heavy paths and must be green here before Task 3 touches HotStuff.

- [ ] **Step 8: Clippy, commit**

```bash
cargo clippy -p randprotocol-core -p randprotocol-node --all-targets -- -D warnings 2>&1 | tail -3
git add crates/randprotocol-core/src/ledger/shared_set.rs crates/randprotocol-core/src/ledger/mod.rs crates/randprotocol-core/src/ledger/aggregation.rs
git commit -m "ledger: SharedSet — commitments and nullifiers as a shared committed base plus an owned delta; a Ledger clone is O(delta), the base moves only at commit

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 3: HotStuff commits the shared sets

**Files:**
- Modify: `crates/randprotocol-core/src/consensus/hotstuff.rs` — `new` (`:187-215`), `resume` (`:217-`), `update_lock_and_commit` tail (`:1539-1554`)
- Test: `crates/randprotocol-core/src/consensus/tests.rs`

**Interfaces:**
- Consumes: `Ledger::{commit_shared_sets, absorb_shared_sets, detach_shared_sets}`, `SharedSet::added_len`.
- Produces: `HotStuff::speculative_delta_len(&self) -> usize` (`#[cfg(test)]`-visible via `pub fn`, the sum of `nullifiers().added_len()` over tree entries), used by the test here and by nothing else.

- [ ] **Step 1: Write the failing test**

In `consensus/tests.rs`, next to `commit_rule_requires_three_consecutive_views` (~`:1606`), using the `one_node()` driver:

```rust
/// Spec 2026-10-05 §5.2: after a commit the committed ledger's delta is empty and the surviving
/// speculative entries hold only the blocks above the head — the tree's memory is O(block), not
/// O(state).
#[test]
fn commit_drains_the_shared_sets_and_survivors_absorb() {
    let mut n = one_node();
    n.node.start();
    // Each block spends two fresh nullifiers; `one_node` proposes empty blocks, so drive
    // proposals with a candidate (see `tx_at` below).
    for view in 1..=8u64 {
        n.now += 1;
        let tx = tx_at(n.node.tip_ledger(), view);
        n.node.propose(view, vec![tx], n.now).expect("propose");
    }
    assert!(n.node.committed_height() >= 4, "three-chain commits happened");
    assert_eq!(n.node.committed_ledger().nullifiers().added_len(), 0, "the committed ledger's delta was drained");
    let above_head = n.node.tip_ledger().height() - n.node.committed_height();
    assert_eq!(n.node.tip_ledger().nullifiers().added_len() as u64, 2 * above_head, "the tip holds exactly the blocks above the head");
    assert!(n.node.committed_ledger().is_spent(&[1, 0, 0, 0, 0, 0, 0, 0]), "the first block's spend is in the base");
}
```
`tx_at(ledger, k)`: a synthetic bundle with nullifiers `[k as u32,0,..]`, `[k as u32 + 1000,0,..]` and two fresh commitments, anchored at `ledger.root()`, `time: k as u32`, stub-proved for `one_node_parts`'s `hc_bundle` and `StubExecutor::bound`. If `tests.rs` already has such a helper (search `fn bundle_tx\|fn spend\|Transaction::shielded`), use it; else add one modelled on `ledger/mod.rs` test helpers `bundle4` + `restub` + `tx` with the fixture's `HC` (`[3; 8]` in `build_with`).

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p randprotocol-core commit_drains_the_shared_sets 2>&1 | tail -6`
Expected: FAIL at the `added_len() == 0` assertion (nothing drains yet).

- [ ] **Step 3: Implement**

In `hotstuff.rs`:

1. `new`: first line of the body: `let mut genesis_ledger = genesis_ledger; genesis_ledger.detach_shared_sets();` with the comment: `// A replica's lineage owns its base (spec 2026-10-05 §5): the genesis ledger the caller keeps, and any other replica built from it, must not see this one's commits.`
2. `resume`: first line: `let mut head_ledger = head_ledger; head_ledger.commit_shared_sets();` with the comment: `// A synced ledger arrives as the old replica's committed ledger plus the synced blocks in its delta; fold them in — the old replica is being replaced, and its tree is dropped with it.`
3. `update_lock_and_commit`, after `self.prune();` (line ~1545):
   ```rust
        // The shared sets' commit step (spec 2026-10-05 §5.2), after `prune` so every entry left
        // in the tree descends from the new head and already holds this delta: the committed
        // ledger's delta becomes base, and each survivor drops what the base now has.
        self.committed_ledger.commit_shared_sets();
        for e in self.tree.values_mut() {
            e.ledger_after.absorb_shared_sets();
        }
   ```

- [ ] **Step 4: Run the consensus suite**

Run: `cargo test -p randprotocol-core consensus:: 2>&1 | tail -4`
Expected: all PASS including the new test. If a simulator test that builds several replicas from one `gs.ledger` fails with cross-replica state, `new`'s detach is missing on that path.

- [ ] **Step 5: Node suite, clippy, commit**

```bash
cargo test -p randprotocol-node 2>&1 | tail -3
cargo clippy -p randprotocol-core --all-targets -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-core/src/consensus/hotstuff.rs crates/randprotocol-core/src/consensus/tests.rs
git commit -m "consensus: the shared sets' commit step — the committed ledger drains its delta into the base after prune, survivors absorb; new detaches, resume folds

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 4: `propose` applies candidates without a clone per candidate

**Files:**
- Modify: `crates/randprotocol-core/src/consensus/hotstuff.rs:1313-1327`
- Test: `crates/randprotocol-core/src/consensus/tests.rs`

**Interfaces:**
- Produces: `pub const MAX_PROPOSE_REPLAYS: usize = 8;` in `hotstuff.rs`.

- [ ] **Step 1: Write the failing test**

In `consensus/tests.rs` (Review Focus item 2):

```rust
/// Spec 2026-10-05 (plan correction 2): the proposer no longer clones the ledger per candidate.
/// A candidate that fails after accepted ones changed state (the second spends the first's
/// nullifier) is dropped, the accepted set is replayed, and the header's state root is the one a
/// replica recomputes from the block — with the failing candidate absent and the third present.
#[test]
fn a_failing_candidate_is_dropped_and_the_block_still_verifies() {
    let mut n = one_node();
    n.node.start();
    n.now += 1;
    let tip = n.node.tip_ledger().clone();
    let ok1 = tx_at(&tip, 1);
    let mut dup = tx_at(&tip, 2);
    // The double spend: dup's first nullifier is ok1's first nullifier.
    dup.bundle.as_mut().unwrap().nullifiers[0] = ok1.bundle.as_ref().unwrap().nullifiers[0];
    let dup = restub_and_bind(dup);
    let ok3 = tx_at(&tip, 3);
    let actions = n.node.propose(1, vec![ok1.clone(), dup, ok3.clone()], n.now).expect("propose");
    let block = actions.iter().find_map(|a| match a { Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b.clone()), _ => None }).unwrap();
    assert_eq!(block.transactions, vec![ok1, ok3], "the double spend is dropped, the third candidate kept");
    let mut replica = tip.clone();
    replica.apply_block_for_sync(&block, &Default::default(), &[], &StubExecutor, &crate::ledger::NoVerified).expect("the header's root is what a replica computes");
}
```
`restub_and_bind(tx)` re-makes the stub proof over the edited bundle's digest and re-binds (`StubExecutor::bound`); add beside `tx_at` if absent.

- [ ] **Step 2: Run it**

Run: `cargo test -p randprotocol-core a_failing_candidate_is_dropped 2>&1 | tail -6`
Expected: PASS already (the clone-per-candidate code is correct) — this test pins behaviour across the rewrite. Confirm it passes, then continue.

- [ ] **Step 3: Rewrite the candidate loop**

Replace `hotstuff.rs:1315-1327` (from `let mut call_gas = 0u64;` through the closing brace of `for tx in ordinary`) with:

```rust
        // Phase 2 (spec §7.1): the calls' gas, for the controller at the block's end — summed
        // exactly as `apply_block_for_sync` sums its receipts.
        let mut call_gas = 0u64;
        // Candidates apply to the running ledger directly (spec 2026-10-05, plan correction 2):
        // a clone per candidate was 2 000 clones a block. `apply_tx_with` is not atomic on its
        // own (its comment), so a failing candidate is undone by rebuilding from the parent and
        // replaying the accepted ones in order — deterministic, so the replay cannot fail; if it
        // ever did, the block closes with no ordinary transactions rather than a wrong root.
        // Replays are bounded: after MAX_PROPOSE_REPLAYS the block closes with what it has.
        let base = ledger.clone();
        let mut replays = 0usize;
        for tx in ordinary {
            match ledger.apply_tx_with(&tx, &me, self.executor.as_ref(), self.verified.as_ref()) {
                Ok(receipt) => {
                    call_gas = call_gas.saturating_add(receipt.map_or(0, |r| r.gas_used));
                    txs.push(tx);
                }
                Err(_) => {
                    replays += 1;
                    ledger = base.clone();
                    call_gas = 0;
                    let mut replayed = true;
                    for t in &txs {
                        match ledger.apply_tx_with(t, &me, self.executor.as_ref(), self.verified.as_ref()) {
                            Ok(r) => call_gas = call_gas.saturating_add(r.map_or(0, |r| r.gas_used)),
                            Err(_) => { replayed = false; break; }
                        }
                    }
                    if !replayed {
                        ledger = base.clone();
                        call_gas = 0;
                        txs.clear();
                    }
                    if replays >= MAX_PROPOSE_REPLAYS {
                        break;
                    }
                }
            }
        }
```
Add near the other constants at the top of `hotstuff.rs`:
```rust
/// How many failing candidates one proposal tolerates before it closes the block with the
/// candidates it has (spec 2026-10-05): each failure replays the accepted set, O(accepted), so
/// a mempool that admitted many mutually conflicting candidates cannot make a proposal quadratic.
pub const MAX_PROPOSE_REPLAYS: usize = 8;
```
Check `base` is not needed by the aggregate loop below (it uses `ledger.clone()` once per aggregate; leave it).

- [ ] **Step 4: Add the bound test**

```rust
#[test]
fn a_proposal_closes_after_max_replays() {
    let mut n = one_node();
    n.node.start();
    n.now += 1;
    let tip = n.node.tip_ledger().clone();
    let ok = tx_at(&tip, 1);
    let mut cands = vec![ok.clone()];
    // MAX_PROPOSE_REPLAYS + 1 double spends of `ok`, then one good candidate that is never reached.
    for k in 0..=MAX_PROPOSE_REPLAYS {
        let mut d = tx_at(&tip, 100 + k as u64);
        d.bundle.as_mut().unwrap().nullifiers[0] = ok.bundle.as_ref().unwrap().nullifiers[0];
        cands.push(restub_and_bind(d));
    }
    cands.push(tx_at(&tip, 50));
    let actions = n.node.propose(1, cands, n.now).unwrap();
    let block = actions.iter().find_map(|a| match a { Action::Broadcast(ConsensusMessage::Proposal(b)) => Some(b.clone()), _ => None }).unwrap();
    assert_eq!(block.transactions.len(), 1, "closed after the bound; the trailing good candidate waits for the next block");
}
```
Import `MAX_PROPOSE_REPLAYS` in the test module (`use super::hotstuff::MAX_PROPOSE_REPLAYS;` or via `crate::consensus::`; re-export from `consensus/mod.rs` if `hotstuff` is private).

- [ ] **Step 5: Run, clippy, commit**

```bash
cargo test -p randprotocol-core consensus:: 2>&1 | tail -4
cargo test -p randprotocol-node 2>&1 | tail -3
cargo clippy -p randprotocol-core --all-targets -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-core/src/consensus/hotstuff.rs crates/randprotocol-core/src/consensus/tests.rs crates/randprotocol-core/src/consensus/mod.rs
git commit -m "consensus: propose applies candidates without a clone each — replay the accepted set on a failure, at most MAX_PROPOSE_REPLAYS a block

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

- [ ] **Step 6: Re-run the harness**

```bash
cargo build --release -p randprotocol-node 2>&1 | tail -1
./target/release/rand-node bench apply --blocks 300 --report-every 50 --fail-over-ms 100000 | tee /tmp/bench-sharedset-300.txt
```
Expected: `clone_ms` flat in the microseconds, `propose_ms` and `apply_ms` roughly flat, `root_ms` still growing (the sorted root, fixed in Task 6). Keep the file for Task 10.

---

### Task 5: `NullifierMmr`

**Files:**
- Create: `crates/randprotocol-core/src/ledger/nullifier_mmr.rs`
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (`pub mod nullifier_mmr;`)
- Test: unit tests in the new file

**Interfaces:**
- Produces:
  ```rust
  #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
  pub struct NullifierMmr { peaks: Vec<Hash>, count: u64 }
  impl NullifierMmr {
      pub fn new() -> NullifierMmr;
      pub fn append(&mut self, nf: &Word8);
      pub fn root(&self) -> Hash;
      pub fn count(&self) -> u64;
      pub fn peaks(&self) -> &[Hash];
  }
  pub fn leaf(nf: &Word8) -> Hash;                 // blake3("rand-nullifier-leaf" ‖ nf)
  pub fn node(left: &Hash, right: &Hash) -> Hash;  // blake3("rand-nullifier-mmr-node" ‖ l ‖ r)
  pub const ROOT_DOMAIN: &[u8] = b"rand-nullifier-mmr-1";
  ```

- [ ] **Step 1: Write the failing tests**

```rust
//! The incremental nullifier root (spec 2026-10-05 §4): a Merkle Mountain Range over
//! nullifiers in insertion order. `O(log n)` state — the peaks and a count — and `O(log n)` per
//! append, where the sorted root `state_root_leaves` computes today is `O(n)` per block. The
//! leaf hash is the sorted root's leaf hash; the node and root domains are this range's own.
//! Insertion order is block order, action order, nullifier slot order (`apply_bundle_notes`).

#[cfg(test)]
mod tests {
    use super::*;

    fn nf(n: u32) -> Word8 { [n, n, 0, 0, 0, 0, 0, 1] }

    /// The root computed from scratch: the leaves split into perfect trees by the binary
    /// decomposition of the count, left to right, bagged from the right.
    fn reference_root(nfs: &[Word8]) -> Hash {
        fn perfect(leaves: &[Hash]) -> Hash {
            if leaves.len() == 1 { return leaves[0]; }
            let (l, r) = leaves.split_at(leaves.len() / 2);
            node(&perfect(l), &perfect(r))
        }
        let leaves: Vec<Hash> = nfs.iter().map(leaf).collect();
        let mut peaks = Vec::new();
        let mut rest = &leaves[..];
        let mut bit = 63;
        while !rest.is_empty() {
            let size = 1usize << bit;
            if rest.len() >= size { let (p, r) = rest.split_at(size); peaks.push(perfect(p)); rest = r; }
            if bit == 0 { break; }
            bit -= 1;
        }
        let mut buf = (nfs.len() as u64).to_be_bytes().to_vec();
        if let Some((last, others)) = peaks.split_last() {
            let bag = others.iter().rev().fold(*last, |acc, p| node(p, &acc));
            buf.extend_from_slice(bag.as_bytes());
        }
        Hash::digest_domain(ROOT_DOMAIN, &buf)
    }

    #[test]
    fn the_range_root_is_the_reference_root_for_every_count_to_70() {
        let mut m = NullifierMmr::new();
        let mut all = Vec::new();
        assert_eq!(m.root(), reference_root(&[]), "empty");
        for n in 0..70u32 {
            all.push(nf(n));
            m.append(&nf(n));
            assert_eq!(m.count(), all.len() as u64);
            assert_eq!(m.root(), reference_root(&all), "{} leaves", all.len());
            assert_eq!(m.peaks().len() as u32, (all.len() as u64).count_ones(), "one peak per set bit");
        }
    }

    #[test]
    fn order_matters_and_equal_sequences_agree() {
        let mut a = NullifierMmr::new();
        let mut b = NullifierMmr::new();
        for n in 0..9u32 { a.append(&nf(n)); b.append(&nf(n)); }
        assert_eq!(a, b);
        assert_eq!(a.root(), b.root());
        let mut c = NullifierMmr::new();
        for n in (0..9u32).rev() { c.append(&nf(n)); }
        assert_ne!(a.root(), c.root(), "a permutation is a different range");
    }

    #[test]
    fn the_root_binds_the_count_and_survives_a_serde_round_trip() {
        let mut a = NullifierMmr::new();
        a.append(&nf(1));
        let bytes = bincode::serialize(&a).unwrap();
        let back: NullifierMmr = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, a);
        assert_eq!(back.root(), a.root());
        let empty = NullifierMmr::new();
        assert_ne!(empty.root(), Hash::ZERO);
        assert_ne!(empty.root(), a.root());
    }
}
```

- [ ] **Step 2: Run to see them fail**

Add `pub mod nullifier_mmr;` to `ledger/mod.rs`. Run `cargo test -p randprotocol-core nullifier_mmr:: 2>&1 | tail -4`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
use crate::crypto::Hash;
use crate::notes::{word8_to_bytes, Word8};
use serde::{Deserialize, Serialize};

pub const ROOT_DOMAIN: &[u8] = b"rand-nullifier-mmr-1";
const NODE_DOMAIN: &[u8] = b"rand-nullifier-mmr-node";

/// The sorted root's leaf hash, unchanged, so the two roots commit the same leaves.
pub fn leaf(nf: &Word8) -> Hash {
    Hash::digest_domain(b"rand-nullifier-leaf", &word8_to_bytes(nf))
}

pub fn node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_bytes());
    buf[32..].copy_from_slice(right.as_bytes());
    Hash::digest_domain(NODE_DOMAIN, &buf)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierMmr {
    /// Peaks of the perfect subtrees, largest first — one per set bit of `count`, high bit first.
    peaks: Vec<Hash>,
    count: u64,
}

impl NullifierMmr {
    pub fn new() -> NullifierMmr {
        NullifierMmr::default()
    }

    /// Append one leaf: the binary-counter step. Each trailing 1 bit of the old count is a peak
    /// of the same height as the new node, merged right-to-left.
    pub fn append(&mut self, nf: &Word8) {
        let mut acc = leaf(nf);
        let mut c = self.count;
        while c & 1 == 1 {
            let left = self.peaks.pop().expect("a set bit has a peak");
            acc = node(&left, &acc);
            c >>= 1;
        }
        self.peaks.push(acc);
        self.count += 1;
    }

    /// `blake3(ROOT_DOMAIN ‖ count_be(8) ‖ bag)`, bag folding the peaks from the smallest:
    /// `bag = node(peak_i, bag_{i+1})`, `bag_last = peak_last`. Empty: the count alone.
    pub fn root(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + 32);
        buf.extend_from_slice(&self.count.to_be_bytes());
        if let Some((last, others)) = self.peaks.split_last() {
            let bag = others.iter().rev().fold(*last, |acc, p| node(p, &acc));
            buf.extend_from_slice(bag.as_bytes());
        }
        Hash::digest_domain(ROOT_DOMAIN, &buf)
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn peaks(&self) -> &[Hash] {
        &self.peaks
    }
}
```

- [ ] **Step 4: Run, clippy, commit**

```bash
cargo test -p randprotocol-core nullifier_mmr:: 2>&1 | tail -6
cargo clippy -p randprotocol-core --all-targets -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-core/src/ledger/nullifier_mmr.rs crates/randprotocol-core/src/ledger/mod.rs
git commit -m "ledger: NullifierMmr — a Merkle Mountain Range over nullifiers in insertion order, peaks and count, O(log n) per append

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 6: the genesis flag, the ledger's accumulator and the state root

**Files:**
- Modify: `crates/randprotocol-core/src/genesis.rs` — `Genesis` struct (add field after `program_state`, `:482-490`), `build` tag block (`:1475-1484`), where `registry.with_incremental_root` is applied (`:1059-1061`, for the ledger flag)
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` — field, `new`, `from_parts`, `eq`, `apply_bundle_notes` (`:1792-1800`), `state_root_leaves` (`:2969`), `state_root` (`:3108`), `debug_state_root_components`
- Modify: `crates/randprotocol-node/src/main.rs` (`Genesis` command flag beside `--tokens-incremental-root`, `:472` and `:1639-1673`; the harness genesis in `bench.rs`)
- Test: `genesis.rs` tests, `ledger/mod.rs` tests, `bench.rs`

**Interfaces:**
- Produces: `Genesis.incremental_nullifier_root: Option<bool>`; `Ledger::set_incremental_nullifier_root(&mut self, on: bool)` (on an empty nullifier set only; a non-empty set with `on == true` is a programming error and panics with a message — storage restores a loaded range with `set_nullifier_mmr`); `Ledger::set_nullifier_mmr(&mut self, mmr: Option<NullifierMmr>)`; `Ledger::nullifier_mmr(&self) -> Option<&NullifierMmr>`; `Ledger::incremental_nullifier_root(&self) -> bool`.
- Consumed by Task 7 (storage) and Task 1's harness.

- [ ] **Step 1: Write the failing tests**

In `ledger/mod.rs` tests:

```rust
    /// Spec 2026-10-05 §4.3: without the flag the state root is byte-identical to before (a
    /// chain-20-shaped ledger); with it the nullifier slot holds the range root and the whole is
    /// re-domained `rand-state-nf-mmr-1` once.
    #[test]
    fn the_incremental_nullifier_root_is_gated_and_wrapped_once() {
        let (a, _) = keys();
        let mut off = ledger();
        let mut on = ledger();
        on.set_incremental_nullifier_root(true);
        assert_eq!(off.state_root(), ledger().state_root(), "the flag is off by default");
        let before_on = on.state_root();
        assert_ne!(before_on, off.state_root(), "the wrapper changes an empty ledger's root");
        for l in [&mut off, &mut on] {
            let t = tx(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
            let root = root_after(l, &[tx(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
            l.apply_block(&signed_block(vec![t], &a, 1, root), &StubExecutor).unwrap();
        }
        assert_eq!(on.nullifier_mmr().unwrap().count(), 2);
        assert_ne!(on.state_root(), off.state_root(), "the slot swap and the wrapper both move the root");
        assert_eq!(off.state_root(), ledger_after_same_block_flag_off(&a), "the flag-off root is what it was");
        // Determinism: the same blocks on a fresh flag-on ledger give the same root.
        let mut again = ledger();
        again.set_incremental_nullifier_root(true);
        let t = tx(&again, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let root = root_after(&again, &[tx(&again, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
        again.apply_block(&signed_block(vec![t], &a, 1, root), &StubExecutor).unwrap();
        assert_eq!(again.state_root(), on.state_root());
        assert_eq!(again, on, "equality covers the range");
    }

    /// The flag-off root for the same block, computed on a fresh ledger with no reference to the
    /// new code paths: pins "byte-identical to before" without a hard-coded hash.
    fn ledger_after_same_block_flag_off(a: &Keypair) -> Hash {
        let mut l = ledger();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let root = root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
        l.apply_block(&signed_block(vec![t], a, 1, root), &StubExecutor).unwrap();
        l.state_root()
    }

    #[test]
    #[should_panic(expected = "insertion order")]
    fn the_flag_cannot_be_switched_on_over_existing_nullifiers() {
        let (a, _) = keys();
        let mut l = ledger();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let root = root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
        l.apply_block(&signed_block(vec![t], &a, 1, root), &StubExecutor).unwrap();
        l.set_incremental_nullifier_root(true);
    }
```

In `genesis.rs` tests (beside the `tokens_incremental_root` hash test ~`:2515`):

```rust
    /// Spec 2026-10-05 §4.1: `incremental_nullifier_root: true` is tagged after
    /// `tokens_incremental_root` and switches the ledger; absent or `false` changes no hash.
    #[test]
    fn incremental_nullifier_root_is_tagged_last_and_switches_the_ledger() {
        let base = minimal_genesis(); // the file's existing minimal fixture; use its name
        let mut off = base.clone();
        off.incremental_nullifier_root = Some(false);
        assert_eq!(build(&off).hash(), build(&base).hash(), "false commits nothing");
        let mut on = base.clone();
        on.incremental_nullifier_root = Some(true);
        let gs = build(&on);
        assert_ne!(gs.hash(), build(&base).hash());
        assert!(gs.ledger.incremental_nullifier_root());
        assert_eq!(gs.ledger.nullifier_mmr().unwrap().count(), 0);
        // Round trip through the genesis file form.
        let json = serde_json::to_string(&on).unwrap();
        let back: Genesis = serde_json::from_str(&json).unwrap();
        assert_eq!(back, on);
    }
```
Use whatever the file's minimal `Genesis` fixture is called (search `fn minimal\|fn base_genesis\|fn genesis()` in genesis.rs tests).

- [ ] **Step 2: Run to see them fail**

Run: `cargo test -p randprotocol-core incremental_nullifier_root 2>&1 | tail -6`. Expected: compile errors.

- [ ] **Step 3: Implement in the ledger**

In `ledger/mod.rs`:
1. Field after `nullifiers`: 
   ```rust
   /// The incremental nullifier root (spec 2026-10-05 §4) under genesis
   /// `incremental_nullifier_root`: a range over the nullifiers in insertion order, whose root
   /// takes the sorted root's slot. `None` on every chain through 20.
   nullifier_mmr: Option<nullifier_mmr::NullifierMmr>,
   ```
   `new` and `from_parts`: `nullifier_mmr: None`. `eq`: `&& self.nullifier_mmr == o.nullifier_mmr` beside the nullifiers comparison.
2. Setters/getters beside `set_tokens_incremental_root`:
   ```rust
   /// Switch the incremental nullifier root on or off. On is only ever set on an empty set —
   /// genesis — because the range needs insertion order, which the set does not have; a loaded
   /// chain restores its range with [`Self::set_nullifier_mmr`].
   pub fn set_incremental_nullifier_root(&mut self, on: bool) {
       match (on, &self.nullifier_mmr) {
           (true, None) => {
               assert!(self.nullifiers.is_empty(), "the incremental nullifier root needs insertion order; it can only be switched on at genesis, not over {} existing nullifiers", self.nullifiers.len());
               self.nullifier_mmr = Some(nullifier_mmr::NullifierMmr::new());
           }
           (false, Some(_)) => self.nullifier_mmr = None,
           _ => {}
       }
   }

   pub fn set_nullifier_mmr(&mut self, mmr: Option<nullifier_mmr::NullifierMmr>) {
       self.nullifier_mmr = mmr;
   }

   pub fn nullifier_mmr(&self) -> Option<&nullifier_mmr::NullifierMmr> {
       self.nullifier_mmr.as_ref()
   }

   pub fn incremental_nullifier_root(&self) -> bool {
       self.nullifier_mmr.is_some()
   }
   ```
3. `apply_bundle_notes`:
   ```rust
   for nf in &b.nullifiers {
       if self.nullifiers.insert(*nf) {
           if let Some(m) = &mut self.nullifier_mmr {
               m.append(nf);
           }
       }
   }
   ```
4. `state_root_leaves`: compute `nf_root` as
   ```rust
   let nf_root = match &self.nullifier_mmr {
       Some(m) => m.root(),
       None => {
           let mut nf_leaves: Vec<Hash> = Vec::with_capacity(self.nullifiers.len());
           self.nullifiers.for_each_sorted(|nf| nf_leaves.push(nullifier_mmr::leaf(nf)));
           merkle_root(&nf_leaves)
       }
   };
   ```
   and return `(nf_root, merkle_root(&val_leaves), merkle_root(&prog_leaves))`. Update the function's doc comment: under the flag the slot holds the range root.
5. `state_root`: directly after the `rand-state-tokens-1` block:
   ```rust
   // The incremental nullifier root (spec 2026-10-05 §4.3): the range root already sits in the
   // nullifier slot of the base; the wrapper keeps a flag-on chain from ever colliding with a
   // flag-off chain whose sorted root happened to equal it. After the tokens wrapper, before the
   // staking wrappers — the order is fixed here.
   if self.nullifier_mmr.is_some() {
       root = Hash::digest_domain(b"rand-state-nf-mmr-1", root.as_bytes());
   }
   ```
6. `debug_state_root_components`: append `format!(" nullifier range {}", match &self.nullifier_mmr { Some(m) => format!("{} leaves", m.count()), None => "off".into() })`.

- [ ] **Step 4: Implement in genesis**

In `genesis.rs`:
1. Field after `program_state`:
   ```rust
   /// Spec 2026-10-05 §4: the nullifier root as an incremental range in insertion order
   /// (`rand-state-nf-mmr-1`) instead of a sorted root recomputed over every nullifier each
   /// block. Absent or `false` (every chain through 20) changes nothing; `true` is committed
   /// under its own tag (`b"incremental_nullifier_root"` ‖ `1`), after `tokens_incremental_root`
   /// — last — and switches the ledger at `build`.
   #[serde(default, skip_serializing_if = "Option::is_none")]
   pub incremental_nullifier_root: Option<bool>,
   ```
   Every `Genesis { .. }` literal in the crate's tests and in `tests.rs` `build_with` gains `incremental_nullifier_root: None,` (run `cargo build --all-targets -p randprotocol-core -p randprotocol-node 2>&1 | grep -c "missing field"` to find them; the node's `main.rs` genesis builder too).
2. In `build`, immediately after the `tokens_incremental_root` tag block (`:1475-1478`) and before `let genesis_binding`:
   ```rust
   // The incremental nullifier root (spec 2026-10-05 §4.1), after `tokens_incremental_root`:
   // tagged only when `true`, so every genesis cut before it hashes as before.
   if self.incremental_nullifier_root == Some(true) {
       commit.extend_from_slice(b"incremental_nullifier_root");
       commit.push(1);
   }
   ```
   and, where the ledger is configured (next to `:1059-1061`'s token-registry switch, before the header's `state_root: ledger.state_root()` is computed):
   ```rust
   if self.incremental_nullifier_root == Some(true) {
       ledger.set_incremental_nullifier_root(true);
   }
   ```
   (The ledger variable's name at that point is whatever `build` uses; it is `ledger` at the header.)
3. `main.rs`: beside `--tokens-incremental-root` on the `Genesis` command, add `#[arg(long)] incremental_nullifier_root: bool,` with the doc comment `/// Cut the genesis with incremental_nullifier_root: true (spec 2026-10-05 §4).` and in the builder set `g.incremental_nullifier_root = incremental_nullifier_root.then_some(true);`.
4. `bench.rs`: replace the `let _ = incremental_nullifier_root;` line with the field `incremental_nullifier_root: incremental_nullifier_root.then_some(true),` in the `Genesis` literal, and delete the Task-1 note.

- [ ] **Step 5: Run the suites**

```bash
cargo test -p randprotocol-core 2>&1 | tail -4
cargo test -p randprotocol-node 2>&1 | tail -4
```
Expected: all PASS, including the two new ledger tests, the genesis test, and the bench smoke test. If a genesis-hash pinning test fails for an existing chain, the tag was placed before an existing tag — move it last.

- [ ] **Step 6: Harness with the flag, clippy, commit**

```bash
cargo build --release -p randprotocol-node 2>&1 | tail -1
./target/release/rand-node bench apply --blocks 300 --report-every 50 --fail-over-ms 100000 --incremental-nullifier-root | tee /tmp/bench-mmr-300.txt
cargo clippy -p randprotocol-core -p randprotocol-node --all-targets -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-core/src/genesis.rs crates/randprotocol-core/src/ledger/mod.rs crates/randprotocol-core/src/consensus/tests.rs crates/randprotocol-node/src/main.rs crates/randprotocol-node/src/bench.rs
git commit -m "genesis, ledger: incremental_nullifier_root — the range root in the nullifier slot, rand-state-nf-mmr-1 wrapper, tagged after tokens_incremental_root; rand-node genesis --incremental-nullifier-root; bench apply --incremental-nullifier-root

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```
Expected in the harness: `root_ms` flat and small with the flag.

---

### Task 7: persisting the range

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs` — META constants (`:155-325`), `init_genesis` (`:1030`), `commit` (`:2886`), `truncate_to` (`:3700`), `load_ledger` (`:2505-2574`), `verify_chain` (`:3391`)
- Modify: `crates/randprotocol-node/src/node.rs` — `reload_ledger` (`:159-263`)
- Test: `storage.rs` tests (beside `reload_ledger_restores_the_incremental_token_root_from_the_genesis`, `:5905`)

**Interfaces:**
- Produces: `const META_NULLIFIER_MMR: &str = "nullifier_mmr";`, `Storage::nullifier_mmr(&self) -> Result<Option<NullifierMmr>>`.

- [ ] **Step 1: Write the failing tests**

In `storage.rs` tests, modelled on the TOK-1 reload test at `:5905` (copy its fixture setup for a genesis with the flag on, applying one block with a bundle):

```rust
    /// Spec 2026-10-05 §4.4: the range rides the commit batch beside the frontier, a reload
    /// restores it, and the reloaded ledger is the head state.
    #[test]
    fn reload_ledger_restores_the_nullifier_range_from_the_store() {
        let (dir, gs, s, key) = flag_on_chain_with_one_spend(); // fixture: see below
        let reloaded = crate::node::reload_ledger(&s, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.nullifier_mmr().unwrap().count(), 2);
        let head = s.block_by_height(1).unwrap().unwrap();
        crate::node::snapshot_is_the_head_state(&head, &reloaded).unwrap();
        drop(dir);
    }

    /// Review focus 4: a flag-on store without the row refuses to start, naming the row.
    #[test]
    fn a_flag_on_store_without_the_range_row_is_refused() {
        let (dir, gs, s, _key) = flag_on_chain_with_one_spend();
        s.delete_meta_for_testing(META_NULLIFIER_MMR);
        let err = crate::node::reload_ledger(&s, &gs, &StubExecutor).err().unwrap().to_string();
        assert!(err.contains("nullifier_mmr") && err.contains("re-sync"), "{err}");
        drop(dir);
    }

    /// A flag-off genesis ignores a stray row (a store copied from a flag-on chain is refused
    /// earlier by the genesis-hash check; this is belt and braces).
    #[test]
    fn a_flag_off_genesis_loads_without_a_range() {
        let (dir, gs, s, _key) = flag_off_chain_with_one_spend();
        let reloaded = crate::node::reload_ledger(&s, &gs, &StubExecutor).unwrap();
        assert!(reloaded.nullifier_mmr().is_none());
        drop(dir);
    }
```
Fixtures `flag_on_chain_with_one_spend()` / `flag_off_chain_with_one_spend()`: build the TOK-1 test's genesis with `incremental_nullifier_root: Some(true)` / `None`, `Storage::open` in a `tempfile::tempdir()`, `init_genesis`, build one block with one stub bundle (the `ledger/mod.rs` test helper shape; `storage.rs` tests already have a block-with-bundle helper — search `fn spend_block\|fn bundle_block\|Transaction::shielded` in storage.rs tests) applied to `gs.ledger.clone()`, `s.commit(&[committed_block], &ledger_after, &[], &StubExecutor)`. Add `pub(crate) fn delete_meta_for_testing(&self, key: &str)` beside `plant_nullifier_for_testing` (`:3070`) if no equivalent exists.

- [ ] **Step 2: Run to see them fail**

`cargo test -p randprotocol-node nullifier_range 2>&1 | tail -5` → compile errors.

- [ ] **Step 3: Implement**

`storage.rs`:
1. After `META_TREE` (`:179`):
   ```rust
   /// `bincode(NullifierMmr)`: the incremental nullifier root's peaks and count (spec 2026-10-05
   /// §4.4), written with every commit beside the frontier. Insertion order is not in
   /// `nullifiers` (keyed by value), so this row is the only copy; a flag-on chain without it
   /// cannot start.
   const META_NULLIFIER_MMR: &str = "nullifier_mmr";
   ```
2. A helper used by the three writers:
   ```rust
   fn put_nullifier_mmr(&self, batch: &mut WriteBatch, ledger: &Ledger) -> Result<()> {
       if let Some(m) = ledger.nullifier_mmr() {
           batch.put_cf(self.cf(CF_META), META_NULLIFIER_MMR, bincode::serialize(m)?);
       }
       Ok(())
   }
   ```
   Call it right after each `META_TREE` write: `init_genesis` (`:1030`, with `&gs.ledger`), `commit` (`:2886`, with `ledger_after`), `truncate_to` (`:3700`, with `ledger`).
3. Reader:
   ```rust
   pub fn nullifier_mmr(&self) -> Result<Option<NullifierMmr>> {
       match self.db.get_cf(self.cf(CF_META), META_NULLIFIER_MMR)? {
           Some(v) => Ok(Some(bincode::deserialize(&v)?)),
           None => Ok(None),
       }
   }
   ```
   with `use randprotocol_core::ledger::nullifier_mmr::NullifierMmr;`.
4. `load_ledger`: before `Ok(ledger)`: `ledger.set_nullifier_mmr(self.nullifier_mmr()?);`.
5. `verify_chain` (`:3391`), beside the token-flag line on `stored`: nothing to set (the row loaded it); but the replayed ledger built from `gs.ledger.clone()` carries the flag from genesis, so `stored == ledger` compares ranges too. Add a comment line saying so.

`node.rs` `reload_ledger`, after the `set_tokens_incremental_root` line:
```rust
    // The incremental nullifier root (spec 2026-10-05 §4.4) rides the store's own row; the
    // genesis says whether there must be one. Missing on a flag-on chain is not rebuildable —
    // the row is the only record of insertion order.
    match (gs.ledger.incremental_nullifier_root(), ledger.nullifier_mmr().is_some()) {
        (true, false) => anyhow::bail!(
            "the genesis says incremental_nullifier_root but the database holds no nullifier_mmr row; the store is damaged or predates the flag — re-sync it (from an archive if it is pruned)"
        ),
        (false, true) => ledger.set_nullifier_mmr(None),
        _ => {}
    }
```

- [ ] **Step 4: Run, clippy, commit**

```bash
cargo test -p randprotocol-node 2>&1 | tail -4
cargo clippy -p randprotocol-node --all-targets -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-node/src/storage.rs crates/randprotocol-node/src/node.rs
git commit -m "storage: the nullifier range as a meta row written with every commit, restored at load; a flag-on store without it refuses to start

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 8: verify workers sized to the host

**Files:**
- Modify: `crates/randprotocol-node/src/admission.rs:545-560` (the two constants), `:674` (`for_transaction_hashed`), the `for_transaction` signature
- Modify: `crates/randprotocol-node/src/node.rs:1039-1045` (`Node` fields), `:2224` (channel), `:2504-2527` (`pump_verify`), `:2601`, `:2634` (callers), `:5630` and `:7386-7432` (tests)
- Modify: `crates/randprotocol-node/src/main.rs` (`Run` flag beside `prover_threads`)
- Test: `admission.rs` unit tests

**Interfaces:**
- Produces:
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub struct VerifyLimits { pub in_flight: usize, pub queue: usize }
  impl VerifyLimits {
      pub const FLOOR: usize = 4;               // was MAX_VERIFY_IN_FLIGHT
      pub const QUEUE_PER_WORKER: usize = 16;   // 64 / 4, today's ratio
      pub fn for_cores(cores: usize) -> VerifyLimits;   // in_flight = max(FLOOR, cores.saturating_sub(2)), queue = 16 × in_flight
      pub fn for_host() -> VerifyLimits;                 // for_cores(available_parallelism)
      pub fn fixed(workers: usize) -> Result<VerifyLimits, String>; // 0 refused
  }
  ```
  `GossipOutcome::for_transaction(.., queued: usize, queue_cap: usize, ..)` gains `queue_cap`. `MAX_VERIFY_IN_FLIGHT` / `MAX_VERIFY_QUEUE` are deleted; `NodeConfig.verify_workers: Option<usize>`.

- [ ] **Step 1: Failing tests** (in `admission.rs` tests)

```rust
    #[test]
    fn verify_limits_follow_the_cores_with_a_floor_of_four() {
        assert_eq!(VerifyLimits::for_cores(1), VerifyLimits { in_flight: 4, queue: 64 }, "a two-core droplet is today's 4/64");
        assert_eq!(VerifyLimits::for_cores(6), VerifyLimits { in_flight: 4, queue: 64 });
        assert_eq!(VerifyLimits::for_cores(8), VerifyLimits { in_flight: 6, queue: 96 });
        assert_eq!(VerifyLimits::for_cores(16), VerifyLimits { in_flight: 14, queue: 224 });
        assert_eq!(VerifyLimits::fixed(3).unwrap(), VerifyLimits { in_flight: 3, queue: 48 });
        assert!(VerifyLimits::fixed(0).unwrap_err().contains("at least 1"));
        assert!(VerifyLimits::for_host().in_flight >= 4);
    }
```

- [ ] **Step 2: Run** → compile error. **Step 3: Implement**

Replace the two constants with:
```rust
/// How many proof verifications run on blocking workers at once, and how many wait for a slot
/// (spec 2026-10-05 §6). The floor is today's four: a warm bundle verification is ~20 ms of
/// pure CPU, and a machine that also runs the consensus loop, RocksDB and the RPC server keeps
/// two cores for them. The queue is sixteen per worker (today's 64 for 4): sized against
/// gossipsub's 2.5 s validation window — at ~20 ms a verification, sixteen deep is ~320 ms of
/// work per worker, inside the window even cold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyLimits {
    pub in_flight: usize,
    pub queue: usize,
}

impl VerifyLimits {
    pub const FLOOR: usize = 4;
    pub const QUEUE_PER_WORKER: usize = 16;

    pub fn for_cores(cores: usize) -> VerifyLimits {
        let in_flight = cores.saturating_sub(2).max(Self::FLOOR);
        VerifyLimits { in_flight, queue: in_flight * Self::QUEUE_PER_WORKER }
    }

    pub fn for_host() -> VerifyLimits {
        Self::for_cores(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(Self::FLOOR))
    }

    /// `--verify-workers N`: exactly N, `0` refused — never defaulted, as `--threads 0` is not.
    pub fn fixed(workers: usize) -> Result<VerifyLimits, String> {
        if workers == 0 {
            return Err("--verify-workers must be at least 1".into());
        }
        Ok(VerifyLimits { in_flight: workers, queue: workers * Self::QUEUE_PER_WORKER })
    }
}
```
Then: `for_transaction_hashed` / `for_transaction` take `queue_cap: usize` after `queued` and compare `queued >= queue_cap`. `Node` gets `verify_limits: VerifyLimits`; the channel is `mpsc::channel(limits.in_flight)`; `pump_verify` loops `while self.verify_in_flight < self.verify_limits.in_flight`; the two callers pass `self.verify_limits.queue`. The limits come from `NodeConfig.verify_workers: Option<usize>` → `verify_workers.map(VerifyLimits::fixed).transpose().map_err(anyhow::Error::msg)?.unwrap_or_else(VerifyLimits::for_host)`, logged once at startup: `tracing::info!("verify workers: {} in flight, {} queued", ..)`. `Run` gets `#[arg(long, value_name = "N")] verify_workers: Option<usize>,` with the doc `/// Proof-verification workers (default: the cores minus two, at least four — spec 2026-10-05 §6).`, threaded into `NodeConfig` exactly where `prover_threads` is (`grep -n prover_threads crates/randprotocol-node/src/main.rs crates/randprotocol-node/src/node.rs`). Tests at `node.rs:5630` and `:7386-7432` use `VerifyLimits::for_cores(1)` (the old 4/64) so their expectations hold. Update the doc comments at `node.rs:507, 1038, 1040, 2222` and `rpc.rs:253` that name the constants.

- [ ] **Step 4: Run, clippy, commit**

```bash
cargo test -p randprotocol-node 2>&1 | tail -4
cargo clippy -p randprotocol-node --all-targets -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-node/src/admission.rs crates/randprotocol-node/src/node.rs crates/randprotocol-node/src/main.rs crates/randprotocol-node/src/rpc.rs
git commit -m "node: verify workers sized to the host — cores minus two, floor four, sixteen queued per worker; --verify-workers overrides

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 9: certificate verification, parallel and once

**Files:**
- Modify: `crates/randprotocol-core/src/types/block.rs:124-146` (`QuorumCertificate::verify`)
- Modify: `crates/randprotocol-core/src/consensus/hotstuff.rs` — struct field, `new`/`resume` init, call sites `:944` and `:1149`
- Test: `block.rs` tests, `consensus/tests.rs`

**Interfaces:**
- Produces: `pub const PARALLEL_VERIFY_MIN: usize = 8;` (block.rs); `pub(crate) struct VerifiedQcs` (hotstuff.rs) with `new(cap: usize)`, `check(&mut self, domain: &SigningDomain, qc: &QuorumCertificate, set: &ValidatorSet) -> bool`, `len()`; `pub const VERIFIED_QCS_KEPT: usize = 1024;`.

- [ ] **Step 1: Failing tests**

`block.rs` tests (beside `:293`):
```rust
    /// Spec 2026-10-05 §7.1: the parallel path (≥ PARALLEL_VERIFY_MIN votes) agrees with the
    /// sequential one on a valid certificate and on each kind of invalid one.
    #[test]
    fn parallel_and_sequential_verification_agree() {
        let keys: Vec<Keypair> = (1..=12u8).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
        let vs = ValidatorSet::new(keys.iter().map(|k| Validator { public_key: k.public_key().clone(), stake: 10 }).collect());
        let domain = SigningDomain::v0(Hash([7; 32]));
        let hash = Hash([9; 32]);
        let votes: Vec<Vote> = keys.iter().map(|k| Vote::sign(&domain, 5, hash, k)).collect();
        let good = QuorumCertificate { view: 5, block_hash: hash, votes: votes.clone() };
        assert!(good.verify(&domain, &vs));
        assert!(good.verify_sequential_for_tests(&domain, &vs));
        let mut bad_sig = good.clone();
        bad_sig.votes[11].signature = bad_sig.votes[3].signature.clone();
        let mut wrong_view = good.clone();
        wrong_view.votes[0].view = 6;
        let mut dup = good.clone();
        dup.votes[1] = dup.votes[0].clone();
        let short = QuorumCertificate { view: 5, block_hash: hash, votes: votes[..8].to_vec() };
        let outsider = {
            let k = Keypair::from_seed([99; 32]).unwrap();
            let mut q = good.clone();
            q.votes[2] = Vote::sign(&domain, 5, hash, &k);
            q
        };
        for (name, qc, expect) in [("bad sig", &bad_sig, false), ("wrong view", &wrong_view, false), ("duplicate", &dup, false), ("8 of 12 = quorum", &short, true), ("outsider", &outsider, false)] {
            assert_eq!(qc.verify(&domain, &vs), expect, "{name}");
            assert_eq!(qc.verify_sequential_for_tests(&domain, &vs), expect, "{name} sequential");
        }
    }
```
`consensus/tests.rs`:
```rust
/// Spec 2026-10-05 §7.2 and review focus 5: a certificate is verified once per (bytes, set); the
/// same certificate under another set is verified afresh and may fail.
#[test]
fn a_certificate_is_verified_once_and_the_key_covers_the_set() {
    let mut sim = setup(4, 4);
    for _ in 0..6 { sim.step(vec![]); }
    let n = &mut sim.nodes[0];
    let qc = n.high_qc().clone();
    let set = n.current_set().clone();   // the accessor the epoch tests use; see `set_for_qc`
    let mut cache = crate::consensus::hotstuff::VerifiedQcs::new(8);
    assert!(cache.check(n.domain(), &qc, &set));
    assert_eq!(cache.len(), 1);
    assert!(cache.check(n.domain(), &qc, &set), "cached");
    assert_eq!(cache.len(), 1);
    let other = ValidatorSet::new(vec![Validator { public_key: Keypair::from_seed([77; 32]).unwrap().public_key().clone(), stake: 1 }]);
    assert!(!cache.check(n.domain(), &qc, &other), "voters outside the set: not a quorum, not cached");
    assert_eq!(cache.len(), 1);
}
```
(If `HotStuff` lacks a public `domain()`/`current_set()` accessor, add `pub fn domain(&self) -> &SigningDomain { &self.cfg.domain }` — `tests.rs:1905` already calls `sim.domain()`, so one may exist on `Sim`; use what exists.)

- [ ] **Step 2: Run** → compile errors. **Step 3: Implement**

`block.rs`:
```rust
/// Below this many votes the signatures are checked on the calling thread; a test chain or a
/// small validator set pays no thread cost. Above it they are split across the cores.
pub const PARALLEL_VERIFY_MIN: usize = 8;

impl QuorumCertificate {
    /// Verify every vote under `domain` and that the signers reach quorum stake. The domain's
    /// genesis hash admits the empty genesis QC. The structural checks run first and in order;
    /// the signature checks run across scoped threads when there are enough of them
    /// (spec 2026-10-05 §7.1) — the result is the conjunction either way.
    pub fn verify(&self, domain: &SigningDomain, validators: &ValidatorSet) -> bool {
        self.verify_with(domain, validators, true)
    }

    #[doc(hidden)]
    pub fn verify_sequential_for_tests(&self, domain: &SigningDomain, validators: &ValidatorSet) -> bool {
        self.verify_with(domain, validators, false)
    }

    fn verify_with(&self, domain: &SigningDomain, validators: &ValidatorSet, parallel: bool) -> bool {
        if self.is_genesis() {
            return self.block_hash == domain.genesis;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut stake = 0u128;
        for v in &self.votes {
            if v.view != self.view || v.block_hash != self.block_hash {
                return false;
            }
            let addr = v.voter_address();
            let Some(val) = validators.get(&addr) else { return false };
            if !seen.insert(addr) {
                return false;
            }
            stake += val.stake;
        }
        if !validators.has_quorum(stake) {
            return false;
        }
        if !parallel || self.votes.len() < PARALLEL_VERIFY_MIN {
            return self.votes.iter().all(|v| v.verify(domain));
        }
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, self.votes.len());
        let chunk = self.votes.len().div_ceil(threads);
        std::thread::scope(|s| {
            let handles: Vec<_> = self.votes.chunks(chunk).map(|c| s.spawn(move || c.iter().all(|v| v.verify(domain)))).collect();
            handles.into_iter().all(|h| h.join().unwrap_or(false))
        })
    }
}
```
`hotstuff.rs`:
```rust
/// Certificates this replica has verified, by the hash of their bytes and the set they passed
/// under (spec 2026-10-05 §7.2), FIFO, oldest first. A QC that arrives as a proposal's justify
/// and again as a NewView's high QC is verified once; an invalid one is never kept.
pub const VERIFIED_QCS_KEPT: usize = 1024;

pub(crate) struct VerifiedQcs {
    seen: std::collections::HashSet<Hash>,
    order: std::collections::VecDeque<Hash>,
    cap: usize,
}

impl VerifiedQcs {
    pub(crate) fn new(cap: usize) -> VerifiedQcs {
        VerifiedQcs { seen: Default::default(), order: Default::default(), cap }
    }

    fn key(qc: &QuorumCertificate, set: &ValidatorSet) -> Hash {
        let mut b = bincode::serialize(qc).expect("a certificate serializes");
        b.extend_from_slice(&bincode::serialize(set).expect("a validator set serializes"));
        Hash::digest_domain(b"rand-verified-qc-1", &b)
    }

    pub(crate) fn check(&mut self, domain: &SigningDomain, qc: &QuorumCertificate, set: &ValidatorSet) -> bool {
        let k = Self::key(qc, set);
        if self.seen.contains(&k) {
            return true;
        }
        if !qc.verify(domain, set) {
            return false;
        }
        if self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(k);
        self.order.push_back(k);
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.seen.len()
    }
}
```
Add the field `verified_qcs: VerifiedQcs` to `HotStuff`, initialised `VerifiedQcs::new(VERIFIED_QCS_KEPT)` in `new` and `resume`. Replace `block.header.justify.verify(&self.cfg.domain, &parent_set)` (`:944`) with `self.verified_qcs.check(&self.cfg.domain, &block.header.justify, &parent_set)` and `nv.high_qc.verify(&self.cfg.domain, &self.set_for_qc(&nv.high_qc))` (`:1149`) with `{ let set = self.set_for_qc(&nv.high_qc).clone(); self.verified_qcs.check(&self.cfg.domain, &nv.high_qc, &set) }` (the clone frees the borrow; a `ValidatorSet` is small). Make the module path `crate::consensus::hotstuff::VerifiedQcs` reachable from `tests.rs` (`pub(crate) mod hotstuff` or a `pub(crate) use`).

- [ ] **Step 4: Run, clippy, commit**

```bash
cargo test -p randprotocol-core 2>&1 | tail -4
cargo test -p randprotocol-node 2>&1 | tail -3
cargo clippy -p randprotocol-core --all-targets -- -D warnings 2>&1 | tail -2
git add crates/randprotocol-core/src/types/block.rs crates/randprotocol-core/src/consensus/hotstuff.rs crates/randprotocol-core/src/consensus/tests.rs crates/randprotocol-core/src/consensus/mod.rs
git commit -m "consensus: certificate verification across scoped threads above eight votes, and once per (certificate, validator set) — VerifiedQcs, 1 024 kept

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

---

### Task 10: the acceptance run and the record

**Files:**
- Modify: `docs/node-hardware.md` (§2.1 table; new §7 "The hot path at synthetic load")
- Modify: `docs/compute-optimization.md` §3 (3.1, 3.2, 3.3 worker count, 3.5, 3.6 rows gain *measured*/"shipped in feat/hot-path", with the numbers)
- Modify: `docs/architecture.md` §5 (the nullifier root under the flag; `SharedSet`), §6 (the commit step)
- Modify: `CHANGELOG.md` (an Unreleased entry), `AGENTS.md` (a project-memory paragraph), `docs/cli.md` (`bench apply`, `genesis --incremental-nullifier-root`, `run --verify-workers`)
- Test: the smoke tests already exist; this task's evidence is the run's output.

- [ ] **Step 1: The acceptance run**

```bash
cd ~/rand-worktrees/fullnode-hot-path
cargo build --release -p randprotocol-node 2>&1 | tail -1
./target/release/rand-node bench apply --blocks 10000 --report-every 500 --incremental-nullifier-root | tee /tmp/bench-final-10000.txt
echo "exit $?"
```
Expected: 20 rows plus the verdict; exit 0; `apply_ms` under 300 at block 10 000; `nullifiers` 40 000 000; `rss_mb` within 5 % between rows 2 000 and 10 000 beyond what 40 M entries themselves cost (the sets are in memory by design; what must be flat is the *per-block* growth beyond the entries — compare the slope of `rss_mb` against `nullifiers`: it should be a constant bytes-per-entry, no term in height). If `apply_ms` is over 300, record the number and stop here: the user decides, this plan does not tune further.

Also run the flag-off comparison at a size it can reach, for the table: `./target/release/rand-node bench apply --blocks 2000 --report-every 500 --fail-over-ms 100000 | tee /tmp/bench-final-flagoff-2000.txt`.

- [ ] **Step 2: Write the record**

`docs/node-hardware.md`, new §7 "The hot path at synthetic load (2026-10-05)": the command, the host (`sysctl -n machdep.cpu.brand_string; sysctl -n hw.memsize` on macOS; `lscpu | head -20; free -g` on Linux), the four tables (baseline 300 blocks from `/tmp/bench-baseline-300.txt`, shared set 300 from `/tmp/bench-sharedset-300.txt`, flag on 300 from `/tmp/bench-mmr-300.txt`, final 10 000 from `/tmp/bench-final-10000.txt`), and one paragraph stating which column each change moved. Add a §2.1 row: `block apply, 2 000 bundles, 40 M nullifiers | <apply_ms> ms (flag on) | this page §7`.

`docs/compute-optimization.md` §3: mark 3.1 "shipped as `incremental_nullifier_root` (genesis-gated, on no chain yet); measured: root_ms <x> → <y>", 3.2 "shipped as `SharedSet`; measured: clone_ms <x> → <y>", 3.3 "the worker count shipped (`--verify-workers`); the digest-keyed cache for every proof kind is still open", 3.5 "shipped: scoped-thread verification above eight votes, once per certificate", 3.6 "measured <date>: <apply_ms> ms at block 10 000, <rss> MB, 40 M nullifiers". Keep every other row as it is.

`docs/architecture.md` §5: after the `nullifier_root` item, a paragraph: under `incremental_nullifier_root` the slot holds the range root (`rand-nullifier-mmr-1` over `rand-nullifier-leaf` leaves, `rand-nullifier-mmr-node` nodes, in insertion order) and the composite is re-domained `rand-state-nf-mmr-1` after the tokens wrapper; the peaks ride `meta/nullifier_mmr`. Rewrite the `commitments`/`nullifiers` lines of the state listing to `SharedSet` and add two sentences on the base/delta split and the commit step. §6: one sentence that commit drains the committed ledger's deltas and survivors absorb, after the tree is pruned to descendants.

`CHANGELOG.md` Unreleased: five bullets, one per change, naming the flag, the subcommand, and that nothing rolls onto chain 20 without a genesis cut.

`AGENTS.md`: a "Validator hot path (2026-10-05, `feat/hot-path`)" paragraph under project memory: the five changes, the commit-step soundness argument in one sentence, the trap (the range row is the only record of insertion order; never delete `meta/nullifier_mmr`; `set_incremental_nullifier_root(true)` panics over existing nullifiers), the harness command, and the measured line.

`docs/cli.md`: the three new flags/subcommands with one line each.

- [ ] **Step 3: Commit**

```bash
git add docs/node-hardware.md docs/compute-optimization.md docs/architecture.md docs/cli.md CHANGELOG.md AGENTS.md
git commit -m "docs: the validator hot path measured — bench apply tables, compute-optimization §3 rows marked, architecture §5–6, CLI, changelog, project memory

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3bbzA8aQjGxnmBMNee7bE"
```

- [ ] **Step 4: Whole-branch check**

```bash
cargo test --workspace --exclude randprotocol-zkvm 2>&1 | tail -5     # the zkvm crate's tests are long; CI runs them
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -2
cargo deny check licenses 2>&1 | tail -2
git log --oneline main..HEAD
```
Expected: green, ten commits (spec, nine tasks, docs — the spec commit is already on the branch).

---

## Self-review notes

- Spec §3 harness: Task 1 (shape corrected). §4.1–4.3: Tasks 5–6. §4.4: Task 7. §4.5: Task 6 (CLI flag). §5.1–5.3: Tasks 2–3 (+ correction 2, Task 4). §6: Task 8. §7: Task 9. §8 tests: each task. §9 docs: Task 10. No spec section is uncovered.
- Names used across tasks: `SharedSet::{from_set, contains, insert, len, added_len, snapshot, for_each_sorted, commit, absorb, detach}`; `Ledger::{commit_shared_sets, absorb_shared_sets, detach_shared_sets, set_incremental_nullifier_root, set_nullifier_mmr, nullifier_mmr, incremental_nullifier_root}`; `NullifierMmr::{new, append, root, count, peaks}`, `nullifier_mmr::{leaf, node, ROOT_DOMAIN}`; `VerifyLimits::{for_cores, for_host, fixed, FLOOR, QUEUE_PER_WORKER}`; `VerifiedQcs::{new, check, len}`, `VERIFIED_QCS_KEPT`, `PARALLEL_VERIFY_MIN`, `MAX_PROPOSE_REPLAYS`; `BenchArgs`, `Row`, `Verdict`, `bench::run`. Consistent.
- Review Focus 1 → Task 1 test 2; 2 → Task 4 test 1; 3 → Task 2 tests 2 and the ledger test; 4 → Task 7 test 2; 5 → Task 9 consensus test.
