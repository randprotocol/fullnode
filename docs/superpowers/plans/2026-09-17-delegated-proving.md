# Delegated proof generation (v1) — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A wallet can hand the witness of any proof it makes to a trusted `rand-prover` service and submit the returned proof, with the chain unchanged.

**Architecture:** A `delegate` module in the zkVM crate defines the job and result types and seals them with ML-KEM-768 plus ChaCha20-Poly1305, the same primitives note envelopes use. A new `randprotocol-prover` crate serves an async job API over axum with a bounded queue and one proving slot per backend. The wallet gains a `Prover` value (local or remote) that replaces the `Backend` parameter of every proving path, so `submit`, `send`, `submit_burn` and `Call` all delegate the same way.

**Tech Stack:** Rust 1.98.1 (`rust-toolchain.toml`), axum 0.7, reqwest 0.12, tokio, postcard 1, ml-kem 0.3.2, chacha20poly1305 0.11.0, zeroize 1, clap 4.

**Spec:** `docs/superpowers/specs/2026-09-17-delegated-proving-design.md`

## Global Constraints

- The vendored zkVM files (`notes.rs`, `viewing.rs`, `ledger.rs`, `machine.rs`, the tables) are **never hand-edited except as this plan says for `machine.rs`**, and any `machine.rs` change is mirrored upstream in `../circuits/research/src/machine.rs` (Task 1, step 8) so the next `deploy/sync-zkvm.sh` carries it.
- New node-local files in `crates/randprotocol-zkvm/src` must be added to the `--exclude` lists in `deploy/sync-zkvm.sh` (Task 2, step 6) or the next sync deletes them.
- The `H_IN` salt is drawn from OS entropy once per proof by the function that uses it; no caller may pass a fixed salt outside tests.
- Every job's private inputs are held in `Zeroizing` on both ends and are never logged.
- No fallback from remote to local proving inside the wallet: a remote failure is an error that names the local alternative.
- Bearer token required unless the prover binds loopback or `--allow-open` is passed.
- The wallet's digest check in `prove_one` is kept as is: a returned proof that does not publish the digest the wallet computed is refused.
- Every proof-taking test runs under `proving_slot()` (see `crates/randprotocol-client/tests/proving_slot/mod.rs`), which is taken *around* the whole `send`/`submit` call.
- Commit messages: imperative subject with the component prefix this repo uses (`zkvm:`, `prover:`, `wallet:`, `docs:`), body says why, and end with the attribution lines from the session's system reminder.
- Run every test with `cargo test -p <crate> --test <file> <name> -- --nocapture` from the worktree root; never from the shared checkout.

---

## File structure

| path | responsibility |
|---|---|
| `crates/randprotocol-zkvm/src/machine.rs` (modify, vendored) | `prove_salted_with` and a salt parameter on `prove_on` |
| `crates/randprotocol-zkvm/src/executor.rs` (modify, local) | `prove_call` on every backend |
| `crates/randprotocol-zkvm/src/delegate.rs` (create, local) | `JobKind`, `JobRequest`, `JobResult`, `Sealed`, `ReplyKey`, `ProverKey`, seal/open, encode/decode |
| `crates/randprotocol-zkvm/src/lib.rs` (modify) | `pub mod delegate;` |
| `crates/randprotocol-zkvm/Cargo.toml` (modify) | `zeroize` dependency |
| `deploy/sync-zkvm.sh` (modify) | exclude `delegate.rs` |
| `crates/randprotocol-prover/Cargo.toml` (create) | the crate, binary `rand-prover` |
| `crates/randprotocol-prover/src/lib.rs` (create) | `Config`, `Service`, job store and worker |
| `crates/randprotocol-prover/src/http.rs` (create) | the four routes, auth, body limits |
| `crates/randprotocol-prover/src/main.rs` (create) | `run`, `address`, `keygen` |
| `crates/randprotocol-prover/tests/service.rs` (create) | in-process server tests |
| `Cargo.toml` (modify) | workspace member and dependency entry |
| `crates/randprotocol-client/src/prover.rs` (create) | `Prover`, `RemoteProver`, `profile_name` |
| `crates/randprotocol-client/src/lib.rs` (modify) | `pub mod prover;` |
| `crates/randprotocol-client/src/wallet.rs` (modify) | `prover: &Prover` replaces `backend: Backend` in `submit`, `send`, `submit_burn`, `prove_bundles`, `prove_one` |
| `crates/randprotocol-client/src/main.rs` (modify) | three flags, `prover_for`, the custody warning, `Call` through `Prover` |
| `crates/randprotocol-client/tests/wallet_flow.rs` (modify) | delegated send, tamper test, delegated call |
| `crates/randprotocol-node/tests/cluster.rs` (modify) | mechanical: `Backend::Cpu` → `&Prover::Local(Backend::Cpu)` at the wallet call sites |
| `docs/delegated-proving.md` (create) | operator and wallet guide |
| `README.md`, `AGENTS.md` (modify) | the rows and the branch entry |
| `scripts/delegated-experiment.sh` (create) | the §11 measurement loop |

---

### Task 1: the zkVM salt change — `prove_salted_with`, and `prove_call` on every backend

**Files:**
- Modify: `crates/randprotocol-zkvm/src/machine.rs:1293-1370` (`prove_with`, `prove_on`)
- Modify: `crates/randprotocol-zkvm/src/executor.rs:467-505` (`prove_call`)
- Test: `crates/randprotocol-zkvm/tests/executor.rs` (local file, not vendored)
- Mirror: `../circuits/research/src/machine.rs` (same hunk, separate repo commit)

**Interfaces:**
- Produces: `Machine::prove_salted_with(&self, backend: Backend, program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>`
- Produces: `executor::prove_call(profile, program, inputs, tier, backend) -> Result<(Vec<u8>, [u32; 8], u8, [u32; 4]), String>` now succeeds for every backend the build enables.

- [ ] **Step 1: Write the failing test**

Append to `crates/randprotocol-zkvm/tests/executor.rs`:

```rust
/// `prove_salted_with` on the CPU backend is `prove_salted`: same salt in, same `H_IN` out.
/// This is the contract `executor::prove_call` relies on to return the salt on any backend.
#[test]
fn prove_salted_with_cpu_publishes_the_same_h_in_as_prove_salted() {
    use randprotocol_zkvm::machine::{Backend, FriProfile, Machine};
    use randprotocol_zkvm::tables::cpu::pv;
    let m = Machine::new(FriProfile::Test);
    let (_, prog, inputs) = randprotocol_zkvm::guests::all().into_iter().find(|(n, _, _)| *n == "fib(20)").unwrap();
    let salt = [7u32, 8, 9, 10];
    let (a, _) = m.prove_salted(&prog, &inputs, &[], salt, None).unwrap();
    let (b, _) = m.prove_salted_with(Backend::Cpu, &prog, &inputs, &[], salt, None).unwrap();
    assert_eq!(a.public_values[pv::IN0..=pv::IN7], b.public_values[pv::IN0..=pv::IN7]);
    let expected = randprotocol_zkvm::hash::input_digest(salt, &inputs);
    let published: Vec<u64> = expected.iter().map(|w| *w as u64).collect();
    assert_eq!(&b.public_values[pv::IN0..=pv::IN7], &published[..]);
    m.verify(&prog.digest(), &b).unwrap();
}
```

If `pv::IN0..IN7` are not named that way in `tables/cpu.rs`, use the names that file exports for the eight `H_IN` words (grep `IN0` there) — the test must compare exactly those eight public values.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p randprotocol-zkvm --test executor prove_salted_with_cpu -- --nocapture`
Expected: compile error, `no method named prove_salted_with`.

- [ ] **Step 3: Add `prove_salted_with` and thread the salt through `prove_on`**

In `machine.rs`, replace the `prove_with` body so it draws a salt and delegates, and add the new method directly below it:

```rust
    /// Prove on `backend`. `Backend::Cpu` is exactly `prove`; the other backends run the same
    /// batch STARK with `rand-zkvm-cuda`'s engines and hand back a `Proof` that this
    /// `Machine`'s own `verify` accepts. Draws the per-proof `H_IN` salt from OS entropy and
    /// delegates to [`Self::prove_salted_with`], as `prove` does to `prove_salted`.
    pub fn prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        use rand::RngExt;
        let salt: [u32; 4] = rand::rng().random();
        self.prove_salted_with(backend, program, inputs, public, salt, tier)
    }

    /// The body of `prove_with`, taking the `H_IN` salt explicitly — the backend-generic
    /// mirror of `prove_salted`. Exists so a caller that must *return* the salt (a call whose
    /// input envelope is sealed with it, `executor::prove_call`) can do so on any backend;
    /// every ordinary caller wants `prove_with`. The salt never leaves the prover except
    /// folded, non-invertibly, into `pv::IN0..7`.
    pub fn prove_salted_with(&self, backend: Backend, program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        match backend {
            Backend::Cpu => self.prove_salted(program, inputs, public, salt, tier),
            #[cfg(feature = "reference-backend")]
            Backend::Reference => {
                let cfg = reference_cfg::config(self.profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = reference_cfg::config(self.profile, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, public, salt, tier)
            }
            #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
            Backend::Cuda => {
                let gpu = rand_zkvm_cuda::gpu::GpuProver::probe(PERM_SEED).map_err(|e| ProveError::Backend(e.to_string()))?;
                let cfg = cuda_cfg::config(self.profile, gpu.clone(), StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = cuda_cfg::config(self.profile, gpu, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, inputs, public, salt, tier)
            }
        }
    }
```

Then in `prove_on`: add `salt: [u32; 4]` as the parameter after `public`, delete the two lines inside it that draw a salt (`use rand::RngExt;` / `let salt: [u32; 4] = rand::rng().random();` near line 1344-1346 — keep the comment above them but reword it to "the salt `prove_salted_with` was given"), and leave the `build_traces_salted(program, inputs, public, salt, &exec, tier)` call as it is. The `#[cfg]` on `prove_on` is unchanged.

- [ ] **Step 4: Make `prove_call` use it on every backend**

In `executor.rs`, replace the `match backend { … }` at the end of `prove_call` with:

```rust
    use rand::RngExt;
    let salt: [u32; 4] = rand::rng().random();
    let m = Machine::new(profile);
    // The empty public segment, as in `prove`. Any backend: `prove_salted_with` threads the
    // salt through `prove_on` for the reference and CUDA engines exactly as `prove_salted`
    // does on the CPU, which is what lets a GPU call proof publish an input envelope.
    let (proof, exec) = m
        .prove_salted_with(backend, program, inputs, &[], salt, tier.map(|t| Tier(t as usize)))
        .map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8, salt))
```

Update `prove_call`'s doc comment: delete the sentences saying it is CPU-only and that other backends draw the salt inside the prover, and say instead "Any backend: the salt is drawn here and threaded through `Machine::prove_salted_with`." Delete the `#[allow(unreachable_patterns)]` arm.

- [ ] **Step 5: Run the new test and the executor file**

Run: `cargo test -p randprotocol-zkvm --test executor -- --nocapture`
Expected: PASS, including the new test.

- [ ] **Step 6: Fix the wallet's now-stale note**

In `crates/randprotocol-client/src/main.rs` near line 612, the comment "It is CPU-only — every other backend draws that salt inside the prover and drops it — so a GPU proof has to go without an envelope" is now false. Replace that comment with:

```rust
            // Two provers, one difference: `prove_call` returns the `H_IN` salt as well, which is
            // what the transcript is sealed with. Since `prove_salted_with` it does so on every
            // backend, so `--cuda` and an envelope go together.
```

(Task 4 rewrites this block anyway; the comment fix here keeps the tree honest between tasks.)

- [ ] **Step 7: Commit**

```bash
git add crates/randprotocol-zkvm/src/machine.rs crates/randprotocol-zkvm/src/executor.rs crates/randprotocol-zkvm/tests/executor.rs crates/randprotocol-client/src/main.rs
git commit -m "zkvm: prove_salted_with — the backend-generic prove_salted, so prove_call returns its H_IN salt on the reference and CUDA backends too

A delegated call proof (docs/superpowers/specs/2026-09-17-delegated-proving-design.md §6) is
made on a GPU prover and its input envelope is sealed by the wallet from the salt, so the
salt has to come back from every backend. prove_with is unchanged for its callers: it draws
the salt and delegates, as prove does to prove_salted.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

- [ ] **Step 8: Mirror the `machine.rs` hunk upstream**

Apply the identical `prove_with`/`prove_salted_with`/`prove_on` change to `/Users/dendisuhubdy/Github/randprotocol/circuits/research/src/machine.rs` (that file is byte-identical to ours apart from the `log_ext_degrees_pub` wrapper the sync script adds). Verify with:

```bash
diff /Users/dendisuhubdy/Github/randprotocol/circuits/research/src/machine.rs crates/randprotocol-zkvm/src/machine.rs
```

Expected: only the six-line `log_ext_degrees_pub` hunk. Then in the circuits checkout:

```bash
cd /Users/dendisuhubdy/Github/randprotocol/circuits && cargo test -p rand-zkvm --lib machine 2>&1 | tail -3
git add research/src/machine.rs
git commit -m "machine: prove_salted_with — the backend-generic prove_salted (fullnode delegated proving §6)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

Do not push the circuits commit; report its hash.

---

### Task 2: the `delegate` module — job types, sealing, wire form

**Files:**
- Create: `crates/randprotocol-zkvm/src/delegate.rs`
- Modify: `crates/randprotocol-zkvm/src/lib.rs` (add `pub mod delegate;` after `pub mod codec;`)
- Modify: `crates/randprotocol-zkvm/Cargo.toml` (`zeroize = { workspace = true }` under `[dependencies]`)
- Modify: `deploy/sync-zkvm.sh:128` (add `--exclude delegate.rs`)
- Test: `crates/randprotocol-zkvm/tests/delegate.rs` (new; add `--exclude delegate.rs` to the tests rsync on line 130 as well)

**Interfaces:**
- Produces, all `pub` in `randprotocol_zkvm::delegate`:

```rust
pub const VERSION: u32 = 1;
pub enum JobKind { Bundle { inputs: Vec<u32> }, Program { base_pc: u32, words: Vec<u32>, inputs: Vec<u32>, tier: Option<u8>, want_salt: bool } }
pub struct JobRequest { pub version: u32, pub profile: String, pub kind: JobKind, pub deadline_secs: u32, pub reply_ek: Vec<u8> }   // zeroizes its inputs on drop
pub enum JobResult { Bundle { proof: Vec<u8>, digest: Word8, tier: u8 }, Program { proof: Vec<u8>, outputs: [u32; 8], tier: u8, salt: Option<[u32; 4]> }, Failed { error: String } }
pub struct Sealed { pub kem_ct: Vec<u8>, pub body: Vec<u8> }
pub struct ReplyKey { pub ek: Vec<u8>, /* private dk */ }        impl ReplyKey { pub fn generate() -> ReplyKey }
pub struct ProverKey { pub address: ShieldedAddress, /* private dk */ }  impl ProverKey { pub fn from_viewing_key(vk: &ViewingKey) -> ProverKey }
pub fn seal_job(to: &ShieldedAddress, job: &JobRequest) -> Result<Sealed, String>
pub fn open_job(key: &ProverKey, sealed: &Sealed) -> Result<JobRequest, String>
pub fn seal_result(reply_ek: &[u8], result: &JobResult) -> Result<Sealed, String>
pub fn open_result(key: &ReplyKey, sealed: &Sealed) -> Result<JobResult, String>
pub fn encode(sealed: &Sealed) -> Vec<u8>
pub fn decode(bytes: &[u8]) -> Result<Sealed, String>
impl JobKind { pub fn name(&self) -> &'static str }  // "bundle" | "program"
```

- [ ] **Step 1: Write the failing tests**

Create `crates/randprotocol-zkvm/tests/delegate.rs`:

```rust
//! The sealed job and result a wallet and a `rand-prover` exchange
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §3–§4).

use randprotocol_zkvm::address::address_of;
use randprotocol_zkvm::delegate::*;
use randprotocol_zkvm::notes::SpendKey;

fn a_job(reply_ek: Vec<u8>) -> JobRequest {
    JobRequest {
        version: VERSION,
        profile: "test".into(),
        kind: JobKind::Program { base_pc: 0, words: vec![0x13, 0x73], inputs: vec![1, 2, 3], tier: None, want_salt: true },
        deadline_secs: 120,
        reply_ek,
    }
}

#[test]
fn a_job_seals_to_the_prover_and_opens_there_only() {
    let prover_vk = SpendKey::random().viewing_key();
    let prover = ProverKey::from_viewing_key(&prover_vk);
    let other = ProverKey::from_viewing_key(&SpendKey::random().viewing_key());
    let reply = ReplyKey::generate();
    let job = a_job(reply.ek.clone());
    let sealed = seal_job(&address_of(&prover_vk), &job).unwrap();
    assert_eq!(open_job(&prover, &sealed).unwrap(), job);
    assert!(open_job(&other, &sealed).is_err(), "a different prover key must not open it");
    let mut tampered = sealed.clone();
    let last = tampered.body.len() - 1;
    tampered.body[last] ^= 1;
    assert!(open_job(&prover, &tampered).is_err(), "a flipped byte must fail authentication");
}

#[test]
fn a_result_seals_to_the_job_reply_key_and_opens_once_there() {
    let reply = ReplyKey::generate();
    let stranger = ReplyKey::generate();
    let result = JobResult::Bundle { proof: vec![9; 40], digest: [1; 8], tier: 14 };
    let sealed = seal_result(&reply.ek, &result).unwrap();
    assert_eq!(open_result(&reply, &sealed).unwrap(), result);
    assert!(open_result(&stranger, &sealed).is_err());
    // A result under a job's key is ciphertext to the prover's own key: the two AADs differ.
    let prover = ProverKey::from_viewing_key(&SpendKey::random().viewing_key());
    assert!(open_job(&prover, &sealed).is_err());
}

#[test]
fn the_wire_form_round_trips_and_rejects_garbage() {
    let sealed = Sealed { kem_ct: vec![1, 2, 3], body: vec![4, 5] };
    assert_eq!(decode(&encode(&sealed)).unwrap(), sealed);
    assert!(decode(&[0xff; 3]).is_err());
}

#[test]
fn the_job_encoding_is_pinned() {
    // A wallet and a prover built from different commits must agree on these bytes; this
    // vector is the postcard form of `a_job(vec![7; 4])`. Regenerate deliberately, never
    // silently, when `JobRequest` changes — and bump `VERSION` when you do.
    let job = a_job(vec![7; 4]);
    let bytes = postcard::to_allocvec(&job).unwrap();
    assert_eq!(hex::encode(&bytes), "010474657374010002130f730301020300017804070707070707");
}

#[test]
fn a_bad_encapsulation_key_is_an_error_not_a_panic() {
    let job = a_job(vec![7; 4]);
    let short = randprotocol_core::notes::ShieldedAddress { pk: [0; 8], kem_ek: vec![0; 10] };
    assert!(seal_job(&short, &job).unwrap_err().contains("10 bytes"));
    assert!(seal_result(&[0; 10], &JobResult::Failed { error: "x".into() }).unwrap_err().contains("10 bytes"));
}
```

The pinned hex in `the_job_encoding_is_pinned` is a placeholder for the value the first run prints: run the test once, copy the `left` value from the assertion failure into the string, and re-run. Add `postcard = { version = "1", features = ["alloc"] }` to the zkVM crate's `[dev-dependencies]` if the test cannot see it (it is a normal dependency already, so it should).

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p randprotocol-zkvm --test delegate`
Expected: compile error, `could not find delegate in randprotocol_zkvm`.

- [ ] **Step 3: Write the module**

Create `crates/randprotocol-zkvm/src/delegate.rs`:

```rust
//! Delegated proof generation: the job a wallet seals to a `rand-prover` and the result it
//! gets back (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §3–§4).
//!
//! Node-local, like `address.rs` and `call_envelope.rs`: never touched by
//! `deploy/sync-zkvm.sh`. It reuses the two primitives the envelope layer pins (ML-KEM-768,
//! ChaCha20-Poly1305) but none of `viewing.rs`'s private helpers, so that file stays
//! byte-identical to upstream.
//!
//! A job carries a witness — for a bundle, the spend key and the notes — so the prover a job
//! is sealed to is trusted with custody, not just privacy (spec §9). The wallet says so.

use crate::address::address_of;
use crate::notes::ViewingKey;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::FromSeed;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem768};
use rand::Rng;
use randprotocol_core::notes::{ShieldedAddress, Word8, KEM_EK_BYTES};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

type Dk = ml_kem::ml_kem_768::DecapsulationKey;
type Ek = ml_kem::ml_kem_768::EncapsulationKey;
type KemCt = ml_kem::ml_kem_768::Ciphertext;

/// Bump when `JobRequest`'s encoding changes; the prover refuses other versions.
pub const VERSION: u32 = 1;
const AAD_JOB: &[u8] = b"rand-prover-job-v1";
const AAD_RESULT: &[u8] = b"rand-prover-result-v1";

/// What to prove. Everything the wallet proves is one of `executor`'s two shapes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobKind {
    /// `executor::prove_bundle`: exactly `notes::bundle_input::COUNT` words. A transfer, a
    /// bond, or one of a bridge burn's two bundles.
    Bundle { inputs: Vec<u32> },
    /// `executor::prove` (`want_salt: false`) or `executor::prove_call` (`want_salt: true`):
    /// a program on private inputs. The wallet asks for the salt when it will seal an input
    /// envelope with it.
    Program { base_pc: u32, words: Vec<u32>, inputs: Vec<u32>, tier: Option<u8>, want_salt: bool },
}

impl JobKind {
    pub fn name(&self) -> &'static str {
        match self {
            JobKind::Bundle { .. } => "bundle",
            JobKind::Program { .. } => "program",
        }
    }
    fn inputs_mut(&mut self) -> &mut Vec<u32> {
        match self {
            JobKind::Bundle { inputs } => inputs,
            JobKind::Program { inputs, .. } => inputs,
        }
    }
}

/// One proving job. Zeroizes its private inputs on drop, on both ends of the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRequest {
    pub version: u32,
    /// `"production"` or `"test"` — `executor::ZkExecutor::profile_from_str`.
    pub profile: String,
    pub kind: JobKind,
    /// The prover must *start* within this many seconds of receipt or refuse the job: a
    /// bundle binds the head height it was planned at, and admission accepts a 256-block window.
    pub deadline_secs: u32,
    /// A fresh ML-KEM-768 encapsulation key for this job only; the result is sealed to it.
    pub reply_ek: Vec<u8>,
}

impl Drop for JobRequest {
    fn drop(&mut self) {
        self.kind.inputs_mut().zeroize();
    }
}

/// What comes back. `Failed` carries the prover's error text and never its inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobResult {
    Bundle { proof: Vec<u8>, digest: Word8, tier: u8 },
    Program { proof: Vec<u8>, outputs: [u32; 8], tier: u8, salt: Option<[u32; 4]> },
    Failed { error: String },
}

/// The wire form of a job or a result: an ML-KEM-768 ciphertext and an AEAD body whose
/// 12-byte nonce is prepended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub kem_ct: Vec<u8>,
    pub body: Vec<u8>,
}

/// The wallet's one-time key for one job's result.
pub struct ReplyKey {
    dk: Dk,
    pub ek: Vec<u8>,
}

impl ReplyKey {
    pub fn generate() -> ReplyKey {
        let mut seed = [0u8; 64];
        rand::rng().fill_bytes(&mut seed);
        let (dk, ek) = MlKem768::from_seed(&ml_kem::Seed::from(seed));
        ReplyKey { dk, ek: ek.to_bytes().to_vec() }
    }
}

/// The prover's identity: a `rand1…` address, whose decapsulation key is derived from a
/// wallet key exactly as a receiving wallet derives its own.
pub struct ProverKey {
    dk: Dk,
    pub address: ShieldedAddress,
}

impl ProverKey {
    pub fn from_viewing_key(vk: &ViewingKey) -> ProverKey {
        let (dk, _) = MlKem768::from_seed(&ml_kem::Seed::from(vk.kem_seed()));
        ProverKey { dk, address: address_of(vk) }
    }
}

fn seal_to(ek_bytes: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, String> {
    if ek_bytes.len() != KEM_EK_BYTES {
        return Err(format!("encapsulation key is {} bytes, expected {KEM_EK_BYTES}", ek_bytes.len()));
    }
    let key = ml_kem::kem::Key::<Ek>::try_from(ek_bytes).map_err(|_| "malformed encapsulation key".to_string())?;
    let ek = Ek::new(&key).map_err(|_| "invalid encapsulation key".to_string())?;
    let (kem_ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
    let ss: [u8; 32] = ss.into();
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(ss))
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| "aead".to_string())?;
    Ok(Sealed { kem_ct: kem_ct.to_vec(), body: [&nonce[..], &ct].concat() })
}

fn open_with(dk: &Dk, aad: &[u8], sealed: &Sealed) -> Result<Vec<u8>, String> {
    let ct = KemCt::try_from(&sealed.kem_ct[..]).map_err(|_| "malformed kem ciphertext".to_string())?;
    let ss: [u8; 32] = dk.decapsulate(&ct).into();
    if sealed.body.len() < 12 {
        return Err("body too short".into());
    }
    let nonce: [u8; 12] = sealed.body[..12].try_into().expect("12 bytes");
    ChaCha20Poly1305::new(&Key::from(ss))
        .decrypt(&Nonce::from(nonce), Payload { msg: &sealed.body[12..], aad })
        .map_err(|_| "failed to open: wrong key or tampered".to_string())
}

pub fn seal_job(to: &ShieldedAddress, job: &JobRequest) -> Result<Sealed, String> {
    let pt = postcard::to_allocvec(job).map_err(|e| e.to_string())?;
    seal_to(&to.kem_ek, AAD_JOB, &pt)
}

pub fn open_job(key: &ProverKey, sealed: &Sealed) -> Result<JobRequest, String> {
    let mut pt = open_with(&key.dk, AAD_JOB, sealed)?;
    let job: JobRequest = postcard::from_bytes(&pt).map_err(|e| e.to_string())?;
    pt.zeroize();
    if job.version != VERSION {
        return Err(format!("job version {} is not {VERSION}", job.version));
    }
    Ok(job)
}

pub fn seal_result(reply_ek: &[u8], result: &JobResult) -> Result<Sealed, String> {
    let pt = postcard::to_allocvec(result).map_err(|e| e.to_string())?;
    seal_to(reply_ek, AAD_RESULT, &pt)
}

pub fn open_result(key: &ReplyKey, sealed: &Sealed) -> Result<JobResult, String> {
    let pt = open_with(&key.dk, AAD_RESULT, sealed)?;
    postcard::from_bytes(&pt).map_err(|e| e.to_string())
}

pub fn encode(sealed: &Sealed) -> Vec<u8> {
    postcard::to_allocvec(sealed).expect("sealed serialises")
}

pub fn decode(bytes: &[u8]) -> Result<Sealed, String> {
    postcard::from_bytes(bytes).map_err(|e| format!("not a sealed job: {e}"))
}
```

`rand` in this crate is 0.10: `use rand::Rng;` gives `fill_bytes` on `rand::rng()`, as `viewing.rs` uses it. If `Rng` does not provide `fill_bytes` in this version, use `use rand::RngCore;` — copy whichever import `viewing.rs` has.

Add to `lib.rs` after `pub mod codec;`: `pub mod delegate;`. Add to the zkVM `Cargo.toml` `[dependencies]`: `zeroize = { workspace = true }`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p randprotocol-zkvm --test delegate`
Expected: four pass, `the_job_encoding_is_pinned` fails with the real hex in `left`. Paste that hex into the test and run again. Expected: all five PASS.

- [ ] **Step 5: Run the crate's other tests that touch the changed manifest**

Run: `cargo test -p randprotocol-zkvm --test executor --test call_envelope`
Expected: PASS.

- [ ] **Step 6: Protect the file from the sync script**

In `deploy/sync-zkvm.sh`, line 128, change
`--exclude address.rs --exclude arx.rs --exclude call_envelope.rs \`
to
`--exclude address.rs --exclude arx.rs --exclude call_envelope.rs --exclude delegate.rs \`
and line 130's tests rsync from
`--exclude viewing.rs --exclude bundle.rs "$SRC/tests/" "$DST/tests/"`
to
`--exclude viewing.rs --exclude bundle.rs --exclude delegate.rs "$SRC/tests/" "$DST/tests/"`.
Add one sentence to the script's header comment list of local additions (line 4-5): `delegate.rs (src and tests) is the delegated-proving job layer, node-local.`

- [ ] **Step 7: Commit**

```bash
git add crates/randprotocol-zkvm/src/delegate.rs crates/randprotocol-zkvm/src/lib.rs crates/randprotocol-zkvm/Cargo.toml crates/randprotocol-zkvm/tests/delegate.rs deploy/sync-zkvm.sh Cargo.lock
git commit -m "zkvm: the delegate module — the job a wallet seals to a rand-prover and the result it gets back

JobRequest/JobResult in postcard, sealed with ML-KEM-768 + ChaCha20-Poly1305 to the prover's
rand1 address and back to a one-time reply key; inputs zeroize on drop; the encoding is
pinned by a test. Node-local like address.rs, excluded from deploy/sync-zkvm.sh.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 3: the `rand-prover` service

**Files:**
- Create: `crates/randprotocol-prover/Cargo.toml`, `src/lib.rs`, `src/http.rs`, `src/main.rs`
- Create: `crates/randprotocol-prover/tests/service.rs`
- Modify: `Cargo.toml` (workspace `members` gains `"crates/randprotocol-prover"`; `[workspace.dependencies]` gains `randprotocol-prover = { path = "crates/randprotocol-prover" }`)

**Interfaces:**
- Consumes: everything in `randprotocol_zkvm::delegate`; `executor::{prove_bundle, prove, prove_call, ZkExecutor::profile_from_str}`; `randprotocol_client::wallet::Wallet` (key file).
- Produces:

```rust
pub struct Config { pub key: ProverKey, pub backend: Backend, pub slots: usize, pub max_queue: usize, pub token: Option<String>, pub per_ip: usize, pub result_ttl: Duration, pub allow_open: bool }
impl Config { pub fn test(key: ProverKey) -> Config }   // cpu, 1 slot, queue 8, no token, per_ip 64, ttl 10 min, allow_open true
pub async fn serve(addr: SocketAddr, cfg: Config) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)>
```

HTTP contract (spec §5): `POST /v1/jobs` (octet-stream `encode(Sealed)`) → `202 {"id","position"}` | `400` | `401` | `429 {"error","retry_after_secs"}`; `GET /v1/jobs/{id}` → `{"state","position"?,"elapsed_ms"?}` | `404`; `GET /v1/jobs/{id}/result` → octet-stream `encode(Sealed)` | `404`; `GET /v1/health` → `{"version","backend","slots","queue_depth","proving","address"}`.

- [ ] **Step 1: Write the failing tests**

Create `crates/randprotocol-prover/tests/service.rs`:

```rust
//! An in-process `rand-prover` on the CPU backend and the test profile
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §5, §12).

use randprotocol_prover::{serve, Config};
use randprotocol_zkvm::delegate::*;
use randprotocol_zkvm::machine::{FriProfile, Machine};
use randprotocol_zkvm::notes::SpendKey;
use std::net::SocketAddr;
use std::time::Duration;

async fn start(cfg: Config) -> (SocketAddr, reqwest::Client) {
    let (addr, _task) = serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    (addr, reqwest::Client::new())
}

fn prover_key() -> (ProverKey, randprotocol_core::notes::ShieldedAddress) {
    let vk = SpendKey::random().viewing_key();
    let key = ProverKey::from_viewing_key(&vk);
    let address = key.address.clone();
    (key, address)
}

fn fib_job(reply_ek: Vec<u8>, deadline_secs: u32) -> JobRequest {
    let (_, prog, inputs) = randprotocol_zkvm::guests::all().into_iter().find(|(n, _, _)| *n == "fib(20)").unwrap();
    JobRequest {
        version: VERSION,
        profile: "test".into(),
        kind: JobKind::Program { base_pc: prog.base_pc, words: prog.words, inputs, tier: None, want_salt: true },
        deadline_secs,
        reply_ek,
    }
}

async fn submit(http: &reqwest::Client, addr: SocketAddr, address: &randprotocol_core::notes::ShieldedAddress, job: &JobRequest, token: Option<&str>) -> reqwest::Response {
    let mut req = http.post(format!("http://{addr}/v1/jobs")).body(encode(&seal_job(address, job).unwrap()));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap()
}

async fn wait_done(http: &reqwest::Client, addr: SocketAddr, id: &str) -> serde_json::Value {
    for _ in 0..600 {
        let v: serde_json::Value = http.get(format!("http://{addr}/v1/jobs/{id}")).send().await.unwrap().json().await.unwrap();
        match v["state"].as_str().unwrap() {
            "done" | "failed" | "expired" => return v,
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    panic!("job never finished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_program_job_proves_and_the_result_opens_and_verifies() {
    let (key, address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let reply = ReplyKey::generate();
    let job = fib_job(reply.ek.clone(), 120);
    let r = submit(&http, addr, &address, &job, None).await;
    assert_eq!(r.status(), 202);
    let id = r.json::<serde_json::Value>().await.unwrap()["id"].as_str().unwrap().to_string();
    let status = wait_done(&http, addr, &id).await;
    assert_eq!(status["state"], "done", "{status}");
    let bytes = http.get(format!("http://{addr}/v1/jobs/{id}/result")).send().await.unwrap().bytes().await.unwrap();
    let result = open_result(&reply, &decode(&bytes).unwrap()).unwrap();
    let JobResult::Program { proof, outputs, tier, salt } = result else { panic!("not a program result: {result:?}") };
    assert!(salt.is_some(), "want_salt: true must return the salt");
    assert_eq!(tier, 10);
    let (_, prog, _) = randprotocol_zkvm::guests::all().into_iter().find(|(n, _, _)| *n == "fib(20)").unwrap();
    let proof: randprotocol_zkvm::machine::Proof = postcard::from_bytes(&proof).unwrap();
    Machine::new(FriProfile::Test).verify(&prog.digest(), &proof).unwrap();
    assert_eq!(outputs[0], 6765, "fib(20)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_refuses_with_429_and_an_estimate() {
    let (key, address) = prover_key();
    let mut cfg = Config::test(key);
    cfg.max_queue = 0;
    let (addr, http) = start(cfg).await;
    let first = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(first.status(), 202, "the slot takes the first job");
    let second = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(second.status(), 429);
    let v: serde_json::Value = second.json().await.unwrap();
    assert!(v["retry_after_secs"].as_u64().is_some(), "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_that_cannot_start_before_its_deadline_is_refused() {
    let (key, address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    // The first job occupies the slot; the second's estimate is one average program proof
    // away, which is more than zero seconds.
    let first = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(first.status(), 202);
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 0), None).await;
    assert_eq!(r.status(), 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_is_400_and_leaves_the_queue_alone() {
    let (key, _) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let r = http.post(format!("http://{addr}/v1/jobs")).body(vec![0xff; 30]).send().await.unwrap();
    assert_eq!(r.status(), 400);
    let h: serde_json::Value = http.get(format!("http://{addr}/v1/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(h["queue_depth"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_sealed_to_another_prover_is_400() {
    let (key, _) = prover_key();
    let (_, other_address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let r = submit(&http, addr, &other_address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(r.status(), 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_gates_every_route_that_takes_or_gives_a_job() {
    let (key, address) = prover_key();
    let mut cfg = Config::test(key);
    cfg.token = Some("s3cret".into());
    let (addr, http) = start(cfg).await;
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(r.status(), 401);
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), Some("wrong")).await;
    assert_eq!(r.status(), 401);
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), Some("s3cret")).await;
    assert_eq!(r.status(), 202);
    // Health is open: a wallet checks the pin before it has proven it holds the token.
    let h = http.get(format!("http://{addr}/v1/health")).send().await.unwrap();
    assert_eq!(h.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_the_key_files_address_and_the_backend() {
    let (key, address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let h: serde_json::Value = http.get(format!("http://{addr}/v1/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(h["address"], address.to_string());
    assert_eq!(h["backend"], "cpu");
    assert_eq!(h["slots"], 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_job_is_404_on_both_routes() {
    let (key, _) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let id = "00".repeat(16);
    assert_eq!(http.get(format!("http://{addr}/v1/jobs/{id}")).send().await.unwrap().status(), 404);
    assert_eq!(http.get(format!("http://{addr}/v1/jobs/{id}/result")).send().await.unwrap().status(), 404);
}
```

- [ ] **Step 2: Create the crate so the tests fail on missing items rather than a missing crate**

`crates/randprotocol-prover/Cargo.toml`:

```toml
[package]
name = "randprotocol-prover"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
description = "RAND delegated prover: proves sealed jobs for wallets that cannot prove in useful time (`rand-prover`)"

[[bin]]
name = "rand-prover"
path = "src/main.rs"

[dependencies]
randprotocol-core = { workspace = true }
randprotocol-zkvm = { workspace = true }
randprotocol-client = { workspace = true }
axum = { workspace = true }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
anyhow = { workspace = true }
clap = { workspace = true }
hex = { workspace = true }
rand = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }

[features]
default = []
cuda = ["randprotocol-zkvm/cuda"]
mock-cuda = ["randprotocol-zkvm/mock-cuda"]

[dev-dependencies]
reqwest = { workspace = true }
postcard = { version = "1", features = ["alloc"] }
```

Add `"crates/randprotocol-prover"` to `members` in the root `Cargo.toml` and `randprotocol-prover = { path = "crates/randprotocol-prover" }` under `[workspace.dependencies]`. Create an empty `src/lib.rs` and a `src/main.rs` containing `fn main() {}`.

Run: `cargo test -p randprotocol-prover --test service`
Expected: compile errors for `serve` and `Config`.

- [ ] **Step 3: Write `src/lib.rs` — config, job store, worker**

```rust
//! `rand-prover`: a trusted proving service for wallets that cannot prove in useful time
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md`). A pure function of the
//! sealed jobs it receives — it never reads the chain — behind a bounded queue and one proving
//! slot per backend. The job's inputs are the wallet's witness, spend key included: whoever
//! runs this holds custody of every wallet that delegates to it (spec §9).

pub mod http;

use randprotocol_zkvm::delegate::{self, JobKind, JobRequest, JobResult, ProverKey, Sealed};
use randprotocol_zkvm::executor::{self, ZkExecutor};
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::Backend;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use http::serve;

pub struct Config {
    pub key: ProverKey,
    pub backend: Backend,
    /// Concurrent proofs. One per GPU; on a CPU box, one.
    pub slots: usize,
    /// Jobs waiting beyond the ones proving. Zero means "only what the slots can take now".
    pub max_queue: usize,
    /// The bearer wallets must send. `None` is loopback-only unless `allow_open`.
    pub token: Option<String>,
    /// Jobs a single client IP may have queued or proving at once.
    pub per_ip: usize,
    /// How long a finished job's sealed result is kept for the wallet to fetch.
    pub result_ttl: Duration,
    pub allow_open: bool,
}

impl Config {
    /// The in-process configuration the tests use: CPU, one slot, a short queue, no token.
    pub fn test(key: ProverKey) -> Config {
        Config { key, backend: Backend::Cpu, slots: 1, max_queue: 8, token: None, per_ip: 64, result_ttl: Duration::from_secs(600), allow_open: true }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Queued, Proving, Done, Failed, Expired }

impl State {
    pub fn as_str(self) -> &'static str {
        match self { State::Queued => "queued", State::Proving => "proving", State::Done => "done", State::Failed => "failed", State::Expired => "expired" }
    }
}

pub struct Entry {
    pub state: State,
    pub kind: &'static str,
    pub ip: IpAddr,
    pub submitted: Instant,
    pub deadline: Duration,
    pub started: Option<Instant>,
    pub finished: Option<Instant>,
    pub result: Option<Sealed>,
}

/// Running averages of proving time per kind, seeded per spec §5 so the very first estimate
/// is not zero: 100 s for a bundle and 30 s for a program on the CPU, a tenth of that on CUDA.
pub struct Averages { pub bundle: f64, pub program: f64 }

impl Averages {
    fn seed(backend: Backend) -> Averages {
        let scale = if backend == Backend::Cpu { 1.0 } else { 0.1 };
        Averages { bundle: 100.0 * scale, program: 30.0 * scale }
    }
    fn get(&self, kind: &str) -> f64 { if kind == "bundle" { self.bundle } else { self.program } }
    fn update(&mut self, kind: &str, secs: f64) {
        let slot = if kind == "bundle" { &mut self.bundle } else { &mut self.program };
        *slot = 0.7 * *slot + 0.3 * secs;
    }
}

pub struct Inner {
    pub entries: HashMap<String, Entry>,
    pub queue: VecDeque<(String, JobRequest)>,
    pub proving: usize,
    pub avg: Averages,
}

pub struct Service {
    pub cfg: Config,
    pub inner: Mutex<Inner>,
    pub wake: tokio::sync::Notify,
}

pub type Shared = Arc<Service>;

pub enum Refusal {
    /// Bad token.
    Unauthorized,
    /// Not a sealed job, or sealed to some other prover, or a version we do not speak.
    Bad(String),
    /// Queue full, per-IP cap, or the deadline cannot be met; with the seconds to wait.
    Busy(String, u64),
}

impl Service {
    pub fn new(cfg: Config) -> Shared {
        let avg = Averages::seed(cfg.backend);
        let svc = Arc::new(Service { cfg, inner: Mutex::new(Inner { entries: HashMap::new(), queue: VecDeque::new(), proving: 0, avg }), wake: tokio::sync::Notify::new() });
        for _ in 0..svc.cfg.slots.max(1) {
            let s = svc.clone();
            tokio::spawn(async move { s.worker().await });
        }
        svc
    }

    pub fn backend_name(&self) -> &'static str {
        match self.cfg.backend { Backend::Cpu => "cpu", #[allow(unreachable_patterns)] _ => "cuda" }
    }

    /// Admission: open the job, apply the caps, estimate the start, enqueue. Returns the id
    /// and the queue position.
    pub fn submit(&self, bytes: &[u8], ip: IpAddr) -> Result<(String, usize), Refusal> {
        let sealed = delegate::decode(bytes).map_err(Refusal::Bad)?;
        let job = delegate::open_job(&self.cfg.key, &sealed).map_err(Refusal::Bad)?;
        if ZkExecutor::profile_from_str(&job.profile).is_none() {
            return Err(Refusal::Bad(format!("unknown fri profile {:?}", job.profile)));
        }
        let kind = job.kind.name();
        let mut g = self.inner.lock().unwrap();
        self.sweep(&mut g);
        let mine = g.entries.values().filter(|e| e.ip == ip && matches!(e.state, State::Queued | State::Proving)).count();
        if mine >= self.cfg.per_ip {
            return Err(Refusal::Busy(format!("{mine} jobs already in flight from this address"), 30));
        }
        if g.queue.len() >= self.cfg.max_queue && g.proving >= self.cfg.slots.max(1) {
            let wait = self.estimate(&g, kind);
            return Err(Refusal::Busy("queue full".into(), wait.ceil() as u64));
        }
        let wait = self.estimate(&g, kind);
        if wait > job.deadline_secs as f64 {
            return Err(Refusal::Busy(format!("cannot start within {} s; the estimate is {:.0} s", job.deadline_secs, wait), wait.ceil() as u64));
        }
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        let id = hex::encode(id);
        g.entries.insert(id.clone(), Entry { state: State::Queued, kind, ip, submitted: Instant::now(), deadline: Duration::from_secs(job.deadline_secs as u64), started: None, finished: None, result: None });
        g.queue.push_back((id.clone(), job));
        let position = g.queue.len();
        drop(g);
        self.wake.notify_one();
        Ok((id, position))
    }

    /// Seconds until a job of `kind` submitted now would start: everything ahead of it,
    /// queued or proving, at the running average, spread over the slots.
    fn estimate(&self, g: &Inner, kind: &str) -> f64 {
        let ahead = g.queue.len() + g.proving;
        if ahead == 0 { return 0.0; }
        ahead as f64 * g.avg.get(kind) / self.cfg.slots.max(1) as f64
    }

    /// Drop finished entries past the result TTL.
    fn sweep(&self, g: &mut Inner) {
        let ttl = self.cfg.result_ttl;
        g.entries.retain(|_, e| match e.finished { Some(t) => t.elapsed() < ttl, None => true });
    }

    pub fn status(&self, id: &str) -> Option<(State, Option<usize>, Option<u128>)> {
        let mut g = self.inner.lock().unwrap();
        self.sweep(&mut g);
        let e = g.entries.get(id)?;
        let position = if e.state == State::Queued { g.queue.iter().position(|(i, _)| i == id).map(|p| p + 1) } else { None };
        let elapsed = e.started.map(|s| e.finished.unwrap_or_else(Instant::now).duration_since(s).as_millis());
        Some((e.state, position, elapsed))
    }

    pub fn result(&self, id: &str) -> Option<Sealed> {
        let g = self.inner.lock().unwrap();
        g.entries.get(id).and_then(|e| e.result.clone())
    }

    pub fn queue_depth(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap();
        (g.queue.len(), g.proving)
    }

    async fn worker(self: Arc<Self>) {
        loop {
            let next = {
                let mut g = self.inner.lock().unwrap();
                match g.queue.pop_front() {
                    Some((id, job)) => {
                        let e = g.entries.get_mut(&id).expect("queued entries exist");
                        if e.submitted.elapsed() > e.deadline {
                            e.state = State::Expired;
                            e.finished = Some(Instant::now());
                            tracing::info!(job = %id, "expired before it could start");
                            continue;
                        }
                        e.state = State::Proving;
                        e.started = Some(Instant::now());
                        g.proving += 1;
                        Some((id, job))
                    }
                    None => None,
                }
            };
            let Some((id, job)) = next else {
                self.wake.notified().await;
                continue;
            };
            let kind = job.kind.name();
            let backend = self.cfg.backend;
            let reply_ek = job.reply_ek.clone();
            let started = Instant::now();
            tracing::info!(job = %id, kind, "proving");
            let result = tokio::task::spawn_blocking(move || prove(job, backend)).await.unwrap_or_else(|e| JobResult::Failed { error: format!("prover panicked: {e}") });
            let secs = started.elapsed().as_secs_f64();
            let (state, sealed) = match delegate::seal_result(&reply_ek, &result) {
                Ok(s) => (if matches!(result, JobResult::Failed { .. }) { State::Failed } else { State::Done }, Some(s)),
                Err(e) => {
                    tracing::warn!(job = %id, "could not seal the result: {e}");
                    (State::Failed, None)
                }
            };
            let mut g = self.inner.lock().unwrap();
            g.proving -= 1;
            g.avg.update(kind, secs);
            if let Some(e) = g.entries.get_mut(&id) {
                e.state = state;
                e.finished = Some(Instant::now());
                e.result = sealed;
            }
            tracing::info!(job = %id, kind, state = state.as_str(), secs = format!("{secs:.1}"), "finished");
        }
    }
}

/// The proof itself: the three `executor` entry points a wallet would have called locally.
/// `job` is consumed and dropped here, which zeroizes its inputs.
fn prove(job: JobRequest, backend: Backend) -> JobResult {
    let Some(profile) = ZkExecutor::profile_from_str(&job.profile) else {
        return JobResult::Failed { error: format!("unknown fri profile {:?}", job.profile) };
    };
    match &job.kind {
        JobKind::Bundle { inputs } => match executor::prove_bundle(profile, inputs, backend) {
            Ok((proof, digest, tier)) => JobResult::Bundle { proof, digest, tier },
            Err(error) => JobResult::Failed { error },
        },
        JobKind::Program { base_pc, words, inputs, tier, want_salt } => {
            if base_pc % 4 != 0 {
                return JobResult::Failed { error: "base_pc is not word-aligned".into() };
            }
            let program = Program { base_pc: *base_pc, words: words.clone() };
            if *want_salt {
                match executor::prove_call(profile, &program, inputs, *tier, backend) {
                    Ok((proof, outputs, tier, salt)) => JobResult::Program { proof, outputs, tier, salt: Some(salt) },
                    Err(error) => JobResult::Failed { error },
                }
            } else {
                match executor::prove(profile, &program, inputs, *tier, backend) {
                    Ok((proof, outputs, tier)) => JobResult::Program { proof, outputs, tier, salt: None },
                    Err(error) => JobResult::Failed { error },
                }
            }
        }
    }
}

/// Refuse to listen on a non-loopback address without a token, unless told to.
pub fn check_bind(addr: SocketAddr, cfg: &Config) -> anyhow::Result<()> {
    if cfg.token.is_none() && !addr.ip().is_loopback() && !cfg.allow_open {
        anyhow::bail!("refusing to listen on {addr} without --token: every job is seconds of GPU or a minute of CPU. Pass --token <bearer>, or --allow-open to accept that");
    }
    Ok(())
}
```

The workspace `rand` is 0.8 (`rand::thread_rng()`, `RngCore::fill_bytes`), unlike the zkVM crate's 0.10; the code above uses the 0.8 API because this crate depends on the workspace `rand`.

- [ ] **Step 4: Write `src/http.rs` — the four routes**

```rust
//! The job API (spec §5): submit, status, result, health.

use crate::{check_bind, Config, Refusal, Service, Shared};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::net::SocketAddr;

/// A job is a program of at most a few hundred KB plus inputs; 8 MiB bounds a malicious body
/// long before it costs anything.
const MAX_JOB_BYTES: usize = 8 * 1024 * 1024;

pub async fn serve(addr: SocketAddr, cfg: Config) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    check_bind(addr, &cfg)?;
    let svc = Service::new(cfg);
    let app = Router::new()
        .route("/v1/jobs", post(submit))
        .route("/v1/jobs/:id", get(status))
        .route("/v1/jobs/:id/result", get(result))
        .route("/v1/health", get(health))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_JOB_BYTES))
        .with_state(svc);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
            tracing::error!("prover server exited: {e}");
        }
    });
    Ok((bound, task))
}

fn authorized(headers: &HeaderMap, svc: &Service) -> bool {
    match &svc.cfg.token {
        None => true,
        Some(t) => headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|got| got == t)
            .unwrap_or(false),
    }
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "missing or wrong bearer token" }))).into_response()
}

async fn submit(State(svc): State<Shared>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&headers, &svc) {
        return unauthorized();
    }
    match svc.submit(&body, peer.ip()) {
        Ok((id, position)) => (StatusCode::ACCEPTED, Json(json!({ "id": id, "position": position }))).into_response(),
        Err(Refusal::Unauthorized) => unauthorized(),
        Err(Refusal::Bad(e)) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
        Err(Refusal::Busy(e, retry)) => (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": e, "retry_after_secs": retry }))).into_response(),
    }
}

async fn status(State(svc): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if !authorized(&headers, &svc) {
        return unauthorized();
    }
    match svc.status(&id) {
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown job" }))).into_response(),
        Some((state, position, elapsed)) => {
            let mut v = json!({ "state": state.as_str() });
            if let Some(p) = position { v["position"] = json!(p); }
            if let Some(ms) = elapsed { v["elapsed_ms"] = json!(ms as u64); }
            Json(v).into_response()
        }
    }
}

async fn result(State(svc): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if !authorized(&headers, &svc) {
        return unauthorized();
    }
    match svc.result(&id) {
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "no result for that job" }))).into_response(),
        Some(sealed) => ([(header::CONTENT_TYPE, "application/octet-stream")], randprotocol_zkvm::delegate::encode(&sealed)).into_response(),
    }
}

/// Open on purpose: a wallet checks the address it pinned before it sends a token or a job.
async fn health(State(svc): State<Shared>) -> Response {
    let (queue_depth, proving) = svc.queue_depth();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "backend": svc.backend_name(),
        "slots": svc.cfg.slots,
        "queue_depth": queue_depth,
        "proving": proving,
        "address": svc.cfg.key.address.to_string(),
    }))
    .into_response()
}
```

- [ ] **Step 5: Run the service tests**

Run: `cargo test -p randprotocol-prover --test service -- --nocapture`
Expected: all eight PASS. The first test proves `fib(20)` at tier 10 in the test profile: seconds, not minutes. If `a_job_that_cannot_start_before_its_deadline_is_refused` races (the first job finishes before the second is submitted), the estimate is 0 and the test gets 202 — make the first job's queue position certain by submitting it and asserting `position == 1`, then submitting the second immediately; if it still flakes, set `cfg.slots = 1` and submit *two* 120 s jobs before the 0 s one.

- [ ] **Step 6: Write `src/main.rs`**

```rust
//! `rand-prover`: run the service, print the address wallets pin, or make a key.
//!
//! The key file is an ordinary wallet key file (`rand keygen` makes one too): the address
//! wallets seal jobs to is that key's `rand1…` address, and its decapsulation key is derived
//! from it exactly as a receiving wallet's is. The spend key in it is never used to spend.

use anyhow::Result;
use clap::{Parser, Subcommand};
use randprotocol_client::wallet::Wallet;
use randprotocol_prover::{serve, Config};
use randprotocol_zkvm::delegate::ProverKey;
use randprotocol_zkvm::machine::Backend;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "rand-prover", version, about = "RAND delegated prover: proves sealed jobs for wallets")]
struct Cli {
    /// Key file (a wallet key file). Its address is what wallets pin.
    #[arg(long, global = true, env = "RAND_PROVER_KEY", default_value = "prover.key.json")]
    key: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve jobs.
    Run {
        #[arg(long, default_value = "127.0.0.1:8600")]
        listen: SocketAddr,
        /// Bearer token wallets must send. Required off loopback unless --allow-open.
        #[arg(long, env = "RAND_PROVER_TOKEN")]
        token: Option<String>,
        /// Prove on an attached NVIDIA GPU (needs a build with --features cuda).
        #[arg(long)]
        cuda: bool,
        /// Concurrent proofs; one per GPU.
        #[arg(long, default_value_t = 1)]
        slots: usize,
        /// Jobs waiting beyond the ones proving.
        #[arg(long, default_value_t = 8)]
        max_queue: usize,
        /// Jobs one client address may have in flight.
        #[arg(long, default_value_t = 2)]
        per_ip: usize,
        /// Seconds a finished result is kept for the wallet to fetch.
        #[arg(long, default_value_t = 600)]
        result_ttl_secs: u64,
        /// Listen off loopback with no token. Every job is then free compute for anyone.
        #[arg(long)]
        allow_open: bool,
    },
    /// Print the address wallets pin (`--prover-address`).
    Address,
    /// Create a new key file (refuses to overwrite).
    Keygen,
}

fn backend_for(cuda: bool) -> Result<Backend> {
    if !cuda {
        return Ok(Backend::Cpu);
    }
    #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
    {
        Ok(Backend::Cuda)
    }
    #[cfg(not(any(feature = "cuda", feature = "mock-cuda")))]
    {
        anyhow::bail!("built without CUDA support; rebuild rand-prover with --features cuda")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => {
            let w = Wallet::generate();
            w.save_new(&cli.key)?;
            println!("wrote {}\naddress: {}", cli.key.display(), w.address);
        }
        Cmd::Address => println!("{}", Wallet::load(&cli.key)?.address),
        Cmd::Run { listen, token, cuda, slots, max_queue, per_ip, result_ttl_secs, allow_open } => {
            let w = Wallet::load(&cli.key)?;
            let key = ProverKey::from_viewing_key(&w.vk);
            let cfg = Config { key, backend: backend_for(cuda)?, slots, max_queue, token, per_ip, result_ttl: Duration::from_secs(result_ttl_secs), allow_open };
            eprintln!("rand-prover: every job holds the sending wallet's spend key; run this only for wallets that trust you with custody");
            let (bound, task) = serve(listen, cfg).await?;
            eprintln!("listening on {bound}; address {}", w.address);
            task.await?;
        }
    }
    Ok(())
}
```

- [ ] **Step 7: Build the binary and check the bind guard by hand**

Run:
```bash
cargo build -p randprotocol-prover
./target/debug/rand-prover keygen --key /tmp/p.key.json
./target/debug/rand-prover address --key /tmp/p.key.json | head -c 12; echo
./target/debug/rand-prover run --key /tmp/p.key.json --listen 0.0.0.0:8600; echo "exit $?"
```
Expected: the keygen writes; the address starts `rand1`; the run on `0.0.0.0` without a token exits non-zero with the "refusing to listen" message.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock crates/randprotocol-prover
git commit -m "prover: rand-prover — a trusted proving service with a sealed job API, a bounded queue, one slot per backend, a bearer token and a deadline refusal

POST /v1/jobs, GET /v1/jobs/{id}, GET /v1/jobs/{id}/result, GET /v1/health (spec §5). The
prover never reads the chain; a job is a pure function. Inputs zeroize with the job; logs carry
ids, kinds and timings only. Off loopback it refuses to bind without --token.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 4: the wallet's `Prover` — local or remote, threaded through every proving path

**Files:**
- Create: `crates/randprotocol-client/src/prover.rs`
- Modify: `crates/randprotocol-client/src/lib.rs` (add `pub mod prover;`)
- Modify: `crates/randprotocol-client/src/wallet.rs:773-880` (`prove_bundles`, `prove_one`), `:939-951` (`submit`), `:1028-1040` (`submit_burn`), `:1268-1280` (`send`)
- Modify: `crates/randprotocol-client/src/main.rs:26-36` (flags), `:299-312` (`backend_for` → `prover_for`), the eight call sites at `:489, :541, :586, :609-634, :757, :824`
- Modify: `crates/randprotocol-client/tests/wallet_flow.rs`, `crates/randprotocol-node/tests/cluster.rs` (mechanical)
- Test: `crates/randprotocol-client/src/prover.rs` unit tests; the wallet-flow additions are Task 5

**Interfaces:**
- Consumes: `randprotocol_zkvm::delegate::*`, `executor::{prove_bundle, prove, prove_call}`.
- Produces, in `randprotocol_client::prover`:

```rust
pub enum Prover { Local(Backend), Remote(RemoteProver) }
pub struct RemoteProver { /* url, address, token, deadline_secs, http, checked */ }
impl RemoteProver { pub fn new(url: String, address: ShieldedAddress, token: Option<String>, deadline_secs: u32) -> RemoteProver }
impl Prover {
    pub async fn prove_bundle(&self, profile: FriProfile, inputs: &[u32]) -> anyhow::Result<(Vec<u8>, Word8, u8)>;
    pub async fn prove_program(&self, profile: FriProfile, program: &Program, inputs: &[u32], tier: Option<u8>, want_salt: bool) -> anyhow::Result<(Vec<u8>, [u32; 8], u8, Option<[u32; 4]>)>;
    pub fn where_(&self) -> String;   // "locally" | "at http://…"
}
pub fn profile_name(p: FriProfile) -> &'static str;
pub const LOCAL_HINT: &str = "drop --prover to prove here (about a minute and a half per bundle on a laptop)";
```

- Wallet signatures after this task: `submit(rpc, w, store, to, action, fee, burn, profile, prover: &Prover, chain_id, wait)`, `send(rpc, w, store, to, amount, fee, profile, prover: &Prover, chain_id, wait)`, `submit_burn(…, profile, prover: &Prover, …)` — the `Backend` parameter is replaced in place, nothing else moves.

- [ ] **Step 1: Write the unit tests for the remote client's error mapping**

At the bottom of the new `crates/randprotocol-client/src/prover.rs` (write the tests first, the module body in step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_round_trip_through_the_executor_parser() {
        use randprotocol_zkvm::executor::ZkExecutor;
        for p in [FriProfile::Production, FriProfile::Test] {
            assert_eq!(ZkExecutor::profile_from_str(profile_name(p)), Some(p));
        }
    }

    #[test]
    fn a_429_names_the_estimate_and_the_local_alternative() {
        let e = map_refusal(429, &serde_json::json!({ "error": "queue full", "retry_after_secs": 90 }));
        let text = e.to_string();
        assert!(text.contains("queue full") && text.contains("90 s") && text.contains(LOCAL_HINT), "{text}");
    }

    #[test]
    fn a_401_says_token() {
        assert!(map_refusal(401, &serde_json::json!({})).to_string().contains("token"));
    }

    #[test]
    fn a_wrong_pin_is_refused_before_any_job() {
        let ours = randprotocol_core::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
        let theirs = randprotocol_core::notes::ShieldedAddress { pk: [3; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
        assert!(check_pin(&ours, &theirs.to_string()).is_err());
        assert!(check_pin(&ours, &ours.to_string()).is_ok());
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p randprotocol-client --lib prover`
Expected: compile error, the module does not exist.

- [ ] **Step 3: Write the module**

```rust
//! Where a proof is made: on this machine, or at a `rand-prover` the user trusts
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §7).
//!
//! Both arms return exactly what `executor`'s functions return, so `wallet.rs` neither knows
//! nor cares. The remote arm posts a sealed job, polls, fetches and opens the sealed result. A
//! remote failure is an error that names the local alternative — never a silent fallback: a
//! user who chose delegation for a phone would rather be told than wait a hundred seconds.

use anyhow::{anyhow, Context, Result};
use randprotocol_core::notes::{ShieldedAddress, Word8};
use randprotocol_zkvm::delegate::{self, JobKind, JobRequest, JobResult, ReplyKey, VERSION};
use randprotocol_zkvm::executor;
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const LOCAL_HINT: &str = "drop --prover to prove here (about a minute and a half per bundle on a laptop)";

pub fn profile_name(p: FriProfile) -> &'static str {
    match p {
        FriProfile::Production => "production",
        FriProfile::Test => "test",
    }
}

pub enum Prover {
    Local(Backend),
    Remote(RemoteProver),
}

pub struct RemoteProver {
    url: String,
    address: ShieldedAddress,
    token: Option<String>,
    deadline_secs: u32,
    http: reqwest::Client,
    checked: AtomicBool,
}

impl RemoteProver {
    pub fn new(url: String, address: ShieldedAddress, token: Option<String>, deadline_secs: u32) -> RemoteProver {
        let url = url.trim_end_matches('/').to_string();
        RemoteProver { url, address, token, deadline_secs, http: reqwest::Client::new(), checked: AtomicBool::new(false) }
    }

    fn req(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => r.bearer_auth(t),
            None => r,
        }
    }

    /// `/v1/health` once per process: the address the service reports must be the one pinned.
    async fn check_once(&self) -> Result<()> {
        if self.checked.load(Ordering::Relaxed) {
            return Ok(());
        }
        let v: serde_json::Value = self
            .http
            .get(format!("{}/v1/health", self.url))
            .send()
            .await
            .with_context(|| format!("the prover at {} is unreachable; {LOCAL_HINT}", self.url))?
            .json()
            .await
            .context("the prover's /v1/health is not JSON")?;
        check_pin(&self.address, v["address"].as_str().unwrap_or(""))?;
        if v["backend"] == "cpu" {
            eprintln!("note: the prover at {} proves on a CPU; expect laptop speed, not GPU speed", self.url);
        }
        self.checked.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn run(&self, profile: FriProfile, kind: JobKind) -> Result<JobResult> {
        self.check_once().await?;
        let reply = ReplyKey::generate();
        let job = JobRequest { version: VERSION, profile: profile_name(profile).into(), kind, deadline_secs: self.deadline_secs, reply_ek: reply.ek.clone() };
        let sealed = delegate::seal_job(&self.address, &job).map_err(|e| anyhow!("sealing the job: {e}"))?;
        let r = self
            .req(self.http.post(format!("{}/v1/jobs", self.url)))
            .body(delegate::encode(&sealed))
            .send()
            .await
            .with_context(|| format!("the prover at {} is unreachable; {LOCAL_HINT}", self.url))?;
        let status = r.status().as_u16();
        let v: serde_json::Value = r.json().await.unwrap_or_default();
        if status != 202 {
            return Err(map_refusal(status, &v));
        }
        let id = v["id"].as_str().ok_or_else(|| anyhow!("the prover accepted the job but returned no id"))?.to_string();
        eprintln!("prover accepted job {} at queue position {}", &id[..8], v["position"]);
        let mut wait = Duration::from_secs(1);
        let started = std::time::Instant::now();
        loop {
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(Duration::from_secs(5));
            let s: serde_json::Value = self.req(self.http.get(format!("{}/v1/jobs/{id}", self.url))).send().await?.json().await?;
            match s["state"].as_str().unwrap_or("") {
                "queued" => eprintln!("  queued, position {} ({:.0?})", s["position"], started.elapsed()),
                "proving" => eprintln!("  proving ({:.0?})", started.elapsed()),
                "done" | "failed" => break,
                "expired" => return Err(anyhow!("the prover could not start the job within {} s; run the command again, or raise --prover-deadline; {LOCAL_HINT}", self.deadline_secs)),
                other => return Err(anyhow!("the prover reports an unknown state {other:?}")),
            }
        }
        let bytes = self.req(self.http.get(format!("{}/v1/jobs/{id}/result", self.url))).send().await?.bytes().await?;
        let sealed = delegate::decode(&bytes).map_err(|e| anyhow!("the prover's result is not a sealed result: {e}"))?;
        delegate::open_result(&reply, &sealed).map_err(|e| anyhow!("the prover's result did not open under this job's key ({e}); not retrying"))
    }
}

pub(crate) fn map_refusal(status: u16, v: &serde_json::Value) -> anyhow::Error {
    let error = v["error"].as_str().unwrap_or("no detail");
    match status {
        401 => anyhow!("the prover refused the token (401): set --prover-token / RAND_PROVER_TOKEN"),
        429 => {
            let retry = v["retry_after_secs"].as_u64().unwrap_or(0);
            anyhow!("the prover is busy (429): {error}; it estimates {retry} s — try again then, raise --prover-deadline, or {LOCAL_HINT}")
        }
        400 => anyhow!("the prover rejected the job (400): {error}"),
        s => anyhow!("the prover answered {s}: {error}"),
    }
}

pub(crate) fn check_pin(pinned: &ShieldedAddress, reported: &str) -> Result<()> {
    if reported != pinned.to_string() {
        return Err(anyhow!("the prover reports a different address than --prover-address pins; refusing to send it anything"));
    }
    Ok(())
}

impl Prover {
    pub fn where_(&self) -> String {
        match self {
            Prover::Local(_) => "locally".into(),
            Prover::Remote(r) => format!("at {}", r.url),
        }
    }

    pub async fn prove_bundle(&self, profile: FriProfile, inputs: &[u32]) -> Result<(Vec<u8>, Word8, u8)> {
        match self {
            Prover::Local(backend) => executor::prove_bundle(profile, inputs, *backend).map_err(|e| anyhow!("proving the bundle failed: {e}")),
            Prover::Remote(r) => match r.run(profile, JobKind::Bundle { inputs: inputs.to_vec() }).await? {
                JobResult::Bundle { proof, digest, tier } => Ok((proof, digest, tier)),
                JobResult::Failed { error } => Err(anyhow!("prover: {error}")),
                other => Err(anyhow!("the prover answered a bundle job with {}", kind_of(&other))),
            },
        }
    }

    pub async fn prove_program(&self, profile: FriProfile, program: &Program, inputs: &[u32], tier: Option<u8>, want_salt: bool) -> Result<(Vec<u8>, [u32; 8], u8, Option<[u32; 4]>)> {
        match self {
            Prover::Local(backend) => {
                if want_salt {
                    let (proof, outputs, tier, salt) = executor::prove_call(profile, program, inputs, tier, *backend).map_err(|e| anyhow!(e))?;
                    Ok((proof, outputs, tier, Some(salt)))
                } else {
                    let (proof, outputs, tier) = executor::prove(profile, program, inputs, tier, *backend).map_err(|e| anyhow!(e))?;
                    Ok((proof, outputs, tier, None))
                }
            }
            Prover::Remote(r) => {
                let kind = JobKind::Program { base_pc: program.base_pc, words: program.words.clone(), inputs: inputs.to_vec(), tier, want_salt };
                match r.run(profile, kind).await? {
                    JobResult::Program { proof, outputs, tier, salt } => {
                        if want_salt && salt.is_none() {
                            return Err(anyhow!("the prover returned no salt for a call that publishes an input envelope"));
                        }
                        Ok((proof, outputs, tier, salt))
                    }
                    JobResult::Failed { error } => Err(anyhow!("prover: {error}")),
                    other => Err(anyhow!("the prover answered a program job with {}", kind_of(&other))),
                }
            }
        }
    }
}

fn kind_of(r: &JobResult) -> &'static str {
    match r {
        JobResult::Bundle { .. } => "a bundle result",
        JobResult::Program { .. } => "a program result",
        JobResult::Failed { .. } => "a failure",
    }
}
```

Add `pub mod prover;` to `crates/randprotocol-client/src/lib.rs`. `serde_json` is already a dependency of the client crate.

- [ ] **Step 4: Run the unit tests**

Run: `cargo test -p randprotocol-client --lib prover`
Expected: four PASS.

- [ ] **Step 5: Thread `Prover` through `wallet.rs`**

In `wallet.rs`:

1. `use crate::prover::Prover;` at the top; remove `use randprotocol_zkvm::executor::prove_bundle;` and the `Backend` import if nothing else uses it.
2. `prove_bundles(rpc, w, plans, profile, prover: &Prover)` — replace the `backend: Backend` parameter; its loop becomes `proved.push(prove_one(w, plan, paths, root, time, &which, profile, prover).await?);`.
3. `prove_one(…, profile: FriProfile, prover: &Prover)` becomes `async fn`; replace
   `eprintln!("proving {which} (tier 14; about a minute on a laptop)…");` with
   `eprintln!("proving {which} {} (tier 14)…", prover.where_());` and
   `let (proof, digest, tier) = prove_bundle(profile, &words, backend).map_err(|e| anyhow!("proving the bundle failed: {e}"))?;` with
   `let (proof, digest, tier) = prover.prove_bundle(profile, &words).await?;`.
   In the digest-mismatch error, change "(wallet bug)" to `"(a wallet bug, or a prover {} that proved some other bundle)", prover.where_()` — keep the rest of the message intact so the tamper test can match "refusing to submit".
4. `submit(…, profile: FriProfile, prover: &Prover, chain_id, wait)` and `submit_burn` likewise; every internal `prove_bundles(rpc, w, &plans, profile, backend)` becomes `prove_bundles(rpc, w, &plans, profile, prover)`.
5. `send(…, profile, prover: &Prover, chain_id, wait)` forwards `prover`.

- [ ] **Step 6: Thread it through `main.rs`**

1. Flags on `Cli`, after `key`:

```rust
    /// A `rand-prover` to delegate proving to. Unset: prove on this machine.
    #[arg(long, global = true, env = "RAND_PROVER")]
    prover: Option<String>,
    /// The prover's rand1… address (`rand-prover address`); jobs are sealed to it. Required with --prover.
    #[arg(long, global = true, env = "RAND_PROVER_ADDRESS")]
    prover_address: Option<String>,
    /// Bearer token the prover expects.
    #[arg(long, global = true, env = "RAND_PROVER_TOKEN")]
    prover_token: Option<String>,
    /// Seconds the prover may take to *start* the job before it must refuse it.
    #[arg(long, global = true, env = "RAND_PROVER_DEADLINE", default_value_t = 120)]
    prover_deadline: u32,
```

2. Replace `backend_for(cuda: bool) -> Result<Backend>` with:

```rust
/// Where this run proves. `--cuda` and `--prover` are two answers to one question, so both is
/// an error; and the first delegated run of a process says what delegation costs.
fn prover_for(cli: &Cli, cuda: bool) -> Result<Prover> {
    match &cli.prover {
        None => Ok(Prover::Local(backend_for(cuda)?)),
        Some(url) => {
            if cuda {
                anyhow::bail!("--cuda proves here and --prover proves there; pass one");
            }
            let address = cli.prover_address.as_deref().ok_or_else(|| anyhow::anyhow!("--prover needs --prover-address (RAND_PROVER_ADDRESS): the rand1… address `rand-prover address` prints"))?;
            let address = parse_address(address).context("--prover-address")?;
            eprintln!("warning: delegating to {url} hands it this wallet's spend key with every bundle; only a prover you would give your key file to");
            Ok(Prover::Remote(RemoteProver::new(url.clone(), address, cli.prover_token.clone(), cli.prover_deadline)))
        }
    }
}
```

Keep `backend_for` as it is (it is what `Local` uses). Add `use randprotocol_client::prover::{Prover, RemoteProver};`.

3. At each of the call sites `:489, :541, :586, :757, :824`: `backend_for(cuda)?` → `&prover_for(&cli, cuda)?`. Since `cli.cmd` is matched by value, `prover_for` must be called with a reference taken *before* the match or with the fields it needs cloned out: at the top of `main` after `let cli = Cli::parse();` add `let delegation = (cli.prover.clone(), cli.prover_address.clone(), cli.prover_token.clone(), cli.prover_deadline);` and make `prover_for` take that tuple instead of `&Cli` — `fn prover_for(d: &(Option<String>, Option<String>, Option<String>, u32), cuda: bool) -> Result<Prover>`, reading `d.0..d.3`. Every call site then reads `&prover_for(&delegation, cuda)?`.

4. The `Call` command (lines 609-634): replace `let backend = backend_for(cuda)?;` with `let prover = prover_for(&delegation, cuda)?;`, and the `if no_envelope { … } else { … }` block with:

```rust
            eprintln!("proving the call {} ({} inputs stay private)…", prover.where_(), inputs.len());
            let t = std::time::Instant::now();
            let (proof, outputs, tier, salt) = prover.prove_program(profile, &prog, &inputs, tier, !no_envelope).await?;
            let (envelope, call_key) = match salt {
                None => (None, None),
                Some(salt) => {
                    let h_in = hash::input_digest(salt, &inputs);
                    let (e, key) = call_envelope::seal_call_envelope(&w.vk, auditor.as_ref(), &h_in, salt, &inputs).map_err(|e| anyhow::anyhow!(e))?;
                    (Some(e), Some(key))
                }
            };
```

and the later `wallet::submit(…, profile, backend, chain_id, true)` becomes `wallet::submit(…, profile, &prover, chain_id, true)`.

- [ ] **Step 7: Mechanical updates in the two test files**

In `crates/randprotocol-client/tests/wallet_flow.rs` and `crates/randprotocol-node/tests/cluster.rs`, every wallet call that passes `Backend::Cpu` now passes `&Prover::Local(Backend::Cpu)`:

```bash
sed -i '' 's/FriProfile::Test, Backend::Cpu, CHAIN_ID/FriProfile::Test, \&Prover::Local(Backend::Cpu), CHAIN_ID/g' crates/randprotocol-client/tests/wallet_flow.rs crates/randprotocol-node/tests/cluster.rs
grep -n 'Backend::Cpu' crates/randprotocol-client/tests/wallet_flow.rs crates/randprotocol-node/tests/cluster.rs
```

Any remaining `Backend::Cpu` that is an argument to `wallet::submit`/`send`/`submit_burn` spread over several lines (cluster.rs `:1091` and wallet_flow.rs `:223-232`) is edited by hand to `&Prover::Local(Backend::Cpu)`. Direct `executor::prove_call(…, Backend::Cpu)` calls stay. Add `use randprotocol_client::prover::Prover;` to both files.

- [ ] **Step 8: Build everything and run the fast suites**

Run:
```bash
cargo build --workspace --tests 2>&1 | grep -E '^(error|warning: unused)' | head
cargo test -p randprotocol-client --lib
cargo test -p randprotocol-core
```
Expected: no errors; the client lib and core suites PASS.

- [ ] **Step 9: Run one existing proving test to prove the local arm is unchanged**

Run: `cargo test -p randprotocol-client --test wallet_flow -- --nocapture 2>&1 | tail -5`
Expected: PASS (minutes; six bundle proofs and a call under the proving slot).

- [ ] **Step 10: Commit**

```bash
git add crates/randprotocol-client crates/randprotocol-node/tests/cluster.rs
git commit -m "wallet: a Prover — local or a rand-prover — replaces the Backend every proving path took; --prover, --prover-address, --prover-token, --prover-deadline

The remote arm seals the job to the pinned address, polls, opens the result and returns
exactly what executor would have; the digest check and the envelope sealing stay in the
wallet, so a wrong prover is caught before submission. No silent fallback: a remote failure
names the local alternative. The first delegated run warns that the prover holds the spend key.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 5: end-to-end — a delegated send, a tampering prover, a delegated call

**Files:**
- Modify: `crates/randprotocol-client/tests/wallet_flow.rs` (append one test function; the existing test is untouched)
- Modify: `crates/randprotocol-client/Cargo.toml` (`[dev-dependencies]` gains `randprotocol-prover = { path = "../randprotocol-prover" }`, `axum = { workspace = true }`)

**Interfaces:**
- Consumes: `randprotocol_prover::{serve, Config}`, `randprotocol_client::prover::{Prover, RemoteProver}`, the existing `genesis`, `init_tracing`, `proving_slot` helpers in the file.

- [ ] **Step 1: Write the failing test**

Append to `wallet_flow.rs`:

```rust
/// Spec §12: the same send, bond-free, through an in-process `rand-prover`; then a prover that
/// answers with a proof of a *different* bundle, which the wallet's digest check refuses; then
/// a call through the prover with an input envelope the caller opens back (the §6 salt path).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegated_proving_sends_calls_and_refuses_a_tampering_prover() {
    use randprotocol_client::prover::{Prover, RemoteProver};
    use randprotocol_prover::{serve, Config};
    use randprotocol_zkvm::delegate::ProverKey;
    init_tracing();
    let validator = Keypair::generate();
    let dir = tempfile::tempdir().unwrap();
    let cfg = NodeConfig {
        datadir: dir.path().join("v"),
        keypair: Some(validator.clone()),
        listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        bootstrap: vec![],
        rpc: Some("127.0.0.1:0".parse().unwrap()),
        genesis: genesis(&validator),
        block_interval: Duration::from_millis(3000),
        view_timeout: Duration::from_secs(10),
        mdns: false,
        verify_chain: false,
        keep_raw_proofs: false,
        fri_profile: FriProfile::Test,
    };
    let NodeHandle { rpc_addr, .. } = node::start(cfg).await.unwrap();
    let rpc = RpcClient::new(format!("http://{}", rpc_addr.unwrap()));

    // The prover.
    let prover_wallet = Wallet::generate();
    let key = ProverKey::from_viewing_key(&prover_wallet.vk);
    let (prover_addr, _prover_task) = serve("127.0.0.1:0".parse().unwrap(), Config::test(key)).await.unwrap();
    let remote = Prover::Remote(RemoteProver::new(format!("http://{prover_addr}"), prover_wallet.address.clone(), None, 600));

    // Two wallets, one funded by the faucet.
    let a = Wallet::generate();
    let b = Wallet::generate();
    let mut a_store = NoteStore::default();
    let mut b_store = NoteStore::default();
    rpc.faucet(&a.address.to_string()).await.unwrap();
    wait_for_balance(&rpc, &a, &mut a_store, 1).await;

    // 1. A delegated send: proved at the prover, submitted by the wallet, found by B.
    let pay = 3 * UNITS_PER_RAND;
    let fee = gas::BUNDLE_BASE_FEE;
    let slot = proving_slot().await;
    let sent = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, &remote, CHAIN_ID, true).await.unwrap();
    drop(slot);
    assert!(sent.committed_height.is_some(), "{}", sent.summary("delegated send"));
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay);

    // 2. A tampering prover: an axum stub that answers every job with a canned proof of some
    //    other bundle. It cannot forge a digest the wallet computed, so the wallet refuses.
    let tamper = tampering_prover(&prover_wallet, sent.bundle_proof.clone()).await;
    let bad = Prover::Remote(RemoteProver::new(format!("http://{tamper}"), prover_wallet.address.clone(), None, 600));
    let slot = proving_slot().await;
    let err = wallet::send(&rpc, &a, &mut a_store, &b.address, UNITS_PER_RAND, fee, FriProfile::Test, &bad, CHAIN_ID, true).await.unwrap_err();
    drop(slot);
    assert!(err.to_string().contains("refusing to submit"), "{err}");
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay, "nothing was submitted");

    // 3. A delegated call with an input envelope: the salt came back from the prover, the
    //    wallet sealed the transcript, and the caller opens it under its own viewing key.
    let prog = guests::private_payment(1000);
    let deploy = Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone() };
    let slot = proving_slot().await;
    wallet::submit(&rpc, &a, &mut a_store, None, deploy, wallet::deploy_fee_default(&Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone() }), Burn::None, FriProfile::Test, &remote, CHAIN_ID, true).await.unwrap();
    drop(slot);
    let inputs = vec![400u32, 250, 300, 75];
    let slot = proving_slot().await;
    let (proof, _outputs, tier, salt) = remote.prove_program(FriProfile::Test, &prog, &inputs, None, true).await.unwrap();
    let salt = salt.expect("want_salt");
    let h_in = hash::input_digest(salt, &inputs);
    let (envelope, _key) = call_envelope::seal_call_envelope(&a.vk, None, &h_in, salt, &inputs).unwrap();
    let pid = randprotocol_core::Hash::from_bytes(&randprotocol_zkvm::executor::ZkExecutor::code_hash_bytes(&prog.digest()));
    let call = Action::Call { program: pid, proof, input_envelope: Some(envelope) };
    let called = wallet::submit(&rpc, &a, &mut a_store, None, call, wallet::call_fee_default(tier), Burn::None, FriProfile::Test, &remote, CHAIN_ID, true).await.unwrap();
    drop(slot);
    let receipt = rpc.wait_for_receipt(&called.hash, Duration::from_secs(120)).await.unwrap();
    let opened = call_envelope::open_call_envelope_as_caller(&a.vk, receipt["input_envelope"].as_str().unwrap(), &h_in).unwrap();
    assert_eq!(opened, inputs);
}

/// A prover that ignores the job and answers with `canned`, sealed properly to the job's
/// reply key — so the only thing wrong with it is *which* bundle it proved.
async fn tampering_prover(prover_wallet: &Wallet, canned: Vec<u8>) -> std::net::SocketAddr {
    use axum::{extract::State, routing::{get, post}, Json, Router};
    use randprotocol_zkvm::delegate::{self, JobResult, ProverKey};
    use std::sync::{Arc, Mutex};
    struct S { key: ProverKey, canned: Vec<u8>, last: Mutex<Option<Vec<u8>>>, address: String }
    let state = Arc::new(S { key: ProverKey::from_viewing_key(&prover_wallet.vk), canned, last: Mutex::new(None), address: prover_wallet.address.to_string() });
    let app = Router::new()
        .route("/v1/health", get(|State(s): State<Arc<S>>| async move { Json(serde_json::json!({ "address": s.address, "backend": "cpu" })) }))
        .route("/v1/jobs", post(|State(s): State<Arc<S>>, body: axum::body::Bytes| async move {
            let job = delegate::open_job(&s.key, &delegate::decode(&body).unwrap()).unwrap();
            let result = JobResult::Bundle { proof: s.canned.clone(), digest: [0xdead_beef; 8], tier: 14 };
            *s.last.lock().unwrap() = Some(delegate::encode(&delegate::seal_result(&job.reply_ek, &result).unwrap()));
            (axum::http::StatusCode::ACCEPTED, Json(serde_json::json!({ "id": "00".repeat(16), "position": 1 })))
        }))
        .route("/v1/jobs/:id", get(|| async { Json(serde_json::json!({ "state": "done" })) }))
        .route("/v1/jobs/:id/result", get(|State(s): State<Arc<S>>| async move { s.last.lock().unwrap().clone().unwrap() }))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}
```

Three names in that test are assumptions about the existing file; verify each against the first test function in `wallet_flow.rs` and use the file's real names: the helper that waits for a faucet note to scan (`wait_for_balance` or whatever the file does inline), the RPC faucet call (`rpc.faucet`), the fields `Submission::committed_height` and `Submission::bundle_proof` (if `Submission` does not carry the proof bytes, take the canned proof from a `randprotocol_zkvm::executor::prove_bundle` call on the *first* send's plan instead — any real bundle proof works, since the wallet's expected digest never matches it), the program-id derivation for `Action::Call` (copy exactly what the first test does after its deploy), and the receipt-opening call (copy what the first test does at its end). The tamper test's assertion is the one that matters: `refusing to submit` and B's balance unchanged.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p randprotocol-client --test wallet_flow delegated_proving -- --nocapture`
Expected: compile error until the dev-dependencies are added; then, once compiling, PASS is the goal.

- [ ] **Step 3: Add the dev-dependencies**

In `crates/randprotocol-client/Cargo.toml` under `[dev-dependencies]`:

```toml
# `tests/wallet_flow.rs` runs a real `rand-prover` in-process for the delegated path, and an axum
# stub for the tampering one. Dev-only, so the wallet library never links the service.
randprotocol-prover = { path = "../randprotocol-prover" }
axum = { workspace = true }
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p randprotocol-client --test wallet_flow delegated_proving -- --nocapture 2>&1 | tail -20`
Expected: PASS. Three bundle proofs (send, tamper's canned one is not proved, deploy) and one call proof through the prover: several minutes.

- [ ] **Step 5: Run the whole wallet-flow file and the cluster suite's proving tests**

Run:
```bash
cargo test -p randprotocol-client --test wallet_flow 2>&1 | tail -3
cargo test -p randprotocol-node --test cluster 2>&1 | tail -3
```
Expected: both PASS. The cluster suite is ~23 minutes; run it in the background and check the tail.

- [ ] **Step 6: Commit**

```bash
git add crates/randprotocol-client/Cargo.toml crates/randprotocol-client/tests/wallet_flow.rs Cargo.lock
git commit -m "wallet: the delegated path end to end — a send and an enveloped call through an in-process rand-prover, and a tampering prover the digest check refuses

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 6: docs, README, AGENTS.md, and the experiment script

**Files:**
- Create: `docs/delegated-proving.md`
- Create: `scripts/delegated-experiment.sh`
- Modify: `README.md` (the component table row for Interfaces at line 21; the wallet section around line 172; the crate list), `AGENTS.md` (an entry for the branch; look at the last entry's shape and copy it)

- [ ] **Step 1: Write `docs/delegated-proving.md`**

```markdown
# Delegated proof generation

**A prover you delegate to holds your spend key.** Every bundle a wallet delegates carries the
wallet's spend key as a private input — the bundle guest derives the viewing key from it in
the circuit — so the operator of a `rand-prover` can spend every note that wallet owns and
every note it will receive. Delegate only to a prover you would hand your key file to: one you
run yourself, or one run by someone who already has that trust. Splitting the key so a prover
can prove but not spend is the next design (spec §9); until it lands, this page describes a
*trusted* prover.

What delegation buys is time and reach: a proof that takes a hundred seconds on a laptop and
cannot be made on a phone at all is made where a GPU is. What it costs, besides custody, is
privacy toward the prover: it sees the notes being spent, the amounts, the recipient and the
client's IP. Toward everyone else — the chain, the network, the other prover's users —
nothing changes: the transaction the chain sees is indistinguishable from a locally proved one.

Spec: `docs/superpowers/specs/2026-09-17-delegated-proving-design.md`.

## Running a prover

```bash
rand-prover keygen --key prover.key.json           # an ordinary wallet key file
rand-prover address --key prover.key.json          # the rand1… address wallets pin
rand-prover run --key prover.key.json --listen 127.0.0.1:8600 --token "$(openssl rand -hex 16)"
```

| flag | default | meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8600` | off loopback needs `--token` or `--allow-open` |
| `--token` (`RAND_PROVER_TOKEN`) | none | the bearer wallets send; without it the service is free compute for anyone who finds it |
| `--cuda` | off | prove on the GPU; needs a build with `--features cuda` |
| `--slots` | 1 | concurrent proofs, one per GPU |
| `--max-queue` | 8 | jobs waiting beyond the slots |
| `--per-ip` | 2 | jobs one client address may have in flight |
| `--result-ttl-secs` | 600 | how long a finished result waits to be fetched |

Put TLS in front of it (any reverse proxy): the job itself is sealed to the prover's key, so
TLS protects the token and hides which wallet talks to which prover from the path.

The log carries job ids, kinds, queue waits and proving times. It never carries an input word,
a note, or an address; if you see one, that is a bug to report.

## Using one from the wallet

```bash
export RAND_PROVER=https://prover.example:8600
export RAND_PROVER_ADDRESS=rand1…        # what `rand-prover address` printed
export RAND_PROVER_TOKEN=…
rand send rand1… 1.5                     # proved there, submitted from here
rand bond <validator> 1000 …             # the same
rand call <program> 400 250 300 75       # a call, with its input envelope
```

Or `--prover`, `--prover-address`, `--prover-token` on any command. `--cuda` and `--prover`
together are an error: a proof is made in one place. The first delegated command of a run
prints the custody warning above.

Before the first job the wallet reads the prover's `/v1/health` and refuses to continue if the
address there is not the one pinned. Then, per proof: the wallet builds the witness exactly as
it would locally, seals it to the prover's address under a fresh one-time reply key, posts it,
polls, fetches the sealed result, opens it, and — this is the part that makes a *wrong* prover
harmless short of custody — checks that the proof publishes the digest the wallet computed
from its own plaintext. A proof of any other bundle is refused before the chain sees it.
Envelopes, transaction keys and submission are the same code as the local path.

**Deadline.** `--prover-deadline` (default 120 s) is how long the prover may take to *start*
the job. A bundle binds the chain height it was planned at, and admission accepts it for 256
blocks — about four minutes at chain 12's one-second interval — so a job that queues for
longer produces a proof the chain rejects. The prover refuses up front, with its estimate,
rather than proving late; the wallet then says so and stops. There is no automatic fallback to
local proving: a phone that delegated because it cannot prove would only hang.

## Errors you will see

| message | what happened | do |
|---|---|---|
| `the prover at … is unreachable` | connect, TLS or a 5xx | check the URL; or drop `--prover` |
| `refused the token (401)` | wrong or missing bearer | set `--prover-token` |
| `is busy (429): …; it estimates N s` | queue full or the deadline cannot be met | wait N s, raise `--prover-deadline`, or prove locally |
| `reports a different address than --prover-address pins` | wrong pin, or a different prover behind that URL | fix the pin; nothing was sent |
| `refusing to submit` | the returned proof is for some other bundle | stop using that prover |
| `could not start the job within N s` | it queued past the deadline | run the command again |

## What the experiment measures

The 2026-09-17 comparison (spec §11): submit-to-commit wall clock of twenty `rand send`s,
local on a laptop versus delegated to a CPU droplet versus delegated to a GPU host. Chain
finality and throughput are expected unchanged — delegation moves proving off the client, it
does not shrink the 1.3 MB proof a block carries — so the only row that can move is the
client's latency, and only a GPU host can move it. `scripts/delegated-experiment.sh` runs the
loop and prints the table. The numbers go here when they exist.
```

- [ ] **Step 2: Write `scripts/delegated-experiment.sh`**

```bash
#!/usr/bin/env bash
# The spec §11 loop: N sends, each timed from submission to the commit the wallet waits for,
# under whatever RAND_PROVER* is (or is not) set in the environment. Prints one line per run and
# a summary. Usage: scripts/delegated-experiment.sh <to rand1…> [amount RAND=0.5] [runs=20]
set -euo pipefail
TO=${1:?destination address}
AMOUNT=${2:-0.5}
RUNS=${3:-20}
RAND=${RAND_BIN:-target/release/rand}
label="local"; [ -n "${RAND_PROVER:-}" ] && label="delegated ${RAND_PROVER}"
echo "mode: $label; runs: $RUNS; amount: $AMOUNT"
total=0
for i in $(seq 1 "$RUNS"); do
  start=$(date +%s.%N)
  "$RAND" send "$TO" "$AMOUNT" >/dev/null
  end=$(date +%s.%N)
  secs=$(echo "$end - $start" | bc)
  total=$(echo "$total + $secs" | bc)
  printf 'run %2d: %7.1f s\n' "$i" "$secs"
done
printf 'mean: %.1f s over %d runs (%s)\n' "$(echo "$total / $RUNS" | bc -l)" "$RUNS" "$label"
```

`chmod +x scripts/delegated-experiment.sh`.

- [ ] **Step 3: README and AGENTS.md**

README: in the component table (line 21), append to the Interfaces row: `; \`rand-prover\`, a trusted delegated prover the wallet can hand its proofs to (\`docs/delegated-proving.md\`)`. Under the wallet section near line 172, after the `rand send` example, add:

```
rand --prover https://prover:8600 --prover-address rand1… send rand1… 1.5   # proved there, ~seconds on a GPU; the prover holds your spend key
```

In the crate list, add a row: `| \`randprotocol-prover\` | \`rand-prover\`: the delegated prover service — a sealed job API, a bounded queue, one slot per backend |`. In the docs table (line ~288), a row for `docs/delegated-proving.md`.

AGENTS.md: read its last dated entry and add one in the same shape: branch `feat/delegated-proof-generation`, spec and plan paths, what landed (the four commits' subjects), that the chain is unchanged, that v0.3 waits on the §11 experiment, and the one trap: `machine.rs` is vendored, so the `prove_salted_with` hunk is mirrored in `circuits/research/src/machine.rs` (commit hash from Task 1 step 8).

- [ ] **Step 4: Commit**

```bash
git add docs/delegated-proving.md scripts/delegated-experiment.sh README.md AGENTS.md
git commit -m "docs: delegated proving — the operator and wallet guide (custody first), the README rows, the AGENTS.md entry, the §11 experiment loop

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013dJJAGbDPDmf9i6UsXLxvB"
```

---

### Task 7: the full suites, and the branch report

- [ ] **Step 1: Run every suite**

```bash
cargo test --workspace --exclude randprotocol-rvm 2>&1 | grep -E '^(test result|error|failures:)' | head -30
```

Expected: every `test result` line is `ok`. This takes the better part of an hour (the cluster suite alone is ~23 minutes; the proving slot serialises the proofs). Run it in the background and read the output file when notified. Check `df -h /` first: keep ≥ 20 GB free while node A runs on the shared checkout.

- [ ] **Step 2: Confirm the chain is untouched**

```bash
git diff main --stat -- crates/randprotocol-core crates/randprotocol-node/src
```

Expected: no output. Nothing in consensus, the ledger, the node, or the wire format changed.

- [ ] **Step 3: Report**

The branch report names: the six commits and the circuits mirror commit; the test counts per suite; the fact that no GPU host exists in the fleet, so the §11 speed row cannot be measured yet and v0.3 waits on it; and the two follow-ups outside this plan — the key split (v2, before any untrusted prover) and a `deploy/` unit for running `rand-prover` on a droplet next to a node.
