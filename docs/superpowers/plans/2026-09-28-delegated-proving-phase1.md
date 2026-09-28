# Delegated Proving, Phase 1 (v0.6.2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A wallet that cannot hold a tier-14 bundle proof in memory hands the witness, sealed, to a prover the wallet's owner runs — `rand-prover` alone or `rand-node run --prover` — gets the proof back sealed, checks it, and submits the transaction itself. No consensus change; ships as v0.6.2 on chain 16.

**Architecture:** A new crate `randprotocol-prover` holds the wire types and the sealed codec (ML-KEM-768 + ChaCha20-Poly1305, the primitives envelopes use), the prover's key and pairing-token store, a bounded job queue whose worker calls `prove_bundle_for` unchanged, and a JSON-RPC 2.0 listener in the node's `prover_*` namespace. The `rand` wallet grows a `Proving::Remote` arm that seals a job, polls, opens the reply and refuses anything whose digest, size or proof does not check. The node can host the same service on its own listener, never on the public RPC.

**Tech Stack:** Rust workspace (tokio 1, axum 0.7, reqwest 0.12 rustls, serde/serde_json, postcard 1, blake3, zeroize 1, ml-kem =0.3.2, chacha20poly1305 =0.11.0, rand =0.10.2 as `randprotocol-zkvm` pins them), clap 4, sysinfo, qrcode 0.14.

**Spec:** `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` (§3 Phase 1, §5 fees, §8 open questions). Companion: `../clients/docs/superpowers/specs/2026-09-28-delegated-proving-design.md` (on branch `docs/delegated-proving-spec` of the clients repo).

**Branch / base:** `feat/delegated-proving` in `/private/tmp/fullnode-deleg`, off `feat/v061` @ `40e0cbf`. Rebase onto the `v0.6.1` tag when it exists (Task 10). **Never edit anything under `crates/randprotocol-zkvm` or `crates/randprotocol-rvm` in this phase** (vendored; cs7 pins are still moving there — the other session's request). `Backend` and `FriProfile` are used as they are.

## Global Constraints

- Wire: JSON-RPC 2.0 over HTTP POST, namespace `prover_`, methods `prover_info`, `prover_submit`, `prover_status`, `prover_cancel`; params are positional arrays like the node's RPC (spec §3.2).
- Sealed job: `kem_ct (1 088 B) ‖ nonce (12 B) ‖ ChaCha20-Poly1305(key, postcard(ProveJob))`, `key = blake3::derive_key("rand-prover-request-1", ml_kem_768_shared_secret)`; the reply is `nonce (12 B) ‖ ChaCha20-Poly1305(reply_key, postcard(ProveReply))` with a fresh 32-byte `reply_key` per job (spec §3.2).
- `ProveJob { version: 1, token: [u8; 32], witness_kind: SpendKey | ViewingKey, hc_bundle: Word8, profile, binding: [u32; TX_BINDING_WORDS], inputs: Vec<u32>, reply_key: [u8; 32] }`, `ProveReply { proof: Vec<u8>, digest: Word8, tier: u8 }` (spec §3.2).
- Job id: 128 random bits, hex. States: `queued | proving | done | failed | expired` (spec §3.2).
- Pairing link: `randprover:<base58(kem_ek)>?url=<https URL>&token=<hex>&own=1` (spec §3.3). A job whose token is unknown is refused before it is queued. A prover started without `--accept-spend-key` refuses `SpendKey` jobs and says so in `prover_info.witness_kinds`; the flag is off by default (spec §3.3).
- `--max-parallel` default 1, `--max-queue` default 8, a full queue answers `busy` with the depth; a job not collected within 10 minutes of `done` is `expired`; at start refuse to run with less than `PROVER_PEAK × max-parallel + 1 GiB` free (spec §3.4).
- Witness hygiene: the witness lives in memory only, zeroized on drop, never written to disk, logged or included in an error; logs carry the job id, the token's label, the tier and the time (spec §3.5).
- The client is not trusting the prover for correctness: it recomputes the expected digest (`hidden_bundle_digest`, already in `Prepared.expected`), refuses a reply whose digest differs or whose proof exceeds the chain's `max_proof_bytes`, and verifies the proof locally (spec §3.6). A `SpendKey` witness goes only to a prover paired with `own=1` (spec §3.3).
- The prover service is never a method of the public RPC (`rpc.rs`); in the node it is its own listener, loopback by default (spec §3.1).
- Phase 1 `prover_info.fee` is `null`; `witness_kinds` never lists `viewing_key` in this phase (today's guests take `sk`).
- Every test that makes a real bundle proof takes the workspace `proving_slot` (AGENTS.md "Proving concurrency is capped").
- Commit messages: imperative, one topic each, ending with the attribution lines the session reminder gives. No `cargo fmt` on this repo (memory: never cargo fmt).

## Review Focus

1. **A sealed job for a different prover** (encapsulated to another ML-KEM key) must be refused as "not sealed to this prover", never panic or leak that the decapsulation produced garbage — pinned in Task 1 (`a_job_sealed_to_another_key_does_not_open`).
2. **A stale reply or a replayed job**: the wallet must refuse a reply whose `digest` is not the one it computed, and the service must refuse a job whose `binding`/witness produce a proof for a different digest silently — pinned in Task 7 (`a_reply_with_the_wrong_digest_is_refused`) and Task 5 (real proof, digest equality).
3. **A prover that hangs** (accepts, never finishes): the wallet must give up after a bounded wait and say so, not sit for ever — pinned in Task 7 (`a_prover_that_never_finishes_times_out`).
4. **Memory the machine does not have**: two `--max-parallel` proofs on an 8 GB box OOM-kill the prover mid-job; the start-up check must refuse — pinned in Task 4 (`required_bytes_is_peak_times_parallel_plus_a_gib`).
5. **A malformed sealed body over the limit** (a 100 MB POST): the listener must refuse it at the body limit before decapsulating anything — pinned in Task 4 (`an_oversized_body_is_refused_at_the_limit`).

---

### Task 1: Crate skeleton and the sealed wire codec

**Files:**
- Create: `crates/randprotocol-prover/Cargo.toml`
- Create: `crates/randprotocol-prover/src/lib.rs`
- Create: `crates/randprotocol-prover/src/wire.rs`
- Create: `crates/randprotocol-prover/tests/wire.rs`
- Modify: `Cargo.toml` (workspace `members` and `[workspace.dependencies]`)

**Interfaces:**
- Consumes: `randprotocol_core::notes::{Word8, KEM_EK_BYTES}`, `randprotocol_core::types::TX_BINDING_WORDS`; ml-kem 0.3.2 exactly as `crates/randprotocol-zkvm/src/viewing.rs:31-60,148-160` uses it (`MlKem768::from_seed`, `Ek::new(&ml_kem::kem::Key::<Ek>::try_from(..))`, `ek.encapsulate_with_rng(&mut rand::rng())`, `dk.decapsulate(&ct)`, `KeyExport::to_bytes`).
- Produces (all `pub` in `randprotocol_prover::wire`):
  ```rust
  pub const WIRE_VERSION: u32 = 1;
  pub const KEM_CT_BYTES: usize = 1088;
  pub const NONCE_BYTES: usize = 12;
  /// A sealed job is 1 100 B of KEM+nonce plus postcard(ProveJob): 1 204 witness words ≈ 5 KB. 64 KiB bounds any honest job.
  pub const MAX_SEALED_JOB_BYTES: usize = 64 * 1024;
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
  pub enum WitnessKind { SpendKey, ViewingKey }
  impl WitnessKind { pub fn as_str(self) -> &'static str /* "spend_key" | "viewing_key" */; pub fn parse(s: &str) -> Option<WitnessKind>; }
  #[derive(Clone, Serialize, Deserialize)]
  pub struct ProveJob { pub version: u32, pub token: [u8; 32], pub witness_kind: WitnessKind, pub hc_bundle: Word8, pub profile: String, pub binding: [u32; TX_BINDING_WORDS], pub inputs: Vec<u32>, pub reply_key: [u8; 32] }
  impl Drop for ProveJob { /* zeroize token, inputs, reply_key, binding */ }
  #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
  pub struct ProveReply { pub proof: Vec<u8>, pub digest: Word8, pub tier: u8 }
  #[derive(Debug, thiserror-free enum)] pub enum WireError { BadKey(String), TooLong(usize), Malformed(String), NotForThisProver, Version(u32) }
  pub type Dk = ml_kem::ml_kem_768::DecapsulationKey;
  pub type Ek = ml_kem::ml_kem_768::EncapsulationKey;
  pub fn seal_job(kem_ek: &[u8], job: &ProveJob) -> Result<Vec<u8>, WireError>;
  pub fn open_job(dk: &Dk, sealed: &[u8]) -> Result<ProveJob, WireError>;
  pub fn seal_reply(reply_key: &[u8; 32], reply: &ProveReply) -> Vec<u8>;
  pub fn open_reply(reply_key: &[u8; 32], sealed: &[u8]) -> Result<ProveReply, WireError>;
  pub fn fresh_reply_key() -> [u8; 32];
  ```

- [ ] **Step 1: Add the crate to the workspace**

`Cargo.toml` (root): add `"crates/randprotocol-prover"` to `members`, and `randprotocol-prover = { path = "crates/randprotocol-prover" }` under `[workspace.dependencies]`.

`crates/randprotocol-prover/Cargo.toml`:

```toml
[package]
name = "randprotocol-prover"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
description = "RandProtocol delegated prover: the sealed job wire, the pairing store and the rand-prover service"

[features]
default = ["service"]
# The listener, the queue, the CLI. Off for a wasm wallet core that only needs the wire codec.
service = ["dep:axum", "dep:tokio", "dep:sysinfo", "dep:tracing", "dep:tracing-subscriber", "dep:clap", "dep:anyhow", "dep:qrcode"]
cuda = ["randprotocol-zkvm/cuda"]
mock-cuda = ["randprotocol-zkvm/mock-cuda"]

[[bin]]
name = "rand-prover"
path = "src/main.rs"
required-features = ["service"]

[dependencies]
randprotocol-core = { workspace = true }
randprotocol-zkvm = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
postcard = { version = "1", features = ["alloc"] }
hex = { workspace = true }
bs58 = { workspace = true }
blake3 = { workspace = true }
zeroize = { workspace = true }
# HCS-1's pins, verbatim from crates/randprotocol-zkvm/Cargo.toml: a job sealed by a wallet must
# open on a prover, and both sides are this one implementation.
ml-kem = "=0.3.2"
chacha20poly1305 = "=0.11.0"
rand = "=0.10.2"
axum = { workspace = true, optional = true }
tokio = { workspace = true, optional = true }
sysinfo = { version = "0.33", optional = true, default-features = false, features = ["system"] }
tracing = { workspace = true, optional = true }
tracing-subscriber = { workspace = true, optional = true }
clap = { workspace = true, optional = true }
anyhow = { workspace = true, optional = true }
qrcode = { version = "0.14", default-features = false, optional = true }

[dev-dependencies]
tokio = { workspace = true }
reqwest = { workspace = true }
tempfile = "3"
```

Copy the exact `rand` line from `crates/randprotocol-zkvm/Cargo.toml` (it is the crate that `rand::rng()` in `viewing.rs` resolves to; if zkvm also pins `rand_core`, pin it too). Check `tracing-subscriber` and `tempfile` are in `[workspace.dependencies]`; if not, add them there with the versions the node crate uses.

- [ ] **Step 2: Write the failing wire tests**

`crates/randprotocol-prover/tests/wire.rs`:

```rust
use randprotocol_prover::wire::*;
use ml_kem::kem::FromSeed;
use ml_kem::{KeyExport, MlKem768};

fn keypair(seed_byte: u8) -> (Dk, Vec<u8>) {
    let (dk, ek) = MlKem768::from_seed(&ml_kem::Seed::from([seed_byte; 64]));
    (dk, ek.to_bytes().to_vec())
}

fn job() -> ProveJob {
    ProveJob {
        version: WIRE_VERSION,
        token: [7; 32],
        witness_kind: WitnessKind::SpendKey,
        hc_bundle: [1, 2, 3, 4, 5, 6, 7, 8],
        profile: "test".into(),
        binding: [9; 8],
        inputs: (0..1204u32).map(|i| i.wrapping_mul(2654435761)).collect(),
        reply_key: [3; 32],
    }
}

#[test]
fn a_job_round_trips_through_the_sealed_wire() {
    let (dk, ek) = keypair(1);
    let sealed = seal_job(&ek, &job()).unwrap();
    assert_eq!(&sealed.len() % 1, 0);
    assert!(sealed.len() > KEM_CT_BYTES + NONCE_BYTES + 16);
    assert!(sealed.len() <= MAX_SEALED_JOB_BYTES);
    let opened = open_job(&dk, &sealed).unwrap();
    let want = job();
    assert_eq!(opened.token, want.token);
    assert_eq!(opened.witness_kind, want.witness_kind);
    assert_eq!(opened.hc_bundle, want.hc_bundle);
    assert_eq!(opened.profile, want.profile);
    assert_eq!(opened.binding, want.binding);
    assert_eq!(opened.inputs, want.inputs);
    assert_eq!(opened.reply_key, want.reply_key);
}

#[test]
fn two_seals_of_one_job_differ() {
    let (_, ek) = keypair(1);
    assert_ne!(seal_job(&ek, &job()).unwrap(), seal_job(&ek, &job()).unwrap(), "fresh KEM randomness and nonce every time");
}

#[test]
fn a_job_sealed_to_another_key_does_not_open() {
    let (_, ek1) = keypair(1);
    let (dk2, _) = keypair(2);
    let sealed = seal_job(&ek1, &job()).unwrap();
    assert!(matches!(open_job(&dk2, &sealed), Err(WireError::NotForThisProver)));
}

#[test]
fn a_flipped_byte_anywhere_is_refused() {
    let (dk, ek) = keypair(1);
    let sealed = seal_job(&ek, &job()).unwrap();
    for at in [0, KEM_CT_BYTES - 1, KEM_CT_BYTES + 3, sealed.len() - 1] {
        let mut t = sealed.clone();
        t[at] ^= 0x40;
        assert!(open_job(&dk, &t).is_err(), "byte {at}");
    }
}

#[test]
fn a_short_or_oversized_body_is_malformed_before_any_crypto() {
    let (dk, _) = keypair(1);
    assert!(matches!(open_job(&dk, &[0u8; 100]), Err(WireError::Malformed(_))));
    assert!(matches!(open_job(&dk, &vec![0u8; MAX_SEALED_JOB_BYTES + 1]), Err(WireError::TooLong(_))));
}

#[test]
fn a_bad_encapsulation_key_is_refused_at_seal_time() {
    assert!(matches!(seal_job(&[0u8; 10], &job()), Err(WireError::BadKey(_))));
}

#[test]
fn a_foreign_wire_version_is_refused() {
    let (dk, ek) = keypair(1);
    let mut j = job();
    j.version = 2;
    let sealed = seal_job(&ek, &j).unwrap();
    assert!(matches!(open_job(&dk, &sealed), Err(WireError::Version(2))));
}

#[test]
fn a_reply_round_trips_and_a_wrong_key_fails() {
    let key = fresh_reply_key();
    let reply = ProveReply { proof: vec![1, 2, 3], digest: [4; 8], tier: 14 };
    let sealed = seal_reply(&key, &reply);
    assert_eq!(open_reply(&key, &sealed).unwrap(), reply);
    let other = fresh_reply_key();
    assert!(open_reply(&other, &sealed).is_err());
    assert_ne!(seal_reply(&key, &reply), sealed, "fresh nonce per seal");
}

#[test]
fn dropping_a_job_zeroizes_its_witness() {
    // The witness Vec is zeroized in place on drop; observe it through a raw pointer taken before.
    let mut j = job();
    let ptr = j.inputs.as_ptr();
    let len = j.inputs.len();
    assert_ne!(j.inputs[5], 0);
    j.inputs.shrink_to_fit();
    let ptr2 = j.inputs.as_ptr();
    assert_eq!(ptr, ptr2);
    drop(j);
    // SAFETY: test-only; the allocation may be reused, but zeroize wrote zeros before the free,
    // and no allocation has happened since. Reading it is UB-adjacent; keep it as the last line.
    let after = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(after.iter().all(|&w| w == 0), "the witness was not zeroized on drop");
}
```

If the last test proves unreliable under the allocator, replace it with a `ZeroizeOnDrop` derive test: wrap `inputs` in `zeroize::Zeroizing<Vec<u32>>` and assert `ProveJob: zeroize::ZeroizeOnDrop` at compile time (`fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}`). Record which in the commit.

- [ ] **Step 3: Run the tests to see them fail**

Run: `cd /private/tmp/fullnode-deleg && cargo test -p randprotocol-prover --no-default-features --test wire`
Expected: compile error, `wire` module missing.

- [ ] **Step 4: Implement `src/lib.rs` and `src/wire.rs`**

`src/lib.rs`:

```rust
//! Delegated proving (`docs/superpowers/specs/2026-09-28-delegated-proving-design.md`): the job a
//! wallet seals to a prover, the prover's key and pairings, and — behind `service` — the queue and
//! the `prover_*` listener. The wire half builds for wasm; the service half does not need to.
pub mod wire;
pub mod key;
pub mod pairing;
#[cfg(feature = "service")]
pub mod service;
#[cfg(feature = "service")]
pub mod http;
#[cfg(feature = "service")]
pub mod memory;
```

(`key`, `pairing` come in Task 2; create empty modules now so the crate builds, or add the `pub mod` lines in Task 2.)

`src/wire.rs` — the codec. Key points the implementer must follow:

```rust
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem768};
use rand::RngCore;
use randprotocol_core::notes::{Word8, KEM_EK_BYTES};
use randprotocol_core::types::TX_BINDING_WORDS;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub type Dk = ml_kem::ml_kem_768::DecapsulationKey;
pub type Ek = ml_kem::ml_kem_768::EncapsulationKey;
type KemCt = ml_kem::ml_kem_768::Ciphertext;

const KDF_CONTEXT: &str = "rand-prover-request-1";
const AAD_JOB: &[u8] = b"rand-prover-job-1";
const AAD_REPLY: &[u8] = b"rand-prover-reply-1";

fn job_key(ss: &[u8; 32]) -> [u8; 32] { blake3::derive_key(KDF_CONTEXT, ss) }

fn aead_seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(*key)).encrypt(&Nonce::from(nonce), Payload { msg: pt, aad }).expect("aead");
    [&nonce[..], &ct].concat()
}
fn aead_open(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if body.len() < NONCE_BYTES + 16 { return None; }
    let nonce: [u8; NONCE_BYTES] = body[..NONCE_BYTES].try_into().ok()?;
    ChaCha20Poly1305::new(&Key::from(*key)).decrypt(&Nonce::from(nonce), Payload { msg: &body[NONCE_BYTES..], aad }).ok().map(Zeroizing::new)
}

pub fn seal_job(kem_ek: &[u8], job: &ProveJob) -> Result<Vec<u8>, WireError> {
    if kem_ek.len() != KEM_EK_BYTES { return Err(WireError::BadKey(format!("{} bytes, expected {KEM_EK_BYTES}", kem_ek.len()))); }
    let key = ml_kem::kem::Key::<Ek>::try_from(kem_ek).map_err(|_| WireError::BadKey("malformed".into()))?;
    let ek = Ek::new(&key).map_err(|_| WireError::BadKey("invalid".into()))?;
    let (kem_ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
    let mut ss: [u8; 32] = ss.into();
    let mut k = job_key(&ss);
    ss.zeroize();
    let pt = Zeroizing::new(postcard::to_allocvec(job).map_err(|e| WireError::Malformed(e.to_string()))?);
    let body = aead_seal(&k, AAD_JOB, &pt);
    k.zeroize();
    let out = [&kem_ct.to_vec()[..], &body].concat();
    if out.len() > MAX_SEALED_JOB_BYTES { return Err(WireError::TooLong(out.len())); }
    Ok(out)
}

pub fn open_job(dk: &Dk, sealed: &[u8]) -> Result<ProveJob, WireError> {
    if sealed.len() > MAX_SEALED_JOB_BYTES { return Err(WireError::TooLong(sealed.len())); }
    if sealed.len() < KEM_CT_BYTES + NONCE_BYTES + 16 { return Err(WireError::Malformed("too short".into())); }
    let ct = KemCt::try_from(&sealed[..KEM_CT_BYTES]).map_err(|_| WireError::Malformed("kem ciphertext".into()))?;
    let mut ss: [u8; 32] = dk.decapsulate(&ct).into();   // implicit rejection: a foreign ct yields a random ss
    let mut k = job_key(&ss);
    ss.zeroize();
    let pt = aead_open(&k, AAD_JOB, &sealed[KEM_CT_BYTES..]);
    k.zeroize();
    let pt = pt.ok_or(WireError::NotForThisProver)?;       // AEAD failure == not ours or tampered
    let job: ProveJob = postcard::from_bytes(&pt).map_err(|e| WireError::Malformed(e.to_string()))?;
    if job.version != WIRE_VERSION { return Err(WireError::Version(job.version)); }
    Ok(job)
}
```

`seal_reply`/`open_reply` use `aead_seal`/`aead_open` with `AAD_REPLY` and `reply_key` directly. `fresh_reply_key` fills 32 bytes from `rand::rng()`. `impl Drop for ProveJob` zeroizes `token`, `reply_key`, `binding` and `inputs` (`Vec<u32>: Zeroize`). Note `Drop` on a type that also derives `Clone` is fine; do not derive `Debug` for `ProveJob` (it would print the witness) — implement `Debug` by hand printing only `version`, `witness_kind`, `profile`, `inputs.len()`.

- [ ] **Step 5: Run the tests to see them pass**

Run: `cargo test -p randprotocol-prover --no-default-features --test wire` and `cargo test -p randprotocol-prover --test wire`
Expected: all 9 pass, both with and without the `service` feature (the crate must build without it).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/randprotocol-prover
git commit -m "prover: the crate and the sealed job wire — ML-KEM-768 + ChaCha20-Poly1305 under rand-prover-request-1, zeroized on drop"
```

---

### Task 2: The prover's key file, the fingerprint, pairing links and the token store

**Files:**
- Create: `crates/randprotocol-prover/src/key.rs`
- Create: `crates/randprotocol-prover/src/pairing.rs`
- Test: `crates/randprotocol-prover/tests/pairing.rs`

**Interfaces:**
- Consumes: `wire::{Dk, Ek}`, `randprotocol_core::fingerprint::Fingerprint` (its tuple field is `pub`, `Display` renders `XXXX-XXXX-XXXX-XXXX`).
- Produces:
  ```rust
  // key.rs
  pub struct ProverKey { /* seed: Zeroizing<[u8; 64]>, dk: Dk, ek_bytes: Vec<u8> */ }
  impl ProverKey {
      pub fn generate() -> ProverKey;
      pub fn from_seed(seed: [u8; 64]) -> ProverKey;
      pub fn kem_ek(&self) -> &[u8];
      pub fn dk(&self) -> &Dk;
      pub fn fingerprint(&self) -> Fingerprint;         // fingerprint_of(self.kem_ek())
      pub fn save_new(&self, path: &Path) -> std::io::Result<()>;   // 0600, refuses to overwrite (ErrorKind::AlreadyExists)
      pub fn load(path: &Path) -> std::io::Result<ProverKey>;       // refuses a file not mode 0600 on unix, like node.key.json
  }
  pub const FINGERPRINT_DOMAIN: &[u8] = b"rand-prover-fingerprint-1";
  pub fn fingerprint_of(kem_ek: &[u8]) -> Fingerprint;   // Fingerprint(blake3(domain ‖ ek)[..10])
  // pairing.rs
  pub const TOKEN_DOMAIN: &[u8] = b"rand-prover-token-1";
  pub const LINK_SCHEME: &str = "randprover:";
  pub struct PairingLink { pub kem_ek: Vec<u8>, pub url: String, pub token: [u8; 32], pub own: bool }
  impl PairingLink { pub fn format(&self) -> String; pub fn parse(s: &str) -> Result<PairingLink, String>; pub fn fingerprint(&self) -> Fingerprint; }
  pub fn token_hash(token: &[u8; 32]) -> [u8; 32];   // blake3(TOKEN_DOMAIN ‖ token)
  #[derive(Clone, Serialize, Deserialize)] pub struct Pairing { pub label: String, pub token_hash: String /* hex */, pub own: bool, pub created_unix: u64 }
  #[derive(Default, Serialize, Deserialize)] pub struct Pairings { pub version: u32, pub pairings: Vec<Pairing> }
  impl Pairings {
      pub fn load(path: &Path) -> std::io::Result<Pairings>;   // missing file == empty
      pub fn save(&self, path: &Path) -> std::io::Result<()>;   // 0600, atomic rename
      pub fn pair(&mut self, label: &str, own: bool) -> Result<[u8; 32], String>;   // fresh token; refuses a duplicate label
      pub fn unpair(&mut self, label: &str) -> bool;
      pub fn lookup(&self, token: &[u8; 32]) -> Option<&Pairing>;
  }
  ```
- The key file JSON: `{"version":1,"kind":"rand-prover-key","seed":"<128 hex>"}`. The pairings file: `{"version":1,"pairings":[…]}`. Neither ever holds a token in clear.

- [ ] **Step 1: Write the failing tests**

`crates/randprotocol-prover/tests/pairing.rs`:

```rust
use randprotocol_prover::key::*;
use randprotocol_prover::pairing::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn a_key_file_is_0600_written_once_and_loads_to_the_same_ek() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("prover.key.json");
    let k = ProverKey::generate();
    k.save_new(&p).unwrap();
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(k.save_new(&p).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    let l = ProverKey::load(&p).unwrap();
    assert_eq!(l.kem_ek(), k.kem_ek());
    assert_eq!(l.fingerprint(), k.fingerprint());
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains("\"rand-prover-key\""));
}

#[test]
fn a_world_readable_key_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("prover.key.json");
    ProverKey::generate().save_new(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ProverKey::load(&p).is_err());
}

#[test]
fn the_fingerprint_is_16_crockford_digits_over_the_ek() {
    let k = ProverKey::from_seed([9; 64]);
    let s = k.fingerprint().to_string();
    assert_eq!(s.len(), 19, "{s}");
    assert_eq!(s.matches('-').count(), 3);
    assert_eq!(fingerprint_of(k.kem_ek()), k.fingerprint());
    assert_ne!(fingerprint_of(k.kem_ek()), randprotocol_core::fingerprint::Fingerprint::of_raw(k.kem_ek()), "its own domain, not the address's");
}

#[test]
fn a_pairing_link_round_trips_and_carries_own() {
    let k = ProverKey::from_seed([1; 64]);
    let link = PairingLink { kem_ek: k.kem_ek().to_vec(), url: "https://prover.example:8600/".into(), token: [0xab; 32], own: true };
    let s = link.format();
    assert!(s.starts_with("randprover:"), "{s}");
    assert!(s.contains("&own=1"), "{s}");
    assert!(s.contains("?url=https%3A%2F%2Fprover.example%3A8600%2F"), "{s}");
    let back = PairingLink::parse(&s).unwrap();
    assert_eq!(back.kem_ek, link.kem_ek);
    assert_eq!(back.url, link.url);
    assert_eq!(back.token, link.token);
    assert!(back.own);
    let not_own = PairingLink { own: false, ..link };
    assert!(!not_own.format().contains("own="));
    assert!(!PairingLink::parse(&not_own.format()).unwrap().own);
}

#[test]
fn a_malformed_link_is_refused_with_a_reason() {
    assert!(PairingLink::parse("randprover:").is_err());
    assert!(PairingLink::parse("http://x?url=y&token=00").is_err());
    let k = ProverKey::from_seed([1; 64]);
    let ok = PairingLink { kem_ek: k.kem_ek().to_vec(), url: "http://127.0.0.1:8600".into(), token: [1; 32], own: true }.format();
    assert!(PairingLink::parse(&ok.replace("token=", "token=zz")).is_err(), "bad hex");
    assert!(PairingLink::parse(&ok[..ok.len() - 40]).is_err(), "truncated");
    let e = PairingLink::parse(&ok.replacen("randprover:", "randprover:1", 1)).unwrap_err();
    assert!(e.contains("key"), "{e}");
}

#[test]
fn pairings_mint_lookup_and_revoke_without_storing_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pairings.json");
    let mut ps = Pairings::load(&p).unwrap();
    assert!(ps.pairings.is_empty());
    let t1 = ps.pair("laptop", true).unwrap();
    let t2 = ps.pair("phone", false).unwrap();
    assert_ne!(t1, t2);
    assert!(ps.pair("laptop", true).is_err(), "duplicate label");
    ps.save(&p).unwrap();
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(!text.contains(&hex::encode(t1)), "the token itself is never on disk");
    let ps = Pairings::load(&p).unwrap();
    assert_eq!(ps.lookup(&t1).unwrap().label, "laptop");
    assert!(ps.lookup(&t1).unwrap().own);
    assert_eq!(ps.lookup(&t2).unwrap().label, "phone");
    assert!(ps.lookup(&[0; 32]).is_none());
    let mut ps = ps;
    assert!(ps.unpair("laptop"));
    assert!(!ps.unpair("laptop"));
    assert!(ps.lookup(&t1).is_none());
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test -p randprotocol-prover --test pairing`
Expected: compile errors, modules missing.

- [ ] **Step 3: Implement `key.rs` and `pairing.rs`**

`key.rs`: the seed is `Zeroizing<[u8; 64]>`; `(dk, ek) = MlKem768::from_seed(&ml_kem::Seed::from(*seed))`; `ek_bytes = ek.to_bytes().to_vec()`. `save_new` opens with `OpenOptions::new().write(true).create_new(true).mode(0o600)` (`std::os::unix::fs::OpenOptionsExt`); `load` checks `metadata.permissions().mode() & 0o077 == 0` on unix and errors "is group/world readable; chmod 600". `fingerprint_of` = `Fingerprint(Hash::digest_domain(FINGERPRINT_DOMAIN, ek).0[..10])` — `randprotocol_core::crypto::Hash::digest_domain` exists (`crypto.rs:46`).

`pairing.rs`: `format()` writes `randprover:{bs58}?url={pct}&token={hex}` plus `&own=1` when `own`. Percent-encode the URL by hand (reserved `:/?#&=%` and non-ASCII) — no `url` crate. `parse` strips the scheme, splits at `?`, decodes base58 and checks `len == KEM_EK_BYTES` (error text "key"), parses `url`, `token` (64 hex → 32 bytes), `own` (`"1"` → true, absent → false). `Pairings::pair` fills 32 bytes from `rand::rng()`, stores `hex(token_hash)` and `created_unix` from `SystemTime::now()`. `save` writes to `path.with_extension("json.tmp")` at mode 0600 then `rename`.

- [ ] **Step 4: Run to see them pass**

Run: `cargo test -p randprotocol-prover --test pairing`
Expected: 6 pass.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-prover
git commit -m "prover: the key file (0600, seed-only), the ek fingerprint, randprover: links and the hashed-token pairing store"
```

---

### Task 3: The job queue and worker (`service.rs`)

**Files:**
- Create: `crates/randprotocol-prover/src/service.rs`
- Test: `crates/randprotocol-prover/tests/service.rs`

**Interfaces:**
- Consumes: `wire::*`, `key::ProverKey`, `pairing::Pairings`, `randprotocol_zkvm::executor::{prove_bundle_for, ZkExecutor}` (`ZkExecutor::known_hc_bundles() -> [Word8; 2]`, `ZkExecutor::profile_from_str(&str) -> Option<FriProfile>`, `prove_bundle_for(&Word8, FriProfile, &[u32], &[u32; 8], Backend) -> Result<(Vec<u8>, Word8, u8), String>`), `randprotocol_zkvm::machine::Backend`, `randprotocol_zkvm::hidden::hidden_input::COUNT` (1204).
- Produces:
  ```rust
  pub type ProveFn = Arc<dyn Fn(&Word8, FriProfile, &[u32], &[u32; TX_BINDING_WORDS], Backend) -> Result<(Vec<u8>, Word8, u8), String> + Send + Sync>;
  pub struct Config {
      pub key: ProverKey,
      pub pairings: Arc<RwLock<Pairings>>,      // std::sync::RwLock; the CLI reloads it on SIGHUP later, not now
      pub backend: Backend,
      pub max_parallel: usize,                  // ≥ 1; the CLI refuses 0
      pub max_queue: usize,
      pub accept_spend_key: bool,
      pub per_token: usize,                     // jobs one token may have queued or proving; default 2
      pub result_ttl: Duration,                 // 600 s
      pub prove: ProveFn,                       // Config::real() uses prove_bundle_for; tests stub it
  }
  impl Config { pub fn new(key: ProverKey, pairings: Pairings) -> Config /* defaults: Cpu, 1, 8, false, 2, 600 s, real prove */; }
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum State { Queued, Proving, Done, Failed, Expired }
  impl State { pub fn as_str(self) -> &'static str; }
  pub struct Status { pub state: State, pub position: Option<usize>, pub reply: Option<Vec<u8>> /* sealed */, pub error: Option<String> }
  #[derive(Serialize)] pub struct Info { pub version: String, pub kem_fingerprint: String, pub kem_ek: String /* hex */, pub hc_bundles: Vec<String>, pub profiles: Vec<&'static str>, pub backend: &'static str, pub witness_kinds: Vec<&'static str>, pub queue: QueueInfo, pub fee: Option<()> }
  #[derive(Serialize)] pub struct QueueInfo { pub depth: usize, pub max: usize, pub proving: usize }
  pub enum Refusal { Bad(String), Unpaired, WitnessKind(String), Busy { depth: usize, max: usize } }
  pub struct Service { /* cfg, Mutex<Inner>, Notify */ }
  pub type Shared = Arc<Service>;
  impl Service {
      pub fn start(cfg: Config) -> Shared;                       // spawns max_parallel workers on the current tokio runtime
      pub fn info(&self) -> Info;
      pub fn submit(&self, sealed: &[u8]) -> Result<String, Refusal>;
      pub fn status(&self, id: &str) -> Option<Status>;          // a Done job's reply is returned once and then the entry is Expired-and-dropped? NO: keep it until collected or ttl; see below
      pub fn cancel(&self, id: &str) -> bool;                    // true if it was queued or proving (a proving job finishes but its reply is dropped)
  }
  ```
- Admission order in `submit` (cheap before expensive; nothing after a refusal keeps the plaintext): size ≤ `MAX_SEALED_JOB_BYTES` → `open_job` (`WireError` → `Bad`) → token lookup (`Unpaired`) → `witness_kind` (`SpendKey` needs `accept_spend_key`; `ViewingKey` is refused in this build with "this build's bundle guests take a spend key") → `hc_bundle ∈ known_hc_bundles()` → `profile_from_str` → `inputs.len() == hidden_input::COUNT` → per-token in-flight < `per_token` (`Busy`) → queued + proving < `max_queue + max_parallel` (`Busy`) → id minted, entry inserted, `Notify`.
- `status` on `Done` returns the sealed reply; the entry stays until `result_ttl` after finishing, then is swept (state `Expired`, reply dropped). A `Done` job whose reply was already served may be served again within the ttl (idempotent polling).
- The worker: pops, marks `Proving`, copies `reply_key`, `hc_bundle`, `profile`, `binding` out, runs `cfg.prove` in `spawn_blocking` **moving the job in** (the job is dropped, zeroized, inside the blocking task the moment `prove` returns), seals the reply under `reply_key`, zeroizes the key copy, records `Done`/`Failed` with the error string (which never contains inputs — `prove_bundle_for`'s errors name the hc or the length only).
- Logging: `tracing::info!(job = %id, label = %pairing.label, kind, "queued")`, `"proving"`, `(tier, secs) "done"`, `"failed"` with the error. Nothing else.

- [ ] **Step 1: Write the failing tests**

`crates/randprotocol-prover/tests/service.rs`:

```rust
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::pairing::Pairings;
use randprotocol_prover::service::*;
use randprotocol_prover::wire::*;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::hidden_input;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A stub prover that returns a fixed proof, or blocks until released, or fails.
fn stub(behaviour: Arc<Mutex<Behaviour>>) -> ProveFn {
    Arc::new(move |_hc, _profile, inputs, _binding, _backend| {
        let b = behaviour.lock().unwrap().clone();
        match b {
            Behaviour::Ok => Ok((vec![0xAA; 1000], [inputs[0]; 8], 14)),
            Behaviour::Fail(e) => Err(e),
            Behaviour::Block(ms) => { std::thread::sleep(Duration::from_millis(ms)); Ok((vec![1], [0; 8], 14)) }
        }
    })
}
#[derive(Clone)] enum Behaviour { Ok, Fail(String), Block(u64) }

struct Rig { svc: Shared, ek: Vec<u8>, token: [u8; 32], own_token: [u8; 32] }

fn rig(accept_spend_key: bool, max_queue: usize, max_parallel: usize, behaviour: Behaviour) -> Rig {
    let key = ProverKey::from_seed([2; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let own_token = pairings.pair("laptop", true).unwrap();
    let token = pairings.pair("phone", false).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.accept_spend_key = accept_spend_key;
    cfg.max_queue = max_queue;
    cfg.max_parallel = max_parallel;
    cfg.result_ttl = Duration::from_millis(300);
    cfg.prove = stub(Arc::new(Mutex::new(behaviour)));
    Rig { svc: Service::start(cfg), ek, token, own_token }
}

fn job(token: [u8; 32], kind: WitnessKind) -> ProveJob {
    ProveJob { version: WIRE_VERSION, token, witness_kind: kind, hc_bundle: ZkExecutor::hc_bundle(), profile: "test".into(),
               binding: [5; 8], inputs: vec![77; hidden_input::COUNT], reply_key: fresh_reply_key() }
}

async fn wait_terminal(svc: &Service, id: &str) -> Status {
    for _ in 0..200 {
        let s = svc.status(id).expect("known job");
        if matches!(s.state, State::Done | State::Failed | State::Expired) { return s; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never finished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_job_proves_and_the_reply_opens_under_the_reply_key() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let j = job(r.own_token, WitnessKind::SpendKey);
    let reply_key = j.reply_key;
    let id = r.svc.submit(&seal_job(&r.ek, &j).unwrap()).unwrap();
    assert_eq!(id.len(), 32, "128 bits, hex");
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Done);
    let reply = open_reply(&reply_key, s.reply.as_ref().unwrap()).unwrap();
    assert_eq!(reply.tier, 14);
    assert_eq!(reply.digest, [77; 8]);
    assert_eq!(reply.proof.len(), 1000);
    assert!(open_reply(&fresh_reply_key(), s.reply.as_ref().unwrap()).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_token_is_refused_before_queueing() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let j = job([0; 32], WitnessKind::SpendKey);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Unpaired)));
    assert_eq!(r.svc.info().queue.depth, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spend_key_job_needs_the_flag_and_info_says_so() {
    let r = rig(false, 8, 1, Behaviour::Ok);
    assert!(r.svc.info().witness_kinds.is_empty());
    let j = job(r.own_token, WitnessKind::SpendKey);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::WitnessKind(_))));
    let r = rig(true, 8, 1, Behaviour::Ok);
    assert_eq!(r.svc.info().witness_kinds, vec!["spend_key"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewing_key_job_is_refused_in_this_build() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let j = job(r.own_token, WitnessKind::ViewingKey);
    let Err(Refusal::WitnessKind(e)) = r.svc.submit(&seal_job(&r.ek, &j).unwrap()) else { panic!() };
    assert!(e.contains("spend key"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_guest_profile_or_witness_length_is_bad() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let mut j = job(r.own_token, WitnessKind::SpendKey);
    j.hc_bundle = [1; 8];
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Bad(_))));
    let mut j = job(r.own_token, WitnessKind::SpendKey);
    j.profile = "fast".into();
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Bad(_))));
    let mut j = job(r.own_token, WitnessKind::SpendKey);
    j.inputs.truncate(10);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Bad(_))));
    assert!(matches!(r.svc.submit(&[0u8; 50]), Err(Refusal::Bad(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_is_busy_with_the_depth_and_a_token_is_capped() {
    let r = rig(true, 1, 1, Behaviour::Block(400));
    let first = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    let second = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    // per_token is 2: a third from the same token is busy even though the queue (1 proving + 1 queued == max_queue + max_parallel) is also full
    let e = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap_err();
    assert!(matches!(e, Refusal::Busy { depth: 1, max: 1 }), "depth is the queued count");
    let e = r.svc.submit(&seal_job(&r.ek, &job(r.token, WitnessKind::SpendKey)).unwrap()).unwrap_err();
    assert!(matches!(e, Refusal::Busy { .. }), "queue full for another token too");
    assert_eq!(r.svc.status(&second).unwrap().position, Some(1));
    wait_terminal(&r.svc, &first).await;
    wait_terminal(&r.svc, &second).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_proof_reports_its_error_and_never_its_inputs() {
    let r = rig(true, 8, 1, Behaviour::Fail("unknown hc".into()));
    let id = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Failed);
    assert_eq!(s.error.as_deref(), Some("unknown hc"));
    assert!(s.reply.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_done_reply_expires_after_the_ttl_and_cancel_drops_a_queued_job() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let id = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Done);
    assert!(r.svc.status(&id).unwrap().reply.is_some(), "served again within the ttl");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let s = r.svc.status(&id).unwrap();
    assert_eq!(s.state, State::Expired);
    assert!(s.reply.is_none());
    let r = rig(true, 8, 1, Behaviour::Block(300));
    let a = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    let b = r.svc.submit(&seal_job(&r.ek, &job(r.token, WitnessKind::SpendKey)).unwrap()).unwrap();
    assert!(r.svc.cancel(&b));
    assert!(r.svc.status(&b).is_none(), "a cancelled queued job is gone");
    assert!(!r.svc.cancel(&b));
    assert!(r.svc.cancel(&a), "a proving job is cancelled: its reply is dropped when it finishes");
    let s = wait_terminal(&r.svc, &a).await;
    assert!(s.reply.is_none());
    assert!(r.svc.status("nope").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_names_the_guests_the_profiles_the_backend_and_the_fingerprint() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let i = r.svc.info();
    assert_eq!(i.hc_bundles.len(), 2);
    assert!(i.hc_bundles.contains(&hex::encode(randprotocol_core::notes::words_to_bytes(&ZkExecutor::hc_bundle()))) || i.hc_bundles.iter().any(|h| h.len() == 64));
    assert_eq!(i.profiles, vec!["test", "production"]);
    assert_eq!(i.backend, "cpu");
    assert_eq!(i.kem_fingerprint, randprotocol_prover::key::fingerprint_of(&r.ek).to_string());
    assert_eq!(hex::decode(&i.kem_ek).unwrap(), r.ek);
    assert_eq!(i.queue.max, 8);
    assert!(i.fee.is_none());
}
```

Use whatever hex form of a `Word8` the wallet already uses (`randprotocol_client::wallet::word8_to_hex` is not reachable from here; core has `word8_to_hex` in `randprotocol_core::notes`? — grep; otherwise `hex::encode(words_to_bytes(..))`), and make `Info.hc_bundles` use the same form `rand_status.hc_bundle` serves (`crates/randprotocol-node/src/rpc.rs:179`, via `word8_to_hex`) so the wallet compares strings directly. Fix the last test to compare against that exact form once chosen.

- [ ] **Step 2: Run to see them fail**

Run: `cargo test -p randprotocol-prover --test service`
Expected: compile error, `service` missing.

- [ ] **Step 3: Implement `service.rs`**

Port the structure of the 2026-09-17 branch's `crates/randprotocol-prover/src/lib.rs` (`git show feat/delegated-proof-generation:crates/randprotocol-prover/src/lib.rs`) — `Inner { entries: HashMap<String, Entry>, queue: VecDeque<(String, ProveJob)>, proving: usize }`, the `worker` loop on `Notify`, `sweep` on ttl — with these changes: the admission order above; `Entry { state, label: String, kind: WitnessKind, token_hash: [u8;32], submitted, finished: Option<Instant>, reply: Option<Vec<u8>>, error: Option<String>, cancelled: bool }`; no deadline, no per-IP, no averages; `cancel` removes a queued entry outright and flags a proving one so the worker discards its reply. `status` returns `Status { state, position (1-based while Queued), reply (Done only), error (Failed only) }`. `Info.version` = `env!("CARGO_PKG_VERSION")`. `backend` string: `"cpu"`, or `"cuda"` under the cuda features (match with `#[allow(unreachable_patterns)] _ => "cuda"` as the old code did).

The worker's blocking closure: `move || { let out = (prove)(&hc, profile, &job.inputs, &job.binding, backend); drop(job); out }` so the witness is zeroized before the result crosses back.

- [ ] **Step 4: Run to see them pass**

Run: `cargo test -p randprotocol-prover --test service`
Expected: 9 pass.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-prover
git commit -m "prover: the queue — pairing-gated admission, one worker per slot, sealed replies kept 10 minutes, cancel, the witness dropped inside the proving task"
```

---

### Task 4: The `prover_*` JSON-RPC listener, the memory check and the `rand-prover` CLI

**Files:**
- Create: `crates/randprotocol-prover/src/http.rs`
- Create: `crates/randprotocol-prover/src/memory.rs`
- Create: `crates/randprotocol-prover/src/main.rs`
- Test: `crates/randprotocol-prover/tests/http.rs`

**Interfaces:**
- Consumes: `service::{Service, Shared, Config, Refusal, State}`; axum 0.7 exactly as `crates/randprotocol-node/src/rpc.rs:530-560` builds its router (`Router::new().route("/", post(handle))`, `DefaultBodyLimit::max`, `TcpListener::bind`, `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())`).
- Produces:
  ```rust
  // http.rs
  pub const MAX_BODY_BYTES: usize = 2 * MAX_SEALED_JOB_BYTES + 4096;   // hex doubles it
  pub async fn serve(addr: SocketAddr, cfg: Config) -> anyhow::Result<(SocketAddr, Shared, tokio::task::JoinHandle<()>)>;
  // JSON-RPC 2.0 on POST /: {"jsonrpc":"2.0","id":…,"method":"prover_info"|"prover_submit"|"prover_status"|"prover_cancel","params":[…]}
  // prover_info   []            → Info as JSON
  // prover_submit [sealed_hex]  → {"job": "<32 hex>"}
  // prover_status [job]         → {"state": "...", "position"?: n, "reply"?: "<hex>", "error"?: "..."}
  // prover_cancel [job]         → {"cancelled": bool}
  // errors: -32700 parse, -32600 invalid request (batch, notification, wrong jsonrpc), -32601 method, -32602 params,
  //         -32001 unknown job, -32003 unpaired, -32004 witness kind {"data": {"reason"}}, -32000 bad job {"data": {"reason"}},
  //         -32005 busy {"data": {"depth", "max"}}; an over-limit body is HTTP 413 with a JSON-RPC -32600 body
  // memory.rs
  pub const PROVER_PEAK_BYTES: u64 = 5_740_000_000;   // docs/node-hardware.md:159, one tier-14 bundle
  pub const HEADROOM_BYTES: u64 = 1 << 30;
  pub fn required_bytes(max_parallel: usize) -> u64;   // PEAK * n + HEADROOM
  pub fn available_bytes() -> u64;                       // sysinfo System::new_all().available_memory()
  pub fn check(max_parallel: usize) -> Result<(), String>;   // Err names both numbers in GB
  ```
- The CLI (`rand-prover`), `--home <DIR>` global (env `RAND_PROVER_HOME`, default `~/.rand-prover`), files `<home>/prover.key.json` and `<home>/pairings.json`:
  - `keygen` — writes the key file (refuses to overwrite), prints the fingerprint.
  - `pair --name <LABEL> [--url <URL>] [--own] [--qr]` — mints a token, saves, prints the link on stdout (and a Unicode QR when `--qr`, via `qrcode::QrCode::new(link)?.render::<qrcode::render::unicode::Dense1x2>().build()`); `--url` default `http://127.0.0.1:8600`; the token is printed **once**, inside the link, never stored.
  - `unpair --name <LABEL>`; `pairings` (labels, own, created; no hashes).
  - `run [--listen 127.0.0.1:8600] [--accept-spend-key] [--max-parallel 1] [--max-queue 8] [--per-token 2] [--cuda] [--skip-memory-check]` — loads key and pairings, `memory::check` unless skipped, warns "no pairings: every job will be refused — run `rand-prover pair`" when empty, prints the fingerprint and the listen address on stderr, serves until ctrl-c. `--max-parallel 0` is refused. When `--accept-spend-key` is on, print the spec's sentence: "every SpendKey job holds the sending wallet's spend key: run this only for wallets you own".

- [ ] **Step 1: Write the failing HTTP tests**

`crates/randprotocol-prover/tests/http.rs`:

```rust
use randprotocol_prover::http::{serve, MAX_BODY_BYTES};
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::pairing::Pairings;
use randprotocol_prover::service::{Config, ProveFn};
use randprotocol_prover::wire::*;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::hidden_input;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn ok_prover() -> ProveFn { Arc::new(|_, _, inputs, _, _| Ok((vec![0xAA; 64], [inputs[0]; 8], 14))) }

async fn start() -> (SocketAddr, Vec<u8>, [u8; 32], reqwest::Client) {
    let key = ProverKey::from_seed([4; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.accept_spend_key = true;
    cfg.prove = ok_prover();
    let (addr, _svc, _task) = serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    (addr, ek, token, reqwest::Client::new())
}

async fn rpc(http: &reqwest::Client, addr: SocketAddr, method: &str, params: Value) -> Value {
    http.post(format!("http://{addr}/")).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await.unwrap().json().await.unwrap()
}

fn job(token: [u8; 32]) -> ProveJob {
    ProveJob { version: WIRE_VERSION, token, witness_kind: WitnessKind::SpendKey, hc_bundle: ZkExecutor::hc_bundle(), profile: "test".into(), binding: [1; 8], inputs: vec![42; hidden_input::COUNT], reply_key: fresh_reply_key() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_submit_status_cancel_over_json_rpc() {
    let (addr, ek, token, http) = start().await;
    let info = rpc(&http, addr, "prover_info", json!([])).await;
    assert_eq!(info["result"]["witness_kinds"], json!(["spend_key"]));
    assert_eq!(info["result"]["queue"]["max"], 8);
    assert!(info["result"]["fee"].is_null());
    let j = job(token);
    let rk = j.reply_key;
    let sealed = hex::encode(seal_job(&ek, &j).unwrap());
    let r = rpc(&http, addr, "prover_submit", json!([sealed])).await;
    let id = r["result"]["job"].as_str().expect(&r.to_string()).to_string();
    let mut last = Value::Null;
    for _ in 0..100 {
        last = rpc(&http, addr, "prover_status", json!([id])).await;
        if last["result"]["state"] == "done" { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(last["result"]["state"], "done", "{last}");
    let reply = open_reply(&rk, &hex::decode(last["result"]["reply"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(reply.digest, [42; 8]);
    assert_eq!(rpc(&http, addr, "prover_cancel", json!([id])).await["result"]["cancelled"], false, "done is not cancellable");
    assert_eq!(rpc(&http, addr, "prover_status", json!(["ffff"])).await["error"]["code"], -32001);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_map_to_their_codes() {
    let (addr, ek, _token, http) = start().await;
    let sealed = hex::encode(seal_job(&ek, &job([0; 32])).unwrap());
    assert_eq!(rpc(&http, addr, "prover_submit", json!([sealed])).await["error"]["code"], -32003);
    assert_eq!(rpc(&http, addr, "prover_submit", json!(["zz"])).await["error"]["code"], -32602);
    assert_eq!(rpc(&http, addr, "prover_submit", json!([hex::encode([0u8; 200])])).await["error"]["code"], -32000);
    assert_eq!(rpc(&http, addr, "prover_nope", json!([])).await["error"]["code"], -32601);
    let r = http.post(format!("http://{addr}/")).json(&json!([{"jsonrpc":"2.0","id":1,"method":"prover_info","params":[]}])).send().await.unwrap().json::<Value>().await.unwrap();
    assert_eq!(r["error"]["code"], -32600, "no batches: {r}");
    let r = http.post(format!("http://{addr}/")).body("{not json").send().await.unwrap().json::<Value>().await.unwrap();
    assert_eq!(r["error"]["code"], -32700);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_body_is_refused_at_the_limit() {
    let (addr, _ek, _token, http) = start().await;
    let big = "a".repeat(MAX_BODY_BYTES + 1);
    let r = http.post(format!("http://{addr}/")).json(&json!({"jsonrpc":"2.0","id":1,"method":"prover_submit","params":[big]})).send().await.unwrap();
    assert_eq!(r.status(), 413);
}

#[test]
fn required_bytes_is_peak_times_parallel_plus_a_gib() {
    use randprotocol_prover::memory::*;
    assert_eq!(required_bytes(1), PROVER_PEAK_BYTES + HEADROOM_BYTES);
    assert_eq!(required_bytes(2), 2 * PROVER_PEAK_BYTES + HEADROOM_BYTES);
    // check() with an absurd parallelism must refuse on any machine, naming both numbers
    let e = check(1_000_000).unwrap_err();
    assert!(e.contains("GB"), "{e}");
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test -p randprotocol-prover --test http`
Expected: compile errors.

- [ ] **Step 3: Implement `http.rs`, `memory.rs`, `main.rs`**

`http.rs`: one `async fn handle(State(svc), body: Bytes) -> Response`. Parse the body as `Value`; an array → `-32600`; missing/absent `id` (a notification) → `-32600`; `jsonrpc != "2.0"` → `-32600`. Dispatch by `method`; `params` must be an array (else `-32602`); `prover_submit`'s one param is a hex string decoded with `hex::decode` (bad hex → `-32602`). Map `Refusal` as the table above. Wrap with `axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES)`; axum answers 413 on its own for an over-limit body — the test only checks the status. Reply JSON: `{"jsonrpc":"2.0","id":<id>,"result":…}` or `{"jsonrpc":"2.0","id":<id>,"error":{"code","message","data"?}}`.

`main.rs`: clap derive as described in Interfaces; `#[tokio::main]`; `tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))`. Expand `~` in `--home` by hand (`std::env::var("HOME")`); create the directory 0700 on `keygen`/`pair`. `run` builds `Config::new(key, pairings)` and applies the flags; `backend_for(cuda)` copied from `crates/randprotocol-client/src/main.rs:850` (errors "built without CUDA support; rebuild rand-prover with --features cuda" when the feature is absent).

- [ ] **Step 4: Run to see them pass, and run the binary once**

Run: `cargo test -p randprotocol-prover --test http`
Expected: 4 pass.

Run: `cargo run -p randprotocol-prover --bin rand-prover -- --home /tmp/rp-test keygen && cargo run -p randprotocol-prover --bin rand-prover -- --home /tmp/rp-test pair --name laptop --own --qr && cargo run -p randprotocol-prover --bin rand-prover -- --home /tmp/rp-test pairings`
Expected: a fingerprint, a `randprover:…&own=1` link with a QR under it, one row `laptop  own  <date>`. Then `rm -rf /tmp/rp-test`.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-prover
git commit -m "prover: the prover_* JSON-RPC listener, the free-memory gate, and rand-prover keygen | pair | unpair | pairings | run"
```

---

### Task 5: Witness hygiene and one real proof through the service

**Files:**
- Create: `crates/randprotocol-prover/tests/hygiene.rs`
- Create: `crates/randprotocol-prover/tests/proving_slot/mod.rs` (a byte-copy of `crates/randprotocol-client/tests/proving_slot/mod.rs`; a third copy — AGENTS.md already records why each test binary needs its own)
- Modify: `crates/randprotocol-prover/Cargo.toml` (dev-deps: `tracing-subscriber` with `fmt`, `randprotocol-client` for `Wallet`? — no: build the witness with `randprotocol_zkvm::hidden::hidden_bundle_inputs` directly, as `crates/randprotocol-zkvm/tests/hidden_bundle.rs`'s `shapes()` helper does; copy the minimal honest-witness construction from there)

**Interfaces:**
- Consumes: `http::serve`, `wire`, `randprotocol_zkvm::hidden::{hidden_bundle_inputs, hidden_bundle_digest, HiddenDigestInput, HiddenOutput}`, `randprotocol_zkvm::notes::{SpendKey, Note}`, the Merkle helpers `tests/hidden_bundle.rs` uses to make a valid path (read that file's `Case`/`shapes()` and reuse the same calls), `randprotocol_zkvm::executor::ZkExecutor` for a local verify of the reply (`ZkExecutor::new(FriProfile::Test)` then `ConfidentialExecutor::verify_bundle(&exec, &hc, &proof, &binding)` — `randprotocol_core::confidential::ConfidentialExecutor` is the trait).

- [ ] **Step 1: Write the tests**

```rust
//! Spec §3.5: nothing the service logs or returns contains the witness. Two runs: a job that fails at
//! admission (the error path), and one real tier-14 proof at the test profile (the whole path).
mod proving_slot;
use proving_slot::proving_slot;
use std::io::Write;
use std::sync::{Arc, Mutex};

/// A tracing writer that keeps everything.
#[derive(Clone, Default)] struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture { fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0.lock().unwrap().extend_from_slice(b); Ok(b.len()) } fn flush(&mut self) -> std::io::Result<()> { Ok(()) } }
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture { type Writer = Capture; fn make_writer(&'a self) -> Capture { self.clone() } }

/// Every rendering of the spend key a log or reply could contain.
fn needles(sk: &[u32; 8], inputs: &[u32]) -> Vec<String> {
    let mut v = Vec::new();
    v.push(hex::encode(randprotocol_core::notes::words_to_bytes(sk)));
    for w in sk { v.push(format!("{w}")); v.push(format!("{w:08x}")); }
    v.push(inputs[8..16].iter().map(|w| format!("{w}")).collect::<Vec<_>>().join(", "));   // the first note's owner field, as Debug would print a slice
    v
}

fn assert_clean(haystack: &[u8], needles: &[String]) {
    let text = String::from_utf8_lossy(haystack);
    let lower_hex = hex::encode(haystack);
    for n in needles {
        assert!(!text.contains(n.as_str()), "the witness leaked as {n:?}");
        assert!(!lower_hex.contains(&hex::encode(n.as_bytes())), "the witness leaked (binary) as {n:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_logged_or_returned_carries_the_witness() {
    let logs = Capture::default();
    let _g = tracing::subscriber::set_default(tracing_subscriber::fmt().with_writer(logs.clone()).with_ansi(false).with_max_level(tracing::Level::TRACE).finish());
    // spend key words are large and distinct so their decimal forms are not coincidences
    let sk = randprotocol_zkvm::notes::SpendKey([0x7a3c_91e5, 0x1f4b_88d2, 0x6e0d_27a9, 0x53c8_1b76, 0x2b9e_4f13, 0x48d1_6c05, 0x0f72_a3be, 0x67ac_5d94]);
    let (inputs, expected, binding) = honest_witness(&sk);   // helper below
    let key = randprotocol_prover::key::ProverKey::from_seed([6; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = randprotocol_prover::pairing::Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let mut cfg = randprotocol_prover::service::Config::new(key, pairings);
    cfg.accept_spend_key = true;
    let (addr, _svc, _task) = randprotocol_prover::http::serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    let http = reqwest::Client::new();
    let mut responses: Vec<u8> = Vec::new();
    // 1. the error path: an unknown guest — refused after the job was opened
    let mut bad = randprotocol_prover::wire::ProveJob { version: 1, token, witness_kind: randprotocol_prover::wire::WitnessKind::SpendKey, hc_bundle: [1; 8], profile: "test".into(), binding, inputs: inputs.clone(), reply_key: randprotocol_prover::wire::fresh_reply_key() };
    let r = http.post(format!("http://{addr}/")).json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"prover_submit","params":[hex::encode(randprotocol_prover::wire::seal_job(&ek, &bad).unwrap())]})).send().await.unwrap().bytes().await.unwrap();
    responses.extend_from_slice(&r);
    // 2. the whole path: a real proof
    bad.hc_bundle = randprotocol_zkvm::executor::ZkExecutor::hc_bundle();
    let rk = bad.reply_key;
    let slot = proving_slot().await;
    let r = http.post(format!("http://{addr}/")).json(&serde_json::json!({"jsonrpc":"2.0","id":2,"method":"prover_submit","params":[hex::encode(randprotocol_prover::wire::seal_job(&ek, &bad).unwrap())]})).send().await.unwrap().bytes().await.unwrap();
    responses.extend_from_slice(&r);
    let id = serde_json::from_slice::<serde_json::Value>(&r).unwrap()["result"]["job"].as_str().unwrap().to_string();
    let mut reply_hex = None;
    for _ in 0..3000 {
        let r = http.post(format!("http://{addr}/")).json(&serde_json::json!({"jsonrpc":"2.0","id":3,"method":"prover_status","params":[id]})).send().await.unwrap().bytes().await.unwrap();
        responses.extend_from_slice(&r);
        let v: serde_json::Value = serde_json::from_slice(&r).unwrap();
        match v["result"]["state"].as_str() { Some("done") => { reply_hex = Some(v["result"]["reply"].as_str().unwrap().to_string()); break; } Some("failed") => panic!("{v}"), _ => tokio::time::sleep(std::time::Duration::from_millis(200)).await }
    }
    drop(slot);
    let reply = randprotocol_prover::wire::open_reply(&rk, &hex::decode(reply_hex.expect("proved")).unwrap()).unwrap();
    assert_eq!(reply.digest, expected, "the honest digest");
    assert_eq!(reply.tier, 14);
    let exec = randprotocol_zkvm::executor::ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    randprotocol_core::confidential::ConfidentialExecutor::verify_bundle(&exec, &randprotocol_zkvm::executor::ZkExecutor::hc_bundle(), &reply.proof, &binding).expect("the reply verifies against the binding");
    // 3. scan everything
    let n = needles(&sk.0, &inputs);
    assert_clean(&responses, &n);
    assert_clean(&logs.0.lock().unwrap(), &n);
    assert!(!logs.0.lock().unwrap().is_empty(), "the capture saw the service's logs at all");
}
```

`honest_witness(&sk) -> (Vec<u32>, Word8, [u32; 8])`: build a 1-in/1-out RAND self-transfer the way `crates/randprotocol-zkvm/tests/hidden_bundle.rs` builds its simplest honest case (read that file; copy its note/path/anchor construction and its `HiddenDigestInput` assembly verbatim), `binding = [11; 8]`. The expected digest is `hidden_bundle_digest(&di)`.

- [ ] **Step 2: Run it**

Run: `cargo test --release -p randprotocol-prover --test hygiene -- --nocapture`
Expected: passes; ~100–150 s for the proof. If the `needles` assert trips on a coincidental decimal, change the sk words, not the assertion.

- [ ] **Step 3: Commit**

```bash
git add crates/randprotocol-prover
git commit -m "prover: hygiene — every log line and every reply of an error path and a real proof is scanned for the spend key; the reply verifies locally"
```

---

### Task 6: `rand-node run --prover`

**Files:**
- Modify: `crates/randprotocol-node/Cargo.toml` (add `randprotocol-prover = { workspace = true }`; forward `cuda`/`mock-cuda` features to it)
- Modify: `crates/randprotocol-node/src/main.rs:410-460` (`Cmd::Run` flags) and `:941-` (the handler)
- Test: `crates/randprotocol-node/tests/prover_flag.rs`

**Interfaces:**
- Consumes: `randprotocol_prover::{http::serve, service::Config, key::ProverKey, pairing::Pairings, memory}`.
- Produces: flags on `rand-node run`:
  - `--prover <ADDR>` (SocketAddr; absent = no prover), `--prover-home <DIR>` (default `<datadir>/prover`), `--prover-accept-spend-key`, `--prover-max-parallel` (1), `--prover-max-queue` (8), `--prover-skip-memory-check`.
  - The node **refuses to start** when `--prover` is set and `<home>/prover.key.json` is missing: "no prover key at …: run `rand-prover --home <DIR> keygen` and `pair` first" (a node never mints a key on its own). Empty pairings = a warning, as `rand-prover run` does.
  - The prover binds after the node's RPC is up; it stops with the node. `--prover` equal to `--rpc` is refused ("the prover is never a method of the public RPC").

- [ ] **Step 1: Write the failing test**

`crates/randprotocol-node/tests/prover_flag.rs` — drive the binary (the node's `tests/genesis_cli.rs` shows how it locates `rand-node` via `env!("CARGO_BIN_EXE_rand-node")`):

```rust
use std::process::Command;

#[test]
fn run_with_prover_refuses_without_a_key_and_refuses_the_rpc_address() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node")).args(["run", "--datadir"]).arg(dir.path()).args(["--prover", "127.0.0.1:0"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("no prover key"), "{err}");
    assert!(err.contains("rand-prover"), "{err}");
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node")).args(["run", "--datadir"]).arg(dir.path()).args(["--rpc", "127.0.0.1:8599", "--prover", "127.0.0.1:8599"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("never a method of the public RPC"), "{err}");
}

#[test]
fn run_help_lists_the_prover_flags() {
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node")).args(["run", "--help"]).output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    for f in ["--prover ", "--prover-home", "--prover-accept-spend-key", "--prover-max-parallel", "--prover-max-queue"] { assert!(s.contains(f), "{f} missing:\n{s}"); }
}
```

The end-to-end (a node hosting a prover, a wallet proving through it) is Task 8's test with the in-process service; a binary-level test that needs a genesis and a real proof is not worth a second 100 s — but add a third case here if cheap: start `rand-node run --prover 127.0.0.1:0 …` on a tmp genesis (copy `tests/genesis_cli.rs`'s genesis making) with a key made by `rand-prover keygen` (`env!("CARGO_BIN_EXE_rand-prover")` is not available across crates — skip; the flag-check tests above are the gate).

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p randprotocol-node --test prover_flag`
Expected: `--prover` unknown → clap error, assertions fail.

- [ ] **Step 3: Implement**

In `Cmd::Run` add the flags with doc comments (they become `--help`). In the handler, before `node::start`: validate `prover != rpc`, load `ProverKey::load(home.join("prover.key.json"))` mapping `NotFound` to the message above (bail before the node opens its database). After `node::start` returns the handle, build `Config::new(key, Pairings::load(home.join("pairings.json"))?)`, apply the flags, `memory::check` unless skipped, `randprotocol_prover::http::serve(prover_addr, cfg).await?`, log `prover listening on {bound}, fingerprint {fp}`; add the returned task to the `tokio::select!` so a prover crash stops the node too.

- [ ] **Step 4: Run to see it pass**

Run: `cargo test -p randprotocol-node --test prover_flag`
Expected: 2 pass. Also `cargo check -p randprotocol-node --features mock-cuda` builds.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-node
git commit -m "node: rand-node run --prover <ADDR> hosts the prover service on its own listener — never the RPC; a missing key refuses to start"
```

---

### Task 7: The wallet's remote arm — `Proving::Remote`, `rand prover pair|show|forget`, `--prover`

**Files:**
- Create: `crates/randprotocol-client/src/prover.rs`
- Modify: `crates/randprotocol-client/src/lib.rs` (`pub mod prover;`)
- Modify: `crates/randprotocol-client/src/wallet.rs:1527-1580` (`Proved`, `Proving`, `Prepared::prove`), `:1774` (`prove_transaction`), and every `pub` entry point that takes `backend: Backend` (`send :3308`, `send_asset :3329`, `send_asset_with :3347`, `submit :1944`, `submit_bridge_action :2003`, `submit_burn :2135`, `submit_token_burn :2211`, `submit_bound_call :1813`, `submit_spend :1898`)
- Modify: `crates/randprotocol-client/src/main.rs` (global `--prover`, the `Prover` subcommand, `backend_for` → `proving_for`)
- Modify: `crates/randprotocol-client/Cargo.toml` (`randprotocol-prover = { workspace = true, default-features = false }`)
- Modify call sites: `crates/randprotocol-client/tests/wallet_flow.rs` (17 × `Backend::Cpu`), `crates/randprotocol-node/tests/cluster.rs` (14), `crates/randprotocol-node/tests/zusd_e2e.rs` (6), `crates/randprotocol-client/src/main.rs` (2)
- Test: `crates/randprotocol-client/src/prover.rs` unit tests (a fake prover HTTP server via `axum` on `127.0.0.1:0`, which the client crate has as a dev-dependency through the workspace — check; else `tokio::net::TcpListener` + a hand-written HTTP/1.1 responder like `wallet.rs`'s `tests::serve` FakeChain does)

**Interfaces:**
- Consumes: `randprotocol_prover::wire::*`, `randprotocol_prover::pairing::PairingLink`, `randprotocol_prover::key::fingerprint_of`; `RpcClient`-style `reqwest::Client`; `wallet::{check_published_digest, check_proof_size, proof_cap}`; `randprotocol_zkvm::executor::ZkExecutor` + `ConfidentialExecutor::verify_bundle` for the local verify.
- Produces:
  ```rust
  // prover.rs
  #[derive(Clone, Serialize, Deserialize)]
  pub struct PairedProver { pub url: String, pub kem_ek: String /* hex */, pub token: String /* hex; the file is 0600 */, pub own: bool, pub fingerprint: String, pub name: Option<String> }
  impl PairedProver {
      pub fn path_for(key_file: &Path) -> PathBuf;                 // <key>.prover.json
      pub fn from_link(link: &PairingLink, name: Option<String>) -> PairedProver;
      pub fn load(key_file: &Path) -> Result<Option<PairedProver>>;
      pub fn save(&self, key_file: &Path) -> Result<()>;           // 0600, overwrite allowed (re-pair)
      pub fn forget(key_file: &Path) -> Result<bool>;
  }
  pub struct RemoteProver { paired: PairedProver, http: reqwest::Client, poll: Duration /* 1 s */, max_wait: Duration /* 20 min */, verify_locally: bool }
  impl RemoteProver {
      pub fn new(paired: PairedProver) -> RemoteProver;
      pub async fn info(&self) -> Result<serde_json::Value>;      // prover_info; refuses a fingerprint ≠ paired.fingerprint
      /// Seal, submit, poll, open, check. `expected` and `proof_cap` are the wallet's own numbers.
      pub async fn prove(&self, hc: &Word8, profile: FriProfile, witness_kind: WitnessKind, inputs: &[u32], binding: &[u32; TX_BINDING_WORDS], expected: &Word8, proof_cap: usize) -> Result<(Vec<u8>, u8)>;
  }
  // wallet.rs
  #[derive(Clone)]
  pub enum Proving { Local(Backend), Remote(Arc<RemoteProver>), #[cfg(test)] Emulated }
  impl Proving { pub fn local(b: Backend) -> Proving; async fn prove(&self, prepared: &Prepared, binding: &[u32; 8], profile: FriProfile) -> Result<Proved>; }
  // every entry point: `profile: FriProfile, proving: &Proving` replaces `profile: FriProfile, backend: Backend`
  ```
- `RemoteProver::prove` rules: (1) `info()` once per `RemoteProver` (cached), checking fingerprint, `hc_bundles` contains the hex of `hc`, `profiles` contains the profile's name, `witness_kinds` contains the kind's name — each failure is an error that says what the prover lacks; (2) `witness_kind == SpendKey && !paired.own` → error "this build's witness carries the spend key; only a prover paired as your own (own=1) may receive it"; (3) seal with a fresh `reply_key`, `prover_submit`, then poll `prover_status` every `poll`; print the queue position / "proving on <name>…" to stderr when it changes; `busy` (-32005) → error naming the depth; (4) on `done`: `open_reply`, `check_published_digest(&reply.digest, expected)`, `check_proof_size(reply.proof.len(), proof_cap)`, and when `verify_locally` (default true; `RAND_PROVER_NO_VERIFY=1` turns it off) `ZkExecutor::new(profile)` → `verify_bundle(hc, &proof, binding)`; (5) `failed` → error with the prover's text; `expired`/`max_wait` exceeded → error "the prover did not finish within …"; on any error after submit, best-effort `prover_cancel`.
- CLI: global `--prover` (`#[arg(long, global = true)]` boolean) — when set, every proving subcommand builds `Proving::Remote(Arc::new(RemoteProver::new(PairedProver::load(&key)?.ok_or("no prover paired for this wallet: rand prover pair <link>")?)))`; otherwise `Proving::Local(backend_for(cuda)?)`. Subcommand `Prover { Pair { link: String, #[arg(long)] name: Option<String> }, Show, Forget }`: `pair` parses the link, calls `prover_info`, checks the fingerprint, saves, prints `paired <fingerprint> at <url> (own: yes|no)`; `show` prints the file minus the token; `forget` deletes it. A link whose URL is `http://` and not loopback is refused ("https anywhere but 127.0.0.1/localhost", the clients' rule).

- [ ] **Step 1: Write the failing unit tests (in `prover.rs`'s `mod tests`)**

Use a tiny fake prover: bind `tokio::net::TcpListener` on `127.0.0.1:0`, read one HTTP request, answer a canned JSON-RPC reply chosen by a `Vec<Value>` script (one per request), like `wallet.rs::tests::serve` does for the FakeChain (read it and reuse its request/response helpers). Cases:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reply_with_the_wrong_digest_is_refused() { /* script: info ok → submit {job} → status done with a reply sealed under the reply_key the test captures by parsing the submitted sealed job with the fake's dk; digest = expected ^ 1 → prove() errs containing "digest" and the fake saw a prover_cancel */ }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_proof_is_refused() { /* reply.proof.len() == proof_cap + 1 → error contains "bytes" */ }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spend_key_witness_goes_only_to_an_own_prover() { /* paired.own == false → error before any HTTP request; the fake saw zero requests */ }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fingerprint_mismatch_is_refused_at_info() { /* info.kem_fingerprint ≠ paired.fingerprint → error, no submit */ }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prover_that_never_finishes_times_out() { /* max_wait = 300 ms, poll = 50 ms, status always "proving" → error contains "did not finish"; the fake saw a prover_cancel last */ }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_that_lacks_the_guest_or_the_kind_is_an_error_that_says_so() { /* hc_bundles: [] → "guest"; witness_kinds: [] → "spend_key" */ }
#[test]
fn a_pairing_file_is_0600_and_show_never_prints_the_token() { /* save; mode; load equals; forget → true then false */ }
#[test]
fn a_plain_http_link_off_loopback_is_refused() { /* PairedProver::from_link + the check fn used by `rand prover pair` */ }
```

For the digest test the fake must open the sealed job (it holds the `ProverKey` whose `kem_ek` the `PairedProver` carries) to learn `reply_key`; `randprotocol_prover::wire::open_job` is available to the test with `--no-default-features` — the client depends on the crate without `service`, and a unit test inside the client crate sees the same features. Verification is stubbed off in these tests (`verify_locally = false`) since the fake's proof bytes are not a proof; one test with `verify_locally = true` and garbage proof bytes asserts the local verify rejects ("did not verify").

- [ ] **Step 2: Run to see them fail**

Run: `cargo test -p randprotocol-client --lib prover::`
Expected: compile errors.

- [ ] **Step 3: Implement**

`prover.rs` per the interface. In `wallet.rs`: make `Proving` `pub`, `Local(Backend)`/`Remote(Arc<RemoteProver>)`, make `Proving::prove` `async` (the `Remote` arm awaits `RemoteProver::prove(&prepared.guest, profile, WitnessKind::SpendKey, &prepared.words, binding, &prepared.expected, cap)`; the `Local` arm calls the existing sync `Prepared::prove` — leave it sync inside the async fn, as it is today), thread `profile` through (`Proving` no longer carries it — the callers already have `profile`), make `prove_transaction` `async fn prove_transaction(tx: &mut Transaction, prepared: &Prepared, proving: &Proving, profile: FriProfile) -> Result<Proved>` and `.await` it at its call sites; the proof cap comes from `proof_cap(limits)` which `submit_spend` already has in scope (check; else fetch `rpc.limits()` there). Replace `backend: Backend` with `proving: &Proving` in the nine entry points; `Proving::local(Backend::Cpu)` at every call site (`sed` the tests: `Backend::Cpu` → `&Proving::local(Backend::Cpu)` where it was an argument; keep the `use` lines compiling). `Emulated` stays `#[cfg(test)]`.

`main.rs`: `proving_for(&cli, cuda, &key) -> Result<Proving>`; the `Prover` subcommand.

- [ ] **Step 4: Run to see them pass, and the whole client lib + node lib compile with tests**

Run: `cargo test -p randprotocol-client --lib` (all, not only `prover::` — the wallet's Emulated tests must still pass) and `cargo check --workspace --tests --release`
Expected: green; no `Backend` argument left anywhere (`grep -rn 'Backend::Cpu' crates/*/tests crates/*/src | grep -v 'Proving::local' | grep -v randprotocol-zkvm | grep -v randprotocol-prover` is empty except the `backend_for` helpers).

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-client crates/randprotocol-node/tests
git commit -m "wallet: Proving::Remote — seal the witness to a paired prover, poll, open, refuse a wrong digest or an oversized proof, verify locally; rand prover pair|show|forget and --prover"
```

---

### Task 8: End to end — a send proved by a paired prover is admitted

**Files:**
- Modify: `crates/randprotocol-client/tests/wallet_flow.rs` (one new test; dev-dep `randprotocol-prover` with `service`)
- Modify: `crates/randprotocol-client/Cargo.toml` (`[dev-dependencies] randprotocol-prover = { workspace = true }`)

**Interfaces:**
- Consumes: `start_with(dir, key, genesis)` (`wallet_flow.rs:114`), `genesis(&Keypair)` (`:57`), `RpcClient::mint_shielded`/`wait_for_transaction`, `wallet::scan`, `wallet::send(rpc, w, store, to, amount, memo, fee, profile, &Proving, chain_id, wait)`, `randprotocol_prover::http::serve`, `randprotocol_prover::service::Config`, `randprotocol_prover::key::ProverKey`, `randprotocol_prover::pairing::{Pairings, PairingLink}`, `randprotocol_client::prover::{PairedProver, RemoteProver}`, `proving_slot()`.

- [ ] **Step 1: Write the test**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_proved_by_a_paired_prover_is_admitted() {
    init_tracing();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::generate();
    let handle = start(&dir, &key).await;                                   // the existing helper
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    // the prover: its own key, one own=1 pairing, spend-key jobs accepted, the real prove fn
    let pkey = randprotocol_prover::key::ProverKey::generate();
    let ek = pkey.kem_ek().to_vec();
    let mut pairings = randprotocol_prover::pairing::Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let mut cfg = randprotocol_prover::service::Config::new(pkey, pairings);
    cfg.accept_spend_key = true;
    let (paddr, _svc, _ptask) = randprotocol_prover::http::serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    let link = randprotocol_prover::pairing::PairingLink { kem_ek: ek, url: format!("http://{paddr}"), token, own: true };
    let paired = randprotocol_client::prover::PairedProver::from_link(&link, Some("laptop".into()));
    let proving = Proving::Remote(std::sync::Arc::new(randprotocol_client::prover::RemoteProver::new(paired)));
    // fund alice, send to bob through the prover, bob sees it
    let alice = Wallet::from_spend_key(SpendKey([21; 8]));
    let bob = Wallet::from_spend_key(SpendKey([22; 8]));
    let h = rpc.mint_shielded(&alice.address.to_string(), Some(5_000_000_000)).await.unwrap();
    rpc.wait_for_transaction(&h, Duration::from_secs(60)).await.unwrap();
    let mut store = NoteStore::default();      // whatever the existing tests use
    wallet::scan(&rpc, &alice, &mut store).await.unwrap();
    let slot = proving_slot().await;
    let sub = wallet::send(&rpc, &alice, &mut store, &bob.address, 1_000_000_000, "", 2_000_000, FriProfile::Test, &proving, CHAIN_ID, true).await.unwrap();
    drop(slot);
    assert_eq!(sub.tier, 14);
    let mut bstore = NoteStore::default();
    wallet::scan(&rpc, &bob, &mut bstore).await.unwrap();
    assert_eq!(bstore.balance(0), 1_000_000_000, "bob received the note the prover's proof carried");
}
```

Match the exact helper names, the `send` signature after Task 7 and the fee constant the other `wallet_flow` tests use (read the file's first `send` call and copy its arguments).

- [ ] **Step 2: Run it**

Run: `cargo test --release -p randprotocol-client --test wallet_flow a_send_proved_by_a_paired_prover_is_admitted -- --nocapture`
Expected: pass in ~2–4 min (node start + one proof + commit). Then run the whole `wallet_flow` binary once to confirm nothing else regressed: `cargo test --release -p randprotocol-client --test wallet_flow` (~25 min).

- [ ] **Step 3: Commit**

```bash
git add crates/randprotocol-client
git commit -m "wallet_flow: a send proved by a paired prover is admitted and received — the end-to-end of Phase 1"
```

---

### Task 9: Docs

**Files:**
- Create: `docs/prover.md`
- Modify: `README.md` (the binaries table / "what runs where"; add `rand-prover`), `docs/cli.md` (`rand prover …`, `--prover`), `docs/deploy.md` (one paragraph: an operator node with `--prover` is loopback-only unless fronted by TLS; never on F/E's public RPC), `docs/node-hardware.md` (the prover's 5.74 GB peak row cross-referenced)

- [ ] **Step 1: Write `docs/prover.md`**

Sections, in this order, each a few paragraphs with the exact commands: (1) what it is (spec §1's table of the three roles); (2) the trust model, verbatim from the spec: a Phase 1 prover receives the spend key — "someone who wants full privacy runs their own"; a Phase 2 prover receives the viewing key and can read the wallet's whole history; (3) run your own: `rand-prover keygen`, `pair --name … --own --qr`, `run --accept-spend-key`; memory (5.74 GB × parallel + 1 GiB), `--cuda`; (4) in a node: `rand-node run --prover 127.0.0.1:8600 --prover-home /root/prover --prover-accept-spend-key`, why it is never the RPC; (5) the wallet: `rand prover pair <link>`, `rand send --prover …`, what the wallet checks (digest, size, local verify), the `own=1` rule; (6) the wire (a copy of spec §3.2's tables and the sealed layout) for other client authors; (7) TLS: `http://` only on loopback; put Caddy in front for a LAN/phone (spec open question 4, unresolved); (8) what Phase 2 changes (one paragraph pointing at the spec §4).

- [ ] **Step 2: Update the other four docs, then check the links**

Run: `grep -n 'prover' README.md docs/cli.md docs/deploy.md docs/node-hardware.md | head` — each file names `docs/prover.md` once.

- [ ] **Step 3: Commit**

```bash
git add docs README.md
git commit -m "docs: prover.md — the delegated prover's runbook, trust model and wire; cli, deploy and hardware cross-references"
```

---

### Task 10: Release v0.6.2

**Preconditions:** the `v0.6.1` tag exists on `origin` and chain 16 is live (the other session, `fullnode-cb`, messages the genesis hash and the release sha). Do not tag before that.

- [ ] **Step 1: Rebase onto the tag**

```bash
cd /private/tmp/fullnode-deleg && git fetch origin --tags && git rebase v0.6.1
```
Resolve conflicts (expected only in `Cargo.lock`, `Cargo.toml` members, `main.rs` flag blocks). `cargo check --workspace --tests --release`.

- [ ] **Step 2: Version bump and the AGENTS.md entry**

`Cargo.toml` `[workspace.package] version = "0.6.2"`. Add an AGENTS.md "Project memory" entry `### v0.6.2 — delegated proving, Phase 1 (<date>)` in the style of the v0.5.10 entry: what it is (crate, binary, node flag, wallet flag), the trust model sentence, what is NOT in it (Phase 2, fees, `ViewingKey` jobs), the traps found while building (fill from the commits), and "Roll: node-only, optional — no consensus, wire or genesis change; a node without `--prover` is unchanged".

- [ ] **Step 3: The suite**

Run, detached with `nohup`, from the worktree: `cargo test --workspace --release 2>&1 | tee /private/tmp/claude-501/.../v062-suite.log` — expect the same counts as v0.6.1's run plus the new binaries (`wire` 9, `pairing` 6, `service` 9, `http` 4, `hygiene` 1, `prover_flag` 2, client lib + ~8, `wallet_flow` + 1). The recursion-fixture tests fail on this laptop as always (AGENTS.md); skip them by name as the release suite does. Record the numbers for the AGENTS.md entry.

- [ ] **Step 4: The whole-branch review**

Dispatch one fresh reviewer (the most capable model) over `git diff v0.6.1...feat/delegated-proving` with the spec and this plan; fix what it finds red-first; a second pass only if the first found anything above Minor.

- [ ] **Step 5: Merge, tag, release**

```bash
git checkout main && git pull --ff-only origin main && git merge --ff-only feat/delegated-proving && git push origin main
git tag -a v0.6.2 -m "v0.6.2 — delegated proving, Phase 1: rand-prover, rand-node run --prover, rand --prover" && git push origin v0.6.2
```
Build the release binaries the way v0.6.1 was built (on E in `/root/build062`, `deploy/rebuild-vps.sh`'s clean-tree build; the memory `feedback-roll-via-release-download` and the v0.5.9 entry describe it), publish the GitHub release with `rand-node`, `rand`, **and `rand-prover`** plus their sha256s. No fleet roll is required (node-only, opt-in); say so in the release notes and leave the roll to the operator.

---

## Self-review

- **Spec coverage:** §3.1 crate/binary/node flag → Tasks 1, 4, 6. §3.2 wire → Task 1 (codec), Task 4 (methods). §3.3 pairing, `own`, `--accept-spend-key` → Tasks 2, 3, 7. §3.4 resources → Tasks 3, 4. §3.5 hygiene → Tasks 1 (zeroize), 3 (drop in the task), 5 (the scan). §3.6 client checks → Task 7. §5 fee → `fee: null` reserved (Task 3); Phase 2. §7 P1-1..P1-6 → Tasks 1–2, 3–4, 6, 2+7, 5+8, 9. §8 Q3 answered "yes, behind a flag, refused on the RPC address" (Task 6); Q4 documented as the operator's TLS (Task 9).
- **Placeholders:** none; the two "read that file and copy" instructions name the file and the function.
- **Type consistency:** `ProveFn` signature = `prove_bundle_for`'s; `Proving` is `pub` with `Local(Backend)`/`Remote(Arc<RemoteProver>)` everywhere; `Info.hc_bundles` uses `rand_status.hc_bundle`'s hex form (Task 3 fixes the test to it).
- **Review Focus:** all five pinned (Tasks 1, 7, 7, 4, 4).
