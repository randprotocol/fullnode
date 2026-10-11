# Private Multisig, Phases 1–2 (in-guest Dilithium2 + multisig auth guest) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and measure a multisig auth guest that proves "M of a hidden N-key Dilithium2 policy signed this transaction's binding" and publishes the same `c = H(AUTH, nk ‖ salt)` as the single-key auth guest.

**Architecture:** A `no_std` round-3 Dilithium2 verifier (`dilithium-core`), generic over a Keccak permutation, runs natively for tests and inside a compiled rVM guest with the `KECCAK` syscall. A host model (`research/src/msauth.rs`) defines the policy hashes and the fixed witness layout. The `msauth` guest checks the relation and publishes `c`. Phase 1 ends with cycles per verification measured. Phase 2 ends with the guest's tier at `M_MAX` ∈ {2, 3, 5} measured, which decides whether phase 3 (a mod-q/NTT chip) is needed.

**Tech Stack:** Rust 1.98.1 (`rust-toolchain.toml`), `riscv32im` guests via `rand-guest build`, `guest-sdk`, Plonky3 0.7 rVM (`research/`), `crystals-dilithium = "=2.0.0"` as the test oracle.

**Spec:** `fullnode/docs/superpowers/specs/2026-10-11-private-multisig-design.md`

**Where the work happens:** the `circuits` repo, in a fresh worktree:

```bash
cd ~/Github/randprotocol/circuits && git fetch origin
git worktree add -b feat/private-multisig ~/rand-worktrees/circuits-private-multisig origin/main
cd ~/rand-worktrees/circuits-private-multisig
```

Run `ListAgents` first. The rVM phase-4 session works in `~/rand-worktrees/circuits-*`. Claim this
branch with a message before writing anything.

## Global Constraints

- Dilithium variant: **round-3 `dilithium2`** from `crystals-dilithium` 2.0.0 (`crate::dilithium2`), the module `fullnode/crates/randprotocol-core/src/crypto.rs` uses. **Not** `ml_dsa_44`.
- Sizes: public key 1 312 bytes = 328 words; signature 2 420 bytes = 605 words; words little-endian.
- Domain tags: `AUTH = 65` (mirrors fullnode `auth::AUTH_DOMAIN`), `MS_LEAF = 66`, `MS_NODE = 67`, `MS_POLICY = 68`, `NK_MS = 69`. Existing `NK`/`PK` tags come from `notes::domain`.
- `H(domain, msg)` = `notes::hash(domain, msg)` = the `POSEIDON2` syscall over `[domain, msg…]` (not `POSEIDON2_LEN`).
- `N_MAX = 16` (Merkle depth 4). `M_MAX` is a `const` in the guest, default 3; `MSAUTH_WORDS = 17 + M_MAX × 967`.
- Signing message: `b"rand-msauth-1"` followed by the 8 binding words as 32 LE bytes (45 bytes).
- Bad witness: the guest panics. The guest-sdk handler writes `0xdead_beef` to output slot 7, which never equals a real `c`.
- Toolchain: `cargo +1.98.1`. Guests are built only by `rand-guest build`, never by hand (`guests-compiled/README.md`).
- Compiled guest crates are their own workspace root (`[workspace]` in their `Cargo.toml`), like `evm`.

## Review Focus

1. **Malformed signatures must be rejected exactly as the crate rejects them.** Cases: hint bytes with indices not strictly increasing, a hint count over ω=80, `‖z‖∞ ≥ γ1 − β`, and a trailing nonzero hint byte. Each must return `false`, not panic. Owned by Task 2's `malformed_signatures_agree_with_the_crate`.
2. **Two active slots with the same index.** This would let one key count twice. Owned by Task 5's `duplicate_index_is_refused`.
3. **An active slot whose Merkle path reaches a different root** than the other slots (keys from two policies). Owned by Task 5's `slots_from_two_policies_are_refused`.
4. **A signature over another binding** (replay onto another transaction). Owned by Task 5's `signature_over_another_binding_is_refused`.
5. **Cycle count must not depend on which slots are active beyond the pinned tier.** Proof shape must be the same for 1 and `M_MAX` active slots. Owned by Task 6's `proof_shape_is_the_same_for_every_m`.

---

### Task 1: `dilithium-core` crate skeleton and the Keccak abstraction

**Files:**
- Create: `guests-compiled/dilithium-core/Cargo.toml`
- Create: `guests-compiled/dilithium-core/src/lib.rs`
- Create: `guests-compiled/dilithium-core/src/fips202.rs`
- Modify: `research/Cargo.toml` (normal dependency `dilithium-core`, dev-dependency `crystals-dilithium = "=2.0.0"`)
- Create: `research/tests/dilithium.rs`

**Interfaces:**
- Produces: `pub trait Keccak { fn permute(&mut self, s: &mut [u64; 25]); }`; `pub struct Shake<'k, K: Keccak>` with `fn new128(k)`, `fn new256(k)`, `fn absorb(&mut self, &[u8])`, `fn finalize(&mut self)`, `fn squeeze(&mut self, out: &mut [u8])`; `pub fn shake256<K: Keccak>(k: &mut K, input: &[&[u8]], out: &mut [u8])`.
- Host impl (in research, `src/dilithium_host.rs`): `pub struct HostKeccak; impl dilithium_core::Keccak for HostKeccak` calling `crate::keccak::keccak_f`.

- [ ] **Step 1: Write the failing test** (`research/tests/dilithium.rs`)

```rust
use dilithium_core::{shake256, Shake};
use rand_zkvm::dilithium_host::HostKeccak;

#[test]
fn shake256_matches_the_crate() {
    // crystals-dilithium exposes its fips202; compare against a fixed vector instead so the test
    // does not depend on a private module: SHAKE256("") first 32 bytes (FIPS 202 test vector).
    let mut out = [0u8; 32];
    shake256(&mut HostKeccak, &[b""], &mut out);
    assert_eq!(hex(&out), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

#[test]
fn shake128_streams_across_block_boundaries() {
    let mut a = Shake::new128(HostKeccak);
    a.absorb(&[7u8; 300]);
    a.finalize();
    let mut whole = [0u8; 400];
    a.squeeze(&mut whole);
    let mut b = Shake::new128(HostKeccak);
    b.absorb(&[7u8; 100]); b.absorb(&[7u8; 200]);
    b.finalize();
    let mut parts = [0u8; 400];
    b.squeeze(&mut parts[..168]); b.squeeze(&mut parts[168..]);
    assert_eq!(whole, parts);
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd research && cargo +1.98.1 test --release --test dilithium`
Expected: compile error, `dilithium_core` not found.

- [ ] **Step 3: Implement.** `Cargo.toml` as `evm-core`'s (no deps, `[workspace]` root, `#![no_std]`). `fips202.rs` is a port of `crystals-dilithium-2.0.0/src/fips202.rs`'s `keccak_absorb`/`keccak_squeeze`/`shake128_*`/`shake256_*`, with every `keccak_f1600_state_permute` call replaced by `k.permute(&mut state)`. Rates: SHAKE128 168, SHAKE256 136, padding `0x1f … 0x80`. `research/src/dilithium_host.rs`:

```rust
//! The host side of `dilithium-core`: its `Keccak` over this crate's own permutation.
pub struct HostKeccak;
impl dilithium_core::Keccak for HostKeccak {
    fn permute(&mut self, s: &mut [u64; 25]) { crate::keccak::keccak_f(s) }
}
```

Add `pub mod dilithium_host;` to `research/src/lib.rs`.

- [ ] **Step 4: Run to verify it passes.** Same command. Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add guests-compiled/dilithium-core research/Cargo.toml research/Cargo.lock research/src/lib.rs research/src/dilithium_host.rs research/tests/dilithium.rs
git commit -m "dilithium-core: no_std SHAKE over a Keccak trait, host impl on keccak_f"
```

### Task 2: Dilithium2 verify, agreeing with the crate

**Files:**
- Create: `guests-compiled/dilithium-core/src/{params.rs,reduce.rs,ntt.rs,poly.rs,packing.rs,rounding.rs,verify.rs}`
- Modify: `guests-compiled/dilithium-core/src/lib.rs` (`pub use verify::verify; pub const PK_BYTES: usize = 1312; pub const SIG_BYTES: usize = 2420;`)
- Test: `research/tests/dilithium.rs`

**Interfaces:**
- Consumes: Task 1's `Keccak`, `Shake`, `shake256`.
- Produces: `pub fn verify<K: Keccak>(k: &mut K, pk: &[u8; 1312], msg: &[u8], sig: &[u8; 2420]) -> bool`. It never panics, and it does no heap allocation.

- [ ] **Step 1: Write the failing tests** (append to `research/tests/dilithium.rs`)

```rust
use crystals_dilithium::dilithium2::{Keypair, PublicKey};

fn case(seed: u64, msg_len: usize) -> (Keypair, Vec<u8>) {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    let kp = Keypair::generate(Some(&s)).unwrap();
    let msg: Vec<u8> = (0..msg_len).map(|i| (i as u64 * 31 + seed) as u8).collect();
    (kp, msg)
}

fn ours(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    dilithium_core::verify(&mut HostKeccak, pk.try_into().unwrap(), msg, sig.try_into().unwrap())
}

#[test]
fn honest_signatures_verify_and_agree_with_the_crate() {
    for seed in 0..200u64 {
        let (kp, msg) = case(seed, (seed as usize * 7) % 300);
        let sig = kp.sign(&msg);
        let pkb = kp.public.to_bytes();
        assert!(PublicKey::from_bytes(&pkb).unwrap().verify(&msg, &sig));
        assert!(ours(&pkb, &msg, &sig), "seed {seed}");
    }
}

#[test]
fn tampering_with_any_part_is_rejected() {
    let (kp, msg) = case(1, 45);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    for i in (0..sig.len()).step_by(37) {
        let mut s = sig.to_vec(); s[i] ^= 1;
        let theirs = PublicKey::from_bytes(&pkb).unwrap().verify(&msg, &s);
        assert_eq!(ours(&pkb, &msg, &s), theirs, "sig byte {i}");
    }
    let mut m = msg.clone(); m[0] ^= 1;
    assert!(!ours(&pkb, &m, &sig));
    let mut p = pkb.to_vec(); p[40] ^= 1;
    assert!(!ours(&p, &msg, &sig));
}

#[test]
fn malformed_signatures_agree_with_the_crate() {
    let (kp, msg) = case(2, 45);
    let sig = kp.sign(&msg);
    let pkb = kp.public.to_bytes();
    let hint = 32 + 4 * 576; // OMEGA + K bytes of hint at the end
    let mut cases: Vec<Vec<u8>> = Vec::new();
    let mut s = sig.to_vec(); s[hint + 80] = 81; cases.push(s);               // count > OMEGA
    let mut s = sig.to_vec(); s[hint + 80] = s[hint + 81]; s[hint + 81] = 0; cases.push(s); // non-monotone count
    let mut s = sig.to_vec(); s[hint + 79] = 1; cases.push(s);                // nonzero tail
    let mut s = sig.to_vec(); s[hint] = 255; s[hint + 1] = 0; cases.push(s);  // indices not increasing
    let mut s = sig.to_vec(); for b in &mut s[32..32 + 18] { *b = 0xff; } cases.push(s); // ‖z‖∞ too big
    for (i, s) in cases.iter().enumerate() {
        let theirs = PublicKey::from_bytes(&pkb).unwrap().verify(&msg, s);
        assert_eq!(ours(&pkb, &msg, s), theirs, "case {i}");
        assert!(!theirs, "case {i} should be malformed");
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test dilithium`. Expected: compile error, `dilithium_core::verify` not found.

- [ ] **Step 3: Implement** by porting the crate's verify path line for line. The source files are under `~/.cargo/registry/src/*/crystals-dilithium-2.0.0/src/`. Source → target:
  - `params.rs` + `params/lvl2.rs` → `params.rs`: `N=256, Q=8380417, D=13, K=4, L=4, ETA=2, TAU=39, BETA=78, GAMMA1=1<<17, GAMMA2=(Q-1)/88, OMEGA=80`, `SEEDBYTES=32`, `CRHBYTES=64`, and the packed sizes.
  - `reduce.rs` → `reduce.rs`: `montgomery_reduce`, `reduce32`, `caddq`. Keep `i64` products. On RV32IM they lower to `MUL`/`MULH`.
  - `ntt.rs` → `ntt.rs`: `ZETAS`, `ntt`, `invntt_tomont`.
  - `poly.rs`, `polyvec.rs` → `poly.rs`: only what verify calls (`poly_uniform` via SHAKE128 rejection sampling, `poly_challenge`, `polyz_unpack`, `polyt1_unpack`, `poly_shiftl`, `poly_pointwise_montgomery`, `poly_chknorm`, `poly_use_hint`, `polyw1_pack`, the vector forms). Fixed-size arrays only, no `Vec`.
  - `packing.rs` → `packing.rs`: `unpack_pk`, `unpack_sig` (with every hint check, returning `false` instead of `Err`).
  - `rounding.rs` → `rounding.rs`: `decompose`, `use_hint`.
  - `sign.rs`'s verify function (reached from `dilithium2.rs:245` `PublicKey::verify`) → `verify.rs`. Every `fips202` call goes through `Shake`/`shake256` with the caller's `K`.

  Keep each function's name and argument order, so a reviewer can diff the port against the source.

- [ ] **Step 4: Run to verify it passes.** Same command. Expected: 5 passed (2 from Task 1, 3 here).

- [ ] **Step 5: Commit**

```bash
git add guests-compiled/dilithium-core research/tests/dilithium.rs
git commit -m "dilithium-core: round-3 Dilithium2 verify, known-answer agreement with crystals-dilithium 2.0.0"
```

### Task 3: the `dilithium-verify` measurement guest (phase-1 gate)

**Files:**
- Create: `guests-compiled/dilithium-verify/{Cargo.toml,src/main.rs}`
- Create: `guests-compiled/bin/dilithium-verify.bin`, `.bin.sha256` (by `rand-guest build`)
- Modify: `guest-sdk/src/lib.rs`: add `pub struct SyscallKeccak; impl dilithium_core::Keccak for SyscallKeccak` behind a `dilithium` feature, so other guests do not take the dependency.
- Modify: `research/src/guests.rs` (`compiled::dilithium_verify()`), `rand-guest/tests/build.rs` (add the new guest to the rebuild list)
- Test: `research/tests/dilithium.rs`

**Interfaces:**
- Consumes: Task 2's `verify`.
- Produces: `guest_sdk::SyscallKeccak` (feature `dilithium`): `permute` copies the 25 lanes to `[u32; 50]` (lane `i` low at `2i`, high at `2i+1`), calls `guest_sdk::keccak`, and copies back. Input layout: words `0..328` pk, `328..933` sig, `933` msg byte length `n ≤ 64`, `934..` msg words. Output slot 0 is `1` on a valid signature and `0` otherwise.

- [ ] **Step 1: Write the failing test**

```rust
fn words(b: &[u8]) -> Vec<u32> {
    b.chunks(4).map(|c| { let mut w = [0u8; 4]; w[..c.len()].copy_from_slice(c); u32::from_le_bytes(w) }).collect()
}

#[test]
fn the_guest_verifies_like_the_host_and_reports_its_cycles() {
    let p = rand_zkvm::guests::compiled::dilithium_verify();
    for (seed, flip) in [(3u64, false), (4, true)] {
        let (kp, msg) = case(seed, 45);
        let mut sig = kp.sign(&msg).to_vec();
        if flip { sig[100] ^= 1; }
        let mut input = words(&kp.public.to_bytes());
        input.extend(words(&sig));
        input.push(msg.len() as u32);
        input.extend(words(&msg));
        let exec = rand_zkvm::emulator::execute(&p, &input, &[], rand_zkvm::machine::Tier(22).max_cycles()).unwrap();
        assert!(exec.halted);
        assert_eq!(exec.outputs[0], (!flip) as u32);
        eprintln!("dilithium2 verify in the rVM: {} cycles (valid = {})", exec.cycles(), !flip);
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `cargo +1.98.1 test --release --test dilithium the_guest -- --nocapture`. Expected: compile error, no `compiled::dilithium_verify`.

- [ ] **Step 3: Implement** the guest. Copy `keccak256`'s `Cargo.toml`, add `dilithium-core`, and add `guest-sdk` with `features = ["dilithium"]`. `main`: read the input into fixed arrays, call `dilithium_core::verify(&mut SyscallKeccak, &pk, &msg[..n], &sig)`, `write_output(0, ok as u32)`, `halt()`. Build it:

```bash
cd rand-guest && cargo +1.98.1 run -- build ../guests-compiled/dilithium-verify --out ../guests-compiled/bin/dilithium-verify.bin --max-words 65535
```

Add the loader beside `compiled::evm()`:

```rust
pub fn dilithium_verify() -> Program {
    const BIN: &[u8] = include_bytes!("../../guests-compiled/bin/dilithium-verify.bin");
    Program::from_flat_image(BIN).expect("dilithium-verify.bin is a committed, known-good build")
}
```

- [ ] **Step 4: Run** the test. Expected: PASS. **Record** the printed cycle count and the keccak permutation count (count `SYS_KECCAK` events in `exec.events`).

- [ ] **Step 5: Gate and document.** Add a "`dilithium-verify` — phase 1 of private multisig" subsection to `research/docs/04-guests.md` with words, cycles, permutations and the implied tier at M = 1, 2, 3, 5. Commit:

```bash
git add guests-compiled/dilithium-verify guests-compiled/bin/dilithium-verify.bin* guest-sdk research/src/guests.rs research/tests/dilithium.rs research/docs/04-guests.md rand-guest/tests/build.rs
git commit -m "dilithium-verify guest: Dilithium2 in the rVM, <N> cycles per verification (private multisig phase 1)"
```

**Stop here and report the number** to the user before Task 4. If one verification is over 600 k cycles, raise phase 3 (the chip) before phase 2.

### Task 4: the host model, `research/src/msauth.rs`

**Files:**
- Create: `research/src/msauth.rs`; Modify: `research/src/lib.rs` (`pub mod msauth;`)
- Test: `research/tests/msauth.rs`

**Interfaces:**
- Produces:

```rust
pub const AUTH: u32 = 65; pub const MS_LEAF: u32 = 66; pub const MS_NODE: u32 = 67;
pub const MS_POLICY: u32 = 68; pub const NK_MS: u32 = 69;
pub const N_MAX: usize = 16; pub const DEPTH: usize = 4; pub const M_MAX: usize = 3;
pub const PK_WORDS: usize = 328; pub const SIG_WORDS: usize = 605; pub const SLOT_WORDS: usize = 967;
pub const MSAUTH_WORDS: usize = 17 + M_MAX * SLOT_WORDS;
pub const MSG_PREFIX: &[u8; 13] = b"rand-msauth-1";
pub fn leaf(pk: &[u8; 1312]) -> Word8;
pub fn signer_tree(pks: &[[u8; 1312]]) -> (Word8, Vec<[Word8; DEPTH]>); // root, path per signer
pub fn policy(threshold: u32, root: &Word8) -> Word8;
pub fn nk(msk: &Word8, policy: &Word8) -> Word8;
pub fn auth_commit(nk: &Word8, salt: &Word8) -> Word8;  // H(AUTH, nk ‖ salt)
pub fn signing_message(binding: &[u32; 8]) -> [u8; 45];
#[derive(Clone)]
pub struct Slot { pub index: u32, pub pk: [u8; 1312], pub sig: [u8; 2420], pub path: [Word8; DEPTH] }
pub fn msauth_inputs(msk: &Word8, salt: &Word8, threshold: u32, active: &[Slot]) -> Vec<u32>; // len MSAUTH_WORDS
```

- [ ] **Step 1: Write the failing tests** (`research/tests/msauth.rs`)

```rust
use rand_zkvm::msauth::*;
use rand_zkvm::notes::{domain, hash};

#[test]
fn tags_are_node_local_and_distinct() {
    let tags = [AUTH, MS_LEAF, MS_NODE, MS_POLICY, NK_MS];
    for t in tags { assert!(t >= 64 && t != 0xff && t != 64); }
    let mut s = tags.to_vec(); s.sort(); s.dedup(); assert_eq!(s.len(), 5);
    assert!(![domain::NK, domain::PK].iter().any(|d| tags.contains(d)));
}

#[test]
fn the_merkle_path_of_every_signer_reaches_the_root() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, paths) = signer_tree(&pks);
    for (i, pk) in pks.iter().enumerate() {
        let mut cur = leaf(pk);
        for (lvl, sib) in paths[i].iter().enumerate() {
            let mut m = [0u32; 16];
            if (i >> lvl) & 1 == 0 { m[..8].copy_from_slice(&cur); m[8..].copy_from_slice(sib); }
            else { m[..8].copy_from_slice(sib); m[8..].copy_from_slice(&cur); }
            cur = hash(MS_NODE, &m);
        }
        assert_eq!(cur, root);
    }
}

#[test]
fn the_policy_binds_threshold_keys_and_msk() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, _) = signer_tree(&pks);
    let msk = [9u32; 8];
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&msk, &policy(3, &root)));
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&[8u32; 8], &policy(2, &root)));
    let (root2, _) = signer_tree(&pks[..2]);
    assert_ne!(policy(2, &root), policy(2, &root2));
}

#[test]
fn the_witness_has_its_fixed_length_whatever_m() {
    let s = |i| Slot { index: i, pk: [1; 1312], sig: [2; 2420], path: [[0; 8]; DEPTH] };
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 1, &[s(0)]).len(), MSAUTH_WORDS);
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 2, &[s(0), s(2)]).len(), MSAUTH_WORDS);
}

#[test]
fn the_signing_message_is_prefix_then_binding() {
    let m = signing_message(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&m[..13], b"rand-msauth-1");
    assert_eq!(&m[13..17], &1u32.to_le_bytes());
}
```

- [ ] **Step 2: Run to verify it fails.** `cd research && cargo +1.98.1 test --release --test msauth`. Expected: unresolved import `rand_zkvm::msauth`.

- [ ] **Step 3: Implement** `msauth.rs`. `leaf` packs the 1 312 bytes into 328 LE words and returns `hash(MS_LEAF, &w)`. `signer_tree` pads to 16 leaves with `[0; 8]` and builds 4 levels with `hash(MS_NODE, left ‖ right)`. `policy` returns `hash(MS_POLICY, &[threshold, root…])`. `nk` returns `hash(NK_MS, msk ‖ policy)`. `auth_commit` returns `hash(AUTH, nk ‖ salt)`. In `msauth_inputs`, active slots fill the first `active.len()` slots in the given order, each `[1, index, pk words, sig words, path words]`, and the remaining slots are all zero words. `debug_assert!` that the length is `MSAUTH_WORDS`.

- [ ] **Step 4: Run.** Expected: 5 passed.

- [ ] **Step 5: Commit** `git add research/src/msauth.rs research/src/lib.rs research/tests/msauth.rs && git commit -m "msauth: host model — policy tree, nk derivation, fixed witness layout"`

### Task 5: the `msauth` guest and its cheating suite

**Files:**
- Create: `guests-compiled/msauth/{Cargo.toml,src/main.rs}`, `guests-compiled/bin/msauth.bin{,.sha256}`
- Modify: `research/src/guests.rs` (`compiled::msauth()`), `rand-guest/tests/build.rs`
- Test: `research/tests/msauth.rs`

**Interfaces:**
- Consumes: Task 2's `verify`, Task 3's `SyscallKeccak`, Task 4's layout and constants (the guest re-declares them; the test pins the two against each other through behaviour).
- Produces: a guest whose output slots 0..8 are `auth_commit(nk, salt)` on a good witness. On a bad one it panics (slot 7 = `0xdead_beef`). It reads the binding with `read_public(0..8)`.

- [ ] **Step 1: Write the failing tests** (append to `research/tests/msauth.rs`)

```rust
use crystals_dilithium::dilithium2::Keypair;
use rand_zkvm::{emulator::execute, guests::compiled, machine::Tier};

struct Fixture { kps: Vec<Keypair>, pks: Vec<[u8; 1312]>, root: Word8, paths: Vec<[Word8; DEPTH]> }
fn fixture(n: usize) -> Fixture {
    let kps: Vec<Keypair> = (0..n).map(|i| Keypair::generate(Some(&[i as u8 + 1; 32])).unwrap()).collect();
    let pks: Vec<[u8; 1312]> = kps.iter().map(|k| k.public.to_bytes().try_into().unwrap()).collect();
    let (root, paths) = signer_tree(&pks);
    Fixture { kps, pks, root, paths }
}
type Word8 = rand_zkvm::notes::Word8;
const BINDING: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
const MSK: Word8 = [5; 8]; const SALT: Word8 = [6; 8];

fn slot(f: &Fixture, i: usize, binding: &[u32; 8]) -> Slot {
    let sig = f.kps[i].sign(&signing_message(binding)); // `Signature = [u8; 2420]`
    Slot { index: i as u32, pk: f.pks[i], sig, path: f.paths[i] }
}
fn run(input: &[u32], binding: &[u32; 8]) -> [u32; 8] {
    let e = execute(&compiled::msauth(), input, binding, Tier(22).max_cycles()).unwrap();
    assert!(e.halted);
    e.outputs[..8].try_into().unwrap()
}
fn expected(f: &Fixture, t: u32) -> Word8 { auth_commit(&nk(&MSK, &policy(t, &f.root)), &SALT) }

#[test]
fn two_of_three_publishes_the_hosts_commit() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 2, &BINDING)]);
    assert_eq!(run(&input, &BINDING), expected(&f, 2));
}

#[test]
fn below_threshold_is_refused() {
    let f = fixture(3);
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn duplicate_index_is_refused() {
    let f = fixture(3);
    let s = slot(&f, 1, &BINDING);
    let input = msauth_inputs(&MSK, &SALT, 2, &[s.clone(), s]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn slots_from_two_policies_are_refused() {
    let (a, b) = (fixture(3), fixture(4));
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&a, 0, &BINDING), slot(&b, 3, &BINDING)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn signature_over_another_binding_is_refused() {
    let f = fixture(3);
    let other = [0u32; 8];
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &other)]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn one_bad_signature_among_enough_good_ones_is_refused() {
    let f = fixture(3);
    let mut bad = slot(&f, 2, &BINDING); bad.sig[200] ^= 1;
    let input = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING), bad]);
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn threshold_zero_and_over_m_max_are_refused() {
    let f = fixture(3);
    for t in [0, M_MAX as u32 + 1] {
        let input = msauth_inputs(&MSK, &SALT, t, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
        assert_eq!(run(&input, &BINDING)[7], 0xdead_beef, "threshold {t}");
    }
}

#[test]
fn index_out_of_range_and_non_boolean_active_are_refused() {
    let f = fixture(3);
    let mut s = slot(&f, 0, &BINDING); s.index = 16;
    assert_eq!(run(&msauth_inputs(&MSK, &SALT, 1, &[s]), &BINDING)[7], 0xdead_beef);
    let mut input = msauth_inputs(&MSK, &SALT, 1, &[slot(&f, 0, &BINDING)]);
    input[17] = 2; // slot 0's `active`
    assert_eq!(run(&input, &BINDING)[7], 0xdead_beef);
}

#[test]
fn a_wrong_msk_publishes_a_different_commit() {
    let f = fixture(3);
    let input = msauth_inputs(&[4; 8], &SALT, 2, &[slot(&f, 0, &BINDING), slot(&f, 1, &BINDING)]);
    assert_ne!(run(&input, &BINDING), expected(&f, 2));
}
```

(`Slot` derives `Clone` in Task 4.)

- [ ] **Step 2: Run to verify it fails.** `cargo +1.98.1 test --release --test msauth`. Expected: no `compiled::msauth`.

- [ ] **Step 3: Implement** `guests-compiled/msauth/src/main.rs`:

```rust
#![no_std]
#![no_main]
use dilithium_core::verify;
use guest_sdk::{halt, poseidon2, read_input, read_public, write_output, SyscallKeccak};

const M_MAX: usize = 3; const SLOT: usize = 967; const DEPTH: usize = 4;
const AUTH: u32 = 65; const MS_LEAF: u32 = 66; const MS_NODE: u32 = 67; const MS_POLICY: u32 = 68; const NK_MS: u32 = 69;

fn h(domain: u32, msg: &[u32], buf: &mut [u32; 330]) -> [u32; 8] {
    buf[0] = domain; buf[1..1 + msg.len()].copy_from_slice(msg);
    unsafe { poseidon2(buf.as_mut_ptr(), 1 + msg.len()) }
    let mut o = [0u32; 8]; o.copy_from_slice(&buf[..8]); o
}
fn words_to_bytes<const B: usize>(base: u32) -> [u8; B] {
    let mut out = [0u8; B];
    for i in 0..B { out[i] = (read_input(base + (i / 4) as u32) >> (8 * (i % 4))) as u8; }
    out
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut buf = [0u32; 330];
    let threshold = read_input(16);
    if threshold == 0 || threshold as usize > M_MAX { panic!() }
    let mut binding = [0u32; 8];
    for i in 0..8 { binding[i] = read_public(i as u32); }
    let mut msg = [0u8; 45];
    msg[..13].copy_from_slice(b"rand-msauth-1");
    for i in 0..32 { msg[13 + i] = (binding[i / 4] >> (8 * (i % 4))) as u8; }

    let mut root: Option<[u32; 8]> = None;
    let mut count = 0u32;
    let mut last_index: i32 = -1;
    for s in 0..M_MAX {
        let base = (17 + s * SLOT) as u32;
        let active = read_input(base);
        if active > 1 { panic!() }
        if active == 0 { continue; }
        let index = read_input(base + 1);
        if index >= 16 || index as i32 <= last_index { panic!() }
        last_index = index as i32;
        let mut pkw = [0u32; 328];
        for i in 0..328 { pkw[i] = read_input(base + 2 + i as u32); }
        let mut cur = h(MS_LEAF, &pkw, &mut buf);
        for lvl in 0..DEPTH {
            let mut sib = [0u32; 8];
            for i in 0..8 { sib[i] = read_input(base + 935 + (lvl * 8 + i) as u32); }
            let mut m = [0u32; 16];
            if (index >> lvl) & 1 == 0 { m[..8].copy_from_slice(&cur); m[8..].copy_from_slice(&sib); }
            else { m[..8].copy_from_slice(&sib); m[8..].copy_from_slice(&cur); }
            cur = h(MS_NODE, &m, &mut buf);
        }
        match root { None => root = Some(cur), Some(r) if r != cur => panic!(), _ => {} }
        let pk: [u8; 1312] = words_to_bytes(base + 2);
        let sig: [u8; 2420] = words_to_bytes(base + 330);
        if !verify(&mut SyscallKeccak, &pk, &msg, &sig) { panic!() }
        count += 1;
    }
    if count < threshold { panic!() }
    let root = root.unwrap_or_else(|| panic!());
    let mut pm = [0u32; 9]; pm[0] = threshold; pm[1..].copy_from_slice(&root);
    let pol = h(MS_POLICY, &pm, &mut buf);
    let mut nm = [0u32; 16];
    for i in 0..8 { nm[i] = read_input(i as u32); } nm[8..].copy_from_slice(&pol);
    let nk = h(NK_MS, &nm, &mut buf);
    let mut cm = [0u32; 16];
    cm[..8].copy_from_slice(&nk); for i in 0..8 { cm[8 + i] = read_input(8 + i as u32); }
    let c = h(AUTH, &cm, &mut buf);
    for i in 0..8 { write_output(i as u32, c[i]); }
    halt();
}
```

Build it with `rand-guest build ../guests-compiled/msauth --out ../guests-compiled/bin/msauth.bin --max-words 65535`, and add `compiled::msauth()` as in Task 3.

- [ ] **Step 4: Run** `cargo +1.98.1 test --release --test msauth`. Expected: 14 passed.

- [ ] **Step 5: Commit** `git add guests-compiled/msauth guests-compiled/bin/msauth.bin* research/src/guests.rs research/tests/msauth.rs rand-guest/tests/build.rs && git commit -m "msauth guest: M-of-N Dilithium2 over the binding, publishes H(AUTH, nk ‖ salt)"`

### Task 6: prove, pin the shape, measure the tier (phase-2 gate)

**Files:**
- Test: `research/tests/msauth.rs`
- Modify: `research/docs/04-guests.md`, `research/docs/05-roadmap.md` (new row "PM-1/PM-2 private multisig")

**Interfaces:**
- Consumes: Task 5's guest, `rand_zkvm::machine::Machine` prove/verify as `tests/e2e.rs` uses it, with the binding as the public segment (`verify_public`).
- Produces: the measured `(tier, heights, proof bytes)` at `M_MAX`. Phase 4 will pin these as `MSAUTH_TIER`.

- [ ] **Step 1: Write the tests**

```rust
#[test]
fn proof_shape_is_the_same_for_every_m() {
    // Cycles vary with M; the tier the executor pads to must be M_MAX's, so compute it once.
    let f = fixture(3);
    let worst: Vec<Slot> = (0..M_MAX.min(3)).map(|i| slot(&f, i, &BINDING)).collect();
    let one = msauth_inputs(&MSK, &SALT, 1, &worst[..1]);
    let all = msauth_inputs(&MSK, &SALT, worst.len() as u32, &worst);
    let c1 = execute(&compiled::msauth(), &one, &BINDING, Tier(22).max_cycles()).unwrap().cycles();
    let cm = execute(&compiled::msauth(), &all, &BINDING, Tier(22).max_cycles()).unwrap().cycles();
    let pinned = Tier::for_cycles(cm).expect("the worst case fits some tier"); // smallest tier holding it
    assert!(Tier::for_cycles(c1).unwrap() <= pinned);
    eprintln!("msauth: 1 active {c1} cycles, {} active {cm} cycles, pinned tier {:?}", worst.len(), pinned);
}

#[test]
#[ignore = "proves at the pinned tier; needs >= 64 GB above tier 18"]
fn msauth_proves_and_verifies_at_its_pinned_tier() {
    let f = fixture(3);
    let worst: Vec<Slot> = (0..M_MAX.min(3)).map(|i| slot(&f, i, &BINDING)).collect();
    let input = msauth_inputs(&MSK, &SALT, worst.len() as u32, &worst);
    let p = compiled::msauth();
    let cycles = execute(&p, &input, &BINDING, Tier(22).max_cycles()).unwrap().cycles();
    let tier = Tier::for_cycles(cycles).unwrap();
    let m = rand_zkvm::machine::Machine::new(rand_zkvm::machine::FriProfile::Production);
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove(&p, &input, &BINDING, Some(tier)).unwrap();
    eprintln!("msauth proof: tier {:?}, {} bytes, {:?}", proof.tier, proof.size(), t0.elapsed());
    m.verify_public(&p.digest(), &BINDING, &proof).unwrap();
    assert_eq!(exec.outputs[..8], expected(&f, worst.len() as u32));
}
```

`Tier::for_cycles` (`research/src/machine.rs:294`) picks by cycles only. Its Poseidon2-budget sibling below it (audit ZH1) must agree for the pinned tier; if it picks higher, pin that one.

- [ ] **Step 2: Run** `cargo +1.98.1 test --release --test msauth proof_shape -- --nocapture`, then the ignored proof on the largest machine available (`-- --ignored --nocapture`). Record cycles, tier, the peak resident memory (`/usr/bin/time -l`) and the proof bytes at Production FRI.

- [ ] **Step 3: Repeat** with `M_MAX` set to 2 and 5 in both `msauth.rs` and the guest. Rebuild, measure, and restore 3. Commit only the `M_MAX = 3` build.

- [ ] **Step 4: Document the gate.** In `research/docs/04-guests.md`, add a table with one row per `M_MAX` (cycles, keccak permutations, tier, proof bytes, peak memory). In the roadmap row, state the decision: tier ≤ 19 at `M_MAX = 3` means phase 3 is skipped and phase 4 is next; otherwise phase 3 (the mod-q/NTT chip) is next.

- [ ] **Step 5: Commit** `git add research/tests/msauth.rs research/docs && git commit -m "msauth: pinned shape and measured tier at M_MAX 2/3/5 (private multisig phase 2 gate)"`

---

## After this plan

Report the phase-2 gate numbers. Phase 3 (if needed) and phase 4 (fullnode: re-vendor, genesis `hc_auth_multisig`, shape-dispatched admission, prover witness, `rand multisig-private`, wallet scanning) each get their own plan, written against the measured numbers.
