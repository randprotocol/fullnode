# Private Multisig Phase 4 (Fullnode Integration) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a chain admit spends authorised by a hidden M-of-N Dilithium2 policy. The second auth guest (`msauth`, tier 18, MODQ chip) is pinned in genesis as `hc_auth_multisig`. Admission tells it apart from the single-key auth guest by the proof's pinned shape, with no wire, txid or binding change. Wallets drive it with `rand multisig-private`.

**Architecture:**
- Re-vendor circuits at the private-multisig Task 9 merge: the MODQ chip, the `msauth` host model and guest, and the rvm re-pinned on purpose.
- `ZkExecutor` gets a fourth pinned `Machine` and a `verify_auth` that dispatches on `hc`.
- `ConfidentialExecutor` gains two required header/warm methods (`auth_proof_shape`, `warm_auth_multisig`). They are forwarded by every wrapper and never cached.
- The ledger's cheap half reads the shape and picks `hc_auth` or `hc_auth_multisig`; the expensive half reuses `verify_auth`, so the verify cache keys it under kind 2 with `hc` in the key.
- Genesis adds one last-position field, bound last into the hash.
- The wallet gets a spend-key-less `Wallet` and a proposal file signed offline by each signer.
- The msauth proof is proved locally.

**Tech Stack:** Rust 1.98.1 (`cargo +1.98.1`), Plonky3 0.7 zkVM (vendored `randprotocol-zkvm`), `crystals-dilithium` 2.0.0 round-3 `dilithium2`, clap, tokio, bash/python3 (the cut script).

**Spec:** `docs/superpowers/specs/2026-10-11-private-multisig-phase4-design.md` (this repo). Parent specs (circuits, `~/rand-worktrees/circuits-private-multisig`): `docs/superpowers/specs/2026-10-11-private-multisig-design.md`, and `docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md` §6.

## Global Constraints

- **Ordering gate.** Do not start Task 1 until circuits `feat/private-multisig` has finished:
  - **Task 8**, which measures `MSAUTH_TIER` and `M_MAX` and writes `msauth::pinned_options()`'s floors and the msauth `hc` into `research/docs/04-guests.md`;
  - **Task 9**, the docs, the merge of rVM phase 4 and the single recursion re-pin, on a commit pushed to a remote, since `CUDA_REV` must be fetchable.

  Record that commit as `$CIRCUITS` in the Task 1 commit message.
- **The two values filled in from circuits Task 8:**
  - **`MSAUTH_TIER`.** The ruling makes it 18. If Task 8 recorded any other tier, stop: the MODQ ruling forbids 19 and 20.
  - **`M_MAX`.** It is 3 if the tier-18 gate passed at three signatures, otherwise 2.

  Everything else that depends on them is read from the vendored `randprotocol_zkvm::msauth` or printed by a command this plan gives, never typed from an estimate:
  - `MSAUTH_WORDS`;
  - the keccak/modq/memory floors in `pinned_options()`;
  - the msauth program `hc`;
  - the core mirrors `MSAUTH_KECCAK_LOG_HEIGHT` and `MSAUTH_MODQ_LOG_HEIGHT`.

  With `M_MAX` = 3 the expected values are keccak 14 and modq 16. If `M_MAX` = 2, the mirror tests print the vendored values to write in.
- **v0.8.0 decision (blocking).** After Task 1 this build cannot run chains 18–20, because every verifier key and the proof encoding change. Before merging Task 1 to `main`, the user chooses one of two options:
  - **(a)** v0.8.0 becomes chain-21-only and the chain-20 flag-day roll in `CHANGELOG.md` is withdrawn;
  - **(b)** v0.8.0 is tagged first from today's `main`, and this work ships as v0.9.0.

  Task 10's CHANGELOG step writes the chosen form. The default text below is (a), because the tag is being held for this.
- **Read-only:** circuits; `deploy/cut-chain21-genesis.sh` until Task 9 Step 1's message to randprotocol-d7 is answered; `feat/verify-cache` (fetch only).
- **Every `cargo` is `cargo +1.98.1`.** Real-proof tests take the workspace proving slot (`proving_slot()`) and are `#[ignore]`d when they take more than 5 minutes or 48 GB. Each one carries its run command.
- **Never `git rebase`.** Every commit ends with the session's `Co-Authored-By:` and `Claude-Session:` trailers.
- **No new consensus refusal path.** Every refusal is an existing `TxError`: `InvalidAuthProof`, `AuthMismatch`, `AuthGasLimit`, `AuthMissing` or `ProofTooLarge`.
- **R-gas.** The msauth prover never passes `gas_limit`; admission compares `pv::GAS` only with the header ceiling `gas_max_with_modq(pinned header)`.
- **R-hide.** Admission pins tier, program, input, keccak, sha256 (0), modq, public and **memory** heights exactly, before any key is built.

## Review Focus

1. `ZkExecutor::verify_auth` dispatches on `hc`, and each path re-pins its own whole shape. A single-key proof under the msauth `hc`, and the reverse, are refused before a key is built (Task 2).
2. Both new trait methods have **no default**. `AggExecutor`, `CachingExecutor` (if merged) and every test executor forward them (Task 4).
3. A modq-bearing call, bundle, single-key auth or perp proof is refused before any key build (Task 2).
4. `honest_fri_arities`/`non_canonical` see the modq instance. Otherwise the msauth proof escapes the FRI-arity rule (Task 2).
5. The genesis hash is unchanged for every committed file, and the new tag is last (Task 3).
6. `sign` never signs a binding it did not recompute from the transaction, and never signs outputs it could not open as sender (Task 6).
7. The rvm re-sync is kept, not reverted, and its pins move with circuits Task 9's (Task 1).

---

### Task 1: Re-vendor circuits at the Task 9 merge (MODQ chip, `msauth`, rvm re-pin, constraint set 9)

**Files:**
- Modify: `deploy/sync-zkvm.sh`
- Modify: `crates/randprotocol-zkvm/Cargo.toml`, `crates/randprotocol-zkvm/src/lib.rs`, `crates/randprotocol-zkvm/src/guests.rs`
- Regenerated by the script: `crates/randprotocol-zkvm/src/**` (vendored), `crates/randprotocol-zkvm/tests/**` (vendored), `crates/randprotocol-zkvm/guests-compiled/{SHA256SUMS,PROVENANCE.md,bin/msauth.bin,bin/msauth.bin.sha256}`, `crates/randprotocol-rvm/**`, `vendor/circuits/{SHA256SUMS,PROVENANCE.md}`
- Modify: `crates/randprotocol-zkvm/tests/guest_provenance.rs`
- Modify: `crates/randprotocol-core/src/gas.rs` (`MODQ_GAS`, `gas_max_with_modq`)
- Modify: `crates/randprotocol-zkvm/src/executor.rs` (the mirror test only)
- Modify: `crates/randprotocol-node/src/node.rs` (`BUILD_CONSTRAINT_SET`, `CHAINS_THIS_BUILD_CANNOT_RUN`, `CONSTRAINT_SET_8_REASON`)
- Modify: `crates/randprotocol-node/fixtures/recursion/Test-{0,1,2}.proof`, `scripts/recursion-fixtures.sh` (pinned digests), `crates/randprotocol-node/src/agg_executor.rs` (pinned vectors)
- Modify: `.github/workflows/ci.yml` (`CIRCUITS_PIN`, guest rebuild covers `msauth`, `--features cheating --test cheating`)

**Interfaces:**
- Consumes: circuits `$CIRCUITS` (`research/`, `recursion/`, `guests-compiled/bin/msauth.bin*`).
- Produces:
  ```rust
  // randprotocol_zkvm (vendored)
  pub mod modq; pub mod msauth;                       // msauth::{AUTH, MS_LEAF, MS_NODE, MS_POLICY, NK_MS, N_MAX, DEPTH, M_MAX, MSAUTH_WORDS,
                                                       //   leaf, signer_tree, policy, nk, auth_commit, signing_message, Slot, msauth_inputs,
                                                       //   MSAUTH_TIER: Tier, pinned_options() -> ProveOptions, poseidon2_permutations}
  pub fn guests::compiled::msauth() -> isa::Program;  // hand-maintained, include_bytes!("../guests-compiled/bin/msauth.bin")
  // machine::Proof gains `pub modq_log_height: u8`; machine::{chips_with_modq, check_declared_heights_with_modq,
  //   Machine::verifier_key_with_modq, Machine::log_ext_degrees_with_modq, ProveOptions::min_{keccak,modq,mem}_log_height}
  // randprotocol_core::gas
  pub const MODQ_GAS: u64 = 168;
  pub fn gas_max_with_modq(tier: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8) -> u64;
  // randprotocol_node::node
  pub const BUILD_CONSTRAINT_SET: u8 = 9;
  pub const CHAINS_THIS_BUILD_CANNOT_RUN: [(u64, &str, &str); 7];
  ```

- [ ] **Step 1: Write the failing tests.**

Append to `crates/randprotocol-zkvm/tests/guest_provenance.rs`, and add `"msauth"` to the list in `each_circuits_pin_names_the_manifest_digest` (`for guest in ["fib", "keccak256", "evm", "sbpf", "msauth"]`):

```rust
/// Private multisig phase 4: the re-vendor brought the MODQ chip (syscall 8, `MODQ_GAS`), the
/// `msauth` host model and the compiled `msauth` guest, and the guest is in the manifest.
#[test]
fn the_msauth_guest_and_the_modq_chip_are_vendored() {
    let manifest = manifest();
    for path in ["bin/msauth.bin", "bin/msauth.bin.sha256"] {
        assert!(manifest.iter().any(|(_, p)| p == path), "{path} is not in SHA256SUMS");
    }
    assert_eq!(randprotocol_zkvm::isa::SYS_MODQ, 8);
    assert_eq!(randprotocol_zkvm::gas::MODQ_GAS, 168);
    assert_eq!(randprotocol_zkvm::msauth::MSAUTH_WORDS, 17 + randprotocol_zkvm::msauth::M_MAX * 967);
    assert!(!randprotocol_zkvm::guests::compiled::msauth().words.is_empty());
    // Its tags are node-local and sit beside auth.rs's: AUTH is the same 65.
    assert_eq!(randprotocol_zkvm::msauth::AUTH, randprotocol_zkvm::auth::AUTH_DOMAIN);
}

/// No guest program moved: every digest pin above is unchanged by the MODQ re-vendor (only
/// verifier keys moved), and the msauth guest is none of them.
#[test]
fn the_modq_re_vendor_moved_no_guest_program() {
    let msauth = randprotocol_zkvm::guests::compiled::msauth().digest();
    assert_eq!(word8_to_hex(&ZkExecutor::hc_auth()), "1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1");
    assert_eq!(word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()), "60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce");
    assert!(!ZkExecutor::known_hc_bundles().contains(&msauth) && msauth != ZkExecutor::hc_auth());
}
```

Append to `crates/randprotocol-core/src/gas.rs`'s `mod tests`:

```rust
/// MODQ re-vendor: `gas_max_with_modq` is `gas_max` plus `MODQ_GAS − 1` per declared 1 024-row
/// modq block; at 0 it is `gas_max` exactly, at every tier.
#[test]
fn gas_max_with_modq_adds_167_per_modq_block() {
    assert_eq!(MODQ_GAS, 168);
    for t in MIN_TIER..=MAX_TIER {
        assert_eq!(gas_max_with_modq(t, 0, 0, 0), gas_max(t, 0, 0));
        assert_eq!(gas_max_with_modq(t, 14, 0, 0), gas_max(t, 14, 0));
    }
    assert_eq!(gas_max_with_modq(18, 14, 0, 16) - gas_max(18, 14, 0), (1u64 << 16) / 1024 * 167);
    assert_eq!(gas_max_with_modq(18, 14, 0, 10) - gas_max(18, 14, 0), 167);
}
```

In `crates/randprotocol-zkvm/src/executor.rs`, extend `the_cores_gas_max_mirror_matches_the_vendored_one`'s innermost loop body with:

```rust
for m in [0u8, 10, 12, 14, 16] {
    assert_eq!(
        randprotocol_core::gas::gas_max_with_modq(t, k, sh, m),
        crate::gas::gas_max_with_modq(Tier(t as usize), k, sh, m),
        "tier {t} keccak {k} sha256 {sh} modq {m}"
    );
}
```

Append to `crates/randprotocol-node/src/node.rs`'s `mod tests`:

```rust
/// Constraint set 9 (the MODQ chip): every verifier key and the proof encoding moved, so this
/// build verifies none of chain 18's, 19's or 20's proofs and must refuse their genesis before
/// touching a datadir.
#[test]
fn this_build_refuses_chains_18_to_20() {
    assert_eq!(BUILD_CONSTRAINT_SET, 9);
    for (chain, hash) in [
        (18, "a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76"),
        (19, "a3defc937d561d4beb1df9a08c9cb87a3dc32dadbfc2d1814ab6f627b0a2228a"),
        (20, "6210cf071a390d7ac61d8cbea5dd9d139d1a493a862b54a45a498f36af2d5135"),
    ] {
        let row = CHAINS_THIS_BUILD_CANNOT_RUN.iter().find(|(c, _, _)| *c == chain).unwrap_or_else(|| panic!("chain {chain} not listed"));
        assert_eq!(row.1, hash, "chain {chain}");
        assert!(row.2.contains("constraint set 8") && row.2.contains("v0.7"), "chain {chain}: {}", row.2);
    }
}
```

- [ ] **Step 2: Run them to see them fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-zkvm --test guest_provenance msauth_guest_and_the_modq 2>&1 | tail -5
cargo +1.98.1 test --release -p randprotocol-core --lib gas_max_with_modq 2>&1 | tail -5
cargo +1.98.1 test --release -p randprotocol-node --lib this_build_refuses_chains_18_to_20 2>&1 | tail -5
```

Expected: compile errors: no `msauth`, no `SYS_MODQ`, no `gas_max_with_modq`; `BUILD_CONSTRAINT_SET` is 8.

- [ ] **Step 3: Implement.**
  1. `deploy/sync-zkvm.sh`:
     - Add `--exclude dilithium_host.rs` to the first (`src`) rsync. Add `--exclude dilithium.rs --exclude modq_reference.rs` to the second (`tests`) rsync.
     - Change the guest loop to `for GUEST in fib keccak256 evm sbpf msauth; do`.
     - After the `sed` that renames `rand_zkvm`, add the hooks guard:
       ```bash
       if grep -lE 'forge_block|build_traces_forged|ModqAirWithout|call_unchecked|execute_unchecked_modq|memory_trace_forged|range_counts_without' "$DST"/tests/*.rs | grep -v '/cheating.rs$' | grep -q .; then
         echo "sync-zkvm.sh: a vendored test other than tests/cheating.rs calls a cheating hook; give it its own [[test]] required-features = [\"cheating\"] entry in $DST/Cargo.toml first" >&2; exit 1
       fi
       ```
     - After the `log_ext_degrees_pub` patch, add the anchor report:
       ```bash
       grep -q 'pub fn verifier_key(&self, tier: Tier, program_log_height: u8, input_log_height: u8, keccak_log_height: u8, sha256_log_height: u8, public_log_height: u8)' "$DST/src/machine.rs" \
         && grep -q 'pub const HC_DOMAIN: u32 = 8;' "$DST/src/hash.rs" \
         && echo "anchors: verifier_key 6-arg ok; notes::domain HC/IN/PUB ok" \
         || { echo "sync-zkvm.sh: an anchor moved (verifier_key 6-arg or HC_DOMAIN)" >&2; exit 1; }
       ```
     - After `cp "$RVM_SRC/Cargo.toml" "$RVM_DST/Cargo.toml"`, add:
       ```bash
       if grep -q 'features = \["cheating"\]' "$RVM_DST/Cargo.toml"; then
         echo "sync-zkvm.sh: recursion's Cargo.toml enables rand_zkvm's cheating feature; the node must never link the hooks — strip it upstream or here" >&2; exit 1
       fi
       ```
     - Change the last echo's `(pin 4a244b6, tree aggregation)` to `(pin $RVM_REV)`.
  2. `crates/randprotocol-zkvm/Cargo.toml`:
     - Under `[dev-dependencies]`, add `crystals-dilithium = { workspace = true }`.
     - Under `[features]`, add `cheating = []` with the comment `# the vendored cheating suite's hooks; only tests/cheating.rs uses them (required-features below). Never a node feature.`.
     - Append:
       ```toml
       [[test]]
       name = "cheating"
       path = "tests/cheating.rs"
       required-features = ["cheating"]
       ```
  3. Check out circuits at `$CIRCUITS`, clean, in `~/rand-worktrees/circuits-private-multisig`, then run the sync **without** reverting the rvm afterwards. The rvm moves with the inner cpu width; spec §5 item 7.
     ```bash
     RVM_SRC=~/rand-worktrees/circuits-private-multisig/recursion deploy/sync-zkvm.sh ~/rand-worktrees/circuits-private-multisig/research
     ```
  4. In `crates/randprotocol-zkvm/src/lib.rs`, add `pub mod modq;` and `pub mod msauth;` after `pub mod sha256;`.
  5. In `crates/randprotocol-zkvm/src/guests.rs`'s `compiled` module, add:
     ```rust
     /// The private-multisig auth guest (circuits `guests-compiled/msauth`, built by `rand-guest`),
     /// an image container vendored as `guests-compiled/bin/msauth.bin`. M-of-N Dilithium2 over the
     /// transaction binding; publishes `c = H(AUTH, nk ‖ salt)` or the panic sentinel.
     pub fn msauth() -> Program {
         const BIN: &[u8] = include_bytes!("../guests-compiled/bin/msauth.bin");
         Program::from_flat_image(BIN).expect("msauth.bin is a committed, known-good build")
     }
     ```
     Extend the module doc's file list to `{fib,keccak256,evm,sbpf,msauth}.bin`.
  6. In `crates/randprotocol-core/src/gas.rs`, beside `SHA256_GAS`:
     ```rust
     /// What one `MODQ` ecall row costs (constraint set 9; circuits `gas::MODQ_GAS`): 1 024 × (59 + 16)
     /// committed cells at ≈ 460 cells per gas.
     pub const MODQ_GAS: u64 = 168;
     /// `gas_max` with the modq table's declared height: `MODQ_GAS − 1` per 1 024-row block.
     pub fn gas_max_with_modq(tier: u8, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8) -> u64 {
         let blocks = if modq_log_height == 0 { 0 } else { (1u64 << modq_log_height.min(40)) / 1024 };
         gas_max(tier, keccak_log_height, sha256_log_height).saturating_add(blocks.saturating_mul(MODQ_GAS - 1))
     }
     ```
  7. In `crates/randprotocol-node/src/node.rs`:
     - Set `pub const BUILD_CONSTRAINT_SET: u8 = 9;`.
     - Grow `CHAINS_THIS_BUILD_CANNOT_RUN` to `[(u64, &str, &str); 7]` with the three rows of the test.
     - Add:
       ```rust
       const CONSTRAINT_SET_8_REASON: &str = "its proofs were made under constraint set 8; this build is constraint \
            set 9 (the MODQ chip, v0.8.0 and later) and verifies none of them, so its startup replay would refuse the \
            chain's own history and a `verify --repair` would truncate it. Use the v0.7.x release for chains 18-20";
       ```
     - Update `refuse_chains_this_build_cannot_run`'s doc comment to name chains 14–20.
  8. Re-prove the recursion fixtures, which no longer decode. Write the new pinned digests that `--check` prints into `scripts/recursion-fixtures.sh` and `agg_executor::tests::the_admission_recompute_reproduces_the_pinned_vectors_byte_for_byte`.
     ```bash
     scripts/recursion-fixtures.sh ~/rand-worktrees/circuits-private-multisig
     scripts/recursion-fixtures.sh --check
     ```
  9. In `.github/workflows/ci.yml`:
     - Set `CIRCUITS_PIN: $CIRCUITS`.
     - Add `msauth` to the guest-rebuild gate's guest list.
     - Add to the zkvm test job: `cargo +1.98.1 test --release -p randprotocol-zkvm --features cheating --test cheating`.
     - Edit the PROVENANCE.md prose to name the msauth row and the five guests.

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-zkvm --test guest_provenance
cargo +1.98.1 test --release -p randprotocol-zkvm --features cheating --test cheating
cargo +1.98.1 test --release -p randprotocol-core --lib gas
cargo +1.98.1 test --release -p randprotocol-zkvm --lib the_cores_gas_max_mirror_matches_the_vendored_one
cargo +1.98.1 test --release --workspace 2>&1 | tail -30
cargo +1.98.1 tree -p randprotocol-node -e normal -f '{p} {f}' | grep 'randprotocol-zkvm' | grep -c cheating   # expect 0
```

Expected: all pass, and the last command prints `0`. Any test that pinned a verifier-key digest, `inner_vk_digest` or an aggregate program digest is re-pinned to the value its failure prints, and only those. A re-pin elsewhere is a stop-and-report.

- [ ] **Step 5: Commit.**

```bash
git add deploy/sync-zkvm.sh crates/randprotocol-zkvm crates/randprotocol-rvm crates/randprotocol-core/src/gas.rs \
        crates/randprotocol-node/src/node.rs crates/randprotocol-node/src/agg_executor.rs crates/randprotocol-node/fixtures \
        scripts/recursion-fixtures.sh vendor/circuits .github/workflows/ci.yml Cargo.lock
git commit -m "zkvm, rvm: re-vendor circuits $CIRCUITS — the MODQ chip (constraint set 9: every key and the proof encoding move), the msauth host model and guest, the rvm re-pinned with it; the node refuses chains 18-20"
```

---

### Task 2: Executor: the msauth path, `NO_MODQ` everywhere else, provenance pins

**Files:**
- Modify: `crates/randprotocol-zkvm/src/executor.rs`
- Create: `crates/randprotocol-zkvm/tests/auth_msauth.rs` (node-local; the sync's `'auth*.rs'` exclude keeps it)
- Modify: `crates/randprotocol-zkvm/tests/guest_provenance.rs`, `crates/randprotocol-zkvm/tests/auth_spike.rs`
- Modify: `crates/randprotocol-core/src/confidential.rs` (only the `AuthShape` enum, which Task 4 uses)

**Interfaces:**
- Consumes: Task 1's vendored `msauth`, `machine::*_with_modq`, `ProveOptions`.
- Produces:
  ```rust
  // randprotocol_core::confidential
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum AuthShape { SingleKey, Multisig }
  // randprotocol_zkvm::executor
  const NO_MODQ: u8 = 0;
  pub const MSAUTH_TIER: usize = crate::msauth::MSAUTH_TIER.0;
  pub const MSAUTH_REFUSAL: u32 = 0xdead_beef;
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub struct MsauthShape { pub tier: usize, pub program_log_height: u8, pub input_log_height: u8, pub keccak_log_height: u8,
                           pub sha256_log_height: u8, pub modq_log_height: u8, pub public_log_height: u8, pub mem_log_height: u8 }
  impl ZkExecutor {
      pub fn msauth_program() -> &'static Program;
      pub fn hc_auth_multisig() -> Word8;
      pub fn msauth_heights() -> MsauthShape;
      pub fn auth_shape_of(proof: &[u8]) -> Result<AuthShape, ConfidentialError>;
      pub fn msauth_proof_commit(&self, proof: &[u8]) -> Result<Word8, ConfidentialError>;
      pub fn verify_msauth_proof(&self, hc: &Word8, proof: &[u8], binding: &[u32; TX_BINDING_WORDS]) -> Result<Word8, ConfidentialError>;
      pub fn cached_msauth_keys(&self) -> usize;
  }
  pub fn hash_bearing_mem_log_height_ceiling_with_modq(tier: Tier, keccak_log_height: u8, sha256_log_height: u8, modq_log_height: u8) -> u8;
  pub fn run_msauth(inputs: &[u32], binding: &[u32; TX_BINDING_WORDS]) -> Result<Word8, String>;
  pub fn prove_msauth(profile: FriProfile, inputs: &[u32], binding: &[u32; TX_BINDING_WORDS]) -> Result<(Vec<u8>, Word8, u8), String>;
  ```

- [ ] **Step 1: Write the failing tests.** Create `crates/randprotocol-zkvm/tests/auth_msauth.rs`:

```rust
//! Private multisig phase 4: the executor's msauth path. Node-local (the sync excludes `auth*.rs`).
//! The cheap tests run the guest in the emulator and check headers; the real-proof tests are
//! `#[ignore]`d (a tier-18 proof: minutes and tens of GB).

use crystals_dilithium::dilithium2::Keypair;
use randprotocol_core::confidential::{AuthShape, ConfidentialError, ConfidentialExecutor};
use randprotocol_zkvm::executor::{decode_canonical, non_canonical, prove_auth, prove_msauth, run_msauth, ZkExecutor, AUTH_TIER, MSAUTH_TIER};
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::msauth::{auth_commit, msauth_inputs, nk, pinned_options, policy, signer_tree, signing_message, Slot, M_MAX, MSAUTH_WORDS};
use randprotocol_zkvm::notes::{SpendKey, Word8};
use randprotocol_zkvm::tables::cpu::pv;

const BINDING: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
const MSK: Word8 = [5; 8];
const SALT: Word8 = [6; 8];

struct Fixture { kps: Vec<Keypair>, pks: Vec<[u8; 1312]>, root: Word8, paths: Vec<[Word8; 4]> }
fn fixture(n: usize) -> Fixture {
    let kps: Vec<Keypair> = (0..n).map(|i| Keypair::generate(Some(&[i as u8 + 1; 32])).unwrap()).collect();
    let pks: Vec<[u8; 1312]> = kps.iter().map(|k| k.public.to_bytes().try_into().unwrap()).collect();
    let (root, paths) = signer_tree(&pks);
    Fixture { kps, pks, root, paths }
}
fn slot(f: &Fixture, i: usize) -> Slot {
    Slot { index: i as u32, pk: f.pks[i], sig: f.kps[i].sign(&signing_message(&BINDING)), path: f.paths[i] }
}
fn expected(f: &Fixture, t: u32) -> Word8 { auth_commit(&nk(&MSK, &policy(t, &f.root)), &SALT) }

#[test]
fn run_msauth_returns_c_for_two_of_three_and_refuses_one() {
    let f = fixture(3);
    let two = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0), slot(&f, 2)]);
    assert_eq!(two.len(), MSAUTH_WORDS);
    assert_eq!(run_msauth(&two, &BINDING), Ok(expected(&f, 2)));
    let one = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0)]);
    let e = run_msauth(&one, &BINDING).unwrap_err();
    assert!(e.contains("refused"), "{e}");
    assert!(run_msauth(&two, &[0; 8]).is_err(), "signatures over another binding");
}

#[test]
fn the_msauth_shape_is_the_vendored_pinned_one() {
    let s = ZkExecutor::msauth_heights();
    let o = pinned_options();
    assert_eq!(s.tier, MSAUTH_TIER);
    assert_eq!((s.keccak_log_height, s.modq_log_height, s.mem_log_height), (o.min_keccak_log_height, o.min_modq_log_height, o.min_mem_log_height));
    assert_eq!(s.sha256_log_height, 0);
    assert!(o.gas_limit.is_none(), "R-gas: the prover keeps the header ceiling");
    assert_eq!(s.public_log_height, ZkExecutor::auth_heights().2, "both bind the 8-word transaction binding");
    assert_eq!(MSAUTH_TIER as u8, randprotocol_core::types::MSAUTH_PROOF_TIER);
    assert_eq!(s.keccak_log_height, randprotocol_core::types::MSAUTH_KECCAK_LOG_HEIGHT, "core's mirror");
    assert_eq!(s.modq_log_height, randprotocol_core::types::MSAUTH_MODQ_LOG_HEIGHT, "core's mirror");
}

#[test]
fn junk_and_a_single_key_proof_take_their_shape_or_none() {
    let ex = ZkExecutor::new(FriProfile::Test);
    assert_eq!(ZkExecutor::auth_shape_of(b"junk"), Err(ConfidentialError::MalformedProof));
    let (single, c, tier) = prove_auth(FriProfile::Test, &SpendKey([7; 8]), &SALT, &BINDING, Backend::Cpu).unwrap();
    assert_eq!(tier as usize, AUTH_TIER);
    assert_eq!(ZkExecutor::auth_shape_of(&single), Ok(AuthShape::SingleKey));
    assert_eq!(ex.auth_proof_digest(&single), Ok(c), "the cheap read accepts either shape");
    // Dispatch on hc: the msauth hc sends a single-key proof to the msauth path, whose shape pin refuses it before a key is built.
    match ex.verify_auth(&ZkExecutor::hc_auth_multisig(), &single, &BINDING) {
        Err(ConfidentialError::InvalidProof(why)) => assert!(why.contains("not the multisig auth guest's shape"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(ex.cached_msauth_keys(), 0, "refused before any msauth key");
    assert_eq!(ex.verify_auth(&ZkExecutor::hc_auth(), &single, &BINDING), Ok(c));
}

/// One real msauth proof at the Test profile, and every header rule checked on it.
/// Run: `cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture a_real_msauth_proof`
#[test]
#[ignore = "a tier-18 proof: minutes, >= 48 GB"]
fn a_real_msauth_proof_takes_the_pinned_shape_and_every_other_header_is_refused() {
    let f = fixture(3);
    let ex = ZkExecutor::new(FriProfile::Test);
    let hc = ZkExecutor::hc_auth_multisig();
    let mut proofs = Vec::new();
    for active in [vec![0usize], vec![0, 2], (0..M_MAX).collect::<Vec<_>>()] {
        let t = active.len() as u32;
        let inputs = msauth_inputs(&MSK, &SALT, t, &active.iter().map(|&i| slot(&f, i)).collect::<Vec<_>>());
        let (bytes, c, tier) = prove_msauth(FriProfile::Test, &inputs, &BINDING).unwrap();
        assert_eq!((tier as usize, c), (MSAUTH_TIER, expected(&f, t)));
        proofs.push(bytes);
    }
    let s = ZkExecutor::msauth_heights();
    for bytes in &proofs {
        let p = decode_canonical(bytes).unwrap();
        // R-hide: every M declares the same header.
        assert_eq!(
            (p.tier.0, p.program_log_height, p.input_log_height, p.keccak_log_height, p.sha256_log_height, p.modq_log_height, p.public_log_height, p.mem_log_height),
            (s.tier, s.program_log_height, s.input_log_height, s.keccak_log_height, s.sha256_log_height, s.modq_log_height, s.public_log_height, s.mem_log_height)
        );
        // R-gas: the header's ceiling, never the run's gas.
        assert_eq!(p.public_values[pv::GAS], randprotocol_core::gas::msauth_gas_limit_pin());
        assert_eq!(non_canonical(&p), None, "an honest msauth proof is canonical");
        assert_eq!(ZkExecutor::auth_shape_of(bytes), Ok(AuthShape::Multisig));
        assert_eq!(ex.auth_gas_limit(bytes), Ok(Some(randprotocol_core::gas::msauth_gas_limit_pin())));
    }
    let c = ex.verify_auth(&hc, &proofs[1], &BINDING).unwrap();
    assert_eq!(c, expected(&f, 2));
    assert_eq!(ex.cached_msauth_keys(), 1);
    assert!(ex.verify_auth(&hc, &proofs[1], &[0; 8]).is_err(), "another binding");
    // The single-key path refuses the multisig shape before building a key.
    assert!(matches!(ex.verify_auth(&ZkExecutor::hc_auth(), &proofs[1], &BINDING), Err(ConfidentialError::InvalidProof(_))));
    // Every header word moved by one is refused by shape, before a key is built.
    let honest = decode_canonical(&proofs[1]).unwrap();
    let fresh = ZkExecutor::new(FriProfile::Test);
    for (what, edit) in [
        ("tier", Box::new(|p: &mut randprotocol_zkvm::machine::Proof| p.tier.0 -= 2) as Box<dyn Fn(&mut _)>),
        ("keccak", Box::new(|p: &mut randprotocol_zkvm::machine::Proof| p.keccak_log_height += 1)),
        ("modq", Box::new(|p: &mut randprotocol_zkvm::machine::Proof| p.modq_log_height += 1)),
        ("mem", Box::new(|p: &mut randprotocol_zkvm::machine::Proof| p.mem_log_height += 1)),
        ("sha256", Box::new(|p: &mut randprotocol_zkvm::machine::Proof| p.sha256_log_height = 7)),
    ] {
        let mut p = honest.clone();
        edit(&mut p);
        let bytes = p.to_bytes();
        assert!(ZkExecutor::auth_shape_of(&bytes).is_err(), "{what}");
        assert!(fresh.verify_auth(&hc, &bytes, &BINDING).is_err(), "{what}");
    }
    assert_eq!(fresh.cached_msauth_keys(), 0, "no forged header built a key");
    // FRI arity is pinned for modq-bearing proofs too (VERIFIER-2).
    let mut forged = honest.clone();
    let arities = &mut forged.batch.opening_proof.1.commit_phase_log_arities;   // the field `honest_fri_arities` pins
    if let Some(a) = arities.first_mut() { *a = 1; }
    assert!(non_canonical(&forged).is_some(), "a finer FRI schedule on an msauth proof is non-canonical");
}

/// The cost a validator pays to warm the msauth key and verify one proof, at Production.
/// Run: `/usr/bin/time -l cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture measure_the_msauth`
#[test]
#[ignore = "Production tier-18 key build and one Production msauth proof: record in docs/node-hardware.md"]
fn measure_the_msauth_verifier_key_build_and_verify_at_the_production_profile() {
    let f = fixture(3);
    let inputs = msauth_inputs(&MSK, &SALT, 2, &[slot(&f, 0), slot(&f, 2)]);
    let (bytes, _, _) = prove_msauth(FriProfile::Production, &inputs, &BINDING).unwrap();
    let ex = ZkExecutor::new(FriProfile::Production);
    let t0 = std::time::Instant::now();
    ex.warm_auth_multisig();
    let warm = t0.elapsed();
    let t1 = std::time::Instant::now();
    ex.verify_auth(&ZkExecutor::hc_auth_multisig(), &bytes, &BINDING).unwrap();
    eprintln!("MSAUTH-PROD: proof {} B, key build {warm:?}, warm verify {:?}", bytes.len(), t1.elapsed());
}
```

If the vendored `Proof`'s FRI-arity field has a different path, name it as `honest_fri_arities` reads it. That function is the reference for the field.

Append to `crates/randprotocol-zkvm/tests/guest_provenance.rs`:

```rust
/// The multisig auth guest (`guests::compiled::msauth()`, private multisig phase 4) is the value a
/// genesis carries as `hc_auth_multisig`. Its digest is circuits Task 8's (`research/docs/04-guests.md`,
/// the msauth table), pinned so a re-vendor that moves it fails here, not at a chain's first block.
const MSAUTH_HC: &str = "";

#[test]
fn the_multisig_auth_guest_is_pinned() {
    assert_eq!(MSAUTH_HC.len(), 64, "write circuits Task 8's msauth hc into MSAUTH_HC (Task 2 Step 3)");
    assert_eq!(word8_to_hex(&ZkExecutor::hc_auth_multisig()), MSAUTH_HC);
    assert_eq!(randprotocol_zkvm::executor::MSAUTH_TIER, 18, "the MODQ ruling: tier 18 only");
    assert_ne!(ZkExecutor::hc_auth_multisig(), ZkExecutor::hc_auth());
    assert!(!ZkExecutor::known_hc_bundles().contains(&ZkExecutor::hc_auth_multisig()));
}
```

Append to `crates/randprotocol-zkvm/tests/auth_spike.rs`:

```rust
/// msauth's tags (66–69) are node-local like AUTH (65) and the hidden bundle's (64), and collide
/// with no tag this crate has.
#[test]
fn the_msauth_domain_tags_are_node_local_and_distinct() {
    use randprotocol_zkvm::msauth::{MS_LEAF, MS_NODE, MS_POLICY, NK_MS};
    let ours = [HIDDEN_BUNDLE_DOMAIN, AUTH_DOMAIN, MS_LEAF, MS_NODE, MS_POLICY, NK_MS];
    assert_eq!(ours[2..], [66, 67, 68, 69]);
    for (i, a) in ours.iter().enumerate() {
        assert!(!(1..=0x3f).contains(a) && *a != notes::domain::TEST, "{a}");
        assert!(ours[i + 1..].iter().all(|b| b != a), "{a} repeats");
    }
}
```

In `executor.rs`'s `mod tests`, add:

```rust
/// Constraint set 9: a modq table is the msauth guest's alone. A bundle, a single-key auth proof
/// and a call declaring one are refused by header, before any key is built.
#[test]
fn a_modq_table_is_refused_on_every_proof_but_msauth() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let (auth, _, _) = prove_auth(FriProfile::Test, &crate::notes::SpendKey([7; 8]), &[6; 8], &[0; 8], Backend::Cpu).unwrap();
    let mut p = decode_canonical(&auth).unwrap();
    p.modq_log_height = 10;
    let (plh, ilh, pubh) = ZkExecutor::auth_heights();
    match ex.check_decoded(p, plh, ilh, pubh, true, AUTH_TIER) {
        Err(ConfidentialError::InvalidProof(why)) => assert!(why.contains("modq"), "{why}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert_eq!(ex.cached_keys() + ex.cached_bundle_keys() + ex.cached_msauth_keys(), 0);
}
```

For the `verify_call` half, extend the existing `verify_call` header-cap test that sets `keccak_log_height = 13` (`MAX_CALL_KECCAK_LOG_HEIGHT` + 1). Add a sibling case with `modq_log_height = 10` that expects `InvalidProof` containing `"declares no modq table"`, and `ex.cached_keys()` unchanged.

Add to `crates/randprotocol-core/src/confidential.rs`, beside `ConfidentialError`:

```rust
/// Which auth guest an auth proof's pinned header names (private multisig phase 4): the
/// single-key auth guest (genesis `hc_auth`) or the multisig one (`hc_auth_multisig`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthShape { SingleKey, Multisig }
```

And to `crates/randprotocol-core/src/types/mod.rs`, after `AUTH_PROOF_TIER`, add the mirrors the shape test reads. These values are for `M_MAX` = 3; if the mirror assertion fails, write the vendored values it prints:

```rust
/// The one tier a multisig auth proof may declare — `randprotocol_zkvm::executor::MSAUTH_TIER`
/// (circuits Task 8: the MODQ ruling's tier 18). Mirrored because core cannot name the zkVM.
pub const MSAUTH_PROOF_TIER: u8 = 18;
/// The keccak and modq heights every multisig auth proof declares (`msauth::pinned_options()`'s
/// floors at `M_MAX`), mirrored for `gas::msauth_gas_limit_pin`; the zkvm tests pin mirror == vendored.
pub const MSAUTH_KECCAK_LOG_HEIGHT: u8 = 14;
pub const MSAUTH_MODQ_LOG_HEIGHT: u8 = 16;
```

and to `crates/randprotocol-core/src/gas.rs`:

```rust
/// The `GAS_LIMIT` every multisig auth proof must declare on a chain with a `gas` section: its
/// pinned header's ceiling (R-gas: a function of public header words only, the same for every M).
pub fn msauth_gas_limit_pin() -> u64 {
    gas_max_with_modq(crate::types::MSAUTH_PROOF_TIER, crate::types::MSAUTH_KECCAK_LOG_HEIGHT, 0, crate::types::MSAUTH_MODQ_LOG_HEIGHT)
}
```

- [ ] **Step 2: Run them to see them fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth --test guest_provenance --test auth_spike 2>&1 | tail -8
cargo +1.98.1 test --release -p randprotocol-zkvm --lib a_modq_table_is_refused 2>&1 | tail -5
```

Expected: compile errors (no `run_msauth`, `prove_msauth`, `MSAUTH_TIER`, `msauth_heights`, `auth_shape_of`, `cached_msauth_keys`, `warm_auth_multisig` on `ZkExecutor`). After those exist, `the_multisig_auth_guest_is_pinned` fails on the empty `MSAUTH_HC`.

- [ ] **Step 3: Implement** in `crates/randprotocol-zkvm/src/executor.rs`.
  1. Add `const NO_MODQ: u8 = 0;` beside `NO_SHA256`, and the `MSAUTH_TIER`, `MSAUTH_REFUSAL` and `MsauthShape` items. `MSAUTH_TIER`'s doc: "pinned like `AUTH_TIER`; `guest_provenance.rs` pins 18".
  2. Add the field `msauth_machine: Machine` (doc: "the msauth guest's own `Machine`, one key, for `auth_machine`'s reason"). Initialise it in `new`, and add `cached_msauth_keys()`.
  3. `check_decoded`: in the exact branch, add `|| proof.modq_log_height != NO_MODQ` to the tier/hash pin, with the message `"tier, hash-table or modq height not the pinned guest's"`. Before the existing `check_declared_heights` call, add `if proof.modq_log_height != NO_MODQ && !exact { return Err(InvalidProof("a call proof declares no modq table".into())) }`, so `verify_call*`, `verify_invoke` and `check_perp` (all `exact = false`) refuse before any key.
  4. `msauth_program()`: an `OnceLock` of `crate::guests::compiled::msauth()`. `hc_auth_multisig()` is its digest. `msauth_heights()`:
     ```rust
     let o = crate::msauth::pinned_options();
     let (plh, ilh, pubh) = pinned_heights(Self::msauth_program(), crate::msauth::MSAUTH_WORDS);
     MsauthShape { tier: MSAUTH_TIER, program_log_height: plh, input_log_height: ilh, keccak_log_height: o.min_keccak_log_height,
                   sha256_log_height: NO_SHA256, modq_log_height: o.min_modq_log_height, public_log_height: pubh, mem_log_height: o.min_mem_log_height }
     ```
  5. `fn decode_and_check_msauth(&self, proof: &[u8]) -> Result<Proof, ConfidentialError>`:
     - `decode_canonical`;
     - `check_declared_heights_with_modq` over all eight words;
     - compare all eight with `msauth_heights()`, failing with `InvalidProof("not the multisig auth guest's shape: {field}")`;
     - require `proof.batch.degree_bits == self.msauth_machine.log_ext_degrees_with_modq(...)` of that shape;
     - require `public_values.len() == pv::NUM`.
  6. `auth_shape_of(proof)`: decode canonically; if the header equals the single-key pinned shape (`AUTH_TIER`, `auth_heights()`, no keccak/sha256/modq), it is `SingleKey`; if it equals `msauth_heights()` (all eight), it is `Multisig`; otherwise `InvalidProof("an auth proof of neither pinned shape")`.
  7. `msauth_proof_commit` is `decode_and_check_msauth` then `published_digest`. `verify_msauth_proof(hc, proof, binding)` is `decode_and_check_msauth`, then `self.msauth_machine.verify_public(hc, binding, &p)`, then `published_digest`.
  8. In the trait impl:
     - `auth_proof_digest` and `auth_gas_limit` match `Self::auth_shape_of(proof)?`: `SingleKey` keeps today's path, `Multisig` takes the msauth one (`p.public_values[pv::GAS]`).
     - `verify_auth` dispatches on `hc` as in spec §3.4. The single-key path's existing shape error stays; the msauth path's error text names "not the multisig auth guest's shape".
     - `auth_proof_shape` is `Self::auth_shape_of`.
     - `warm_auth_multisig` builds `verifier_key_with_modq(Tier(MSAUTH_TIER), plh, ilh, klh, 0, mlh, pubh)` on `msauth_machine` under `warming`.

     (Task 4 adds the two methods to the trait. Until then, write them as inherent `pub fn`s with the same signatures; Task 4 moves them into the impl.)
  9. `honest_fri_arities`: replace `crate::machine::chips(…)` with `crate::machine::chips_with_modq(proof.tier, clamped(keccak), clamped(sha256), clamped_hash_log_height(proof.modq_log_height, crate::tables::modq::MAX_LOG_HEIGHT))`.
  10. `non_canonical`'s memory rules: the plain rule (`mem == t + 2`) applies only when keccak, sha256 **and** modq are all 0. The hash-bearing rule applies when any is non-zero, and uses
      ```rust
      pub fn hash_bearing_mem_log_height_ceiling_with_modq(tier: Tier, k: u8, s: u8, m: u8) -> u8
      ```
      which is `hash_bearing_mem_log_height_ceiling`'s body plus `rows(m) * 5`: five `MEMORY` interactions per modq row, MODQ spec §0. `hash_bearing_mem_log_height_ceiling(t, k, s)` delegates with `m = 0`.
  11. `run_msauth(inputs, binding)`: refuse `inputs.len() != MSAUTH_WORDS`; run `crate::emulator::execute(Self::msauth_program(), inputs, binding, Tier(MSAUTH_TIER).max_cycles())`; `Err("the multisig auth guest refused this witness (sentinel)")` when `outputs[7] == MSAUTH_REFUSAL` or the run did not halt; otherwise `Ok(outputs[..8])`. The word "refused" is what the test reads.
  12. `prove_msauth(profile, inputs, binding)`: the same length check, then `Machine::new(profile).prove_with_options(Self::msauth_program(), inputs, binding, Some(Tier(MSAUTH_TIER)), crate::msauth::pinned_options())` (CPU; `pinned_options().gas_limit` is `None`), then `Ok((proof.to_bytes(), exec.outputs[..8], proof.tier.0 as u8))`.
  13. Write the pin. Run `cargo +1.98.1 test --release -p randprotocol-zkvm --test guest_provenance the_multisig_auth_guest_is_pinned -- --nocapture`. The failing `assert_eq!` prints the left side, `hc_auth_multisig()`. Check it equals the `hc` circuits Task 8 recorded in `research/docs/04-guests.md`. If they differ, stop: the vendored binary is not Task 8's. Otherwise write it into `MSAUTH_HC`.

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth --test guest_provenance --test auth_spike --test executor
cargo +1.98.1 test --release -p randprotocol-zkvm --lib
cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture a_real_msauth_proof
/usr/bin/time -l cargo +1.98.1 test --release -p randprotocol-zkvm --test auth_msauth -- --ignored --nocapture measure_the_msauth 2>&1 | tee /tmp/msauth-node-prod.log
```

Expected: all pass. The last command prints `MSAUTH-PROD:` and a maximum resident set size. **If the key build's peak exceeds 1.5 GB above a plain `rand-node` baseline, stop and report** (spec §3.5). If the proof is more than 3 984 588 bytes, Task 3 uses `6 << 20` for `MSAUTH_MIN_PROOF_BYTES` (spec §3.3).

- [ ] **Step 5: Commit.**

```bash
git add crates/randprotocol-zkvm/src/executor.rs crates/randprotocol-zkvm/tests/auth_msauth.rs crates/randprotocol-zkvm/tests/guest_provenance.rs \
        crates/randprotocol-zkvm/tests/auth_spike.rs crates/randprotocol-core/src/confidential.rs crates/randprotocol-core/src/types/mod.rs crates/randprotocol-core/src/gas.rs
git commit -m "zkvm: the msauth path — msauth_machine, the pinned tier-18 shape (every height exact), verify_auth dispatched on hc, run/prove_msauth at the header's gas ceiling; modq refused on every other proof; FRI-arity and memory canonicality see the modq table; hc_auth_multisig pinned"
```

---

### Task 3: Genesis `hc_auth_multisig`: field, validation, hash, ledger parameter, node startup, `rand-node genesis --auth-multisig-guest`

**Files:**
- Modify: `crates/randprotocol-core/src/genesis.rs`, `crates/randprotocol-core/src/ledger/mod.rs` (field + accessors), `crates/randprotocol-core/src/gas.rs` (`MSAUTH_MIN_PROOF_BYTES`)
- Modify: `crates/randprotocol-node/src/node.rs` (`reload_ledger`, `check_build_runs_genesis`), `crates/randprotocol-node/src/main.rs` (genesis flag), `crates/randprotocol-node/src/bench.rs` and every `Genesis { … }` literal the compiler names (`hc_auth_multisig: None`)

**Interfaces:**
- Consumes: Task 2's `ZkExecutor::hc_auth_multisig()`.
- Produces:
  ```rust
  pub struct Genesis { /* … */ pub aggregation_tree: Option<TreeConfig>, pub hc_auth_multisig: Option<String> }  // last
  pub enum GenesisError { /* … */ BadHcAuthMultisig(String), HcAuthMultisigWithoutHcAuth, HcAuthMultisigIsHcAuth,
                          ProofCapTooSmallForMsauth { proof: usize, need: usize } }
  impl Ledger { pub fn hc_auth_multisig(&self) -> Option<Word8>; pub fn set_hc_auth_multisig(&mut self, hc: Option<Word8>); }
  pub const gas::MSAUTH_MIN_PROOF_BYTES: usize = 4 << 20;
  ```

- [ ] **Step 1: Write the failing tests.** Append to `genesis.rs`'s `mod tests`:

```rust
/// Private multisig phase 4: `hc_auth_multisig` is opt-in, the file's last key, bound into the
/// hash last (after `aggregation_tree`) and only when present, set on the ledger, never state.
#[test]
fn hc_auth_multisig_is_bound_last_and_only_when_present() {
    let mut plain = genesis(2);
    plain.max_proof_bytes = Some(4 << 20);
    plain.max_block_bytes = Some(20 << 20);
    plain.hc_auth = Some(word8_to_hex(&[21; 8]));
    assert!(!plain.to_json().contains("hc_auth_multisig"), "absent from the file");
    let s = build(&plain);
    assert_eq!(s.ledger.hc_auth_multisig(), None);

    let mut on = plain.clone();
    on.hc_auth_multisig = Some(word8_to_hex(&[23; 8]));
    let g = build(&on);
    assert_eq!(g.ledger.hc_auth_multisig(), Some([23; 8]));
    assert_ne!(g.hash(), s.hash(), "a different chain");
    assert_eq!(g.ledger.state_root(), s.ledger.state_root(), "a parameter, not state");
    let mut other = on.clone();
    other.hc_auth_multisig = Some(word8_to_hex(&[24; 8]));
    assert_ne!(build(&other).hash(), g.hash(), "the pin itself is bound");
    let json = on.to_json();
    let last_key = json.rfind("\"hc_auth_multisig\"").unwrap();
    assert!(json[last_key..].matches("\": ").count() == 1, "the file's last key: {json}");
    assert_eq!(Genesis::from_json(&json).unwrap(), on, "round-trips");
}

#[test]
fn hc_auth_multisig_needs_hc_auth_must_differ_from_it_and_must_parse() {
    let mut g = genesis(2);
    g.max_proof_bytes = Some(4 << 20);
    g.max_block_bytes = Some(20 << 20);
    g.hc_auth_multisig = Some(word8_to_hex(&[23; 8]));
    assert!(matches!(g.build(&StubExecutor), Err(GenesisError::HcAuthMultisigWithoutHcAuth)));
    g.hc_auth = Some(word8_to_hex(&[23; 8]));
    assert!(matches!(g.build(&StubExecutor), Err(GenesisError::HcAuthMultisigIsHcAuth)));
    g.hc_auth = Some(word8_to_hex(&[21; 8]));
    g.hc_auth_multisig = Some("not hex".into());
    assert!(matches!(g.build(&StubExecutor), Err(GenesisError::BadHcAuthMultisig(_))));
}

/// Spec §2.3 item 4: at Production FRI the proof cap must admit an msauth proof (~3.6 MB); the
/// three-proof block rule is unchanged and then covers bundle + msauth + call.
#[test]
fn a_production_hc_auth_multisig_genesis_needs_a_4_mib_proof_cap() {
    let caps = |profile: &str, proof: Option<u32>, block: Option<u32>| {
        let mut g = genesis(2);
        g.fri_profile = profile.into();
        g.hc_auth = Some(word8_to_hex(&[21; 8]));
        g.hc_auth_multisig = Some(word8_to_hex(&[23; 8]));
        g.max_proof_bytes = proof;
        g.max_block_bytes = block;
        g
    };
    let need = crate::gas::MSAUTH_MIN_PROOF_BYTES;
    assert_eq!(need, 4 << 20);
    match caps("production", Some(need as u32 - 1), Some(20 << 20)).build(&StubExecutor) {
        Err(e @ GenesisError::ProofCapTooSmallForMsauth { proof, need: n }) => {
            assert_eq!((proof, n), (need - 1, need));
            assert!(e.to_string().contains("multisig auth proof"), "{e}");
        }
        other => panic!("{:?}", other.map(|s| s.hash())),
    }
    assert!(matches!(caps("production", None, Some(20 << 20)).build(&StubExecutor), Err(GenesisError::ProofCapTooSmallForMsauth { .. })), "the 2 MiB default");
    assert!(caps("production", Some(need as u32), Some(20 << 20)).build(&StubExecutor).is_ok(), "chain 21's 4 MiB / 20 MiB");
    assert!(matches!(caps("production", Some(need as u32), Some(12 << 20)).build(&StubExecutor), Err(GenesisError::BlockTooSmallForSplitAuth { .. })), "3·4 MiB + 1 MiB still rules the block");
    assert!(caps("test", None, Some(7 << 20)).build(&StubExecutor).is_ok(), "the Test profile is not judged by it");
}
```

Append to `node.rs`'s `mod tests`:

```rust
/// `hc_auth_multisig` must be this build's msauth guest.
#[test]
fn startup_refuses_an_hc_auth_multisig_this_build_does_not_carry() {
    let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
    let known = ZkExecutor::known_hc_bundles();
    gs.hc_bundle = ZkExecutor::hc_hidden_bundle_v3();
    gs.ledger.set_hc_auth(Some(ZkExecutor::hc_auth()));
    gs.ledger.set_hc_auth_multisig(Some(ZkExecutor::hc_auth_multisig()));
    assert!(check_build_runs_genesis(&gs, &known).is_ok());
    gs.ledger.set_hc_auth_multisig(Some([0xdead; 8]));
    let e = check_build_runs_genesis(&gs, &known).unwrap_err().to_string();
    assert!(e.contains("not this build's multisig auth guest"), "{e}");
}

#[test]
fn a_restart_restores_hc_auth_multisig() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
    gs.ledger.set_hc_auth(Some([21; 8]));
    gs.ledger.set_hc_auth_multisig(Some([23; 8]));
    storage.init_genesis(&gs).unwrap();
    assert_eq!(storage.load_ledger(&StubExecutor).unwrap().hc_auth_multisig(), None);
    assert_eq!(reload_ledger(&storage, &gs, &StubExecutor).unwrap().hc_auth_multisig(), Some([23; 8]));
}
```

Append to `main.rs`'s tests, next to the `--auth-guest` genesis test at `main.rs:4757`. Use that test's own writer helper; it runs `genesis` into a tempdir and reads the file back, and here it is called with `--auth-guest --auth-multisig-guest`:

```rust
#[test]
fn genesis_auth_multisig_guest_writes_this_builds_msauth_hc_and_needs_auth_guest() {
    let gen = genesis_written_with(&["--bundle-guest", "v3", "--auth-guest", "--auth-multisig-guest", "--max-proof-bytes", "4194304", "--max-block-bytes", "20971520"]);
    assert_eq!(gen.hc_auth_multisig.as_deref(), Some(word8_to_hex(&ZkExecutor::hc_auth_multisig()).as_str()));
    assert!(Cli::try_parse_from(["rand-node", "genesis", "--auth-multisig-guest", "--out", "g.json"]).is_err(), "requires --auth-guest");
}
```

`genesis_written_with` is the existing helper in that test module that the `--auth-guest` assertions at `main.rs:4757`/`4788` call. If it has another name, use that name.

- [ ] **Step 2: Run them to see them fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-core --lib hc_auth_multisig 2>&1 | tail -5
cargo +1.98.1 test --release -p randprotocol-node --lib hc_auth_multisig 2>&1 | tail -5
cargo +1.98.1 test --release -p randprotocol-node --bin rand-node genesis_auth_multisig_guest 2>&1 | tail -5
```

Expected: compile errors (no field, variants, accessors or flag).

- [ ] **Step 3: Implement.**
  1. Add the `Genesis.hc_auth_multisig` field **last**, with spec §2.1's doc, and `hc_auth_multisig: None` in every literal the compiler lists. Add the ledger field (`None` in both `Ledger` constructors) and its accessors, beside `hc_auth`.
  2. In `build`, after `set_hc_auth`, parse into `BadHcAuthMultisig` and call `ledger.set_hc_auth_multisig`. In the hash, after the `aggregation_tree` block, add spec §2.2's three lines with the comment "Private multisig, after `aggregation_tree` — last — tagged, present-only".
  3. In `validate`, after the split-auth block rule: rules 2–4 of spec §2.3. The `ProofCapTooSmallForMsauth` message is `"max_proof_bytes {proof} cannot hold a multisig auth proof (about 3.6 MB at production FRI): a chain with hc_auth_multisig needs max_proof_bytes ≥ {need}"`. In `gas.rs`, add `pub const MSAUTH_MIN_PROOF_BYTES: usize = 4 << 20;`, documented with spec §3.3's estimate and the 95 % rule. Use `6 << 20` if Task 2's measurement said so.
  4. In `node.rs`:
     - `reload_ledger`: `ledger.set_hc_auth_multisig(gs.ledger.hc_auth_multisig());`, with a comment in the `hc_auth` comment's style.
     - `check_build_runs_genesis`: `if let Some(h) = gs.ledger.hc_auth_multisig() { if h != ZkExecutor::hc_auth_multisig() { bail!("the genesis hc_auth_multisig ({}) is not this build's multisig auth guest ({}); rebuild from the chain's pinned commit", …) } }`.
  5. In `main.rs`'s `genesis` subcommand, add `#[arg(long, requires = "auth_guest")] auth_multisig_guest: bool` (doc: "Pin this build's multisig auth guest as `hc_auth_multisig` (private multisig)"). Write `hc_auth_multisig: auth_multisig_guest.then(|| word8_to_hex(&ZkExecutor::hc_auth_multisig()))`, and append `hc_auth_multisig {}` to the summary line.

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-core --lib genesis
cargo +1.98.1 test --release -p randprotocol-node --lib startup_ a_restart_restores
cargo +1.98.1 test --release -p randprotocol-node --bin rand-node genesis
cargo +1.98.1 test --release -p randprotocol-node --lib every_committed_genesis_file
```

Expected: all pass. Every committed `deploy/genesis-chain*.json` keeps its hash.

- [ ] **Step 5: Commit.**

```bash
git add crates/randprotocol-core crates/randprotocol-node
git commit -m "genesis: hc_auth_multisig — last field, hash-bound last (after aggregation_tree), needs hc_auth and differs from it, a 4 MiB proof cap at production; restored on restart; startup refuses another build's msauth guest; rand-node genesis --auth-multisig-guest"
```

---

### Task 4: Admission dispatch by shape (trait, stub, ledger, wrappers, warm, verify-cache compatibility)

**Files:**
- Modify: `crates/randprotocol-core/src/confidential.rs` (trait + `StubExecutor`)
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (`check_auth_fields`, `verify_auth_proof`, `check_bundle_proof`, and the test executors at `CountingExecutor`, `FlaggingExecutor`, `PaddedStub`, `LyingDigest`, `NoGas`, `FlakyDeploy`)
- Modify: `crates/randprotocol-core/src/ledger/aggregation.rs` (`HeaderRefusing`, `TreeProbe`)
- Modify: `crates/randprotocol-zkvm/src/executor.rs` (move Task 2's inherent methods into the trait impl)
- Modify: `crates/randprotocol-node/src/agg_executor.rs` (`AggExecutor`, `AsProvedBinding`), `crates/randprotocol-node/src/node.rs` (warm)
- Modify, only if `feat/verify-cache` is on `main` when this task starts: `crates/randprotocol-node/src/verify_cache.rs`

**Interfaces:**
- Consumes: Task 2 (`AuthShape`, `ZkExecutor::auth_shape_of`, `warm_auth_multisig`), Task 3 (`Ledger::hc_auth_multisig`), `gas::msauth_gas_limit_pin`.
- Produces:
  ```rust
  // ConfidentialExecutor — both REQUIRED (no default):
  fn auth_proof_shape(&self, proof: &[u8]) -> Result<AuthShape, ConfidentialError>;
  fn warm_auth_multisig(&self);
  // StubExecutor
  pub fn make_msauth_proof(hc_auth_multisig: &Word8, c: &Word8, binding: &[u32; TX_BINDING_WORDS]) -> Vec<u8>;
  pub const STUB_MSAUTH_GAS_LIMIT: u64;   // == gas::msauth_gas_limit_pin()
  // Ledger (private): fn check_auth_fields(&self, b, ex) -> Result<Option<AuthShape>, TxError>;
  //                   fn verify_auth_proof(&self, b, shape: Option<AuthShape>, binding, ex) -> Result<(), TxError>;
  ```

- [ ] **Step 1: Write the failing tests.**
  - Extend `CountingExecutor` (`ledger/mod.rs:4451`) with a `auth_hcs: std::sync::Mutex<Vec<Word8>>` that `verify_auth` pushes `*hc_auth` onto, and an accessor `fn auth_hcs(&self) -> Vec<Word8>`.
  - Add `fn auth_proof_shape(&self, p: &[u8]) -> … { StubExecutor.auth_proof_shape(p) }` and `fn warm_auth_multisig(&self) {}` to every test executor in the Files list.

  Then append to `ledger/mod.rs`'s tests, after the split-authorisation block:

```rust
// ---- Private multisig phase 4: dispatch on the auth proof's shape -----------------------------

/// The multisig auth guest a test chain pins (genesis `hc_auth_multisig`).
const HCM: Word8 = [23; 8];

fn msig_ledger() -> Ledger {
    let mut l = v3_ledger();
    l.set_hc_auth_multisig(Some(HCM));
    l
}

/// A v3 transaction whose auth proof is a stub multisig proof made by `hc`, publishing `proof_c`.
fn msig_tx_with(l: &Ledger, c: Word8, proof_c: Word8, hc: Word8) -> Transaction {
    let mut b = bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE);
    b.auth_commit = c;
    b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest_v3(&b.digest_input()), &[0; 8]);
    b.auth_proof = StubExecutor::make_msauth_proof(&hc, &proof_c, &[0; 8]);
    StubExecutor::bound(Transaction::shielded(7, b, Action::None))
}

#[test]
fn a_multisig_auth_proof_is_verified_against_hc_auth_multisig_and_single_key_still_works() {
    let (a, _) = keys();
    let mut l = msig_ledger();
    let t = msig_tx_with(&l, C, C, HCM);
    let exec = CountingExecutor::default();
    assert_eq!(l.validate(&t, &exec), Ok(()));
    assert_eq!(exec.auth_hcs(), vec![HCM], "verify_auth got hc_auth_multisig");
    l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
    let l = msig_ledger();
    let exec = CountingExecutor::default();
    assert_eq!(l.validate(&v3_tx(&l), &exec), Ok(()), "a single-key spend on the same chain");
    assert_eq!(exec.auth_hcs(), vec![HCA], "verify_auth got hc_auth");
}

#[test]
fn a_multisig_shaped_proof_made_by_another_guest_is_refused() {
    let l = msig_ledger();
    assert_eq!(l.validate(&msig_tx_with(&l, C, C, HCA), &StubExecutor), Err(TxError::InvalidAuthProof(ConfidentialError::WrongProgram)));
}

#[test]
fn a_multisig_auth_proof_on_a_chain_without_hc_auth_multisig_is_refused_before_any_verify() {
    let l = v3_ledger();
    let t = msig_tx_with(&l, C, C, HCM);
    let exec = CountingExecutor::default();
    match l.validate(&t, &exec) {
        Err(TxError::InvalidAuthProof(ConfidentialError::InvalidProof(why))) => assert!(why.contains("without hc_auth_multisig"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!((exec.bundles(), exec.auths()), (0, 0));
}

#[test]
fn a_multisig_auth_proof_publishing_another_c_is_auth_mismatch() {
    let l = msig_ledger();
    let t = msig_tx_with(&l, C, [0xc1; 8], HCM);
    assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::AuthMismatch));
    let b = t.bundle.as_ref().unwrap();
    assert_eq!(l.check_bundle_proof(&t, b, &t.binding(&crate::types::BindingDomain::ChainId), &StubExecutor, true), Err(TxError::AuthMismatch), "on a verified-set hit too");
}

/// R-gas: under the section a multisig proof must declare its header's ceiling, the msauth pin —
/// not the single-key pin, and not any run-exact value.
#[test]
fn under_gas_a_multisig_auth_proof_must_declare_the_msauth_ceiling() {
    let (a, _) = keys();
    let mut l = msig_ledger();
    l.set_gas(Some(gas::GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: gas::bundle_gas_limit_pin(), metering: gas::GasMetering::Circuit, dynamic: None }));
    let pin = gas::msauth_gas_limit_pin();
    assert_eq!(pin, crate::confidential::STUB_MSAUTH_GAS_LIMIT);
    let ok = msig_tx_with(&l, C, C, HCM);
    assert_eq!(l.validate(&ok, &StubExecutor), Ok(()));
    for other in [pin - 1, pin + 1, gas::auth_gas_limit_pin(), 1] {
        let mut t = ok.clone();
        StubExecutor::with_auth_gas(&mut t.bundle.as_mut().unwrap().auth_proof, other);
        let t = StubExecutor::bound(t);
        let want = Err(TxError::AuthGasLimit { want: pin, got: Some(other) });
        let exec = CountingExecutor::default();
        assert_eq!(l.validate(&t, &exec), want, "{other}");
        assert_eq!((exec.bundles(), exec.auths()), (0, 0), "refused before either verify");
        let mut applied = l.clone();
        assert_eq!(applied.apply_tx_with(&t, &a.address(), &StubExecutor, &Admitted::of(&[&t])).map(|_| ()), want);
    }
}

#[test]
fn an_auth_proof_of_neither_shape_is_invalid() {
    let l = msig_ledger();
    let mut t = v3_tx(&l);
    t.bundle.as_mut().unwrap().auth_proof = b"neither".to_vec();
    let t = StubExecutor::bound(t);
    assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::InvalidAuthProof(ConfidentialError::MalformedProof)));
}
```

Append to `agg_executor.rs`'s tests:

```rust
/// Both phase-4 methods are forwarded, never left at a default: the inner executor's answer
/// comes back through the node's wrapper.
#[test]
fn the_auth_shape_and_the_multisig_warm_are_forwarded() {
    let ex = AggExecutor::new(Arc::new(StubExecutor), randprotocol_zkvm::machine::FriProfile::Test);
    let msig = StubExecutor::make_msauth_proof(&[23; 8], &[1; 8], &[0; 8]);
    let single = StubExecutor::make_auth_proof(&[21; 8], &[1; 8], &[0; 8]);
    assert_eq!(ex.auth_proof_shape(&msig), Ok(AuthShape::Multisig));
    assert_eq!(ex.auth_proof_shape(&single), Ok(AuthShape::SingleKey));
    ex.warm_auth_multisig();
}
```

`AggExecutor::new(...)` is written here with the constructor the other `agg_executor` tests use. If its signature differs, use the existing tests' construction.

If `verify_cache.rs` is on `main`, append to its tests:

```rust
#[test]
fn the_phase_4_methods_forward_and_a_multisig_verify_is_its_own_kind_2_entry() {
    let inner = Arc::new(Counting::default());
    let ex = CachingExecutor::new(inner.clone());
    let msig = StubExecutor::make_msauth_proof(&[23; 8], &[1; 8], &[0; 8]);
    assert_eq!(ex.auth_proof_shape(&msig), Ok(AuthShape::Multisig));
    ex.warm_auth_multisig();
    assert_eq!(ex.verify_auth(&[23; 8], &msig, &[0; 8]), Ok([1; 8]));
    assert_eq!(ex.verify_auth(&[23; 8], &msig, &[0; 8]), Ok([1; 8]));
    assert_eq!(inner.auths(), 1, "cached under (hc, proof, binding)");
    let _ = ex.verify_auth(&[21; 8], &msig, &[0; 8]);
    assert_eq!(inner.auths(), 2, "another hc is another entry");
}
```

`Counting` is that file's counting inner executor, and `auths()` its `verify_auth` count; use the names the file defines.

- [ ] **Step 2: Run them to see them fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-core --lib multisig_auth_proof auth_proof_of_neither 2>&1 | tail -5
cargo +1.98.1 test --release -p randprotocol-node --lib the_auth_shape_and_the_multisig_warm_are_forwarded 2>&1 | tail -5
```

Expected: compile errors (no trait methods, `make_msauth_proof` or `STUB_MSAUTH_GAS_LIMIT`).

- [ ] **Step 3: Implement.**
  1. Trait (`confidential.rs`): add both methods **without** a body, documented as in spec §3.4. Add the line "Every wrapper (`AggExecutor`, `CachingExecutor`) forwards them; they verify nothing and are never cached." Extend the trait's doc note on forwarding to name them.
  2. `StubExecutor`:
     - `const STUB_MSAUTH_MARKER: &[u8; 5] = b"msau:";`, with the same layout as the auth stub;
     - `pub const STUB_MSAUTH_GAS_LIMIT: u64` written as the literal value of `gas::msauth_gas_limit_pin()`, which the test pins;
     - `make_msauth_proof` hashes `hc` under `b"rand-stub-auth"` exactly as `make_auth_proof` does, so `verify_auth`'s `WrongProgram` check works for both;
     - `auth_proof_shape` reads the marker (`auth:` → `SingleKey`, `msau:` → `Multisig`, else `MalformedProof`);
     - `auth_proof_digest`, `verify_auth`, `auth_gas_limit`, `bind_in` and `with_auth_gas` accept either marker;
     - `warm_auth_multisig` is a no-op.
  3. Ledger. Rewrite `check_auth_fields` to spec §3.2's sequence, returning `Ok(Some(shape))` on a `hc_auth` chain and `Ok(None)` otherwise. The shape refusal is `TxError::InvalidAuthProof(ConfidentialError::InvalidProof("a multisig auth proof on a chain without hc_auth_multisig".into()))`. `verify_auth_proof` takes the shape and selects `hc` as in spec §3.2. `check_bundle_proof` threads the shape from the cheap half to the expensive one, and the verified-set path keeps skipping the expensive half.
  4. `ZkExecutor`: move `auth_proof_shape` and `warm_auth_multisig` into `impl ConfidentialExecutor`.
  5. `AggExecutor`, `AsProvedBinding` and the test executors forward to `inner` / `StubExecutor`. In `node.rs`'s warm task, read `let multisig = hs.committed_ledger().hc_auth_multisig().is_some();` beside `split_auth`, and add `if multisig { ex.warm_auth_multisig(); tracing::info!("multisig auth verifier key warmed"); }` after `warm_auth`.
  6. `verify_cache.rs`. If it is on `main`, add the two forwards to `CachingExecutor`'s "forwarded unchanged" group. If it is not, append to `docs/superpowers/specs/2026-10-11-verify-cache-design.md` §3.2 on **this** branch:

     > Phase-4 private multisig adds two required, uncached methods, `auth_proof_shape` and `warm_auth_multisig`. `CachingExecutor` must forward both. Multisig verifies reuse `verify_auth`, kind 2, with `hc` in the key.

     Then send that sentence to the `feat/verify-cache` owner.

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-core --lib
cargo +1.98.1 test --release -p randprotocol-node --lib
cargo +1.98.1 test --release -p randprotocol-zkvm --lib --test auth_msauth
```

Expected: all pass, the earlier split-auth tests included and unchanged.

- [ ] **Step 5: Commit.**

```bash
git add crates/randprotocol-core crates/randprotocol-zkvm/src/executor.rs crates/randprotocol-node docs/superpowers/specs/2026-10-11-verify-cache-design.md
git commit -m "ledger: dispatch the auth proof on its pinned shape — single-key → hc_auth, multisig → hc_auth_multisig, else InvalidAuthProof; the msauth gas pin under the gas section; verify_auth reused (cached by hc); auth_proof_shape and warm_auth_multisig required and forwarded by every wrapper"
```

---

### Task 5: RPC: `hc_auth_multisig` in `rand_status` and `rand_getLimits`

**Files:**
- Modify: `crates/randprotocol-node/src/rpc.rs`, `crates/randprotocol-node/src/node.rs` (status fill)
- Modify: `crates/randprotocol-client/src/lib.rs` (`ChainLimits.hc_auth_multisig`)
- Modify: `crates/randprotocol-node/tests/rpc_contract.rs` (if it lists the fields of `rand_getLimits`/`rand_status`)

**Interfaces:**
- Consumes: Task 3's `Ledger::hc_auth_multisig`.
- Produces: `rpc::Status.hc_auth_multisig: Option<String>`, `rpc::ChainLimits.hc_auth_multisig: Option<String>`, client `ChainLimits.hc_auth_multisig: Option<String>` (`#[serde(default)]`).

- [ ] **Step 1: Write the failing test.** In `rpc.rs`'s tests, beside the `hc_auth` limits test at `rpc.rs:5472`:

```rust
/// Private multisig: a wallet reads `hc_auth_multisig` to know whether this chain admits a
/// multisig spend at all; `null` (present) where the genesis has none.
#[tokio::test]
async fn limits_and_status_serve_hc_auth_multisig() {
    let st = state_with(|gs| {
        gs.ledger.set_hc_auth(Some([7; 8]));
    });
    assert!(ok(&st, "rand_getLimits", json!([])).await["hc_auth_multisig"].is_null(), "null without the field");
    assert!(ok(&st, "rand_status", json!([])).await.as_object().unwrap().contains_key("hc_auth_multisig"));
    let st = state_with(|gs| {
        gs.ledger.set_hc_auth(Some([7; 8]));
        gs.ledger.set_hc_auth_multisig(Some([8; 8]));
    });
    assert_eq!(ok(&st, "rand_getLimits", json!([])).await["hc_auth_multisig"], json!(word8_to_hex(&[8; 8])));
}
```

`state_with` is the genesis-mutating helper the `hc_auth` test at `rpc.rs:5472` uses (it sets `gs.ledger.set_hc_auth(Some([7; 8]))` on a fresh state); use that test's own construction verbatim.

- [ ] **Step 2: Run it to see it fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-node --lib limits_and_status_serve_hc_auth_multisig 2>&1 | tail -5
```

Expected: compile error (no `set_hc_auth_multisig` on the state, or the key is missing).

- [ ] **Step 3: Implement.**
  - Add `pub hc_auth_multisig: Option<String>` to `Status` and to `ChainLimits`. Use the `hc_auth` docs, adapted: "the multisig auth guest; `null` where the chain has none".
  - Fill `ChainLimits::of` with `ledger.hc_auth_multisig().map(|h| word8_to_hex(&h))`, and the status refresh in `node.rs` beside `s.hc_auth`.
  - Add `"hc_auth_multisig": s.hc_auth_multisig` to the status JSON at `rpc.rs:2739`.
  - Client `ChainLimits`: `#[serde(default)] pub hc_auth_multisig: Option<String>`.
  - Fix every JSON fixture in the tests (`"hc_auth": null` blocks at `rpc.rs:5381`/`5413`/`5447`) to add `"hc_auth_multisig": null`.

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-node --lib rpc
cargo +1.98.1 test --release -p randprotocol-node --test rpc_contract
cargo +1.98.1 test --release -p randprotocol-client --lib
```

- [ ] **Step 5: Commit.**

```bash
git add crates/randprotocol-node crates/randprotocol-client/src/lib.rs
git commit -m "rpc: rand_status and rand_getLimits serve hc_auth_multisig (null without it)"
```

---

### Task 6: Wallet library: spend-key-less `Wallet`, `Policy`, `Proposal`, sign / assemble / prove

**Files:**
- Modify: `crates/randprotocol-client/src/wallet.rs` (`Wallet.sk: Option<SpendKey>`, `from_viewing_key`, `spend_key`, `AuthWitness`, `pub(crate)` on `Prepared` and `prepare_bundle`)
- Create: `crates/randprotocol-client/src/msig_private.rs`
- Modify: `crates/randprotocol-client/src/lib.rs` (`pub mod msig_private;`), `crates/randprotocol-client/src/main.rs` and `crates/randprotocol-node/src/main.rs` (every `w.sk` → `w.spend_key()?`, as the compiler lists)

**Interfaces:**
- Consumes: Task 2 (`run_msauth`, `prove_msauth`, `ZkExecutor::hc_auth_multisig`), the vendored `msauth::*`, Task 5 (`rand_status.hc_auth_multisig`).
- Produces:
  ```rust
  // wallet.rs
  pub struct Wallet { pub sk: Option<SpendKey>, pub vk: ViewingKey, pub address: ShieldedAddress, pub scan_key: ScanKey }
  impl Wallet { pub fn from_viewing_key(vk: ViewingKey) -> Wallet; pub fn spend_key(&self) -> Result<&SpendKey>; }
  pub(crate) enum AuthWitness<'a> { Key(&'a SpendKey), Multisig(&'a [u32]) }
  // msig_private.rs
  pub struct Policy { pub threshold: u32, pub signers: Vec<PublicKey>, pub msk: Word8 }
  impl Policy {
      pub fn new(signers: Vec<PublicKey>, threshold: u32) -> Result<Policy>;   // fresh msk
      pub fn check(&self) -> Result<()>;
      pub fn pks(&self) -> Vec<[u8; 1312]>;
      pub fn signer_root(&self) -> Word8;
      pub fn policy_hash(&self) -> Word8;
      pub fn nk(&self) -> Word8;
      pub fn wallet(&self) -> Wallet;
      pub fn fingerprint(&self) -> String;
      pub fn save(&self, path: &Path) -> Result<()>;   // 0600, refuses an existing file
      pub fn load(path: &Path) -> Result<Policy>;      // refuses group/world-readable
  }
  #[derive(Serialize, Deserialize)] pub struct Proposal { pub version: u32, pub chain_id: u64, pub genesis: String, pub binding_domain: u32,
      pub policy: String, pub tx: String, pub bundle_words: String, pub expected: String, pub salt: String, pub auth_commit: String,
      pub binding: String, pub signing_message: String, pub expires_at: u64, pub summary: Vec<String> }
  pub struct Share { pub index: u8, pub signature: Signature }   // Display/FromStr "index:hex"
  pub async fn prepare(rpc: &RpcClient, policy: &Policy, store: &mut NoteStore, to: &ShieldedAddress, amount: u64, memo: &str, fee: u64, chain_id: u64) -> Result<Proposal>;
  pub async fn prepare_sweep(rpc: &RpcClient, policy: &Policy, store: &mut NoteStore, to: &ShieldedAddress, fee: u64, chain_id: u64) -> Result<Proposal>;
  pub fn sign(proposal: &Proposal, policy: &Policy, key: &Keypair) -> Result<(Share, Vec<String>)>;   // the share, and the summary lines it showed
  pub fn assemble_witness(proposal: &Proposal, policy: &Policy, shares: &[Share]) -> Result<Vec<u32>>;
  pub async fn prove(proposal: &Proposal, policy: &Policy, shares: &[Share], proving: &Proving, profile: FriProfile) -> Result<Transaction>;
  pub fn save_proposal(p: &Proposal, path: &Path) -> Result<()>; pub fn load_proposal(path: &Path) -> Result<Proposal>;
  ```

- [ ] **Step 1: Write the failing tests.** Create `msig_private.rs` with only `#[cfg(test)] mod tests` first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::Keypair;

    fn keys(n: u8) -> Vec<Keypair> { (0..n).map(|i| Keypair::from_seed([0x40 + i; 32]).unwrap()).collect() }
    fn two_of_three() -> (Policy, Vec<Keypair>) {
        let k = keys(3);
        (Policy::new(k.iter().map(|k| k.public_key().clone()).collect(), 2).unwrap(), k)
    }

    #[test]
    fn a_policy_derives_the_guests_nk_and_a_viewing_only_wallet() {
        let (p, _) = two_of_three();
        let want = randprotocol_zkvm::msauth::nk(&p.msk, &randprotocol_zkvm::msauth::policy(2, &p.signer_root()));
        assert_eq!(p.nk(), want);
        let w = p.wallet();
        assert_eq!(w.vk.nk, want);
        assert!(w.sk.is_none() && w.spend_key().is_err(), "no spend key: spends go through multisig-private");
        assert_eq!(w.address, crate::wallet::Wallet::from_viewing_key(w.vk).address);
        assert_ne!(Policy::new(p.signers.clone(), 2).unwrap().nk(), p.nk(), "a fresh msk is another account");
    }

    #[test]
    fn a_policy_is_refused_when_the_guest_could_never_spend_it() {
        let k = keys(3);
        let pk = |i: usize| k[i].public_key().clone();
        assert!(Policy::new(vec![], 1).is_err(), "no signer");
        assert!(Policy::new(vec![pk(0), pk(1)], 0).is_err(), "threshold 0");
        assert!(Policy::new(vec![pk(0), pk(1)], 3).is_err(), "threshold above n");
        assert!(Policy::new(vec![pk(0), pk(0)], 1).is_err(), "a repeated key");
        assert!(Policy::new((0..17).map(|i| Keypair::from_seed([i; 32]).unwrap().public_key().clone()).collect(), 1).is_err(), "n > N_MAX");
        let m = randprotocol_zkvm::msauth::M_MAX as u32;
        let many: Vec<_> = (0..(m as u8 + 1)).map(|i| Keypair::from_seed([0x60 + i; 32]).unwrap().public_key().clone()).collect();
        assert!(Policy::new(many, m + 1).is_err(), "threshold above M_MAX");
    }

    #[test]
    fn the_policy_file_is_0600_and_round_trips() {
        let (p, _) = two_of_three();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        p.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Policy::load(&path).is_err(), "group/world readable is refused");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let back = Policy::load(&path).unwrap();
        assert_eq!((back.threshold, back.signers.clone(), back.msk), (p.threshold, p.signers.clone(), p.msk));
        assert!(p.save(&path).is_err(), "never overwrites");
    }

    /// A proposal over a real v3 bundle (no proof), built offline by the test helper below.
    fn proposal(p: &Policy) -> Proposal { tests_support::offline_proposal(p, 10 * randprotocol_core::UNITS_PER_RAND) }

    #[test]
    fn sign_recomputes_the_binding_and_opens_every_output_before_signing() {
        let (p, k) = two_of_three();
        let prop = proposal(&p);
        let (share, shown) = sign(&prop, &p, &k[2]).unwrap();
        assert_eq!(share.index, 2);
        let msg = hex::decode(&prop.signing_message).unwrap();
        assert!(k[2].public_key().verify(&msg, &share.signature));
        assert!(shown.iter().any(|l| l.contains("10 RAND")), "{shown:?}");
        assert_eq!(share.to_string().parse::<Share>().unwrap().index, 2, "index:hex round-trips");
        // A key outside the policy is refused.
        assert!(sign(&prop, &p, &Keypair::from_seed([9; 32]).unwrap()).is_err());
        // A tampered transaction (its binding moves) is refused.
        let mut bad = prop.clone();
        let mut tx: Transaction = bincode::deserialize(&hex::decode(&bad.tx).unwrap()).unwrap();
        tx.bundle.as_mut().unwrap().fee += 1;
        bad.tx = hex::encode(bincode::serialize(&tx).unwrap());
        assert!(sign(&bad, &p, &k[0]).unwrap_err().to_string().contains("binding"));
        // A proposal from another policy's account is refused.
        let (other, _) = two_of_three();
        assert!(sign(&prop, &other, &k[0]).unwrap_err().to_string().contains("auth_commit"));
    }

    #[test]
    fn assemble_witness_needs_the_threshold_and_runs_like_the_guest() {
        let (p, k) = two_of_three();
        let prop = proposal(&p);
        let s0 = sign(&prop, &p, &k[0]).unwrap().0;
        let s2 = sign(&prop, &p, &k[2]).unwrap().0;
        let w = assemble_witness(&prop, &p, &[s2.clone(), s0.clone()]).unwrap();
        assert_eq!(w.len(), randprotocol_zkvm::msauth::MSAUTH_WORDS);
        let binding = parse_binding(&prop.binding).unwrap();
        assert_eq!(randprotocol_zkvm::executor::run_msauth(&w, &binding).unwrap(), parse_word8(&prop.auth_commit).unwrap(), "the guest publishes auth_commit");
        let e = assemble_witness(&prop, &p, &[s0.clone()]).unwrap_err().to_string();
        assert!(e.contains("1 signature") && e.contains("needs 2"), "{e}");
        assert!(assemble_witness(&prop, &p, &[s0.clone(), s0.clone()]).is_err(), "a repeated index");
        let mut forged = s2.clone();
        forged.index = 1;
        assert!(assemble_witness(&prop, &p, &[s0, forged]).unwrap_err().to_string().contains("signer 1"), "names the bad share");
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! An offline proposal: a v3 bundle spending one synthetic note of the policy's account to a
    //! fresh address, through the same `build_bundle` the online path calls.
    use super::*;
    pub(crate) fn offline_proposal(p: &Policy, amount: u64) -> Proposal {
        crate::wallet::tests::offline_v3_proposal_for(&p.wallet(), amount, |prepared, tx, binding| {
            Proposal::from_prepared(p, prepared, tx, binding, 7, &randprotocol_core::Hash::ZERO, 0, 1_000)
        })
    }
}
```

`crate::wallet::tests::offline_v3_proposal_for` is a new `pub(crate)` test helper in `wallet.rs`'s `mod tests`. It takes a `Wallet`, mints one synthetic note of `amount + gas::BUNDLE_BASE` into a one-leaf tree (as the existing `build_bundle` unit tests do), calls `build_bundle` with the v3 guest, wraps the result in `Transaction::shielded(7, …, Action::None)` with binding domain `ChainId`, and hands `(&Prepared, &Transaction, binding)` to the closure. Write it beside the existing `build_bundle` tests, reusing their tree and note setup.

- [ ] **Step 2: Run them to see them fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-client --lib msig_private 2>&1 | tail -5
```

Expected: compile errors (no `Policy`, `Proposal`, `sign`, `assemble_witness`, `Wallet::from_viewing_key`).

- [ ] **Step 3: Implement.**
  1. `wallet.rs`:
     - `sk: Option<SpendKey>`. `from_spend_key` sets `Some`. `from_viewing_key(vk)` sets `None` and derives `address`/`scan_key` from `vk`.
     - `spend_key()` errors with "this wallet is a private multisig account: spend with `rand multisig-private`".
     - Replace the three `&w.sk` uses (`wallet.rs:2054`, `2287`, `2880`) with `w.spend_key()?`. Fix every other use the compiler lists in both `main.rs` files. Tests comparing `.sk` compare `Option`s.
     - Add `AuthWitness`. `prove_auth_locally(prepared, auth: AuthWitness, binding, profile, backend)` dispatches: `Key(sk)` → `prove_auth`; `Multisig(words)` → `run_msauth` (refuse on `Err`), then `prove_msauth` (CPU), then `check_published_auth`. The print line says "tier 18; minutes" for the multisig variant. `Proving::prove` takes `AuthWitness` in place of `&SpendKey`.
     - Make `Prepared` and its fields `pub(crate)`, plus `prepare_bundle`, `build_bundle`, `prove_transaction_by`, `scanned_binding_domain` and `chain_bundle_guest`.
  2. `msig_private.rs`, every function in the Interfaces block:
     - `Policy::check` applies spec §6.1's rules, with `M_MAX`/`N_MAX` from the vendored `msauth`. `Policy::new` draws `msk` with `wallet::fresh_word()`.
     - The JSON is `{version: 1, threshold, signers: [hex], msk: hex}`. `save` and `load` use the key-file mode rules (`Wallet::load`'s unix check, verbatim).
     - `Proposal::from_prepared(policy, prepared, tx, binding, chain_id, genesis, binding_domain_version, expires_at)` fills every field: `summary` from the plan's payee, amount, fee and memo; `signing_message = msauth::signing_message(binding)`.
     - `prepare`:
       - require `rand_status.hc_bundle == hc_hidden_bundle_v3` and `rand_status.hc_auth_multisig == ZkExecutor::hc_auth_multisig()`, else "this chain has no private multisig (hc_auth_multisig) for this build";
       - `scan(rpc, &policy.wallet(), store)`;
       - `Plan::select` with `Spend { asset: 0, to: Some((to, amount)), memo, fee, burn_a: 0, burn_r: 0, prover_fee: None }`;
       - `rpc.envelope_format(chain_id)`, `prepare_bundle(…, &hc_hidden_bundle_v3())`;
       - `Transaction::shielded(chain_id, prepared.bundle.clone(), Action::None)`, `binding = tx.binding(&scanned_binding_domain(…))`;
       - `expires_at = time + limits.proof_window_blocks.unwrap_or(256)`.
     - `prepare_sweep`: the same, with `amount = store.balance() - fee`; refuse when the plan needs more than two RAND inputs, with "send to yourself first to merge".
     - `sign`, per spec §6.5:
       - decode `tx` (bincode hex); rebuild `BindingDomain::for_version(binding_domain, genesis)` (`ChainId` for version 0);
       - compare the recomputed binding with `binding` ("the transaction does not hash to the proposal's binding") and `signing_message`;
       - check `auth_commit == msauth::auth_commit(&policy.nk(), &salt)` ("the proposal's auth_commit is not this policy's account");
       - open each output envelope with `env.open_as_sender_with(cm, &wallet.scan_key)` and require the opened note's commitment equal the bundle's commitment in that slot;
       - build the summary lines (`"{n}: {amount} RAND to {fingerprint} memo {memo:?}"`, `"fee {fee} RAND"`) and print them to stderr in the CLI;
       - find the key's index in `policy.signers` (else "this key is not one of the policy's signers") and sign `signing_message` with `Keypair::sign`.
     - `assemble_witness`:
       - parse and sort the shares by index; drop duplicates with an error ("signer {i} appears twice");
       - verify each with `policy.signers[i].verify(msg, sig)` ("signer {i}'s signature does not verify over this proposal");
       - require `count >= threshold` ("{count} signature(s), the policy needs {threshold}"); keep the lowest `M_MAX`;
       - build `Slot { index, pk, sig, path: paths[index] }` from `signer_tree(&policy.pks())`;
       - return `msauth_inputs(&policy.msk, &salt, threshold, &slots)`.
     - `prove`:
       - refuse if `rpc` head ≥ `expires_at - 16`. (`prove` takes no rpc; the CLI checks expiry before calling. Add an `expires_at` check in the CLI step of Task 7.)
       - rebuild `Prepared` from the proposal (`bundle_words`, `expected`, `salt`, `auth_commit`, v3 guest);
       - `assemble_witness`, then `Proving::prove(&prepared, AuthWitness::Multisig(&words), &binding, profile, cap)`;
       - set `bundle.proof` and `bundle.auth_proof` on the decoded `tx`; recompute `tx.binding(domain)` and require it unchanged; return `tx`.
  3. In `lib.rs`, add `pub mod msig_private;`.

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-client --lib
cargo +1.98.1 test --release -p randprotocol-node --bin rand-node
cargo +1.98.1 build --release -p randprotocol-client -p randprotocol-node
```

Expected: all pass, including every existing wallet test, which still uses `Wallet::from_spend_key`.

- [ ] **Step 5: Commit.**

```bash
git add crates/randprotocol-client crates/randprotocol-node/src/main.rs
git commit -m "wallet: a spend-key-less Wallet (from_viewing_key), the multisig auth witness, and msig_private — Policy (0600, the guest's nk), Proposal, sign (recomputes the binding, opens every output as sender), assemble_witness (threshold, distinct indices, native verify, emulator run), prove (msauth local)"
```

---

### Task 7: CLI: `rand multisig-private new-policy|address|balance|prepare|sign|prove|submit`

**Files:**
- Modify: `crates/randprotocol-client/src/main.rs`
- Modify: `docs/cli.md` (the command section)

**Interfaces:**
- Consumes: Task 6's `msig_private::*`, `wallet::load_authority_key`, `wallet::submit_refused`/settle path, `proving_for`.
- Produces:
  ```rust
  enum Cmd { /* … */ MultisigPrivate(MultisigPrivateCmd) }
  #[derive(Subcommand)] enum MultisigPrivateCmd {
      NewPolicy { #[arg(long = "signer", required = true)] signers: Vec<String>, #[arg(long)] threshold: u32, #[arg(long, default_value = "policy.json")] out: PathBuf },
      Address { #[arg(long)] policy: PathBuf },
      Balance { #[arg(long)] policy: PathBuf, #[arg(long)] store: Option<PathBuf> },
      Prepare { #[arg(long)] policy: PathBuf, #[arg(long, conflicts_with = "sweep_to")] to: Option<String>, #[arg(long, requires = "to")] amount: Option<String>,
                #[arg(long)] sweep_to: Option<String>, #[arg(long, default_value = "")] memo: String, #[arg(long)] fee: Option<String>,
                #[arg(long, default_value = "proposal.json")] out: PathBuf, #[arg(long)] store: Option<PathBuf> },
      Sign { #[arg(long)] proposal: PathBuf, #[arg(long)] policy: PathBuf, #[arg(long)] key: PathBuf },
      Prove { #[arg(long)] proposal: PathBuf, #[arg(long)] policy: PathBuf, #[arg(long = "signature", required = true, value_name = "INDEX:HEX")] signatures: Vec<String>,
              #[arg(long, default_value = "proposal.tx")] out: PathBuf, #[arg(long)] cuda: bool },
      Submit { #[arg(long)] tx: PathBuf, #[arg(long)] no_wait: bool },
  }
  ```

- [ ] **Step 1: Write the failing test.** In `main.rs`'s tests, beside `the_multisig_commands_parse_with_their_documented_flags`:

```rust
#[test]
fn the_multisig_private_commands_parse_with_their_documented_flags() {
    let k = "ab".repeat(1312);
    let Ok(Cmd::MultisigPrivate(MultisigPrivateCmd::NewPolicy { signers, threshold, out })) =
        parse(&["multisig-private", "new-policy", "--signer", &k, "--signer", &k, "--threshold", "2"]) else { panic!() };
    assert_eq!((signers.len(), threshold, out), (2, 2, PathBuf::from("policy.json")));
    assert!(matches!(parse(&["multisig-private", "address", "--policy", "p.json"]), Ok(Cmd::MultisigPrivate(MultisigPrivateCmd::Address { .. }))));
    let Ok(Cmd::MultisigPrivate(MultisigPrivateCmd::Prepare { to, amount, sweep_to, out, .. })) =
        parse(&["multisig-private", "prepare", "--policy", "p.json", "--to", "rand1x", "--amount", "1.5"]) else { panic!() };
    assert_eq!((to.as_deref(), amount.as_deref(), sweep_to, out), (Some("rand1x"), Some("1.5"), None, PathBuf::from("proposal.json")));
    assert!(parse(&["multisig-private", "prepare", "--policy", "p.json", "--to", "rand1x", "--sweep-to", "rand1y"]).is_err(), "one or the other");
    assert!(parse(&["multisig-private", "sign", "--proposal", "x", "--policy", "p", "--key", "k"]).is_ok());
    let Ok(Cmd::MultisigPrivate(MultisigPrivateCmd::Prove { signatures, .. })) =
        parse(&["multisig-private", "prove", "--proposal", "x", "--policy", "p", "--signature", "0:aa", "--signature", "2:bb"]) else { panic!() };
    assert_eq!(signatures, ["0:aa", "2:bb"]);
    assert!(parse(&["multisig-private", "prove", "--proposal", "x", "--policy", "p"]).is_err(), "at least one --signature");
    assert!(parse(&["multisig-private", "submit", "--tx", "t"]).is_ok());
}
```

- [ ] **Step 2: Run it to see it fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-client --bin rand the_multisig_private_commands_parse 2>&1 | tail -5
```

Expected: compile error (no `MultisigPrivate`).

- [ ] **Step 3: Implement** the enum and its handlers. Each one is a thin call into `msig_private`:
  - `new-policy`: parse the keys with `PublicKey::from_hex`; warn on stderr for each key that `rpc.multisig_signer_reused(pk)` reports. That check is skipped when no `--rpc` node answers, and it uses `rand_getMultisig` over the accounts the node lists. Then `Policy::new` and `save`, and print the address and fingerprint.
  - `address`: print `rand1…`, the fingerprint and `policy` hex.
  - `balance`: `scan` into the store (`--store`, default `<policy>.notes.json`) and print it.
  - `prepare`: `prepare` or `prepare_sweep`, `save_proposal` (0600), then print the summary and "gather ≥ T signatures and prove before height {expires_at}".
  - `sign`: `load_authority_key`, then `sign`. Print the summary lines to stderr and `index:hex` to stdout.
  - `prove`:
    - read `rand_status.height` and refuse at or past `expires_at - 16` ("prepare again");
    - use `proving_for(cli.prover, cuda, cli.cpu, …)` for the bundle;
    - `prove`, then write the transaction (bincode hex, 0600), and print both proofs' sizes.
  - `submit`: `rpc.send_transaction(&tx).await.map_err(crate::submit_refused)?`, then `wait_for_transaction` unless `--no-wait`, and print the hash.
  - `docs/cli.md`: a `## rand multisig-private` section with the seven commands, the 2-of-3 walk-through (new-policy → address → prepare → sign ×2 → prove → submit), the expiry window, and "the auth proof is proved on this machine (tier 18: minutes, ≥ 48 GB)".

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-client --bin rand
cargo +1.98.1 run --release -p randprotocol-client --bin rand -- multisig-private --help
```

- [ ] **Step 5: Commit.**

```bash
git add crates/randprotocol-client/src/main.rs docs/cli.md
git commit -m "cli: rand multisig-private new-policy|address|balance|prepare|sign|prove|submit"
```

---

### Task 8: Real-proof end to end on a test chain

**Files:**
- Modify: `crates/randprotocol-client/tests/wallet_flow.rs`

**Interfaces:**
- Consumes: Tasks 1–7; `node::start` via `start_with`; `genesis_v3`; `proving_slot`; `wallet::payout_note_for`; `multisig_pay_tx` (this file).
- Produces: `a_private_multisig_receives_spends_rotates_and_refuses_one_signature_end_to_end` (ignored).

- [ ] **Step 1: Write the failing test.** Append to `wallet_flow.rs`:

```rust
/// The chain the private-multisig end to end runs on: split authorisation plus the multisig auth
/// guest, chain-21's proof and block caps, a `gas` section (so R-gas is checked on real proofs),
/// and a `multisig` section seeding one public 2-of-3 account with 20 RAND (for the MultisigPay leg).
fn genesis_private_multisig(validator: &Keypair, public_signers: &[Keypair]) -> Genesis {
    use randprotocol_core::ledger::multisig::{MultisigAccountConfig, MultisigConfig};
    Genesis {
        hc_auth_multisig: Some(word8_to_hex(&ZkExecutor::hc_auth_multisig())),
        max_proof_bytes: Some(4 << 20),
        max_block_bytes: Some(20 << 20),
        gas: Some(gas::GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: gas::bundle_gas_limit_pin(), metering: gas::GasMetering::Circuit, dynamic: None }),
        multisig: Some(MultisigConfig {
            create_fee: 0,
            accounts: vec![MultisigAccountConfig { salt: [33; 32], signers: public_signers.iter().map(|k| k.public_key().clone()).collect(), threshold: 2, balance: 20 * UNITS_PER_RAND }],
        }),
        ..genesis_v3(validator)
    }
}

/// Private multisig phase 4's gate (spec §7.1), with real proofs: a 2-of-3 private address
/// receives, spends with signers 0 and 2, refuses a 1-signature attempt (in the wallet, and at the
/// node as AuthMismatch), receives a public MultisigPay, and rotates (sweeps) to a new policy
/// with signers 1 and 2. About four bundle proofs and three tier-18 msauth proofs on the Test profile.
///
/// Run on a >= 48 GB machine:
/// `cargo +1.98.1 test --release -p randprotocol-client --test wallet_flow -- --ignored --nocapture a_private_multisig`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real proofs, three of them tier 18: run on a >= 48 GB machine"]
async fn a_private_multisig_receives_spends_rotates_and_refuses_one_signature_end_to_end() {
    use randprotocol_client::msig_private::{self, Policy, Share};
    use randprotocol_core::ledger::multisig::account_id;
    use randprotocol_core::ledger::program_state::Payout;
    use randprotocol_zkvm::executor::{decode_canonical, prove_msauth, ZkExecutor};

    init_tracing();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([121; 32]).unwrap();
    let public: Vec<Keypair> = [91u8, 92, 93].iter().map(|s| Keypair::from_seed([*s; 32]).unwrap()).collect();
    let handle = start_with(&dir, &key, genesis_private_multisig(&key, &public)).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    let cpu = Proving::local(Backend::Cpu);
    assert_eq!(rpc.limits().await.unwrap().unwrap().hc_auth_multisig, Some(word8_to_hex(&ZkExecutor::hc_auth_multisig())));

    // ---- a 2-of-3 private policy; the faucet pays its address ----
    let k: Vec<Keypair> = [101u8, 102, 103].iter().map(|s| Keypair::from_seed([*s; 32]).unwrap()).collect();
    let policy = Policy::new(k.iter().map(|k| k.public_key().clone()).collect(), 2).unwrap();
    let account = policy.wallet();
    let mut store = NoteStore::default();
    let hash = rpc.mint_shielded(&account.address.to_string(), Some(100 * UNITS_PER_RAND)).await.unwrap();
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.unwrap();
    wallet::scan(&rpc, &account, &mut store).await.unwrap();
    assert_eq!(store.balance(), 100 * UNITS_PER_RAND, "the account's own scan finds the mint");

    // ---- spend 10 RAND to B with signers 0 and 2 ----
    let b = Wallet::from_spend_key(SpendKey([77; 8]));
    let fee = gas::BUNDLE_BASE;
    let prop = msig_private::prepare(&rpc, &policy, &mut store, &b.address, 10 * UNITS_PER_RAND, "rent", fee, CHAIN_ID).await.unwrap();
    let shares: Vec<Share> = [0usize, 2].iter().map(|&i| msig_private::sign(&prop, &policy, &k[i]).unwrap().0).collect();
    let slot = proving_slot().await;
    let tx = msig_private::prove(&prop, &policy, &shares, &cpu, FriProfile::Test).await.unwrap();
    drop(slot);
    let auth = &tx.bundle.as_ref().unwrap().auth_proof;
    let hdr = decode_canonical(auth).unwrap();
    let s = ZkExecutor::msauth_heights();
    assert_eq!((hdr.tier.0, hdr.keccak_log_height, hdr.modq_log_height, hdr.mem_log_height), (s.tier, s.keccak_log_height, s.modq_log_height, s.mem_log_height), "R-hide");
    assert_eq!(hdr.public_values[randprotocol_zkvm::tables::cpu::pv::GAS], gas::msauth_gas_limit_pin(), "R-gas");
    let h = rpc.send_transaction(&tx).await.expect("a 2-of-3 spend is admitted");
    rpc.wait_for_transaction(&h, Duration::from_secs(120)).await.expect("and commits");
    let mut b_store = NoteStore::default();
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), 10 * UNITS_PER_RAND, "B finds the payment");
    wallet::scan(&rpc, &account, &mut store).await.unwrap();
    assert_eq!(store.balance(), 90 * UNITS_PER_RAND - fee, "and the account its change");

    // ---- one signature: refused by the wallet, and by the node when forced ----
    let prop1 = msig_private::prepare(&rpc, &policy, &mut store, &b.address, UNITS_PER_RAND, "", fee, CHAIN_ID).await.unwrap();
    let one = vec![msig_private::sign(&prop1, &policy, &k[0]).unwrap().0];
    let e = msig_private::prove(&prop1, &policy, &one, &cpu, FriProfile::Test).await.unwrap_err().to_string();
    assert!(e.contains("1 signature") && e.contains("needs 2"), "{e}");
    // Forced: the witness with one active slot, proved anyway, publishes the sentinel.
    let mut forced = randprotocol_zkvm::msauth::msauth_inputs(&policy.msk, &msig_private::parse_word8(&prop1.salt).unwrap(), 2, &[
        msig_private::slot_for(&prop1, &policy, &one[0]).unwrap(),
    ]);
    forced.truncate(randprotocol_zkvm::msauth::MSAUTH_WORDS);
    let binding = msig_private::parse_binding(&prop1.binding).unwrap();
    let slot = proving_slot().await;
    let (sentinel_proof, c, _) = prove_msauth(FriProfile::Test, &forced, &binding).unwrap();
    let mut tx1 = msig_private::prove_bundle_only(&prop1, &cpu, FriProfile::Test).await.unwrap();
    drop(slot);
    assert_eq!(c[7], randprotocol_zkvm::executor::MSAUTH_REFUSAL);
    tx1.bundle.as_mut().unwrap().auth_proof = sentinel_proof;
    let refused = rpc.send_transaction(&tx1).await.unwrap_err().to_string();
    assert!(refused.contains("different commitment"), "AuthMismatch: {refused}");

    // ---- a public MultisigPay from the seeded account into the private address ----
    let genesis = rpc.genesis_hash().await.unwrap();
    let id = account_id(CHAIN_ID, &[33; 32], 2, &public.iter().map(|k| k.public_key().clone()).collect::<Vec<_>>());
    let time = rpc.status().await.unwrap()["height"].as_u64().unwrap() as u32;
    let format = rpc.envelope_format(CHAIN_ID).await.unwrap();
    let (note, envelope) = wallet::payout_note_for(&b, &account.address, 5 * UNITS_PER_RAND, 0, time, format).unwrap();
    let pays = vec![Payout { asset: 0, amount: 5 * UNITS_PER_RAND, recipient: account.address.clone(), r: note.r, envelope }];
    let pay = multisig_pay_tx(&genesis, id, 0, time, pays, &[(0, &public[0]), (1, &public[1])]);
    let h = rpc.send_transaction(&pay).await.unwrap();
    rpc.wait_for_transaction(&h, Duration::from_secs(60)).await.unwrap();
    wallet::scan(&rpc, &account, &mut store).await.unwrap();
    let before_rotation = store.balance();
    assert_eq!(before_rotation, 95 * UNITS_PER_RAND - fee, "the MultisigPay landed in the private account");

    // ---- rotate: sweep everything to a new policy, signed by 1 and 2 ----
    let k2: Vec<Keypair> = [111u8, 112].iter().map(|s| Keypair::from_seed([*s; 32]).unwrap()).collect();
    let next = Policy::new(k2.iter().map(|k| k.public_key().clone()).collect(), 2).unwrap();
    let sweep = msig_private::prepare_sweep(&rpc, &policy, &mut store, &next.wallet().address, fee, CHAIN_ID).await.unwrap();
    let shares: Vec<Share> = [1usize, 2].iter().map(|&i| msig_private::sign(&sweep, &policy, &k[i]).unwrap().0).collect();
    let slot = proving_slot().await;
    let tx = msig_private::prove(&sweep, &policy, &shares, &cpu, FriProfile::Test).await.unwrap();
    drop(slot);
    assert_eq!(decode_canonical(&tx.bundle.as_ref().unwrap().auth_proof).unwrap().public_values[randprotocol_zkvm::tables::cpu::pv::GAS], gas::msauth_gas_limit_pin());
    let h = rpc.send_transaction(&tx).await.unwrap();
    rpc.wait_for_transaction(&h, Duration::from_secs(120)).await.unwrap();
    wallet::scan(&rpc, &account, &mut store).await.unwrap();
    assert_eq!(store.balance(), 0, "the old account is empty");
    let mut next_store = NoteStore::default();
    wallet::scan(&rpc, &next.wallet(), &mut next_store).await.unwrap();
    assert_eq!(next_store.balance(), before_rotation - fee, "the new policy holds the sweep");
    handle.shutdown().await;
}
```

The test needs three small public helpers in `msig_private`, so add them in this task:

```rust
pub fn parse_word8(hex: &str) -> Result<Word8>;
pub fn parse_binding(hex: &str) -> Result<[u32; TX_BINDING_WORDS]>;
pub fn slot_for(p: &Proposal, policy: &Policy, share: &Share) -> Result<randprotocol_zkvm::msauth::Slot>;   // pk, sig, path for one share
#[doc(hidden)] pub async fn prove_bundle_only(p: &Proposal, proving: &Proving, profile: FriProfile) -> Result<Transaction>;   // test-only: the bundle proof, auth_proof empty
```

- [ ] **Step 2: Run it to see it fail.**

```bash
cargo +1.98.1 test --release -p randprotocol-client --test wallet_flow --no-run 2>&1 | tail -5
```

Expected: compile error (no `slot_for`, `prove_bundle_only`, `parse_word8` or `parse_binding` yet).

- [ ] **Step 3: Implement** the four helpers in `msig_private.rs`:
  - `parse_word8` and `parse_binding` are the hex parsers `sign` already uses, made `pub`.
  - `slot_for` is one iteration of `assemble_witness`'s slot loop.
  - `prove_bundle_only` is `prove` without the auth half; it is `#[doc(hidden)]`, documented "never a wallet path".

- [ ] **Step 4: Run it to see it pass** (≥ 48 GB machine).

```bash
cargo +1.98.1 test --release -p randprotocol-client --test wallet_flow -- --ignored --nocapture a_private_multisig 2>&1 | tee /tmp/private-multisig-e2e.log
cargo +1.98.1 test --release -p randprotocol-client --test wallet_flow   # the non-ignored tests still pass
```

Expected: `test a_private_multisig_receives_spends_rotates_and_refuses_one_signature_end_to_end ... ok`. Record the wall time and peak RSS in the commit message.

- [ ] **Step 5: Commit.**

```bash
git add crates/randprotocol-client/tests/wallet_flow.rs crates/randprotocol-client/src/msig_private.rs
git commit -m "test: private multisig end to end with real proofs — a 2-of-3 address receives, spends with signers 0 and 2, refuses one signature (wallet and node AuthMismatch), takes a public MultisigPay, rotates with signers 1 and 2; R-gas and R-hide checked on the chain's bytes"
```

---

### Task 9: Extend `deploy/cut-chain21-genesis.sh` for `hc_auth_multisig`

**Files:**
- Modify: `deploy/cut-chain21-genesis.sh` (owned by randprotocol-d7)

**Interfaces:**
- Consumes: Task 3's `rand-node genesis --auth-multisig-guest`, Task 5's RPC fields, Task 2's `MSAUTH_HC`.
- Produces:
  - `EXPECT_HC_AUTH_MULTISIG` and `AUTH_MULTISIG_SKIPPED`;
  - the gate, the assertions, the probe variant, the check-limits read-back and the selftest refuse cases for `hc_auth_multisig`.

- [ ] **Step 1: Message randprotocol-d7 before editing.** Send:

  > Private multisig phase 4 needs `hc_auth_multisig` in `deploy/cut-chain21-genesis.sh`: a constant, the `--auth-multisig-guest` gate (DRY_RUN skips loudly), finished-file assertions, the chain-20 `excused` set, a 7th field-probe variant, a check-limits read-back, and five selftest refuse cases. May I edit it now, or do you want to apply the patch yourself?

  Wait for the answer. If d7 applies it, hand over Steps 2–3 as a patch and skip to Step 4. If chain 21 has already been cut, stop: the field goes to chain 22's script, and this task is re-targeted there.

- [ ] **Step 2: Write the failing selftest cases.** In the selftest block, after the multisig refuse cases at `deploy/cut-chain21-genesis.sh:1716-1718`, add:

```bash
  # the new field: hc_auth_multisig (private multisig phase 4)
  refuse "hc_auth_multisig absent"                 "$B" 'del d["hc_auth_multisig"]' "--auth-multisig-guest did not take"
  refuse "hc_auth_multisig not this build's"       "$B" 'd["hc_auth_multisig"] = "cd" * 32' "is not this build's multisig auth guest"
  refuse "hc_auth_multisig equal to hc_auth"       "$B" 'd["hc_auth_multisig"] = d["hc_auth"]' "must differ from hc_auth"
  refuse "max_proof_bytes under 4 MiB"             "$B" 'd["max_proof_bytes"] = 4194303' "cannot hold a multisig auth proof"
  refuse "hc_auth_multisig on chain 20's genesis"  "$G" 'd["hc_auth_multisig"] = "cd" * 32' "no fees, perps, multisig or hc_auth_multisig"
```

In the selftest's base fixture (`deploy/cut-chain21-genesis.sh:1540`, `base.update(...)`), add `hc_auth_multisig=E["EXPECT_HC_AUTH_MULTISIG"]`. Then update the order assertion at `:1604` to `list(g)[-10:] == [..., "multisig", "hc_auth_multisig"]` and the one at `:1606` to `list(g)[:-4]`.

Run: `SELFTEST=1 deploy/cut-chain21-genesis.sh 2>&1 | tail -20`. Expected: the five new cases report `accepted` or a wrong reason, so the selftest fails.

- [ ] **Step 3: Implement**, following the `multisig` section's pattern:
  1. **Constants** (after `EXPECT_HC_AUTH`, `:229`). Add `EXPECT_HC_AUTH_MULTISIG=${EXPECT_HC_AUTH_MULTISIG:-<MSAUTH_HC from crates/randprotocol-zkvm/tests/guest_provenance.rs>}`, written as the literal value of `MSAUTH_HC`. Add `AUTH_MULTISIG_SKIPPED_FROM_ENV=${AUTH_MULTISIG_SKIPPED:-}` and `AUTH_MULTISIG_SKIPPED=`. Export both. Keep `MAX_PROOF_BYTES` at 4194304, or 6291456 if Task 2 measured an msauth proof above 3 984 588 bytes.
  2. **Binary-flag gate** (after the `--multisig` gate, `:2140`):
     ```bash
     if ! grep -qE -- '(^|[[:space:]])--auth-multisig-guest([[:space:]=<]|$)' <<<"$HELP"; then
       if [ "${DRY_RUN:-}" = 1 ]; then
         AUTH_MULTISIG_SKIPPED=1; export AUTH_MULTISIG_SKIPPED
         echo "cut-chain21: ⚠⚠⚠ AUTH_MULTISIG SKIPPED ⚠⚠⚠ — $NODE genesis has no --auth-multisig-guest: the dry run goes on WITHOUT hc_auth_multisig; the REAL cut refuses this binary" >&2
       else
         echo "cut-chain21: $NODE genesis has no --auth-multisig-guest — a build before private multisig phase 4; hc_auth_multisig cannot be written" >&2; exit 1
       fi
     fi
     ```
     Pass `--auth-multisig-guest` to `rand-node genesis` unless `AUTH_MULTISIG_SKIPPED`.
  3. **Finished-file assertions** (`py_splice`, after the multisig block at `:1135`):
     ```python
     if E.get("AUTH_MULTISIG_SKIPPED"):
         need("hc_auth_multisig" not in g, "AUTH_MULTISIG_SKIPPED yet hc_auth_multisig is present")
         warnings.append("AUTH_MULTISIG SKIPPED — no private multisig on this chain; the real cut refuses such a rand-node")
     else:
         need("hc_auth_multisig" in g, "no hc_auth_multisig — --auth-multisig-guest did not take")
         need(g["hc_auth_multisig"] == E["EXPECT_HC_AUTH_MULTISIG"], f"hc_auth_multisig {g['hc_auth_multisig']} is not this build's multisig auth guest")
         need(g["hc_auth_multisig"] != g.get("hc_auth"), "hc_auth_multisig must differ from hc_auth")
         need(g["max_proof_bytes"] >= 4194304, f"max_proof_bytes {g['max_proof_bytes']} cannot hold a multisig auth proof (≥ 4194304)")
     ```
     Append `"hc_auth_multisig"` to `order` (`:1043`).
  4. **Chain-20 comparison.** Add `"hc_auth_multisig"` to `excused` (`:1207`). Make the `g20` sanity check refuse a chain-20 file carrying it, and widen its message to "no fees, perps, multisig or hc_auth_multisig section".
  5. **Field probe.** In `py_variants`, add `if "hc_auth_multisig" in g: drop("hc_auth_multisig", ["hc_auth_multisig"]); n += 1`. In `probe_fields`, loop `for s in FEES PERPS MULTISIG AUTH_MULTISIG`, and change the full count to `7`, with the message listing `hc_auth_multisig`.
  6. **check-limits read-back** (after `want("hc_auth", …)`, `:1400`): `want("hc_auth_multisig", L.get("hc_auth_multisig"), gen.get("hc_auth_multisig"))` and `want("status hc_auth_multisig", rpc("rand_status").get("hc_auth_multisig"), gen.get("hc_auth_multisig"))`.
  7. **Header and summary.** Add a `* THE NEW hc_auth_multisig FIELD` paragraph to the header comment, after the multisig one. Add `hc_auth_multisig $HC_AUTH_MULTISIG_REPORTED` to the final summary line (`:2335`), read like `HC_AUTH_REPORTED`. Add `hc_auth_multisig` to the cut record's `require_cut_record_mentions`.

- [ ] **Step 4: Run to see it pass.**

```bash
SELFTEST=1 deploy/cut-chain21-genesis.sh 2>&1 | tail -30
DRY_RUN=1 NODE=target/release/rand-node deploy/cut-chain21-genesis.sh 2>&1 | grep -E 'hc_auth_multisig|AUTH_MULTISIG|field probe|check-limits' | head -20
bash -n deploy/cut-chain21-genesis.sh
```

Expected:
- every selftest case is `ok`;
- the dry run on a Task-3 build prints 7 probe variants, the `hc_auth_multisig` assertions and the read-back;
- a dry run with `NODE` pointed at a pre-phase-4 build prints `AUTH_MULTISIG SKIPPED`.

- [ ] **Step 5: Commit.**

```bash
git add deploy/cut-chain21-genesis.sh
git commit -m "cut-chain21: hc_auth_multisig — the --auth-multisig-guest gate (DRY_RUN skips loudly), finished-file assertions (this build's guest, differs from hc_auth, ≥ 4 MiB proofs), excused from the chain-20 comparison, a 7th probe variant, read back from rand_getLimits/rand_status, five selftest refusals"
```

---

### Task 10: Docs and CHANGELOG

**Files:**
- Modify: `docs/shielded.md` (§2: a "Private multisig: the second auth guest" subsection after "Split authorisation"; §4 RPC fields), `docs/prover.md` (§8: the second auth guest, local-only), `docs/multisig.md` (a "Private accounts" section: private vs public, MultisigPay into a private address, rotation), `docs/rpc.md` (`hc_auth_multisig` on both methods, plus its changelog line), `docs/node-hardware.md` (Task 2's key-build and verify measurement), `docs/zkvm.md` (constraint set 9: the MODQ chip, proof-size deltas), `docs/deploy.md` (the cut's new field), `CHANGELOG.md`

**Interfaces:**
- Consumes: Tasks 1–9's measured values (Task 2's `MSAUTH-PROD:` line, Task 8's e2e times).
- Produces: documentation only.

- [ ] **Step 1: Write the failing check.** The docs carry the pinned facts, so add to `crates/randprotocol-zkvm/tests/guest_provenance.rs`:

```rust
/// The docs name the pinned multisig auth guest and its tier, as they do hc_auth.
#[test]
fn the_docs_name_the_multisig_auth_guest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let hc = word8_to_hex(&ZkExecutor::hc_auth_multisig());
    for doc in ["docs/shielded.md", "docs/prover.md", "docs/rpc.md"] {
        let text = std::fs::read_to_string(root.join(doc)).unwrap();
        assert!(text.contains("hc_auth_multisig"), "{doc} does not mention hc_auth_multisig");
    }
    let shielded = std::fs::read_to_string(root.join("docs/shielded.md")).unwrap();
    assert!(shielded.contains(&hc) && shielded.contains("tier 18"), "docs/shielded.md names the guest's digest and tier");
    let changelog = std::fs::read_to_string(root.join("CHANGELOG.md")).unwrap();
    assert!(changelog.contains("hc_auth_multisig") && changelog.contains("constraint set 9"), "CHANGELOG v0.8.0 carries the line");
}
```

Run: `cargo +1.98.1 test --release -p randprotocol-zkvm --test guest_provenance the_docs_name_the_multisig_auth_guest`. Expected: FAIL.

- [ ] **Step 2: Write the docs.**
  - **`docs/shielded.md`:**
    - the new subsection: the two shapes table (spec §3.1); the admission order (spec §3.2); what the chain sees (parent spec §5); the measured size; the pinned `hc_auth_multisig` digest and "tier 18";
    - §4: `hc_auth_multisig` on `rand_status`/`rand_getLimits`;
    - §7: delegated msauth proving is a follow-up.
  - **`docs/prover.md` §8:** one paragraph. The multisig auth proof is made on the wallet's machine only (tier 18, ≥ 48 GB, minutes). The bundle proof of a multisig spend may still go to a paired prover. A `MultisigAuth` witness kind is specified in the phase-4 spec §6.6 and is not built.
  - **`docs/multisig.md`:** "Private accounts". Public register against private policy (what each shows); a public `MultisigPay` can pay a private address; rotation is a sweep; the signing-domain separation (`rand-msauth-1`); and the key-reuse warning.
  - **`docs/rpc.md`:** both fields. Changelog line: "`rand_status`, `rand_getLimits`: `hc_auth_multisig` (hex, `null` without it)".
  - **`docs/node-hardware.md`:** the tier-18 key build and warm verify from Task 2's `MSAUTH-PROD:` line, and the peak RSS.
  - **`docs/zkvm.md`:** a "Constraint set 9: the MODQ chip" section. Every key moved; `Proof.modq_log_height`; chip-free proofs +≈1 KB; a modq table only in the msauth guest's proofs; calls refuse it.
  - **`docs/deploy.md`:** the cut's `hc_auth_multisig` and `--auth-multisig-guest`.

- [ ] **Step 3: Write the CHANGELOG line.** Under `## v0.8.0`'s "Chain 21 and later, by genesis section" list, add the spec §8 bullet verbatim, with `M_MAX` written as the Task 8 value and the measured proof size from Task 2. Then rewrite the "**Chain 20, rolled as a flag day**" bullet to the user's v0.8.0 decision (Global Constraints):
  - **(a):** "**Not for chain 20.** Constraint set 9 changes every verifier key and the proof encoding: this build refuses chains 18–20 at startup (`CHAINS_THIS_BUILD_CANNOT_RUN`). Chain 20 stays on v0.7.x until chain 21's cut."
  - **(b):** move the whole private-multisig bullet and the constraint-set-9 sentence to a new `## v0.9.0 — TAG_DATE` entry above v0.8.0, and leave v0.8.0's chain-20 bullet as it is.

  Also change the v0.8.0 header's vendoring sentence to name `$CIRCUITS`.

- [ ] **Step 4: Run to see it pass.**

```bash
cargo +1.98.1 test --release -p randprotocol-zkvm --test guest_provenance
cargo +1.98.1 test --release --workspace 2>&1 | tail -15
```

Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add docs CHANGELOG.md crates/randprotocol-zkvm/tests/guest_provenance.rs
git commit -m "docs: private multisig — the second auth guest (shielded §2, prover §8, multisig private accounts, rpc, zkvm constraint set 9, node-hardware's tier-18 key, deploy); CHANGELOG v0.8.0: hc_auth_multisig and the chain-20 consequence"
```
