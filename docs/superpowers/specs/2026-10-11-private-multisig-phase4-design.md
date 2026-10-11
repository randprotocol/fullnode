# Private multisig, phase 4: the fullnode integration

> Status: **design, 2026-10-11.** Nothing here is built. Parent spec (circuits):
> `docs/superpowers/specs/2026-10-11-private-multisig-design.md` (§4 as amended: tier **and every
> table height** pinned; every spend, 1-of-N included, pays `M_MAX`'s tier). MODQ chip spec
> (circuits): `docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md`, §6 "Fork impact".
> Plan: `docs/superpowers/plans/2026-10-11-private-multisig-phase4.md`.
>
> **Starts only after circuits Task 8** (the measured `MSAUTH_TIER` and `M_MAX`, the floors in
> `msauth::pinned_options()`) **and Task 9** (the merge with rVM phase 4 and the one recursion
> re-pin). Every number below marked *(Task 8)* is read from that commit, never estimated into code.

## 0. Summary

| question | answer |
|---|---|
| genesis | `hc_auth_multisig: Option<String>`, last struct field, hash-bound last (tag `b"hc_auth_multisig"`, after `aggregation_tree`), present-only. Requires `hc_auth`, must differ from it, and at the Production profile requires `max_proof_bytes ≥ MSAUTH_MIN_PROOF_BYTES` (4 MiB); the existing `3·max_proof_bytes + 1 MiB` block rule then covers bundle + msauth + call |
| admission | the ledger asks the executor for the auth proof's **shape** (a header decode): single-key → `hc_auth`, multisig → `hc_auth_multisig`, anything else → `InvalidAuthProof`. No wire, txid or binding change |
| verify | **reuse `verify_auth(hc, proof, binding)`**. `ZkExecutor` dispatches on `hc`: the build's msauth digest → the msauth path, otherwise the single-key path; each path pins its own full shape. The verify cache keys on `hc` (kind 2), so the two guests never share an entry. Two new trait methods, both header/warm-only and **required** (no default): `auth_proof_shape`, `warm_auth_multisig` — forwarded, never cached |
| gas (R-gas) | the msauth prover keeps the header ceiling; under a `gas` section admission requires `GAS == gas_max_with_modq(pinned header)`, the same function of public header words for every M. The run's exact gas is never required |
| shape (R-hide) | admission pins tier, program, input, keccak, sha256 (0), modq, public and memory heights exactly to `msauth_heights()`, before any key is built |
| proof size | ≈ **3.6 MB** at Production FRI (range 3.5–3.8 MB, §3.3); a multisig transfer ≈ 5.1 MB |
| wallet | `rand multisig-private new-policy / address / balance / prepare / sign / prove / submit`; the msauth proof is made **locally only** (delegated msauth proving is a follow-up, §6.6); the bundle proof may go to a paired prover as today |
| fork | the MODQ re-vendor changes every verifier key and the `Proof` encoding: this build runs chain 21 on and refuses chains 18–20 (`CHAINS_THIS_BUILD_CANNOT_RUN`, constraint set 9) |

## 1. What is fixed by the circuits side

From the circuits branch `feat/private-multisig` at the Task 9 merge (read-only here):

- `research/src/msauth.rs` (vendored as `crates/randprotocol-zkvm/src/msauth.rs`): tags
  `AUTH = 65`, `MS_LEAF = 66`, `MS_NODE = 67`, `MS_POLICY = 68`, `NK_MS = 69`; `N_MAX = 16`,
  `DEPTH = 4`, `M_MAX` *(Task 8: 3, or 2 if the tier-18 gate failed)*; `MSAUTH_WORDS =
  17 + M_MAX·967`; `leaf`, `signer_tree`, `policy`, `nk`, `auth_commit`, `signing_message`
  (`b"rand-msauth-1" ‖ binding LE` = 45 bytes), `Slot`, `msauth_inputs`; and from Task 8
  `MSAUTH_TIER: Tier` *(Task 8: `Tier(18)`)*, `pinned_options() -> ProveOptions` (the
  `min_{keccak,modq,mem}_log_height` of a full `M_MAX` run, `gas_limit: None`) and
  `poseidon2_permutations`.
- `guests-compiled/bin/msauth.bin` (+ `.sha256`): reads the binding with `read_public 0..8`, verifies
  M Dilithium2 signatures over `signing_message(binding)`, publishes `c = H(AUTH, nk ‖ salt)` in
  outputs 0..8; a refused witness publishes the guest-sdk sentinel `0xdead_beef` in output 7.
- The MODQ chip (syscall 8): the cpu table is 283 columns wide, `Proof` gains
  `modq_log_height: u8` after `sha256_log_height`, the key is the 7-tuple
  `(tier, program, input, keccak, sha256, modq, public)`, and the API grows `_with_modq` siblings
  (`verifier_key`, `check_declared_heights`, `log_ext_degrees`, `gas::gas_max`, `chips`,
  `max_constraint_degrees`). The six-argument originals keep their signatures and delegate with
  `modq_log_height = 0`. `MODQ_GAS = 168`. `pv::NUM` stays 35. `notes::domain` is unchanged
  (checked: the `pub mod domain` blocks of both trees are identical).

## 2. Genesis

### 2.1 The field

```rust
/// Private multisig (phase 4): the multisig auth guest's program commitment, 64 hex characters.
/// Present, an auth proof may also be of this guest's pinned shape … (doc as in §2)
#[serde(default, skip_serializing_if = "Option::is_none")]
pub hc_auth_multisig: Option<String>,
```

It is the **last** field of `Genesis` (after `aggregation_tree`), so a file that has it lists it
last, and a file without it serialises byte for byte as before. The ledger gets
`hc_auth_multisig: Option<Word8>` beside `hc_auth`, with `hc_auth_multisig()` /
`set_hc_auth_multisig()`. It is a genesis parameter, never state: `node::reload_ledger` restores it
on every restart beside `set_hc_auth` (a node that forgot it would refuse every multisig spend its
peers apply: a fork at its first restart).

### 2.2 Hash binding

Appended after `aggregation_tree` (the last tagged field today), present-only:

```rust
if let Some(h) = ledger.hc_auth_multisig() {
    commit.extend_from_slice(b"hc_auth_multisig");
    commit.extend_from_slice(&word8_to_bytes(&h));
}
```

Every genesis without it (chains 14–21 as cut so far) hashes as before.

### 2.3 `Genesis::validate`

In this order, after the `hc_auth` parse:

1. Not 64 hex characters → `GenesisError::BadHcAuthMultisig(String)` (raised in `build`, where
   `BadHcAuth` is).
2. `hc_auth` absent → `GenesisError::HcAuthMultisigWithoutHcAuth`. The multisig auth guest
   publishes the same `c` bundle guest v3 folds in, and only an `hc_auth` chain runs v3.
3. Equal to `hc_auth` → `GenesisError::HcAuthMultisigIsHcAuth`. Dispatch is by shape, and one
   digest cannot have two shapes.
4. **Proof cap.** At `fri_profile: "production"`, the effective `max_proof_bytes` (2 MiB default)
   must be at least `gas::MSAUTH_MIN_PROOF_BYTES = 4 << 20` →
   `GenesisError::ProofCapTooSmallForMsauth { proof, need }`. The ledger already caps
   `auth_proof.len() ≤ max_proof_bytes` (`ledger/mod.rs`, `ProofTooLarge`), so below this cap no
   multisig spend could ever land. The existing rule `max_block_bytes ≥ 3·max_proof_bytes + 1 MiB`
   (`gas::min_block_bytes(_, true)`, `BlockTooSmallForSplitAuth`) is unchanged: a transaction still
   carries at most three proofs (bundle, auth of either kind, call), each at most
   `max_proof_bytes`, so the block rule needs no new term. At the Test profile the rule does not
   apply (Test proofs are about a quarter of the size).

The node, which can name guests, adds at startup (`check_build_runs_genesis`, beside the
`hc_auth`/v3 pairing):

- `hc_auth_multisig` present and not `ZkExecutor::hc_auth_multisig()` → bail ("not this build's
  multisig auth guest; rebuild from the chain's pinned commit").

### 2.4 Tooling and RPC

- `rand-node genesis --auth-multisig-guest` (requires `--auth-guest`) writes
  `hc_auth_multisig = ZkExecutor::hc_auth_multisig()`, and the summary line prints it.
- `rand_status.hc_auth_multisig` and `rand_getLimits.hc_auth_multisig`: hex, or `null` on a chain
  without it. Always present, like `hc_auth`. A wallet reads it to decide whether a private
  multisig address can spend on this chain at all.

### 2.5 Fork impact: what this build can run

The re-vendor (§5) changes every verifier key (the cpu table gained a column) and the postcard
encoding of every proof (one byte). So this build verifies none of chain 18's, 19's or 20's
proofs, and its startup replay would refuse their history. `node::BUILD_CONSTRAINT_SET` becomes
`9`, and `CHAINS_THIS_BUILD_CANNOT_RUN` gains:

| chain | genesis hash | reason |
|---|---|---|
| 18 | `a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76` | `CONSTRAINT_SET_8_REASON` |
| 19 | `a3defc937d561d4beb1df9a08c9cb87a3dc32dadbfc2d1814ab6f627b0a2228a` | `CONSTRAINT_SET_8_REASON` |
| 20 | `6210cf071a390d7ac61d8cbea5dd9d139d1a493a862b54a45a498f36af2d5135` | `CONSTRAINT_SET_8_REASON` |

`CONSTRAINT_SET_8_REASON`: "its proofs were made under constraint set 8; this build is constraint
set 9 (the MODQ chip, v0.8.0 and later) and verifies none of them … Use the v0.7.x release for
chains 18–20."

**This contradicts the v0.8.0 draft in `CHANGELOG.md`**, which rolls v0.8.0 onto chain 20 as a
flag day "with no bundle verifier key change". A release cannot do both. The plan's Global
Constraints make this a decision the user takes before the re-vendor merges (§9).

## 3. Admission: dispatch on the auth proof's shape

### 3.1 The two shapes

| header word | single-key (`auth_heights()`) | multisig (`msauth_heights()`) |
|---|---|---|
| `tier` | `AUTH_TIER` = 10 | `MSAUTH_TIER` *(Task 8: 18)* |
| `program_log_height` | of `guests::auth()` | `program_log_height(msauth.bin words)` |
| `input_log_height` | `input_log_height(16)` | `input_log_height(MSAUTH_WORDS)` |
| `keccak_log_height` | 0 | `pinned_options().min_keccak_log_height` *(Task 8; ≈ 14 at `M_MAX` = 3)* |
| `sha256_log_height` | 0 | 0 |
| `modq_log_height` | 0 | `pinned_options().min_modq_log_height` *(Task 8; ≈ 16: 54 calls × 1 024 rows)* |
| `public_log_height` | `public_log_height(8)` | `public_log_height(8)` |
| `mem_log_height` | ranged (pinned by `non_canonical`) | `pinned_options().min_mem_log_height` *(Task 8)* — **exact** |
| `pv::GAS` | `gas_max(10,0,0)` = 1 279 under `gas` | `gas_max_with_modq(MSAUTH_TIER, k, 0, m)` under `gas` |

Every multisig field is compared **exactly**, including `mem_log_height` (R-hide: a multisig
proof's memory height would otherwise grow with M). The degree-bits vector must equal
`log_ext_degrees_with_modq` of the pinned shape (which is also the instance-count check), and
`public_values.len() == pv::NUM`. All of it runs before any verifier key is built, so a junk header
costs comparisons, never a tier-18 key build.

### 3.2 The ledger

`Ledger::check_auth_fields` (the cheap half, every path: admission, apply, verified-set hit,
pruned bundle) becomes:

```text
hc_auth None:  as today (AuthUnexpected / Ok)
hc_auth Some:  proof empty → AuthMissing
               shape = executor.auth_proof_shape(proof)          → InvalidAuthProof on Err
               shape == Multisig && hc_auth_multisig None        → InvalidAuthProof(InvalidProof("a multisig auth proof on a chain without hc_auth_multisig"))
               c = executor.auth_proof_digest(proof); c != auth_commit → AuthMismatch
               under gas: got = executor.auth_gas_limit(proof);
                          want = match shape { SingleKey => auth_gas_limit_pin(), Multisig => msauth_gas_limit_pin() }
                          got != Some(want) → AuthGasLimit { want, got }
               returns shape
```

`Ledger::verify_auth_proof` (the expensive half) takes that shape and calls

```rust
let hc = match shape { AuthShape::SingleKey => hc_auth, AuthShape::Multisig => hc_auth_multisig };
let c = executor.verify_auth(&hc, &b.auth_proof, binding).map_err(TxError::InvalidAuthProof)?;
```

then compares `c` with `auth_commit` as today. Every refusal stays permanent. No new `TxError`
variant: the shape refusal is an `InvalidAuthProof` naming itself, and the gas refusal is
`AuthGasLimit` with the multisig pin as `want`.

What is unchanged: the bundle wire, `auth_commit`, the v3 digest, `Transaction::binding` (which
blanks `auth_proof` and keeps `auth_commit`), `rand-txid-3` (which hashes the auth proof by
digest), pruning (the auth proof is never pruned), the `max_proof_bytes` cap and
`non_canonical_proofs` (which already runs on `auth_proof`).

### 3.3 Proof size and the block cap

Measured sizes in this repository at Production FRI (80 queries, blowup 8):

- the single-key auth proof, tier 10: about 1.37 MB (`docs/prover.md` §8);
- a v3 bundle proof, tier 14: 1.49 MB (`docs/shielded.md` §2), so about +30 KB per tier;
- a keccak-bearing proof: +1.91 MB for the keccak table's width (`docs/block-space.md` §1,
  `docs/zkvm.md`), whatever its height, because every query opens a full-width leaf;
- the modq table: about +75 KB (MODQ spec §6: 107 opened columns × 80 queries × 8 B).

So the msauth proof is ≈ 1.49 MB + 4 × 30 KB (tier 14 → 18) + 1.91 MB + 75 KB ≈ **3.6 MB**
(3.5–3.8 MB). Circuits Task 8 records the real figure (`research/docs/04-guests.md`). The rule
is `MSAUTH_MIN_PROOF_BYTES = 4 MiB` if the measured proof is at most 95 % of it (3 984 588 bytes).
Otherwise the constant becomes `6 << 20`, and chain 21's `MAX_PROOF_BYTES` 6 291 456. Its
20 MiB block still clears `3 × 6 MiB + 1 MiB = 19 MiB`.

A multisig transfer is therefore ≈ 5.1 MB of proof, about 3.5 times a single-key one's 2.85 MB.
Bundle bytes are not priced today (`settled_floor` is `fee_floor(action)` for every non-call
action), so it pays the same `BUNDLE_BASE`. That is a fee-policy question, recorded in §9, and not
changed here.

### 3.4 The executor's dispatch, and the verify cache

`ConfidentialExecutor` gains two **required** methods (no trait default):

```rust
/// Cheap: decode an auth proof canonically and name its pinned shape. `Err(InvalidProof)` for a
/// header that is neither shape. Verifies nothing.
fn auth_proof_shape(&self, proof: &[u8]) -> Result<AuthShape, ConfidentialError>;
/// Precompute the multisig auth guest's one verifier key. A node calls it only on a chain whose
/// genesis names `hc_auth_multisig`.
fn warm_auth_multisig(&self);
```

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthShape { SingleKey, Multisig }
```

They are required because every wrapper must forward them. With a default, `AggExecutor`, or
`CachingExecutor` from `feat/verify-cache`, would silently answer the default
(`agg_executor.rs:456` warns about exactly this). A missing forward is then a compile error.
Neither method verifies anything, so neither is cached and neither takes a kind tag: they join the
verify-cache spec's "forwards to `inner` unchanged" list (§3.2 there).

`auth_proof_digest(proof)` and `auth_gas_limit(proof)` keep their signatures. In `ZkExecutor` they
accept either pinned shape: they decode, match the header against the two shapes, and read the
public values. `verify_auth(hc, proof, binding)` keeps its signature and **dispatches on `hc`**:

```rust
fn verify_auth(&self, hc: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<Word8, ConfidentialError> {
    if *hc == Self::hc_auth_multisig() { self.verify_msauth_proof(hc, proof, binding) }
    else { self.verify_auth_proof(hc, proof, binding) }
}
```

Each path pins its own full shape before building a key. A single-key proof sent with the msauth
`hc` dies in the msauth shape check, and the reverse dies in the single-key one, so the two locks
(the ledger picks `hc` by shape, the executor picks the machine by `hc`) cannot disagree into a
verify. The program digest is bound in-circuit anyway.

**Verify cache.** `verify_auth` is already cached by `CachingExecutor` under kind 2, keyed by
`(hc, proof, binding)`. A multisig verify is cached automatically, and the `hc` in the key keeps
it apart from a single-key verdict over the same bytes, which is the verify-cache spec §4 test 4.
Nothing new is cached, and kind 9 is not used. If `feat/verify-cache` merges first, the plan's
admission task adds the two forwards to `CachingExecutor`. If it merges after, its own merge fails
to compile until it adds them, and the plan says so in the verify-cache owner's ledger.

### 3.5 Keys and memory

`ZkExecutor` gets a fourth `Machine`, `msauth_machine`, for the same reason `auth_machine` exists:
`decode_and_check` pins every component of the key, so this cache holds exactly one key
(`verifier_key_with_modq(MSAUTH_TIER, plh, ilh, klh, 0, mlh, pubh)`), and nothing a deploy, a
bundle or a single-key auth proof brings can evict it. `warm_auth_multisig` builds it.
`node::warm` calls it beside `warm_auth`, only when the committed ledger has `hc_auth_multisig`.

Cost, by extrapolation from `executor.rs`'s measured call keys (tier 16 ≈ 13.7 s / 893 MB, tier 20
≈ 216 s / 6.5 GB at Production, plus keccak's preprocessed columns): **roughly 60 s and 1.5–2 GB
peak** for the tier-18 msauth key. The validators are 2–4 GB droplets. The plan's executor task
includes an ignored Production measurement
(`measure_the_msauth_verifier_key_build_and_verify_at_the_production_profile`), recorded in
`docs/node-hardware.md`. **If the peak exceeds 1.5 GB above the node's baseline, stop and report**
before any cut carries the field.

## 4. The executor (`crates/randprotocol-zkvm`)

### 4.1 New items

```rust
// executor.rs
const NO_MODQ: u8 = 0;
pub const MSAUTH_TIER: usize = crate::msauth::MSAUTH_TIER.0;   // pinned by guest_provenance.rs
pub struct MsauthShape { pub tier: usize, pub program_log_height: u8, pub input_log_height: u8,
    pub keccak_log_height: u8, pub sha256_log_height: u8, pub modq_log_height: u8,
    pub public_log_height: u8, pub mem_log_height: u8 }
pub const MSAUTH_REFUSAL: u32 = 0xdead_beef;                     // guest-sdk's panic sentinel, output 7

impl ZkExecutor {
    pub fn msauth_program() -> &'static Program;                 // OnceLock(guests::compiled::msauth())
    pub fn hc_auth_multisig() -> Word8;                          // msauth_program().digest()
    pub fn msauth_heights() -> MsauthShape;
    pub fn auth_shape_of(proof: &[u8]) -> Result<AuthShape, ConfidentialError>;
    pub fn msauth_proof_commit(&self, proof: &[u8]) -> Result<Word8, ConfidentialError>;
    pub fn verify_msauth_proof(&self, hc: &Word8, proof: &[u8], binding: &[u32; TX_BINDING_WORDS]) -> Result<Word8, ConfidentialError>;
    pub fn cached_msauth_keys(&self) -> usize;
}
pub fn run_msauth(inputs: &[u32], binding: &[u32; TX_BINDING_WORDS]) -> Result<Word8, String>;      // emulator; Err on the sentinel
pub fn prove_msauth(profile: FriProfile, inputs: &[u32], binding: &[u32; TX_BINDING_WORDS]) -> Result<(Vec<u8>, Word8, u8), String>;
```

`prove_msauth` is `Machine::prove_with_options(msauth_program(), inputs, binding,
Some(Tier(MSAUTH_TIER)), msauth::pinned_options())`, CPU only (`prove_with` ignores options).
`pinned_options().gas_limit` is `None`, so the proof declares the header's ceiling (R-gas), and
`prove_msauth` refuses an `inputs.len() != MSAUTH_WORDS`. `guests::compiled::msauth()` is added by
hand to the hand-maintained `guests.rs`: `Program::from_flat_image(include_bytes!(
"../guests-compiled/bin/msauth.bin"))`, mirroring upstream's `compiled` module.

### 4.2 Changes to existing checks (the modq table must not leak into other proofs)

- `check_decoded`, exact case (bundle, single-key auth): also refuse `modq_log_height != NO_MODQ`
  (MODQ spec §6 item 5).
- `verify_call` / `verify_call_hardened` / `verify_invoke` / `check_perp`: refuse
  `modq_log_height != NO_MODQ` with `InvalidProof("a call proof declares no modq table")`
  **before** any key is built. Otherwise any caller could make a validator build modq-bearing call
  keys, which is the DoS the call tier cap closed. No deployed program issues `SYS_MODQ`.
- `non_canonical` and `honest_fri_arities`: `honest_fri_arities` uses
  `chips_with_modq(tier, k, s, clamped(modq))`. Without that, a modq-bearing proof's instance count
  never matches `chips`, the schedule is `None`, and the FRI-arity rule silently skips the msauth
  proof, leaving it malleable (VERIFIER-2). The memory ceiling becomes
  `hash_bearing_mem_log_height_ceiling_with_modq`, adding the modq table's traffic: five `MEMORY`
  interactions per row (MODQ spec §0). It applies when keccak, sha256 or modq is declared, and the
  plain-tier memory rule (`mem == t + 2`) only when all three are 0. The guard is a test that an
  honest msauth proof passes `non_canonical`, and that the msauth proof with its FRI arity forged
  does not.
- `decode_canonical` is unchanged. Postcard adds the byte, and the canonical re-encode compares it.

### 4.3 Pins (`tests/guest_provenance.rs`)

- `bin/msauth.bin` and `bin/msauth.bin.sha256` are in `SHA256SUMS`, and
  `each_circuits_pin_names_the_manifest_digest` covers `"msauth"`.
- `the_multisig_auth_guest_is_pinned`: `word8_to_hex(&ZkExecutor::hc_auth_multisig())` equals the
  `msauth.bin` program digest *(Task 8's guest commit)*. It is not a bundle guest's or `hc_auth`'s,
  and `MSAUTH_TIER == 18` *(Task 8)*.
- **What does not re-pin.** `hc_bundle` v1/v2/v3 and `hc_auth` are program digests. The re-vendor
  moves no guest program, so every existing digest pin stays byte for byte, and the test proves
  it. **What re-pins:** every verifier key (vendored `tests/verifier_key.rs`, from circuits),
  `inner_vk_digest` and `verify_rv32.digest` (vendored rvm `tests/pins.json`), the node's
  `aggregate_program_digest` pins, the recursion fixtures (`crates/randprotocol-node/fixtures/
  recursion/Test-{0,1,2}.proof` no longer decode and are re-proved by `scripts/recursion-fixtures.sh`,
  so the pinned-vectors digest `3534960f…` moves), and `CIRCUITS_PIN`.

## 5. The re-vendor (`deploy/sync-zkvm.sh`)

The circuits commit is the Task 9 merge on `feat/private-multisig`, or `origin/main` once it is
there. That commit must be pushed: `CUDA_REV` must be fetchable.

1. **Excludes.** Add `--exclude dilithium_host.rs` to the `src` rsync. It needs `dilithium-core`,
   which the node does not need: the wallet pre-checks with the guest itself in the emulator. Add
   `--exclude dilithium.rs --exclude modq_reference.rs` to the `tests` rsync: these are
   `dilithium-core`'s KAT suites, which need `dilithium_host`, `crystals-dilithium` and the
   `dilithium-verify` guest. `tests/msauth.rs` and `tests/modq.rs` are vendored (`modq.rs` is kept
   free of `dilithium-core` upstream; MODQ spec §6 item 1).
2. **Guests.** `for GUEST in fib keccak256 evm sbpf msauth`. `dilithium-verify.bin` is a
   measurement guest and is not vendored.
3. **Hand-maintained files.** `src/lib.rs` gains `pub mod modq;` and `pub mod msauth;`
   (`tables/mod.rs` is vendored and declares `tables::modq`). `src/guests.rs` gains
   `compiled::msauth()`.
4. **The `cheating` feature.** Upstream's self dev-dependency
   `rand_zkvm = { path = ".", features = ["cheating"] }` is in research's `Cargo.toml`, which is not
   copied. The fullnode's hand-maintained `crates/randprotocol-zkvm/Cargo.toml` does **not** mirror
   it. A self dev-dependency would unify `cheating` into every workspace test build, the node's
   included. Instead it declares `[features] cheating = []` (so the vendored
   `#[cfg(feature = "cheating")]` items compile out cleanly), plus
   `[[test]] name = "cheating" path = "tests/cheating.rs" required-features = ["cheating"]`, the
   one vendored test that calls the hooks (`forge_block`, `build_traces_forged`, `ModqAirWithout`,
   `call_unchecked`, `execute_unchecked_modq`, `memory_trace_forged`, `range_counts_without`).
   CI runs `cargo test -p randprotocol-zkvm --features cheating --test cheating`. The script gains
   a guard: if any vendored test other than `cheating.rs` names a hook, it fails. It also refuses
   any `features = ["cheating"]` in the copied `crates/randprotocol-rvm/Cargo.toml`.
5. **Dev-dependency.** `tests/msauth.rs` needs `crystals-dilithium`, so the zkvm crate gains
   `crystals-dilithium = { workspace = true }` under `[dev-dependencies]`. The workspace pins 2.0
   and `Cargo.lock` resolves 2.0.0, the oracle's version.
6. **Anchors, asserted unchanged.** The `verifier_key` six-argument anchor still matches (upstream
   kept the signature and added `verifier_key_with_modq`). The `notes::domain` inlining needs
   nothing new (`HC`, `IN`, `PUB` unchanged, and `msauth.rs`'s tags are its own constants). The
   script now prints `anchors: verifier_key 6-arg ok; notes::domain HC/IN/PUB ok` so the run log
   shows it.
7. **The rvm is re-vendored on purpose this time.** The script's tail re-syncs
   `crates/randprotocol-rvm` from `../circuits/recursion`. The usual trap, a re-vendor that should
   not move the rvm, is reverted with `git checkout -- crates/randprotocol-rvm`. Here it must
   **not** be reverted: the inner cpu width moved, so `verify_rv32.digest`, `tests/pins.json` and
   `inner_vk_digest` move with it, and that is exactly circuits Task 9's re-pin. Re-vendor the rvm
   from the **same** circuits commit (`RVM_SRC=../circuits/recursion` at the Task 9 merge). The
   script's last echo line (`pin 4a244b6`) becomes the new commit.
8. `CIRCUITS_PIN` in `.github/workflows/ci.yml`, both `PROVENANCE.md` files and the CUDA rev all
   name that commit. CI's guest-rebuild gate covers `msauth` (five guests).
9. Mirror `MODQ_GAS` and `gas_max_with_modq` in `randprotocol-core/src/gas.rs`.
   `the_cores_gas_max_mirror_matches_the_vendored_one` gains a modq sweep.

Out of scope here, and recorded for the clients repo: `clients/core` vendors the fullnode, and its
wallet core needs the new `Proof` field and keys (MODQ spec §6 item 7).

## 6. Wallet and CLI (`randprotocol-client`)

### 6.1 The policy file

```json
{ "version": 1, "threshold": 2, "signers": ["<1312-byte Dilithium2 pk, hex>", "…", "…"], "msk": "<64 hex>" }
```

`rand multisig-private new-policy --signer <PK_HEX>… --threshold T --out policy.json` draws a fresh
`msk` (8 words, OS entropy) and writes the file with mode 0600: it holds viewing power over the
account. `Wallet::load` already refuses group- or world-readable key files, and `Policy::load`
refuses them the same way. The policy is refused if `n = 0`, `n > N_MAX`, `T = 0`,
`T > min(n, M_MAX)`, or a key is repeated or not 1 312 bytes (parent spec §3). The command also
warns when a signer key is a public-register (`rand_getMultisig`) signer, because reuse links the
two accounts for anyone who knows both policies (parent spec §8 Q2). Every signer gets the same
file: the order of `signers` is the leaf order, so it is part of the address.

Derived: `signer_root = msauth::signer_tree(pks).0`, `policy = msauth::policy(T, root)`,
`nk = msauth::nk(msk, policy)`, `ViewingKey { nk }`, then the address, `ovk` and KEM keys exactly
as for a single-key wallet (`address_of(&vk)`). `Policy::fingerprint()` is the address's
fingerprint, which every signer compares out of band.

### 6.2 `Wallet` without a spend key

`Wallet.sk` becomes `Option<SpendKey>`, with `Wallet::from_viewing_key(vk)` (no spend key) and
`Wallet::spend_key(&self) -> Result<&SpendKey>` ("this wallet is a private multisig account:
spend with `rand multisig-private`"). Scanning (`scan`, the two-phase scan over
`rand_getScanLeaves` with `scan_key`), `NoteStore`, `Plan::select` and `build_bundle`'s v3 branch
read only `vk`, `scan_key` and `address`, so a multisig account reuses them unchanged. The v1/v2
branch and the auth proof take `spend_key()?`. The auth witness the provers take becomes

```rust
pub(crate) enum AuthWitness<'a> { Key(&'a SpendKey), Multisig(&'a [u32]) }   // the full MSAUTH_WORDS vector
```

and `prove_auth_locally` proves `prove_auth` or `prove_msauth` by variant.

### 6.3 The flow

| command | needs | does |
|---|---|---|
| `address --policy P` | P | prints `rand1…`, the fingerprint and `policy` hex |
| `balance --policy P` | P, node | scans as the account; prints balance and notes |
| `prepare --policy P --to ADDR --amount X [--memo M] [--fee F] --out prop.json`, or `--sweep-to ADDR` | P, node | checks the chain (`rand_status.hc_bundle` is v3, `hc_auth_multisig` is this build's), scans, selects notes, builds the v3 bundle with `nk` from P and a **fresh `salt`**, `auth_commit = msauth::auth_commit(nk, salt)`, places it in `Transaction::shielded(chain_id, bundle, Action::None)`, computes `binding = tx.binding(domain)` and `signing_message(binding)`, and writes the proposal (§6.4) with mode 0600. `--sweep-to` spends every note to ADDR minus the fee, refusing more than two RAND notes ("send to yourself first to merge"); it is how a rotation is done |
| `sign --proposal prop.json --policy P --key K [--index i]` | P, a signer key file; offline | re-derives everything it signs over (§6.5), prints the summary to stderr, then prints `i:<sig hex>` |
| `prove --proposal prop.json --policy P --signature i:hex… [--prover]` | P, ≥ T signatures, ≥ 48 GB | checks the shares (§6.5), assembles `msauth_inputs(msk, salt, T, slots)` with slots in ascending index order, each with `pk`, `sig` and the path from `signer_tree`; runs the guest in the emulator (`run_msauth`, refusing the sentinel or a `c ≠ auth_commit`); proves msauth locally (tier 18, minutes); proves the bundle locally or on the paired prover (the witness carries `nk`, as today); writes `prop.tx` (the transaction, bincode hex) |
| `submit --tx prop.tx [--no-wait]` | node | `rand_sendTransaction`, then the usual settle and rescan |

Both proofs are made against the binding computed at `prepare`. `prove` refuses if the chain head
is past `expires_at - 16` ("prepare again"). `expires_at` is the bundle's `time` plus the chain's
`proof_window_blocks`, 1 024 on chain 21, about 20 minutes at 1.17 s blocks. That is the window in
which signatures must be gathered and both proofs made.

### 6.4 The proposal file

JSON, `version: 1`, mode 0600: `chain_id`, `genesis` (hex), `binding_domain` (the version),
`policy` (hex of the policy hash, not `msk`), `tx` (bincode hex, both proofs empty),
`bundle_words` (hex: the v3 witness, which carries `nk` and the salt), `expected` (the v3 digest),
`salt`, `auth_commit`, `binding` (8 words hex), `signing_message` (45 bytes hex), `expires_at`, and
an informational `summary` (recipient, amount, fee, memo). The file holds viewing-level secrets
(`nk`, note openings) and nothing that can spend: spending also needs T signatures over this one
binding.

### 6.5 What `sign` and `prove` check

`sign` never signs an opaque hash. It decodes `tx` and checks:

- `tx.chain_id` and the proposal's `binding_domain` match;
- `tx.binding(domain) == binding`, and `signing_message(binding) == signing_message`;
- the bundle's `auth_commit == msauth::auth_commit(policy.nk(), salt)`, so the proposal spends
  from this policy's account;
- every output envelope opens **as sender** under the policy's scan key
  (`open_as_sender_with`), and the opened note's commitment is the bundle's commitment in that
  slot.

It shows each output's recipient, amount, asset and memo, and the fee, then signs
`signing_message` with the Dilithium2 key (`load_authority_key`, a `rand-node keygen` file). The
key's index is looked up in `policy.signers`, and a key not in the policy is refused.

`prove` checks every share's index is in range and distinct, each signature verifies natively
(`PublicKey::verify(signing_message, sig)`), and the count is at least T and at most `M_MAX`
(extra shares beyond `M_MAX` are dropped, lowest index first kept). A failure names the share.

### 6.6 Where the msauth proof is made: locally, and why delegation is a follow-up

Phase 4 proves the msauth proof only on the signer's own machine. Reasons:

- The MODQ ruling on tier 18 rests on "users proving their own auth proofs" (MODQ spec §4.3).
- The witness gives a prover `msk` and the policy, which is the account's viewing power (parent
  spec §5). That is acceptable, but it is a trust step the user should take explicitly.
- The prover wire keys a job by `hc_bundle` and knows one `WitnessKind` (`ViewingKey`). A
  `MultisigAuth` kind changes the sealed-job format, the prover's `hc_bundles`/`witness_kinds`
  advertisement and its memory class (a tier-18 job is about 33 GB), which is prover-pool sizing
  work of its own.
- The phase-4 gate does not need it.

**Follow-up, specified.** `WitnessKind::MultisigAuth`; the job carries `hc_auth_multisig`, the
`MSAUTH_WORDS` vector and the binding; the reply carries the proof, checked by
`ZkExecutor::msauth_proof_commit` against `auth_commit` and by `auth_proof_shape == Multisig`;
the prover advertises `auth_guests: [hc]`; and `rand multisig-private prove --auth-prover`. The
bundle proof can already be delegated today (`--prover`).

### 6.7 Scanning

The account's `nk` is `msauth::nk(msk, policy)`. `Wallet::from_viewing_key(ViewingKey { nk })`
gives `scan_key = vk.scan_key()` and the two-phase scan from main `0712a979` as is. Every signer
scans with its own copy of the policy. The default note store is `<policy file>.notes.json`, and
`--store` overrides it.

## 7. The cut

`deploy/cut-chain21-genesis.sh` belongs to another session. The plan's cut task begins with
"message randprotocol-d7 before editing", and extends it in the pattern the `multisig` section
set:

- **Constants:** `EXPECT_HC_AUTH_MULTISIG` = this build's digest *(Task 8 guest)*, and
  `MAX_PROOF_BYTES` re-checked against §3.3.
- **Binary-flag gate:** `rand-node genesis --help` must list `--auth-multisig-guest`. The real
  cut refuses a binary without it, and `DRY_RUN` skips loudly (`AUTH_MULTISIG_SKIPPED`).
- **Finished-file assertions:** `hc_auth_multisig == EXPECT_HC_AUTH_MULTISIG`; `hc_auth` present
  and different from it; `max_proof_bytes ≥ 4194304`; it is the last key; it is added to `order`.
- **Chain-20 comparison allowlist:** `excused` gains `hc_auth_multisig`.
- **Field probe:** a variant without `hc_auth_multisig` must hash differently. The expected count
  goes from 6 to 7.
- **check-limits read-back:** `rand_getLimits.hc_auth_multisig` and `rand_status.hc_auth_multisig`
  equal the file's.
- **Selftest refuse cases:** absent (gate on), not chain 20's flag set, equal to `hc_auth`, a
  `max_proof_bytes` under 4 MiB, a wrong digest.

### 7.1 The end-to-end gate (a test chain, real proofs)

`crates/randprotocol-client/tests/wallet_flow.rs`,
`a_private_multisig_receives_spends_rotates_and_refuses_one_signature_end_to_end`, is `#[ignore]`d
because it runs about 4 bundle proofs and 3 tier-18 msauth proofs and needs a machine with
≥ 48 GB. On a one-validator Test-profile chain with v3, `hc_auth`, `hc_auth_multisig`, a `gas`
section and a `multisig` section seeding one 2-of-3 public account:

1. A 2-of-3 private policy (signers K0, K1, K2) gets its address. The faucet mints 100 RAND to it,
   and the account's scan finds the note.
2. It spends 10 RAND to wallet B: `prepare`, `sign` by K0 and K2, `prove`, `submit`. The
   transaction commits, B scans and finds it, and the account's change note is found.
3. A 1-signature attempt: `prove` refuses before proving ("1 signature, the policy needs 2"). Then
   a test-only `prove_msauth` over the 1-slot witness publishes the sentinel; the transaction made
   with it is refused by the node with `AuthMismatch`.
4. A public `MultisigPay` from the seeded public account, signed by two of its signers, pays
   5 RAND to the private address. The account's scan finds it, from the transaction alone.
5. A rotation: a new policy (K3, K4, threshold 2, fresh `msk`); `prepare --sweep-to <new address>`
   signed by K1 and K2 (a different pair). It commits, the old account's balance is 0, and the new
   one's is the swept amount.
6. Every committed multisig auth proof's header equals `msauth_heights()`, and its `pv::GAS` equals
   `msauth_gas_limit_pin()` for both the 2-signature spends. That is R-gas and R-hide checked on
   the chain's own bytes.

## 8. CHANGELOG (v0.8.0)

Under "Chain 21 and later, by genesis section":

> - **Private multisig** (`hc_auth_multisig`): an M-of-N Dilithium2 policy hidden inside a second
>   auth guest (tier 18, the MODQ chip; `M_MAX` *(Task 8)*, `N_MAX` 16). Admission tells the two
>   auth guests apart by the proof's pinned shape, with no wire, txid or binding change; the chain
>   learns only "multisig-authorised". `rand multisig-private new-policy|address|balance|prepare|
>   sign|prove|submit`; the auth proof is proved locally (about 3.6 MB at Production FRI, so a
>   multisig transfer is about 5.1 MB). **Constraint set 9:** every verifier key and the proof
>   encoding change, so this build runs chain 21 on and refuses chains 18–20.

## 9. Risks and open points

1. **v0.8.0 and chain 20** (§2.5): the decision is the user's. Either v0.8.0 becomes chain-21-only
   and the chain-20 flag-day roll is withdrawn, or v0.8.0 is tagged before the re-vendor and this
   ships as v0.9.0 at the cut that carries it.
2. **Chain-21 timing.** If chain 21 is cut before this lands, `hc_auth_multisig` and the
   constraint-set change move to chain 22's script. The cut task then edits that script instead.
3. **The verifier key's memory on 2–4 GB validators** (§3.5): measured, with a stop rule.
4. **Byte pricing.** Bundle and auth bytes are unpriced, so a multisig transfer uses about 3.5 times
   the block space for the same floor. This is a fees follow-up, not phase 4.
5. **Proof size above 95 % of 4 MiB**: the constant and chain 21's cap move to 6 MiB (§3.3).
6. **Delegated msauth proving** (§6.6): a follow-up.
