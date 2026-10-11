# Private multisig, phase 4: the fullnode integration

> Status: **design, 2026-10-11.** Nothing here is built. Parent spec (circuits):
> `docs/superpowers/specs/2026-10-11-private-multisig-design.md` (§4 as amended: tier **and every
> table height** pinned; every spend, 1-of-N included, pays `M_MAX`'s tier). MODQ chip spec
> (circuits): `docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md`, §6 "Fork impact".
> Plan: `docs/superpowers/plans/2026-10-11-private-multisig-phase4.md`.
>
> **Amended 2026-10-11 after the pre-flight review** (4 Critical, 9 Important, all folded in; see
> §10 for the finding-to-section map). Two brief premises were corrected: `Transaction::binding`
> blanks **both** the bundle proof and the auth proof (so signing before proving is sound, and
> `salt`/`auth_commit` are fixed at `prepare`), and `deploy/sync-zkvm.sh` never copies research's
> `Cargo.toml`, so its `cheating` self dev-dependency has nothing to strip.
>
> **Starts only after circuits Task 8** (the measured `MSAUTH_TIER` and `M_MAX`, the floors in
> `msauth::pinned_options()`) **and Task 9** (the merge with rVM phase 4 and the one recursion
> re-pin). Every number below marked *(Task 8)* is read from that commit, never estimated into code.

## 0. Summary

| question | answer |
|---|---|
| genesis | `hc_auth_multisig: Option<String>`, last struct field, hash-bound last (tag `b"hc_auth_multisig"`, after `aggregation_tree`), present-only. Requires `hc_auth`, must differ from it, and at the Production profile requires `max_proof_bytes ≥ MSAUTH_MIN_PROOF_BYTES` (4 MiB); the existing `3·max_proof_bytes + 1 MiB` block rule then covers bundle + msauth + call |
| admission | the ledger asks the executor for the auth proof's **shape** (a header decode): single-key → `hc_auth`, multisig → `hc_auth_multisig`, anything else → `InvalidAuthProof`. No wire, txid or binding change |
| verify | **reuse `verify_auth(hc, proof, binding)`**. `ZkExecutor` dispatches on `hc`: the build's msauth digest → the msauth path, otherwise the single-key path; each path pins its own full shape. The verify cache keys on `hc` (kind 2), so the two guests never share an entry. Three new trait methods, all header/warm-only and **required** (no default): `auth_header`, `warm_auth_multisig`, `auth_multisig_key_ready` — forwarded, never cached |
| gas (R-gas) | the msauth prover keeps the header ceiling; under a `gas` section admission requires `GAS == gas_max_with_modq(pinned header)`, the same function of public header words for every M. The run's exact gas is never required |
| shape (R-hide) | admission pins tier, program, input, keccak, sha256 (0), modq, public and memory heights exactly to `msauth_heights()`, before any key is built |
| proof size | ≈ **3.6 MB** at Production FRI (range 3.5–3.8 MB, §3.3); a multisig transfer ≈ 5.1 MB |
| wallet | `rand multisig-private new-policy / address / balance / prepare / sign / prove / submit`; the msauth proof is made **locally only** (delegated msauth proving is a follow-up, §6.6); the bundle proof may go to a paired prover as today |
| fork | the MODQ re-vendor changes every verifier key and the `Proof` encoding: this build refuses chains 18–20 (`CHAINS_THIS_BUILD_CANNOT_RUN`, constraint set 9), and chain 21 too if it is cut before this lands (§9.2, a gate before any code) |
| key build | the tier-18 msauth key is built **once** (`OnceLock<Arc<CommonData>>`, single flight), warmed first; the mempool defers a multisig-shaped proof (retryable) until it is warm |

## 1. What is fixed by the circuits side

From the circuits branch `feat/private-multisig` at the Task 9 merge (read-only here):

- `research/src/msauth.rs` (vendored as `crates/randprotocol-zkvm/src/msauth.rs`): tags
  `AUTH = 65`, `MS_LEAF = 66`, `MS_NODE = 67`, `MS_POLICY = 68`, `NK_MS = 69`; `N_MAX = 16`,
  `DEPTH = 4`, `M_MAX` *(Task 8: 3, or 2 if the tier-18 gate failed)*; `MSAUTH_WORDS =
  17 + M_MAX·967`; `leaf`, `signer_tree`, `policy`, `nk`, `auth_commit`, `signing_message`
  (`b"rand-msauth-1" ‖ binding LE` = 45 bytes), `Slot`, `msauth_inputs`; and from Task 8
  `MSAUTH_TIER: Tier` *(Task 8: `Tier(18)`)*, `pinned_options() -> ProveOptions` (the
  `min_{keccak,modq,mem}_log_height` of a full `M_MAX` run, `gas_limit: None`),
  `poseidon2_permutations`, and `check_pinned_shape_with` / `prove_msauth`, which refuse before
  proving (naming the field) when a witness's natural heights differ from the pins.
- **Task 8's measured values (controller ruling, filled in):** `MSAUTH_TIER = 18`, `M_MAX = 3`.
  Five-fixture gate: at M = 3, 250 685–252 775 cycles, exactly 1 942 Poseidon2 permutations, the
  largest fixture inside tier 18 with 9 368 cycles to spare. Pinned heights: program 12, input 12,
  keccak 14, sha256 0, modq 16, public 7, mem 20. Because the prover hard-errors on any witness
  whose natural heights miss a pin, a pathological signature (an unusual hint count, say) makes a
  spend that cannot be proved: stuck and visible, never a leaked shape. Admission refuses any
  header off by one in any height or the tier (§3.1, tested).
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
3. Equal to `hc_auth`, compared as parsed `Word8`s (never as hex strings, so case or padding
   cannot slip one past) → `GenesisError::HcAuthMultisigIsHcAuth`. Dispatch is by shape, and one
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
- **RPC body cap.** `rpc_max_body_bytes` (`rpc.rs`) counts two proofs at the cap, arguing that the
  single-key auth proof is a small fixed shape (~1.36 MB). The msauth proof is ~3.6 MB, so on a
  genesis with `hc_auth_multisig` it counts **three** (bundle + msauth + call, each at
  `max_proof_bytes`): `rpc_max_body_bytes(max_proof_bytes, max_call_envelope_bytes,
  three_proofs: bool)`, and its doc says why.
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

If chain 21 has been cut (on constraint set 8) before this lands, chain 21 joins the table too, with
the same reason, and the field goes to chain 22: the plan checks this as a gate **before Task 1**,
because Task 1 alone already makes the build constraint set 9.

The v0.8.0 draft's "Rollback" paragraph (`CHANGELOG.md`, the `drop-perp-inputs` step back to
v0.7.1) no longer holds across a constraint set: a database written by a constraint-set-9 build
holds blocks v0.7.1 cannot verify, so "rollback" to v0.7.1 is only to a chain v0.7.1 runs. The
plan's Task 10 rewrites that paragraph (§8).

**Decided (user, option A, 2026-10-11):** v0.8.0 carries private multisig and runs chain 21 onward;
the draft's chain-20 flag-day roll is withdrawn.

## 3. Admission: dispatch on the auth proof's shape

### 3.1 The two shapes

| header word | single-key (`auth_heights()`) | multisig (`msauth_heights()`) |
|---|---|---|
| `tier` | `AUTH_TIER` = 10 | `MSAUTH_TIER` = 18 |
| `program_log_height` | of `guests::auth()` | 12 (`program_log_height(msauth.bin words)`) |
| `input_log_height` | `input_log_height(16)` | 12 (`input_log_height(MSAUTH_WORDS)`) |
| `keccak_log_height` | 0 | 14 (`pinned_options().min_keccak_log_height`) |
| `sha256_log_height` | 0 | 0 |
| `modq_log_height` | 0 | 16 (`pinned_options().min_modq_log_height`: 54 calls × 1 024 rows) |
| `public_log_height` | `public_log_height(8)` | 7 (`public_log_height(8)`) |
| `mem_log_height` | ranged (pinned by `non_canonical`) | 20 (`pinned_options().min_mem_log_height`) — **exact** |
| `pv::GAS` | `gas_max(10,0,0)` = 1 279 under `gas` | `gas_max_with_modq(MSAUTH_TIER, k, 0, m)` under `gas` |

Every multisig field is compared **exactly**, including `mem_log_height` (R-hide: a multisig
proof's memory height would otherwise grow with M). The degree-bits vector must equal
`log_ext_degrees_with_modq` of the pinned shape (which is also the instance-count check), and
`public_values.len() == pv::NUM`. All of it runs before any verifier key is built, so a junk header
costs comparisons, never a tier-18 key build. A ledger/executor test moves each of the eight
header words (and the tier) by one and expects `InvalidAuthProof` every time.

### 3.2 The ledger

The three cheap reads are one decode: a required trait method
`auth_header(proof) -> Result<(AuthShape, Word8, Option<u64>), ConfidentialError>` returns the
shape, the published `c` and the declared gas together (finding 14), replacing the separate
`auth_proof_shape` of the first draft; `auth_proof_digest`/`auth_gas_limit` stay for their
existing callers and accept either shape.

`Ledger::check_auth_fields` (the cheap half, every path: admission, apply, verified-set hit,
pruned bundle) becomes:

```text
hc_auth None:  as today (AuthUnexpected / Ok)
hc_auth Some:  proof empty → AuthMissing
               (shape, c, gas) = executor.auth_header(proof)    → InvalidAuthProof on Err
               shape == Multisig && hc_auth_multisig None        → InvalidAuthProof(InvalidProof("a multisig auth proof on a chain without hc_auth_multisig"))
               c != auth_commit → AuthMismatch
               under gas: got = gas;
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

`ConfidentialExecutor` gains three **required** methods (no trait default); the third, `auth_multisig_key_ready`, is in §3.5:

```rust
/// Cheap: decode an auth proof canonically once, name its pinned shape, and return the `c` it
/// publishes and its declared `pv::GAS`. `Err(InvalidProof)` for a header of neither shape.
fn auth_header(&self, proof: &[u8]) -> Result<(AuthShape, Word8, Option<u64>), ConfidentialError>;
/// Precompute the multisig auth guest's one verifier key. A node calls it only on a chain whose
/// genesis names `hc_auth_multisig`.
fn warm_auth_multisig(&self);
/// Whether that key is built (§3.5): admission defers a multisig proof, retryably, until it is.
fn auth_multisig_key_ready(&self) -> bool;
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
admission task adds the three forwards to `CachingExecutor`. If it merges after, its own merge fails
to compile until it adds them, and the plan says so in the verify-cache owner's ledger.

### 3.5 Keys and memory (single flight)

`ZkExecutor` gets a fourth `Machine`, `msauth_machine`, for the same reason `auth_machine` exists,
**and** the one msauth key is held in `msauth_key: OnceLock<Arc<CommonData<Config>>>`, built by
`get_or_init` (`verifier_key_with_modq(MSAUTH_TIER, plh, ilh, klh, 0, mlh, pubh)`). The vendored
`Machine` cache is FIFO without single flight here (`executor.rs:489-497`): four verify workers
plus the warm thread could each build a 1.5–2 GB key at once and OOM a 2–4 GB validator, and junk
msauth proofs with a correct header would trigger exactly that. With the `OnceLock` the key is
built once and every other caller waits for it. The verify path uses that key directly.

- `node::warm` calls `warm_auth_multisig` **first** (before the bundle and auth keys) when the
  committed ledger has `hc_auth_multisig`.
- The mempool: until the key is warm, admission **defers** a
  transaction whose `auth_header` is `Multisig` as a retryable refusal (never a permanent one, so
  the `RefusedCache` does not remember it), rather than building the key on a worker.
- Block validation (`on_proposal`, apply, sync, a restarted follower) waits on the `OnceLock`: the
  first caller builds, the rest wait; a node never builds two.

Naming: the **trait** method is `auth_multisig_key_ready(&self) -> bool` (required, forwarded by
every wrapper like the other two; the stub answers `true`). `ZkExecutor` implements it by calling
its **inherent** `msauth_key_ready()` (`self.msauth_key.get().is_some()`), the name the executor's
own tests use. The mempool's refusal is `MempoolError::Warming(&'static str)`, a new variant: not
`Invalid`, so never judged by `is_permanent`, never `RefusedCache`d, never a peer penalty, and
`MempoolError::is_retryable()` is `true` for it (and for `Full`).

Cost, by extrapolation from `executor.rs`'s measured call keys (tier 16 ≈ 13.7 s / 893 MB, tier 20
≈ 216 s / 6.5 GB at Production, plus keccak's preprocessed columns): **roughly 60 s and 1.5–2 GB
peak** for the tier-18 msauth key. The validators are 2–4 GB droplets. The plan's executor task
includes an ignored Production measurement
(`measure_the_msauth_verifier_key_build_and_verify_at_the_production_profile`), recorded in
`docs/node-hardware.md`. **Stop rule:** if the peak during the build, **or the resident memory after it**
(the key stays resident for the life of the process), exceeds 1.5 GB above a plain `rand-node`
baseline, stop and report before any cut carries the field.

**Measured (plan Task 2, commit `14904597`): the stop rule tripped.** The Production build took
78.6 s, with about 4.0 GB peak and about 4.0 GB resident after it (macOS). The fleet's validators
are `s-2vcpu-4gb`, and the user has ruled that the roll uses the current machines, so **no
validator builds this key at startup**. The key is precomputed instead (§3.6).

### 3.6 The precomputed msauth verifier key (plan Task 2b)

**What the key is.** The vendored type is `p3_batch_stark::CommonData<Config>`, which has two fields:

- `preprocessed: Option<GlobalPreprocessed>`: the global preprocessed **commitment** (a Merkle
  cap), plus per-instance `{matrix_index, width, degree_bits}` and `matrix_to_instance`;
- `lookups: Vec<Lookups<Val>>`, one per instance.

`CommonData` derives no `Serialize`. Of its contents, only the commitment is expensive: it is the
root over the low-degree extension of every table's preprocessed columns, which is where the 78 s
and the 4 GB go. The metadata and the lookups are symbolic functions of the AIRs and the pinned
heights, cheap to recompute. All of it is deterministic in the msauth program, the pinned shape
(`msauth_heights()`) and the FRI profile.

**The blob.** `msauth-vk-<profile>.bin` is `postcard` of
`MsauthVkBlob { version: 1, profile, shape: MsauthShape, hc: Word8, commitment: Commitment<Config>, instances: Vec<Option<(usize, usize, usize)>>, matrix_to_instance: Vec<usize> }`.
Its size is a few KB at most: a Merkle cap of a few 32-byte digests plus small vectors. Task 2b
measures it.

**Trust.** A wrong commitment could let a forged multisig proof verify, so the blob is
consensus-critical, like `hc`. Its blake3 is pinned in `tests/guest_provenance.rs` for both
profiles, and `warm_auth_multisig` refuses a blob whose digest is not the pinned one, or whose
`shape`, `hc` or profile is not this build's.

**Building it.** `rand-node keygen-msauth-vk --profile production --out <file>` runs on a big host
and does the full build once (78.6 s, about 4 GB). It extracts the commitment and metadata from the
built `CommonData` and writes the blob, printing its blake3.

**Loading it.** `ZkExecutor::install_msauth_vk(blob)` checks the digest, profile, `hc` and shape.
It then rebuilds the lookups and per-instance metadata from the AIRs: a `sync-zkvm.sh` patch to
`machine.rs`, anchored like `log_ext_degrees_pub`, adds
`Machine::verifier_key_with_modq_from_commitment(…7-tuple…, commitment) -> Arc<CommonData<Config>>`.
That function runs `from_airs_and_degrees`'s lookup/metadata half without the commit, and inserts
the result into the cache slot for the 7-tuple. The function also checks that the rebuilt metadata
equals the blob's. The result goes into the same single-flight `msauth_key` `OnceLock` and the
`Machine` slot, so `verify_public` finds it built.

**Where the blob comes from at startup, in order:**

1. `--msauth-vk <path>`.
2. `<datadir>/msauth-vk-<profile>.bin`.
3. `msauth-vk-<profile>.bin` beside the executable.
4. **Embedded.** If Task 2b measures the blob at ≤ 64 KB, it is committed at
   `crates/randprotocol-zkvm/keys/msauth-vk-{production,test}.bin` and `include_bytes!`'d, so a
   binary always carries its own. That is the expected case, and it makes items 1–3 overrides.
5. **None found.** Fall back to building only if `MemAvailable` (Linux `/proc/meminfo`;
   `sysctl hw.memsize` minus usage on macOS) exceeds 6 GB, logging loudly at `warn`. Otherwise the
   key stays absent: multisig spends are deferred (`MempoolError::Warming`), and a block carrying
   one stalls this node's apply rather than OOM-killing it. `rand_status` says why.

**Status.** `rand_status.msauth_key` is one of `"loaded"` (from a blob or embedded), `"built"`,
`"absent"` (multisig chain, no blob, not enough memory), or `"not_required"` (no
`hc_auth_multisig`).

**Release.** v0.8.0 ships `msauth-vk-production.bin` as a release asset, listed in `SHA256SUMS`
and signed. `deploy/roll-all.sh` copies it beside the binary on every host, and the cut checklist
lists it. Embedding (item 4) makes this belt-and-braces.

**Linux.** macOS libmalloc kept the 4 GB after the build. The load path never allocates the LDE,
so resident memory after a load should be small on any OS; glibc behaviour after a fallback build
may differ. Plan Task 8 and the cut rehearsal must **measure on an `s-2vcpu-4gb` droplet**: RSS
after load, and RSS after the first tier-18 verify, which has its own allocations.

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
- **`non_canonical`'s preprocessed-round count** (`executor.rs:276-284`) counts the preprocessed
  instances via `chips(tier, k, s)`, which omits the modq table's 16 preprocessed columns, so every
  honest msauth proof would be named non-canonical: refused by the mempool
  (`mempool.rs:665` → `admission.rs:1033`) and, under `hardening_v6` (chain 21), by consensus. It
  uses `chips_with_modq(tier, clamped(k), clamped(s), clamped(modq))`. A fast, non-ignored test: a
  tier-10 Test-profile proof with one modq block (circuits' `tests/common` modq fixture) has
  `non_canonical == None` and `honest_fri_arities == Some(_)`.
- **No modq-bearing inner proof is aggregated** (circuits Task 9b: `recursion/src` does not know
  the MODQ chip, so it verifies chip-free inner proofs only). Every aggregate/tree path refuses an
  inner proof with `modq_log_height != 0` where it decodes the inner header, before the rVM:
  `verify_aggregate`, `verify_tree`, `verify_tree`'s bottom-up recompute, the aggregator's cover
  assembly and the `decode_call` mirror. The refusal is `InvalidAggregateProof` (`InvalidProof` on
  calls), with one test per path on a tier-10, one-modq-block inner proof. Auth proofs (msauth
  included) are never aggregated, so a multisig spend is unaffected.
- `AggExecutor::decode_call` (`agg_executor.rs:466-512`) mirrors the call header checks itself; it
  gains the same `modq_log_height != 0` refusal.
- `const` asserts beside `MAX_HONEST_DEGREE_BITS` gain `tables::modq::MAX_LOG_HEIGHT`.
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
  so the pinned-vectors digest `3534960f…` moves), and `CIRCUITS_PIN`. Every pre-rVM-phase-4
  recursion digest and key is purged in the same commit and guarded by a test (§5 item 8).

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
   a guard over `tests/*.rs` **and `tests/common/*.rs`**: if any vendored file other than
   `cheating.rs` names a hook, it fails (circuits is moving `modq_harness` out from behind
   `cheating` so that this holds). The vendored `tests/modq.rs` therefore runs on the real
   `ModqAir`, never a hooked one. The guard also refuses any `features = ["cheating"]` in the copied
   `crates/randprotocol-rvm/Cargo.toml`. (Research's own `Cargo.toml`, with its self
   dev-dependency, is never copied; there is nothing to strip.)
5. **Dev-dependency.** `tests/msauth.rs` needs `crystals-dilithium`, so the zkvm crate gains
   `crystals-dilithium = { workspace = true }` under `[dev-dependencies]`. The workspace pins 2.0
   and `Cargo.lock` resolves 2.0.0, the oracle's version.
6. **Anchors, asserted unchanged.** The `verifier_key` six-argument anchor still matches (upstream
   kept the signature and added `verifier_key_with_modq`). The `notes::domain` inlining needs
   nothing new (`HC`, `IN`, `PUB` unchanged, and `msauth.rs`'s tags are its own constants). The
   script now prints `anchors: verifier_key 6-arg ok; notes::domain HC/IN/PUB ok` so the run log
   shows it.
7. **The circuits SHA** is the one randprotocol-3a names after rVM phase 4's final review, as
   merged into `feat/private-multisig` by circuits Task 9; it is not `origin/main`.
8. **The rvm is re-vendored on purpose this time.** The script's tail re-syncs
   `crates/randprotocol-rvm` from `../circuits/recursion`. The usual trap, a re-vendor that should
   not move the rvm, is reverted with `git checkout -- crates/randprotocol-rvm`. Here it must
   **not** be reverted: the inner cpu width moved, so `verify_rv32.digest`, `tests/pins.json` and
   `inner_vk_digest` move with it, and that is exactly circuits Task 9's re-pin. Re-vendor the rvm
   from the **same** circuits commit (`RVM_SRC=../circuits/recursion` at the Task 9 merge). The
   script's last echo line (`pin 4a244b6`) becomes the new commit.

   **rVM phase 4's silent semantic change (randprotocol-3a).** Phase 4 changed recursion opcodes 25
   and 27 (their 4th word is now an absolute address) **without changing the verifier key**. Any
   pre-phase-4 program digest, aggregate or tree digest, or pinned key would therefore keep
   verifying while meaning something else. In the **same commit** that bumps `CIRCUITS_PIN`, the
   re-vendor drops or re-records every one of them:
   - `inner_vk_digest` `346ee184…` (→ `1b0c4b00…` at the branch's post-9b HEAD, the vendored SHA,
     not `bba7875`) and the pinned-vectors digest `3534960f…`; `verify_rv32.digest` → `79ebe02b…`;
     the production `aggregate_program_digest` `e0eede8b…` → `8bc2cecb…` (production rows
     315 391, tier 19);
   - `verify_rv32.digest` `cf5a350a…` and `dsl-sample.digest` `8c77648e…`;
   - the sixteen `tree_test.vk_*` words, which are `agg_executor.rs`'s `PIN_VK_{LEAF,T_LEAF,INT,FIX}`;
   - every test `TreeConfig` step key in the node and core tests, and the recursion fixtures.

   A guard test, `crates/randprotocol-node/tests/no_pre_phase4_recursion_pins.rs`, asserts that
   none of the moved literals remains anywhere in the tree. The commit message names each digest
   that moved and why, and any value that did not move as invariant, with the reason. No committed
   genesis carries `aggregation_tree` today; if one did, its step pins would be consensus and the
   cut would have to be redone.
9. `CIRCUITS_PIN` in `.github/workflows/ci.yml`, both `PROVENANCE.md` files and the CUDA rev all
   name that commit. CI's guest-rebuild gate covers `msauth` (five guests).
10. Mirror `MODQ_GAS` and `gas_max_with_modq` in `randprotocol-core/src/gas.rs`.
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
| `prepare --policy P --to ADDR --amount X [--memo M] [--fee F] --out prop.json`, or `--sweep-to ADDR` | P, node | checks the chain (`rand_status.hc_bundle` is v3, `hc_auth_multisig` is this build's), scans, selects notes, builds the v3 bundle with `nk` from P and a **fresh `salt`**, `auth_commit = msauth::auth_commit(nk, salt)`, places it in `Transaction::shielded(chain_id, bundle, Action::None)`, computes `binding = tx.binding(domain)` and `signing_message(binding)`, and writes the proposal (§6.4) with mode 0600. Every output envelope, **dummies included**, is sealed with the account's `vk` as sender (a single-key wallet seals dummies under a throwaway key; here that would make them unopenable by the signers). `prepare` does **not** mark the selected notes pending: nothing is spent until a transaction commits, and an abandoned proposal must not hide notes from the next one. `--sweep-to` spends every **RAND** note to ADDR minus the fee, refusing more than two ("send to yourself first to merge"); it is how a rotation is done. Token notes are not swept (use `--to … --asset`), and the old address stays spendable by the old policy for any payment that arrives later |
| `sign --proposal prop.json --policy P --key K [--index i]` | P, a signer key file; offline | re-derives everything it signs over (§6.5), prints the summary to stderr, then prints `i:<sig hex>`. Warns if K is a validator consensus key (the key's address is in `rand_getValidators` when `--rpc` answers, or the file is a `rand-node` node key by path) |
| `prove --proposal prop.json --policy P --signature i:hex… [--prover]` | P, ≥ T signatures, ≥ 48 GB | checks the shares (§6.5), assembles `msauth_inputs(msk, salt, T, slots)` with slots in ascending index order, each with `pk`, `sig` and the path from `signer_tree`; runs the guest in the emulator (`run_msauth`, refusing the sentinel or a `c ≠ auth_commit`); proves msauth locally (tier 18, minutes); proves the bundle locally or on the paired prover (the witness carries `nk`, as today); writes `prop.tx` (the transaction, bincode hex) |
| `submit --tx prop.tx [--no-wait]` | node | `rand_sendTransaction`, then the usual settle and rescan |

Both proofs are made against the binding computed at `prepare`. The **CLI** `prove` reads the head
and refuses at or past `expires_at - 16` ("prepare again"); the library `prove` takes no RPC and
does not check (the e2e calls the library). `expires_at` is the bundle's `time` plus the chain's
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

**Where the checks live (user decision).** Every wallet app runs these checks through the clients
wasm/native core. So they form a pure crate, `randprotocol-msig`, re-exported as
`randprotocol_client::multisig_private`. It has no RPC, no filesystem, no OS entropy and no
prover/rocksdb/tokio, and it compiles for `wasm32-unknown-unknown`. Its API:

- `check_proposal(proposal_json, policy_json) -> ProposalSummary` runs every check below. The
  summary carries the outputs (recipient, amount, asset, memo), the fee, the burns, `expires_at`,
  the 45-byte signing message and the policy fingerprint.
- `sign(proposal_json, policy_json, signer_seed: &[u8; 32]) -> (index, 2420-byte sig)` re-runs
  `check_proposal` and derives the Dilithium2 key deterministically from the seed.
- `verify_share(proposal_json, policy_json, "i:hex")`.

A new crate rather than a feature, because `randprotocol-client` depends unconditionally on
reqwest, tokio, clap, image and the prover wire. The CLI's `multisig-private check` and `sign` wrap
the crate. The CLI keeps the file-mode checks and the validator-key warning. `policy_json` carries
the secret `msk`; `proposal_json` carries the witness words. Both are secrets. Against the chain
head, expiry is the caller's check; the crate checks only
`bundle.time < expires_at ≤ bundle.time + MAX_PROOF_WINDOW_BLOCKS`.

`sign` never signs an opaque hash. It decodes `tx` and checks:

- `tx.chain_id` and the proposal's `binding_domain` match;
- `tx.binding(domain) == binding`, and `signing_message(binding) == signing_message`;
- the bundle's `auth_commit == msauth::auth_commit(policy.nk(), salt)`, so the proposal spends
  from this policy's account;
- every one of the **four** output envelopes opens **as sender** under the policy's scan key
  (`open_as_sender_with`), and the opened note's commitment is the bundle's commitment in that
  slot (an unopenable output is refused, never skipped: skipping would let a proposer hide value);
- **value conservation against the witness:** the input notes decoded from `bundle_words`,
  re-derived to nullifiers with the policy's `nk`, are exactly the transaction's four nullifiers,
  and per asset Σ inputs = Σ opened outputs + fee + `burn_a`/`burn_r`.

It shows each output's recipient, amount, asset and memo, the fee, and any burn, then signs
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
`ZkExecutor::msauth_proof_commit` against `auth_commit` and by `auth_header(..).0 == Multisig`;
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

Cut checklist addition: no genesis `aggregation_tree` step pin may predate rVM phase 4 (§5 item 8;
opcodes 25/27 changed meaning under an unchanged key). Also, the `rand-prover` fleet (prover.randprotocol.org) and `clients/core`'s
vendored fullnode must be on constraint set 9 at the cut, or every delegated bundle proof and every
light wallet fails on chain 21's keys.

### 7.1 The end-to-end gate (a test chain, real proofs)

`crates/randprotocol-client/tests/wallet_flow.rs`,
`a_private_multisig_receives_spends_rotates_and_refuses_one_signature_end_to_end`, is `#[ignore]`d
because it runs about 4 bundle proofs and 3 tier-18 msauth proofs and needs a machine with
≥ 48 GB. On a one-validator Test-profile chain with v3, `hc_auth`, `hc_auth_multisig`, a `gas`
section, `proof_window_blocks: 1024` (3 s test blocks would otherwise give 12.8 minutes for two
signatures, a tier-18 Test prove and a bundle prove) and a `multisig` section seeding one 2-of-3
public account. Before it runs, the Test-profile msauth prove time and peak RSS from the plan's
Task 2 are recorded; stop if the peak exceeds 40 GB (the node runs in-process on the 48 GB
laptop):

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
6. Size: the ignored executor test (plan Task 2) asserts M = 1, 2, 3 proofs differ in length only
   within the hiding noise (≤ 1 %).
7. Every committed multisig auth proof's header equals `msauth_heights()`, and its `pv::GAS` equals
   `msauth_gas_limit_pin()` for both the 2-signature spends. That is R-gas and R-hide checked on
   the chain's own bytes.

## 8. CHANGELOG (v0.8.0) — the release section

The user's decision is option A: v0.8.0 carries this, from chain 21 onward. The plan's Task 10
edits `CHANGELOG.md` after a one-line in-session confirmation. It keeps lines 30–35 (the
startup-checkpoint and verify-cache bullets) verbatim, and makes three changes:

- **The node bullet.** The chain-20 flag-day bullet is withdrawn and replaced by: "**Chain 21
  onward; not for chain 20.** Constraint set 9 (the MODQ chip) changes every verifier key and the
  proof encoding: this build refuses chains 18–20 at startup (`CHAINS_THIS_BUILD_CANNOT_RUN`).
  Chain 20 stays on v0.7.x until chain 21's cut."
- **Rollback.** "Going back to v0.7.1 is possible only on a chain v0.7.1 runs (18–20); a chain-21
  database cannot be rolled back across constraint set 9."
- **Private multisig.** The following bullet goes under "Chain 21 and later, by genesis section":

> - **Private multisig** (`hc_auth_multisig`): an M-of-N Dilithium2 policy hidden inside a second
>   auth guest (tier 18, the MODQ chip; `M_MAX` 3, `N_MAX` 16). Admission tells the two
>   auth guests apart by the proof's pinned shape, with no wire, txid or binding change; the chain
>   learns only "multisig-authorised". `rand multisig-private new-policy|address|balance|prepare|
>   sign|prove|submit`; the auth proof is proved locally (about 3.6 MB at Production FRI, so a
>   multisig transfer is about 5.1 MB). **Constraint set 9:** every verifier key and the proof
>   encoding change, so this build runs chain 21 on and refuses chains 18–20.

## 9. Risks and open points

1. **v0.8.0 and chain 20** (§2.5): decided by the user, option A. v0.8.0 runs chain 21 onward,
   and the chain-20 flag-day roll is withdrawn.
2. **Chain-21 timing** (now a gate before Task 1): if chain 21 is cut before this lands, chain 21
   joins `CHAINS_THIS_BUILD_CANNOT_RUN`, `hc_auth_multisig` moves to chain 22's script, and the
   CHANGELOG wording changes accordingly.
3. **The verifier key's memory on 2–4 GB validators** (§3.5): measured, with a stop rule.
4. **Byte pricing.** Bundle and auth bytes are unpriced, so a multisig transfer uses about 3.5 times
   the block space for the same floor. This is a fees follow-up, not phase 4.
5. **Proof size above 95 % of 4 MiB**: the constant and chain 21's cap move to 6 MiB (§3.3).
6. **Delegated msauth proving** (§6.6): a follow-up.

## 10. Pre-flight review (2026-10-11): where each finding landed

| # | finding | section |
|---|---|---|
| 1 | preprocessed count omits modq; `decode_call` mirror | §4.2 |
| 2 | `modq_harness` behind `cheating`; guard `tests/common` | §5 item 4 |
| 3 | no single flight on the tier-18 key | §3.5 |
| 4 | dummies unopenable; value conservation | §6.3, §6.5 |
| 5 | chain-21 gate; rollback paragraph | §2.5, §9.2 |
| 6 | chain 18–20 genesis tests | plan Task 1 |
| 7 | floors from one sample; off-by-one header test | §1, §3.1 |
| 8 | RPC body cap counts three proofs | §2.4 |
| 9 | `AggExecutor::new`, `Counting`, no spec-file fallback | plan Task 4 |
| 10 | `Proof` not `Clone`; FRI field path | plan Task 2 |
| 11 | e2e window, RSS stop rule, `prepare` not pending | §6.3, §7.1 |
| 13 | size-uniformity assertion | §7.1 item 6 |
| 14 | one `auth_header` decode | §3.2, §3.4 |
| 15 | rule 3 compares `Word8`s | §2.3 |
| 16 | `--sweep-to` scope | §6.3 |
| 17 | expiry check in the CLI; helpers | §6.3, plan Tasks 3, 6, 7 |
| 18 | `MAX_HONEST_DEGREE_BITS` asserts | §4.2 |
| 19 | stale parent-spec copy | replaced with circuits' |
| 20 | prover fleet and `clients/core` at the cut | §7 |
| 21 | `sign` warns on a validator key | §6.3 |
| — | (Task 2 measurement) the precomputed msauth key | §3.6, plan Task 2b |
| — | (user decision) signer checks as the pure, wasm32-clean crate `randprotocol-msig` | §6.5, plan Task 6 |
