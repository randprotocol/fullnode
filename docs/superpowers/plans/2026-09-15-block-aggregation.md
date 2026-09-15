# Block aggregation — chain-side implementation plan

Status: **plan, written 2026-09-15, for review.** Spec: `docs/superpowers/specs/2026-09-15-block-aggregation.md`
(**under user review** — this plan is written so review nits slot in without restructuring: every
task names its spec section). Predecessors whose structure and discipline this mirrors:
`2026-09-12-shielded-pool-s1.md`, `2026-09-12-shielded-pool-s2.md` (the register pattern),
`2026-09-13-rpc-hardening.md` (the reconciliation convention). The zkVM half is **done and
pinned**: the rVM, the N-generic aggregate program, and the chain-facing API at
`circuits/` main merge `271679d` (zkvm-m5-4), with `circuits/recursion/docs/02-aggregate.md`'s
admission stub and pinned vectors. Branch discipline as always: per-task TDD, all green before
each commit, `docs/core/node: <area> — <what>` style, no push.

## Global Constraints

1. **Chain-9 fork semantics.** Everything here is genesis-gated on `genesis.aggregation`:
   a chain without the section behaves **byte-for-byte as today** — same state root
   (`aggregators_root` is absent, not zeroed), same `Action` decoding of old bytes is unaffected
   (new variants are new tags, never renumbered), same fee schedule. Chain 8 keeps its
   per-bundle proofs forever; nothing from chain 8 is ever coverable.
2. **The constraint set is unchanged.** The rVM verify is a *new executor capability*, not a
   proof-format change: bundle proofs verify exactly as today, `MAX_PROOF_BYTES` stays 2 MiB,
   and no existing proof's meaning moves. The only new verification is of rVM proofs, against
   the registered aggregate program (spec §2.3).
3. **Cheap before expensive, exactly as `validate_inner` has it.** The rVM verify (~1–2 s warm)
   is the *last* thing admission does, and it runs on the RPC-hardening task's workers off the
   consensus loop (`crates/shrugg-node/src/admission.rs`), with gossipsub reported exactly once
   (spec §4 step 8).
4. **Measured numbers in the docs** (`AGENTS.md` rule): the registered shape's digests, the
   startup key-build time, the warm aggregate verify, the cluster run's walls —
   `docs/aggregation.md` is amended when the measurements land, never before.
5. **The spec stays the binding design.** Where this plan must settle something the spec left
   open, it is a ruling in the table below (user-overturnable), not a quiet edit. Anything that
   would change the spec's wire format, consensus rule or economics goes back to the user.
6. **No production proof runs from these tasks.** The cluster suite's aggregate is produced at
   the test FRI profile through the proving slot; the production measurements are the
   activation checklist's, sequenced per the 2026-09-15 ruling (production proofs execute on a
   ≥ 64 GB machine after chain-side aggregation lands — see "What activation hands to ops").

## Rulings made in this plan (the spec leaves these open; the user can overturn any of them)

| # | ruling | basis |
|---|---|---|
| R1 | **Vendor `circuits/recursion` into `crates/shrugg-rvm` via `deploy/sync-zkvm.sh`, pinned at circuits main `271679d`** — not a path dependency. A path dep `fullnode → circuits/recursion` pulls recursion's own `rand_zkvm = { path = "../research" }` along with it, giving two *distinct* `rand_zkvm` crates (`circuits/research` and the vendored `crates/shrugg-zkvm`): `recursion::InnerProof` and `shrugg_zkvm::machine::Proof` would be different types, and the executor could not pass a bundle's proof to `recursion::aggregate` at all. The sync script's existing `rand_zkvm → shrugg_zkvm` rename (its `@@RAND_ZKVM@@` two-step) applied to the recursion copy makes the types unify — the same mechanism `shrugg-zkvm` itself lands by. `circuits/` must still sit beside `fullnode/` for the *source*; the build consumes only `crates/`. | `deploy/sync-zkvm.sh`'s comment block and rename; `recursion/Cargo.toml`'s `rand_zkvm = { path = "../research" }` |
| R2 | **`AdmittedShape` carries `profile` + `tier` + the six heights (the "declared shape") and the chain-9 genesis pins `aggregate_program_digest` per admitted shape; the `InnerKey` cap is derived at startup, never stored.** Spec §2.3 verbatim; the startup key-build (~30–70 s at 2²¹ production, 18.31 s measured at 2¹⁹) is a node-startup obligation documented for ops, cached in recursion's own 64-entry FIFO. | `circuits/recursion/docs/02-aggregate.md` "Startup: the key-build story" |
| R3 | **The pruned record is a `CF_TXS` value-level form, not a new column family**: `TxRecord { Raw(Transaction), Pruned { tx: Transaction, proof_hash: Hash, public_values: [u64; 34], shape: DeclaredShape } }`. A new family would split every tx lookup across two reads for zero benefit; the marker lives on the value, and `verify_chain` reads the same key either way. `CF_SEALS` *is* new: `bundle_hash → aggregate_tx_hash` (`sealed_by`) plus per-block `sealed: bool`, both derived state. | storage.rs's existing CF list (`CF_TXS` at storage.rs:25) |
| R4 | **`AGGREGATION_WINDOW = 256` and `MAX_COVERS = 3` are genesis parameters with those defaults, not shared constants.** The window shares its *value* with the anchor/time window by default but is independently configurable (the subsidy schedule and the pruning gate hang off it; tying it to the anchor window would couple two policies). | spec §3.3 |
| R5 | **`Action::Aggregate`'s fee floor is 0** (it is bundle-less, and `fee_floor`'s own rule says a bundle-less action has nothing to pay *from*). The proving share is collected from the *covered bundles'* excess, not from the aggregate's author; a fee field on the action would double-count. | gas.rs:68–74, spec §5.2 |
| R6 | **The executor surface is two methods, not the recursion API re-exported**: `aggregate_program_digest(shape) -> Word8` (startup constant) and `verify_aggregate(shape, covered, proof) -> Result<Vec<[u32; 8]>, _>`. The ledger never sees `recursion` types; `CoveredBundle { public_values: [u64; 34], shape: DeclaredShape }` is a shrugg-core type. The stub executor for tests implements the same two methods with a recorded-calls fake; the conformance suite (Task 4) exercises the real one byte-for-byte before anything trusts the stubbed path. | spec §4 steps 6–8; `circuits/recursion/docs/02-aggregate.md`'s vectors |
| R7 | **The proving slot covers the cluster's aggregate proof.** The fullnode's proving-slot discipline (`crates/shrugg-node/tests/proving_slot/`) hands out one permit at a time; the cluster suite's recursion prove (test profile, ~2–4 min at N=3 over the small fixture shape) takes it, exactly as the wallet-flow bundles do. | AGENTS.md "Proving concurrency is capped" |
| R8 | **`shrugg_getUnsealed` is a node-side view over `CF_TXS` + `CF_SEALS`, paginated by height, and deliberately read-only for the daemon's polling pattern.** It answers `(hash, height, excess_fee)` for bundles that are finalised, chain-9, inside the window, and `sealed_by`-absent. | spec §8 |

## File structure

```
crates/shrugg-core/src/
  types/transaction.rs        [Task 1] Action::{Aggregate,RegisterAggregator,UnbondAggregator,
                                 WithdrawAggregator,SlashAggregator}; bundle_less(); AggregatorRegistration
  types/mod.rs                [Task 1] DeclaredShape, CoveredBundle (R6's shrugg-core types)
  genesis.rs                  [Task 1][Task 9] genesis.aggregation: Option<AggregationConfig>
  gas.rs                      [Task 1] MAX_AGGREGATE_BYTES; [Task 5] subsidy()
  ledger/mod.rs               [Task 2] validate_inner/apply_tx arms for the five actions
  ledger/aggregation.rs       [Task 1] AggregatorEntry, the register, leaf/root
                              [Task 2] the four register actions (validate/apply)
                              [Task 4] validate_aggregate (spec §4's 9 steps)
                              [Task 5] subsidy/sealed_blocks/unsealed_fees/payout note
  ledger/supply.rs            [Task 5] the four counters and the issued − slashed invariant
  ledger/staking.rs           [Task 1] derived_commitment gains the two new note arms
crates/shrugg-zkvm/src/
  executor.rs                 [Task 3] ConfidentialExecutor gains the aggregate surface
crates/shrugg-rvm/            [Task 3] NEW: vendored circuits/recursion at 271679d (R1)
crates/shrugg-node/src/
  storage.rs                  [Task 6] CF_SEALS; the TxRecord pruned form (R3)
  mempool.rs                  [Task 4] the payout-cm and (aggregator, nonce) claims
  admission.rs                [Task 4] is_permanent arms for the new permanent verdicts
  node.rs                     [Task 4] the Aggregate arm on the verify workers; publish_status
  network/                    [Task 7] the second block form + apply_synced
  rpc.rs                      [Task 8] the spec's methods and status/supply fields
  main.rs                     [Task 8] `aggregator register|unbond|withdraw`, `aggregate --watch`
deploy/
  sync-zkvm.sh                [Task 3] the recursion vendoring section (R1)
  cut-chain9-genesis.sh       [Task 9] NEW, modeled on cut-chain8-genesis.sh
  genesis-chain9.json         [Task 9] produced at activation, not in this plan
docs/
  aggregation.md              [Task 10] amended with measured numbers
  rpc.md                      [Task 8] the hard-fork changelog entry
  cli.md                      [Task 8] the aggregator commands
  deploy.md                   [Task 9] the chain-9 cut runbook
AGENTS.md                     [Task 10] the aggregation project-memory entry
```

### Task 1: Core types, the register state, genesis gating

**Files:** `crates/shrugg-core/src/types/{transaction.rs,mod.rs}`, `crates/shrugg-core/src/genesis.rs`,
`crates/shrugg-core/src/gas.rs`, `crates/shrugg-core/src/ledger/aggregation.rs` (new),
`crates/shrugg-core/src/ledger/staking.rs` (derived_commitment only).

**Interfaces:**

```rust
// types/mod.rs
/// The declared shape of a bundle proof: the profile, the tier, and the six declared
/// log-heights, read off its stored proof header (spec §0.1 finding (a); 8 values, kept
/// per bundle through pruning).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DeclaredShape {
    pub profile: FriProfile,
    pub tier: u8,
    pub program_log_height: u8,
    pub input_log_height: u8,
    pub keccak_log_height: u8,
    pub sha256_log_height: u8,
    pub public_log_height: u8,
    pub mem_log_height: u8,
}
/// What admission needs of a covered bundle and nothing more (R6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CoveredBundle { pub public_values: [u64; 34], pub shape: DeclaredShape }

// types/transaction.rs — the five actions, all but the first bundle-less (spec §2.2, §3.1)
Action::RegisterAggregator { registration: AggregatorRegistration },
Action::UnbondAggregator { aggregator: Address, nonce: u64, signature: Signature },
Action::WithdrawAggregator { aggregator: Address, nonce: u64, time: u32, r: Word8,
                             envelope: Envelope, signature: Signature },
Action::SlashAggregator { a: Box<SignedAggregateHeader>, b: Box<SignedAggregateHeader> },
Action::Aggregate {
    covers: Vec<Hash>,            // bundle transaction hashes, in the proof's order
    proof: Vec<u8>,               // postcard(recursion::machine::Proof), capped by gas::MAX_AGGREGATE_BYTES
    aggregator: Address,
    nonce: u64,
    time: u32,
    r: Word8,
    envelope: Envelope,
    signature: Signature,
}

pub struct AggregatorRegistration { pub public_key: PublicKey, pub payout: ShieldedAddress,
                                    pub signature: Signature }
pub struct SignedAggregateHeader { pub aggregator: Address, pub nonce: u64, pub time: u32,
                                   pub r: Word8, pub covers: Vec<Hash>, pub proof_hash: Hash,
                                   pub signature: Signature }

// ledger/aggregation.rs
pub struct AggregatorEntry { pub public_key: PublicKey, pub bond: u64,
                             pub payout: ShieldedAddress, pub nonce: u64,
                             pub unbonding: Option<u64> }
impl Ledger {
    pub fn aggregators(&self) -> &BTreeMap<Address, AggregatorEntry>;   // empty when ungated
    pub fn sealed_blocks(&self) -> u64;                                  // the schedule index n
}

// genesis.rs
pub struct AggregationConfig {
    pub bond: u64, pub max_covers: u32, pub subsidy_base: u64,
    pub halving_blocks: u64, pub window: u64,
    pub admitted_shapes: Vec<AdmittedShape>,
}
pub struct AdmittedShape {
    pub shape: DeclaredShape,
    pub hc: Hash,                            // the bundle guest's digest (pv::HC0..7)
    pub aggregate_program_digest: [u64; 4],  // recursion's aggregate_program_digest(shape, key)
}

// gas.rs
pub const MAX_AGGREGATE_BYTES: usize = MAX_PROOF_BYTES + 3 * 32 + (4 + 1 + 34 * 3) * 8 + 4_400;
pub fn subsidy(n: u64, cfg: &AggregationConfig) -> u64 {
    if n / cfg.halving_blocks >= 64 { 0 } else { cfg.subsidy_base >> (n / cfg.halving_blocks) }
}
```

- [x] **Step 1: Write the failing tests** — `ledger/aggregation.rs` tests: (a) a chain without
  `genesis.aggregation` computes today's state root byte-for-byte over the fixture ledger, and a
  gated chain's root differs exactly by the `aggregators_root` component (empty register ⇒
  component is the hash of nothing); (b) `Action::Aggregate` round-trips bincode and is
  bundle-less (`bundle_less()` names it and the other three bundle-less register actions, and
  `RegisterAggregator` is the one that rides a bundle); (c) `MAX_AGGREGATE_BYTES` admits a
  2 MiB proof plus the caps and refuses one byte past; (d) `subsidy` at `n = 0`, `209 999`,
  `210 000`, and the 64th halving's zero.
- [x] **Step 2: Run to verify it fails** — no such types exist.
- [x] **Step 3: Implement** — the types, the register map with the leaf
  `blake3("shrugg-aggregator-leaf-1", addr || bond || nonce || release || payout pk || payout
  kem_ek)`, the `shrugg-state-3`-domained `aggregators_root` joined into `Ledger::state_root`
  exactly when `genesis.aggregation.is_some()`; the `Genesis` section with the same gating
  pattern `bridge` uses; `derived_commitment` in `ledger/staking.rs:161` extended to the two
  new derived-note actions (an `Aggregate`'s payout note and a `WithdrawAggregator`'s) so the
  mempool has one function to ask.
- [x] **Step 4: Run to verify it passes** — the new tests green; the workspace suite green
  (state-root and wire-format pins unmoved).
- [x] **Step 5: Commit** — `core: aggregation — the action and register types, genesis-gated: the aggregator register, the state-root component, the subsidy schedule`

### Task 2: The four register actions

**Files:** `crates/shrugg-core/src/ledger/aggregation.rs`, `crates/shrugg-core/src/ledger/mod.rs`
(the two `match &tx.action` arms), `crates/shrugg-core/src/gas.rs` (`fee_floor` arms).

**Interfaces** (the `staking.rs` shape, mirrored):

```rust
pub(super) fn validate(ledger: &Ledger, tx: &Transaction, action: &Action,
                       executor: &dyn ConfidentialExecutor) -> Result<(), TxError>;
pub(super) fn apply(ledger: &mut Ledger, tx: &Transaction, action: &Action,
                    proposer: &Address, executor: &dyn ConfidentialExecutor) -> Result<(), TxError>;
impl Ledger {
    fn register_aggregator(&mut self, registration: &AggregatorRegistration, burn: u64,
                           chain_id: u64) -> Result<(), TxError>;
    fn unbond_aggregator(&mut self, aggregator: &Address, nonce: u64,
                         signature: &Signature, chain_id: u64) -> Result<(), TxError>;
    fn withdraw_aggregator(&mut self, aggregator: &Address, nonce: u64, time: u32, r: &Word8,
                           envelope: &Envelope, signature: &Signature, chain_id: u64)
        -> Result<(), TxError>;
    fn slash_aggregator(&mut self, a: &SignedAggregateHeader, b: &SignedAggregateHeader)
        -> Result<(), TxError>;
}
```

Semantics, point-for-point from spec §2.2: `RegisterAggregator` requires a bundle whose
`burn == AGGREGATION.bond` (the `Bond` arm's check in `validate_inner`'s burn match — extended
with the register arm), the signature over `blake3("shrugg-aggregator-register", chain_id ||
payout)`, refusal when the address is registered, entry created at `nonce = 0`;
`UnbondAggregator` sets `unbonding = Some(head + window)` and bars submissions;
`WithdrawAggregator` is the S2 `Withdraw` verbatim (release check, derived note of
`bond − BUNDLE_BASE`, base to the proposer, entry deleted); `SlashAggregator` requires the two
headers to share `(aggregator, nonce)` with different content, burns the bond into `slashed`,
deletes the entry. One monotonic nonce per entry, consumed per accepted action.

- [x] **Step 1: Write the failing tests** — register → duplicate register refused; unbond →
  submission with `unbonding` set refused; withdraw before the release height refused, after it
  pays `bond − BUNDLE_BASE` as a derived note the wallet opens, entry gone; a slash with
  mismatched nonces refused, a well-formed one burns the bond and deletes; the nonce rules
  (replay of an accepted action refused); the `burn != bond` register refused in
  `validate_inner`'s burn arm, before any signature work.
- [x] **Step 2: Run to verify it fails.**
- [x] **Step 3: Implement** — the module plus the two `validate_inner`/`apply_tx` arms and the
  `fee_floor` arms (`Aggregate`, `UnbondAggregator`, `WithdrawAggregator`, `SlashAggregator` →
  0 per R5; `RegisterAggregator` → `BUNDLE_BASE`).
- [x] **Step 4: Run to verify it passes** — plus the full core suite.
- [x] **Step 5: Commit** — `core: aggregation — the aggregator register's four actions: register, unbond, withdraw, slash (S2's semantics, mirrored)`

### Task 3: The rVM executor capability and the vendoring (R1)

**Files:** `deploy/sync-zkvm.sh` (the recursion section), `crates/shrugg-rvm/` (produced by it),
`crates/shrugg-zkvm/src/executor.rs`, `crates/shrugg-zkvm/Cargo.toml`.

**Interfaces:**

```rust
// shrugg-core (types/mod.rs) — the executor surface's own types, so the trait stays shrugg-core's.
impl DeclaredShape { pub fn from_proof_header(header: &ProofHeader) -> DeclaredShape; }

// shrugg-zkvm/src/executor.rs — the trait, extended (R6)
pub trait ConfidentialExecutor {
    /* … today … */
    /// The registered aggregate program's digest for an admitted shape: a startup constant.
    fn aggregate_program_digest(&self, shape: &DeclaredShape) -> Result<Word8, ConfidentialError>;
    /// spec §4 steps 6–8: the declared-shape check per covered bundle, the interface-list
    /// recompute and digest compare, then the rVM verify against the registered program.
    /// Returns each covered bundle's OUT0..7 in cover order.
    fn verify_aggregate(&self, shape: &DeclaredShape, covered: &[CoveredBundle],
                        proof: &[u8]) -> Result<Vec<[u32; 8]>, ConfidentialError>;
}
// ZkExecutor: builds the shrugg_rvm Machine at startup (the key-build — R2), and a stub for
// tests with the same surface and recorded calls.
```

The vendoring itself, as R1 rules: a `sync_recursion()` section in `deploy/sync-zkvm.sh` that
rsyncs `../../../circuits/recursion/{src,Cargo.toml}` into `crates/shrugg-rvm/` with the
`@@RAND_ZKVM@@` two-step rename applied (`rand_zkvm` → `shrugg_zkvm` in its Cargo.toml and
sources, so its `rand_zkvm` dep resolves to the vendored `crates/shrugg-zkvm`), the
`rand_zkvm_cuda` references left alone (recursion does not depend on it by default), and the
pin recorded as circuits main `271679d` in the script's header and in `crates/shrugg-rvm/AGENTS.md`
(one paragraph: what it is, whence, how to re-sync).

- [x] **Step 1: Write the failing tests** — (a) `ZkExecutor::aggregate_program_digest` for the
  test-profile fixture shape equals the recursion-crate-computed value (the pinned
  `33a94ec6…` is the *inner* vk digest; the *program* digest pin is recomputed in the test from
  the vendored crate and recorded in `docs/aggregation.md` at activation); (b) the stub
  executor records `verify_aggregate` calls and replays canned answers, so ledger tests never
  touch a proof.
- [x] **Step 2: Run to verify it fails** — no `shrugg-rvm` crate, no such methods.
- [x] **Step 3: Implement** — the vendoring section, run it (produces `crates/shrugg-rvm`), the
  trait extension and the real `ZkExecutor` wiring (the startup key-build at `Node` startup
  when `genesis.aggregation` is present: build the registered program, call recursion's
  `verifier_key`, cache; log the build's wall time — R2's measured number).
- [x] **Step 4: Run to verify it passes** — the digest test green; `cargo check -p shrugg-zkvm
  -p shrugg-rvm` clean (this is the one build step of the plan; it stays off the heavy suite
  until Task 10).
- [x] **Step 5: Commit** — `zkvm: vendored recursion as shrugg-rvm (circuits 271679d) + the executor's aggregate surface and the startup key-build`

### Task 4: Aggregate admission (spec §4) and the conformance suite

**Files:** `crates/shrugg-core/src/ledger/aggregation.rs`, `crates/shrugg-node/src/mempool.rs`,
`crates/shrugg-node/src/admission.rs`, `crates/shrugg-node/src/node.rs`.

**Interfaces:**

```rust
// ledger/aggregation.rs — spec §4's nine steps, in order, cheap before expensive.
pub(super) fn validate_aggregate(
    ledger: &Ledger, tx: &Transaction, covers: &[Hash], aggregator: &Address, nonce: u64,
    time: u32, r: &Word8, envelope: &Envelope, signature: &Signature, proof: &[u8],
    executor: &dyn ConfidentialExecutor,
) -> Result<ValidatedAggregate, TxError>;
pub struct ValidatedAggregate {
    pub covered: Vec<CoveredBundle>,   // per covered bundle, its 34 pv + declared shape (stored)
    pub payout_cm: Word8,              // the derived payout note's commitment (spec §4.5/§5.4)
    pub outs: Vec<[u32; 8]>,           // verify_aggregate's return, for apply
}
```

Steps, exactly the spec's §4: (1) size caps, `chain_id`; (2) registered, not unbonding, nonce,
signature over `blake3("shrugg-aggregate", chain_id || nonce || time || r || covers || proof
hash)`; (3) `time` window; (4) the cover set (`1 ≤ covers.len() ≤ max_covers`, no duplicates,
every hash a coverable bundle — finalised, chain-9, in-window, unsealed); (5) the payout
commitment is new (`derived_commitment`, claimed in the mempool like a `BridgeAttest`'s); (6)
per covered bundle, read its declared shape from its stored proof header and refuse on the
first mismatch with any registered shape; (7) recompute the interface list from the registered
shape and the covered pvs, digest-compare against the proof's batch public values (decoded
without verification); (8) `executor.verify_aggregate` — last, on the workers; (9) payment
computed for apply. The mempool claims: `payout_cm` (as today) and `(aggregator, nonce)` (the
`claimed_nonce` pattern at mempool.rs:74); covers deliberately unclaimed (spec §3.4).
`admission.rs::is_permanent` gains the byte-verdicts (bad signature, size caps, digest
mismatch, invalid aggregate proof, a covered bundle whose stored header mismatches the
registered shape); state-verdicts (already-sealed, window, unknown bundle, unknown aggregator)
stay uncached, exactly the file's own rule.

- [x] **Step 1: Write the failing tests** — ledger: the nine steps each refuse in their own
  order with a named error (a test per step, built on the stub executor); the **conformance
  suite**: the pinned vectors of `circuits/recursion/docs/02-aggregate.md` — the fixture set's
  inner vk digest `33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8`, the
  107-word interface list, and its digest
  `9f11f1aeb33546be79efe66a4829dc39c28f49f2ebd0bb055ac8a1a3fe088dcd` — reproduced byte-for-byte
  by the executor's recompute path (the test pins all three, and the plan accepts nothing less
  before admission is trusted, spec §4's own gate); a wrong-shape covered bundle refused at
  step 6 with the bundle named; a tampered `public` word failing step 7; a bad proof failing
  step 8. Node: a gossiped aggregate is reported to gossipsub exactly once on each outcome.
- [x] **Step 2: Run to verify it fails.**
- [x] **Step 3: Implement** — the validator, the mempool claims, the worker arm in `node.rs`
  (the `GossipOutcome::Verify` path unchanged; the verdict's `acceptance_for` covers the new
  `TxError`s).
- [x] **Step 4: Run to verify it passes** — the conformance suite green *first*, then the rest.
- [x] **Step 5: Commit** — `core+node: aggregation — admission: the nine steps cheap-before-expensive, the declared-shape check, the pinned conformance vectors`

### Task 5: Subsidy, the proving share, and the supply audit

**Files:** `crates/shrugg-core/src/ledger/aggregation.rs`, `crates/shrugg-core/src/ledger/mod.rs`
(the bundle-inclusion split), `crates/shrugg-core/src/ledger/supply.rs`,
`crates/shrugg-core/src/gas.rs`, `crates/shrugg-node/src/rpc.rs` (the `shrugg_getSupply`
extension — folded here, not in Task 8, because the audit's test lives here).

**Interfaces:**

```rust
// ledger/aggregation.rs
pub struct Payment { pub subsidy: u64, pub proving_shares: u64, pub total: u64, pub note: Word8 }
impl Ledger {
    /// At bundle inclusion: the proposer keeps BUNDLE_BASE; the excess is bucketed (spec §5.2).
    fn bucket_excess(&mut self, bundle_hash: Hash, excess: u64, proposer: Address, expires_at: u64);
    /// At block commit: every bucket entry whose window passed is credited to its proposer.
    fn sweep_expired_excesses(&mut self, head_height: u64);
    /// The aggregate's one deposit note (spec §5.4): subsidy(n) + Σ covered excesses.
    fn aggregate_payment(&self, covers: &[Hash], cfg: &AggregationConfig, time: u32,
                         r: &Word8, payout: &ShieldedAddress, executor: &dyn ConfidentialExecutor)
        -> Result<Payment, TxError>;
}
// supply.rs
pub struct Supply { /* …today… */
    pub subsidised: u64, pub sealed_blocks: u64,
    pub aggregator_bonds: u64, pub slashed: u64 }
impl Audit { pub fn invariant_holds(&self) -> bool }   // total_supply == issued − slashed
```

The payout note's commitment is `note_commitment(payout.pk, [0;8], total, 0, time, r)`,
derived exactly as a validator's `Withdraw` note (spec §5.4), sealed by the action's envelope,
and appended at apply with `withdraw_deposited` *not* touched — the subsidy is counted by
`subsidised`, and `withdraw_deposited` stays the validator-only counter (spec §5.3's identity).

- [x] **Step 1: Write the failing tests** — the fee bucket's three exits (covered → to the
  aggregator; expired → to the recorded proposer; never-included → still bucketed); the subsidy
  schedule at the halving edges; the supply invariant holding across a register, an aggregate,
  a withdraw and a slash (`total_supply == issued − slashed` exactly); `sealed_blocks`
  incrementing per included aggregate and not per block; `shrugg_getSupply` reporting the four
  new counters separately from `faucet_minted`.
- [x] **Step 2: Run to verify it fails.**
- [x] **Step 3: Implement** — the split in `apply_tx` (the proposer credit becomes
  `BUNDLE_BASE` with the excess bucketed, gated on `genesis.aggregation` — ungated chains keep
  the full fee to the proposer, byte-for-byte), the sweep at `apply_block`'s commit, the
  payment and note at the aggregate's apply, the counters.
- [x] **Step 4: Run to verify it passes.**
- [x] **Step 5: Commit** — `core: aggregation — the subsidy schedule, the proving share, and the supply audit's four new counters`

### Task 6: Sealing and pruning

**Files:** `crates/shrugg-node/src/storage.rs` (CF_SEALS, the `TxRecord` form),
`crates/shrugg-node/src/node.rs` (marking on commit, the pruning pass, the
`--keep-raw-proofs` flag), `crates/shrugg-node/src/main.rs` (the flag).

**Interfaces:**

```rust
// storage.rs (R3)
pub enum TxRecord {
    Raw(Transaction),
    Pruned { tx: Transaction, proof_hash: Hash, public_values: [u64; 34], shape: DeclaredShape },
}
impl Storage {
    pub fn mark_sealed(&self, bundle_hash: Hash, aggregate_tx: Hash) -> Result<(), Error>;
    pub fn sealed_by(&self, bundle_hash: Hash) -> Result<Option<Hash>, Error>;
    pub fn block_sealed(&self, block_hash: Hash) -> Result<bool, Error>;
    /// The pruning pass (policy, never consensus): after `window` blocks sealed, turn each
    /// sealed bundle's Raw record into its Pruned form, filling the 34 pv and the shape from
    /// the stored proof. Never touches: aggregate transactions, covers lists, unsealed bundles.
    pub fn prune_sealed(&self, head_height: u64, window: u64) -> Result<u64, Error>;
}
```

- [x] **Step 1: Write the failing tests** — the sealing marks land per bundle and per block
  (`sealed` only once every bundle in the block has one); the pruned record round-trips with
  the 34 pv and the 7 shape bytes intact; the gate refuses to prune before `window` blocks;
  the never-prune list is honored (an aggregate's own record is never rewritten);
  `verify_chain` on a pruned store recomputes the same ledger and the same state root as the
  archival store (spec §6.2's proof, as a test); the admission path reads a covered bundle's
  shape from the pruned record when raw bytes are gone (Task 4's step 6, both record forms).
- [x] **Step 2: Run to verify it fails.**
- [x] **Step 3: Implement** — the record forms, the marks at commit, the pruning pass and the
  flag.
- [x] **Step 4: Run to verify it passes** — plus the node suite.
- [x] **Step 5: Commit** — `node: aggregation — sealing and pruning: CF_SEALS, the pruned record (34 pv + 7 shape bytes), the 256-block gate`

### Task 7: Sealed-form sync

**Files:** `crates/shrugg-node/src/network/` (the second block form on the wire),
`crates/shrugg-node/src/node.rs` (`apply_synced`'s acceptance rule), the cluster tests
(`crates/shrugg-node/tests/`).

**Interfaces:**

```rust
// node.rs — spec §7's rule, on top of today's apply_synced
fn apply_synced_block(&mut self, form: SyncedBlock) -> Result<(), SyncError>;
enum SyncedBlock { Raw(Block), Sealed(Block) }   // Sealed carries pruned bundles + aggregates inline
// acceptance: a pruned bundle only if its block is finalised, a covering Aggregate is already
// applied, and covers names the bundle's hash — else request the raw form from another peer.
```

- [x] **Step 1: Write the failing tests** — the three failure modes of spec §7 (missing
  aggregate → raw-form fallback; aggregate failing any admission step → batch fails as an
  invalid block; pruned bundle with neither aggregate nor raw → retry from another peer, no
  ban); `verify_chain` on a pruned store; **the cluster test**: two nodes run a window of real
  bundles, an aggregate is produced through the proving slot (test profile), submitted,
  admitted, sealed, pruned on node A; node B joins fresh, syncs in sealed form, and both reach
  the same state root with node B doing **one rVM verification per sealed window** (the sync
  log's verify count asserted).
- [x] **Step 2: Run to verify it fails.**
- [x] **Step 3: Implement** — the wire form, the acceptance rule, the fallback.
- [x] **Step 4: Run to verify it passes** — the cluster test green (the suite's slowest;
  scheduled alone per the proving-slot discipline, R7).
- [x] **Step 5: Commit** — `node: aggregation — sealed-form sync: the second block form, the acceptance rule, the one-verify-per-window cluster test`

### Task 8: RPC, CLI, and the changelog

**Files:** `crates/shrugg-node/src/rpc.rs`, `crates/shrugg-node/src/main.rs`,
`docs/rpc.md`, `docs/cli.md`.

**Interfaces (spec §8, in `docs/rpc.md`'s conventions):** `shrugg_submitAggregate` (an alias of
`shrugg_sendTransaction`, no new path); `shrugg_getBlockByHeight`/`ByHash` gain `sealed` and
per-bundle `sealed_by`; `shrugg_getAggregate(hash) -> { covers, aggregator, subsidy,
proving_share, n }`; `shrugg_getAggregators` (the register); `shrugg_getUnsealed(from, limit)
-> { bundles: [{ hash, height, excess }], next_from }` (R8); `shrugg_getSupply` with the four
counters; `shrugg_status.aggregation: { registered, unsealed, verify_queue }`; `tx_json` for
the five actions. The node CLI: `shrugg-node aggregator register --bond --payout`, `unbond`,
`withdraw`, and `shrugg-node aggregate --watch --rpc <url>` (poll `shrugg_getUnsealed`, fetch
raw bundles, call `shrugg_rvm::aggregate::aggregate`, submit — a separate process, RPC-only).

- [x] **Step 1: Write the failing tests** — the methods' shapes against the spec (request/
  response fixtures), `tx_json`'s five renderings, the changelog entry's presence in
  `docs/rpc.md` with the hard-fork framing (wire format, block rules and consensus change —
  not an interop-compatible hardening).
- [x] **Step 2: Run to verify it fails.**
- [x] **Step 3: Implement** — the methods, the CLI arms, the changelog and `cli.md`.
- [x] **Step 4: Run to verify it passes.**
- [x] **Step 5: Commit** — `node+docs: aggregation — the RPC surface, the aggregator CLI, the aggregate --watch daemon, the hard-fork changelog`

### Task 9: The chain-9 genesis

**Files:** `crates/shrugg-core/src/genesis.rs`, `deploy/cut-chain9-genesis.sh` (new),
`docs/deploy.md`.

**Interfaces:** the `genesis` CLI gains
`--aggregation bond,max_covers,subsidy_base,halving_blocks,window` and
`--admitted-shape profile,tier,program,input,keccak,sha256,public,mem,hc,program_digest`;
`deploy/cut-chain9-genesis.sh` mirrors the chain-8 script's validator/alloc mechanics with
chain-id 9 and the aggregation section, with `admitted_shapes[0]`'s values taken from the
activation measurements (see "What activation hands to ops" — the file ships with them marked
`FILL-AT-ACTIVATION`, and `genesis.rs`'s validation refuses a section with a zero program
digest so the placeholder can never reach a fleet).

- [x] **Step 1: Write the failing tests** — a genesis without the section behaves as today; a
  genesis with it carries the register empty at block 0 with `aggregators_root` present; the
  zero-digest placeholder is refused by validation; the cut script produces a valid
  `genesis-chain9.json` against a fixture admitted shape.
- [x] **Step 2: Run to verify it fails.**
- [x] **Step 3: Implement** — the CLI arms, the script, the deploy runbook section.
- [x] **Step 4: Run to verify it passes.**
- [x] **Step 5: Commit** — `deploy: aggregation — the chain-9 genesis: the aggregation section, the cut script, the activation checklist`

### Task 10: End-to-end, the full suite, and the docs

**Files:** `crates/shrugg-node/tests/` (the cluster suite), `docs/aggregation.md`,
`AGENTS.md`.

**The end-to-end** (R7's discipline): register an aggregator → bond it → a window of real
bundles (the cluster's existing wallet-flow machinery, proving slot held) → the daemon (or the
test driver) produces an aggregate at the test profile → submitted, admitted, sealed → the
subsidy and shares paid as one note the aggregator's wallet opens → a window passes, node A
prunes → node B joins and syncs in sealed form → both roots agree and the supply audit holds
(`total_supply == issued − slashed`, exactly) → the run's walls recorded (register, window,
aggregate prove, admission, seal+prune, resync) into `docs/aggregation.md`.

- [ ] **Step 1: Write the failing tests** — the end-to-end test itself; the full workspace
  suite (`cargo test --workspace --release`, proving slot held) green.
- [ ] **Step 2: Implement** — whatever the end-to-end exposes (this is where review findings
  land).
- [ ] **Step 3: The docs** — `docs/aggregation.md` amended with the measured numbers;
  `AGENTS.md` gains the aggregation project-memory entry (the invariants this plan added:
  genesis gating, the nine-step admission, the pruned record, the supply identity).
- [ ] **Step 4: Commit** — `docs: aggregation — the end-to-end: cluster-sealed-sync, the measured numbers, the project memory entry`

## What activation hands to ops

Activation is a chain cut with the production proofs run first — the 2026-09-15 ruling,
sequenced here as a checklist, not a date:

1. **The ≥ 64 GB batch session** (the M5.4 runbook's runs 3–6, in order): M5.2's tier-21 exit,
   the M5.3 N=2 and N=3 test-profile aggregates, and the production N=1 aggregate. Each run's
   wall, peak RSS and proof size recorded into `circuits/recursion/docs/02-aggregate.md` and
   mirrored into `docs/aggregation.md`.
2. **The activation measurements** (from those runs, filling `admitted_shapes[0]`
   `FILL-AT-ACTIVATION`): the production bundle guest's declared heights and `hc`;
   `aggregate_program_digest(shape, key)` recomputed and recorded; the startup key-build wall
   at 2²¹ production (the ops expectation for node startup); the warm aggregate verify wall
   (the per-block cost budget).
3. **The chain-9 cut**: `deploy/cut-chain9-genesis.sh` with the measured section, the genesis
   hash distributed byte-identically, the fleet upgraded to the aggregation build, the
   aggregator daemon started on the GPU host as M5.4 delivers it (CPU-first is supported and
   is how the cluster test runs).
4. **Go/no-go gates**: the conformance suite green on the fleet build; the cluster end-to-end
   green on the release candidate; `shrugg_getSupply`'s invariant holding from block 0.

## Self-review

- The executor-vendoring crux (R1) is the one place a naive path dep silently produces
  uncompilable code (two `rand_zkvm`s); the ruling and its evidence are stated for exactly that
  reason.
- The spec was written against this tree on 2026-09-15; anything that lands after this plan's
  date gets a Reconciliation section at the top, per the rpc-hardening plan's convention.
- Nothing here changes consensus HotStuff, the proving-slot discipline, or the bundle pipeline;
  each is named where a task could be mistaken for touching it.
