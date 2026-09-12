# Fully shielded pool — Phase S2 (staking with public weights) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the shielded chain its validator register with public weights: `Bond` (from a bundle, value leaving the pool as `burn`), `Unbond` and `Withdraw` (validator-signed), registration of new validators, epochs of `EPOCH_BLOCKS` blocks with the validator set for epoch `e` derived from the register as of the last block of epoch `e − 1`, rewards paid out as deposit notes, and genesis seeding with payout addresses.

**Architecture:** The register lives in `shrugg-core`'s ledger as `ValidatorEntry { public_key, stake, pending, rewards, payout, nonce }` and is hashed into the state root. Staking rules live in a new `ledger/staking.rs` module the ledger delegates to, so S3's action modules (call envelopes, bridge) can land beside it without touching the same functions. HotStuff stops reading one static validator set: it derives the set for a block height from the ledger of that height's epoch-start parent, verifies each QC against the set of the certified block's epoch, and picks leaders from the set of the next height. Storage persists one `ValidatorSet` per epoch so replay and sync verify QCs without re-deriving. The wallet gains `bond`; the node binary gains `unbond`, `withdraw` and `register` (they need the validator's Dilithium2 key). S2 ships with S3 as one hard fork.

**Tech Stack:** unchanged from S1 (Rust 1.98.1, RocksDB, bincode; no new dependencies).

**Spec:** `docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §6 (Bond/Unbond/Withdraw rows), §8 (staking), §9 (state root), §12 (S2 row), §13 (rulings: no slashing). Builds on the S1 plan `docs/superpowers/plans/2026-09-12-shielded-pool-s1.md` and its merged code.

## Global Constraints

- `EPOCH_BLOCKS` default `1000`, configurable in genesis (`epoch_blocks`, part of the genesis hash) so cluster tests can use small epochs; `UNBONDING_EPOCHS = 2`; `MIN_STAKE = 1000 * UNITS_PER_SHRUGG`; `MAX_VALIDATORS = 100`. Stake is `u64` units from S2 on (the register's `stake: u128` in `ValidatorSet` is kept for consensus arithmetic by widening at the boundary).
- **Epoch of a height**: `epoch(h) = h / epoch_blocks`; genesis (height 0) is epoch 0. The set for epoch 0 is the genesis validators. The set for epoch `e ≥ 1` is `derive_set(register after block e·epoch_blocks − 1)`: every entry with `stake ≥ MIN_STAKE`, the top `MAX_VALIDATORS` by `(stake desc, address asc)`, then sorted by address. `derive_set` is a pure function in `shrugg-core` and the only place the rule is written.
- **Consensus rules**: a block at height `h` is proposed and voted by the set of `epoch(h)`; the leader for a view is `set(epoch(high_qc.height + 1)).leader(view)`; a QC certifying block `B` is verified against `set(epoch(B.height))`; a `NewView` quorum for view `v` is counted against the set of `epoch(high_qc.height + 1)` of the receiver. Because every replica derives the set from the same parent ledger, the derivation is deterministic along one chain; competing forks at an epoch boundary derive their own sets and HotStuff safety picks one.
- **Validator-signed actions** carry `chain_id`, the validator's current `nonce` and the action fields in the signed message; the register increments `nonce` on every accepted Unbond/Withdraw/registration, which is the replay protection.
- **Withdraw creates a deposit note the ledger can check**: the action carries the note's blinding `r` and the ledger computes `cm = H(CM, (payout.pk, from = 0, amount, asset 0, time = height, r))` itself through a new executor method, so a validator cannot mint more than it withdraws. The payout address is public in the register already (spec §8), so publishing `r` leaks nothing new; the note's later spend is unlinkable as any other.
- **State root**: unchanged formula and domain (`shrugg-state-2`), but the validator leaf becomes `blake3("shrugg-validator-leaf-2", addr || stake || rewards || nonce || Σ pending (release_epoch, amount) || payout pk || payout kem_ek)`.
- `burn` is allowed only when the action is `Bond` and equals the bond amount; every other action keeps `burn = 0` (S3 adds `BridgeBurn`).
- No slashing, no jailing (spec §13).
- Commit style as S1.

## Rulings made in this plan

| ruling | why | cost if wrong |
|---|---|---|
| epoch set derived from the parent ledger in the block tree (not only from committed state) | the epoch-start block's parent may be uncommitted under chained HotStuff; all replicas hold the same parent ledger | forks across a boundary derive different sets, which HotStuff resolves like any fork |
| QCs verified per certified block's epoch; `epoch_sets` persisted | replay and sync must verify old QCs without holding old registers | one extra column family |
| Withdraw publishes `r` | closes the "validator declares one amount, mints another" gap flagged in S1 | the withdraw note is linkable to the validator, which the public payout address already is |
| validator `nonce` in the register | Unbond/Withdraw are signed but the chain has no accounts or nonces since S1 | one more `u64` per entry |
| `epoch_blocks` in genesis | cluster tests cannot wait 1000 blocks per epoch | one more genesis field |
| the node binary, not the wallet, signs Unbond/Withdraw/register | they need the Dilithium2 validator key the node already holds | operators use two tools (`shrugg` for bonds, `shrugg-node` for the validator side) |

## File structure

```
crates/shrugg-core/src/
  ledger.rs               [edit] delegates Bond/Unbond/Withdraw to staking.rs; epoch(); validator leaf v2; burn rule
  ledger/staking.rs       [new]  ValidatorEntry, Registration, derive_set, bond/unbond/withdraw/credit_fee, StakingError
  types/transaction.rs    [edit] Action::{Bond, Unbond, Withdraw}, signing messages
  types/validator.rs      [edit] ValidatorSet::from_entries, stake u64 → u128 boundary
  consensus/mod.rs        [edit] ConsensusConfig { genesis_set, epoch_blocks }; EpochSets
  consensus/hotstuff.rs   [edit] set_for_height, leader/quorum/QC verification per epoch
  consensus/tests.rs      [edit] epoch rollover simulation
  confidential.rs         [edit] trait: note_commitment(); StubExecutor impl
  genesis.rs              [edit] GenesisValidator.payout, epoch_blocks
crates/shrugg-zkvm/src/executor.rs [edit] note_commitment()
crates/shrugg-node/src/
  storage.rs              [edit] validators rows v2; epoch_sets CF; commit/load/truncate; verify_chain per-epoch QCs
  node.rs                 [edit] HotStuff resume with EpochSets; sync QC verification per epoch
  rpc.rs                  [edit] shrugg_getValidators (full entries), shrugg_getEpoch
  main.rs                 [edit] genesis --validator key,stake,payout; unbond/withdraw/register subcommands
crates/shrugg-client/src/
  wallet.rs, main.rs      [edit] `shrugg bond <validator> <amount>`
crates/shrugg-node/tests/cluster.rs [edit] bond, epoch rollover with a fifth validator, unbond+withdraw
docs/shielded.md, docs/staking.md [edit/new]
```

---

### Task 1: The register and the staking rules in `shrugg-core`

**Files:**
- Create: `crates/shrugg-core/src/ledger/staking.rs` (move `ledger.rs` to `ledger/mod.rs` first)
- Modify: `crates/shrugg-core/src/types/transaction.rs`, `confidential.rs`, `types/validator.rs`, `ledger/mod.rs`, `genesis.rs`
- Test: unit tests in `staking.rs`, `ledger/mod.rs`, `genesis.rs`

**Interfaces:**

```rust
// staking.rs
pub const EPOCH_BLOCKS_DEFAULT: u64 = 1000; pub const UNBONDING_EPOCHS: u64 = 2;
pub const MIN_STAKE: u64 = 1000 * UNITS_PER_SHRUGG; pub const MAX_VALIDATORS: usize = 100;
pub struct ValidatorEntry { pub public_key: PublicKey, pub stake: u64, pub pending: Vec<(u64 /*release_epoch*/, u64)>, pub rewards: u64, pub payout: ShieldedAddress, pub nonce: u64 }
pub struct Registration { pub public_key: PublicKey, pub payout: ShieldedAddress, pub signature: Signature }   // signs registration_message(chain_id, payout)
pub fn derive_set(register: &BTreeMap<Address, ValidatorEntry>) -> ValidatorSet;
pub enum StakingError { UnknownValidator(Address), AlreadyRegistered(Address), BelowMinStake { amount: u64, min: u64 }, RegistrationRequired, BadRegistration, BadNonce { expected: u64, actual: u64 }, BadSignature, InsufficientStake { have: u64, want: u64 }, NothingReleased { available: u64, want: u64 }, BurnMismatch { burn: u64, amount: u64 }, Overflow }
impl Register (methods on Ledger, delegating here):
  pub fn bond(&mut self, validator: Address, amount: u64, registration: Option<&Registration>, chain_id: u64) -> Result<(), StakingError>;
  pub fn unbond(&mut self, validator: &Address, amount: u64, nonce: u64, signature: &Signature, chain_id: u64) -> Result<(), StakingError>;
  pub fn withdraw(&mut self, validator: &Address, amount: u64, nonce: u64, signature: &Signature, chain_id: u64) -> Result<u64 /*available after*/, StakingError>;
  pub fn released(&self, validator: &Address) -> u64;   // rewards + pending with release_epoch <= current epoch
// transaction.rs
pub enum Action { None, Mint{..}, Deploy{..}, Call{..},
  Bond { validator: Address, amount: u64, registration: Option<Registration> },
  Unbond { validator: Address, amount: u64, nonce: u64, signature: Signature },
  Withdraw { validator: Address, amount: u64, nonce: u64, r: Word8, envelope: Envelope, signature: Signature } }
pub fn unbond_message(chain_id, validator, amount, nonce) -> Hash;   // blake3 "shrugg-unbond"
pub fn withdraw_message(chain_id, validator, amount, nonce, r, envelope) -> Hash;  // blake3 "shrugg-withdraw"
pub fn registration_message(chain_id, payout: &ShieldedAddress) -> Hash;  // blake3 "shrugg-register"
// confidential.rs
fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8;   // H(CM, 28 words) — Stub: blake3 stand-in
// ledger
pub fn epoch_blocks(&self) -> u64; pub fn epoch(&self) -> u64 /* of self.height */; pub fn set_epoch_blocks(&mut self, n: u64);
pub fn derive_next_set(&self) -> ValidatorSet;   // = staking::derive_set(&self.validators)
```

Admission additions (spec §7 order, action step): `Bond` → the bundle's `burn == amount` else `BurnMismatch`; registration present iff the validator is unknown; `amount ≥ MIN_STAKE` when registering; `Unbond`/`Withdraw` → validator known, nonce matches, signature valid, amounts available; `Withdraw` → the ledger computes `cm` via `executor.note_commitment(payout.pk, [0;8], amount, 0, height as u32, r)` and treats it exactly like a Mint deposit (commitment new, appended, envelope stored). Apply: `Bond` adds to `stake` (registration inserts the entry with `nonce = 0`), `Unbond` moves to `pending` with `release_epoch = epoch + UNBONDING_EPOCHS` and bumps `nonce`, `Withdraw` drains released pending entries then rewards, bumps `nonce`, appends the note.

- [ ] Step 1: tests first — `derive_set_filters_sorts_and_caps` (11 entries, two below min stake, cap 100 not hit; a second case with 101 eligible caps at 100 by stake then address), `bond_registers_and_tops_up`, `bond_requires_burn_equal_to_amount`, `unbond_moves_to_pending_and_needs_nonce_and_signature`, `withdraw_pays_released_and_rewards_into_a_checkable_note` (Stub `note_commitment` equals the appended cm; a wrong `r` changes it), `withdraw_rejects_unreleased_pending`, `validator_leaf_v2_changes_the_root_when_pending_or_payout_change`, `genesis_seeds_payout_and_epoch_blocks`.
- [ ] Step 2: run, see them fail. Step 3: implement `staking.rs` and the ledger/transaction/genesis edits. Step 4: `cargo test -p shrugg-core` green (the S1 tests keep passing: existing bundles have `burn = 0` and no staking action). Step 5: commit `core: staking register — ValidatorEntry v2, Bond/Unbond/Withdraw, epoch derivation, checkable withdraw notes`.

---

### Task 2: Epoch-aware HotStuff

**Files:** `crates/shrugg-core/src/consensus/{mod.rs, hotstuff.rs, tests.rs}`, `types/validator.rs`, `types/block.rs` (QC verify takes the set as today).

**Interfaces:**

```rust
pub struct ConsensusConfig { pub genesis_hash: Hash, pub genesis_set: ValidatorSet, pub epoch_blocks: u64, /* existing timing fields */ }
pub struct EpochSets { .. }  // known sets: epoch -> ValidatorSet, seeded with (0, genesis_set); persisted by the node
impl EpochSets { pub fn get(&self, epoch: u64) -> Option<&ValidatorSet>; pub fn insert(&mut self, epoch: u64, set: ValidatorSet); pub fn known(&self) -> impl Iterator<Item=(u64, &ValidatorSet)>; }
impl HotStuff {
    pub fn set_for_height(&self, h: u64, parent: &Hash) -> Option<ValidatorSet>;   // epoch(h) == epoch(parent height) ⇒ parent's set; else derive_set(parent entry's ledger_after) — cached per (epoch, epoch-start parent hash)
    pub fn current_set(&self) -> &ValidatorSet;   // set of epoch(high_qc height + 1)
    pub fn epoch_sets(&self) -> &EpochSets;        // sets of committed epochs, for the node to persist
}
```

Rules to implement: `leader(view)` uses `current_set()`; `on_proposal` checks `block.proposer() == set_for_height(block.height(), &block.parent()).leader(block.view())` and verifies `justify` against `set_for_height(parent.height, parent.parent)` (the certified block's own epoch); `on_vote` accepts voters in the set of the voted block's height and counts quorum in that set; `on_new_view` counts quorum in `current_set()`; committing the first block of an epoch records that epoch's set in `epoch_sets` (an `Action::RecordEpochSet(epoch, set)` for the node to persist, alongside `Action::Commit`); `resume` takes `EpochSets` loaded from storage. A validator whose key is not in the current set observes (no votes, no proposals) but keeps `signer` so it can rejoin next epoch. `ValidatorSet::from_entries` widens `u64` stake to `u128`.

- [ ] Tests (simulated network in `consensus/tests.rs`, `epoch_blocks = 4`): `epoch_rollover_uses_the_register_after_the_last_block_of_the_previous_epoch` (five keys, genesis set = four; a Bond registering the fifth lands in block 2; from block 4 on the leader schedule and quorum count the fifth and its votes; a vote from it in epoch 0 is rejected), `an_unbond_below_min_stake_drops_a_validator_next_epoch_and_the_chain_keeps_quorum`, `qcs_across_a_boundary_verify_against_their_own_epoch` (a replica resumed from committed height 3 with persisted sets verifies block 4's justify against epoch 0's set and block 5's against epoch 1's), plus the existing suite green.
- [ ] Commit `core: epoch-aware HotStuff — per-epoch validator sets derived from the register, QCs verified per certified epoch`.

---

### Task 3: Storage, node, RPC, node CLI

**Files:** `crates/shrugg-node/src/{storage.rs, node.rs, rpc.rs, main.rs}`, `crates/shrugg-zkvm/src/executor.rs` (`note_commitment` = `Note{..}.commitment()`).

- Storage: `validators` rows hold `ValidatorEntry` v2; new CF `epoch_sets` (epoch BE u64 → bincode(ValidatorSet)); `commit` writes every touched entry (bond/unbond/withdraw targets and the proposer) and the epoch set carried by `Action::RecordEpochSet`; `load_epoch_sets`; `truncate_to` deletes epoch sets above the epoch of the new head and rewrites entries from the ledger; `verify_chain` verifies each block's QC against the persisted set of its epoch and re-derives the set at every boundary from its replayed ledger, failing on mismatch; `init_genesis` writes epoch 0.
- Node: `HotStuff::resume(cfg with genesis_set + epoch_blocks, .., epoch_sets)`; `apply_synced` verifies QCs per epoch; the node's `is_validator` becomes "signer present", while "in the current set" is reported in `shrugg_status` as `active_validator: bool`.
- RPC: `shrugg_getValidators` → `[{address, stake, pending: [{release_epoch, amount}], rewards, payout, nonce, active}]`; `shrugg_getEpoch` → `{epoch, epoch_blocks, next_set: [addresses]}`.
- `shrugg-node genesis --validator <keyfile>,<stake>,<payout shrugg1…>` (repeatable), `--epoch-blocks n`; `shrugg-node register --payout <addr>` prints a `Registration` (hex) for a wallet to attach to its bond; `shrugg-node unbond <amount>` and `shrugg-node withdraw <amount>` build and submit the validator-signed transactions (they read the node's key and query `shrugg_getValidators` for the nonce; `withdraw` draws `r`, seals the envelope to the payout address with a throwaway sender key, prints the tx hash).
- Tests: storage round-trips of v2 entries and epoch sets; `verify_chain` rejects a block whose QC is signed by a set from the wrong epoch; RPC shapes. Gate `cargo test -p shrugg-node` (cluster tests come in Task 5).
- Commit `node: staking — epoch sets persisted and verified, validator register RPC, register/unbond/withdraw commands`.

---

### Task 4: Wallet `bond`

**Files:** `crates/shrugg-client/src/{wallet.rs, main.rs, lib.rs}`.

- `shrugg bond <validator address> <amount SHRUGG> [--registration <hex>] [--fee]`: `wallet::submit` with `burn = amount` and `action = Bond { .. }` (the bundle's outputs are the change only: `amount` leaves the pool; the guest's balance is `in = out + fee + burn`). `RpcClient::{validators, epoch}`.
- Tests: `bond_bundle_balances_with_burn` (unit, stub-free arithmetic on the note selection), and the flow test in `tests/wallet_flow.rs` gains a bond against a genesis validator and asserts the register's stake grew by the amount (proves one bundle, ~1 min).
- Commit `client: shrugg bond`.

---

### Task 5: Cluster end-to-end and docs

- `cluster.rs`, `epoch_blocks = 6`: `a_fifth_validator_registers_bonds_and_joins_the_next_epoch` (bond with registration from wallet A; wait for the epoch boundary; the fifth node proposes at least one block; every node agrees on the state root), `unbond_below_min_stake_leaves_the_set_and_withdraw_pays_a_spendable_note` (validator D unbonds to 0, drops out after two epochs, withdraws after `UNBONDING_EPOCHS`, the payout wallet scans the note and sends 1 SHRUGG from it).
- `docs/staking.md` (new): the register, epochs, the three actions with exact CLI commands, what is public; `docs/shielded.md` and `docs/rpc.md` updated; `deploy/README.md` genesis command.
- Full workspace suite green; commit `node: staking end-to-end; docs: staking`.

## Self-review

Spec §8 coverage: register ✓ (T1), epochs and set derivation ✓ (T1 derive_set, T2), registration ✓, Bond ✓, Unbond ✓, rewards to proposer (S1) and Withdraw ✓, no slashing ✓, register in the state root ✓ (leaf v2), genesis seeding ✓ (T1/T3). §6 rows: Bond burn = amount ✓, Unbond/Withdraw validator-signed ✓ with nonces (plan ruling). Placeholder scan: every task names its tests and commands; the consensus rules are stated as decidable predicates. Type consistency: `ValidatorEntry`, `Registration`, `derive_set`, `EpochSets`, `set_for_height`, `Action::RecordEpochSet`, `note_commitment`, `epoch_blocks` are named identically across tasks.
