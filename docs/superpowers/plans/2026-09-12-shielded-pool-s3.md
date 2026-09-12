# Fully shielded pool — Phase S3 (call-input envelopes, bridge as notes) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the shielded chain's action model: (1) confidential calls leave an encrypted transcript of their private inputs on chain that only the caller's viewing key, a per-call key, or a designated auditor can open (spec §6.1); (2) the bridge moves onto the pool — attestations deposit notes in the bridged asset, `BridgeBurn` spends an asset bundle plus a SHRUGG fee bundle, per-account bridge balances disappear, and the bridge's own public state (emitters, guardian sets, asset registry, spent digests, burn log) returns to the state root (spec §10).

**Architecture:** S3 runs in parallel with S2 after a shared scaffold task (Task 0, executed once, before either phase's Task 1) that adds every S2 and S3 `Action` variant to the enum with `TxError::UnsupportedAction` stubs and splits the ledger's action handling into per-feature modules: `ledger/staking.rs` (S2), `ledger/call_envelope.rs` and `ledger/bridge_notes.rs` (S3). S3 then touches only its two modules, the `bridge` module, the executor's call proving API, the bridge RPC methods, and the wallet's `call`/`bridge-*` commands. The chain checks nothing about a call envelope's ciphertext (as with note envelopes); binding comes from the proof's public `H_IN`, which the envelope carries as AEAD associated data. Bridged assets are notes with `asset = index` where the bridge registry assigns a dense `u32` index per registered asset (0 is SHRUGG). S2 and S3 ship as one hard fork.

**Tech Stack:** unchanged (the `ml-kem`/`chacha20poly1305` already in `shrugg-zkvm`; `bridge-codec` unchanged).

**Spec:** `docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §6 (BridgeAttest, BridgeBurn rows), §6.1 (call input envelopes), §7, §10 (bridge on the shielded chain), §12 (S3 row). `docs/bridge.md` describes the bridge wire format and state as of the account era.

## Global Constraints

- **Scaffold first** (Task 0) — S2's Task 1 and S3's Task 1 both start from its commit.
- **Call envelope**: `CallEnvelope { kem_ct: Vec<u8>, to_sender: Vec<u8>, to_auditor: Vec<u8>, body: Vec<u8> }`; `body = ChaCha20-Poly1305(K_call; nonce || salt(16 bytes) || inputs as LE u32 words)` with AAD = the 32 bytes of `H_IN` (`pv::IN0..7` of the call proof, LE words); `to_sender = ChaCha20-Poly1305(ovk_caller; K_call)` with AAD `b"shrugg-call-sender"`; `to_auditor`/`kem_ct` = `K_call` sealed with ML-KEM-768 to the auditor's `kem_ek`, empty when no auditor. Caps: inputs ≤ 4096 words, so `body ≤ 16 KiB + 12 + 16 + 16`; `MAX_CALL_ENVELOPE_BYTES = 17_000`. The ledger checks only the caps and that an envelope is present or absent (`input_envelope: Option<CallEnvelope>`), never the ciphertext.
- **Asset index**: `BridgeState.assets` gains `index: u32` per asset (assigned `1, 2, …` in registration order, persisted in `BridgeMeta`); `asset_index(&AssetId) -> Option<u32>`, `asset_by_index(u32) -> Option<AssetId>`. A note's `asset` field is that index. Bridged amounts must fit `u64` (`BridgeError::AmountTooLarge` otherwise; the wire format's `u128` is preserved on the bridge side).
- **Recipient binding for attestations**: the wire `to: [u8; 32]` field of a Transfer payload is `blake3("shrugg-shielded-recipient", pk_bytes || kem_ek)` of the recipient's shielded address; the submitting transaction carries the full `recipient: ShieldedAddress` and a blinding `r`, and the ledger recomputes both the hash and `cm = note_commitment(recipient.pk, [0; 8], amount as u64, asset_index, height as u32, r)` (the S2 executor method). Deposit amount public, recipient's address public in that transaction only (the same as a Withdraw).
- **BridgeBurn is one transaction with two bundles**: the outer `Transaction.bundle` is the SHRUGG bundle paying `BUNDLE_BASE` (`asset = 0`, `burn = 0`); `Action::BridgeBurn { asset_bundle: Bundle, asset: u32, amount: u64, relayer_fee: u64, to_chain: u16, to: [u8; 32] }` carries the asset bundle with `asset_bundle.asset = asset`, `asset_bundle.fee = 0`, `asset_bundle.burn = amount + relayer_fee`. Both bundles go through the full admission (all four nullifiers distinct and unspent, all four commitments new, both digests, both STARK verifies). The burn record's sender field is the transaction hash (there is no sender identity).
- **Bridge state root** returns to the state root as the fifth component when a genesis has a `bridge` section: `blake3("shrugg-state-2" || tree || nullifiers || validators || programs || bridge_root)`; `BridgeState::root` no longer covers `balances`, which are deleted from the struct, the storage and the RPC.
- Genesis `bridge` sections are accepted again (S1's rejection removed).
- Commit style as S1/S2.

## Rulings made in this plan

| ruling | why | cost if wrong |
|---|---|---|
| the asset bundle rides inside the `BridgeBurn` action | keeps `Transaction { bundle, action }` and one admission path; the spec's "two bundles" is a shape, not a wire requirement | an action carrying a 300 KB proof; sizes capped |
| dense `u32` asset indices in the registry | the note format has a `u32` asset word; the bridge's 32-byte asset ids do not fit | index assignment is consensus state (in `BridgeMeta`) |
| attestation `to` = blake3 of the shielded address, full address in the action | the wire format's recipient field is 32 bytes; guardians sign what the source-chain contract emitted | a source-chain user must compute the hash of a 1.2 KB address; documented in `docs/bridge.md` |
| call envelope is optional (`--no-envelope`) and never checked beyond sizes | spec §6.1 (voluntary disclosure; chain checks nothing about ciphertexts) | a false envelope is provable by whoever decrypts it, not by the chain |
| `prove_call` returns the salt | the envelope must carry the salt that produced `H_IN`; `Machine::prove` draws it internally today | none; `prove_salted` already exists |

## File structure

```
crates/shrugg-core/src/
  types/transaction.rs      [Task 0] Action gains Bond/Unbond/Withdraw/BridgeAttest/BridgeBurn; Call gains input_envelope
  types/actions.rs          [Task 0, new] Registration, CallEnvelope, the staking/bridge action field structs
  ledger/mod.rs             [Task 0] action dispatch to modules; UnsupportedAction
  ledger/staking.rs         [Task 0 stub; S2 fills]
  ledger/call_envelope.rs   [S3 Task 1] size checks; envelope stored with the receipt
  ledger/bridge_notes.rs    [S3 Task 2] attest → deposit note; burn → two-bundle admission; state root
  bridge/state.rs           [S3 Task 2] balances removed; asset indices; check/apply without balances
  confidential.rs           [Task 0] note_commitment() on the trait (S2 and S3 both need it)
crates/shrugg-zkvm/src/executor.rs [S3 Task 1] prove_call → (proof, outputs, tier, salt); note_commitment
crates/shrugg-zkvm/src/call_envelope.rs [S3 Task 1, new] seal/open helpers over viewing.rs primitives
crates/shrugg-node/src/{storage.rs, rpc.rs, node.rs} [S3 Task 3] receipts carry the envelope; bridge CFs (spent, burns) back; bridge RPC; shrugg_getCallEnvelope
crates/shrugg-client/src/{wallet.rs, main.rs, lib.rs} [S3 Task 4] call --auditor/--no-envelope, open-call, bridge-mint, bridge-burn, asset-balance
crates/shrugg-node/tests/cluster.rs [S3 Task 5]; docs/bridge.md, docs/confidential.md, docs/shielded.md [S3 Task 5]
```

---

### Task 0: Scaffold shared by S2 and S3 (run once, first)

**Files:** `types/transaction.rs`, `types/actions.rs` (new), `ledger/mod.rs` (moved from `ledger.rs`), `ledger/{staking,call_envelope,bridge_notes}.rs` (stubs), `confidential.rs`, `rpc.rs` (`tx_json` variant names), `genesis.rs` (accept `bridge` and the S2 fields with defaults).

- Add to `Action`: `Bond { validator: Address, amount: u64, registration: Option<Registration> }`, `Unbond { validator: Address, amount: u64, nonce: u64, signature: Signature }`, `Withdraw { validator: Address, amount: u64, nonce: u64, r: Word8, envelope: Envelope, signature: Signature }`, `BridgeAttest { attestation: Vec<u8>, recipient: ShieldedAddress, r: Word8, envelope: Envelope }`, `BridgeBurn { asset_bundle: Bundle, asset: u32, amount: u64, relayer_fee: u64, to_chain: u16, to: [u8; 32] }`; `Call` gains `input_envelope: Option<CallEnvelope>` (S1's `Call` constructors pass `None`).
- `ledger/mod.rs::validate_inner` and `apply_tx` dispatch the five new variants to `staking::{validate, apply}` and `bridge_notes::{validate, apply}` and the envelope to `call_envelope::validate`; every stub returns `Err(TxError::UnsupportedAction(&'static str))`; a test per variant asserts the stub error so S2/S3 turn it green.
- `ConfidentialExecutor::note_commitment(pk, from, amount, asset, time, r) -> Word8` with the stub (blake3) and `ZkExecutor` (`Note { .. }.commitment()`) implementations and a test that the zkvm one equals the vendored `Note::commitment()`.
- `gas::fee_floor` returns `BUNDLE_BASE` for the new actions (S2/S3 refine).
- Gate: whole workspace green (S1's suites unchanged). Commit `core: S2/S3 scaffold — action variants, per-feature ledger modules, note_commitment`.

---

### Task 1: Call-input envelopes

**Files:** `crates/shrugg-zkvm/src/{executor.rs, call_envelope.rs}`, `crates/shrugg-core/src/ledger/call_envelope.rs`, `crates/shrugg-core/src/program.rs` (`CallReceipt.input_envelope: Option<CallEnvelope>`), node `rpc.rs` (`shrugg_getCallEnvelope(tx) -> envelope hex fields | null`), storage receipts (the envelope is inside the receipt row).

**Interfaces:**

```rust
// shrugg-zkvm
pub fn prove_call(profile, program: &Program, inputs: &[u32], tier: Option<u8>, backend) -> Result<(Vec<u8>, [u32; 8], u8, [u32; 4] /*salt*/), String>;
pub struct CallKey(pub [u8; 32]);
pub fn seal_call_envelope(caller: &ViewingKey, auditor: Option<&ShieldedAddress>, h_in: &Word8, salt: [u32; 4], inputs: &[u32]) -> Result<(CallEnvelope, CallKey), String>;
pub fn open_call_as_sender(e: &CallEnvelope, h_in: &Word8, vk: &ViewingKey) -> Option<(CallKey, [u32; 4], Vec<u32>)>;
pub fn open_call_with_key(e: &CallEnvelope, h_in: &Word8, key: &CallKey) -> Option<([u32; 4], Vec<u32>)>;
pub fn open_call_as_auditor(e: &CallEnvelope, h_in: &Word8, auditor: &ViewingKey) -> Option<(CallKey, [u32; 4], Vec<u32>)>;
/// True iff input_digest(salt, inputs) == h_in — what a holder checks before trusting a transcript.
pub fn call_envelope_is_faithful(h_in: &Word8, salt: [u32; 4], inputs: &[u32]) -> bool;
```

- Ledger: `call_envelope::validate(env: &Option<CallEnvelope>) -> Result<(), TxError>` (size caps only); `apply` stores it in the receipt.
- Tests (zkvm): seal/open as sender, with the key, and as auditor; a tampered `h_in` fails to open (AAD); a faithful envelope passes `call_envelope_is_faithful` and a wrong salt does not; `prove_call`'s salt reproduces `pv::IN0..7` via `hash::input_digest`. Ledger: cap enforcement; receipts round-trip the envelope.
- Commit `zkvm+core: call-input envelopes — sealed to the caller's ovk and an optional auditor, bound to H_IN`.

---

### Task 2: Bridge as notes (`shrugg-core`)

**Files:** `bridge/state.rs`, `ledger/bridge_notes.rs`, `ledger/mod.rs` (state root fifth component; genesis bridge accepted), `genesis.rs`.

- `BridgeState`: delete `balances` and every read/write of it; `assets: BTreeMap<AssetId, AssetInfo { chain: u16, token: [u8; 32], index: u32 }>`, `next_index: u32` in `BridgeMeta`; `check_attest`/`apply_attest` return the decoded transfer `(asset_index, amount: u64, to_hash)` instead of crediting a balance; `check_burn(asset_index, amount, to_chain, to, relayer_fee)` validates the destination format and asset only; `apply_burn(tx_hash, ..)` records the burn message with the tx hash as sender; `root()` over the remaining collections.
- `bridge_notes::validate`: `BridgeAttest` → attestation size cap → decode/verify (existing guardian logic) → `amount ≤ u64::MAX` → `blake3(recipient) == to` → `cm = note_commitment(..)` new → deposit path; `BridgeBurn` → the outer bundle is SHRUGG with `burn = 0`; the asset bundle passes the full bundle admission with `asset == action.asset`, `fee == 0`, `burn == amount + relayer_fee`, nullifiers/commitments distinct from the outer bundle's; `check_burn`. `apply`: attest appends the note and marks the digest spent; burn inserts both bundles' nullifiers/commitments and records the burn.
- Tests (stub executor): attest deposits a checkable note and rejects a recipient whose hash differs; a second identical attestation is rejected (spent digest); burn with a wrong `asset`/`fee`/`burn` on the asset bundle is rejected before any verify; a valid two-bundle burn spends four nullifiers and records a burn message with the tx hash; the state root gains the bridge root only on bridged chains (an unbridged genesis's root is byte-identical to S1's).
- Commit `core: bridge as notes — attestations deposit notes by asset index, two-bundle BridgeBurn, balances removed, bridge root back in the state root`.

---

### Task 3: Node — storage, RPC, sync

- Storage: `bridge_spent`, `bridge_burns` families and the `bridge_state` meta return (`bridge_balances` gone); `commit`/`load_ledger`/`truncate_to` handle them as S1's account-era code did minus balances; receipts carry the call envelope.
- RPC: `shrugg_getBridgeState`, `shrugg_getBridgeBurn`, `shrugg_bridgeAssetId`, `shrugg_getAssets` (registry with indices), `shrugg_getCallEnvelope`; `tx_json` renders the new actions (attestation length, recipient, asset index, amount; burn: asset, amount, relayer fee, destination, the asset bundle's public fields).
- Sync/replay unchanged in structure (apply_block does the work).
- Gate `cargo test -p shrugg-node`. Commit `node: bridge state families and RPC on the shielded chain; call envelopes in receipts`.

---

### Task 4: Wallet

- `shrugg call ... [--auditor <shrugg1…>] [--no-envelope]`: proves with `prove_call`, seals the envelope (unless disabled), submits `Action::Call { input_envelope }`; prints the per-call key on request (`--print-call-key`).
- `shrugg open-call <txhash> [--call-key <hex>] [--as-auditor]`: fetches the receipt and envelope, opens it, checks faithfulness against the receipt's `H_IN`, re-runs the emulator on the program code and inputs, prints inputs and outputs.
- `shrugg bridge-mint @attestation.hex [--to <own address>]`: builds `BridgeAttest` with `r` and an envelope sealed to the recipient, on a fee bundle from this wallet.
- `shrugg bridge-burn <asset index> <amount> <to_chain> <to hex> [--relayer-fee]`: selects asset notes for the asset bundle and SHRUGG notes for the fee bundle, proves both (two proofs), submits.
- `shrugg asset-balance [index]`: sums unspent notes of that asset; `notes` shows the asset column.
- `RpcClient` methods for the four bridge RPCs and `call_envelope`.
- Tests: `wallet_flow.rs` gains a call with an envelope opened back as sender; bridge commands are covered in Task 5.
- Commit `client: call envelopes (seal, open, verify), bridge-mint/bridge-burn on bundles, asset balances`.

---

### Task 5: Cluster end-to-end and docs

- `cluster.rs` with a bridged genesis (the existing guardian test keys): `bridge_mint_deposits_a_note_and_a_burn_spends_it` (attestation → note; asset balance on the wallet; two-bundle burn; burn record on every node; the attestation replayed is rejected), `a_call_envelope_is_opened_by_the_caller_and_the_auditor_only` (call with an auditor; the sender and auditor open it, a third wallet cannot; a tampered envelope fails the faithfulness check).
- Docs: `docs/bridge.md` rewritten for the shielded chain (the recipient hash, asset indices, two-bundle burns, what stays public; a banner that balances are notes now); `docs/confidential.md` §call envelopes; `docs/shielded.md` updated; `docs/rpc.md` methods.
- Full workspace green; commit `node: bridge and call-envelope end-to-end; docs`.

## Self-review

Spec coverage: §6.1 (what goes on chain, binding via `H_IN` AAD, who can open, voluntary, `--no-envelope`) → Tasks 1, 4; §6 BridgeAttest/BridgeBurn rows → Tasks 2–4; §10 (assets as notes, two-bundle burn, bridge state public, balances deleted) → Tasks 2–3; §7 admission (both bundles through the same order) → Task 2; §12 S3 row complete. Placeholder scan: sizes, domains and error variants are named; tests are named with their assertions. Type consistency: `CallEnvelope`, `prove_call`, `seal_call_envelope`/`open_call_*`, `note_commitment`, `asset_index`, `BridgeBurn { asset_bundle, .. }` used identically across tasks; Task 0's variant shapes are the ones S2's plan consumes (`Bond`, `Unbond`, `Withdraw`, `Registration`).
