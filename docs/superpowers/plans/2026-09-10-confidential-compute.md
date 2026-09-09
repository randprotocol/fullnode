# Confidential Computation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let SHRUGG pay for confidential zkVM calls: programs are deployed on chain, calls carry a STARK proof plus eight public outputs, every node verifies the proof, charges gas, and applies the transfer the program's outputs request.

**Architecture:** The zkVM (`rand_zkvm`, RV32I under a Plonky3 batch STARK) is vendored as `crates/shrugg-zkvm`. `shrugg-core` stays free of Plonky3: it defines programs, the two new transaction kinds, gas, the output-effect encoding, and an executor trait; `shrugg-zkvm` implements that trait with cached verifier keys; `shrugg-node` stores programs and receipts and exposes RPC; `shrugg-client` proves locally and submits.

**Tech Stack:** Rust 1.98.1, Plonky3 0.7 (Goldilocks, Poseidon2), postcard, RocksDB, libp2p, axum, clap.

**Spec:** `docs/superpowers/specs/2026-09-10-confidential-compute-design.md`

## Global Constraints

- Toolchain: `rust-toolchain.toml` pins `1.98.1` (Plonky3 0.7 needs `maybe_uninit_slice`); everything must build on it.
- `shrugg-core` must not depend on any `p3-*` crate. Only `shrugg-zkvm` does.
- Limits (constants in `shrugg_core::gas`): `MAX_PROGRAM_WORDS = 4096`, `MAX_PROOF_BYTES = 1 << 20`, `MAX_RECIPIENTS = 8`, `MAX_BLOCK_BYTES = 4 << 20`.
- Gas v0 (units, 1 SHRUGG = 1e9): `DEPLOY_PER_WORD = 100_000`, `CALL_BASE = 1_000_000`, `CALL_PER_TIER_STEP = 100_000`; transfers and mints stay free.
- Effect encoding: `out0` kind (0 none, 1 transfer), `out1` recipient index, `out2|out3` amount as LE u64, `out4..7` free.
- Every task ends with `cargo test -p <crate>` green and a commit. Commit messages end with the session attribution lines already used in this repo.
- Existing behaviour (transfers, mint, faucet, consensus, sync, integrity check) must keep passing its tests.

---

## File structure

| path | responsibility |
|---|---|
| `rust-toolchain.toml` (new) | pin 1.98.1 |
| `crates/shrugg-zkvm/` (new, vendored) | upstream `rand_zkvm` unchanged + `src/executor.rs` (ZkExecutor, key cache), `src/codec.rs` (program file formats), guest `private_payment` in `src/guests.rs` |
| `deploy/sync-zkvm.sh` (new) | copy `../circuits/research/{src,tests}` into the vendored crate |
| `crates/shrugg-core/src/gas.rs` (new) | limits and fee schedule |
| `crates/shrugg-core/src/effect.rs` (new) | decode the eight outputs into an `Effect` |
| `crates/shrugg-core/src/program.rs` (new) | `ProgramId`, `ProgramRecord`, `CallOutcome`, `CallReceipt` |
| `crates/shrugg-core/src/confidential.rs` (rewrite) | executor trait, `StubExecutor` v2 (no crypto, test only) |
| `crates/shrugg-core/src/types/transaction.rs` | `TxKind::{Deploy, Call}`, constructors |
| `crates/shrugg-core/src/ledger.rs` | programs map, Deploy/Call rules, receipts, state root |
| `crates/shrugg-core/src/genesis.rs` | `confidential`, `fri_profile` fields |
| `crates/shrugg-node/src/storage.rs` | `programs`, `receipts` column families |
| `crates/shrugg-node/src/mempool.rs` | byte accounting, verified-tx set |
| `crates/shrugg-node/src/node.rs` | executor construction, block byte cap, receipts on commit |
| `crates/shrugg-node/src/rpc.rs` | `shrugg_getProgram`, `shrugg_getProgramCode`, `shrugg_getReceipt`, `shrugg_estimateFee` |
| `crates/shrugg-client/src/{lib,main}.rs` | `program build/deploy/show`, `call`, `receipt` |
| `crates/shrugg-node/tests/cluster.rs` | end-to-end deploy + call |
| `docs/{cli,rpc,architecture}.md`, `README.md` | documentation |

---

### Task 1: Vendor the zkVM and move the workspace to Rust 1.98.1

**Files:**
- Create: `rust-toolchain.toml`, `deploy/sync-zkvm.sh`, `crates/shrugg-zkvm/Cargo.toml`, `crates/shrugg-zkvm/src/**`, `crates/shrugg-zkvm/tests/**` (copied)
- Modify: `Cargo.toml` (workspace members, dependency entry)

**Interfaces:**
- Produces: crate `shrugg-zkvm` (lib name `shrugg_zkvm`) re-exporting upstream modules `isa, asm, guests, emulator, tables, machine`.

- [ ] **Step 1: Pin the toolchain and confirm the existing workspace builds on it**

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.98.1"
```

Run: `cargo build --release && cargo test -p shrugg-core`
Expected: builds; 47 core tests pass (this was already verified with `cargo +1.98.1 check --workspace`).

- [ ] **Step 2: Write the sync script and run it**

```bash
#!/usr/bin/env bash
# deploy/sync-zkvm.sh — copy the research zkVM into crates/shrugg-zkvm. Run from the repo root.
set -euo pipefail
SRC=${1:-../circuits/research}
DST=crates/shrugg-zkvm
mkdir -p "$DST"
rsync -a --delete --exclude target --exclude .git --exclude Cargo.lock --exclude rust-toolchain.toml \
      --exclude src/executor.rs --exclude src/codec.rs --exclude src/guests.rs "$SRC/src" "$SRC/tests" "$DST/"
# guests.rs is kept locally (it gains private_payment); copy it only if we have none yet
[ -f "$DST/src/guests.rs" ] || cp "$SRC/src/guests.rs" "$DST/src/guests.rs"
REV=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)
echo "synced zkVM from $SRC at $REV into $DST"
```

Run: `chmod +x deploy/sync-zkvm.sh && ./deploy/sync-zkvm.sh`

- [ ] **Step 3: Write the crate manifest (renamed, same dependencies as upstream)**

```toml
# crates/shrugg-zkvm/Cargo.toml
[package]
name = "shrugg-zkvm"
version.workspace = true
edition = "2021"
license.workspace = true
authors.workspace = true
description = "Rand zkVM (RV32I under a Plonky3 batch STARK) plus the SHRUGG chain executor"

[lib]
name = "shrugg_zkvm"
path = "src/lib.rs"

[[bin]]
name = "shrugg-zkvm-demo"
path = "src/main.rs"

[dependencies]
shrugg-core = { workspace = true }
p3-air = "=0.7.0"
p3-uni-stark = "=0.7.0"
p3-batch-stark = "=0.7.0"
p3-lookup = "=0.7.0"
p3-goldilocks = "=0.7.0"
p3-field = "=0.7.0"
p3-matrix = "=0.7.0"
p3-challenger = "=0.7.0"
p3-commit = "=0.7.0"
p3-fri = "=0.7.0"
p3-dft = "=0.7.0"
p3-merkle-tree = "=0.7.0"
p3-symmetric = "=0.7.0"
rand = { version = "0.10", features = ["std_rng"] }
serde = { workspace = true }
serde_json = { workspace = true }
postcard = { version = "1", features = ["alloc"] }
```

Note: upstream uses `rand 0.10`; the workspace uses `rand 0.8` for the node. Both can coexist (different major versions). Do not add `rand 0.10` to `[workspace.dependencies]`.

- [ ] **Step 4: Fix upstream references to the crate name**

Upstream code refers to itself as `rand_zkvm` in `src/main.rs` and `tests/*.rs`. Run:
`grep -rl "rand_zkvm" crates/shrugg-zkvm | xargs sed -i '' 's/rand_zkvm/shrugg_zkvm/g'`

- [ ] **Step 5: Add the crate to the workspace**

In `Cargo.toml`: `members = ["crates/shrugg-core", "crates/shrugg-zkvm", "crates/shrugg-client", "crates/shrugg-node"]` and under `[workspace.dependencies]`: `shrugg-zkvm = { path = "crates/shrugg-zkvm" }`.

- [ ] **Step 6: Run the upstream tests inside the workspace**

Run: `cargo test -p shrugg-zkvm --release` (release: the STARK tests take minutes in debug)
Expected: all upstream tests pass (e2e, zk, cheating, emulator, isa, asm, tables).

- [ ] **Step 7: Commit**

```bash
git add rust-toolchain.toml deploy/sync-zkvm.sh crates/shrugg-zkvm Cargo.toml Cargo.lock
git commit -m "zkvm: vendor rand_zkvm as shrugg-zkvm; workspace on Rust 1.98.1"
```

---

### Task 2: Gas schedule and output-effect decoding (pure, in shrugg-core)

**Files:**
- Create: `crates/shrugg-core/src/gas.rs`, `crates/shrugg-core/src/effect.rs`
- Modify: `crates/shrugg-core/src/lib.rs` (add `pub mod gas; pub mod effect;`)

**Interfaces:**
- Produces: `gas::{MAX_PROGRAM_WORDS, MAX_PROOF_BYTES, MAX_RECIPIENTS, MAX_BLOCK_BYTES, DEPLOY_PER_WORD, CALL_BASE, CALL_PER_TIER_STEP, deploy_fee(words: usize) -> u128, call_fee(tier: u8) -> u128, MIN_TIER, MAX_TIER}` and `effect::{Effect, EffectError, decode(outputs: &[u32; 8], recipients: &[Address]) -> Result<Effect, EffectError>}`.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/shrugg-core/src/gas.rs
//! Limits and the v0 fee schedule for confidential computation.

/// Largest program, in 32-bit words (16 KiB of code).
pub const MAX_PROGRAM_WORDS: usize = 4096;
/// Largest proof accepted in a transaction.
pub const MAX_PROOF_BYTES: usize = 1 << 20;
/// Largest public recipient list on a call.
pub const MAX_RECIPIENTS: usize = 8;
/// Transaction bytes per block (proofs are ~0.9 MB each).
pub const MAX_BLOCK_BYTES: usize = 4 << 20;
/// zkVM tiers (log2 of the CPU table height).
pub const MIN_TIER: u8 = 10;
pub const MAX_TIER: u8 = 20;

pub const DEPLOY_PER_WORD: u128 = 100_000;
pub const CALL_BASE: u128 = 1_000_000;
pub const CALL_PER_TIER_STEP: u128 = 100_000;

/// Minimum fee to deploy a program of `words` words.
pub fn deploy_fee(words: usize) -> u128 {
    DEPLOY_PER_WORD * words as u128
}

/// Minimum fee for a call proven at `tier` (10, 12, ..., 20).
pub fn call_fee(tier: u8) -> u128 {
    let steps = (tier.saturating_sub(MIN_TIER) / 2) as u128;
    CALL_BASE + CALL_PER_TIER_STEP * steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_fee_is_linear_in_words() {
        assert_eq!(deploy_fee(0), 0);
        assert_eq!(deploy_fee(1), 100_000);
        assert_eq!(deploy_fee(256), 25_600_000); // 0.0256 SHRUGG for a 1 KiB program
    }

    #[test]
    fn call_fee_steps_every_two_tiers() {
        assert_eq!(call_fee(10), 1_000_000);
        assert_eq!(call_fee(12), 1_100_000);
        assert_eq!(call_fee(20), 1_500_000);
        assert_eq!(call_fee(0), 1_000_000, "below MIN_TIER saturates");
    }
}
```

```rust
// crates/shrugg-core/src/effect.rs
//! The eight public output words of a call are the program's instruction to the chain.

use crate::crypto::Address;

pub const KIND_NONE: u32 = 0;
pub const KIND_TRANSFER: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    Transfer { to: Address, amount: u128 },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum EffectError {
    #[error("unknown effect kind {0}")]
    UnknownKind(u32),
    #[error("recipient index {index} out of range (list has {len})")]
    RecipientIndex { index: u32, len: usize },
}

/// Decode `outputs` against the call's public recipient list.
/// out0 = kind, out1 = recipient index, out2|out3 = amount as little-endian u64, out4..7 free.
pub fn decode(outputs: &[u32; 8], recipients: &[Address]) -> Result<Effect, EffectError> {
    match outputs[0] {
        KIND_NONE => Ok(Effect::None),
        KIND_TRANSFER => {
            let index = outputs[1];
            let to = *recipients
                .get(index as usize)
                .ok_or(EffectError::RecipientIndex { index, len: recipients.len() })?;
            let amount = (outputs[2] as u64) | ((outputs[3] as u64) << 32);
            Ok(Effect::Transfer { to, amount: amount as u128 })
        }
        other => Err(EffectError::UnknownKind(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn addr(n: u8) -> Address {
        Keypair::from_seed([n; 32]).unwrap().address()
    }

    #[test]
    fn kind_none_ignores_other_words() {
        assert_eq!(decode(&[0, 99, 1, 1, 0, 0, 0, 0], &[]), Ok(Effect::None));
    }

    #[test]
    fn transfer_picks_recipient_and_u64_amount() {
        let list = [addr(1), addr(2)];
        let out = [1, 1, 0xffff_ffff, 1, 0, 0, 0, 0]; // amount = 2^32 + 2^32 - 1
        assert_eq!(decode(&out, &list), Ok(Effect::Transfer { to: addr(2), amount: 0x1_ffff_ffff }));
    }

    #[test]
    fn errors() {
        assert_eq!(decode(&[7, 0, 0, 0, 0, 0, 0, 0], &[]), Err(EffectError::UnknownKind(7)));
        assert_eq!(decode(&[1, 2, 5, 0, 0, 0, 0, 0], &[addr(1)]), Err(EffectError::RecipientIndex { index: 2, len: 1 }));
    }
}
```

- [ ] **Step 2: Wire the modules and run**

In `crates/shrugg-core/src/lib.rs` add `pub mod effect;` and `pub mod gas;` next to the other modules.
Run: `cargo test -p shrugg-core gas effect`
Expected: 5 new tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/shrugg-core/src/gas.rs crates/shrugg-core/src/effect.rs crates/shrugg-core/src/lib.rs
git commit -m "core: gas schedule and call-effect decoding"
```

---

### Task 3: Programs, new transaction kinds, and the executor trait (shrugg-core)

**Files:**
- Create: `crates/shrugg-core/src/program.rs`
- Rewrite: `crates/shrugg-core/src/confidential.rs`
- Modify: `crates/shrugg-core/src/types/transaction.rs`, `crates/shrugg-core/src/types/mod.rs`, `crates/shrugg-core/src/lib.rs`

**Interfaces:**
- Produces:
  - `program::{ProgramId (= Hash), ProgramRecord { id, base_pc, words, code_hash: Vec<u8>, deployer, deployed_at }, program_id(base_pc, &[u32]) -> ProgramId, CallOutcome { tier: u8, outputs: [u32; 8] }, CallReceipt { tx, program, tier, outputs, effect: Option<(Address, u128)>, height, index }}`
  - `confidential::{ConfidentialError, ConfidentialExecutor { fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError>; fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError>; }, StubExecutor, StubExecutor::make_proof(tier: u8, outputs: [u32; 8]) -> Vec<u8>}`
  - `TxKind::Deploy { base_pc: u32, words: Vec<u32> }`, `TxKind::Call { program: ProgramId, proof: Vec<u8>, recipients: Vec<Address> }`, `Transaction::deploy(key, chain_id, nonce, base_pc, words, fee)`, `Transaction::call(key, chain_id, nonce, program, proof, recipients, fee)`, `Transaction::encoded_len(&self) -> usize`.
- The old `TxKind::Confidential` and old stub semantics are removed.

- [ ] **Step 1: Write `program.rs` with its tests**

```rust
// crates/shrugg-core/src/program.rs
//! On-chain programs and call receipts.

use crate::crypto::{Address, Hash};
use serde::{Deserialize, Serialize};

pub type ProgramId = Hash;

/// Content address of a program: blake3 over base_pc and the code words.
pub fn program_id(base_pc: u32, words: &[u32]) -> ProgramId {
    let mut buf = Vec::with_capacity(4 + 4 * words.len());
    buf.extend_from_slice(&base_pc.to_le_bytes());
    for w in words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    Hash::digest_domain(b"shrugg-program", &buf)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRecord {
    pub id: ProgramId,
    pub base_pc: u32,
    pub words: Vec<u32>,
    /// zkVM code commitment (informational; verification uses `words`).
    pub code_hash: Vec<u8>,
    pub deployer: Address,
    pub deployed_at: u64,
}

/// What a verified call proved: its gas tier and the eight public outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallOutcome {
    pub tier: u8,
    pub outputs: [u32; 8],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallReceipt {
    pub tx: Hash,
    pub program: ProgramId,
    pub tier: u8,
    pub outputs: [u32; 8],
    /// The transfer the outputs requested, if any.
    pub effect: Option<(Address, u128)>,
    pub height: u64,
    pub index: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_id_depends_on_code_and_base_pc() {
        let a = program_id(0, &[1, 2, 3]);
        assert_eq!(a, program_id(0, &[1, 2, 3]));
        assert_ne!(a, program_id(4, &[1, 2, 3]));
        assert_ne!(a, program_id(0, &[1, 2, 4]));
        assert_ne!(a, program_id(0, &[1, 2]));
    }
}
```

- [ ] **Step 2: Rewrite `confidential.rs`**

```rust
// crates/shrugg-core/src/confidential.rs
//! Confidential computation: the executor the ledger calls to validate programs and verify
//! call proofs. `shrugg-zkvm` provides the real implementation; `StubExecutor` is a
//! crypto-free stand-in for fast tests and for chains started with `confidential: false`.

use crate::crypto::Hash;
use crate::program::{CallOutcome, ProgramRecord};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ConfidentialError {
    #[error("program word {index} does not decode: {reason}")]
    BadInstruction { index: usize, reason: String },
    #[error("malformed proof")]
    MalformedProof,
    #[error("proof does not verify: {0}")]
    InvalidProof(String),
    #[error("proof is for another program")]
    WrongProgram,
    #[error("confidential computation is disabled on this chain")]
    Disabled,
}

pub trait ConfidentialExecutor: Send + Sync {
    /// Validate program code at deploy time and return its zkVM code commitment.
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError>;
    /// Verify `proof` against `program`; on success return the tier and the eight outputs.
    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError>;
}

/// Test executor. A "proof" is `STUB` || tier (1 byte) || 8 outputs (LE u32) || blake3(program id)[..8].
/// Any code is accepted. Never use on a real chain.
#[derive(Debug, Default, Clone)]
pub struct StubExecutor;

pub const STUB_MARKER: &[u8; 4] = b"STUB";
const STUB_LEN: usize = 4 + 1 + 32 + 8;

impl StubExecutor {
    pub fn make_proof(program: &Hash, tier: u8, outputs: [u32; 8]) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.push(tier);
        for o in outputs {
            v.extend_from_slice(&o.to_le_bytes());
        }
        v.extend_from_slice(&Hash::digest_domain(b"shrugg-stub-binding", program.as_bytes()).0[..8]);
        v
    }
}

impl ConfidentialExecutor for StubExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        Ok(crate::program::program_id(base_pc, words).0.to_vec())
    }

    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        if proof.len() != STUB_LEN || &proof[..4] != STUB_MARKER {
            return Err(ConfidentialError::MalformedProof);
        }
        let expected = &Hash::digest_domain(b"shrugg-stub-binding", program.id.as_bytes()).0[..8];
        if &proof[STUB_LEN - 8..] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        let tier = proof[4];
        let mut outputs = [0u32; 8];
        for (i, o) in outputs.iter_mut().enumerate() {
            *o = u32::from_le_bytes(proof[5 + 4 * i..9 + 4 * i].try_into().unwrap());
        }
        Ok(CallOutcome { tier, outputs })
    }
}

/// Executor that refuses everything: for chains with `confidential: false`.
#[derive(Debug, Default, Clone)]
pub struct DisabledExecutor;

impl ConfidentialExecutor for DisabledExecutor {
    fn check_program(&self, _: u32, _: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        Err(ConfidentialError::Disabled)
    }
    fn verify_call(&self, _: &ProgramRecord, _: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        Err(ConfidentialError::Disabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn record(id: Hash) -> ProgramRecord {
        ProgramRecord { id, base_pc: 0, words: vec![0x13], code_hash: vec![], deployer: Keypair::from_seed([1; 32]).unwrap().address(), deployed_at: 0 }
    }

    #[test]
    fn stub_roundtrips_outputs_and_binds_program() {
        let id = Hash::digest(b"p");
        let proof = StubExecutor::make_proof(&id, 12, [1, 0, 5, 0, 0, 0, 0, 9]);
        let out = StubExecutor.verify_call(&record(id), &proof).unwrap();
        assert_eq!(out, CallOutcome { tier: 12, outputs: [1, 0, 5, 0, 0, 0, 0, 9] });
        assert_eq!(StubExecutor.verify_call(&record(Hash::digest(b"q")), &proof), Err(ConfidentialError::WrongProgram));
        assert_eq!(StubExecutor.verify_call(&record(id), b"junk"), Err(ConfidentialError::MalformedProof));
    }

    #[test]
    fn disabled_rejects() {
        assert_eq!(DisabledExecutor.check_program(0, &[0x13]), Err(ConfidentialError::Disabled));
    }
}
```

- [ ] **Step 3: Replace `TxKind::Confidential` with `Deploy` and `Call`**

In `crates/shrugg-core/src/types/transaction.rs`:

```rust
use crate::program::ProgramId;   // add to imports

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxKind {
    Transfer { to: Address, amount: u128 },
    /// Testnet faucet.
    Mint { to: Address, amount: u128 },
    /// Put a zkVM program on chain. Content addressed; see `program::program_id`.
    Deploy { base_pc: u32, words: Vec<u32> },
    /// A confidential call: a STARK proof that `program` ran on private inputs and produced the
    /// eight public outputs carried in the proof. `recipients` is the public list the outputs may
    /// pick a transfer target from (see `effect`).
    Call { program: ProgramId, proof: Vec<u8>, recipients: Vec<Address> },
}
```

Replace the `Confidential` arm everywhere in this file (`total_cost`: `TxKind::Mint { .. } | TxKind::Deploy { .. } | TxKind::Call { .. } => Some(self.body.fee)`). Note: for `Call` the emitted transfer amount is not known until verification; `Ledger` checks it separately (Task 4).

Add constructors and a size helper:

```rust
    pub fn deploy(key: &Keypair, chain_id: u64, nonce: u64, base_pc: u32, words: Vec<u32>, fee: u128) -> Transaction {
        Transaction::sign(TxBody { chain_id, from: key.public_key().clone(), nonce, fee, kind: TxKind::Deploy { base_pc, words } }, key)
    }

    pub fn call(key: &Keypair, chain_id: u64, nonce: u64, program: ProgramId, proof: Vec<u8>, recipients: Vec<Address>, fee: u128) -> Transaction {
        Transaction::sign(TxBody { chain_id, from: key.public_key().clone(), nonce, fee, kind: TxKind::Call { program, proof, recipients } }, key)
    }

    /// Wire size, used for block byte accounting.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }
```

Add a test:

```rust
    #[test]
    fn deploy_and_call_roundtrip() {
        let k = key(1);
        let d = Transaction::deploy(&k, 1, 0, 0, vec![0x13, 0x73], 5);
        assert!(d.verify_signature());
        assert_eq!(Transaction::decode(&d.encode()).unwrap(), d);
        let c = Transaction::call(&k, 1, 1, Hash::digest(b"p"), vec![1, 2, 3], vec![key(2).address()], 7);
        assert_eq!(Transaction::decode(&c.encode()).unwrap(), c);
        assert_eq!(c.total_cost(), Some(7));
        assert!(c.encoded_len() > 2420 + 1312);
    }
```

- [ ] **Step 4: Fix every other use of the old variant**

`grep -rn "Confidential {" crates/` and update: `crates/shrugg-core/src/ledger.rs` (validate/apply arms: temporarily map `Deploy`/`Call` to `Err(TxError::Overflow)`-style placeholders is NOT allowed; instead leave these arms returning `Err(TxError::FaucetDisabled)` only until Task 4 replaces them — better: do Task 3 and Task 4 in one commit if the placeholder feels wrong), `crates/shrugg-node/src/storage.rs` (touched set: `TxKind::Deploy { .. } | TxKind::Call { .. } => {}` for now; Task 7 completes it), `crates/shrugg-node/src/rpc.rs` (`tx_json`: `Deploy` → `{"type":"deploy","base_pc","words_len"}`, `Call` → `{"type":"call","program","proof_len","recipients":[...]}`), the ledger test `confidential_tx_pays_fee_and_requires_valid_stub_proof` (delete it; Task 4 adds the replacements).

Export from `lib.rs`: `pub mod program;` and `pub use program::{CallOutcome, CallReceipt, ProgramId, ProgramRecord};`.

Run: `cargo test -p shrugg-core`
Expected: everything except the deleted test passes.

- [ ] **Step 5: Commit**

```bash
git add crates/shrugg-core crates/shrugg-node/src/storage.rs crates/shrugg-node/src/rpc.rs
git commit -m "core: programs, Deploy/Call transactions, executor trait v2, stub executor"
```

---

### Task 4: Ledger rules for Deploy and Call, receipts, state root

**Files:**
- Modify: `crates/shrugg-core/src/ledger.rs`

**Interfaces:**
- Consumes: Task 2 `gas`, `effect`; Task 3 `program`, `confidential`.
- Produces: `Ledger::{programs() -> &BTreeMap<ProgramId, ProgramRecord>, program(&ProgramId) -> Option<&ProgramRecord>, from_parts(chain_id, accounts, programs), set_height(u64)}`, `Ledger::apply_tx_with_receipt(&mut self, tx, fee_recipient, executor) -> Result<Option<CallReceiptData>, TxError>` where `CallReceiptData { program, tier, outputs, effect }`, `Ledger::apply_transactions` now returns `Result<Vec<(usize, CallReceiptData)>, BlockError>` (index, receipt data) and `apply_block` returns `Result<Vec<CallReceipt>, BlockError>`. New `TxError` variants: `ProgramTooLarge, BadProgram(ConfidentialError), UnknownProgram(ProgramId), ProofTooLarge, TooManyRecipients, InvalidProof(ConfidentialError), FeeTooLow { min: u128, fee: u128 }, BadEffect(EffectError), InsufficientForEffect { have, need }`.

- [ ] **Step 1: Write the failing tests (append to the `tests` module in ledger.rs)**

```rust
    fn deployed(l: &mut Ledger, deployer: &Keypair) -> ProgramId {
        let words = vec![0x00000013u32; 4]; // four nops
        let tx = Transaction::deploy(deployer, 1, l.nonce(&deployer.address()), 0, words.clone(), crate::gas::deploy_fee(4));
        l.apply_tx(&tx, &key(3).address(), &StubExecutor).unwrap();
        crate::program::program_id(0, &words)
    }

    #[test]
    fn deploy_stores_program_and_charges_gas() {
        let (mut l, alice, _, proposer) = funded_with(1_000_000_000);
        let words = vec![0x13u32; 4];
        let cheap = Transaction::deploy(&alice, 1, 0, 0, words.clone(), 1);
        assert!(matches!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: 400_000, fee: 1 })));
        let ok = Transaction::deploy(&alice, 1, 0, 0, words.clone(), 400_000);
        l.apply_tx(&ok, &proposer, &StubExecutor).unwrap();
        let id = crate::program::program_id(0, &words);
        let rec = l.program(&id).unwrap();
        assert_eq!(rec.words, words);
        assert_eq!(rec.deployer, alice.address());
        assert_eq!(l.balance(&proposer), 400_000);
        // redeploy is a no-op that still pays
        let again = Transaction::deploy(&alice, 1, 1, 0, words.clone(), 400_000);
        l.apply_tx(&again, &proposer, &StubExecutor).unwrap();
        assert_eq!(l.programs().len(), 1);
        // too large
        let big = Transaction::deploy(&alice, 1, 2, 0, vec![0x13; crate::gas::MAX_PROGRAM_WORDS + 1], u64::MAX as u128);
        assert!(matches!(l.validate(&big, &StubExecutor), Err(TxError::ProgramTooLarge)));
    }

    #[test]
    fn call_verifies_proof_charges_gas_and_applies_transfer_effect() {
        let (mut l, alice, bob, proposer) = funded_with(1_000_000_000);
        let id = deployed(&mut l, &alice);
        let fee = crate::gas::call_fee(10);
        // out0 = 1 (transfer), out1 = 0 (first recipient), amount = 250
        let proof = StubExecutor::make_proof(&id, 10, [1, 0, 250, 0, 0, 0, 0, 0]);
        let tx = Transaction::call(&alice, 1, 1, id, proof, vec![bob.address()], fee);
        let before = l.balance(&alice.address());
        let r = l.apply_tx_with_receipt(&tx, &proposer, &StubExecutor).unwrap().expect("call receipt");
        assert_eq!(r.tier, 10);
        assert_eq!(r.effect, Some((bob.address(), 250)));
        assert_eq!(l.balance(&bob.address()), 1_000_000_000 + 250);
        assert_eq!(l.balance(&alice.address()), before - fee - 250);
        assert_eq!(l.nonce(&alice.address()), 2);
    }

    #[test]
    fn call_rejections() {
        let (mut l, alice, bob, _) = funded_with(1_000_000_000);
        let id = deployed(&mut l, &alice);
        let fee = crate::gas::call_fee(10);
        let unknown = Transaction::call(&alice, 1, 1, Hash::digest(b"nope"), StubExecutor::make_proof(&Hash::digest(b"nope"), 10, [0; 8]), vec![], fee);
        assert!(matches!(l.validate(&unknown, &StubExecutor), Err(TxError::UnknownProgram(_))));
        let bad_proof = Transaction::call(&alice, 1, 1, id, b"garbage".to_vec(), vec![], fee);
        assert!(matches!(l.validate(&bad_proof, &StubExecutor), Err(TxError::InvalidProof(_))));
        let low_fee = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 12, [0; 8]), vec![], fee);
        assert!(matches!(l.validate(&low_fee, &StubExecutor), Err(TxError::FeeTooLow { .. })), "tier 12 needs more than tier 10 fee");
        let bad_index = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [1, 3, 1, 0, 0, 0, 0, 0]), vec![bob.address()], fee);
        assert!(matches!(l.validate(&bad_index, &StubExecutor), Err(TxError::BadEffect(_))));
        let too_much = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [1, 0, 0xffff_ffff, 0xffff_ffff, 0, 0, 0, 0]), vec![bob.address()], fee);
        assert!(matches!(l.validate(&too_much, &StubExecutor), Err(TxError::InsufficientForEffect { .. })));
        let many: Vec<Address> = (0..9).map(|i| key(20 + i).address()).collect();
        let too_many = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [0; 8]), many, fee);
        assert!(matches!(l.validate(&too_many, &StubExecutor), Err(TxError::TooManyRecipients)));
        // kind 0: pays gas, no transfer, receipt has no effect
        let none = Transaction::call(&alice, 1, 1, id, StubExecutor::make_proof(&id, 10, [0, 0, 0, 0, 0, 0, 0, 42]), vec![], fee);
        let r = l.apply_tx_with_receipt(&none, &key(3).address(), &StubExecutor).unwrap().unwrap();
        assert_eq!(r.effect, None);
        assert_eq!(r.outputs[7], 42);
    }

    #[test]
    fn state_root_covers_programs() {
        let (mut a, alice, _, _) = funded_with(1_000_000_000);
        let b = a.clone();
        let root_before = a.state_root();
        let _ = deployed(&mut a, &alice);
        assert_ne!(a.state_root(), root_before);
        // same program deployed on an identical ledger gives an identical root
        let mut c = b.clone();
        let _ = deployed(&mut c, &alice);
        assert_eq!(a.state_root(), c.state_root());
    }
```

Add the helper `funded_with(units)` next to `funded()`: same as `funded()` but crediting `units` to alice AND bob (bob needs funds for nothing here, but a known balance makes the transfer assertion readable).

- [ ] **Step 2: Implement**

In `ledger.rs`:

```rust
use crate::confidential::{ConfidentialError, ConfidentialExecutor};
use crate::effect::{self, Effect, EffectError};
use crate::gas;
use crate::program::{program_id, CallReceipt, ProgramId, ProgramRecord};

// TxError: add
    #[error("program too large")]
    ProgramTooLarge,
    #[error("bad program: {0}")]
    BadProgram(ConfidentialError),
    #[error("unknown program {0}")]
    UnknownProgram(ProgramId),
    #[error("proof too large")]
    ProofTooLarge,
    #[error("too many recipients")]
    TooManyRecipients,
    #[error("invalid proof: {0}")]
    InvalidProof(ConfidentialError),
    #[error("fee {fee} below minimum {min}")]
    FeeTooLow { min: u128, fee: u128 },
    #[error("bad effect: {0}")]
    BadEffect(#[from] EffectError),
    #[error("insufficient balance for emitted transfer: have {have}, need {need}")]
    InsufficientForEffect { have: u128, need: u128 },

/// Receipt data for a call, before it is placed in a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallReceiptData { pub program: ProgramId, pub tier: u8, pub outputs: [u32; 8], pub effect: Option<(Address, u128)> }

pub struct Ledger {
    chain_id: u64,
    faucet: bool,
    accounts: BTreeMap<Address, Account>,
    programs: BTreeMap<ProgramId, ProgramRecord>,
    /// Height of the block being applied (for `deployed_at`). Set by the node before apply.
    height: u64,
}
```

Update `new`/`from_accounts` to initialise `programs: BTreeMap::new(), height: 0`; add `from_parts(chain_id, accounts, programs)`, `programs()`, `program(&id)`, `set_height(h)`.

`validate` gets two new arms; factor the call check into a helper that returns the outcome so `apply` does not verify twice:

```rust
    fn check_call(&self, tx: &Transaction, program: &ProgramId, proof: &[u8], recipients: &[Address], executor: &dyn ConfidentialExecutor)
        -> Result<(crate::program::CallOutcome, Effect), TxError> {
        if proof.len() > gas::MAX_PROOF_BYTES { return Err(TxError::ProofTooLarge); }
        if recipients.len() > gas::MAX_RECIPIENTS { return Err(TxError::TooManyRecipients); }
        let record = self.programs.get(program).ok_or(TxError::UnknownProgram(*program))?;
        let outcome = executor.verify_call(record, proof).map_err(TxError::InvalidProof)?;
        let min = gas::call_fee(outcome.tier);
        if tx.body.fee < min { return Err(TxError::FeeTooLow { min, fee: tx.body.fee }); }
        let effect = effect::decode(&outcome.outputs, recipients)?;
        if let Effect::Transfer { amount, .. } = effect {
            let have = self.balance(&tx.sender());
            let need = amount.checked_add(tx.body.fee).ok_or(TxError::Overflow)?;
            if have < need { return Err(TxError::InsufficientForEffect { have, need }); }
        }
        Ok((outcome, effect))
    }
```

In `validate`, the `match &tx.body.kind` becomes:

```rust
            TxKind::Deploy { base_pc, words } => {
                if words.len() > gas::MAX_PROGRAM_WORDS { return Err(TxError::ProgramTooLarge); }
                let min = gas::deploy_fee(words.len());
                if tx.body.fee < min { return Err(TxError::FeeTooLow { min, fee: tx.body.fee }); }
                executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
            }
            TxKind::Call { program, proof, recipients } => { self.check_call(tx, program, proof, recipients, executor)?; }
```

`apply_tx` becomes a thin wrapper over the new `apply_tx_with_receipt`:

```rust
    pub fn apply_tx(&mut self, tx: &Transaction, fee_recipient: &Address, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        self.apply_tx_with_receipt(tx, fee_recipient, executor).map(|_| ())
    }

    pub fn apply_tx_with_receipt(&mut self, tx: &Transaction, fee_recipient: &Address, executor: &dyn ConfidentialExecutor)
        -> Result<Option<CallReceiptData>, TxError> {
        self.validate(tx, executor)?;
        let sender = tx.sender();
        let cost = tx.total_cost().ok_or(TxError::Overflow)?;
        // For calls, verify once here (validate already did; the stub is cheap, the zk executor caches).
        let call = match &tx.body.kind {
            TxKind::Call { program, proof, recipients } => Some(self.check_call(tx, program, proof, recipients, executor)?),
            _ => None,
        };
        {
            let acct = self.accounts.entry(sender).or_default();
            acct.balance -= cost;
            acct.nonce += 1;
        }
        let mut receipt = None;
        match &tx.body.kind {
            TxKind::Transfer { to, amount } | TxKind::Mint { to, amount } => self.credit(*to, *amount)?,
            TxKind::Deploy { base_pc, words } => {
                let id = program_id(*base_pc, words);
                if !self.programs.contains_key(&id) {
                    let code_hash = executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
                    self.programs.insert(id, ProgramRecord { id, base_pc: *base_pc, words: words.clone(), code_hash, deployer: sender, deployed_at: self.height });
                }
            }
            TxKind::Call { program, .. } => {
                let (outcome, effect) = call.expect("checked above");
                let applied = match effect {
                    Effect::Transfer { to, amount } => {
                        let acct = self.accounts.entry(sender).or_default();
                        acct.balance -= amount; // covered: check_call verified amount + fee
                        self.credit(to, amount)?;
                        Some((to, amount))
                    }
                    Effect::None => None,
                };
                receipt = Some(CallReceiptData { program: *program, tier: outcome.tier, outputs: outcome.outputs, effect: applied });
            }
        }
        self.credit(*fee_recipient, tx.body.fee)?;
        Ok(receipt)
    }
```

Note the double `check_call` in validate + apply: to avoid verifying a real STARK twice, `validate` for `Call` should call `check_call` and `apply_tx_with_receipt` should NOT call `validate` for calls; restructure as: `let (outcome_effect) = self.validate_inner(tx, executor)?` where `validate_inner` returns `Option<(CallOutcome, Effect)>` and `validate` discards it. Implement it that way (one verification per apply).

`apply_transactions` collects receipts:

```rust
    pub fn apply_transactions(&mut self, txs: &[Transaction], fee_recipient: &Address, executor: &dyn ConfidentialExecutor)
        -> Result<Vec<(usize, CallReceiptData)>, BlockError> {
        let mut scratch = self.clone();
        let mut receipts = Vec::new();
        for (index, tx) in txs.iter().enumerate() {
            if let Some(r) = scratch.apply_tx_with_receipt(tx, fee_recipient, executor).map_err(|error| BlockError::InvalidTx { index, error })? {
                receipts.push((index, r));
            }
        }
        *self = scratch;
        Ok(receipts)
    }
```

`apply_block` sets `scratch.set_height(block.height())` before applying and returns `Vec<CallReceipt>` built from the data plus `tx: block.transactions[i].hash(), height, index`.

`state_root`:

```rust
    pub fn state_root(&self) -> Hash {
        let accounts_root = merkle_root(&/* existing leaves */);
        let program_leaves: Vec<Hash> = self.programs.keys().map(|id| Hash::digest_domain(b"shrugg-program-leaf", id.as_bytes())).collect();
        let programs_root = merkle_root(&program_leaves);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(accounts_root.as_bytes());
        buf[32..].copy_from_slice(programs_root.as_bytes());
        Hash::digest_domain(b"shrugg-state", &buf)
    }
```

This changes every state root, including genesis: that is intended (new chain).

- [ ] **Step 3: Fix callers**

`grep -rn "apply_transactions\|apply_block" crates/` — the consensus state machine (`hotstuff.rs`), storage `verify_chain`, node sync, and tests use `apply_block(..)?` / `apply_transactions(..)?` as `Result<(), _>`; change to `let _ = ...?;` where receipts are not needed (Task 8 uses them in the node). `PartialEq` on `Ledger` still derives (add `programs`, `height` fields; height must be excluded from equality: implement `PartialEq` manually comparing chain_id, faucet, accounts, programs).

Run: `cargo test -p shrugg-core`
Expected: all pass, including the four new tests.

- [ ] **Step 4: Commit**

```bash
git add crates/shrugg-core
git commit -m "core: ledger rules for Deploy and Call, receipts, programs in state root"
```

---

### Task 5: Genesis flags `confidential` and `fri_profile`

**Files:**
- Modify: `crates/shrugg-core/src/genesis.rs`, `crates/shrugg-node/src/main.rs` (genesis flags), `deploy/genesis.json` regenerated later (Task 11)

**Interfaces:**
- Produces: `Genesis { ..., confidential: bool (default true), fri_profile: String (default "production") }`, `GenesisState { confidential, fri_profile }`; both are folded into the genesis hash binding.

- [ ] **Step 1: Test**

```rust
    #[test]
    fn confidential_flags_are_in_the_genesis_hash() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.confidential = false;
        let mut c = genesis(1);
        c.fri_profile = "test".into();
        let ha = a.build().unwrap().hash();
        assert_ne!(ha, b.build().unwrap().hash());
        assert_ne!(ha, c.build().unwrap().hash());
        let mut d = genesis(1);
        d.fri_profile = "bogus".into();
        assert!(matches!(d.build(), Err(GenesisError::BadFriProfile(_))));
    }
```

Update the `genesis(n)` test helper to set `confidential: true, fri_profile: "production".into()`.

- [ ] **Step 2: Implement**

```rust
fn default_true() -> bool { true }
fn default_profile() -> String { "production".into() }

pub struct Genesis {
    // ...existing...
    /// Allow Deploy/Call transactions (zkVM verification). Part of the genesis hash.
    #[serde(default = "default_true")]
    pub confidential: bool,
    /// zkVM FRI profile every node must use: "production" or "test" (tests only). Part of the genesis hash.
    #[serde(default = "default_profile")]
    pub fri_profile: String,
}
// GenesisError: add  #[error("unknown fri_profile {0} (production|test)")] BadFriProfile(String)
// build(): validate fri_profile ∈ {"production","test"}; extend `commit` with
//   commit.push(self.confidential as u8); commit.extend_from_slice(self.fri_profile.as_bytes());
// GenesisState: add `pub confidential: bool, pub fri_profile: String`
```

`shrugg-node genesis` gets `--no-confidential` and `--fri-profile <production|test>` flags. Update every `Genesis { .. }` literal in tests (`consensus/tests.rs`, `storage.rs`, `cluster.rs`, `genesis.rs`) with `confidential: true, fri_profile: "test".into()` for cluster/storage tests and `"production"` elsewhere.

Run: `cargo test -p shrugg-core && cargo test -p shrugg-node --lib`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add crates/shrugg-core/src/genesis.rs crates/shrugg-node crates/shrugg-core/src/consensus/tests.rs
git commit -m "genesis: confidential and fri_profile flags"
```

---

### Task 6: The real executor in shrugg-zkvm (verifier-key cache, program codec, new guest)

**Files:**
- Create: `crates/shrugg-zkvm/src/executor.rs`, `crates/shrugg-zkvm/src/codec.rs`, `crates/shrugg-zkvm/tests/executor.rs`
- Modify: `crates/shrugg-zkvm/src/lib.rs` (add modules), `crates/shrugg-zkvm/src/guests.rs` (add `private_payment`), `crates/shrugg-zkvm/src/asm.rs` (add `emit_transfer`)

**Interfaces:**
- Consumes: `shrugg_core::confidential::{ConfidentialExecutor, ConfidentialError}`, `shrugg_core::program::{ProgramRecord, CallOutcome}`; upstream `machine::{Machine, FriProfile, Tier, Proof, chips, Val}`, `isa::{Program, Instr}`.
- Produces: `executor::ZkExecutor::new(profile: FriProfile) -> ZkExecutor` (implements the trait), `ZkExecutor::profile_from_str(&str) -> Option<FriProfile>`, `codec::{program_from_bytes(&[u8]) -> Result<Program, String>  (raw LE u32 words, base_pc 0), program_from_json(&str) -> Result<Program, String> ({"base_pc","words"}), program_to_json(&Program) -> String}`, `guests::private_payment(threshold: u32) -> Program`, `asm::ops::emit_transfer(index: u32, amount_lo_reg: u32, amount_hi_reg: u32) -> Vec<Instr>`.
- Prover helper for clients/tests: `executor::prove(profile, program, inputs, tier: Option<u8>) -> Result<(Vec<u8> /*proof bytes*/, [u32; 8], u8), String>`.

- [ ] **Step 1: Write the failing tests** (`tests/executor.rs`, run in release)

```rust
use shrugg_core::confidential::{ConfidentialError, ConfidentialExecutor};
use shrugg_core::program::{program_id, ProgramRecord};
use shrugg_core::Keypair;
use shrugg_zkvm::executor::{prove, ZkExecutor};
use shrugg_zkvm::guests;
use shrugg_zkvm::machine::FriProfile;
use std::sync::OnceLock;

fn record(p: &shrugg_zkvm::isa::Program) -> ProgramRecord {
    let ex = ZkExecutor::new(FriProfile::Test);
    let code_hash = ex.check_program(p.base_pc, &p.words).unwrap();
    ProgramRecord { id: program_id(p.base_pc, &p.words), base_pc: p.base_pc, words: p.words.clone(), code_hash, deployer: Keypair::from_seed([1; 32]).unwrap().address(), deployed_at: 0 }
}

/// One proof shared by every test (proving takes ~20 s).
fn shared() -> &'static (Vec<u8>, [u32; 8], u8) {
    static P: OnceLock<(Vec<u8>, [u32; 8], u8)> = OnceLock::new();
    P.get_or_init(|| prove(FriProfile::Test, &guests::private_payment(1000), &[400, 250, 300, 75], None).unwrap())
}

#[test]
fn verifies_a_real_proof_and_reports_outputs() {
    let p = guests::private_payment(1000);
    let (proof, outputs, tier) = shared();
    let ex = ZkExecutor::new(FriProfile::Test);
    let out = ex.verify_call(&record(&p), proof).unwrap();
    assert_eq!(out.tier, *tier);
    assert_eq!(out.outputs, *outputs);
    assert_eq!(out.outputs[0], 1, "sum 1025 >= 1000 -> transfer");
    assert_eq!(out.outputs[1], 0);
    assert_eq!(out.outputs[2], 1025 - 1000, "pays the surplus");
    // second verification hits the key cache and is fast
    let t = std::time::Instant::now();
    ex.verify_call(&record(&p), proof).unwrap();
    assert!(t.elapsed().as_millis() < 500, "cached verify took {:?}", t.elapsed());
}

#[test]
fn rejects_wrong_program_tampered_bytes_and_wrong_profile() {
    let p = guests::private_payment(1000);
    let (proof, _, _) = shared();
    let ex = ZkExecutor::new(FriProfile::Test);
    let other = guests::private_payment(1001);
    assert!(matches!(ex.verify_call(&record(&other), proof), Err(ConfidentialError::InvalidProof(_))));
    let mut bad = proof.clone();
    bad[bad.len() / 2] ^= 1;
    assert!(ex.verify_call(&record(&p), &bad).is_err());
    assert_eq!(ex.verify_call(&record(&p), b"nope"), Err(ConfidentialError::MalformedProof));
    let prod = ZkExecutor::new(FriProfile::Production);
    assert!(prod.verify_call(&record(&p), proof).is_err(), "a test-profile proof must not pass a production verifier");
}

#[test]
fn check_program_rejects_bad_words() {
    let ex = ZkExecutor::new(FriProfile::Test);
    assert!(matches!(ex.check_program(0, &[0xffff_ffff]), Err(ConfidentialError::BadInstruction { index: 0, .. })));
    assert!(ex.check_program(0, &[0x13]).is_ok());
    assert!(ex.check_program(2, &[0x13]).is_err(), "base_pc must be word aligned");
}

#[test]
fn private_payment_emits_no_transfer_below_threshold() {
    let (_, outputs, _) = prove(FriProfile::Test, &guests::private_payment(2000), &[400, 250, 300, 75], None).unwrap();
    assert_eq!(outputs[0], 0);
}
```

- [ ] **Step 2: Implement `executor.rs`**

```rust
//! The chain-side verifier: implements shrugg-core's executor trait with the zkVM.
use crate::isa::{Instr, Program};
use crate::machine::{chips, FriProfile, Machine, Proof, Tier, Val, TIERS};
use p3_batch_stark::{verify_batch, CommonData};
use p3_field::PrimeCharacteristicRing;
use shrugg_core::confidential::{ConfidentialError, ConfidentialExecutor};
use shrugg_core::program::{CallOutcome, ProgramId, ProgramRecord};
use std::collections::HashMap;
use std::sync::Mutex;

const KEY_CACHE: usize = 64;

pub struct ZkExecutor {
    machine: Machine,
    /// (program id, tier) -> verifier key. Computing one costs ~2 s; verifying with it ~20 ms.
    keys: Mutex<HashMap<(ProgramId, usize), CommonData<crate::machine::Config>>>,
}

impl ZkExecutor {
    pub fn new(profile: FriProfile) -> ZkExecutor {
        ZkExecutor { machine: Machine::new(profile), keys: Mutex::new(HashMap::new()) }
    }

    pub fn profile_from_str(s: &str) -> Option<FriProfile> {
        match s { "production" => Some(FriProfile::Production), "test" => Some(FriProfile::Test), _ => None }
    }

    fn program(record: &ProgramRecord) -> Program { Program { base_pc: record.base_pc, words: record.words.clone() } }

    fn key_for(&self, record: &ProgramRecord, tier: Tier) -> CommonData<crate::machine::Config> {
        let k = (record.id, tier.0);
        if let Some(c) = self.keys.lock().unwrap().get(&k) { return c.clone(); }
        let key = self.machine.verifier_key(&Self::program(record), tier);
        let mut cache = self.keys.lock().unwrap();
        if cache.len() >= KEY_CACHE { cache.clear(); }
        cache.insert(k, key.clone());
        key
    }
}

impl ConfidentialExecutor for ZkExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        if base_pc % 4 != 0 { return Err(ConfidentialError::BadInstruction { index: 0, reason: "base_pc not word aligned".into() }); }
        for (index, w) in words.iter().enumerate() {
            Instr::decode(*w).map_err(|e| ConfidentialError::BadInstruction { index, reason: format!("{e:?}") })?;
        }
        let program = Program { base_pc, words: words.to_vec() };
        // Warm the cache for the smallest tier; code_hash is the preprocessed commitment.
        let hc = self.machine.code_hash(&program, Tier(TIERS[0]));
        Ok(hex_to_bytes(&hc))
    }

    fn verify_call(&self, record: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        let proof: Proof = postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        if !TIERS.contains(&proof.tier.0) { return Err(ConfidentialError::InvalidProof("tier".into())); }
        if proof.public_values.len() != crate::tables::cpu::pv::NUM { return Err(ConfidentialError::MalformedProof); }
        if proof.public_values[crate::tables::cpu::pv::PC_ENTRY] != record.base_pc as u64 { return Err(ConfidentialError::WrongProgram); }
        if proof.public_values[crate::tables::cpu::pv::TIER] != proof.tier.0 as u64 { return Err(ConfidentialError::InvalidProof("tier mismatch".into())); }
        let program = Self::program(record);
        if proof.batch.degree_bits != self.machine.log_ext_degrees_pub(&program, proof.tier) { return Err(ConfidentialError::InvalidProof("degrees".into())); }
        let key = self.key_for(record, proof.tier);
        let airs = chips(&program);
        let pv: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..5).map(|i| if i == 1 { pv.clone() } else { vec![] }).collect();
        verify_batch(&self.machine.config, &airs, &proof.batch, &pvs, &key).map_err(|e| ConfidentialError::InvalidProof(format!("{e:?}")))?;
        let mut outputs = [0u32; 8];
        for (i, o) in outputs.iter_mut().enumerate() { *o = proof.public_values[crate::tables::cpu::pv::OUT0 + i] as u32; }
        Ok(CallOutcome { tier: proof.tier.0 as u8, outputs })
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> { (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect() }

/// Prover entry point for the wallet and tests. Returns (proof bytes, outputs, tier).
pub fn prove(profile: FriProfile, program: &Program, inputs: &[u32], tier: Option<u8>) -> Result<(Vec<u8>, [u32; 8], u8), String> {
    let m = Machine::new(profile);
    let (proof, exec) = m.prove(program, inputs, tier.map(|t| Tier(t as usize))).map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}
```

`Machine::log_ext_degrees` is private upstream; add a one-line public wrapper `pub fn log_ext_degrees_pub(&self, program: &Program, tier: Tier) -> Vec<usize> { self.log_ext_degrees(program, tier) }` in the vendored `machine.rs` (the only upstream edit; note it in `deploy/sync-zkvm.sh` as a post-sync patch: `grep -q log_ext_degrees_pub || sed ...`). `CommonData` must be `Clone`; if it is not, store `Arc<CommonData<_>>` in the cache and pass `&*key`.

- [ ] **Step 3: Implement `codec.rs`, `emit_transfer`, and `private_payment`**

```rust
// codec.rs
use crate::isa::Program;
pub fn program_from_bytes(bytes: &[u8]) -> Result<Program, String> {
    if bytes.len() % 4 != 0 { return Err("program bytes must be a multiple of 4".into()); }
    Ok(Program { base_pc: 0, words: bytes.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect() })
}
#[derive(serde::Serialize, serde::Deserialize)]
struct ProgramJson { base_pc: u32, words: Vec<u32> }
pub fn program_from_json(s: &str) -> Result<Program, String> {
    let p: ProgramJson = serde_json::from_str(s).map_err(|e| e.to_string())?;
    if p.base_pc % 4 != 0 { return Err("base_pc must be word aligned".into()); }
    Ok(Program { base_pc: p.base_pc, words: p.words })
}
pub fn program_to_json(p: &Program) -> String { serde_json::to_string_pretty(&ProgramJson { base_pc: p.base_pc, words: p.words.clone() }).unwrap() }
```

In `asm.rs` `ops`:

```rust
    /// Emit the chain effect "transfer amount (lo, hi registers) to recipient `index`":
    /// out0 = 1, out1 = index, out2 = lo, out3 = hi.
    pub fn emit_transfer(index: u32, amount_lo_reg: u32, amount_hi_reg: u32) -> Vec<Instr> {
        let mut v = Vec::new();
        v.extend(li(REG_A2, 1)); v.extend(write_output(0, REG_A2));
        v.extend(li(REG_A2, index as i32)); v.extend(write_output(1, REG_A2));
        v.extend(write_output(2, amount_lo_reg));
        v.extend(write_output(3, amount_hi_reg));
        v
    }
```

(`REG_A2` is x12; `write_output` clobbers a7/a0/a1 only, so a2 survives.) In `guests.rs`:

```rust
/// Private payment: reads four private balances; if their sum >= threshold, pays recipient 0
/// the surplus (sum - threshold); otherwise emits no effect. Only the effect words are public.
pub fn private_payment(threshold: u32) -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T5, 0));
    for idx in 0..4 { a.extend(read_input(idx)); a.push(add(T5, T5, REG_A0)); }
    a.extend(li(T0, threshold as i32));
    a.push(sltu(T1, T5, T0));               // T1 = sum < threshold
    a.branch(BranchCond::Ne, T1, 0, "done"); // below threshold: outputs stay 0 (kind none)
    a.push(sub(T2, T5, T0));                // surplus
    a.extend(li(T3, 0));                    // amount hi
    a.extend(emit_transfer(0, T2, T3));
    a.label("done");
    a.extend(halt());
    a.assemble()
}
```

Add it to `guests::all()` as `("private_payment", private_payment(1000), vec![400, 250, 300, 75])`.

- [ ] **Step 4: Run**

Run: `cargo test -p shrugg-zkvm --release --test executor`
Expected: 4 tests pass (about a minute: three proofs).

- [ ] **Step 5: Commit**

```bash
git add crates/shrugg-zkvm deploy/sync-zkvm.sh
git commit -m "zkvm: ZkExecutor with verifier-key cache, program codec, private_payment guest"
```

---

### Task 7: Storage for programs and receipts

**Files:**
- Modify: `crates/shrugg-node/src/storage.rs`

**Interfaces:**
- Produces: column families `programs` (id → bincode ProgramRecord), `receipts` (tx hash → bincode CallReceipt); `Storage::{program(&ProgramId) -> Result<Option<ProgramRecord>>, programs_count() -> Result<u64>, receipt(&Hash) -> Result<Option<CallReceipt>>, load_ledger() (now also loads programs), commit(blocks, ledger_after, receipts: &[CallReceipt])}` and `verify_chain`/`truncate_to` cover programs and receipts.

- [ ] **Step 1: Test (in storage tests)**

```rust
    #[test]
    fn programs_and_receipts_round_trip_and_truncate() {
        let (_d, st, gs, blocks) = chain_fixture(2);
        let deployer = shrugg_core::Keypair::from_seed([9u8; 32]).unwrap().address();
        let rec = ProgramRecord { id: Hash::digest(b"prog"), base_pc: 0, words: vec![0x13; 3], code_hash: vec![1, 2], deployer, deployed_at: 3 };
        let mut ledger = st.load_ledger().unwrap();
        // pretend block 3 deployed it and block 3 also carried a call
        let mut programs = ledger.programs().clone();
        programs.insert(rec.id, rec.clone());
        ledger = Ledger::from_parts(ledger.chain_id(), ledger.accounts().clone(), programs);
        let b3 = /* build block 3 like chain_fixture does, height 3, parent blocks[1] */;
        let receipt = CallReceipt { tx: Hash::digest(b"tx"), program: rec.id, tier: 10, outputs: [1, 0, 5, 0, 0, 0, 0, 0], effect: None, height: 3, index: 0 };
        st.commit(&[b3.clone()], &ledger, &[receipt.clone()]).unwrap();
        assert_eq!(st.program(&rec.id).unwrap().unwrap(), rec);
        assert_eq!(st.receipt(&receipt.tx).unwrap().unwrap(), receipt);
        assert_eq!(st.load_ledger().unwrap().programs().len(), 1);
        // truncating below the deploy removes both
        let older = st.verify_chain(&gs, VerifyMode::Quick).unwrap().ledger; // replay up to head
        st.truncate_to(&gs, 2, &gs.ledger).unwrap();
        assert!(st.program(&rec.id).unwrap().is_none());
        assert!(st.receipt(&receipt.tx).unwrap().is_none());
        let _ = older;
    }
```

(Refactor `chain_fixture` so block building is a reusable `fn make_block(prev: &Block, txs, ledger_after, key) -> CommittedBlock` used by both.)

- [ ] **Step 2: Implement**

- `ALL_CFS` gains `"programs"`, `"receipts"` (open creates missing CFs on existing DBs: `create_missing_column_families(true)` is already set; verify).
- `commit(..., receipts: &[CallReceipt])`: put each receipt under its tx hash; put every program in `ledger_after.programs()` whose `deployed_at` is within the committed height range (`>= first_height`); the touched-accounts set adds `Call` recipients: since the effect recipient is only known from the receipt, add `receipt.effect.0` for each receipt, plus the sender and proposer as today.
- `load_ledger()`: iterate `programs` CF into the map; `Ledger::from_parts`.
- `truncate_to(gs, height, ledger)`: delete receipts whose `height > height` (iterate CF, decode, compare) and programs whose `deployed_at > height`; rewrite the accounts CF as today.
- `verify_chain`: `ledger.set_height(h)` before applying each block; collect `apply_transactions` receipts and check each stored receipt matches (`receipt(tx)` equals the replayed one) — a mismatch is a `problem` at that height; after the loop, `stored.programs()` must equal `ledger.programs()` (else "programs snapshot does not match").

Run: `cargo test -p shrugg-node storage`
Expected: 11 storage tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/shrugg-node/src/storage.rs
git commit -m "storage: programs and receipts column families; verify and truncate cover them"
```

---

### Task 8: Node wiring: executor from genesis, block byte cap, receipts, RPC

**Files:**
- Modify: `crates/shrugg-node/src/node.rs`, `crates/shrugg-node/src/mempool.rs`, `crates/shrugg-node/src/rpc.rs`, `crates/shrugg-node/Cargo.toml` (add `shrugg-zkvm`)

**Interfaces:**
- Consumes: `ZkExecutor`, `DisabledExecutor`, `StubExecutor`; `Ledger::apply_block -> Vec<CallReceipt>`; storage from Task 7.
- Produces: `Mempool::candidates(ledger, max_txs, max_bytes) -> Vec<Transaction>`; `NodeStatus.confidential: bool, fri_profile: String, programs: u64`; RPC methods `shrugg_getProgram [id]`, `shrugg_getProgramCode [id]`, `shrugg_getReceipt [tx]`, `shrugg_estimateFee ["deploy", words | "call", tier]`; `tx_json` renders deploy/call.

- [ ] **Step 1: Mempool byte cap test**

```rust
    #[test]
    fn candidates_stop_at_byte_budget() {
        let l = ledger();
        let mut m = Mempool::new(100, 16);
        let a = key(1); let to = key(3).address();
        for n in 0..3 { m.insert(Transaction::transfer(&a, 1, n, to, 1, 0), &l, &StubExecutor).unwrap(); }
        let one = Transaction::transfer(&a, 1, 0, to, 1, 0).encoded_len();
        assert_eq!(m.candidates(&l, 10, one * 2 + 1).len(), 2);
        assert_eq!(m.candidates(&l, 10, usize::MAX).len(), 3);
    }
```

Implement: in `candidates`, track `bytes += tx.encoded_len()` and stop when it would exceed `max_bytes`. Node calls `candidates(tip, MAX_TXS_PER_BLOCK, gas::MAX_BLOCK_BYTES)`.

- [ ] **Step 2: Executor selection and receipts in the node**

In `node::start`:

```rust
    let executor: Arc<dyn ConfidentialExecutor> = if !gs.confidential {
        Arc::new(DisabledExecutor)
    } else {
        let profile = ZkExecutor::profile_from_str(&gs.fri_profile).context("genesis fri_profile")?;
        Arc::new(ZkExecutor::new(profile))
    };
```

Thread `executor: Arc<dyn ConfidentialExecutor>` through `HotStuff::new/resume` (it takes `Box<dyn ConfidentialExecutor>` today: change to `Arc` so the node, mempool and consensus share one key cache), the mempool calls, `apply_synced`, and `check_and_repair_chain` (`verify_chain` gets an `executor: &dyn ConfidentialExecutor` parameter; storage tests pass `&StubExecutor`). Remove every remaining `StubExecutor` use from `node.rs`.

Receipts: the consensus state machine applies blocks inside `HotStuff::on_proposal`; it must keep the receipts per block. Add `receipts: Vec<CallReceipt>` to `CommittedBlock` (set from `apply_block`'s return in the tree entry; the sync path computes them the same way in `apply_synced`). `Node::commit` passes `cb.receipts` to `storage.commit`. Serialize `CommittedBlock.receipts` with `#[serde(default)]` so sync responses from peers carry them (a syncing node recomputes anyway and must compare: if the peer's receipts differ from the recomputed ones, reject the batch).

`Ledger::set_height(block.height())` must be called before `apply_block` in `on_proposal`, `propose`, and sync (`apply_block` does it internally per the Task 4 design, so only `propose` needs `ledger.set_height(parent.height + 1)` before applying candidate txs).

- [ ] **Step 3: RPC**

In `rpc.rs` `dispatch`:

```rust
        "shrugg_getProgram" => {
            let id = parse_hash(p, 0)?;
            match st.storage.program(&id).map_err(RpcError::internal)? {
                None => Ok(Value::Null),
                Some(r) => Ok(json!({ "id": r.id.to_hex(), "base_pc": r.base_pc, "words_len": r.words.len(), "code_hash": hex::encode(&r.code_hash), "deployer": r.deployer.to_base58(), "deployed_at": r.deployed_at })),
            }
        }
        "shrugg_getProgramCode" => {
            let id = parse_hash(p, 0)?;
            Ok(st.storage.program(&id).map_err(RpcError::internal)?.map(|r| json!({ "base_pc": r.base_pc, "words": r.words })).unwrap_or(Value::Null))
        }
        "shrugg_getReceipt" => {
            let h = parse_hash(p, 0)?;
            Ok(st.storage.receipt(&h).map_err(RpcError::internal)?.map(|r| json!({
                "tx": r.tx.to_hex(), "program": r.program.to_hex(), "tier": r.tier, "outputs": r.outputs,
                "effect": r.effect.map(|(to, amt)| json!({ "to": to.to_base58(), "amount": amt.to_string() })),
                "height": r.height, "index": r.index })).unwrap_or(Value::Null))
        }
        "shrugg_estimateFee" => {
            let kind: String = param(p, 0, "kind")?;
            let n: u64 = param(p, 1, "size_or_tier")?;
            let fee = match kind.as_str() {
                "deploy" => shrugg_core::gas::deploy_fee(n as usize),
                "call" => shrugg_core::gas::call_fee(n as u8),
                _ => return Err(RpcError::invalid_params("kind must be deploy or call")),
            };
            Ok(json!(fee.to_string()))
        }
```

`NodeStatus` gains `confidential`, `fri_profile`, `programs` (count from storage at publish time is too slow per loop iteration: count on commit and keep in `Node`).

- [ ] **Step 4: Run**

Run: `cargo test -p shrugg-node --lib && cargo test -p shrugg-core`
Expected: pass. (Cluster tests use `fri_profile: "test"` and `StubExecutor`-free paths; they get real proofs in Task 10.)

- [ ] **Step 5: Commit**

```bash
git add crates/shrugg-node Cargo.lock
git commit -m "node: zk executor from genesis, receipts, program/receipt RPC, block byte cap"
```

---

### Task 9: Wallet: program build/deploy/show, call, receipt

**Files:**
- Modify: `crates/shrugg-client/Cargo.toml` (add `shrugg-zkvm`, `hex`), `crates/shrugg-client/src/lib.rs`, `crates/shrugg-client/src/main.rs`

**Interfaces:**
- Produces: `RpcClient::{program(&ProgramId) -> Result<Option<Value>>, program_code(&ProgramId) -> Result<Option<(u32, Vec<u32>)>>, receipt(&Hash) -> Result<Option<Value>>, estimate_fee(kind: &str, n: u64) -> Result<u128>, deploy(key, base_pc, words) -> Result<(ProgramId, Hash)>, call(key, program, proof, recipients, fee) -> Result<Hash>}`; CLI commands below.

- [ ] **Step 1: Library methods** (straightforward wrappers; `deploy` fetches chain id and nonce, computes `gas::deploy_fee`, signs `Transaction::deploy`, returns `(program_id(base_pc, &words), tx hash)`; `call` likewise with the given fee).

- [ ] **Step 2: CLI**

```
shrugg program build --guest <fib|memcpy|bubble_sort|balance_check|private_payment> [--arg N]... --out prog.json
shrugg program deploy <prog.json|prog.bin>          # waits for commit; prints program id
shrugg program show <id>
shrugg call <id> --input N... [--to <addr>]... [--tier T] [--fee <SHRUGG>]   # proves locally (prints prove time), submits, waits, prints outputs and receipt
shrugg receipt <tx>
shrugg fee deploy <words> | fee call <tier>
```

`program build` maps guest names to `shrugg_zkvm::guests::*` (args: `fib n`, `memcpy n`, `bubble_sort v...`, `balance_check threshold`, `private_payment threshold`) and writes `codec::program_to_json`. `program deploy` reads `.json` via `codec::program_from_json` or `.bin` via `program_from_bytes`. `call` loads the program code from the node (`shrugg_getProgramCode`), runs `shrugg_zkvm::executor::prove(profile, ...)` with the profile from `shrugg_status.fri_profile`, sets the fee to `estimate_fee("call", tier)` unless `--fee` is given, submits, waits, prints `outputs` and the receipt.

- [ ] **Step 3: Smoke test by hand against a local node** (cluster test in Task 10 covers it automatically):
`cargo run --release -p shrugg-client -- program build --guest private_payment --arg 1000 --out /tmp/pp.json` then inspect the JSON.

- [ ] **Step 4: Commit**

```bash
git add crates/shrugg-client Cargo.lock
git commit -m "client: program build/deploy/show, confidential call, receipt"
```

---

### Task 10: End-to-end cluster test

**Files:**
- Modify: `crates/shrugg-node/tests/cluster.rs`

- [ ] **Step 1: Test**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confidential_call_moves_funds_on_every_node() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks, &ks); // fri_profile "test", confidential true
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), false).await; // observer verifies too
    wait_height(&[&n0, &n1, &n2, &n3], 2, Duration::from_secs(40)).await;

    // deploy
    let program = shrugg_zkvm::guests::private_payment(1000);
    let (pid, dtx) = n0.rpc.deploy(&ks[0], program.base_pc, program.words.clone()).await.unwrap();
    n0.rpc.wait_for_transaction(&dtx, Duration::from_secs(60)).await.unwrap();
    wait_for("program on n3", Duration::from_secs(60), || n3.handle.storage.program(&pid).unwrap().is_some()).await;

    // prove off-chain (test profile, ~20 s) and call with bob as recipient 0
    let bob = Keypair::from_seed([9; 32]).unwrap().address();
    let (proof, outputs, tier) = shrugg_zkvm::executor::prove(shrugg_zkvm::machine::FriProfile::Test, &program, &[400, 250, 300, 75], None).unwrap();
    assert_eq!(outputs[0], 1);
    let fee = shrugg_core::gas::call_fee(tier);
    let ctx = n1.rpc.call(&ks[0], pid, proof, vec![bob], fee).await.unwrap();
    let r = n1.rpc.wait_for_transaction(&ctx, Duration::from_secs(90)).await.unwrap();
    wait_for("receipt on all nodes", Duration::from_secs(60), || [&n0, &n1, &n2, &n3].iter().all(|n| n.handle.storage.receipt(&ctx).unwrap().is_some())).await;
    for n in [&n0, &n1, &n2, &n3] {
        let rc = n.handle.storage.receipt(&ctx).unwrap().unwrap();
        assert_eq!(rc.effect, Some((bob, 25)));
        assert_eq!(rc.height, r.height);
        assert_eq!(n.rpc.balance(&bob).await.unwrap(), 25);
    }
    assert_chains_equal(&[&n0, &n1, &n2, &n3], &ks);
    // a replayed proof is rejected (nonce) and a proof for another program is rejected (verification)
    assert!(n1.rpc.call(&ks[0], pid, StubExecutor_free_junk(), vec![bob], fee).await.is_err());
}
```

(Replace the last line with a real check: resubmit the same call bytes with the next nonce; the node must reject it because the mempool/ledger verify the proof against `pid` again and it verifies fine — so instead deploy `private_payment(1001)`, and submit the *old* proof against that id: expect an RPC error containing "invalid proof".)

- [ ] **Step 2: Run** `cargo test -p shrugg-node --release --test cluster confidential_call` (release: proving in debug is far too slow).
Expected: pass in about 1 to 2 minutes.

- [ ] **Step 3: Commit**

```bash
git add crates/shrugg-node/tests/cluster.rs
git commit -m "tests: end-to-end confidential deploy and call across a cluster"
```

---

### Task 11: Docs, genesis for chain 4, rollout

**Files:**
- Modify: `README.md`, `docs/cli.md`, `docs/rpc.md`, `docs/architecture.md`, `deploy/README.md`, `deploy/genesis.json`, `deploy/run-a.sh`, `deploy/run-b.sh`, `deploy/nodes.env`, `deploy/vps-setup.sh` (if the systemd unit needs `LimitNOFILE` or memory notes)

- [ ] **Step 1: Documentation** — add the transaction kinds, effect table, gas table, RPC methods and wallet commands from the spec to the four docs; replace the "confidential computation is a stub" sentences.
- [ ] **Step 2: Genesis** — `shrugg-node genesis --chain-id 4 --validator deploy/node-a.key.json ... --alloc-each 100 --faucet --out deploy/genesis.json` (confidential on, production profile); update run scripts' datadir suffix and `deploy/README.md`/`nodes.env` (addresses and peer ids do not change this time).
- [ ] **Step 3: Rollout** — `cargo test` green; push; `deploy/push-to-vps.sh` for C, D, E, F (the droplets must install Rust 1.98.1: `rust-toolchain.toml` makes rustup do it automatically; the first build recompiles Plonky3, ~20 min); restart A with `deploy/run-a.sh`; signal B's session.
- [ ] **Step 4: Live check** — `shrugg program build --guest private_payment --arg 1000 --out pp.json`, `shrugg program deploy pp.json`, `shrugg call <id> --input 400 --input 250 --input 300 --input 75 --to <B address>`; verify the receipt and B's balance on every node; note prove time on the laptop and verify time in the droplet logs.
- [ ] **Step 5: Commit and push.**

---

## Self-review

- Spec coverage: programs (T3/T4/T7), Deploy/Call kinds and validity (T3/T4), effect encoding (T2/T4), gas and limits (T2/T4/T8), executor trait and ZkExecutor with cached keys (T3/T6), toolchain and vendoring (T1), receipts and storage (T4/T7/T8), RPC and wallet (T8/T9), genesis flags (T5), sync/verify (T7/T8), tests (every task + T10), rollout (T11). No gaps found.
- Placeholders: Task 7 Step 1 contains one `/* build block 3 like chain_fixture does */` — the executor must use the `make_block` helper described in the same step; Task 10 Step 1's last line is replaced per the note in the same step.
- Type consistency: `CallReceiptData` (ledger) vs `CallReceipt` (program.rs) are distinct on purpose; `apply_block` returns `Vec<CallReceipt>`; `verify_call` returns `CallOutcome`; `prove` returns `(Vec<u8>, [u32; 8], u8)` in both T6 and T10; `candidates(ledger, max_txs, max_bytes)` in T8 matches the node call.
