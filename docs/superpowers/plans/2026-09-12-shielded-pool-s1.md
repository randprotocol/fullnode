# Fully shielded pool — Phase S1 (full node) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the transparent account ledger of the SHRUGG full node with a notes ledger: every balance is a set of unspent notes, every transfer is a 2-in-2-out `Bundle` carrying a STARK proof from the zkVM's `bundle` guest, the faucet mints deposit notes, the wallet (`shrugg`) derives shielded keys, scans envelopes, proves and sends, the RPC exposes commitments/nullifiers/anchors/witnesses instead of balances, and genesis seeds deposit notes. Deploy and Call ride on bundles from day one (the bundle pays the fee; call effect kind 1 is gone). Staking, bridge and call-input envelopes stay for S2/S3.

**Architecture:** `shrugg-core` stays free of the zkVM's field-arithmetic crates: it holds the pure data types (`Word8`, `Envelope`, `Bundle`, `Action`, `Transaction`, `ShieldedAddress`), an incremental (frontier) commitment tree and a reference full tree that are generic over a node-hash supplied through the existing `ConfidentialExecutor` trait, and the ledger rules (admission order of spec §7, state root of §9). `shrugg-zkvm` vendors the research crate's note layer (`notes.rs`, `viewing.rs`, `ledger.rs`) and its `bundle` guest, and implements the executor's new methods (`node_hash`, `bundle_digest`, `bundle_proof_digest`, `verify_bundle`) plus wallet-side proving. `shrugg-node` swaps the `accounts` column family for `notes`/`nullifiers`/`anchors`/`validators`, keeps the tree frontier in `meta`, rewrites the mempool around nullifier conflicts instead of nonces, redacts the RPC, and signs faucet mints with the validator key. `shrugg-client` becomes a shielded wallet with a spend-key file and a local note store. Every task keeps its own crate green; the workspace as a whole compiles again at Task 4.

**Tech Stack:** Rust 1.98.1 (`rust-toolchain.toml`), Plonky3 `=0.7.0` (in `shrugg-zkvm` only), `ml-kem =0.3.2`, `chacha20poly1305 =0.11.0` (new, `shrugg-zkvm` only), RocksDB 0.22, bincode 1.3, serde_json, bs58, blake3.

**Spec:** `docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §3 (transaction shape), §4 (relation, 47-word digest with `bad` fixed to 0), §5 (notes, keys, addresses), §6 (actions; S1 implements None, Mint, Deploy, Call), §7 (admission order), §9 (state, storage, state root), §11 (RPC), §12 (S1 row), §13 (rulings). Research-side facts this plan relies on: `circuits/research/src/{notes,viewing,ledger}.rs` at the commit named in the Task 2 dispatch (phase Z merged, `SpendKey` = `Word8`, `bundle_input::COUNT = 612`, bundle proves at tier 14, `notes::bundle_digest(anchor, nf1, nf2, cm1, cm2, fee, burn, asset, time)` fixes the taint word to 0 itself).

## Global Constraints

- **Toolchain**: every cargo command is run with the pinned 1.98.1 toolchain from the repo root (`rust-toolchain.toml` selects it; `cargo test -p <crate>` as written below).
- **`shrugg-core` must not depend on any `p3-*` crate, `ml-kem` or `chacha20poly1305`**: every Poseidon2 hash it needs goes through `ConfidentialExecutor`. Verified by `grep -E 'p3-|ml-kem|chacha' crates/shrugg-core/Cargo.toml` being empty.
- **Amounts are `u64` units** (`UNITS_PER_SHRUGG = 1_000_000_000`), fees are `u64`; validator stake stays `u128` in `ValidatorSet` (consensus code is not touched).
- **Word encoding**: a `Word8` on the wire (bincode) is `[u32; 8]`; as bytes it is 32 little-endian bytes (`word8_to_bytes`); in JSON and CLI it is the 64-hex-char string of those bytes.
- **Admission order** (spec §7) is exactly the order of `Ledger::validate` in Task 3; the STARK verification of the bundle is the last check before the action's own proof.
- **State root**: `blake3("shrugg-state-2" || tree_root || nullifier_root || validators_root || programs_root)` (Task 3 defines each root). No bridge root in S1.
- **Constants**: `BUNDLE_BASE = 1_000_000` units, `ANCHOR_WINDOW = 64` blocks, `TIME_WINDOW = 64` blocks, `MAX_ENVELOPE_BYTES = 2048`, `MAX_PROOF_BYTES = 1 << 20` (unchanged), `FAUCET_MAX_UNITS = 100 * UNITS_PER_SHRUGG`, `DEPTH = 32`, `KEM_EK_BYTES = 1184`, address prefix `shrugg1`.
- **Vendored files are never hand-edited**: `crates/shrugg-zkvm/src/{notes,viewing,ledger}.rs` come from `deploy/sync-zkvm.sh`; anything node-specific goes in hand-maintained files (`executor.rs`, `address.rs`, `guests.rs`, `asm.rs`).
- **Bridge is not wired in S1**: a genesis with a `bridge` section is rejected; `shrugg_core::bridge` and `bridge-codec` compile untouched with their own tests; ledger/storage/RPC/client bridge paths are removed (S3 re-adds them as notes).
- **Cluster tests** use `fri_profile: "test"` and prove real bundles (about 35 s per proof at tier 14 with the test profile); mark nothing `#[ignore]`.
- **Commit style**: `<crate or area>: <what>` as in `git log` (`core: ...`, `node: ...`, `client: ...`, `zkvm: ...`, `docs: ...`).

## Rulings made in this plan (the spec leaves these open; the user can overturn any of them)

| ruling | why | cost if wrong |
|---|---|---|
| `Transaction { chain_id, bundle: Option<Bundle>, action }`; `bundle` is `None` only for `Action::Mint` | a new wallet has no note to pay a bundle fee with; the faucet is validator-authorized (spec §6 "the node key") and pays no fee | a second bundle-less action kind later needs the same carve-out |
| Deploy and Call are S1 actions (spec puts them in S3) | the testnet keeps confidential calls working; the action enum must exist from the start anyway | S3 shrinks to call-input envelopes and the bridge |
| deposits publish `(cm, amount, envelope)` and the ledger trusts the minter for the note's content (spec §6, faucet row) | exactly what the approved spec says; a deposit proof is open item §14 | S2's Withdraw must add a deposit proof or plaintext before validators can be trusted with it; flagged for the user |
| anchors are recorded once per block (block-end tree root, keyed by height), window = last 64 blocks | spec §7 "64 gives a prover about a minute at 1 s blocks" is a per-block window | a bundle cannot cite a root produced mid-block; harmless |
| `time` is a `u32` block height on the wire | the guest's digest has one word for it; `u64` would not fit the 47-word preimage | none before block 4.29e9 |
| the ledger keeps the full commitment set in memory (`BTreeSet<Word8>`) for spec §7 item 6 | the frontier tree cannot answer membership | memory O(notes); an on-disk check is a later change |
| `shrugg_getWitness` takes a leaf index and the node builds the path from the `notes` column family with a full tree in memory | spec §9 stores only the frontier for appends; a witness needs the leaves, which `notes` has | O(notes) hashing per witness call; fine below ~10^5 notes |
| the wallet asks the node for witnesses instead of keeping a local tree | simplest correct wallet; spec §11 allows it | the node learns which leaf indices a wallet spends — a testnet-grade privacy leak, documented in `docs/shielded.md` as the first wallet follow-up |
| fees accrue to a per-validator `rewards` field in a `validators` register seeded from genesis (`ValidatorEntry { public_key, stake, rewards }`) | spec §8's register minus Bond/Unbond/Withdraw; S2 adds the rest without moving the root | none |
| the node's `hc_bundle` (digest of the vendored `bundle` guest) must equal the genesis `hc_bundle` or the node refuses to start | spec §13 "hc_bundle pinned in genesis" | a build with a different guest cannot join, by design |
| genesis `build` takes the executor (`Genesis::build(&self, executor)`) because alloc notes are appended to the tree | the tree root needs Poseidon2 | genesis hashes computed with `StubExecutor` differ from real ones; tests use the stub consistently and the pinned-hash test lives in `shrugg-node` |
| the size cap "transaction ≤ 8 KiB before the proof" is realized as per-field caps (envelopes ≤ 2 KiB each, proofs ≤ 1 MiB, program ≤ 4096 words, everything else fixed-size) | a Deploy alone is up to 16 KiB | none |
| `DisabledExecutor` is deleted; `confidential: false` gates Deploy/Call inside the ledger (`TxError::ConfidentialDisabled`) | bundles always need the zkVM verifier | none |
| `SpendKey` is 256 bits (research follow-up plan `circuits/docs/superpowers/plans/2026-09-12-shielded-z-spend-key.md`) | `pk` is known to every counterparty; a 64-bit key is a brute-force target | none |

## File structure

```
crates/shrugg-core/src/
  notes.rs            [new]  Word8 helpers, Envelope, Bundle, BundleDigestInput, ShieldedAddress,
                             CommitmentTree (frontier), FullTree (reference + witness paths)
  confidential.rs     [edit] trait gains node_hash / bundle_digest / bundle_proof_digest / verify_bundle;
                             StubExecutor implements them (blake3 stand-ins); DisabledExecutor removed
  types/transaction.rs [rewrite] Action, Transaction (bundle + action), mint signing, amounts as u64
  gas.rs              [edit] u64 fees, BUNDLE_BASE, fee_floor(action)
  ledger.rs           [rewrite] notes ledger, ValidatorEntry, admission order, state root
  genesis.rs          [edit] alloc = deposit notes, hc_bundle, build(executor), bridge rejected
  program.rs          [edit] ProgramRecord loses `deployer`; CallReceipt loses `effect`
  effect.rs           [delete]
  lib.rs              [edit] exports
crates/shrugg-zkvm/
  Cargo.toml          [edit] ml-kem, chacha20poly1305
  src/{notes,viewing,ledger}.rs [vendored] from research (sync script)
  src/guests.rs, src/asm.rs     [edit] bundle guest + Z asm helpers copied from research
  src/executor.rs     [edit] hc_bundle, node_hash, bundle_digest, bundle_proof_digest, verify_bundle,
                             prove_bundle, warm_bundle, conversions core<->research types
  src/address.rs      [new]  ShieldedAddress <-> viewing::Address, key derivation helpers for the wallet
  tests/executor.rs   [edit] bundle prove/verify e2e, tree cross-check against the vendored tree
  deploy/sync-zkvm.sh [edit] vendor notes/viewing/ledger; exclude their tests
crates/shrugg-node/src/
  storage.rs          [rewrite parts] CFs notes/nullifiers/anchors/validators, meta tree, commit, load, truncate, verify_chain
  mempool.rs          [rewrite] nullifier/commitment conflicts, fee ordering
  node.rs             [edit] Mint command builds a note, hc_bundle startup check, warm_bundle
  rpc.rs              [edit] redaction + the five new methods
  main.rs             [edit] genesis with shielded alloc; balance/transfer subcommands removed
  tests/cluster.rs    [rewrite] shielded helpers
crates/shrugg-client/src/
  lib.rs              [edit] RpcClient: new methods, account/balance/transfer removed
  wallet.rs           [new]  key file v2, note store, scan, select, build+prove+send
  main.rs             [edit] commands
docs/shielded.md      [new]  user guide; docs/rpc.md, architecture.md, cli.md, confidential.md, bridge.md [edit]
deploy/README.md, deploy/genesis.json [edit] (a new chain is cut by the fleet operator, not this plan)
```

---

### Task 1: Core shielded types, the commitment tree, and the executor extension

**Files:**
- Create: `crates/shrugg-core/src/notes.rs`
- Modify: `crates/shrugg-core/src/confidential.rs`
- Modify: `crates/shrugg-core/src/lib.rs` (add `pub mod notes;` and `pub use notes::{Word8, Envelope, Bundle, ShieldedAddress};`)
- Test: unit tests inside `notes.rs` and `confidential.rs`

**Interfaces:**
- Produces (consumed by every later task):

```rust
// crates/shrugg-core/src/notes.rs
pub type Word8 = [u32; 8];
pub const DEPTH: usize = 32;
pub const MAX_ENVELOPE_BYTES: usize = 2048;
pub const KEM_EK_BYTES: usize = 1184;
pub const ADDRESS_PREFIX: &str = "shrugg1";
pub fn word8_to_bytes(w: &Word8) -> [u8; 32];            // little-endian words
pub fn word8_from_bytes(b: &[u8]) -> Option<Word8>;       // None unless b.len() == 32
pub fn word8_to_hex(w: &Word8) -> String;
pub fn word8_from_hex(s: &str) -> Option<Word8>;
pub struct Envelope { pub kem_ct: Vec<u8>, pub to_receiver: Vec<u8>, pub to_sender: Vec<u8>, pub body: Vec<u8> }
impl Envelope { pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool; }
pub struct Bundle { pub anchor: Word8, pub nullifiers: [Word8; 2], pub commitments: [Word8; 2], pub fee: u64, pub burn: u64, pub asset: u32, pub time: u32, pub envelopes: [Envelope; 2], pub proof: Vec<u8> }
pub struct BundleDigestInput { pub anchor: Word8, pub nullifiers: [Word8; 2], pub commitments: [Word8; 2], pub fee: u64, pub burn: u64, pub asset: u32, pub time: u32 }
impl Bundle { pub fn digest_input(&self) -> BundleDigestInput; }
pub struct ShieldedAddress { pub pk: Word8, pub kem_ek: Vec<u8> }
impl ShieldedAddress { pub fn to_string(&self) -> String; pub fn parse(s: &str) -> Result<ShieldedAddress, AddressError>; }
pub enum AddressError { Prefix, Base58, Length(usize) }
pub struct CommitmentTree { .. }   // Serialize + Deserialize + Clone + PartialEq
impl CommitmentTree {
    pub fn new(h: &dyn ConfidentialExecutor) -> CommitmentTree;
    pub fn root(&self) -> Word8;
    pub fn next_index(&self) -> u64;
    pub fn append(&mut self, cm: Word8, h: &dyn ConfidentialExecutor) -> u64;   // returns the leaf index
    pub fn empty_root(h: &dyn ConfidentialExecutor) -> Word8;
}
pub struct FullTree { .. }
impl FullTree {
    pub fn new(leaves: Vec<Word8>, h: &dyn ConfidentialExecutor) -> FullTree;
    pub fn root(&self) -> Word8;
    pub fn path(&self, index: u64) -> Option<[Word8; DEPTH]>;   // None if index >= leaves
    pub fn len(&self) -> usize;
}
```

```rust
// crates/shrugg-core/src/confidential.rs — additions to the trait
pub trait ConfidentialExecutor: Send + Sync {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError>;
    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError>;
    fn warm(&self, _program: &ProgramRecord) {}
    /// Poseidon2 tree-node hash `H(NODE, left || right)` — the hash `MERKLE_VERIFY` checks against.
    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8;
    /// `notes::bundle_digest(..)` over the public bundle fields with the taint word fixed to 0.
    fn bundle_digest(&self, input: &BundleDigestInput) -> Word8;
    /// Cheap: decode `proof`, check its declared tier/heights/public-value canonicity, and return
    /// the digest it publishes in `OUT0..OUT7`. Verifies nothing cryptographic.
    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError>;
    /// Expensive: the STARK verification of a bundle proof against the pinned bundle guest.
    fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError>;
    /// Precompute the bundle verifier key. May be a no-op.
    fn warm_bundle(&self) {}
}
```

`ConfidentialError` gains `#[error("bundle proof: {0}")] InvalidBundleProof(String)`.

- [ ] **Step 1: Write the failing tests for words, envelopes and addresses**

Create `crates/shrugg-core/src/notes.rs` with only a `#[cfg(test)] mod tests` block for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;

    #[test]
    fn word8_bytes_are_little_endian_and_roundtrip() {
        let w: Word8 = [1, 2, 3, 4, 5, 6, 7, 0x8000_0000];
        let b = word8_to_bytes(&w);
        assert_eq!(&b[..4], &[1, 0, 0, 0]);
        assert_eq!(&b[28..], &[0, 0, 0, 0x80]);
        assert_eq!(word8_from_bytes(&b), Some(w));
        assert_eq!(word8_from_bytes(&b[..31]), None);
        assert_eq!(word8_from_hex(&word8_to_hex(&w)), Some(w));
        assert_eq!(word8_from_hex("zz"), None);
    }

    #[test]
    fn envelope_len_sums_every_part() {
        let e = Envelope { kem_ct: vec![0; 1088], to_receiver: vec![0; 60], to_sender: vec![0; 60], body: vec![0; 140] };
        assert_eq!(e.len(), 1348);
        assert!(e.len() <= MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn shielded_address_roundtrips_and_rejects_bad_input() {
        let a = ShieldedAddress { pk: [9; 8], kem_ek: vec![7; KEM_EK_BYTES] };
        let s = a.to_string();
        assert!(s.starts_with(ADDRESS_PREFIX));
        assert_eq!(ShieldedAddress::parse(&s).unwrap(), a);
        assert_eq!(ShieldedAddress::parse("abc").unwrap_err(), AddressError::Prefix);
        assert_eq!(ShieldedAddress::parse("shrugg10OIl").unwrap_err(), AddressError::Base58);
        let short = format!("{ADDRESS_PREFIX}{}", bs58::encode([1u8; 40]).into_string());
        assert_eq!(ShieldedAddress::parse(&short).unwrap_err(), AddressError::Length(40));
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p shrugg-core notes::`
Expected: compile errors (`word8_to_bytes`, `Envelope`, `ShieldedAddress` undefined).

- [ ] **Step 3: Implement words, envelopes, bundles and addresses**

Above the tests in `notes.rs`:

```rust
//! Shielded-pool data types shared by the ledger, storage, RPC and wallet: fixed-width words,
//! envelopes, bundles, addresses and the commitment tree. No hash lives here: every Poseidon2
//! evaluation the pool needs is reached through `ConfidentialExecutor`, which keeps this crate
//! free of the zkVM's field-arithmetic crates.

use crate::confidential::ConfidentialExecutor;
use serde::{Deserialize, Serialize};

pub type Word8 = [u32; 8];
pub const DEPTH: usize = 32;
pub const MAX_ENVELOPE_BYTES: usize = 2048;
/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const KEM_EK_BYTES: usize = 1184;
pub const ADDRESS_PREFIX: &str = "shrugg1";

pub fn word8_to_bytes(w: &Word8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, x) in w.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    out
}

pub fn word8_from_bytes(b: &[u8]) -> Option<Word8> {
    if b.len() != 32 {
        return None;
    }
    Some(std::array::from_fn(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap())))
}

pub fn word8_to_hex(w: &Word8) -> String {
    hex::encode(word8_to_bytes(w))
}

pub fn word8_from_hex(s: &str) -> Option<Word8> {
    word8_from_bytes(&hex::decode(s).ok()?)
}

/// What travels with a created note besides its commitment. The chain checks nothing about it;
/// it exists so the right keys can open the note later (`shrugg-zkvm`'s vendored `viewing.rs`
/// seals and opens it; this is the same four-part layout).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub kem_ct: Vec<u8>,
    pub to_receiver: Vec<u8>,
    pub to_sender: Vec<u8>,
    pub body: Vec<u8>,
}

impl Envelope {
    pub fn len(&self) -> usize {
        self.kem_ct.len() + self.to_receiver.len() + self.to_sender.len() + self.body.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A shielded 2-in-2-out bundle (spec §3). Every field is public chain data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub anchor: Word8,
    pub nullifiers: [Word8; 2],
    pub commitments: [Word8; 2],
    pub fee: u64,
    pub burn: u64,
    pub asset: u32,
    /// Block height the sender targeted; copied into both output notes by the guest.
    pub time: u32,
    /// `envelopes[i]` is sealed against `commitments[i]`.
    pub envelopes: [Envelope; 2],
    /// `postcard(rand_zkvm::Proof)` of the `bundle` guest.
    pub proof: Vec<u8>,
}

/// The public preimage of a bundle digest, minus the taint word the verifier fixes to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleDigestInput {
    pub anchor: Word8,
    pub nullifiers: [Word8; 2],
    pub commitments: [Word8; 2],
    pub fee: u64,
    pub burn: u64,
    pub asset: u32,
    pub time: u32,
}

impl Bundle {
    pub fn digest_input(&self) -> BundleDigestInput {
        BundleDigestInput {
            anchor: self.anchor,
            nullifiers: self.nullifiers,
            commitments: self.commitments,
            fee: self.fee,
            burn: self.burn,
            asset: self.asset,
            time: self.time,
        }
    }
}

/// A shielded address: the note owner field `pk` plus the ML-KEM-768 encapsulation key
/// envelopes are sealed to. Text form: `shrugg1` + base58(pk bytes || kem_ek).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAddress {
    pub pk: Word8,
    pub kem_ek: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AddressError {
    #[error("shielded address must start with {ADDRESS_PREFIX}")]
    Prefix,
    #[error("shielded address is not base58")]
    Base58,
    #[error("shielded address decodes to {0} bytes, expected {}", 32 + KEM_EK_BYTES)]
    Length(usize),
}

impl ShieldedAddress {
    pub fn to_string(&self) -> String {
        let mut raw = word8_to_bytes(&self.pk).to_vec();
        raw.extend_from_slice(&self.kem_ek);
        format!("{ADDRESS_PREFIX}{}", bs58::encode(raw).into_string())
    }

    pub fn parse(s: &str) -> Result<ShieldedAddress, AddressError> {
        let rest = s.strip_prefix(ADDRESS_PREFIX).ok_or(AddressError::Prefix)?;
        let raw = bs58::decode(rest).into_vec().map_err(|_| AddressError::Base58)?;
        if raw.len() != 32 + KEM_EK_BYTES {
            return Err(AddressError::Length(raw.len()));
        }
        Ok(ShieldedAddress { pk: word8_from_bytes(&raw[..32]).unwrap(), kem_ek: raw[32..].to_vec() })
    }
}

impl std::fmt::Display for ShieldedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&ShieldedAddress::to_string(self))
    }
}
```

(`hex` and `bs58` are already `shrugg-core` dependencies.) Run `cargo test -p shrugg-core notes::` — the three tests pass.

- [ ] **Step 4: Extend the executor trait and the stub**

In `confidential.rs`, add the imports `use crate::notes::{BundleDigestInput, Word8, word8_to_bytes, word8_from_bytes};`, the four trait methods and `warm_bundle` from the Interfaces block above, the `InvalidBundleProof(String)` error variant, delete `DisabledExecutor` and its test, and implement the stub:

```rust
/// Stub bundle proof: `STUB` || 32-byte digest || blake3("shrugg-stub-bundle", hc_bundle bytes)[..8].
const STUB_BUNDLE_LEN: usize = 4 + 32 + 8;

impl StubExecutor {
    pub fn make_bundle_proof(hc_bundle: &Word8, digest: &Word8) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.extend_from_slice(&word8_to_bytes(digest));
        v.extend_from_slice(&Hash::digest_domain(b"shrugg-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8]);
        v
    }
    fn hash_words(domain: &[u8], parts: &[&[u8]]) -> Word8 {
        let mut buf = Vec::new();
        for p in parts {
            buf.extend_from_slice(p);
        }
        word8_from_bytes(&Hash::digest_domain(domain, &buf).0).unwrap()
    }
}

impl ConfidentialExecutor for StubExecutor {
    // check_program / verify_call unchanged
    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        Self::hash_words(b"shrugg-stub-node", &[&word8_to_bytes(left), &word8_to_bytes(right)])
    }
    fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
        Self::hash_words(
            b"shrugg-stub-bundle-digest",
            &[
                &word8_to_bytes(&i.anchor),
                &word8_to_bytes(&i.nullifiers[0]),
                &word8_to_bytes(&i.nullifiers[1]),
                &word8_to_bytes(&i.commitments[0]),
                &word8_to_bytes(&i.commitments[1]),
                &i.fee.to_le_bytes(),
                &i.burn.to_le_bytes(),
                &i.asset.to_le_bytes(),
                &i.time.to_le_bytes(),
            ],
        )
    }
    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        if proof.len() != STUB_BUNDLE_LEN || &proof[..4] != STUB_MARKER {
            return Err(ConfidentialError::MalformedProof);
        }
        Ok(word8_from_bytes(&proof[4..36]).unwrap())
    }
    fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError> {
        self.bundle_proof_digest(proof)?;
        let expected = &Hash::digest_domain(b"shrugg-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8];
        if &proof[36..] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        Ok(())
    }
}
```

Add a test in `confidential.rs`:

```rust
#[test]
fn stub_bundle_proof_carries_its_digest_and_binds_hc() {
    let hc = [3u32; 8];
    let d = [5u32; 8];
    let p = StubExecutor::make_bundle_proof(&hc, &d);
    assert_eq!(StubExecutor.bundle_proof_digest(&p).unwrap(), d);
    assert_eq!(StubExecutor.verify_bundle(&hc, &p), Ok(()));
    assert_eq!(StubExecutor.verify_bundle(&[4u32; 8], &p), Err(ConfidentialError::WrongProgram));
    assert_eq!(StubExecutor.bundle_proof_digest(b"junk"), Err(ConfidentialError::MalformedProof));
    assert_ne!(StubExecutor.node_hash(&[1; 8], &[2; 8]), StubExecutor.node_hash(&[2; 8], &[1; 8]));
}
```

`cargo test -p shrugg-core confidential::` passes. (The `ledger.rs` code that names `DisabledExecutor` — `default_executor` does not; `grep -rn DisabledExecutor crates/` must be empty after this step, fix any use in `shrugg-node` only by leaving a `// S1: removed` note if that crate is not compiled by this task's gate.)

- [ ] **Step 5: Write the failing tree tests**

Append to the `tests` module in `notes.rs`:

```rust
    /// Naive reference: hash every level over the padded leaf list.
    fn naive_root(leaves: &[Word8], h: &dyn ConfidentialExecutor) -> Word8 {
        let mut empty = vec![[0u32; 8]; DEPTH + 1];
        for d in 1..=DEPTH {
            empty[d] = h.node_hash(&empty[d - 1], &empty[d - 1]);
        }
        let mut level: Vec<Word8> = leaves.to_vec();
        for d in 0..DEPTH {
            if level.is_empty() {
                return empty[DEPTH];
            }
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let r = if pair.len() == 2 { pair[1] } else { empty[d] };
                next.push(h.node_hash(&pair[0], &r));
            }
            level = next;
        }
        level[0]
    }

    fn leaf(i: u32) -> Word8 { [i, i + 1, i + 2, i + 3, 0, 0, 0, 0] }

    #[test]
    fn frontier_tree_matches_the_naive_tree_for_every_size() {
        let h = StubExecutor;
        let mut t = CommitmentTree::new(&h);
        assert_eq!(t.root(), naive_root(&[], &h));
        assert_eq!(t.root(), CommitmentTree::empty_root(&h));
        let mut leaves = Vec::new();
        for i in 0..40u32 {
            let idx = t.append(leaf(i), &h);
            assert_eq!(idx, i as u64);
            leaves.push(leaf(i));
            assert_eq!(t.root(), naive_root(&leaves, &h), "size {}", i + 1);
            assert_eq!(t.next_index(), leaves.len() as u64);
        }
        let bytes = bincode::serialize(&t).unwrap();
        let back: CommitmentTree = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn full_tree_paths_recompute_the_root() {
        let h = StubExecutor;
        let leaves: Vec<Word8> = (0..13u32).map(leaf).collect();
        let full = FullTree::new(leaves.clone(), &h);
        assert_eq!(full.root(), naive_root(&leaves, &h));
        for (index, l) in leaves.iter().enumerate() {
            let path = full.path(index as u64).unwrap();
            let mut node = *l;
            let mut pos = index;
            for sib in path.iter() {
                node = if pos & 1 == 0 { h.node_hash(&node, sib) } else { h.node_hash(sib, &node) };
                pos >>= 1;
            }
            assert_eq!(node, full.root(), "leaf {index}");
        }
        assert!(full.path(13).is_none());
    }
```

- [ ] **Step 6: Run to verify they fail**

Run: `cargo test -p shrugg-core notes::`
Expected: compile errors (`CommitmentTree`, `FullTree` undefined).

- [ ] **Step 7: Implement the frontier tree and the full tree**

Add to `notes.rs`:

```rust
/// The append-only depth-32 commitment tree as a frontier: the left sibling kept at each
/// level of the rightmost path, plus the empty-subtree digests. `O(DEPTH)` per append and
/// `O(DEPTH)` state, so a chain never materializes its leaves in consensus state. Leaves are
/// `Word8`; `empty[0]` is the all-zero leaf, `empty[d] = H(NODE, empty[d-1], empty[d-1])` —
/// exactly the research crate's `ledger::CommitmentTree`, so a witness built from the
/// `FullTree` below verifies inside the `bundle` guest's `MERKLE_VERIFY`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentTree {
    next_index: u64,
    /// `frontier[d]` is the completed left subtree at depth `d` that the next leaf's path
    /// will use as a left sibling, if any.
    frontier: Vec<Option<Word8>>,
    empty: Vec<Word8>,
    root: Word8,
}

fn empty_digests(h: &dyn ConfidentialExecutor) -> Vec<Word8> {
    let mut empty = vec![[0u32; 8]; DEPTH + 1];
    for d in 1..=DEPTH {
        empty[d] = h.node_hash(&empty[d - 1], &empty[d - 1]);
    }
    empty
}

impl CommitmentTree {
    pub fn new(h: &dyn ConfidentialExecutor) -> CommitmentTree {
        let empty = empty_digests(h);
        CommitmentTree { next_index: 0, frontier: vec![None; DEPTH], root: empty[DEPTH], empty }
    }

    pub fn empty_root(h: &dyn ConfidentialExecutor) -> Word8 {
        empty_digests(h)[DEPTH]
    }

    pub fn root(&self) -> Word8 {
        self.root
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Append `cm` as the next leaf and return its index. Panics if the tree is full (2^32 leaves).
    pub fn append(&mut self, cm: Word8, h: &dyn ConfidentialExecutor) -> u64 {
        assert!(self.next_index < (1u64 << DEPTH), "commitment tree is full");
        let index = self.next_index;
        let mut node = cm;
        let mut pos = index;
        for d in 0..DEPTH {
            if pos & 1 == 0 {
                // `node` is a left child whose right sibling is still empty; it becomes the left
                // sibling of the next leaf's path at this depth.
                self.frontier[d] = Some(node);
                node = h.node_hash(&node, &self.empty[d]);
            } else {
                let left = self.frontier[d].expect("a right child always has a completed left sibling");
                node = h.node_hash(&left, &node);
            }
            pos >>= 1;
        }
        self.root = node;
        self.next_index = index + 1;
        index
    }
}

/// Every level materialized — the reference for `CommitmentTree` and the witness source for
/// `shrugg_getWitness` and the cluster tests. `O(leaves)` memory and hashing.
#[derive(Clone, Debug)]
pub struct FullTree {
    levels: Vec<Vec<Word8>>,
    empty: Vec<Word8>,
}

impl FullTree {
    pub fn new(leaves: Vec<Word8>, h: &dyn ConfidentialExecutor) -> FullTree {
        let empty = empty_digests(h);
        let mut levels = vec![leaves];
        for d in 0..DEPTH {
            let cur = &levels[d];
            let next: Vec<Word8> = if cur.is_empty() {
                Vec::new()
            } else {
                cur.chunks(2).map(|p| h.node_hash(&p[0], if p.len() == 2 { &p[1] } else { &empty[d] })).collect()
            };
            levels.push(next);
        }
        FullTree { levels, empty }
    }

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn root(&self) -> Word8 {
        self.levels[DEPTH].first().copied().unwrap_or(self.empty[DEPTH])
    }

    /// Sibling per level, leaf level first — the layout `notes::bundle_inputs` expects.
    pub fn path(&self, index: u64) -> Option<[Word8; DEPTH]> {
        if index >= self.len() as u64 {
            return None;
        }
        let mut path = [[0u32; 8]; DEPTH];
        let mut pos = index as usize;
        for (d, sib) in path.iter_mut().enumerate() {
            let s = pos ^ 1;
            *sib = self.levels[d].get(s).copied().unwrap_or(self.empty[d]);
            pos >>= 1;
        }
        Some(path)
    }
}
```

- [ ] **Step 8: Run the tests**

Run: `cargo test -p shrugg-core notes:: confidential::`
Expected: all pass. Then `cargo test -p shrugg-core` — every existing test still passes (nothing else changed yet).

- [ ] **Step 9: Commit**

```bash
git add crates/shrugg-core/src/notes.rs crates/shrugg-core/src/confidential.rs crates/shrugg-core/src/lib.rs
git commit -m "core: shielded-pool types — Word8, Envelope, Bundle, ShieldedAddress, frontier and full commitment trees; executor gains node_hash/bundle_digest/verify_bundle"
```

---

### Task 2: Vendor the note layer and the bundle guest into `shrugg-zkvm`

**Files:**
- Modify: `deploy/sync-zkvm.sh` (stop excluding `notes.rs`, `viewing.rs`, `ledger.rs`; keep excluding `tests/viewing.rs` and add `tests/bundle.rs` to the excluded tests)
- Modify: `crates/shrugg-zkvm/Cargo.toml` (add `ml-kem = "=0.3.2"`, `chacha20poly1305 = "=0.11.0"`)
- Vendored: `crates/shrugg-zkvm/src/notes.rs`, `src/viewing.rs`, `src/ledger.rs` (run the script; they now compile against `hash.rs` which already exists — the script's `HC_DOMAIN`/`IN_DOMAIN` patch must be reverted for `hash.rs` and `tables/cpu.rs` now that `notes::domain` is present, or kept with `notes::domain::HC == hash::HC_DOMAIN` asserted by a test: choose the latter, it is smaller)
- Modify: `crates/shrugg-zkvm/src/guests.rs`, `src/asm.rs` (copy from research, at the commit named in the dispatch: `asm.rs`'s phase Z helpers `emit_merkle_verify` (looped), `copy_word8_from_reg`, `emit_eq8`, `emit_bool_or`, `emit_range_check_u63`, `emit_add64_carry`; `guests.rs`'s `transfer()`, `bundle()`, `note_commit_probe()`, `merkle_probe()`; keep the node-local `private_payment`/`balance_check` and `emit_transfer`)
- Modify: `crates/shrugg-zkvm/src/lib.rs` (`pub mod notes; pub mod viewing; pub mod ledger; pub mod address;`)
- Create: `crates/shrugg-zkvm/src/address.rs`
- Modify: `crates/shrugg-zkvm/src/executor.rs`
- Test: `crates/shrugg-zkvm/tests/executor.rs`, `crates/shrugg-zkvm/tests/shielded.rs` (new)

**Interfaces:**
- Consumes: Task 1's `Word8`, `Envelope`, `BundleDigestInput`, `ShieldedAddress`, `FullTree`, `CommitmentTree`, the trait methods.
- Produces:

```rust
// crates/shrugg-zkvm/src/executor.rs
impl ZkExecutor {
    /// Digest of the vendored `bundle` guest — the value a genesis pins as `hc_bundle`.
    pub fn hc_bundle() -> Word8;
    pub fn bundle_program() -> Program;
}
/// Wallet-side: prove `guests::bundle()` on `inputs` (from `notes::bundle_inputs`). Returns
/// (postcard proof bytes, published digest, tier).
pub fn prove_bundle(profile: FriProfile, inputs: &[u32], backend: Backend) -> Result<(Vec<u8>, Word8, u8), String>;

// crates/shrugg-zkvm/src/address.rs
pub fn address_of(vk: &notes::ViewingKey) -> ShieldedAddress;          // pk + kem_ek
pub fn to_research(a: &ShieldedAddress) -> viewing::Address;
pub fn envelope_to_core(e: &viewing::Envelope) -> Envelope;
pub fn envelope_from_core(e: &Envelope) -> viewing::Envelope;
pub fn seal_note(sender: &notes::ViewingKey, to: &ShieldedAddress, note: &notes::Note, tx_key: &viewing::TxKey) -> Envelope;
pub fn digest_input_of(anchor: Word8, nf: [Word8; 2], cm: [Word8; 2], fee: u64, burn: u64, asset: u32, time: u32) -> BundleDigestInput;
```

- [ ] **Step 1: Update the sync script and vendor**

Edit `deploy/sync-zkvm.sh`: remove `--exclude notes.rs --exclude viewing.rs --exclude ledger.rs` from the `src/` rsync; add `--exclude bundle.rs` next to `--exclude viewing.rs` on the `tests/` rsync; update the header comment (the note layer is vendored from S1 on; `tests/viewing.rs` and `tests/bundle.rs` stay upstream because they take minutes). Run `deploy/sync-zkvm.sh <research commit>` as the script documents. Add the two dependencies to `crates/shrugg-zkvm/Cargo.toml` (also `rand = "0.10"` is already there; `viewing.rs` needs `rand::Rng` — it compiles upstream with the same versions).

Run: `cargo build -p shrugg-zkvm`
Expected: errors only in `guests.rs`/`asm.rs` (missing `bundle`, `emit_eq8`, ...) — resolved in Step 2.

- [ ] **Step 2: Bring the guest and assembler additions across**

Diff `../circuits/research/src/asm.rs` and `src/guests.rs` against the node's copies and copy every phase Z addition (the functions named in Files above) verbatim, keeping the node-local additions. The node's `guests::all()` must now include `("transfer", transfer(), ...)` only if the research `all()` does; mirror research. Then:

Run: `cargo build -p shrugg-zkvm && cargo test -p shrugg-zkvm --test executor`
Expected: builds; existing executor tests pass.

- [ ] **Step 3: Write the failing shielded tests**

Create `crates/shrugg-zkvm/tests/shielded.rs`:

```rust
use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::notes::{CommitmentTree, FullTree, Word8, DEPTH};
use shrugg_zkvm::executor::{prove_bundle, ZkExecutor};
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::notes::{self, Note, SpendKey};
use shrugg_zkvm::address::{address_of, digest_input_of, seal_note};
use shrugg_zkvm::viewing::TxKey;

fn leaf(i: u32) -> Word8 { [i, 7, 7, 7, 0, 0, 0, i] }

#[test]
fn core_trees_agree_with_the_vendored_research_tree() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let mut research = shrugg_zkvm::ledger::CommitmentTree::new();
    let mut frontier = CommitmentTree::new(&ex);
    let mut leaves = Vec::new();
    for i in 0..21u32 {
        research.append(leaf(i));
        frontier.append(leaf(i), &ex);
        leaves.push(leaf(i));
        assert_eq!(frontier.root(), research.root(), "size {}", i + 1);
        let full = FullTree::new(leaves.clone(), &ex);
        assert_eq!(full.root(), research.root());
        for idx in 0..leaves.len() {
            assert_eq!(full.path(idx as u64).unwrap(), research.path(idx), "path {idx} at size {}", i + 1);
        }
    }
    assert_eq!(CommitmentTree::empty_root(&ex), shrugg_zkvm::ledger::CommitmentTree::new().root());
}

#[test]
fn hc_bundle_is_the_vendored_guest_digest_and_domains_agree() {
    assert_eq!(ZkExecutor::hc_bundle(), ZkExecutor::bundle_program().digest());
    assert_eq!(notes::domain::HC, shrugg_zkvm::hash::HC_DOMAIN);
    assert_eq!(notes::domain::IN, shrugg_zkvm::hash::IN_DOMAIN);
}

/// A 1-in-1-out-with-dummies bundle proves, its digest matches the core-side recompute, and
/// the executor verifies it (about 35 s at the test profile).
#[test]
fn a_bundle_proves_and_the_executor_verifies_it() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let sk = SpendKey::random();
    let vk = sk.viewing_key();
    let me = address_of(&vk);
    let time = 5u32;
    let spent = Note::new(vk.pk(), [0; 8], 1_000, 0, time);
    let mut tree = shrugg_zkvm::ledger::CommitmentTree::new();
    tree.append(spent.commitment());
    let (path, index) = tree.path_for(&spent.commitment()).unwrap();
    let anchor = tree.root();
    let dummy = (Note::new([0; 8], [0; 8], 0, 0, time), [[0; 8]; DEPTH], 0u32);
    let fee = 10u64;
    let out1 = Note::new(vk.pk(), vk.pk(), 600, 0, time);
    let out2 = Note::new(vk.pk(), vk.pk(), 390, 0, time);
    let inputs = notes::bundle_inputs(&sk, &[(spent, path, index), dummy], &[out1, out2], anchor, fee, 0, 0, time);
    let (proof, digest, tier) = prove_bundle(FriProfile::Test, &inputs, Backend::Cpu).unwrap();
    assert_eq!(tier, 14);
    let nf1 = vk.nullifier(&spent.commitment());
    let nf2 = vk.nullifier(&dummy.0.commitment());
    let di = digest_input_of(anchor, [nf1, nf2], [out1.commitment(), out2.commitment()], fee, 0, 0, time);
    assert_eq!(ex.bundle_digest(&di), digest);
    assert_eq!(ex.bundle_proof_digest(&proof).unwrap(), digest);
    ex.verify_bundle(&ZkExecutor::hc_bundle(), &proof).unwrap();
    assert!(ex.verify_bundle(&[1u32; 8], &proof).is_err());
    let e = seal_note(&vk, &me, &out1, &TxKey::random());
    assert!(e.len() <= shrugg_core::notes::MAX_ENVELOPE_BYTES);
}
```

Run: `cargo test -p shrugg-zkvm --test shielded`
Expected: compile errors (`address`, `prove_bundle`, `hc_bundle` undefined).

- [ ] **Step 4: Implement `address.rs`, the executor methods and `prove_bundle`**

`crates/shrugg-zkvm/src/address.rs`:

```rust
//! Bridges the vendored note layer (`notes`, `viewing`) and the node's pure data types.
use crate::notes::{Note, ViewingKey};
use crate::viewing::{self, TxKey};
use shrugg_core::notes::{BundleDigestInput, Envelope, ShieldedAddress, Word8};

pub fn address_of(vk: &ViewingKey) -> ShieldedAddress {
    let a = vk.address();
    ShieldedAddress { pk: a.pk, kem_ek: a.kem_ek }
}

pub fn to_research(a: &ShieldedAddress) -> viewing::Address {
    viewing::Address { pk: a.pk, kem_ek: a.kem_ek.clone() }
}

pub fn envelope_to_core(e: &viewing::Envelope) -> Envelope {
    Envelope { kem_ct: e.kem_ct.clone(), to_receiver: e.to_receiver.clone(), to_sender: e.to_sender.clone(), body: e.body.clone() }
}

pub fn envelope_from_core(e: &Envelope) -> viewing::Envelope {
    viewing::Envelope { kem_ct: e.kem_ct.clone(), to_receiver: e.to_receiver.clone(), to_sender: e.to_sender.clone(), body: e.body.clone() }
}

pub fn seal_note(sender: &ViewingKey, to: &ShieldedAddress, note: &Note, tx_key: &TxKey) -> Envelope {
    envelope_to_core(&viewing::Envelope::seal(sender, &to_research(to), note, tx_key))
}

pub fn digest_input_of(anchor: Word8, nullifiers: [Word8; 2], commitments: [Word8; 2], fee: u64, burn: u64, asset: u32, time: u32) -> BundleDigestInput {
    BundleDigestInput { anchor, nullifiers, commitments, fee, burn, asset, time }
}
```

In `executor.rs`, factor the proof-header checks of `verify_call` into a private `fn decode_and_check(&self, proof: &[u8], program_log_height: u8, input_log_height: u8) -> Result<Proof, ConfidentialError>` that does: postcard decode → `TIERS.contains(tier)` → `proof.program_log_height == program_log_height` and `proof.input_log_height == input_log_height` (exact for bundles; ranged as today for calls, so give it an `exact: bool` flag) → `batch.degree_bits == log_ext_degrees_pub(..)` → every `OUT` public value `<= u32::MAX`. Then:

```rust
impl ZkExecutor {
    pub fn bundle_program() -> Program { crate::guests::bundle() }
    pub fn hc_bundle() -> Word8 { Self::bundle_program().digest() }
    fn bundle_heights() -> (u8, u8) {
        (crate::tables::program::program_log_height(Self::bundle_program().words.len()),
         crate::tables::input::input_log_height(crate::notes::bundle_input::COUNT))
    }
}

impl ConfidentialExecutor for ZkExecutor {
    // check_program, verify_call, warm unchanged
    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        let mut msg = [0u32; 16];
        msg[..8].copy_from_slice(left);
        msg[8..].copy_from_slice(right);
        crate::notes::hash(crate::notes::domain::NODE, &msg)
    }
    fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
        crate::notes::bundle_digest(&i.anchor, &i.nullifiers[0], &i.nullifiers[1], &i.commitments[0], &i.commitments[1], i.fee, i.burn, i.asset, i.time)
    }
    fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        let (plh, ilh) = Self::bundle_heights();
        let p = self.decode_and_check(proof, plh, ilh, true)?;
        Ok(std::array::from_fn(|k| p.public_values[crate::tables::cpu::pv::OUT0 + k] as u32))
    }
    fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError> {
        let (plh, ilh) = Self::bundle_heights();
        let p = self.decode_and_check(proof, plh, ilh, true)?;
        self.machine.verify(hc_bundle, &p).map_err(|e| ConfidentialError::InvalidBundleProof(format!("{e:?}")))
    }
    fn warm_bundle(&self) {
        let (plh, ilh) = Self::bundle_heights();
        let _ = self.machine.verifier_key(crate::machine::Tier(14), plh, ilh);
    }
}

pub fn prove_bundle(profile: FriProfile, inputs: &[u32], backend: Backend) -> Result<(Vec<u8>, Word8, u8), String> {
    let m = Machine::new(profile);
    let program = ZkExecutor::bundle_program();
    let (proof, exec) = m.prove_with(backend, &program, inputs, None).map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}
```

(`Machine::verifier_key`, `prove_with`, `Proof::to_bytes`, `log_ext_degrees_pub` exist in the vendored `machine.rs`; `exec.outputs` is `[u32; 8]`.)

- [ ] **Step 5: Run the shielded tests and the crate suite**

Run: `cargo test -p shrugg-zkvm --test shielded -- --nocapture` (the proving test takes about a minute), then `cargo test -p shrugg-zkvm`.
Expected: all pass. Record the printed tier and the wall-clock of the proof in the report.

- [ ] **Step 6: Commit**

```bash
git add deploy/sync-zkvm.sh crates/shrugg-zkvm
git commit -m "zkvm: vendor the note layer (notes/viewing/ledger) and the bundle guest; executor implements node_hash/bundle_digest/verify_bundle; prove_bundle for wallets"
```

---

### Task 3: The notes ledger, transactions, gas and genesis in `shrugg-core`

**Files:**
- Rewrite: `crates/shrugg-core/src/types/transaction.rs`
- Modify: `crates/shrugg-core/src/gas.rs`
- Rewrite: `crates/shrugg-core/src/ledger.rs`
- Modify: `crates/shrugg-core/src/genesis.rs`, `src/program.rs`, `src/lib.rs`, `src/types/mod.rs`
- Delete: `crates/shrugg-core/src/effect.rs`
- Modify: `crates/shrugg-core/src/consensus/hotstuff.rs` only where it calls `apply_tx`/`state_root` (signatures below keep those calls unchanged; check `consensus/tests.rs` fixtures that build `Transaction::transfer` — replace with `Transaction::mint` fixtures or bundle-less blocks)
- Modify: `crates/shrugg-zkvm/tests/executor.rs` and `src/executor.rs` only if they construct `ProgramRecord { deployer, .. }` (drop the field)
- Test gate for this task: `cargo test -p shrugg-core` green and `cargo build -p shrugg-zkvm --tests` green. `shrugg-node` and `shrugg-client` do not compile until Task 4/5 — expected.

**Interfaces:**
- Consumes: Task 1 types and trait.
- Produces:

```rust
// types/transaction.rs
pub const TOKEN_SYMBOL: &str = "SHRUGG"; pub const TOKEN_DECIMALS: u32 = 9;
pub const UNITS_PER_SHRUGG: u64 = 1_000_000_000;
pub const FAUCET_MAX_UNITS: u64 = 100 * UNITS_PER_SHRUGG;
pub fn format_amount(units: u64) -> String; pub fn parse_amount(s: &str) -> Result<u64, AmountError>;
pub enum Action {
    None,
    Mint { cm: Word8, envelope: Envelope, amount: u64, minter: PublicKey, signature: Signature },
    Deploy { base_pc: u32, words: Vec<u32> },
    Call { program: ProgramId, proof: Vec<u8> },
}
pub struct Transaction { pub chain_id: u64, pub bundle: Option<Bundle>, pub action: Action }
impl Transaction {
    pub fn encode(&self) -> Vec<u8>; pub fn decode(b: &[u8]) -> Result<Transaction, bincode::Error>;
    pub fn hash(&self) -> Hash;                       // blake3 "shrugg-txid" over encode()
    pub fn encoded_len(&self) -> usize;
    pub fn fee(&self) -> u64;                         // bundle fee or 0
    pub fn nullifiers(&self) -> Vec<Word8>;           // the bundle's, or empty
    pub fn commitments(&self) -> Vec<Word8>;          // bundle slots in order, then a Mint's cm
    pub fn mint(chain_id: u64, cm: Word8, envelope: Envelope, amount: u64, minter: &Keypair) -> Transaction;
    pub fn mint_signing_hash(chain_id: u64, cm: &Word8, envelope: &Envelope, amount: u64) -> Hash;
    pub fn shielded(chain_id: u64, bundle: Bundle, action: Action) -> Transaction;
}

// gas.rs (all u64)
pub const BUNDLE_BASE: u64 = 1_000_000;
pub const DEPLOY_PER_WORD: u64 = 100_000; pub const CALL_BASE: u64 = 1_000_000; pub const CALL_PER_TIER_STEP: u64 = 100_000;
pub fn deploy_fee(words: usize) -> u64; pub fn call_fee(tier: u8) -> u64;
/// The floor a bundle must pay before the action's proof is verified (Call's tier-dependent part is checked after).
pub fn fee_floor(action: &Action) -> u64;   // None => BUNDLE_BASE; Deploy => BUNDLE_BASE + deploy_fee; Call => BUNDLE_BASE + CALL_BASE; Mint => 0

// ledger.rs
pub const ANCHOR_WINDOW: usize = 64; pub const TIME_WINDOW: u64 = 64;
pub struct ValidatorEntry { pub public_key: PublicKey, pub stake: u128, pub rewards: u64 }
pub struct Ledger { .. }   // Clone + Debug + PartialEq
impl Ledger {
    pub fn new(chain_id: u64, hc_bundle: Word8, validators: &ValidatorSet, executor: &dyn ConfidentialExecutor) -> Ledger;
    pub fn from_parts(chain_id: u64, hc_bundle: Word8, tree: CommitmentTree, commitments: BTreeSet<Word8>, nullifiers: BTreeSet<Word8>, anchors: Vec<(u64, Word8)>, validators: BTreeMap<Address, ValidatorEntry>, programs: BTreeMap<ProgramId, ProgramRecord>) -> Ledger;
    pub fn chain_id(&self) -> u64; pub fn hc_bundle(&self) -> Word8;
    pub fn faucet_enabled(&self) -> bool; pub fn set_faucet(&mut self, on: bool);
    pub fn confidential_enabled(&self) -> bool; pub fn set_confidential(&mut self, on: bool);
    pub fn set_height(&mut self, h: u64); pub fn set_timestamp_ms(&mut self, t: u64); pub fn timestamp_ms(&self) -> u64;
    pub fn tree(&self) -> &CommitmentTree; pub fn root(&self) -> Word8; pub fn next_index(&self) -> u64;
    pub fn anchors(&self) -> &VecDeque<(u64, Word8)>; pub fn is_anchor(&self, root: &Word8) -> bool;
    pub fn nullifiers(&self) -> &BTreeSet<Word8>; pub fn is_spent(&self, nf: &Word8) -> bool;
    pub fn has_commitment(&self, cm: &Word8) -> bool;
    pub fn validators(&self) -> &BTreeMap<Address, ValidatorEntry>;
    pub fn programs(&self) -> &BTreeMap<ProgramId, ProgramRecord>; pub fn program(&self, id: &ProgramId) -> Option<&ProgramRecord>;
    pub fn validate(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<(), TxError>;
    pub fn apply_tx(&mut self, tx: &Transaction, proposer: &Address, executor: &dyn ConfidentialExecutor) -> Result<Option<CallReceiptData>, TxError>;
    pub fn apply_transactions(&mut self, txs: &[Transaction], proposer: &Address, executor: &dyn ConfidentialExecutor) -> Result<Vec<(usize, CallReceiptData)>, BlockError>;
    pub fn apply_block(&mut self, block: &Block, executor: &dyn ConfidentialExecutor) -> Result<Vec<CallReceipt>, BlockError>;
    pub fn state_root(&self) -> Hash;
    /// Genesis only: append a deposit note without a transaction.
    pub fn deposit(&mut self, cm: Word8, executor: &dyn ConfidentialExecutor) -> Result<u64, TxError>;
    pub fn record_anchor(&mut self, height: u64);
}
pub struct CallReceiptData { pub program: ProgramId, pub tier: u8, pub outputs: [u32; 8] }

// program.rs
pub struct ProgramRecord { pub id: ProgramId, pub base_pc: u32, pub words: Vec<u32>, pub code_hash: Vec<u8>, pub deployed_at: u64 }
pub struct CallReceipt { pub tx: Hash, pub program: ProgramId, pub tier: u8, pub outputs: [u32; 8], pub height: u64, pub index: u32 }

// genesis.rs
pub struct GenesisNote { pub cm: String /* hex */, pub envelope: EnvelopeHex, pub amount: u64 }
pub struct EnvelopeHex { pub kem_ct: String, pub to_receiver: String, pub to_sender: String, pub body: String }
pub struct Genesis { pub chain_id: u64, pub timestamp_ms: u64, pub validators: Vec<GenesisValidator>, #[serde(default)] pub alloc: Vec<GenesisNote>, #[serde(default)] pub faucet: bool, #[serde(default = "default_true")] pub confidential: bool, #[serde(default = "default_profile")] pub fri_profile: String, pub hc_bundle: String /* hex */, #[serde(default, skip_serializing_if = "Option::is_none")] pub bridge: Option<BridgeConfig> }
impl Genesis { pub fn build(&self, executor: &dyn ConfidentialExecutor) -> Result<GenesisState, GenesisError>; }
pub struct GenesisState { pub chain_id, pub faucet, pub confidential, pub fri_profile, pub hc_bundle: Word8, pub validators: ValidatorSet, pub ledger: Ledger, pub block: Block, pub notes: Vec<(Word8, Envelope, u64)> /* cm, envelope, amount in alloc order */ }
```

`TxError` variants (replace the account-era ones): `WrongChain{expected,actual}`, `MissingBundle`, `MintCarriesBundle`, `EnvelopeTooLarge`, `ProofTooLarge`, `ProgramTooLarge`, `UnsupportedAsset(u32)`, `UnsupportedBurn(u64)`, `FeeTooLow{min,fee}`, `UnknownAnchor`, `TimeOutOfWindow{time,height}`, `DuplicateNullifierInBundle`, `Spent(Word8)`, `DuplicateCommitmentInBundle`, `CommitmentExists(Word8)`, `FaucetDisabled`, `MintTooLarge{amount,cap}`, `MinterNotValidator(Address)`, `BadMintSignature`, `ConfidentialDisabled`, `BadProgram(ConfidentialError)`, `UnknownProgram(ProgramId)`, `InvalidProof(ConfidentialError)`, `BadDigest`, `InvalidBundleProof(ConfidentialError)`, `Overflow`. `BlockError` keeps `InvalidTx`, `TxRootMismatch`, `StateRootMismatch`, `BadProposerSignature`, `TooManyTransactions`, `TooLarge`, `UnknownProposer(Address)`; `TimestampRewind` is deleted with the bridge rule.

- [ ] **Step 1: Rewrite `transaction.rs` with its tests first**

Replace the file. Keep `format_amount`/`parse_amount`/`AmountError` as they are but over `u64`. Then:

```rust
use crate::crypto::{Hash, Keypair, PublicKey, Signature};
use crate::notes::{Bundle, Envelope, Word8};
use crate::program::ProgramId;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// A plain shielded transfer.
    None,
    /// Testnet faucet deposit (spec §6): a note of public `amount` created by a validator.
    /// Carried by a bundle-less transaction; `signature` is `minter`'s Dilithium2 signature over
    /// `Transaction::mint_signing_hash`.
    Mint { cm: Word8, envelope: Envelope, amount: u64, minter: PublicKey, signature: Signature },
    Deploy { base_pc: u32, words: Vec<u32> },
    Call { program: ProgramId, proof: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: u64,
    /// `None` only for `Action::Mint`.
    pub bundle: Option<Bundle>,
    pub action: Action,
}

impl Transaction {
    pub fn shielded(chain_id: u64, bundle: Bundle, action: Action) -> Transaction {
        Transaction { chain_id, bundle: Some(bundle), action }
    }
    pub fn mint_signing_hash(chain_id: u64, cm: &Word8, envelope: &Envelope, amount: u64) -> Hash {
        let bytes = bincode::serialize(&(chain_id, cm, envelope, amount)).expect("serializes");
        Hash::digest_domain(b"shrugg-mint", &bytes)
    }
    pub fn mint(chain_id: u64, cm: Word8, envelope: Envelope, amount: u64, minter: &Keypair) -> Transaction {
        let signature = minter.sign(&Self::mint_signing_hash(chain_id, &cm, &envelope, amount));
        Transaction { chain_id, bundle: None, action: Action::Mint { cm, envelope, amount, minter: minter.public_key().clone(), signature } }
    }
    pub fn encode(&self) -> Vec<u8> { bincode::serialize(self).expect("Transaction serializes") }
    pub fn decode(b: &[u8]) -> Result<Transaction, bincode::Error> { bincode::deserialize(b) }
    pub fn hash(&self) -> Hash { Hash::digest_domain(b"shrugg-txid", &self.encode()) }
    pub fn encoded_len(&self) -> usize { self.encode().len() }
    pub fn fee(&self) -> u64 { self.bundle.as_ref().map_or(0, |b| b.fee) }
    pub fn nullifiers(&self) -> Vec<Word8> { self.bundle.as_ref().map_or(Vec::new(), |b| b.nullifiers.to_vec()) }
    pub fn commitments(&self) -> Vec<Word8> {
        let mut v: Vec<Word8> = self.bundle.as_ref().map_or(Vec::new(), |b| b.commitments.to_vec());
        if let Action::Mint { cm, .. } = &self.action { v.push(*cm); }
        v
    }
}
```

Check how `Keypair::sign` and `PublicKey::verify` are spelled in `crypto.rs` and use those names. Tests in the same file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn env() -> Envelope { Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] } }
    fn bundle() -> Bundle {
        Bundle { anchor: [1; 8], nullifiers: [[2; 8], [3; 8]], commitments: [[4; 8], [5; 8]], fee: 1_000_000, burn: 0, asset: 0, time: 9, envelopes: [env(), env()], proof: vec![9; 40] }
    }
    #[test]
    fn transactions_roundtrip_and_hash_their_full_encoding() {
        let tx = Transaction::shielded(7, bundle(), Action::None);
        let back = Transaction::decode(&tx.encode()).unwrap();
        assert_eq!(back, tx);
        assert_eq!(tx.fee(), 1_000_000);
        assert_eq!(tx.nullifiers(), vec![[2; 8], [3; 8]]);
        assert_eq!(tx.commitments(), vec![[4; 8], [5; 8]]);
        let mut other = tx.clone();
        other.bundle.as_mut().unwrap().fee += 1;
        assert_ne!(other.hash(), tx.hash());
    }
    #[test]
    fn a_mint_is_signed_by_its_minter_and_has_no_bundle() {
        let k = Keypair::from_seed([5; 32]).unwrap();
        let tx = Transaction::mint(7, [8; 8], env(), 100, &k);
        assert!(tx.bundle.is_none());
        assert_eq!(tx.fee(), 0);
        assert_eq!(tx.commitments(), vec![[8; 8]]);
        let Action::Mint { cm, envelope, amount, minter, signature } = &tx.action else { panic!() };
        assert!(minter.verify(&Transaction::mint_signing_hash(7, cm, envelope, *amount), signature));
        assert!(!minter.verify(&Transaction::mint_signing_hash(8, cm, envelope, *amount), signature));
    }
    #[test]
    fn amounts_format_and_parse_in_shrugg() {
        assert_eq!(format_amount(1_500_000_000), "1.5");
        assert_eq!(parse_amount("0.000001").unwrap(), 1_000);
        assert!(parse_amount("1.0000000001").is_err());
    }
}
```

Run: `cargo test -p shrugg-core types::transaction::` — passes once `types/mod.rs`/`lib.rs` re-export `Action`, `Transaction`, the constants, and drop `TxKind`/`TxBody`/`Account`.

- [ ] **Step 2: `gas.rs` and `program.rs`**

Convert the four fee constants/functions to `u64`, add `BUNDLE_BASE` and `fee_floor(action: &Action) -> u64` as specified. Add a test `fee_floor_adds_the_bundle_base`: `fee_floor(&Action::None) == 1_000_000`, `fee_floor(&Action::Deploy{base_pc:0, words: vec![0x13; 10]}) == 1_000_000 + 1_000_000`, `fee_floor(&Action::Call{..}) == 2_000_000`, `fee_floor(&Action::Mint{..}) == 0`. Remove `deployer` from `ProgramRecord` and `effect` from `CallReceipt`; delete `effect.rs` and its `pub mod effect;` line.

- [ ] **Step 3: Write the ledger tests first**

Replace the `#[cfg(test)] mod tests` of `ledger.rs` with the following (delete every account-era and bridge-era ledger test; the bridge module's own tests in `bridge/` stay):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::notes::Envelope;
    use crate::types::{Validator, ValidatorSet};

    const HC: Word8 = [11; 8];
    fn env() -> Envelope { Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] } }
    fn keys() -> (Keypair, Keypair) { (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap()) }
    fn ledger() -> Ledger {
        let (a, b) = keys();
        let set = ValidatorSet::new(vec![Validator { public_key: a.public_key().clone(), stake: 10 }, Validator { public_key: b.public_key().clone(), stake: 10 }]);
        let mut l = Ledger::new(7, HC, &set, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l
    }
    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes.
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Bundle {
        let mut b = Bundle { anchor: l.root(), nullifiers: nfs, commitments: cms, fee, burn: 0, asset: 0, time: l.height as u32, envelopes: [env(), env()], proof: vec![] };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        b
    }
    fn tx(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2]) -> Transaction { Transaction::shielded(7, bundle(l, nfs, cms, gas::BUNDLE_BASE), Action::None) }

    #[test]
    fn a_valid_bundle_spends_appends_and_pays_the_proposer() {
        let mut l = ledger();
        let (a, _) = keys();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert!(l.is_spent(&[1; 8]) && l.is_spent(&[2; 8]));
        assert!(l.has_commitment(&[3; 8]) && l.has_commitment(&[4; 8]));
        assert_eq!(l.next_index(), 2);
        assert_eq!(l.validators()[&a.address()].rewards, gas::BUNDLE_BASE);
        // replay: both nullifiers now spent
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Spent([1; 8])));
    }

    #[test]
    fn admission_checks_run_in_spec_order() {
        let mut l = ledger();
        let (a, _) = keys();
        // wrong chain
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.chain_id = 8;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::WrongChain { expected: 7, actual: 8 }));
        // envelope cap
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().envelopes[0].body = vec![0; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::EnvelopeTooLarge));
        // fee floor
        let t = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE - 1), Action::None);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE - 1 }));
        // asset / burn unsupported in S1
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().asset = 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedAsset(1)));
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().burn = 5;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedBurn(5)));
        // unknown anchor
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().anchor = [9; 8];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnknownAnchor));
        // time window: future and too old
        l.set_height(100);
        l.record_anchor(100);
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().time = 101;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: 101, height: 100 }));
        t.bundle.as_mut().unwrap().time = 35;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: 35, height: 100 }));
        t.bundle.as_mut().unwrap().time = 36; // height - 64 is allowed
        let mut b = t.bundle.clone().unwrap();
        b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()));
        t.bundle = Some(b);
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        // duplicate nullifier inside the bundle, duplicate commitment inside the bundle
        assert_eq!(l.validate(&tx(&l, [[1; 8], [1; 8]], [[3; 8], [4; 8]]), &StubExecutor), Err(TxError::DuplicateNullifierInBundle));
        assert_eq!(l.validate(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [3; 8]]), &StubExecutor), Err(TxError::DuplicateCommitmentInBundle));
        // existing commitment
        l.apply_tx(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.validate(&tx(&l, [[5; 8], [6; 8]], [[3; 8], [7; 8]]), &StubExecutor), Err(TxError::CommitmentExists([3; 8])));
        // digest mismatch: plaintext fee differs from what the proof committed to
        let mut t = tx(&l, [[5; 8], [6; 8]], [[8; 8], [9; 8]]);
        t.bundle.as_mut().unwrap().fee += 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BadDigest));
        // proof for another guest
        let mut t = tx(&l, [[5; 8], [6; 8]], [[8; 8], [9; 8]]);
        let d = StubExecutor.bundle_digest(&t.bundle.as_ref().unwrap().digest_input());
        t.bundle.as_mut().unwrap().proof = StubExecutor::make_bundle_proof(&[12; 8], &d);
        assert!(matches!(l.validate(&t, &StubExecutor), Err(TxError::InvalidBundleProof(_))));
    }

    #[test]
    fn anchors_are_a_sliding_window_of_block_end_roots() {
        let mut l = ledger();
        let (a, _) = keys();
        let genesis_root = l.root();
        for h in 1..=(ANCHOR_WINDOW as u64) {
            l.set_height(h);
            l.apply_tx(&tx(&l, [[h as u32; 8], [h as u32 + 1000; 8]], [[h as u32 + 2000; 8], [h as u32 + 3000; 8]]), &a.address(), &StubExecutor).unwrap();
            l.record_anchor(h);
        }
        assert_eq!(l.anchors().len(), ANCHOR_WINDOW);
        assert!(!l.is_anchor(&genesis_root), "the genesis root scrolled out after 64 blocks");
        assert!(l.is_anchor(&l.root()));
    }

    #[test]
    fn mint_needs_the_faucet_a_validator_signature_and_no_bundle() {
        let mut l = ledger();
        let (a, _) = keys();
        let stranger = Keypair::from_seed([9; 32]).unwrap();
        let t = Transaction::mint(7, [5; 8], env(), FAUCET_MAX_UNITS, &a);
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        assert_eq!(l.validate(&Transaction::mint(7, [5; 8], env(), FAUCET_MAX_UNITS + 1, &a), &StubExecutor), Err(TxError::MintTooLarge { amount: FAUCET_MAX_UNITS + 1, cap: FAUCET_MAX_UNITS }));
        assert_eq!(l.validate(&Transaction::mint(7, [5; 8], env(), 1, &stranger), &StubExecutor), Err(TxError::MinterNotValidator(stranger.address())));
        let mut forged = Transaction::mint(7, [5; 8], env(), 1, &a);
        if let Action::Mint { amount, .. } = &mut forged.action { *amount = 2; }
        assert_eq!(l.validate(&forged, &StubExecutor), Err(TxError::BadMintSignature));
        let with_bundle = Transaction { bundle: Some(bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE)), ..t.clone() };
        assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::MintCarriesBundle));
        let no_bundle = Transaction { chain_id: 7, bundle: None, action: Action::None };
        assert_eq!(l.validate(&no_bundle, &StubExecutor), Err(TxError::MissingBundle));
        l.set_faucet(false);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::FaucetDisabled));
        l.set_faucet(true);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&[5; 8]));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentExists([5; 8])));
    }

    #[test]
    fn deploy_and_call_ride_on_bundles_and_pay_their_floors() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone() };
        let under = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), deploy.clone());
        assert_eq!(l.validate(&under, &StubExecutor), Err(TxError::FeeTooLow { min: gas::fee_floor(&deploy), fee: gas::BUNDLE_BASE }));
        let ok = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy.clone());
        l.apply_tx(&ok, &a.address(), &StubExecutor).unwrap();
        let id = program_id(0, &words);
        assert!(l.program(&id).is_some());
        let proof = StubExecutor::make_proof(&id, 12, [1, 2, 3, 4, 5, 6, 7, 8]);
        let call = Action::Call { program: id, proof };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12);
        let t = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], fee), call.clone());
        let r = l.apply_tx(&t, &a.address(), &StubExecutor).unwrap().unwrap();
        assert_eq!(r.outputs, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.tier, 12);
        let cheap = Transaction::shielded(7, bundle(&l, [[9; 8], [10; 8]], [[11; 8], [12; 8]], fee - 1), call.clone());
        assert_eq!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: fee, fee: fee - 1 }));
        l.set_confidential(false);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::ConfidentialDisabled));
    }

    #[test]
    fn state_root_covers_tree_nullifiers_validators_and_programs() {
        let mut l = ledger();
        let (a, _) = keys();
        let r0 = l.state_root();
        l.apply_tx(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        let r1 = l.state_root();
        assert_ne!(r0, r1);
        let mut l2 = ledger();
        l2.apply_tx(&tx(&l2, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        assert_eq!(l2.state_root(), r1, "deterministic");
        let rebuilt = Ledger::from_parts(7, HC, l.tree().clone(), l.commitments_set().clone(), l.nullifiers().clone(), l.anchors().iter().copied().collect(), l.validators().clone(), l.programs().clone());
        assert_eq!(rebuilt.state_root(), r1);
        assert_eq!(rebuilt, l);
    }

    #[test]
    fn a_block_with_two_bundles_sharing_a_nullifier_is_invalid() {
        let l = ledger();
        let t1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let t2 = tx(&l, [[2; 8], [5; 8]], [[6; 8], [7; 8]]);
        let (a, _) = keys();
        let mut scratch = l.clone();
        let err = scratch.apply_transactions(&[t1, t2], &a.address(), &StubExecutor).unwrap_err();
        assert_eq!(err, BlockError::InvalidTx { index: 1, error: TxError::Spent([2; 8]) });
        assert_eq!(scratch, l, "unchanged on error");
    }
}
```

(`Ledger::commitments_set()` is the accessor for the in-memory commitment set; name it so.)

- [ ] **Step 4: Run to verify they fail**

Run: `cargo test -p shrugg-core ledger::`
Expected: compile errors.

- [ ] **Step 5: Rewrite `ledger.rs`**

```rust
//! The shielded notes ledger and block application rules (design spec §7, §9).

use crate::confidential::{ConfidentialError, ConfidentialExecutor};
use crate::crypto::{merkle_root, Address, Hash, PublicKey};
use crate::gas;
use crate::notes::{word8_to_bytes, CommitmentTree, Word8, MAX_ENVELOPE_BYTES};
use crate::program::{program_id, CallOutcome, CallReceipt, ProgramId, ProgramRecord};
use crate::types::{Action, Block, Transaction, ValidatorSet, FAUCET_MAX_UNITS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const ANCHOR_WINDOW: usize = 64;
pub const TIME_WINDOW: u64 = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub public_key: PublicKey,
    pub stake: u128,
    /// Bundle fees credited to this proposer (spec §8); paid out by S2's Withdraw.
    pub rewards: u64,
}

// TxError / BlockError / CallReceiptData per the Interfaces block.

#[derive(Clone, Debug)]
pub struct Ledger {
    chain_id: u64,
    hc_bundle: Word8,
    faucet: bool,
    confidential: bool,
    tree: CommitmentTree,
    /// Every leaf ever appended — spec §7 item 6 needs membership the frontier cannot answer.
    commitments: BTreeSet<Word8>,
    nullifiers: BTreeSet<Word8>,
    /// Block-end roots, oldest first, at most ANCHOR_WINDOW.
    anchors: VecDeque<(u64, Word8)>,
    validators: BTreeMap<Address, ValidatorEntry>,
    programs: BTreeMap<ProgramId, ProgramRecord>,
    height: u64,
    timestamp_ms: u64,
}

impl PartialEq for Ledger {
    fn eq(&self, o: &Ledger) -> bool {
        self.chain_id == o.chain_id && self.hc_bundle == o.hc_bundle && self.faucet == o.faucet && self.confidential == o.confidential
            && self.tree == o.tree && self.commitments == o.commitments && self.nullifiers == o.nullifiers
            && self.anchors == o.anchors && self.validators == o.validators && self.programs == o.programs
    }
}
impl Eq for Ledger {}

impl Ledger {
    pub fn new(chain_id: u64, hc_bundle: Word8, validators: &ValidatorSet, executor: &dyn ConfidentialExecutor) -> Ledger {
        let tree = CommitmentTree::new(executor);
        let mut anchors = VecDeque::new();
        anchors.push_back((0, tree.root()));
        let validators = validators.iter().map(|v| (v.public_key.address(), ValidatorEntry { public_key: v.public_key.clone(), stake: v.stake, rewards: 0 })).collect();
        Ledger { chain_id, hc_bundle, faucet: false, confidential: true, tree, commitments: BTreeSet::new(), nullifiers: BTreeSet::new(), anchors, validators, programs: BTreeMap::new(), height: 0, timestamp_ms: 0 }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(chain_id: u64, hc_bundle: Word8, tree: CommitmentTree, commitments: BTreeSet<Word8>, nullifiers: BTreeSet<Word8>, anchors: Vec<(u64, Word8)>, validators: BTreeMap<Address, ValidatorEntry>, programs: BTreeMap<ProgramId, ProgramRecord>) -> Ledger {
        Ledger { chain_id, hc_bundle, faucet: false, confidential: true, tree, commitments, nullifiers, anchors: anchors.into_iter().collect(), validators, programs, height: 0, timestamp_ms: 0 }
    }

    // accessors per the Interfaces block ...

    pub fn is_anchor(&self, root: &Word8) -> bool { self.anchors.iter().any(|(_, r)| r == root) }

    pub fn record_anchor(&mut self, height: u64) {
        self.anchors.push_back((height, self.tree.root()));
        while self.anchors.len() > ANCHOR_WINDOW { self.anchors.pop_front(); }
    }

    pub fn deposit(&mut self, cm: Word8, executor: &dyn ConfidentialExecutor) -> Result<u64, TxError> {
        if !self.commitments.insert(cm) { return Err(TxError::CommitmentExists(cm)); }
        Ok(self.tree.append(cm, executor))
    }

    pub fn validate(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        self.validate_inner(tx, executor).map(|_| ())
    }

    /// Spec §7, in order. Returns the verified call outcome so `apply_tx` verifies once.
    fn validate_inner(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<Option<CallOutcome>, TxError> {
        // 1. size caps
        if let Some(b) = &tx.bundle {
            if b.envelopes.iter().any(|e| e.len() > MAX_ENVELOPE_BYTES) { return Err(TxError::EnvelopeTooLarge); }
            if b.proof.len() > gas::MAX_PROOF_BYTES { return Err(TxError::ProofTooLarge); }
        }
        match &tx.action {
            Action::Mint { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => return Err(TxError::EnvelopeTooLarge),
            Action::Deploy { words, .. } if words.len() > gas::MAX_PROGRAM_WORDS => return Err(TxError::ProgramTooLarge),
            Action::Call { proof, .. } if proof.len() > gas::MAX_PROOF_BYTES => return Err(TxError::ProofTooLarge),
            _ => {}
        }
        // 2. chain id
        if tx.chain_id != self.chain_id { return Err(TxError::WrongChain { expected: self.chain_id, actual: tx.chain_id }); }
        // 3. shape and fee floor
        let is_mint = matches!(tx.action, Action::Mint { .. });
        let bundle = match (&tx.bundle, is_mint) {
            (None, true) => None,
            (None, false) => return Err(TxError::MissingBundle),
            (Some(_), true) => return Err(TxError::MintCarriesBundle),
            (Some(b), false) => Some(b),
        };
        if let Some(b) = bundle {
            if b.asset != 0 { return Err(TxError::UnsupportedAsset(b.asset)); }
            if b.burn != 0 { return Err(TxError::UnsupportedBurn(b.burn)); }
            let min = gas::fee_floor(&tx.action);
            if b.fee < min { return Err(TxError::FeeTooLow { min, fee: b.fee }); }
            // 4. anchor
            if !self.is_anchor(&b.anchor) { return Err(TxError::UnknownAnchor); }
            // 5. time
            let t = b.time as u64;
            if t > self.height || self.height - t > TIME_WINDOW { return Err(TxError::TimeOutOfWindow { time: b.time, height: self.height }); }
            // 6. nullifiers and commitments
            if b.nullifiers[0] == b.nullifiers[1] { return Err(TxError::DuplicateNullifierInBundle); }
            for nf in &b.nullifiers { if self.nullifiers.contains(nf) { return Err(TxError::Spent(*nf)); } }
            if b.commitments[0] == b.commitments[1] { return Err(TxError::DuplicateCommitmentInBundle); }
            for cm in &b.commitments { if self.commitments.contains(cm) { return Err(TxError::CommitmentExists(*cm)); } }
        }
        // 7. action-specific cheap checks
        let mut call_record = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, envelope, amount, minter, signature } => {
                if !self.faucet { return Err(TxError::FaucetDisabled); }
                if *amount > FAUCET_MAX_UNITS { return Err(TxError::MintTooLarge { amount: *amount, cap: FAUCET_MAX_UNITS }); }
                let addr = minter.address();
                if !self.validators.contains_key(&addr) { return Err(TxError::MinterNotValidator(addr)); }
                if !minter.verify(&Transaction::mint_signing_hash(tx.chain_id, cm, envelope, *amount), signature) { return Err(TxError::BadMintSignature); }
                if self.commitments.contains(cm) { return Err(TxError::CommitmentExists(*cm)); }
            }
            Action::Deploy { base_pc, words } => {
                if !self.confidential { return Err(TxError::ConfidentialDisabled); }
                executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
            }
            Action::Call { program, .. } => {
                if !self.confidential { return Err(TxError::ConfidentialDisabled); }
                call_record = Some(self.programs.get(program).ok_or(TxError::UnknownProgram(*program))?);
            }
        }
        // 8-9. the bundle's digest, then its proof
        if let Some(b) = bundle {
            let published = executor.bundle_proof_digest(&b.proof).map_err(TxError::InvalidBundleProof)?;
            if published != executor.bundle_digest(&b.digest_input()) { return Err(TxError::BadDigest); }
            executor.verify_bundle(&self.hc_bundle, &b.proof).map_err(TxError::InvalidBundleProof)?;
        }
        // 10. the call's own proof, then its tier-dependent fee
        if let (Some(record), Action::Call { proof, .. }) = (call_record, &tx.action) {
            let outcome = executor.verify_call(record, proof).map_err(TxError::InvalidProof)?;
            let min = gas::BUNDLE_BASE + gas::call_fee(outcome.tier);
            let fee = tx.fee();
            if fee < min { return Err(TxError::FeeTooLow { min, fee }); }
            return Ok(Some(outcome));
        }
        Ok(None)
    }

    pub fn apply_tx(&mut self, tx: &Transaction, proposer: &Address, executor: &dyn ConfidentialExecutor) -> Result<Option<CallReceiptData>, TxError> {
        let outcome = self.validate_inner(tx, executor)?;
        if let Some(b) = &tx.bundle {
            for nf in &b.nullifiers { self.nullifiers.insert(*nf); }
            for cm in &b.commitments { self.commitments.insert(*cm); self.tree.append(*cm, executor); }
            let entry = self.validators.get_mut(proposer).ok_or(TxError::Overflow)?; // proposer is always a validator; see apply_block
            entry.rewards = entry.rewards.checked_add(b.fee).ok_or(TxError::Overflow)?;
        }
        let mut receipt = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, .. } => { self.commitments.insert(*cm); self.tree.append(*cm, executor); }
            Action::Deploy { base_pc, words } => {
                let id = program_id(*base_pc, words);
                if !self.programs.contains_key(&id) {
                    let code_hash = executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
                    self.programs.insert(id, ProgramRecord { id, base_pc: *base_pc, words: words.clone(), code_hash, deployed_at: self.height });
                }
            }
            Action::Call { program, .. } => {
                let o = outcome.expect("validate_inner returns the outcome for calls");
                receipt = Some(CallReceiptData { program: *program, tier: o.tier, outputs: o.outputs });
            }
        }
        Ok(receipt)
    }

    // apply_transactions: as today (scratch clone, InvalidTx { index, error }).

    pub fn apply_block(&mut self, block: &Block, executor: &dyn ConfidentialExecutor) -> Result<Vec<CallReceipt>, BlockError> {
        if block.transactions.len() > gas::MAX_BLOCK_TXS { return Err(BlockError::TooManyTransactions); }
        let mut bytes = 0usize;
        for tx in &block.transactions { bytes += tx.encoded_len(); if bytes > gas::MAX_BLOCK_BYTES { return Err(BlockError::TooLarge); } }
        if !block.verify_signature() { return Err(BlockError::BadProposerSignature); }
        if !block.verify_tx_root() { return Err(BlockError::TxRootMismatch); }
        let proposer = block.proposer();
        if !self.validators.contains_key(&proposer) { return Err(BlockError::UnknownProposer(proposer)); }
        let mut scratch = self.clone();
        scratch.set_height(block.height());
        scratch.set_timestamp_ms(block.header.timestamp_ms);
        let data = scratch.apply_transactions(&block.transactions, &proposer, executor)?;
        scratch.record_anchor(block.height());
        let computed = scratch.state_root();
        if computed != block.header.state_root { return Err(BlockError::StateRootMismatch { computed, header: block.header.state_root }); }
        *self = scratch;
        Ok(data.into_iter().map(|(index, r)| CallReceipt { tx: block.transactions[index].hash(), program: r.program, tier: r.tier, outputs: r.outputs, height: block.height(), index: index as u32 }).collect())
    }

    /// `blake3("shrugg-state-2" || tree_root || nullifier_root || validators_root || programs_root)`.
    pub fn state_root(&self) -> Hash {
        let nf_leaves: Vec<Hash> = self.nullifiers.iter().map(|nf| Hash::digest_domain(b"shrugg-nullifier-leaf", &word8_to_bytes(nf))).collect();
        let val_leaves: Vec<Hash> = self.validators.iter().map(|(addr, v)| {
            let mut buf = Vec::with_capacity(32 + 16 + 8);
            buf.extend_from_slice(addr.as_bytes());
            buf.extend_from_slice(&v.stake.to_be_bytes());
            buf.extend_from_slice(&v.rewards.to_be_bytes());
            Hash::digest_domain(b"shrugg-validator-leaf", &buf)
        }).collect();
        let prog_leaves: Vec<Hash> = self.programs.keys().map(|id| Hash::digest_domain(b"shrugg-program-leaf", id.as_bytes())).collect();
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&word8_to_bytes(&self.tree.root()));
        buf.extend_from_slice(merkle_root(&nf_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&val_leaves).as_bytes());
        buf.extend_from_slice(merkle_root(&prog_leaves).as_bytes());
        Hash::digest_domain(b"shrugg-state-2", &buf)
    }
}
```

Note the proposer check in `apply_block` (`UnknownProposer`) makes the `ok_or(Overflow)` in `apply_tx` unreachable from block application; the mempool and `HotStuff::propose` call `apply_tx` with the node's own address, which is a validator whenever it proposes.

Run: `cargo test -p shrugg-core ledger::` — passes.

- [ ] **Step 6: Genesis**

In `genesis.rs`: replace `alloc: BTreeMap<String, u128>` with `alloc: Vec<GenesisNote>`, add `hc_bundle: String` (no serde default), add `GenesisNote`/`EnvelopeHex` (with `EnvelopeHex::to_envelope() -> Result<Envelope, GenesisError>` and `from_envelope`), reject `bridge: Some(_)` with `GenesisError::BadBridgeConfig("bridge is not available on the shielded chain until phase S3".into())`, and rewrite `build`:

```rust
pub fn build(&self, executor: &dyn ConfidentialExecutor) -> Result<GenesisState, GenesisError> {
    // validators, fri profile checks as today; bridge rejected
    let hc_bundle = word8_from_hex(&self.hc_bundle).ok_or_else(|| GenesisError::BadHcBundle(self.hc_bundle.clone()))?;
    let mut ledger = Ledger::new(self.chain_id, hc_bundle, &validators, executor);
    ledger.set_faucet(self.faucet);
    ledger.set_confidential(self.confidential);
    ledger.set_timestamp_ms(self.timestamp_ms);
    let mut notes = Vec::new();
    for n in &self.alloc {
        let cm = word8_from_hex(&n.cm).ok_or_else(|| GenesisError::BadNote(n.cm.clone()))?;
        let envelope = n.envelope.to_envelope()?;
        ledger.deposit(cm, executor).map_err(|_| GenesisError::DuplicateNote(n.cm.clone()))?;
        notes.push((cm, envelope, n.amount));
    }
    ledger.record_anchor(0); // replaces the empty-tree root recorded by `new`
    // genesis binding: chain_id, validators, faucet, confidential, fri_profile, hc_bundle, every (cm, amount)
    let mut commit = Vec::new();
    commit.extend_from_slice(&self.chain_id.to_be_bytes());
    commit.extend_from_slice(&bincode::serialize(&validators).expect("serializes"));
    commit.push(self.faucet as u8);
    commit.push(self.confidential as u8);
    commit.extend_from_slice(self.fri_profile.as_bytes());
    commit.extend_from_slice(&word8_to_bytes(&hc_bundle));
    for (cm, _, amount) in &notes { commit.extend_from_slice(&word8_to_bytes(cm)); commit.extend_from_slice(&amount.to_be_bytes()); }
    let genesis_binding = Hash::digest_domain(b"shrugg-genesis-2", &commit);
    // header/block as today, state_root = ledger.state_root()
    ...
}
```

`record_anchor(0)` must replace, not append: make `Ledger::new` record nothing and have `build` (and `from_parts` callers) record the genesis root explicitly — pick one and keep `ledger.anchors().len() == 1` after `build`. Add `GenesisError::{BadHcBundle(String), BadNote(String), DuplicateNote(String)}`. Genesis tests: replace the account-era tests with (a) `alloc_notes_are_in_the_tree_and_the_binding` (two notes → `ledger.next_index() == 2`, `has_commitment`, hash changes when an amount changes), (b) `hc_bundle_is_required_and_bound` (missing field fails to parse; a different value changes the hash), (c) `faucet_and_confidential_flags_change_the_hash_not_the_state_root` (adapt the existing one), (d) `bridge_section_is_rejected`. The pinned-hash test over `deploy/genesis.json` moves to Task 4 (it needs the real hasher).

- [ ] **Step 7: Consensus fixtures and the crate gate**

`consensus/tests.rs` builds transfer transactions for block bodies; replace those fixtures with `Transaction::mint(chain_id, [i; 8], env(), 1, &validator_key)` (mints are valid without notes) and give the fixture ledgers `set_faucet(true)`. `HotStuff::propose` calls `apply_tx(tx, &self_address, executor)` — the signature is unchanged. Delete anything referencing `Account`, `TxKind`, `balance`, `nonce`, `effect`, `bridge` in `ledger.rs`/`genesis.rs`/`consensus/`.

Run: `cargo test -p shrugg-core 2>&1 | tail -5` → green; `cargo build -p shrugg-zkvm --tests` → green (fix `ProgramRecord` constructions).

- [ ] **Step 8: Commit**

```bash
git add crates/shrugg-core crates/shrugg-zkvm
git commit -m "core: the notes ledger — Bundle/Action transactions, spec §7 admission order, shrugg-state-2 root, genesis with deposit notes and hc_bundle; accounts, effects and bridge wiring removed"
```

---

### Task 4: Storage, mempool, node and RPC

**Files:**
- Modify: `crates/shrugg-node/src/storage.rs`, `mempool.rs`, `node.rs`, `rpc.rs`, `main.rs`, `keyfile.rs` (unchanged), `network/wire.rs` (type only)
- Test: unit tests in `storage.rs`, `mempool.rs`, `rpc.rs`; `crates/shrugg-node/tests/cluster.rs` compiles but is rewritten in Task 6 — for this task make it compile with the minimal helper changes (genesis with `alloc: vec![]`, `hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle())`) and `#[ignore]` nothing; tests that no longer make sense (`two_validators_commit_and_transfer`, `faucet_*`, `confidential_call_*`, `bridge_mint_*`) are deleted here and rebuilt in Task 6.
- Gate: `cargo test -p shrugg-node` green (unit tests + the surviving cluster tests).

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces (used by Task 5/6):

```rust
// storage.rs
const CF_NOTES: &str = "notes";           // index BE u64 -> bincode(NoteRow)
const CF_NULLIFIERS: &str = "nullifiers"; // nf 32 bytes -> height BE u64
const CF_ANCHORS: &str = "anchors";       // height BE u64 -> root 32 bytes
const CF_VALIDATORS: &str = "validators"; // address 32 bytes -> bincode(ValidatorEntry)
const META_TREE: &str = "tree";           // bincode(CommitmentTree)
const META_HC_BUNDLE: &str = "hc_bundle"; // 32 bytes
pub struct NoteRow { pub cm: Word8, pub envelope: Envelope, pub height: u64 }
impl Storage {
    pub fn note(&self, index: u64) -> Result<Option<NoteRow>>;
    pub fn notes_from(&self, from: u64, limit: usize) -> Result<Vec<(u64, NoteRow)>>;
    pub fn notes_count(&self) -> Result<u64>;
    pub fn nullifier_height(&self, nf: &Word8) -> Result<Option<u64>>;
    pub fn nullifiers_count(&self) -> Result<u64>;
    pub fn anchor(&self, height: u64) -> Result<Option<Word8>>;
    pub fn tree(&self) -> Result<CommitmentTree>;
    pub fn hc_bundle(&self) -> Result<Word8>;
    pub fn validator(&self, a: &Address) -> Result<Option<ValidatorEntry>>;
    /// The Merkle witness of leaf `index` against the current root (rebuilds a FullTree from `notes`).
    pub fn witness(&self, index: u64, executor: &dyn ConfidentialExecutor) -> Result<Option<(Word8, [Word8; DEPTH])>>;
    pub fn load_ledger(&self) -> Result<Ledger>;
    pub fn commit(&self, blocks: &[CommittedBlock], ledger_after: &Ledger) -> Result<()>;
    pub fn init_genesis(&self, gs: &GenesisState) -> Result<()>;
    pub fn truncate_to(&self, height: u64, ledger: &Ledger) -> Result<()>;
}
// mempool.rs
pub enum MempoolError { Invalid(TxError), Duplicate, Conflict(Word8), Full }
impl Mempool {
    pub fn new(max_size: usize) -> Mempool;
    pub fn insert(&mut self, tx: Transaction, ledger: &Ledger, executor: &dyn ConfidentialExecutor) -> Result<Hash, MempoolError>;
    pub fn candidates_within(&self, ledger: &Ledger, max: usize, max_bytes: usize) -> Vec<Transaction>;  // fee desc, then hash
    pub fn remove(&mut self, hashes: &[Hash]);
    pub fn prune(&mut self, ledger: &Ledger);   // drop spent / existing-commitment / stale-anchor / out-of-window txs
    pub fn len(&self) -> usize;
}
// rpc.rs — method table
shrugg_chainId, shrugg_tokenInfo, shrugg_sendTransaction(hex), shrugg_mint(address: shrugg1.., amount?: units),
shrugg_getCommitments(from_index, limit<=1000) -> [{index, cm, envelope{kem_ct,to_receiver,to_sender,body}, height}],
shrugg_getNullifiers(from_height, limit<=1000) -> [{height, nullifier}],
shrugg_getAnchor(height?) -> {height, root},
shrugg_getWitness(index) -> {index, root, path: [hex; 32]},
shrugg_getTreeInfo -> {next_index, root, nullifiers},
shrugg_getProgram, shrugg_getProgramCode, shrugg_getReceipt (no `effect`), shrugg_estimateFee ({kind: "bundle"|"deploy"|"call", ...}),
shrugg_getTransaction, shrugg_getBlockByHeight, shrugg_getBlockByHash, shrugg_getHead, shrugg_status, shrugg_getPeers, shrugg_getValidators (-> [{address, stake, rewards}])
// removed: shrugg_getBalance, shrugg_getAccount, every shrugg_*Asset*/*Bridge* method
// NodeCommand::Mint { to: ShieldedAddress, amount: u64 }  (node builds the note; errors if this node is not a validator)
```

`tx_json` shape:

```json
{"hash": "...", "chain_id": 7,
 "bundle": {"anchor": "..", "nullifiers": ["..", ".."], "commitments": ["..", ".."], "fee": 1000000, "burn": 0, "asset": 0, "time": 42, "proof_len": 450000, "envelope_len": [1348, 1348]} | null,
 "action": {"kind": "none"} | {"kind": "mint", "cm": "..", "amount": 100000000000, "minter": "<address>"} | {"kind": "deploy", "program": "..", "words": 12} | {"kind": "call", "program": "..", "proof_len": 290000}}
```

- [ ] **Step 1: Storage tests first**

In `storage.rs`'s `tests` module (keep `fixtures` but rebuild it on the new genesis), write:

```rust
#[test]
fn genesis_notes_land_in_the_notes_family_and_the_tree_reloads() {
    let (dir, s, gs) = fixtures::genesis_with_two_notes();   // alloc of two deposit notes, StubExecutor-built
    s.init_genesis(&gs).unwrap();
    assert_eq!(s.notes_count().unwrap(), 2);
    let row = s.note(1).unwrap().unwrap();
    assert_eq!(row.cm, gs.notes[1].0);
    assert_eq!(row.height, 0);
    assert_eq!(s.tree().unwrap(), gs.ledger.tree().clone());
    assert_eq!(s.anchor(0).unwrap(), Some(gs.ledger.root()));
    assert_eq!(s.hc_bundle().unwrap(), gs.hc_bundle);
    let l = s.load_ledger().unwrap();
    assert_eq!(l, gs.ledger);
    drop(dir);
}

#[test]
fn commit_writes_notes_nullifiers_anchors_and_rewards_and_reloads_equal() {
    // build a block with one stub bundle via fixtures::bundle_tx, apply it to a ledger clone,
    // commit, then: notes_count == 4, nullifier_height(nf) == Some(1), anchor(1) == root,
    // validator(proposer).rewards == fee, load_ledger() == ledger_after, state roots equal.
}

#[test]
fn witness_paths_verify_against_the_current_root() {
    // after the commit above: for index in 0..4, (root, path) = witness(index); fold the path
    // with StubExecutor::node_hash exactly as FullTree's test does; equals root; witness(4) == None.
}

#[test]
fn truncate_rewinds_notes_nullifiers_anchors_and_the_tree() {
    // commit two blocks (heights 1, 2); truncate_to(1, &ledger_at_1); notes_count == count at 1,
    // nullifier of block 2 gone, anchor(2) == None, tree() == ledger_at_1.tree(), load_ledger() == ledger_at_1.
}
```

Write `fixtures::genesis_with_two_notes()` and `fixtures::bundle_tx(ledger, nfs, cms, fee)` (the same stub-proof construction as Task 3's ledger tests) in the `pub mod fixtures` the RPC tests import.

- [ ] **Step 2: Implement the storage changes**

Replace `CF_ACCOUNTS` and the three bridge families with the four new families in `ALL_CFS`; add the meta keys; implement the accessors; `init_genesis` writes every `gs.notes[i]` as `NoteRow { height: 0 }` at index `i`, every validator entry, `anchors[0]`, `META_TREE`, `META_HC_BUNDLE`; `commit` writes, per block: block/qc/index/tx-locations as today, then for every tx `for cm in tx.commitments()` → the next `NoteRow` (index from a running counter starting at the pre-commit `notes_count`; envelopes come from the bundle's slot or the mint action), every nullifier → height, receipts, then `anchors[height] = ledger_after`'s anchor for that height (`ledger_after.anchors()` has it), the proposer's `ValidatorEntry` from `ledger_after`, and finally `META_TREE = ledger_after.tree()` and head height; `load_ledger` iterates `nullifiers` (the set), `notes` (the commitment set), `anchors` (the last 64 by key order), `validators`, `programs`, reads `META_TREE`/`META_HC_BUNDLE` and calls `Ledger::from_parts`, then `set_faucet`/`set_confidential` from the genesis flags the node passes (keep the existing pattern: `node.rs` sets them after loading); `truncate_to(height, ledger)`: delete blocks/qcs/index/txs/receipts above `height` as today, delete `notes` rows with index `>= ledger.next_index()`, delete `nullifiers` rows whose height `> height`, `anchors` rows `> height`, rewrite every validator row and `META_TREE` from `ledger`, programs as today. `witness(index, ex)`: iterate `notes` in order into a `Vec<Word8>`, `FullTree::new(leaves, ex)`, return `(root, path)`.

`verify_chain` keeps its structure; the per-block re-execution is `ledger.apply_block(block, executor)` semantics via `apply_transactions` + `record_anchor` + state-root compare, exactly mirroring `Ledger::apply_block`; simplest is to call `apply_block` itself now that the bridge timestamp rule is gone. Remove the bridge cross-checks.

Run: `cargo test -p shrugg-node storage::` — passes.

- [ ] **Step 3: Mempool**

Rewrite `mempool.rs` per the interface; tests:

```rust
#[test] fn inserts_validates_and_orders_by_fee()        // two valid stub bundles, fees 2M and 3M → candidates order [3M, 2M]; total bytes cap respected
#[test] fn rejects_duplicates_and_nullifier_conflicts() // same hash → Duplicate; a second tx sharing a nullifier → Conflict(nf); sharing a commitment → Conflict(cm)
#[test] fn prune_drops_spent_and_stale()               // after applying tx A to the ledger, prune removes A and a tx B spending A's nullifier; a tx with anchor scrolled out is removed
#[test] fn full_pool_rejects()                           // max_size 1
```

`node.rs:272` constructs `Mempool::new(10_000)`.

- [ ] **Step 4: Node and RPC**

`node.rs`: at startup, after loading genesis, `if ZkExecutor::hc_bundle() != gs.hc_bundle { bail!("this build's bundle guest ({}) differs from the genesis hc_bundle ({}); rebuild from the chain's pinned commit", ..) }`; spawn `executor.warm_bundle()` in the background like program warms; `NodeCommand::Mint { to, amount }`: if `!validator` → error "faucet mints are signed by validators; ask a validator node"; else build `Note::new(to.pk, [0; 8], amount, 0, head_height as u32)` (from `shrugg_zkvm::notes`), seal with a throwaway `SpendKey::random().viewing_key()` via `address::seal_note`, `Transaction::mint(chain_id, note.commitment(), envelope, amount, &node_keypair)`, insert into the mempool and gossip, return the tx hash. `propose` uses `candidates_within(tip_ledger, MAX_BLOCK_TXS, MAX_BLOCK_BYTES)`; after every commit `mempool.prune(&ledger)`.

`rpc.rs`: implement the method table above; `shrugg_mint` parses `ShieldedAddress::parse`; `shrugg_getCommitments` clamps `limit` to 1000; `shrugg_getWitness` uses `storage.witness(index, &*executor)`; `shrugg_estimateFee` takes `{"kind":"bundle"}` → `BUNDLE_BASE`, `{"kind":"deploy","words":n}` → `fee_floor(Deploy)`, `{"kind":"call","tier":t}` → `BUNDLE_BASE + call_fee(t)`; `NodeStatus` gains `notes`, `nullifiers`, `tree_root`, `hc_bundle`. RPC unit tests (replace the six bridge tests): `get_commitments_pages_in_order`, `get_witness_matches_storage`, `mint_rejects_a_bad_address` (`-32602` with the `AddressError` text), `send_transaction_rejects_a_stale_anchor` (`-32000`, error text contains "unknown anchor"), `status_reports_note_and_nullifier_counts`.

`main.rs`: `Cmd::Genesis` takes `--alloc <shrugg1address>=<amount in SHRUGG>` (repeatable) and writes `hc_bundle` from `ZkExecutor::hc_bundle()`; it builds each note as the mint path does (throwaway sender) and prints the amounts; `Cmd::Balance`/`Cmd::Transfer` are deleted. Add the pinned-genesis-hash test here (a genesis built in the test from two seeded validators and one alloc note from `SpendKey([7; 8])`, hashed with `ZkExecutor::new(FriProfile::Test)`; pin the hex the first run prints and comment "changes whenever the bundle guest, the note format, or the genesis binding changes").

- [ ] **Step 5: Gate**

Run: `cargo test -p shrugg-node 2>&1 | grep -E 'test result|FAILED'`
Expected: unit tests green; the surviving cluster tests (`four_validators_plus_late_observer_syncs`, `validator_restarts_from_disk_and_resumes`, `restart_cycles_keep_all_nodes_in_sync`, `two_of_four_down_halts_and_recovers_without_fork`, `node_behind_by_more_than_one_sync_batch_catches_up`, `corrupted_rocksdb_is_detected_truncated_and_resynced`) green with faucet mints as their traffic where they used transfers (a validator node's `rpc.mint(...)` with a shielded address derived from `SpendKey([1; 8])`; add `RpcClient::mint_shielded(address: &str, amount: u64)` to the client crate in this task since these tests need it — the rest of the client is Task 5). `cargo build --workspace` still fails only in `shrugg-client` binaries; that is Task 5.

- [ ] **Step 6: Commit**

```bash
git add crates/shrugg-node crates/shrugg-client/src/lib.rs
git commit -m "node: notes/nullifiers/anchors/validators storage, nullifier-conflict mempool, validator-signed faucet mints, redacted RPC with commitments/nullifiers/anchors/witness methods"
```

---

### Task 5: The shielded wallet (`shrugg`)

**Files:**
- Modify: `crates/shrugg-client/src/lib.rs` (`RpcClient`)
- Create: `crates/shrugg-client/src/wallet.rs`
- Modify: `crates/shrugg-client/src/main.rs`
- Test: unit tests in `wallet.rs` (key file, note store, coin selection) and `crates/shrugg-client/tests/wallet_flow.rs` (one node, mint → scan → send → scan; proves a real bundle)

**Interfaces:**
- Consumes: Task 2's `address_of`, `seal_note`, `prove_bundle`, `envelope_from_core`; vendored `notes::{SpendKey, ViewingKey, Note, bundle_inputs, expected_bundle_outputs}`, `viewing::{Envelope, TxKey}`; Task 4's RPC.
- Produces:

```rust
// lib.rs additions
impl RpcClient {
    pub async fn commitments(&self, from: u64, limit: usize) -> Result<Vec<CommitmentRow>>;   // CommitmentRow { index, cm: Word8, envelope: Envelope, height }
    pub async fn nullifiers(&self, from_height: u64, limit: usize) -> Result<Vec<(u64, Word8)>>;
    pub async fn anchor(&self, height: Option<u64>) -> Result<(u64, Word8)>;
    pub async fn witness(&self, index: u64) -> Result<(Word8, [Word8; DEPTH])>;
    pub async fn tree_info(&self) -> Result<TreeInfo>;   // { next_index, root, nullifiers }
    pub async fn mint_shielded(&self, address: &str, amount: u64) -> Result<Hash>;
    pub async fn send_transaction(&self, tx: &Transaction) -> Result<Hash>;
    pub async fn wait_for_transaction(&self, hash: &Hash, timeout: Duration) -> Result<TxReceipt>;
    // removed: account, balance, transfer, mint, bridge_*
}
// wallet.rs
pub struct KeyFile { pub version: u32 /* 2 */, pub spend_key: String /* hex 32 bytes */ }
pub struct Wallet { pub sk: SpendKey, pub vk: ViewingKey, pub address: ShieldedAddress }
impl Wallet { pub fn generate() -> Wallet; pub fn load(path) -> Result<Wallet>; pub fn save_new(&self, path) -> Result<()>; }
pub struct OwnedNote { pub index: u64, pub note: Note /* vendored */, pub cm: Word8, pub nf: Word8, pub spent: bool, pub height: u64 }
pub struct NoteStore { pub scanned_index: u64, pub scanned_height: u64, pub notes: Vec<OwnedNote>, pub sent: Vec<SentRow> }   // JSON at <key>.notes.json
impl NoteStore { pub fn load(path) -> NoteStore; pub fn save(&self, path) -> Result<()>; pub fn balance(&self) -> u64; pub fn spendable(&self) -> Vec<&OwnedNote>; }
pub async fn scan(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore) -> Result<()>;
pub fn select_inputs(spendable: &[&OwnedNote], need: u64) -> Result<Vec<OwnedNote>, SelectError>;  // largest-first, at most 2; SelectError::NeedsMoreThanTwo { largest_two: u64 } | Insufficient { have }
pub async fn send(rpc: &RpcClient, w: &Wallet, store: &mut NoteStore, to: &ShieldedAddress, amount: u64, fee: u64, profile: FriProfile, backend: Backend, chain_id: u64) -> Result<Hash>;
```

- [ ] **Step 1: Wallet unit tests first**

```rust
#[test] fn key_file_v2_roundtrips_and_refuses_overwrite()
#[test] fn address_is_derived_from_the_spend_key()          // two loads give the same address; different keys differ
#[test] fn note_store_balance_ignores_spent_and_zero_notes()
#[test] fn select_inputs_takes_the_largest_two_or_fails_clearly()
    // notes [5, 3, 2], need 7 → [5, 3]; need 9 → NeedsMoreThanTwo { largest_two: 8 }; need 11 → Insufficient { have: 10 }; need 4 → [5]
```

- [ ] **Step 2: Implement `wallet.rs`**

`scan`: page `rpc.commitments(store.scanned_index, 500)` until empty; for each row, `Envelope::open_as_receiver(cm, &w.vk)` → own note (push `OwnedNote` with `nf = w.vk.nullifier(&cm)`); else `open_as_sender(cm, &w.vk)` → `SentRow { index, to_pk, amount, height }` (history only); advance `scanned_index`. Then page `rpc.nullifiers(store.scanned_height, 500)` and mark any own `nf` as spent; advance `scanned_height` to the head. Save.

`send`: `scan` first; `need = amount + fee`; `select_inputs`; `(height, root) = rpc.anchor(None)`; witnesses `rpc.witness(i.index)` for each real input, retrying (up to 3 times) if a witness's root differs from `root`; dummy input for a missing second input: `(Note::new([0; 8], [0; 8], 0, 0, time), [[0; 8]; DEPTH], 0)` with `time = height as u32`; outputs `out1 = Note::new(to.pk, w.vk.pk(), amount, 0, time)`, `out2 = Note::new(w.vk.pk(), w.vk.pk(), change, 0, time)`; `inputs = bundle_inputs(&w.sk, &[in1, in2], &[out1, out2], root, fee, 0, 0, time)`; `prove_bundle(profile, &inputs, backend)`; assert the returned digest equals `expected_bundle_outputs(..)` (a wallet-side sanity check; mismatch is a bug, not a chain error); envelopes `seal_note(&w.vk, to, &out1, &TxKey::random())` and `seal_note(&w.vk, &w.address, &out2, &TxKey::random())`; `Bundle { anchor: root, nullifiers: [nf1, nf2], commitments: [out1.commitment(), out2.commitment()], fee, burn: 0, asset: 0, time, envelopes, proof }`; `Transaction::shielded(chain_id, bundle, Action::None)`; `rpc.send_transaction`; `wait_for_transaction(hash, 180 s)`; on success mark the inputs spent in the store (the change note is picked up by the next scan). Proving with `FriProfile::Production` at tier 14 takes on the order of a minute on a laptop: print "proving (tier 14, this takes about a minute)…" before and the elapsed time after.

- [ ] **Step 3: `main.rs` commands**

`keygen`, `address`, `balance` (scan + print `balance:`, `notes: <n> unspent`), `sync`, `notes` (table: index, amount, height, spent), `history` (sent rows), `send <to> <amount> [--fee] [--no-wait]`, `faucet [address] [--amount]` (calls `mint_shielded`; default this wallet's address), `program build|deploy|show` (deploy now builds a bundle paying `fee_floor(Deploy)` from this wallet: reuse `send` machinery with `amount = 0` to self and `action = Deploy`), `call` (same, `action = Call`; its `--fee` default is `fee_floor(Call) + call_fee(tier)`), `receipt`, `fee` (`fee bundle` | `fee deploy <words>` | `fee call <tier>`), `tx`, `block`, `head`, `status`, `peers`, `validators`. Generalize `wallet::send` into `wallet::submit(.., amount_to: Option<(&ShieldedAddress, u64)>, action: Action)` so Deploy/Call reuse it.

- [ ] **Step 4: Integration test**

`crates/shrugg-client/tests/wallet_flow.rs`: start one validator node in-process (as `cluster.rs` does; `fri_profile: "test"`, faucet on), wallet A and B from `SpendKey([1; 8])`/`SpendKey([2; 8])`; `mint_shielded(A, 100 SHRUGG)`; `scan` → A balance 100 SHRUGG, one note; `send(A → B, 1 SHRUGG, BUNDLE_BASE)`; `scan` both → B has 1 SHRUGG, A has `100 - 1 - 0.001` SHRUGG in one change note, the spent note marked spent; a second `send` from A works (the change note is spendable). About 2 minutes.

- [ ] **Step 5: Gate**

Run: `cargo test -p shrugg-client 2>&1 | grep -E 'test result|FAILED'` → green; `cargo build --workspace` → green.

- [ ] **Step 6: Commit**

```bash
git add crates/shrugg-client
git commit -m "client: shielded wallet — spend-key file v2, envelope scanning, largest-first coin selection, bundle proving and send; deploy/call ride on bundles"
```

---

### Task 6: Cluster end-to-end, docs and deploy notes

**Files:**
- Rewrite: `crates/shrugg-node/tests/cluster.rs` (helpers + the tests deleted in Task 4)
- Create: `docs/shielded.md`
- Modify: `docs/rpc.md`, `docs/architecture.md`, `docs/cli.md`, `docs/confidential.md`, `docs/bridge.md` (banner), `deploy/README.md`, `README.md`
- Modify: `deploy/genesis.json` is NOT regenerated here (the fleet operator cuts the shielded chain); add `deploy/genesis-shielded.example.json` produced by `shrugg-node genesis` with the four validator keys and one alloc note per test wallet, and document the command.

- [ ] **Step 1: Cluster helpers and tests**

Helpers: `wallet(i) -> Wallet` from `SpendKey([i; 8])`; `genesis(validators, funded: &[&Wallet])` with one 1,000 SHRUGG alloc note per funded wallet (built exactly as `shrugg-node genesis` does) and `hc_bundle` from the executor; `balance(node, wallet) -> u64` = a fresh `NoteStore` scanned against that node's RPC. Tests:

- `two_validators_commit_and_shielded_transfer`: genesis funds A; A sends 1 SHRUGG to B; every node reports B's balance 1 SHRUGG and A's `999 - 0.001`; a replay of the same transaction is rejected (`send_transaction` error contains "spent").
- `faucet_mint_via_rpc_reaches_every_node`: validator mints to C; C's balance is 100 SHRUGG on every node; an observer's `mint_shielded` errors; an over-cap mint errors.
- `faucet_is_rejected_when_genesis_disables_it`.
- `confidential_call_rides_on_a_bundle`: A deploys `private_payment` via a bundle, then calls it via a bundle; receipt visible on every node; A's balance dropped by exactly the two fee floors.
- `two_bundles_spending_one_note_only_one_commits`: submit two conflicting bundles (same input note, different outputs) to two different validators simultaneously; exactly one commits, the other is rejected or pruned, and every node agrees on the state root.
- keep the six structural tests from Task 4.

Run: `cargo test -p shrugg-node --test cluster -- --test-threads=1 2>&1 | grep -E 'test result|FAILED'` → green (expect 10–15 minutes; record the time).

- [ ] **Step 2: Docs**

`docs/shielded.md` (new, the user guide): keys and addresses, what is on chain, `shrugg keygen/address/faucet/balance/send`, what the node sees, the admission order, the RPC methods with one example each, privacy notes (what the node learns from witness requests; what an explorer can and cannot show), and the S2/S3 roadmap. `docs/rpc.md`: replace the removed methods and the "Building a transaction without the wallet" section with the `Transaction { chain_id, bundle, action }` layout and bincode sizes. `docs/architecture.md`: the ledger section, column families, state root formula. `docs/cli.md`: commands. `docs/confidential.md`: calls pay through a bundle; effect kind 1 removed. `docs/bridge.md`: a top banner "not wired on the shielded chain until phase S3". `deploy/README.md`: how to cut a shielded genesis, and that the fleet's chain is unchanged until the operator forks.

- [ ] **Step 3: Final gate and commit**

Run: `cargo test --workspace 2>&1 | grep -E 'test result|FAILED'` → every binary green.

```bash
git add crates/shrugg-node/tests/cluster.rs docs deploy/README.md deploy/genesis-shielded.example.json README.md
git commit -m "node: shielded cluster end-to-end; docs: shielded pool user guide, RPC/CLI/architecture updates, bridge parked until S3"
```

## Self-review

**Spec coverage.** §3 transaction shape → Task 1 `Bundle`, Task 3 `Transaction`/`Action` (with the `Option<Bundle>` ruling for Mint). §4 relation → vendored guest (Task 2), digest recompute and `hc_bundle` pin (Task 3). §5 notes/keys/addresses → vendored `notes.rs`, `ShieldedAddress` (Task 1), wallet keys (Task 5). §6 actions → None/Mint/Deploy/Call (Task 3); Bond/Unbond/Withdraw S2; bridge S3; §6.1 S3. §7 admission order → `validate_inner` (Task 3), mempool (Task 4). §8 register → `ValidatorEntry` with rewards (Task 3); epochs/unbonding S2. §9 state/storage/root → Task 3 `state_root`, Task 4 column families and frontier in `meta`, `--verify-chain` replay. §10 bridge → parked with a banner (Task 6). §11 RPC → Task 4 (five new methods, redaction), wallet scanning (Task 5). §12 S1 row: notes ledger ✓, Bundle ✓, admission ✓, storage ✓, state root ✓, deposits via Mint ✓, wallet ✓, RPC redaction ✓, genesis with deposit notes ✓, replay ✓. §13 rulings honored: 2-in-2-out fixed shape, u64 amounts, public fee to proposer rewards, deposits with public amount, windows 64/64, kind 1 deleted, ML-KEM addresses, no slashing, nullifier root recomputed per block, `hc_bundle` pinned.

**Placeholder scan.** Tasks 4–6 describe RPC handlers, storage writes and CLI commands by exact method tables, key layouts and JSON shapes rather than full bodies; every test is named with its assertions; no "TBD"/"appropriate"/"similar to". The one deliberately unstated value is the pinned genesis hash in Task 4 Step 4, which is produced by the first run and then pinned, as the existing test does.

**Type consistency.** `Word8`, `Envelope`, `Bundle`, `BundleDigestInput`, `ShieldedAddress`, `CommitmentTree`, `FullTree` are defined in Task 1 and used by name in Tasks 2–6; `ConfidentialExecutor::{node_hash, bundle_digest, bundle_proof_digest, verify_bundle, warm_bundle}` are defined in Task 1, implemented in Task 2, called in Task 3; `Transaction::{shielded, mint, mint_signing_hash, fee, nullifiers, commitments, hash, encode, decode}` defined in Task 3, used in Tasks 4–6; `Ledger::{new, from_parts, validate, apply_tx, apply_transactions, apply_block, state_root, deposit, record_anchor, is_anchor, is_spent, has_commitment, commitments_set, tree, root, next_index, anchors, validators, programs}` defined in Task 3, used in Task 4; `Storage::{note, notes_from, notes_count, nullifier_height, anchor, tree, hc_bundle, validator, witness, load_ledger, commit, init_genesis, truncate_to}` defined in Task 4, used by the RPC in Task 4 and tests in Task 6; `RpcClient::{commitments, nullifiers, anchor, witness, tree_info, mint_shielded, send_transaction, wait_for_transaction}` defined in Tasks 4–5, used in Tasks 5–6; `prove_bundle`, `address_of`, `seal_note`, `envelope_from_core`, `digest_input_of` defined in Task 2, used in Tasks 4–5.

## For the user — what this plan decides that the spec did not

1. Deploy/Call are in S1 (spec: S3). The testnet keeps confidential calls.
2. The faucet is a bundle-less, validator-signed transaction. Deposits are trusted for their note content, per the spec's §6 table; before S2's Withdraw this needs either a deposit proof (a tiny zkVM guest) or the note plaintext on chain — decide then.
3. The wallet asks the node for Merkle witnesses (privacy leak: which leaf indices it spends). A local wallet tree is the first follow-up.
4. The research crate's 64-bit spend key is widened to 256 bits first (separate one-task plan in `circuits/`).
