# Short Shielded Addresses Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 1,667-character shielded address with a 54-character receiver id that resolves, through a payment request or the explorer's registry, to a receiver-signed record holding the note key and the current ML-KEM-768 key.

**Architecture:** A new `ReceiverId` (blake3 of a Dilithium2 signing key derived from the wallet's spend key) is the address; a versioned, signed `ReceiverRecord` carries `pk` and `kem_ek`; the ledger keeps a `receivers` registry in consensus state (published by `Action::RegisterReceiver`, standalone or riding on a sender's transfer), payouts and the bridge recipient store the id and resolve `pk` from the registry; the wallet resolves records from a payment request or the explorer and verifies them the same way; the explorer indexes and serves the registry. Ships as chain 11.

**Tech Stack:** Rust (the five `randprotocol-*` crates), `ml-kem =0.3.2` (the vendored zkVM viewing module, upstream in `circuits/research`), Dilithium2 via the crate's `Keypair`, the explorer's Rust API + Postgres + Next.js frontend.

**Spec:** `docs/superpowers/specs/2026-09-17-short-shielded-address.md` (approved 2026-09-17). Every commit for this feature carries the line `Design: Anish Mohammad (https://github.com/zeroknowledge)`.

## Global Constraints

1. **Chain 11 fork semantics.** The address text form, register state (`payout` fields), the state root (`rand-state-4`, a `receivers_root` component) and the bridge wire meaning of `to` all change. No genesis gate: a chain-10 node and a chain-11 node never share a chain. Old `Action` tags are never renumbered; `RegisterReceiver` is a new tag.
2. **Proofs are untouched.** Notes, commitments, nullifiers, envelopes, the bundle guest and the aggregate program are byte-identical. `Envelope` is still sealed to a `kem_ek`; only where the sender finds the key changes.
3. **One verifier.** `ReceiverRecord::verify(id, chain_id)` in `randprotocol-core` is the only verification code: the wallet, the ledger and the explorer call it. Two checks, in this order: `blake3(signing_key) == id`, then the Dilithium2 signature over `blake3("rand-receiver-record-1" ‖ chain_id ‖ version ‖ pk ‖ kem_ek)`.
4. **Sizes.** `MAX_RECORD_BYTES = 8192` (a record is ~4,980 bytes). The address is exactly 36 raw bytes (32 id + 4 checksum) under `rand1` + base58.
5. **The vendored zkVM rule (AGENTS.md).** The versioned KEM derivation is a change to `viewing.rs`, which is vendored from `circuits/research`: it lands upstream first and arrives here through `deploy/sync-zkvm.sh`, never as a local edit.
6. **Commit style.** `core: …`, `node: …`, `client: …`, `zkvm: …`, `docs: …`, `deploy: …`; per-task TDD; all green before each commit; the design credit line in every commit body; no push until Task 10 says so.

## Rulings made in this plan (the spec leaves these open or the code forces them; the user can overturn any)

- **R1. Retired KEM keys are re-derived, not stored.** The wallet's KEM keypair is a pure function of the spend key (`vk.kem_seed()` → `MlKem768::from_seed`), so "keep every retired key" becomes "keep the current version number": key version `v` derives from `blake3("rand-kem-version" ‖ kem_seed ‖ v)` with **version 0 = today's unversioned key** (so existing wallets and envelopes are unaffected). Opening tries versions `current..=0`. Nothing is ever lost; the wallet file gains one integer.
- **R2. Sender-paid registration needs no note-to-pk proof.** The spec §6.3 tie ("the bundle must create a note for the record's pk") cannot be checked without opening the note. It is also unnecessary: a record is authorisation by construction (the receiver signed it), and the version rule (`version == current + 1`, or 1 when absent) refuses replay and downgrade. Any transaction may carry a valid record; the payer only pays the fee.
- **R3. A validator/aggregator registration must name an id the registry already holds** (or the same transaction carries its `RegisterReceiver`). Genesis validators and the genesis notes' owners bring their records in the genesis file (`receivers` section).
- **R4. `ShieldedAddress` stays the in-memory pair `{pk, kem_ek}`** the sealing code takes; it loses its text form. The user-facing type is `ReceiverId`; a resolved record yields a `ShieldedAddress` for sealing.

## File structure

- `crates/randprotocol-core/src/receiver.rs` (new): `ReceiverId`, `ReceiverRecord`, `RecordError`, `receiver_signing_keypair`, the address text form. One responsibility: the identity and its record, with the verifier.
- `crates/randprotocol-core/src/notes.rs`: `ShieldedAddress` loses `to_string`/`parse`/`recipient_hash`; gains `From<&ReceiverRecord>`.
- `crates/randprotocol-core/src/types/actions.rs`: `Action::RegisterReceiver { record }`; `Registration.payout`, `AggregatorRegistration.payout` become `ReceiverId`; `registration_message`/`aggregator_register_message` over the id.
- `crates/randprotocol-core/src/ledger/receivers.rs` (new): the registry (`BTreeMap<ReceiverId, ReceiverRecord>`), `receivers_root`, validate/apply of `RegisterReceiver`, `resolve_pk`.
- `crates/randprotocol-core/src/ledger/mod.rs`: the field, the state root (`rand-state-4`), the size cap at step 1, the arm at step 7 and in `apply_tx`, the debug components.
- `crates/randprotocol-core/src/ledger/staking.rs`, `aggregation.rs`, `bridge_notes.rs`: `payout`/`recipient` as `ReceiverId`, `pk` resolved from the registry.
- `crates/randprotocol-core/src/genesis.rs`: `receivers: Vec<ReceiverRecordHex>`, validators' `payout` as an address string of the short form, alloc owners resolved from `receivers`.
- `circuits/research/src/viewing.rs` (upstream) then `crates/randprotocol-zkvm/src/viewing.rs` (vendored): `kem_seed_at`, `address_at`, `open_as_receiver_at`.
- `crates/randprotocol-node/src/storage.rs`: `META_RECEIVERS`; `rpc.rs`: `rand_getReceiver`, the `register_receiver` action JSON; `main.rs`: `genesis --receiver`.
- `crates/randprotocol-client/src/receiver.rs` (new): resolution (record file, registry URL), the payment-request URI; `wallet.rs`: signing keypair, `kem_version`, versioned opening; `main.rs`: `address`, `request`, `register`, `send --record/--registry`, the bridge refusal.
- randscan: `migrations/008_receivers.sql`, `crates/randscan-db/src/queries/receivers.rs`, `crates/randscan-indexer/src/rpc.rs` + `processor.rs`, `crates/randscan-api/src/handlers/receivers.rs` + `routes.rs`, `docs/api.md`.
- `deploy/cut-chain11-genesis.sh`, `deploy/README.md`, `docs/shielded.md`, `docs/staking.md`, `docs/bridge.md`, `docs/rpc.md`.

---

### Task 1: The receiver id, the address text form, the record and its verifier

**Files:**
- Create: `crates/randprotocol-core/src/receiver.rs`
- Modify: `crates/randprotocol-core/src/lib.rs` (add `pub mod receiver; pub use receiver::{ReceiverId, ReceiverRecord};`)
- Test: inline `#[cfg(test)]` in `receiver.rs`

**Interfaces:**
- Produces: `ReceiverId(pub [u8; 32])` with `Display` (`rand1…`, 54 chars), `FromStr`/`parse`, `as_bytes`, `From<&PublicKey>`, `From<Address>`; `ReceiverRecord { version: u32, pk: Word8, kem_ek: Vec<u8>, signing_key: PublicKey, signature: Signature }` with `sign(kp, chain_id, version, pk, kem_ek) -> ReceiverRecord`, `id(&self) -> ReceiverId`, `verify(&self, id: &ReceiverId, chain_id: u64) -> Result<(), RecordError>`, `signing_hash(chain_id, version, pk, kem_ek) -> Hash`, `encoded_len()`; `receiver_signing_keypair(spend_key: &[u8; 32]) -> Keypair`; `MAX_RECORD_BYTES: usize = 8192`; `RecordError { WrongId, BadSignature, KemLength(usize), TooLarge(usize) }`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::notes::KEM_EK_BYTES;

    fn kp() -> Keypair { receiver_signing_keypair(&[7u8; 32]) }

    #[test]
    fn the_signing_key_derives_from_the_spend_key_and_the_id_is_its_address() {
        let a = receiver_signing_keypair(&[7u8; 32]);
        let b = receiver_signing_keypair(&[7u8; 32]);
        assert_eq!(a.public_key(), b.public_key(), "deterministic");
        assert_ne!(receiver_signing_keypair(&[8u8; 32]).public_key(), a.public_key());
        let id = ReceiverId::from(a.public_key());
        assert_eq!(id.0, a.address().0, "the receiver id is the transparent address of the signing key");
    }

    #[test]
    fn the_address_is_54_chars_and_round_trips() {
        let id = ReceiverId::from(kp().public_key());
        let s = id.to_string();
        assert!(s.starts_with("rand1"));
        assert_eq!(s.len(), 54, "{s}");
        assert_eq!(s.parse::<ReceiverId>().unwrap(), id);
    }

    #[test]
    fn the_address_refuses_a_bad_checksum_a_bad_prefix_and_the_long_form() {
        let id = ReceiverId::from(kp().public_key());
        let mut s = id.to_string();
        let last = s.pop().unwrap();
        s.push(if last == '1' { '2' } else { '1' });
        assert!(matches!(s.parse::<ReceiverId>(), Err(RecordError::Checksum)));
        assert!(matches!("xand1abc".parse::<ReceiverId>(), Err(RecordError::Prefix)));
        let long = format!("rand1{}", bs58::encode(vec![1u8; 32 + KEM_EK_BYTES]).into_string());
        assert!(matches!(long.parse::<ReceiverId>(), Err(RecordError::LongForm)));
    }

    #[test]
    fn a_record_verifies_and_every_tampering_is_refused() {
        let k = kp();
        let id = ReceiverId::from(k.public_key());
        let rec = ReceiverRecord::sign(&k, 11, 1, [3; 8], vec![9; KEM_EK_BYTES]);
        assert_eq!(rec.id(), id);
        rec.verify(&id, 11).unwrap();
        assert!(matches!(rec.verify(&ReceiverId([0; 32]), 11), Err(RecordError::WrongId)));
        assert!(matches!(rec.verify(&id, 12), Err(RecordError::BadSignature)), "chain id is in the hash");
        let mut t = rec.clone(); t.version = 2;
        assert!(matches!(t.verify(&id, 11), Err(RecordError::BadSignature)));
        let mut t = rec.clone(); t.pk[0] ^= 1;
        assert!(matches!(t.verify(&id, 11), Err(RecordError::BadSignature)));
        let mut t = rec.clone(); t.kem_ek[5] ^= 1;
        assert!(matches!(t.verify(&id, 11), Err(RecordError::BadSignature)));
        let mut t = rec.clone(); t.kem_ek.truncate(100);
        assert!(matches!(t.verify(&id, 11), Err(RecordError::KemLength(100))));
        let other = receiver_signing_keypair(&[8u8; 32]);
        let mut t = rec.clone(); t.signing_key = other.public_key().clone();
        assert!(matches!(t.verify(&id, 11), Err(RecordError::WrongId)));
        assert!(rec.encoded_len() < MAX_RECORD_BYTES, "{}", rec.encoded_len());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release -p randprotocol-core --lib receiver::`
Expected: compile error, `receiver` module not found.

- [ ] **Step 3: Write the module**

```rust
//! The receiver id (the short shielded address) and the receiver record (spec
//! docs/superpowers/specs/2026-09-17-short-shielded-address.md §1–§3).
use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::notes::{word8_to_bytes, Word8, KEM_EK_BYTES};
use serde::{Deserialize, Serialize};

pub const ADDRESS_PREFIX: &str = "rand1";
pub const MAX_RECORD_BYTES: usize = 8192;
const CHECKSUM_LEN: usize = 4;

/// blake3 of the receiver's Dilithium2 signing key: the shielded address, 32 bytes, the same
/// bytes as the transparent `Address` of that key (spec §1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReceiverId(pub [u8; 32]);

impl ReceiverId {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    fn checksum(&self) -> [u8; CHECKSUM_LEN] {
        let h = Hash::digest_domain(b"rand-receiver-addr-1", &self.0);
        h.0[..CHECKSUM_LEN].try_into().unwrap()
    }
    pub fn parse(s: &str) -> Result<ReceiverId, RecordError> {
        let rest = s.strip_prefix(ADDRESS_PREFIX).ok_or(RecordError::Prefix)?;
        let raw = bs58::decode(rest).into_vec().map_err(|_| RecordError::Base58)?;
        if raw.len() == 32 + KEM_EK_BYTES { return Err(RecordError::LongForm); }
        if raw.len() != 32 + CHECKSUM_LEN { return Err(RecordError::Length(raw.len())); }
        let id = ReceiverId(raw[..32].try_into().unwrap());
        if raw[32..] != id.checksum() { return Err(RecordError::Checksum); }
        Ok(id)
    }
}
impl From<&PublicKey> for ReceiverId { fn from(pk: &PublicKey) -> Self { ReceiverId(pk.address().0) } }
impl From<Address> for ReceiverId { fn from(a: Address) -> Self { ReceiverId(a.0) } }
impl std::fmt::Display for ReceiverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut raw = self.0.to_vec();
        raw.extend_from_slice(&self.checksum());
        write!(f, "{ADDRESS_PREFIX}{}", bs58::encode(raw).into_string())
    }
}
impl std::fmt::Debug for ReceiverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self}") }
}
impl std::str::FromStr for ReceiverId {
    type Err = RecordError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { ReceiverId::parse(s) }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum RecordError {
    #[error("shielded address must start with {ADDRESS_PREFIX}")] Prefix,
    #[error("shielded address is not base58")] Base58,
    #[error("this is the pre-chain-11 long address form (pk + KEM key); chain 11 addresses are 54 characters — ask the receiver for their current address")] LongForm,
    #[error("shielded address decodes to {0} bytes, expected 36")] Length(usize),
    #[error("shielded address checksum mismatch")] Checksum,
    #[error("the record's signing key is not the address's")] WrongId,
    #[error("the record's signature does not verify")] BadSignature,
    #[error("the record's KEM key is {0} bytes, expected {KEM_EK_BYTES}")] KemLength(usize),
    #[error("the record is {0} bytes, over the {MAX_RECORD_BYTES}-byte cap")] TooLarge(usize),
}

/// The signed, versioned record a receiver id resolves to (spec §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverRecord {
    pub version: u32,
    pub pk: Word8,
    pub kem_ek: Vec<u8>,
    pub signing_key: PublicKey,
    pub signature: Signature,
}

impl ReceiverRecord {
    pub fn signing_hash(chain_id: u64, version: u32, pk: &Word8, kem_ek: &[u8]) -> Hash {
        let mut buf = Vec::with_capacity(8 + 4 + 32 + kem_ek.len());
        buf.extend_from_slice(&chain_id.to_be_bytes());
        buf.extend_from_slice(&version.to_be_bytes());
        buf.extend_from_slice(&word8_to_bytes(pk));
        buf.extend_from_slice(kem_ek);
        Hash::digest_domain(b"rand-receiver-record-1", &buf)
    }
    pub fn sign(kp: &Keypair, chain_id: u64, version: u32, pk: Word8, kem_ek: Vec<u8>) -> ReceiverRecord {
        let signature = kp.sign(Self::signing_hash(chain_id, version, &pk, &kem_ek).as_bytes());
        ReceiverRecord { version, pk, kem_ek, signing_key: kp.public_key().clone(), signature }
    }
    pub fn id(&self) -> ReceiverId { ReceiverId::from(&self.signing_key) }
    pub fn encoded_len(&self) -> usize { bincode::serialize(self).expect("serializes").len() }
    /// The one verifier (spec §3): the id, then the signature. Cheap checks first.
    pub fn verify(&self, id: &ReceiverId, chain_id: u64) -> Result<(), RecordError> {
        if self.kem_ek.len() != KEM_EK_BYTES { return Err(RecordError::KemLength(self.kem_ek.len())); }
        let len = self.encoded_len();
        if len > MAX_RECORD_BYTES { return Err(RecordError::TooLarge(len)); }
        if self.id() != *id { return Err(RecordError::WrongId); }
        let h = Self::signing_hash(chain_id, self.version, &self.pk, &self.kem_ek);
        if !self.signing_key.verify(h.as_bytes(), &self.signature) { return Err(RecordError::BadSignature); }
        Ok(())
    }
}

/// The receiver signing key, derived from the wallet's spend key (spec §1): nothing new to
/// back up, and the key that makes the id equal the wallet's transparent address.
pub fn receiver_signing_keypair(spend_key: &[u8; 32]) -> Keypair {
    let seed = Hash::digest_domain(b"rand-receiver-sign-1", spend_key);
    Keypair::from_seed(seed.0).expect("a 32-byte seed is valid")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --release -p randprotocol-core --lib receiver::`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-core/src/receiver.rs crates/randprotocol-core/src/lib.rs
git commit -m "core: the receiver id (the 54-char rand1 address) and the signed receiver record with its one verifier

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 2: Versioned KEM keys in the viewing module (upstream, then re-vendored)

**Files:**
- Modify (upstream): `../circuits/research/src/viewing.rs` (the `ViewingKey` impl and `Envelope::open_as_receiver`)
- Then run `deploy/sync-zkvm.sh` so `crates/randprotocol-zkvm/src/viewing.rs` carries the change
- Test: `../circuits/research/tests/viewing.rs` (upstream), `crates/randprotocol-zkvm/src/viewing.rs` inline tests after sync

**Interfaces:**
- Produces (on `ViewingKey`): `kem_seed_at(&self, version: u32) -> [u8; 64]` (version 0 == `kem_seed()`), `kem_keys_at(&self, version: u32) -> (Dk, Ek)`, `address_at(&self, version: u32) -> Address`; (on `Envelope`): `open_as_receiver_at(&self, cm: Word8, vk: &ViewingKey, version: u32) -> Option<(TxKey, Note)>`; `open_as_receiver` stays and equals `open_as_receiver_at(.., 0)`.

- [ ] **Step 1: Write the failing test (upstream)**

```rust
#[test]
fn kem_key_versions_differ_and_version_zero_is_the_unversioned_key() {
    let vk = SpendKey([5; 8]).viewing_key();
    assert_eq!(vk.address_at(0), vk.address(), "version 0 is today's key: old wallets and envelopes are unaffected");
    assert_ne!(vk.address_at(1).kem_ek, vk.address().kem_ek);
    assert_eq!(vk.address_at(1).pk, vk.address().pk, "pk never changes with the KEM version");
    let sender = SpendKey([6; 8]).viewing_key();
    let note = Note::new(vk.pk(), [0; 8], 50, 0, 3);
    let env = Envelope::seal(&sender, &vk.address_at(1), &note, &TxKey::random());
    assert!(env.open_as_receiver(note.commitment(), &vk).is_none(), "the version-0 key cannot open a version-1 envelope");
    let (_, opened) = env.open_as_receiver_at(note.commitment(), &vk, 1).expect("the version-1 key opens it");
    assert_eq!(opened, note);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run (in `../circuits/research`): `cargo test --release --test viewing kem_key_versions`
Expected: compile error, no method `address_at`.

- [ ] **Step 3: Implement upstream**

In `ViewingKey`:
```rust
    /// The KEM seed for key version `v` (fullnode spec 2026-09-17 §7, ruling R1): version 0 is
    /// the unversioned seed, so nothing already sealed changes meaning; every later version is
    /// domain-separated from it and re-derivable forever.
    pub fn kem_seed_at(&self, version: u32) -> [u8; 64] {
        if version == 0 { return self.kem_seed(); }
        let base = self.kem_seed();
        let mut h = blake3::Hasher::new_derive_key("rand-kem-version");
        h.update(&base);
        h.update(&version.to_be_bytes());
        let mut out = [0u8; 64];
        h.finalize_xof().fill(&mut out);
        out
    }
    pub fn kem_keys_at(&self, version: u32) -> (Dk, Ek) { MlKem768::from_seed(&ml_kem::Seed::from(self.kem_seed_at(version))) }
    pub fn address_at(&self, version: u32) -> Address {
        let (_, ek) = self.kem_keys_at(version);
        Address { pk: self.pk(), kem_ek: ek.as_bytes().to_vec() }
    }
```
Refactor `kem_keys` to `self.kem_keys_at(0)` and `address` to `self.address_at(0)`. In `Envelope`, add `open_as_receiver_at(&self, cm, vk, version)` by extracting the body of `open_as_receiver` into it with `let (dk, _) = vk.kem_keys_at(version);` and make `open_as_receiver` call it with `0`. (Use the same blake3 the crate already depends on; if `new_derive_key` is unavailable at the pinned version, `blake3::Hasher::new()` over `b"rand-kem-version" ‖ base ‖ version` with `finalize_xof` is equivalent for this purpose.)

- [ ] **Step 4: Run upstream tests, then re-vendor**

Run: `cargo test --release --test viewing` (upstream) — Expected: all pass, including the new one.
Then in the fullnode repo: `bash deploy/sync-zkvm.sh` (follow its header: it rsyncs `viewing.rs` and applies the domain-tag inlining), then `cargo test --release -p randprotocol-zkvm --lib viewing` — Expected: pass; `git diff --stat` shows only `crates/randprotocol-zkvm/src/viewing.rs` (and the sync's usual pins).

- [ ] **Step 5: Commit (both repos)**

```bash
# circuits/research
git commit -am "viewing: versioned KEM keys — kem_seed_at/address_at/open_as_receiver_at, version 0 is the unversioned key

Design: Anish Mohammad (https://github.com/zeroknowledge)"
# fullnode
git add crates/randprotocol-zkvm/src/viewing.rs deploy/sync-zkvm.sh
git commit -m "zkvm: re-vendor viewing.rs with the versioned KEM keys (research <commit>)

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 3: The registry in ledger state, `Action::RegisterReceiver`, the state root

**Files:**
- Create: `crates/randprotocol-core/src/ledger/receivers.rs`
- Modify: `crates/randprotocol-core/src/ledger/mod.rs` (field `receivers`, `set_receivers`/`receivers()`, `state_root` → `rand-state-4` with `receivers_root`, `debug_state_root_components`, step 1 size cap, step 7 arm, `apply_tx` arm), `crates/randprotocol-core/src/types/actions.rs` (the variant, bundle-carrying), `crates/randprotocol-core/src/ledger/mod.rs` `TxError` (a `Receiver(RecordError)` variant and `ReceiverVersion { expected, actual }`, `ReceiverPkChanged`)
- Test: inline `#[cfg(test)] mod tests` in `receivers.rs`

**Interfaces:**
- Consumes: Task 1's `ReceiverId`, `ReceiverRecord`, `RecordError`, `MAX_RECORD_BYTES`.
- Produces: `Ledger::receivers(&self) -> &BTreeMap<ReceiverId, ReceiverRecord>`, `Ledger::set_receivers(&mut self, BTreeMap<..>)`, `Ledger::resolve_pk(&self, id: &ReceiverId) -> Option<Word8>`, `Ledger::resolve_record(&self, id) -> Option<&ReceiverRecord>`, `receivers_root(&BTreeMap<ReceiverId, ReceiverRecord>) -> Hash`, `Ledger::validate_register_receiver(&self, record: &ReceiverRecord) -> Result<(), TxError>` (pub(crate)), `Action::RegisterReceiver { record: ReceiverRecord }` (bundle-carrying: not in `bundle_less`).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::notes::KEM_EK_BYTES;
    use crate::receiver::{receiver_signing_keypair, ReceiverId, ReceiverRecord};
    use crate::types::{Action, Transaction};

    fn ledger() -> Ledger {
        // The same fixture `ledger/mod.rs`'s tests build: chain 7, two validators, faucet on.
        crate::ledger::tests::fixtures::ledger_with_validators(7)
    }
    fn record(seed: u8, version: u32, chain: u64) -> (ReceiverRecord, ReceiverId) {
        let k = receiver_signing_keypair(&[seed; 32]);
        (ReceiverRecord::sign(&k, chain, version, [seed as u32; 8], vec![seed; KEM_EK_BYTES]), ReceiverId::from(k.public_key()))
    }
    fn tx_with(l: &Ledger, action: Action) -> Transaction {
        crate::ledger::tests::fixtures::bundle_tx(l, action)   // a valid stub bundle at the base fee
    }

    #[test]
    fn a_first_record_registers_and_the_state_root_moves() {
        let mut l = ledger();
        let before = l.state_root();
        let (rec, id) = record(1, 1, 7);
        let tx = tx_with(&l, Action::RegisterReceiver { record: rec.clone() });
        l.validate(&tx, &StubExecutor).unwrap();
        l.apply_tx(&tx, &crate::ledger::tests::fixtures::proposer(&l), &StubExecutor).unwrap();
        assert_eq!(l.receivers().get(&id), Some(&rec));
        assert_eq!(l.resolve_pk(&id), Some(rec.pk));
        assert_ne!(l.state_root(), before, "the registry is in the state root");
    }

    #[test]
    fn versions_must_step_by_one_and_pk_may_not_change() {
        let mut l = ledger();
        let (v1, id) = record(1, 1, 7);
        let p = crate::ledger::tests::fixtures::proposer(&l);
        l.apply_tx(&tx_with(&l, Action::RegisterReceiver { record: v1.clone() }), &p, &StubExecutor).unwrap();
        // replay of v1: refused
        match l.validate(&tx_with(&l, Action::RegisterReceiver { record: v1.clone() }), &StubExecutor) {
            Err(TxError::ReceiverVersion { expected: 2, actual: 1 }) => {}
            other => panic!("{other:?}"),
        }
        // v3 skips: refused
        let k = receiver_signing_keypair(&[1; 32]);
        let v3 = ReceiverRecord::sign(&k, 7, 3, v1.pk, vec![2; KEM_EK_BYTES]);
        assert!(matches!(l.validate(&tx_with(&l, Action::RegisterReceiver { record: v3 }), &StubExecutor), Err(TxError::ReceiverVersion { expected: 2, actual: 3 })));
        // v2 with a changed pk: refused
        let bad = ReceiverRecord::sign(&k, 7, 2, [9; 8], vec![2; KEM_EK_BYTES]);
        assert!(matches!(l.validate(&tx_with(&l, Action::RegisterReceiver { record: bad }), &StubExecutor), Err(TxError::ReceiverPkChanged)));
        // v2 rotation: applies, and the registry holds the new key
        let v2 = ReceiverRecord::sign(&k, 7, 2, v1.pk, vec![2; KEM_EK_BYTES]);
        l.apply_tx(&tx_with(&l, Action::RegisterReceiver { record: v2.clone() }), &p, &StubExecutor).unwrap();
        assert_eq!(l.receivers()[&id].kem_ek, vec![2; KEM_EK_BYTES]);
        // a first registration must be version 1
        let (v5, _) = record(2, 5, 7);
        assert!(matches!(l.validate(&tx_with(&l, Action::RegisterReceiver { record: v5 }), &StubExecutor), Err(TxError::ReceiverVersion { expected: 1, actual: 5 })));
    }

    #[test]
    fn a_record_for_another_chain_or_with_a_bad_signature_is_refused_by_name() {
        let l = ledger();
        let (other_chain, _) = record(1, 1, 8);
        assert!(matches!(l.validate(&tx_with(&l, Action::RegisterReceiver { record: other_chain }), &StubExecutor), Err(TxError::Receiver(RecordError::BadSignature))));
        let (mut rec, _) = record(1, 1, 7);
        rec.kem_ek = vec![1; 10];
        assert!(matches!(l.validate(&tx_with(&l, Action::RegisterReceiver { record: rec }), &StubExecutor), Err(TxError::Receiver(RecordError::KemLength(10)))));
    }

    #[test]
    fn the_root_is_a_merkle_over_id_version_pk_kem_leaves() {
        let (a, ida) = record(1, 1, 7);
        let (b, idb) = record(2, 1, 7);
        let m: BTreeMap<_, _> = [(ida, a.clone()), (idb, b.clone())].into_iter().collect();
        let leaf = |id: &ReceiverId, r: &ReceiverRecord| {
            let mut buf = id.0.to_vec();
            buf.extend_from_slice(&r.version.to_be_bytes());
            buf.extend_from_slice(&crate::notes::word8_to_bytes(&r.pk));
            buf.extend_from_slice(&r.kem_ek);
            crate::crypto::Hash::digest_domain(b"rand-receiver-leaf-1", &buf)
        };
        assert_eq!(receivers_root(&m), crate::crypto::merkle_root(&[leaf(&ida, &a), leaf(&idb, &b)]));
        assert_eq!(receivers_root(&BTreeMap::new()), crate::crypto::merkle_root(&[]));
    }
}
```
(If `ledger::tests::fixtures` does not exist under those names, use the same helpers `ledger/mod.rs`'s own tests use for a bundle transaction at the base fee and the proposer address; name them in the test as they are named there.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release -p randprotocol-core --lib ledger::receivers::`
Expected: compile errors — no variant `RegisterReceiver`, no `receivers` module.

- [ ] **Step 3: Implement**

`types/actions.rs` — the variant (bundle-carrying, so it is NOT listed in `bundle_less`):
```rust
    /// Publishes (or rotates) a receiver record (spec §6.2/§6.3). Anyone may carry a valid
    /// record — it is authorisation by construction — and pays the bundle's fee for it.
    RegisterReceiver { record: crate::receiver::ReceiverRecord },
```

`ledger/receivers.rs`:
```rust
//! The receiver registry (spec §6.1–§6.3): consensus state, keyed by receiver id.
use super::{Ledger, TxError};
use crate::crypto::{merkle_root, Hash};
use crate::notes::{word8_to_bytes, Word8};
use crate::receiver::{ReceiverId, ReceiverRecord};
use std::collections::BTreeMap;

pub fn receivers_root(m: &BTreeMap<ReceiverId, ReceiverRecord>) -> Hash {
    let leaves: Vec<Hash> = m.iter().map(|(id, r)| {
        let mut buf = Vec::with_capacity(32 + 4 + 32 + r.kem_ek.len());
        buf.extend_from_slice(&id.0);
        buf.extend_from_slice(&r.version.to_be_bytes());
        buf.extend_from_slice(&word8_to_bytes(&r.pk));
        buf.extend_from_slice(&r.kem_ek);
        Hash::digest_domain(b"rand-receiver-leaf-1", &buf)
    }).collect();
    merkle_root(&leaves)
}

impl Ledger {
    pub fn receivers(&self) -> &BTreeMap<ReceiverId, ReceiverRecord> { &self.receivers }
    pub fn set_receivers(&mut self, m: BTreeMap<ReceiverId, ReceiverRecord>) { self.receivers = m; }
    pub fn resolve_record(&self, id: &ReceiverId) -> Option<&ReceiverRecord> { self.receivers.get(id) }
    pub fn resolve_pk(&self, id: &ReceiverId) -> Option<Word8> { self.receivers.get(id).map(|r| r.pk) }

    /// Spec §6.2: the record verifies under the id it names, for this chain; a first
    /// registration is version 1; a later one is exactly `current + 1` with the same `pk`.
    pub(crate) fn validate_register_receiver(&self, record: &ReceiverRecord) -> Result<(), TxError> {
        let id = record.id();
        record.verify(&id, self.chain_id()).map_err(TxError::Receiver)?;
        match self.receivers.get(&id) {
            None if record.version != 1 => Err(TxError::ReceiverVersion { expected: 1, actual: record.version }),
            None => Ok(()),
            Some(cur) if record.version != cur.version + 1 => Err(TxError::ReceiverVersion { expected: cur.version + 1, actual: record.version }),
            Some(cur) if record.pk != cur.pk => Err(TxError::ReceiverPkChanged),
            Some(_) => Ok(()),
        }
    }
    pub(crate) fn apply_register_receiver(&mut self, record: &ReceiverRecord) {
        self.receivers.insert(record.id(), record.clone());
    }
}
```

`ledger/mod.rs`: add `mod receivers; pub use receivers::receivers_root;`, the field `receivers: BTreeMap<ReceiverId, ReceiverRecord>` (both constructors, the `PartialEq` list next to `aggregators`), `TxError::Receiver(#[from] crate::receiver::RecordError)`, `TxError::ReceiverVersion { expected: u32, actual: u32 }` (`"receiver record version {actual}, expected {expected}"`), `TxError::ReceiverPkChanged` (`"a receiver record may not change pk"`). Step 1 (size caps): `Action::RegisterReceiver { record } if record.encoded_len() > crate::receiver::MAX_RECORD_BYTES => return Err(TxError::Receiver(RecordError::TooLarge(record.encoded_len())))`. Step 7 (action-specific cheap checks): `Action::RegisterReceiver { record } => self.validate_register_receiver(record)?,`. `apply_tx`: `Action::RegisterReceiver { record } => self.apply_register_receiver(record),`. `state_root`: after the aggregators component, always append `receivers_root(&self.receivers).as_bytes()` and use domain `rand-state-4` for both branches (chain 11 has no gate; the aggregation branch keeps its extra component before it). `debug_state_root_components`: add `receivers`.

- [ ] **Step 4: Run the tests to verify they pass, and the rest of core**

Run: `cargo test --release -p randprotocol-core --lib`
Expected: the four new tests pass; the two pinned root tests (`bridge::state::tests::root_is_pinned_for_a_fixed_state` is unaffected; `genesis::tests::a_bridge_section_is_accepted_and_only_a_bridged_chain_changes` pins a state root) move once — update that one pin to the new value, with a comment naming `rand-state-4`.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-core
git commit -m "core: the receiver registry in ledger state — Action::RegisterReceiver, the version rule, receivers_root under rand-state-4

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 4: Payouts become receiver ids (staking, aggregation, genesis)

**Files:**
- Modify: `crates/randprotocol-core/src/types/actions.rs` (`Registration.payout: ReceiverId`, `AggregatorRegistration.payout: ReceiverId`, `registration_message(chain_id, payout: &ReceiverId)`, `aggregator_register_message` likewise), `crates/randprotocol-core/src/ledger/staking.rs` (`ValidatorEntry.payout: ReceiverId`; the `KEM_EK_BYTES` check becomes "the registry holds the id"; `withdraw_note` resolves `pk`; the v3 validator leaf hashes the 32-byte id), `crates/randprotocol-core/src/ledger/aggregation.rs` (`AggregatorEntry.payout: ReceiverId`, `check_register`, `withdraw_note`, `payout_note`, `aggregators_root` leaf), `crates/randprotocol-core/src/genesis.rs` (`GenesisValidator.payout` parses the short form; new `receivers: Vec<ReceiverRecordHex>`; `build` registers them first and refuses a validator or alloc whose id has no record: `GenesisError::UnknownReceiver(String)`; alloc notes take the id and seal to the record), `crates/randprotocol-core/src/ledger/mod.rs` (the validator leaf domain `rand-validator-leaf-3`)
- Test: the existing staking/aggregation/genesis tests updated to build a record first; new tests below.

**Interfaces:**
- Consumes: Task 3's `resolve_pk`, `resolve_record`, `set_receivers`.
- Produces: `StakingError::UnknownReceiver(ReceiverId)`, `AggregationError::UnknownReceiver(ReceiverId)`, `GenesisError::UnknownReceiver(String)`, `Genesis.receivers: Vec<ReceiverRecordHex>` with `ReceiverRecordHex { version, pk, kem_ek, signing_key, signature }` (all hex strings) and `to_record()/from_record()`.

- [ ] **Step 1: Write the failing tests**

In `staking.rs` tests (next to the existing registration tests):
```rust
    #[test]
    fn a_registration_names_a_receiver_id_the_registry_must_hold() {
        let (mut l, kp) = fresh_ledger_and_validator_key();
        let signing = receiver_signing_keypair(&[4; 32]);
        let payout = ReceiverId::from(signing.public_key());
        let reg = Registration { public_key: kp.public_key().clone(), payout, signature: kp.sign(registration_message(l.chain_id(), &payout).as_bytes()) };
        assert!(matches!(check_register(&l, &kp.address(), MIN_STAKE, None, Some(&reg)), Err(StakingError::UnknownReceiver(p)) if p == payout));
        let rec = ReceiverRecord::sign(&signing, l.chain_id(), 1, [4; 8], vec![4; KEM_EK_BYTES]);
        l.apply_register_receiver(&rec);
        check_register(&l, &kp.address(), MIN_STAKE, None, Some(&reg)).unwrap();
    }

    #[test]
    fn a_withdraw_note_is_derived_from_the_registrys_pk() {
        let (mut l, kp) = registered_validator_with_record([4; 8]);
        let cm = withdraw_note(&l, &kp.address(), 100, 5, &[9; 8], &StubExecutor).unwrap();
        assert_eq!(cm, StubExecutor.note_commitment(&[4; 8], &[0; 8], 100 - gas::BUNDLE_BASE, 0, 5, &[9; 8]));
    }
```
In `genesis.rs` tests:
```rust
    #[test]
    fn genesis_registers_its_receivers_first_and_refuses_an_unknown_payout_or_alloc_owner() {
        let signing = receiver_signing_keypair(&[4; 32]);
        let rec = ReceiverRecord::sign(&signing, 1, 1, [4; 8], vec![4; KEM_EK_BYTES]);
        let id = rec.id();
        let mut g = genesis_with_one_validator_paid_to(id);      // payout: id.to_string()
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::UnknownReceiver(s)) if s == id.to_string()));
        g.receivers.push(ReceiverRecordHex::from_record(&rec));
        let s = g.build(&StubExecutor).unwrap();
        assert_eq!(s.ledger.receivers().len(), 1);
        assert_eq!(s.ledger.validators().values().next().unwrap().payout, id);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --release -p randprotocol-core --lib`
Expected: compile errors (`payout` is a `ShieldedAddress`, no `UnknownReceiver`).

- [ ] **Step 3: Implement**

Change every `payout: ShieldedAddress` to `payout: ReceiverId`; the messages serialize `(chain_id, payout)` as before (the id is 32 bytes). In `check_register`, replace the `KEM_EK_BYTES` check with `if ledger.resolve_record(&r.payout).is_none() { return Err(StakingError::UnknownReceiver(r.payout)); }`. In `withdraw_note`: `let pk = ledger.resolve_pk(&e.payout).ok_or(StakingError::UnknownReceiver(e.payout))?;` then `executor.note_commitment(&pk, …)`. Same shape in `aggregation.rs` (`check_register`, `withdraw_note`, `payout_note`). The validator leaf: `buf.extend_from_slice(&v.payout.0)` in place of the pk bytes and kem_ek, domain `rand-validator-leaf-3`; the aggregator leaf likewise (`rand-aggregator-leaf-2`). Genesis: `pub receivers: Vec<ReceiverRecordHex>` (`#[serde(default)]`), in `build`: first `for r in &self.receivers { let rec = r.to_record()?; rec.verify(&rec.id(), self.chain_id).map_err(|e| GenesisError::BadReceiver(e.to_string()))?; ledger.apply_register_receiver(&rec); }`, then validators (`ReceiverId::parse(&v.payout)` → `GenesisError::BadPayout`; `ledger.resolve_record(&id).is_none()` → `GenesisError::UnknownReceiver(v.payout.clone())`), then allocs: `GenesisNote` keeps `cm`/`envelope`/`amount` (the node's `genesis` command seals them, Task 6, from the record). Remove `ShieldedAddress::to_string/parse/recipient_hash`; add `impl From<&ReceiverRecord> for ShieldedAddress { fn from(r) -> Self { ShieldedAddress { pk: r.pk, kem_ek: r.kem_ek.clone() } } }`.

- [ ] **Step 4: Run the core suite**

Run: `cargo test --release -p randprotocol-core --lib`
Expected: all pass (every fixture that built a `ShieldedAddress` payout now builds a record, registers it on the fixture ledger, and uses its id).

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-core
git commit -m "core: payouts are receiver ids — staking and aggregator registrations name an id the registry holds; withdraw and payout notes resolve pk from it; genesis carries its receivers

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 5: The bridge recipient is the receiver id

**Files:**
- Modify: `crates/randprotocol-core/src/types/actions.rs` (`BridgeAttest.recipient: ReceiverId`), `crates/randprotocol-core/src/ledger/bridge_notes.rs` (the `to_hash` compare becomes `t.to_hash != recipient.0`; `deposit_commitment` takes `pk` resolved from the registry; `TxError::Bridge(BridgeError::UnknownReceiver(ReceiverId))`), `crates/randprotocol-core/src/bridge/state.rs` (the `to_hash` doc: "the receiver id"), `crates/randprotocol-core/src/bridge/*.rs` where `recipient_hash` was used
- Test: `bridge_notes.rs` tests

**Interfaces:**
- Consumes: Task 3's `resolve_pk`.
- Produces: `BridgeError::UnknownReceiver(ReceiverId)`; `deposit_commitment(pk: &Word8, amount, index, time, r, executor)`.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn a_deposit_to_an_unregistered_receiver_is_refused_and_a_registered_one_lands_on_its_pk() {
        let (mut l, guardians) = bridged_ledger();
        let signing = receiver_signing_keypair(&[4; 32]);
        let id = ReceiverId::from(signing.public_key());
        let tx = attest_tx(&l, &guardians, id, 500);     // wire `to` = id.0
        assert!(matches!(l.validate(&tx, &StubExecutor), Err(TxError::Bridge(BridgeError::UnknownReceiver(r))) if r == id));
        l.apply_register_receiver(&ReceiverRecord::sign(&signing, l.chain_id(), 1, [4; 8], vec![4; KEM_EK_BYTES]));
        l.validate(&tx, &StubExecutor).unwrap();
        let cm = l.derived_commitment(&tx.action, &StubExecutor).unwrap();
        assert_eq!(cm, StubExecutor.note_commitment(&[4; 8], &DEPOSIT_FROM, 500, 1, time_of(&tx), &r_of(&tx)));
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo test --release -p randprotocol-core --lib bridge_notes` — Expected: compile error (`recipient` is a `ShieldedAddress`).

- [ ] **Step 3: Implement** — as listed under Files: `if t.to_hash != recipient.0 { return Err(TxError::BridgeRecipientMismatch); }`; `let pk = ledger.resolve_pk(recipient).ok_or(TxError::Bridge(BridgeError::UnknownReceiver(*recipient)))?;` before the commitment; `derived_commitment`'s `BridgeAttest` arm resolves the same way (returns `None` when unknown).

- [ ] **Step 4: Run the core suite** — `cargo test --release -p randprotocol-core --lib` — Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-core
git commit -m "core: the bridge recipient is the receiver id — the wire to field is the id, deposits to an unregistered receiver are refused

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 6: Node — storage, RPC, the action JSON, the genesis command

**Files:**
- Modify: `crates/randprotocol-node/src/storage.rs` (`META_RECEIVERS`, written where `META_AGGREGATORS` is written at lines ~376/1332/1716, read at ~649, restored at ~1059), `crates/randprotocol-node/src/rpc.rs` (`rand_getReceiver`, `rand_getReceivers`, action JSON `{"kind":"register_receiver","id":…,"version":…,"pk":…,"kem_ek":…,"signing_key":…,"signature":…}`, `rand_getAggregators`/`rand_getValidators` print `payout` as the short address), `crates/randprotocol-node/src/main.rs` (`genesis --receiver <record.json>` repeatable; `--validator <key>,<stake>,<rand1 id>`; `--alloc <rand1 id>=<amount>` sealed to the record from `--receiver`), `crates/randprotocol-node/src/mempool.rs` (nothing to claim for `RegisterReceiver`; `derived_commitment` already covers the bridge)
- Test: `storage.rs` tests (round-trip), `rpc.rs` tests, `main.rs` tests (`deposit_note` from a record)

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces: `Storage::receivers() -> Result<BTreeMap<ReceiverId, ReceiverRecord>>`; RPC `rand_getReceiver(address) -> record | null`, `rand_getReceivers() -> [record]`; `deposit_note(record: &ReceiverRecord, amount) -> GenesisNote`.

- [ ] **Step 1: Write the failing tests**

storage:
```rust
    #[test]
    fn the_receiver_registry_round_trips_through_meta_and_reload() {
        let (_d, storage, mut gs) = fresh_genesis_state();
        let signing = receiver_signing_keypair(&[4; 32]);
        let rec = ReceiverRecord::sign(&signing, gs.chain_id, 1, [4; 8], vec![4; KEM_EK_BYTES]);
        gs.ledger.apply_register_receiver(&rec);
        storage.init_genesis(&gs).unwrap();
        assert_eq!(storage.receivers().unwrap().get(&rec.id()), Some(&rec));
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.receivers(), gs.ledger.receivers());
        assert_eq!(reloaded.state_root(), gs.ledger.state_root());
    }
```
rpc:
```rust
    #[tokio::test]
    async fn rand_get_receiver_serves_the_record_and_null_for_the_unknown() {
        let (st, rec) = state_with_one_receiver().await;
        let v = ok(&st, "rand_getReceiver", json!([rec.id().to_string()])).await;
        assert_eq!(v["version"], 1);
        assert_eq!(v["kem_ek"].as_str().unwrap().len(), KEM_EK_BYTES * 2);
        assert_eq!(v["signing_key"], rec.signing_key.to_hex());
        let none = ok(&st, "rand_getReceiver", json!([ReceiverId([1; 32]).to_string()])).await;
        assert!(none.is_null());
        assert_eq!(call(&st, "rand_getReceiver", json!(["rand1notanaddress"])).await.unwrap_err().code, -32602);
    }
```

- [ ] **Step 2: Run to verify they fail** — `cargo test --release -p randprotocol-node --lib receiver` — Expected: compile errors.

- [ ] **Step 3: Implement**

storage: `const META_RECEIVERS: &str = "receivers";` and three `batch.put_cf(self.cf(CF_META), META_RECEIVERS, bincode::serialize(ledger.receivers())?)` next to the aggregators' three; `pub fn receivers(&self) -> Result<BTreeMap<ReceiverId, ReceiverRecord>>` like `aggregators()`; `ledger.set_receivers(self.receivers()?)` in `reload_ledger`. rpc:
```rust
        "rand_getReceiver" => {
            let s: String = param(&params, 0)?;
            let id = ReceiverId::parse(&s).map_err(|e| RpcError::invalid_params(e.to_string()))?;
            let m = st.storage.receivers().map_err(RpcError::internal)?;
            Ok(m.get(&id).map(record_json).unwrap_or(Value::Null))
        }
        "rand_getReceivers" => {
            let m = st.storage.receivers().map_err(RpcError::internal)?;
            Ok(json!(m.values().map(record_json).collect::<Vec<_>>()))
        }
```
with `fn record_json(r: &ReceiverRecord) -> Value { json!({ "id": r.id().to_string(), "version": r.version, "pk": word8_to_hex(&r.pk), "kem_ek": hex::encode(&r.kem_ek), "signing_key": r.signing_key.to_hex(), "signature": hex::encode(r.signature.as_bytes()) }) }`, and the action arm `Action::RegisterReceiver { record } => { let mut v = record_json(record); v["kind"] = json!("register_receiver"); v }`. main.rs `genesis`: `#[arg(long = "receiver")] receivers: Vec<PathBuf>` (each a JSON `ReceiverRecordHex`), loaded into `gen.receivers` first; `deposit_note(addr, amount)` becomes `deposit_note(record: &ReceiverRecord, amount)` sealing to `ShieldedAddress::from(record)`, and `--alloc <rand1 id>=<amount>` looks the id up among `--receiver` files (error: "alloc owner rand1… has no --receiver record").

- [ ] **Step 4: Run the node unit suite and the fast integration suites**

Run: `RECURSION_FIXTURES=… cargo test --release -p randprotocol-node --lib` and `cargo test --release -p randprotocol-node --test ws --test submit`
Expected: all pass (cluster fixtures that registered validators with a `ShieldedAddress` now register a record first — `tests/common/mod.rs`'s genesis builder takes the records).

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-node
git commit -m "node: the receiver registry persisted and served — rand_getReceiver, the register_receiver action JSON, genesis --receiver

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 7: The wallet — signing key, short address, record, request, register, resolve, versioned opening

**Files:**
- Create: `crates/randprotocol-client/src/receiver.rs` (resolution + payment request)
- Modify: `crates/randprotocol-client/src/wallet.rs` (`KeyFile { version: 3, spend_key, kem_version: u32 }` — version 2 files load with `kem_version = 0`; `Wallet { sk, vk, signing: Keypair, id: ReceiverId, kem_version }`; `fn record(&self, chain_id) -> ReceiverRecord`; `fn current_address(&self) -> ShieldedAddress` = `address_of_at(&self.vk, self.kem_version)`; scanning tries `open_as_receiver_at` for `kem_version..=0`; bridge deposit address refuses when unregistered), `crates/randprotocol-client/src/main.rs` (`address [--record]`, `request [--amount] [--memo]`, `register [--rotate]`, `send … [--record <file>] [--registry <url>]`, the §4 error text), `crates/randprotocol-client/src/lib.rs` (`RpcClient::receiver(id)`)
- Test: `wallet.rs` tests, `receiver.rs` tests, `tests/wallet_flow.rs` (one new stage: request → send with no registry; rotate → old notes still open)

**Interfaces:**
- Consumes: Task 1, Task 2 (`address_at`, `open_as_receiver_at`), Task 6's RPC.
- Produces: `receiver::PaymentRequest { id: ReceiverId, record: ReceiverRecord, amount: Option<u64>, memo: Option<String> }` with `to_uri()`/`parse(&str)`; `receiver::resolve(id, chain_id, record_file: Option<&Path>, registry: Option<&str>) -> Result<ShieldedAddress>`; `Wallet::record(&self, chain_id) -> ReceiverRecord`; `Wallet::rotate(&mut self) -> u32`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn the_wallet_has_one_identity_and_signs_its_own_record() {
        let w = Wallet::from_spend_key(SpendKey([11; 8]));
        assert_eq!(w.id, ReceiverId::from(w.signing.public_key()));
        assert_eq!(w.id.to_string().len(), 54);
        let rec = w.record(10);
        rec.verify(&w.id, 10).unwrap();
        assert_eq!(rec.pk, w.vk.pk());
        assert_eq!(rec.kem_ek, w.current_address().kem_ek);
    }

    #[test]
    fn a_rotation_bumps_the_version_and_every_earlier_envelope_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut me = Wallet::generate();
        me.save_new(&path).unwrap();
        let sender = Wallet::generate();
        let note0 = Note::new(me.vk.pk(), [0; 8], 5, 0, 1);
        let env0 = sealed_to(&sender, &me.current_address(), &note0);
        assert_eq!(me.rotate(), 1);
        me.save(&path).unwrap();
        let note1 = Note::new(me.vk.pk(), [0; 8], 6, 0, 1);
        let env1 = sealed_to(&sender, &me.current_address(), &note1);
        assert_eq!(me.rotate(), 2);
        let reloaded = Wallet::load(&path).unwrap();
        assert_eq!(reloaded.kem_version, 1, "the file keeps the version");
        assert_eq!(me.open_received(&env0, note0.commitment()).unwrap(), note0);
        assert_eq!(me.open_received(&env1, note1.commitment()).unwrap(), note1);
        assert_ne!(me.record(10).kem_ek, me.record_at(10, 0).kem_ek);
    }

    #[test]
    fn a_payment_request_round_trips_and_resolves_offline() {
        let w = Wallet::from_spend_key(SpendKey([11; 8]));
        let req = PaymentRequest { id: w.id, record: w.record(10), amount: Some(1_500_000_000), memo: Some("coffee".into()) };
        let uri = req.to_uri();
        assert!(uri.starts_with(&format!("rand:{}?rec=", w.id)));
        let back = PaymentRequest::parse(&uri).unwrap();
        assert_eq!(back, req);
        let addr = resolve_from_request(&back, 10).unwrap();
        assert_eq!(addr.pk, w.vk.pk());
        let mut forged = back.clone();
        forged.record.kem_ek[0] ^= 1;
        assert!(resolve_from_request(&forged, 10).is_err(), "a tampered record never resolves");
    }
```

- [ ] **Step 2: Run to verify they fail** — `cargo test --release -p randprotocol-client --lib` — Expected: compile errors.

- [ ] **Step 3: Implement**

`wallet.rs`: derive `signing = receiver_signing_keypair(&word8_to_bytes(&sk.0))` in `from_spend_key`; `id = ReceiverId::from(signing.public_key())`; `kem_version` from the key file (default 0); `current_address()` via `randprotocol_zkvm::address::address_of_at(&self.vk, self.kem_version)` (add that helper next to `address_of`, calling `vk.address_at(v)`); `record(chain_id)` = `ReceiverRecord::sign(&self.signing, chain_id, self.kem_version + 1, self.vk.pk(), self.current_address().kem_ek)` — version numbering: record version = `kem_version + 1` so version 1 is KEM version 0; `rotate()` increments `kem_version` and returns it; `open_received(env, cm)` tries `for v in (0..=self.kem_version).rev() { if let Some((_, n)) = env_from_core(env).open_as_receiver_at(cm, &self.vk, v) { return Some(n) } }`; the scan uses `open_received`. `receiver.rs`: `PaymentRequest::to_uri` = `format!("rand:{}?rec={}{}{}", id, base64url(bincode(record)), amount.map(|a| format!("&amount={a}")).unwrap_or_default(), memo…)`, `parse` the reverse, `resolve_from_request(req, chain_id)` = `req.record.verify(&req.id, chain_id)?; Ok(ShieldedAddress::from(&req.record))`; `resolve(id, chain_id, record_file, registry)`: file → parse JSON `ReceiverRecordHex` → verify; else `GET {registry}/receivers/{id}` → JSON → verify; else the §4 error: `no receiver record for {id}: ask the receiver for a payment request, or for them to register`. `main.rs`: `Address { record: bool }` prints the id, or the record JSON; `Request { amount, memo }` prints the URI; `Register { rotate: bool }` builds `RegisterReceiver { record: w.record(chain) }` on a self-transfer bundle (the existing `send` path to `w.current_address()` with the action), rotating first when `--rotate`; `Send { to, …, record: Option<PathBuf>, registry: Option<String> }` resolves before the proof; `bridge deposit-address` (wherever `recipient_hash` was printed) checks `rpc.receiver(w.id)` is `Some` first: "register first (rand register) before a bridge deposit can be claimed".

- [ ] **Step 4: Run the client suite and the wallet flow**

Run: `cargo test --release -p randprotocol-client --lib` then `cargo test --release -p randprotocol-client --test wallet_flow`
Expected: pass; the wallet flow's new stage sends by payment request to a fresh wallet, registers it sender-paid, rotates, sends again, and both notes open.

- [ ] **Step 5: Commit**

```bash
git add crates/randprotocol-client crates/randprotocol-zkvm/src/address.rs
git commit -m "client: the short address — the derived signing key, rand address/request/register, send by record or registry, versioned KEM opening

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 8: The explorer — index the registry and serve `/receivers`

**Files (randscan repo):**
- Create: `migrations/008_receivers.sql`, `crates/randscan-db/src/queries/receivers.rs`, `crates/randscan-api/src/handlers/receivers.rs`
- Modify: `crates/randscan-db/src/models.rs` (`ReceiverRow`), `crates/randscan-db/src/lib.rs` (export), `crates/randscan-indexer/src/rpc.rs` (`RpcAction::RegisterReceiver { id, version, pk, kem_ek, signing_key, signature }`), `crates/randscan-indexer/src/processor.rs` (insert on that action, after the tx insert, like `Deploy`), `crates/randscan-api/src/routes.rs` (`/receivers/:address`, `/receivers/:address/history`), `crates/randscan-core/src/lib.rs` (`ReceiverRecordView`), `docs/api.md`, `crates/randscan-api/tests/common/mock_node.rs` (a `register_receiver` action in a block)
- Test: `crates/randscan-api/tests/receivers.rs`

**Interfaces:**
- Consumes: Task 6's action JSON and `rand_getReceiver` (for the indexer's verification: the explorer re-runs `ReceiverRecord::verify` via `randprotocol-core`, which randscan-viewing already depends on).
- Produces: `GET /api/v1/receivers/:address` → `{ "id", "version", "pk", "kem_ek", "signing_key", "signature", "tx_hash", "height" }`, 404 when unknown, 400 when the address does not parse; `GET /api/v1/receivers/:address/history` → `[ … ]` newest first.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn receivers_are_indexed_and_served_current_and_history() {
    let (app, node) = common::app_with_mock_node().await;
    let (rec1, rec2, id) = common::two_versions_of_a_record(node.chain_id);
    node.push_block_with_actions(vec![common::register_receiver(&rec1)]).await;
    node.push_block_with_actions(vec![common::register_receiver(&rec2)]).await;
    common::wait_synced(&app).await;
    let cur: serde_json::Value = common::get_json(&app, &format!("/api/v1/receivers/{id}")).await;
    assert_eq!(cur["version"], 2);
    assert_eq!(cur["kem_ek"], hex::encode(&rec2.kem_ek));
    let hist: serde_json::Value = common::get_json(&app, &format!("/api/v1/receivers/{id}/history")).await;
    assert_eq!(hist.as_array().unwrap().len(), 2);
    assert_eq!(common::get_status(&app, "/api/v1/receivers/rand1nope").await, 400);
    assert_eq!(common::get_status(&app, &format!("/api/v1/receivers/{}", randprotocol_core::ReceiverId([9; 32]))).await, 404);
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p randscan-api --test receivers` — Expected: 404/compile errors.

- [ ] **Step 3: Implement**

```sql
-- 008_receivers.sql: the receiver registry (fullnode spec 2026-09-17 §5, §8). One row per
-- published version; the current record is the highest version per id.
CREATE TABLE receivers (
    id          TEXT    NOT NULL,   -- the rand1… address
    version     INTEGER NOT NULL,
    pk          TEXT    NOT NULL,   -- hex
    kem_ek      TEXT    NOT NULL,   -- hex, 2368 chars
    signing_key TEXT    NOT NULL,   -- hex
    signature   TEXT    NOT NULL,   -- hex
    tx_hash     TEXT    NOT NULL REFERENCES transactions(hash) ON DELETE CASCADE,
    height      BIGINT  NOT NULL,
    PRIMARY KEY (id, version)
);
CREATE INDEX receivers_current ON receivers (id, version DESC);
```
`queries/receivers.rs`: `insert_receiver(conn, &row)`, `get_receiver(pool, id) -> Option<ReceiverRow>` (`ORDER BY version DESC LIMIT 1`), `receiver_history(pool, id) -> Vec<ReceiverRow>`. Indexer: the `RpcAction::RegisterReceiver` variant deserialises the node's `register_receiver` JSON; the processor verifies (`randprotocol_core::ReceiverRecord { … }.verify(&id, chain_id)`, logging and skipping a row that fails — the chain already refused such a record, so a failure here is an indexer bug) and inserts. Handler: parse with `ReceiverId::parse` (400 on error), 404 when absent. Routes and `docs/api.md` rows as in Interfaces.

- [ ] **Step 4: Run the explorer suites** — `cargo test -p randscan-api` (mock node) and, with `RAND_NODE_BIN` pointing at Task 6's `rand-node`, `--test real_node` — Expected: pass.

- [ ] **Step 5: Commit (randscan)**

```bash
git add migrations/008_receivers.sql crates docs/api.md
git commit -m "receivers: index the receiver registry and serve /receivers/:address and its history

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 9: Docs

**Files:**
- Modify: `docs/shielded.md` (a new section "The address and the receiver record": the id, the record, the two paths, the privacy note), `docs/staking.md` (payout is an id; register requires the record), `docs/bridge.md` §10 (`to` is the receiver id; deposits to unregistered receivers are refused), `docs/rpc.md` (`rand_getReceiver`, `rand_getReceivers`, the `register_receiver` action), `docs/cli.md` (`address`, `request`, `register`, `send --record/--registry`), `README.md` (the address example), `AGENTS.md` (the feature record, the chain-11 note)

- [ ] **Step 1: Write the sections** — each states what the code does (Tasks 1–8), with the exact method and flag names from their Interfaces blocks, and the sizes from Global Constraints.
- [ ] **Step 2: Check every name against the code** — `git grep -n 'rand_getReceiver\|rand register\|--registry' docs README.md` matches the handlers and clap definitions.
- [ ] **Step 3: Commit**

```bash
git add docs README.md AGENTS.md
git commit -m "docs: short shielded addresses — the receiver id, the record, the two delivery paths, the RPC and CLI

Design: Anish Mohammad (https://github.com/zeroknowledge)"
```

---

### Task 10: Chain 11 — the genesis, the full suite, the rollout

**Files:**
- Create: `deploy/cut-chain11-genesis.sh` (from `cut-chain10-genesis.sh`: `--receiver deploy/payout/<name>.record.json` for the 18 validators and `wallets/shielded-{1..5}.record.json` for the notes' owners; the validators' payouts as the short form of their payout wallets' ids; the record files produced once by `rand address --record --key …` and committed for the payout wallets, gitignored for the shielded ones), `deploy/genesis-chain11.json`
- Modify: `deploy/README.md` (chain 11 header, the record files, the cut-over: `deploy/cutover-droplet.sh <ip> 4d757f11 <chain11 prefix> deploy/genesis-chain11.json` — same service and peer ids as chain 10), `deploy/run-a.sh`, `deploy/run-b.sh`, `.update-pin`

- [ ] **Step 1: The full suite on the branch** — `RECURSION_FIXTURES=… cargo test --workspace --release -- --skip round_trips --skip two_test_profile` — Expected: 0 failed. Record the totals in AGENTS.md.
- [ ] **Step 2: Cut** — produce the 23 record files, run the cut script, print the hash, `rand-node init` on the file to confirm chain id 11.
- [ ] **Step 3: Commit and push** — `git commit -am "deploy: chain 11 — the genesis with its receiver records, the run scripts, the README"`, then merge to main and push (the one push of this plan).
- [ ] **Step 4: Roll out** — build on E (`rsync` + `cargo build --release -p randprotocol-node -p randprotocol-client`), then `deploy/cutover-droplet.sh` one droplet at a time (regional first, then F, C, D, E — peer ids do not change), then A; redeploy the explorer (Task 8's commit) with `deploy/push-to-vps.sh` right after E; confirm `rand status` on every node, the explorer's `/health`, and one `rand send` by payment request to a fresh wallet.
- [ ] **Step 5: Record** — AGENTS.md and the deploy README's "what the rollout actually did", as for chains 9 and 10.

---

## Self-review

- **Spec coverage:** §1 keys → Task 1 (`receiver_signing_keypair`) and Task 7; §2 address → Task 1; §3 record and verify → Task 1; §4 payment request → Task 7; §5 registry via explorer → Tasks 6 (node RPC for the indexer), 7 (`--registry`), 8; §6.1 state → Task 3; §6.2 action → Task 3; §6.3 sender-paid → Task 3 with ruling R2 (any transaction may carry a valid record); §6.4 payouts and bridge → Tasks 4, 5; §6.5 proofs untouched → Global Constraint 2; §7 wallet flows → Task 7 (rotation via Task 2, ruling R1); §8 explorer → Task 8; §9 chain 11 → Task 10; §10 tests → each task's Step 1; §11 rulings: 1 → R1 (re-derived, never lost), 2 → R2, 3 → Task 5.
- **Placeholder scan:** none of the forbidden patterns; every code step shows code. Task 4 and Task 6 name existing fixture helpers by their role where the file's own names must be used; the implementer reads the file.
- **Type consistency:** `ReceiverId`, `ReceiverRecord::{sign, verify, id, encoded_len, signing_hash}`, `receiver_signing_keypair`, `Ledger::{receivers, set_receivers, resolve_pk, resolve_record, validate_register_receiver, apply_register_receiver}`, `receivers_root`, `TxError::{Receiver, ReceiverVersion, ReceiverPkChanged}`, `StakingError::UnknownReceiver`, `AggregationError::UnknownReceiver`, `BridgeError::UnknownReceiver`, `GenesisError::{UnknownReceiver, BadReceiver}`, `ViewingKey::{kem_seed_at, kem_keys_at, address_at}`, `Envelope::open_as_receiver_at`, `address_of_at`, `Wallet::{record, record_at, rotate, current_address, open_received, id, signing, kem_version}`, `PaymentRequest::{to_uri, parse}`, `resolve`, `resolve_from_request`, RPC `rand_getReceiver`/`rand_getReceivers`, explorer `/receivers/:address[/history]` — used with the same names throughout.

---

## Parallel side task (not part of this feature's tasks): the developer docs at randprotocol.org/docs

Requested by the user 2026-09-17, run by a separate agent in `../randprotocol.org`: a Solana-docs-style
developer site — address derivation, the protocol's cryptography, internals, proof generation,
program deployment, bridging and unbridging, mint and burn, RPC and CLI reference — written from
`fullnode/docs/*.md`, the README, the whitepapers and randscan's `docs/api.md`, truthful to the
code as it is on chain 10, with this feature's short address marked as chain 11 / upcoming.
